#include <assert.h>
#include <errno.h>
#include <stdatomic.h>

#include "ipa_task_supervisor.h"

static atomic_int starts;
static atomic_int ends;
static atomic_int completed;

static void on_start(uint32_t task_id) {
  assert(task_id == 42);
  atomic_fetch_add(&starts, 1);
}

static void on_end(uint32_t task_id) {
  assert(task_id == 42);
  atomic_fetch_add(&ends, 1);
}

static void *immediate_worker(void *context) {
  (void)context;
  atomic_store(&completed, 1);
  return NULL;
}

typedef struct {
  ipa_task_supervisor_t *supervisor;
  ipa_task_slot_id_t slot;
} blocked_context_t;

static void *blocked_worker(void *context) {
  blocked_context_t *blocked = context;
  ipa_task_supervisor_wait_for_stop(blocked->supervisor, blocked->slot);
  atomic_store(&completed, 1);
  return NULL;
}

static int fail_create(pthread_t *thread, const pthread_attr_t *attributes,
                       void *(*entry)(void *), void *context) {
  (void)thread;
  (void)attributes;
  (void)entry;
  (void)context;
  return EAGAIN;
}

int main(void) {
  ipa_task_supervisor_t *supervisor = NULL;
  blocked_context_t blocked;

  assert(ipa_task_supervisor_init(&supervisor, on_start, on_end) == 0);
  assert(ipa_task_supervisor_start(supervisor, IPA_TASK_SLOT_INIT, 42,
                                   immediate_worker, NULL) == 0);
  assert(ipa_task_supervisor_join_all(supervisor) == 0);
  assert(atomic_load(&completed) == 1);
  assert(atomic_load(&starts) == 1);
  assert(atomic_load(&ends) == 1);

  atomic_store(&completed, 0);
  blocked.supervisor = supervisor;
  blocked.slot = IPA_TASK_SLOT_MQTT;
  assert(ipa_task_supervisor_start(supervisor, blocked.slot, 42,
                                   blocked_worker, &blocked) == 0);
  ipa_task_supervisor_request_stop(supervisor);
  assert(ipa_task_supervisor_join_all(supervisor) == 0);
  assert(atomic_load(&completed) == 1);
  assert(atomic_load(&starts) == 2);
  assert(atomic_load(&ends) == 2);

  ipa_task_supervisor_set_create_fn(supervisor, fail_create);
  assert(ipa_task_supervisor_start(supervisor, IPA_TASK_SLOT_HTTP, 42,
                                   immediate_worker, NULL) == EAGAIN);
  assert(ipa_task_supervisor_join_all(supervisor) == 0);
  ipa_task_supervisor_set_create_fn(supervisor, NULL);
  assert(ipa_task_supervisor_start(supervisor, IPA_TASK_SLOT_HTTP, 42,
                                   immediate_worker, NULL) == 0);
  assert(ipa_task_supervisor_join_all(supervisor) == 0);
  assert(atomic_load(&starts) == 3);
  assert(atomic_load(&ends) == 3);

  ipa_task_supervisor_destroy(supervisor);
  return 0;
}
