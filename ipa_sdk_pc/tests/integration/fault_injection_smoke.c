#include <assert.h>
#include <errno.h>
#include <sched.h>

#include "ipa_core.h"
#include "ipa_runtime.h"
#include "ipa_task_supervisor.h"

static ipa_runtime_t *runtime;

static int fail_create(pthread_t *thread, const pthread_attr_t *attributes,
                       void *(*entry)(void *), void *context) {
  (void)thread;
  (void)attributes;
  (void)entry;
  (void)context;
  return EAGAIN;
}

static void *successful_worker(void *context) {
  (void)context;
  ipa_runtime_complete_initialization(runtime, true);
  return NULL;
}

static void *wait_for_stop(void *context) {
  (void)context;
  while (!ipa_runtime_stop_requested(runtime)) sched_yield();
  ipa_runtime_complete_initialization(runtime, false);
  return NULL;
}

int main(void) {
  ipa_task_supervisor_t *supervisor = NULL;
  char driver_id[] = "/dev/fake-at";
  cl_config_t config = {ES10_DRIVER_AT, driver_id, eLogInfo, 1, 2, 60};

  assert(ipa_task_supervisor_init(&supervisor, NULL, NULL) == 0);
  ipa_task_supervisor_set_create_fn(supervisor, fail_create);
  assert(ipa_task_supervisor_start(supervisor, IPA_TASK_SLOT_INIT, 0,
                                   successful_worker, NULL) == EAGAIN);
  ipa_task_supervisor_set_create_fn(supervisor, NULL);
  assert(ipa_task_supervisor_start(supervisor, IPA_TASK_SLOT_INIT, 0,
                                   successful_worker, NULL) == 0);
  assert(ipa_task_supervisor_join_all(supervisor) == 0);
  ipa_task_supervisor_destroy(supervisor);

  assert(ipa_runtime_create(&runtime, NULL, NULL) == 0);
  assert(ipa_runtime_start(runtime, &config, wait_for_stop) == 0);
  assert(!ipa_runtime_stop(runtime));
  assert(ipa_runtime_start(runtime, &config, successful_worker) == 0);
  while (ipa_runtime_state(runtime) == IPA_RUNTIME_INITIALIZING) sched_yield();
  assert(ipa_runtime_state(runtime) == IPA_RUNTIME_READY);
  assert(ipa_runtime_stop(runtime));
  ipa_runtime_destroy(runtime);
  return 0;
}
