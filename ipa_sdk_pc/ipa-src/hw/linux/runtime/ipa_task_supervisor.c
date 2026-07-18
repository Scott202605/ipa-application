#include "ipa_task_supervisor.h"

#include <errno.h>
#include <stdlib.h>

typedef struct {
  pthread_t thread;
  bool joinable;
  bool running;
  bool stop_requested;
  uint32_t task_id;
  ipa_task_supervisor_worker_fn worker;
  void *worker_context;
  struct ipa_task_supervisor *owner;
} ipa_task_slot_t;

struct ipa_task_supervisor {
  pthread_mutex_t mutex;
  pthread_cond_t stop_condition;
  ipa_task_slot_t slots[IPA_TASK_SUPERVISOR_SLOT_COUNT];
  ipa_task_supervisor_notify_fn on_start;
  ipa_task_supervisor_notify_fn on_end;
  ipa_task_supervisor_create_fn create_thread;
};

static bool valid_slot(ipa_task_slot_id_t slot) {
  return slot >= IPA_TASK_SLOT_INIT && slot < IPA_TASK_SUPERVISOR_SLOT_COUNT;
}

static void *run_slot(void *context) {
  ipa_task_slot_t *slot = context;
  ipa_task_supervisor_t *owner = slot->owner;
  ipa_task_supervisor_notify_fn notify;
  ipa_task_supervisor_worker_fn worker;
  void *worker_context;
  uint32_t task_id;

  pthread_mutex_lock(&owner->mutex);
  notify = owner->on_start;
  worker = slot->worker;
  worker_context = slot->worker_context;
  task_id = slot->task_id;
  pthread_mutex_unlock(&owner->mutex);

  if (notify) notify(task_id);
  worker(worker_context);

  pthread_mutex_lock(&owner->mutex);
  slot->running = false;
  notify = owner->on_end;
  pthread_cond_broadcast(&owner->stop_condition);
  pthread_mutex_unlock(&owner->mutex);
  if (notify) notify(task_id);
  return NULL;
}

int ipa_task_supervisor_init(ipa_task_supervisor_t **out,
                             ipa_task_supervisor_notify_fn on_start,
                             ipa_task_supervisor_notify_fn on_end) {
  ipa_task_supervisor_t *supervisor;
  size_t index;
  if (!out) return EINVAL;
  *out = NULL;
  supervisor = calloc(1, sizeof(*supervisor));
  if (!supervisor) return ENOMEM;
  if (pthread_mutex_init(&supervisor->mutex, NULL) != 0) {
    free(supervisor);
    return EAGAIN;
  }
  if (pthread_cond_init(&supervisor->stop_condition, NULL) != 0) {
    pthread_mutex_destroy(&supervisor->mutex);
    free(supervisor);
    return EAGAIN;
  }
  supervisor->on_start = on_start;
  supervisor->on_end = on_end;
  supervisor->create_thread = pthread_create;
  for (index = 0; index < IPA_TASK_SUPERVISOR_SLOT_COUNT; ++index)
    supervisor->slots[index].owner = supervisor;
  *out = supervisor;
  return 0;
}

int ipa_task_supervisor_start(ipa_task_supervisor_t *supervisor,
                              ipa_task_slot_id_t slot_id, uint32_t task_id,
                              ipa_task_supervisor_worker_fn worker,
                              void *worker_context) {
  ipa_task_slot_t *slot;
  int result;
  if (!supervisor || !worker || !valid_slot(slot_id)) return EINVAL;
  pthread_mutex_lock(&supervisor->mutex);
  slot = &supervisor->slots[slot_id];
  if (slot->joinable) {
    pthread_mutex_unlock(&supervisor->mutex);
    return EBUSY;
  }
  slot->running = true;
  slot->stop_requested = false;
  slot->task_id = task_id;
  slot->worker = worker;
  slot->worker_context = worker_context;
  result = supervisor->create_thread(&slot->thread, NULL, run_slot, slot);
  if (result == 0) {
    slot->joinable = true;
  } else {
    slot->running = false;
    slot->worker = NULL;
    slot->worker_context = NULL;
  }
  pthread_mutex_unlock(&supervisor->mutex);
  return result;
}

void ipa_task_supervisor_request_stop(ipa_task_supervisor_t *supervisor) {
  size_t index;
  if (!supervisor) return;
  pthread_mutex_lock(&supervisor->mutex);
  for (index = 0; index < IPA_TASK_SUPERVISOR_SLOT_COUNT; ++index)
    if (supervisor->slots[index].joinable)
      supervisor->slots[index].stop_requested = true;
  pthread_cond_broadcast(&supervisor->stop_condition);
  pthread_mutex_unlock(&supervisor->mutex);
}

bool ipa_task_supervisor_should_stop(ipa_task_supervisor_t *supervisor,
                                     ipa_task_slot_id_t slot_id) {
  bool result;
  if (!supervisor || !valid_slot(slot_id)) return true;
  pthread_mutex_lock(&supervisor->mutex);
  result = supervisor->slots[slot_id].stop_requested;
  pthread_mutex_unlock(&supervisor->mutex);
  return result;
}

void ipa_task_supervisor_wait_for_stop(ipa_task_supervisor_t *supervisor,
                                       ipa_task_slot_id_t slot_id) {
  if (!supervisor || !valid_slot(slot_id)) return;
  pthread_mutex_lock(&supervisor->mutex);
  while (supervisor->slots[slot_id].running &&
         !supervisor->slots[slot_id].stop_requested)
    pthread_cond_wait(&supervisor->stop_condition, &supervisor->mutex);
  pthread_mutex_unlock(&supervisor->mutex);
}

int ipa_task_supervisor_join_all(ipa_task_supervisor_t *supervisor) {
  size_t index;
  int first_error = 0;
  if (!supervisor) return EINVAL;
  for (index = 0; index < IPA_TASK_SUPERVISOR_SLOT_COUNT; ++index) {
    pthread_t thread;
    bool joinable;
    int result;
    pthread_mutex_lock(&supervisor->mutex);
    joinable = supervisor->slots[index].joinable;
    thread = supervisor->slots[index].thread;
    pthread_mutex_unlock(&supervisor->mutex);
    if (!joinable) continue;
    result = pthread_join(thread, NULL);
    if (result != 0 && first_error == 0) first_error = result;
    if (result == 0) {
      pthread_mutex_lock(&supervisor->mutex);
      supervisor->slots[index].joinable = false;
      supervisor->slots[index].worker = NULL;
      supervisor->slots[index].worker_context = NULL;
      pthread_mutex_unlock(&supervisor->mutex);
    }
  }
  return first_error;
}

void ipa_task_supervisor_destroy(ipa_task_supervisor_t *supervisor) {
  if (!supervisor) return;
  ipa_task_supervisor_request_stop(supervisor);
  ipa_task_supervisor_join_all(supervisor);
  pthread_cond_destroy(&supervisor->stop_condition);
  pthread_mutex_destroy(&supervisor->mutex);
  free(supervisor);
}

void ipa_task_supervisor_set_create_fn(ipa_task_supervisor_t *supervisor,
                                       ipa_task_supervisor_create_fn create_fn) {
  if (!supervisor) return;
  pthread_mutex_lock(&supervisor->mutex);
  supervisor->create_thread = create_fn ? create_fn : pthread_create;
  pthread_mutex_unlock(&supervisor->mutex);
}
