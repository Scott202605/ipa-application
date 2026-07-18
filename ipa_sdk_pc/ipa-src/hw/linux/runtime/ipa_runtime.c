#include "../../../../include/ipa_core.h"
#include "ipa_config_snapshot.h"
#include "ipa_runtime.h"

#include <errno.h>
#include <stdlib.h>

struct ipa_runtime {
  pthread_mutex_t mutex;
  ipa_runtime_state_t state;
  bool resources_ready;
  ipa_core_config_snapshot_t *config;
  ipa_task_supervisor_t *supervisor;
  ipa_task_supervisor_worker_fn init_worker;
};

static void *run_initialization(void *context) {
  ipa_runtime_t *runtime = context;
  ipa_task_supervisor_worker_fn worker;
  ipa_core_config_snapshot_t *config;
  pthread_mutex_lock(&runtime->mutex);
  worker = runtime->init_worker;
  config = runtime->config;
  pthread_mutex_unlock(&runtime->mutex);
  worker(config);
  pthread_mutex_lock(&runtime->mutex);
  if (runtime->state == IPA_RUNTIME_INITIALIZING)
    runtime->state = IPA_RUNTIME_UNINITIALIZED;
  pthread_mutex_unlock(&runtime->mutex);
  return NULL;
}

int ipa_runtime_create(ipa_runtime_t **out,
                       ipa_task_supervisor_notify_fn on_task_start,
                       ipa_task_supervisor_notify_fn on_task_end) {
  ipa_runtime_t *runtime;
  int result;
  if (!out) return EINVAL;
  *out = NULL;
  runtime = calloc(1, sizeof(*runtime));
  if (!runtime) return ENOMEM;
  if (pthread_mutex_init(&runtime->mutex, NULL) != 0) {
    free(runtime);
    return EAGAIN;
  }
  result = ipa_task_supervisor_init(&runtime->supervisor, on_task_start,
                                    on_task_end);
  if (result != 0) {
    pthread_mutex_destroy(&runtime->mutex);
    free(runtime);
    return result;
  }
  runtime->state = IPA_RUNTIME_UNINITIALIZED;
  *out = runtime;
  return 0;
}

int ipa_runtime_start(ipa_runtime_t *runtime, const cl_config_t *config,
                      ipa_task_supervisor_worker_fn init_worker) {
  ipa_core_config_snapshot_t *snapshot = NULL;
  int result;
  if (!runtime || !config || !init_worker) return EINVAL;
  pthread_mutex_lock(&runtime->mutex);
  if (runtime->state != IPA_RUNTIME_UNINITIALIZED) {
    pthread_mutex_unlock(&runtime->mutex);
    return 0;
  }
  if (runtime->config) {
    ipa_task_supervisor_join_all(runtime->supervisor);
    ipa_core_config_snapshot_destroy(runtime->config);
    runtime->config = NULL;
  }
  result = ipa_core_config_snapshot_create(config, &snapshot);
  if (result != eOk) {
    pthread_mutex_unlock(&runtime->mutex);
    return result == eNoMem ? ENOMEM : EINVAL;
  }
  runtime->config = snapshot;
  runtime->init_worker = init_worker;
  runtime->resources_ready = false;
  runtime->state = IPA_RUNTIME_INITIALIZING;
  result = ipa_task_supervisor_start(runtime->supervisor, IPA_TASK_SLOT_INIT,
                                     0, run_initialization, runtime);
  if (result != 0) {
    runtime->state = IPA_RUNTIME_UNINITIALIZED;
    runtime->config = NULL;
    runtime->init_worker = NULL;
    ipa_core_config_snapshot_destroy(snapshot);
  }
  pthread_mutex_unlock(&runtime->mutex);
  return result;
}

void ipa_runtime_complete_initialization(ipa_runtime_t *runtime, bool success) {
  if (!runtime) return;
  pthread_mutex_lock(&runtime->mutex);
  if (runtime->state == IPA_RUNTIME_INITIALIZING && success) {
    runtime->resources_ready = success;
    runtime->state = IPA_RUNTIME_READY;
  } else if (success) {
    runtime->resources_ready = true;
  }
  pthread_mutex_unlock(&runtime->mutex);
}

bool ipa_runtime_stop_requested(ipa_runtime_t *runtime) {
  if (!runtime) return true;
  return ipa_task_supervisor_should_stop(runtime->supervisor,
                                         IPA_TASK_SLOT_INIT);
}

bool ipa_runtime_stop(ipa_runtime_t *runtime) {
  bool resources_ready;
  ipa_core_config_snapshot_t *snapshot;
  if (!runtime) return false;
  pthread_mutex_lock(&runtime->mutex);
  if (runtime->state == IPA_RUNTIME_UNINITIALIZED && !runtime->config) {
    pthread_mutex_unlock(&runtime->mutex);
    return false;
  }
  runtime->state = IPA_RUNTIME_STOPPING;
  pthread_mutex_unlock(&runtime->mutex);

  ipa_task_supervisor_request_stop(runtime->supervisor);
  ipa_task_supervisor_join_all(runtime->supervisor);

  pthread_mutex_lock(&runtime->mutex);
  resources_ready = runtime->resources_ready;
  runtime->resources_ready = false;
  snapshot = runtime->config;
  runtime->config = NULL;
  runtime->init_worker = NULL;
  runtime->state = IPA_RUNTIME_UNINITIALIZED;
  pthread_mutex_unlock(&runtime->mutex);
  ipa_core_config_snapshot_destroy(snapshot);
  return resources_ready;
}

ipa_runtime_state_t ipa_runtime_state(ipa_runtime_t *runtime) {
  ipa_runtime_state_t state;
  if (!runtime) return IPA_RUNTIME_UNINITIALIZED;
  pthread_mutex_lock(&runtime->mutex);
  state = runtime->state;
  pthread_mutex_unlock(&runtime->mutex);
  return state;
}

void ipa_runtime_destroy(ipa_runtime_t *runtime) {
  if (!runtime) return;
  ipa_runtime_stop(runtime);
  ipa_task_supervisor_destroy(runtime->supervisor);
  pthread_mutex_destroy(&runtime->mutex);
  free(runtime);
}
