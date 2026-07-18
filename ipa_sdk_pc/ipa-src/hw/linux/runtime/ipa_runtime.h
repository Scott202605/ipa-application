#ifndef IPA_RUNTIME_H
#define IPA_RUNTIME_H

#include <stdbool.h>
#include "ipa_task_supervisor.h"

typedef enum {
  IPA_RUNTIME_UNINITIALIZED,
  IPA_RUNTIME_INITIALIZING,
  IPA_RUNTIME_READY,
  IPA_RUNTIME_STOPPING
} ipa_runtime_state_t;

typedef struct ipa_runtime ipa_runtime_t;

int ipa_runtime_create(ipa_runtime_t **out,
                       ipa_task_supervisor_notify_fn on_task_start,
                       ipa_task_supervisor_notify_fn on_task_end);
int ipa_runtime_start(ipa_runtime_t *runtime, const cl_config_t *config,
                      ipa_task_supervisor_worker_fn init_worker);
void ipa_runtime_complete_initialization(ipa_runtime_t *runtime, bool success);
bool ipa_runtime_stop_requested(ipa_runtime_t *runtime);
bool ipa_runtime_stop(ipa_runtime_t *runtime);
ipa_runtime_state_t ipa_runtime_state(ipa_runtime_t *runtime);
void ipa_runtime_destroy(ipa_runtime_t *runtime);

#endif
