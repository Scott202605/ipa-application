#ifndef IPA_TASK_SUPERVISOR_H
#define IPA_TASK_SUPERVISOR_H

#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

#define IPA_TASK_SUPERVISOR_SLOT_COUNT 4

typedef enum {
  IPA_TASK_SLOT_INIT = 0,
  IPA_TASK_SLOT_MQTT,
  IPA_TASK_SLOT_LWM2M,
  IPA_TASK_SLOT_HTTP
} ipa_task_slot_id_t;

typedef void (*ipa_task_supervisor_notify_fn)(uint32_t task_id);
typedef void *(*ipa_task_supervisor_worker_fn)(void *context);
typedef int (*ipa_task_supervisor_create_fn)(pthread_t *, const pthread_attr_t *,
                                             void *(*)(void *), void *);

typedef struct ipa_task_supervisor ipa_task_supervisor_t;

int ipa_task_supervisor_init(ipa_task_supervisor_t **out,
                             ipa_task_supervisor_notify_fn on_start,
                             ipa_task_supervisor_notify_fn on_end);
int ipa_task_supervisor_start(ipa_task_supervisor_t *supervisor,
                              ipa_task_slot_id_t slot, uint32_t task_id,
                              ipa_task_supervisor_worker_fn worker,
                              void *worker_context);
void ipa_task_supervisor_request_stop(ipa_task_supervisor_t *supervisor);
bool ipa_task_supervisor_should_stop(ipa_task_supervisor_t *supervisor,
                                     ipa_task_slot_id_t slot);
void ipa_task_supervisor_wait_for_stop(ipa_task_supervisor_t *supervisor,
                                       ipa_task_slot_id_t slot);
int ipa_task_supervisor_join_all(ipa_task_supervisor_t *supervisor);
void ipa_task_supervisor_destroy(ipa_task_supervisor_t *supervisor);

/* Private test seam; NULL restores pthread_create. */
void ipa_task_supervisor_set_create_fn(ipa_task_supervisor_t *supervisor,
                                       ipa_task_supervisor_create_fn create_fn);

#endif
