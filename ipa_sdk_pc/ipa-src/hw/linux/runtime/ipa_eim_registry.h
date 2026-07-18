#ifndef IPA_EIM_REGISTRY_H
#define IPA_EIM_REGISTRY_H

#include <pthread.h>

typedef enum {
  IPA_EIM_SLOT_MQTT = 0,
  IPA_EIM_SLOT_LWM2M,
  IPA_EIM_SLOT_HTTP,
  IPA_EIM_SLOT_COUNT
} ipa_eim_slot_id_t;

typedef struct ipa_eim_registry ipa_eim_registry_t;
typedef void *(*ipa_eim_worker_fn)(void *context);
typedef void (*ipa_eim_cleanup_fn)(void *context);
typedef void (*ipa_eim_disconnect_fn)(void *protocol_object);

int ipa_eim_registry_create(ipa_eim_registry_t **out);
int ipa_eim_registry_start(ipa_eim_registry_t *registry,
                           ipa_eim_slot_id_t slot,
                           ipa_eim_worker_fn worker, void *worker_context,
                           ipa_eim_cleanup_fn cleanup);
void ipa_eim_registry_publish(ipa_eim_registry_t *registry,
                              ipa_eim_slot_id_t slot, void *protocol_object);
void ipa_eim_registry_clear(ipa_eim_registry_t *registry,
                            ipa_eim_slot_id_t slot, void *protocol_object);
void ipa_eim_registry_stop(ipa_eim_registry_t *registry,
                           ipa_eim_slot_id_t slot,
                           ipa_eim_disconnect_fn disconnect);
void ipa_eim_registry_stop_all(ipa_eim_registry_t *registry,
                               const ipa_eim_disconnect_fn disconnectors[]);
void ipa_eim_registry_destroy(ipa_eim_registry_t *registry,
                              const ipa_eim_disconnect_fn disconnectors[]);

#endif
