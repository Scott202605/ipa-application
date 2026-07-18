#include "ipa_eim_registry.h"

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>

typedef struct {
  pthread_t thread;
  bool joinable;
  bool running;
  bool stop_requested;
  void *protocol_object;
  ipa_eim_worker_fn worker;
  void *worker_context;
  ipa_eim_cleanup_fn cleanup;
  ipa_eim_disconnect_fn disconnect;
  struct ipa_eim_registry *owner;
  ipa_eim_slot_id_t id;
} ipa_eim_slot_t;

struct ipa_eim_registry {
  pthread_mutex_t mutex;
  ipa_eim_slot_t slots[IPA_EIM_SLOT_COUNT];
};

static bool valid_slot(ipa_eim_slot_id_t slot) {
  return slot >= IPA_EIM_SLOT_MQTT && slot < IPA_EIM_SLOT_COUNT;
}

static void *run_slot(void *opaque) {
  ipa_eim_slot_t *slot = opaque;
  ipa_eim_registry_t *registry = slot->owner;
  ipa_eim_worker_fn worker;
  ipa_eim_cleanup_fn cleanup;
  void *context;
  pthread_mutex_lock(&registry->mutex);
  worker = slot->worker;
  cleanup = slot->cleanup;
  context = slot->worker_context;
  pthread_mutex_unlock(&registry->mutex);
  worker(context);
  if (cleanup) cleanup(context);
  pthread_mutex_lock(&registry->mutex);
  slot->running = false;
  slot->protocol_object = NULL;
  slot->worker_context = NULL;
  pthread_mutex_unlock(&registry->mutex);
  return NULL;
}

int ipa_eim_registry_create(ipa_eim_registry_t **out) {
  ipa_eim_registry_t *registry;
  int index;
  if (!out) return EINVAL;
  *out = NULL;
  registry = calloc(1, sizeof(*registry));
  if (!registry) return ENOMEM;
  if (pthread_mutex_init(&registry->mutex, NULL) != 0) {
    free(registry);
    return EAGAIN;
  }
  for (index = 0; index < IPA_EIM_SLOT_COUNT; ++index) {
    registry->slots[index].owner = registry;
    registry->slots[index].id = (ipa_eim_slot_id_t)index;
  }
  *out = registry;
  return 0;
}

int ipa_eim_registry_start(ipa_eim_registry_t *registry,
                           ipa_eim_slot_id_t slot_id,
                           ipa_eim_worker_fn worker, void *worker_context,
                           ipa_eim_cleanup_fn cleanup) {
  ipa_eim_slot_t *slot;
  int result;
  if (!registry || !valid_slot(slot_id) || !worker) return EINVAL;
  pthread_mutex_lock(&registry->mutex);
  slot = &registry->slots[slot_id];
  if (slot->joinable) {
    if (!slot->running) {
      pthread_join(slot->thread, NULL);
      slot->joinable = false;
    } else {
      pthread_mutex_unlock(&registry->mutex);
      return EBUSY;
    }
  }
  slot->running = true;
  slot->stop_requested = false;
  slot->worker = worker;
  slot->worker_context = worker_context;
  slot->cleanup = cleanup;
  result = pthread_create(&slot->thread, NULL, run_slot, slot);
  if (result == 0) {
    slot->joinable = true;
  } else {
    slot->running = false;
    slot->worker = NULL;
    slot->worker_context = NULL;
    slot->cleanup = NULL;
  }
  pthread_mutex_unlock(&registry->mutex);
  return result;
}

void ipa_eim_registry_publish(ipa_eim_registry_t *registry,
                              ipa_eim_slot_id_t slot, void *protocol_object) {
  bool stop_requested = false;
  ipa_eim_disconnect_fn disconnect = NULL;
  if (!registry || !valid_slot(slot)) return;
  pthread_mutex_lock(&registry->mutex);
  if (registry->slots[slot].running) {
    registry->slots[slot].protocol_object = protocol_object;
    stop_requested = registry->slots[slot].stop_requested;
    disconnect = registry->slots[slot].disconnect;
  }
  pthread_mutex_unlock(&registry->mutex);
  if (stop_requested && protocol_object && disconnect)
    disconnect(protocol_object);
}

void ipa_eim_registry_clear(ipa_eim_registry_t *registry,
                            ipa_eim_slot_id_t slot, void *protocol_object) {
  if (!registry || !valid_slot(slot)) return;
  pthread_mutex_lock(&registry->mutex);
  if (registry->slots[slot].protocol_object == protocol_object)
    registry->slots[slot].protocol_object = NULL;
  pthread_mutex_unlock(&registry->mutex);
}

void ipa_eim_registry_stop(ipa_eim_registry_t *registry,
                           ipa_eim_slot_id_t slot_id,
                           ipa_eim_disconnect_fn disconnect) {
  ipa_eim_slot_t *slot;
  void *object;
  pthread_t thread;
  bool joinable;
  if (!registry || !valid_slot(slot_id)) return;
  pthread_mutex_lock(&registry->mutex);
  slot = &registry->slots[slot_id];
  slot->stop_requested = true;
  slot->disconnect = disconnect;
  object = slot->protocol_object;
  thread = slot->thread;
  joinable = slot->joinable;
  pthread_mutex_unlock(&registry->mutex);
  if (object && disconnect) disconnect(object);
  if (joinable) pthread_join(thread, NULL);
  pthread_mutex_lock(&registry->mutex);
  slot->joinable = false;
  slot->running = false;
  slot->protocol_object = NULL;
  slot->worker = NULL;
  slot->cleanup = NULL;
  slot->disconnect = NULL;
  slot->stop_requested = false;
  pthread_mutex_unlock(&registry->mutex);
}

void ipa_eim_registry_stop_all(ipa_eim_registry_t *registry,
                               const ipa_eim_disconnect_fn disconnectors[]) {
  int index;
  if (!registry) return;
  for (index = 0; index < IPA_EIM_SLOT_COUNT; ++index)
    ipa_eim_registry_stop(registry, (ipa_eim_slot_id_t)index,
                          disconnectors ? disconnectors[index] : NULL);
}

void ipa_eim_registry_destroy(ipa_eim_registry_t *registry,
                              const ipa_eim_disconnect_fn disconnectors[]) {
  if (!registry) return;
  ipa_eim_registry_stop_all(registry, disconnectors);
  pthread_mutex_destroy(&registry->mutex);
  free(registry);
}
