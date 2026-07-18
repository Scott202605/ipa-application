#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>

#include "ipa_eim_registry.h"

typedef struct {
  ipa_eim_registry_t *registry;
  ipa_eim_slot_id_t slot;
  atomic_int published;
  atomic_int disconnected;
} fake_session_t;

static void disconnect_fake(void *object) {
  fake_session_t *session = object;
  atomic_store(&session->disconnected, 1);
}

static void *run_fake(void *opaque) {
  fake_session_t *session = opaque;
  ipa_eim_registry_publish(session->registry, session->slot, session);
  atomic_store(&session->published, 1);
  while (!atomic_load(&session->disconnected)) sched_yield();
  ipa_eim_registry_clear(session->registry, session->slot, session);
  return NULL;
}

int main(void) {
  ipa_eim_registry_t *registry = NULL;
  fake_session_t mqtt;
  fake_session_t lwm2m;
  const ipa_eim_disconnect_fn disconnectors[IPA_EIM_SLOT_COUNT] = {
      disconnect_fake, disconnect_fake, disconnect_fake};
  assert(ipa_eim_registry_create(&registry) == 0);
  mqtt = (fake_session_t){.registry = registry, .slot = IPA_EIM_SLOT_MQTT};
  lwm2m = (fake_session_t){.registry = registry, .slot = IPA_EIM_SLOT_LWM2M};
  assert(ipa_eim_registry_start(registry, mqtt.slot, run_fake, &mqtt, NULL) == 0);
  assert(ipa_eim_registry_start(registry, mqtt.slot, run_fake, &mqtt, NULL) == EBUSY);
  assert(ipa_eim_registry_start(registry, lwm2m.slot, run_fake, &lwm2m, NULL) == 0);
  while (!atomic_load(&mqtt.published) || !atomic_load(&lwm2m.published))
    sched_yield();
  ipa_eim_registry_stop(registry, mqtt.slot, disconnect_fake);
  assert(atomic_load(&mqtt.disconnected) == 1);
  assert(atomic_load(&lwm2m.disconnected) == 0);
  ipa_eim_registry_stop(registry, mqtt.slot, disconnect_fake);
  ipa_eim_registry_stop_all(registry, disconnectors);
  assert(atomic_load(&lwm2m.disconnected) == 1);
  ipa_eim_registry_destroy(registry, disconnectors);
  return 0;
}
