#include <assert.h>
#include <string.h>

#include "ipa_core.h"
#include "ipa_config_snapshot.h"

int main(void) {
  char driver_id[] = "/dev/ttyUSB0";
  cl_config_t core = {ES10_DRIVER_AT, driver_id, eLogInfo, 2, 30, 60};
  ipa_core_config_snapshot_t *core_copy = NULL;
  ipa_config_mqtt_t mqtt = {0};
  ipa_mqtt_config_snapshot_t *mqtt_copy = NULL;

  assert(ipa_core_config_snapshot_create(&core, &core_copy) == eOk);
  strcpy(driver_id, "/dev/ttyACM0");
  assert(strcmp(core_copy->driver_id, "/dev/ttyUSB0") == 0);
  assert(core_copy->refresh_max_sleep == 30);

  strcpy(mqtt.protocol, "mqtts");
  strcpy(mqtt.hostname, "broker.example");
  strcpy(mqtt.username, "device");
  strcpy(mqtt.password, "secret");
  assert(ipa_mqtt_config_snapshot_create(&mqtt, &mqtt_copy) == eOk);
  memset(&mqtt, 0, sizeof(mqtt));
  assert(strcmp(mqtt_copy->value.hostname, "broker.example") == 0);
  assert(strcmp(mqtt_copy->value.password, "secret") == 0);

  ipa_mqtt_config_snapshot_destroy(mqtt_copy);
  ipa_core_config_snapshot_destroy(core_copy);
  assert(ipa_core_config_snapshot_create(NULL, &core_copy) == eBadArg);
  ipa_core_config_snapshot_destroy(NULL);
  return 0;
}
