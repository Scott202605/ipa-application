#include "../../../include/ipa_core.h"
#include "ipa_config_snapshot.h"

#include <stdlib.h>
#include <string.h>

static void secure_zero(void *data, size_t size) {
  volatile unsigned char *cursor = data;
  while (size--) *cursor++ = 0;
}

static char *duplicate_string(const char *source) {
  size_t size;
  char *copy;
  if (!source) return NULL;
  size = strlen(source) + 1;
  copy = malloc(size);
  if (copy) memcpy(copy, source, size);
  return copy;
}

ErrCode ipa_core_config_snapshot_create(const cl_config_t *source,
                                        ipa_core_config_snapshot_t **out) {
  ipa_core_config_snapshot_t *snapshot;
  if (!source || !out || !source->driver_id) return eBadArg;
  *out = NULL;
  snapshot = calloc(1, sizeof(*snapshot));
  if (!snapshot) return eNoMem;
  snapshot->driver_id = duplicate_string(source->driver_id);
  if (!snapshot->driver_id) {
    free(snapshot);
    return eNoMem;
  }
  snapshot->driver_type = source->es10_driver_selected;
  snapshot->log_level = source->log_level;
  snapshot->initial_refresh_sleep = source->initial_refresh_sleep;
  snapshot->refresh_max_sleep = source->refresh_max_sleep;
  snapshot->esipa_sync_package_retrieval_time =
      source->esipa_sync_package_retrieval_time;
  *out = snapshot;
  return eOk;
}

void ipa_core_config_snapshot_destroy(ipa_core_config_snapshot_t *snapshot) {
  if (!snapshot) return;
  if (snapshot->driver_id) {
    secure_zero(snapshot->driver_id, strlen(snapshot->driver_id));
    free(snapshot->driver_id);
  }
  secure_zero(snapshot, sizeof(*snapshot));
  free(snapshot);
}

#define DEFINE_VALUE_SNAPSHOT(prefix, public_type, snapshot_type)              \
  ErrCode prefix##_create(const public_type *source, snapshot_type **out) {    \
    snapshot_type *snapshot;                                                   \
    if (!source || !out) return eBadArg;                                       \
    *out = NULL;                                                               \
    snapshot = malloc(sizeof(*snapshot));                                      \
    if (!snapshot) return eNoMem;                                              \
    memcpy(&snapshot->value, source, sizeof(*source));                         \
    *out = snapshot;                                                           \
    return eOk;                                                                \
  }                                                                            \
  void prefix##_destroy(snapshot_type *snapshot) {                             \
    if (!snapshot) return;                                                     \
    secure_zero(snapshot, sizeof(*snapshot));                                  \
    free(snapshot);                                                            \
  }

DEFINE_VALUE_SNAPSHOT(ipa_mqtt_config_snapshot, ipa_config_mqtt_t,
                      ipa_mqtt_config_snapshot_t)
DEFINE_VALUE_SNAPSHOT(ipa_lwm2m_config_snapshot, ipa_config_lwm2m_t,
                      ipa_lwm2m_config_snapshot_t)
DEFINE_VALUE_SNAPSHOT(ipa_http_config_snapshot, ipa_config_http_t,
                      ipa_http_config_snapshot_t)
