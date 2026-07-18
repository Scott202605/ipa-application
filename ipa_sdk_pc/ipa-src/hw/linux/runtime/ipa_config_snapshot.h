#ifndef IPA_CONFIG_SNAPSHOT_H
#define IPA_CONFIG_SNAPSHOT_H

typedef struct {
  es10_driver_type_t driver_type;
  char *driver_id;
  enum LogLevel log_level;
  int initial_refresh_sleep;
  int refresh_max_sleep;
  int esipa_sync_package_retrieval_time;
} ipa_core_config_snapshot_t;

typedef struct { ipa_config_mqtt_t value; } ipa_mqtt_config_snapshot_t;
typedef struct { ipa_config_lwm2m_t value; } ipa_lwm2m_config_snapshot_t;
typedef struct { ipa_config_http_t value; } ipa_http_config_snapshot_t;

ErrCode ipa_core_config_snapshot_create(const cl_config_t *source,
                                        ipa_core_config_snapshot_t **out);
void ipa_core_config_snapshot_destroy(ipa_core_config_snapshot_t *snapshot);
ErrCode ipa_mqtt_config_snapshot_create(const ipa_config_mqtt_t *source,
                                        ipa_mqtt_config_snapshot_t **out);
void ipa_mqtt_config_snapshot_destroy(ipa_mqtt_config_snapshot_t *snapshot);
ErrCode ipa_lwm2m_config_snapshot_create(const ipa_config_lwm2m_t *source,
                                         ipa_lwm2m_config_snapshot_t **out);
void ipa_lwm2m_config_snapshot_destroy(ipa_lwm2m_config_snapshot_t *snapshot);
ErrCode ipa_http_config_snapshot_create(const ipa_config_http_t *source,
                                        ipa_http_config_snapshot_t **out);
void ipa_http_config_snapshot_destroy(ipa_http_config_snapshot_t *snapshot);

#endif
