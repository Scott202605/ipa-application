#ifndef IPA_CORE_INTERNAL_H
#define IPA_CORE_INTERNAL_H

#define IPA_PUBLIC __attribute__((visibility("default")))

#include "es10.h"
#include "es9.h"
#include "linux_typedefs.h"
#include "log.h"
#include "mqtt_client.h"
#include "typedefs.h"

typedef enum {
  IPA_STATE_UNINITIALIZED,
  IPA_STATE_INITIALIZING,
  IPA_STATE_WAITING_FOR_PROVISIONING,
  IPA_STATE_INITIALIZED,
} ipa_state_t;

typedef enum {
  IPA_EVENT_PROVISIONING_NEEDED,
  IPA_EVENT_INITIALIZATION_SUCCESS,
  IPA_EVENT_INITIALIZATION_FAILED,
  IPA_EVENT_SERVICE_CONNECT_SUCCESS,
} ipa_event_type_t;

typedef enum es10_driver_type_e {
  ES10_DRIVER_AT,
  ES10_DRIVER_NONE
} es10_driver_type_t;

typedef struct cl_config_s {
  es10_driver_type_t es10_driver_selected;
  char *driver_id;
  enum LogLevel log_level;
  int initial_refresh_sleep;
  int refresh_max_sleep;
  int esipa_sync_package_retrieval_time;
} cl_config_t;

typedef struct ipa_config_mqtt_s {
  char protocol[6];
  char hostname[100];
  int port;
  char username[20];
  char password[20];
  mqtt_tls_config_t tls_config;
  mqtt_proxy_config_t proxy_config;
} ipa_config_mqtt_t;

typedef struct ipa_config_lwm2m_s {
  char hostname[100];
  int port;
  bool dtls;
  bool bootstrap;
  bool ipv4;
  char client_name[33];
} ipa_config_lwm2m_t;

typedef struct ipa_config_http_s {
  char fqdn[100];
  uint32_t max_time_without_transmission;
  uint32_t http_timeout;
  uint32_t sync_sleep_time;
} ipa_config_http_t;

extern es10_t g_es10;
extern es9_t g_es9;
extern ipa_state_t g_ipa_state;

void notify_task_start(uint32_t task_id);
void notify_task_end(uint32_t task_id);
typedef void (*ipa_task_start_cb_t)(uint32_t task_id);
typedef void (*ipa_task_end_cb_t)(uint32_t task_id);
typedef struct {
  ipa_task_start_cb_t task_start_cb;
  ipa_task_end_cb_t task_end_cb;
} ipa_task_callbacks_t;

IPA_PUBLIC void
ipa_register_task_callbacks(const ipa_task_callbacks_t *callbacks);

typedef void (*ipa_event_cb_t)(ipa_event_type_t event_type, void *event_data);

IPA_PUBLIC int ipa_init_library(cl_config_t *config, ipa_event_cb_t event_cb);
void notify_app(ipa_event_type_t event_type, void *event_data);
IPA_PUBLIC ErrCode connect_mqtt_service(const ipa_config_mqtt_t *config);
IPA_PUBLIC ErrCode connect_lwm2m_service(const ipa_config_lwm2m_t *config);
IPA_PUBLIC ErrCode connect_http_service(const ipa_config_http_t *config);
IPA_PUBLIC void stop_eim_service(void);
IPA_PUBLIC void ipa_deinit_library(void);

#endif
