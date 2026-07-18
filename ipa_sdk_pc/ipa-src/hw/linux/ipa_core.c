/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include "esipa.h"
#include "ipa.h"
#include "log.h"
#include "smartcard_at_external.h"
#include "typedefs.h"
#include <pthread.h>
#include <unistd.h>

#ifndef IPA_FEATURE_INDIRECT_DOWNLOAD

#endif
#ifdef ENABLE_MQTT

#include "esipa_mqtt.h"

#endif
#ifdef ENABLE_LWM2M

#include "esipa_lwm2m.h"

#endif
#ifdef ENABLE_HTTP_ESIPA

#include "esipa_http.h"

#endif

#include "ipa_core.h"
#include "runtime/ipa_config_snapshot.h"
#include "runtime/ipa_eim_registry.h"
#include "runtime/ipa_runtime.h"

#define BAUD_RATE 115200
#define DEFAULT_LOG_LEVEL eLogInfo
#define CONFIG_FILE_PATH "config.json"
#define CONFIG_FILE_MAX_SIZE 8192
#define PEM_FILE_EXTENSION ".pem"
#ifdef ENABLE_HTTP_ESIPA
#define PACKAGE_RETRIEVAL_TIME_DEF 60
#define PACKAGE_RETRIEVAL_TIME_MIN 60
#endif

#define STDIN_EVENT_TIMEOUT 60 // In seconds
#define INPUT_KEYBOARD_BUFFER_SIZE 64
#define STDIN_QUIT_EVENT_1 "Q\n"
#define STDIN_QUIT_EVENT_2 "q\n"
#if defined(SGP32) && defined(EXTRA_FEATURE_FALLBACK_MECHANISM)
#define STDIN_FALLBACK_ENABLE_EVENT "fe\n"
#define STDIN_FALLBACK_DISABLE_EVENT "fd\n"
#endif
#if defined(SGP32) && defined(EXTRA_FEATURE_EMERGENCY_PROFILE_MANAGMENT)
#define STDIN_ENABLE_EMERGENCY_PROFILE_EVENT "ee\n"
#define STDIN_DISABLE_EMERGENCY_PROFILE_EVENT "ed\n"
#endif
#if defined(SGP32) && defined(TEST_FEATURE_PROFILE_ROLLBACK)
#define STDIN_PROFILE_ROLLBACK_EVENT "r\n"
#endif

/* Command line options */
#define AT_DRIVER_OPTION "-at"
#define LOG_LEVEL_OPTION "-d"
#define INITIAL_REFRESH_SLEEP_OPTION "-refresh-initial-sleep"
#define MAX_REFRESH_SLEEP_OPTION "-refresh-max-sleep"
#define FILE_PATH_OPTION "-f"
#ifdef ENABLE_HTTP_ESIPA
#define PACKAGE_RETRIEVAL_TIME "-package-retrieval-time"
#endif

#define COMMAND_EUICC_MEMORY_RESET "euicc-memory-reset"
#define COMMAND_SET_DEFAULT_DP_ADDRESS "set-default-dp-address"
#ifndef IPA_FEATURE_INDIRECT_DOWNLOAD
#define COMMAND_NOTIFICATIONS_DELIVERY "notifications-delivery"
#endif
#ifdef SGP32
#define COMMAND_CONFIGURE_IMMEDIATE_PROFILE_ENABLING                           \
  "configure-immediate-profile-enabling"
#define COMMAND_ADD_INITIAL_EIM "add-initial-eim"
#endif
#ifdef ENABLE_MQTT
#define MQTT_JSON_KEY "\"mqtt\""
#define PROTOCOL_MQTT_JSON_KEY "\"protocol\""
#define ADDRESS_MQTT_JSON_KEY "\"address\""
#define PORT_MQTT_JSON_KEY "\"port\""
#define USERNAME_MQTT_JSON_KEY "\"username\""
#define PASSWORD_MQTT_JSON_KEY "\"password\""
#define SERVER_CERTIFICATE_MQTT_JSON_KEY "\"server_trust_certificate\""
#define CLIENT_CERTIFICATE_MQTT_JSON_KEY "\"client_certificate\""
#define PRIVATE_KEY_MQTT_JSON_KEY "\"private_key\""
#define PROXY_URL_MQTT_JSON_KEY "\"proxy_url\""
#endif
#ifdef ENABLE_LWM2M
#define LWM2M_JSON_KEY "\"lwm2m\""
#define ADDRESS_LWM2M_JSON_KEY "\"address\""
#define PORT_LWM2M_JSON_KEY "\"port\""
#define DTLS_LWM2M_JSON_KEY "\"dtls\""
#define BOOTSTRAP_LWM2M_JSON_KEY "\"bootstrap\""
#define IPV4_LWM2M_JSON_KEY "\"ipv4\""
#define CLIENT_NAME_LWM2M_JSON_KEY "\"client_name\""
#endif
#ifdef ENABLE_HTTP_ESIPA
#define HTTP_JSON_KEY "\"http\""
#define FQDN_HTTP_JSON_KEY "\"fqdn\""
#endif

#define EUICC_MEMORY_RESET_KEY "eUICCMemoryReset"
#define SET_DEFAULT_DP_ADDRESS_KEY "setDefaultDpAddress"
#ifdef SGP32
#define CONFIGURE_IMMEDIATE_PROFILE_ENABLING_KEY                               \
  "configureImmediateProfileEnabling"
#define ADD_INITIAL_EIM_KEY "addInitialEim"
#endif

#if defined(ENABLE_MQTT) || defined(ENABLE_LWM2M) || defined(ENABLE_HTTP_ESIPA)
typedef struct ipa_configs_presence_s {
#ifdef ENABLE_MQTT
  bool mqtt_config;
#endif
#ifdef ENABLE_LWM2M
  bool lwm2m_config;
#endif
#ifdef ENABLE_HTTP_ESIPA
  bool http_config;
#endif
} ipa_configs_presence_t;

typedef struct ipa_config_s {
#ifdef ENABLE_MQTT
  ipa_config_mqtt_t mqtt_config;
#endif
#ifdef ENABLE_LWM2M
  ipa_config_lwm2m_t lwm2m_config;
#endif
#ifdef ENABLE_HTTP_ESIPA
  ipa_config_http_t http_config;
#endif
  ipa_configs_presence_t config_is_present;
} ipa_config_t;
#endif

typedef union es10_driver_u {
  smartcard_at_external_t at_external_driver;
} es10_driver_t;

#ifdef ENABLE_MQTT

static void *connect_esipa_mqtt(void *ipa_config);
#endif
#ifdef ENABLE_LWM2M
static void *connect_esipa_lwm2m(void *ipa_config);
#endif
#ifdef ENABLE_HTTP_ESIPA
static void *connect_esipa_http(void *ipa_config);

#endif
ipa_state_t g_ipa_state = IPA_STATE_UNINITIALIZED;
static ipa_event_cb_t g_event_cb = NULL;
static ipa_task_callbacks_t g_task_callbacks = {0};
static ipa_runtime_t *g_runtime = NULL;
static pthread_once_t g_runtime_once = PTHREAD_ONCE_INIT;
static ipa_eim_registry_t *g_eim_registry = NULL;
static pthread_once_t g_eim_registry_once = PTHREAD_ONCE_INIT;
static int ipa_continue_initialization_internal(void);
static void *ipa_init_thread_func(void *arg);
static void initialize_runtime(void);
static void initialize_eim_registry(void);

void ipa_register_task_callbacks(const ipa_task_callbacks_t *callbacks) {
  if (callbacks) {
    g_task_callbacks = *callbacks;
  }
}

void notify_task_start(uint32_t task_id) {
  if (g_task_callbacks.task_start_cb) {
    g_task_callbacks.task_start_cb(task_id);
  }
}

void notify_task_end(uint32_t task_id) {
  if (g_task_callbacks.task_end_cb) {
    g_task_callbacks.task_end_cb(task_id);
  }
}

static void initialize_runtime(void) {
  if (ipa_runtime_create(&g_runtime, notify_task_start, notify_task_end) != 0)
    g_runtime = NULL;
}

static void initialize_eim_registry(void) {
  if (ipa_eim_registry_create(&g_eim_registry) != 0)
    g_eim_registry = NULL;
}

static bool fixed_string_terminated(const char *value, size_t capacity) {
  return value && memchr(value, '\0', capacity) != NULL;
}

void notify_app(ipa_event_type_t event_type, void *event_data) {
  if (g_event_cb != NULL) {
    g_event_cb(event_type, event_data);
  }
}

es9_t g_es9;
es10_t g_es10;
static es11_t g_es11;
static es10_driver_t g_es10_driver;
static es10_driver_type_t es10_driver_selected = ES10_DRIVER_NONE;

static void *ipa_init_thread_func(void *arg) {
  ipa_core_config_snapshot_t *config = (ipa_core_config_snapshot_t *)arg;
  int err = -1;
  if (config->log_level < eLogErr || config->log_level > eLogTrace) {
    goto error_exit;
  }
  LOG_INIT(config->log_level);
  es9__ctor(&g_es9);
  es11__ctor(&g_es11);
  es10_driver_selected = config->driver_type;
  switch (config->driver_type) {
  case ES10_DRIVER_AT:
    if ((err = smartcard_at_external__ctor(&g_es10_driver.at_external_driver,
                                           config->driver_id, BAUD_RATE)) < 0) {
      LOGE("Failed to construct AT driver, err %d", err);
      goto error_exit;
    }
    break;

  default:
    LOGE("Unsupported driver type selected.");
    goto error_exit;
  }

  if ((err = es10__ctor(&g_es10, (smartcard_t *)&g_es10_driver)) < 0) {
    LOGE("Failed to construct ES10, err %d", err);
    goto destroy_driver;
  }
  if (config->initial_refresh_sleep) {
    es10__set_initial_refresh_sleep(&g_es10, config->initial_refresh_sleep);
    LOGI("[ipa_init_library] Set ES10 initial refresh sleep to: %u seconds.",
         config->initial_refresh_sleep);
  }
  if (config->refresh_max_sleep) {
    es10__set_max_refresh_sleep(&g_es10, config->refresh_max_sleep);
    LOGI("[ipa_init_library] Set ES10 max refresh sleep to: %u seconds.",
         config->refresh_max_sleep);
  }

  if (ipa_continue_initialization_internal() != 0) {
    goto destroy_es10;
  }

  return NULL;
destroy_es10:
  es10__deinit(&g_es10);
  es10__destroy(&g_es10);
destroy_driver:
  LOGI("[ipa_init_thread] Cleaning up driver due to initialization failure...");
  switch (config->driver_type) {
  case ES10_DRIVER_AT:
    smartcard_at_external__destory(&g_es10_driver.at_external_driver);
    break;
  default:
    break;
  }
  es10_driver_selected = ES10_DRIVER_NONE;

error_exit:
  ipa_runtime_complete_initialization(g_runtime, false);
  g_ipa_state = IPA_STATE_UNINITIALIZED;
  notify_app(IPA_EVENT_INITIALIZATION_FAILED, &err);
  return NULL;
}

int ipa_init_library(cl_config_t *config, ipa_event_cb_t event_cb) {
  int result;
  if (!config) return -1;
  pthread_once(&g_runtime_once, initialize_runtime);
  if (!g_runtime) return -1;
  if (ipa_runtime_state(g_runtime) != IPA_RUNTIME_UNINITIALIZED) {
    LOGW("IPA library already initialized or in progress. Current state: %d",
         g_ipa_state);
    return 0;
  }
  g_event_cb = event_cb;
  result = ipa_runtime_start(g_runtime, config, ipa_init_thread_func);
  if (result != 0) {
    LOGE("Failed to create IPA initialization thread.");
    g_ipa_state = IPA_STATE_UNINITIALIZED;
    g_event_cb = NULL;
    return -1;
  }
  g_ipa_state = IPA_STATE_INITIALIZING;
  return 0;
}

static int ipa_continue_initialization_internal(void) {
  int err;
  LOGI("[ipa_continue] eIM provisioned. Continuing initialization...");
  if ((err = ipa__init(&g_es9, &g_es10, &g_es11)) != 0) {
    LOGE("[ipa_continue] Error on init the IPA, rc %d", err);
    g_ipa_state = IPA_STATE_UNINITIALIZED;
    return err;
  }
  ipa_runtime_complete_initialization(g_runtime, true);
  g_ipa_state = IPA_STATE_INITIALIZED;
  LOGI("[ipa_continue] IPA library initialized successfully.");
  err = 0;
  notify_app(IPA_EVENT_INITIALIZATION_SUCCESS, &err);
  return err;
}

void ipa_deinit_library() {
  bool resources_ready;
  LOGI("De-initializing IPA library...\n");
  pthread_once(&g_runtime_once, initialize_runtime);
  if (!g_runtime) return;
  resources_ready = ipa_runtime_stop(g_runtime);
  if (!resources_ready) {
    LOGI("Warning: IPA library was not initialized or already "
         "de-initialized.\n");
    g_ipa_state = IPA_STATE_UNINITIALIZED;
    g_event_cb = NULL;
    return;
  }
  if (!ipa__get_ipa_exit()) {
    ipa__set_ipa_exit();
  }

  ipa__deinit();
  es10__destroy(&g_es10);

  switch (es10_driver_selected) {
  case ES10_DRIVER_AT:
    smartcard_at_external__destory(&g_es10_driver.at_external_driver);
    break;
  default:
    break;
  }
  es10_driver_selected = ES10_DRIVER_NONE;
  memset(&g_es10_driver, 0, sizeof(g_es10_driver));
  memset(&g_es10, 0, sizeof(g_es10));
  g_ipa_state = IPA_STATE_UNINITIALIZED;
  g_event_cb = NULL;
  LOGI("IPA library de-initialized.\n");
}

#ifdef ENABLE_MQTT

/* Extern declaration since it is not in the header explicitly included here */
ErrCode esipa_async__disconnect(esipa_async_t *const me);

static void disconnect_async_object(void *object) {
  esipa_async__disconnect((esipa_async_t *)object);
}

static void destroy_mqtt_snapshot(void *snapshot) {
  ipa_mqtt_config_snapshot_destroy(snapshot);
}

static void disconnect_mqtt_service() {
  if (!g_eim_registry) return;
  LOGI("[disconnect_mqtt_service] Stopping MQTT service...");
  ipa_eim_registry_stop(g_eim_registry, IPA_EIM_SLOT_MQTT,
                        disconnect_async_object);
}

ErrCode connect_mqtt_service(const ipa_config_mqtt_t *config) {
  ipa_mqtt_config_snapshot_t *snapshot = NULL;
  int err;
  if (!config || !fixed_string_terminated(config->protocol,
                                           sizeof(config->protocol)) ||
      !fixed_string_terminated(config->hostname,
                               sizeof(config->hostname)) ||
      !fixed_string_terminated(config->username,
                               sizeof(config->username)) ||
      !fixed_string_terminated(config->password,
                               sizeof(config->password)) ||
      !fixed_string_terminated(config->tls_config.server_cert_absolute_pem_path,
                               sizeof(config->tls_config.server_cert_absolute_pem_path)) ||
      !fixed_string_terminated(config->tls_config.client_cert_absolute_pem_path,
                               sizeof(config->tls_config.client_cert_absolute_pem_path)) ||
      !fixed_string_terminated(config->tls_config.private_key_absolute_pem_path,
                               sizeof(config->tls_config.private_key_absolute_pem_path)) ||
      !fixed_string_terminated(config->proxy_config.url,
                               sizeof(config->proxy_config.url)) ||
      config->port < 1 || config->port > 65535)
    return eBadArg;
  pthread_once(&g_eim_registry_once, initialize_eim_registry);
  if (!g_eim_registry) return eFatal;
  if (ipa_mqtt_config_snapshot_create(config, &snapshot) != eOk) return eFatal;
  LOGI("[start_mqtt_service] Starting MQTT service thread...");
  if (0 != (err = ipa_eim_registry_start(
                    g_eim_registry, IPA_EIM_SLOT_MQTT, connect_esipa_mqtt,
                    snapshot, destroy_mqtt_snapshot))) {
    ipa_mqtt_config_snapshot_destroy(snapshot);
    LOGE("[start_mqtt_service] Error creating the MQTT ESipa thread, err %d",
         err);
    return eFatal;
  }
  LOGI("[start_mqtt_service] MQTT service thread started successfully.");
  return eOk;
}

#endif

#ifdef ENABLE_LWM2M

static void destroy_lwm2m_snapshot(void *snapshot) {
  ipa_lwm2m_config_snapshot_destroy(snapshot);
}

static void disconnect_lwm2m_service() {
  if (!g_eim_registry) return;
  LOGI("[disconnect_lwm2m_service] Stopping LwM2M service...");
  ipa_eim_registry_stop(g_eim_registry, IPA_EIM_SLOT_LWM2M,
                        disconnect_async_object);
}

ErrCode connect_lwm2m_service(const ipa_config_lwm2m_t *config) {
  ipa_lwm2m_config_snapshot_t *snapshot = NULL;
  int err;
  if (!config || !fixed_string_terminated(config->hostname,
                                           sizeof(config->hostname)) ||
      !fixed_string_terminated(config->client_name,
                               sizeof(config->client_name)) ||
      config->port < 1 || config->port > 65535)
    return eBadArg;
  pthread_once(&g_eim_registry_once, initialize_eim_registry);
  if (!g_eim_registry) return eFatal;
  if (ipa_lwm2m_config_snapshot_create(config, &snapshot) != eOk) return eFatal;
  LOGI("[disconnect_lwm2m_service] Starting LwM2M service thread...");
  if (0 != (err = ipa_eim_registry_start(
                    g_eim_registry, IPA_EIM_SLOT_LWM2M, connect_esipa_lwm2m,
                    snapshot, destroy_lwm2m_snapshot))) {
    ipa_lwm2m_config_snapshot_destroy(snapshot);
    LOGE("[disconnect_lwm2m_service] Error creating the LwM2M ESipa thread, "
         "err %d",
         err);
    return eFatal;
  }
  LOGI("[disconnect_lwm2m_service] LwM2M service thread started successfully.");
  return eOk;
}
#endif
#ifdef ENABLE_HTTP_ESIPA

static void disconnect_http_object(void *object) {
  esipa_http__destroy((esipa_http_t *)object);
}

static void destroy_http_snapshot(void *snapshot) {
  ipa_http_config_snapshot_destroy(snapshot);
}

static void disconnect_http_service() {
  if (!g_eim_registry) return;
  LOGI("[disconnect_http_service] Stopping HTTP service...");
  ipa_eim_registry_stop(g_eim_registry, IPA_EIM_SLOT_HTTP,
                        disconnect_http_object);
}

ErrCode connect_http_service(const ipa_config_http_t *config) {
  ipa_http_config_snapshot_t *snapshot = NULL;
  int err;
  if (!config || !fixed_string_terminated(config->fqdn,
                                           sizeof(config->fqdn)) ||
      config->fqdn[0] == '\0')
    return eBadArg;
  pthread_once(&g_eim_registry_once, initialize_eim_registry);
  if (!g_eim_registry) return eFatal;
  if (ipa_http_config_snapshot_create(config, &snapshot) != eOk) return eFatal;
  LOGI("[connect_http_service] Starting HTTP service thread...");
  if (0 != (err = ipa_eim_registry_start(
                    g_eim_registry, IPA_EIM_SLOT_HTTP, connect_esipa_http,
                    snapshot, destroy_http_snapshot))) {
    ipa_http_config_snapshot_destroy(snapshot);
    LOGE("[connect_http_service] Error creating the HTTP ESipa thread, err %d",
         err);
    return eFatal;
  }
  LOGI("[connect_http_service] HTTP service thread started successfully.");
  return eOk;
}
#endif

void stop_eim_service() {
  LOGI("[disconnect_all_services] Stopping all services...");
#ifdef ENABLE_HTTP_ESIPA
  disconnect_http_service();
#endif
#ifdef ENABLE_MQTT
  disconnect_mqtt_service();
#endif
#ifdef ENABLE_LWM2M
  disconnect_lwm2m_service();
#endif
}

#ifdef ENABLE_MQTT

static void *connect_esipa_mqtt(void *ipa_config) {
  ErrCode rc;
  esipa_mqtt_t esipa_mqtt;
  ipa_mqtt_config_snapshot_t *snapshot = ipa_config;
  ipa_config_mqtt_t *config = &snapshot->value;

  if ((rc = esipa_mqtt__ctor(&esipa_mqtt,
                             config->protocol, config->hostname, config->port,
                             config->username, config->password,
                             &config->tls_config, &config->proxy_config,
                             ASN1_DATA_BINDING)) != eOk) {
    LOGE("[start_esipa_mqtt] Error initializing the ESipa MQTT, rc %d", rc);
    return NULL;
  }
  ipa_eim_registry_publish(g_eim_registry, IPA_EIM_SLOT_MQTT,
                           &esipa_mqtt.super);

  if ((rc = esipa__init((esipa_t *)&esipa_mqtt)) != eOk) {
    LOGE("[start_esipa_mqtt] Error connecting the ESipa MQTT, rc %d", rc);
  }

  ipa_eim_registry_clear(g_eim_registry, IPA_EIM_SLOT_MQTT,
                         &esipa_mqtt.super);
  esipa_mqtt__destroy(&esipa_mqtt);
  return NULL;
}

#endif

#ifdef ENABLE_LWM2M

static void *connect_esipa_lwm2m(void *ipa_config) {
  ErrCode rc;
  esipa_lwm2m_t esipa_lwm2m;
  ipa_lwm2m_config_snapshot_t *snapshot = ipa_config;
  ipa_config_lwm2m_t *config = &snapshot->value;

  if ((rc = esipa_lwm2m__ctor(
           &esipa_lwm2m, config->hostname, config->port, config->dtls,
           config->bootstrap, config->ipv4, config->client_name,
           ASN1_DATA_BINDING)) != eOk) {
    LOGE("[start_esipa_lwm2m] Error initializing the ESipa LwM2m, rc %d", rc);
    return NULL;
  }
  ipa_eim_registry_publish(g_eim_registry, IPA_EIM_SLOT_LWM2M,
                           &esipa_lwm2m.super);
  if ((rc = esipa__init((esipa_t *)&esipa_lwm2m)) != eOk) {
    LOGE("Error connecting the ESipa LwM2M, rc %d", rc);
  }

  ipa_eim_registry_clear(g_eim_registry, IPA_EIM_SLOT_LWM2M,
                         &esipa_lwm2m.super);
  esipa_lwm2m__destroy(&esipa_lwm2m);

  return NULL;
}

#endif
#ifdef ENABLE_HTTP_ESIPA
static void *connect_esipa_http(void *ipa_config) {
  ErrCode rc;
  esipa_http_t esipa_http = {0};
  ipa_http_config_snapshot_t *snapshot = ipa_config;
  ipa_config_http_t *config = &snapshot->value;

  esipa_http__ctor(&esipa_http, config->fqdn,
                   config->max_time_without_transmission,
                   ASN1_DATA_BINDING, config->http_timeout,
                   config->sync_sleep_time);
  ipa_eim_registry_publish(g_eim_registry, IPA_EIM_SLOT_HTTP, &esipa_http);
  if ((rc = esipa__init((esipa_t *)&esipa_http)) != eOk) {
    ipa_eim_registry_clear(g_eim_registry, IPA_EIM_SLOT_HTTP, &esipa_http);
    esipa_http__destroy(&esipa_http);
    LOGE("Error on initialize the ESipa HTTP, rc %d", rc);
    return NULL;
  }
  ipa_eim_registry_clear(g_eim_registry, IPA_EIM_SLOT_HTTP, &esipa_http);
  return NULL;
}
#endif
