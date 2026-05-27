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
static pthread_t g_init_thread_id;
static cl_config_t g_cl_config;
static ipa_event_cb_t g_event_cb = NULL;
static ipa_task_callbacks_t g_task_callbacks = {0};
static int ipa_continue_initialization_internal(void);
static void *ipa_init_thread_func(void *arg);

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
  cl_config_t *config = (cl_config_t *)arg;
  int err = -1;
  if (config->log_level < eLogErr || config->log_level > eLogTrace) {
    goto error_exit;
  }
  LOG_INIT(config->log_level);
  es9__ctor(&g_es9);
  es11__ctor(&g_es11);
  switch (config->es10_driver_selected) {
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
  switch (config->es10_driver_selected) {
  case ES10_DRIVER_AT:
    smartcard_at_external__destory(&g_es10_driver.at_external_driver);
    break;
  default:
    break;
  }

error_exit:
  g_ipa_state = IPA_STATE_UNINITIALIZED;
  return NULL;
}

int ipa_init_library(cl_config_t *config, ipa_event_cb_t event_cb) {
  if (g_ipa_state != IPA_STATE_UNINITIALIZED) {
    LOGW("IPA library already initialized or in progress. Current state: %d",
         g_ipa_state);
    return 0;
  }
  g_ipa_state = IPA_STATE_INITIALIZING;
  memcpy(&g_cl_config, config, sizeof(cl_config_t));
  g_event_cb = event_cb;

  if (pthread_create(&g_init_thread_id, NULL, ipa_init_thread_func,
                     &g_cl_config) != 0) {
    LOGE("Failed to create IPA initialization thread.");
    g_ipa_state = IPA_STATE_UNINITIALIZED;
    g_event_cb = NULL;
    return -1;
  }

  pthread_detach(g_init_thread_id);

  return 0;
}

static int ipa_continue_initialization_internal(void) {
  int err;
  LOGI("[ipa_continue] eIM provisioned. Continuing initialization...");
  if ((err = ipa__init(&g_es9, &g_es10, &g_es11)) != 0) {
    LOGE("[ipa_continue] Error on init the IPA, rc %d", err);
    g_ipa_state = IPA_STATE_UNINITIALIZED;
    notify_app(IPA_EVENT_INITIALIZATION_FAILED, &err);
    return err;
  }
  g_ipa_state = IPA_STATE_INITIALIZED;
  LOGI("[ipa_continue] IPA library initialized successfully.");
  err = 0;
  notify_app(IPA_EVENT_INITIALIZATION_SUCCESS, &err);
  return err;
}

void ipa_deinit_library() {
  LOGI("De-initializing IPA library...\n");

  if (g_ipa_state != IPA_STATE_INITIALIZED) {
    LOGI("Warning: IPA library was not initialized or already "
         "de-initialized.\n");
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
  memset(&g_es10_driver, 0, sizeof(g_es10_driver));
  memset(&g_es10, 0, sizeof(g_es10));
  g_ipa_state = IPA_STATE_UNINITIALIZED;
  LOGI("IPA library de-initialized.\n");
}

#ifdef ENABLE_MQTT

static esipa_mqtt_t *g_esipa_mqtt = NULL;

/* Extern declaration since it is not in the header explicitly included here */
ErrCode esipa_async__disconnect(esipa_async_t *const me);

static void disconnect_mqtt_service() {
  if (g_esipa_mqtt) {
    LOGI("[disconnect_mqtt_service] Stopping MQTT service...");
    esipa_async__disconnect(&g_esipa_mqtt->super);
    LOGI("[disconnect_mqtt_service] MQTT service stopped.");
    g_esipa_mqtt = NULL;
  } else {
    LOGW("[disconnect_mqtt_service] MQTT service is not running.");
  }
}

ErrCode connect_mqtt_service(const ipa_config_mqtt_t *config) {
  pthread_t mqtt_thread = {0};
  int err;
  LOGI("[start_mqtt_service] Starting MQTT service thread...");
  if (0 != (err = pthread_create(&mqtt_thread, NULL, connect_esipa_mqtt,
                                 (void *)config))) {
    LOGE("[start_mqtt_service] Error creating the MQTT ESipa thread, err %d",
         err);
    return eFatal;
  }
  pthread_detach(mqtt_thread);
  LOGI("[start_mqtt_service] MQTT service thread started successfully.");
  return eOk;
}

#endif

#ifdef ENABLE_LWM2M

static esipa_lwm2m_t *g_esipa_lwm2m = NULL;

static void disconnect_lwm2m_service() {
  if (g_esipa_lwm2m) {
    LOGI("[disconnect_lwm2m_service] Stopping LwM2M service...");
    esipa_async__disconnect(&g_esipa_mqtt->super);
  } else {
    LOGW("[disconnect_lwm2m_service] LwM2M service is not running.");
  }
}

ErrCode connect_lwm2m_service(const ipa_config_lwm2m_t *config) {
  pthread_t lwm2m_thread = {0};
  int err;
  LOGI("[disconnect_lwm2m_service] Starting LwM2M service thread...");
  if (0 != (err = pthread_create(&lwm2m_thread, NULL, connect_esipa_lwm2m,
                                 (void *)config))) {
    LOGE("[disconnect_lwm2m_service] Error creating the LwM2M ESipa thread, "
         "err %d",
         err);
    return eFatal;
  }
  pthread_detach(lwm2m_thread);
  LOGI("[disconnect_lwm2m_service] LwM2M service thread started successfully.");
  return eOk;
}
#endif
#ifdef ENABLE_HTTP_ESIPA

static esipa_http_t *g_esipa_http = NULL;

static void disconnect_http_service() {
  if (g_esipa_http) {
    LOGI("[disconnect_http_service] Stopping HTTP service...");
    esipa_http__destroy(g_esipa_http);
  } else {
    LOGW("[disconnect_http_service] HTTP service is not running.");
  }
}

ErrCode connect_http_service(const ipa_config_http_t *config) {
  pthread_t http_thread = {0};
  int err;
  LOGI("[connect_http_service] Starting HTTP service thread...");
  if (0 != (err = pthread_create(&http_thread, NULL, connect_esipa_http,
                                 (void *)config))) {
    LOGE("[connect_http_service] Error creating the HTTP ESipa thread, err %d",
         err);
    return eFatal;
  }
  pthread_detach(http_thread);
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

  if (g_esipa_mqtt != NULL) {
    LOGW("[connect_esipa_mqtt] MQTT service is already running.");
    return NULL;
  }
  g_esipa_mqtt = &esipa_mqtt;

  if ((rc = esipa_mqtt__ctor(&esipa_mqtt,
                             ((ipa_config_mqtt_t *)ipa_config)->protocol,
                             ((ipa_config_mqtt_t *)ipa_config)->hostname,
                             ((ipa_config_mqtt_t *)ipa_config)->port,
                             ((ipa_config_mqtt_t *)ipa_config)->username,
                             ((ipa_config_mqtt_t *)ipa_config)->password,
                             &((ipa_config_mqtt_t *)ipa_config)->tls_config,
                             &((ipa_config_mqtt_t *)ipa_config)->proxy_config,
                             ASN1_DATA_BINDING)) != eOk) {
    LOGE("[start_esipa_mqtt] Error initializing the ESipa MQTT, rc %d", rc);
    g_esipa_mqtt = NULL;
    return NULL;
  }

  if ((rc = esipa__init((esipa_t *)&esipa_mqtt)) != eOk) {
    LOGE("[start_esipa_mqtt] Error connecting the ESipa MQTT, rc %d", rc);
  }

  g_esipa_mqtt = NULL;
  esipa_mqtt__destroy(&esipa_mqtt);
  return NULL;
}

#endif

#ifdef ENABLE_LWM2M

static void *connect_esipa_lwm2m(void *ipa_config) {
  ErrCode rc;
  esipa_lwm2m_t esipa_lwm2m;

  g_esipa_lwm2m = &esipa_lwm2m;

  if ((rc = esipa_lwm2m__ctor(
           &esipa_lwm2m, ((ipa_config_lwm2m_t *)ipa_config)->hostname,
           ((ipa_config_lwm2m_t *)ipa_config)->port,
           ((ipa_config_lwm2m_t *)ipa_config)->dtls,
           ((ipa_config_lwm2m_t *)ipa_config)->bootstrap,
           ((ipa_config_lwm2m_t *)ipa_config)->ipv4,
           ((ipa_config_lwm2m_t *)ipa_config)->client_name,
           ASN1_DATA_BINDING)) != eOk) {
    LOGE("[start_esipa_lwm2m] Error initializing the ESipa LwM2m, rc %d", rc);
    g_esipa_lwm2m = NULL;
    return NULL;
  }
  if ((rc = esipa__init((esipa_t *)&esipa_lwm2m)) != eOk) {
    LOGE("Error connecting the ESipa LwM2M, rc %d", rc);
  }

  esipa_lwm2m__destroy(&esipa_lwm2m);
  g_esipa_lwm2m = NULL;

  return NULL;
}

#endif
#ifdef ENABLE_HTTP_ESIPA
static void *connect_esipa_http(void *ipa_config) {
  ErrCode rc;
  esipa_http_t esipa_http = {0};
  ipa_config_http_t *config = (ipa_config_http_t *)ipa_config;

  g_esipa_http = &esipa_http;

  esipa_http__ctor(&esipa_http, config->fqdn,
                   config->max_time_without_transmission,
                   ASN1_DATA_BINDING, config->http_timeout,
                   config->sync_sleep_time);
  if ((rc = esipa__init((esipa_t *)&esipa_http)) != eOk) {
    esipa_http__destroy(&esipa_http);
    LOGE("Error on initialize the ESipa HTTP, rc %d", rc);
  }
  g_esipa_http = NULL;
  return NULL;
}
#endif
