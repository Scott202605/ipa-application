#pragma once
#include <stdbool.h>
#include "typedefs.h"
#include "linux_typedefs.h"


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

enum LogLevel {
    eLogErr = 1,
    eLogWarn = 2,
    eLogInfo = 3,
    eLogDebug = 4,
    eLogTrace = 5
};

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
void notify_task_start(uint32_t task_id);
void notify_task_end(uint32_t task_id);
typedef void (*ipa_task_start_cb_t)(uint32_t task_id);
typedef void (*ipa_task_end_cb_t)(uint32_t task_id);
typedef struct {
    ipa_task_start_cb_t task_start_cb;
    ipa_task_end_cb_t task_end_cb;
}ipa_task_callbacks_t ;

/**
 * @brief   Registers task-specific callback functions with the IPA library.
 * @details The application provides a structure containing function pointers for various
 *          task lifecycle events (e.g., task start, completion, error). These callbacks
 *          allow the application to be notified asynchronously when task-related events occur.
 *
 * @param[in] callbacks   Pointer to a structure containing task callback functions.
 *                        The structure must remain valid for the duration of the IPA library usage.
 *                        If NULL, any previously registered callbacks will be cleared.
 */
void ipa_register_task_callbacks(const ipa_task_callbacks_t* callbacks);

/**
 * @brief   Defines the function pointer type for the application event callback.
 * @details The application must provide a function matching this signature to ipa_init_library
 *          to receive asynchronous events from the IPA library, such as initialization status.
 *
 * @param[in] event_type    The type of event being notified (e.g., IPA_EVENT_INITIALIZATION_SUCCESS).
 * @param[in] event_data    A pointer to data associated with the event, which can be cast
 *                          to the appropriate type based on the event_type. Can be NULL.
 */
typedef void (*ipa_event_cb_t)(ipa_event_type_t event_type, void *event_data);

/**
 * @brief   Initializes the IPA library.
 * @details This is the main entry point to start the IPA library. It takes configuration
 *          parameters and an event callback, then starts the initialization process
 *          in a background thread. The final result is delivered via the callback.
 *
 * @param[in] config      Pointer to a cl_config_t structure containing core library
 *                        and driver configuration parameters.
 * @param[in] event_cb    Function pointer to the application's event handler.
 *
 * @return 0 if initialization has started successfully, or a negative value
 *         for immediate failures (e.g., thread creation failed).
 */
int ipa_init_library(cl_config_t *config, ipa_event_cb_t event_cb);

/**
 * @brief   Starts the MQTT client service with the specified configuration.
 * @details Initializes and establishes the MQTT client connection using
 *          the provided broker configuration parameters.
 *
 * @param[in] config    Pointer to an ipa_config_mqtt_t structure containing
 *                      MQTT broker connection details.
 *
 * @return eOk on success, or an error code on failure.
 */
ErrCode connect_mqtt_service(const ipa_config_mqtt_t *config);

/**
 * @brief   Starts the LwM2M client service with the specified configuration.
 * @details Initializes and establishes the LwM2M client connection using
 *          the provided server configuration parameters.
 *
 * @param[in] config    Pointer to an ipa_config_lwm2m_t structure containing
 *                      LwM2M server connection details.
 *
 * @return eOk on success, or an error code on failure.
 */
ErrCode connect_lwm2m_service(const ipa_config_lwm2m_t *config);

/**
 * @brief   Starts the HTTP client service for eSIPa communication.
 * @details Initializes the HTTP client using the provided server address
 *          and communication parameters.
 *
 * @param[in] config    Pointer to an ipa_config_http_t structure containing
 *                      the server FQDN and HTTP configuration parameters.
 *
 * @return eOk on success, or an error code on failure.
 */
ErrCode connect_http_service(const ipa_config_http_t *config);

/**
 * @brief   Stops all running communication services.
 * @details Stops and releases all active communication services including
 *          HTTP, MQTT, and LwM2M.
 */
void stop_eim_service(void);

/**
 * @brief   Deinitializes the IPA library and releases all resources.
 * @details Releases all allocated memory, threads, handles, and internal
 *          resources used by the IPA library. This function should be
 *          called during application shutdown.
 */
void ipa_deinit_library(void);
