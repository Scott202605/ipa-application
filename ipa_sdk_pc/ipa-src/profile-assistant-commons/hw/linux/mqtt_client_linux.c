/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#ifdef ENABLE_MQTT
#include <pthread.h>
#include <MQTTClient.h>
#include <stdio.h>
#include <errno.h>

#include "mqtt_client.h"
#include "timer.h"
#include "log.h"
#include "memory_manager.h"
#include "network_utils.h"
#include "linux_typedefs.h"

#define TIMEOUT         10000L
#define SLEEP_ON_RECONNECT  1
#define URL_TEMPLATE    "%s://%s:%d"

typedef struct message_arrived_thread_args_s{
    char* topic;
    int topic_len;
    MQTTClient_message* message;
    mqtt_client_t* me;
} message_arrived_thread_args_t;

static void connection_lost(void* context, char* cause);
static int  message_arrived(void *context, char *topic_name, int topic_len, MQTTClient_message *message_data);
static void message_delivered(void* context, MQTTClient_deliveryToken dt);
static void * message_arrived_thread_execution(void *thread_args);

int MQTT_create_client(mqtt_client_t* const me, char* protocol, char* address, int port, char* client_id, mqtt_connect_callback_t connect_callback_func, mqtt_connection_lost_notification_callback_t connection_lost_notification_callback_func, mqtt_message_arrived_callback_t message_arrived_callback_func, void* user_data) {
    int rc;
    char* broker_url;
    int broker_url_len;
	MQTTClient_createOptions client_options = MQTTClient_createOptions_initializer;
    client_options.MQTTVersion = MQTTVERSION_5;
    
    broker_url_len = snprintf(NULL, 0, URL_TEMPLATE, protocol, address, port);
    if (broker_url_len < 0) {
        LOGE("[MQTT]\t[MQTT_create_client] Error calculating the length of the broker URL");
        return -eFatal;
    }

    broker_url = (char*) M_malloc(sizeof(char) * ((size_t) broker_url_len + 1));
    if (!broker_url) {
        LOGE("[MQTT]\t[MQTT_create_client] Memory allocation in broker URL failed");
        return -eNoMem;
    }

    broker_url_len = snprintf(broker_url, (size_t) broker_url_len + 1, URL_TEMPLATE, protocol, address, port);
    if (broker_url_len < 0) {
        LOGE("[MQTT]\t[MQTT_create_client] Error writting data inside the broker URL");
        M_free(broker_url);
        return -eFatal;
    }

	rc = MQTTClient_createWithOptions((MQTTClient*) &me->mqtt_client_handler, broker_url, client_id, MQTTCLIENT_PERSISTENCE_DEFAULT, NULL, &client_options);
    M_free(broker_url);
    broker_url = NULL;

	if (rc != MQTTCLIENT_SUCCESS) {
		LOGE("[MQTT]\t[MQTT_create_client] MQTTClient_createWithOptions failed, rc %d", rc);
		return -eFatal;
	}
    
    /* Assign all the values to the mqtt client interface structure */
    me->connect_function = connect_callback_func;
    me->connection_lost_function = connection_lost_notification_callback_func; 
    me->message_arrived_function = message_arrived_callback_func;
    me->user_data = user_data;
    me->protocol = protocol;
    me->address = address;
    me->port = port;
    me->client_id = client_id;

    /* Optional configuration */
    me->username = NULL;
    me->password = NULL;
    me->tls_config = NULL;
    me->proxy_config = NULL;

    return MQTTCLIENT_SUCCESS;
}

int MQTT__set_broker_credentials(mqtt_client_t* const me, char* username, char* password) {
    if (!username || strlen(username) == 0) {
        LOGE("[MQTT]\t[MQTT__set_broker_credentials] The Username is empty/null");
        return MQTTCLIENT_FAILURE;
    }

    if (!password || strlen(password) == 0) {
        LOGE("[MQTT]\t[MQTT__set_broker_credentials] The Password is empty/null");
        return MQTTCLIENT_FAILURE;
    }

    me->username = username;
    me->password = password;

    LOGD("[MQTT]\t[MQTT__set_broker_credentials] MQTT client credentials: username='%s', password='%s'", me->username, me->password);

    return MQTTCLIENT_SUCCESS;
}

int MQTT__set_tls_config(mqtt_client_t* const me, mqtt_tls_config_t* config) {
    if (!config) {
        LOGD("[MQTT]\t[MQTT__set_proxy_config] The TLS config object is null");
        return MQTTCLIENT_SUCCESS;
    }

    if ((strlen(config->client_cert_absolute_pem_path) > 0) != (strlen(config->private_key_absolute_pem_path) > 0)) {
        LOGE("[MQTT]\t[MQTT__set_tls_config] To enable the client authentication is mandatory to configure a Private Key and a Client Certificate. The %s is missing", strlen(config->client_cert_absolute_pem_path) ? "Private Key" : "Client Certificate");
        return MQTTCLIENT_FAILURE;
    }

    if (strlen(config->client_cert_absolute_pem_path) > 0) {
        me->tls_config = config;
        LOGD("[MQTT]\t[MQTT__set_tls_config] Client Authentication enabled: Client Certificate PEM file path='%s', Private Key PEM file path='%s'", me->tls_config->client_cert_absolute_pem_path, me->tls_config->private_key_absolute_pem_path);
    }

    if (strlen(config->server_cert_absolute_pem_path) > 0) {
        me->tls_config = config;
        LOGD("[MQTT]\t[MQTT__set_tls_config] Server Authentication enabled: Server Certificate PEM file path='%s'", me->tls_config->server_cert_absolute_pem_path);
    }
    
    return MQTTCLIENT_SUCCESS;
}

int MQTT__set_proxy_config(mqtt_client_t* const me, mqtt_proxy_config_t* config) {
    if (!config) {
        LOGD("[MQTT]\t[MQTT__set_proxy_config] The Proxy config object is null");
        return MQTTCLIENT_SUCCESS;
    }

    if (strlen(config->url) > 0) {
        if (network_utils__is_http_scheme(config->url)) {
            me->proxy_config = config;
            LOGD("[MQTT]\t[MQTT__set_proxy_config] HTTP Proxy URL configured. URL='%s'", me->proxy_config->url);
        } else if (network_utils__is_https_scheme(config->url)) {
            me->proxy_config = config;
            LOGD("[MQTT]\t[MQTT__set_proxy_config] HTTPS Proxy URL configured. URL='%s'", me->proxy_config->url);
        } else {
            LOGE("[MQTT]\t[MQTT__set_proxy_config] Bad Proxy URL scheme. The MQTT library only supports %s and %s", HTTP_SCHEME, HTTPS_SCHEME);
            return MQTTCLIENT_FAILURE;
        }
    }
    
    return MQTTCLIENT_SUCCESS;
}

int MQTT_connect(mqtt_client_t* const me) {
	int err;
    ErrCode rc;
    MQTTClient_connectOptions connection_options = MQTTClient_connectOptions_initializer5;
	MQTTClient_willOptions will_options = MQTTClient_willOptions_initializer;
	MQTTProperties connection_properties = MQTTProperties_initializer;
	MQTTProperties will_properties = MQTTProperties_initializer;
	MQTTResponse response = MQTTResponse_initializer;

    if ((err = MQTTClient_setCallbacks((MQTTClient) me->mqtt_client_handler, (void*) me, connection_lost, message_arrived, message_delivered)) != MQTTCLIENT_SUCCESS) {
        LOGE("[MQTT]\t[MQTT_connect] MQTTClient_setCallbacks failed, err %d", err);
        return err;
    }

    // TLS configuration
    if (network_utils__is_secure_protocol(me->protocol)) {
        LOGD("[MQTT]\t[MQTT_connect] TLS connection");
        MQTTClient_SSLOptions ssl_connection_options = MQTTClient_SSLOptions_initializer;
        ssl_connection_options.enableServerCertAuth = 0;
        // declare values for ssl options, here we use only the ones necessary for TLS
        ssl_connection_options.verify = 1;
        ssl_connection_options.CApath = NULL;
        if (me->tls_config && strlen(me->tls_config->client_cert_absolute_pem_path) > 0) {
            ssl_connection_options.keyStore = me->tls_config->client_cert_absolute_pem_path; // file of certificate for client to present to server
        } else {
            ssl_connection_options.keyStore = NULL;
        }
        if (me->tls_config && strlen(me->tls_config->server_cert_absolute_pem_path) > 0) {
            ssl_connection_options.trustStore = me->tls_config->server_cert_absolute_pem_path; // file of certificates trusted by client
            ssl_connection_options.enableServerCertAuth = true;
        } else {
            ssl_connection_options.trustStore = NULL;
        }
        if (me->tls_config && strlen(me->tls_config->private_key_absolute_pem_path) > 0) {
            ssl_connection_options.privateKey = me->tls_config->private_key_absolute_pem_path;
        } else {
            ssl_connection_options.privateKey = NULL;
        }
        ssl_connection_options.privateKeyPassword = NULL;
        ssl_connection_options.enabledCipherSuites = NULL;

        // use TLS for a secure connection, "ssl_connection_options" includes TLS
        connection_options.ssl = &ssl_connection_options;
    }

	connection_options.keepAliveInterval = 20;
	connection_options.cleanstart = 1;

    // Broker credentials
	if (me->username && me->password) {
        connection_options.username = me->username;
        connection_options.password = me->password;
        LOGD("[MQTT]\tCredentials to be used to connect to the broker: username [%s] and password [%s]", connection_options.username, connection_options.password);
    } else {
        LOGD("[MQTT]\tNo username and password will be used to connect to the broker");
    }

    // Proxy configuration
    if (me->proxy_config && strlen(me->proxy_config->url) > 0) {
        if (network_utils__is_http_scheme(me->proxy_config->url)) {
            connection_options.httpProxy = me->proxy_config->url;
        } else if (network_utils__is_https_scheme(me->proxy_config->url)) {
            connection_options.httpsProxy = me->proxy_config->url;
        } else {
            LOGW("[MQTT]\tBad Proxy URL scheme");
        }
    }

    // Will configuration (for now dummy values)
	connection_options.will = &will_options;
	connection_options.will->message = "will message";
	connection_options.will->qos = 1;
	connection_options.will->retained = 0;
	connection_options.will->topicName = "will topic";

	connection_options.MQTTVersion = MQTTVERSION_5;

	LOGD("[MQTT]\t[MQTT_connect] Connecting to the broker using the MQTT version %d", connection_options.MQTTVersion);
	response = MQTTClient_connect5((MQTTClient) me->mqtt_client_handler, &connection_options, &connection_properties, &will_properties);

    if (response.reasonCode == MQTTREASONCODE_SUCCESS) {
        if ((rc = me->connect_function(me->user_data)) != eOk) {
            LOGE("[MQTT]\t[MQTT_connect] connect callback failed, rc %d", rc);
        }
        return -rc;
    } else {
        return (int) response.reasonCode;
    }	
}

int MQTT_publish_message(mqtt_client_t* const me, const char* topic, const unsigned char* message, const size_t message_len, int qos) {
    MQTTClient_deliveryToken dt;
    MQTTProperties publish_properties = MQTTProperties_initializer;
	MQTTResponse response;
    response = MQTTClient_publish5((MQTTClient) me->mqtt_client_handler, topic, (int) message_len, (void*) message, qos, 0, &publish_properties, &dt);

    if (response.reasonCode == MQTTREASONCODE_SUCCESS) {
        LOGD("[MQTT]\t[MQTT_publish_message] Message published to topic '%s'", topic);
        LOG_DATA(eLogTrace, "[MQTT]\t[MQTT_publish_message] Message", message, message_len);
    } else {
        LOGE("[MQTT]\t[MQTT_publish_message] MQTTClient_publish5 failed, rc %d", response.reasonCode);
    }

    return response.reasonCode;
}

int MQTT_subscribe_topic(mqtt_client_t* const me, char* topic, int qos) {
	MQTTSubscribe_options subscription_options = MQTTSubscribe_options_initializer;
    MQTTProperties subscription_properties = MQTTProperties_initializer;
    MQTTResponse response;

    subscription_options.retainAsPublished = 1;

    response = MQTTClient_subscribe5((MQTTClient) me->mqtt_client_handler, topic, qos, &subscription_options, &subscription_properties);

    if (response.reasonCode == MQTTREASONCODE_SUCCESS || response.reasonCode == MQTTREASONCODE_GRANTED_QOS_0 || response.reasonCode == MQTTREASONCODE_GRANTED_QOS_1 || response.reasonCode == MQTTREASONCODE_GRANTED_QOS_2) {
        LOGI("[MQTT]\tSubscribed to topic %s with QoS %d", topic, response.reasonCode);
    } else {
        LOGE("[MQTT]\t[MQTT_subscribe_topic] MQTTClient_subscribe5 failed, rc %d", response.reasonCode);
    }

    return response.reasonCode;
}

int MQTT_unsubscribe_topic(mqtt_client_t* const me, char* topic, int qos) {
    MQTTProperties unsubscribe_properties = MQTTProperties_initializer;
    MQTTResponse response;

    response = MQTTClient_unsubscribe5((MQTTClient) me->mqtt_client_handler, topic, &unsubscribe_properties);

    if (response.reasonCode == MQTTREASONCODE_SUCCESS) {
        LOGI("[MQTT]\tUnsubscribed from the topic %s", topic);
    } else {
        LOGE("[MQTT]\t[MQTT_unsubscribe_topic] MQTTClient_unsubscribe5 failed, rc %d", response.reasonCode);
    }

    return response.reasonCode;
}

bool MQTT_wait_thread_condition(mqtt_client_t* const me) {
    timer__sleep(5);
    return true; // Signal can be captured (application-specific implementation) to stop the thread 
}

int MQTT_disconnect(mqtt_client_t* const me) {
    MQTTProperties disconnect_properties = MQTTProperties_initializer;
    return MQTTClient_disconnect5((MQTTClient) me->mqtt_client_handler, TIMEOUT, MQTTREASONCODE_NORMAL_DISCONNECTION, &disconnect_properties);
}

void MQTT_destroy(mqtt_client_t* const me) {
    MQTTClient_destroy((MQTTClient*) &me->mqtt_client_handler);
    me->mqtt_client_handler = NULL;
    /* Just in case */
    me->user_data = NULL;
    me->protocol = NULL;
    me->address = NULL;
    me->port = 0;
    me->client_id = NULL;
    me->username = NULL;
    me->password = NULL;
}

static void connection_lost(void* context, char* cause) {
    uint32_t attempt = 1;
    int rc;

    LOGE("[MQTT]\t[connection_lost] Connection lost. Cause: %s", cause);

    // Notify the disconnect
    ((mqtt_client_t*) context)->connection_lost_function(((mqtt_client_t*) context)->user_data);

    /* Try to reconnect */
reconnect_connect:
    LOGI("[MQTT]\tReconnecting to broker, attempt %u...", attempt);
    if ((rc = MQTT_connect((mqtt_client_t*) context)) < 0) {
        LOGE("[MQTT]\t[connection_lost] Error connecting to the broker, rc %d", rc);
        attempt++;
        timer__sleep(SLEEP_ON_RECONNECT);
        goto reconnect_connect;
    }
}

static int message_arrived(void *context, char *topic_name, int topic_len, MQTTClient_message *message_data) {
    pthread_t message_arrived_thread;
    message_arrived_thread_args_t* thread_args;

    if (topic_len <= 0) {
        topic_len = (int) strlen(topic_name);
    }

    LOG_UTF8_DATA(eLogDebug, "[MQTT]\tMessage arrived from topic ", (uint8_t*) topic_name, (size_t) topic_len);
    LOG_DATA(eLogDebug, "[MQTT]\tMessage", (uint8_t*) message_data->payload, (size_t) message_data->payloadlen);

    thread_args = (message_arrived_thread_args_t*) M_malloc(sizeof(message_arrived_thread_args_t));
    if (!thread_args) {
        LOGE("[MQTT]\t[message_arrived] Cannot assign memory to the thread arguments when message arrived");
        MQTTClient_free(topic_name);
        MQTTClient_freeMessage(&message_data);
        return 1; //TODO Maybe is better to return a 0?
    }

    thread_args->topic = topic_name;
    thread_args->topic_len = topic_len;
    thread_args->message = message_data;
    thread_args->me =  (mqtt_client_t*) context;

    //Frees of thread_args, topic_name and message_data will be done inside the thread
    pthread_create(&message_arrived_thread, NULL, message_arrived_thread_execution, (void*) thread_args);

    return 1;
}

static void message_delivered(void* context, MQTTClient_deliveryToken dt) {
    LOGD("[MQTT]\t[callback_delivery_complete] Message with token %d delivery complete", dt);
}

/**
 * Dangerous function.
 * This function will free data from the params, frees: 
 *  th_args->topic
 *  th_args->message
 *  th_args.
*/
static void * message_arrived_thread_execution(void *thread_args) {    
    message_arrived_thread_args_t* args = (message_arrived_thread_args_t*) thread_args;    
    ErrCode rc;

    rc = args->me->message_arrived_function(args->me->user_data, 
                                           (unsigned char*) args->topic,
                                           (size_t) args->topic_len,
                                           (unsigned char*) args->message->payload, 
                                           (uint32_t) args->message->payloadlen);
    MQTTClient_free(args->topic);
    MQTTClient_freeMessage(&args->message);
    M_free(args);

    if (rc != eOk) {
        LOGE("[MQTT]\t[message_arrived_thread_execution] message_arrived_function failed, rc %d", rc);
    }

    return NULL;
}
#endif
