/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#ifdef ENABLE_MQTT
#include <stdio.h>

#include "esipa_mqtt.h"
#include "mqtt_client.h"
#include "ipa.h"
#include "linux_typedefs.h"
#include "log.h"
#include "memory_manager.h"

#define QOS             1
#define IPA_TO_EIM_TOPIC            "ipa-to-eim"
#define EIM_TO_IPA_TOPIC_HDR        "eim-to-ipa/"

static ErrCode esipa_mqtt__connect(esipa_async_t* const me);
static ErrCode esipa_mqtt__disconnect(esipa_async_t* const me);
static bool esipa_mqtt__keep_alive(esipa_async_t* const me);
static ErrCode esipa_mqtt__send_message(esipa_async_t* const me, uint8_t** message, uint32_t* message_size);
/* MQTT client callbacks */
static ErrCode esipa_mqtt__client_connected_callback(void* const context);
static void esipa_mqtt__client_connection_lost_callback(void* const context);
static ErrCode esipa_mqtt__client_message_arrived_callback(void* const context, unsigned char *topic, size_t topic_len, unsigned char* message, uint32_t message_size);


ErrCode esipa_mqtt__ctor(esipa_mqtt_t * const me, char* protocol, char* fqdn, int port, char* username, char* password, mqtt_tls_config_t* tls_config, mqtt_proxy_config_t* proxy_config, gsma_data_binding_t data_binding) {
    ErrCode rc;
    int err;
    
    static struct esipa_async_vtbl_s const vtbl = {  /* vtbl of the ESipa async class */
        &esipa_mqtt__connect,
        &esipa_mqtt__disconnect,
        &esipa_mqtt__keep_alive,
        &esipa_mqtt__send_message
    };
    // The eIM data is not retrieved from the UICC. For the moment, the eimId and TLS data will not be configured in the ESipa instance.
    esipa_async__ctor(&me->super, NULL, 0, fqdn, port, NULL, 0, data_binding); /* call the superclass constructor */
    me->super.vptr = &vtbl; /* override the vptr */
    
    /* Set attributes of the subclass */
    me->protocol = protocol;
    me->username = username;
    me->password = password;
    if ((rc = ipa__get_eid_cstring(me->eid, sizeof(me->eid))) != eOk) {
        LOGE("[esipa_mqtt__ctor] Error assigning the client id (EID) %d", rc);
        return rc;
    }
    err = (int32_t) MQTT_create_client(&me->client, protocol, fqdn, port, me->eid, &esipa_mqtt__client_connected_callback, &esipa_mqtt__client_connection_lost_callback, &esipa_mqtt__client_message_arrived_callback, (void*) me);
    if (err < 0) {
        LOGE("[esipa_mqtt__ctor] Error creating the MQTT Client %d", err);
        esipa_async__destroy(&me->super);
        memset(me, 0, sizeof(esipa_mqtt_t)); //Clear all the struct
        return eFatal;
    }

    if (username && password && strlen(username) > 0 && strlen(password) > 0) {
        if ((err = MQTT__set_broker_credentials(&me->client, username, password)) < 0) {
            LOGE("[esipa_mqtt__ctor] Error setting the broker credentials, err %d", err);
            MQTT_destroy(&me->client);
            esipa_async__destroy(&me->super);
            memset(me, 0, sizeof(esipa_mqtt_t)); //Clear all the struct
            return eFatal;
        }
    }

    if (tls_config) {
        if ((err = MQTT__set_tls_config(&me->client, tls_config)) < 0) {
            LOGE("[esipa_mqtt__ctor] Error setting the TLS configuration, err %d", err);
            MQTT_destroy(&me->client);
            esipa_async__destroy(&me->super);
            memset(me, 0, sizeof(esipa_mqtt_t)); //Clear all the struct
            return eFatal;
        }
    }

    if (proxy_config) {
        if ((err = MQTT__set_proxy_config(&me->client, proxy_config)) < 0) {
            LOGE("[esipa_mqtt__ctor] Error setting the Proxy configuration, err %d", err);
            MQTT_destroy(&me->client);
            esipa_async__destroy(&me->super);
            memset(me, 0, sizeof(esipa_mqtt_t)); //Clear all the struct
            return eFatal;
        }
    }

    return eOk;
}

void esipa_mqtt__destroy(esipa_mqtt_t * const me) {
    /* Destroy the MQTT client */
    MQTT_destroy(&me->client);

    /* Destory parent struct */
    esipa_async__destroy(&me->super);

    memset(me, 0, sizeof(esipa_mqtt_t)); //Clear all the struct
}

static ErrCode esipa_mqtt__connect(esipa_async_t* const me) {
    int err = 0;
    esipa_mqtt_t* const me_ = (esipa_mqtt_t*) me; /* explicit downcast */

    if ((err = MQTT_connect(&me_->client)) < 0) {
        LOGE("[esipa_mqtt__connect] Error on connect to the broker, err %d", err);
        return eFatal;
    }

    return eOk;
}

static ErrCode esipa_mqtt__disconnect(esipa_async_t* const me) {
    int err;
    char eim_to_ipa_topic[sizeof(EIM_TO_IPA_TOPIC_HDR) + OCTET16 * 2] = { 0 }; //Null ponter counted on sizeof topic header string
    esipa_mqtt_t* const me_ = (esipa_mqtt_t*) me; /* explicit downcast */

    strcpy(eim_to_ipa_topic, EIM_TO_IPA_TOPIC_HDR);
    strcpy(eim_to_ipa_topic + sizeof(EIM_TO_IPA_TOPIC_HDR) - 1, me_->eid);

    if (!me) {
        LOGE("[esipa_mqtt__disconnect] The ESipa MQTT instance is null");
        return eBadArg;
    }

    /* Unsuscribe. How we can be sure that we reach the subscribe to topic? I think it's not a problem */
    if ((err = MQTT_unsubscribe_topic(&me_->client, eim_to_ipa_topic, QOS)) < 0) {
        LOGW("[esipa_mqtt__disconnect] Failed to unsubscribe %s topic, err %d", eim_to_ipa_topic, err);
    }
    /* Disconnect */
    if ((err = MQTT_disconnect(&me_->client)) < 0) {
        LOGE("[esipa_mqtt__disconnect] Failed to disconnect the MQTT client, err %d", err);
        return eFatal;
    }

    LOGI("ESipa MQTT disconnected from the broker");
    return eOk;
}

static bool esipa_mqtt__keep_alive(esipa_async_t* const me) {
    esipa_mqtt_t* const me_ = (esipa_mqtt_t*) me; /* explicit downcast */
    return MQTT_wait_thread_condition(&me_->client);
}

static ErrCode esipa_mqtt__send_message(esipa_async_t* const me, uint8_t** message, uint32_t* message_size) {
    int err = 0;
    ErrCode rc = eOk;
    esipa_mqtt_t* const me_ = (esipa_mqtt_t*) me; /* explicit downcast */

    if ((err = MQTT_publish_message(&me_->client, IPA_TO_EIM_TOPIC, *message, *message_size, QOS)) < 0) {
        LOGE("[esipa_mqtt__send_message] Error on publish the EsipaMessageFromIpaToEim message to the broker, err %d", err);
        rc = eFatal;
    }
    M_free(*message);
    *message = NULL;
    *message_size = 0;

    return rc;
}

/* MQTT client callbacks */
static ErrCode esipa_mqtt__client_connected_callback(void* const context) {
    ErrCode rc;
    int err;
    char eim_to_ipa_topic[sizeof(EIM_TO_IPA_TOPIC_HDR) + OCTET16 * 2] = { 0 }; //Null ponter counted on sizeof topic header string
    esipa_mqtt_t * const me = (esipa_mqtt_t*) context;  /* Get ESipa MQTT data */

    LOGI("[MQTT]\tIoT Device connected to the MQTT broker");
    
    strcpy(eim_to_ipa_topic, EIM_TO_IPA_TOPIC_HDR);
    strcpy(eim_to_ipa_topic + sizeof(EIM_TO_IPA_TOPIC_HDR) - 1, me->eid);
    
    if ((err = MQTT_subscribe_topic(&me->client, eim_to_ipa_topic, QOS)) < 0) {
        LOGE("[esipa_mqtt__client_connected_callback] Failed to subscribe to %s topic, rc %d", eim_to_ipa_topic);
        return eFatal;
    }

    if ((rc = esipa_async__connected((esipa_async_t*) context)) != eOk) { /* Upcast to superclass */
        LOGE("[esipa_mqtt__client_connected_callback] Failed to execute the ESipa Async connected procedure, rc %d", rc);
        return rc;
    }

    return eOk;
}

static void esipa_mqtt__client_connection_lost_callback(void* const context) {
    ErrCode rc;
    if ((rc = esipa_async__connection_lost((esipa_async_t*) context)) != eOk) {
        LOGW("[esipa_mqtt__client_connection_lost_callback] Failed to execute the ESipa Async connection lost procedure, rc %d", rc);
    }
}

static ErrCode esipa_mqtt__client_message_arrived_callback(void* const context, unsigned char *topic, size_t topic_len, unsigned char* message, uint32_t message_size) {
    ErrCode rc;

    // Only suscribed to one topic, no need to filter by topic
    LOGI("[MQTT]\tMessage from the eIM received");
    LOG_DATA(eLogDebug, "[MQTT]\tEsipaMessageFromEimToIpa", message, message_size);

    if ((rc = esipa_async__execute_message((esipa_async_t *) context, (uint8_t*) message, message_size)) != eOk) { /* Upcast to superclass */
        LOGE("[esipa_mqtt__client_message_arrived_callback] Failed to process the EsipaMessageFromEimToIpa, rc %d", rc);
    } else {
        LOGD("[ESipa]\tEsipaMessageFromEimToIpa processed successfully\n");
    }

    return rc;
}
#endif
