/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#ifdef ENABLE_LWM2M
#include "esipa_lwm2m.h"
#include "ipa.h"
#include "memory_manager.h"
#include "log.h"
#include "tlv_lengths.h"

#define LWM2M_LIFETIME  300
#define RES_STATE_READY 0
#define RES_STATE_BUSY  1

#define LWM2M_ESIM_IOT_OBJECT_ID                3443 // Object ID of eSIM IoT
#define LWM2M_ESIM_IOT_OBJECT_INSTANCE_ID       0 // eSIM IoT object is single instance
#define LWM2M_ESIM_IOT_IPA_MESSAGE_RESOURCE_ID  3 // Resource ID of IPA message
#define LWM2M_ESIM_IOT_RESOURCE_INSTANCE_ID     0 // All the eSIM IoT resources are single instance

/* ESipa inheritance functions */
static ErrCode esipa_lwm2m__connect(esipa_async_t* const me);
 ErrCode esipa_lwm2m__disconnect(esipa_async_t* const me);
static bool esipa_lwm2m__keep_alive(esipa_async_t* const me);
static ErrCode esipa_lwm2m__send_message(esipa_async_t* const me, uint8_t** message, uint32_t* message_size);
/* LwM2M client callbacks */
// Client connected to the server callback
static void esipa_lwm2m__client_connected_callback(void* context);
static void esipa_lwm2m__client_disconnected_callback(void* context);
// eSIM IoT resource operation callbacks
static uint8_t esim_iot_state_read(void* context);
static int esim_iot_eid_read(void* context, char *buffer, const uint32_t buffer_size);
static int esim_iot_eim_message_write(void* context, const unsigned char *eim_message, const uint32_t eim_message_size);
static int esim_iot_ipa_message_read(void* context, unsigned char **buffer, uint32_t *buffer_size);
static void esim_iot_clear_ipa_message_execute(void* context);

ErrCode esipa_lwm2m__ctor(esipa_lwm2m_t * const me, char* fqdn, int port, bool dtls, bool bootstrap, bool ipv4, const char* client_name, gsma_data_binding_t data_binding) {
    int32_t err;
    ErrCode rc;

    static struct esipa_async_vtbl_s const vtbl = {  /* vtbl of the mqtt esipa class */
        &esipa_lwm2m__connect,
        &esipa_lwm2m__disconnect,
        &esipa_lwm2m__keep_alive,
        &esipa_lwm2m__send_message
    };
    // The eIM data is not retrieved from the UICC. For the moment, the eimId and TLS data will not be configured in the ESipa instance.
    esipa_async__ctor(&me->super, NULL, 0, fqdn, port, NULL, 0, data_binding); /* call the superclass constructor */
    me->super.vptr = &vtbl; /* override the vptr */
    /* Set attributes of the subclass */
    me->dtls = dtls;
    me->bootstrap = bootstrap;
    me->ipv4 = ipv4;
    me->ipa_message = NULL;
    me->ipa_message_size = 0;
    me->is_first_wakeup_msg = false; // Client is not connected yet
    if (client_name) {
        if (strlen(client_name) < sizeof(me->client_name)) {
            strcpy(me->client_name, client_name);
        } else {
            memcpy(me->client_name, client_name, sizeof(me->client_name));
            me->client_name[sizeof(me->client_name) - 1] = '\0';
        }
    } else {
        if ((rc = ipa__get_eid_cstring(me->client_name, sizeof(me->client_name))) != eOk) {
            LOGE("[esipa_lwm2m__ctor] Error retrieving the EID %d", rc);
            esipa_async__destroy(&me->super);
            return rc;
        }
    }
    err = (int32_t) lwm2m_create_client(&me->client, fqdn, port, dtls, bootstrap, ipv4, me->client_name, LWM2M_LIFETIME, &esipa_lwm2m__client_connected_callback, &esipa_lwm2m__client_disconnected_callback,
        &esim_iot_state_read, &esim_iot_eid_read, &esim_iot_eim_message_write, &esim_iot_ipa_message_read, &esim_iot_clear_ipa_message_execute, (void*) me);
    if (err < 0) {
        LOGE("[esipa_lwm2m__ctor] Error creating the LwM2M Client %d", err);
        esipa_async__destroy(&me->super);
        return eFatal;
    }

    return eOk;
}

void esipa_lwm2m__destroy(esipa_lwm2m_t * const me) {
    /* Free the last IPA message */
    M_free(me->ipa_message);

    /* Destroy the LwM2M client */
    lwm2m_destroy(&me->client);

    /* Destory parent struct */
    esipa_async__destroy(&me->super);

    memset(me, 0, sizeof(esipa_lwm2m_t)); //Clear all the struct
}

static ErrCode esipa_lwm2m__connect(esipa_async_t* const me) {
    int err = 0;
    esipa_lwm2m_t * const me_ = (esipa_lwm2m_t*) me;  /* explicit downcast */

    if ((err = lwm2m_initialize(&me_->client)) < 0) {
        LOGE("[esipa_lwm2m__connect] Error connecting to the LwM2M server, err %d", err);
        return eFatal;
    }

    return eOk;
}

 ErrCode esipa_lwm2m__disconnect(esipa_async_t* const me) {
    int err = 0;
    esipa_lwm2m_t * const me_ = (esipa_lwm2m_t*) me;  /* explicit downcast */

    /* Disconnect the LwM2M client */
    if ((err = lwm2m_disconnect(&me_->client)) < 0) {
        LOGE("[esipa_lwm2m__disconnect] Failed to disconnect the LwM2M client, err %d", err);
        return eFatal;
    }

    return eOk;
}

static bool esipa_lwm2m__keep_alive(esipa_async_t* const me) {
    esipa_lwm2m_t * const me_ = (esipa_lwm2m_t*) me;  /* explicit downcast */

    return lwm2m_connect(&me_->client);
}

static ErrCode esipa_lwm2m__send_message(esipa_async_t* const me, uint8_t** message, uint32_t* message_size) {
    esipa_lwm2m_t * const me_ = (esipa_lwm2m_t*) me;  /* explicit downcast */
    int err;
    /* Free the last IPA message available on the IPA message resource */
    M_free(me_->ipa_message);
    /* Set the new IPA message on the pointer of read IPA message resource */
    me_->ipa_message = *message;
    me_->ipa_message_size = *message_size;

    if (me_->is_first_wakeup_msg) {
        /* Is the first wake up message. Don't call the send operation, just write the message in the resource */
        me_->is_first_wakeup_msg = false; // The next message will be send to the eIM using the send operation
    } else {
        /* Send the IPA message resource to the LwM2M server */
        if ((err = lwm2m_send_operation(&me_->client, LWM2M_ESIM_IOT_OBJECT_ID, LWM2M_ESIM_IOT_OBJECT_INSTANCE_ID, LWM2M_ESIM_IOT_IPA_MESSAGE_RESOURCE_ID, LWM2M_ESIM_IOT_RESOURCE_INSTANCE_ID)) < 0) {
            LOGE("[esipa_lwm2m__send_message] Send operation to LwM2M server failed, rc %d", err);
            return eFatal;
        } else {
            LOGI("[LwM2M]\tSend operation sucessfully executed");
        }
    }

    return eOk;
}

static void esipa_lwm2m__client_connected_callback(void* context) {
    ErrCode rc;

    ((esipa_lwm2m_t*) context)->is_first_wakeup_msg = true;

    if ((rc = esipa_async__connected((esipa_async_t*) context)) != eOk) {
        LOGE("[esipa_lwm2m__client_connected_callback] Failed to execute the ESipa Async connected procedure, rc %d", rc);
    }
}

static void esipa_lwm2m__client_disconnected_callback(void* context) {
    ErrCode rc;
    if ((rc = esipa_async__connection_lost((esipa_async_t*) context)) != eOk) {
        LOGW("[esipa_lwm2m__client_disconnected_callback] Failed to execute the ESipa Async connection lost procedure, rc %d", rc);
    }
}

static uint8_t esim_iot_state_read(void* context) {
    if (ipa__is_available()) {
        return RES_STATE_READY;
    } else {
        return RES_STATE_BUSY;
    }
}

static int esim_iot_eid_read(void* context, char *buffer, uint32_t buffer_size) {
    ErrCode rc;
    if ((rc = ipa__get_eid_cstring(buffer, buffer_size)) != eOk) {
        LOGE("[esim_iot_eid_read] Error retrieving the EID from the IPA %d", rc);
        return -rc;
    }

    return 0;
}

static int esim_iot_eim_message_write(void* context, const unsigned char *eim_message, const uint32_t eim_message_size) {
    ErrCode rc;

    LOGI("[LwM2M]\tMessage from the eIM received");
    LOG_DATA(eLogDebug, "[esim_iot_eim_message_write] EsipaMessageFromEimToIpa", eim_message, eim_message_size);

    if ((rc = esipa_async__execute_message((esipa_async_t*) context, (uint8_t*) eim_message, eim_message_size)) != eOk) { /* Upcast to superclass */
        LOGE("[esim_iot_eim_message_write] Failed to process the EsipaMessageFromEimToIpa, rc %d", rc);
        return -rc;
    } else {
        LOGD("[esim_iot_eim_message_write] EsipaMessageFromEimToIpa processed successfully");
        return 0;
    }
}

static int esim_iot_ipa_message_read(void* context, unsigned char **buffer, uint32_t *buffer_size) {
    esipa_lwm2m_t * const me_ = (esipa_lwm2m_t*) context;  /* explicit downcast */

    *buffer = me_->ipa_message;
    *buffer_size = me_->ipa_message_size;
    return 0;
}

static void esim_iot_clear_ipa_message_execute(void* context) {
    esipa_lwm2m_t * const me_ = (esipa_lwm2m_t*) context;  /* explicit downcast */

    M_free(me_->ipa_message);
    me_->ipa_message = NULL;
    me_->ipa_message_size = 0;
}
#endif
