/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
/*
 * Implements an eSIM IoT object for SGP.32 support
 *
 * |  Object   |   ID   | Object version | LWM2M Version |       Object URN       | Inst. | Mand.|
 * |-----------+--------+----------------+---------------+------------------------+-------+------|
 * | eSIM IoT  |  3443  |      1.0       |      1.0      | urn:oma:lwm2m:ext:3443 | Single|  No  |
 *
 *  Resources:
 *
 *          Name         | ID | Oper. | Inst. | Mand.|  Type   | Range | Units | Description                                                                      |
 *  ---------------------+----+-------+-------+------+---------+-------+-------+----------------------------------------------------------------------------------+
 *  State                |  0 |   R   | Single|  Yes | Integer |       |       |                                                                                  |
 *  EID                  |  1 |   R   | Single|  Yes | String  |       |       |                                                                                  |
 *  eIM Message          |  2 |   W   | Single|  Yes | Opaque  |       |       |                                                                                  |
 *  IPA message          |  3 |   R   | Single|  Yes | Opaque  |       |       |                                                                                  |
 *  Clear IPA message    |  4 |   E   | Single|  Yes |         |       |       |                                                                                  |
 *
 */
#ifdef ENABLE_LWM2M
#include "object_esim_iot.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>
#include <unistd.h>
#include <pthread.h>

#include "tlv_lengths.h"
#include "log.h"
#include "memory_manager.h"

// Resource Id's:
#define RES_M_STATE             0
#define RES_M_EID               1
#define RES_M_EIM_MESSAGE       2
#define RES_M_IPA_MESSAGE       3
#define RES_M_CLEAR_IPA_MESSAGE 4

typedef struct th_execute_eim_message_args_s {
    esim_iot_eim_message_write_callback_t esipa_message_from_eim_to_ipa;
    unsigned char* eim_message;
    uint32_t eim_message_size;
    void* context;
} th_execute_eim_message_args_t;

typedef struct esim_iot_obj_user_data_s {
    lwm2m_esim_iot_callbacks_t callbacks;
    void* callbacks_context;
} esim_iot_obj_user_data_t;

static uint8_t prv_get_value(lwm2m_data_t * dataP,
                             esim_iot_obj_user_data_t * user_data)
{
    int err;
    uint8_t state = 0;
    unsigned char* ipa_message = NULL;
    uint32_t ipa_message_size = 0;
    char eid[OCTET16 * 2 + 1] = { 0 };
    LOGD("[LWM2M]\t[eSIM IoT] Get resource dataP(id=%u, type=%u)", dataP->id, dataP->type);

    switch (dataP->id)
    {
    case RES_M_STATE:
        LOGD("[LWM2M]\t[eSIM IoT] Get resource State");
        state = user_data->callbacks.read_state(user_data->callbacks_context);
        LOGD("[LWM2M]\t[eSIM IoT] State: %01X", state);
        lwm2m_data_encode_int((int64_t) state, dataP);
        return COAP_205_CONTENT;

    case RES_M_EID:
        LOGD("[LWM2M]\t[eSIM IoT] Get resource EID");
        if ((err = user_data->callbacks.read_eid(user_data->callbacks_context, eid, sizeof(eid))) < 0) {
            LOGE("[LWM2M]\t[eSIM IoT] Error reading the eid, err %d", err);
            return COAP_500_INTERNAL_SERVER_ERROR;
        }
        LOGD("[LWM2M]\t[eSIM IoT] EID: %s", eid);
        lwm2m_data_encode_string(eid, dataP);
        return COAP_205_CONTENT;

    case RES_M_EIM_MESSAGE:
        return COAP_405_METHOD_NOT_ALLOWED;

    case RES_M_IPA_MESSAGE:
        LOGD("[LWM2M]\t[eSIM IoT] Get resource IPA message");
        //TODO What if its NULL
        if ((err = user_data->callbacks.esipa_message_from_ipa_to_eim(user_data->callbacks_context, &ipa_message, &ipa_message_size)) < 0) {
            LOGE("[LWM2M]\t[eSIM IoT] Error reading the IPA message, err %d", err);
            return COAP_500_INTERNAL_SERVER_ERROR;
        }
        LOGD("[LWM2M]\t[eSIM IoT] IPA message read requested");
        LOG_DATA(eLogTrace, "[LWM2M]\t[eSIM IoT] IPA message", ipa_message, ipa_message_size);
        lwm2m_data_encode_opaque((uint8_t*) ipa_message, (size_t) ipa_message_size, dataP);
        return COAP_205_CONTENT;

    case RES_M_CLEAR_IPA_MESSAGE:
        return COAP_405_METHOD_NOT_ALLOWED;

    default:
        LOGW("[LWM2M]\t[eSIM IoT] Get resource NOT FOUND. id=%u", dataP->id);
        return COAP_404_NOT_FOUND;
    }
}

/**
  * Implementation (callback-) function of reading object resources. For whole
  * object, single resources or a sequence of resources
  * 
  * @param[in]     context unused pointer to LWM2M context
  * @param[in]     instance_id instance ID of the eSIM IoT object to read. Should be always zero (eSIM IoT is a single instance object)
  * @param[in,out] resources_num pointer to the number of resources to read. 0 is the exception for all readable resource of object instance.
  * @param[in,out] resources_data data sequence with initialized resource ID to read
  * @param[in]     lwm2m_object pointer to a LwM2M object that includes the private eSIM IoT data structure
  */
static uint8_t prv_esim_iot_read(lwm2m_context_t *context,
                                 uint16_t instance_id,
                                 int * resources_num,
                                 lwm2m_data_t ** resources_data,
                                 lwm2m_object_t * object)
{
    uint8_t result;
    int i;
    LOGD("[LWM2M]\t[eSIM IoT] Read operation over the eSIM IoT object (instance_id=%u, resources_num=%d)", instance_id, *resources_num);

    /* unused parameter */
    (void)context;

    // this is a single instance object
    if (instance_id != 0) {
        return COAP_404_NOT_FOUND;
    }

    // is the server asking for the full readable resources object ?
    if (*resources_num == 0) {
        uint8_t res_list[] = {
            RES_M_STATE,
            RES_M_EID,
            RES_M_IPA_MESSAGE
        };// readable resources!
        uint8_t num_read_res = sizeof(res_list)/sizeof(uint8_t);

        *resources_data = lwm2m_data_new(num_read_res);
        if (*resources_data == NULL) {
            return COAP_500_INTERNAL_SERVER_ERROR;
        }

        // init readable resource id's
        *resources_num = (int) num_read_res;
        for (i = 0 ; i < num_read_res ; i++) {
            (*resources_data)[i].id = (uint32_t) res_list[i];
        }
    }

    i = 0;
    do
    {
        result = prv_get_value((*resources_data) + i, (esim_iot_obj_user_data_t*)(object->userData));
        i++;
    } while (i < *resources_num && result == COAP_205_CONTENT);

    return result;
}

static uint8_t prv_esim_iot_discover(lwm2m_context_t *context,
                                     uint16_t instance_id,
                                     int * resources_num,
                                     lwm2m_data_t ** resources_data,
                                     lwm2m_object_t * object)
{
    int i;

    /* unused parameter */
    (void)context;

    //TODO: Should we check if instance_id != 0 ?

    // is the server asking for the full object ?
    if (*resources_num == 0)
    {
        uint8_t res_list[] = {
            RES_M_STATE,
            RES_M_EID,
            RES_M_EIM_MESSAGE,
            RES_M_IPA_MESSAGE,
            RES_M_CLEAR_IPA_MESSAGE
        };// all resources!
        uint8_t num_read_res = sizeof(res_list)/sizeof(uint8_t);

        *resources_data = lwm2m_data_new(num_read_res);
        if (*resources_data == NULL) {
            return COAP_500_INTERNAL_SERVER_ERROR;
        }

        // init resource id's
        *resources_num = (int) num_read_res;
        for (i = 0 ; i < num_read_res ; i++) {
            (*resources_data)[i].id = (uint32_t) res_list[i];
        }
    }
    else
    {
        for (i = 0; i < *resources_num; i++)
        {
            switch ((*resources_data)[i].id)
            {
            case 1:
            case 2:
            case 3:
            case 5:
                break;
            default:
                return COAP_404_NOT_FOUND;
            }
        }
    }

    return COAP_205_CONTENT;
}

static void * execute_eim_message(void* execute_eim_message_args) {
    int err = ((th_execute_eim_message_args_t*)execute_eim_message_args)->esipa_message_from_eim_to_ipa(((th_execute_eim_message_args_t*)execute_eim_message_args)->context,
        ((th_execute_eim_message_args_t*)execute_eim_message_args)->eim_message, ((th_execute_eim_message_args_t*)execute_eim_message_args)->eim_message_size);
    if (err < 0) {
        LOGE("[LWM2M]\t[eSIM IoT] Error processing the eIM Message");
    }
    M_free(((th_execute_eim_message_args_t*)execute_eim_message_args)->eim_message);
    M_free(execute_eim_message_args);

    return NULL;
}

static uint8_t prv_write_eim_message(lwm2m_data_t * write_data,
                                     esim_iot_obj_user_data_t * user_data)
{
    th_execute_eim_message_args_t* th_args;
    pthread_t th;

    LOGD("[LWM2M]\t[eSIM IoT] eIM message received");
    LOG_DATA(eLogDebug, "[LWM2M]\t[eSIM IoT] eIM message received", write_data->value.asBuffer.buffer, write_data->value.asBuffer.length);

    // Check if the datatype is correct
    if (write_data->type != LWM2M_TYPE_OPAQUE) {
        return COAP_400_BAD_REQUEST;
    }

    // Allocate memory to store the thread data
    th_args = M_malloc(sizeof(th_execute_eim_message_args_t));
    if (!th_args) {
        LOGE("[LWM2M]\t[eSIM IoT] Error allocating data to the thread args");
        return COAP_500_INTERNAL_SERVER_ERROR;
    }
    th_args->esipa_message_from_eim_to_ipa = user_data->callbacks.esipa_message_from_eim_to_ipa;
    th_args->context = user_data->callbacks_context;

    // Allocate memory to store the received eIM message
    th_args->eim_message = M_malloc(write_data->value.asBuffer.length);
    if (!th_args->eim_message) {
        LOGE("[LWM2M]\t[eSIM IoT] Error allocating data to store the eIM message received");
        M_free(th_args);
        return COAP_500_INTERNAL_SERVER_ERROR;
    }
    // Copy the eIM message
    memcpy(th_args->eim_message, write_data->value.asBuffer.buffer, write_data->value.asBuffer.length);
    th_args->eim_message_size = write_data->value.asBuffer.length;

    
    // Free the last ipa message generated
    /*M_free(esim_iot_data->ipa_message);
    esim_iot_data->ipa_message = NULL;
    esim_iot_data->ipa_message_size = 0;*/

    pthread_create(&th, NULL, execute_eim_message, (void*) th_args);

    return COAP_204_CHANGED;

}

static uint8_t prv_esim_iot_write(lwm2m_context_t *context,
                                  uint16_t instance_id,
                                  int resources_num,
                                  lwm2m_data_t * resources_data,
                                  lwm2m_object_t * object,
                                  lwm2m_write_type_t write_type)
{
    int i;
    uint8_t result;

    /* unused parameter */
    (void)context;

    // All write types are treated the same here
    (void)write_type;

    // this is a single instance object
    if (instance_id != 0)
    {
        return COAP_404_NOT_FOUND;
    }

    i = 0;
    do
    {
        /* No multiple instance resources */
        if (resources_data[i].type == LWM2M_TYPE_MULTIPLE_RESOURCE)
        {
            result = COAP_404_NOT_FOUND;
            continue;
        }

        switch (resources_data[i].id)
        {
        case RES_M_STATE:
            result = COAP_405_METHOD_NOT_ALLOWED;
            break;
        case RES_M_EID:
            result = COAP_405_METHOD_NOT_ALLOWED;
            break;
        case RES_M_EIM_MESSAGE:
            result = prv_write_eim_message(&resources_data[i], (esim_iot_obj_user_data_t*)(object->userData));
            break;
        case RES_M_IPA_MESSAGE:
            result = COAP_405_METHOD_NOT_ALLOWED;
            break;
        case RES_M_CLEAR_IPA_MESSAGE:
            result = COAP_405_METHOD_NOT_ALLOWED;
            break;

        default:
            result = COAP_404_NOT_FOUND;
        }

        i++;
    } while (i < resources_num && result == COAP_204_CHANGED);

    return result;
}

static uint8_t prv_esim_iot_execute(lwm2m_context_t *context,
                        uint16_t instance_id,
                        uint16_t resourceId,
                        uint8_t * buffer,
                        int length,
                        lwm2m_object_t * object)
{
    /* unused parameter */
    (void)context;

    // this is a single instance object
    if (instance_id != 0) {
        return COAP_404_NOT_FOUND;
    }

    if (length != 0) {
        return COAP_400_BAD_REQUEST;
    }

    switch (resourceId)
    {
    case RES_M_STATE:
        return COAP_405_METHOD_NOT_ALLOWED;
    case RES_M_EID:
        return COAP_405_METHOD_NOT_ALLOWED;
    case RES_M_EIM_MESSAGE:
        return COAP_405_METHOD_NOT_ALLOWED;
    case RES_M_IPA_MESSAGE:
        return COAP_405_METHOD_NOT_ALLOWED;
    case RES_M_CLEAR_IPA_MESSAGE:
        LOGD("[LWM2M]\t[eSIM IoT] Execute Clear IPA message");
        ((esim_iot_obj_user_data_t*)object->userData)->callbacks.clear_ipa_message(((esim_iot_obj_user_data_t*)object->userData)->callbacks_context);
        return COAP_204_CHANGED;
    default:
        return COAP_404_NOT_FOUND;
    }
}

/*
 * The get_esim_iot_object function create the object itself and return a pointer to the structure that represent it.
 */
lwm2m_object_t * get_esim_iot_object(lwm2m_esim_iot_callbacks_t* callbacks, void* context)
{
    lwm2m_object_t * esim_iot_obj;

    esim_iot_obj = (lwm2m_object_t *)M_malloc(sizeof(lwm2m_object_t));

    if (!esim_iot_obj) {
        return NULL;
    }

    memset(esim_iot_obj, 0, sizeof(lwm2m_object_t));

    // Assign his unique ID
    esim_iot_obj->objID = ESIM_IOT_OBJECT_ID;

    /**
     * TODO: Should we add the version?
     *  esim_iot_obj->versionMajor = 1;
     *  esim_iot_obj->versionMinor = 0;
    */

    // Assign his unique instance
    esim_iot_obj->instanceList = (lwm2m_list_t *)M_malloc(sizeof(lwm2m_list_t));
    if (!esim_iot_obj->instanceList) {
        M_free(esim_iot_obj);
        return NULL;
    }

    memset(esim_iot_obj->instanceList, 0, sizeof(lwm2m_list_t));

    /*
     * Assign the private function that will access the object. 
     * Those function will be called when a read/write/execute query is made by the server.
    */
    esim_iot_obj->readFunc     = prv_esim_iot_read;
    esim_iot_obj->discoverFunc = prv_esim_iot_discover;
    esim_iot_obj->writeFunc    = prv_esim_iot_write;
    esim_iot_obj->executeFunc  = prv_esim_iot_execute;

    // Assign user data in the object with a private structure containing the needed variables
    esim_iot_obj->userData = M_malloc(sizeof(esim_iot_obj_user_data_t));
    if (!esim_iot_obj->userData) {
        M_free(esim_iot_obj->instanceList);
        M_free(esim_iot_obj);
        return NULL;
    }
    // Copy all the callbacks and callback context
    ((esim_iot_obj_user_data_t*)esim_iot_obj->userData)->callbacks.read_state = callbacks->read_state;
    ((esim_iot_obj_user_data_t*)esim_iot_obj->userData)->callbacks.read_eid = callbacks->read_eid;
    ((esim_iot_obj_user_data_t*)esim_iot_obj->userData)->callbacks.esipa_message_from_eim_to_ipa = callbacks->esipa_message_from_eim_to_ipa;
    ((esim_iot_obj_user_data_t*)esim_iot_obj->userData)->callbacks.esipa_message_from_ipa_to_eim = callbacks->esipa_message_from_ipa_to_eim;
    ((esim_iot_obj_user_data_t*)esim_iot_obj->userData)->callbacks.clear_ipa_message = callbacks->clear_ipa_message;
    ((esim_iot_obj_user_data_t*)esim_iot_obj->userData)->callbacks_context = context;

    return esim_iot_obj;
}

void free_esim_iot_object(lwm2m_object_t * object)
{
    M_free(object->userData);
    M_free(object->instanceList);
    M_free(object);
}
#endif
