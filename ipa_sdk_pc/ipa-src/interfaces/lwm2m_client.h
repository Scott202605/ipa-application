/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 *
 *  @file lwm2m_client.h
 *  @brief lwm2m interface, describing the necessary operations related to the lwm2m protocol for the specific SGP.32 use case.
 *  
 *  The functions described in this interface needs to be implemented in for each hardware specific
 * 
 *  @author Giesecke+Devrient Mobile Security
 *  @bug No known bugs.
*/
#pragma once
#ifdef ENABLE_LWM2M
#include "ipa_typedefs.h"

typedef void (*lwm2m_client_connected_t) (void* context);
typedef void (*lwm2m_client_connection_lost_notification_callback_t) (void* context);
typedef uint8_t (*esim_iot_state_read_callback_t) (void* context);
typedef int (*esim_iot_eid_read_callback_t) (void* context, char *buffer, uint32_t buffer_size);
typedef int (*esim_iot_eim_message_write_callback_t) (void* context, const unsigned char *eim_message, const uint32_t eim_message_size);
typedef int (*esim_iot_ipa_message_read_callback_t) (void* context, unsigned char **buffer, uint32_t *buffer_size);
typedef void (*esim_iot_clear_ipa_message_execute_callback_t) (void* context);

typedef struct lwm2m_esim_iot_callbacks_s {
    esim_iot_state_read_callback_t read_state;
    esim_iot_eid_read_callback_t read_eid;
    esim_iot_eim_message_write_callback_t esipa_message_from_eim_to_ipa;
    esim_iot_ipa_message_read_callback_t esipa_message_from_ipa_to_eim;
    esim_iot_clear_ipa_message_execute_callback_t clear_ipa_message;
} lwm2m_esim_iot_callbacks_t;

typedef struct lwm2m_client_s {
    void* lwm2m_client_handler; // Hardware specific lwm2m client handler. In first position to allow downcast
    char* server_hostname;      // LwM2M server IP address or hostname
    int server_port;            // LwM2M server port number
    char* client_name;          // LwM2M client name (usually called client endpoint)
    int life_time;              // Lifetime of the registration in seconds
    bool bootstrap_server;      // True if the LwM2M server is a bootstrap server
    lwm2m_client_connected_t connected_callback;  // Callback called on a sucessful conection to a LwM2M server
    lwm2m_client_connection_lost_notification_callback_t connection_lost_callback;  // Callback called on a connection lost between the client and the LwM2M server
    lwm2m_esim_iot_callbacks_t esim_iot_callbacks;  // Callbacks to handle the eSIM IoT LwM2M object (SGP.32 use case)
    void* context;              // Context passed to the connected_callback & esim_iot_callbacks functions
} lwm2m_ipa_client_t;

/**
 * This function creates an LwM2M client ready for connection to the specified server.
 * See also lwm2m_destroy()
 * 
 * @param me A pointer to a lwm2m_ipa_client_t structure. The object is populated with a valid client reference following a successful return from this function.
 * @param address A null-terminated string specifying the LwM2M server IP address or host name.
 * @param port LwM2M server port number
 * @param dtls True if the LwM2M server use a DTLS connection.
 * @param is_bootstrap_server True if the LwM2M server is a bootstrap server.
 * @param ipv4  True if the address family identifier of the LwM2M server is IPv4. Otherwise it is assumed that is IPv6.
 * @param client_name A null-terminated string specifying the LwM2M client name (usually called client endpoint). Can be NULL.
 * @param life_time Lifetime of the registration to the LwM2M server in seconds.
 * @param connected_function A pointer to an lwm2m_client_connected_t() callback function. This function will be called when the LwM2M client is connected sucessfully to a LwM2M server.
 * @param connection_lost_function A pointer to an lwm2m_client_connection_lost_notification_callback_t() callback function. This function will be called when the client is disconnected from the broker due a connection lost.
 * After the call to this callback, the client will try internally to recover the connection.
 * @param read_state_function A pointer to an esim_iot_state_read_callback_t() callback function. This function will be called when the client receive a read operation for the resource 'State' on the eSIM IoT LwM2M object.
 * @param read_eid_function A pointer to an esim_iot_eid_read_callback_t() callback function. This function will be called when the client receive a read operation for the resource 'EID' on the eSIM IoT LwM2M object.
 * @param write_eim_message A pointer to an esim_iot_eim_message_write_callback_t() callback function. This function will be called when the client receive a write operation for the resource 'eIM message' on the eSIM IoT LwM2M object.
 * @param read_ipa_message A pointer to an esim_iot_ipa_message_read_callback_t() callback function. This function will be called when the client receive a read operation for the resource 'IPA message' on the eSIM IoT LwM2M object.
 * @param execute_clear_ipa_message A pointer to an esim_iot_clear_ipa_message_execute_callback_t() callback function. This function will be called when the client receive a execute operation for the resource 'Clear IPA message' on the eSIM IoT LwM2M object.
 * @param callbacks_context A pointer to any application-specific context. The callbacks_context pointer is passed to each of the callback functions as context to provide access to the callbacks_context information in the callback function.
 * 
 * @return 0 if the client is successfully created, otherwise a negative error code is returned.
*/
int lwm2m_create_client(lwm2m_ipa_client_t* const me, char* address, int port, bool dtls, bool is_bootstrap_server, bool ipv4, char* client_name, int life_time, lwm2m_client_connected_t connected_function,
                        lwm2m_client_connection_lost_notification_callback_t connection_lost_function, esim_iot_state_read_callback_t read_state_function, esim_iot_eid_read_callback_t read_eid_function, esim_iot_eim_message_write_callback_t write_eim_message, 
                        esim_iot_ipa_message_read_callback_t read_ipa_message, esim_iot_clear_ipa_message_execute_callback_t execute_clear_ipa_message, void* callbacks_context);

/**
 * This function initialize/configure the previously-created client (see lwm2m_create_client()).
 * 
 * @param me A valid client handle from a successful call to lwm2m_create_client().
 * 
 * @return 0 if the init is successful, otherwise a negative error code is returned.
*/
int lwm2m_initialize(lwm2m_ipa_client_t* const me);

/**
 * This function is used to start and mantain a conection against a LwM2M server.
 * 
 * This function must be called repeatedly to maintain the connection to the LwM2M server until it returns false.
 * 
 * Once the connection to the server is established, this function will call the connected callback 
 * function passed on the lwm2m_create_client function.
 * 
 * @param me A valid client handle from a successful call to lwm2m_create_client() and lwm2m_initialize().
 * 
 * @return true if the connection should be maintained (call this same function again). false if the connection process should be aborted. 
*/
bool lwm2m_connect(lwm2m_ipa_client_t* const me);

/**
 * This function implements the "Send" operation of the Information Reporting Interface defined in the LwM2M 1.1 specification.
 * 
 * The "Send" operation can be used by the LwM2M Client to report values for Resources and Resource Instances of
 * LwM2M Object Instance(s) to the LwM2M Server without explicit request by that Server.
 * 
 * @param me A valid client handle from a successful call to lwm2m_create_client() and lwm2m_initialize(). Also the client must be successfully connected to a server to execute this function.
 * @param object_id Object ID of the resource to be sent to the LwM2M server.
 * @param object_instance_id Object Instance ID of the resource to be sent to the LwM2M server. 0 if the object is single instance.
 * @param resource_id Resource ID to be sent to the LwM2M server.
 * @param resource_instance_id Resource Instance ID to be sent to the LwM2M server. 0 if the resource is single instance.
 *
 * @return 0 if the send operation request is successful, otherwise a negative error code is returned.
*/
int lwm2m_send_operation(lwm2m_ipa_client_t* const me, const uint16_t object_id, const uint16_t object_instance_id, const uint16_t resource_id, const int16_t resource_instance_id);

/**
 * This function attempts to disconnect the client from the LwM2M server.
 * 
 * @param me A valid client handle from a successful call to lwm2m_create_client().
 * 
 * @return 0 if the disconnect request is successful, or a negative error code.
*/
int lwm2m_disconnect(lwm2m_ipa_client_t* const me);

/**
 * This function is used to deallocate possible memory allocations made in lwm2m_create_client()
 * 
 * @param me A valid client handle from a successful call to lwm2m_create_client().
 * 
 * @return This function does not return any value.
*/
void lwm2m_destroy(lwm2m_ipa_client_t* const me);
#endif
