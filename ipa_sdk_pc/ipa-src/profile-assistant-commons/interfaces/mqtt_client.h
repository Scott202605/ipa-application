/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 * 
 *  @file mqtt_client.h
 *  @brief mqtt interface, describing the necessary operations related to the mqtt protocol
 *  
 *  The functions described in this interface needs to be implemented in for each hardware specific
 * 
 *  @author Giesecke+Devrient Mobile Security
 *  @bug No known bugs.
*/
#pragma once
#ifdef ENABLE_MQTT
#include "typedefs.h"

/* Opaque structures (Each hardware must define its own, taking into account the needs of the library it uses) */
typedef struct mqtt_tls_config_s mqtt_tls_config_t;
typedef struct mqtt_proxy_config_s mqtt_proxy_config_t;

/* Callbacks to be executed outside client implementation */
typedef ErrCode (*mqtt_connect_callback_t) (void* const context);
typedef void (*mqtt_connection_lost_notification_callback_t) (void* const context);
typedef ErrCode (*mqtt_message_arrived_callback_t) (void* const context, unsigned char *topic, size_t topic_len, unsigned char* message, uint32_t message_size);

/* Structure with all the data of the interface initialized in the create, public because is common in all the hw impl */
typedef struct mqtt_client_s {
    void* mqtt_client_handler; /* Hardware specific mqtt client handler. In first position to allow downcast */
    mqtt_connect_callback_t connect_function;                   // Client connected callback function
    mqtt_connection_lost_notification_callback_t connection_lost_function;
    mqtt_message_arrived_callback_t message_arrived_function;   // Message arrived callback function
    void* user_data;    // Store useful developer data here
    char* protocol;     // MQTT broker protocol. e.g. 'tcp', 'ssl', 'mqtt', 'mqtts'...
    char* address;      // MQTT broker IP address or hostname
    int port;           // MQTT broker port
    char* client_id;    // Client id used to connect to the MQTT broker
    char* username;     // Username used to connect to the MQTT broker. Can be NULL
    char* password;     // Password used to connect to the MQTT broker. Can be NULL
    mqtt_tls_config_t* tls_config;
    mqtt_proxy_config_t* proxy_config;
} mqtt_client_t;

/**
 * This function creates an MQTT client ready for connection to the specified server.
 * See also MQTT_destroy()
 * 
 * @param me A pointer to a mqtt_client_t structure. The object is populated with a valid client reference following a successful return from this function.
 * @param protocol A null-terminated string specifying the MQTT server protocol. E.g. 'tcp', 'ssl', 'ws', 'wss', 'mqtt', 'mqtts'...
 * @param address A null-terminated string specifying the MQTT server IP address or host name.
 * @param port MQTT server port
 * @param client_id The client identifier passed to the server when the client connects to it. It is a null-terminated UTF-8 encoded string.
 * @param connect_callback_func A pointer to an mqtt_connect_callback_t() callback function. This function will be called when the client is connected to the broker.
 * @param connection_lost_notification_callback_func A pointer to an mqtt_connection_lost_notification_callback_t() callback function. This function will be called when the client is disconnected from the broker due a connection lost.
 * After the call to this callback, the client will try internally to recover the connection.
 * @param message_arrived_callback_func A pointer to an mqtt_message_arrived_callback_t() callback function. This function will be called when the client receive a MQTT message.
 * @param user_data A pointer to any application-specific context. The user_data pointer is passed to each of the callback functions as context to provide access to the user_data information in the callback.
 * 
 * @return 0 if the client is successfully created, otherwise a negative error code is returned.
*/
int MQTT_create_client(mqtt_client_t* const me, char* protocol, char* address, int port, char* client_id, mqtt_connect_callback_t connect_callback_func, mqtt_connection_lost_notification_callback_t connection_lost_notification_callback_func, mqtt_message_arrived_callback_t message_arrived_callback_func, void* user_data);

/**
 * This funtion adds the username and password authentication credentials to a previously-created client (see MQTT_create_client())
 * 
 * @param me A valid client handle from a successful call to MQTT_create_client().
 * @param username A null-terminated string specifying the MQTT username.
 * @param password A null-terminated string specifying the MQTT password.
 * 
 * @return 0 if the client credentials are successfully configured on the client, otherwise a negative error code is returned.
*/
int MQTT__set_broker_credentials(mqtt_client_t* const me, char* username, char* password);

/**
 * This funtion adds the TLS configuration to a previously-created client (see MQTT_create_client())
 * 
 * @param me A valid client handle from a successful call to MQTT_create_client().
 * @param config Pointer to a hardware-specific structure to configure the TLS in the MQTT client.
 * 
 * @return 0 if the TLS is successfully configured on the client, otherwise a negative error code is returned.
*/
int MQTT__set_tls_config(mqtt_client_t* const me, mqtt_tls_config_t* config);

/**
 * This funtion adds the proxy configuration to a previously-created client (see MQTT_create_client())
 * 
 * @param me A valid client handle from a successful call to MQTT_create_client().
 * @param config Pointer to a hardware-specific structure to configure the proxy in the MQTT client.
 * 
 * @return 0 if the proxy settings are successfully configured on the client, otherwise a negative error code is returned.
*/
int MQTT__set_proxy_config(mqtt_client_t* const me, mqtt_proxy_config_t* config);

/**
 * Attempts to connect a previously-created client (see MQTT_create_client()) to an MQTT server.
 * 
 * @param me A valid client handle from a successful call to MQTT_create_client().
 * 
 * @return 0 if the connect request is successful, otherwise a negative error code is returned.
*/
int MQTT_connect(mqtt_client_t* const me);

/**
 * This function attempts to publish a message to a given topic
 * 
 * @param me A valid client handle from a successful call to MQTT_create_client().
 * @param topic A null-terminated string specifying the topic where the message will be published.
 * @param message Pointer to a byte array with the content of the message to publish.
 * @param message_len The length of the message byte array in bytes.
 * @param qos The QoS of the message to publish.
 * 
 * @return 0 if the publish request is successful, or a negative error code.
*/
int MQTT_publish_message(mqtt_client_t* const me, const char* topic, const unsigned char* message, const size_t message_len, int qos);

/**
 * This function attempts to subscribe a client to a single topic.
 * 
 * @param me A valid client handle from a successful call to MQTT_create_client().
 * @param topic A null-terminated string specifying the topic to suscribe.
 * @param qos The requested QoS for the subscription.
 * 
 * @return 0 if the subscription request is successful, or a negative error code.
*/
int MQTT_subscribe_topic(mqtt_client_t* const me, char* topic, int qos);

/**
 * This function attempts to remove an existing subscription made by the client
 * 
 * @param me A valid client handle from a successful call to MQTT_create_client().
 * @param topic A null-terminated string specifying the topic to unsubscribe.
 * @param qos The requested QoS for the unsubscription.
 * 
 * @return 0 if the unsubscription request is successful, or a negative error code.
*/
int MQTT_unsubscribe_topic(mqtt_client_t* const me, char* topic, int qos);

/**
 * This function defines a condition to keep the main program running, preventing the main program 
 * from terminating or the client from disconnecting. This function can be used to make the client 
 * send the keep alive packages to the broker.
 * 
 * @param me A valid client handle from a successful call to MQTT_create_client().
 * 
 * @return true if is wanted to keep the client alive. Otherwise return false.
*/
bool MQTT_wait_thread_condition(mqtt_client_t* const me);

/**
 * This function attempts to disconnect the client from the MQTT server.
 * 
 * @param me A valid client handle from a successful call to MQTT_create_client().
 * 
 * @return 0 if the disconnect request is successful, or a negative error code.
*/
int MQTT_disconnect(mqtt_client_t* const me);

/**
 * This function is used to deallocate possible memory allocations made in MQTT_create_client()
 * 
 * @param me A valid client handle from a successful call to MQTT_create_client().
 * 
 * @return This function does not return any value.
*/
void MQTT_destroy(mqtt_client_t* const me);
#endif