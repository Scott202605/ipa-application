/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 * 
 *  @file esipa_mqtt.h
 *  @brief This file implements the MQTT protocol for the interface ESipa.
 *  
 *  This file contains the representation of the MQTT ESipa class (a subclass of an ESipa Async class, defined in esipa_async.h).
 * 
 *  All procedures related to the MQTT communication protocol for the ESipa interface must be executed in this file.
 * 
 *  @author Giesecke+Devrient Mobile Security
 *  @bug No known bugs.
 */
#pragma once
#ifdef ENABLE_MQTT
#include "typedefs.h"
#include "esipa_async.h"
#include "mqtt_client.h"

typedef struct esipa_mqtt_s {
    esipa_async_t super; /* <== inherits esipa async*/
    /* attributes of the subclass */
    mqtt_client_t client;  // MQTT client structure, from the mqtt client interface
    char* protocol; // MQTT broker protocol.
    char* username; // MQTT broker username, can be NULL
    char* password; // MQTT broker password, can be NULL
    char eid[OCTET16 * 2 + 1]; //Client id
} esipa_mqtt_t;

/**
 * This function creates a MQTT ESipa instance.
 * See also esipa_mqtt__destroy()
 * 
 * @param me A pointer to a esipa_mqtt_t structure. The object is populated with a valid MQTT ESipa instance.
 * @param protocol A null-terminated string specifying the MQTT server protocol. E.g. 'tcp', 'ssl', 'ws', 'wss', 'mqtt', 'mqtts'...
 * @param fqdn A null-terminated string specifying the MQTT server IP address or host name.
 * @param port MQTT server port
 * @param username A null-terminated string specifying the MQTT username. Can be NULL.
 * @param password A null-terminated string specifying the MQTT password. Can be NULL.
 * @param tls_config Points to a hardware-specific MQTT TLS configuration structure. Can be NULL.
 * @param proxy_config Points to a hardware-specific MQTT proxy configuration structure. Can be NULL.
 * 
 * @return eOk in case the MQTT ESipa instance has been created successfully. Otherwise, an error code is returned.
*/
ErrCode esipa_mqtt__ctor(esipa_mqtt_t * const me, char* protocol, char* fqdn, int port, char* username, char* password, mqtt_tls_config_t* tls_config, mqtt_proxy_config_t* proxy_config, gsma_data_binding_t data_binding);

/**
 * This function is used to deallocate possible memory allocations made in esipa_mqtt__ctor().
 * This function SHALL be called if the esipa_mqtt__ctor() function has been called previously.
 * 
 * @param[in] me A valid ESipa MQTT handle from a successful call to esipa_mqtt__ctor().
 * 
 * @return This function does not return any value.
*/
void esipa_mqtt__destroy(esipa_mqtt_t * const me);
#endif
