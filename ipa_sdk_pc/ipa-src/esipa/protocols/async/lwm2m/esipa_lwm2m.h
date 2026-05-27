/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 * 
 *  @file esipa_lwm2m.h
 *  @brief This file implements the LwM2M protocol for the interface ESipa.
 *  
 *  This file contains the representation of the LwM2M ESipa class (a subclass of an ESipa Async class, defined in esipa_async.h).
 * 
 *  All procedures related to the LwM2M communication protocol for the ESipa interface must be executed in this file.
 * 
 *  @author Giesecke+Devrient Mobile Security
 *  @bug No known bugs.
 */
#pragma once
#ifdef ENABLE_LWM2M
#include "typedefs.h"
#include "esipa_async.h"
#include "lwm2m_client.h"
#include "tlv_lengths.h"

typedef struct esipa_lwm2m_s {
    esipa_async_t super; /* <== inherits esipa */
    /* attributes of the subclass */
    lwm2m_ipa_client_t client;  // LWM2M client structure, from the lwm2m client interface
    uint8_t* ipa_message;          // Pointer to a byte array with the last message that the IPA sent to the eIM. Used as the IPA message resource value of the eSIM IoT LwM2M object.  
    uint32_t ipa_message_size;  // Size of the ipa_message byte array
    bool dtls;                  // True if the LwM2M server use a DTLS connection
    bool bootstrap;             // True if the LwM2M server is a bootstrap server
    bool ipv4;                  // True if the address family identifier of the LwM2M server is IPv4. Otherwise we will assume that is IPv6.
    bool is_first_wakeup_msg;   // True if the first wake up message is not sent yet.
    char client_name[OCTET16 * 2 + 1]; // LwM2M client name
} esipa_lwm2m_t;

/**
 * This function creates a LwM2M ESipa instance.
 * See also esipa_lwm2m__destroy()
 * 
 * @param me A pointer to a esipa_lwm2m_t structure. The object is populated with a valid LwM2M ESipa instance.
 * @param hostname A null-terminated string specifying the LwM2M server IP address or host name.
 * @param port LwM2M server port
 * @param dtls True if the LwM2M server use a DTLS connection.
 * @param bootstrap True if the LwM2M server is a bootstrap server.
 * @param ipv4  True if the address family identifier of the LwM2M server is IPv4. Otherwise it is assumed that is IPv6.
 * @param client_name A null-terminated string specifying the LwM2M client name (usually called client endpoint). Can be NULL.
 * 
 * @return eOk in case the LwM2M ESipa instance has been created successfully. Otherwise, an error code is returned.
*/
ErrCode esipa_lwm2m__ctor(esipa_lwm2m_t * const me, char* hostname, int port, bool dtls, bool bootstrap, bool ipv4, const char* client_name, gsma_data_binding_t data_binding);

/**
 * This function is used to deallocate possible memory allocations made in esipa_lwm2m__ctor().
 * This function SHALL be called if the esipa_lwm2m__ctor() function has been called previously with a sucessful return value.
 * 
 * @param me A valid LwM2M ESipa instance from a successful call to esipa_lwm2m__ctor().
 * 
 * @return This function does not return any value.
*/
void esipa_lwm2m__destroy(esipa_lwm2m_t * const me);
#endif
