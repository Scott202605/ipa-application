/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 * 
 *  @file esipa_async.h
 *  @brief This file implements the common behavior of the interface ESipa for asynchronous protocols.
 *  
 *  This file contains the representation of the ESipa Async class. This class must be inherited by other 
 *  subclasses that implement and manage a specific ESipa asynchronous communication protocol. 
 * 
 *  All procedures not related to a specific communication protocol must be executed in this file.
 * 
 *  @author Giesecke+Devrient Mobile Security
 *  @bug No known bugs.
 */
#pragma once
#if defined(ENABLE_MQTT) || defined(ENABLE_LWM2M)
#include "typedefs.h"
#include "esipa.h"

struct esipa_async_vtbl_s; /* forward declaration */

/* ESipa Async attributes... */
typedef struct {
    esipa_t super; /* <== inherits esipa */
    struct esipa_async_vtbl_s const *vptr; // ESipa Virtual Pointer to abstract functions
    bool on_retrieval_procedure;
    bool is_connected;
} esipa_async_t;

// Esipa Async Virtual table with the pointers to the virtual functions (interface) of ESipa Async
struct esipa_async_vtbl_s {
    // Function to establish the connection with the eIM.
    ErrCode(*esipa_async_connect) (esipa_async_t* const me);
    // Function to stop the connection with the eIM.
    ErrCode(*esipa_async_disconnect) (esipa_async_t* const me);
    // Function to keep alive the connection with the eIM (called continuously after the establish the connection).
    bool(*esipa_async_keep_alive) (esipa_async_t* const me);
    // Function to send a message to the eIM. The function must be in charge of freeing the memory of the message pointer by calling M_free() function.
    ErrCode(*esipa_async_send_message) (esipa_async_t* const me, uint8_t** message, uint32_t* message_size);
};

/**
 * This function creates an ESipa Async instance.
 * This function should be called only by an ESipa Async subclass.
 * See also esipa_async__destroy().
 * 
 * @param[out] me A pointer to a esipa_async_t structure. The object is populated with a valid ESipa Async instance.
 * @param[in] eim_id Points to a byte array with the eimId of the eIM. Not used in this version.
 * @param[in] eim_id_size Size of the eim_id byte array.
 * @param[in] fqdn A null-terminated string with the FQDN of eIM or intermediate server.
 * @param[in] port Port of the eIM or intermediate server.
 * @param[in] trusted_certificate_tls Points to a byte array with either the certificate of eIM, used for (D)TLS, 
 * or the certificate of the CA, where the encoding follows X.509 standard.
 * @param[in] trusted_certificate_tls_size Size of the trusted_certificate_tls byte array.
 * 
 * @return This function does not return any value.
*/
void esipa_async__ctor(esipa_async_t * const me, uint8_t* eim_id, uint8_t eim_id_size, char* fqdn, int port, uint8_t* trusted_certificate_tls, uint32_t trusted_certificate_tls_size, gsma_data_binding_t data_binding);

/**
 * This function is used to deallocate possible memory allocations made in esipa_async__ctor().
 * This function SHALL be called if the esipa_async__ctor() function has been called previously.
 * This function should be called only by an ESipa Sync subclass.
 * 
 * @param[in] me A valid ESipa Async handle from a successful call to esipa_async__ctor().
 * 
 * @return This function does not return any value.
*/
void esipa_async__destroy(esipa_async_t * const me);

/**
 * This function must be called when the connection with the eIM is established.
 * This function should be called only by an ESipa Async subclass.
 * 
 * @param[in] me A valid ESipa Async handle from a successful call to esipa_async__ctor().
 * 
 * @return eOk in case the procedure after establish the connection is done successfully. Otherwise, an error code is returned.
*/
ErrCode esipa_async__connected(esipa_async_t* const me);

/**
 * This function must be called when a connection lost with the eIM is detected.
 * This function should be called only by an ESipa Async subclass.
 * 
 * @param[in] me A valid ESipa Async handle from a successful call to esipa_async__ctor().
 * 
 * @return eOk in case the procedure after a connection lost is done successfully. Otherwise, an error code is returned.
*/
ErrCode esipa_async__connection_lost(esipa_async_t* const me);

/**
 * This function must be called when a message from the eIM is received.
 * This function should be called only by an ESipa Async subclass.
 * 
 * @param[in] me A valid ESipa Async handle from a successful call to esipa_async__ctor().
 * 
 * @return eOk in case the message is processed successfully. Otherwise, an error code is returned.
*/
ErrCode esipa_async__execute_message(esipa_async_t * const me, const uint8_t* message, const uint32_t message_size);
#endif
