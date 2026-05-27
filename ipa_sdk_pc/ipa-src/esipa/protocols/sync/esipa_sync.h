/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 * 
 *  @file esipa_sync.h
 *  @brief This file implements the common behavior of the interface ESipa for synchronous protocols.
 *  
 *  This file contains the representation of the ESipa Sync class. This class must be inherited by other 
 *  subclasses that implement and manage a specific ESipa synchronous communication protocol. 
 * 
 *  All procedures not related to a specific communication protocol must be executed in this file.
 * 
 *  @author Giesecke+Devrient Mobile Security
 *  @bug No known bugs.
 */
#pragma once
#if defined(ENABLE_HTTP_ESIPA)
#include "typedefs.h"
#include "esipa.h"

#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
#define ESIPA_PATH_INITIATE_AUTHENTICATION      "/gsma/rsp2/esipa/initiateAuthentication"
#define ESIPA_PATH_AUTHENTICATE_CLIENT          "/gsma/rsp2/esipa/authenticateClient"
#define ESIPA_PATH_GET_BOUND_PROFILE_PACKAGE    "/gsma/rsp2/esipa/getBoundProfilePackage"
#define ESIPA_PATH_CANCEL_SESSION               "/gsma/rsp2/esipa/cancelSession"
#endif
#define ESIPA_PATH_GET_EIM_PACKAGE              "/gsma/rsp2/esipa/getEimPackage"
#define ESIPA_PATH_PROVIDE_EIM_PACKAGE_RESULT   "/gsma/rsp2/esipa/provideEimPackageResult"
#define ESIPA_PATH_HANDLE_NOTIFICATION          "/gsma/rsp2/esipa/handleNotification"


struct esipa_sync_vtbl_s; /* forward declaration */

/* ESipa Sync attributes... */
typedef struct {
    esipa_t super; /* <== inherits esipa */
    struct esipa_sync_vtbl_s const *vptr; // ESipa Virtual Pointer to abstract functions
    uint32_t max_time_without_transmission;
    uint32_t sync_sleep_time;
} esipa_sync_t;

// Esipa Sync Virtual table with the pointers to the virtual functions (interface) of ESipa Sync
struct esipa_sync_vtbl_s {
    /**
     * Function to send a message to the eIM. The caller is the responsible for freeing the response_body by calling the M_free() function.
     * The function may also free the request_body pointer to optimize the usage of memory.
     */
    ErrCode(*esipa_sync_send_message) (esipa_sync_t* const me, const char* path, unsigned char** request_body, uint32_t* request_body_size, unsigned char** response_body, uint32_t* response_body_size);
};

/**
 * This function creates an ESipa Sync instance.
 * This function should be called only by an ESipa Sync subclass.
 * See also esipa_sync__destroy().
 * 
 * @param[out] me A pointer to a esipa_sync_t structure. The object is populated with a valid ESipa Sync instance.
 * @param[in] eim_id Points to a byte array with the eimId of the eIM. Not used in this version.
 * @param[in] eim_id_size Size of the eim_id byte array.
 * @param[in] fqdn A null-terminated string with the FQDN of eIM or intermediate server.
 * @param[in] trusted_certificate_tls Points to a byte array with either the certificate of eIM, used for (D)TLS, 
 * or the certificate of the CA, where the encoding follows X.509 standard.
 * @param[in] trusted_certificate_tls_size Size of the trusted_certificate_tls byte array.
 * @param max_time_without_transmission Time that will elapse from receiving a noEimPackageAvailable until a new GetEimPackageRequest is sent.
 * 
 * @return This function does not return any value.
*/
void esipa_sync__ctor(esipa_sync_t * const me, uint8_t* eim_id, uint8_t eim_id_size, char* fqdn, uint8_t* trusted_certificate_tls, uint32_t trusted_certificate_tls_size, uint32_t max_time_without_transmission, gsma_data_binding_t data_binding, uint32_t sync_sleep_time);

/**
 * This function is used to deallocate possible memory allocations made in esipa_sync__ctor().
 * This function SHALL be called if the esipa_sync__ctor() function has been called previously.
 * This function should be called only by an ESipa Sync subclass.
 * 
 * @param[in] me A valid ESipa Sync handle from a successful call to esipa_sync__ctor().
 * 
 * @return This function does not return any value.
*/
void esipa_sync__destroy(esipa_sync_t * const me);
#endif
