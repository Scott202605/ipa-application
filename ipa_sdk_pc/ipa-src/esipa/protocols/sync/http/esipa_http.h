/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 * 
 *  @file esipa_http.h
 *  @brief This file implements the HTTP protocol for the interface ESipa.
 *  
 *  This file contains the representation of the HTTP ESipa class (a subclass of an ESipa Sync class, defined in esipa_sync.h).
 * 
 *  All procedures related to the HTTP communication protocol for the ESipa interface must be executed in this file.
 * 
 *  @author Giesecke+Devrient Mobile Security
 *  @bug No known bugs.
 */
#pragma once
#ifdef ENABLE_HTTP_ESIPA
#include "typedefs.h"
#include "esipa_sync.h"

typedef struct esipa_http_s {
    esipa_sync_t super; /* <== inherits esipa sync*/
    uint32_t http_timeout;
} esipa_http_t;

/**
 * This function creates a HTTP ESipa instance.
 * See also esipa_http__destroy()
 * 
 * @param[out] me A pointer to a esipa_http_t structure. The object is populated with a valid HTTP ESipa instance.
 * @param[in] fqdn A null-terminated string specifying the HTTP server IP address or host name.
 * @param[in] max_time_without_transmission Time that will elapse from receiving a noEimPackageAvailable until a new GetEimPackageRequest is sent.
 * 
 * @return eOk in case the HTTP ESipa instance has been created successfully. Otherwise, an error code is returned.
*/
void esipa_http__ctor(esipa_http_t * const me, char* fqdn, uint32_t max_time_without_transmission, gsma_data_binding_t data_binding,uint32_t http_timeout, uint32_t sync_sleep_time);

/**
 * This function is used to deallocate possible memory allocations made in esipa_http__ctor().
 * This function SHALL be called if the esipa_http__ctor() function has been called previously.
 * 
 * @param[in] me A valid ESipa HTTP handle from a successful call to esipa_http__ctor().
 * 
 * @return This function does not return any value.
*/
void esipa_http__destroy(esipa_http_t * const me);
#endif