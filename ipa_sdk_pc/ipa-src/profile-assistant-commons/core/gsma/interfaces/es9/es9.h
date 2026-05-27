/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"
#include "es9_typedefs.h"
#include "gsma_typedefs.h"

typedef struct es9_s {
    gsma_data_binding_t data_binding;
} es9_t;

/**
 * This function creates an ES9 instance.
 * @note A default value for the ES9 data binding is set on the constructor.
 * 
 * @param[in] es9 Pointer to a es9_t structure. The object is populated with a valid ES9 instance.
*/
void es9__ctor(es9_t * const es9);

/**
 * This function sets JSON format as the data binding for the ES9 interface.
 * 
 * @param[in] es9 A valid ES9 handle from a successful call to es9__ctor().
*/
void es9__set_json_data_binding(es9_t * const es9);

/**
 * This funtion executes the InitiateAuthentication function defined in the ES9+ interface of the SGP.22.
 * 
 * @param[in]  es9 interface A valid ES9 handle from a successful call to es9__ctor().
 * @param[in]  smdp_address null-terminated string with the SM-DP+ Address.
 * @param[in]  request pointer to an initiate_authentication_request_t structure populated with the input data.
 * @param[out] response pointer to an initiate_authentication_response_t structure that will be populated with 
 * the output data if the function return is success. The caller is the responsible for freeing this structure 
 * if the function return is success by calling the es9__free_initiate_authentication_response().
 * 
 * @return eOk in case the ES9+.InitiateAuthentication funtion has been executed successfully. 
 * Otherwise, an error code is returned.
*/
ErrCode es9__initiate_authentication(es9_t * const es9, const char* smdp_address, const initiate_authentication_request_t* request, initiate_authentication_response_t* response);

/**
 * This funtion executes the AuthenticateClient function defined in the ES9+ interface of the SGP.22.
 * 
 * @param[in]  es9 interface A valid ES9 handle from a successful call to es9__ctor().
 * @param[in]  smdp_address null-terminated string with the SM-DP+ Address.
 * @param[in]  request pointer to an authenticate_client_request_t structure populated with the input data.
 * @param[out] response pointer to an authenticate_client_response_es9_t structure that will be populated with 
 * the output data if the function return is success. The caller is the responsible for freeing this structure 
 * if the function return is success by calling the es9__free_authenticate_client_response().
 * 
 * @return eOk in case the ES9+.AuthenticateClient funtion has been executed successfully. 
 * Otherwise, an error code is returned.
*/
ErrCode es9__authenticate_client(es9_t * const es9, const char* smdp_address, const authenticate_client_request_t* request, authenticate_client_response_es9_t* response);

/**
 * This funtion executes the GetBoundProfilePackage function defined in the ES9+ interface of the SGP.22.
 * 
 * @param[in]  es9 interface A valid ES9 handle from a successful call to es9__ctor().
 * @param[in]  smdp_address null-terminated string with the SM-DP+ Address.
 * @param[in]  request pointer to a get_bound_profile_package_request_t structure populated with the input data.
 * @param[out] response pointer to a get_bound_profile_package_response_t structure that will be populated with 
 * the output data if the function return is success. The caller is the responsible for freeing this structure 
 * if the function return is success by calling the es9__free_get_bound_profile_package_response().
 * 
 * @return eOk in case the ES9+.GetBoundProfilePackage funtion has been executed successfully. 
 * Otherwise, an error code is returned.
*/
ErrCode es9__get_bound_profile_package(es9_t * const es9, const char* smdp_address, const get_bound_profile_package_request_t* request, get_bound_profile_package_response_t* response);

/**
 * This funtion executes the HandleNotification function defined in the ES9+ interface of the SGP.22.
 * 
 * @param[in]  es9 interface A valid ES9 handle from a successful call to es9__ctor().
 * @param[in]  smdp_address null-terminated string with the SM-DP+ Address.
 * @param[in]  pending_notification pointer to a byte array with the PendingNotification TLV.
 * @param[in] pending_notification_size size of the PendingNotification TLV byte array.
 * 
 * @return eOk in case the ES9+.HandleNotification funtion has been executed successfully. 
 * Otherwise, an error code is returned.
*/
ErrCode es9__handle_notification(es9_t * const es9, const char* smdp_address, const uint8_t* pending_notification, const size_t pending_notification_size);

/**
 * This funtion executes the CancelSession function defined in the ES9+ interface of the SGP.22.
 * 
 * @param[in]  es9 interface A valid ES9 handle from a successful call to es9__ctor().
 * @param[in]  smdp_address null-terminated string with the SM-DP+ Address.
 * @param[in]  request pointer to a cancel_session_request_es9_t structure populated with the input data.
 * @param[out] response pointer to a cancel_session_response_es9_t structure that will be populated with 
 * the output data if the function return is success.
 * 
 * @return eOk in case the ES9+.CancelSession funtion has been executed successfully. 
 * Otherwise, an error code is returned.
*/
ErrCode es9__cancel_session(es9_t * const es9, const char* smdp_address, const cancel_session_request_es9_t* request, cancel_session_response_es9_t* response);

/** Free datatypes functions according the allocations made in the es9.c file */
void es9__free_initiate_authentication_response(initiate_authentication_response_t* obj);
void es9__free_authenticate_client_response(authenticate_client_response_es9_t* obj);
void es9__free_get_bound_profile_package_response(get_bound_profile_package_response_t* obj);
