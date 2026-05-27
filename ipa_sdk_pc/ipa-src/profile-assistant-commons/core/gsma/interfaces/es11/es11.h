/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"
#include "gsma_typedefs.h"
#include "es9_typedefs.h"
#include "es11_typedefs.h"

typedef struct es11_s {
    gsma_data_binding_t data_binding;
} es11_t;

/**
 * This function creates an ES11 instance.
 * @note A default value for the ES11 data binding is set on the constructor.
 * 
 * @param[in] es11 Pointer to a es11_t structure. The object is populated with a valid ES11 instance.
*/
void es11__ctor(es11_t * const es11);

/**
 * This function sets JSON format as the data binding for the ES11 interface.
 * 
 * @param[in] es11 A valid ES11 handle from a successful call to es11__ctor().
*/
void es11__set_json_data_binding(es11_t * const es11);

/**
 * This funtion executes the InitiateAuthentication function defined in the ES11 interface of the SGP.22.
 * 
 * @param[in]  es11 A valid ES11 handle from a successful call to es11__ctor().
 * @param[in]  smds_address null-terminated string with the SM-DS Address.
 * @param[in]  request pointer to an initiate_authentication_request_t structure populated with the input data.
 * @param[out] response pointer to an initiate_authentication_response_t structure that will be populated with 
 * the output data if the function return is success. The caller is the responsible for freeing this structure 
 * if the function return is success by calling the es11__free_initiate_authentication_response().
 * 
 * @return eOk in case the ES11.InitiateAuthentication funtion has been executed successfully. 
 * Otherwise, an error code is returned.
*/
ErrCode es11__initiate_authentication(es11_t * const es11, const char* smds_address, const initiate_authentication_request_t* request, initiate_authentication_response_t* response);

/**
 * This funtion executes the AuthenticateClient function defined in the ES11 interface of the SGP.22.
 * 
 * @param[in]  es11 A valid ES11 handle from a successful call to es11__ctor().
 * @param[in]  smds_address null-terminated string with the SM-DS Address.
 * @param[in]  request pointer to an authenticate_client_request_t structure populated with the input data.
 * @param[out] response pointer to an authenticate_client_response_es11_t structure that will be populated with 
 * the output data if the function return is success. The caller is the responsible for freeing this structure 
 * if the function return is success by calling the es11__free_authenticate_client_response(). 
 * See also es11__get_next_event_entry() and es11__get_event_entry_list_size().
 * 
 * @return eOk in case the ES11.AuthenticateClient funtion has been executed successfully. 
 * Otherwise, an error code is returned.
*/
ErrCode es11__authenticate_client(es11_t * const es11, const char* smds_address, const authenticate_client_request_t* request, authenticate_client_response_es11_t* response);

/**
 * This function gets the next element of the EventEntries List.
 * 
 * @param[in]  es11 A valid ES11 handle from a successful call to es11__ctor().
 * @param[in]  response Pointer to a authenticate_client_response_es11_t structure obtained in the response of function es11__authenticate_client().
 * @param[out] event_entry_t Pointer to a event_entry_t structure. This structure will be populated with the next EventEntry from the 
 * EventEntries List if the function return is success. The structure data may be referencing data from the response structure, 
 * do not deallocate the response structure while using the event entry.
 * 
 * @return eOk in case the extraction has been done successfully. 
 * eNoData in case there is no next EventEntry in the EventEntries List.
 * Otherwise, another error code is returned.
*/
ErrCode es11__get_next_event_entry(es11_t * const es11, authenticate_client_response_es11_t* response, event_entry_t* event_entry);

/**
 * This function returns the number of elements in the EventEntries List.
 * 
 * @param[in]  es11 A valid ES11 handle from a successful call to es11__ctor().
 * @param[in]  response Pointer to a authenticate_client_response_es11_t structure obtained in the response of function es11__authenticate_client().
 * @param[out] list_size Will point to the number of elements of the EventEntries List if the function return is success.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, another error code is returned.
*/
ErrCode es11__get_event_entry_list_size(es11_t * const es11, authenticate_client_response_es11_t* response, uint32_t* list_size);

/** Free datatypes functions according the allocations made in the es11.c file */
void es11__free_initiate_authentication_response(initiate_authentication_response_t* obj);
void es11__free_authenticate_client_response(authenticate_client_response_es11_t* obj);
