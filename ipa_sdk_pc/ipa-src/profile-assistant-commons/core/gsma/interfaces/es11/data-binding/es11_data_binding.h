/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"
#include "es9_typedefs.h"
#include "es11_typedefs.h"
#include "gsma_typedefs.h"

/**
 * This function can generate a ES11.InitiateAuthentication request in different formats.
 * @note ASN.1 data binding is not yet supported.
 * 
 * @param[in, out] buffer Pointer to the buffer to where the request content will be written. If null, the function 
 * will only calculate the number of bytes that the buffer needs to write the request content.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] data_binding Request data binding.
 * @param[in] obj Pointer to a initiate_authentication_request_t structure populated with the data needed to 
 * generate the request. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the number of bytes written in the buffer.
 * If an output error is encountered, a negative value is returned.
*/
int32_t es11_data_binding__generate_initiate_authentication_request(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, const initiate_authentication_request_t* obj);

/**
 * This function can generate a ES11.AuthenticateClient request in different formats.
 * @note ASN.1 data binding is not yet supported.
 * 
 * @param[in, out] buffer Pointer to the buffer to where the request content will be written. If null, the function 
 * will only calculate the number of bytes that the buffer needs to write the request content.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] data_binding Request data binding.
 * @param[in] obj Pointer to a authenticate_client_request_t structure populated with the data needed to 
 * generate the request. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the number of bytes written in the buffer.
 * If an output error is encountered, a negative value is returned.
*/
int32_t es11_data_binding__generate_authenticate_client_request(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, const authenticate_client_request_t* obj);

/**
 * This function extracts the ES11.InitiateAuthentication response in different formats.
 * @note ASN.1 data binding is not yet supported.
 * @note To optimize memory, the buffer may be modified during the data extraction (to decode the some data formats in the 
 * same buffer as the response buffer is allocated). For this reason, the response buffer pointer must be treated as a context 
 * after the execution of this function (the structure will be referencing the buffer data, so it cannot be deallocated).
 * 
 * @param[in]  buffer Points to the response buffer.
 * @param[in]  json_len Size of the response buffer.
 * @param[in]  data_binding Response buffer data binding.
 * @param[out] obj Pointer to a initiate_authentication_response_t structure. The structure is populated following its 
 * documentation with the data from the response buffer if the function return is success. The structure data may be 
 * referencing data from the response buffer, do not deallocate the response buffer while using the structure.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned.
*/
ErrCode es11_data_binding__extract_initiate_authentication_response(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, initiate_authentication_response_t* obj);

/**
 * This function extracts the ES11.AuthenticateClient response in different formats.
 * @note ASN.1 data binding is not yet supported.
 * 
 * @param[in]  buffer Points to the response buffer.
 * @param[in]  json_len Size of the response buffer.
 * @param[in]  data_binding Response buffer data binding.
 * @param[out] obj Pointer to a authenticate_client_response_es11_t structure. The structure is populated following its 
 * documentation with the data from the response buffer if the function return is success. The structure data may be 
 * referencing data from the response buffer, do not deallocate the response buffer while using the structure.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned.
*/
ErrCode es11_data_binding__extract_authenticate_client_response(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, authenticate_client_response_es11_t* obj);

/**
 * This function gets the next element of the EventEntries List.
 * @note ASN.1 data binding is not yet supported.
 * 
 * @param[in]  response Pointer to a authenticate_client_response_es11_t structure initialized in the es11_data_binding__extract_authenticate_client_response() call.
 * @param[in]  data_binding Response data binding.
 * @param[out] obj Pointer to a event_entry_t structure. This structure will be populated with the next EventEntry from the 
 * EventEntries List if the function return is success. The structure data may be referencing data from the main response buffer, 
 * do not deallocate the response buffer while using the structure.
 * 
 * @return eOk in case the extraction has been done successfully. 
 * eNoData in case there is no next EventEntry in the EventEntries List.
 * Otherwise, another error code is returned.
*/
ErrCode es11_data_binding__extract_next_event_entry(authenticate_client_response_es11_t* response, const gsma_data_binding_t data_binding, event_entry_t* obj);

/**
 * This function returns the number of elements in the EventEntries List.
 * @note ASN.1 data binding is not yet supported.
 * 
 * @param[in]  response Pointer to a authenticate_client_response_es11_t structure initialized in the es11_data_binding__extract_authenticate_client_response() call.
 * @param[in]  data_binding Response data binding.
 * @param[out] list_size Will point to the number of elements of the EventEntries List if the function return is success.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, another error code is returned.
*/
ErrCode es11_data_binding__extract_event_entry_list_size(authenticate_client_response_es11_t* response, const gsma_data_binding_t data_binding, uint32_t* list_size);
