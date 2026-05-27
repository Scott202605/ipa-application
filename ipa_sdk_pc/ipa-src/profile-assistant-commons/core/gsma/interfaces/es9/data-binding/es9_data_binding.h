/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"
#include "es9_typedefs.h"
#include "gsma_typedefs.h"

/**
 * This function can generate a ES9.InitiateAuthentication request in different formats.
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
int32_t es9_data_binding__generate_initiate_authentication_request(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, const initiate_authentication_request_t* obj);

/**
 * This function can generate a ES9.AuthenticateClient request in different formats.
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
int32_t es9_data_binding__generate_authenticate_client_request(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, const authenticate_client_request_t* obj);

/**
 * This function can generate a ES9.GetBoundProfilePackage request in different formats.
 * @note ASN.1 data binding is not yet supported.
 * 
 * @param[in, out] buffer Pointer to the buffer to where the request content will be written. If null, the function 
 * will only calculate the number of bytes that the buffer needs to write the request content.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] data_binding Request data binding.
 * @param[in] obj Pointer to a get_bound_profile_package_request_t structure populated with the data needed to 
 * generate the request. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the number of bytes written in the buffer.
 * If an output error is encountered, a negative value is returned.
*/
int32_t es9_data_binding__generate_get_bound_profile_package_request(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, const get_bound_profile_package_request_t* obj);

/**
 * This function can generate a ES9.HandleNotification request in different formats.
 * @note ASN.1 data binding is not yet supported.
 * 
 * @param[in, out] buffer Pointer to the buffer to where the request content will be written. If null, the function 
 * will only calculate the number of bytes that the buffer needs to write the request content.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] data_binding Request data binding.
 * @param[in] pending_notification pointer to a byte array with the PendingNotification TLV.
 * @param[in] pending_notification_size size of the PendingNotification TLV byte array.
 * 
 * @return Upon successful execution, will return the number of bytes written in the buffer.
 * If an output error is encountered, a negative value is returned.
*/
int32_t es9_data_binding__generate_handle_notification_request(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, const uint8_t* pending_notification, const size_t pending_notification_size);

/**
 * This function can generate a ES9.CancelSession request in different formats.
 * @note ASN.1 data binding is not yet supported.
 * 
 * @param[in, out] buffer Pointer to the buffer to where the request content will be written. If null, the function 
 * will only calculate the number of bytes that the buffer needs to write the request content.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] data_binding Request data binding.
 * @param[in] obj Pointer to a cancel_session_request_es9_t structure populated with the data needed to 
 * generate the request. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the number of bytes written in the buffer.
 * If an output error is encountered, a negative value is returned.
*/
int32_t es9_data_binding__generate_cancel_session_request(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, const cancel_session_request_es9_t* obj);

/**
 * This function extracts the ES9.InitiateAuthentication response in different formats.
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
ErrCode es9_data_binding__extract_initiate_authentication_response(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, initiate_authentication_response_t* obj);

/**
 * This function extracts the ES9.AuthenticateClient response in different formats.
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
ErrCode es9_data_binding__extract_authenticate_client_response(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, authenticate_client_response_es9_t* obj);

/**
 * This function extracts the ES9.GetBoundProfilePackage response in different formats.
 * @note ASN.1 data binding is not yet supported.
 * 
 * @param[in]  buffer Points to the response buffer.
 * @param[in]  json_len Size of the response buffer.
 * @param[in]  data_binding Response buffer data binding.
 * @param[out] obj Pointer to a get_bound_profile_package_response_t structure. The structure is populated following its 
 * documentation with the data from the response buffer if the function return is success. The structure data may be 
 * referencing data from the response buffer, do not deallocate the response buffer while using the structure.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned.
*/
ErrCode es9_data_binding__extract_get_bound_profile_package_response(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, get_bound_profile_package_response_t* obj);

/**
 * This function extracts the ES9.CancelSession response in different formats.
 * @note ASN.1 data binding is not yet supported.
 * 
 * @param[in]  buffer Points to the response buffer.
 * @param[in]  json_len Size of the response buffer.
 * @param[in]  data_binding Response buffer data binding.
 * @param[out] obj Pointer to a cancel_session_response_es9_t structure. The structure is populated following its documentation
 * with the data from the response buffer if the function return is success. The structure data don't reference any data from  
 * the response buffer, so the response buffer can be deallocated after the execution of the function.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned.
*/
ErrCode es9_data_binding__extract_cancel_session_response(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, cancel_session_response_es9_t* obj);