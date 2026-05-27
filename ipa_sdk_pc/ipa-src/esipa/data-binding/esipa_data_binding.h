/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "esipa_typedefs.h"

/**
 * This function can generate a ESipa.HandleNotification request in different formats.
 * 
 * @param[in, out] buffer Pointer to the buffer to where the request content will be written. If null, the function 
 * will only calculate the number of bytes that the buffer needs to write the request content.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] data_binding Request data binding.
 * @param[in] obj Pointer to a handle_notification_esipa_t structure populated with the data needed to 
 * generate the request. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the number of bytes written in the buffer.
 * If an output error is encountered, a negative value is returned.
*/
int32_t esipa_data_binding__generate_handle_notification_esipa(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, const handle_notification_esipa_t* obj);

/**
 * This function can generate a ESipa.TransferEimPackage response in different formats.
 * 
 * @param[in, out] buffer Pointer to the buffer to where the response content will be written. If null, the function 
 * will only calculate the number of bytes that the buffer needs to write the response content.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] data_binding Response data binding.
 * @param[in] obj Pointer to a transfer_eim_package_response_t structure populated with the data needed to 
 * generate the response. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the number of bytes written in the buffer.
 * If an output error is encountered, a negative value is returned.
*/
int32_t esipa_data_binding__generate_transfer_eim_package_response(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, const transfer_eim_package_response_t* obj);

/**
 * This function can generate a ESipa.GetEimPackage request in different formats.
 * 
 * @param[in, out] buffer Pointer to the buffer to where the request content will be written. If null, the function 
 * will only calculate the number of bytes that the buffer needs to write the request content.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] data_binding Request data binding.
 * @param[in] obj Pointer to a get_eim_package_request_t structure populated with the data needed to 
 * generate the request. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the number of bytes written in the buffer.
 * If an output error is encountered, a negative value is returned.
*/
int32_t esipa_data_binding__generate_get_eim_package_request(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, const get_eim_package_request_t* obj);

/**
 * This function can generate a ESipa.ProvideEimPackageResult request in different formats.
 * 
 * @param[in, out] buffer Pointer to the buffer to where the request content will be written. If null, the function 
 * will only calculate the number of bytes that the buffer needs to write the request content.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] data_binding Request data binding.
 * @param[in] obj Pointer to a provide_eim_package_result_t structure populated with the data needed to 
 * generate the request. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the number of bytes written in the buffer.
 * If an output error is encountered, a negative value is returned.
*/
int32_t esipa_data_binding__generate_provide_eim_package_result(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, const provide_eim_package_result_t* obj);

#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
/**
 * This function can generate a ESipa.InitiateAuthentication request in different formats.
 * 
 * @param[in, out] buffer Pointer to the buffer to where the request content will be written. If null, the function 
 * will only calculate the number of bytes that the buffer needs to write the request content.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] data_binding Request data binding.
 * @param[in] obj Pointer to a initiate_authentication_request_esipa_t structure populated with the data needed to 
 * generate the request. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the number of bytes written in the buffer.
 * If an output error is encountered, a negative value is returned.
*/
int32_t esipa_data_binding__generate_initiate_authentication_request(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, const initiate_authentication_request_esipa_t* obj);

/**
 * This function can generate a ESipa.AuthenticateClient request in different formats.
 * 
 * @param[in, out] buffer Pointer to the buffer to where the request content will be written. If null, the function 
 * will only calculate the number of bytes that the buffer needs to write the request content.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] data_binding Request data binding.
 * @param[in] obj Pointer to a authenticate_client_request_esipa_t structure populated with the data needed to 
 * generate the request. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the number of bytes written in the buffer.
 * If an output error is encountered, a negative value is returned.
*/
int32_t esipa_data_binding__generate_authenticate_client_request_esipa(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, const authenticate_client_request_esipa_t* obj);

/**
 * This function can generate a ESipa.CancelSession request in different formats.
 * 
 * @param[in, out] buffer Pointer to the buffer to where the request content will be written. If null, the function 
 * will only calculate the number of bytes that the buffer needs to write the request content.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] data_binding Request data binding.
 * @param[in] obj Pointer to a cancel_session_request_esipa_t structure populated with the data needed to 
 * generate the request. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the number of bytes written in the buffer.
 * If an output error is encountered, a negative value is returned.
*/
int32_t esipa_data_binding__generate_cancel_session_request_esipa(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, const cancel_session_request_esipa_t* obj);

/**
 * This function can generate a ESipa.GetBoundProfilePackage request in different formats.
 * 
 * @param[in, out] buffer Pointer to the buffer to where the request content will be written. If null, the function 
 * will only calculate the number of bytes that the buffer needs to write the request content.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] data_binding Request data binding.
 * @param[in] obj Pointer to a get_bound_profile_package_request_esipa_t structure populated with the data needed to 
 * generate the request. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the number of bytes written in the buffer.
 * If an output error is encountered, a negative value is returned.
*/
int32_t esipa_data_binding__generate_get_bound_profile_package_request_esipa(uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, const get_bound_profile_package_request_esipa_t* obj);
#endif

/**
 * This function extracts the ESipa.TransferEimPackage request in different formats.
 * @note To optimize memory, the buffer may be modified during the data extraction (to decode the some data formats in the 
 * same buffer as the request buffer is allocated). For this reason, the request buffer pointer must be treated as a context 
 * after the execution of this function (the structure will be referencing the buffer data, so it cannot be deallocated).
 * 
 * @param[in]  buffer Points to the request buffer.
 * @param[in]  json_len Size of the request buffer.
 * @param[in]  data_binding Request buffer data binding.
 * @param[out] obj Pointer to a transfer_eim_package_request_t structure. The structure is populated following its 
 * documentation with the data from the request buffer if the function return is success. The structure data may be 
 * referencing data from the request buffer, do not deallocate the request buffer while using the structure.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned.
*/
ErrCode esipa_data_binding__extract_transfer_eim_package_request(const uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, transfer_eim_package_request_t* obj);

/**
 * This function extracts the ESipa.GetEimPackage response in different formats.
 * @note To optimize memory, the buffer may be modified during the data extraction (to decode the some data formats in the 
 * same buffer as the response buffer is allocated). For this reason, the response buffer pointer must be treated as a context 
 * after the execution of this function (the structure will be referencing the buffer data, so it cannot be deallocated).
 * 
 * @param[in]  buffer Points to the response buffer.
 * @param[in]  json_len Size of the response buffer.
 * @param[in]  data_binding Response buffer data binding.
 * @param[out] obj Pointer to a get_eim_package_response_t structure. The structure is populated following its 
 * documentation with the data from the response buffer if the function return is success. The structure data may be 
 * referencing data from the response buffer, do not deallocate the response buffer while using the structure.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned.
*/
ErrCode esipa_data_binding__extract_get_eim_package_response(const uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, get_eim_package_response_t* obj);

/**
 * This function extracts the ESipa.ProvideEimPackageResult response in different formats.
 * @note To optimize memory, the buffer may be modified during the data extraction (to decode the some data formats in the 
 * same buffer as the response buffer is allocated). For this reason, the response buffer pointer must be treated as a context 
 * after the execution of this function (the structure will be referencing the buffer data, so it cannot be deallocated).
 * 
 * @param[in]  buffer Points to the response buffer.
 * @param[in]  json_len Size of the response buffer.
 * @param[in]  data_binding Response buffer data binding.
 * @param[out] obj Pointer to a provide_eim_package_result_response_t structure. The structure is populated following its 
 * documentation with the data from the response buffer if the function return is success. The structure data may be 
 * referencing data from the response buffer, do not deallocate the response buffer while using the structure.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned.
*/
ErrCode esipa_data_binding__extract_provide_eim_package_result_response(const uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, provide_eim_package_result_response_t* obj);

#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
/**
 * This function extracts the ESipa.InitiateAuthentication response in different formats.
 * @note To optimize memory, the buffer may be modified during the data extraction (to decode the some data formats in the 
 * same buffer as the response buffer is allocated). For this reason, the response buffer pointer must be treated as a context 
 * after the execution of this function (the structure will be referencing the buffer data, so it cannot be deallocated).
 * 
 * @param[in]  buffer Points to the response buffer.
 * @param[in]  json_len Size of the response buffer.
 * @param[in]  data_binding Response buffer data binding.
 * @param[out] obj Pointer to a initiate_authentication_response_esipa_t structure. The structure is populated following its 
 * documentation with the data from the response buffer if the function return is success. The structure data may be 
 * referencing data from the response buffer, do not deallocate the response buffer while using the structure.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned.
*/
ErrCode esipa_data_binding__extract_initiate_authentication_response_esipa(const uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, initiate_authentication_response_esipa_t* obj);

/**
 * This function extracts the ESipa.AuthenticateClient response in different formats.
 * @note To optimize memory, the buffer may be modified during the data extraction (to decode the some data formats in the 
 * same buffer as the response buffer is allocated). For this reason, the response buffer pointer must be treated as a context 
 * after the execution of this function (the structure will be referencing the buffer data, so it cannot be deallocated).
 * 
 * @param[in]  buffer Points to the response buffer.
 * @param[in]  json_len Size of the response buffer.
 * @param[in]  data_binding Response buffer data binding.
 * @param[out] obj Pointer to a authenticate_client_response_esipa_t structure. The structure is populated following its 
 * documentation with the data from the response buffer if the function return is success. The structure data may be 
 * referencing data from the response buffer, do not deallocate the response buffer while using the structure.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned.
*/
ErrCode esipa_data_binding__extract_authenticate_client_response_esipa(const uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, authenticate_client_response_esipa_t* obj);

/**
 * This function extracts the ESipa.GetBoundProfilePackage response in different formats.
 * @note To optimize memory, the buffer may be modified during the data extraction (to decode the some data formats in the 
 * same buffer as the response buffer is allocated). For this reason, the response buffer pointer must be treated as a context 
 * after the execution of this function (the structure will be referencing the buffer data, so it cannot be deallocated).
 * 
 * @param[in]  buffer Points to the response buffer.
 * @param[in]  json_len Size of the response buffer.
 * @param[in]  data_binding Response buffer data binding.
 * @param[out] obj Pointer to a get_bound_profile_package_response_esipa_t structure. The structure is populated following its 
 * documentation with the data from the response buffer if the function return is success. The structure data may be 
 * referencing data from the response buffer, do not deallocate the response buffer while using the structure.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned.
*/
ErrCode esipa_data_binding__extract_get_bound_profile_package_response_esipa(const uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, get_bound_profile_package_response_esipa_t* obj);

/**
 * This function extracts the ESipa.CancelSession response in different formats.
 * @note To optimize memory, the buffer may be modified during the data extraction (to decode the some data formats in the 
 * same buffer as the response buffer is allocated). For this reason, the response buffer pointer must be treated as a context 
 * after the execution of this function (the structure will be referencing the buffer data, so it cannot be deallocated).
 * 
 * @param[in]  buffer Points to the response buffer.
 * @param[in]  json_len Size of the response buffer.
 * @param[in]  data_binding Response buffer data binding.
 * @param[out] obj Pointer to a cancel_session_response_esipa_t structure. The structure is populated following its 
 * documentation with the data from the response buffer if the function return is success. The structure data may be 
 * referencing data from the response buffer, do not deallocate the response buffer while using the structure.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned.
*/
ErrCode esipa_data_binding__extract_cancel_session_response_esipa(const uint8_t* buffer, const uint32_t buffer_size, const gsma_data_binding_t data_binding, cancel_session_response_esipa_t* obj);
#endif

/**
 * This function can determine from a message received from the eIM, to which ESipa function it belongs.
 * 
 * @param[in]  message Points to the message buffer.
 * @param[in]  message_size Size of the message buffer.
 * @param[in]  data_binding Message buffer data binding.
 * @param[in]  last_message_sent last ESipa message type sent. This parameter will only be used in case the message type received from the eIM cannot be determined by its content.
 * @param[out] result Will point to the message type if the funtion result is success.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned.
*/
ErrCode esipa_data_binding__get_esipa_message_from_eim_to_ipa_choice(const uint8_t* message, const uint32_t message_size, const gsma_data_binding_t data_binding, esipa_message_from_ipa_to_eim_choice_t last_message_sent, esipa_message_from_eim_to_ipa_choice_t* result);
