/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#ifdef ENABLE_ESIPA_JSON
#include "typedefs.h"
#include "esipa_typedefs.h"
/**
 * This function generates a ESipa.HandleNotification request in JSON format.
 * @note This function doesn't add a null character at the end of the string.
 * 
 * @param[in, out] buffer Pointer to the buffer to where the JSON string will be written. If null, the function 
 * will only calculate the number of bytes that the buffer needs to write the generated string.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] obj Pointer to a handle_notification_esipa_t structure populated with the data needed to 
 * generate the JSON string. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the number of bytes written in the buffer.
 * If an output error is encountered, a negative value is returned.
*/
int32_t esipa_json_generator__handle_notification_esipa(uint8_t* buffer, const uint32_t buffer_size, const handle_notification_esipa_t* obj);

/**
 * This function generates a ESipa.TransferEimPackage request in JSON format.
 * @note This function doesn't add a null character at the end of the string.
 * 
 * @param[in, out] buffer Pointer to the buffer to where the JSON string will be written. If null, the function 
 * will only calculate the number of bytes that the buffer needs to write the generated string.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] obj Pointer to a transfer_eim_package_response_t structure populated with the data needed to 
 * generate the JSON string. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the number of bytes written in the buffer.
 * If an output error is encountered, a negative value is returned.
*/
int32_t esipa_json_generator__transfer_eim_package_response(uint8_t* buffer, const uint32_t buffer_size, const transfer_eim_package_response_t* obj);

/**
 * This function generates a ESipa.GetEimPackage request in JSON format.
 * @note This function doesn't add a null character at the end of the string.
 * 
 * @param[in, out] buffer Pointer to the buffer to where the JSON string will be written. If null, the function 
 * will only calculate the number of bytes that the buffer needs to write the generated string.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] obj Pointer to a get_eim_package_request_t structure populated with the data needed to 
 * generate the JSON string. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the number of bytes written in the buffer.
 * If an output error is encountered, a negative value is returned.
*/
int32_t esipa_json_generator__get_eim_package_request(uint8_t* buffer, const uint32_t buffer_size, const get_eim_package_request_t* obj);

/**
 * This function generates a ESipa.ProvideEimPackageResult request in JSON format.
 * @note This function doesn't add a null character at the end of the string.
 * 
 * @param[in, out] buffer Pointer to the buffer to where the JSON string will be written. If null, the function 
 * will only calculate the number of bytes that the buffer needs to write the generated string.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] obj Pointer to a provide_eim_package_result_t structure populated with the data needed to 
 * generate the JSON string. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the number of bytes written in the buffer.
 * If an output error is encountered, a negative value is returned.
*/
int32_t esipa_json_generator__provide_eim_package_result(uint8_t* buffer, const uint32_t buffer_size, const provide_eim_package_result_t* obj);

#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
/**
 * This function generates a ESipa.InitiateAuthentication request in JSON format.
 * @note This function doesn't add a null character at the end of the string.
 * 
 * @param[in, out] buffer Pointer to the buffer to where the JSON string will be written. If null, the function 
 * will only calculate the number of bytes that the buffer needs to write the generated string.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] obj Pointer to a initiate_authentication_request_esipa_t structure populated with the data needed to 
 * generate the JSON string. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the number of bytes written in the buffer.
 * If an output error is encountered, a negative value is returned.
*/
int32_t esipa_json_generator__initiate_authentication_request(uint8_t* buffer, const uint32_t buffer_size, const initiate_authentication_request_esipa_t* obj);

/**
 * This function generates a ESipa.AuthenticateClient request in JSON format.
 * @note This function doesn't add a null character at the end of the string.
 * 
 * @param[in, out] buffer Pointer to the buffer to where the JSON string will be written. If null, the function 
 * will only calculate the number of bytes that the buffer needs to write the generated string.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] obj Pointer to a authenticate_client_request_esipa_t structure populated with the data needed to 
 * generate the JSON string. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the number of bytes written in the buffer.
 * If an output error is encountered, a negative value is returned.
*/
int32_t esipa_json_generator__authenticate_client_request_esipa(uint8_t* buffer, const uint32_t buffer_size, const authenticate_client_request_esipa_t* obj);

/**
 * This function generates a ESipa.CancelSession request in JSON format.
 * @note This function doesn't add a null character at the end of the string.
 * 
 * @param[in, out] buffer Pointer to the buffer to where the JSON string will be written. If null, the function 
 * will only calculate the number of bytes that the buffer needs to write the generated string.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] obj Pointer to a cancel_session_request_esipa_t structure populated with the data needed to 
 * generate the JSON string. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the number of bytes written in the buffer.
 * If an output error is encountered, a negative value is returned.
*/
int32_t esipa_json_generator__cancel_session_request_esipa(uint8_t* buffer, const uint32_t buffer_size, const cancel_session_request_esipa_t* obj);

/**
 * This function generates a ESipa.GetBoundProfilePackage request in JSON format.
 * @note This function doesn't add a null character at the end of the string.
 * 
 * @param[in, out] buffer Pointer to the buffer to where the JSON string will be written. If null, the function 
 * will only calculate the number of bytes that the buffer needs to write the generated string.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] obj Pointer to a get_bound_profile_package_request_esipa_t structure populated with the data needed to 
 * generate the JSON string. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the number of bytes written in the buffer.
 * If an output error is encountered, a negative value is returned.
*/
int32_t esipa_json_generator__get_bound_profile_package_request_esipa(uint8_t* buffer, const uint32_t buffer_size, const get_bound_profile_package_request_esipa_t* obj);
#endif
#endif