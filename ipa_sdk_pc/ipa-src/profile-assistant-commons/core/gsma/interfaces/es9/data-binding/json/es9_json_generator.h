/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"
#include "es9_typedefs.h"

/**
 * This function generates a ES9.InitiateAuthentication request in JSON format.
 * @note This function doesn't add a null character at the end of the string.
 * 
 * @param[in, out] buffer Pointer to the buffer to where the JSON string will be written. If null, the function 
 * will only calculate the number of bytes that the buffer needs to write the generated string.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] obj Pointer to a initiate_authentication_request_t structure populated with the data needed to 
 * generate the JSON string. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the number of bytes written in the buffer.
 * If an output error is encountered, a negative value is returned.
*/
int32_t es9_json_generator__initiate_authentication_request(uint8_t* buffer, const uint32_t buffer_size, const initiate_authentication_request_t* obj);

/**
 * This function generates a ES9.AuthenticateClient request in JSON format.
 * @note This function doesn't add a null character at the end of the string.
 * 
 * @param[in, out] buffer Pointer to the buffer to where the JSON string will be written. If null, the function 
 * will only calculate the number of bytes that the buffer needs to write the generated string.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] obj Pointer to a authenticate_client_request_t structure populated with the data needed to 
 * generate the JSON string. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the number of bytes written in the buffer.
 * If an output error is encountered, a negative value is returned.
*/
int32_t es9_json_generator__authenticate_client_request(uint8_t* buffer, const uint32_t buffer_size, const authenticate_client_request_t* obj);

/**
 * This function generates a ES9.GetBoundProfilePackage request in JSON format.
 * @note This function doesn't add a null character at the end of the string.
 * 
 * @param[in, out] buffer Pointer to the buffer to where the JSON string will be written. If null, the function 
 * will only calculate the number of bytes that the buffer needs to write the generated string.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] obj Pointer to a get_bound_profile_package_request_t structure populated with the data needed to 
 * generate the JSON string. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the number of bytes written in the buffer.
 * If an output error is encountered, a negative value is returned.
*/
int32_t es9_json_generator__get_bound_profile_package_request(uint8_t* buffer, const uint32_t buffer_size, const get_bound_profile_package_request_t* obj);

/**
 * This function generates a ES9.GetBoundProfilePackage request in JSON format.
 * @note This function doesn't add a null character at the end of the string.
 * 
 * @param[in, out] buffer Pointer to the buffer to where the JSON string will be written. If null, the function 
 * will only calculate the number of bytes that the buffer needs to write the generated string.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] pending_notification pointer to a byte array with the PendingNotification TLV.
 * @param[in] pending_notification_size size of the PendingNotification TLV byte array.
 *  
 * @return Upon successful execution, will return the number of bytes written in the buffer.
 * If an output error is encountered, a negative value is returned.
*/
int32_t es9_json_generator__handle_notification_request(uint8_t* buffer, const uint32_t buffer_size, const uint8_t* pending_notification, const size_t pending_notification_size);

/**
 * This function generates a ES9.CancelSession request in JSON format.
 * @note This function doesn't add a null character at the end of the string.
 * 
 * @param[in, out] buffer Pointer to the buffer to where the JSON string will be written. If null, the function 
 * will only calculate the number of bytes that the buffer needs to write the generated string.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] obj Pointer to a cancel_session_request_es9_t structure populated with the data needed to 
 * generate the JSON string. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the number of bytes written in the buffer.
 * If an output error is encountered, a negative value is returned.
*/
int32_t es9_json_generator__cancel_session_request(uint8_t* buffer, const uint32_t buffer_size, const cancel_session_request_es9_t* obj);
