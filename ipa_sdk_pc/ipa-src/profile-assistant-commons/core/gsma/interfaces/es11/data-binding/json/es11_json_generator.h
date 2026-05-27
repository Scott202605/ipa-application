/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"
#include "es9_typedefs.h"
#include "es11_typedefs.h"

/**
 * This function generates a ES11.InitiateAuthentication request in JSON format.
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
int32_t es11_json_generator__initiate_authentication_request(uint8_t* buffer, const uint32_t buffer_size, const initiate_authentication_request_t* obj);

/**
 * This function generates a ES11.AuthenticateClient request in JSON format.
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
int32_t es11_json_generator__authenticate_client_request(uint8_t* buffer, const uint32_t buffer_size, const authenticate_client_request_t* obj);
