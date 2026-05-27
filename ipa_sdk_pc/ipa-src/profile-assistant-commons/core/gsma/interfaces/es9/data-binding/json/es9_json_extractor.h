/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "es9_typedefs.h"

/**
 * This function extracts the ES9+.InitiateAuthentication JSON response.
 * @note To optimize memory, the json string will be modified during the data extraction (to decode the base64 in the 
 * same buffer as the JSON string is allocated). For this reason, the string pointer must be treated as a context 
 * after the execution of this function (the structure will be referencing the buffer data, so it cannot be deallocated).
 * 
 * @param[in]  json string in JSON format (can be not null-terminated).
 * @param[in]  json_len length of the json string (excluding the null-terminated character).
 * @param[out] obj Pointer to a initiate_authentication_response_t structure. The structure is populated following its 
 * documentation with the data from the json string if the function return is success. The structure data may be 
 * referencing data from the json string, do not deallocate the json string while using the structure.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned.
*/
ErrCode es9_json_extractor__initiate_authentication_response(unsigned char* json, uint32_t json_len, initiate_authentication_response_t* obj);

/**
 * This function extracts the ES9+.AuthenticateClient JSON response.
 * @note To optimize memory, the json string will be modified during the data extraction (to decode the base64 in the 
 * same buffer as the JSON string is allocated). For this reason, the string pointer must be treated as a context 
 * after the execution of this function (the structure will be referencing the buffer data, so it cannot be deallocated).
 * 
 * @param[in]  json string in JSON format (can be not null-terminated).
 * @param[in]  json_len length of the json string (excluding the null-terminated character).
 * @param[out] obj Pointer to a authenticate_client_response_es9_t structure. The structure is populated following its 
 * documentation with the data from the json string if the function return is success. The structure data may be 
 * referencing data from the json string, do not deallocate the json string while using the structure.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned.
*/
ErrCode es9_json_extractor__authenticate_client_response(unsigned char* json, uint32_t json_len, authenticate_client_response_es9_t* obj);

/**
 * This function extracts the ES9+.GetBoundProfilePackage JSON response.
 * @note To optimize memory, the json string will be modified during the data extraction (to decode the base64 in the 
 * same buffer as the JSON string is allocated). For this reason, the string pointer must be treated as a context 
 * after the execution of this function (the structure will be referencing the buffer data, so it cannot be deallocated).
 * 
 * @param[in]  json string in JSON format (can be not null-terminated).
 * @param[in]  json_len length of the json string (excluding the null-terminated character).
 * @param[out] obj Pointer to a get_bound_profile_package_response_t structure. The structure is populated following its 
 * documentation with the data from the json string if the function return is success. The structure data may be 
 * referencing data from the json string, do not deallocate the json string while using the structure.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned.
*/
ErrCode es9_json_extractor__get_bound_profile_package_response(unsigned char* json, uint32_t json_len, get_bound_profile_package_response_t* obj);

/**
 * This function extracts the ES9+.CancelSession JSON response.
 * 
 * @param[in]  json string in JSON format (can be not null-terminated).
 * @param[in]  json_len length of the json string (excluding the null-terminated character).
 * @param[out] obj Pointer to a cancel_session_response_es9_t structure. The structure is populated following its 
 * documentation with the data from the json string if the function return is success. The structure data don't 
 * reference any data from the json string, so the json string can be deallocated after the execution of the function.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned.
*/
ErrCode es9_json_extractor__cancel_session_response(unsigned char* json, uint32_t json_len, cancel_session_response_es9_t* obj);
