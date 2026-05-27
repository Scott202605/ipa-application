/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#ifdef ENABLE_ESIPA_JSON
#include "typedefs.h"
#include "esipa_typedefs.h"

/**
 * This function extracts the EsipaMessageFromEimToIpa CHOICE of a JSON message.
 *
 * @param[in]  json string in JSON format (can be not null-terminated).
 * @param[in]  json_len length of the json string (excluding the null-terminated character).
 * @param[in]  last_message_sent last ESipa message type sent. This parameter will only be used in case the message type received from the eIM cannot be determined by its content.
 * @param[out] result Will point to the message type if the funtion result is success.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode esipa_json_extractor__esipa_message_from_eim_to_ipa_choice(unsigned char* json, uint32_t json_len, esipa_message_from_ipa_to_eim_choice_t last_message_sent, esipa_message_from_eim_to_ipa_choice_t* result);

/**
 * This function extracts the ESipa.TransferEimPackage JSON response.
 * @note To optimize memory, the json string will be modified during the data extraction (to decode the base64 in the 
 * same buffer as the JSON string is allocated). For this reason, the string pointer must be treated as a context 
 * after the execution of this function (the structure will be referencing the buffer data, so it cannot be deallocated).
 * 
 * @param[in]  json string in JSON format (can be not null-terminated).
 * @param[in]  json_len length of the json string (excluding the null-terminated character).
 * @param[out] obj Pointer to a transfer_eim_package_request_t structure. The structure is populated following its 
 * documentation with the data from the json string if the function return is success. The structure data may be 
 * referencing data from the json string, do not deallocate the json string while using the structure.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned.
*/
ErrCode esipa_json_extractor__transfer_eim_package_request(unsigned char* json, uint32_t json_len, transfer_eim_package_request_t* obj);

/**
 * This function extracts the ESipa.GetEimPackage JSON response.
 * @note To optimize memory, the json string will be modified during the data extraction (to decode the base64 in the 
 * same buffer as the JSON string is allocated). For this reason, the string pointer must be treated as a context 
 * after the execution of this function (the structure will be referencing the buffer data, so it cannot be deallocated).
 * 
 * @param[in]  json string in JSON format (can be not null-terminated).
 * @param[in]  json_len length of the json string (excluding the null-terminated character).
 * @param[out] obj Pointer to a get_eim_package_response_t structure. The structure is populated following its 
 * documentation with the data from the json string if the function return is success. The structure data may be 
 * referencing data from the json string, do not deallocate the json string while using the structure.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned.
*/
ErrCode esipa_json_extractor__get_eim_package_response(unsigned char* json, uint32_t json_len, get_eim_package_response_t* obj);

/**
 * This function extracts the ESipa.ProvideEimPackageResult JSON response.
 * @note To optimize memory, the json string will be modified during the data extraction (to decode the base64 in the 
 * same buffer as the JSON string is allocated). For this reason, the string pointer must be treated as a context 
 * after the execution of this function (the structure will be referencing the buffer data, so it cannot be deallocated).
 * 
 * @param[in]  json string in JSON format (can be not null-terminated).
 * @param[in]  json_len length of the json string (excluding the null-terminated character).
 * @param[out] obj Pointer to a provide_eim_package_result_response_t structure. The structure is populated following its 
 * documentation with the data from the json string if the function return is success. The structure data may be 
 * referencing data from the json string, do not deallocate the json string while using the structure.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned.
*/
ErrCode esipa_json_extractor__provide_eim_package_result_response(unsigned char* json, uint32_t json_len, provide_eim_package_result_response_t* obj);

#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
/**
 * This function extracts the ESipa.InitiateAuthentication JSON response.
 * @note To optimize memory, the json string will be modified during the data extraction (to decode the base64 in the 
 * same buffer as the JSON string is allocated). For this reason, the string pointer must be treated as a context 
 * after the execution of this function (the structure will be referencing the buffer data, so it cannot be deallocated).
 * 
 * @param[in]  json string in JSON format (can be not null-terminated).
 * @param[in]  json_len length of the json string (excluding the null-terminated character).
 * @param[out] obj Pointer to a initiate_authentication_response_esipa_t structure. The structure is populated following its 
 * documentation with the data from the json string if the function return is success. The structure data may be 
 * referencing data from the json string, do not deallocate the json string while using the structure.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned.
*/
ErrCode esipa_json_extractor__initiate_authentication_response_esipa(unsigned char* json, uint32_t json_len, initiate_authentication_response_esipa_t* obj);

/**
 * This function extracts the ESipa.AuthenticateClient JSON response.
 * @note To optimize memory, the json string will be modified during the data extraction (to decode the base64 in the 
 * same buffer as the JSON string is allocated). For this reason, the string pointer must be treated as a context 
 * after the execution of this function (the structure will be referencing the buffer data, so it cannot be deallocated).
 * 
 * @param[in]  json string in JSON format (can be not null-terminated).
 * @param[in]  json_len length of the json string (excluding the null-terminated character).
 * @param[out] obj Pointer to a authenticate_client_response_esipa_t structure. The structure is populated following its 
 * documentation with the data from the json string if the function return is success. The structure data may be 
 * referencing data from the json string, do not deallocate the json string while using the structure.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned.
*/
ErrCode esipa_json_extractor__authenticate_client_response_esipa(unsigned char* json, uint32_t json_len, authenticate_client_response_esipa_t* obj);

/**
 * This function extracts the ESipa.GetBoundProfilePackage JSON response.
 * @note To optimize memory, the json string will be modified during the data extraction (to decode the base64 in the 
 * same buffer as the JSON string is allocated). For this reason, the string pointer must be treated as a context 
 * after the execution of this function (the structure will be referencing the buffer data, so it cannot be deallocated).
 * 
 * @param[in]  json string in JSON format (can be not null-terminated).
 * @param[in]  json_len length of the json string (excluding the null-terminated character).
 * @param[out] obj Pointer to a get_bound_profile_package_response_esipa_t structure. The structure is populated following its 
 * documentation with the data from the json string if the function return is success. The structure data may be 
 * referencing data from the json string, do not deallocate the json string while using the structure.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned.
*/
ErrCode esipa_json_extractor__get_bound_profile_package_response_esipa(unsigned char* json, uint32_t json_len, get_bound_profile_package_response_esipa_t* obj);

/**
 * This function extracts the ESipa.CancelSession JSON response.
 * @note To optimize memory, the json string will be modified during the data extraction (to decode the base64 in the 
 * same buffer as the JSON string is allocated). For this reason, the string pointer must be treated as a context 
 * after the execution of this function (the structure will be referencing the buffer data, so it cannot be deallocated).
 * 
 * @param[in]  json string in JSON format (can be not null-terminated).
 * @param[in]  json_len length of the json string (excluding the null-terminated character).
 * @param[out] obj Pointer to a cancel_session_response_esipa_t structure. The structure is populated following its 
 * documentation with the data from the json string if the function return is success. The structure data may be 
 * referencing data from the json string, do not deallocate the json string while using the structure.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned.
*/
ErrCode esipa_json_extractor__cancel_session_response_esipa(unsigned char* json, uint32_t json_len, cancel_session_response_esipa_t* obj);
#endif
#endif