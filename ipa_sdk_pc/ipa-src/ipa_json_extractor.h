/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "es10_typedefs.h"

/**
 * JSON format:
 * {
 *   "deleteOperationalProfiles": Boolean -- OPTIONAL
 *   "deleteFieldLoadedTestProfiles": Boolean -- OPTIONAL
 *   "resetDefaultSmdpAddress": Boolean -- OPTIONAL
 *   "resetEimConfigData": Boolean -- OPTIONAL (Only SGP.32)
 *   "resetAutoEnableConfig": Boolean -- OPTIONAL (Only SGP.32)
 * }
 * 
 * @param[in]  json A string with the JSON format described (can be not null-terminated).
 * @param[in]  json_len length of the json string (excluding the null-terminated character)
 * @param[out] obj A pointer to a euicc_memory_reset_request_t structure. The structure is populated 
 * following its documentation with the data from the json string if the function return is success. The structure data don't reference any data from 
 * the json string, so the json string can be deallocated after the execution of the function.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned. 
*/
ErrCode ipa_json_extractor__euicc_memory_reset_request(const unsigned char* json, uint32_t json_len, euicc_memory_reset_request_t* obj);

/**
 * JSON format:
 * {
 *   "defaultDpAddress": String -- OPTIONAL
 * }
 * 
 * @param[in]  json A string with the JSON format described (can be not null-terminated).
 * @param[in]  json_len length of the json string (excluding the null-terminated character)
 * @param[out] obj A pointer to a set_default_dp_address_request_t structure initialized with SET_DEFAULT_DP_ADDRESS_INITIALIZER. The structure is populated 
 * following its documentation with the data from the json string if the function return is success. The structure data don't reference any data from 
 * the json string, so the json string can be deallocated after the execution of the function.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned. 
*/
ErrCode ipa_json_extractor__set_default_dp_address_request(const unsigned char* json, uint32_t json_len, set_default_dp_address_request_t* obj);

#ifdef SGP32
/**
 * JSON format:
 * {
 *   "eimId": String
 *   "eimFqdn": String -- OPTIONAL
 *   "eimIdType": Integer -- OPTIONAL, eimIdTypeOid(1),	eimIdTypeFqdn(2), eimIdTypeProprietary(3)
 *   "counterValue": Integer -- OPTIONAL
 *   "associationToken": Integer -- OPTIONAL
 *   "eimPublicKey" | "eimCertificate": String -- OPTIONAL, in Base64 format
 *   "trustedEimPkTls" | "trustedCertificateTls": String -- OPTIONAL, in Base64 format
 *   "eimRetrieveHttps": Boolean -- OPTIONAL
 *   "eimRetrieveCoaps": Boolean -- OPTIONAL
 *   "eimInjectHttps": Boolean -- OPTIONAL
 *   "eimInjectCoaps": Boolean -- OPTIONAL
 *   "eimProprietary": Boolean -- OPTIONAL
 *   "euiccCiPKId": String -- OPTIONAL, in hexadecimal format
 *   "indirectProfileDownload": Boolean -- OPTIONAL
 * }
 * 
 * @param[in]  json A string with the JSON format described (can be not null-terminated).
 * @param[in]  json_len length of the json string (excluding the null-terminated character)
 * @param[out] obj A pointer to a eim_configuration_data_t structure. The structure is populated following its documentation with the data from the json 
 * string if the function return is success. The structure data may be referencing data from the json string, do not deallocate the json string while using 
 * the structure.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned. 
*/
ErrCode ipa_json_extractor__eim_configuration_data(unsigned char* json, uint32_t json_len, eim_configuration_data_t* obj);

/**
 * JSON format:
 * {
 *   "immediateEnableFlag": Boolean -- OPTIONAL
 *   "defaultSmdpOid": String -- OPTIONAL
 *   "defaultSmdpAddress": String -- OPTIONAL
 * }
 * 
 * @param[in]  json A string with the JSON format described (can be not null-terminated).
 * @param[in]  json_len length of the json string (excluding the null-terminated character)
 * @param[out] obj A pointer to a configure_immediate_profile_enabling_request_t structure initialized with CONFIGURE_IMMEDIATE_PROFILE_ENABLING_REQUEST_INITIALIZER. 
 * The structure is populated following its documentation with the data from the json string if the function return is success. The structure data may be 
 * referencing data from the json string, do not deallocate the json string while using the structure.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned. 
*/
ErrCode ipa_json_extractor__configure_immediate_profile_enabling_request(const unsigned char* json, uint32_t json_len, configure_immediate_profile_enabling_request_t* obj);
#endif
