/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"
#include "esipa_typedefs.h"

/** 
 * This function extracts the CHOICE of a EsipaMessageFromEimToIpa TLV.
 *
 * @param[in]  buffer Pointer to a byte array with the EsipaMessageFromEimToIpa TLV.
 * @param[in]  buffer_size Size of the buffer byte array.
 * @param[out] choice Will point to the EsipaMessageFromEimToIpa CHOICE if the funtion result is success.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode esipa_tlv_extractor__esipa_message_from_eim_to_ipa_choice(const uint8_t* buffer, const uint32_t buffer_size, esipa_message_from_eim_to_ipa_choice_t* choice);

/** 
 * This function extracts data from a TransferEimPackageRequest TLV.
 *
 * @param[in]  buffer Pointer to a byte array with the TransferEimPackageRequest TLV.
 * @param[in]  buffer_size Size of the buffer byte array.
 * @param[out] obj A pointer to a transfer_eim_package_request_t structure. The structure is populated following its documentation with the data 
 * from the buffer if the function return is success. The structure data may be referencing buffer data, do not deallocate the buffer while using the structure.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode esipa_tlv_extractor__transfer_eim_package_request(const uint8_t* buffer, const uint32_t buffer_size, transfer_eim_package_request_t* obj);

/** 
 * This function extracts data from a GetEimPackageResponse TLV.
 *
 * @param[in]  buffer Pointer to a byte array with the GetEimPackageResponse TLV.
 * @param[in]  buffer_size Size of the buffer byte array.
 * @param[out] obj A pointer to a get_eim_package_response_t structure. The structure is populated following its documentation with the data 
 * from the buffer if the function return is success. The structure data may be referencing buffer data, do not deallocate the buffer while using the structure.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode esipa_tlv_extractor__get_eim_package_response(const uint8_t* buffer, const uint32_t buffer_size, get_eim_package_response_t* obj);

/** 
 * This function extracts data from a ProvideEimPackageResultResponse TLV.
 *
 * @param[in]  buffer Pointer to a byte array with the ProvideEimPackageResultResponse TLV.
 * @param[in]  buffer_size Size of the buffer byte array.
 * @param[out] obj A pointer to a provide_eim_package_result_response_t structure. The structure is populated following its documentation with the data 
 * from the buffer if the function return is success. The structure data may be referencing buffer data, do not deallocate the buffer while using the structure.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode esipa_tlv_extractor__provide_eim_package_result_response(const uint8_t* buffer, const uint32_t buffer_size, provide_eim_package_result_response_t* obj);

/** 
 * This function extracts data from a EuiccPackageRequest TLV.
 *
 * @param[in]  buffer Pointer to a byte array with the EuiccPackageRequest TLV.
 * @param[in]  buffer_size Size of the buffer byte array.
 * @param[out] obj A pointer to a euicc_package_request_plain_t structure. The structure is populated following its documentation with the data 
 * from the buffer if the function return is success. The structure data may be referencing buffer data, do not deallocate the buffer while using the structure.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode esipa_tlv_extractor__euicc_package_request(const uint8_t* buffer, const uint32_t buffer_size, euicc_package_request_t* obj);

#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
/** 
 * This function extracts data from a InitiateAuthenticationResponseEsipa TLV.
 *
 * @param[in]  buffer Pointer to a byte array with the InitiateAuthenticationResponseEsipa TLV.
 * @param[in]  buffer_size Size of the buffer byte array.
 * @param[out] obj A pointer to a initiate_authentication_response_esipa_t structure. The structure is populated following its documentation with the data 
 * from the buffer if the function return is success. The structure data may be referencing buffer data, do not deallocate the buffer while using the structure.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode esipa_tlv_extractor__initiate_authentication_response_esipa(const uint8_t* buffer, const uint32_t buffer_size, initiate_authentication_response_esipa_t* obj);

/** 
 * This function extracts data from a AuthenticateClientResponseEsipa TLV.
 *
 * @param[in]  buffer Pointer to a byte array with the AuthenticateClientResponseEsipa TLV.
 * @param[in]  buffer_size Size of the buffer byte array.
 * @param[out] obj A pointer to a authenticate_client_response_esipa_t structure. The structure is populated following its documentation with the data 
 * from the buffer if the function return is success. The structure data may be referencing buffer data, do not deallocate the buffer while using the structure.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode esipa_tlv_extractor__authenticate_client_response_esipa(const uint8_t* buffer, const uint32_t buffer_size, authenticate_client_response_esipa_t* obj);

/** 
 * This function extracts data from a GetBoundProfilePackageResponseEsipa TLV.
 *
 * @param[in]  buffer Pointer to a byte array with the GetBoundProfilePackageResponseEsipa TLV.
 * @param[in]  buffer_size Size of the buffer byte array.
 * @param[out] obj A pointer to a get_bound_profile_package_response_esipa_t structure. The structure is populated following its documentation with the data 
 * from the buffer if the function return is success. The structure data may be referencing buffer data, do not deallocate the buffer while using the structure.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode esipa_tlv_extractor__get_bound_profile_package_response_esipa(const uint8_t* buffer, const uint32_t buffer_size, get_bound_profile_package_response_esipa_t* obj);

/** 
 * This function extracts data from a CancelSessionResponseEsipa TLV.
 *
 * @param[in]  buffer Pointer to a byte array with the CancelSessionResponseEsipa TLV.
 * @param[in]  buffer_size Size of the buffer byte array.
 * @param[out] obj A pointer to a cancel_session_response_esipa_t structure. The structure is populated following its documentation with the data 
 * from the buffer if the function return is success.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode esipa_tlv_extractor__cancel_session_response_esipa(const uint8_t* buffer, const uint32_t buffer_size, cancel_session_response_esipa_t* obj);

#ifdef IPA_FEATURE_EIM_DOWNLOAD_DATA_HANDLING
/** 
 * This function returns if the MatchingId field is found or not in a CtxParams1 TLV.
 *
 * @param[in]  tlv Pointer to a byte array with the CtxParams1 TLV that may contain the MatchingId.
 * @param[in]  tlv_size Size of the tlv buffer.
 * @param[out] matchind_id_is_present A boolean pointer that will indicate if the MatchingId is found or not.
 * The value of this boolean is only valid if the function return is success.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode esipa_tlv_extractor__matching_id_is_present_ctx_params1_value(const uint8_t* tlv, const uint16_t tlv_size, bool* matchind_id_is_present);
#endif

#endif

ErrCode esipa_tlv_extractor__ipa_euicc_data_request(const uint8_t* buffer, const uint32_t buffer_size, ipa_euicc_data_request_t* ipa_euicc_data_request);
ErrCode esipa_tlv_extractor__profile_download_trigger_request(const uint8_t* buffer, const uint32_t buffer_size, profile_download_trigger_request_t* profile_download_request);
ErrCode esipa_tlv_extractor__eim_acknowledgements(const uint8_t* buffer, const uint32_t buffer_size, eim_acknowledgements_t* eim_acknowlegdements);


#ifdef SGP22
ErrCode esipa_tlv_extractor__euicc_package_request_plain_data(const uint8_t* euicc_package_req, const size_t euicc_package_req_size,
    size_t* eim_id_tlv_offset, uint8_t* eim_id_tlv_size, size_t* counter_value_tlv_offset, size_t* counter_value_tlv_size, 
    size_t* transaction_id_tlv_offset, uint8_t* transaction_id_tlv_size, size_t* psmo_tlv_offset, size_t* psmo_tlv_size);

ErrCode esipa_tlv_extractor__iccid_value_from_psmo(const uint8_t* psmo, const size_t psmo_size, iccid_t* iccid);
#endif
