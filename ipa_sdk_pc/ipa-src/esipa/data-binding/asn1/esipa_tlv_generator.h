/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "esipa_message_from_ipa_to_eim_typedefs.h"

/**
 * Generate a EsipaMessageFromIpaToEim TLV
 * 
 * @param[in, out] buffer Pointer to the buffer to where the EsipaMessageFromIpaToEim TLV will be generated. If null, the function will only calculate the offset that the 
 * buffer would have had if the EsipaMessageFromIpaToEim TLV had been appended.
 * @param[in] buffer_size Size of the buffer
 * @param[in] offset Offset of the buffer where the EsipaMessageFromIpaToEim TLV will be appended.
 * @param[in] obj Pointer to a esipa_message_from_ipa_to_eim_t structure populated with the data needed to generate the TLV. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t esipa_tlv_generator__esipa_message_from_ipa_to_eim(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const esipa_message_from_ipa_to_eim_t* obj);

/**
 * Generate a HandleNotificationEsipa TLV
 * 
 * @param[in, out] buffer Pointer to the buffer to where the HandleNotificationEsipa TLV will be generated. If null, the function will only calculate the offset that the 
 * buffer would have had if the HandleNotificationEsipa TLV had been appended.
 * @param[in] buffer_size Size of the buffer
 * @param[in] offset Offset of the buffer where the HandleNotificationEsipa TLV will be appended.
 * @param[in] obj Pointer to a handle_notification_esipa_t structure populated with the data needed to generate the TLV. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t esipa_tlv_generator__handle_notification_esipa(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const handle_notification_esipa_t* obj);

/**
 * Generate a TransferEimPackageResponse TLV
 * 
 * @param[in, out] buffer Pointer to the buffer to where the TransferEimPackageResponse TLV will be generated. If null, the function will only calculate the offset that the 
 * buffer would have had if the TransferEimPackageResponse TLV had been appended.
 * @param[in] buffer_size Size of the buffer
 * @param[in] offset Offset of the buffer where the TransferEimPackageResponse TLV will be appended.
 * @param[in] obj Pointer to a transfer_eim_package_response_t structure populated with the data needed to generate the TLV. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t esipa_tlv_generator__transfer_eim_package_response(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const transfer_eim_package_response_t* obj);

/**
 * Generate a GetEimPackageRequest TLV
 * 
 * @param[in, out] buffer Pointer to the buffer to where the GetEimPackageRequest TLV will be generated. If null, the function will only calculate the offset that the 
 * buffer would have had if the GetEimPackageRequest TLV had been appended.
 * @param[in] buffer_size Size of the buffer
 * @param[in] offset Offset of the buffer where the GetEimPackageRequest TLV will be appended.
 * @param[in] obj Pointer to a get_eim_package_request_t structure populated with the data needed to generate the TLV. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t esipa_tlv_generator__get_eim_package_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const get_eim_package_request_t* obj);

/**
 * Generate a ProvideEimPackageResult TLV
 * 
 * @param[in, out] buffer Pointer to the buffer to where the ProvideEimPackageResult TLV will be generated. If null, the function will only calculate the offset that the 
 * buffer would have had if the ProvideEimPackageResult TLV had been appended.
 * @param[in] buffer_size Size of the buffer
 * @param[in] offset Offset of the buffer where the ProvideEimPackageResult TLV will be appended.
 * @param[in] obj Pointer to a provide_eim_package_result_t structure populated with the data needed to generate the TLV. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t esipa_tlv_generator__provide_eim_package_result(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const provide_eim_package_result_t* obj);

#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
/**
 * Generate a InitiateAuthenticationRequestEsipa TLV
 * 
 * @param[in, out] buffer Pointer to the buffer to where the InitiateAuthenticationRequestEsipa TLV will be generated. If null, the function will only calculate the offset that the 
 * buffer would have had if the InitiateAuthenticationRequestEsipa TLV had been appended.
 * @param[in] buffer_size Size of the buffer
 * @param[in] offset Offset of the buffer where the InitiateAuthenticationRequestEsipa TLV will be appended.
 * @param[in] obj Pointer to a initiate_authentication_request_esipa_t structure populated with the data needed to generate the TLV. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t esipa_tlv_generator__initiate_authentication_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const initiate_authentication_request_esipa_t* obj);

/**
 * Generate a AuthenticateClientRequestEsipa TLV
 * 
 * @param[in, out] buffer Pointer to the buffer to where the AuthenticateClientRequestEsipa TLV will be generated. If null, the function will only calculate the offset that the 
 * buffer would have had if the AuthenticateClientRequestEsipa TLV had been appended.
 * @param[in] buffer_size Size of the buffer
 * @param[in] offset Offset of the buffer where the AuthenticateClientRequestEsipa TLV will be appended.
 * @param[in] obj Pointer to a authenticate_client_request_esipa_t structure populated with the data needed to generate the TLV. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t esipa_tlv_generator__authenticate_client_request_esipa(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const authenticate_client_request_esipa_t* obj);

/**
 * Generate a CancelSessionRequestEsipa TLV
 * 
 * @param[in, out] buffer Pointer to the buffer to where the CancelSessionRequestEsipa TLV will be generated. If null, the function will only calculate the offset that the 
 * buffer would have had if the CancelSessionRequestEsipa TLV had been appended.
 * @param[in] buffer_size Size of the buffer
 * @param[in] offset Offset of the buffer where the CancelSessionRequestEsipa TLV will be appended.
 * @param[in] obj Pointer to a cancel_session_request_esipa_t structure populated with the data needed to generate the TLV. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t esipa_tlv_generator__cancel_session_request_esipa(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const cancel_session_request_esipa_t* obj);

/**
 * Generate a GetBoundProfilePackageRequest TLV
 *
 * @param[in, out] buffer Pointer to the buffer to where the GetBoundProfilePackageRequest TLV will be generated. If null, the function will only calculate the offset that the
 * buffer would have had if the GetBoundProfilePackageRequest TLV had been appended.
 * @param[in] buffer_size Size of the buffer
 * @param[in] offset Offset of the buffer where the GetBoundProfilePackageRequest TLV will be appended.
 * @param[in] obj Pointer to a get_bound_profile_package_request_esipa_t structure populated with the data needed to generate the TLV. The structure is populated following its documentation.
 *
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t esipa_tlv_generator__get_bound_profile_package_request_esipa(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const get_bound_profile_package_request_esipa_t* obj);
#endif

int32_t esipa_tlv_generator__ipa_euicc_data_response(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const ipa_euicc_data_response_t* obj);
int32_t esipa_tlv_generator__eim_package_result(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const eim_package_result_t* obj);

#ifdef SGP22
int32_t esipa_tlv_generator__euicc_package_result(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const uint8_t* eim_id, const uint8_t eim_id_size, const uint8_t* counter_value, const uint32_t counter_value_size, 
    const uint8_t* transaction_id, const uint8_t transaction_id_size, const uint8_t* euicc_result_data, const uint32_t euicc_result_data_size);
#endif
