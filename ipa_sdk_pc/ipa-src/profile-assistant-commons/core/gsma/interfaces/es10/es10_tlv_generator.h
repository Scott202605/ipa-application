/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "es10_typedefs.h"

/**
 * Generate a EuiccMemoryResetRequest TLV
 * 
 * @param[in, out] buffer Pointer to the buffer to where the EuiccMemoryResetRequest TLV will be generated. If null, the function will only calculate the offset that the 
 * buffer would have had if the EuiccMemoryResetRequest TLV had been appended.
 * @param[in] buffer_size Size of the buffer
 * @param[in] offset Offset of the buffer where the EuiccMemoryResetRequest TLV will be appended.
 * @param[in] obj Pointer to a euicc_memory_reset_request_t structure populated with the data needed to generate the TLV. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t es10_tlv_generator__euicc_memory_reset(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const euicc_memory_reset_request_t* obj);

/**
 * Generate a AuthenticateServerRequest TLV
 * 
 * @param[in, out] buffer Pointer to the buffer to where the AuthenticateServerRequest TLV will be generated. If null, the function will only calculate the offset that the 
 * buffer would have had if the AuthenticateServerRequest TLV had been appended.
 * @param[in] buffer_size Size of the buffer
 * @param[in] offset Offset of the buffer where the AuthenticateServerRequest TLV will be appended.
 * @param[in] obj Pointer to a authenticate_server_request_t structure populated with the data needed to generate the TLV. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t es10_tlv_generator__authenticate_server_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const authenticate_server_request_t* obj);

/**
 * Generate a PrepareDownloadRequest TLV
 * 
 * @param[in, out] buffer Pointer to the buffer to where the PrepareDownloadRequest TLV will be generated. If null, the function will only calculate the offset that the 
 * buffer would have had if the PrepareDownloadRequest TLV had been appended.
 * @param[in] buffer_size Size of the buffer
 * @param[in] offset Offset of the buffer where the PrepareDownloadRequest TLV will be appended.
 * @param[in] obj Pointer to a prepare_download_request_t structure populated with the data needed to generate the TLV. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t es10_tlv_generator__prepare_download_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const prepare_download_request_t* obj);

/**
 * Generate a CancelSessionRequest TLV
 * 
 * @param[in, out] buffer Pointer to the buffer to where the CancelSessionRequest TLV will be generated. If null, the function will only calculate the offset that the 
 * buffer would have had if the CancelSessionRequest TLV had been appended.
 * @param[in] buffer_size Size of the buffer
 * @param[in] offset Offset of the buffer where the CancelSessionRequest TLV will be appended.
 * @param[in] obj Pointer to a cancel_session_request_t structure populated with the data needed to generate the TLV. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t es10_tlv_generator__cancel_session_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const cancel_session_request_t* obj);

/**
 * Generate a RetrieveNotificationsListRequest TLV
 * 
 * @param[in, out] buffer Pointer to the buffer to where the RetrieveNotificationsListRequest TLV will be generated. If null, the function will only calculate the offset that the 
 * buffer would have had if the RetrieveNotificationsListRequest TLV had been appended.
 * @param[in] buffer_size Size of the buffer
 * @param[in] offset Offset of the buffer where the RetrieveNotificationsListRequest TLV will be appended.
 * @param[in] obj Pointer to a retrieve_notifications_list_request_t structure populated with the data needed to generate the TLV. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t es10_tlv_generator__retrieve_notifications_list_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const retrieve_notifications_list_request_t* obj);

/**
 * Generate a NotificationSentRequest TLV
 * 
 * @param[in, out] buffer Pointer to the buffer to where the NotificationSentRequest TLV will be generated. If null, the function will only calculate the offset that the 
 * buffer would have had if the NotificationSentRequest TLV had been appended.
 * @param[in] buffer_size Size of the buffer
 * @param[in] offset Offset of the buffer where the NotificationSentRequest TLV will be appended.
 * @param[in] obj Pointer to a notification_sent_request_t structure populated with the data needed to generate the TLV. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t es10_tlv_generator__notification_sent_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const notification_sent_request_t* obj);

/**
 * Generate a ProfileInfoListRequest TLV
 * 
 * @param[in, out] buffer Pointer to the buffer to where the ProfileInfoListRequest TLV will be generated. If null, the function will only calculate the offset that the 
 * buffer would have had if the ProfileInfoListRequest TLV had been appended.
 * @param[in] buffer_size Size of the buffer
 * @param[in] offset Offset of the buffer where the ProfileInfoListRequest TLV will be appended.
 * @param[in] obj Pointer to a profile_info_list_request_t structure populated with the data needed to generate the TLV. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t es10_tlv_generator__profile_info_list_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const profile_info_list_request_t* obj);

/**
 * Generate a SetDefaultDpAddressRequest TLV
 * 
 * @param[in, out] buffer Pointer to the buffer to where the SetDefaultDpAddressRequest TLV will be generated. If null, the function will only calculate the offset that the 
 * buffer would have had if the SetDefaultDpAddressRequest TLV had been appended.
 * @param[in] buffer_size Size of the buffer
 * @param[in] offset Offset of the buffer where the SetDefaultDpAddressRequest TLV will be appended.
 * @param[in] obj Pointer to a set_default_dp_address_request_t structure populated with the data needed to generate the TLV. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t es10_tlv_generator__set_default_dp_address_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const set_default_dp_address_request_t* obj);

#ifdef SGP22
/**
 * Generate a ListNotificationRequest TLV
 * 
 * @param[in, out] buffer Pointer to the buffer to where the ListNotificationRequest TLV will be generated. If null, the function will only calculate the offset that the 
 * buffer would have had if the ListNotificationRequest TLV had been appended.
 * @param[in] buffer_size Size of the buffer
 * @param[in] offset Offset of the buffer where the ListNotificationRequest TLV will be appended.
 * @param[in] obj Pointer to a list_notification_request_t structure populated with the data needed to generate the TLV. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t es10_tlv_generator__list_notification_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const list_notification_request_t* obj);

/**
 * Generate a EnableProfileRequest TLV
 * 
 * @param[in, out] buffer Pointer to the buffer to where the EnableProfileRequest TLV will be generated. If null, the function will only calculate the offset that the 
 * buffer would have had if the EnableProfileRequest TLV had been appended.
 * @param[in] buffer_size Size of the buffer
 * @param[in] offset Offset of the buffer where the EnableProfileRequest TLV will be appended.
 * @param[in] obj Pointer to a enable_profile_request_t structure populated with the data needed to generate the TLV. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t es10_tlv_generator__enable_profile_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const enable_profile_request_t* obj);

/**
 * Generate a DisableProfileRequest TLV
 * 
 * @param[in, out] buffer Pointer to the buffer to where the DisableProfileRequest TLV will be generated. If null, the function will only calculate the offset that the 
 * buffer would have had if the DisableProfileRequest TLV had been appended.
 * @param[in] buffer_size Size of the buffer
 * @param[in] offset Offset of the buffer where the DisableProfileRequest TLV will be appended.
 * @param[in] obj Pointer to a disable_profile_request_t structure populated with the data needed to generate the TLV. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t es10_tlv_generator__disable_profile_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const disable_profile_request_t* obj);

/**
 * Generate a DeleteProfileRequest TLV
 * 
 * @param[in, out] buffer Pointer to the buffer to where the DeleteProfileRequest TLV will be generated. If null, the function will only calculate the offset that the 
 * buffer would have had if the DeleteProfileRequest TLV had been appended.
 * @param[in] buffer_size Size of the buffer
 * @param[in] offset Offset of the buffer where the DeleteProfileRequest TLV will be appended.
 * @param[in] obj Pointer to a delete_profile_request_t structure populated with the data needed to generate the TLV. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t es10_tlv_generator__delete_profile_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const delete_profile_request_t* obj);

/**
 * Generate a SetNicknameRequest TLV
 * 
 * @param[in, out] buffer Pointer to the buffer to where the SetNicknameRequest TLV will be generated. If null, the function will only calculate the offset that the 
 * buffer would have had if the SetNicknameRequest TLV had been appended.
 * @param[in] buffer_size Size of the buffer
 * @param[in] offset Offset of the buffer where the SetNicknameRequest TLV will be appended.
 * @param[in] obj Pointer to a set_nickname_request_t structure populated with the data needed to generate the TLV. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t es10_tlv_generator__set_nickname_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const set_nickname_request_t* obj);
#endif

#ifdef SGP32
/**
 * Generate a AddInitialEimRequest TLV
 * 
 * @param[in, out] buffer Pointer to the buffer to where the AddInitialEimRequest TLV will be generated. If null, the function will only calculate the offset that the 
 * buffer would have had if the AddInitialEimRequest TLV had been appended.
 * @param[in] buffer_size Size of the buffer
 * @param[in] offset Offset of the buffer where the AddInitialEimRequest TLV will be appended.
 * @param[in] obj Pointer to a eim_configuration_data_t structure populated with the data needed to generate the TLV. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t es10_tlv_generator__add_initial_eim_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const eim_configuration_data_t* obj);

/**
 * Generate a GetCertsRequest TLV
 * 
 * @param[in, out] buffer Pointer to the buffer to where the GetCertsRequest TLV will be generated. If null, the function will only calculate the offset that the 
 * buffer would have had if the GetCertsRequest TLV had been appended.
 * @param[in] buffer_size Size of the buffer
 * @param[in] offset Offset of the buffer where the GetCertsRequest TLV will be appended.
 * @param[in] obj Pointer to a get_certs_request_t structure populated with the data needed to generate the TLV. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t es10_tlv_generator__get_certs_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const get_certs_request_t* obj);

/**
 * Generate a ImmediateEnableRequest TLV
 * 
 * @param[in, out] buffer Pointer to the buffer to where the ImmediateEnableRequest TLV will be generated. If null, the function will only calculate the offset that the 
 * buffer would have had if the ProfileRollbackRequest TLV had been appended.
 * @param[in] buffer_size Size of the buffer
 * @param[in] offset Offset of the buffer where the ImmediateEnableRequest TLV will be appended.
 * @param[in] obj Pointer to a immediate_enable_request_t structure populated with the data needed to generate the TLV. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t es10_tlv_generator__immediate_enable_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const immediate_enable_request_t* obj);

/**
 * Generate a ProfileRollbackRequest TLV
 * 
 * @param[in, out] buffer Pointer to the buffer to where the ProfileRollbackRequest TLV will be generated. If null, the function will only calculate the offset that the 
 * buffer would have had if the ProfileRollbackRequest TLV had been appended.
 * @param[in] buffer_size Size of the buffer
 * @param[in] offset Offset of the buffer where the ProfileRollbackRequest TLV will be appended.
 * @param[in] obj Pointer to a profile_rollback_request_t structure populated with the data needed to generate the TLV. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t es10_tlv_generator__profile_rollback_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const profile_rollback_request_t* obj);

/**
 * Generate a ConfigureImmediateProfileEnablingRequest TLV
 * 
 * @param[in, out] buffer Pointer to the buffer to where the ConfigureImmediateProfileEnablingRequest TLV will be generated. If null, the function will only calculate the offset that the 
 * buffer would have had if the ConfigureImmediateProfileEnablingRequest TLV had been appended.
 * @param[in] buffer_size Size of the buffer
 * @param[in] offset Offset of the buffer where the ConfigureImmediateProfileEnablingRequest TLV will be appended.
 * @param[in] obj Pointer to a configure_immediate_profile_enabling_request_t structure populated with the data needed to generate the TLV. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t es10_tlv_generator__configure_immediate_profile_enabling_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const configure_immediate_profile_enabling_request_t* obj);


/**
 * Generate a GetEimConfigurationDataRequest TLV
 * 
 * @param[in, out] buffer Pointer to the buffer to where the GetEimConfigurationDataRequest TLV will be generated. If null, the function will only calculate the offset that the 
 * buffer would have had if the GetEimConfigurationDataRequest TLV had been appended.
 * @param[in] buffer_size Size of the buffer
 * @param[in] offset Offset of the buffer where the GetEimConfigurationDataRequest TLV will be appended.
 * @param[in] obj Pointer to a get_eim_configuration_data_request_t structure populated with the data needed to generate the TLV. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t es10_tlv_generator__get_eim_configuration_data_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const get_eim_configuration_data_request_t* obj);

#ifdef EXTRA_FEATURE_EMERGENCY_PROFILE_MANAGMENT
/**
 * Generate an EnableEmergencyProfileRequest TLV.
 *
 * @param[in, out] buffer Pointer to the buffer to where the EnableEmergencyProfileRequest TLV will be generated. If null, the function will only calculate the offset that the
 * buffer would have had if the EnableEmergencyProfileRequest TLV had been appended.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] offset Offset of the buffer where the EnableEmergencyProfileRequest TLV will be appended.
 * @param[in] obj Pointer to an enable_emergency_profile_request_t structure populated with the data needed to generate the TLV. The structure is populated following its documentation.
 *
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t es10_tlv_generator__enable_emergency_profile_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const enable_emergency_profile_request_t* obj);

/**
 * Generate a DisableEmergencyProfileRequest TLV.
 *
 * @param[in, out] buffer Pointer to the buffer to where the DisableEmergencyProfileRequest TLV will be generated. If null, the function will only calculate the offset that the
 * buffer would have had if the DisableEmergencyProfileRequest TLV had been appended.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] offset Offset of the buffer where the DisableEmergencyProfileRequest TLV will be appended.
 * @param[in] obj Pointer to a disable_emergency_profile_request_t structure populated with the data needed to generate the TLV. The structure is populated following its documentation.
 *
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t es10_tlv_generator__disable_emergency_profile_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const disable_emergency_profile_request_t* obj);
#endif

#ifdef EXTRA_FEATURE_FALLBACK_MECHANISM
/**
 * Generate a ExecuteFallbackMechanismRequest TLV
 * 
 * @param[in, out] buffer Pointer to the buffer to where the ExecuteFallbackMechanismRequest TLV will be generated. If null, the function will only calculate the offset that the 
 * buffer would have had if the ExecuteFallbackMechanismRequest TLV had been appended.
 * @param[in] buffer_size Size of the buffer
 * @param[in] offset Offset of the buffer where the ExecuteFallbackMechanismRequest TLV will be appended.
 * @param[in] obj Pointer to a execute_fallback_mechanism_request_t structure populated with the data needed to generate the TLV. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t es10_tlv_generator__execute_fallback_mechanism_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const execute_fallback_mechanism_request_t* obj);

/**
 * Generate a ReturnFromFallbackRequest TLV
 * 
 * @param[in, out] buffer Pointer to the buffer to where the ReturnFromFallbackRequest TLV will be generated. If null, the function will only calculate the offset that the 
 * buffer would have had if the ReturnFromFallbackRequest TLV had been appended.
 * @param[in] buffer_size Size of the buffer
 * @param[in] offset Offset of the buffer where the ReturnFromFallbackRequest TLV will be appended.
 * @param[in] obj Pointer to a return_from_fallback_request_t structure populated with the data needed to generate the TLV. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t es10_tlv_generator__return_from_fallback_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const return_from_fallback_request_t* obj);
#endif
#endif
