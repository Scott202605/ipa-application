/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once

#include "typedefs.h"
#include "tlv_data_extractor.h"
#include "es10_typedefs.h"

/** 
 * This function extracts data from a ServerSigned1 TLV.
 *
 * @param[in]  tlv Pointer to a byte array with the ServerSigned1 TLV.
 * @param[in]  tlv_size Size of the tlv buffer.
 * @param[out] obj A pointer to a server_signed_1_t structure. The structure is populated following its documentation with the data 
 * from the tlv buffer if the function return is success. The structure data don't reference any data from the tlv buffer, so the tlv 
 * buffer can be deallocated after the execution of the function.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode es10_tlv_extractor__server_signed_1(const uint8_t *tlv, const uint32_t tlv_size,
                                            server_signed_1_t *obj);

/** 
 * This function extracts data from a SmdpSigned2 TLV.
 *
 * @param[in]  tlv Pointer to a byte array with the SmdpSigned2 TLV.
 * @param[in]  tlv_size Size of the tlv buffer.
 * @param[out] obj A pointer to a smdp_signed_2_t structure. The structure is populated following its documentation with the data 
 * from the tlv buffer if the function return is success. The structure data may be referencing data from the tlv buffer, do not 
 * deallocate the tlv buffer while using the structure.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode es10_tlv_extractor__smdp_signed_2(const uint8_t *tlv, const uint32_t tlv_size,
                                          smdp_signed_2_t *obj);

/** 
 * This function extracts data from a EuiccConfiguredAddressesResponse TLV.
 *
 * @param[in]  tlv Pointer to a byte array with the EuiccConfiguredAddressesResponse TLV.
 * @param[in]  tlv_size Size of the tlv buffer.
 * @param[out] obj A pointer to a euicc_configured_addresses_response_t structure. The structure is populated following its documentation 
 * with the data from the tlv buffer if the function return is success. The structure data don't reference any data from the tlv buffer, so 
 * the tlv buffer can be deallocated after the execution of the function.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode
es10_tlv_extractor__euicc_configured_addresses_response(const uint8_t *tlv, const uint32_t tlv_size,
                                                        euicc_configured_addresses_response_t *addresses);

/** 
 * This function extracts data from a GetEuiccChallengeResponse TLV.
 *
 * @param[in]  tlv Pointer to a byte array with the GetEuiccChallengeResponse TLV.
 * @param[in]  tlv_size Size of the tlv buffer.
 * @param[out] obj A pointer to a get_euicc_challenge_response_t structure. The structure is populated following its documentation 
 * with the data from the tlv buffer if the function return is success. The structure data don't reference any data from the tlv buffer, so 
 * the tlv buffer can be deallocated after the execution of the function.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode
es10_tlv_extractor__get_euicc_challenge_response(const uint8_t *tlv, const uint32_t tlv_size,
                                                 get_euicc_challenge_response_t *obj);

/** 
 * This function extracts data from a EuiccMemoryResetResponse TLV.
 *
 * @param[in]  tlv Pointer to a byte array with the EuiccMemoryResetResponse TLV.
 * @param[in]  tlv_size Size of the tlv buffer.
 * @param[out] obj A pointer to a euicc_memory_reset_response_t structure. The structure is populated following its documentation 
 * with the data from the tlv buffer if the function return is success. The structure data don't reference any data from the tlv buffer, so 
 * the tlv buffer can be deallocated after the execution of the function.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode es10_tlv_extractor__euicc_memory_reset_response(const uint8_t *tlv, const uint32_t tlv_size,
                                                        euicc_memory_reset_response_t *obj);

/** 
 * This function extracts data from a BoundProfilePackage TLV.
 *
 * @param[in]  tlv Pointer to a byte array with the BoundProfilePackage TLV.
 * @param[in]  tlv_size Size of the tlv buffer.
 * @param[out] obj A pointer to a bound_profile_package_t structure. The structure is populated following its documentation with the data 
 * from the tlv buffer if the function return is success. The structure data may be referencing data from the tlv buffer, do not 
 * deallocate the tlv buffer while using the structure.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode es10_tlv_extractor__bound_profile_package(const uint8_t *tlv, const uint32_t tlv_size,
                                                  bound_profile_package_t *obj);

/** 
 * This function extracts data from a InitialiseSecureChannelRequest TLV.
 *
 * @param[in]  tlv Pointer to a byte array with the InitialiseSecureChannelRequest TLV.
 * @param[in]  tlv_size Size of the tlv buffer.
 * @param[out] obj A pointer to a initialise_secure_channel_request_t structure. The structure is populated following its documentation 
 * with the data from the tlv buffer if the function return is success. The structure data may be referencing data from the tlv buffer, 
 * do not deallocate the tlv buffer while using the structure.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode es10_tlv_extractor__initialise_secure_channel(const uint8_t *tlv, const uint32_t tlv_size,
                                                      initialise_secure_channel_request_t *obj);

ErrCode es10_tlv_extractor__store_metadata_request(const uint8_t *tlv, const uint32_t tlv_size,
                                                   profile_info_t *obj);

/** 
 * This function segments a BoundProfilePackage TLV.
 *
 * @param[in]  tlv Pointer to a byte array with the BoundProfilePackage TLV.
 * @param[in]  tlv_size Size of the tlv buffer.
 * @param[out] obj A pointer to a segmented_bound_profile_package_t structure. The structure is populated following its documentation 
 * with the data from the tlv buffer if the function return is success. The structure data may be referencing data from the tlv buffer, 
 * do not deallocate the tlv buffer while using the structure.
 *
 * @return eOk in case the data segmentation has been done successfully, otherwise an error code is returned.
*/
ErrCode
es10_tlv_extractor__segmented_bound_profile_package(const uint8_t *tlv, const uint32_t tlv_size,
                                                    segmented_bound_profile_package_t *obj);

/** 
 * This function extracts data from a NotificationEvent TLV.
 *
 * @param[in]  tag ASN.1 tag of the NotificationEvent TLV
 * @param[in]  tlv Pointer to a byte array with the NotificationEvent TLV.
 * @param[in]  tlv_size Size of the tlv buffer.
 * @param[out] obj A pointer to a notification_event_t enum. The enum will point to the NotificationEvent of the TLV if the function return is success.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode es10_tlv_extractor__notification_event(const unsigned short tag, const uint8_t *tlv,
                                               const uint32_t tlv_size, notification_event_t *obj);

/** 
 * This function extracts data from a NotificationMetadata TLV.
 *
 * @param[in]  tlv Pointer to a byte array with the NotificationMetadata TLV.
 * @param[in]  tlv_size Size of the tlv buffer.
 * @param[out] obj A pointer to a notification_metadata_t structure. The structure is populated following its documentation with the 
 * data from the tlv buffer if the function return is success. The structure data don't reference any data from the tlv buffer, so 
 * the tlv buffer can be deallocated after the execution of the function.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode es10_tlv_extractor__notification_metadata(const uint8_t *tlv, const uint32_t tlv_size,
                                                  notification_metadata_t *obj);

/** 
 * This function extracts data from a ProfileInstallationResult TLV.
 *
 * @param[in]  tlv Pointer to a byte array with the ProfileInstallationResult TLV.
 * @param[in]  tlv_size Size of the tlv buffer.
 * @param[out] obj A pointer to a profile_installation_result_t structure. The structure is populated following its documentation 
 * with the data from the tlv buffer if the function return is success. The structure data may be referencing data from the tlv buffer, 
 * do not deallocate the tlv buffer while using the structure.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode es10_tlv_extractor__profile_installation_result(const uint8_t *tlv, const uint32_t tlv_size,
                                                        profile_installation_result_t *obj);

/** 
 * This function extracts data from a RetrieveNotificationsListResponse TLV.
 *
 * @param[in]  tlv Pointer to a byte array with the RetrieveNotificationsListResponse TLV.
 * @param[in]  tlv_size Size of the tlv buffer.
 * @param[out] obj A pointer to a retrieve_notifications_list_response_t structure. The structure is populated following its documentation 
 * with the data from the tlv buffer if the function return is success. The structure data may be referencing data from the tlv buffer, 
 * do not deallocate the tlv buffer while using the structure.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode es10_tlv_extractor__retrieve_notifications_list_response(const uint8_t *tlv,
                                                                 const uint32_t tlv_size,
                                                                 retrieve_notifications_list_response_t *obj);

ErrCode
es10_tlv_extractor__notifications_list_from_retrieve_notifications_list_response(const uint8_t *tlv,
                                                                                 const uint32_t tlv_size,
                                                                                 asn1_list_iterator_t *obj);

/** 
 * This function extracts the NotificationMetadata from a PendingNotification TLV.
 *
 * @param[in]  tlv Pointer to a byte array with the PendingNotification TLV.
 * @param[in]  tlv_size Size of the tlv buffer.
 * @param[out] obj A pointer to a notification_metadata_t structure. The structure is populated following its documentation with the data 
 * from the tlv buffer if the function return is success. The structure data don't reference any data from the tlv buffer, so the tlv buffer 
 * can be deallocated after the execution of the function.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode es10_tlv_extractor__notification_metadata_from_pending_notification(const uint8_t *tlv,
                                                                            const uint32_t tlv_size,
                                                                            notification_metadata_t *obj);

/** 
 * This function extracts data from a NotificationSentResponse TLV.
 *
 * @param[in]  tlv Pointer to a byte array with the NotificationSentResponse TLV.
 * @param[in]  tlv_size Size of the tlv buffer.
 * @param[out] obj A pointer to a notification_sent_response_t structure. The structure is populated following its documentation with 
 * the data from the tlv buffer if the function return is success. The structure data don't reference any data from the tlv buffer, 
 * so the tlv buffer can be deallocated after the execution of the function.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode es10_tlv_extractor__notification_sent_response(const uint8_t *tlv, const uint32_t tlv_size,
                                                       notification_sent_response_t *obj);

ErrCode es10_tlv_extractor__profile_info_list_response(const uint8_t *tlv, uint32_t tlv_size,
                                                       profile_info_list_response_t *obj);

ErrCode
es10_tlv_extractor__profile_info(const uint8_t *tlv, const uint32_t tlv_size, profile_info_t *obj);

ErrCode
es10_tlv_extractor__profile_info_enabled_profile(const uint8_t *tlv, const uint32_t tlv_size,
                                                 bool *is_profile_enabled, profile_info_t *obj);

ErrCode es10_tlv_extractor__get_all_profiles_info(const uint8_t *tlv, const uint32_t tlv_size,
                                                  profile_info_t **profiles,
                                                  uint32_t *num_profiles);

ErrCode es10_tlv_extractor__notification_configuration_information(const uint8_t *tlv,
                                                                   const uint32_t tlv_size,
                                                                   notification_configuration_information_t *obj);

/** 
 * This function extracts data from a GetEuiccDataResponse TLV.
 *
 * @param[in]  tlv Pointer to a byte array with the GetEuiccDataResponse TLV.
 * @param[in]  tlv_size Size of the tlv buffer.
 * @param[out] obj A pointer to a get_euicc_data_response_t structure. The structure is populated following its documentation with 
 * the data from the tlv buffer if the function return is success. The structure data don't reference any data from the tlv buffer, 
 * so the tlv buffer can be deallocated after the execution of the function.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode es10_tlv_extractor__get_euicc_data_response(const uint8_t *tlv, uint32_t tlv_size,
                                                    get_euicc_data_response_t *obj);

ErrCode es10_tlv_extractor__get_rat_response(const uint8_t *tlv, uint32_t tlv_size,
                                             get_rat_response_t *obj);

ErrCode es10_tlv_extractor__profile_policy_authorisation_rule(const uint8_t *tlv, uint32_t tlv_size,
                                                              profile_policy_authorisation_rule_t *obj);

/** 
 * This function extracts data from a SetDefaultDpAddressResponse TLV.
 *
 * @param[in]  tlv Pointer to a byte array with the SetDefaultDpAddressResponse TLV.
 * @param[in]  tlv_size Size of the tlv buffer.
 * @param[out] obj A pointer to a set_default_dp_address_response_t structure. The structure is populated following its documentation with 
 * the data from the tlv buffer if the function return is success. The structure data don't reference any data from the tlv buffer, 
 * so the tlv buffer can be deallocated after the execution of the function.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode
es10_tlv_extractor__set_default_dp_address_response(const uint8_t *tlv, const uint32_t tlv_size,
                                                    set_default_dp_address_response_t *obj);

#ifdef SGP22
/** 
 * This function extracts data from a ListNotificationResponse TLV.
 *
 * @param[in]  tlv Pointer to a byte array with the ListNotificationResponse TLV.
 * @param[in]  tlv_size Size of the tlv buffer.
 * @param[out] obj A pointer to a list_notification_response_t structure. The structure is populated following its documentation 
 * with the data from the tlv buffer if the function return is success. The structure data may be referencing data from the tlv 
 * buffer, do not deallocate the tlv buffer while using the structure.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode es10_tlv_extractor__list_notification_response(const uint8_t* tlv, const uint32_t tlv_size, list_notification_response_t* obj);

/** 
 * This function extracts data from a EnableProfileResponse TLV.
 *
 * @param[in]  tlv Pointer to a byte array with the EnableProfileResponse TLV.
 * @param[in]  tlv_size Size of the tlv buffer.
 * @param[out] obj A pointer to a enable_profile_response_t structure. The structure is populated following its documentation with 
 * the data from the tlv buffer if the function return is success. The structure data don't reference any data from the tlv buffer, 
 * so the tlv buffer can be deallocated after the execution of the function.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode es10_tlv_extractor__enable_profile_response(const uint8_t* tlv, const uint32_t tlv_size, enable_profile_response_t* obj);

/** 
 * This function extracts data from a DisableProfileResponse TLV.
 *
 * @param[in]  tlv Pointer to a byte array with the DisableProfileResponse TLV.
 * @param[in]  tlv_size Size of the tlv buffer.
 * @param[out] obj A pointer to a disable_profile_response_t structure. The structure is populated following its documentation with 
 * the data from the tlv buffer if the function return is success. The structure data don't reference any data from the tlv buffer, 
 * so the tlv buffer can be deallocated after the execution of the function.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode es10_tlv_extractor__disable_profile_response(const uint8_t* tlv, const uint32_t tlv_size, disable_profile_response_t* obj);

/** 
 * This function extracts data from a DeleteProfileResponse TLV.
 *
 * @param[in]  tlv Pointer to a byte array with the DeleteProfileResponse TLV.
 * @param[in]  tlv_size Size of the tlv buffer.
 * @param[out] obj A pointer to a delete_profile_response_t structure. The structure is populated following its documentation with 
 * the data from the tlv buffer if the function return is success. The structure data don't reference any data from the tlv buffer, 
 * so the tlv buffer can be deallocated after the execution of the function.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode es10_tlv_extractor__delete_profile_response(const uint8_t* tlv, const uint32_t tlv_size, delete_profile_response_t* obj);

/** 
 * This function extracts data from a SetNicknameResponse TLV.
 *
 * @param[in]  tlv Pointer to a byte array with the SetNicknameResponse TLV.
 * @param[in]  tlv_size Size of the tlv buffer.
 * @param[out] obj A pointer to a set_nickname_response_t structure. The structure is populated following its documentation with 
 * the data from the tlv buffer if the function return is success. The structure data don't reference any data from the tlv buffer, 
 * so the tlv buffer can be deallocated after the execution of the function.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode es10_tlv_extractor__set_nickname_response(const uint8_t* tlv, const uint32_t tlv_size, set_nickname_response_t* obj);
#endif

#ifdef SGP32

/**
 * This function extracts data from a EuiccPackageResult TLV.
 *
 * @param[in]  buffer Pointer to a byte array with the EuiccPackageResult TLV.
 * @param[in]  buffer_size Size of the buffer byte array.
 * @param[out] obj A pointer to a euicc_package_result_t structure. The structure is populated following its documentation with the data 
 * from the buffer if the function return is success. The structure data may be referencing buffer data, do not deallocate the buffer while using the structure.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode es10_tlv_extractor__euicc_package_result(const uint8_t *buffer, const uint32_t buffer_size,
                                                 euicc_package_result_t *obj);

/** 
 * This function extracts data from a AddInitialEimResponse TLV.
 *
 * @param[in]  tlv Pointer to a byte array with the AddInitialEimResponse TLV.
 * @param[in]  tlv_size Size of the tlv buffer.
 * @param[out] obj A pointer to a add_initial_eim_response_t structure. The structure is populated following its documentation with 
 * the data from the tlv buffer if the function return is success. The structure data don't reference any data from the tlv buffer, 
 * so the tlv buffer can be deallocated after the execution of the function.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode es10_tlv_extractor__add_initial_eim_response(const uint8_t *tlv, const uint32_t tlv_size,
                                                     add_initial_eim_response_t *obj);

/** 
 * This function extracts data from a GetCertsResponse TLV.
 *
 * @param[in]  tlv Pointer to a byte array with the GetCertsResponse TLV.
 * @param[in]  tlv_size Size of the tlv buffer.
 * @param[out] obj A pointer to a get_certs_response_t structure. The structure is populated following its documentation with the 
 * data from the tlv buffer if the function return is success. The structure data may be referencing data from the tlv buffer, do 
 * not deallocate the tlv buffer while using the structure.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode es10_tlv_extractor__get_certs_response(const uint8_t *tlv, const uint32_t tlv_size,
                                               get_certs_response_t *obj);

/** 
 * This function extracts data from a EnableUsingDDResponse TLV.
 *
 * @param[in]  tlv Pointer to a byte array with the EnableUsingDDResponse TLV.
 * @param[in]  tlv_size Size of the tlv buffer.
 * @param[out] obj A pointer to a enable_using_dd_response_t structure. The structure is populated following its documentation with 
 * the data from the tlv buffer if the function return is success. The structure data don't reference any data from the tlv buffer, 
 * so the tlv buffer can be deallocated after the execution of the function.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode es10_tlv_extractor__immediate_enable_response(const uint8_t *tlv, const uint32_t tlv_size,
                                                      immediate_enable_response_t *obj);

/** 
 * This function extracts data from a ProfileRollbackResponse TLV.
 *
 * @param[in]  tlv Pointer to a byte array with the ProfileRollbackResponse TLV.
 * @param[in]  tlv_size Size of the tlv buffer.
 * @param[out] obj A pointer to a profile_rollback_response_t structure. The structure is populated following its documentation with the 
 * data from the tlv buffer if the function return is success. The structure data may be referencing data from the tlv buffer, do 
 * not deallocate the tlv buffer while using the structure.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode es10_tlv_extractor__profile_rollback_response(const uint8_t *tlv, const uint32_t tlv_size,
                                                      profile_rollback_response_t *obj);

/** 
 * This function extracts data from a ConfigureImmediateProfileEnablingResponse TLV.
 *
 * @param[in]  tlv Pointer to a byte array with the ConfigureImmediateProfileEnablingResponse TLV.
 * @param[in]  tlv_size Size of the tlv buffer.
 * @param[out] obj A pointer to a configure_immediate_profile_enabling_response_t structure. The structure is populated following its 
 * documentation with the data from the tlv buffer if the function return is success. The structure data don't reference any data 
 * from the tlv buffer, so the tlv buffer can be deallocated after the execution of the function.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode es10_tlv_extractor__configure_immediate_profile_enabling_response(const uint8_t *tlv,
                                                                          const uint32_t tlv_size,
                                                                          configure_immediate_profile_enabling_response_t *obj);

ErrCode
es10_tlv_extractor__get_eim_configuration_data_response(const uint8_t *tlv, const uint32_t tlv_size,
                                                        get_eim_configuration_data_response_t *obj);
ErrCode es10_tlv_extractor__eim_configuration_data(const uint8_t* tlv, const uint32_t tlv_size, eim_configuration_data_t* obj);

/** 
 * This function returns the number of EimConfigurationData that are in a GetEimConfigurationDataResponse TLV
 *
 * @param[in]  tlv Pointer to a byte array with the ConfigureAutoProfileEnablingResponse TLV.
 * @param[in]  tlv_size Size of the tlv buffer.
 * @param[out] count Will point to the number of EimConfigurationData if the function result is success.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode es10_tlv_extractor__get_eim_configuration_data_response_list_size(const uint8_t *tlv,
                                                                          const uint32_t tlv_size,
                                                                          uint32_t *count);

/** 
 * This function extracts the associationToken from a GetEimConfigurationDataResponse TLV.
 *
 * @param[in]  tlv Pointer to a byte array with the ConfigureAutoProfileEnablingResponse TLV.
 * @param[in]  tlv_size Size of the tlv buffer.
 * @param[out] association_token Will point to the associationToken value if the function result is success.
 * If no associationToken is found in the GetEimConfigurationDataResponse TLV, will point to the associationToken
 * default value.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode es10_tlv_extractor__get_eim_configuration_data_response_assocation_token(const uint8_t *tlv,
                                                                                 const uint32_t tlv_size,
                                                                                 uint32_t *association_token);

#ifdef EXTRA_FEATURE_EMERGENCY_PROFILE_MANAGMENT

/**
 * This function extracts the EnableEmergencyProfileResponse from a TLV.
 *
 * @param[in]  tlv Pointer to a byte array with the EnableEmergencyProfileResponse TLV.
 * @param[in]  tlv_size Size of the tlv buffer.
 * @param[out] obj Will point to the EnableEmergencyProfileResponse object if the function result is success.
 * If no EnableEmergencyProfileResponse is found in the TLV, will point to the default value.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode
es10_tlv_extractor__enable_emergency_profile_response(const uint8_t *tlv, const uint32_t tlv_size,
                                                      enable_emergency_profile_response_t *obj);

/**
 * This function extracts the DisableEmergencyProfileResponse from a TLV.
 *
 * @param[in]  tlv Pointer to a byte array with the DisableEmergencyProfileResponse TLV.
 * @param[in]  tlv_size Size of the tlv buffer.
 * @param[out] obj Will point to the DisableEmergencyProfileResponse object if the function result is success.
 * If no DisableEmergencyProfileResponse is found in the TLV, will point to the default value.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode
es10_tlv_extractor__disable_emergency_profile_response(const uint8_t *tlv, const uint32_t tlv_size,
                                                       disable_emergency_profile_response_t *obj);

#endif

#ifdef EXTRA_FEATURE_FALLBACK_MECHANISM

/**
 * This function extracts data from a ExecuteFallbackMechanismResponse TLV.
 *
 * @param[in]  tlv Pointer to a byte array with the ExecuteFallbackMechanismResponse TLV.
 * @param[in]  tlv_size Size of the tlv buffer.
 * @param[out] obj A pointer to a execute_fallback_mechanism_response_t structure. The structure is populated following its documentation with 
 * the data from the tlv buffer if the function return is success. The structure data don't reference any data from the tlv buffer, 
 * so the tlv buffer can be deallocated after the execution of the function.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode
es10_tlv_extractor__execute_fallback_mechanism_response(const uint8_t *tlv, const uint32_t tlv_size,
                                                        execute_fallback_mechanism_response_t *obj);

/** 
 * This function extracts data from a ReturnFromFallbackResponse TLV.
 *
 * @param[in]  tlv Pointer to a byte array with the ReturnFromFallbackResponse TLV.
 * @param[in]  tlv_size Size of the tlv buffer.
 * @param[out] obj A pointer to a return_from_fallback_response_t structure. The structure is populated following its documentation with 
 * the data from the tlv buffer if the function return is success. The structure data don't reference any data from the tlv buffer, 
 * so the tlv buffer can be deallocated after the execution of the function.
 *
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode
es10_tlv_extractor__return_from_fallback_response(const uint8_t *tlv, const uint32_t tlv_size,
                                                  return_from_fallback_response_t *obj);

#endif
#endif
