/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"
#include "es10_typedefs.h"
#include "smartcard.h"

#if defined(SGP22) && defined(SGP32)
#error "ES10 can not compile with CPP flags SGP22 and SGP32 defined together"
#endif

#if defined(SGP22)
#define SGP_VERSION	"SGP.22 2.2.2"
#elif defined(SGP32)
#define SGP_VERSION	"SGP.32 1.2.0"
#else
#error "SGP Version SHALL be specified with a CPP flag. Flags available: SGP22, SGP32"
#endif

typedef struct es10_s {
    smartcard_t* smart_card;
    uint8_t initial_refresh_sleep; // In seconds
    uint8_t max_refresh_sleep; // In seconds
} es10_t;

/**
 * This function creates an ES10 instance.
 * 
 * @param[in] es10 A pointer to a es10_t structure. The object is populated with a valid ES10 instance.
 * @param[in] smart_card A pointer to a smartcard_t structure. This smartcard instance will be used by 
 * the ES10 interface to communicate with the UICC.
 * 
 * @return Upon successful execution, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int es10__ctor(es10_t * const es10, smartcard_t* smart_card);

/**
 * This function initialize an ES10 instance.
 * Once the instance is initialized, the communication with the Smartcard will be opened and it 
 * will be able to execute any ES10 function.
 * See also es10__deinit()
 * 
 * @param[in] es10 A valid ES10 handle from a successful call to es10__ctor().
 * 
 * @return Upon successful execution, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int es10__init(es10_t * const es10);

/**
 * This function deinitialize an ES10 instance.
 * Once the instance is deinitialized, the communication with the Smartcard will be closed and 
 * the ES10 instance will not be able to execute ES10 functions until it is initialized again.
 * 
 * @param[in] es10 A valid ES10 handle from a successful call to es10__ctor().
 * 
 * @return Upon successful execution, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int es10__deinit(es10_t * const es10);

/**
 * Destroys and cleans up the ES10 instance.
 *
 * @param[in] es10 A valid ES10 handle from a successful call to es10__ctor().
 * 
 * @return Upon successful execution, will return 0.
 * If an output error is encountered, a negative value is returned.
 */
int es10__destroy(es10_t * const es10);

/**
 * Sets the seconds of the initial sleep in case of communication failure with the Smartcard due to REFRESH.
 * This initial sleep will increase at a rate of 2 as long as the errors due to the REFRESH keep appearing, 
 * until the maximum sleep (see es10__set_max_refresh_sleep()) is reached, then the operation will be considered 
 * as failed.
 * @note A default value for the initial sleep is set on the constructor.
 *
 * @param[in] es10 A valid ES10 handle from a successful call to es10__ctor().
 * @param[in] seconds Seconds of initial sleep. 0 if it is desired to deactivate the retries mechanism.
 */
void es10__set_initial_refresh_sleep(es10_t * const es10, const uint8_t seconds);

/**
 * Sets the seconds of the maximum sleep in case of communication failure with the Smartcard due to REFRESH.
 * See es10__set_initial_refresh_sleep().
 * @note A default value for the maximum sleep is set on the constructor.
 *
 * @param[in] es10 A valid ES10 handle from a successful call to es10__ctor().
 * @param[in] seconds Seconds of maximum sleep. 0 if it is desired to deactivate the retries mechanism.
 */
void es10__set_max_refresh_sleep(es10_t * const es10, const uint8_t seconds);

/**
 * This function executes the GetEuiccConfiguredAddresses function defined in the ES10 interface.
 * 
 * @param[in]  es10 A initialized ES10 handle from a successful call to es10__init().
 * @param[out] response Will point to a byte array with the EuiccConfiguredAddressesResponse TLV if the function 
 * return is success. The caller is the responsible for freeing the byte array by calling the M_free() function.
 * @param[out] response_size Will point to the size of the tlv byte array if the function return is success.
 * 
 * @return Upon successful execution of the ES10.GetEuiccConfiguredAddresses, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int es10__get_euicc_configured_addresses(es10_t * const es10, uint8_t** response, uint32_t* response_size);

/**
 * This function executes the GetEUICCInfo (1) function defined in the ES10 interface.
 * 
 * @param[in]  es10 A initialized ES10 handle from a successful call to es10__init().
 * @param[out] response Will point to a byte array with the EUICCInfo1 TLV if the function return is success. 
 * The caller is the responsible for freeing the byte array by calling the M_free() function.
 * @param[out] response_size Will point to the size of the tlv byte array if the function return is success.
 * 
 * @return Upon successful execution of the ES10.GetEUICCInfo, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int es10__get_euicc_info_1(es10_t * const es10, uint8_t** response, uint32_t* response_size);

/**
 * This function executes the GetEUICCInfo (2) function defined in the ES10 interface.
 * 
 * @param[in]  es10 A initialized ES10 handle from a successful call to es10__init().
 * @param[out] response Will point to a byte array with the EUICCInfo2 TLV if the function return is success. 
 * The caller is the responsible for freeing the byte array by calling the M_free() function.
 * @param[out] response_size Will point to the size of the tlv byte array if the function return is success.
 * 
 * @return Upon successful execution of the ES10.GetEUICCInfo, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int es10__get_euicc_info_2(es10_t * const es10, uint8_t** response, uint32_t* response_size);

/**
 * This function executes the GetEUICCChallenge function defined in the ES10 interface.
 * 
 * @param[in]  es10 A initialized ES10 handle from a successful call to es10__init().
 * @param[out] response Will point to a byte array with the GetEuiccChallengeResponse TLV if the function return 
 * is success. The caller is the responsible for freeing the byte array by calling the M_free() function.
 * @param[out] response_size Will point to the size of the tlv byte array if the function return is success.
 * 
 * @return Upon successful execution of the ES10.GetEUICCChallenge, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int es10__get_euicc_challenge(es10_t * const es10, uint8_t** response, uint32_t* response_size);

/**
 * This function executes the eUICCMemoryReset function defined in the ES10 interface.
 * 
 * @param[in]  es10 A initialized ES10 handle from a successful call to es10__init().
 * @param[in]  request_obj Pointer to an euicc_memory_reset_request_t structure populated with the input data.
 * @param[out] response Will point to a byte array with the EuiccMemoryResetResponse TLV if the function return 
 * is success. The caller is the responsible for freeing the byte array by calling the M_free() function.
 * @param[out] response_size Will point to the size of the tlv byte array if the function return is success.
 * 
 * @return Upon successful execution of the ES10.eUICCMemoryReset, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int es10__euicc_memory_reset(es10_t * const es10, const euicc_memory_reset_request_t* request_obj, uint8_t** response, uint32_t* response_size);

/**
 * This function executes the AuthenticateServer function defined in the ES10 interface.
 * 
 * @param[in]  es10 A initialized ES10 handle from a successful call to es10__init().
 * @param[in]  request_obj Pointer to an authenticate_server_request_t structure populated with the input data.
 * @param[out] response Will point to a byte array with the AuthenticateServerResponse TLV if the function return 
 * is success. The caller is the responsible for freeing the byte array by calling the M_free() function.
 * @param[out] response_size Will point to the size of the tlv byte array if the function return is success.
 * 
 * @return Upon successful execution of the ES10.AuthenticateServer, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int es10__authenticate_server(es10_t * const es10, const authenticate_server_request_t* request_obj, uint8_t** response, uint32_t* response_size);

/**
 * This function executes the PrepareDownload function defined in the ES10 interface.
 * 
 * @param[in]  es10 A initialized ES10 handle from a successful call to es10__init().
 * @param[in]  request_obj Pointer to a prepare_download_request_t structure populated with the input data.
 * @param[out] response Will point to a byte array with the PrepareDownloadResponse TLV if the function return 
 * is success. The caller is the responsible for freeing the byte array by calling the M_free() function.
 * @param[out] response_size Will point to the size of the tlv byte array if the function return is success.
 * 
 * @return Upon successful execution of the ES10.PrepareDownload, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int es10__prepare_download(es10_t * const es10, const prepare_download_request_t* request_obj, uint8_t** response, uint32_t* response_size);

/**
 * This function executes the LoadBoundProfilePackage function defined in the ES10 interface.
 * 
 * @param[in]  es10 A initialized ES10 handle from a successful call to es10__init().
 * @param[in]  bpp Pointer to a byte array with the Bound Profile Package to load.
 * @param[in]  bpp_size Size of the Bound Profile Package byte array.
 * @param[out] response Will point to a byte array with the a ProfileInstallationResult TLV if the function return 
 * is success. The caller is the responsible for freeing the byte array by calling the M_free() function.
 * @param[out] response_size Will point to the size of the tlv byte array if the function return is success.
 * 
 * @return Upon successful execution of the ES10.LoadBoundProfilePackage, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int es10__load_bound_profile_package(es10_t * const es10, const uint8_t* bpp, const uint32_t bpp_size, uint8_t** response, uint32_t* response_size);

/**
 * This function executes the CancelSession function defined in the ES10 interface.
 * 
 * @param[in]  es10 A initialized ES10 handle from a successful call to es10__init().
 * @param[in]  request_obj Pointer to a cancel_session_request_t structure populated with the input data.
 * @param[out] response Will point to a byte array with the CancelSessionResponse TLV if the function return 
 * is success. The caller is the responsible for freeing the byte array by calling the M_free() function.
 * @param[out] response_size Will point to the size of the tlv byte array if the function return is success.
 * 
 * @return Upon successful execution of the ES10.CancelSession, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int es10__cancel_session(es10_t * const es10, const cancel_session_request_t* request_obj, uint8_t** response, uint32_t* response_size);

/**
 * This function executes the RetrieveNotificationsList function defined in the ES10 interface.
 * 
 * @param[in]  es10 A initialized ES10 handle from a successful call to es10__init().
 * @param[in]  request_obj Pointer to a retrieve_notifications_list_request_t structure populated with the input data.
 * @param[out] response Will point to a byte array with the RetrieveNotificationsListResponse TLV if the function return 
 * is success. The caller is the responsible for freeing the byte array by calling the M_free() function.
 * @param[out] response_size Will point to the size of the tlv byte array if the function return is success.
 * 
 * @return Upon successful execution of the ES10.RetrieveNotificationsList, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int es10__retrieve_notifications_list(es10_t * const es10, const retrieve_notifications_list_request_t* request_obj, uint8_t** response, uint32_t* response_size);

/**
 * This function executes the RemoveNotificationFromList function defined in the ES10 interface.
 * 
 * @param[in]  es10 A initialized ES10 handle from a successful call to es10__init().
 * @param[in]  request_obj Pointer to a notification_sent_request_t structure populated with the input data.
 * @param[out] response Will point to a byte array with the NotificationSentResponse TLV if the function return 
 * is success. The caller is the responsible for freeing the byte array by calling the M_free() function.
 * @param[out] response_size Will point to the size of the tlv byte array if the function return is success.
 * 
 * @return Upon successful execution of the ES10.RemoveNotificationFromList, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int es10__remove_notification_from_list(es10_t * const es10, const notification_sent_request_t* request_obj, uint8_t** response, uint32_t* response_size);

/**
 * This function executes the GetRAT function defined in the ES10 interface.
 * 
 * @param[in]  es10 A initialized ES10 handle from a successful call to es10__init().
 * @param[out] response Will point to a byte array with the GetRatResponse TLV if the function return 
 * is success. The caller is the responsible for freeing the byte array by calling the M_free() function.
 * @param[out] response_size Will point to the size of the tlv byte array if the function return is success.
 * 
 * @return Upon successful execution of the ES10.GetRAT, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int es10__get_rat(es10_t * const es10, uint8_t** response, uint32_t* response_size);

/**
 * This function executes the GetProfilesInfo function defined in the ES10 interface.
 * 
 * @param[in]  es10 A initialized ES10 handle from a successful call to es10__init().
 * @param[in]  request_obj Pointer to a profile_info_list_request_t structure populated with the input data.
 * @param[out] response Will point to a byte array with the ProfileInfoListResponse TLV if the function return 
 * is success. The caller is the responsible for freeing the byte array by calling the M_free() function.
 * @param[out] response_size Will point to the size of the tlv byte array if the function return is success.
 * 
 * @return Upon successful execution of the ES10.GetProfilesInfo, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int es10__get_profiles_info(es10_t * const es10, const profile_info_list_request_t* request_obj, uint8_t** response, uint32_t* response_size);

/**
 * This function executes the GetEID function defined in the ES10 interface.
 * 
 * @param[in]  es10 A initialized ES10 handle from a successful call to es10__init().
 * @param[out] response Will point to a byte array with the GetEuiccDataResponse TLV if the function return 
 * is success. The caller is the responsible for freeing the byte array by calling the M_free() function.
 * @param[out] response_size Will point to the size of the tlv byte array if the function return is success.
 * 
 * @return Upon successful execution of the ES10.GetEID, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int es10__get_eid(es10_t * const es10, uint8_t** response, uint32_t* response_size);

/**
 * This function executes the SetDefaultDpAddress function defined in the ES10 interface.
 * 
 * @param[in]  es10 A initialized ES10 handle from a successful call to es10__init().
 * @param[in]  request_obj Pointer to a set_default_dp_address_request_t structure populated with the input data.
 * @param[out] response Will point to a byte array with the SetDefaultDpAddressResponse TLV if the function return 
 * is success. The caller is the responsible for freeing the byte array by calling the M_free() function.
 * @param[out] response_size Will point to the size of the tlv byte array if the function return is success.
 * 
 * @return Upon successful execution of the ES10.SetDefaultDpAddress, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int es10__set_default_dp_address(es10_t * const es10, const set_default_dp_address_request_t* request_obj, uint8_t** response, uint32_t* response_size);

#ifdef SGP22
/**
 * This function executes the ListNotification function defined in the ES10 interface.
 * 
 * @param[in]  es10 A initialized ES10 handle from a successful call to es10__init().
 * @param[in]  request_obj Pointer to a list_notification_request_t structure populated with the input data.
 * @param[out] response Will point to a byte array with the ListNotificationResponse TLV if the function return 
 * is success. The caller is the responsible for freeing the byte array by calling the M_free() function.
 * @param[out] response_size Will point to the size of the tlv byte array if the function return is success.
 * 
 * @return Upon successful execution of the ES10.ListNotification, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int es10__list_notification(es10_t * const es10, const list_notification_request_t* request_obj, uint8_t** response, uint32_t* response_size);

// int es10__load_crl(es10_t * const es10, const load_crl_request_t* request_obj, uint8_t** response, uint32_t* response_size);

/**
 * This function executes the EnableProfile function defined in the ES10 interface.
 * 
 * @param[in]  es10 A initialized ES10 handle from a successful call to es10__init().
 * @param[in]  request_obj Pointer to an enable_profile_request_t structure populated with the input data.
 * @param[out] response Will point to a byte array with the EnableProfileResponse TLV if the function return 
 * is success. The caller is the responsible for freeing the byte array by calling the M_free() function.
 * @param[out] response_size Will point to the size of the tlv byte array if the function return is success.
 * 
 * @return Upon successful execution of the ES10.EnableProfile, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int es10__enable_profile(es10_t * const es10, const enable_profile_request_t* request_obj, uint8_t** response, uint32_t* response_size);

/**
 * This function executes the DisableProfile function defined in the ES10 interface.
 * 
 * @param[in]  es10 A initialized ES10 handle from a successful call to es10__init().
 * @param[in]  request_obj Pointer to a disable_profile_request_t structure populated with the input data.
 * @param[out] response Will point to a byte array with the DisableProfileResponse TLV if the function return 
 * is success. The caller is the responsible for freeing the byte array by calling the M_free() function.
 * @param[out] response_size Will point to the size of the tlv byte array if the function return is success.
 * 
 * @return Upon successful execution of the ES10.DisableProfile, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int es10__disable_profile(es10_t * const es10, const disable_profile_request_t* request_obj, uint8_t** response, uint32_t* response_size);

/**
 * This function executes the DeleteProfile function defined in the ES10 interface.
 * 
 * @param[in]  es10 A initialized ES10 handle from a successful call to es10__init().
 * @param[in]  request_obj Pointer to a delete_profile_request_t structure populated with the input data.
 * @param[out] response Will point to a byte array with the DeleteProfileResponse TLV if the function return 
 * is success. The caller is the responsible for freeing the byte array by calling the M_free() function.
 * @param[out] response_size Will point to the size of the tlv byte array if the function return is success.
 * 
 * @return Upon successful execution of the ES10.DeleteProfile, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int es10__delete_profile(es10_t * const es10, const delete_profile_request_t* request_obj, uint8_t** response, uint32_t* response_size);

/**
 * This function executes the SetNickname function defined in the ES10 interface.
 * 
 * @param[in]  es10 A initialized ES10 handle from a successful call to es10__init().
 * @param[in]  request_obj Pointer to a set_nickname_request_t structure populated with the input data.
 * @param[out] response Will point to a byte array with the SetNicknameResponse TLV if the function return 
 * is success. The caller is the responsible for freeing the byte array by calling the M_free() function.
 * @param[out] response_size Will point to the size of the tlv byte array if the function return is success.
 * 
 * @return Upon successful execution of the ES10.SetNickname, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int es10__set_nickname(es10_t * const es10, const set_nickname_request_t* request_obj, uint8_t** response, uint32_t* response_size);
#endif

#ifdef SGP32
/**
 * This function executes the LoadEuiccPackage function defined in the ES10 interface.
 * 
 * @param[in]  es10 A initialized ES10 handle from a successful call to es10__init().
 * @param[in]  request Pointer to a byte array with the EuiccPackageRequest to load.
 * @param[in]  request_size Size of the EuiccPackageRequest byte array.
 * @param[out] response Will point to a byte array with the a EuiccPackageResult TLV if the function return 
 * is success. The caller is the responsible for freeing the byte array by calling the M_free() function.
 * @param[out] response_size Will point to the size of the tlv byte array if the function return is success.
 * 
 * @return Upon successful execution of the ES10.LoadEuiccPackage, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int es10__load_euicc_package(es10_t * const es10, const uint8_t* request, const uint32_t request_size, uint8_t** response, uint32_t* response_size);

/**
 * This function executes the AddInitialEim function defined in the ES10 interface.
 * 
 * @param[in]  es10 A initialized ES10 handle from a successful call to es10__init().
 * @param[in]  request_obj Pointer to an eim_configuration_data_t structure populated with the input data.
 * @param[out] response Will point to a byte array with the AddInitialEimResponse TLV if the function return 
 * is success. The caller is the responsible for freeing the byte array by calling the M_free() function.
 * @param[out] response_size Will point to the size of the tlv byte array if the function return is success.
 * 
 * @return Upon successful execution of the ES10.AddInitialEim, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int es10__add_initial_eim(es10_t * const es10, const eim_configuration_data_t* request_obj, uint8_t** response, uint32_t* response_size);

/**
 * This function executes the GetCerts function defined in the ES10 interface.
 * 
 * @param[in]  es10 A initialized ES10 handle from a successful call to es10__init().
 * @param[in]  request_obj Pointer to a get_certs_request_t structure populated with the input data.
 * @param[out] response Will point to a byte array with the GetCertsResponse TLV if the function return 
 * is success. The caller is the responsible for freeing the byte array by calling the M_free() function.
 * @param[out] response_size Will point to the size of the tlv byte array if the function return is success.
 * 
 * @return Upon successful execution of the ES10.GetCerts, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int es10__get_certs(es10_t * const es10, const get_certs_request_t* request_obj, uint8_t** response, uint32_t* response_size);

/**
 * This function executes the ImmediateEnable function defined in the ES10 interface.
 * 
 * @param[in]  es10 A initialized ES10 handle from a successful call to es10__init().
 * @param[in]  request_obj Pointer to a immediate_enable_request_t structure populated with the input data.
 * @param[out] response Will point to a byte array with the ImmediateEnableResponse TLV if the function return 
 * is success. The caller is the responsible for freeing the byte array by calling the M_free() function.
 * @param[out] response_size Will point to the size of the tlv byte array if the function return is success.
 * 
 * @return Upon successful execution of the ES10.EnableUsingDD, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int es10__immediate_enable(es10_t * const es10,  const immediate_enable_request_t* request_obj, uint8_t** response, uint32_t* response_size);

/**
 * This function executes the ProfileRollback function defined in the ES10 interface.
 * 
 * @param[in]  es10 A initialized ES10 handle from a successful call to es10__init().
 * @param[in]  request_obj Pointer to a profile_rollback_request_t structure populated with the input data.
 * @param[out] response Will point to a byte array with the ProfileRollbackResponse TLV if the function return 
 * is success. The caller is the responsible for freeing the byte array by calling the M_free() function.
 * @param[out] response_size Will point to the size of the tlv byte array if the function return is success.
 * 
 * @return Upon successful execution of the ES10.ProfileRollback, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int es10__profile_rollback(es10_t * const es10, const profile_rollback_request_t* request_obj, uint8_t** response, uint32_t* response_size);

/**
 * This function executes the ConfigureImmediateProfileEnabling function defined in the ES10 interface.
 * 
 * @param[in]  es10 A initialized ES10 handle from a successful call to es10__init().
 * @param[in]  request_obj Pointer to a configure_immediate_profile_enabling_request_t structure populated with the input data.
 * @param[out] response Will point to a byte array with the ConfigureImmediateProfileEnablingResponse TLV if the function return 
 * is success. The caller is the responsible for freeing the byte array by calling the M_free() function.
 * @param[out] response_size Will point to the size of the tlv byte array if the function return is success.
 * 
 * @return Upon successful execution of the ES10.ConfigureImmediateProfileEnabling, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int es10__configure_immediate_profile_enabling(es10_t * const es10, const configure_immediate_profile_enabling_request_t* request_obj, uint8_t** response, uint32_t* response_size);

/**
 * This function executes the GetEimConfigurationData function defined in the ES10 interface.
 * 
 * @param[in]  es10 A initialized ES10 handle from a successful call to es10__init().
 * @param[in]  request_obj Pointer to a get_eim_configuration_data_request_t structure populated with the input data.
 * @param[out] response Will point to a byte array with the GetEimConfigurationDataResponse TLV if the function 
 * return is success. The caller is the responsible for freeing the byte array by calling the M_free() function.
 * @param[out] response_size Will point to the size of the tlv byte array if the function return is success.
 * 
 * @return Upon successful execution of the ES10.GetEimConfigurationData, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int es10__get_eim_configuration_data(es10_t * const es10, const get_eim_configuration_data_request_t* request_obj, uint8_t** response, uint32_t* response_size);

#ifdef EXTRA_FEATURE_EMERGENCY_PROFILE_MANAGMENT
/**
 * This function executes the EnableEmergencyProfile function defined in the ES10 interface.
 *
 * @param[in]  es10 An initialized ES10 handle from a successful call to es10__init().
 * @param[in]  request_obj Pointer to an enable_emergency_profile_request_t structure populated with the data needed to make the request.
 * @param[out] response Will point to a byte array with the EnableEmergencyProfileResponse TLV if the function
 * return is success. The caller is responsible for freeing the byte array by calling the M_free() function.
 * @param[out] response_size Will point to the size of the tlv byte array if the function return is success.
 *
 * @return Upon successful execution of the ES10.EnableEmergencyProfile, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int es10__enable_emergency_profile(es10_t* const es10, const enable_emergency_profile_request_t* request_obj, uint8_t** response, uint32_t* response_size);

/**
 * This function executes the DisableEmergencyProfile function defined in the ES10 interface.
 *
 * @param[in]  es10 An initialized ES10 handle from a successful call to es10__init().
 * @param[in]  request_obj Pointer to a disable_emergency_profile_request_t structure populated with the data needed to make the request.
 * @param[out] response Will point to a byte array with the DisableEmergencyProfileResponse TLV if the function
 * return is success. The caller is responsible for freeing the byte array by calling the M_free() function.
 * @param[out] response_size Will point to the size of the tlv byte array if the function return is success.
 *
 * @return Upon successful execution of the ES10.DisableEmergencyProfile, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int es10__disable_emergency_profile(es10_t* const es10, const disable_emergency_profile_request_t* request_obj, uint8_t** response, uint32_t* response_size);
#endif

#ifdef EXTRA_FEATURE_FALLBACK_MECHANISM
/**
 * This function executes the ExecuteFallbackMechanism function defined in the ES10 interface.
 * 
 * @param[in]  es10 A initialized ES10 handle from a successful call to es10__init().
 * @param[in]  request_obj Pointer to a execute_fallback_mechanism_request_t structure populated with the input data.
 * @param[out] response Will point to a byte array with the ExecuteFallbackMechanismResponse TLV if the function 
 * return is success. The caller is the responsible for freeing the byte array by calling the M_free() function.
 * @param[out] response_size Will point to the size of the tlv byte array if the function return is success.
 * 
 * @return Upon successful execution of the ES10.ExecuteFallbackMechanism, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int es10__execute_fallback_mechanism(es10_t * const es10, const execute_fallback_mechanism_request_t* request_obj, uint8_t** response, uint32_t* response_size);

/**
 * This function executes the ReturnFromFallback function defined in the ES10 interface.
 * 
 * @param[in]  es10 A initialized ES10 handle from a successful call to es10__init().
 * @param[in]  request_obj Pointer to a return_from_fallback_request_t structure populated with the input data.
 * @param[out] response Will point to a byte array with the ReturnFromFallbackResponse TLV if the function 
 * return is success. The caller is the responsible for freeing the byte array by calling the M_free() function.
 * @param[out] response_size Will point to the size of the tlv byte array if the function return is success.
 * 
 * @return Upon successful execution of the ES10.ReturnFromFallback, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int es10__return_from_fallback(es10_t * const es10, const return_from_fallback_request_t* request_obj, uint8_t** response, uint32_t* response_size);
#endif
#endif
