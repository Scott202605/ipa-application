/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "es10.h"
#include "es11.h"
#include "es9.h"
#include "esipa_typedefs.h"
#include "ipa_core.h"
#include "ipa_typedefs.h"
#include "notifications_delivery.h"
#include "typedefs.h"


#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
typedef enum profile_download_trigger_result_choice_e {
  PROFILE_DOWNLOAD_TRIGGER_RESULT_CHOICE,
  INITIATE_AUTHENTICATION_REQUEST_ESIPA_CHOICE
} profile_download_trigger_result_choice_t;

typedef union profile_download_trigger_result_choice_value_u {
  initiate_authentication_request_esipa_t initiate_authentication_request_esipa;
  profile_download_trigger_result_t profile_download_trigger_result;
} profile_download_trigger_result_choice_value_t;

typedef struct profile_download_trigger_response_result_s {
  profile_download_trigger_result_choice_t choice;
  profile_download_trigger_result_choice_value_t value;
} profile_download_trigger_response_result_t;

typedef enum authenticate_client_response_result_choice_e {
  PROFILE_DOWNLOAD_TRIGGER_RESPONSE_RESULT_CHOICE,
  GET_BOUND_PROFILE_PACKAGE_AUTHENTICATE_CLIENT_RESULT_CHOICE,
  CANCEL_SESSION_REQUEST_AUTHENTICATE_CLIENT_RESULT_CHOICE,
  OK_AUTHENTICATE_CLIENT_RESULT_CHOICE
} authenticate_client_response_result_choice_t;

typedef union authenticate_client_response_result_choice_value_u {
  profile_download_trigger_response_result_t
      profile_download_trigger_response_result;
  get_bound_profile_package_request_esipa_t
      get_bound_profile_package_request_esipa;
  cancel_session_request_esipa_t cancel_session_request_esipa;
} authenticate_client_response_result_choice_value_t;

typedef struct authenticate_client_response_result_esipa_s {
  authenticate_client_response_result_choice_t choice;
  authenticate_client_response_result_choice_value_t value;
} authenticate_client_response_result_esipa_t;

typedef enum get_bound_profile_package_response_result_choice_e {
  CANCEL_SESSION_REQUEST_GET_BOUND_PROFILE_PACKAGE_RESULT_CHOICE,
  HANDLE_NOTIFICATION_GET_BOUND_PROFILE_PACKAGE_RESULT_CHOICE
} get_bound_profile_package_response_result_choice_t;

typedef union get_bound_profile_package_response_result_choice_value_u {
  cancel_session_request_esipa_t cancel_session_request_esipa;
  handle_notification_esipa_t handle_notification_esipa;
} get_bound_profile_package_response_result_choice_value_t;

typedef struct get_bound_profile_package_response_result_esipa_s {
  get_bound_profile_package_response_result_choice_t choice;
  get_bound_profile_package_response_result_choice_value_t value;
} get_bound_profile_package_response_result_esipa_t;
#endif
typedef struct euicc_data_s {
  uint8_t *retrieve_notifications_list_response;
  uint32_t retrieve_notifications_list_response_size;
#ifdef SGP32
  uint8_t *retrieve_euicc_packages_list_response;
  uint32_t retrieve_euicc_packages_list_response_size;
#endif
  uint8_t *euicc_configured_addresses_response;
  uint32_t euicc_configured_addresses_response_size;
  uint8_t *euicc_info_1;
  uint32_t euicc_info_1_size;
  uint8_t *euicc_info_2;
  uint32_t euicc_info_2_size;
#ifdef SGP32
  uint8_t *get_eim_configuration_data_response;
  uint32_t get_eim_configuration_data_response_size;
  uint8_t *get_certs_response;
  uint32_t get_certs_response_size;
#endif
} euicc_data_t;

typedef struct {
  uint8_t *pkid;
  uint32_t pkid_size;
} ipa_pkid_t;

typedef struct {
  ipa_pkid_t *items;
  uint32_t count;
} ipa_pkid_list_t;

typedef struct {
  uint8_t *raw;
  uint32_t raw_size;

  uint8_t *svn;
  uint32_t svn_size;
  bool svn_present;

  ipa_pkid_list_t ci_pkid_list_for_verification;
  bool verification_list_present;

  ipa_pkid_list_t ci_pkid_list_for_signing;
  bool signing_list_present;
} ipa_euicc_info1_t;

/* Java Enum EuiccCategory (Tag 0x8B) -> C enum */
typedef enum {
  IPA_EUICC_CATEGORY_OTHER = 0,
  IPA_EUICC_CATEGORY_BASIC_EUICC = 1,
  IPA_EUICC_CATEGORY_MEDIUM_EUICC = 2,
  IPA_EUICC_CATEGORY_CONTACTLESS_EUICC = 3,
} ipa_euicc_category_t;

typedef struct {
  int32_t installed_app_number;
  int32_t free_non_volatile_mem;
  int32_t free_volatile_mem;
} ipa_ext_card_resources_t;

typedef struct {
  ipa_pkid_list_t ci_pkid_list_for_verification;
  ipa_pkid_list_t ci_pkid_list_for_signing;
} ipa_pkid_list_data_t;

typedef struct {
  char *profile_version;
  char *svn;
  char *euicc_firmware_ver;
  char *pp_version;
  char *sas_acreditation_number;
  ipa_ext_card_resources_t ext_card_res_info;
  uint8_t uicc_capability_mask[32];
  uint8_t rsp_capability_mask[16];

  ipa_pkid_list_data_t ipa_pkid_list_data;

  char *javacard_version;
  char *globalplatform_version;
  ipa_euicc_category_t euicc_category;
  bool euicc_category_present;
  uint8_t *forbidden_pprs;
  bool forbidden_pprs_present;
} ipa_euicc_info2_t;

void print_hex(const uint8_t *data, size_t size);

/**
 * This function initializes the IPA instance (singleton).
 * It is mandatory to call this function before any other IPA function (defined
 * on this file). It is also mandatory to call the ipa__deinit() function when
 * the IPA instance will not be used anymore.
 *
 * @param[in] es9 es9 A valid ES9 handle from a successful call to es9__ctor().
 * @param[in] es10 es10 A valid ES10 handle from a successful call to
 * es10__ctor().
 * @param[in] es11 es11 A valid ES11 handle from a successful call to
 * es11__ctor().
 *
 * @return eOk in case the IPA instance has been initialized successfully.
 * Otherwise, an error code is returned.
 */
ErrCode ipa__init(es9_t *const es9, es10_t *const es10, es11_t *const es11);

/**
 * @brief   Retrieves and parses eUICC certificate information.
 * @details Sends the GetCerts command to the eUICC and parses EUM and eUICC
 *          certificates into structured data.
 *
 * @param[out] out_data  Pointer to store parsed certificate data.
 *                       Set to NULL on failure.
 *
 * @return eOk on success; an error code on failure.
 *
 * @note    The caller must free allocated memory using ipa__free_certs_data()
 *          to avoid memory leaks.
 */
IPA_PUBLIC ErrCode ipa__get_certs(ipa_pkid_list_data_t *out_data);

/**
 * @brief   Frees the allocated memory within ipa_pkid_list_data_t.
 * @param   data Pointer to the certs data to be freed.
 */
IPA_PUBLIC void ipa__free_certs_data(ipa_pkid_list_data_t *data);

/**
 * This function deinitializes the IPA instance (initialized by function
 * ipa__init()). After executing this function, no other IPA function (defined
 * in this file) should be called until the IPA is initialized again.
 *
 * @return This function does not return any value.
 */
void ipa__deinit();

/**
 * This function returns the EID of the previously initialized IPA.
 *
 * @param[out] eid A pointer to an eid_t structure. The structure is populated
 * with the EID of the IPA.
 *
 * @return This function does not return any value.
 */
void ipa__get_eid(eid_t *eid);

/**
 * @brief   Retrieves multiple raw data sets from the eUICC in a single
 * operation.
 * @details According to the flags in the request structure, this function
 * obtains the corresponding raw TLV data (euiccInfo1, euiccInfo2, etc.) by
 * executing multiple underlying commands.
 *
 * @param[in]  request     Pointer to the request structure specifying data
 * items to fetch.
 * @param[out] response    Pointer to the response structure storing raw TLV
 * data buffers.
 *
 * @return eOk on success; an error code if any fetch operation fails.
 *
 * @note    Response buffers are allocated internally. Caller must free memory
 *          using ipa__free_euicc_data_response() to avoid leaks.
 */
ErrCode ipa__euicc_data(const ipa_euicc_data_request_t *request,euicc_data_t *response);

/**
 * @brief   Retrieves information of all installed eUICC profiles.
 * @details Obtains the complete profile list with states and key attributes.
 *
 * @param[out] profiles       Pointer to store the allocated profile info array.
 * @param[out] num_profiles   Pointer to store the number of valid profiles.
 *
 * @return eOk on success; an error code on failure.
 *
 * @note    Caller must free allocated memory for *profiles to prevent memory leaks.
 */
IPA_PUBLIC ErrCode ipa__get_all_profiles_info(profile_info_t **profiles, uint32_t *num_profiles, uint8_t **profile_info_list_response_tlv_out);

/**
 * @brief   Retrieves the single eIM configuration from the eUICC.
 * @details Parses and stores eIM configuration data into the caller-provided
 * struct. Only one eIM is supported at maximum.
 *
 * @param[out] eim_configuration_info  Caller-allocated struct to store parsed
 * eIM data.
 * @param[out] response_tlv_out        Pointer to store the allocated TLV buffer.
 *                                     Caller must free this buffer when done.
 *
 * @return eOk        if eIM data is retrieved and parsed successfully.
 * @return eNotFound  if no eIM configuration exists.
 * @return Other error codes for failures (eBadArg, eFatal, eNoMem, etc.).
 */
IPA_PUBLIC ErrCode ipa__get_eim_configuration(eim_configuration_data_t *eim_configuration_info, uint8_t **response_tlv_out);

/**
 * @brief   Retrieves and parses euiccInfo1 data from the eUICC.
 * @details euiccInfo1 contains eUICC identification, capabilities, and security
 * information.
 *
 * @param[out] out_data  Pointer to store the parsed euiccInfo1 data.
 *
 * @return eOk if successful; otherwise an error code.
 *
 * @note    The caller must free allocated memory using void
 * ipa__free_euicc_info1_data().
 */
IPA_PUBLIC ErrCode ipa__get_euicc_info_1(ipa_euicc_info1_t *out_data);

/**
 * @brief   Frees memory allocated for euiccInfo1 data.
 * @details Releases the internal resources and memory of the parsed euiccInfo1
 * structure.
 *
 * @param[in] data  Pointer to the ipa_euicc_info1_t structure to be freed.
 */
IPA_PUBLIC void ipa__free_euicc_info1_data(ipa_euicc_info1_t *data);
/**
 * @brief   Get and parse euiccInfo2 from the eUICC.
 * @details Contains eUICC capabilities, versions and certificate information.
 *
 * @param[out] out_data  Pointer to store the parsed euiccInfo2 data.
 *
 * @return eOk on success, error code on failure.
 *
 * @note    Caller must free memory via ipa__free_euicc_info2_data().
 */
IPA_PUBLIC ErrCode ipa__get_euicc_info_2(ipa_euicc_info2_t *out_data);
/**
 * @brief   Frees memory allocated for euiccInfo2 data.
 * @details Releases the internal resources and memory of the parsed euiccInfo2
 * structure.
 *
 * @param[in] data  Pointer to the ipa_euicc_info2_t structure to be freed.
 */
IPA_PUBLIC void ipa__free_euicc_info2_data(ipa_euicc_info2_t *data);

/**
 * This function returns the EID of the previously initialized IPA.
 * The EID is returned in C String format (UTF-8 hexadecimal + null character)
 *
 * @param[out] buffer Pointer to a buffer to which the EID will be written if
 * the function return is success.
 * @param[in]  buffer_size Size of the buffer. The size should be at least 33
 * bytes.
 *
 * @return This function does not return any value.
 */
IPA_PUBLIC ErrCode ipa__get_eid_cstring(char *buffer, uint32_t buffer_size);

/**
 * This function returns the MCC & MNC of the enabled profile (if any) of the
 * previously initialized IPA. The MCC & MNC is coded as 3GPP TS 24.008.
 *
 * @param[out] mcc_mnc A pointer to an mcc_mnc_t structure. The structure is
 * populated with the MCC & MNC of the enabled profile if the function return is
 * success.
 *
 * @return eOk in case it has been possible to extract the MCC & MNC from the
 * UICC-enabled profile. Otherwise, an error code is returned (also when there
 * is no profile enabled or the enabled profile does not has an OperatorId).
 */
ErrCode ipa__get_mcc_mnc(mcc_mnc_t *mcc_mnc);

/**
 * This function set the notifyStateChange and the stateChangeCause of the
 * previously initialized IPA. See also ipa__get_notify_state_change.
 *
 * @param[in] cause Points to the stateChangeCause value to be set in the IPA
 * instance. If null the notifyStateChange will be set to false.
 *
 * @return This function does not return any value.
 */
void ipa__set_notify_state_change(state_change_cause_t *cause);

/**
 * This function returns the notifyStateChange and the stateChangeCause of the
 * previously initialized IPA. The notifyStateChange indicates if the eIM that
 * the IPA has associated with it should update its information about the UICC,
 * and the stateChangeCause is the reason. This value can be used in the
 * GetEimPackageRequest.
 *
 * @param[out] cause A pointer to an state_change_cause_t enum. If not null, the
 * pointer will be populated with the current stateChangeCause in case the
 * notifyStateChange is true (function return value). If null, the function will
 * only return the notifyStateChange value.
 *
 * @return The value of the notifyStateChange.
 */
bool ipa__get_notify_state_change(state_change_cause_t *cause);

/**
 * This function can be called by any process to indicate that all processes
 * that are using the IPA should terminate their execution. The IPA should be
 * previously initialized (see ipa__init()).
 *
 * The circumstances under which this function is called are hardware specific.
 */
void ipa__set_ipa_exit();

/**
 * This function must be called periodically from all processes that use the
 * IPA. The IPA should be previously initialized (see ipa__init()).
 *
 * As soon as this function returns a true value, all the processes that are
 * using the IPA must terminate its execution. The functionality of the IPA exit
 * acts as a kind of signal.
 *
 * @return True if the process that has called this function must terminate,
 * false in any other case.
 */
bool ipa__get_ipa_exit();

/** TODO: LPA-205 The management of the IPA semaphore should be private. */
int ipa__take();
/** TODO: LPA-205 The management of the IPA semaphore should be private. */
void ipa__give();

/**
 * This function returns if the IPA is available to perform operations. The IPA
 * should be previously initialized (see ipa__init()). Some IPA operations
 * cannot be executed in parallel, by using this function, the caller can make
 * sure that the IPA is available before executing an operation. It is specified
 * in the documentation of the IPA functions if the IPA is required to be
 * available before the function is executed.
 *
 * @return true if the IPA is available to perform operations, otherwise return
 * false.
 */
bool ipa__is_available();

/**
 * This function executes an EuiccPackageRequest against the IPA.
 * The IPA should be previously initialized (see ipa__init()).
 * The IPA should be available (see ipa__is_available())
 *
 * @param[in]  euicc_package_request Pointer to an euicc_package_request_plain_t
 * structure populated with the data of the EuiccPackageRequest to load into the
 * eUICC. The structure is populated following its documentation.
 * @param[out] epr_and_notifications A pointer to an epr_and_notifications_t
 * structure. The structure is populated following its documentation with the
 * EuiccPackageResult and RetrieveNotificationsListResponse (if there are any
 * notifications on the UICC) if the function return is success. The caller is
 * the responsible for freeing this structure if the function return is success
 * by calling the ipa__free_epr_and_notifications().
 *
 * @return eOk in case the Euicc Package procedure has been executed
 * successfully. Otherwise, an error code is returned.
 */
ErrCode
ipa__euicc_package(const euicc_package_request_plain_t *euicc_package_request,
                   epr_and_notifications_t *epr_and_notifications);

/**
 * @brief   Registers a callback function to be invoked on profile state
 * changes.
 * @details This function allows the application to register a callback that
 * will be executed by the IPA library whenever the profile list changes
 * (enable, disable, delete, download).
 *
 * @param[in] callback   A function pointer of type
 * `ipa_profile_state_change_callback_t`. The provided function will be called
 * with the complete list of profiles currently installed on the eUICC.
 */
typedef void (*ipa_profile_state_change_callback_t)(
    const profile_info_t *profiles, uint32_t num_profiles);

/**
 * @brief   Registers a callback function to be invoked on profile state
 * changes.
 * @details This function allows the application to register a callback that
 * will be executed by the IPA library whenever a profile is enabled or
 * disabled.
 *
 * @param[in] callback   A function pointer of type
 * `ipa_profile_state_change_callback_t`. The provided function will be called
 * with the new profile state and a pointer to the enabled profile's information
 * (if any).
 */
IPA_PUBLIC void ipa__register_profile_state_callback(
    ipa_profile_state_change_callback_t callback);

/**
 * @brief   Notifies the eUICC about the result of a profile rollback operation.
 * @details After a fallback mechanism is triggered and the device successfully
 * connects to a network, this function must be called to inform the eUICC
 *          whether the newly enabled profile is functional (`success`) or if
 * the rollback should be finalized (`failure`).
 *
 * @param[in] result   A pointer to a `profile_rollback_result_t` structure
 * indicating the outcome of the rollback test.
 *
 * @return `eOk` if the result was successfully sent to the eUICC, or an error
 * code on failure.
 */
IPA_PUBLIC ErrCode
ipa__execute_profile_rollback_result(profile_rollback_result_t *result);

/**
 * This function executes an IpaEuiccDataRequest against the IPA.
 * The IPA should be previously initialized (see ipa__init()).
 * The IPA should be available (see ipa__is_available())
 *
 * @param[in]  ipa_euicc_data_request Pointer to a ipa_euicc_data_request_t
 * structure populated with the data to be requested to the IPA and/or eUICC.
 * The structure is populated following its documentation.
 * @param[out] ipa_euicc_data_response A pointer to an ipa_euicc_data_response_t
 * structure. The structure is populated following its documentation with the
 * data collected from the IPA and/or eUICC if the function return is success.
 * The caller is the responsible for freeing this structure if the function
 * return is success by calling the ipa__free_ipa_euicc_data_response().
 *
 * @return eOk in case the IPA and/or eUICC data has been collected
 * successfully. Otherwise, an error code is returned.
 */
ErrCode
ipa__ipa_euicc_data(const ipa_euicc_data_request_t *ipa_euicc_data_request,
                    ipa_euicc_data_response_t *ipa_euicc_data_response);

#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
/**
 * This function executes a ProfileDownloadTriggerRequest in indirect download
 * mode against the IPA. The IPA should be previously initialized (see
 * ipa__init()). The IPA should be available (see ipa__is_available())
 *
 * @param[in]  request Pointer to a profile_download_trigger_request_t structure
 * populated with the necessary data to start the indirect download. The
 * structure is populated following its documentation.
 * @param[out] response A pointer to an initiate_authentication_request_esipa_t
 * structure. The structure is populated following its documentation with the
 * necessary data to execute an InitiateAuthentication request against the eIM
 * if the function return is success. The caller is the responsible for freeing
 * this structure if the function return is success by calling the
 * ipa__free_initiate_authentication_request_esipa().
 *
 * @return eOk in case the InitiateAuthenticationRequestEsipa has been prepared
 * successfully. Otherwise, an error code is returned.
 */
ErrCode ipa__profile_download_trigger(
    const profile_download_trigger_request_t *request,
    profile_download_trigger_response_result_t *response);

/**
 * This function executes a InitiateAuthenticationResponseEsipa in indirect
 * download mode against the IPA. The IPA should be previously initialized (see
 * ipa__init()). The IPA should be available (see ipa__is_available())
 *
 * @param[in]  port_name Serial port name where the APDUs will be sent to (e.g.
 * "/dev/ttyUSB1", "COM1"...).
 * @param[in]  request Pointer to a initiate_authentication_response_esipa_t
 * structure populated with the necessary data to authenticate the server
 * against the UICC. The structure is populated following its documentation.
 * @param[out] response A pointer to an authenticate_client_request_esipa_t
 * structure. The structure is populated following its documentation with the
 * necessary data to execute an AuthenticateClient request against the eIM if
 * the function return is success. The caller is the responsible for freeing
 * this structure if the function return is success by calling the
 * ipa__free_authenticate_client_request_esipa().
 *
 * @return eOk in case the AuthenticateClientRequestEsipa has been prepared
 * successfully. Otherwise, an error code is returned.
 */
ErrCode ipa__initiate_authentication_response(
    const initiate_authentication_response_esipa_t *request,
    authenticate_client_request_esipa_t *response);

/**
 * This function executes an AuthenticateClientResponseEsipa in indirect
 * download mode against the IPA. The IPA should be previously initialized (see
 * ipa__init()). The IPA should be available (see ipa__is_available()).
 *
 * @param[in] request A pointer to an authenticate_client_response_esipa_t
 * structure that is populated with the necessary data to prepare for the
 * subsequent interaction with eIM as IPA. The structure is populated following
 * its documentation.
 * @param[out] response A pointer to an
 * authenticate_client_response_result_esipa_t structure. The structure is
 * populated following its documentation with the necessary data to execute the
 * result of AuthenticateClient response against the eIM if the function return
 * is success. The caller is responsible for freeing this structure if the
 * function return is success by calling the
 * ipa__free_authenticate_client_response_result_esipa().
 *
 * @return eOk in case the AuthenticateClientResponseEsipa has been executed
 * successfully. Otherwise, an error code is returned.
 */
ErrCode ipa__authenticate_client_response(
    const authenticate_client_response_esipa_t *request,
    authenticate_client_response_result_esipa_t *response);

/**
 * This function executes an GetBoundProfilePackageResponseEsipa in indirect
 * download mode against the IPA. The IPA should be previously initialized (see
 * ipa__init()). The IPA should be available (see ipa__is_available()).
 *
 * @param[in] request A pointer to an get_bound_profile_package_response_esipa_t
 * structure that is populated with the necessary data to prepare for the
 * subsequent interaction with eIM as IPA. The structure is populated following
 * its documentation.
 * @param[out] response A pointer to an
 * get_bound_profile_package_response_result_esipa_t structure. The structure is
 * populated following its documentation with the necessary data to execute the
 * result of GetBoundProfilePackage response against the eIM if the function
 * return is success. The caller is responsible for freeing this structure if
 * the function return is success by calling the
 * ipa__free_get_bound_profile_package_response_result_esipa().
 *
 * @return eOk in case the GetBoundProfilePackageResponseEsipa has been executed
 * successfully. Otherwise, an error code is returned.
 */
ErrCode ipa__get_bound_profile_package_response(
    const get_bound_profile_package_response_esipa_t *request,
    get_bound_profile_package_response_result_esipa_t *response);
#else
/**
 * This function executes a ProfileDownloadTriggerRequest in direct download
 * mode against the IPA. The IPA should be previously initialized (see
 * ipa__init()). The IPA should be available (see ipa__is_available())
 *
 * @param[in]  profile_download_trigger_request Pointer to a
 * profile_download_trigger_request_t structure populated with the necessary
 * data to start the direct download. The structure is populated following its
 * documentation.
 * @param[out] profile_download_trigger_result A pointer to an
 * profile_download_trigger_result_t structure. The structure is populated
 * following its documentation with the result of the direct download if the
 * function return is success. The caller is the responsible for freeing this
 * structure if the function return is success by calling the
 * ipa__free_profile_download_trigger_result().
 *
 * @return eOk in case the direct download has been executed successfully.
 * Otherwise, an error code is returned.
 */
ErrCode ipa__profile_download_trigger(
    const profile_download_trigger_request_t *profile_download_trigger_request,
    profile_download_trigger_result_t *profile_download_trigger_result);
#endif

/**
 * This function executes an EimAcknowledgements against the IPA.
 * The IPA should be previously initialized (see ipa__init()).
 * The IPA should be available (see ipa__is_available())
 *
 * @param[in]  eim_acknowledgements Pointer to a eim_acknowledgements_t
 * structure populated with the EimAcknowledgements. The structure is populated
 * following its documentation.
 *
 * @return eOk in case the EimAcknowledgements has been executed successfully.
 * Otherwise, an error code is returned.
 */
ErrCode ipa__eim_acknowledgements(eim_acknowledgements_t *eim_acknowledgements);

#if defined(SGP32) && defined(EXTRA_FEATURE_EMERGENCY_PROFILE_MANAGMENT)
/**
 * This function executes an EnableEmergencyProfile against the IPA.
 * The IPA should be previously initialized (see ipa__init()).
 * The IPA should be available (see ipa__is_available())
 *
 * @return eOk in case the EnableEmergencyProfile has been executed
 * successfully. Otherwise, an error code is returned.
 */
IPA_PUBLIC ErrCode ipa__enable_emergency_profile();
/**
 * This function executes a DisableEmergencyProfile against the IPA.
 * The IPA should be previously initialized (see ipa__init()).
 * The IPA should be available (see ipa__is_available()
 *
 * @return eOk in case the DisableEmergencyProfile has been executed
 * successfully. Otherwise, an error code is returned.
 */
IPA_PUBLIC ErrCode ipa__disable_emergency_profile();
#endif

#if defined(SGP32) && defined(EXTRA_FEATURE_FALLBACK_MECHANISM)
/**
 * This function executes an ExecuteFallbackMechanism against the IPA.
 * The IPA should be previously initialized (see ipa__init()).
 * The IPA should be available (see ipa__is_available())
 *
 * @return eOk in case the Fallback Profile has been enabled successfully.
 * Otherwise, an error code is returned.
 */
IPA_PUBLIC ErrCode ipa__execute_fallback_mechanism();

/**
 * This function executes a ReturnFromFallback against the IPA.
 * The IPA should be previously initialized (see ipa__init()).
 * The IPA should be available (see ipa__is_available())
 *
 * @return eOk in case the return from the Fallback Profile has been done
 * successfully. Otherwise, an error code is returned.
 */
IPA_PUBLIC ErrCode ipa__return_from_fallback();
#endif

#if defined(SGP32) && defined(TEST_FEATURE_PROFILE_ROLLBACK)
/**
 * Once this function is called, the Profile Rollback test use case flag will be
 * enabled in the IPA. The IPA should be previously initialized (see
 * ipa__init()).
 *
 * While this flag is active, the IPA will call the ES10.ProfileRollback
 * function after calling the ES10.LoadEuiccPackage function. If the Profile is
 * rolled back successfully, the IPA will replace the EuiccPackageResult
 * received in the response of the ES10.LoadEuiccPackage function for the
 * EuiccPackageResult received in the response of ES10.ProfileRollback.
 *
 * The Profile Rollback test use case flag will be disabled only after a Profile
 * has been successfully rolled back.
 *
 * @return This function does not return any value.
 */
void ipa__activate_profile_rollback_test_use_case();
#endif

/** Free datatypes functions according the allocations made in the ipa.c file */
void ipa__free_epr_and_notifications(
    epr_and_notifications_t *epr_and_notifications);
void ipa__free_ipa_euicc_data_response(
    ipa_euicc_data_response_t *ipa_euicc_data_response);
#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
void ipa__free_initiate_authentication_request_esipa(
    initiate_authentication_request_esipa_t *obj);
void ipa__free_authenticate_client_request_esipa(
    authenticate_client_request_esipa_t *obj);
void ipa__free_cancel_session_request_esipa(
    cancel_session_request_esipa_t *obj);
void ipa__free_get_bound_profile_package_response_result_esipa(
    get_bound_profile_package_response_result_esipa_t *obj);
void ipa__free_authenticate_client_response_result_esipa(
    authenticate_client_response_result_esipa_t *obj);
void ipa__free_profile_download_trigger_response_result(
    profile_download_trigger_response_result_t *obj);
void ipa__free_initiate_authentication_response_esipa(
    initiate_authentication_response_esipa_t *obj);
void ipa__free_authenticate_client_response_esipa(
    authenticate_client_response_esipa_t *obj);
void ipa__free_get_bound_profile_package_response_esipa(
    get_bound_profile_package_response_esipa_t *obj);
void ipa__free_cancel_session_response_esipa(
    cancel_session_response_esipa_t *obj);
#endif

void ipa__free_profile_download_trigger_result(profile_download_trigger_result_t *profile_download_trigger_result);
/**
 * Initializes the notification group list for notification delivery management.
 *
 * @param[out] notifications_list Double pointer to the notification group node
 * list to be initialized.
 *
 * @return eOk if the notification group list is initialized successfully.
 * Otherwise, an error code is returned.
 */
IPA_PUBLIC ErrCode ipa__notifications_delivery__initialize_notifications_group_list(notification_group_node_t **notifications_list);

/**
 * This function removes all pending notifications from the UICC.
 *
 * @return eOk in case all notifications have been removed successfully.
 * Otherwise, an error code is returned.
 */
IPA_PUBLIC ErrCode ipa__notifications_delivery__all_notifications();

/**
 * Delivers a single notification based on the specified sequence number.
 *
 * @param[in] remove_after_send Boolean flag indicating whether to remove the
 * notification after successful delivery.
 * @param[in] smdp_address Pointer to a string containing the SM-DP+ server
 * address.
 * @param[in] seq_number Sequence number of the single notification to be
 * delivered.
 *
 * @return eOk if the single notification is delivered successfully. Otherwise,
 * an error code is returned.
 */
IPA_PUBLIC ErrCode ipa__notifications_delivery__seq_number_single_notification_delivery(bool remove_after_send, const char *smdp_address, uint32_t seq_number);

/**
 * This function removes all pending notifications from the UICC.
 *
 * @return eOk in case all notifications have been removed successfully.
 * Otherwise, an error code is returned.
 */
IPA_PUBLIC ErrCode ipa__notifications_delivery__remove_all_notifications();

/**
 * This function removes a notification from the UICC by its sequence number.
 *
 * @param[in] sequence_number Sequence number of the notification to be removed.
 *
 * @return eOk in case the notification has been removed successfully.
 * Otherwise, an error code is returned.
 */
IPA_PUBLIC ErrCode ipa__notifications_delivery__remove_notification(uint32_t sequence_number);
/**
 * Frees the entire linked list of notifications and releases all allocated resources.
 *
 * @param[in,out] head  Double pointer to the head node of the notification linked list.
 *                      Set to NULL after all memory is freed successfully.
 *
 * @return None
*/
IPA_PUBLIC void ipa__notifications_delivery__free_notification_list(notification_group_node_t** head);
