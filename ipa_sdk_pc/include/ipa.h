/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once

#include "es10_typedefs.h"
#include "typedefs.h"

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

typedef struct notification_group_node_s {
  fqdn_t notification_address;
  uint32_t *sequence_number_list;
  size_t sequence_number_list_size;
  struct notification_group_node_s *next;
} notification_group_node_t;

/**
 * This function executes a ReturnFromFallback against the IPA.
 * The IPA should be previously initialized (see ipa__init()).
 * The IPA should be available (see ipa__is_available())
 *
 * @return eOk in case the return from the Fallback Profile has been done
 * successfully. Otherwise, an error code is returned.
 */
ErrCode ipa__return_from_fallback();

/**
 * @brief   Callback type for profile state change events.
 * @details This callback is triggered when the profile list or profile states
 *          are modified (enable, disable, delete, download).
 *
 * @param[in] profiles      Pointer to the array of installed profile
 * information.
 * @param[in] num_profiles  Number of valid profiles in the array.
 */
typedef void (*ipa_profile_state_change_callback_t)(
    const profile_info_t *profiles, uint32_t num_profiles);

/**
 * @brief   Executes the fallback mechanism via the IPA interface.
 * @details Triggers the fallback profile mechanism to enable the fallback
 * profile. The IPA must be initialized and available before calling this
 * function.
 *
 * @return eOk if the fallback profile is enabled successfully; otherwise an
 * error code.
 */
ErrCode ipa__execute_fallback_mechanism(void);

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
ErrCode ipa__get_certs(ipa_pkid_list_data_t *out_data);

/**
 * @brief   Frees the allocated memory within ipa_pkid_list_data_t.
 * @param   data Pointer to the certs data to be freed.
 */
void ipa__free_certs_data(ipa_pkid_list_data_t *data);

/**
 * @brief   Gets information of all installed eUICC profiles.
 * @details Obtains the full list of profiles with their states and attributes.
 *
 * @param[out] profiles      Pointer to store the allocated profile info array.
 * @param[out] num_profiles  Pointer to store the number of profiles.
 *
 * @return eOk on success; an error code on failure.
 *
 * @note    The caller must free the allocated profile memory to avoid leaks.
 */
ErrCode ipa__get_all_profiles_info(profile_info_t** profiles,
                                   uint32_t* num_profiles,
                                   uint8_t** profile_info_list_response_tlv_out);

/**
 * @brief   Gets the eIM configuration information from the eUICC.
 * @details Retrieves and parses the single configured eIM on the eUICC.
 *
 * @param[out] eim_configuration_info  Caller-allocated struct to store parsed
 * eIM data.
 *
 * @param[out] response_tlv_out        Pointer to store the allocated TLV buffer.
 *                                     Caller must free this buffer when done.
 *
 * @return eOk        if data is retrieved successfully.
 * @return eNotFound  if no eIM configuration exists.
 * @return Other error codes for failures.
 */
ErrCode ipa__get_eim_configuration(eim_configuration_data_t *eim_configuration_info, uint8_t **response_tlv_out);

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
ErrCode ipa__get_euicc_info_1(ipa_euicc_info1_t *out_data);

/**
 * @brief   Frees memory allocated for euiccInfo1 data.
 * @details Releases the internal resources and memory of the parsed euiccInfo1
 * structure.
 *
 * @param[in] data  Pointer to the ipa_euicc_info1_t structure to be freed.
 */
void ipa__free_euicc_info1_data(ipa_euicc_info1_t *data);

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
ErrCode ipa__get_euicc_info_2(ipa_euicc_info2_t *out_data);
/**
 * @brief   Frees memory allocated for euiccInfo2 data.
 * @details Releases the internal resources and memory of the parsed euiccInfo2
 * structure.
 *
 * @param[in] data  Pointer to the ipa_euicc_info2_t structure to be freed.
 */
void ipa__free_euicc_info2_data(ipa_euicc_info2_t *data);
/**
 * @brief   Gets the eUICC EID in C string format.
 * @details Returns the EID as a null-terminated UTF-8 hexadecimal string.
 *
 * @param[out] buffer        Buffer to store the EID string.
 * @param[in]  buffer_size   Size of the provided buffer (minimum 33 bytes).
 *
 * @return eOk on success; an error code on failure.
 */
ErrCode ipa__get_eid_cstring(char *buffer, uint32_t buffer_size);

/**
 * @brief   Registers a profile state change callback.
 * @details The registered callback is invoked when a profile is enabled,
 * disabled, added, or removed.
 *
 * @param[in] callback  Callback function to be triggered on state changes.
 */
void ipa__register_profile_state_callback(
    ipa_profile_state_change_callback_t callback);

/**
 * @brief   Reports profile rollback operation result to the eUICC.
 * @details Notifies the eUICC whether the fallback profile is functional after
 * rollback.
 *
 * @param[in] result  Rollback test result structure.
 *
 * @return eOk if the result is sent successfully; otherwise an error code.
 */
ErrCode ipa__execute_profile_rollback_result(profile_rollback_result_t *result);

/**
 * This function executes an EnableEmergencyProfile against the IPA.
 * The IPA should be previously initialized (see ipa__init()).
 * The IPA should be available (see ipa__is_available())
 *
 * @return eOk in case the EnableEmergencyProfile has been executed
 * successfully. Otherwise, an error code is returned.
 */
ErrCode ipa__enable_emergency_profile();

/**
 * This function executes a DisableEmergencyProfile against the IPA.
 * The IPA should be previously initialized (see ipa__init()).
 * The IPA should be available (see ipa__is_available()
 *
 * @return eOk in case the DisableEmergencyProfile has been executed
 * successfully. Otherwise, an error code is returned.
 */
ErrCode ipa__disable_emergency_profile();

/**
 * This function processes all pending UICC notifications.
 * Notifications are grouped by SMDP+ and sorted by sequence number before being
 * sent to SMDP+ and removed from the UICC. The execution process that follows
 * this function is described in section 3.5 of the SGP.22
 *
 * @return eOk in case the notifications delivery procedure has been executed
 * successfully. Otherwise, an error code is returned.
 */
ErrCode ipa__notifications_delivery__all_notifications();

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
ErrCode ipa__notifications_delivery__seq_number_single_notification_delivery(
    bool remove_after_send, const char *smdp_address, uint32_t seq_number);

/**
 * This function removes a notification from the UICC by its sequence number.
 *
 * @param[in] sequence_number Sequence number of the notification to be removed.
 *
 * @return eOk in case the notification has been removed successfully.
 * Otherwise, an error code is returned.
 */
ErrCode
ipa__notifications_delivery__remove_notification(uint32_t sequence_number);

/**
 * This function removes all pending notifications from the UICC.
 *
 * @return eOk in case all notifications have been removed successfully.
 * Otherwise, an error code is returned.
 */
ErrCode ipa__notifications_delivery__remove_all_notifications();

/**
 * Initializes the notification group list for notification delivery management.
 *
 * @param[out] notifications_list Double pointer to the notification group node
 * list to be initialized.
 *
 * @return eOk if the notification group list is initialized successfully.
 * Otherwise, an error code is returned.
 */
ErrCode ipa__notifications_delivery__initialize_notifications_group_list(
    notification_group_node_t **notifications_list);
/**
 * Frees the entire linked list of notifications and releases all allocated resources.
 *
 * @param[in,out] head  Double pointer to the head node of the notification linked list.
 *                      Set to NULL after all memory is freed successfully.
 *
 * @return None
*/
void ipa__notifications_delivery__free_notification_list(notification_group_node_t** head);
