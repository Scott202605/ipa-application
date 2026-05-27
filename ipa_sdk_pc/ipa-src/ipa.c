/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include "ipa.h"
#include <errno.h>

#include <stdio.h>
#include <unistd.h>

#include "ber_tlv_parser.h"
#include "byte_utils.h"
#include "device_info.h"
#include "es10.h"
#include "es10_tlv_extractor.h"
#include "es10_typedefs.h"
#include "es9.h"
#include "esipa_tlv_extractor.h"
#include "ipa_core.h"
#include "ipa_display.h"
#include "log.h"
#include "memory_manager.h"
#include "rsp.h"
#include "semaphore_manager.h"
#include "timer.h"
#include "tlv_data_extractor.h"
#include "tlv_tags.h"

#ifdef SGP22
#include "ber_tlv_parser.h"
#include "esipa_tlv_generator.h"
#include "tlv_tags.h"

#endif

#ifndef IPA_FEATURE_INDIRECT_DOWNLOAD
#if defined(IPA_FEATURE_EIM_DOWNLOAD_DATA_HANDLING) ||                         \
    defined(IPA_FEATURE_EIM_CTX_PARAMS1_GENERATION) ||                         \
    defined(IPA_FEATURE_EIM_PROFILE_METADATA_VERIFICATION) ||                  \
    defined(IPA_FEATURE_MINIMIZE_ESIPA_BYTES)
#error                                                                         \
    "EIM_DOWNLOAD_DATA_HANDLING,EIM_CTX_PARAMS1_GENERATION, EIM_PROFILE_METADATA_VERIFICATION and MINIMIZE_ESIPA_BYTES features can only be defined if IPA_FEATURE_INDIRECT_DOWNLOAD is defined"
#endif
#endif

#define NOTIFY_STATE_CHANGE_DEFAULT true
#define STATE_CHANGE_CAUSE_DEFAULT STATE_CHANGE_CAUSE_UNDEFINED

typedef struct ipa_data_presence_s {
  bool mcc_mnc;
} ipa_data_presence_t;

#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
typedef struct indirect_rsp_context_presence_s {

#ifndef IPA_FEATURE_EIM_DOWNLOAD_DATA_HANDLING
  bool matching_id;
#endif
  bool default_smdp_use_case;
  bool transaction_id;
} indirect_rsp_context_presence_t;

typedef struct indirect_rsp_context_s {
#ifndef IPA_FEATURE_EIM_DOWNLOAD_DATA_HANDLING
  uint8_t matching_id[255];
  uint8_t matching_id_size;
#endif
  transaction_id_t transaction_id;
  indirect_rsp_context_presence_t field_is_present;
} indirect_rsp_context_t;
#endif
void print_hex(const uint8_t *data, size_t size) {
  LOGI("Hex: ");
  for (size_t i = 0; i < size; i++) {
    printf("%02X ", data[i]);
  }
  LOGI("\n");
}

typedef struct ipa_s {
  es9_t *es9;
  es10_t *es10;
  es11_t *es11;
  eid_t eid;
  mcc_mnc_t mcc_mnc;
  bool notify_state_change;
  state_change_cause_t state_change_cause;
  bool emergency_profile_enabled;
  semaphore_t *ipa_semaphore;
  const ipa_capabilities_t ipa_capabilities;
#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
  indirect_rsp_context_t indirect_rsp_context;
#endif
  ipa_data_presence_t field_is_present;
  semaphore_t *exit_sem; // The semaphore is taken until the IPA can exit
#if defined(SGP32) && defined(TEST_FEATURE_PROFILE_ROLLBACK)
  bool profile_rollback_test_use_case;
#endif
  ipa_profile_state_change_callback_t profile_state_callback;
} ipa_t;

static void ipa__get_notification_list(
    const uint8_t *retrieve_notifications_list_response,
    const uint32_t retrieve_notifications_list_response_size,
    uint8_t **notification_list, uint32_t *notification_list_size);

#ifdef SGP32

static ErrCode ipa__ipa_euicc_data_response_set_certificates(
    const ipa_euicc_data_request_t *request, euicc_data_t *euicc_data,
    ipa_euicc_data_response_t *response);

static ErrCode ipa__ipa_euicc_data_response_set_association_token(
    const ipa_euicc_data_request_t *request, euicc_data_t *euicc_data,
    ipa_euicc_data_response_t *response);

static ErrCode ipa__ipa_euicc_data_response_set_euicc_package_result_list(
    const ipa_euicc_data_request_t *request, euicc_data_t *euicc_data,
    ipa_euicc_data_response_t *response);

#endif

static ErrCode ipa__parse_pkid_list(const uint8_t *tlv_data, uint32_t tlv_size,
                                    ipa_pkid_list_t *pkid_list);
static ErrCode ipa__ipa_euicc_data_response_set_addresses(
    const ipa_euicc_data_request_t *request, euicc_data_t *euicc_data,
    ipa_euicc_data_response_t *response);
static ErrCode ipa__ipa_euicc_data_response_set_notifications_list(
    const ipa_euicc_data_request_t *request, euicc_data_t *euicc_data,
    ipa_euicc_data_response_t *response);
static ErrCode ipa__ipa_euicc_data_response_set_euicc_info(
    const ipa_euicc_data_request_t *request, euicc_data_t *euicc_data,
    ipa_euicc_data_response_t *response);
static ErrCode ipa__set_ipa_euicc_data_response_error(
    const ipa_euicc_data_request_t *request,
    const ipa_euicc_data_error_code_t error_code,
    ipa_euicc_data_response_t *response);
static ErrCode ipa__parse_euicc_info_1_tlv(const uint8_t *euicc_info_tlv,
                                           uint32_t euicc_info_tlv_size,
                                           ipa_euicc_info1_t *out_data);
static ErrCode ipa__update_ipa_profiles_state();
static ErrCode ipa__parse_version_type(const uint8_t *value_ptr,
                                       uint32_t length, char **out_version_str);
static ErrCode ipa__parse_euicc_info2_tlv(const uint8_t *tlv_buffer,
                                          uint32_t buffer_size,
                                          ipa_euicc_info2_t *out_data);
void ipa__free_pkid_list(ipa_pkid_list_t *pkid_list);
#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
static ErrCode ipa__cancel_session(
    const transaction_id_t *transaction_id,
    const cancel_session_reason_t reason,
    cancel_session_request_esipa_t *cancel_session_request_esipa);
static ErrCode ipa__profile_download_trigger_response_result_set_error(
    const profile_download_trigger_request_t *request,
    profile_download_trigger_response_result_t *response,
    profile_download_error_reason_t error_reason);
#ifdef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
static ErrCode ipa__reconstruct_truncated_euicc_ci_pk_id(
    const uint8_t *euicc_info_1, size_t euicc_info_1_size,
    const truncated_subject_key_identifier_t *truncated_euicc_ci_pk_id,
    subject_key_identifier_t *reconstructed_euicc_ci_pk_id);
#endif
static void
ipa__free_handle_notification_esipa(handle_notification_esipa_t *obj);
static void ipa__free_get_bound_profile_package_request_esipa(
    get_bound_profile_package_request_esipa_t *obj);
static void clear_indirect_rsp_context();
#else

static ErrCode ipa__rsp_custom_smds(const uint8_t *smds_address,
                                    uint32_t smds_address_len, pir_t **pir_list,
                                    uint32_t *pir_list_size);

#endif
#if defined(SGP32) && defined(TEST_FEATURE_PROFILE_ROLLBACK)

static ErrCode
ipa__execute_profile_rollback(uint8_t **euicc_package_result,
                              uint32_t *euicc_package_result_size);

#endif

/** Free datatypes functions according the allocations made in this file */
static void free_ipa_euicc_data(ipa_euicc_data_t *obj);

static void free_euicc_data(euicc_data_t *obj);

#ifdef SGP22
static int
load_euicc_package_sgp22_translator(const uint8_t *euicc_package_request,
                                    const uint32_t euicc_package_request_size,
                                    uint8_t **euicc_package_result,
                                    uint32_t *euicc_package_result_size);
#endif

/** Singleton instance */
static ipa_t g_ipa = {
    .notify_state_change = NOTIFY_STATE_CHANGE_DEFAULT,
    .state_change_cause = STATE_CHANGE_CAUSE_DEFAULT,
    .ipa_semaphore = NULL,
#if defined(SGP32) && defined(TEST_FEATURE_PROFILE_ROLLBACK)
    .profile_rollback_test_use_case = false,
#endif
    .profile_state_callback = NULL,
    .ipa_capabilities = {
        .ipa_features =
            {
#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
                .indirect_rsp_server_communication = true,
                .direct_rsp_server_communication = false,
#else
                .direct_rsp_server_communication = true,
                .indirect_rsp_server_communication = false,
#endif
#ifdef IPA_FEATURE_EIM_DOWNLOAD_DATA_HANDLING
                .eim_download_data_handling = true,
#else
                .eim_download_data_handling = false,
#endif
#ifdef IPA_FEATURE_EIM_CTX_PARAMS1_GENERATION
                .eim_ctx_params_1_generation = true,
#else
                .eim_ctx_params_1_generation = false,
#endif
#ifdef IPA_FEATURE_EIM_PROFILE_METADATA_VERIFICATION
                .eim_profile_metadata_verification = true,
#else
                .eim_profile_metadata_verification = false,
#endif
#ifdef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
                .minimize_esipa_bytes = true
#else
                .minimize_esipa_bytes = false
#endif
            },
        .ipa_supported_protocols =
            {
#if defined(ENABLE_HTTP_ESIPA)
                .ipa_retrieve_https = true,
#else
                .ipa_retrieve_https = false,
#endif
                .ipa_retrieve_coaps = false,
                .ipa_inject_https = false,
                .ipa_inject_coaps = false,
#if defined(ENABLE_MQTT) || defined(ENABLE_LWM2M)
                .ipa_proprietary = true
#else
                .ipa_proprietary = false
#endif
            },
        .field_is_present = {.ipa_supported_protocols = true}}};
static profile_info_t g_ipa_enabled_profile_info = {0};
static bool g_ipa_profile_is_enabled = false;

ErrCode ipa__init(es9_t *const es9, es10_t *const es10, es11_t *const es11) {
  ErrCode rc;
  int err;
  uint8_t *get_euicc_data_response = NULL;
  uint32_t get_euicc_data_response_size;
  get_euicc_data_response_t get_euicc_data_response_obj;
#ifdef SGP32
  get_eim_configuration_data_request_t get_eim_configuration_data_request = {
      .field_is_present = {.search_criteria = false}};
  uint8_t *get_eim_configuration_data_response = NULL;
  uint32_t get_eim_configuration_data_response_size;
  uint32_t configured_eims;
#endif
  LOGI("[ipa__init] Initializing the IPA");
  if (!es9) {
    LOGE("[ipa__init] The ES9 is null");
    return eBadArg;
  }
  if (!es10) {
    LOGE("[ipa__init] The ES10 is null");
    return eBadArg;
  }
  if (!es11) {
    LOGE("[ipa__init] The ES11 is null");
    return eBadArg;
  }
  g_ipa.es9 = es9;
  g_ipa.es10 = es10;
  g_ipa.es11 = es11;
  if ((err = es10__init(g_ipa.es10)) < 0) {
    LOGE("[ipa__init] Error initializing the ES10, err %d", err);
    return eFatal;
  }

#ifdef SGP32
  if ((err = es10__get_eim_configuration_data(
           g_ipa.es10, &get_eim_configuration_data_request,
           &get_eim_configuration_data_response,
           &get_eim_configuration_data_response_size)) < 0) {
    LOGE("[ipa__init] ES10.GetEimConfigurationData failed, err %d", err);
    get_eim_configuration_data_response = NULL;
    rc = eFatal;
    goto ipa__init_deinit_es10;
  }
  LOG_DATA(eLogDebug, "GetEimConfigurationDataResponse",
           get_eim_configuration_data_response,
           get_eim_configuration_data_response_size);
#endif

  if ((err = es10__get_eid(g_ipa.es10, &get_euicc_data_response,
                           &get_euicc_data_response_size)) < 0) {
    LOGE("[ipa__init] ES10.GetEID failed, err %d", err);
    get_euicc_data_response = NULL;
    rc = eFatal;
    goto ipa__init_deinit_es10;
  }
  LOG_DATA(eLogDebug, "GetEuiccDataResponse", get_euicc_data_response,
           get_euicc_data_response_size);

  if ((rc = ipa__update_ipa_profiles_state()) != eOk) {
    LOGE("[ipa__init] Error updating the IPA profile state, rc %d", rc);
  }

ipa__init_deinit_es10:
  if ((err = es10__deinit(es10)) < 0) {
    LOGE("[ipa__init] Error deinitializing the ES10, err %d", err);
  }

  if (rc != eOk) {
    LOGE("[ipa__init] IPA initialization procedure stoped, rc %d", rc);
#ifdef SGP32
    M_free(get_eim_configuration_data_response);
#endif
    M_free(get_euicc_data_response);
    return rc;
  }

#ifdef SGP32
  rc = es10_tlv_extractor__get_eim_configuration_data_response_list_size(
      get_eim_configuration_data_response,
      get_eim_configuration_data_response_size, &configured_eims);
  M_free(get_eim_configuration_data_response);
  get_eim_configuration_data_response = NULL;
  get_eim_configuration_data_response_size = 0;
  if (rc == eOk) {
    LOGI("The IPA has %u configured eIM", configured_eims);
  } else {
    LOGE("[ipa__init] Error counting the number of eIM configured in the IPA, "
         "rc %d",
         rc);
    M_free(get_euicc_data_response);
    return rc;
  }

  if (0 == configured_eims) {
    LOGE("[ipa__init] eIM Configuration Data is empty on the UICC, an "
         "AddInitialEim command should be executed before start the IPA");
    g_ipa_state = IPA_STATE_WAITING_FOR_PROVISIONING;
    notify_app(IPA_EVENT_PROVISIONING_NEEDED, NULL);
    LOGI("[ipa__init] Waiting for provisioning state to be resolved (max 30 "
         "seconds)...");

    int wait_time_ms = 0;
    const int max_wait_ms = 30000;
    const int sleep_interval_ms = 100;

    while (g_ipa_state == IPA_STATE_WAITING_FOR_PROVISIONING &&
           wait_time_ms < max_wait_ms) {
      usleep(sleep_interval_ms * 1000);
      wait_time_ms += sleep_interval_ms;
    }

    if (g_ipa_state == IPA_STATE_WAITING_FOR_PROVISIONING) {
      LOGE("[ipa__init] Timeout: Provisioning was not completed within 30 "
           "seconds. Aborting initialization.");
      M_free(get_euicc_data_response);
      g_ipa_state = IPA_STATE_UNINITIALIZED;
      return eFatal;
    }
  }
#endif

  rc = es10_tlv_extractor__get_euicc_data_response(
      get_euicc_data_response, get_euicc_data_response_size,
      &get_euicc_data_response_obj);
  M_free(get_euicc_data_response);
  get_euicc_data_response = NULL;
  if (rc != eOk) {
    LOGE("[ipa__init] Error extracting the EID from the GetEuiccDataResponse, "
         "rc %d",
         rc);
    return rc;
  }
  memcpy(&g_ipa.eid, &get_euicc_data_response_obj.eid_value, sizeof(eid_t));
  LOGI("IoT device EID: "
       "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
       g_ipa.eid.eid[0], g_ipa.eid.eid[1], g_ipa.eid.eid[2], g_ipa.eid.eid[3],
       g_ipa.eid.eid[4], g_ipa.eid.eid[5], g_ipa.eid.eid[6], g_ipa.eid.eid[7],
       g_ipa.eid.eid[8], g_ipa.eid.eid[9], g_ipa.eid.eid[10], g_ipa.eid.eid[11],
       g_ipa.eid.eid[12], g_ipa.eid.eid[13], g_ipa.eid.eid[14],
       g_ipa.eid.eid[15]);

  /** TODO: LPA-190 Load the eIM configuration data and use it to connect to the
   * different eIMs */

  if (!(g_ipa.ipa_semaphore = make_semaphore())) {
    LOGE("[ipa__init] Error generating the IPA state semaphore");
    return eFatal;
  }

  if (!(g_ipa.exit_sem = make_semaphore())) {
    LOGE("[ipa__init] Error generating the IPA exit semaphore");
    semaphore_destroy(g_ipa.ipa_semaphore);
    g_ipa.ipa_semaphore = NULL;
    return eFatal;
  }

  // Safer way to make sure that the semaphore is taken (should be taken in the
  // first iteration)
  while (semaphore_take(g_ipa.exit_sem) < 0) {
    timer__sleep(1);
  }

  return eOk;
}

void ipa__deinit() {
  stop_eim_service();
  semaphore_destroy(g_ipa.ipa_semaphore);
  g_ipa.ipa_semaphore = NULL;
  semaphore_destroy(g_ipa.exit_sem);
  g_ipa.exit_sem = NULL;
  g_ipa.notify_state_change = NOTIFY_STATE_CHANGE_DEFAULT;
}

void ipa__get_eid(eid_t *eid) {
  if (eid) {
    memcpy(eid, &g_ipa.eid, sizeof(eid_t));
  }
}

ErrCode ipa__get_eid_cstring(char *buffer, uint32_t buffer_size) {
  if (buffer_size < sizeof(g_ipa.eid.eid) * 2 + 1) {
    return eNotEnoughBuffer;
  }

  if (byte_utils__byte_array_to_hex_string(
          (unsigned char *)g_ipa.eid.eid, sizeof(g_ipa.eid.eid),
          (unsigned char *)buffer, (size_t)buffer_size) < 0) {
    LOGE("[ipa__get_eid_cstring] Error parsing the EID byte array to hex "
         "string");
    return eFatal;
  }

  buffer[sizeof(g_ipa.eid.eid) * 2] = '\0';
  return eOk;
}

ErrCode ipa__get_mcc_mnc(mcc_mnc_t *mcc_mnc) {
  if (!g_ipa.field_is_present.mcc_mnc) {
    return eFatal;
  }
  memcpy(mcc_mnc, &g_ipa.mcc_mnc, sizeof(mcc_mnc_t));
  return eOk;
}

static ErrCode ipa__parse_euicc_info1_for_certs(const uint8_t *tlv_buffer,uint32_t buffer_size,ipa_pkid_list_data_t *data) {
  ErrCode rc = eFatal;
  _BerTlv root_tlv, sub_tlv;
  uint32_t offset = 0;

  if (data == NULL) {
    return eBadArg;
  }

  if ((rc = ber_tlv_parser__ber_tlv_2(tlv_buffer, buffer_size, 0, &root_tlv)) !=eOk ||root_tlv.tag != EUICC_INFO_1) {
    LOGE("[ipa__parse_for_certs] Failed to parse root TLV or tag is not "
         "0xBF20. Found tag 0x%X.",
         root_tlv.tag);
    return eFatal;
  }

  memset(data, 0, sizeof(ipa_pkid_list_data_t));

  const uint8_t *root_value_ptr = tlv_buffer + root_tlv.nTag + root_tlv.nLength;

  while (offset < root_tlv.length) {
    if ((rc = ber_tlv_parser__ber_tlv_2(root_value_ptr, root_tlv.length, offset,&sub_tlv)) != eOk) {
      LOGE("[ipa__parse_cert_objects] Failed to parse sub-TLV inside "
           "euiccInfo1 at offset %u.",
           offset);
      break;
    }

    const uint8_t *sub_value_ptr =root_value_ptr + offset + sub_tlv.nTag + sub_tlv.nLength;
    switch (sub_tlv.tag) {
    case CIPKID_LIST_FOR_VERIFICATION: // euiccCiPKIdListForVerification
      rc = ipa__parse_pkid_list(sub_value_ptr, sub_tlv.length,&data->ci_pkid_list_for_verification);
      break;
    case CIPKID_LIST_FOR_SIGNING: // euiccCiPKIdListForSigning
      rc = ipa__parse_pkid_list(sub_value_ptr, sub_tlv.length,&data->ci_pkid_list_for_signing);
      break;
    default:
      break;
    }
    if (rc != eOk) {
      break;
    }
    offset += sub_tlv.nTag + sub_tlv.nLength + sub_tlv.length;
  }
  if (rc != eOk) {
    ipa__free_certs_data(data);
  }
  return rc;
}

ErrCode ipa__get_certs(ipa_pkid_list_data_t *out_data) {

  ErrCode rc = eFatal;
  int err;
  uint8_t *raw_tlv_buffer = NULL;
  uint32_t raw_tlv_size = 0;

  if (out_data == NULL) {
    LOGE("[ipa__get_certs] Output parameter is NULL.");
    return eBadArg;
  }

  if ((err = es10__init(g_ipa.es10)) < 0) {
    LOGE("[ipa__get_certs] Failed to initialize ES10, err %d", err);
    return eFatal;
  }

  if ((err = es10__get_euicc_info_1(g_ipa.es10, &raw_tlv_buffer,
                                    &raw_tlv_size)) < 0) {
    LOGE("[ipa__get_certs] ES10.get_euicc_info_1 failed, err %d", err);
    rc = eFatal;
    goto deinit_es10;
  }

  LOG_DATA(eLogDebug, "Fetched raw euiccInfo1 TLV", raw_tlv_buffer,
           raw_tlv_size);
  rc = ipa__parse_euicc_info1_for_certs(raw_tlv_buffer, raw_tlv_size, out_data);
  if (rc != eOk) {
    LOGE("[ipa__get_certs] Failed to parse the fetched euiccInfo1 TLV, rc %d",rc);
  } else {
    LOGI("[ipa__get_certs] Successfully fetched and parsed euiccInfo1.");
  }

deinit_es10:
  if ((err = es10__deinit(g_ipa.es10)) < 0) {
    LOGE("[ipa__get_certs] Failed to deinitialize ES10, err %d", err);
    if (rc == eOk) {
      rc = eFatal;
    }
  }

  if (rc != eOk) {
    ipa__free_certs_data(out_data);
  }

  M_free(raw_tlv_buffer);

  return rc;
}
void ipa__free_certs_data(ipa_pkid_list_data_t *data) {
  if (data == NULL) {
    return;
  }
  ipa__free_pkid_list(&data->ci_pkid_list_for_verification);
  ipa__free_pkid_list(&data->ci_pkid_list_for_signing);
}

void ipa__set_notify_state_change(state_change_cause_t *cause) {
  if (cause) {
    switch (*cause) {
    case STATE_CHANGE_CAUSE_OTHER_EIM:
    case STATE_CHANGE_CAUSE_FALLBACK:
    case STATE_CHANGE_CAUSE_EMERGENCY_PROFILE:
    case STATE_CHANGE_CAUSE_LOCAL:
    case STATE_CHANGE_CAUSE_RESET:
    case STATE_CHANGE_CAUSE_IMMEDIATE_ENABLE_PROFILE:
    case STATE_CHANGE_CAUSE_DEVICE_CHANGE:
    case STATE_CHANGE_CAUSE_UNDEFINED:
      g_ipa.state_change_cause = *cause;
      break;
    default:
      g_ipa.state_change_cause = STATE_CHANGE_CAUSE_UNDEFINED;
      break;
    }
    g_ipa.notify_state_change = true;

  } else {
    g_ipa.notify_state_change = false;
  }
}

bool ipa__get_notify_state_change(state_change_cause_t *cause) {
  if (cause) {
    *cause = g_ipa.state_change_cause;
  }

  return g_ipa.notify_state_change;
}

void ipa__set_ipa_exit() {
  LOGI("IPA has received a signal to terminate the execution. All running "
       "threads that are using the IPA should terminate. This process may take "
       "a few minutes, do not turn off your device.");
  semaphore_give(g_ipa.exit_sem);
}

bool ipa__get_ipa_exit() {
  if (0 == semaphore_take(g_ipa.exit_sem)) {
    semaphore_give(g_ipa.exit_sem);
    return true;
  } else {
    return false;
  }
}

int ipa__take() { return semaphore_take(g_ipa.ipa_semaphore); }

void ipa__give() { semaphore_give(g_ipa.ipa_semaphore); }

bool ipa__is_available() {
  if (0 == ipa__take()) {
    ipa__give();
    return true;
  } else {
    return false;
  }
}

ErrCode
ipa__euicc_package(const euicc_package_request_plain_t *euicc_package_request,
                   epr_and_notifications_t *epr_and_notifications) {
  ErrCode rc = eFatal;
  int err = 0;
  uint32_t retrieve_notifications_list_response_size = 0;
  retrieve_notifications_list_request_t retrieve_notifications_list_request = {
      .field_is_present = {.search_criteria = false}};

  /* Validate the input parameters */
  if (!euicc_package_request) {
    LOGE("[ipa__euicc_package] The EuiccPackageRequest is null");
    return eBadArg;
  }
  if (!epr_and_notifications) {
    LOGE("[ipa__euicc_package] The EprAndNotifications object is null");
    return eBadArg;
  }
  memset(epr_and_notifications, 0, sizeof(epr_and_notifications_t));

  /* Load the eUICC Package */
  if ((err = es10__init(g_ipa.es10)) < 0) {
    LOGE("[ipa__euicc_package] Error initializing the ES10, err %d", err);
    return eFatal;
  }

#ifdef SGP32
  err = es10__load_euicc_package(
      g_ipa.es10, euicc_package_request->euicc_package_request,
      euicc_package_request->euicc_package_request_size,
      &epr_and_notifications->euicc_package_result.tlv,
      &epr_and_notifications->euicc_package_result.tlv_size);
#else
  err = load_euicc_package_sgp22_translator(
      euicc_package_request->euicc_package_request,
      euicc_package_request->euicc_package_request_size,
      &epr_and_notifications->euicc_package_result,
      &epr_and_notifications->euicc_package_result_size);
#endif

  if (err < 0) {
    LOGE("[ipa__euicc_package] ES10.LoadEuiccPackage failed, err %d", err);
    epr_and_notifications->euicc_package_result.tlv = NULL;
    epr_and_notifications->euicc_package_result.tlv_size = 0;
    if ((err = es10__deinit(g_ipa.es10)) < 0) {
      LOGE("[ipa__euicc_package] Error deinitializing the ES10, err %d", err);
    }
    return eFatal;
  }

#if defined(SGP32) && defined(TEST_FEATURE_PROFILE_ROLLBACK)
  if (g_ipa.profile_rollback_test_use_case) {
    uint8_t *rollback_euicc_package_result = NULL;
    uint32_t rollback_euicc_package_result_size = 0;
    if (eOk == (rc = ipa__execute_profile_rollback(
                    &rollback_euicc_package_result,
                    &rollback_euicc_package_result_size))) {
      M_free(epr_and_notifications->euicc_package_result
                 .tlv); // discard the previous eIM Package Result
      epr_and_notifications->euicc_package_result.tlv =
          rollback_euicc_package_result; // include the new eUICC Package Result
                                         // returned by the
                                         // ES10b.ProfileRollback
      epr_and_notifications->euicc_package_result.tlv_size =
          rollback_euicc_package_result_size;
      g_ipa.profile_rollback_test_use_case = false;
      LOGI("Profile Rollback Test use case flag disabled");
    } else {
      LOGE("[ipa__euicc_package] Error executing the Profile Rollback, rc %d",
           rc);
    }
  }
#endif

  // Retrieve the notifications
  if ((err = es10__retrieve_notifications_list(
           g_ipa.es10, &retrieve_notifications_list_request,
           (uint8_t **)&epr_and_notifications->context_notification_list,
           &retrieve_notifications_list_response_size)) < 0) {
    LOGE("[ipa__euicc_package] ES10.RetrieveNotificationsList failed, err %d",
         err);
    state_change_cause_t state_change_cause = STATE_CHANGE_CAUSE_UNDEFINED;
    ipa__set_notify_state_change(&state_change_cause);
    epr_and_notifications->context_notification_list = NULL;
  }

  if ((rc = ipa__update_ipa_profiles_state()) != eOk) {
    LOGW("[ipa__euicc_package] Error updating the IPA profile state, rc %d",
         rc);
  }

  if ((err = es10__deinit(g_ipa.es10)) < 0) {
    LOGE("[ipa__euicc_package] Error deinitializing the ES10, err %d", err);
  }

  // Parse the EuiccPackageResult
  if ((rc = es10_tlv_extractor__euicc_package_result(
           epr_and_notifications->euicc_package_result.tlv,
           epr_and_notifications->euicc_package_result.tlv_size,
           &epr_and_notifications->euicc_package_result.obj)) != eOk) {
    LOGE("[ipa__euicc_package] Error on parse the EuiccPackageResult, rc %d",
         rc);
    M_free(epr_and_notifications->euicc_package_result.tlv);
    epr_and_notifications->euicc_package_result.tlv = NULL;
    M_free(epr_and_notifications->context_notification_list);
    epr_and_notifications->context_notification_list = NULL;
    return rc;
  }

  // Check if there are PendingNotifications on the
  // RetrieveNotificationsListResponse
  if (epr_and_notifications->context_notification_list) {
    ipa__get_notification_list(
        (uint8_t *)epr_and_notifications->context_notification_list,
        retrieve_notifications_list_response_size,
        &epr_and_notifications->notification_list,
        &epr_and_notifications->notification_list_size);
    if (!epr_and_notifications->notification_list) {
      M_free(epr_and_notifications->context_notification_list);
      epr_and_notifications->context_notification_list = NULL;
    }
  }

  return eOk;
}

void ipa__register_profile_state_callback(
    const ipa_profile_state_change_callback_t callback) {
  g_ipa.profile_state_callback = callback;
  if (callback) {
    LOGI("[ipa__register_profile_state_callback] Profile state change callback "
         "has been registered.");
  } else {
    LOGI("[ipa__register_profile_state_callback] Profile state change callback "
         "has been unregistered.");
  }
}

ErrCode ipa__ipa_euicc_data(const ipa_euicc_data_request_t *request,
                            ipa_euicc_data_response_t *response) {
  ErrCode rc;
  euicc_data_t euicc_data;

  /* Check input params */
  if (!request) {
    LOGE("[ipa__ipa_euicc_data] IpaEuiccDataRequest object is null");
    return eBadArg;
  }
  if (!response) {
    LOGE("[ipa__ipa_euicc_data] IpaEuiccDataResponse object is null");
    return eBadArg;
  }

  /* Check ecallActive */
  if (g_ipa.emergency_profile_enabled) {
    LOGW("[ipa__ipa_euicc_data] The Emergency Profile is enabled");
    return ipa__set_ipa_euicc_data_response_error(
        request, IPA_EUICC_DATA_ERROR_ECALL_ACTIVE, response);
  }

  /* Initialize the response */
  memset(response, 0, sizeof(ipa_euicc_data_response_t));
  response->choice = IPA_EUICC_DATA_CHOICE;

  /* Retrieve the eUICC data */
  if ((rc = ipa__euicc_data(request, &euicc_data)) != eOk) {
    LOGW("[ipa__ipa_euicc_data] Error retrieving eUICC data, rc %d", rc);
    return ipa__set_ipa_euicc_data_response_error(
        request, IPA_EUICC_DATA_ERROR_UNDEFINED_ERROR, response);
  }

#ifdef SGP32
  // Certificates
  rc = ipa__ipa_euicc_data_response_set_certificates(request, &euicc_data,
                                                     response);
  if (rc != eOk || IPA_EUICC_DATA_RESPONSE_ERROR_CHOICE == response->choice) {
    LOGW("[ipa__ipa_euicc_data] Error including the certificates on the "
         "response, rc %d",
         rc);
    free_euicc_data(&euicc_data);
    return rc;
  }

  // associationToken
  rc = ipa__ipa_euicc_data_response_set_association_token(request, &euicc_data,
                                                          response);
  if (rc != eOk || IPA_EUICC_DATA_RESPONSE_ERROR_CHOICE == response->choice) {
    LOGW("[ipa__ipa_euicc_data] Error including the association token on the "
         "response, rc %d",
         rc);
    free_euicc_data(&euicc_data);
    return rc;
  }
  M_free(euicc_data.get_eim_configuration_data_response); // Not needed anymore
  euicc_data.get_eim_configuration_data_response = NULL;
  euicc_data.get_eim_configuration_data_response_size = 0;

  // euiccPackageResultList
  rc = ipa__ipa_euicc_data_response_set_euicc_package_result_list(
      request, &euicc_data, response);
  if (rc != eOk || IPA_EUICC_DATA_RESPONSE_ERROR_CHOICE == response->choice) {
    LOGW("[ipa__ipa_euicc_data] Error including the euiccPackageResultList on "
         "the response, rc %d",
         rc);
    free_euicc_data(&euicc_data);
    return rc;
  }
#endif
  // Addresses
  rc = ipa__ipa_euicc_data_response_set_addresses(request, &euicc_data,
                                                  response);
  if (rc != eOk || IPA_EUICC_DATA_RESPONSE_ERROR_CHOICE == response->choice) {
    LOGW("[ipa__ipa_euicc_data] Error including the addresses on the response, "
         "rc %d",
         rc);
    free_euicc_data(&euicc_data);
    return rc;
  }
  M_free(euicc_data.euicc_configured_addresses_response); // Not needed anymore
  euicc_data.euicc_configured_addresses_response = NULL;
  euicc_data.euicc_configured_addresses_response_size = 0;

  // notificationsList
  rc = ipa__ipa_euicc_data_response_set_notifications_list(request, &euicc_data,
                                                           response);
  if (rc != eOk || IPA_EUICC_DATA_RESPONSE_ERROR_CHOICE == response->choice) {
    LOGW("[ipa__ipa_euicc_data] Error including the notificationsList on the "
         "response, rc %d",
         rc);
    free_euicc_data(&euicc_data);
    return rc;
  }

  // euiccInfo
  rc = ipa__ipa_euicc_data_response_set_euicc_info(request, &euicc_data,
                                                   response);
  if (rc != eOk || IPA_EUICC_DATA_RESPONSE_ERROR_CHOICE == response->choice) {
    LOGW("[ipa__ipa_euicc_data] Error including the eUICCInfo on the response, "
         "rc %d",
         rc);
    free_euicc_data(&euicc_data);
    return rc;
  }

  // ipaCapabilities
  if (request->tag_list.ipa_capabilities) {
    memcpy(&response->value.ipa_euicc_data.ipa_capabilities,
           &g_ipa.ipa_capabilities, sizeof(ipa_capabilities_t));
    response->value.ipa_euicc_data.field_is_present.ipa_capabilities = true;
  }
  // deviceInfo
  if (request->tag_list.device_information) {
    response->value.ipa_euicc_data.device_info = device_info__get_instance();
    response->value.ipa_euicc_data.field_is_present.device_information = true;
  }

  /* Copy the transactionId */
  if (request->field_is_present.eim_transaction_id) {
    memcpy(&response->value.ipa_euicc_data.eim_transaction_id,
           &request->eim_transaction_id, sizeof(transaction_id_t));
    response->value.ipa_euicc_data.field_is_present.eim_transaction_id = true;
  }

  return eOk;
}

#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
ErrCode ipa__profile_download_trigger(
    const profile_download_trigger_request_t *request,
    profile_download_trigger_response_result_t *response) {
  ErrCode rc;
  int err;
  uint8_t *get_euicc_challenge_response_tlv = NULL;
  uint32_t get_euicc_challenge_response_tlv_size;
  get_euicc_challenge_response_t get_euicc_challenge_response_obj;
#if !defined(IPA_FEATURE_MINIMIZE_ESIPA_BYTES) &&                              \
    !defined(IPA_FEATURE_EIM_DOWNLOAD_DATA_HANDLING)
  uint8_t *euicc_configured_addresses_response_tlv = NULL;
  uint32_t euicc_configured_addresses_response_tlv_size;
  euicc_configured_addresses_response_t
      euicc_configured_addresses_response_obj = {0};
#endif
#ifndef IPA_FEATURE_EIM_DOWNLOAD_DATA_HANDLING
  activation_code_t ac; // Only used in the activation code use case
#endif

  /* Check input parameters */
  if (!request) {
    LOGE("[ipa__profile_download_trigger] The request pointer is null");
    return eBadArg;
  }
  if (!response) {
    LOGE("[ipa__profile_download_trigger] The response pointer is null");
    return eBadArg;
  }

  if (g_ipa.emergency_profile_enabled) {
    LOGD("[ipa__profile_download_trigger] The emergency profile is enabled, "
         "error will be returned");
    return ipa__profile_download_trigger_response_result_set_error(
        request, response, PROFILE_DOWNLOAD_ERROR_REASON_ECALL_ACTIVE);
  }

#ifndef IPA_FEATURE_EIM_DOWNLOAD_DATA_HANDLING
  if (ACTIVATION_CODE_CHOICE == request->profile_download_data.choice) {
    // Parse the Activation Code
    if ((rc = rsp__parse_activation_code(
             request->profile_download_data.data,
             request->profile_download_data.data_len, &ac)) != eOk) {
      LOGE("[ipa__profile_download_trigger] Error parsing the Activation Code, "
           "rc %d");
      return ipa__profile_download_trigger_response_result_set_error(
          request, response, PROFILE_DOWNLOAD_ERROR_REASON_UNDEFINED_REASON);
    }
  }
#endif

  /* Retrieve data from the UICC */
  if ((err = es10__init(g_ipa.es10)) < 0) {
    LOGE("[ipa__profile_download_trigger] Error initializing the ES10, err %d",
         err);
    return ipa__profile_download_trigger_response_result_set_error(
        request, response, PROFILE_DOWNLOAD_ERROR_REASON_UNDEFINED_REASON);
  }

  if ((err = es10__get_euicc_challenge(
           g_ipa.es10, &get_euicc_challenge_response_tlv,
           &get_euicc_challenge_response_tlv_size)) < 0) {
    LOGE(
        "[ipa__profile_download_trigger] ES10.GetEUICCChallenge failed, err %d",
        err);
    goto profile_download_trigger_es10_deinit;
  }

#ifndef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
  if ((err = es10__get_euicc_info_1(
           g_ipa.es10,
           &response->value.initiate_authentication_request_esipa.euicc_info_1,
           &response->value.initiate_authentication_request_esipa
                .euicc_info_1_size)) < 0) {
    LOGE("[ipa__profile_download_trigger] ES10.GetEUICCInfo failed, err %d",
         err);
    goto profile_download_trigger_es10_deinit;
  }
#endif

#if !defined(IPA_FEATURE_MINIMIZE_ESIPA_BYTES) &&                              \
    !defined(IPA_FEATURE_EIM_DOWNLOAD_DATA_HANDLING)
  if (CONTACT_DEFAULT_SMDP_CHOICE == request->profile_download_data.choice ||
      (CONTACT_SMDS_CHOICE == request->profile_download_data.choice &&
       (!request->profile_download_data.data ||
        0 == request->profile_download_data.data_len))) {
    if ((err = es10__get_euicc_configured_addresses(
             g_ipa.es10, &euicc_configured_addresses_response_tlv,
             &euicc_configured_addresses_response_tlv_size)) < 0) {
      LOGE("[ipa__profile_download_trigger] ES10.GetEuiccConfiguredAddresses "
           "failed, err %d",
           err);
      goto profile_download_trigger_es10_deinit;
    }
  }

#endif

profile_download_trigger_es10_deinit:
  if (es10__deinit(g_ipa.es10) < 0) {
    LOGW("[ipa__profile_download_trigger] Error deinitializing the ES10");
  }

  if (err < 0) {
    LOGE("[ipa__profile_download_trigger] Error retriving data from the UICC, "
         "err %d",
         err);
    rc = eFatal;
    goto profile_download_trigger_es10_terminate;
  }

  /* Extract the euiccChallenge */
  rc = es10_tlv_extractor__get_euicc_challenge_response(
      get_euicc_challenge_response_tlv, get_euicc_challenge_response_tlv_size,
      &get_euicc_challenge_response_obj);
  M_free(get_euicc_challenge_response_tlv);
  get_euicc_challenge_response_tlv = NULL;
  get_euicc_challenge_response_tlv_size = 0;
  if (rc != eOk) {
    LOGE("[ipa__profile_download_trigger] Error extracting the euiccChallenge "
         "from the GetEuiccChallengeResponse, rc %d",
         rc);
    goto profile_download_trigger_es10_terminate;
  }
  /* Set the euiccChallenge in the InitiateAuthenticationRequestEsipa */
  memcpy(&response->value.initiate_authentication_request_esipa.euicc_challenge,
         &get_euicc_challenge_response_obj.euicc_challenge,
         sizeof(challenge_t));

#if !defined(IPA_FEATURE_MINIMIZE_ESIPA_BYTES) &&                              \
    !defined(IPA_FEATURE_EIM_DOWNLOAD_DATA_HANDLING)
  /* Extract the euicc configured addresses */
  if (euicc_configured_addresses_response_tlv) {
    rc = es10_tlv_extractor__euicc_configured_addresses_response(
        euicc_configured_addresses_response_tlv,
        euicc_configured_addresses_response_tlv_size,
        &euicc_configured_addresses_response_obj);
    M_free(euicc_configured_addresses_response_tlv);
    euicc_configured_addresses_response_tlv = NULL;
    euicc_configured_addresses_response_tlv_size = 0;
    if (rc != eOk) {
      LOGE("[ipa__profile_download_trigger] Error extracting the addresses "
           "from the EuiccConfiguredAddressesResponse, rc %d",
           rc);
      goto profile_download_trigger_es10_terminate;
    }
  }

  /* Set the smdpAddress in the InitiateAuthenticationRequestEsipa */
  switch (request->profile_download_data.choice) {
  case ACTIVATION_CODE_CHOICE:
    memcpy(
        response->value.initiate_authentication_request_esipa.smdp_address.fqdn,
        ac.smdp_address,
        ac.smdp_address_size); // We don't need to check the length of the
                               // address since the AC is already parsed
    response->value.initiate_authentication_request_esipa.smdp_address
        .fqdn[ac.smdp_address_size] = '\0';
    break;

  case CONTACT_DEFAULT_SMDP_CHOICE:
    if (euicc_configured_addresses_response_obj.field_is_present
            .default_dp_address) {
      memcpy(
          &response->value.initiate_authentication_request_esipa.smdp_address,
          &euicc_configured_addresses_response_obj.default_dp_address,
          sizeof(fqdn_t));
    } else {
      LOGE("[ipa__profile_download_trigger] The UICC does not have a Default "
           "SM-DP+ address configured");
      rc = eFatal;
      goto profile_download_trigger_es10_terminate;
    }
    break;

  case CONTACT_SMDS_CHOICE:
    if (!request->profile_download_data.data ||
        0 == request->profile_download_data.data_len) {
      memcpy(
          &response->value.initiate_authentication_request_esipa.smdp_address,
          &euicc_configured_addresses_response_obj.root_ds_address,
          sizeof(fqdn_t));
    } else {
      if (request->profile_download_data.data_len >=
          sizeof(response->value.initiate_authentication_request_esipa
                     .smdp_address.fqdn)) {
        LOGE("[ipa__profile_download_trigger] Bad smdsAddress length %u. "
             "Maximum length %u",
             request->profile_download_data.data_len,
             sizeof(response->value.initiate_authentication_request_esipa
                        .smdp_address.fqdn) -
                 1);
        rc = eFatal;
        goto profile_download_trigger_es10_terminate;
      } else {
        memcpy(&response->value.initiate_authentication_request_esipa
                    .smdp_address.fqdn,
               request->profile_download_data.data,
               request->profile_download_data.data_len);
        response->value.initiate_authentication_request_esipa.smdp_address
            .fqdn[request->profile_download_data.data_len] = '\0';
      }
    }
    break;

  default:
    LOGE(
        "[ipa__profile_download_trigger] Unknown ProfileDownloadData CHOICE %d",
        request->profile_download_data.choice);
    rc = eBadArg;
    goto profile_download_trigger_es10_terminate;
  }
#endif

  clear_indirect_rsp_context(); // Clear context from previous RSP session (if
                                // any) to start a new one
#ifndef IPA_FEATURE_EIM_DOWNLOAD_DATA_HANDLING
  /* In case we have the MatchingId, we will store it in the Indirect RSP
   * context */
  if (ACTIVATION_CODE_CHOICE == request->profile_download_data.choice) {
    memcpy(g_ipa.indirect_rsp_context.matching_id, ac.ac_token,
           ac.ac_token_size); // We don't need to check the length of the AC
                              // token since the AC is already parsed
    g_ipa.indirect_rsp_context.matching_id_size = ac.ac_token_size;
    g_ipa.indirect_rsp_context.field_is_present.matching_id = true;
  }
  if (CONTACT_DEFAULT_SMDP_CHOICE == request->profile_download_data.choice) {
    g_ipa.indirect_rsp_context.field_is_present.default_smdp_use_case = true;
  }
#endif

  /* Set the eimTransactionId in the InitiateAuthenticationRequestEsipa */
  response->value.initiate_authentication_request_esipa.field_is_present
      .eim_transaction_id = request->field_is_present.eim_transaction_id;
  if (response->value.initiate_authentication_request_esipa.field_is_present
          .eim_transaction_id) {
    memcpy(&response->value.initiate_authentication_request_esipa
                .eim_transaction_id,
           &request->eim_transaction_id, sizeof(transaction_id_t));
  }

profile_download_trigger_es10_terminate:
  if (eOk == rc) {
    LOGD("[ipa__profile_download_trigger] ProfileDownloadTriggerRequest successfully executed");
    response->choice = INITIATE_AUTHENTICATION_REQUEST_ESIPA_CHOICE;
    return eOk;
  } else {
    LOGE("[ipa__profile_download_trigger] Error executing the ProfileDownloadTriggerRequest, rc %d",rc);
    M_free(get_euicc_challenge_response_tlv);
#ifndef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
    M_free(response->value.initiate_authentication_request_esipa.euicc_info_1);
#endif
#if !defined(IPA_FEATURE_MINIMIZE_ESIPA_BYTES) &&                              \
    !defined(IPA_FEATURE_EIM_DOWNLOAD_DATA_HANDLING)
    M_free(euicc_configured_addresses_response_tlv);
#endif
    clear_indirect_rsp_context(); // Clear the RSP session context on error
    return ipa__profile_download_trigger_response_result_set_error(
        request, response, PROFILE_DOWNLOAD_ERROR_REASON_UNDEFINED_REASON);
  }
}

ErrCode ipa__initiate_authentication_response(
    const initiate_authentication_response_esipa_t *request,
    authenticate_client_request_esipa_t *response) {
  ErrCode rc;
  int err;
  server_signed_1_t server_signed_1;
  authenticate_server_request_t authenticate_server_request;

  /* Check input parameters */
  if (!request) {
    LOGE("[ipa__initiate_authentication_response] The request pointer is null");
    return eBadArg;
  }
  if (!response) {
    LOGE(
        "[ipa__initiate_authentication_response] The response pointer is null");
    return eBadArg;
  }
  if (INITIATE_AUTHENTICATION_ERROR_ESIPA_CHOICE == request->choice) {
    LOGE("[ipa__initiate_authentication_response] The "
         "InitiateAuthenticationResponseEsipa is a "
         "initiateAuthenticationErrorEsipa(%u). Indirect mutual authentication "
         "procedure aborted.",
         request->value.initiate_authentication_error_esipa);
    clear_indirect_rsp_context();
    return eBadArg;
  }

  /* Extract the transactionId */
#ifndef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
  if (request->value.initiate_authentication_ok_esipa.field_is_present
          .transaction_id) {
    memcpy(&response->transaction_id,
           &request->value.initiate_authentication_ok_esipa.transaction_id,
           sizeof(transaction_id_t));
  } else {
#endif
    LOGD("[ipa__initiate_authentication_response] The TransactionId will be "
         "extracted from the ServerSigned1");
    if ((rc = es10_tlv_extractor__server_signed_1(
             request->value.initiate_authentication_ok_esipa.server_signed_1,
             request->value.initiate_authentication_ok_esipa
                 .server_signed_1_size,
             &server_signed_1)) != eOk) {
      LOGE("[ipa__initiate_authentication_response] Error extracting the "
           "transactionId from the ServerSigned1, rc %d. Indirect mutual "
           "authentication procedure aborted.",
           rc);
      clear_indirect_rsp_context();
      return rc;
    }
    memcpy(&response->transaction_id, &server_signed_1.transaction_id,
           sizeof(transaction_id_t));
#ifndef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
  }
#endif

  /* Prepare the AuthenticateServerRequest */
  // ctxParams1
#ifdef IPA_FEATURE_EIM_CTX_PARAMS1_GENERATION
  authenticate_server_request.ctx_params_1.type = CTX_PARAMS_1_PLAIN;
  authenticate_server_request.ctx_params_1.value.ctx_params_1_plain_value.data =
      request->value.initiate_authentication_ok_esipa.ctx_params_1_value;
  authenticate_server_request.ctx_params_1.value.ctx_params_1_plain_value.size =
      request->value.initiate_authentication_ok_esipa.ctx_params_1_value_size;
#ifdef IPA_FEATURE_EIM_DOWNLOAD_DATA_HANDLING
  bool plain_ctx_params_1_matching_id;
  if ((rc = esipa_tlv_extractor__matching_id_is_present_ctx_params1_value(
           request->value.initiate_authentication_ok_esipa.ctx_params_1_value,
           (uint32_t)request->value.initiate_authentication_ok_esipa
               .ctx_params_1_value_size,
           &plain_ctx_params_1_matching_id)) != eOk) {
    LOGE("[ipa__initiate_authentication_response] Error extracting the "
         "optional MatchingId from the CtxParams1 , rc %d. Indirect mutual "
         "authentication procedure aborted.",
         rc);
    clear_indirect_rsp_context();
    return rc;
  }
  if (!plain_ctx_params_1_matching_id) {
    g_ipa.indirect_rsp_context.field_is_present.default_smdp_use_case = true;
  }
#endif
  LOGD("[ipa__initiate_authentication_response] The CtxParams1 used are "
       "generated by the eIM");
#else
  authenticate_server_request.ctx_params_1.type = CTX_PARAMS_1_OBJ;
  authenticate_server_request.ctx_params_1.value.ctx_params_1_obj
      .ctx_params_for_common_authentication.device_info =
      device_info__get_instance();
  if (request->value.initiate_authentication_ok_esipa.field_is_present
          .matching_id) {
    authenticate_server_request.ctx_params_1.value.ctx_params_1_obj
        .ctx_params_for_common_authentication.field_is_present.matching_id =
        true;
    authenticate_server_request.ctx_params_1.value.ctx_params_1_obj
        .ctx_params_for_common_authentication.matching_id =
        request->value.initiate_authentication_ok_esipa.matching_id;
    authenticate_server_request.ctx_params_1.value.ctx_params_1_obj
        .ctx_params_for_common_authentication.matching_id_size =
        request->value.initiate_authentication_ok_esipa.matching_id_size;
    LOGD("[ipa__initiate_authentication_response] The MatchingId used in the "
         "CtxParams1 comes from the eIM");
#ifndef IPA_FEATURE_EIM_DOWNLOAD_DATA_HANDLING
  } else if (g_ipa.indirect_rsp_context.field_is_present.matching_id) {
    authenticate_server_request.ctx_params_1.value.ctx_params_1_obj
        .ctx_params_for_common_authentication.field_is_present.matching_id =
        true;
    authenticate_server_request.ctx_params_1.value.ctx_params_1_obj
        .ctx_params_for_common_authentication.matching_id =
        g_ipa.indirect_rsp_context.matching_id;
    authenticate_server_request.ctx_params_1.value.ctx_params_1_obj
        .ctx_params_for_common_authentication.matching_id_size =
        g_ipa.indirect_rsp_context.matching_id_size;
    LOGD("[ipa__initiate_authentication_response] The MatchingId used in the "
         "CtxParams1 comes from the IPA context");
#endif
  } else {
    authenticate_server_request.ctx_params_1.value.ctx_params_1_obj
        .ctx_params_for_common_authentication.field_is_present.matching_id =
        false;
    LOGD("[ipa__initiate_authentication_response] No MatchingId is used in the "
         "CtxParams1");
#ifdef IPA_FEATURE_EIM_DOWNLOAD_DATA_HANDLING
    g_ipa.indirect_rsp_context.field_is_present.default_smdp_use_case = true;
#endif
  }
#endif

  // serverSigned1
  authenticate_server_request.server_signed_1 =
      request->value.initiate_authentication_ok_esipa.server_signed_1;
  authenticate_server_request.server_signed_1_size =
      request->value.initiate_authentication_ok_esipa.server_signed_1_size;

  // serverSignature1
  authenticate_server_request.server_signature_1 =
      request->value.initiate_authentication_ok_esipa.server_signature_1;
  authenticate_server_request.server_signature_1_size =
      request->value.initiate_authentication_ok_esipa.server_signature_1_size;

  // serverCertificate
  authenticate_server_request.server_certificate =
      request->value.initiate_authentication_ok_esipa.server_certificate;
  authenticate_server_request.server_certificate_size =
      request->value.initiate_authentication_ok_esipa.server_certificate_size;

  if ((err = es10__init(g_ipa.es10)) < 0) {
    LOGE("[ipa__initiate_authentication_response] Error initializing the ES10, "
         "err %d. Indirect mutual authentication procedure aborted.",
         err);
    clear_indirect_rsp_context();
    return eFatal;
  }

  // euiccCiPKIdToBeUsed
#ifdef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
  uint8_t *euicc_info_1;
  uint32_t euicc_info_1_size;
  if (request->value.initiate_authentication_ok_esipa.euicc_ci_pk_id_to_be_used
          .subject_key_identifier.size ==
      sizeof(authenticate_server_request.euicc_ci_pk_id_to_be_used.value)) {
    memcpy(&authenticate_server_request.euicc_ci_pk_id_to_be_used.value,
           &request->value.initiate_authentication_ok_esipa
                .euicc_ci_pk_id_to_be_used.subject_key_identifier.value,
           sizeof(authenticate_server_request.euicc_ci_pk_id_to_be_used.value));
  } else {
    if ((err = es10__get_euicc_info_1(g_ipa.es10, &euicc_info_1,
                                      &euicc_info_1_size)) < 0) {
      LOGE("[ipa__initiate_authentication_response] ES10.GetEUICCInfo failed, "
           "err %d",
           err);
      goto initiate_authentication_response_es10_deinit;
    }
    rc = ipa__reconstruct_truncated_euicc_ci_pk_id(
        euicc_info_1, euicc_info_1_size,
        &request->value.initiate_authentication_ok_esipa
             .euicc_ci_pk_id_to_be_used.subject_key_identifier,
        &authenticate_server_request.euicc_ci_pk_id_to_be_used);
    M_free(euicc_info_1);
    euicc_info_1 = NULL;
    euicc_info_1_size = 0;
    if (rc != eOk) {
      LOGE("[ipa__initiate_authentication_response] Error reconstructing the "
           "truncated euiccCiPKIdToBeUsed, rc %d",
           rc);
      err = -1;
      goto initiate_authentication_response_es10_deinit;
    }
  }
#else
  memcpy(&authenticate_server_request.euicc_ci_pk_id_to_be_used,
         &request->value.initiate_authentication_ok_esipa
              .euicc_ci_pk_id_to_be_used,
         sizeof(subject_key_identifier_t));
#endif

  /* Execute the ES10.AuthenticateServer */
  if ((err = es10__authenticate_server(
           g_ipa.es10, &authenticate_server_request,
           &response->authenticate_server_response,
           &response->authenticate_server_response_size)) < 0) {
    LOGE("[ipa__initiate_authentication_response] ES10.AuthenticateServer "
         "failed, err %d",
         err);
    goto initiate_authentication_response_es10_deinit; // To avoid warnings
  }

initiate_authentication_response_es10_deinit:
  if (es10__deinit(g_ipa.es10) < 0) {
    LOGW("[ipa__initiate_authentication_response] Error deinitializing the "
         "ES10");
  }

  if (err < 0) {
    LOGE("[ipa__initiate_authentication_response] Error retriving data from "
         "the UICC, err %d. Indirect mutual authentication procedure aborted.",
         err);
    clear_indirect_rsp_context();
    return eFatal;
  }

#ifdef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
  /** TODO: LPA-243 Compact the AuthenticateServerResponse
   * if ((rc =
   * ipa__compact_authenticate_server_response(response->authenticate_server_response,
   * &response->authenticate_server_response_size)) != eOk) {
   *     LOGE("[ipa__initiate_authentication_response] Error compacting the
   * AuthenticateServerResponse, rc %d. Indirect mutual authentication procedure
   * aborted.", rc); M_free(response->authenticate_server_response);
   *     clear_indirect_rsp_context();
   *     return rc;
   * }
   */
#endif

  /* Set the TransactionId in the context */
  g_ipa.indirect_rsp_context.field_is_present.transaction_id = true;
  memcpy(&g_ipa.indirect_rsp_context.transaction_id, &response->transaction_id,
         sizeof(transaction_id_t));

  return eOk;
}

ErrCode ipa__authenticate_client_response(
    const authenticate_client_response_esipa_t *request,
    authenticate_client_response_result_esipa_t *response) {
  ErrCode rc;
  int err;
  cancel_session_reason_t cancel_session_reason =
      CANCEL_SESSION_REASON_UNDEFINED_REASON;
  smdp_signed_2_t smdp_signed_2;
  prepare_download_request_t prepare_download_request;

  /* Check input parameters */
  if (!request) {
    LOGE("[ipa__authenticate_client_response] The request pointer is null");
    return eBadArg;
  }
  if (!response) {
    LOGE("[ipa__authenticate_client_response] The response pointer is null");
    return eBadArg;
  }

  if (AUTHENTICATE_CLIENT_ERROR_ESIPA_CHOICE == request->choice) {
    LOGW("[ipa__authenticate_client_response] The "
         "AuthenticateClientResponseEsipa is a "
         "authenticateClientErrorEsipa(%u).",
         request->value.authenticate_client_error_esipa);
#ifdef IPA_FEATURE_EIM_PROFILE_METADATA_VERIFICATION
    if (AUTHENTICATE_CLIENT_ERROR_ESIPA_PPR_NOT_ALLOWED ==
        request->value.authenticate_client_error_esipa) {
      cancel_session_reason = CANCEL_SESSION_REASON_PPR_NOT_ALLOWED;
    }
#endif
    goto indirect_authenticate_client_trigger_cancel_session;
  }

  if (AUTHENTICATE_CLIENT_OK_DS_ESIPA_CHOICE == request->choice) {
    if (request->value.authenticate_client_ok_ds_esipa.field_is_present
            .profile_download_trigger) {
      LOGD("[ipa__authenticate_client_response] Profile Download Trigger "
           "present.");
      if ((rc = ipa__profile_download_trigger(
               &request->value.authenticate_client_ok_ds_esipa
                    .profile_download_trigger,
               &response->value.profile_download_trigger_response_result)) !=
          eOk) {
        LOGE("[ipa__authenticate_client_response] Error profile download "
             "request, rc %d",
             rc);
        clear_indirect_rsp_context(); // Clear the RSP session context on error
      }
      response->choice = PROFILE_DOWNLOAD_TRIGGER_RESPONSE_RESULT_CHOICE;
      return rc;
    } else {
      LOGD("[ipa__authenticate_client_response] Profile Download Trigger not "
           "present, procedure aborted.");
      response->choice = OK_AUTHENTICATE_CLIENT_RESULT_CHOICE;
      clear_indirect_rsp_context(); // Indirect download finished, RSP session
                                    // context can be cleared
      return eOk;
    }
  }
  /* AUTHENTICATE_CLIENT_OK_DP_ESIPA_CHOICE */
#ifndef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
  if (request->value.authenticate_client_ok_dp_esipa.field_is_present
          .transaction_id) {
    memcpy(
        &response->value.get_bound_profile_package_request_esipa.transaction_id,
        &request->value.authenticate_client_ok_dp_esipa.transaction_id,
        sizeof(transaction_id_t));
  } else {
#endif
    LOGD("[ipa__authenticate_client_response] The TransactionId will be "
         "extracted from the SmdpSigned2");
    if ((rc = es10_tlv_extractor__smdp_signed_2(
             request->value.authenticate_client_ok_dp_esipa.smdp_signed_2,
             request->value.authenticate_client_ok_dp_esipa.smdp_signed_2_size,
             &smdp_signed_2)) != eOk) {
      LOGE("[ipa__authenticate_client_response] Error extracting data from the "
           "smdpSigned2 of the AuthenticateClientResponse, rc %d",
           rc);
      clear_indirect_rsp_context(); // Clear the RSP session context on error
      return rc;
    }
    memcpy(
        &response->value.get_bound_profile_package_request_esipa.transaction_id,
        &smdp_signed_2.transaction_id, sizeof(transaction_id_t));
#ifndef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
  }
#endif

  g_ipa.indirect_rsp_context.field_is_present.transaction_id = true;
  memcpy(
      &g_ipa.indirect_rsp_context.transaction_id,
      &response->value.get_bound_profile_package_request_esipa.transaction_id,
      sizeof(transaction_id_t));
#ifndef IPA_FEATURE_EIM_PROFILE_METADATA_VERIFICATION
  // TODO: LPA-250
  LOGE("[ipa__authenticate_client_response] Verify Profile Metadata is not "
       "implemented yet");
#endif
  /* Prepare the PrepareDownloadRequest */
  prepare_download_request.smdp_signed_2 =
      request->value.authenticate_client_ok_dp_esipa.smdp_signed_2;
  prepare_download_request.smdp_signed_2_size =
      request->value.authenticate_client_ok_dp_esipa.smdp_signed_2_size;
  prepare_download_request.smdp_signature_2 =
      request->value.authenticate_client_ok_dp_esipa.smdp_signature_2;
  prepare_download_request.smdp_signature_2_size =
      request->value.authenticate_client_ok_dp_esipa.smdp_signature_2_size;
  prepare_download_request.smdp_certificate =
      request->value.authenticate_client_ok_dp_esipa.smdp_certificate;
  prepare_download_request.smdp_certificate_size =
      request->value.authenticate_client_ok_dp_esipa.smdp_certificate_size;

  prepare_download_request.field_is_present.hash_cc =
      request->value.authenticate_client_ok_dp_esipa.field_is_present.hash_cc;
  if (prepare_download_request.field_is_present.hash_cc) {
    memcpy(&prepare_download_request.hash_cc,
           &request->value.authenticate_client_ok_dp_esipa.hash_cc,
           sizeof(sha256_hash_t));
  }

  if ((err = es10__init(g_ipa.es10)) < 0) {
    LOGE("[ipa__authenticate_client_response] Error initializing the ES10, err "
         "%d",
         err);
    goto indirect_authenticate_client_trigger_cancel_session;
  }
  /* Send the PrepareDownloadRequest */
  if ((err = es10__prepare_download(
           g_ipa.es10, &prepare_download_request,
           &response->value.get_bound_profile_package_request_esipa
                .prepare_download_response,
           &response->value.get_bound_profile_package_request_esipa
                .prepare_download_response_size)) < 0) {
    LOGE("[ipa__authenticate_client_response] ES10.PrepareDownload failed, err "
         "%d",
         err);
  }

  if (es10__deinit(g_ipa.es10) < 0) {
    LOGE("[ipa__authenticate_client_response] Error deinitializing the ES10");
  }

  if (err < 0) {
    LOGE("[ipa__authenticate_client_response] Error retriving data from the "
         "UICC, err %d. prepare downlaod procedure aborted.",
         err);
    goto indirect_authenticate_client_trigger_cancel_session;
  }
#ifdef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
  // TODO: LPA-251
#endif
  response->choice =
      GET_BOUND_PROFILE_PACKAGE_AUTHENTICATE_CLIENT_RESULT_CHOICE;
  return eOk;

indirect_authenticate_client_trigger_cancel_session:
  LOGW("[ipa__authenticate_client_response] Canceling the session of the "
       "ongoing indirect download.");
  if (!g_ipa.indirect_rsp_context.field_is_present.transaction_id) {
    LOGE("[ipa__authenticate_client_response] Error retriving transaction id, "
         "prepare downlaod procedure aborted.");
    clear_indirect_rsp_context(); // Clear the RSP session context on error
    return eFatal;
  }
  if ((rc = ipa__cancel_session(
           &g_ipa.indirect_rsp_context.transaction_id, cancel_session_reason,
           &response->value.cancel_session_request_esipa)) != eOk) {
    LOGE("[ipa__authenticate_client_response] Error canceling session, rc %d",
         rc);
  }
  clear_indirect_rsp_context(); // Indirect download finished, RSP session
                                // context can be cleared
  response->choice = CANCEL_SESSION_REQUEST_AUTHENTICATE_CLIENT_RESULT_CHOICE;
  return rc;
}

ErrCode ipa__get_bound_profile_package_response(
    const get_bound_profile_package_response_esipa_t *request,
    get_bound_profile_package_response_result_esipa_t *response) {
  ErrCode rc;
  int err;
  cancel_session_reason_t cancel_session_reason =
      CANCEL_SESSION_REASON_UNDEFINED_REASON;
#if defined(IPA_FEATURE_MINIMIZE_ESIPA_BYTES) ||                               \
    defined(IPA_FEATURE_EIM_PROFILE_METADATA_VERIFICATION)
  bound_profile_package_t bound_profile_package;
#endif
#ifdef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
  initialise_secure_channel_request_t initialise_secure_channel_request;
#endif

  /* Check input parameters */
  if (!request) {
    LOGE("[ipa__get_bound_profile_package_response] The request pointer is "
         "null");
    return eBadArg;
  }
  if (!response) {
    LOGE("[ipa__get_bound_profile_package_response] The response pointer is "
         "null");
    return eBadArg;
  }

  if (GET_BOUND_PROFILE_PACKAGE_ERROR_ESIPA_CHOICE == request->choice) {
    LOGW("[ipa__get_bound_profile_package_response] The "
         "GetBoundProfilePackageResponseEsipa is a "
         "getBoundProfilePackageErrorEsipa(%u). Processing get bound profile "
         "package request procedure aborted.",
         request->value.get_bound_profile_package_error_esipa);
#ifdef IPA_FEATURE_EIM_PROFILE_METADATA_VERIFICATION
    if (GET_BPP_ERROR_ESIPA_METADATA_MISMATCH ==
        request->value.get_bound_profile_package_error_esipa) {
      cancel_session_reason = CANCEL_SESSION_REASON_METADATA_MISMATCH;
    }
#endif
    goto get_bound_profile_package_trigger_cancel_session;
  }

  /* GetBoundProfilePackageOkEsipa */
#if defined(IPA_FEATURE_MINIMIZE_ESIPA_BYTES) ||                               \
    defined(IPA_FEATURE_EIM_PROFILE_METADATA_VERIFICATION)
  if ((rc = es10_tlv_extractor__bound_profile_package(
           request->value.get_bound_profile_package_ok_esipa
               .bound_profile_package,
           request->value.get_bound_profile_package_ok_esipa
               .bound_profile_package_size,
           &bound_profile_package)) != eOk) {
    LOGE("[ipa__get_bound_profile_package_response] Error extracting data from "
         "the boundProfilePackage of the BoundProfilePackageOkEsipa, rc %d",
         rc);
    clear_indirect_rsp_context(); // Clear the RSP session context on error
    return rc;
  }
#endif

#ifdef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
  if ((rc = es10_tlv_extractor__initialise_secure_channel(
           bound_profile_package.initialise_secure_channel_request,
           bound_profile_package.initialise_secure_channel_request_size,
           &initialise_secure_channel_request)) != eOk) {
    LOGE("[ipa__get_bound_profile_package_response] Error extracting data from "
         "the initialiseSecureChannelRequest of the BoundProfilePackage, rc %d",
         rc);
    clear_indirect_rsp_context(); // Clear the RSP session context on error
    return rc;
  }
  memcpy(&g_ipa.indirect_rsp_context.transaction_id,
         &initialise_secure_channel_request.transaction_id,
         sizeof(transaction_id_t));
#else
  memcpy(&g_ipa.indirect_rsp_context.transaction_id,
         &request->value.get_bound_profile_package_ok_esipa.transaction_id,
         sizeof(transaction_id_t));
#endif

  g_ipa.indirect_rsp_context.field_is_present.transaction_id = true;

#ifndef IPA_FEATURE_EIM_PROFILE_METADATA_VERIFICATION
  // TODO: LPA-250
  LOGE("[ipa__get_bound_profile_package_response] Verify Profile Metadata is "
       "not implemented yet");
#endif

  cancel_session_reason = CANCEL_SESSION_REASON_LOAD_BPP_EXECUTION_ERROR;

  if ((err = es10__init(g_ipa.es10)) < 0) {
    LOGE("[ipa__authenticate_client_response] Error initializing the ES10, err "
         "%d",
         err);
    goto get_bound_profile_package_trigger_cancel_session;
  }

  /* Send the LoadBoundProfilePackage */
  if ((err = es10__load_bound_profile_package(
           g_ipa.es10,
           request->value.get_bound_profile_package_ok_esipa
               .bound_profile_package,
           request->value.get_bound_profile_package_ok_esipa
               .bound_profile_package_size,
           &response->value.handle_notification_esipa.value.pending_notification
                .pending_notification,
           &response->value.handle_notification_esipa.value.pending_notification
                .pending_notification_size)) < 0) {
    LOGE("[ipa__get_bound_profile_package_response] "
         "ES10.LoadBoundProfilePackage failed, err %d",
         err);
  } else {
    response->value.handle_notification_esipa.choice =
        PENDING_NOTIFICATION_CHOICE_HNE;
  }

  if (es10__deinit(g_ipa.es10) < 0) {
    LOGE("[ipa__get_bound_profile_package_response] Error deinitializing the "
         "ES10");
  }

  if (err < 0) {
    LOGE("[ipa__get_bound_profile_package_response] Error retriving data from "
         "the UICC, err %d. load bound profile package procedure aborted.",
         err);
    goto get_bound_profile_package_trigger_cancel_session;
  }

#if defined(SGP32) && defined(EXTRA_FEATURE_IMMEDIATE_PROFILE_ENABLING)
  // Executing immediate Profile enabling in case of using default SM-DP+
  if (g_ipa.indirect_rsp_context.field_is_present.default_smdp_use_case) {
    if (eOk == (rc = rsp__immediate_profile_enabling(g_ipa.es10))) {
      state_change_cause_t state_change_cause =
          STATE_CHANGE_CAUSE_IMMEDIATE_ENABLE_PROFILE;
      ipa__set_notify_state_change(&state_change_cause);
      LOGI("Immediate Profile enabled");
    } else {
      LOGW("[ipa__get_bound_profile_package_response] Error on immediate "
           "Profile enabling, rc %d",
           rc);
    }
  }
#endif

#ifdef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
  // TODO: LPA-256
#endif
  response->choice =
      HANDLE_NOTIFICATION_GET_BOUND_PROFILE_PACKAGE_RESULT_CHOICE;
  clear_indirect_rsp_context(); // Indirect download finished, RSP session
                                // context can be cleared
  return eOk;

get_bound_profile_package_trigger_cancel_session:
  LOGW("[ipa__get_bound_profile_package_response] Canceling the session of the "
       "ongoing indirect download.");
  if (!g_ipa.indirect_rsp_context.field_is_present.transaction_id) {
    LOGE(
        "[ipa__get_bound_profile_package_response] No transactionId is present "
        "on the context, load bound profile package procedure aborted.");
    clear_indirect_rsp_context(); // Clear the RSP session context on error
    return eFatal;
  }
  if ((rc = ipa__cancel_session(
           &g_ipa.indirect_rsp_context.transaction_id, cancel_session_reason,
           &response->value.cancel_session_request_esipa)) != eOk) {
    LOGE("[ipa__get_bound_profile_package_response] Error canceling session, "
         "rc %d",
         rc);
  }
  clear_indirect_rsp_context(); // Indirect download finished, RSP session
                                // context can be cleared
  response->choice =
      CANCEL_SESSION_REQUEST_GET_BOUND_PROFILE_PACKAGE_RESULT_CHOICE;
  return rc;
}
#else
ErrCode ipa__profile_download_trigger(
    const profile_download_trigger_request_t *profile_download_trigger_request,
    profile_download_trigger_result_t *profile_download_trigger_result) {
  ErrCode rc;
  pir_t *pir_list; // SM-DS use case. For the moment there is no way to send
                   // this list back to the eIM, so this use case will sent the
                   // last PIR (if any)
  uint32_t pir_list_size;

  /* Check input parameters */
  if (!profile_download_trigger_request) {
    LOGE("[ipa__profile_download_trigger] The request pointer is null");
    return eBadArg;
  }
  if (!profile_download_trigger_result) {
    LOGE("[profile_download_trigger_result] The response pointer is null");
    return eBadArg;
  }

  /* Copy the eIM transaction Id to the response if exists in the request */
  if (profile_download_trigger_request->field_is_present.eim_transaction_id) {
    profile_download_trigger_result->field_is_present.eim_transaction_id = true;
    memcpy(&profile_download_trigger_result->eim_transaction_id,
           &profile_download_trigger_request->eim_transaction_id,
           sizeof(transaction_id_t));
  }

  if (g_ipa.emergency_profile_enabled) {
    profile_download_trigger_result->profile_download_trigger_result_data
        .choice = PROFILE_DOWNLOAD_ERROR_CHOICE;
    profile_download_trigger_result->profile_download_trigger_result_data.value
        .profile_download_error.profile_download_error_reason =
        PROFILE_DOWNLOAD_ERROR_REASON_ECALL_ACTIVE;
    profile_download_trigger_result->profile_download_trigger_result_data.value
        .profile_download_error.error_response = NULL;
    profile_download_trigger_result->profile_download_trigger_result_data.value
        .profile_download_error.error_response_size = 0;
    return eOk;
  }

  profile_download_trigger_result->profile_download_trigger_result_data.choice =
      PROFILE_INSTALLATION_RESULT_CHOICE;
  switch (profile_download_trigger_request->profile_download_data.choice) {
  case ACTIVATION_CODE_CHOICE:
    LOGI("Starting the Remote Sim Provisioning with activation code");
    rc = rsp__activation_code(
        g_ipa.es9, g_ipa.es10,
        profile_download_trigger_request->profile_download_data.data,
        profile_download_trigger_request->profile_download_data.data_len, NULL,
        0,
        &profile_download_trigger_result->profile_download_trigger_result_data
             .value.profile_installation_result);
    break;

  case CONTACT_DEFAULT_SMDP_CHOICE:
    LOGI("Starting the Remote Sim Provisioning against the default SMDP+ address");
    rc = rsp__default_smdp(
        g_ipa.es9, g_ipa.es10,
        &profile_download_trigger_result->profile_download_trigger_result_data
             .value.profile_installation_result);
#if defined(SGP32) && defined(EXTRA_FEATURE_IMMEDIATE_PROFILE_ENABLING)
    if (eOk == rc) {
      if (profile_download_trigger_result->profile_download_trigger_result_data
              .value.profile_installation_result.immediate_profile_enabled) {
        state_change_cause_t state_change_cause =
            STATE_CHANGE_CAUSE_IMMEDIATE_ENABLE_PROFILE;
        ipa__set_notify_state_change(&state_change_cause);
        LOGD("[ipa__profile_download_trigger] Immediate profile enabled");
      } else {
        LOGD("[ipa__profile_download_trigger] Immediate profile not enabled");
      }
    }
#endif
    break;

  case CONTACT_SMDS_CHOICE:
    if (profile_download_trigger_request->profile_download_data.data &&
        profile_download_trigger_request->profile_download_data.data_len > 0) {
      LOG_UTF8_DATA(
          eLogInfo,
          "Starting the Remote Sim Provisioning against the SMDS address: ",
          profile_download_trigger_request->profile_download_data.data,
          profile_download_trigger_request->profile_download_data.data_len);
      rc = ipa__rsp_custom_smds(
          profile_download_trigger_request->profile_download_data.data,
          profile_download_trigger_request->profile_download_data.data_len,
          &pir_list, &pir_list_size);
    } else {
      LOGI(
          "Starting the Remote Sim Provisioning against the root SMDS address");
      rc = rsp__root_smds(g_ipa.es9, g_ipa.es10, g_ipa.es11, &pir_list,
                          &pir_list_size);
    }
    if (eOk == rc && pir_list_size > 0) {
      LOGW("[ipa__profile_download_trigger] %u SM-DS events processed, since the PIRs of all the events can not be sent to the eIM, only the last PIR will be included on the response",
           pir_list_size);
      profile_download_trigger_result->profile_download_trigger_result_data
          .value.profile_installation_result.pir =
          pir_list[pir_list_size - 1].pir;
      profile_download_trigger_result->profile_download_trigger_result_data
          .value.profile_installation_result.pir_size =
          pir_list[pir_list_size - 1].pir_size;
      pir_list_size--; // Dirty trick to avoid free the last PIR of the list on
                       // the rsp__free_pir_list call
      rsp__free_pir_list(&pir_list, &pir_list_size);
    } else {
      rc = eFatal; // Considered as error since we can not send any PIR to the
                   // eIM
    }
    break;

  default:
    LOGE("[ipa__profile_download_trigger] ProfileDownloadData use case unknown %d",
         profile_download_trigger_request->profile_download_data.choice);
    return eBadArg;
  }

  if (rc != eOk) {
    LOGD("[ipa__profile_download_trigger] RSP with failed, rc %d", rc);
    profile_download_trigger_result->profile_download_trigger_result_data
        .choice = PROFILE_DOWNLOAD_ERROR_CHOICE;
    profile_download_trigger_result->profile_download_trigger_result_data.value
        .profile_download_error.profile_download_error_reason =
        PROFILE_DOWNLOAD_ERROR_REASON_UNDEFINED_REASON;
    /** NOTE: For the moment we don't support the errorResponse string*/
    profile_download_trigger_result->profile_download_trigger_result_data.value
        .profile_download_error.error_response = NULL;
    profile_download_trigger_result->profile_download_trigger_result_data.value
        .profile_download_error.error_response_size = 0;
  }

  return eOk;
}
#endif

ErrCode
ipa__eim_acknowledgements(eim_acknowledgements_t *eim_acknowledgements) {
  ErrCode rc;
  int err;
  uint8_t *sequence_number_tlv;
  uint32_t sequence_number_tlv_size;
  uint8_t *notification_sent_response_tlv;
  uint32_t notification_sent_response_tlv_size;
  notification_sent_request_t notification_sent_request = {0};
  notification_sent_response_t notification_sent_response = {0};

  if (!eim_acknowledgements) {
    LOGD("[ipa__eim_acknowledgements] EimAcknowledgements is null");
    return eBadArg;
  }

  if ((err = es10__init(g_ipa.es10)) < 0) {
    LOGE("[ipa__eim_acknowledgements] Error initializing the ES10, err %d",
         err);
    return eFatal;
  }

  // Iterate over the EimAcknowledgements SEQUENCE OF SequenceNumber
  while ((rc = tlv_data_extractor__asn1_list_get_next(
              &eim_acknowledgements->sequence_number_list, &sequence_number_tlv,
              &sequence_number_tlv_size)) == eOk &&
         sequence_number_tlv != NULL) {
    // Extract SequenceNumber INTEGER VALUE
    if ((rc = tlv_data_extractor__uint32(
             eim_acknowledgements->sequence_number_list.elem_tag,
             sequence_number_tlv, sequence_number_tlv_size, NULL,
             &notification_sent_request.seq_number)) == eOk) {
      LOGD("[ipa__eim_acknowledgements] Removing a notification with SequenceNumber %lu",
           notification_sent_request.seq_number);
      // Remove the notification from the UICC
      if ((err = es10__remove_notification_from_list(
               g_ipa.es10, &notification_sent_request,
               &notification_sent_response_tlv,
               &notification_sent_response_tlv_size)) < 0) {
        LOGE("[ipa__eim_acknowledgements] Error removing the notification with SequenceNumber %lu, err %d",
             notification_sent_request.seq_number, err);
      } else {
        rc = es10_tlv_extractor__notification_sent_response(
            notification_sent_response_tlv, notification_sent_response_tlv_size,
            &notification_sent_response);
        M_free(notification_sent_response_tlv);
        notification_sent_response_tlv = NULL;
        notification_sent_response_tlv_size = 0;
        if (rc == eOk) {
          ipa_display__notification_sent_response(
              notification_sent_request.seq_number,
              &notification_sent_response);
        } else {
          LOGE("[ipa__eim_acknowledgements] Error extracting the deleteNotificationStatus from the NotificationSentResponse, rc %d",
               rc);
        }
      }
    } else {
      LOGE("[ipa__eim_acknowledgements] Error extracting the SequenceNumber "
           "INTEGER VALUE, rc %d",
           rc);
    }
  }

  if ((err = es10__deinit(g_ipa.es10)) < 0) {
    LOGE("[ipa__eim_acknowledgements] eUICC__terminate failed, err %d", err);
  }

  if (rc != eOk) {
    LOGE("[ipa__eim_acknowledgements] Error iterating over the "
         "EimAcknowledgements SEQUENCE, rc %d",
         rc);
  }

  return rc;
}

#if defined(SGP32) && defined(EXTRA_FEATURE_EMERGENCY_PROFILE_MANAGMENT)
ErrCode ipa__enable_emergency_profile() {
  int err = -1;
  ErrCode rc = eFatal;
  uint8_t *response_tlv = NULL;
  uint32_t response_tlv_size = 0;
  enable_emergency_profile_request_t req = {.refresh_flag = REFRESH_FLAG};
  enable_emergency_profile_response_t rsp = {0};

  LOGI("Executing the enable emergency profile");
  if ((err = es10__init(g_ipa.es10)) < 0) {
    LOGE("[ipa__enable_emergency_profile] Error initializing the ES10, err %d",
         err);
    return eFatal;
  }

  /* Send the Enable Emergency Profile command against the UICC */
  if ((err = es10__enable_emergency_profile(g_ipa.es10, &req, &response_tlv,
                                            &response_tlv_size)) < 0) {
    LOGE("[ipa__enable_emergency_profile] ES10.EnableEmergencyProfile failed, err %d",
         err);
    goto es10_deinit_enable_emergency_profile;
  }

  /* Parse the EnableEmergencyProfileResponse */
  rc = es10_tlv_extractor__enable_emergency_profile_response(
      response_tlv, response_tlv_size, &rsp);
  M_free(response_tlv);
  response_tlv = NULL;
  response_tlv_size = 0;
  if (rc != eOk) {
    LOGE("[ipa__enable_emergency_profile] Error on parse the EnableEmergencyProfileResponse, rc %d",
         rc);
    goto es10_deinit_enable_emergency_profile;
  }

  // Print the result
  ipa_display__enable_emergency_profile_response(&rsp);

  if (ENABLE_EMERGENCY_PROFILE_RESULT_OK ==
      rsp.enable_emergency_profile_result) {
    state_change_cause_t state_change_cause =
        STATE_CHANGE_CAUSE_EMERGENCY_PROFILE;
    ipa__set_notify_state_change(&state_change_cause);
    if ((rc = ipa__update_ipa_profiles_state()) !=
        eOk) { // Update the IPA profile state
      LOGW("[ipa__enable_emergency_profile] Error updating the IPA profile state, rc %d",
           rc);
    }
    rc = eOk; // The emergency profile is enabled successfully
  } else {
    LOGE("[ipa__enable_emergency_profile] The enableEmergencyProfileResult(%d) is not ok",
         rsp.enable_emergency_profile_result);
    rc = eFatal;
  }

es10_deinit_enable_emergency_profile:
  if ((err = es10__deinit(g_ipa.es10)) < 0) {
    LOGW(
        "[ipa__enable_emergency_profile] Error deinitializing the ES10, err %d",
        err);
  }

  return rc;
}

ErrCode ipa__disable_emergency_profile() {
  int err = -1;
  ErrCode rc = eFatal;
  uint8_t *response_tlv = NULL;
  uint32_t response_tlv_size = 0;
  disable_emergency_profile_request_t req = {.refresh_flag = REFRESH_FLAG};
  disable_emergency_profile_response_t rsp = {0};

  LOGI("Executing the disable emergency profile");
  if ((err = es10__init(g_ipa.es10)) < 0) {
    LOGE("[ipa__disable_emergency_profile] Error initializing the ES10, err %d",
         err);
    return eFatal;
  }

  /* Send the disable Emergency Profile command against the UICC */
  if ((err = es10__disable_emergency_profile(g_ipa.es10, &req, &response_tlv,
                                             &response_tlv_size)) < 0) {
    LOGE("[ipa__disable_emergency_profile] ES10.DisableEmergencyProfile failed, err %d",
         err);
    goto es10_deinit_disable_emergency_profile;
  }

  /* Parse the DisableEmergencyProfileResponse */
  rc = es10_tlv_extractor__disable_emergency_profile_response(
      response_tlv, response_tlv_size, &rsp);
  M_free(response_tlv);
  response_tlv = NULL;
  response_tlv_size = 0;
  if (rc != eOk) {
    LOGE("[ipa__disable_emergency_profile] Error on parse the DisableEmergencyProfileResponse, rc %d",
         rc);
    goto es10_deinit_disable_emergency_profile;
  }

  // Print the result
  ipa_display__disable_emergency_profile_response(&rsp);

  if (DISABLE_EMERGENCY_PROFILE_RESULT_OK ==
      rsp.disable_emergency_profile_result) {
    state_change_cause_t state_change_cause =
        STATE_CHANGE_CAUSE_EMERGENCY_PROFILE;
    ipa__set_notify_state_change(&state_change_cause);
    if ((rc = ipa__update_ipa_profiles_state()) !=
        eOk) { // Update the IPA profile state
      LOGW("[ipa__disable_emergency_profile] Error updating the IPA profile state, rc %d",
           rc);
    }
    rc = eOk; // The emergency profile is disabled successfully
  } else {
    LOGE("[ipa__disable_emergency_profile] The disableEmergencyProfileResult(%d) is not ok",
         rsp.disable_emergency_profile_result);
    rc = eFatal;
  }

es10_deinit_disable_emergency_profile:
  if ((err = es10__deinit(g_ipa.es10)) < 0) {
    LOGW("[ipa__disable_emergency_profile] Error deinitializing the ES10, err %d",
         err);
  }

  return rc;
}
#endif

#if defined(SGP32) && defined(EXTRA_FEATURE_FALLBACK_MECHANISM)
ErrCode ipa__execute_fallback_mechanism() {
  int err = -1;
  ErrCode rc = eFatal;
  uint8_t *response_tlv = NULL;
  uint32_t response_tlv_size = 0;
  execute_fallback_mechanism_request_t request = {.refresh_flag = REFRESH_FLAG};
  execute_fallback_mechanism_response_t response = {0};

  LOGI("Executing the fallback mechanism");
  /* Execute the fallback mechanism against the ES10*/
  if ((err = es10__init(g_ipa.es10)) < 0) {
    LOGE(
        "[ipa__execute_fallback_mechanism] Error initializing the ES10, err %d",
        err);
    return eFatal;
  }

  /* Send the execute Fallback Mechanism command against the UICC */
  if ((err = es10__execute_fallback_mechanism(
           g_ipa.es10, &request, &response_tlv, &response_tlv_size)) < 0) {
    LOGE("[ipa__execute_fallback_mechanism] ES10.ExecuteFallbackMechanism failed, err %d",
         err);
    goto es10_deinit_execute_fallback_mechanism;
  }

  /* Parse the ExecuteFallbackMechanismResponse */
  rc = es10_tlv_extractor__execute_fallback_mechanism_response(
      response_tlv, response_tlv_size, &response);
  M_free(response_tlv);
  response_tlv = NULL;
  response_tlv_size = 0;
  if (rc != eOk) {
    LOGE("[ipa__execute_fallback_mechanism] Error on parse the ExecuteFallbackMechanismResponse, rc %d",
         rc);
    goto es10_deinit_execute_fallback_mechanism;
  }

  // Print the result
  ipa_display__execute_fallback_mechanism_response(&response);

  if (response.execute_fallback_mechanism_result ==
      EXECUTE_FALLBACK_MECHANISM_RESULT_OK) {
    state_change_cause_t state_change_cause = STATE_CHANGE_CAUSE_FALLBACK;
    ipa__set_notify_state_change(&state_change_cause);
    if ((rc = ipa__update_ipa_profiles_state()) !=
        eOk) { // Update the IPA profile state
      LOGW("[ipa__execute_fallback_mechanism] Error updating the IPA profile state, rc %d",
           rc);
    }
    rc = eOk; // The fallback mechanism is executed successfully
  } else {
    LOGE("[ipa__execute_fallback_mechanism] The executeFallbackMechanismResult(%d) is not ok",
         response.execute_fallback_mechanism_result);
    rc = eFatal;
  }

es10_deinit_execute_fallback_mechanism:
  if ((err = es10__deinit(g_ipa.es10)) < 0) {
    LOGW("[ipa__execute_fallback_mechanism] Error deinitializing the ES10, err %d",
         err);
  }

  return rc;
}

ErrCode ipa__return_from_fallback() {
  int err = -1;
  ErrCode rc = eFatal;
  uint8_t *response_tlv = NULL;
  uint32_t response_tlv_size = 0;
  return_from_fallback_request_t request = {.refresh_flag = REFRESH_FLAG};
  return_from_fallback_response_t response = {0};

  LOGI("Executing the return from fallback");
  /* Execute the return from fallback against the ES10*/
  if ((err = es10__init(g_ipa.es10)) < 0) {
    LOGE("[ipa__return_from_fallback] Error initializing the ES10, err %d",
         err);
    return eFatal;
  }

  /* Send the execute Return From Fallback command against the UICC */
  if ((err = es10__return_from_fallback(g_ipa.es10, &request, &response_tlv,
                                        &response_tlv_size)) < 0) {
    LOGE("[ipa__return_from_fallback] ES10.ReturnFromFallback failed, err %d",
         err);
    goto es10_deinit_return_from_fallback;
  }

  /* Parse the ReturnFromFallbackResponse */
  rc = es10_tlv_extractor__return_from_fallback_response(
      response_tlv, response_tlv_size, &response);
  M_free(response_tlv);
  response_tlv = NULL;
  response_tlv_size = 0;
  if (rc != eOk) {
    LOGE("[ipa__return_from_fallback] Error on parse the ReturnFromFallbackResponse, rc %d",
         rc);
    goto es10_deinit_return_from_fallback;
  }

  // Print the result
  ipa_display__return_from_fallback_response(&response);

  if (response.return_from_fallback_result == RETURN_FROM_FALLBACK_RESULT_OK) {
    state_change_cause_t state_change_cause = STATE_CHANGE_CAUSE_FALLBACK;
    ipa__set_notify_state_change(&state_change_cause);
    if ((rc = ipa__update_ipa_profiles_state()) !=
        eOk) { // Update the IPA profile state
      LOGW("[ipa__return_from_fallback] Error updating the IPA profile state, rc %d",
           rc);
    }
    rc = eOk; // The return from fallback is executed successfully
  } else {
    LOGE("[ipa__return_from_fallback] The returnFromFallbackResult(%d) is not ok",
         response.return_from_fallback_result);
    rc = eFatal;
  }

es10_deinit_return_from_fallback:
  if ((err = es10__deinit(g_ipa.es10)) < 0) {
    LOGW("[ipa__return_from_fallback] Error deinitializing the ES10, err %d",
         err);
  }

  return rc;
}
#endif

#if defined(SGP32) && defined(TEST_FEATURE_PROFILE_ROLLBACK)
void ipa__activate_profile_rollback_test_use_case() {
  g_ipa.profile_rollback_test_use_case = true;
  LOGI("Profile Rollback Test use case flag enabled");
}
#endif

#ifndef IPA_FEATURE_INDIRECT_DOWNLOAD
static ErrCode ipa__rsp_custom_smds(const uint8_t *smds_address,
                                    uint32_t smds_address_len, pir_t **pir_list,
                                    uint32_t *pir_list_size) {
  fqdn_t fqdn;
  ErrCode rc;

  if ((rc = rsp__utf8_to_fqdn(smds_address, smds_address_len, &fqdn)) != eOk) {
    LOGE("[ipa__rsp_custom_smds] Error parsing the smdsAddress to FQDN, rc %d",
         rc);
    return rc;
  }

  return rsp__smds(g_ipa.es9, g_ipa.es10, g_ipa.es11, &fqdn, pir_list,
                   pir_list_size);
}
#endif

#if defined(SGP32) && defined(TEST_FEATURE_PROFILE_ROLLBACK)
// Prerequisite: ES10 interface is already initialized
static ErrCode
ipa__execute_profile_rollback(uint8_t **euicc_package_result,
                              uint32_t *euicc_package_result_size) {
  int err = -1;
  ErrCode rc = eFatal;
  uint8_t *response_tlv = NULL;
  uint32_t response_tlv_size = 0;
  profile_rollback_request_t request = {.refresh_flag = REFRESH_FLAG};
  profile_rollback_response_t response = {0};

  LOGI("Executing the Profile Rollback Procedure");
  /* Send the Profile Rollback command against the UICC */
  if ((err = es10__profile_rollback(g_ipa.es10, &request, &response_tlv,
                                    &response_tlv_size)) < 0) {
    LOGE("[ipa__execute_profile_rollback] ES10.ProfileRollback failed, err %d",
         err);
  }

  /* Parse the ProfileRollbackResponse */
  if ((rc = es10_tlv_extractor__profile_rollback_response(
           response_tlv, response_tlv_size, &response)) != eOk) {
    LOGE("[ipa__execute_profile_rollback] Error on parse the ProfileRollbackResponse TLV, rc %d",
         rc);
    M_free(response_tlv);
    return rc;
  }

  /* Display the ProfileRollbackResponse */
  ipa_display__profile_rollback_response(&response);

  if (PROFILE_ROLLBACK_RESULT_OK == response.cmd_result) {
    /**
     * Map the ProfileRollbackResponse to the function response
     * This approach cause memory fragmentation, but as it is a test feature
     * it's okey
     */
    if (!response.euicc_package_result ||
        0 == response.euicc_package_result_size) {
      LOGE("[ipa__execute_profile_rollback] The eUICCPackageResult is empty/null while the cmdResult is ok");
      M_free(response_tlv);
      return eFatal;
    }
    *euicc_package_result = M_malloc(response.euicc_package_result_size);
    if (!(*euicc_package_result)) {
      LOGE("[ipa__execute_profile_rollback] Error allocating data to store the eUICCPackageResult");
      M_free(response_tlv);
      return eNoMem;
    }
    memcpy(*euicc_package_result, response.euicc_package_result,
           response.euicc_package_result_size);
    M_free(response_tlv); // The useful data is copied
    *euicc_package_result_size = response.euicc_package_result_size;
    return eOk; // The profile rollback is executed successfully
  } else {
    LOGW("[ipa__execute_profile_rollback] The ProfileRollbackResult(%d) is not ok",
         response.cmd_result);
    M_free(response_tlv);
    return eFatal;
  }
}

ErrCode
ipa__execute_profile_rollback_result(profile_rollback_result_t *result) {
  int err;
  ErrCode rc = eFatal;
  uint8_t *response_tlv = NULL;
  uint32_t response_tlv_size = 0;

  profile_rollback_response_t full_response;

  profile_rollback_request_t request = {.refresh_flag = REFRESH_FLAG};

  if (result == NULL) {
    LOGE("[ipa__execute_profile_rollback2] Output parameter 'result' is NULL.");
    return eBadArg;
  }

  *result = PROFILE_ROLLBACK_RESULT_UNDEFINED_ERROR;
  memset(&full_response, 0, sizeof(profile_rollback_response_t));

  LOGI("Executing the Profile Rollback Procedure");

  if ((err = es10__profile_rollback(g_ipa.es10, &request, &response_tlv,
                                    &response_tlv_size)) < 0) {
    LOGE("[ipa__execute_profile_rollback2] ES10.ProfileRollback failed, err %d",
         err);
    return eFatal;
  }

  rc = es10_tlv_extractor__profile_rollback_response(
      response_tlv, response_tlv_size, &full_response);

  if (rc != eOk) {
    LOGE("[ipa__execute_profile_rollback2] Error on parse the ProfileRollbackResponse TLV, rc %d",
         rc);
    goto cleanup_and_fail;
  }

  ipa_display__profile_rollback_response(&full_response);

  *result = full_response.cmd_result;

  if (PROFILE_ROLLBACK_RESULT_OK != *result) {
    LOGW("[ipa__execute_profile_rollback2] The ProfileRollbackResult is not OK: %d",
         *result);
  }

  LOGI("Profile rollback command executed and response parsed successfully.");

cleanup_and_fail:
  M_free(response_tlv);
  return rc;
}

#endif

void ipa__free_epr_and_notifications(
    epr_and_notifications_t *epr_and_notifications) {
  if (epr_and_notifications) {
    M_free(epr_and_notifications->euicc_package_result.tlv);
    M_free(epr_and_notifications->context_notification_list);
    memset(epr_and_notifications, 0, sizeof(epr_and_notifications_t));
  }
}

void ipa__free_ipa_euicc_data_response(
    ipa_euicc_data_response_t *ipa_euicc_data_response) {
  if (ipa_euicc_data_response) {
    if (ipa_euicc_data_response->choice == IPA_EUICC_DATA_CHOICE) {
      free_ipa_euicc_data(&ipa_euicc_data_response->value.ipa_euicc_data);
    }
    memset(ipa_euicc_data_response, 0, sizeof(ipa_euicc_data_response_t));
    /* Set default values */
    ipa_euicc_data_response->choice = IPA_EUICC_DATA_RESPONSE_ERROR_CHOICE;
    ipa_euicc_data_response->value.ipa_euicc_data_response_error
        .ipa_euicc_data_error_code = IPA_EUICC_DATA_ERROR_UNDEFINED_ERROR;
  }
}
#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
void ipa__free_initiate_authentication_response_esipa(
    initiate_authentication_response_esipa_t *obj) {
  if (obj) {
#ifdef ENABLE_HTTP_ESIPA
    M_free(obj->context);
#endif
    memset(obj, 0, sizeof(initiate_authentication_response_esipa_t));
  }
}

void ipa__free_initiate_authentication_request_esipa(
    initiate_authentication_request_esipa_t *obj) {
#ifndef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
  M_free(obj->euicc_info_1);
#endif
  memset(obj, 0, sizeof(initiate_authentication_request_esipa_t));
}

void ipa__free_authenticate_client_request_esipa(
    authenticate_client_request_esipa_t *obj) {
  M_free(obj->authenticate_server_response);
  memset(obj, 0, sizeof(authenticate_client_request_esipa_t));
}

void ipa__free_authenticate_client_response_esipa(
    authenticate_client_response_esipa_t *obj) {
  if (obj) {
#ifdef ENABLE_HTTP_ESIPA
    M_free(obj->context);
#endif
    memset(obj, 0, sizeof(authenticate_client_response_esipa_t));
  }
}

void ipa__free_get_bound_profile_package_response_esipa(
    get_bound_profile_package_response_esipa_t *obj) {
  if (obj) {
#ifdef ENABLE_HTTP_ESIPA
    M_free(obj->context);
#endif
    memset(obj, 0, sizeof(get_bound_profile_package_response_esipa_t));
  }
}

void ipa__free_cancel_session_response_esipa(
    cancel_session_response_esipa_t *obj) {
  if (obj) {
#ifdef ENABLE_HTTP_ESIPA
    M_free(obj->context);
#endif
    memset(obj, 0, sizeof(cancel_session_response_esipa_t));
  }
}

void ipa__free_cancel_session_request_esipa(
    cancel_session_request_esipa_t *obj) {
  M_free(obj->cancel_session_response);
  memset(obj, 0, sizeof(cancel_session_request_esipa_t));
}

void ipa__free_get_bound_profile_package_response_result_esipa(
    get_bound_profile_package_response_result_esipa_t *obj) {
  switch (obj->choice) {
  case CANCEL_SESSION_REQUEST_GET_BOUND_PROFILE_PACKAGE_RESULT_CHOICE:
    ipa__free_cancel_session_request_esipa(
        &obj->value.cancel_session_request_esipa);
    break;
  case HANDLE_NOTIFICATION_GET_BOUND_PROFILE_PACKAGE_RESULT_CHOICE:
    ipa__free_handle_notification_esipa(&obj->value.handle_notification_esipa);
    break;
  default:
    LOGE("[ipa__free_get_bound_profile_package_response_result_esipa] Unknown "
         "choice %d",
         obj->choice);
  }
  memset(obj, 0, sizeof(get_bound_profile_package_response_result_esipa_t));
}
void ipa__free_authenticate_client_response_result_esipa(
    authenticate_client_response_result_esipa_t *obj) {
  switch (obj->choice) {
  case PROFILE_DOWNLOAD_TRIGGER_RESPONSE_RESULT_CHOICE:
    ipa__free_profile_download_trigger_response_result(
        &obj->value.profile_download_trigger_response_result);
    break;
  case OK_AUTHENTICATE_CLIENT_RESULT_CHOICE:
    break;
  case GET_BOUND_PROFILE_PACKAGE_AUTHENTICATE_CLIENT_RESULT_CHOICE:
    ipa__free_get_bound_profile_package_request_esipa(
        &obj->value.get_bound_profile_package_request_esipa);
    break;
  case CANCEL_SESSION_REQUEST_AUTHENTICATE_CLIENT_RESULT_CHOICE:
    ipa__free_cancel_session_request_esipa(
        &obj->value.cancel_session_request_esipa);
    break;
  default:
    LOGE("[ipa__free_authenticate_client_response_result_esipa] Unknown choice %d",
         obj->choice);
  }
  memset(obj, 0, sizeof(authenticate_client_response_result_esipa_t));
}

void ipa__free_profile_download_trigger_response_result(
    profile_download_trigger_response_result_t *obj) {
  if (obj) {
    switch (obj->choice) {
    case PROFILE_DOWNLOAD_TRIGGER_RESULT_CHOICE:
      ipa__free_profile_download_trigger_result(
          &obj->value.profile_download_trigger_result);
      break;
    case INITIATE_AUTHENTICATION_REQUEST_ESIPA_CHOICE:
      ipa__free_initiate_authentication_request_esipa(
          &obj->value.initiate_authentication_request_esipa);
      break;
    default:
      LOGE("[ipa__free_profile_download_trigger_response_result] Unknown CHOICE %d",
           obj->choice);
      break;
    }
    memset(obj, 0, sizeof(profile_download_trigger_response_result_t));
  }
}
#endif
void ipa__free_profile_download_trigger_result(
    profile_download_trigger_result_t *profile_download_trigger_result) {
  if (profile_download_trigger_result->profile_download_trigger_result_data
          .choice == PROFILE_INSTALLATION_RESULT_CHOICE) {
    rsp__free_pir(
        &profile_download_trigger_result->profile_download_trigger_result_data
             .value.profile_installation_result);
  }
  if (profile_download_trigger_result->profile_download_trigger_result_data
          .choice == PROFILE_DOWNLOAD_ERROR_CHOICE) {
    M_free(profile_download_trigger_result->profile_download_trigger_result_data
               .value.profile_download_error.error_response);
  }
  /* Set default values */
  profile_download_trigger_result->profile_download_trigger_result_data.choice =
      PROFILE_DOWNLOAD_ERROR_CHOICE;
  profile_download_trigger_result->profile_download_trigger_result_data.value
      .profile_download_error.profile_download_error_reason =
      PROFILE_DOWNLOAD_ERROR_REASON_UNDEFINED_REASON;
  profile_download_trigger_result->profile_download_trigger_result_data.value
      .profile_download_error.error_response = NULL;
  profile_download_trigger_result->profile_download_trigger_result_data.value
      .profile_download_error.error_response_size = 0;
}

static void ipa__get_notification_list(
    const uint8_t *retrieve_notifications_list_response,
    const uint32_t retrieve_notifications_list_response_size,
    uint8_t **notification_list, uint32_t *notification_list_size) {
  ErrCode rc = eFatal;
  retrieve_notifications_list_response_t obj = {0};
  bool empty_list = true;

  // Initialize the response
  *notification_list = NULL;
  *notification_list_size = 0;

  // Parse the RetrieveNotificationsListResponse
  if ((rc = es10_tlv_extractor__retrieve_notifications_list_response(
           retrieve_notifications_list_response,
           retrieve_notifications_list_response_size, &obj)) != eOk) {
    LOGW("[ipa__get_notification_list] Error on parse the RetrieveNotificationsListResponse, rc %d",
         rc);
    return;
  }

  // Check that the RetrieveNotificationsListResponse choice is notificationList
  if (NOTIFICATIONS_LIST_CHOICE != obj.choice) {
    LOGD("[ipa__get_notification_list] The RetrieveNotificationsListResponse choice is not notificationList, choice %d",
         obj.choice);
    return;
  }

  // Check if the notificationList is empty or not
  if ((rc = tlv_data_extractor__asn1_list_is_empty(&obj.value.notification_list,
                                                   &empty_list)) != eOk) {
    LOGD("[ipa__get_notification_list] Error on check if the notificationList is empty or not, rc %d",
         rc);
    return;
  }

  if (!empty_list) {
    LOGD("[ipa__get_notification_list] The notificationList is not empty");
    *notification_list = obj.value.notification_list.asn1_list_tlv;
    *notification_list_size = obj.value.notification_list.asn1_list_tlv_size;
  } else {
    LOGD("[ipa__get_notification_list] The notificationList is empty");
  }
}

void ipa__free_pkid_list(ipa_pkid_list_t *pkid_list) {
  if (pkid_list && pkid_list->items) {
    for (uint32_t i = 0; i < pkid_list->count; ++i) {
      M_free(pkid_list->items[i].pkid);
    }
    M_free(pkid_list->items);
    pkid_list->items = NULL;
    pkid_list->count = 0;
  }
}

ErrCode ipa__get_euicc_info_1(ipa_euicc_info1_t *out_data) {
  ErrCode rc = eFatal;
  int err;
  uint8_t *raw_tlv_buffer = NULL;
  uint32_t raw_tlv_size = 0;

  if (out_data == NULL) {
    LOGE("[ipa__get_euicc_info_1] Output parameter is NULL.");
    return eBadArg;
  }

  if ((err = es10__init(g_ipa.es10)) < 0) {
    LOGE("[ipa__get_euicc_info_1] Failed to initialize ES10, err %d", err);
    return eFatal;
  }

  if ((err = es10__get_euicc_info_1(g_ipa.es10, &raw_tlv_buffer,
                                    &raw_tlv_size)) < 0) {
    LOGE("[ipa__get_euicc_info_1] ES10.get_euicc_info_1 failed, err %d", err);
    rc = eFatal;
    goto deinit_es10;
  }

  LOG_DATA(eLogDebug, "Fetched raw euiccInfo1 TLV", raw_tlv_buffer,
           raw_tlv_size);

  rc = ipa__parse_euicc_info_1_tlv(raw_tlv_buffer, raw_tlv_size, out_data);
  if (rc != eOk) {
    LOGE("[ipa__get_euicc_info_1] Failed to parse the fetched euiccInfo1 TLV, rc %d",
         rc);
    goto free_raw_and_deinit;
  }

  LOGI("[ipa__get_euicc_info_1] Successfully fetched and parsed euiccInfo1.");

free_raw_and_deinit:
  M_free(raw_tlv_buffer);

deinit_es10:
  if ((err = es10__deinit(g_ipa.es10)) < 0) {
    LOGE("[ipa__get_euicc_info_1] Failed to deinitialize ES10, err %d", err);
    if (rc == eOk) {
      ipa__free_euicc_info1_data(out_data);
      rc = eFatal;
    }
  }

  return rc;
}

ErrCode ipa__get_euicc_info_2(ipa_euicc_info2_t *out_data) {
  ErrCode rc = eFatal;
  int err;
  uint8_t *raw_tlv_buffer = NULL;
  uint32_t raw_tlv_size = 0;

  if (out_data == NULL) {
    LOGE("[ipa__get_euicc_info_2] Output parameter is NULL.");
    return eBadArg;
  }

  if ((err = es10__init(g_ipa.es10)) < 0) {
    LOGE("[ipa__get_euicc_info_2] Failed to initialize ES10, err %d", err);
    return eFatal;
  }

  if ((err = es10__get_euicc_info_2(g_ipa.es10, &raw_tlv_buffer,
                                    &raw_tlv_size)) < 0) {
    LOGE("[ipa__get_euicc_info_2] ES10.get_euicc_info_2 failed, err %d", err);
    rc = eFatal;
    goto deinit_es10;
  }

  rc = ipa__parse_euicc_info2_tlv(raw_tlv_buffer, raw_tlv_size, out_data);
  M_free(raw_tlv_buffer);
  raw_tlv_buffer = NULL;
  if (rc != eOk) {
    LOGE("[ipa__get_euicc_info_2] Failed to parse euiccInfo2 TLV, rc %d", rc);
  }

deinit_es10:
  if ((err = es10__deinit(g_ipa.es10)) < 0) {
    LOGE("[ipa__get_euicc_info_2] Failed to deinitialize ES10, err %d", err);
    if (rc == eOk) {
      /* If main logic was OK but deinit failed, it's a failure overall */
      ipa__free_euicc_info2_data(out_data);
      rc = eFatal;
    }
  }
  return rc;
}

static ErrCode
ipa__parse_ext_card_resources(const uint8_t *tlv_data, uint32_t tlv_size,
                              ipa_ext_card_resources_t *out_res) {
  ErrCode rc;
  _BerTlv sub_tlv;
  uint32_t offset = 0;
  bool tag81_found = false;
  bool tag82_found = false;
  bool tag83_found = false;

  if (tlv_data == NULL || out_res == NULL) {
    return eBadArg;
  }

  while (offset < tlv_size) {
    if ((rc = ber_tlv_parser__ber_tlv_2(tlv_data, tlv_size, offset,
                                        &sub_tlv)) != eOk) {
      LOGE("[ipa__parse_ext_card_resources] Failed to parse sub-TLV at offset "
           "%u.",
           offset);
      return rc;
    }

    const uint8_t *sub_value_ptr =
        tlv_data + offset + sub_tlv.nTag + sub_tlv.nLength;
    int32_t int_value = 0;

    if ((rc = tlv_data_extractor__ber_tlv_to_int(sub_value_ptr, sub_tlv.length,
                                                 &int_value)) != eOk) {
      LOGE("[ipa__parse_ext_card_resources] Failed to convert TLV value to integer for tag 0x%X.",
           sub_tlv.tag);
      return rc;
    }

    switch (sub_tlv.tag) {
    case CONTEXT_PRIMITIVE_1: // Number of installed applications
      out_res->installed_app_number = int_value;
      tag81_found = true;
      break;

    case CONTEXT_PRIMITIVE_2: // Free non-volatile memory
      out_res->free_non_volatile_mem = int_value;
      tag82_found = true;
      break;

    case CONTEXT_PRIMITIVE_3: // Free volatile memory
      out_res->free_volatile_mem = int_value;
      tag83_found = true;
      break;

    default:
      LOGW("[ipa__parse_ext_card_resources] Ignoring unexpected tag 0x%X "
           "inside ExtCardResources.",
           sub_tlv.tag);
      break;
    }

    offset += sub_tlv.nTag + sub_tlv.nLength + sub_tlv.length;
  }

  if (!tag81_found || !tag82_found || !tag83_found) {
    LOGE("[ipa__parse_ext_card_resources] Missing one or more required fields inside ExtCardResources.");
    return eNotEnoughBuffer;
  }

  return eOk;
}

static ErrCode ipa__parse_euicc_info2_tlv(const uint8_t *tlv_buffer,
                                          uint32_t buffer_size,
                                          ipa_euicc_info2_t *data) {
  ErrCode rc = eFatal;
  _BerTlv root_tlv, sub_tlv;
  uint32_t offset = 0;
  const uint8_t *root_value_ptr = NULL;

  if ((rc = ber_tlv_parser__ber_tlv_2(tlv_buffer, buffer_size, 0, &root_tlv)) !=
      eOk) {
    LOGE("[ipa__parse_euicc_info2_tlv] Failed to parse root TLV.");
    return rc;
  }

  if (root_tlv.tag != EUICC_INFO_2) {
    LOGW("[ipa__parse_euicc_info2_tlv] Root TLV tag is 0x%X, not 0xBF22.",
         root_tlv.tag);
  }

  if (data == NULL) {
    return eBadArg;
  }

  root_value_ptr = tlv_buffer + root_tlv.nTag + root_tlv.nLength;

  while (offset < root_tlv.length) {
    rc = ber_tlv_parser__ber_tlv_2(root_value_ptr, root_tlv.length, offset,
                                   &sub_tlv);
    if (rc != eOk) {
      break;
    }

    const uint8_t *sub_value_ptr =
        root_value_ptr + offset + sub_tlv.nTag + sub_tlv.nLength;

    rc = eOk;
    switch (sub_tlv.tag) {
    case CONTEXT_PRIMITIVE_1: // profileVersion
      rc = ipa__parse_version_type(sub_value_ptr, sub_tlv.length,
                                   &data->profile_version);
      break;

    case CONTEXT_PRIMITIVE_2: // svn
      rc = ipa__parse_version_type(sub_value_ptr, sub_tlv.length, &data->svn);
      break;

    case CONTEXT_PRIMITIVE_3: // euiccFirmwareVer
      rc = ipa__parse_version_type(sub_value_ptr, sub_tlv.length,
                                   &data->euicc_firmware_ver);
      break;

    case EXT_CARD_RES: // extCardResource
      rc = ipa__parse_ext_card_resources(sub_value_ptr, sub_tlv.length,
                                         &data->ext_card_res_info);
      break;

    case UICC_CAPABILITY: // uiccCapability
      if (byte_utils__bit_string_decode(data->uicc_capability_mask,
                                        sizeof(data->uicc_capability_mask),
                                        sub_value_ptr, sub_tlv.length) < 0) {
        rc = eFatal;
      }
      break;

    case JAVACARD_VER: // javacardVersion
      rc = ipa__parse_version_type(sub_value_ptr, sub_tlv.length,
                                   &data->javacard_version);
      break;

    case GP_VERSION: // globalplatformVersion
      rc = ipa__parse_version_type(sub_value_ptr, sub_tlv.length,
                                   &data->globalplatform_version);
      break;

    case RSP_CAPABILITY: // rspCapability
      if (byte_utils__bit_string_decode(data->rsp_capability_mask,
                                        sizeof(data->rsp_capability_mask),
                                        sub_value_ptr, sub_tlv.length) < 0) {
        rc = eFatal;
      }
      break;

    case CIPKID_LIST_FOR_VERIFICATION: // euiccCiPKIdListForVerification
      rc = ipa__parse_pkid_list(
          sub_value_ptr, sub_tlv.length,
          &data->ipa_pkid_list_data.ci_pkid_list_for_verification);
      break;

    case CIPKID_LIST_FOR_SIGNING: // euiccCiPKIdListForSigning
      rc = ipa__parse_pkid_list(
          sub_value_ptr, sub_tlv.length,
          &data->ipa_pkid_list_data.ci_pkid_list_for_signing);
      break;

    case EUICC_CATEGORY: // euiccCategory
      if (sub_tlv.length > 0)
        data->euicc_category = (ipa_euicc_category_t)sub_value_ptr[0];
      data->euicc_category_present = true;
      break;

    case FORBIDDEN_PPRS: // forbiddenProfilePolicyRules
      if (sub_tlv.length > 0) {
        data->forbidden_pprs = (uint8_t *)M_malloc(sub_tlv.length);
        if (!data->forbidden_pprs) {
          LOGE("[ipa__parse_euicc_info2_tlv] Failed to allocate memory for forbiddenPprs.");
          rc = eNoMem;
        } else {
          memcpy(data->forbidden_pprs, sub_value_ptr, sub_tlv.length);
          data->forbidden_pprs_present = true;
        }
      } else {
        data->forbidden_pprs_present = false;
      }
      break;

    case ASN1_DER_OCTET_STRING: // ppVersion
      rc = ipa__parse_version_type(sub_value_ptr, sub_tlv.length,
                                   &data->pp_version);
      break;

    case ASN1_DER_UTF8_STRING: // sasAcreditationNumber
      data->sas_acreditation_number = (char *)M_malloc(sub_tlv.length + 1);
      if (!data->sas_acreditation_number) {
        rc = eNoMem;
      } else {
        memcpy(data->sas_acreditation_number, sub_value_ptr, sub_tlv.length);
        data->sas_acreditation_number[sub_tlv.length] = '\0';
      }
      break;

    default:

      break;
    }

    if (rc != eOk) {
      break;
    }

    offset += sub_tlv.nTag + sub_tlv.nLength + sub_tlv.length;
  }

  if (rc != eOk) {
    ipa__free_euicc_info2_data(data);
  }

  return rc;
}

void ipa__free_euicc_info2_data(ipa_euicc_info2_t *data) {
  if (data == NULL) {
    return;
  }
  M_free(data->profile_version);
  M_free(data->svn);
  M_free(data->euicc_firmware_ver);
  M_free(data->pp_version);
  M_free(data->sas_acreditation_number);
  M_free(data->javacard_version);
  M_free(data->globalplatform_version);

  M_free(data->forbidden_pprs);

  ipa__free_pkid_list(&data->ipa_pkid_list_data.ci_pkid_list_for_verification);
  ipa__free_pkid_list(&data->ipa_pkid_list_data.ci_pkid_list_for_signing);
}

static ErrCode ipa__parse_version_type(const uint8_t *value_ptr,
                                       uint32_t length,
                                       char **out_version_str) {
  if (value_ptr == NULL || out_version_str == NULL) {
    return eBadArg;
  }
  *out_version_str = NULL;

  if (length < 3) {
    LOGE("[ipa__parse_version_type] Invalid VersionType data: length is %u, expected at least 3.",
         length);
    return eFatal;
  }

  int required_size =
      snprintf(NULL, 0, "%u.%u.%u", value_ptr[0], value_ptr[1], value_ptr[2]);
  if (required_size < 0) {
    LOGE("[ipa__parse_version_type] Failed to calculate required string size.");
    return eFatal;
  }

  *out_version_str = (char *)M_malloc(required_size + 1);
  if (*out_version_str == NULL) {
    LOGE("[ipa__parse_version_type] Failed to allocate memory for version string.");
    return eNoMem;
  }

  int written_size = snprintf(*out_version_str, required_size + 1, "%u.%u.%u",
                              value_ptr[0], value_ptr[1], value_ptr[2]);
  if (written_size != required_size) {
    LOGE(
        "[ipa__parse_version_type] Failed to format version string correctly.");
    M_free(*out_version_str);
    *out_version_str = NULL;
    return eFatal;
  }

  return eOk;
}

static ErrCode ipa__parse_euicc_info_1_tlv(const uint8_t *euicc_info_tlv,
                                           uint32_t euicc_info_tlv_size,
                                           ipa_euicc_info1_t *out_data) {
  ErrCode rc = eFatal;
  _BerTlv root_tlv;
  _BerTlv sub_tlv;
  uint32_t offset_in_value = 0;
  const uint8_t *root_tlv_value_ptr = NULL;

  if (euicc_info_tlv == NULL || euicc_info_tlv_size == 0 || out_data == NULL) {
    LOGE("[ipa__parse_euicc_info_1_tlv] Invalid input parameters.");
    return eBadArg;
  }

  if ((rc = ber_tlv_parser__ber_tlv_2(euicc_info_tlv, euicc_info_tlv_size, 0,
                                      &root_tlv)) != eOk) {
    LOGE("[ipa__parse_euicc_info_1_tlv] Failed to parse root TLV.");
    return rc;
  }

  if (root_tlv.tag != EUICC_INFO_1) {
    LOGW("[ipa__parse_euicc_info_1_tlv] Warning: Root TLV tag is 0x%X, not the expected euiccInfo1 tag (0x%X).",
         root_tlv.tag, EUICC_INFO_1);
  }

  memset(out_data, 0, sizeof(ipa_euicc_info1_t));

  out_data->raw = (uint8_t *)M_malloc(euicc_info_tlv_size);
  if (out_data->raw == NULL) {
    rc = eNoMem;
    goto cleanup_and_exit;
  }
  memcpy(out_data->raw, euicc_info_tlv, euicc_info_tlv_size);
  out_data->raw_size = euicc_info_tlv_size;

  root_tlv_value_ptr = euicc_info_tlv + root_tlv.nTag + root_tlv.nLength;

  while (offset_in_value < root_tlv.length) {
    if ((rc = ber_tlv_parser__ber_tlv_2(root_tlv_value_ptr, root_tlv.length,
                                        offset_in_value, &sub_tlv)) != eOk) {
      goto cleanup_and_exit;
    }

    const uint8_t *sub_tlv_value_ptr =
        root_tlv_value_ptr + offset_in_value + sub_tlv.nTag + sub_tlv.nLength;

    switch (sub_tlv.tag) {
    case CONTEXT_PRIMITIVE_2:
      out_data->svn = (uint8_t *)M_malloc(sub_tlv.length);
      if (out_data->svn == NULL) {
        rc = eNoMem;
        goto cleanup_and_exit;
      }
      memcpy(out_data->svn, sub_tlv_value_ptr, sub_tlv.length);
      out_data->svn_size = sub_tlv.length;
      out_data->svn_present = true;
      break;
    case CIPKID_LIST_FOR_VERIFICATION:
      if ((rc = ipa__parse_pkid_list(
               sub_tlv_value_ptr, sub_tlv.length,
               &out_data->ci_pkid_list_for_verification)) != eOk) {
        goto cleanup_and_exit;
      }
      out_data->verification_list_present = true;
      break;
    case CIPKID_LIST_FOR_SIGNING:
      if ((rc = ipa__parse_pkid_list(sub_tlv_value_ptr, sub_tlv.length,
                                     &out_data->ci_pkid_list_for_signing)) !=
          eOk) {
        goto cleanup_and_exit;
      }
      out_data->signing_list_present = true;
      break;
    }
    offset_in_value += sub_tlv.nTag + sub_tlv.nLength + sub_tlv.length;
  }
  rc = eOk;

cleanup_and_exit:
  if (rc != eOk) {
    ipa__free_euicc_info1_data(out_data);
  }
  return rc;
}

void ipa__free_euicc_info1_data(ipa_euicc_info1_t *data) {
  if (data == NULL) {
    return;
  }

  M_free(data->raw);
  M_free(data->svn);

  if (data->ci_pkid_list_for_verification.items != NULL) {
    for (uint32_t i = 0; i < data->ci_pkid_list_for_verification.count; i++) {
      M_free(data->ci_pkid_list_for_verification.items[i].pkid);
    }
    M_free(data->ci_pkid_list_for_verification.items);
  }

  if (data->ci_pkid_list_for_signing.items != NULL) {
    for (uint32_t i = 0; i < data->ci_pkid_list_for_signing.count; i++) {
      M_free(data->ci_pkid_list_for_signing.items[i].pkid);
    }
    M_free(data->ci_pkid_list_for_signing.items);
  }
}

static ErrCode ipa__parse_pkid_list(const uint8_t *tlv_data, uint32_t tlv_size,
                                    ipa_pkid_list_t *pkid_list) {
  ErrCode rc;
  _BerTlv pkid_item_tlv;
  uint32_t offset = 0;
  uint32_t count = 0;

  if (tlv_data == NULL || pkid_list == NULL) {
    return eBadArg;
  }

  if (pkid_list->items != NULL) {
    ipa__free_pkid_list(pkid_list);
  }

  pkid_list->items = NULL;
  pkid_list->count = 0;

  if (tlv_size == 0) {
    return eOk;
  }
  while (offset < tlv_size) {
    if ((rc = ber_tlv_parser__ber_tlv_2(tlv_data, tlv_size, offset,&pkid_item_tlv)) != eOk) {
      LOGE("[ipa__parse_pkid_list] Failed to parse sub-item TLV for counting at offset %u",offset);
      return rc;
    }
    count++;
    offset += pkid_item_tlv.nTag + pkid_item_tlv.nLength + pkid_item_tlv.length;
  }

  if (count == 0) {
    return eOk;
  }

  pkid_list->items = (ipa_pkid_t *)M_malloc(sizeof(ipa_pkid_t) * count);
  if (pkid_list->items == NULL) {
    LOGE("[ipa__parse_pkid_list] Failed to allocate memory for %u pkid list "
         "items.",
         count);
    return eNoMem;
  }
  memset(pkid_list->items, 0, sizeof(ipa_pkid_t) * count);
  pkid_list->count = count;

  offset = 0;
  for (uint32_t i = 0; i < count; i++) {
    ber_tlv_parser__ber_tlv_2(tlv_data, tlv_size, offset, &pkid_item_tlv);

    const uint8_t *value_start =
        tlv_data + offset + pkid_item_tlv.nTag + pkid_item_tlv.nLength;

    pkid_list->items[i].pkid = (uint8_t *)M_malloc(pkid_item_tlv.length);
    if (pkid_list->items[i].pkid == NULL) {
      LOGE("[ipa__parse_pkid_list] Failed to allocate memory for pkid value at "
           "index %u.",
           i);
      return eNoMem;
    }

    memcpy(pkid_list->items[i].pkid, value_start, pkid_item_tlv.length);
    pkid_list->items[i].pkid_size = pkid_item_tlv.length;

    offset += pkid_item_tlv.nTag + pkid_item_tlv.nLength + pkid_item_tlv.length;
  }

  return eOk;
}

ErrCode ipa__euicc_data(const ipa_euicc_data_request_t *request,
                        euicc_data_t *response) {
  int err;
  retrieve_notifications_list_request_t retrieve_notifications_list_request = {
      .field_is_present = {.search_criteria = false}};
#ifdef SGP32
  retrieve_notifications_list_request_t retrieve_euicc_packages_list_request = {
      .field_is_present = {.search_criteria = true},
      .search_criteria = {.choice = EUICC_PACKAGE_RESULTS_CHOICE}};
  get_certs_request_t get_certs_request = {
      .field_is_present = {.euicc_ci_pk_id = false}};
  get_eim_configuration_data_request_t get_eim_configuration_data_request = {
      .field_is_present = {.search_criteria = false}};
#endif

  /* Check input parameters */
  if (!request) {
    LOGE("[ipa__euicc_data] The request pointer is null");
    return eBadArg;
  }
  if (!response) {
    LOGE("[ipa__euicc_data] The response pointer is null");
    return eBadArg;
  }

  memset(response, 0, sizeof(euicc_data_t));

  /* Check if there is eUICC data to retrieve */
  if (!request->tag_list.notifications_list &&
      !request->tag_list.default_smdp &&
      !request->tag_list.euicc_package_results &&
      !request->tag_list.euicc_info_1 && !request->tag_list.euicc_info_2 &&
      !request->tag_list.association_token && !request->tag_list.eum_cert &&
      !request->tag_list.euicc_cert) {
    LOGD("[ipa__euicc_data] No eUICC data requested");
    return eOk;
  }

  /* Apply the searchCriteriaNotification filter if present */
  if (request->field_is_present.search_criteria_notification) {
    retrieve_notifications_list_request.field_is_present.search_criteria = true;
    switch (request->search_criteria_notification.choice) {
    case ESIPA_NOTIFICATION_SEQ_NUMBER_CHOICE:
      retrieve_notifications_list_request.search_criteria.choice =
          SEQ_NUMBER_CHOICE;
      retrieve_notifications_list_request.search_criteria.value.seq_number =
          request->search_criteria_notification.value.seq_number;
      break;
    case ESIPA_NOTIFICATION_PROFILE_MANAGEMENT_OPERATION_CHOICE:
      retrieve_notifications_list_request.search_criteria.choice =
          PROFILE_MANAGEMENT_OPERATION_CHOICE;
      retrieve_notifications_list_request.search_criteria.value
          .profile_management_operation =
          request->search_criteria_notification.value.seq_number;
      break;
    default:
      LOGE("[ipa__euicc_data] Unknown searchCriteriaNotification CHOICE %d",
           request->search_criteria_notification.choice);
      return eBadArg;
    }
  }
#ifdef SGP32
  /* Apply the searchCriteriaEuiccPackageResult filter if present */
  if (request->field_is_present.search_criteria_euicc_package_result) {
    retrieve_euicc_packages_list_request.field_is_present.search_criteria =
        true;
    switch (request->search_criteria_euicc_package_result.choice) {
    case ESIPA_EUICC_PACKAGE_RESULT_SEQ_NUMBER_CHOICE:
      retrieve_euicc_packages_list_request.search_criteria.choice =
          SEQ_NUMBER_CHOICE;
      retrieve_euicc_packages_list_request.search_criteria.value.seq_number =
          request->search_criteria_euicc_package_result.value.seq_number;
      break;
    default:
      LOGE("[ipa__euicc_data] Unknown searchCriteriaEuiccPackageResult CHOICE "
           "%d",
           request->search_criteria_euicc_package_result.choice);
      return eBadArg;
    }
  }
#endif

  /* Initialize the ES10 interface */
  if ((err = es10__init(g_ipa.es10)) < 0) {
    LOGE("[ipa__euicc_data] Error initializing the ES10, err %d", err);
    return eFatal;
  }

  /* Retrieve GetEUICCInfo */
  if (request->tag_list.euicc_info_2) {
    if ((err = es10__get_euicc_info_2(g_ipa.es10, &response->euicc_info_2,
                                      &response->euicc_info_2_size)) < 0) {
      LOGE("[ipa__euicc_data] ES10.GetEUICCInfo(2) failed, err %d", err);
      response->euicc_info_2 = NULL;
      goto euicc_data_deinit_es10;
    }
  }
#ifdef SGP32
#ifdef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
  // Just before the GetCerts to use less memory in case we have a truncated
  // euiccCiPKId
  if (request->tag_list.euicc_info_1 ||
      (request->field_is_present.euicc_ci_pk_id &&
       (request->tag_list.eum_cert || request->tag_list.euicc_cert))) {
#else
  if (request->tag_list.euicc_info_1) {
#endif
    if ((err = es10__get_euicc_info_1(g_ipa.es10, &response->euicc_info_1,
                                      &response->euicc_info_1_size)) < 0) {
      LOGE("[ipa__euicc_data] ES10.GetEUICCInfo(1) failed, err %d", err);
      response->euicc_info_1 = NULL;
      goto euicc_data_deinit_es10;
    }
  }
#endif

  /* Retrieve GetCerts */
  if (request->tag_list.eum_cert || request->tag_list.euicc_cert) {
#ifdef SGP32
    /* Apply the euiccCiPKIdentifierToBeUsed filter if present */
    if (request->field_is_present.euicc_ci_pk_id) {
      get_certs_request.field_is_present.euicc_ci_pk_id = true;
#ifdef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
      ErrCode rc;
      if ((rc = ipa__reconstruct_truncated_euicc_ci_pk_id(
               response->euicc_info_1, response->euicc_info_1_size,
               &request->euicc_ci_pk_id_to_be_used.subject_key_identifier,
               &get_certs_request.euicc_ci_pk_id)) != eOk) {
        LOGE("[ipa__euicc_data] Error on reconstruct the truncated "
             "euiccCiPKId, rc %d",
             rc);
        err = -ECANCELED;
        goto euicc_data_deinit_es10;
      }
      // Free it in case is not requested by the eIM
      if (!request->tag_list.euicc_info_1) {
        M_free(response->euicc_info_1);
        response->euicc_info_1 = NULL;
        response->euicc_info_1_size = 0;
      }
#else
      memcpy(&get_certs_request.euicc_ci_pk_id,
             &request->euicc_ci_pk_id_to_be_used.subject_key_identifier,
             sizeof(subject_key_identifier_t));
#endif // IPA_FEATURE_MINIMIZE_ESIPA_BYTES
    }
    if ((err = es10__get_certs(g_ipa.es10, &get_certs_request,
                               &response->get_certs_response,
                               &response->get_certs_response_size)) < 0) {
      LOGE("[ipa__euicc_data] ES10.GetCerts failed, err %d", err);
      response->get_certs_response = NULL;
      goto euicc_data_deinit_es10;
    }
#else // SGP32
    LOGW("[ipa__euicc_data] An IPA without an eUICC SGP32 cannot retrieve the "
         "eUICC/EUM certificates.");
#endif
  }

  /* Retrieve RetrieveNotificationsList */
  if (request->tag_list.notifications_list) {
    if ((err = es10__retrieve_notifications_list(
             g_ipa.es10, &retrieve_notifications_list_request,
             &response->retrieve_notifications_list_response,
             &response->retrieve_notifications_list_response_size)) < 0) {
      LOGE("[ipa__euicc_data] "
           "ES10.RetrieveNotificationsList(notificationsList) failed, err %d",
           err);
      response->retrieve_notifications_list_response = NULL;
      goto euicc_data_deinit_es10;
    }
  }
  if (request->tag_list.euicc_package_results) {
#ifdef SGP32
    if ((err = es10__retrieve_notifications_list(
             g_ipa.es10, &retrieve_euicc_packages_list_request,
             &response->retrieve_euicc_packages_list_response,
             &response->retrieve_euicc_packages_list_response_size)) < 0) {
      LOGE("[ipa__euicc_data] "
           "ES10.RetrieveNotificationsList(euiccPackageResultList) failed, err "
           "%d",
           err);
      response->retrieve_euicc_packages_list_response = NULL;
      goto euicc_data_deinit_es10;
    }
#else
    LOGW("[ipa__euicc_data] An IPA without an eUICC SGP32 cannot retrieve the "
         "eUICC Package results.");
#endif // SGP32
  }
  /* Retrieve GetEuiccConfiguredAddresses */
  if (request->tag_list.default_smdp || request->tag_list.root_smds) {
    if ((err = es10__get_euicc_configured_addresses(
             g_ipa.es10, &response->euicc_configured_addresses_response,
             &response->euicc_configured_addresses_response_size)) < 0) {
      LOGE("[ipa__euicc_data] ES10.GetEuiccConfiguredAddresses failed, err %d",
           err);
      response->euicc_configured_addresses_response = NULL;
      goto euicc_data_deinit_es10;
    }
  }

  /* Retrieve GetEimConfigurationData */
  if (request->tag_list.association_token) {
#ifdef SGP32
    if ((err = es10__get_eim_configuration_data(
             g_ipa.es10, &get_eim_configuration_data_request,
             &response->get_eim_configuration_data_response,
             &response->get_eim_configuration_data_response_size)) < 0) {
      LOGE("[ipa__get_bound_profile_package_response] "
           "ES10.GetEimConfigurationData failed, err %d",
           err);
      response->get_eim_configuration_data_response = NULL;
      goto euicc_data_deinit_es10;
    }
#else
    LOGW("[ipa__euicc_data] An IPA without an eUICC SGP32 cannot retrieve the "
         "associationToken.");
#endif // SGP32
  }

euicc_data_deinit_es10:
  if (es10__deinit(g_ipa.es10) < 0) {
    LOGE("[ipa__euicc_data] Error deinitializing the ES10");
  }

  if (err < 0) {
    LOGE("[ipa__euicc_data] Error retriving data from the UICC, err %d", err);
    free_euicc_data(response);
    return eFatal;
  }

  return eOk;
}

#ifdef SGP32
static ErrCode ipa__ipa_euicc_data_response_set_certificates(
    const ipa_euicc_data_request_t *request, euicc_data_t *euicc_data,
    ipa_euicc_data_response_t *response) {
  ErrCode rc;
  get_certs_response_t get_certs_response = {0};

  if (!request) {
    LOGE("[ipa__ipa_euicc_data_response_set_certificates] IpaEuiccDataRequest "
         "object is null");
    return eBadArg;
  }
  if (!response) {
    LOGE("[ipa__ipa_euicc_data_response_set_certificates] IpaEuiccDataResponse "
         "object is null");
    return eBadArg;
  }

  // Set default response
  response->value.ipa_euicc_data.field_is_present.eum_cert = false;
  response->value.ipa_euicc_data.field_is_present.euicc_cert = false;

  if (!request->tag_list.eum_cert && !request->tag_list.euicc_cert) {
    LOGD("[ipa__ipa_euicc_data_response_set_certificates] No certificates "
         "needs to be added");
    return eOk;
  }

  if (!euicc_data) {
    LOGW("[ipa__ipa_euicc_data_response_set_certificates] eUICC data object is "
         "null");
    return ipa__set_ipa_euicc_data_response_error(
        request, IPA_EUICC_DATA_ERROR_UNDEFINED_ERROR, response);
  }

  if (!euicc_data->get_certs_response ||
      0 == euicc_data->get_certs_response_size) {
    LOGW("[ipa__ipa_euicc_data_response_set_certificates] GetCertsResponse tlv "
         "is empty/null");
    return ipa__set_ipa_euicc_data_response_error(
        request, IPA_EUICC_DATA_ERROR_UNDEFINED_ERROR, response);
  }

  /* Parse the GetCertsResponse */
  if ((rc = es10_tlv_extractor__get_certs_response(
           euicc_data->get_certs_response, euicc_data->get_certs_response_size,
           &get_certs_response)) != eOk) {
    LOGW("[ipa__ipa_euicc_data_response_set_certificates] Error on parse the "
         "GetCertsResponse, rc %d",
         rc);
    return ipa__set_ipa_euicc_data_response_error(
        request, IPA_EUICC_DATA_ERROR_UNDEFINED_ERROR, response);
  }

  /* Set the certificates into the IpaEuiccDataResponse */
  switch (get_certs_response.choice) {
  case CERTS_CHOICE:
    // Set the eumCertificate
    if (request->tag_list.eum_cert) {
      response->value.ipa_euicc_data.eum_certificate =
          get_certs_response.value.certs.eum_certificate;
      response->value.ipa_euicc_data.eum_certificate_size =
          get_certs_response.value.certs.eum_certificate_size;
      response->value.ipa_euicc_data.field_is_present.eum_cert = true;
      LOG_DATA(eLogDebug,
               "[ipa__ipa_euicc_data_response_set_certificates] eumCertificate",
               response->value.ipa_euicc_data.eum_certificate,
               response->value.ipa_euicc_data.eum_certificate_size);
      response->value.ipa_euicc_data.get_certs_context =
          (void *)euicc_data->get_certs_response; // Set the context
    }
    // Set the euiccCertificate
    if (request->tag_list.euicc_cert) {
      response->value.ipa_euicc_data.euicc_certificate =
          get_certs_response.value.certs.euicc_certificate;
      response->value.ipa_euicc_data.euicc_certificate_size =
          get_certs_response.value.certs.euicc_certificate_size;
      response->value.ipa_euicc_data.field_is_present.euicc_cert = true;
      LOG_DATA(
          eLogDebug,
          "[ipa__ipa_euicc_data_response_set_certificates] euiccCertificate",
          response->value.ipa_euicc_data.euicc_certificate,
          response->value.ipa_euicc_data.euicc_certificate_size);
      response->value.ipa_euicc_data.get_certs_context =
          (void *)euicc_data->get_certs_response; // Set the context
    }
    return eOk;
  case GET_CERTS_ERROR_CHOICE:
    switch (get_certs_response.value.get_certs_error) {
    case GET_CERTS_ERROR_INVALID_CI_PK_ID:
      LOGW("[ipa__ipa_euicc_data_response_set_certificates] "
           "GetCertsResponse(getCertsError=invalidCiPKId)",
           get_certs_response.value.get_certs_error);
      return ipa__set_ipa_euicc_data_response_error(
          request, IPA_EUICC_DATA_ERROR_EUICC_CI_PK_ID_NOT_FOUND, response);
    default:
      LOGW("[ipa__ipa_euicc_data_response_set_certificates] "
           "GetCertsResponse(getCertsError=%d)",
           get_certs_response.value.get_certs_error);
      return ipa__set_ipa_euicc_data_response_error(
          request, IPA_EUICC_DATA_ERROR_UNDEFINED_ERROR, response);
    }
  default:
    LOGW("[ipa__ipa_euicc_data_response_set_certificates] Unknown "
         "GetCertsResponse CHOICE (%d)",
         get_certs_response.choice);
    return ipa__set_ipa_euicc_data_response_error(
        request, IPA_EUICC_DATA_ERROR_UNDEFINED_ERROR, response);
  }
}

static ErrCode ipa__ipa_euicc_data_response_set_association_token(
    const ipa_euicc_data_request_t *request, euicc_data_t *euicc_data,
    ipa_euicc_data_response_t *response) {
  ErrCode rc;

  if (!request) {
    LOGE("[ipa__ipa_euicc_data_response_set_association_token] "
         "IpaEuiccDataRequest object is null");
    return eBadArg;
  }
  if (!response) {
    LOGE("[ipa__ipa_euicc_data_response_set_association_token] "
         "IpaEuiccDataResponse object is null");
    return eBadArg;
  }

  // Set default response
  response->value.ipa_euicc_data.field_is_present.association_token = false;

  if (!request->tag_list.association_token) {
    LOGD("[ipa__ipa_euicc_data_response_set_association_token] No "
         "associationToken needs to be added");
    return eOk;
  }

  if (!euicc_data) {
    LOGW("[ipa__ipa_euicc_data_response_set_association_token] eUICC data "
         "object is null");
    return ipa__set_ipa_euicc_data_response_error(
        request, IPA_EUICC_DATA_ERROR_UNDEFINED_ERROR, response);
  }

  if (!euicc_data->get_eim_configuration_data_response ||
      0 == euicc_data->get_eim_configuration_data_response_size) {
    LOGW("[ipa__ipa_euicc_data_response_set_association_token] "
         "GetEimConfigurationDataResponse tlv is empty/null");
    return ipa__set_ipa_euicc_data_response_error(
        request, IPA_EUICC_DATA_ERROR_UNDEFINED_ERROR, response);
  }

  /* Parse the GetEimConfigurationDataResponse */
  if ((rc =
           es10_tlv_extractor__get_eim_configuration_data_response_assocation_token(
               euicc_data->get_eim_configuration_data_response,
               euicc_data->get_eim_configuration_data_response_size,
               &response->value.ipa_euicc_data.association_token)) != eOk) {
    LOGW("[ipa__ipa_euicc_data_response_set_association_token] Error on "
         "retrieve the association token from the "
         "GetEimConfigurationDataResponse, rc %d",
         rc);
    return ipa__set_ipa_euicc_data_response_error(
        request, IPA_EUICC_DATA_ERROR_UNDEFINED_ERROR, response);
  }

  /* Include the association token in the response only if it is configured on
   * the UICC (is not the default) */
  if (ASSOCIATION_TOKEN_DEFAULT_VALUE !=
      response->value.ipa_euicc_data.association_token) {
    response->value.ipa_euicc_data.field_is_present.association_token = true;
  }

  return eOk;
}

static ErrCode ipa__ipa_euicc_data_response_set_euicc_package_result_list(
    const ipa_euicc_data_request_t *request, euicc_data_t *euicc_data,
    ipa_euicc_data_response_t *response) {
  ErrCode rc;
  retrieve_notifications_list_response_t
      retrieve_notifications_list_response_obj = {0};

  if (!request) {
    LOGE("[ipa__ipa_euicc_data_response_set_euicc_package_result_list] "
         "IpaEuiccDataRequest object is null");
    return eBadArg;
  }
  if (!response) {
    LOGE("[ipa__ipa_euicc_data_response_set_euicc_package_result_list] "
         "IpaEuiccDataResponse object is null");
    return eBadArg;
  }

  // Set default response
  response->value.ipa_euicc_data.field_is_present.euicc_package_result_list =
      false;

  if (!request->tag_list.euicc_package_results) {
    LOGD("[ipa__ipa_euicc_data_response_set_euicc_package_result_list] No "
         "euiccPackageResultList needs to be added");
    return eOk;
  }

  if (!euicc_data) {
    LOGW("[ipa__ipa_euicc_data_response_set_euicc_package_result_list] eUICC "
         "data object is null");
    return ipa__set_ipa_euicc_data_response_error(
        request, IPA_EUICC_DATA_ERROR_UNDEFINED_ERROR, response);
  }

  if (!euicc_data->retrieve_euicc_packages_list_response ||
      0 == euicc_data->retrieve_euicc_packages_list_response_size) {
    LOGW("[ipa__ipa_euicc_data_response_set_euicc_package_result_list] "
         "RetrieveNotificationsListResponse tlv is empty/null");
    return ipa__set_ipa_euicc_data_response_error(
        request, IPA_EUICC_DATA_ERROR_UNDEFINED_ERROR, response);
  }

  /* Parse the RetrieveNotificationsListResponse */
  if ((rc = es10_tlv_extractor__retrieve_notifications_list_response(
           euicc_data->retrieve_euicc_packages_list_response,
           euicc_data->retrieve_euicc_packages_list_response_size,
           &retrieve_notifications_list_response_obj)) != eOk) {
    LOGW("[ipa__ipa_euicc_data_response_set_euicc_package_result_list] Error "
         "on parse the RetrieveNotificationsListResponse, rc %d",
         rc);
    return ipa__set_ipa_euicc_data_response_error(
        request, IPA_EUICC_DATA_ERROR_UNDEFINED_ERROR, response);
  }

  switch (retrieve_notifications_list_response_obj.choice) {
  case EUICC_PACKAGE_RESULT_LIST_CHOICE:
    response->value.ipa_euicc_data.field_is_present.euicc_package_result_list =
        true;
    response->value.ipa_euicc_data.euicc_package_result_list =
        retrieve_notifications_list_response_obj.value.euicc_package_result_list
            .asn1_list_tlv;
    response->value.ipa_euicc_data.euicc_package_result_list_size =
        retrieve_notifications_list_response_obj.value.euicc_package_result_list
            .asn1_list_tlv_size;
    LOG_DATA(eLogDebug,
             "[ipa__ipa_euicc_data_response_set_euicc_package_result_list] "
             "euiccPackageResultList",
             response->value.ipa_euicc_data.euicc_package_result_list,
             response->value.ipa_euicc_data.euicc_package_result_list_size);
    response->value.ipa_euicc_data.retrieve_euicc_packages_list_context =
        (void *)euicc_data
            ->retrieve_euicc_packages_list_response; // Set the context
    break;
  case NOTIFICATIONS_LIST_CHOICE:
    // To be more robust in case a filter has been applied and returned a
    // notificationsList
    M_free(euicc_data->retrieve_euicc_packages_list_response);
    euicc_data->retrieve_euicc_packages_list_response = NULL;
    euicc_data->retrieve_euicc_packages_list_response_size = 0;
    break;
  default:
    LOGW("[ipa__ipa_euicc_data_response_set_euicc_package_result_list] "
         "RetrieveNotificationsListResponse CHOICE (%d)",
         retrieve_notifications_list_response_obj.choice);
    return ipa__set_ipa_euicc_data_response_error(
        request, IPA_EUICC_DATA_ERROR_UNDEFINED_ERROR, response);
  }

  return eOk;
}
#endif

static ErrCode ipa__ipa_euicc_data_response_set_addresses(
    const ipa_euicc_data_request_t *request, euicc_data_t *euicc_data,
    ipa_euicc_data_response_t *response) {
  ErrCode rc;
  euicc_configured_addresses_response_t
      euicc_configured_addresses_response_obj = {0};

  if (!request) {
    LOGE("[ipa__ipa_euicc_data_response_set_addresses] IpaEuiccDataRequest "
         "object is null");
    return eBadArg;
  }
  if (!response) {
    LOGE("[ipa__ipa_euicc_data_response_set_addresses] IpaEuiccDataResponse "
         "object is null");
    return eBadArg;
  }

  // Set default response
  response->value.ipa_euicc_data.field_is_present.default_smdp_address = false;
  response->value.ipa_euicc_data.field_is_present.root_smds_address = false;

  if (!request->tag_list.default_smdp && !request->tag_list.root_smds) {
    LOGD("[ipa__ipa_euicc_data_response_set_addresses] No addresses needs to "
         "be added");
    return eOk;
  }

  if (!euicc_data) {
    LOGW("[ipa__ipa_euicc_data_response_set_addresses] eUICC data object is "
         "null");
    return ipa__set_ipa_euicc_data_response_error(
        request, IPA_EUICC_DATA_ERROR_UNDEFINED_ERROR, response);
  }

  if (!euicc_data->euicc_configured_addresses_response ||
      0 == euicc_data->euicc_configured_addresses_response_size) {
    LOGW("[ipa__ipa_euicc_data_response_set_addresses] "
         "EuiccConfiguredAddressesResponse tlv is empty/null");
    return ipa__set_ipa_euicc_data_response_error(
        request, IPA_EUICC_DATA_ERROR_UNDEFINED_ERROR, response);
  }

  /* Parse the EuiccConfiguredAddressesResponse */
  if ((rc = es10_tlv_extractor__euicc_configured_addresses_response(
           euicc_data->euicc_configured_addresses_response,
           euicc_data->euicc_configured_addresses_response_size,
           &euicc_configured_addresses_response_obj)) != eOk) {
    LOGW("[ipa__ipa_euicc_data_response_set_addresses] Error on parse the "
         "EuiccConfiguredAddressesResponse, rc %d",
         rc);
    return ipa__set_ipa_euicc_data_response_error(
        request, IPA_EUICC_DATA_ERROR_UNDEFINED_ERROR, response);
  }

  // Set the defaultSmdpAddress
  if (request->tag_list.default_smdp &&
      euicc_configured_addresses_response_obj.field_is_present
          .default_dp_address) {
    memcpy(&response->value.ipa_euicc_data.default_smdp_address,
           &euicc_configured_addresses_response_obj.default_dp_address,
           sizeof(fqdn_t));
    response->value.ipa_euicc_data.field_is_present.default_smdp_address = true;
    LOGD(
        "[ipa__ipa_euicc_data_response_set_addresses] defaultSmdpAddress: '%s'",
        response->value.ipa_euicc_data.default_smdp_address.fqdn);
  }

  // Set the rootSmdsAddress
  if (request->tag_list.root_smds) {
    memcpy(&response->value.ipa_euicc_data.root_smds_address,
           &euicc_configured_addresses_response_obj.root_ds_address,
           sizeof(fqdn_t));
    response->value.ipa_euicc_data.field_is_present.root_smds_address = true;
    LOGD("[ipa__ipa_euicc_data_response_set_addresses] rootSmdsAddress: '%s'",
         response->value.ipa_euicc_data.default_smdp_address.fqdn);
  }

  return eOk;
}

static ErrCode ipa__ipa_euicc_data_response_set_notifications_list(
    const ipa_euicc_data_request_t *request, euicc_data_t *euicc_data,
    ipa_euicc_data_response_t *response) {
  ErrCode rc;
  retrieve_notifications_list_response_t
      retrieve_notifications_list_response_obj = {0};

  if (!request) {
    LOGE("[ipa__ipa_euicc_data_response_set_notifications_list] "
         "IpaEuiccDataRequest object is null");
    return eBadArg;
  }
  if (!response) {
    LOGE("[ipa__ipa_euicc_data_response_set_notifications_list] "
         "IpaEuiccDataResponse object is null");
    return eBadArg;
  }

  // Set default response
  response->value.ipa_euicc_data.field_is_present.notifications_list = false;

  if (!request->tag_list.notifications_list) {
    LOGD("[ipa__ipa_euicc_data_response_set_notifications_list] No "
         "notificationsList needs to be added");
    return eOk;
  }

  if (!euicc_data) {
    LOGW("[ipa__ipa_euicc_data_response_set_notifications_list] eUICC data "
         "object is null");
    return ipa__set_ipa_euicc_data_response_error(
        request, IPA_EUICC_DATA_ERROR_UNDEFINED_ERROR, response);
  }

  if (!euicc_data->retrieve_notifications_list_response ||
      0 == euicc_data->retrieve_notifications_list_response_size) {
    LOGW("[ipa__ipa_euicc_data_response_set_notifications_list] "
         "RetrieveNotificationsListResponse tlv is empty/null");
    return ipa__set_ipa_euicc_data_response_error(
        request, IPA_EUICC_DATA_ERROR_UNDEFINED_ERROR, response);
  }

  /* Parse the RetrieveNotificationsListResponse */
  if ((rc = es10_tlv_extractor__retrieve_notifications_list_response(
           euicc_data->retrieve_notifications_list_response,
           euicc_data->retrieve_notifications_list_response_size,
           &retrieve_notifications_list_response_obj)) != eOk) {
    LOGW("[ipa__ipa_euicc_data_response_set_notifications_list] Error on parse "
         "the RetrieveNotificationsListResponse, rc %d",
         rc);
    return ipa__set_ipa_euicc_data_response_error(
        request, IPA_EUICC_DATA_ERROR_UNDEFINED_ERROR, response);
  }

  switch (retrieve_notifications_list_response_obj.choice) {
  case NOTIFICATIONS_LIST_CHOICE:
    response->value.ipa_euicc_data.field_is_present.notifications_list = true;
    response->value.ipa_euicc_data.notifications_list =
        retrieve_notifications_list_response_obj.value.notification_list
            .asn1_list_tlv;
    response->value.ipa_euicc_data.notifications_list_size =
        retrieve_notifications_list_response_obj.value.notification_list
            .asn1_list_tlv_size;
    LOG_DATA(eLogDebug,
             "[ipa__ipa_euicc_data_response_set_notifications_list] "
             "notificationsList",
             response->value.ipa_euicc_data.notifications_list,
             response->value.ipa_euicc_data.notifications_list_size);
    response->value.ipa_euicc_data.retrieve_notifications_list_context =
        (void *)
            euicc_data->retrieve_notifications_list_response; // Set the context
    break;
#ifdef SGP32
  case EUICC_PACKAGE_RESULT_LIST_CHOICE:
    // To be more robust in case a filter has been applied and returned a
    // euiccPackageResultList
    M_free(euicc_data->retrieve_notifications_list_response);
    euicc_data->retrieve_notifications_list_response = NULL;
    euicc_data->retrieve_notifications_list_response_size = 0;
    break;
#endif
  default:
    LOGW("[ipa__ipa_euicc_data_response_set_notifications_list] "
         "RetrieveNotificationsListResponse CHOICE (%d)",
         retrieve_notifications_list_response_obj.choice);
    return ipa__set_ipa_euicc_data_response_error(
        request, IPA_EUICC_DATA_ERROR_UNDEFINED_ERROR, response);
  }

  return eOk;
}

static ErrCode ipa__ipa_euicc_data_response_set_euicc_info(
    const ipa_euicc_data_request_t *request, euicc_data_t *euicc_data,
    ipa_euicc_data_response_t *response) {
  if (!request) {
    LOGE("[ipa__ipa_euicc_data_response_set_euicc_info] IpaEuiccDataRequest "
         "object is null");
    return eBadArg;
  }
  if (!response) {
    LOGE("[ipa__ipa_euicc_data_response_set_euicc_info] IpaEuiccDataResponse "
         "object is null");
    return eBadArg;
  }

  // Set default response
  response->value.ipa_euicc_data.field_is_present.euicc_info_1 = false;
  response->value.ipa_euicc_data.field_is_present.euicc_info_2 = false;

  if (!request->tag_list.euicc_info_1 && !request->tag_list.euicc_info_2) {
    LOGD("[ipa__ipa_euicc_data_response_set_euicc_info] No euiccInfo needs to "
         "be added");
    return eOk;
  }

  if (!euicc_data) {
    LOGW("[ipa__ipa_euicc_data_response_set_euicc_info] eUICC data object is "
         "null");
    return ipa__set_ipa_euicc_data_response_error(
        request, IPA_EUICC_DATA_ERROR_UNDEFINED_ERROR, response);
  }

  // Set the euiccInfo1
  if (request->tag_list.euicc_info_1) {
    if (!euicc_data->euicc_info_1 || 0 == euicc_data->euicc_info_1_size) {
      LOGW("[ipa__ipa_euicc_data_response_set_notifications_list] EUICCInfo1 "
           "tlv is empty/null");
      return ipa__set_ipa_euicc_data_response_error(
          request, IPA_EUICC_DATA_ERROR_UNDEFINED_ERROR, response);
    }
    response->value.ipa_euicc_data.euicc_info_1 = euicc_data->euicc_info_1;
    response->value.ipa_euicc_data.euicc_info_1_size =
        euicc_data->euicc_info_1_size;
    response->value.ipa_euicc_data.field_is_present.euicc_info_1 = true;
    LOG_DATA(eLogDebug,
             "[ipa__ipa_euicc_data_response_set_euicc_info] euiccInfo1",
             response->value.ipa_euicc_data.euicc_info_1,
             response->value.ipa_euicc_data.euicc_info_1_size);
  }

  // Set the euiccInfo2
  if (request->tag_list.euicc_info_2) {
    if (!euicc_data->euicc_info_2 || 0 == euicc_data->euicc_info_2_size) {
      LOGW("[ipa__ipa_euicc_data_response_set_notifications_list] EUICCInfo2 "
           "tlv is empty/null");
      return ipa__set_ipa_euicc_data_response_error(
          request, IPA_EUICC_DATA_ERROR_UNDEFINED_ERROR, response);
    }
    response->value.ipa_euicc_data.euicc_info_2 = euicc_data->euicc_info_2;
    response->value.ipa_euicc_data.euicc_info_2_size =
        euicc_data->euicc_info_2_size;
    response->value.ipa_euicc_data.field_is_present.euicc_info_2 = true;
    LOG_DATA(eLogDebug,
             "[ipa__ipa_euicc_data_response_set_euicc_info] euiccInfo2",
             response->value.ipa_euicc_data.euicc_info_2,
             response->value.ipa_euicc_data.euicc_info_2_size);
  }

  return eOk;
}

static ErrCode ipa__set_ipa_euicc_data_response_error(
    const ipa_euicc_data_request_t *request,
    const ipa_euicc_data_error_code_t error_code,
    ipa_euicc_data_response_t *response) {
  /* Check input params */
  if (!request) {
    LOGE("[ipa__set_ipa_euicc_data_response_error] IpaEuiccDataRequest object "
         "is null");
    return eBadArg;
  }
  if (!response) {
    LOGE("[ipa__set_ipa_euicc_data_response_error] IpaEuiccDataResponse object "
         "is null");
    return eBadArg;
  }

  memset(response, 0,
         sizeof(ipa_euicc_data_response_t)); // Clean current response data

  /* Populate the response object */
  response->choice =
      IPA_EUICC_DATA_RESPONSE_ERROR_CHOICE; // Set the IpaEuiccDataResponse
                                            // CHOICE
  response->value.ipa_euicc_data_response_error.ipa_euicc_data_error_code =
      error_code; // Set the ipaEuiccDataErrorCode
  LOGD("[ipa__set_ipa_euicc_data_response_error] ipaEuiccDataErrorCode(%d)",
       response->value.ipa_euicc_data_response_error.ipa_euicc_data_error_code);
  if (request->field_is_present
          .eim_transaction_id) { // Set the eimTransactionId (if present)
    memcpy(&response->value.ipa_euicc_data_response_error.eim_transaction_id,
           &request->eim_transaction_id, sizeof(transaction_id_t));
    response->value.ipa_euicc_data_response_error.field_is_present
        .eim_transaction_id = true;
    LOG_DATA(eLogDebug,
             "[ipa__set_ipa_euicc_data_response_error] eimTransactionId",
             response->value.ipa_euicc_data_response_error.eim_transaction_id
                 .transaction_id,
             response->value.ipa_euicc_data_response_error.eim_transaction_id
                 .transaction_id_size);
  } else {
    response->value.ipa_euicc_data_response_error.field_is_present
        .eim_transaction_id = false;
    LOGD("[ipa__set_ipa_euicc_data_response_error] eimTransactionId is not "
         "present");
  }

  return eOk;
}

ErrCode ipa__get_all_profiles_info(profile_info_t **profiles, uint32_t *num_profiles, uint8_t **profile_info_list_response_tlv_out) {
    ErrCode rc;
    int err;
    uint8_t *profile_info_list_response_tlv = NULL;
    uint32_t profile_info_list_response_size = 0;

    if (!profiles || !num_profiles || !profile_info_list_response_tlv_out) {
        LOGE("[ipa__get_all_profiles_info] Output parameters are null");
        return eBadArg;
    }
    *profiles = NULL;
    *num_profiles = 0;
    *profile_info_list_response_tlv_out = NULL;

    profile_info_list_request_t profile_info_list_request = {0};
    memset(&profile_info_list_request.tag_list, 0xFF, sizeof(profile_info_list_request.tag_list));
    profile_info_list_request.field_is_present.tag_list = true;
    profile_info_list_request.field_is_present.search_criteria = false;

    if ((err = es10__init(g_ipa.es10)) < 0) {
        LOGE("[ipa__get_all_profiles_info] Error initializing the ES10, err %d", err);
        return eFatal;
    }

    if ((err = es10__get_profiles_info(g_ipa.es10, &profile_info_list_request,
                                       &profile_info_list_response_tlv,
                                       &profile_info_list_response_size)) < 0) {
        LOGE("[ipa__get_all_profiles_info] ES10.GetProfilesInfo failed, err %d", err);
        rc = eFatal;
        goto deinit_es10;
    }
    LOG_DATA(eLogDebug, "[ipa__get_all_profiles_info] ProfileInfoListResponse",
             profile_info_list_response_tlv, profile_info_list_response_size);

    rc = es10_tlv_extractor__get_all_profiles_info(profile_info_list_response_tlv,
                                                   profile_info_list_response_size,
                                                   profiles, num_profiles);
    if (rc != eOk) {
        LOGE("[ipa__get_all_profiles_info] Error extracting profile information, rc %d", rc);
    } else {
        *profile_info_list_response_tlv_out = profile_info_list_response_tlv;
    }

deinit_es10:
    if ((err = es10__deinit(g_ipa.es10)) < 0) {
        LOGE("[ipa__get_all_profiles_info] Error deinitializing the ES10, err %d", err);
        if (rc == eOk) {
            rc = eFatal;
        }
    }

    if (rc != eOk) {
        if (*profiles) {
            M_free(*profiles);
            *profiles = NULL;
        }
        *num_profiles = 0;
        if (profile_info_list_response_tlv) {
            M_free(profile_info_list_response_tlv);
        }
    }

    return rc;
}

ErrCode ipa__get_eim_configuration(eim_configuration_data_t *eim_configuration_info, uint8_t **response_tlv_out) {
  int err;
  ErrCode rc = eFatal;
  uint8_t *response_tlv = NULL;
  uint32_t response_tlv_size = 0;
  uint32_t num_configurations = 0;

  if (eim_configuration_info == NULL || response_tlv_out == NULL) {
    LOGE("[ipa__get_eim_configuration] Output parameter cannot be NULL.");
    return eBadArg;
  }
  *response_tlv_out = NULL;
  LOGI("Getting eIM configuration data from the eUICC...");

  get_eim_configuration_data_request_t request = {
      .field_is_present = {.search_criteria = false}};

  if ((err = es10__init(g_ipa.es10)) < 0) {
    LOGE("[ipa__get_eim_configuration] Error initializing the ES10, err %d",err);
    return eFatal;
  }

  if ((err = es10__get_eim_configuration_data(
           g_ipa.es10, &request, &response_tlv, &response_tlv_size)) < 0) {
    LOGE("[ipa__get_eim_configuration] ES10.GetEimConfigurationData failed, err %d",err);
    rc = eFatal;
    goto cleanup_and_exit;
  }
  LOG_DATA(eLogDebug, "GetEimConfigurationDataResponse TLV", response_tlv,response_tlv_size);

  rc = es10_tlv_extractor__get_eim_configuration_data_response_list_size(response_tlv, response_tlv_size, &num_configurations);
  if (rc != eOk) {
    LOGE("[ipa__get_eim_configuration] Failed to count eIM configurations, rc %d",rc);
    goto cleanup_and_exit;
  }

  if (num_configurations == 0) {
    LOGI("[ipa__get_eim_configuration] No eIM configurations found.");
    rc = eOk;
    goto cleanup_and_exit;
  }

  if (num_configurations > 1) {
    LOGW("[ipa__get_eim_configuration] Found %u eIMs, but assuming only one is expected. Proceeding with the first one.",
         num_configurations);
  }

  get_eim_configuration_data_response_t iterator_response = {0};
  uint8_t *sub_tlv = NULL;
  uint32_t sub_tlv_size = 0;

  if ((rc = es10_tlv_extractor__get_eim_configuration_data_response(
           response_tlv, response_tlv_size, &iterator_response)) != eOk) {
    LOGE("[ipa__get_eim_configuration] Failed to initialize iterator, rc %d",rc);
    goto cleanup_and_exit;
  }

  if ((rc = tlv_data_extractor__asn1_list_get_next(&iterator_response.eim_configuration_data_list_iterator, &sub_tlv,&sub_tlv_size)) == eOk &&sub_tlv != NULL) {
    rc = es10_tlv_extractor__eim_configuration_data(sub_tlv, sub_tlv_size,eim_configuration_info);

    if (rc != eOk) {
      LOGE("[ipa__get_eim_configuration] Failed to parse the eIM configuration, rc %d",
           rc);
      goto cleanup_and_exit;
    }
  } else {
    LOGE("[ipa__get_eim_configuration] Inconsistency: Counted %u eIMs, but could not extract the first one.",num_configurations);
    rc = eFatal;
    goto cleanup_and_exit;
  }

  LOGI("[ipa__get_eim_configuration] Successfully retrieved and parsed 1 eIM configuration.");
  rc = eOk;
  *response_tlv_out = response_tlv;

cleanup_and_exit:
  if (rc != eOk) {
    M_free(response_tlv);
  }

  if ((err = es10__deinit(g_ipa.es10)) < 0) {
    LOGE("[ipa__get_eim_configuration] Error deinitializing the ES10, err %d",err);
    if (rc == eOk)
      rc = eFatal;
  }
  return rc;
}


/** ES10 SHALL be initialized before call this function */
static ErrCode ipa__update_ipa_profiles_state() {
  ErrCode rc;
  int err;
  uint8_t *profile_info_list_response;
  uint32_t profile_info_list_response_size;
  profile_info_t *profiles = NULL;
  uint32_t num_profiles = 0;

  profile_info_list_request_t profile_info_list_request = {
      .tag_list = {.profile_state = true,
#ifdef SGP32
                   .ecall_indication = true
#endif
      },
      .field_is_present = {.search_criteria = false, .tag_list = true}};
  profile_info_t enabled_profile = {0};

  // Clean the current state
  g_ipa.field_is_present.mcc_mnc = false;
  g_ipa.emergency_profile_enabled = false;

  // Retrieve the Profile Info list
  if ((err = es10__get_profiles_info(g_ipa.es10, &profile_info_list_request,
                                     &profile_info_list_response,
                                     &profile_info_list_response_size)) < 0) {
    LOGE("[ipa__update_ipa_profiles_state] ES10.GetProfilesInfo failed, err %d",
         err);
    return eFatal;
  }
  LOG_DATA(eLogDebug, "ProfileInfoListResponse", profile_info_list_response,
           profile_info_list_response_size);

  // Extract the profile info of the enabled profile
  rc = es10_tlv_extractor__get_all_profiles_info(
      profile_info_list_response, profile_info_list_response_size, &profiles,
      &num_profiles);
  if (rc != eOk) {
    LOGE("[ipa__update_ipa_profiles_state] Error extracting the ProfileInfo of "
         "the enabled profile, rc %d",
         rc);
    return rc;
  }
  g_ipa_profile_is_enabled = false;
  memset(&g_ipa_enabled_profile_info, 0, sizeof(profile_info_t));

  for (uint32_t i = 0; i < num_profiles; i++) {
    if (profiles[i].profile_state == PROFILE_STATE_ENABLED) {
      g_ipa_profile_is_enabled = true;
      memcpy(&g_ipa_enabled_profile_info, &profiles[i], sizeof(profile_info_t));
      break;
    }
  }

  // Update the MCC MNC
  if (enabled_profile.field_is_present.profile_owner) {
    g_ipa.field_is_present.mcc_mnc = true;
    memcpy(&g_ipa.mcc_mnc, &enabled_profile.profile_owner.mcc_mnc,
           sizeof(mcc_mnc_t));
    LOG_DATA(eLogDebug, "[ipa__update_ipa_profiles_state] MCC MNC",
             g_ipa.mcc_mnc.value, sizeof(g_ipa.mcc_mnc.value));
  }

#ifdef SGP32
  // Update the Emergency Profile
  if (enabled_profile.field_is_present.ecall_indication &&
      enabled_profile.ecall_indication) {
    g_ipa.emergency_profile_enabled = true;
    LOGD("[ipa__update_ipa_profiles_state] The Emergency Profile is enabled");
  }
#endif
  if (g_ipa.profile_state_callback != NULL) {
    LOGD("[ipa] Notifying application of profile list update (%u profiles).",
         num_profiles);
    g_ipa.profile_state_callback(profiles, num_profiles);
  }

  M_free(profiles);
  M_free(profile_info_list_response);

  return rc;
}

#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
static ErrCode ipa__cancel_session(
    const transaction_id_t *transaction_id,
    const cancel_session_reason_t reason,
    cancel_session_request_esipa_t *cancel_session_request_esipa) {
  int err;
  cancel_session_request_t cancel_session_request;

  /* Check input parameters */
  if (!transaction_id) {
    LOGD("[ipa__cancel_session] TransactionId is null");
    return eBadArg;
  }

  if (!cancel_session_request_esipa) {
    LOGD("[ipa__cancel_session] CancelSessionRequestEsipa is null");
    return eBadArg;
  }

  /* Initialize de ES10 */
  if ((err = es10__init(g_ipa.es10)) < 0) {
    LOGE("[ipa__cancel_session] Error initializing the ES10, err %d", err);
    return eFatal;
  }

  /* Execute the ES10.CancelSession */
  cancel_session_request.reason = reason;
  memcpy(&cancel_session_request.transaction_id, transaction_id,
         sizeof(transaction_id_t));
  if ((err = es10__cancel_session(
           g_ipa.es10, &cancel_session_request,
           &cancel_session_request_esipa->cancel_session_response,
           &cancel_session_request_esipa->cancel_session_response_size)) < 0) {
    LOGE("[ipa__cancel_session] Error executing the ES10.CancelSession, err %d",
         err);
  }

  /* Denitialize de ES10 */
  if (es10__deinit(g_ipa.es10) < 0) {
    LOGE("[ipa__cancel_session] Error deinitializing the ES10, err %d", err);
  }

  /* Prepare the CancelSessionRequestEsipa */
  if (err < 0) {
    LOGE("[ipa__cancel_session] Cancel Session Procedure for Indirect Profile "
         "Download aborted, err %d",
         err);
    return eFatal;
  }
#ifdef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
  // Compact the CancelSessionResponse
  /** TODO: LPA-259
   *  if ((rc =
   * ipa__compact_cancel_session_response(cancel_session_request_esipa->cancel_session_response,
   * &cancel_session_request_esipa->cancel_session_response_size)) != eOk) {
   *      LOGE("[ipa__cancel_session] Error compacting the
   * CancelSessionResponse, Cancel Session Procedure for Indirect Profile
   * Download aborted, rc %d", rc); return rc;
   *  }
   */
#endif
  memcpy(&cancel_session_request_esipa->transaction_id, transaction_id,
         sizeof(transaction_id_t)); // Set the TransactionID

  return eOk;
}

static ErrCode ipa__profile_download_trigger_response_result_set_error(
    const profile_download_trigger_request_t *request,
    profile_download_trigger_response_result_t *response,
    profile_download_error_reason_t error_reason) {
  /* Check input parameters */
  if (!request) {
    LOGE("[ipa__profile_download_trigger_response_result_set_error] The "
         "request pointer is null");
    return eBadArg;
  }
  if (!response) {
    LOGE("[ipa__profile_download_trigger_response_result_set_error] The "
         "response pointer is null");
    return eBadArg;
  }
  memset(response, 0, sizeof(profile_download_trigger_response_result_t));
  response->choice = PROFILE_DOWNLOAD_TRIGGER_RESULT_CHOICE;
  response->value.profile_download_trigger_result
      .profile_download_trigger_result_data.choice =
      PROFILE_DOWNLOAD_ERROR_CHOICE;
  response->value.profile_download_trigger_result
      .profile_download_trigger_result_data.value.profile_download_error
      .profile_download_error_reason = error_reason;

  /* Copy the eIM transaction Id to the response if exists in the request */
  if (request->field_is_present.eim_transaction_id) {
    response->value.profile_download_trigger_result.field_is_present
        .eim_transaction_id = true;
    memcpy(&response->value.profile_download_trigger_result.eim_transaction_id,
           &request->eim_transaction_id, sizeof(transaction_id_t));
  }
  return eOk;
}

#ifdef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
static ErrCode ipa__reconstruct_truncated_euicc_ci_pk_id(
    const uint8_t *euicc_info_1, size_t euicc_info_1_size,
    const truncated_subject_key_identifier_t *truncated_euicc_ci_pk_id,
    subject_key_identifier_t *reconstructed_euicc_ci_pk_id) {
  /** TODO: LPA-258 Regenerate truncated euiccCiPKIdToBeUsed */
  return eNotImpl;
}
#endif

static void clear_indirect_rsp_context() {
#ifndef IPA_FEATURE_EIM_DOWNLOAD_DATA_HANDLING
  memset(&g_ipa.indirect_rsp_context.matching_id, 0,
         sizeof(g_ipa.indirect_rsp_context.matching_id));
  g_ipa.indirect_rsp_context.matching_id_size = 0;
  g_ipa.indirect_rsp_context.field_is_present.matching_id = false;
#endif
  memset(&g_ipa.indirect_rsp_context.transaction_id, 0,
         sizeof(transaction_id_t));
  g_ipa.indirect_rsp_context.field_is_present.transaction_id = false;
  g_ipa.indirect_rsp_context.field_is_present.default_smdp_use_case = false;
}

static void
ipa__free_handle_notification_esipa(handle_notification_esipa_t *obj) {
  M_free(obj->value.pending_notification.pending_notification);
  memset(obj, 0, sizeof(handle_notification_esipa_t));
}
static void ipa__free_get_bound_profile_package_request_esipa(
    get_bound_profile_package_request_esipa_t *obj) {
  M_free(obj->prepare_download_response);
  memset(obj, 0, sizeof(get_bound_profile_package_request_esipa_t));
}
#endif
static void free_ipa_euicc_data(ipa_euicc_data_t *obj) {
  if (obj) {
    M_free(obj->euicc_info_1);
    M_free(obj->euicc_info_2);
    M_free(obj->get_certs_context);
    M_free(obj->retrieve_notifications_list_context);
    M_free(obj->retrieve_euicc_packages_list_context);
    memset(obj, 0, sizeof(ipa_euicc_data_t));
  }
}

static void free_euicc_data(euicc_data_t *obj) {
  if (obj) {
    M_free(obj->euicc_configured_addresses_response);
    M_free(obj->euicc_info_1);
    M_free(obj->euicc_info_2);
    M_free(obj->retrieve_notifications_list_response);
#ifdef SGP32
    M_free(obj->get_certs_response);
    M_free(obj->get_eim_configuration_data_response);
    M_free(obj->retrieve_euicc_packages_list_response);
#endif
    memset(obj, 0, sizeof(euicc_data_t));
  }
}

ErrCode ipa__notifications_delivery__initialize_notifications_group_list(
    notification_group_node_t **notifications_list) {
  return notifications_delivery__initialize_notifications_group_list(
      &g_es10, notifications_list);
}

ErrCode ipa__notifications_delivery__all_notifications() {
  return notifications_delivery__all_notifications(&g_es9, &g_es10);
}

ErrCode ipa__notifications_delivery__seq_number_single_notification_delivery(
    bool remove_after_send, const char *smdp_address, uint32_t seq_number) {
  return notifications_delivery__seq_number_single_notification_delivery(
      &g_es9, &g_es10, true, remove_after_send, smdp_address, seq_number);
}

ErrCode ipa__notifications_delivery__remove_notification(
    const uint32_t sequence_number) {
  return notifications_delivery__remove_notification(&g_es10, sequence_number);
}

ErrCode ipa__notifications_delivery__remove_all_notifications() {
  return notifications_delivery__remove_all_notifications(&g_es10);
}

void ipa__notifications_delivery__free_notification_list(notification_group_node_t** head) {
  notifications_delivery__free_notification_list(head);
}
#ifdef SGP22
static int
load_euicc_package_sgp22_translator(const uint8_t *euicc_package_request,
                                    const uint32_t euicc_package_request_size,
                                    uint8_t **euicc_package_result,
                                    uint32_t *euicc_package_result_size) {
  ErrCode rc;
  int err = -1;
  _BerTlv psmo;
  size_t eim_id_offset;
  uint8_t eim_id_size;
  size_t counter_value_offset;
  size_t counter_value_size;
  size_t transaction_id_offset;
  uint8_t transaction_id_size;
  size_t psmo_offset;
  size_t psmo_size;
  uint8_t *psmo_response = NULL;
  uint32_t psmo_response_size = 0;
  int32_t tlv_response_size;
  enable_profile_request_t enable_profile_request = {0};
  disable_profile_request_t disable_profile_request = {0};
  delete_profile_request_t delete_profile_request = {0};
  profile_info_list_request_t profile_info_list_request = {
      .tag_list = {.iccid = true,
                   .isdp_aid = true,
                   .profile_state = true,
                   .profile_nickname = true,
                   .service_provider_name = true,
                   .profile_name = true,
                   .icon_type = true,
                   .icon = true,
                   .profile_class = true,
                   .notification_configuration_info = true,
                   .profile_owner = true,
                   .smdp_propietary_data = true,
                   .profile_policy_rules = true},
      .field_is_present = {.search_criteria = false, .tag_list = true}};

  if ((rc = esipa_tlv_extractor__euicc_package_request_plain_data(
           euicc_package_request, euicc_package_request_size, &eim_id_offset,
           &eim_id_size, &counter_value_offset, &counter_value_size,
           &transaction_id_offset, &transaction_id_size, &psmo_offset,
           &psmo_size)) != eOk) {
    LOGE("[load_euicc_package_sgp22_translator] Error extracting data from the "
         "EuiccPackageRequest, rc %d",
         rc);
    return -1;
  }

  if ((rc = ber_tlv_parser__ber_tlv_2(euicc_package_request + psmo_offset,
                                      psmo_size, 0, &psmo)) != eOk) {
    LOGE("[load_euicc_package_sgp22_translator] Error parsing the Psmo to TLV, "
         "rc %d",
         rc);
    return -1;
  }

  switch (psmo.tag) {
  case PSMO_ENABLE:
    // Psmo enable
    LOGI("The eUICC package has a PSMO to Enable a Profile");
    if ((rc = esipa_tlv_extractor__iccid_value_from_psmo(
             euicc_package_request + psmo_offset, psmo_size,
             &enable_profile_request.profile_identifier.value.iccid)) == eOk) {
      enable_profile_request.profile_identifier.choice =
          ICCID_PROFILE_IDENTIFIER_CHOICE;
      enable_profile_request.refresh_flag = false;
      err = es10__enable_profile(g_ipa.es10, &enable_profile_request,
                                 &psmo_response, &psmo_response_size);
    } else {
      LOGE("[load_euicc_package_sgp22_translator] Error extracting the iccid "
           "value from the Psmo TLV, rc %d",
           rc);
    }
    break;

  case PSMO_DISABLE:
    // Psmo disable
    LOGI("The eUICC package has a PSMO to Disable a Profile");
    if ((rc = esipa_tlv_extractor__iccid_value_from_psmo(
             euicc_package_request + psmo_offset, psmo_size,
             &disable_profile_request.profile_identifier.value.iccid)) == eOk) {
      disable_profile_request.profile_identifier.choice =
          ICCID_PROFILE_IDENTIFIER_CHOICE;
      disable_profile_request.refresh_flag = false;
      err = es10__disable_profile(g_ipa.es10, &disable_profile_request,
                                  &psmo_response, &psmo_response_size);
    } else {
      LOGE("[load_euicc_package_sgp22_translator] Error extracting the iccid "
           "value from the Psmo TLV, rc %d",
           rc);
    }
    break;

  case PSMO_DELETE:
    // Psmo delete
    LOGI("The eUICC package has a PSMO to Delete a Profile");
    if ((rc = esipa_tlv_extractor__iccid_value_from_psmo(
             euicc_package_request + psmo_offset, psmo_size,
             &delete_profile_request.value.iccid)) == eOk) {
      delete_profile_request.choice = ICCID_PROFILE_IDENTIFIER_CHOICE;
      err = es10__delete_profile(g_ipa.es10, &delete_profile_request,
                                 &psmo_response, &psmo_response_size);
    } else {
      LOGE("[load_euicc_package_sgp22_translator] Error extracting the iccid "
           "value from the Psmo TLV, rc %d",
           rc);
    }
    break;

  case PROFILE_INFO_LIST:
    // Psmo listProfileInfo
    LOGI("The eUICC package has a PSMO to retrieve the list of Profiles");
    LOGI("ES10.GetProfilesInfo");
    LOG_DATA(eLogDebug, "Sending a ProfileInfoListRequest",
             euicc_package_request + psmo_offset, psmo_size);
    /** We should not store data directly from here... We want to invest time on
     * this? */
    err = es10__get_profiles_info(g_ipa.es10, &profile_info_list_request,
                                  &psmo_response, &psmo_response_size);
    break;

  case PSMO_GET_RAT:
    // Psmo getRAT
    LOGI("The eUICC package has a PSMO to retrieve the Rules Authorisation "
         "Table (RAT)");
    rc = es10__get_rat(g_ipa.es10, &psmo_response, &psmo_response_size);
    break;

  default:
    LOGE("[load_euicc_package_sgp22_translator] Unrecognized tag %04X of Psmo "
         "TLV",
         psmo.tag);
    return -1;
  }

  if (rc != eOk || err < 0) {
    LOGE("[load_euicc_package_sgp22_translator] Psmo execution failed, rc %d, "
         "err %d",
         rc, err);
    return -1;
  }
  // Calculate the size of the EuiccPackageResult TLV
  tlv_response_size = esipa_tlv_generator__euicc_package_result(
      NULL, 0, 0, euicc_package_request + eim_id_offset, eim_id_size,
      euicc_package_request + counter_value_offset,
      (uint32_t)counter_value_size,
      euicc_package_request + transaction_id_offset, transaction_id_size,
      psmo_response, psmo_response_size);
  if (tlv_response_size < 0) {
    LOGE("[load_euicc_package_sgp22_translator] Error calculating the size of "
         "the EuiccPackageResult TLV, rc %ld",
         tlv_response_size);
    M_free(psmo_response);
    return -1;
  }
  // Allocate a buffer for the EuiccPackageResult TLV
  *euicc_package_result = (uint8_t *)M_malloc((size_t)tlv_response_size);
  if (!(*euicc_package_result)) {
    LOGE("[load_euicc_package_sgp22_translator] Can not allocate data to "
         "euicc_package_result");
    M_free(psmo_response);
    return -1;
  }
  // Fill the allocated buffer with the EuiccPackageResult TLV
  tlv_response_size = esipa_tlv_generator__euicc_package_result(
      *euicc_package_result, (uint32_t)tlv_response_size, 0,
      euicc_package_request + eim_id_offset, eim_id_size,
      euicc_package_request + counter_value_offset,
      (uint32_t)counter_value_size,
      euicc_package_request + transaction_id_offset, transaction_id_size,
      psmo_response, psmo_response_size);
  M_free(psmo_response);
  psmo_response = NULL;
  if (tlv_response_size < 0) {
    LOGE("[load_euicc_package_sgp22_translator] Error generating the "
         "EuiccPackageResult TLV, rc %ld",
         tlv_response_size);
    M_free(*euicc_package_result);
    *euicc_package_result = NULL;
    return -1;
  }

  *euicc_package_result_size = (uint32_t)tlv_response_size;
  LOG_DATA(eLogDebug,
           "[load_euicc_package_sgp22_translator] EuiccPackageResult TLV",
           *euicc_package_result, *euicc_package_result_size);

  return 0;
}
#endif
