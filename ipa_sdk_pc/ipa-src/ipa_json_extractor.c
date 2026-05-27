/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include "ipa_json_extractor.h"
#include "json_data_extractor.h"
#include "base64.h"
#include "byte_utils.h"
#include "tlv_values.h"
#include "log.h"

// EuiccMemoryResetRequest 
#define DELETE_OPERATIONAL_PROFILES_JSON_KEY        "deleteOperationalProfiles"
#define DELETE_FIELD_LOADED_TEST_PROFILES_JSON_KEY  "deleteFieldLoadedTestProfiles"
#define RESET_DEFAULT_SMDP_ADDRESS_JSON_KEY         "resetDefaultSmdpAddress"
#ifdef SGP32
#define DELETE_PRE_LOADED_TEST_PROFILES_JSON_KEY    "deletePreLoadedTestProfiles"
#define DELETE_PROVISIONING_PROFILES_JSON_KEY       "deleteProvisioningProfiles"
#define RESET_EIM_CONFIG_DATA_JSON_KEY              "resetEimConfigData"
#define RESET_IMMEDIATE_ENABLE_CONFIG_JSON_KEY      "resetImmediateEnableConfig"
#endif

// SetDefaultDpAddressRequest
#define DEFAULT_DP_ADDRESS_JSON_KEY         "defaultDpAddress"

// EimConfigurationData
#define EIM_ID_JSON_KEY                     "\"eimId\""
#define EIM_FQDN_JSON_KEY                   "\"eimFqdn\""
#define EIM_ID_TYPE_JSON_KEY                "\"eimIdType\""
#define COUNTER_VALUE_JSON_KEY              "\"counterValue\""
#define ASSOCIATION_TOKEN_JSON_KEY          "\"associationToken\""
#define EIM_PUBLIC_KEY_JSON_KEY             "\"eimPublicKey\""
#define EIM_CERTIFICATE_JSON_KEY            "\"eimCertificate\""
#define TRUSTED_EIM_PK_TLS_JSON_KEY         "\"trustedEimPkTls\""
#define TRUSTED_CERTIFICATE_TLS_JSON_KEY    "\"trustedCertificateTls\""
#define EIM_RETRIEVE_HTTPS_JSON_KEY         "\"eimRetrieveHttps\""
#define EIM_RETRIEVE_COAPS_JSON_KEY         "\"eimRetrieveCoaps\""
#define EIM_INJECT_HTTPS_JSON_KEY           "\"eimInjectHttps\""
#define EIM_INJECT_COAPS_JSON_KEY           "\"eimInjectCoaps\""
#define EIM_PROPIETARY_JSON_KEY             "\"eimProprietary\""
#define EUICC_CI_PK_ID_JSON_KEY             "\"euiccCiPKId\""
#define INDIRECT_PROFILE_DOWNLOAD_JSON_KEY  "\"indirectProfileDownload\""

// ConfigureImmediateProfileEnablingRequest
#define IMMEDIATE_ENABLE_FLAG_JSON_KEY   "\"immediateEnableFlag\""
#define DEFAULT_SMDP_OID_JSON_KEY           "\"defaultSmdpOid\""
#define DEFAULT_SMDP_ADDRESS_JSON_KEY       "\"defaultSmdpAddress\""


ErrCode ipa_json_extractor__euicc_memory_reset_request(const unsigned char* json, uint32_t json_len, euicc_memory_reset_request_t* obj) {
    ErrCode rc;

    if (!json || 0 == json_len) {
        LOGE("[ipa_json_extractor__euicc_memory_reset_request] json parameter is empty/null");
        return eBadArg;
    }

    if (!obj) {
        LOGE("[ipa_json_extractor__euicc_memory_reset_request] eUICC memory reset request is empty/null");
        return eBadArg;
    }

    /* All the fields are OPTIONAL */
    // deleteOperationalProfiles
    if ((rc = json_data_extractor__get_boolean_value(json, json_len, DELETE_OPERATIONAL_PROFILES_JSON_KEY, &obj->delete_operational_profiles)) == eOk) {
        LOGD("[ipa_json_extractor__euicc_memory_reset_request] deleteOperationalProfiles: %d", obj->delete_operational_profiles);
    } else {
        LOGD("[ipa_json_extractor__euicc_memory_reset_request] Can not get the value of %s, assuming false value, rc %d", DELETE_OPERATIONAL_PROFILES_JSON_KEY, rc);
        obj->delete_operational_profiles = false;
    }
    // deleteFieldLoadedTestProfiles
    if ((rc = json_data_extractor__get_boolean_value(json, json_len, DELETE_FIELD_LOADED_TEST_PROFILES_JSON_KEY, &obj->delete_field_loaded_test_profiles)) == eOk) {
        LOGD("[ipa_json_extractor__euicc_memory_reset_request] deleteFieldLoadedTestProfiles: %d", obj->delete_field_loaded_test_profiles);
    } else {
        LOGD("[ipa_json_extractor__euicc_memory_reset_request] Can not get the value of %s, assuming false value, rc %d", DELETE_FIELD_LOADED_TEST_PROFILES_JSON_KEY, rc);
        obj->delete_field_loaded_test_profiles = false;
    }
    // resetDefaultSmdpAddress
    if ((rc = json_data_extractor__get_boolean_value(json, json_len, RESET_DEFAULT_SMDP_ADDRESS_JSON_KEY, &obj->reset_default_smdp_address)) == eOk) {
        LOGD("[ipa_json_extractor__euicc_memory_reset_request] resetDefaultSmdpAddress: %d", obj->reset_default_smdp_address);
    } else {
        LOGD("[ipa_json_extractor__euicc_memory_reset_request] Can not get the value of %s, assuming false value, rc %d", RESET_DEFAULT_SMDP_ADDRESS_JSON_KEY, rc);
        obj->reset_default_smdp_address = false;
    }
#ifdef SGP32
    // deletePreLoadedTestProfiles
    if ((rc = json_data_extractor__get_boolean_value(json, json_len, DELETE_PRE_LOADED_TEST_PROFILES_JSON_KEY, &obj->delete_preloaded_test_profiles)) == eOk) {
        LOGD("[ipa_json_extractor__euicc_memory_reset_request] deletePreLoadedTestProfiles: %d", obj->delete_preloaded_test_profiles);
    }
    else {
        LOGD("[ipa_json_extractor__euicc_memory_reset_request] Can not get the value of %s, assuming false value, rc %d", DELETE_PRE_LOADED_TEST_PROFILES_JSON_KEY, rc);
        obj->delete_preloaded_test_profiles = false;
    }
    // deleteProvisioningProfiles
    if ((rc = json_data_extractor__get_boolean_value(json, json_len, DELETE_PROVISIONING_PROFILES_JSON_KEY, &obj->delete_provisioning_profiles)) == eOk) {
        LOGD("[ipa_json_extractor__euicc_memory_reset_request] deleteProvisioningProfiles: %d", obj->delete_provisioning_profiles);
    }
    else {
        LOGD("[ipa_json_extractor__euicc_memory_reset_request] Can not get the value of %s, assuming false value, rc %d", DELETE_PROVISIONING_PROFILES_JSON_KEY, rc);
        obj->delete_provisioning_profiles = false;
    }
    // resetEimConfigData
    if ((rc = json_data_extractor__get_boolean_value(json, json_len, RESET_EIM_CONFIG_DATA_JSON_KEY, &obj->reset_eim_config_data)) == eOk) {
        LOGD("[ipa_json_extractor__euicc_memory_reset_request] resetEimConfigData: %d", obj->reset_eim_config_data);
    } else {
        LOGD("[ipa_json_extractor__euicc_memory_reset_request] Can not get the value of %s, assuming false value, rc %d", RESET_EIM_CONFIG_DATA_JSON_KEY, rc);
        obj->reset_eim_config_data = false;
    }
    // resetImmediateEnableConfig
    if ((rc = json_data_extractor__get_boolean_value(json, json_len, RESET_IMMEDIATE_ENABLE_CONFIG_JSON_KEY, &obj->reset_immediate_enable_config)) == eOk) {
        LOGD("[ipa_json_extractor__euicc_memory_reset_request] resetImmediateEnableConfig: %d", obj->reset_immediate_enable_config);
    }
    else {
        LOGD("[ipa_json_extractor__euicc_memory_reset_request] Can not get the value of %s, assuming false value, rc %d", RESET_IMMEDIATE_ENABLE_CONFIG_JSON_KEY, rc);
        obj->reset_immediate_enable_config = false;
    }
#endif

    return eOk;
}

ErrCode ipa_json_extractor__set_default_dp_address_request(const unsigned char* json, uint32_t json_len, set_default_dp_address_request_t* obj) {
    ErrCode rc;

    if (!json || 0 == json_len) {
        LOGE("[ipa_json_extractor__set_default_dp_address_request] json parameter is empty/null");
        return eBadArg;
    }

    if (!obj) {
        LOGE("[ipa_json_extractor__set_default_dp_address_request] Set Default Dp Address request is empty/null");
        return eBadArg;
    }

    /* OPTIONAL fields */
    // defaultDpAddress
    if ((rc = json_data_extractor__get_string_value(json, json_len, DEFAULT_DP_ADDRESS_JSON_KEY, &obj->default_dp_address, &obj->default_dp_address_len)) == eOk) {
        LOG_UTF8_DATA(eLogDebug, "[ipa_json_extractor__set_default_dp_address_request] smdpAddress: ", obj->default_dp_address, obj->default_dp_address_len);
    } else {
        LOGD("[ipa_json_extractor__set_default_dp_address_request] Can not get the value of %s, assuming is not present, rc %d", DEFAULT_DP_ADDRESS_JSON_KEY, rc);
        obj->default_dp_address = NULL;
        obj->default_dp_address_len = 0;
    }

    return eOk;
}

#ifdef SGP32
ErrCode ipa_json_extractor__eim_configuration_data(unsigned char* json, uint32_t json_len, eim_configuration_data_t* obj) {
    ErrCode rc;
    int tmp;
    unsigned char* euicc_ci_pk_id;
    uint32_t euicc_ci_pk_id_len;
    int32_t base64_written_bytes;

    if (!json || 0 == json_len) {
        LOGE("[ipa_json_extractor__eim_configuration_data] json parameter is empty/null");
        return eBadArg;
    }

    if (!obj) {
        LOGE("[ipa_json_extractor__eim_configuration_data] Eim Configuration Data is empty/null");
        return eBadArg;
    }

    /* First the REQUIRED fields */
    // eimId
    if ((rc = json_data_extractor__get_string_value(json, json_len, EIM_ID_JSON_KEY, (unsigned char**) &obj->eim_id, &obj->eim_id_len)) == eOk) {
        LOG_UTF8_DATA(eLogDebug, "[ipa_json_extractor__eim_configuration_data] eimId: ", obj->eim_id, obj->eim_id_len);
    } else {
        LOGE("[ipa_json_extractor__eim_configuration_data] Can not get the value of %s, rc %d", EIM_ID_JSON_KEY, rc);
        obj->eim_id = NULL;
        obj->eim_id_len = 0;
        return rc;
    }

    /* OPTIONAL fields */
    // eimFqdn
    if ((rc = json_data_extractor__get_string_value(json, json_len, EIM_FQDN_JSON_KEY, (unsigned char**) &obj->eim_fqdn, &obj->eim_fqdn_len)) == eOk) {
        LOG_UTF8_DATA(eLogDebug, "[ipa_json_extractor__eim_configuration_data] eimFqdn: ", obj->eim_fqdn, obj->eim_fqdn_len);
        obj->field_is_present.eim_fqdn = true;
    } else {
        LOGD("[ipa_json_extractor__eim_configuration_data] Can not get the value of %s, assuming is not present, rc %d", EIM_FQDN_JSON_KEY, rc);
        obj->field_is_present.eim_fqdn = false;
    }
    // eimIdType
    if ((rc = json_data_extractor__get_int_value(json, json_len, EIM_ID_TYPE_JSON_KEY, &tmp)) == eOk) {
        if (EIM_ID_TYPE_OID == tmp || EIM_ID_TYPE_FQDN == tmp || EIM_ID_TYPE_PROPIETARY == tmp) {
            obj->eim_id_type = tmp;
            obj->field_is_present.eim_id_type = true;
        } else {
            LOGE("[ipa_json_extractor__eim_configuration_data] Bad format of the eimIdType. The eimIdType can only have the values %u, %u, or %u. Current value %d", EIM_ID_TYPE_OID, EIM_ID_TYPE_FQDN, EIM_ID_TYPE_PROPIETARY, tmp);
            return eFatal;
        }
    } else {
        LOGD("[ipa_json_extractor__eim_configuration_data] Can not get the value of %s, assuming is not present, rc %d", EIM_ID_TYPE_JSON_KEY, rc);
        obj->field_is_present.eim_id_type = false;
    }
    // counterValue
    if ((rc = json_data_extractor__get_int_value(json, json_len, COUNTER_VALUE_JSON_KEY, &tmp)) == eOk) {
        LOGD("[ipa_json_extractor__eim_configuration_data] counterValue: %d", tmp);
        if (tmp < 0) {
            LOGE("[ipa_json_extractor__eim_configuration_data] Bad format of the counterValue. The counterValue SHALL be a positive valuse. Current value %d", tmp);
            return eFatal;
        } else {
            obj->field_is_present.counter_value = true;
            obj->counter_value = (uint32_t) tmp;
        }
    } else {
        LOGD("[ipa_json_extractor__eim_configuration_data] Can not get the value of %s, assuming is not present, rc %d", COUNTER_VALUE_JSON_KEY, rc);
            obj->field_is_present.counter_value = false;
    }
    // associationToken
    if ((rc = json_data_extractor__get_boolean_value(json, json_len, ASSOCIATION_TOKEN_JSON_KEY, &obj->field_is_present.association_token)) == eOk) {
        LOGD("[ipa_json_extractor__eim_configuration_data] configure associationToken: %d", obj->field_is_present.association_token);
    } else {
        obj->field_is_present.association_token = false;
        LOGD("[ipa_json_extractor__eim_configuration_data] Can not get the value of %s, assuming is not present, rc %d", ASSOCIATION_TOKEN_JSON_KEY, rc);
    }
    // eimPublicKeyData
    if ((rc = json_data_extractor__get_string_value(json, json_len, EIM_PUBLIC_KEY_JSON_KEY, (unsigned char**) &obj->eim_public_key_data.value, &obj->eim_public_key_data.value_size)) == eOk) {
        LOG_UTF8_DATA(eLogDebug, "[ipa_json_extractor__eim_configuration_data] eimPublicKeyData: ", obj->eim_public_key_data.value, obj->eim_public_key_data.value_size);
        obj->field_is_present.eim_public_key_data = true;
        obj->eim_public_key_data.choice = EIM_PUBLIC_KEY_CHOICE;
    } else {
        LOGD("[ipa_json_extractor__eim_configuration_data] Can not get the value of %s, rc %d. Searching for %s", EIM_PUBLIC_KEY_JSON_KEY, rc, EIM_CERTIFICATE_JSON_KEY);
        if ((rc = json_data_extractor__get_string_value(json, json_len, EIM_CERTIFICATE_JSON_KEY, (unsigned char**) &obj->eim_public_key_data.value, &obj->eim_public_key_data.value_size)) == eOk) {
            LOG_UTF8_DATA(eLogDebug, "[ipa_json_extractor__eim_configuration_data] eimPublicKeyData: ", obj->eim_public_key_data.value, obj->eim_public_key_data.value_size);
            obj->field_is_present.eim_public_key_data = true;
            obj->eim_public_key_data.choice = EIM_CERTIFICATE_CHOICE;
        } else {
            LOGD("[ipa_json_extractor__eim_configuration_data] Can not get the value of %s, assuming eimPublicKeyData is not present, rc %d", EIM_CERTIFICATE_JSON_KEY, rc);
            obj->field_is_present.eim_public_key_data = false;
        }
    }
    // trustedPublicKeyDataTls 
    if ((rc = json_data_extractor__get_string_value(json, json_len, TRUSTED_EIM_PK_TLS_JSON_KEY, (unsigned char**) &obj->trusted_public_key_data_tls.value, &obj->trusted_public_key_data_tls.value_size)) == eOk) {
        LOG_UTF8_DATA(eLogDebug, "[ipa_json_extractor__eim_configuration_data] trustedPublicKeyDataTls: ", obj->trusted_public_key_data_tls.value, obj->trusted_public_key_data_tls.value_size);
        obj->field_is_present.trusted_public_key_data_tls = true;
        obj->trusted_public_key_data_tls.choice = TRUSTED_EIM_PK_TLS_CHOICE;
    } else {
        LOGD("[ipa_json_extractor__eim_configuration_data] Can not get the value of %s, rc %d. Searching for %s", TRUSTED_EIM_PK_TLS_JSON_KEY, rc, TRUSTED_CERTIFICATE_TLS_JSON_KEY);
        if ((rc = json_data_extractor__get_string_value(json, json_len, TRUSTED_CERTIFICATE_TLS_JSON_KEY, (unsigned char**) &obj->trusted_public_key_data_tls.value, &obj->trusted_public_key_data_tls.value_size)) == eOk) {
            LOG_UTF8_DATA(eLogDebug, "[ipa_json_extractor__eim_configuration_data] trustedPublicKeyDataTls: ", obj->trusted_public_key_data_tls.value, obj->trusted_public_key_data_tls.value_size);
            obj->field_is_present.trusted_public_key_data_tls = true;
            obj->trusted_public_key_data_tls.choice = TRUSTED_CERTIFICATE_TLS_CHOICE;
        } else {
            LOGD("[ipa_json_extractor__eim_configuration_data] Can not get the value of %s, assuming trustedPublicKeyDataTls is not present, rc %d", TRUSTED_CERTIFICATE_TLS_JSON_KEY, rc);
            obj->field_is_present.trusted_public_key_data_tls = false;
        }
    }
    // eimSupportedProtocol
    if ((rc = json_data_extractor__get_boolean_value(json, json_len, EIM_RETRIEVE_HTTPS_JSON_KEY, &obj->eim_supported_protocol.eim_retrieve_https)) == eOk) {
        LOGD("[ipa_json_extractor__eim_configuration_data] eimRetrieveHttps: %d", obj->eim_supported_protocol.eim_retrieve_https);
        obj->field_is_present.eim_supported_protocol = true;
    } else {
        LOGD("[ipa_json_extractor__eim_configuration_data] Can not get the value of %s, assuming false value, rc %d", EIM_RETRIEVE_HTTPS_JSON_KEY, rc);
        obj->eim_supported_protocol.eim_retrieve_https = false;
    }
    if ((rc = json_data_extractor__get_boolean_value(json, json_len, EIM_RETRIEVE_COAPS_JSON_KEY, &obj->eim_supported_protocol.eim_retrieve_coaps)) == eOk) {
        LOGD("[ipa_json_extractor__eim_configuration_data] eimRetrieveCoaps: %d", obj->eim_supported_protocol.eim_retrieve_coaps);
        obj->field_is_present.eim_supported_protocol = true;
    } else {
        LOGD("[ipa_json_extractor__eim_configuration_data] Can not get the value of %s, assuming false value, rc %d", EIM_RETRIEVE_COAPS_JSON_KEY, rc);
        obj->eim_supported_protocol.eim_retrieve_coaps = false;
    }
    if ((rc = json_data_extractor__get_boolean_value(json, json_len, EIM_INJECT_HTTPS_JSON_KEY, &obj->eim_supported_protocol.eim_inject_https)) == eOk) {
        LOGD("[ipa_json_extractor__eim_configuration_data] eimInjectHttps: %d", obj->eim_supported_protocol.eim_inject_https);
        obj->field_is_present.eim_supported_protocol = true;
    } else {
        LOGD("[ipa_json_extractor__eim_configuration_data] Can not get the value of %s, assuming false value, rc %d", EIM_INJECT_HTTPS_JSON_KEY, rc);
        obj->eim_supported_protocol.eim_inject_https = false;
    }
    if ((rc = json_data_extractor__get_boolean_value(json, json_len, EIM_INJECT_COAPS_JSON_KEY, &obj->eim_supported_protocol.eim_inject_coaps)) == eOk) {
        LOGD("[ipa_json_extractor__eim_configuration_data] eimInjectCoaps: %d", obj->eim_supported_protocol.eim_inject_coaps);
        obj->field_is_present.eim_supported_protocol = true;
    } else {
        LOGD("[ipa_json_extractor__eim_configuration_data] Can not get the value of %s, assuming false value, rc %d", EIM_INJECT_COAPS_JSON_KEY, rc);
        obj->eim_supported_protocol.eim_inject_coaps = false;
    }
    if ((rc = json_data_extractor__get_boolean_value(json, json_len, EIM_PROPIETARY_JSON_KEY, &obj->eim_supported_protocol.eim_proprietary)) == eOk) {
        LOGD("[ipa_json_extractor__eim_configuration_data] eimProprietary: %d", obj->eim_supported_protocol.eim_proprietary);
        obj->field_is_present.eim_supported_protocol = true;
    } else {
        LOGD("[ipa_json_extractor__eim_configuration_data] Can not get the value of %s, assuming false value, rc %d", EIM_PROPIETARY_JSON_KEY, rc);
        obj->eim_supported_protocol.eim_proprietary = false;
    }
    // euiccCiPKId
    if ((rc = json_data_extractor__get_string_value(json, json_len, EUICC_CI_PK_ID_JSON_KEY, &euicc_ci_pk_id, &euicc_ci_pk_id_len)) == eOk) {
        LOG_UTF8_DATA(eLogDebug, "[ipa_json_extractor__eim_configuration_data] euiccCiPKId: ", euicc_ci_pk_id, euicc_ci_pk_id_len);
        if ((rc = byte_utils__hex_string_to_byte_array(euicc_ci_pk_id, euicc_ci_pk_id_len, obj->euicc_ci_pk_id.value, sizeof(obj->euicc_ci_pk_id.value))) != eOk) {
            LOGE("[ipa_json_extractor__eim_configuration_data] Bad format of the euiccCiPKId. The euiccCiPKId SHALL be an hexadecimal string with fixed size of %u characters. Current number of characters: %u.", sizeof(obj->euicc_ci_pk_id.value) * 2, euicc_ci_pk_id_len);
            return rc;
        }
        obj->field_is_present.euicc_ci_pk_id = true;
    } else {
        LOGD("[ipa_json_extractor__eim_configuration_data] Can not get the value of %s, assuming is not present, rc %d", EUICC_CI_PK_ID_JSON_KEY, rc);
        obj->field_is_present.euicc_ci_pk_id = false;
    }
    // indirectProfileDownload
    if ((rc = json_data_extractor__get_boolean_value(json, json_len, INDIRECT_PROFILE_DOWNLOAD_JSON_KEY, &obj->field_is_present.indirect_profile_download)) == eOk) {
        LOGD("[ipa_json_extractor__eim_configuration_data] indirectProfileDownload: %d", obj->field_is_present.indirect_profile_download);
    } else {
        LOGD("[ipa_json_extractor__eim_configuration_data] Can not get the value of %s, assuming false value, rc %d", INDIRECT_PROFILE_DOWNLOAD_JSON_KEY, rc);
        obj->field_is_present.indirect_profile_download = false;
    }

    /* Parse the base64 in place, overwriting the json string buffer */
    if (obj->field_is_present.eim_public_key_data) {
        if ((base64_written_bytes = base64__decode((unsigned char*) obj->eim_public_key_data.value, obj->eim_public_key_data.value_size, (unsigned char*) obj->eim_public_key_data.value, obj->eim_public_key_data.value_size)) < 0) {
            LOGE("[ipa_json_extractor__eim_configuration_data] Error parsing the base64 eimPublicKeyData, err %d", base64_written_bytes);
            return eFatal;
        }
        obj->eim_public_key_data.value_size = (uint32_t) base64_written_bytes;
        LOG_DATA(eLogDebug, "[ipa_json_extractor__eim_configuration_data] eimPublicKeyData", obj->eim_public_key_data.value, obj->eim_public_key_data.value_size);
    }

    if (obj->field_is_present.trusted_public_key_data_tls) {
        if ((base64_written_bytes = base64__decode((unsigned char*) obj->trusted_public_key_data_tls.value, obj->trusted_public_key_data_tls.value_size, (unsigned char*) obj->trusted_public_key_data_tls.value, obj->trusted_public_key_data_tls.value_size)) < 0) {
            LOGE("[ipa_json_extractor__eim_configuration_data] Error parsing the base64 trustedPublicKeyDataTls, err %d", base64_written_bytes);
            return eFatal;
        }
        obj->trusted_public_key_data_tls.value_size = (uint32_t) base64_written_bytes;
        LOG_DATA(eLogDebug, "[ipa_json_extractor__eim_configuration_data] trustedPublicKeyDataTls", obj->trusted_public_key_data_tls.value, obj->trusted_public_key_data_tls.value_size);
    }
    
    return eOk;
}

ErrCode ipa_json_extractor__configure_immediate_profile_enabling_request(const unsigned char* json, uint32_t json_len, configure_immediate_profile_enabling_request_t* obj) {
    ErrCode rc;

    if (!json || 0 == json_len) {
        LOGE("[ipa_json_extractor__configure_immediate_profile_enabling_request] json parameter is empty/null");
        return eBadArg;
    }

    if (!obj) {
        LOGE("[ipa_json_extractor__configure_immediate_profile_enabling_request] Configure Immediate Profile Enabling request is empty/null");
        return eBadArg;
    }

    /* OPTIONAL fields */
    // immediateEnableFlag
    if ((rc = json_data_extractor__get_boolean_value(json, json_len, IMMEDIATE_ENABLE_FLAG_JSON_KEY, &obj->field_is_present.immediate_enable_flag)) == eOk) {
        if (obj->field_is_present.immediate_enable_flag) {
            LOGD("[ipa_json_extractor__configure_immediate_profile_enabling_request] autoEnableFlag is present");
        } else {
            LOGD("[ipa_json_extractor__configure_immediate_profile_enabling_request] autoEnableFlag is not present");
        }
    } else {
        obj->field_is_present.immediate_enable_flag = false;
        LOGD("[ipa_json_extractor__configure_immediate_profile_enabling_request] Can not get the value of %s, assuming autoEnableFlag is not present, rc %d", IMMEDIATE_ENABLE_FLAG_JSON_KEY, rc);
    }
    // defaultSmdpOid
    if ((rc = json_data_extractor__get_string_value(json, json_len, DEFAULT_SMDP_OID_JSON_KEY, &obj->default_smdp_oid, &obj->default_smdp_oid_len)) == eOk) {
        LOG_UTF8_DATA(eLogDebug, "[ipa_json_extractor__configure_immediate_profile_enabling_request] smdpOid: ", obj->default_smdp_oid, obj->default_smdp_oid_len);
        obj->field_is_present.default_smdp_oid = true;
    } else {
        LOGD("[ipa_json_extractor__configure_immediate_profile_enabling_request] Can not get the value of %s, assuming smdpOid is not present, rc %d", DEFAULT_SMDP_OID_JSON_KEY, rc);
        obj->field_is_present.default_smdp_oid = false;
    }
    // defaultSmdpAddress 
    if ((rc = json_data_extractor__get_string_value(json, json_len, DEFAULT_SMDP_ADDRESS_JSON_KEY, &obj->default_smdp_address, &obj->default_smdp_address_len)) == eOk) {
        LOG_UTF8_DATA(eLogDebug, "[ipa_json_extractor__configure_immediate_profile_enabling_request] smdpAddress: ", obj->default_smdp_address, obj->default_smdp_address_len);
        obj->field_is_present.default_smdp_address = true;
    } else {
        LOGD("[ipa_json_extractor__configure_immediate_profile_enabling_request] Can not get the value of %s, assuming smdpAddress is not present, rc %d", DEFAULT_SMDP_ADDRESS_JSON_KEY, rc);
        obj->field_is_present.default_smdp_address = false;
    }

    return eOk;
}
#endif
