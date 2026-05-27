/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include "es10_display.h"

#include <stdio.h>
#include "es10_tlv_extractor.h"
#include "log.h"
#include "byte_utils.h"

#define STR_BOOL(E) (E ? "true" : "false")

#define STR_CANCEL_SESSION_REASON(E)                                                \
((E) == CANCEL_SESSION_REASON_END_USER_REJECTION ? "endUserRejection" :             \
((E) == CANCEL_SESSION_REASON_POSTPONED ? "postponed" :                             \
((E) == CANCEL_SESSION_REASON_TIMEOUT ? "timeout" :                                 \
((E) == CANCEL_SESSION_REASON_PPR_NOT_ALLOWED ? "pprNotAllowed" :                   \
((E) == CANCEL_SESSION_REASON_METADATA_MISMATCH ? "metadataMismatch" :              \
((E) == CANCEL_SESSION_REASON_LOAD_BPP_EXECUTION_ERROR ? "loadBppExecutionError" :  \
((E) == CANCEL_SESSION_REASON_UNDEFINED_REASON ? "undefinedReason" :                \
"Unknown")))))))
#define STR_NOTIFICATION_EVENT(E)                               \
((E) == NOTIFICATION_EVENT_INSTALL ? "notificationInstall" :    \
((E) == NOTIFICATION_EVENT_ENABLE ? "notificationEnable" :      \
((E) == NOTIFICATION_EVENT_DISABLE ? "notificationDisable" :    \
((E) == NOTIFICATION_EVENT_DELETE ? "notificationDelete" :      \
"Unknown"))))
#define STR_PROFILE_STATE(E) \
((E) == PROFILE_STATE_DISABLED ? "disabled" : \
((E) == PROFILE_STATE_ENABLED ? "enabled" : \
"Unknown"))
#define STR_ICON_TYPE(E) \
((E) == ICON_TYPE_JPG ? "jpg" : \
((E) == ICON_TYPE_PNG ? "png" : \
"Unknown"))
#define STR_PROFILE_CLASS(E)                            \
((E) == PROFILE_CLASS_TEST ? "test" :                   \
((E) == PROFILE_CLASS_PROVISIONING ? "provisioning" :   \
((E) == PROFILE_CLASS_OPERATIONAL ? "operational" :     \
"Unknown")))
#ifdef SGP32
#define STR_EIM_ID_TYPE(E)                                  \
((E) == EIM_ID_TYPE_OID ? "eimIdTypeOid" :                  \
((E) == EIM_ID_TYPE_FQDN ? "eimIdTypeFqdn" :                \
((E) == EIM_ID_TYPE_PROPIETARY ? "eimIdTypeProprietary" :   \
"Unknown")))
#endif

static void es10_display__iccid(const char* title, const char* end, const iccid_t* obj);
static void es10_display__isdp_aid(const char* title, const char* end, const isdp_aid_t* obj);
static void es10_display__subject_key_identifier(const char* title, const char* end, const subject_key_identifier_t* obj);
static void es10_display__transaction_id(const transaction_id_t* obj);
#ifdef SGP22
static void es10_display__profile_identifier(const profile_identifier_t* obj);
#endif

void es10_display__euicc_memory_reset_request(const euicc_memory_reset_request_t* obj) {
    LOGI("ES10.eUICCMemoryReset");
#ifdef SGP22
    LOGI("\tresetOptions(deleteOperationalProfiles=%d, deleteFieldLoadedTestProfiles=%d, resetDefaultSmdpAddress=%d)", obj->delete_operational_profiles, obj->delete_field_loaded_test_profiles, obj->reset_default_smdp_address);
#elif defined(SGP32)
    LOGI("\tresetOptions(deleteOperationalProfiles=%d, deleteFieldLoadedTestProfiles=%d, resetDefaultSmdpAddress=%d, deletePreLoadedTestProfiles=%d, deleteProvisioningProfiles=%d, resetEimConfigData=%d, resetImmediateEnableConfig=%d)", 
        obj->delete_operational_profiles, 
        obj->delete_field_loaded_test_profiles, 
        obj->reset_default_smdp_address, 
        obj->delete_preloaded_test_profiles, 
        obj->delete_provisioning_profiles, 
        obj->reset_eim_config_data, 
        obj->reset_immediate_enable_config);
#endif
}

void es10_display__cancel_session_request(const cancel_session_request_t* obj) {
    LOGI("ES10.CancelSession");
    es10_display__transaction_id(&obj->transaction_id);
    LOGI("\treason(%s)", STR_CANCEL_SESSION_REASON(obj->reason));
}

void es10_display__retrieve_notifications_list_request(const retrieve_notifications_list_request_t* obj) {
    LOGI("ES10.RetrieveNotificationsList");
    if (obj->field_is_present.search_criteria) {
        switch (obj->search_criteria.choice)
        {
        case SEQ_NUMBER_CHOICE:
            LOGI("\tsearchCriteria(seqNumber=%u)", obj->search_criteria.value.seq_number);
            break;
        case PROFILE_MANAGEMENT_OPERATION_CHOICE:
            LOGI("\tsearchCriteria(profileManagementOperation=%s)", STR_NOTIFICATION_EVENT(obj->search_criteria.value.profile_management_operation));
            break;
#ifdef SGP32
        case EUICC_PACKAGE_RESULTS_CHOICE:
            LOGI("\tsearchCriteria(euiccPackageResults)");
            break;
#endif
        default:
            LOGE("[es10_display__retrieve_notifications_list_request] Unknown searchCriteria CHOICE %d", obj->search_criteria.choice);
            break;
        }
    }
}

void es10_display__notification_sent_request(const notification_sent_request_t* obj) {
    LOGI("ES10.RemoveNotificationFromList(seqNumber=%u)", obj->seq_number);
}

void es10_display__profile_info_list_request(const profile_info_list_request_t* obj) {
    LOGI("ES10.GetProfilesInfo");
    if (obj->field_is_present.search_criteria) {
        switch (obj->search_criteria.choice)
        {
        case ISDP_AID_PROFILE_INFO_LIST_CHOICE:
            es10_display__isdp_aid("\tsearchCriteria(isdpAid=", ")", &obj->search_criteria.value.isdp_aid);
            break;
        case ICCID_PROFILE_INFO_LIST_CHOICE:
            es10_display__iccid("\tsearchCriteria(iccid=", ")", &obj->search_criteria.value.iccid);
            break;
        case PROFILE_CLASS_PROFILE_INFO_LIST_CHOICE:
            LOGI("\tsearchCriteria(profileClass=%s)", STR_PROFILE_CLASS(obj->search_criteria.value.profile_class));
            break;
        default:
            LOGE("[es10_display__profile_info_list_request] Unknown searchCriteria CHOICE %d", obj->search_criteria.choice);
            break;
        }
    }
    if (obj->field_is_present.tag_list) {
        LOGI("\ttagList(iccid=%d, isdpAid=%d, profileState=%d, profileNickname=%d, serviceProviderName=%d, profileName=%d, iconType=%d", obj->tag_list.iccid, obj->tag_list.isdp_aid, obj->tag_list.profile_state, obj->tag_list.profile_nickname, obj->tag_list.service_provider_name, obj->tag_list.profile_name, obj->tag_list.icon_type);
        LOGI("\ticon=%d, profileClass=%d, notificationConfigurationInfo=%d, profileOwner=%d, dpProprietaryData=%d, profilePolicyRules=%d)", obj->tag_list.icon, obj->tag_list.profile_class, obj->tag_list.notification_configuration_info, obj->tag_list.profile_owner, obj->tag_list.smdp_propietary_data, obj->tag_list.profile_policy_rules);
    }
}

void es10_display__profile_info(profile_info_t* obj) {
    ErrCode rc;
    uint8_t* notification_config_info_tlv;
    uint32_t notification_config_info_tlv_size;
    notification_configuration_information_t notification_config_info;

    LOGI("ProfileInfo");
    if (obj->field_is_present.iccid) {
        es10_display__iccid("\ticcid=", "", &obj->iccid);
    }
    if (obj->field_is_present.isdp_aid) {
        es10_display__isdp_aid("\tisdpAid=", "", &obj->isdp_aid);
    }
    if (obj->field_is_present.profile_state) {
        LOGI("\tprofileState=%s", STR_PROFILE_STATE(obj->profile_state));
    }
    if (obj->field_is_present.profile_nickname) {
        LOG_UTF8_DATA(eLogInfo, "\tprofileNickname=", obj->profile_nickname.value, obj->profile_nickname.len);
    }
    if (obj->field_is_present.service_provider_name) {
        LOG_UTF8_DATA(eLogInfo, "\tserviceProviderName=", obj->service_provider_name.value, obj->service_provider_name.len);
    }
    if (obj->field_is_present.profile_name) {
        LOG_UTF8_DATA(eLogInfo, "\tprofileName=", obj->profile_name.value, obj->profile_name.len);
    }
    if (obj->field_is_present.icon_type) {
        LOGI("\ticonType=%s", STR_ICON_TYPE(obj->icon_type));
    }
    if (obj->field_is_present.icon) {
        LOG_DATA(eLogInfo, "\ticon", obj->icon.value, obj->icon.size);
    }
    if (obj->field_is_present.profile_class) {
        LOGI("\tprofileClass=%s", STR_PROFILE_CLASS(obj->profile_class));
    }
    if (obj->field_is_present.notification_configuration_info) {
        LOGI("\tnotificationConfigurationInfo");
        while ((rc = tlv_data_extractor__asn1_list_get_next(&obj->notification_configuration_info, &notification_config_info_tlv, &notification_config_info_tlv_size)) == eOk && notification_config_info_tlv != NULL) {
            if ((rc = es10_tlv_extractor__notification_configuration_information(notification_config_info_tlv, notification_config_info_tlv_size, &notification_config_info)) == eOk) {
                LOGI("\t\tprofileManagementOperation=%s", STR_NOTIFICATION_EVENT(notification_config_info.profile_management_operation));
                LOGI("\t\tnotificationAddress=%s", notification_config_info.notification_address.fqdn);
            } else {
                LOGW("[es10_display__profile_info] Error parsing the NotificationConfigurationInformation, rc %d", rc);
            }
        }
        if (rc != eOk) {
            LOGW("[es10_display__profile_info] Error iterating over the NotificationConfigurationInformation List, rc %d", rc);
        }
    }
    if (obj->field_is_present.profile_owner) {
        LOGI("\tprofileOwner");
        LOG_DATA(eLogInfo, "\t\tmccMnc", obj->profile_owner.mcc_mnc.value, sizeof(obj->profile_owner.mcc_mnc.value));
        if (obj->profile_owner.field_is_present.gid1) {
            LOG_DATA(eLogInfo, "\t\tgid1", obj->profile_owner.gid1, obj->profile_owner.gid1_size);
        }
        if (obj->profile_owner.field_is_present.gid2) {
            LOG_DATA(eLogInfo, "\t\tgid2", obj->profile_owner.gid2, obj->profile_owner.gid2_size);
        }
    }
    if (obj->field_is_present.dp_propietary_data) {
        LOGI("\tdpProprietaryData");
        LOG_DATA(eLogInfo, "\t\tdpOid", obj->dp_propietary_data.dp_oid, obj->dp_propietary_data.dp_oid_size);
    }
    if (obj->field_is_present.profile_policy_rules) {
        LOGI("\tprofilePolicyRules=(pprUpdateControl=%s, ppr1=%s, ppr2=%s)", STR_BOOL(obj->profile_policy_rules.ppr_update_control), STR_BOOL(obj->profile_policy_rules.ppr1), STR_BOOL(obj->profile_policy_rules.ppr2));
    }
}


void es10_display__set_default_dp_address_request(const set_default_dp_address_request_t* obj) {
    LOGI("ES10.SetDefaultDpAddress");
    if (obj->default_dp_address_len > 0) {
        LOG_UTF8_DATA(eLogInfo, "\tdefaultDpAddress=", obj->default_dp_address, obj->default_dp_address_len);
    }
}

#ifdef SGP22
void es10_display__list_notification_request(const list_notification_request_t* obj) {
    LOGI("ES10.ListNotification");
    if (obj->field_is_present.profile_management_operation) {
        LOGI("\tprofileManagementOperation(%s)", STR_NOTIFICATION_EVENT(obj->profile_management_operation));
    }
}

void es10_display__enable_profile_request(const enable_profile_request_t* obj) {
    LOGI("ES10.EnableProfile");
    es10_display__profile_identifier(&obj->profile_identifier);
    LOGI("\trefreshFlag=%s", STR_BOOL(obj->refresh_flag));
}

void es10_display__disable_profile_request(const disable_profile_request_t* obj) {
    LOGI("ES10.DisableProfile");
    es10_display__profile_identifier(&obj->profile_identifier);
    LOGI("\trefreshFlag=%s", STR_BOOL(obj->refresh_flag));
}

void es10_display__delete_profile_request(const delete_profile_request_t* obj) {
    LOGI("ES10.DeleteProfile");
    switch (obj->choice)
    {
    case ISDP_AID_PROFILE_IDENTIFIER_CHOICE:
        es10_display__isdp_aid("\tisdpAid=", "", &obj->value.isdp_aid);
        break;
    case ICCID_PROFILE_IDENTIFIER_CHOICE:
        es10_display__iccid("\ticcid=", "", &obj->value.iccid);
        break;
    default:
        LOGE("[es10_display__delete_profile_request] Unknown DeleteProfileRequest CHOICE %d", obj->choice);
        break;
    }
}

void es10_display__set_nickname_request(const set_nickname_request_t* obj) {
    LOGI("ES10.SetNickname");
    es10_display__iccid("\ticcid=", "", &obj->iccid);
    if (obj->profile_nickname.len > 0) {
        LOG_UTF8_DATA(eLogInfo, "\tprofileNickname=", obj->profile_nickname.value, obj->profile_nickname.len);
    }
}
#endif

#ifdef SGP32
void es10_display__add_initial_eim_request(const eim_configuration_data_t* obj) {
    LOGI("ES10.AddInitialEim");
    LOG_UTF8_DATA(eLogInfo, "\teimId=", obj->eim_id, obj->eim_id_len);
    if (obj->field_is_present.eim_fqdn) {
        LOG_UTF8_DATA(eLogInfo, "\teimFqdn=", obj->eim_fqdn, obj->eim_fqdn_len);
    }
    if (obj->field_is_present.eim_id_type) {
        LOGI("\teimIdType(%s)", STR_EIM_ID_TYPE(obj->eim_id_type));
    }
    if (obj->field_is_present.counter_value) {
        LOGI("\tcounterValue=%u", obj->counter_value);
    }
    if (obj->field_is_present.association_token) {
        LOGI("\tassociationToken=true");
    }
    if (obj->field_is_present.eim_public_key_data) {
        switch (obj->eim_public_key_data.choice)
        {
        case EIM_PUBLIC_KEY_CHOICE:
            LOGI("\teimPublicKeyData(eimPublicKey=...)");
            break;
        case EIM_CERTIFICATE_CHOICE:
            LOGI("\teimPublicKeyData(eimCertificate=...)");
            break;
        default:
            LOGE("[es10_display__add_initial_eim_request] Unknown eimPublicKeyData CHOICE %d", obj->eim_public_key_data.choice);
            break;
        }
    }
    if (obj->field_is_present.trusted_public_key_data_tls) {
        switch (obj->trusted_public_key_data_tls.choice)
        {
        case TRUSTED_EIM_PK_TLS_CHOICE:
            LOGI("\ttrustedPublicKeyDataTls(trustedEimPkTls=...)");
            break;
        case TRUSTED_CERTIFICATE_TLS_CHOICE:
            LOGI("\ttrustedPublicKeyDataTls(trustedCertificateTls=...)");
            break;
        default:
            LOGE("[es10_display__add_initial_eim_request] Unknown trustedPublicKeyDataTls CHOICE %d", obj->trusted_public_key_data_tls.choice);
            break;
        }
    }
    if (obj->field_is_present.eim_supported_protocol) {
        LOGI("\teimSupportedProtocol(eimRetrieveHttps=%d, eimRetrieveCoaps=%d, eimInjectHttps=%d, eimInjectCoaps=%d, eimProprietary=%d)",
        obj->eim_supported_protocol.eim_retrieve_https, obj->eim_supported_protocol.eim_retrieve_coaps, obj->eim_supported_protocol.eim_inject_https, obj->eim_supported_protocol.eim_inject_coaps, obj->eim_supported_protocol.eim_proprietary);
    }
    if (obj->field_is_present.euicc_ci_pk_id) {
        es10_display__subject_key_identifier("\teuiccCiPKId=", "", &obj->euicc_ci_pk_id);
    }
    if (obj->field_is_present.indirect_profile_download) {
        LOGI("\tindirectProfileDownload");
    }
}

void es10_display__get_certs_request(const get_certs_request_t* obj) {
    LOGI("ES10.GetCerts");
    if (obj->field_is_present.euicc_ci_pk_id) {
        es10_display__subject_key_identifier("\teuiccCiPKId=", "", &obj->euicc_ci_pk_id);
    }
}

void es10_display__immediate_enable_request(const immediate_enable_request_t* obj) {
    LOGI("ES10.ImmediateEnable(refreshFlag=%d)", obj->refresh_flag);
}

void es10_display__profile_rollback_request(const profile_rollback_request_t* obj) {
    LOGI("ES10.ProfileRollback(refreshFlag=%d)", obj->refresh_flag);
}

void es10_display__configure_immediate_profile_enabling_request(const configure_immediate_profile_enabling_request_t* obj) {
    LOGI("ES10.ConfigureImmediateProfileEnabling");
    if (obj->field_is_present.immediate_enable_flag) {
        LOGI("\timmediateEnableFlag");
    }
    if (obj->field_is_present.default_smdp_oid) {
        LOG_UTF8_DATA(eLogInfo, "\tdefaultSmdpOid=", obj->default_smdp_oid, obj->default_smdp_oid_len);
    }
    if (obj->field_is_present.default_smdp_address) {
        LOG_UTF8_DATA(eLogInfo, "\tdefaultSmdpAddress=", obj->default_smdp_address, obj->default_smdp_address_len);
    }
}

void es10_display__get_eim_configuration_data_request(const get_eim_configuration_data_request_t* obj) {
    LOGI("ES10.GetEimConfigurationData");
    if (obj->field_is_present.search_criteria) {
        switch (obj->search_criteria.choice)
        {
        case EIM_ID:
            LOG_UTF8_DATA(eLogInfo, "\teimId=", obj->search_criteria.value.eim_id.value, obj->search_criteria.value.eim_id.len);
            break;
        default:
            LOGE("[es10_display__get_eim_configuration_data_request] Unknown searchCriteria CHOICE %d", obj->search_criteria.choice);
            break;
        }
    }
}

#ifdef EXTRA_FEATURE_EMERGENCY_PROFILE_MANAGMENT
void es10_display__enable_emergency_profile_request(const enable_emergency_profile_request_t* obj) {
    LOGI("ES10.EnableEmergencyProfile(refreshFlag=%d)", obj->refresh_flag);
}

void es10_display__disable_emergency_profile_request(const disable_emergency_profile_request_t* obj) {
    LOGI("ES10.DisableEmergencyProfile(refreshFlag=%d)", obj->refresh_flag);
}
#endif

#ifdef EXTRA_FEATURE_FALLBACK_MECHANISM
void es10_display__execute_fallback_mechanism_request(const execute_fallback_mechanism_request_t* obj) {
    LOGI("ES10.ExecuteFallbackMechanism(refreshFlag=%d)", obj->refresh_flag);
}

void es10_display__return_from_fallback_request(const return_from_fallback_request_t* obj) {
    LOGI("ES10.ReturnFromFallback(refreshFlag=%d)", obj->refresh_flag);
}
#endif
#endif

static void es10_display__iccid(const char* title, const char* end, const iccid_t* obj) {
    iccid_t plain_iccid = { 0 }; // Just for print the ICCID in plain format
    memcpy(plain_iccid.value, obj->value, sizeof(plain_iccid.value));
    if (byte_utils__iccid_parse_format(&plain_iccid, false) == eOk) {
        LOGI("%s%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%s", 
        title,
        plain_iccid.value[0], plain_iccid.value[1], plain_iccid.value[2], plain_iccid.value[3], plain_iccid.value[4], 
        plain_iccid.value[5], plain_iccid.value[6], plain_iccid.value[7], plain_iccid.value[8], plain_iccid.value[9],
        end);
    } else {
        LOGE("[es10_display__iccid] Bad iccid format");
    }
    
}

static void es10_display__isdp_aid(const char* title, const char* end, const isdp_aid_t* obj) {
    LOGI("%s%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%s", 
    title,
    obj->value[0], obj->value[1], obj->value[2], obj->value[3],
    obj->value[4], obj->value[5], obj->value[6], obj->value[7],
    obj->value[8], obj->value[9], obj->value[10], obj->value[11],
    obj->value[12], obj->value[13], obj->value[14], obj->value[15],
    end);
}

static void es10_display__subject_key_identifier(const char* title, const char* end, const subject_key_identifier_t* obj) {
    LOGI("%s%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%s", 
    title,
    obj->value[0], obj->value[1], obj->value[2], obj->value[3], obj->value[4],
    obj->value[5], obj->value[6], obj->value[7], obj->value[8], obj->value[9],
    obj->value[10], obj->value[11], obj->value[12], obj->value[13], obj->value[14],
    obj->value[15], obj->value[16], obj->value[17], obj->value[18], obj->value[19],
    end);
}

static void es10_display__transaction_id(const transaction_id_t* obj) {
    int err;
    char transaction_id[sizeof(obj->transaction_id) * 2 + 1];

    err = sprintf(transaction_id, "%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X", 
    obj->transaction_id[0], obj->transaction_id[1], obj->transaction_id[2], obj->transaction_id[3],
    obj->transaction_id[4], obj->transaction_id[5], obj->transaction_id[6], obj->transaction_id[7],
    obj->transaction_id[8], obj->transaction_id[9], obj->transaction_id[10], obj->transaction_id[11],
    obj->transaction_id[12], obj->transaction_id[13], obj->transaction_id[14], obj->transaction_id[15]);
    
    if (err < 0) {
        LOGW("[es10_display__transaction_id] Error printing the transactionId, err %d", err);
        return;
    }

    transaction_id[obj->transaction_id_size * 2] = '\0';
    LOGI("\ttransactionId=%s", transaction_id);
}

#ifdef SGP22
static void es10_display__profile_identifier(const profile_identifier_t* obj) {
    switch (obj->choice)
    {
    case ISDP_AID_PROFILE_IDENTIFIER_CHOICE:
        es10_display__isdp_aid("\tprofileIdentifier(isdpAid=", ")", &obj->value.isdp_aid);
        break;
    case ICCID_PROFILE_IDENTIFIER_CHOICE:
        es10_display__iccid("\tprofileIdentifier(iccid=", ")", &obj->value.iccid);
        break;
    default:
        LOGE("[es10_display__profile_identifier] Unknown profileIdentifier CHOICE %d", obj->choice);
        break;
    }
}
#endif
