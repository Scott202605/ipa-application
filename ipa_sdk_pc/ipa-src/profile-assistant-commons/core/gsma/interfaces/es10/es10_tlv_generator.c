/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include "es10_tlv_generator.h"
#include "tlv_generator.h"
#include "byte_utils.h"
#include "tlv_tags.h"
#include "log.h"

static int32_t es10_tlv_generator__authenticate_server_request_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const authenticate_server_request_t* obj);
static int32_t es10_tlv_generator__authenticate_server_request_ctx_params_1(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const authenticate_server_request_ctx_params_1_t* obj);
static int32_t es10_tlv_generator__ctx_params_1(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const ctx_params_1_t* obj);
static int32_t es10_tlv_generator__ctx_params_for_common_authentication_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const ctx_params_for_common_authentication_t* obj);
static int32_t es10_tlv_generator__prepare_download_request_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const prepare_download_request_t* obj);
static int32_t es10_tlv_generator__cancel_session_request_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const cancel_session_request_t* obj);
static int32_t es10_tlv_generator__notification_event(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, unsigned short tag, const notification_event_t obj);
static int32_t es10_tlv_generator__retrieve_notifications_list_request_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const retrieve_notifications_list_request_t* obj);
static int32_t es10_tlv_generator__retrieve_notifications_list_request_search_criteria_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const retrieve_notifications_list_request_search_criteria_t* obj);
static int32_t es10_tlv_generator__profile_info_list_request_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const profile_info_list_request_t* obj);
static int32_t es10_tlv_generator__profile_info_list_request_search_critreria(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const profile_info_list_request_serach_criteria_t* obj);
static int32_t es10_tlv_generator__profile_info_list_request_search_critreria_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const profile_info_list_request_serach_criteria_t* obj);
static int32_t es10_tlv_generator__profile_info_list_request_tag_list(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const profile_info_list_request_tag_list_t* obj);
static int32_t es10_tlv_generator__profile_info_list_request_tag_list_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const profile_info_list_request_tag_list_t* obj);
#ifdef SGP22
static int32_t es10_tlv_generator__list_notification_request_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const list_notification_request_t* obj);
static int32_t es10_tlv_generator__profile_state_change_request_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const profile_state_change_request_t* obj);
static int32_t es10_tlv_generator__profile_identifier(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const profile_identifier_t* obj);
static int32_t es10_tlv_generator__profile_identifier_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const profile_identifier_t* obj);
static int32_t es10_tlv_generator__set_nickname_request_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const set_nickname_request_t* obj);
#endif
#ifdef SGP32
static int32_t es10_tlv_generator__add_initial_eim_request_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const eim_configuration_data_t* obj);
static int32_t es10_tlv_generator__eim_public_key_data(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const eim_public_key_data_t* obj);
static int32_t es10_tlv_generator__trusted_public_key_data_tls(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const trusted_public_key_data_tls_t* obj);
static int32_t es10_tlv_generator__eim_configuration_data(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const eim_configuration_data_t* obj);
static int32_t es10_tlv_generator__eim_configuration_data_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const eim_configuration_data_t* obj);
static int32_t es10_tlv_generator__eim_supported_protocol(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const eim_supported_protocol_t* obj);
static int32_t es10_tlv_generator__get_certs_request_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const get_certs_request_t* obj);
static int32_t es10_tlv_generator__configure_immediate_profile_enabling_request_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const configure_immediate_profile_enabling_request_t* obj);
static int32_t es10_tlv_generator__get_eim_configuration_data_request_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const get_eim_configuration_data_request_t* obj);
static int32_t es10_tlv_generator__get_eim_configuration_data_request_search_criteria_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const get_eim_configuration_data_request_search_criteria_t* obj);
#endif

int32_t es10_tlv_generator__euicc_memory_reset(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const euicc_memory_reset_request_t* obj) {
    int32_t buffer_offset;

    uint8_t reset_options_bit_string[] = { 
        obj->delete_operational_profiles, 
        obj->delete_field_loaded_test_profiles, 
        obj->reset_default_smdp_address,
#ifdef SGP32
        obj->delete_preloaded_test_profiles, 
        obj->delete_provisioning_profiles, 
        obj->reset_eim_config_data, 
        obj->reset_immediate_enable_config
#endif
    };

    // resetOptions
    if ((buffer_offset = tlv_generator__add_tlv_bit_string_value(buffer, buffer_size, offset, MEMORY_RESET_OPTIONS, reset_options_bit_string, sizeof(reset_options_bit_string))) < 0) {
        LOGE("[es10_tlv_generator__euicc_memory_reset] Error on resetOptions BIT STRING, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__euicc_memory_reset] EuiccMemoryResetRequest VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap EuiccMemoryResetRequest VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, EUICC_MEMORY_RESET)) < 0) {
        LOGE("[es10_tlv_generator__euicc_memory_reset] Error on wrapping the EuiccMemoryResetRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__euicc_memory_reset] EuiccMemoryResetRequest TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

int32_t es10_tlv_generator__authenticate_server_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const authenticate_server_request_t* obj) {
    int32_t buffer_offset;

    // AuthenticateServerRequest VALUE
    if ((buffer_offset = es10_tlv_generator__authenticate_server_request_value(buffer, buffer_size, offset, obj)) < 0) {
        LOGE("[es10_tlv_generator__authenticate_server_request] Error on AuthenticateServerRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__authenticate_server_request] AuthenticateServerRequest VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap AuthenticateServerRequest VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, AUTHENTICATE_SERVER)) < 0) {
        LOGE("[es10_tlv_generator__authenticate_server_request] Error on wrapping the AuthenticateServerRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__authenticate_server_request] AuthenticateServerRequest TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

int32_t es10_tlv_generator__prepare_download_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const prepare_download_request_t* obj) {
    int32_t buffer_offset;

    // PrepareDownloadRequest VALUE
    if ((buffer_offset = es10_tlv_generator__prepare_download_request_value(buffer, buffer_size, offset, obj)) < 0) {
        LOGE("[es10_tlv_generator__prepare_download_request] Error on PrepareDownloadRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__prepare_download_request] PrepareDownloadRequest VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap PrepareDownloadRequest VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, PREPARE_DOWNLOAD_REQUEST)) < 0) {
        LOGE("[es10_tlv_generator__prepare_download_request] Error on wrapping the PrepareDownloadRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__prepare_download_request] PrepareDownloadRequest TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

int32_t es10_tlv_generator__cancel_session_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const cancel_session_request_t* obj) {
    int32_t buffer_offset;

    // CancelSessionRequest VALUE
    if ((buffer_offset = es10_tlv_generator__cancel_session_request_value(buffer, buffer_size, offset, obj)) < 0) {
        LOGE("[es10_tlv_generator__cancel_session_request] Error on CancelSessionRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__cancel_session_request] CancelSessionRequest VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap CancelSessionRequest VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, CANCEL_SESSION)) < 0) {
        LOGE("[es10_tlv_generator__cancel_session_request] Error on wrapping the CancelSessionRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__cancel_session_request] CancelSessionRequest TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

int32_t es10_tlv_generator__retrieve_notifications_list_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const retrieve_notifications_list_request_t* obj) {
    int32_t buffer_offset;

    // RetrieveNotificationsListRequest VALUE
    if ((buffer_offset = es10_tlv_generator__retrieve_notifications_list_request_value(buffer, buffer_size, offset, obj)) < 0) {
        LOGE("[es10_tlv_generator__retrieve_notifications_list_request] Error on RetrieveNotificationsListRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__retrieve_notifications_list_request] RetrieveNotificationsListRequest VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap RetrieveNotificationsListRequest VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, RETRIEVE_NOTIF_LIST)) < 0) {
        LOGE("[es10_tlv_generator__retrieve_notifications_list_request] Error on wrapping the RetrieveNotificationsListRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__retrieve_notifications_list_request] RetrieveNotificationsListRequest TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

int32_t es10_tlv_generator__notification_sent_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const notification_sent_request_t* obj) {
    int32_t buffer_offset;

    // NotificationSentRequest VALUE
    if ((buffer_offset = tlv_generator__add_tlv_integer_value(buffer, buffer_size, offset, CONTEXT_PRIMITIVE_0, obj->seq_number)) < 0) {
        LOGE("[es10_tlv_generator__retrieve_notifications_list_request] Error on NotificationSentRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__retrieve_notifications_list_request] NotificationSentRequest VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap NotificationSentRequest VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, NOTIFICATION_SENT)) < 0) {
        LOGE("[es10_tlv_generator__retrieve_notifications_list_request] Error on wrapping the NotificationSentRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__retrieve_notifications_list_request] NotificationSentRequest TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

int32_t es10_tlv_generator__profile_info_list_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const profile_info_list_request_t* obj) {
    int32_t buffer_offset;

    // ProfileInfoListRequest VALUE
    if ((buffer_offset = es10_tlv_generator__profile_info_list_request_value(buffer, buffer_size, offset, obj)) < 0) {
        LOGE("[es10_tlv_generator__profile_info_list_request] Error on ProfileInfoListRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__profile_info_list_request] ProfileInfoListRequest VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap ProfileInfoListRequest VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, PROFILE_INFO_LIST)) < 0) {
        LOGE("[es10_tlv_generator__profile_info_list_request] Error on wrapping the ProfileInfoListRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__profile_info_list_request] ProfileInfoListRequest TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

int32_t es10_tlv_generator__set_default_dp_address_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const set_default_dp_address_request_t* obj) {
    int32_t buffer_offset;

    // defaultDpAddress
    if ((buffer_offset = tlv_generator__add_tlv(buffer, buffer_size, offset, CONTEXT_PRIMITIVE_0, (uint8_t*) obj->default_dp_address, obj->default_dp_address_len)) < 0) {
        LOGE("[es10_tlv_generator__set_default_dp_address_request] Error on defaultDpAddress, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__set_default_dp_address_request] SetDefaultDpAddressRequest VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap SetDefaultDpAddressRequest VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, SET_DEFAULT_SMDP_ADDRESS)) < 0) {
        LOGE("[es10_tlv_generator__set_default_dp_address_request] Error on wrapping the SetDefaultDpAddressRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__set_default_dp_address_request] SetDefaultDpAddressRequest TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

#ifdef SGP22
int32_t es10_tlv_generator__list_notification_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const list_notification_request_t* obj) {
    int32_t buffer_offset;

    // ListNotificationRequest VALUE
    if ((buffer_offset = es10_tlv_generator__list_notification_request_value(buffer, buffer_size, offset, obj)) < 0) {
        LOGE("[es10_tlv_generator__list_notification_request] Error on ListNotificationRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__list_notification_request] ListNotificationRequest VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap ListNotificationRequest VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, LIST_NOTIFICATION)) < 0) {
        LOGE("[es10_tlv_generator__list_notification_request] Error on wrapping the ListNotificationRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__list_notification_request] ListNotificationRequest TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

int32_t es10_tlv_generator__enable_profile_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const enable_profile_request_t* obj) {
    int32_t buffer_offset;

    // EnableProfileRequest VALUE
    if ((buffer_offset = es10_tlv_generator__profile_state_change_request_value(buffer, buffer_size, offset, (profile_state_change_request_t*) obj)) < 0) {
        LOGE("[es10_tlv_generator__enable_profile_request] Error on EnableProfileRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__enable_profile_request] EnableProfileRequest VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap EnableProfileRequest VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, ENABLE_PROFILE)) < 0) {
        LOGE("[es10_tlv_generator__enable_profile_request] Error on wrapping the EnableProfileRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__enable_profile_request] EnableProfileRequest TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

int32_t es10_tlv_generator__disable_profile_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const disable_profile_request_t* obj) {
    int32_t buffer_offset;

    // DisableProfileRequest VALUE
    if ((buffer_offset = es10_tlv_generator__profile_state_change_request_value(buffer, buffer_size, offset, (profile_state_change_request_t*) obj)) < 0) {
        LOGE("[es10_tlv_generator__disable_profile_request] Error on DisableProfileRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__disable_profile_request] DisableProfileRequest VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap DisableProfileRequest VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, DISABLE_PROFILE)) < 0) {
        LOGE("[es10_tlv_generator__disable_profile_request] Error on wrapping the DisableProfileRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__disable_profile_request] DisableProfileRequest TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

int32_t es10_tlv_generator__delete_profile_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const delete_profile_request_t* obj) {
    int32_t buffer_offset;

    // DeleteProfileRequest VALUE
    if ((buffer_offset = es10_tlv_generator__profile_identifier_value(buffer, buffer_size, offset, (profile_identifier_t*) obj)) < 0) {
        LOGE("[es10_tlv_generator__delete_profile_request] Error on DeleteProfileRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__delete_profile_request] DeleteProfileRequest VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap DeleteProfileRequest VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, DELETE_PROFILE)) < 0) {
        LOGE("[es10_tlv_generator__delete_profile_request] Error on wrapping the DeleteProfileRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__delete_profile_request] DeleteProfileRequest TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

int32_t es10_tlv_generator__set_nickname_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const set_nickname_request_t* obj) {
    int32_t buffer_offset;

    // SetNicknameRequest VALUE
    if ((buffer_offset = es10_tlv_generator__set_nickname_request_value(buffer, buffer_size, offset, obj)) < 0) {
        LOGE("[es10_tlv_generator__set_nickname_request] Error on SetNicknameRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__set_nickname_request] SetNicknameRequest VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap SetNicknameRequest VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, SET_NICKNAME)) < 0) {
        LOGE("[es10_tlv_generator__set_nickname_request] Error on wrapping the SetNicknameRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__set_nickname_request] SetNicknameRequest TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}
#endif

#ifdef SGP32
int32_t es10_tlv_generator__add_initial_eim_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const eim_configuration_data_t* obj) {
    int32_t buffer_offset;

    // AddInitialEimRequest VALUE
    if ((buffer_offset = es10_tlv_generator__add_initial_eim_request_value(buffer, buffer_size, offset, obj)) < 0) {
        LOGE("[es10_tlv_generator__add_initial_eim_request] Error on AddInitialEimRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__add_initial_eim_request] AddInitialEimRequest VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap AddInitialEimRequest VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, ADD_INITIAL_EIM)) < 0) {
        LOGE("[es10_tlv_generator__add_initial_eim_request] Error on wrapping the AddInitialEimRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__add_initial_eim_request] AddInitialEimRequest TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

int32_t es10_tlv_generator__get_certs_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const get_certs_request_t* obj) {
    int32_t buffer_offset;

    // GetCertsRequest VALUE
    if ((buffer_offset = es10_tlv_generator__get_certs_request_value(buffer, buffer_size, offset, obj)) < 0) {
        LOGE("[es10_tlv_generator__get_certs_request] Error on GetCertsRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__get_certs_request] GetCertsRequest VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap GetCertsRequest VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, GET_CERTS)) < 0) {
        LOGE("[es10_tlv_generator__get_certs_request] Error on wrapping the GetCertsRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__get_certs_request] GetCertsRequest TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

int32_t es10_tlv_generator__immediate_enable_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const immediate_enable_request_t* obj) {
    int32_t buffer_offset;

    // ImmediateEnableRequest VALUE
    if ((buffer_offset = tlv_generator__add_tlv_boolean_value(buffer, buffer_size, offset, CONTEXT_PRIMITIVE_0, obj->refresh_flag)) < 0) {
        LOGE("[es10_tlv_generator__immediate_enable_request] Error on ImmediateEnableRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__immediate_enable_request] ImmediateEnableRequest VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap ImmediateEnableRequest VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, IMMEDIATE_ENABLE)) < 0) {
        LOGE("[es10_tlv_generator__immediate_enable_request] Error on wrapping the ImmediateEnableRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__immediate_enable_request] ImmediateEnableRequest TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

int32_t es10_tlv_generator__profile_rollback_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const profile_rollback_request_t* obj) {
    int32_t buffer_offset;

    // ProfileRollbackRequest VALUE
    if ((buffer_offset = tlv_generator__add_tlv_boolean_value(buffer, buffer_size, offset, CONTEXT_PRIMITIVE_0, obj->refresh_flag)) < 0) {
        LOGE("[es10_tlv_generator__profile_rollback_request] Error on ProfileRollbackRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__profile_rollback_request] ProfileRollbackRequest VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap ProfileRollbackRequest VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, PROFILE_ROLLBACK)) < 0) {
        LOGE("[es10_tlv_generator__profile_rollback_request] Error on wrapping the ProfileRollbackRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__profile_rollback_request] ProfileRollbackRequest TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

int32_t es10_tlv_generator__configure_immediate_profile_enabling_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const configure_immediate_profile_enabling_request_t* obj) {
    int32_t buffer_offset;

    // ConfigureImmediateProfileEnablingRequest VALUE
    if ((buffer_offset = es10_tlv_generator__configure_immediate_profile_enabling_request_value(buffer, buffer_size, offset, obj)) < 0) {
        LOGE("[es10_tlv_generator__configure_immediate_profile_enabling_request] Error on ConfigureImmediateProfileEnablingRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__configure_immediate_profile_enabling_request] ConfigureImmediateProfileEnablingRequest VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap ConfigureImmediateProfileEnablingRequest VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, CONFIGURE_IMMEDIATE_PROFILE_ENABLING)) < 0) {
        LOGE("[es10_tlv_generator__configure_immediate_profile_enabling_request] Error on wrapping the ConfigureImmediateProfileEnablingRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__configure_immediate_profile_enabling_request] ConfigureImmediateProfileEnablingRequest TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

int32_t es10_tlv_generator__get_eim_configuration_data_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const get_eim_configuration_data_request_t* obj) {
    int32_t buffer_offset;

    // GetEimConfigurationDataRequest VALUE
    if ((buffer_offset = es10_tlv_generator__get_eim_configuration_data_request_value(buffer, buffer_size, offset, obj)) < 0) {
        LOGE("[es10_tlv_generator__get_eim_configuration_data_request] Error on GetEimConfigurationDataRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__get_eim_configuration_data_request] GetEimConfigurationDataRequest VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap GetEimConfigurationDataRequest VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, GET_EIM_CONFIGURATION_DATA)) < 0) {
        LOGE("[es10_tlv_generator__get_eim_configuration_data_request] Error on wrapping the GetEimConfigurationDataRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__get_eim_configuration_data_request] GetEimConfigurationDataRequest TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

#ifdef EXTRA_FEATURE_FALLBACK_MECHANISM
int32_t es10_tlv_generator__execute_fallback_mechanism_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const execute_fallback_mechanism_request_t* obj) {
    int32_t buffer_offset;

    // ExecuteFallbackMechanismRequest VALUE
    if ((buffer_offset = tlv_generator__add_tlv_boolean_value(buffer, buffer_size, offset, CONTEXT_PRIMITIVE_0, obj->refresh_flag)) < 0) {
        LOGE("[es10_tlv_generator__execute_fallback_mechanism_request] Error on ExecuteFallbackMechanismRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__execute_fallback_mechanism_request] ExecuteFallbackMechanismRequest VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap ExecuteFallbackMechanismRequest VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, EXECUTE_FALLBACK_MECHANISM)) < 0) {
        LOGE("[es10_tlv_generator__execute_fallback_mechanism_request] Error on wrapping the ExecuteFallbackMechanismRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__execute_fallback_mechanism_request] ExecuteFallbackMechanismRequest TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

int32_t es10_tlv_generator__return_from_fallback_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const return_from_fallback_request_t* obj) {
    int32_t buffer_offset;

    // ReturnFromFallbackRequest VALUE
    if ((buffer_offset = tlv_generator__add_tlv_boolean_value(buffer, buffer_size, offset, CONTEXT_PRIMITIVE_0, obj->refresh_flag)) < 0) {
        LOGE("[es10_tlv_generator__return_from_fallback_request] Error on ReturnFromFallbackRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__return_from_fallback_request] ReturnFromFallbackRequest VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap ReturnFromFallbackRequest VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, RETURN_FROM_FALLBACK)) < 0) {
        LOGE("[es10_tlv_generator__return_from_fallback_request] Error on wrapping the ReturnFromFallbackRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__return_from_fallback_request] ReturnFromFallbackRequest TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}
#endif
#endif
static int32_t es10_tlv_generator__authenticate_server_request_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const authenticate_server_request_t* obj) {
    int32_t buffer_offset = (int32_t) offset;

    // serverSigned1
    if ((buffer_offset = tlv_generator__add_tlv_full_bytes(buffer, buffer_size, (uint32_t) buffer_offset, obj->server_signed_1, obj->server_signed_1_size)) < 0) {
        LOGE("[es10_tlv_generator__authenticate_server_request_value] Error on serverSigned1 TLV, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__authenticate_server_request_value] AuthenticateServerRequest VALUE size after serverSigned1: %u", buffer_offset - offset);

    // serverSignature1
    if ((buffer_offset = tlv_generator__add_tlv_full_bytes(buffer, buffer_size, (uint32_t) buffer_offset, obj->server_signature_1, (uint32_t) obj->server_signature_1_size)) < 0) {
        LOGE("[es10_tlv_generator__authenticate_server_request_value] Error on serverSignature1 TLV, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__authenticate_server_request_value] AuthenticateServerRequest VALUE size after serverSignature1: %u", buffer_offset - offset);

    //euiccCiPKIdToBeUsed
    if ((buffer_offset = tlv_generator__add_tlv(buffer, buffer_size, (uint32_t) buffer_offset, EUICC_CI_PK_ID, obj->euicc_ci_pk_id_to_be_used.value, sizeof(obj->euicc_ci_pk_id_to_be_used.value))) < 0) {
        LOGE("[es10_tlv_generator__authenticate_server_request_value] Error on euiccCiPKIdToBeUsed, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__authenticate_server_request_value] AuthenticateServerRequest VALUE size after euiccCiPKIdToBeUsed: %u", buffer_offset - offset);

    // serverCertificate
    if ((buffer_offset = tlv_generator__add_tlv_full_bytes(buffer, buffer_size, (uint32_t) buffer_offset, obj->server_certificate, obj->server_certificate_size)) < 0) {
        LOGE("[es10_tlv_generator__authenticate_server_request_value] Error on serverCertificate TLV, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__authenticate_server_request_value] AuthenticateServerRequest VALUE size after serverCertificate: %u", buffer_offset - offset);

    // ctxParams1
    if ((buffer_offset = es10_tlv_generator__authenticate_server_request_ctx_params_1(buffer, buffer_size, (uint32_t) buffer_offset, &obj->ctx_params_1)) < 0) {
        LOGE("[es10_tlv_generator__authenticate_server_request_value] Error on ctxParams1 TLV, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__authenticate_server_request_value] AuthenticateServerRequest VALUE size after ctxParams1: %u", buffer_offset - offset);

    return buffer_offset;
}

static int32_t es10_tlv_generator__authenticate_server_request_ctx_params_1(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const authenticate_server_request_ctx_params_1_t* obj) {
    switch (obj->type)
    {
    case CTX_PARAMS_1_OBJ:
        return es10_tlv_generator__ctx_params_1(buffer, buffer_size, offset, &obj->value.ctx_params_1_obj);
    case CTX_PARAMS_1_PLAIN:
        return tlv_generator__add_tlv_full_bytes(buffer, buffer_size, offset, obj->value.ctx_params_1_plain_value.data, obj->value.ctx_params_1_plain_value.size);
    default:
        LOGE("[es10_tlv_generator__authenticate_server_request_ctx_params_1] Invalid CtxParams1 type %d", obj->type);
        return -eBadArg;
    }
}

static int32_t es10_tlv_generator__ctx_params_1(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const ctx_params_1_t* obj) {
    int32_t buffer_offset;

    // CtxParams1 VALUE
    if ((buffer_offset = es10_tlv_generator__ctx_params_for_common_authentication_value(buffer, buffer_size, offset, &obj->ctx_params_for_common_authentication)) < 0) {
        LOGE("[es10_tlv_generator__ctx_params_1] Error on CtxParams1 VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__ctx_params_1] CtxParams1 VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap CtxParams1 VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, CONTEXT_CONSTRUCTED_0)) < 0) {
        LOGE("[es10_tlv_generator__ctx_params_1] Error on wrapping the CtxParams1 VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__ctx_params_1] CtxParams1 TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;

}

static int32_t es10_tlv_generator__ctx_params_for_common_authentication_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const ctx_params_for_common_authentication_t* obj) {
    int32_t buffer_offset = (int32_t) offset;

    // matchingId
    if (obj->field_is_present.matching_id) {
        if ((buffer_offset = tlv_generator__add_tlv(buffer, buffer_size, (uint32_t) buffer_offset, CONTEXT_PRIMITIVE_0, obj->matching_id, (uint32_t) obj->matching_id_size)) < 0) {
            LOGE("[es10_tlv_generator__ctx_params_for_common_authentication_value] Error on matchingId TLV, err %d", buffer_offset);
            return buffer_offset;
        }
        LOGT("[es10_tlv_generator__ctx_params_for_common_authentication_value] CtxParamsForCommonAuthentication VALUE size after matchingId: %u", buffer_offset - offset);
    }
    
    // deviceInfo
    if ((buffer_offset = device_info__tlv_generator(buffer, buffer_size, (uint32_t) buffer_offset, false, CONTEXT_CONSTRUCTED_1, obj->device_info)) < 0) {
        LOGE("[es10_tlv_generator__ctx_params_for_common_authentication_value] Error on deviceInfo TLV, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__ctx_params_for_common_authentication_value] CtxParamsForCommonAuthentication VALUE size after deviceInfo: %u", buffer_offset - offset);

    return buffer_offset;
}

static int32_t es10_tlv_generator__prepare_download_request_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const prepare_download_request_t* obj) {
    int32_t buffer_offset = (int32_t) offset;

    // smdpSigned2
    if ((buffer_offset = tlv_generator__add_tlv_full_bytes(buffer, buffer_size, (uint32_t) buffer_offset, obj->smdp_signed_2, obj->smdp_signed_2_size)) < 0) {
        LOGE("[es10_tlv_generator__prepare_download_request_value] Error on smdpSigned2 TLV, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__prepare_download_request_value] PrepareDownloadRequest VALUE size after smdpSigned2: %u", buffer_offset - offset);

    // smdpSignature2
    if ((buffer_offset = tlv_generator__add_tlv_full_bytes(buffer, buffer_size, (uint32_t) buffer_offset, obj->smdp_signature_2, obj->smdp_signature_2_size)) < 0) {
        LOGE("[es10_tlv_generator__prepare_download_request_value] Error on smdpSignature2 TLV, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__prepare_download_request_value] PrepareDownloadRequest VALUE size after smdpSignature2: %u", buffer_offset - offset);

    // hashCc OPTIONAL
    if (obj->field_is_present.hash_cc) {
        if ((buffer_offset = tlv_generator__add_tlv(buffer, buffer_size, (uint32_t) buffer_offset, ASN1_DER_OCTET_STRING, obj->hash_cc.hash, sizeof(obj->hash_cc.hash))) < 0) {
            LOGE("[es10_tlv_generator__prepare_download_request_value] Error on hashCc TLV, err %d", buffer_offset);
            return buffer_offset;
        }
        LOGT("[es10_tlv_generator__prepare_download_request_value] PrepareDownloadRequest VALUE size after hashCc: %u", buffer_offset - offset);
    }

    // smdpCertificate
    if ((buffer_offset = tlv_generator__add_tlv_full_bytes(buffer, buffer_size, (uint32_t) buffer_offset, obj->smdp_certificate, obj->smdp_certificate_size)) < 0) {
        LOGE("[es10_tlv_generator__prepare_download_request_value] Error on smdpSignature2 TLV, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__prepare_download_request_value] PrepareDownloadRequest VALUE size after smdpSignature2: %u", buffer_offset - offset);

    return buffer_offset;
}

static int32_t es10_tlv_generator__cancel_session_request_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const cancel_session_request_t* obj) {
    int32_t buffer_offset = (int32_t) offset;
    uint8_t reason = (uint8_t) obj->reason;

    // transactionId
    if ((buffer_offset = tlv_generator__add_tlv_transaction_id_value(buffer, buffer_size, (uint32_t) buffer_offset, CONTEXT_PRIMITIVE_0, &obj->transaction_id)) < 0) {
        LOGE("[es10_tlv_generator__cancel_session_request_value] Error on transactionId TLV, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__cancel_session_request_value] CancelSessionRequest VALUE size after transactionId: %u", buffer_offset - offset);

    // reason
    if ((buffer_offset = tlv_generator__add_tlv(buffer, buffer_size, (uint32_t) buffer_offset, CONTEXT_PRIMITIVE_1, &reason, sizeof(uint8_t))) < 0) {
        LOGE("[es10_tlv_generator__cancel_session_request_value] Error on reason TLV, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__cancel_session_request_value] CancelSessionRequest VALUE size after reason: %u", buffer_offset - offset);

    return buffer_offset;
}

static int32_t es10_tlv_generator__notification_event(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, unsigned short tag, const notification_event_t obj) {
    uint8_t notification_event_bit_string[4] = { 0 };

    if (obj < 0 || obj >= sizeof(notification_event_bit_string)) {
        LOGE("[es10_tlv_generator__notification_event] Invalid notification event value %d", obj);
        return -eBadArg;
    }

    notification_event_bit_string[(uint8_t) obj] = 1;
    return tlv_generator__add_tlv_bit_string_value(buffer, buffer_size, offset, tag, notification_event_bit_string, sizeof(notification_event_bit_string));
}

static int32_t es10_tlv_generator__retrieve_notifications_list_request_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const retrieve_notifications_list_request_t* obj) {
    int32_t buffer_offset;

    if (obj->field_is_present.search_criteria) {
        // searchCriteria VALUE
        if ((buffer_offset = es10_tlv_generator__retrieve_notifications_list_request_search_criteria_value(buffer, buffer_size, offset, &obj->search_criteria)) < 0) {
            LOGE("[es10_tlv_generator__retrieve_notifications_list_request_value] Error on searchCriteria VALUE, err %d", buffer_offset);
            return buffer_offset;
        }
        LOGT("[es10_tlv_generator__retrieve_notifications_list_request_value] searchCriteria VALUE size: %u", (uint32_t) buffer_offset - offset);

        // Wrap searchCriteria VALUE
        if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, CONTEXT_CONSTRUCTED_0)) < 0) {
            LOGE("[es10_tlv_generator__retrieve_notifications_list_request_value] Error on wrapping the searchCriteria VALUE, err %d", buffer_offset);
            return buffer_offset;
        }
        LOGT("[es10_tlv_generator__retrieve_notifications_list_request_value] searchCriteria TLV size: %u", (uint32_t) buffer_offset - offset);

        return buffer_offset; 
    } else {
        return (int32_t) offset;
    }
}

static int32_t es10_tlv_generator__retrieve_notifications_list_request_search_criteria_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const retrieve_notifications_list_request_search_criteria_t* obj) {
    switch (obj->choice)
    {
    case SEQ_NUMBER_CHOICE:
        return tlv_generator__add_tlv_integer_value(buffer, buffer_size, offset, CONTEXT_PRIMITIVE_0, obj->value.seq_number);
    case PROFILE_MANAGEMENT_OPERATION_CHOICE:
        return es10_tlv_generator__notification_event(buffer, buffer_size, offset, CONTEXT_PRIMITIVE_1, obj->value.profile_management_operation);
#ifdef SGP32
    case EUICC_PACKAGE_RESULTS_CHOICE:
        return tlv_generator__add_tlv_null_value(buffer, buffer_size, offset, CONTEXT_PRIMITIVE_2);
#endif   
    default:
        LOGE("[es10_tlv_generator__retrieve_notifications_list_request_search_criteria] Invalid search criteria %d", obj->choice);
        return -eBadArg;
    }
}

static int32_t es10_tlv_generator__profile_info_list_request_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const profile_info_list_request_t* obj) {
    int32_t buffer_offset = (int32_t) offset;

    // searchCriteria
    if (obj->field_is_present.search_criteria) {
        if ((buffer_offset = es10_tlv_generator__profile_info_list_request_search_critreria(buffer, buffer_size, (uint32_t) buffer_offset, &obj->search_criteria)) < 0) {
            LOGE("[es10_tlv_generator__profile_info_list_request_value] Error on searchCriteria TLV, err %d", buffer_offset);
            return buffer_offset;
        }
        LOGT("[es10_tlv_generator__profile_info_list_request_value] ProfileInfoListRequest VALUE size after searchCriteria: %u", buffer_offset - offset);
    }

    // tagList
    if (obj->field_is_present.tag_list) {
        if ((buffer_offset = es10_tlv_generator__profile_info_list_request_tag_list(buffer, buffer_size, (uint32_t) buffer_offset, &obj->tag_list)) < 0) {
            LOGE("[es10_tlv_generator__profile_info_list_request_value] Error on tagList TLV, err %d", buffer_offset);
            return buffer_offset;
        }
        LOGT("[es10_tlv_generator__profile_info_list_request_value] ProfileInfoListRequest VALUE size after tagList: %u", buffer_offset - offset);
    }

    return buffer_offset;
}

static int32_t es10_tlv_generator__profile_info_list_request_search_critreria(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const profile_info_list_request_serach_criteria_t* obj) {
    int32_t buffer_offset;

    // searchCriteria VALUE
    if ((buffer_offset = es10_tlv_generator__profile_info_list_request_search_critreria_value(buffer, buffer_size, offset, obj)) < 0) {
        LOGE("[es10_tlv_generator__profile_info_list_request_search_critreria] Error on searchCriteria VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__profile_info_list_request_search_critreria] searchCriteria VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap searchCriteria VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, CONTEXT_CONSTRUCTED_0)) < 0) {
        LOGE("[es10_tlv_generator__profile_info_list_request_search_critreria] Error on wrapping the searchCriteria VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__profile_info_list_request_search_critreria] searchCriteria TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

static int32_t es10_tlv_generator__profile_info_list_request_search_critreria_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const profile_info_list_request_serach_criteria_t* obj) {
    uint8_t profile_class;
    
    switch (obj->choice)
    {
    case ISDP_AID_PROFILE_INFO_LIST_CHOICE:
        return tlv_generator__add_tlv(buffer, buffer_size, offset, AID, obj->value.isdp_aid.value, sizeof(obj->value.isdp_aid.value));
    case ICCID_PROFILE_INFO_LIST_CHOICE:
        return tlv_generator__add_tlv_iccid_nibble_swap_value(buffer, buffer_size, offset, ICCID, &obj->value.iccid);
    case PROFILE_CLASS_PROFILE_INFO_LIST_CHOICE:
        profile_class = (uint8_t) obj->value.profile_class;
        return tlv_generator__add_tlv(buffer, buffer_size, offset, PROFILE_INFO_CLASS, &profile_class, sizeof(uint8_t));
    default:
        LOGE("[es10_tlv_generator__profile_info_list_request_search_critreria_value] Unknown searchCriteria CHOICE %d", obj->choice);
        return -eBadArg;
    }
}

static int32_t es10_tlv_generator__profile_info_list_request_tag_list(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const profile_info_list_request_tag_list_t* obj) {
    int32_t buffer_offset;

    // tagList VALUE
    if ((buffer_offset = es10_tlv_generator__profile_info_list_request_tag_list_value(buffer, buffer_size, offset, obj)) < 0) {
        LOGE("[es10_tlv_generator__profile_info_list_request_tag_list] Error on tagList VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__profile_info_list_request_tag_list] tagList VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap tagList VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, TAG_LIST)) < 0) {
        LOGE("[es10_tlv_generator__profile_info_list_request_tag_list] Error on wrapping the tagList VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__profile_info_list_request_tag_list] tagList TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

static int32_t es10_tlv_generator__profile_info_list_request_tag_list_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const profile_info_list_request_tag_list_t* obj) {
    int32_t buffer_offset = offset;

    if (obj->iccid) {
        if ((buffer_offset = tlv_generator__add_tag(buffer, buffer_size, buffer_offset, ICCID)) < 0) {
            LOGE("[es10_tlv_generator__profile_info_list_request_tag_list_value] Error on tag ICCID, err %d", buffer_offset);
            return buffer_offset;
        }
    }
    if (obj->isdp_aid) {
        if ((buffer_offset = tlv_generator__add_tag(buffer, buffer_size, buffer_offset, AID)) < 0) {
            LOGE("[es10_tlv_generator__profile_info_list_request_tag_list_value] Error on tag ISD-P AID, err %d", buffer_offset);
            return buffer_offset;
        }
    }
    if (obj->profile_state) {
        if ((buffer_offset = tlv_generator__add_tag(buffer, buffer_size, buffer_offset, PROFILE_INFO_STATE)) < 0) {
            LOGE("[es10_tlv_generator__profile_info_list_request_tag_list_value] Error on tag Profile state, err %d", buffer_offset);
            return buffer_offset;
        }
    }
    if (obj->profile_nickname) {
        if ((buffer_offset = tlv_generator__add_tag(buffer, buffer_size, buffer_offset, PROFILE_INFO_NICKNAME)) < 0) {
            LOGE("[es10_tlv_generator__profile_info_list_request_tag_list_value] Error on tag Profile Nickname, err %d", buffer_offset);
            return buffer_offset;
        }
    }
    if (obj->service_provider_name) {
        if ((buffer_offset = tlv_generator__add_tag(buffer, buffer_size, buffer_offset, PROFILE_INFO_PROV_NAME)) < 0) {
            LOGE("[es10_tlv_generator__profile_info_list_request_tag_list_value] Error on tag Service provider name, err %d", buffer_offset);
            return buffer_offset;
        }
    }
    if (obj->profile_name) {
        if ((buffer_offset = tlv_generator__add_tag(buffer, buffer_size, buffer_offset, PROFILE_INFO_NAME)) < 0) {
            LOGE("[es10_tlv_generator__profile_info_list_request_tag_list_value] Error on tag Profile name, err %d", buffer_offset);
            return buffer_offset;
        }
    }
    if (obj->icon_type) {
        if ((buffer_offset = tlv_generator__add_tag(buffer, buffer_size, buffer_offset, PROFILE_INFO_ICON_TYPE)) < 0) {
            LOGE("[es10_tlv_generator__profile_info_list_request_tag_list_value] Error on tag Icon type, err %d", buffer_offset);
            return buffer_offset;
        }
    }
    if (obj->icon) {
        if ((buffer_offset = tlv_generator__add_tag(buffer, buffer_size, buffer_offset, PROFILE_INFO_ICON)) < 0) {
            LOGE("[es10_tlv_generator__profile_info_list_request_tag_list_value] Error on tag Icon, err %d", buffer_offset);
            return buffer_offset;
        }
    }
    if (obj->profile_class) {
        if ((buffer_offset = tlv_generator__add_tag(buffer, buffer_size, buffer_offset, PROFILE_INFO_CLASS)) < 0) {
            LOGE("[es10_tlv_generator__profile_info_list_request_tag_list_value] Error on tag Profile Class, err %d", buffer_offset);
            return buffer_offset;
        }
    }
    if (obj->notification_configuration_info) {
        if ((buffer_offset = tlv_generator__add_tag(buffer, buffer_size, buffer_offset, PROFILE_INFO_NOTIF_CONFIG)) < 0) {
            LOGE("[es10_tlv_generator__profile_info_list_request_tag_list_value] Error on tag Notification Configuration Info, err %d", buffer_offset);
            return buffer_offset;
        }
    }
    if (obj->profile_owner) {
        if ((buffer_offset = tlv_generator__add_tag(buffer, buffer_size, buffer_offset, PROFILE_INFO_OWNER)) < 0) {
            LOGE("[es10_tlv_generator__profile_info_list_request_tag_list_value] Error on tag Profile Owner, err %d", buffer_offset);
            return buffer_offset;
        }
    }
    if (obj->smdp_propietary_data) {
        if ((buffer_offset = tlv_generator__add_tag(buffer, buffer_size, buffer_offset, PROFILE_INFO_SMDP_DATA)) < 0) {
            LOGE("[es10_tlv_generator__profile_info_list_request_tag_list_value] Error on tag SM-DP+ proprietary data, err %d", buffer_offset);
            return buffer_offset;
        }
    }
    if (obj->profile_policy_rules) {
        if ((buffer_offset = tlv_generator__add_tag(buffer, buffer_size, buffer_offset, PROFILE_INFO_PPRS)) < 0) {
            LOGE("[es10_tlv_generator__profile_info_list_request_tag_list_value] Error on tag Profile Policy Rules, err %d", buffer_offset);
            return buffer_offset;
        }
    }
#ifdef SGP32
    if (obj->ecall_indication) {
        if ((buffer_offset = tlv_generator__add_tag(buffer, buffer_size, buffer_offset, PROFILE_INFO_ECALL_INDICATION)) < 0) {
            LOGE("[es10_tlv_generator__profile_info_list_request_tag_list_value] Error on tag ecall Indication, err %d", buffer_offset);
            return buffer_offset;
        }
    }
    if (obj->fallback_attribute) {
        if ((buffer_offset = tlv_generator__add_tag(buffer, buffer_size, buffer_offset, PROFILE_INFO_FALLBACK_ATTRIBUTE)) < 0) {
            LOGE("[es10_tlv_generator__profile_info_list_request_tag_list_value] Error on tag Fallback Attribute, err %d", buffer_offset);
            return buffer_offset;
        }
    }
    if (obj->fallback_allowed) {
        if ((buffer_offset = tlv_generator__add_tag(buffer, buffer_size, buffer_offset, PROFILE_INFO_FALLBACK_ALLOWED)) < 0) {
            LOGE("[es10_tlv_generator__profile_info_list_request_tag_list_value] Error on tag Fallback Allowed, err %d", buffer_offset);
            return buffer_offset;
        }
    }
#endif

    return buffer_offset;
}

#ifdef SGP22
static int32_t es10_tlv_generator__list_notification_request_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const list_notification_request_t* obj) {
    int32_t buffer_offset;
    
    // ListNotificationRequest VALUE
    if (obj->field_is_present.profile_management_operation) {
        // profileManagementOperation
        if ((buffer_offset = es10_tlv_generator__notification_event(buffer, buffer_size, offset, CONTEXT_PRIMITIVE_1, obj->profile_management_operation)) < 0) {
            LOGE("[es10_tlv_generator__list_notification_request_value] Error on profileManagementOperation, err %d", buffer_offset);
            return buffer_offset;
        }
        LOGT("[es10_tlv_generator__retrieve_notifications_list_request_value] ListNotificationRequest VALUE size: %u", (uint32_t) buffer_offset - offset);
        return buffer_offset; 
    } else {
        return (int32_t) offset;
    }
}

static int32_t es10_tlv_generator__profile_state_change_request_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const profile_state_change_request_t* obj) {
    int32_t buffer_offset = (int32_t) offset;

    // profileIdentifier
    if ((buffer_offset = es10_tlv_generator__profile_identifier(buffer, buffer_size, (uint32_t) buffer_offset, &obj->profile_identifier)) < 0) {
        LOGE("[es10_tlv_generator__profile_state_change_request_value] Error on profileIdentifier TLV, err %d", buffer_offset);
        return buffer_offset;
    }

    // refreshFlag
    if ((buffer_offset = tlv_generator__add_tlv_boolean_value(buffer, buffer_size, (uint32_t) buffer_offset, CONTEXT_PRIMITIVE_1, obj->refresh_flag)) < 0) {
        LOGE("[es10_tlv_generator__profile_state_change_request_value] Error on refreshFlag TLV, err %d", buffer_offset);
        return buffer_offset;
    }

    return buffer_offset;
}

static int32_t es10_tlv_generator__profile_identifier(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const profile_identifier_t* obj) {
    int32_t buffer_offset;

    // profileIdentifier VALUE
    if ((buffer_offset = es10_tlv_generator__profile_identifier_value(buffer, buffer_size, offset, obj)) < 0) {
        LOGE("[es10_tlv_generator__profile_identifier] Error on profileIdentifier VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__profile_identifier] profileIdentifier VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap profileIdentifier VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, CONTEXT_CONSTRUCTED_0)) < 0) {
        LOGE("[es10_tlv_generator__profile_identifier] Error on wrapping the profileIdentifier VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__profile_identifier] profileIdentifier TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

static int32_t es10_tlv_generator__profile_identifier_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const profile_identifier_t* obj) {
    switch (obj->choice)
    {
    case ISDP_AID_PROFILE_IDENTIFIER_CHOICE:
        return tlv_generator__add_tlv(buffer, buffer_size, offset, AID, obj->value.isdp_aid.value, sizeof(obj->value.isdp_aid.value));
    case ICCID_PROFILE_IDENTIFIER_CHOICE:
        return tlv_generator__add_tlv_iccid_nibble_swap_value(buffer, buffer_size, offset, ICCID, &obj->value.iccid);
    default:
        LOGE("[es10_tlv_generator__profile_identifier_value] Unknown profileIdentifier CHOICE %d", obj->choice);
        return -eBadArg;
    }
}

static int32_t es10_tlv_generator__set_nickname_request_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const set_nickname_request_t* obj) {
    int32_t buffer_offset = (int32_t) offset;

    // iccid
    if ((buffer_offset = tlv_generator__add_tlv_iccid_nibble_swap_value(buffer, buffer_size, offset, ICCID, &obj->iccid)) < 0) {
        LOGE("[es10_tlv_generator__set_nickname_request_value] Error on iccid TLV, err %d", buffer_offset);
        return buffer_offset;
    }

    // profileNickname
    if ((buffer_offset = tlv_generator__add_tlv(buffer, buffer_size, (uint32_t) buffer_offset, PROFILE_INFO_NICKNAME, obj->profile_nickname.value, obj->profile_nickname.len)) < 0) {
        LOGE("[es10_tlv_generator__set_nickname_request_value] Error on profileNickname TLV, err %d", buffer_offset);
        return buffer_offset;
    }

    return buffer_offset;
}
#endif

#ifdef SGP32
static int32_t es10_tlv_generator__add_initial_eim_request_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const eim_configuration_data_t* obj) {
    int32_t buffer_offset;

    // eimConfigurationDataList VALUE (Single item on the list)
    if ((buffer_offset = es10_tlv_generator__eim_configuration_data(buffer, buffer_size, offset, obj)) < 0) {
        LOGE("[es10_tlv_generator__add_initial_eim_request_value] Error on EimConfigurationData, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__add_initial_eim_request_value] eimConfigurationDataList VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap eimConfigurationDataList VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, CONTEXT_CONSTRUCTED_0)) < 0) {
        LOGE("[es10_tlv_generator__add_initial_eim_request_value] Error on wrapping the eimConfigurationDataList VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__add_initial_eim_request_value] eimConfigurationDataList TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

static int32_t es10_tlv_generator__eim_configuration_data(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const eim_configuration_data_t* obj) {
    int32_t buffer_offset;

    // EimConfigurationData VALUE
    if ((buffer_offset = es10_tlv_generator__eim_configuration_data_value(buffer, buffer_size, offset, obj)) < 0) {
        LOGE("[es10_tlv_generator__eim_configuration_data] Error on EimConfigurationData VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__eim_configuration_data] EimConfigurationData VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap EimConfigurationData VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, ASN1_DER_SEQUENCE)) < 0) {
        LOGE("[es10_tlv_generator__eim_configuration_data] Error on wrapping the EimConfigurationData VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__eim_configuration_data] EimConfigurationData TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

static int32_t es10_tlv_generator__eim_configuration_data_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const eim_configuration_data_t* obj) {
    int32_t buffer_offset = (int32_t) offset;

    //eimId
    if ((buffer_offset = tlv_generator__add_tlv(buffer, buffer_size, (uint32_t) buffer_offset, EIM_CONF_EIM_ID, obj->eim_id, obj->eim_id_len)) < 0) {
        LOGE("[es10_tlv_generator__eim_configuration_data_value] Error on eimId, err %d", buffer_offset);
        return buffer_offset;
    }
    
    //eimFqdn OPTIONAL
    if (obj->field_is_present.eim_fqdn) {
        if ((buffer_offset = tlv_generator__add_tlv(buffer, buffer_size, (uint32_t) buffer_offset, EIM_CONF_EIM_FQDN, obj->eim_fqdn, obj->eim_fqdn_len)) < 0) {
            LOGE("[es10_tlv_generator__eim_configuration_data_value] Error on eimFqdn, err %d", buffer_offset);
            return buffer_offset;
        }
    }
    //eimIdType OPTIONAL
    if (obj->field_is_present.eim_id_type) {
        if ((buffer_offset = tlv_generator__add_tlv_integer_value(buffer, buffer_size, (uint32_t) buffer_offset, EIM_CONF_EIM_ID_TYPE, obj->eim_id_type)) < 0) {
            LOGE("[es10_tlv_generator__eim_configuration_data_value] Error on eimIdType, err %d", buffer_offset);
            return buffer_offset;
        }
    }
    //counterValue OPTIONAL
    if (obj->field_is_present.counter_value) {
        if ((buffer_offset = tlv_generator__add_tlv_integer_value(buffer, buffer_size, (uint32_t) buffer_offset, EIM_CONF_COUNTER_VALUE, obj->counter_value)) < 0) {
            LOGE("[es10_tlv_generator__eim_configuration_data_value] Error on counterValue, err %d", buffer_offset);
            return buffer_offset;
        }
    }
    //associationToken OPTIONAL
    if (obj->field_is_present.association_token) {
        uint8_t request_association_token[] = { 0xFF };
        if ((buffer_offset = tlv_generator__add_tlv(buffer, buffer_size, (uint32_t) buffer_offset, EIM_CONF_ASSOCIATION_TOKEN, request_association_token, sizeof(request_association_token))) < 0) {
            LOGE("[es10_tlv_generator__eim_configuration_data_value] Error on associationToken, err %d", buffer_offset);
            return buffer_offset;
        }
    }
    //eimPublicKeyData OPTIONAL
    if (obj->field_is_present.eim_public_key_data) {
        if ((buffer_offset = es10_tlv_generator__eim_public_key_data(buffer, buffer_size, (uint32_t) buffer_offset, &obj->eim_public_key_data)) < 0) {
            LOGE("[es10_tlv_generator__eim_configuration_data_value] Error on eimPublicKeyData, err %d", buffer_offset);
            return buffer_offset;
        }
    }
    //trustedPublicKeyDataTls OPTIONAL
    if (obj->field_is_present.trusted_public_key_data_tls) {
        if ((buffer_offset = es10_tlv_generator__trusted_public_key_data_tls(buffer, buffer_size, (uint32_t) buffer_offset, &obj->trusted_public_key_data_tls)) < 0) {
            LOGE("[es10_tlv_generator__eim_configuration_data_value] Error on trustedPublicKeyDataTls, err %d", buffer_offset);
            return buffer_offset;
        }
    }
    //eimSupportedProtocol OPTIONAL
    if (obj->field_is_present.eim_supported_protocol) {
        if ((buffer_offset = es10_tlv_generator__eim_supported_protocol(buffer, buffer_size, (uint32_t) buffer_offset, &obj->eim_supported_protocol)) < 0) {
            LOGE("[es10_tlv_generator__eim_configuration_data_value] Error on eimSupportedProtocol, err %d", buffer_offset);
            return buffer_offset;
        }
    }

    //euiccCiPKId OPTIONAL
    if (obj->field_is_present.euicc_ci_pk_id) {
        if ((buffer_offset = tlv_generator__add_tlv(buffer, buffer_size, (uint32_t) buffer_offset, EIM_CONF_EUICC_CI_PK_ID, obj->euicc_ci_pk_id.value, sizeof(obj->euicc_ci_pk_id.value))) < 0) {
            LOGE("[es10_tlv_generator__eim_configuration_data_value] Error on euiccCiPKId, err %d", buffer_offset);
            return buffer_offset;
        }
    }

    //indirectProfileDownload OPTIONAL
    if (obj->field_is_present.indirect_profile_download) {
        if ((buffer_offset = tlv_generator__add_tlv_null_value(buffer, buffer_size, (uint32_t) buffer_offset, EIM_CONF_INDIRECT_PROFILE_DOWNLOAD)) < 0) {
            LOGE("[es10_tlv_generator__eim_configuration_data_value] Error on indirectProfileDownload, err %d", buffer_offset);
            return buffer_offset;
        }
    }

    LOGT("[es10_tlv_generator__eim_configuration_data_value] EimConfigurationData TLV value size %u", buffer_offset);
    return buffer_offset;
}

static int32_t es10_tlv_generator__eim_public_key_data(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const eim_public_key_data_t* obj) {
    int32_t buffer_offset;
    unsigned short choice_tag = (unsigned short) (obj->choice == EIM_PUBLIC_KEY_CHOICE ? EIM_CONF_EIM_PUBLIC_KEY : EIM_CONF_EIM_CERTIFICATE);

    // eimPublicKeyData VALUE
    if ((buffer_offset = tlv_generator__add_tlv_full_bytes_overwrite_tag(buffer, buffer_size, offset, obj->value, obj->value_size, choice_tag)) < 0) {
        LOGE("[es10_tlv_generator__eim_public_key_data] Error on eimPublicKeyData VALUE (eimPublicKey or eimCertificate), err %d", buffer_offset);
        return buffer_offset;
    }

    LOGT("[es10_tlv_generator__eim_public_key_data] eimPublicKeyData VALUE (eimPublicKey or eimCertificate) size %u", (uint32_t) buffer_offset - offset);
    // Wrap eimPublicKeyData VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, EIM_CONF_EIM_PUBLIC_KEY_DATA)) < 0) {
        LOGE("[es10_tlv_generator__eim_public_key_data] Error on wrapping the eimPublicKeyData VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__eim_public_key_data] eimPublicKeyData TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

static int32_t es10_tlv_generator__trusted_public_key_data_tls(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const trusted_public_key_data_tls_t* obj) {
    int32_t buffer_offset;
    unsigned short choice_tag = (unsigned short) (obj->choice == TRUSTED_EIM_PK_TLS_CHOICE ? EIM_CONF_TRUSTED_EIM_PK_TLS : EIM_CONF_TRUSTED_CERTIFICATE_TLS);

    // trustedPublicKeyDataTls VALUE
    if ((buffer_offset = tlv_generator__add_tlv_full_bytes_overwrite_tag(buffer, buffer_size, offset, obj->value, obj->value_size, choice_tag)) < 0) {
        LOGE("[es10_tlv_generator__trusted_public_key_data_tls] Error on trustedPublicKeyDataTls VALUE (trustedEimPkTls or trustedCertificateTls), err %d", buffer_offset);
        return buffer_offset;
    }
    
    LOGT("[es10_tlv_generator__trusted_public_key_data_tls] trustedPublicKeyDataTls VALUE (trustedEimPkTls or trustedCertificateTls) size %u", (uint32_t) buffer_offset - offset);
    // Wrap trustedPublicKeyDataTls VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, EIM_CONF_TRUSTED_PUBLIC_KEY_DATA_TLS)) < 0) {
        LOGE("[es10_tlv_generator__trusted_public_key_data_tls] Error on wrapping the trustedPublicKeyDataTls VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__trusted_public_key_data_tls] trustedPublicKeyDataTls TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

static int32_t es10_tlv_generator__eim_supported_protocol(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const eim_supported_protocol_t* obj) {
    uint8_t eim_supported_protocol_bit_string[] = { obj->eim_retrieve_https, obj->eim_retrieve_coaps, obj->eim_inject_https, obj->eim_inject_coaps, obj->eim_proprietary };

    return tlv_generator__add_tlv_bit_string_value(buffer, buffer_size, offset, EIM_CONF_EIM_SUPPORTED_PROTOCOL, eim_supported_protocol_bit_string, sizeof(eim_supported_protocol_bit_string));
}

static int32_t es10_tlv_generator__get_certs_request_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const get_certs_request_t* obj) {
     int32_t buffer_offset;

    // GetCertsRequest VALUE
    if (obj->field_is_present.euicc_ci_pk_id) {
        // euiccCiPKId 
        if ((buffer_offset = tlv_generator__add_tlv(buffer, buffer_size, offset, CONTEXT_PRIMITIVE_0, obj->euicc_ci_pk_id.value, (uint32_t) sizeof(obj->euicc_ci_pk_id.value))) < 0) {
            LOGE("[es10_tlv_generator__get_certs_request_value] Error on euiccCiPKId , err %d", buffer_offset);
            return buffer_offset;
        }
        LOGT("[es10_tlv_generator__get_certs_request_value] GetCertsRequest VALUE size: %u", (uint32_t) buffer_offset - offset);
        return buffer_offset; 
    } else {
        return (int32_t) offset;
    }
}

static int32_t es10_tlv_generator__configure_immediate_profile_enabling_request_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const configure_immediate_profile_enabling_request_t* obj) {
    int32_t buffer_offset = (int32_t) offset;

    // immediateEnableFlag
    if (obj->field_is_present.immediate_enable_flag) {
        if ((buffer_offset = tlv_generator__add_tlv_null_value(buffer, buffer_size, (uint32_t) buffer_offset, CONTEXT_PRIMITIVE_0)) < 0) {
            LOGE("[es10_tlv_generator__configure_immediate_profile_enabling_request_value] Error on immediateEnableFlag, err %d", buffer_offset);
            return buffer_offset;
        }
    }
    
    // defaultSmdpOid
    if (obj->field_is_present.default_smdp_oid) {
        if ((buffer_offset = tlv_generator__add_tlv_oid_value(buffer, buffer_size, (uint32_t) buffer_offset, CONTEXT_PRIMITIVE_1, obj->default_smdp_oid, obj->default_smdp_oid_len)) < 0) {
            LOGE("[es10_tlv_generator__configure_immediate_profile_enabling_request_value] Error on defaultSmdpOid, err %d", buffer_offset);
            return buffer_offset;
        }
    }
    // defaultSmdpAddress
    if (obj->field_is_present.default_smdp_address) {
        if ((buffer_offset = tlv_generator__add_tlv(buffer, buffer_size, (uint32_t) buffer_offset, CONTEXT_PRIMITIVE_2, (uint8_t*) obj->default_smdp_address, obj->default_smdp_address_len)) < 0) {
            LOGE("[es10_tlv_generator__configure_immediate_profile_enabling_request_value] Error on defaultSmdpAddress, err %d", buffer_offset);
            return buffer_offset;
        }
    }

    LOGT("[es10_tlv_generator__configure_immediate_profile_enabling_request_value] ConfigureImmediateProfileEnablingRequest TLV value size %u", buffer_offset);
    return buffer_offset;
}

static int32_t es10_tlv_generator__get_eim_configuration_data_request_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const get_eim_configuration_data_request_t* obj) {
    int32_t buffer_offset;

    if (obj->field_is_present.search_criteria) {
        // searchCriteria VALUE
        if ((buffer_offset = es10_tlv_generator__get_eim_configuration_data_request_search_criteria_value(buffer, buffer_size, offset, &obj->search_criteria)) < 0) {
            LOGE("[es10_tlv_generator__get_eim_configuration_data_request_value] Error on searchCriteria VALUE, err %d", buffer_offset);
            return buffer_offset;
        }
        LOGT("[es10_tlv_generator__get_eim_configuration_data_request_value] searchCriteria VALUE size: %u", (uint32_t) buffer_offset - offset);

        // Wrap searchCriteria VALUE
        if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, CONTEXT_CONSTRUCTED_0)) < 0) {
            LOGE("[es10_tlv_generator__get_eim_configuration_data_request_value] Error on wrapping the searchCriteria VALUE, err %d", buffer_offset);
            return buffer_offset;
        }
        LOGT("[es10_tlv_generator__get_eim_configuration_data_request_value] searchCriteria TLV size: %u", (uint32_t) buffer_offset - offset);

        return buffer_offset; 
    } else {
        return (int32_t) offset;
    }
}

static int32_t es10_tlv_generator__get_eim_configuration_data_request_search_criteria_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const get_eim_configuration_data_request_search_criteria_t* obj) {
    switch (obj->choice)
    {
    case EIM_ID:
        return tlv_generator__add_tlv(buffer, buffer_size, offset, CONTEXT_PRIMITIVE_0, obj->value.eim_id.value, (uint32_t) obj->value.eim_id.len);

    default:
        LOGE("[es10_tlv_generator__get_eim_configuration_data_request_search_criteria_value] Invalid search criteria %d", obj->choice);
        return -eBadArg;
    }
}

#ifdef EXTRA_FEATURE_EMERGENCY_PROFILE_MANAGMENT
int32_t es10_tlv_generator__enable_emergency_profile_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const enable_emergency_profile_request_t* obj) {
    int32_t buffer_offset;

    // EnableEmergencyProfile VALUE
    if ((buffer_offset = tlv_generator__add_tlv_boolean_value(buffer, buffer_size, offset, CONTEXT_PRIMITIVE_0, obj->refresh_flag)) < 0) {
        LOGE("[es10_tlv_generator__enable_emergency_profile_request] Error on EnableEmergencyProfile VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__enable_emergency_profile_request] EnableEmergencyProfile VALUE size: %u", (uint32_t)buffer_offset - offset);

    // Wrap EnableEmergencyProfile VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t)buffer_offset, ENABLE_EMERGENCY_PROFILE)) < 0) {
        LOGE("[es10_tlv_generator__enable_emergency_profile_request] Error on wrapping the EnableEmergencyProfile VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__enable_emergency_profile_request] EnableEmergencyProfile TLV size: %u", (uint32_t)buffer_offset - offset);

    return buffer_offset;
}

int32_t es10_tlv_generator__disable_emergency_profile_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const disable_emergency_profile_request_t* obj) {
    int32_t buffer_offset;

    // DisableEmergencyProfile VALUE
    if ((buffer_offset = tlv_generator__add_tlv_boolean_value(buffer, buffer_size, offset, CONTEXT_PRIMITIVE_0, obj->refresh_flag)) < 0) {
        LOGE("[es10_tlv_generator__disable_emergency_profile_request] Error on DisableEmergencyProfile VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__disable_emergency_profile_request] DisableEmergencyProfile VALUE size: %u", (uint32_t)buffer_offset - offset);

    // Wrap DisableEmergencyProfile VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t)buffer_offset, DISABLE_EMERGENCY_PROFILE)) < 0) {
        LOGE("[es10_tlv_generator__disable_emergency_profile_request] Error on wrapping the DisableEmergencyProfile VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[es10_tlv_generator__disable_emergency_profile_request] DisableEmergencyProfile TLV size: %u", (uint32_t)buffer_offset - offset);

    return buffer_offset;
}
#endif
#endif
