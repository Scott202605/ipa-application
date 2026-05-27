/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#ifdef ENABLE_ESIPA_JSON
#include "log.h"
#include "esipa_json_generator.h"
#include "json_generator.h"
#include "esipa_tlv_generator.h"

#define PENDING_NOTIFICATION_ESIPA_JSON_KEY "pendingNotification"
#define PROVIDE_EIM_PACKAGE_RESULT_ESIPA_JSON_KEY "provideEimPackageResult"
#define EUICC_PACKAGE_RESULT_ESIPA_JSON_KEY "euiccPackageResult"
#define NOTIFICATION_LIST_ESIPA_JSON_KEY "notificationList"
#define IPA_EUICC_DATA_RESPONSE_ESIPA_JSON_KEY "ipaEuiccDataResponse"
#define EIM_PACKAGE_RECEIVED_ESIPA_JSON_KEY "eimPackageReceived"
#define EIM_PACKAGE_ERROR_ESIPA_JSON_KEY "eimPackageError"
#define EID_VALUE_ESIPA_JSON_KEY "eidValue"
#define NOTIFY_STATE_CHANGE_ESIPA_JSON_KEY "notifyStateChange"
#define STATE_CHANGE_CAUSE_ESIPA_JSON_KEY "stateChangeCause"
#define RPLMN_ESIPA_JSON_KEY "rPlmn"
#define EIM_PACKAGE_RESULT_ESIPA_JSON_KEY "eimPackageResult"

#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
#define EIM_TRANSACTION_ID_ESIPA_JSON_KEY "eimTransactionId"
#define EUICC_CHALLENGE_ESIPA_JSON_KEY "euiccChallenge"
#ifndef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
#define EUICC_INFO_1_ESIPA_JSON_KEY "euiccInfo1"
#endif
#if !defined (IPA_FEATURE_EIM_DOWNLOAD_DATA_HANDLING) && !defined (IPA_FEATURE_MINIMIZE_ESIPA_BYTES)
#define SMDP_ADDRESS_ESIPA_JSON_KEY "smdpAddress"
#endif
#define TRANSACTION_ID_ESIPA_JSON_KEY "transactionId"
#define AUTHENTICATE_SERVER_RESPONSE_ESIPA_JSON_KEY "authenticateServerResponse"
#define PREPARE_DOWNLOAD_RESPONSE_ESIPA_JSON_KEY "prepareDownloadResponse"
#define CANCEL_SESSION_RESPONSE_ESIPA_JSON_KEY "cancelSessionResponse"
#endif

#define EPR_AND_NOTIFICATIONS_ESIPA_JSON_STRING ",\"ePRAndNotifications\":"
#define TRANSFER_EIM_PACKAGE_RESPONSE_HEADER_KEY "header"

static int32_t esipa_json_generator__add_epr_and_notifications(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const epr_and_notifications_t* obj);
static int32_t esipa_json_generator__provide_eim_package_result_encoder(unsigned char* buffer, const uint32_t buffer_size, const void* obj);
static int32_t esipa_json_generator__eim_package_result_encoder(unsigned char* buffer, const uint32_t buffer_size, const void* obj);
static int32_t esipa_json_generator__ipa_euicc_data_response(uint8_t* buffer, const uint32_t buffer_size, const void* obj);

int32_t esipa_json_generator__handle_notification_esipa(uint8_t* buffer, const uint32_t buffer_size, const handle_notification_esipa_t* obj) {
    int32_t buffer_offset = 0;

    switch (obj->choice)
    {
    case PENDING_NOTIFICATION_CHOICE_HNE:
        buffer_offset = json_generator__add_base64_string_child(buffer, buffer_size, 0, true, true, PENDING_NOTIFICATION_ESIPA_JSON_KEY, obj->value.pending_notification.pending_notification, obj->value.pending_notification.pending_notification_size);
        break;
    case PROVIDE_EIM_PACKAGE_RESULT_CHOICE_HNE:
        buffer_offset = json_generator__add_base64_string_child_with_custom_byte_array_encoder(buffer, buffer_size, 0, true, true, PROVIDE_EIM_PACKAGE_RESULT_ESIPA_JSON_KEY, (void*) &obj->value.provide_eim_package_result, &esipa_json_generator__provide_eim_package_result_encoder);
        break;
    default:
        LOGE("[esipa_json_generator__handle_notification_esipa] Unknown choice %d", obj->choice);
        return -eBadArg;
    }

    if (buffer) {
        LOG_UTF8_DATA(eLogDebug, "[esipa_json_generator__handle_notification_esipa] ", buffer, buffer_offset);
    }

    return buffer_offset;
}

int32_t esipa_json_generator__transfer_eim_package_response(uint8_t* buffer, const uint32_t buffer_size, const transfer_eim_package_response_t* obj) {
    int32_t buffer_offset = 0;
    const char header_value[] = "{\"functionExecutionStatus\":{\"status\":\"Executed-Success\"}}";

    // JSON responseHeader
    if ((buffer_offset = json_generator__add_json_object_child(buffer, buffer_size, buffer_offset, true, EIM_PACKAGE_RECEIVED_CHOICE_TEPR == obj->choice, TRANSFER_EIM_PACKAGE_RESPONSE_HEADER_KEY, (unsigned char*) header_value, (uint32_t) strlen(header_value))) < 0) {
        LOGE("[esipa_json_generator__transfer_eim_package_response] Error on JSON responseHeader, err %d", buffer_offset);
        return buffer_offset;
    }

    // JSON responseBody
    switch (obj->choice)
    {
    case EUICC_PACKAGE_RESULT_CHOICE_TEPR:
        buffer_offset = json_generator__add_base64_string_child(buffer, buffer_size, buffer_offset, false, true, EUICC_PACKAGE_RESULT_ESIPA_JSON_KEY, obj->value.euicc_package_result.tlv, obj->value.euicc_package_result.tlv_size);
        break;
    case EPR_AND_NOTIFICATIONS_CHOICE_TEPR:
        buffer_offset = esipa_json_generator__add_epr_and_notifications(buffer, buffer_size, (uint32_t) buffer_offset, &obj->value.epr_and_notifications);
        break;
    case IPA_EUICC_DATA_RESPONSE_CHOICE_TEPR:
        buffer_offset = json_generator__add_base64_string_child_with_custom_byte_array_encoder(buffer, buffer_size, buffer_offset, false, true, IPA_EUICC_DATA_RESPONSE_ESIPA_JSON_KEY, (void*) &obj->value.ipa_euicc_data_response, &esipa_json_generator__ipa_euicc_data_response);
        break;
    case EIM_PACKAGE_RECEIVED_CHOICE_TEPR:
        break; // Do nothing, only the JSON header response is returned
    case EIM_PACKAGE_ERROR_CHOICE_TEPR:
        buffer_offset = json_generator__add_number_child(buffer, buffer_size, buffer_offset, false, true, EIM_PACKAGE_ERROR_ESIPA_JSON_KEY, (int) obj->value.eim_package_error);
        break;
    default:
        LOGE("[esipa_json_generator__transfer_eim_package_response] Unknown choice %d", obj->choice);
        return -eBadArg;
    }

    if (buffer) {
        LOG_UTF8_DATA(eLogDebug, "[esipa_json_generator__transfer_eim_package_response] ", buffer, buffer_offset);
    }

    return buffer_offset;
}

int32_t esipa_json_generator__get_eim_package_request(uint8_t* buffer, const uint32_t buffer_size, const get_eim_package_request_t* obj) {
    int32_t buffer_offset = 0;

    if ((buffer_offset = json_generator__add_hexadecimal_string_child(buffer, buffer_size, buffer_offset, true, !obj->field_is_present.notify_state_change && !obj->field_is_present.rplmn, EID_VALUE_ESIPA_JSON_KEY, obj->eid.eid, sizeof(obj->eid.eid))) < 0) {
        LOGE("[esipa_json_generator__get_eim_package_request] Error on eidValue, err %d", buffer_offset);
        return buffer_offset;
    }

    if (obj->field_is_present.notify_state_change) {
        if ((buffer_offset = json_generator__add_boolean_child(buffer, buffer_size, buffer_offset, false, false, NOTIFY_STATE_CHANGE_ESIPA_JSON_KEY, true)) < 0) {
            LOGE("[esipa_json_generator__get_eim_package_request] Error on notifyStateChange, err %d", buffer_offset);
            return buffer_offset;
        }
        if ((buffer_offset = json_generator__add_number_child(buffer, buffer_size, buffer_offset, false, !obj->field_is_present.rplmn, STATE_CHANGE_CAUSE_ESIPA_JSON_KEY, (int) obj->state_change_cause)) < 0) {
            LOGE("[esipa_json_generator__get_eim_package_request] Error on stateChangeCause, err %d", buffer_offset);
            return buffer_offset;
        }
    }

    if (obj->field_is_present.rplmn) {
        if ((buffer_offset = json_generator__add_base64_string_child(buffer, buffer_size, buffer_offset, false, true, RPLMN_ESIPA_JSON_KEY, obj->rplmn.value, sizeof(obj->rplmn.value))) < 0) {
            LOGE("[esipa_json_generator__get_eim_package_request] Error on rPlmn, err %d", buffer_offset);
            return buffer_offset;
        }
    }

    if (buffer) {
        LOG_UTF8_DATA(eLogDebug, "[esipa_json_generator__get_eim_package_request] ", buffer, buffer_offset);
    }

    return buffer_offset;
}

int32_t esipa_json_generator__provide_eim_package_result(uint8_t* buffer, const uint32_t buffer_size, const provide_eim_package_result_t* obj) {
    int32_t buffer_offset = 0;

    if (obj->field_is_present.eid_value) {
        if ((buffer_offset = json_generator__add_hexadecimal_string_child(buffer, buffer_size, buffer_offset, true, false, EID_VALUE_ESIPA_JSON_KEY, obj->eid_value.eid, sizeof(obj->eid_value.eid))) < 0) {
            LOGE("[esipa_json_generator__provide_eim_package_result] Error on eidValue, err %d", buffer_offset);
            return buffer_offset;
        }
    }

    if ((buffer_offset = json_generator__add_base64_string_child_with_custom_byte_array_encoder(buffer, buffer_size, buffer_offset, !obj->field_is_present.eid_value, true, EIM_PACKAGE_RESULT_ESIPA_JSON_KEY, (void*) &obj->eim_package_result, &esipa_json_generator__eim_package_result_encoder)) < 0) {
        LOGE("[esipa_json_generator__provide_eim_package_result] Error on eimPackageResult, err %d", buffer_offset);
        return buffer_offset;
    }

    if (buffer) {
        LOG_UTF8_DATA(eLogDebug, "[esipa_json_generator__provide_eim_package_result] ", buffer, buffer_offset);
    }

    return buffer_offset;
}

#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
int32_t esipa_json_generator__initiate_authentication_request(uint8_t* buffer, const uint32_t buffer_size, const initiate_authentication_request_esipa_t* obj) {
    int32_t buffer_offset = 0;

    if ((buffer_offset = json_generator__add_base64_string_child(buffer, buffer_size, buffer_offset, true, 
#ifndef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
        false,
#elif !defined (IPA_FEATURE_EIM_DOWNLOAD_DATA_HANDLING) && !defined (IPA_FEATURE_MINIMIZE_ESIPA_BYTES)
        false,
#else
        !obj->field_is_present.eim_transaction_id,
#endif
        EUICC_CHALLENGE_ESIPA_JSON_KEY, obj->euicc_challenge.challenge, sizeof(obj->euicc_challenge.challenge))) < 0) {
        LOGE("[esipa_json_generator__initiate_authentication_request] Error on euiccChallenge, err %d", buffer_offset);
        return buffer_offset;
    }

#ifndef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
    if ((buffer_offset = json_generator__add_base64_string_child(buffer, buffer_size, buffer_offset, false, 
#if !defined (IPA_FEATURE_EIM_DOWNLOAD_DATA_HANDLING) && !defined (IPA_FEATURE_MINIMIZE_ESIPA_BYTES)
        false,
#else
        !obj->field_is_present.eim_transaction_id,
#endif
        EUICC_INFO_1_ESIPA_JSON_KEY, obj->euicc_info_1, obj->euicc_info_1_size)) < 0) {
        LOGE("[esipa_json_generator__initiate_authentication_request] Error on euiccInfo1, err %d", buffer_offset);
        return buffer_offset;
    }
#endif

#if !defined (IPA_FEATURE_EIM_DOWNLOAD_DATA_HANDLING) && !defined (IPA_FEATURE_MINIMIZE_ESIPA_BYTES)
    if ((buffer_offset = json_generator__add_string_child(buffer, buffer_size, buffer_offset, false, !obj->field_is_present.eim_transaction_id, SMDP_ADDRESS_ESIPA_JSON_KEY, (unsigned char*) obj->smdp_address.fqdn, (uint32_t) strlen(obj->smdp_address.fqdn))) < 0) {
        LOGE("[esipa_json_generator__initiate_authentication_request] Error on smdpAddress, err %d", buffer_offset);
        return buffer_offset;
    }
#endif

    if(obj->field_is_present.eim_transaction_id) {
        if ((buffer_offset = json_generator__add_hexadecimal_string_child(buffer, buffer_size, buffer_offset, false, true, EIM_TRANSACTION_ID_ESIPA_JSON_KEY, obj->eim_transaction_id.transaction_id, (uint32_t) obj->eim_transaction_id.transaction_id_size)) < 0) {
            LOGE("[esipa_json_generator__initiate_authentication_request] Error on eimTransactionId, err %d", buffer_offset);
            return buffer_offset;
        }
    }

    if (buffer) {
        LOG_UTF8_DATA(eLogDebug, "[esipa_json_generator__initiate_authentication_request] ", buffer, buffer_offset);
    }

    return buffer_offset;
}

int32_t esipa_json_generator__authenticate_client_request_esipa(uint8_t* buffer, const uint32_t buffer_size, const authenticate_client_request_esipa_t* obj) {
    int32_t buffer_offset = 0;

    if ((buffer_offset = json_generator__add_hexadecimal_string_child(buffer, buffer_size, buffer_offset, true, false, TRANSACTION_ID_ESIPA_JSON_KEY, obj->transaction_id.transaction_id, obj->transaction_id.transaction_id_size)) < 0) {
        LOGE("[esipa_json_generator__authenticate_client_request_esipa] Error on transactionId, err %d", buffer_offset);
        return buffer_offset;
    }

    if ((buffer_offset = json_generator__add_base64_string_child(buffer, buffer_size, buffer_offset, false, true, AUTHENTICATE_SERVER_RESPONSE_ESIPA_JSON_KEY, obj->authenticate_server_response, obj->authenticate_server_response_size)) < 0) {
        LOGE("[esipa_json_generator__authenticate_client_request_esipa] Error on authenticateServerResponse, err %d", buffer_offset);
        return buffer_offset;
    }

    if (buffer) {
        LOG_UTF8_DATA(eLogDebug, "[esipa_json_generator__authenticate_client_request_esipa] ", buffer, buffer_offset);
    }

    return buffer_offset;
}

int32_t esipa_json_generator__cancel_session_request_esipa(uint8_t* buffer, const uint32_t buffer_size, const cancel_session_request_esipa_t* obj) {
    int32_t buffer_offset = 0;

    if ((buffer_offset = json_generator__add_hexadecimal_string_child(buffer, buffer_size, buffer_offset, true, false, TRANSACTION_ID_ESIPA_JSON_KEY, obj->transaction_id.transaction_id, obj->transaction_id.transaction_id_size)) < 0) {
        LOGE("[esipa_json_generator__cancel_session_request_esipa] Error on transactionId, err %d", buffer_offset);
        return buffer_offset;
    }

    if ((buffer_offset = json_generator__add_base64_string_child(buffer, buffer_size, buffer_offset, false, true, CANCEL_SESSION_RESPONSE_ESIPA_JSON_KEY, obj->cancel_session_response, obj->cancel_session_response_size)) < 0) {
        LOGE("[esipa_json_generator__cancel_session_request_esipa] Error on cancelSessionResponse, err %d", buffer_offset);
        return buffer_offset;
    }

    if (buffer) {
        LOG_UTF8_DATA(eLogDebug, "[esipa_json_generator__cancel_session_request_esipa] ", buffer, buffer_offset);
    }

    return buffer_offset;
}

int32_t esipa_json_generator__get_bound_profile_package_request_esipa(uint8_t* buffer, const uint32_t buffer_size, const get_bound_profile_package_request_esipa_t* obj) {
    int32_t buffer_offset = 0;

    if ((buffer_offset = json_generator__add_hexadecimal_string_child(buffer, buffer_size, buffer_offset, true, false, TRANSACTION_ID_ESIPA_JSON_KEY, obj->transaction_id.transaction_id, obj->transaction_id.transaction_id_size)) < 0) {
        LOGE("[esipa_json_generator__get_bound_profile_package_request_esipa] Error on transactionId, err %d", buffer_offset);
        return buffer_offset;
    }

    if ((buffer_offset = json_generator__add_base64_string_child(buffer, buffer_size, buffer_offset, false, true, PREPARE_DOWNLOAD_RESPONSE_ESIPA_JSON_KEY, obj->prepare_download_response, obj->prepare_download_response_size)) < 0) {
        LOGE("[esipa_json_generator__get_bound_profile_package_request_esipa] Error on prepareDownloadResponse, err %d", buffer_offset);
        return buffer_offset;
    }

    if (buffer) {
        LOG_UTF8_DATA(eLogDebug, "[esipa_json_generator__get_bound_profile_package_request_esipa] ", buffer, buffer_offset);
    }

    return buffer_offset;
}
#endif

static int32_t esipa_json_generator__add_epr_and_notifications(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const epr_and_notifications_t* obj) {
    int32_t buffer_offset = (int32_t) offset;
    int32_t result = 0;
    int32_t header_len = (int32_t) strlen(EPR_AND_NOTIFICATIONS_ESIPA_JSON_STRING);

    if ((buffer_offset = json_generator__add_base64_string_child(buffer, buffer_size, buffer_offset, true, false, EUICC_PACKAGE_RESULT_ESIPA_JSON_KEY, obj->euicc_package_result.tlv, obj->euicc_package_result.tlv_size)) < 0) {
        LOGE("[esipa_json_generator__add_epr_and_notifications] Error on euiccPackageResult, err %d", buffer_offset);
        return buffer_offset;
    }

    if ((buffer_offset = json_generator__add_base64_string_child(buffer, buffer_size, buffer_offset, false, true, NOTIFICATION_LIST_ESIPA_JSON_KEY, obj->notification_list, obj->notification_list_size)) < 0) {
        LOGE("[esipa_json_generator__add_epr_and_notifications] Error on notificationList, err %d", buffer_offset);
        return buffer_offset;
    }

    result = buffer_offset + header_len + 1; // + for the '}' character
    // If no buffer is provided, return what would be the new offset
    if (!buffer) {
        return result;
    }

    // Check if the space of the buffer is enough to wrap the JSON
    if ((uint32_t) result > buffer_size) {
        LOGE("[esipa_json_generator__add_epr_and_notifications] Not enough space to wrap the JSON on the buffer. Buffer size %lu, buffer size needed %ld", buffer_size, result);
        return -eNotEnoughBuffer;
    }

    memmove(buffer + offset + header_len, buffer + offset, (size_t) buffer_offset - (size_t) offset);
    memcpy(buffer + offset, EPR_AND_NOTIFICATIONS_ESIPA_JSON_STRING, header_len);
    buffer[result - 1] = '}';
    LOG_UTF8_DATA(eLogDebug, "[esipa_json_generator__add_epr_and_notifications] JSON string generated: ", buffer, result);
    return result;
}

static int32_t esipa_json_generator__provide_eim_package_result_encoder(unsigned char* buffer, const uint32_t buffer_size, const void* obj) {
    return esipa_tlv_generator__provide_eim_package_result(buffer, buffer_size, 0, (provide_eim_package_result_t*) obj);
}

static int32_t esipa_json_generator__eim_package_result_encoder(unsigned char* buffer, const uint32_t buffer_size, const void* obj) {
    return esipa_tlv_generator__eim_package_result(buffer, buffer_size, 0, (eim_package_result_t*) obj);
}

static int32_t esipa_json_generator__ipa_euicc_data_response(uint8_t* buffer, const uint32_t buffer_size,const void* obj) {
    return esipa_tlv_generator__ipa_euicc_data_response(buffer, buffer_size, 0, (ipa_euicc_data_response_t*) obj);
}
#endif