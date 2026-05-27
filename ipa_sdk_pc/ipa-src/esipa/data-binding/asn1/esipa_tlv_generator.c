/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include "esipa_tlv_generator.h"

#include "device_info.h"
#include "log.h"
#include "tlv_tags.h"
#include "tlv_lengths.h"
#include "tlv_values.h"
#include "tlv_generator.h"
#include "ipa_tlv_generator.h"
#include "byte_utils.h"

#ifdef SGP22
static int32_t esipa_tlv_generator__euicc_package_result_data_signed(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const uint8_t* eim_id, const uint8_t eim_id_size, const uint8_t* counter_value, 
    const uint32_t counter_value_size, const uint8_t* transaction_id, const uint8_t transaction_id_size, const uint8_t* euicc_result_data, const uint32_t euicc_result_data_size);
static int32_t esipa_tlv_generator__euicc_package_result_signed(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const uint8_t* eim_id, const uint8_t eim_id_size, const uint8_t* counter_value,
    const uint32_t counter_value_size, const uint8_t* transaction_id, const uint8_t transaction_id_size, const uint8_t* euicc_result_data, const uint32_t euicc_result_data_size);
#endif
static int32_t esipa_tlv_generator__handle_notification_esipa_choice_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const handle_notification_esipa_t* obj);
static int32_t esipa_tlv_generator__transfer_eim_package_response_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const transfer_eim_package_response_t* obj);
static int32_t esipa_tlv_generator__get_eim_package_request_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const get_eim_package_request_t* obj);
static int32_t esipa_tlv_generator__provide_eim_package_result_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const provide_eim_package_result_t* obj);
static int32_t esipa_tlv_generator__eim_package_result_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const eim_package_result_t* obj);
static int32_t esipa_tlv_generator__eim_package_result_response_error(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const eim_package_result_response_error_t* obj);
static int32_t esipa_tlv_generator__eim_package_result_response_error_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const eim_package_result_response_error_t* obj);
static int32_t esipa_tlv_generator__profile_download_trigger_result(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const profile_download_trigger_result_t* obj);
static int32_t esipa_tlv_generator__profile_download_trigger_result_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const profile_download_trigger_result_t* obj);
static int32_t esipa_tlv_generator__profile_download_trigger_result_data_value(uint8_t* buffer, uint32_t buffer_size, uint32_t offset, const profile_download_trigger_result_data_t* obj);
static int32_t esipa_tlv_generator__profile_download_error(uint8_t* buffer, uint32_t buffer_size, uint32_t offset, const profile_download_error_t* obj);
static int32_t esipa_tlv_generator__profile_download_error_value(uint8_t* buffer, uint32_t buffer_size, uint32_t offset, const profile_download_error_t* obj);
static int32_t esipa_tlv_generator__ipa_euicc_data_response_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const ipa_euicc_data_response_t* obj);
static int32_t esipa_tlv_generator__ipa_euicc_data(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const ipa_euicc_data_t* obj);
static int32_t esipa_tlv_generator__ipa_euicc_data_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const ipa_euicc_data_t* obj);
static int32_t esipa_tlv_generator__ipa_euicc_data_response_error(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const ipa_euicc_data_response_error_t* obj);
static int32_t esipa_tlv_generator__ipa_euicc_data_response_error_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const ipa_euicc_data_response_error_t* obj);
static int32_t esipa_tlv_generator__epr_and_notifications(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const epr_and_notifications_t* obj);
static int32_t esipa_tlv_generator__epr_and_notifications_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const epr_and_notifications_t* obj);
static int32_t esipa_tlv_generator__eim_package_error(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const eim_package_error_from_ipa_to_eim_t error);
static int32_t esipa_tlv_generator__profile_download_error_reason(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const profile_download_error_reason_t error);
static int32_t esipa_tlv_generator__ipa_euicc_data_error_code(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const ipa_euicc_data_error_code_t error);
#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
static int32_t esipa_tlv_generator__initiate_authentication_request_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const initiate_authentication_request_esipa_t* obj);
static int32_t esipa_tlv_generator__authenticate_client_request_esipa_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const authenticate_client_request_esipa_t* obj);
static int32_t esipa_tlv_generator__get_bound_profile_package_request_esipa_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const get_bound_profile_package_request_esipa_t* obj);
static int32_t esipa_tlv_generator__cancel_session_request_esipa_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const cancel_session_request_esipa_t* obj);
#endif

int32_t esipa_tlv_generator__esipa_message_from_ipa_to_eim(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const esipa_message_from_ipa_to_eim_t* obj) {
    switch (obj->choice)
    {
    case HANDLE_NOTIFICATION_ESIPA_CHOICE_EMFI:
        return esipa_tlv_generator__handle_notification_esipa(buffer, buffer_size, offset, &obj->value.handle_notification_esipa);
    case TRANSFER_EIM_PACKAGE_RESPONSE_CHOICE_EMFI:
        return esipa_tlv_generator__transfer_eim_package_response(buffer, buffer_size, offset, &obj->value.transfer_eim_package_response);
    case GET_EIM_PACKAGE_REQUEST_CHOICE_EMFI:
        return esipa_tlv_generator__get_eim_package_request(buffer, buffer_size, offset, &obj->value.get_eim_package_request);
    case PROVIDE_EIM_PACKAGE_RESULT_CHOICE_EMFI:
        return esipa_tlv_generator__provide_eim_package_result(buffer, buffer_size, offset, &obj->value.provide_eim_package_result);
    default:
        LOGE("[esipa_tlv_generator__esipa_message_from_ipa_to_eim] Unknown choice %d", obj->choice);
        return -eBadArg;
    }
}

int32_t esipa_tlv_generator__handle_notification_esipa(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const handle_notification_esipa_t* obj) {
    int32_t buffer_offset;

    // HandleNotificationEsipa CHOICE VALUE
    if ((buffer_offset = esipa_tlv_generator__handle_notification_esipa_choice_value(buffer, buffer_size, offset, obj)) < 0) {
        LOGE("[esipa_tlv_generator__handle_notification_esipa] Error on HandleNotificationEsipa CHOICE VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__handle_notification_esipa] HandleNotificationEsipa CHOICE VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap HandleNotificationEsipa CHOICE VALUE
    if (PENDING_NOTIFICATION_CHOICE_HNE == obj->choice) {
        if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, CONTEXT_CONSTRUCTED_0)) < 0) {
            LOGE("[esipa_tlv_generator__handle_notification_esipa] Error on wrapping the HandleNotificationEsipa CHOICE VALUE TLV, err %d", buffer_offset);
            return buffer_offset;
        }
    }
    LOGT("[esipa_tlv_generator__handle_notification_esipa] HandleNotificationEsipa VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap HandleNotificationEsipa VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, HANDLE_NOTIFICATION)) < 0) {
        LOGE("[esipa_tlv_generator__handle_notification_esipa] Error on wrapping the HandleNotificationEsipa VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__handle_notification_esipa] HandleNotificationEsipa TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

int32_t esipa_tlv_generator__transfer_eim_package_response(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const transfer_eim_package_response_t* obj) {
    int32_t buffer_offset;

    // TransferEimPackageResponse VALUE
    if ((buffer_offset = esipa_tlv_generator__transfer_eim_package_response_value(buffer, buffer_size, offset, obj)) < 0) {
        LOGE("[esipa_tlv_generator__transfer_eim_package_response] Error on TransferEimPackageResponse VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__transfer_eim_package_response] TransferEimPackageResponse VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap TransferEimPackageResponse VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, TRANSFER_EIM_PACKAGE)) < 0) {
        LOGE("[esipa_tlv_generator__transfer_eim_package_response] Error on wrapping the TransferEimPackageResponse VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__transfer_eim_package_response] TransferEimPackageResponse TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

int32_t esipa_tlv_generator__get_eim_package_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const get_eim_package_request_t* obj) {
    int32_t buffer_offset;

    // GetEimPackageRequest VALUE
    if ((buffer_offset = esipa_tlv_generator__get_eim_package_request_value(buffer, buffer_size, offset, obj)) < 0) {
        LOGE("[esipa_tlv_generator__get_eim_package_request] Error on GetEimPackageRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__get_eim_package_request] GetEimPackageRequest VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap GetEimPackageRequest VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, GET_EIM_PACKAGE)) < 0) {
        LOGE("[esipa_tlv_generator__get_eim_package_request] Error on wrapping the GetEimPackageRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__get_eim_package_request] GetEimPackageRequest TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

int32_t esipa_tlv_generator__provide_eim_package_result(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const provide_eim_package_result_t* obj) {
    int32_t buffer_offset;

    // ProvideEimPackageResult VALUE
    if ((buffer_offset = esipa_tlv_generator__provide_eim_package_result_value(buffer, buffer_size, offset, obj)) < 0) {
        LOGE("[esipa_tlv_generator__provide_eim_package_result] Error on ProvideEimPackageResult VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__provide_eim_package_result] ProvideEimPackageResult VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap ProvideEimPackageResult VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, PROVIDE_EIM_PACKAGE_RESULT)) < 0) {
        LOGE("[esipa_tlv_generator__provide_eim_package_result] Error on wrapping the ProvideEimPackageResult VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__provide_eim_package_result] ProvideEimPackageResult TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
int32_t esipa_tlv_generator__initiate_authentication_request(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const initiate_authentication_request_esipa_t* obj) {
    int32_t buffer_offset;

    // InitiateAuthenticationRequestEsipa VALUE
    if ((buffer_offset = esipa_tlv_generator__initiate_authentication_request_value(buffer, buffer_size, offset, obj)) < 0) {
        LOGE("[esipa_tlv_generator__initiate_authentication_request] Error on InitiateAuthenticationRequestEsipa VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__initiate_authentication_request] InitiateAuthenticationRequestEsipa VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap InitiateAuthenticationRequestEsipa VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, INITIATE_AUTHENTICATION)) < 0) {
        LOGE("[esipa_tlv_generator__initiate_authentication_request] Error on wrapping the InitiateAuthenticationRequestEsipa VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__initiate_authentication_request] InitiateAuthenticationRequestEsipa TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

int32_t esipa_tlv_generator__authenticate_client_request_esipa(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const authenticate_client_request_esipa_t* obj) {
    int32_t buffer_offset;

    // AuthenticateClientRequestEsipa VALUE
    if ((buffer_offset = esipa_tlv_generator__authenticate_client_request_esipa_value(buffer, buffer_size, offset, obj)) < 0) {
        LOGE("[esipa_tlv_generator__authenticate_client_request_esipa] Error on AuthenticateClientRequestEsipa VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__authenticate_client_request_esipa] AuthenticateClientRequestEsipa VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap AuthenticateClientRequestEsipa VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, AUTHENTICATE_CLIENT)) < 0) {
        LOGE("[esipa_tlv_generator__authenticate_client_request_esipa] Error on wrapping the AuthenticateClientRequestEsipa VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__authenticate_client_request_esipa] AuthenticateClientRequestEsipa TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

int32_t esipa_tlv_generator__cancel_session_request_esipa(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const cancel_session_request_esipa_t* obj) {
     int32_t buffer_offset;

    // CancelSessionRequestEsipa VALUE
    if ((buffer_offset = esipa_tlv_generator__cancel_session_request_esipa_value(buffer, buffer_size, offset, obj)) < 0) {
        LOGE("[esipa_tlv_generator__cancel_session_request_esipa] Error on CancelSessionRequestEsipa VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__cancel_session_request_esipa] CancelSessionRequestEsipa VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap CancelSessionRequestEsipa VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, CANCEL_SESSION)) < 0) {
        LOGE("[esipa_tlv_generator__cancel_session_request_esipa] Error on wrapping the CancelSessionRequestEsipa VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__cancel_session_request_esipa] CancelSessionRequestEsipa TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}


int32_t esipa_tlv_generator__get_bound_profile_package_request_esipa(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const get_bound_profile_package_request_esipa_t* obj) {
    int32_t buffer_offset;

    // Calculate the size of the GetBoundProfilePackageRequestEsipa VALUE
    if ((buffer_offset = esipa_tlv_generator__get_bound_profile_package_request_esipa_value(buffer, buffer_size, offset, obj)) < 0) {
        LOGE("[esipa_tlv_generator__get_bound_profile_package_request_esipa] Error calculating the size of the GetBoundProfilePackageRequestEsipa VALUE TLV, rc %d", buffer_offset);
        return buffer_offset;
    }

    LOGT("[esipa_tlv_generator__get_bound_profile_package_request_esipa] GetBoundProfilePackageRequest VALUE size : %u", (uint32_t)buffer_offset - offset);

    // Wrap GetBoundProfilePackageRequestEsipa VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t)buffer_offset, GET_BOUND_PROFILE_PACKAGE)) < 0) {
        LOGE("[esipa_tlv_generator__get_bound_profile_package_request_esipa] Error on wrapping the GetBoundProfilePackageRequest VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__get_bound_profile_package_request_esipa] GetBoundProfilePackageRequest TLV size: %u", (uint32_t)buffer_offset - offset);

    return buffer_offset;
}

#endif

int32_t esipa_tlv_generator__ipa_euicc_data_response(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const ipa_euicc_data_response_t* obj) {
    int32_t buffer_offset;

    // IpaEuiccDataResponse VALUE
    if ((buffer_offset = esipa_tlv_generator__ipa_euicc_data_response_value(buffer, buffer_size, offset, obj)) < 0) {
        LOGE("[esipa_tlv_generator__ipa_euicc_data_response] Error on IpaEuiccDataResponse VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__ipa_euicc_data_response] IpaEuiccDataResponse VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap IpaEuiccDataResponse VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, IPA_EUICC_DATA)) < 0) {
        LOGE("[esipa_tlv_generator__ipa_euicc_data_response] Error on wrapping the IpaEuiccDataResponse VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__ipa_euicc_data_response] IpaEuiccDataResponse TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

int32_t esipa_tlv_generator__eim_package_result(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const eim_package_result_t* obj) {
    int32_t buffer_offset;

    // EimPackageResult VALUE
    if ((buffer_offset = esipa_tlv_generator__eim_package_result_value(buffer, buffer_size, offset, obj)) < 0) {
        LOGE("[esipa_tlv_generator__eim_package_result] Error on EimPackageResult VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__eim_package_result] EimPackageResult VALUE size: %u", (uint32_t) buffer_offset - offset);

    // EimPackageResult VALUE is not wrapped by any tag

    return buffer_offset;
}

static int32_t esipa_tlv_generator__handle_notification_esipa_choice_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const handle_notification_esipa_t* obj) {
    switch (obj->choice)
    {
    case PENDING_NOTIFICATION_CHOICE_HNE:
        return tlv_generator__add_tlv_full_bytes(buffer, buffer_size, offset, obj->value.pending_notification.pending_notification, obj->value.pending_notification.pending_notification_size);
    case PROVIDE_EIM_PACKAGE_RESULT_CHOICE_HNE:
        return esipa_tlv_generator__provide_eim_package_result(buffer, buffer_size, offset, &obj->value.provide_eim_package_result);
    default:
        LOGE("[esipa_tlv_generator__handle_notification_esipa_value] Unknown choice %d", obj->choice);
        return -eBadArg;
    }
}

static int32_t esipa_tlv_generator__transfer_eim_package_response_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const transfer_eim_package_response_t* obj) {
    switch (obj->choice)
    {
    case EUICC_PACKAGE_RESULT_CHOICE_TEPR:
        return tlv_generator__add_tlv_full_bytes(buffer, buffer_size, offset, obj->value.euicc_package_result.tlv, obj->value.euicc_package_result.tlv_size);
    case EPR_AND_NOTIFICATIONS_CHOICE_TEPR:
        return esipa_tlv_generator__epr_and_notifications(buffer, buffer_size, offset, &obj->value.epr_and_notifications);
    case IPA_EUICC_DATA_RESPONSE_CHOICE_TEPR:
        return esipa_tlv_generator__ipa_euicc_data_response(buffer, buffer_size, offset, &obj->value.ipa_euicc_data_response);
    case EIM_PACKAGE_RECEIVED_CHOICE_TEPR:
        return tlv_generator__add_tlv_null_value(buffer, buffer_size, offset, ASN1_DER_NULL);
    case EIM_PACKAGE_ERROR_CHOICE_TEPR:
        return esipa_tlv_generator__eim_package_error(buffer, buffer_size, offset, obj->value.eim_package_error);
    default:
        LOGE("[esipa_tlv_generator__transfer_eim_package_response_value] Unknown choice %d", obj->choice);
        return -eBadArg;
    }
}

static int32_t esipa_tlv_generator__get_eim_package_request_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const get_eim_package_request_t* obj) {
    int32_t buffer_offset = (int32_t) offset;

    // eidValue
    if ((buffer_offset = tlv_generator__add_tlv(buffer, buffer_size, (uint32_t) buffer_offset, (unsigned short) EID, (uint8_t*) obj->eid.eid, sizeof(obj->eid.eid))) < 0) {
        LOGE("[esipa_tlv_generator__get_eim_package_request_value] Error on eidValue TLV, rc %ld", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__get_eim_package_request_value] Buffer offset after eidValue: %u", buffer_offset);

    // notifyStateChange
    if (obj->field_is_present.notify_state_change) {
        if ((buffer_offset = tlv_generator__add_tlv_null_value(buffer, buffer_size, (uint32_t) buffer_offset, CONTEXT_PRIMITIVE_0)) < 0) {
            LOGE("[esipa_tlv_generator__get_eim_package_request_value] Error on notifyStateChange TLV, rc %ld", buffer_offset);
            return buffer_offset;
        }
        LOGT("[esipa_tlv_generator__get_eim_package_request_value] Buffer offset after notifyStateChange: %u", buffer_offset);

        if ((buffer_offset = tlv_generator__add_tlv_integer_value(buffer, buffer_size, (uint32_t) buffer_offset, CONTEXT_PRIMITIVE_1, (unsigned int) obj->state_change_cause)) < 0) {
            LOGE("[esipa_tlv_generator__get_eim_package_request_value] Error on stateChangeCause TLV, rc %ld", buffer_offset);
            return buffer_offset;
        }
        LOGT("[esipa_tlv_generator__get_eim_package_request_value] Buffer offset after stateChangeCause: %u", buffer_offset);
    }    

    //rPLMN
    if (obj->field_is_present.rplmn) {
        if ((buffer_offset = tlv_generator__add_tlv(buffer, buffer_size, (uint32_t) buffer_offset, (unsigned short) CONTEXT_PRIMITIVE_2, (uint8_t*) obj->rplmn.value, sizeof(obj->rplmn.value))) < 0) {
            LOGE("[esipa_tlv_generator__get_eim_package_request_value] Error on rPLMN TLV, rc %ld", buffer_offset);
            return buffer_offset;
        }
        LOGT("[esipa_tlv_generator__get_eim_package_request_value] Buffer offset after rPLMN: %u", buffer_offset);
    }

    LOGT("[esipa_tlv_generator__get_eim_package_request_value] getEimPackageRequest TLV value size %u", (uint32_t) buffer_offset - offset);
    return buffer_offset;
}

static int32_t esipa_tlv_generator__provide_eim_package_result_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const provide_eim_package_result_t* obj) {
    int32_t buffer_offset = (int32_t) offset;

    // eidValue OPTIONAL
    if (obj->field_is_present.eid_value) {
        if ((buffer_offset = tlv_generator__add_tlv(buffer, buffer_size, (uint32_t) buffer_offset, EID, obj->eid_value.eid, sizeof(obj->eid_value.eid))) < 0) {
            LOGE("[esipa_tlv_generator__provide_eim_package_result_value] Error on eidValue TLV, err %d", buffer_offset);
            return buffer_offset;
        }
        LOGT("[esipa_tlv_generator__provide_eim_package_result_value] ProvideEimPackageResult VALUE size after eidValue: %u", buffer_offset - offset);
    }

    // eimPackageResult
    if ((buffer_offset = esipa_tlv_generator__eim_package_result(buffer, buffer_size, (uint32_t) buffer_offset, &obj->eim_package_result)) < 0) {
        LOGE("[esipa_tlv_generator__provide_eim_package_result_value] Error on eimPackageResult TLV, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__provide_eim_package_result_value] ProvideEimPackageResult VALUE size after eimPackageResult: %u", buffer_offset - offset);

    return buffer_offset;
}

static int32_t esipa_tlv_generator__eim_package_result_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const eim_package_result_t* obj) {
    switch (obj->choice)
    {
    case EUICC_PACKAGE_RESULT_CHOICE_PEPR:
        return tlv_generator__add_tlv_full_bytes(buffer, buffer_size, offset, obj->value.euicc_package_result.tlv, obj->value.euicc_package_result.tlv_size);
    case EPR_AND_NOTIFICATIONS_CHOICE_PEPR:
        return esipa_tlv_generator__epr_and_notifications(buffer, buffer_size, offset, &obj->value.epr_and_notifications);
    case IPA_EUICC_DATA_RESPONSE_CHOICE_PEPR:
        return esipa_tlv_generator__ipa_euicc_data_response(buffer, buffer_size, offset, &obj->value.ipa_euicc_data_response);
    case PROFILE_DOWNLOAD_TRIGGER_RESULT_CHOICE_PEPR:
        return esipa_tlv_generator__profile_download_trigger_result(buffer, buffer_size, offset, &obj->value.profile_download_trigger_result);
    case EIM_PACKAGE_RESULT_RESPONSE_ERROR_CHOICE_PEPR:
        return esipa_tlv_generator__eim_package_result_response_error(buffer, buffer_size, offset, &obj->value.eim_package_result_response_error);
    default:
        LOGE("[esipa_tlv_generator__provide_eim_package_result_value] Unknown choice %d", obj->choice);
        return -eBadArg;
    }
}

static int32_t esipa_tlv_generator__eim_package_result_response_error(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const eim_package_result_response_error_t* obj) {
    int32_t buffer_offset;

    // EimPackageResultResponseError VALUE
    if ((buffer_offset = esipa_tlv_generator__eim_package_result_response_error_value(buffer, buffer_size, offset, obj)) < 0) {
        LOGE("[esipa_tlv_generator__eim_package_result_response_error] Error on EimPackageResultResponseError VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__eim_package_result_response_error] EimPackageResultResponseError VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap EimPackageResultResponseError VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, CONTEXT_CONSTRUCTED_0)) < 0) {
        LOGE("[esipa_tlv_generator__eim_package_result_response_error] Error on wrapping the EimPackageResultResponseError VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__eim_package_result_response_error] EimPackageResultResponseError TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

static int32_t esipa_tlv_generator__eim_package_result_response_error_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const eim_package_result_response_error_t* obj) {
    int32_t buffer_offset = (int32_t) offset;

    // eimTransactionId OPTIONAL
    if (obj->field_is_present.eim_transaction_id) {
        if ((buffer_offset = tlv_generator__add_tlv_transaction_id_value(buffer, buffer_size, (uint32_t) buffer_offset, CONTEXT_PRIMITIVE_0, &obj->eim_transaction_id)) < 0) {
            LOGE("[esipa_tlv_generator__eim_package_result_response_error_value] Error on eimTransactionId TLV, err %d", buffer_offset);
            return buffer_offset;
        }
        LOGT("[esipa_tlv_generator__eim_package_result_response_error_value] EimPackageResultResponseError VALUE size after eimTransactionId: %u", buffer_offset - offset);
    }

    // eimPackageResultErrorCode
    if ((buffer_offset = esipa_tlv_generator__eim_package_error(buffer, buffer_size, (uint32_t) buffer_offset, obj->eim_package_result_error_code)) < 0) {
        LOGE("[esipa_tlv_generator__eim_package_result_response_error_value] Error on eimPackageResult TLV, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__eim_package_result_response_error_value] EimPackageResultResponseError VALUE size after eimPackageResult: %u", buffer_offset - offset);

    return buffer_offset;
}

static int32_t esipa_tlv_generator__profile_download_trigger_result(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const profile_download_trigger_result_t* obj) {
    int32_t buffer_offset;

    // ProfileDownloadTriggerResult VALUE
    if ((buffer_offset = esipa_tlv_generator__profile_download_trigger_result_value(buffer, buffer_size, offset, obj)) < 0) {
        LOGE("[esipa_tlv_generator__profile_download_trigger_result] Error on ProfileDownloadTriggerResult VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__profile_download_trigger_result] ProfileDownloadTriggerResult VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap ProfileDownloadTriggerResult VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, PROFILE_DOWNLOAD_TRIGGER)) < 0) {
        LOGE("[esipa_tlv_generator__profile_download_trigger_result] Error on wrapping the ProfileDownloadTriggerResult VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__profile_download_trigger_result] ProfileDownloadTriggerResult TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

static int32_t esipa_tlv_generator__profile_download_trigger_result_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const profile_download_trigger_result_t* obj) {
    int32_t buffer_offset = (int32_t) offset;

    // eimTransactionId OPTIONAL
    if (obj->field_is_present.eim_transaction_id) {
        if ((buffer_offset = tlv_generator__add_tlv_transaction_id_value(buffer, buffer_size, (uint32_t) buffer_offset, PROFILE_DOWNLOAD_TRIGGER_EIM_TRANSACTION_ID, &obj->eim_transaction_id)) < 0) {
            LOGE("[esipa_tlv_generator__profile_download_trigger_result_value] Error on eimTransactionId TLV, err %d", buffer_offset);
            return buffer_offset;
        }
        LOGT("[esipa_tlv_generator__profile_download_trigger_result_value] ProfileDownloadTriggerResult VALUE size after eimTransactionId: %u", buffer_offset - offset);
    }

    // profileDownloadTriggerResultData
    if ((buffer_offset = esipa_tlv_generator__profile_download_trigger_result_data_value(buffer, buffer_size, (uint32_t) buffer_offset, &obj->profile_download_trigger_result_data)) < 0) {
        LOGE("[esipa_tlv_generator__profile_download_trigger_result_value] Error on profileDownloadTriggerResultData TLV, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__profile_download_trigger_result_value] PrepareDownloadRequest VALUE size after profileDownloadTriggerResultData: %u", buffer_offset - offset);

    return buffer_offset;
}

static int32_t esipa_tlv_generator__profile_download_trigger_result_data_value(uint8_t* buffer, uint32_t buffer_size, uint32_t offset, const profile_download_trigger_result_data_t* obj) {
    switch (obj->choice) 
    {
    case PROFILE_INSTALLATION_RESULT_CHOICE:
        return tlv_generator__add_tlv_full_bytes(buffer, buffer_size, offset, obj->value.profile_installation_result.pir, obj->value.profile_installation_result.pir_size);
    case PROFILE_DOWNLOAD_ERROR_CHOICE:
        return esipa_tlv_generator__profile_download_error(buffer, buffer_size, offset, &obj->value.profile_download_error);
    default:
        LOGE("[esipa_tlv_generator__profile_download_trigger_result_data_value] Unknown choice %d", obj->choice);
        return -eBadArg;
    }
}

static int32_t esipa_tlv_generator__profile_download_error(uint8_t* buffer, uint32_t buffer_size, uint32_t offset, const profile_download_error_t* obj) {
    int32_t buffer_offset;

    // profileDownloadError VALUE
    if ((buffer_offset = esipa_tlv_generator__profile_download_error_value(buffer, buffer_size, offset, obj)) < 0) {
        LOGE("[esipa_tlv_generator__profile_download_error] Error on profileDownloadError VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__profile_download_error] profileDownloadError VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap profileDownloadError VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, ASN1_DER_SEQUENCE)) < 0) {
        LOGE("[esipa_tlv_generator__profile_download_error] Error on wrapping the profileDownloadError VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__profile_download_error] profileDownloadError TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

static int32_t esipa_tlv_generator__profile_download_error_value(uint8_t* buffer, uint32_t buffer_size, uint32_t offset, const profile_download_error_t* obj) {
    int32_t buffer_offset = (int32_t) offset;

    /** profileDownloadError children TLVs */
    // profileDownloadErrorReason
    if ((buffer_offset = esipa_tlv_generator__profile_download_error_reason(buffer, buffer_size, (uint32_t) buffer_offset, obj->profile_download_error_reason)) < 0) {
        LOGE("[esipa_tlv_generator__profile_download_error_value] Error on profileDownloadErrorReason TLV, rc %ld", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__profile_download_error_value] Buffer offset after profileDownloadErrorReason: %u", buffer_offset);

    // errorResponse
    if (obj->error_response) {
        if ((buffer_offset = tlv_generator__add_tlv(buffer, buffer_size, (uint32_t) buffer_offset, (unsigned short) ASN1_DER_OCTET_STRING, obj->error_response, obj->error_response_size)) < 0) {
            LOGE("[esipa_tlv_generator__profile_download_error_value] Error on errorResponse TLV, rc %ld", buffer_offset);
            return buffer_offset;
        }
        LOGT("[esipa_tlv_generator__profile_download_error_value] Buffer offset after errorResponse: %u", buffer_offset);
    }
    LOGT("[esipa_tlv_generator__profile_download_error_value] profileDownloadError TLV value size %u", buffer_offset);

    return buffer_offset;
}

static int32_t esipa_tlv_generator__ipa_euicc_data_response_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const ipa_euicc_data_response_t* obj) {
    switch (obj->choice)
    {
    case IPA_EUICC_DATA_CHOICE:
        return esipa_tlv_generator__ipa_euicc_data(buffer, buffer_size, offset, &obj->value.ipa_euicc_data);
    case IPA_EUICC_DATA_RESPONSE_ERROR_CHOICE:
        return esipa_tlv_generator__ipa_euicc_data_response_error(buffer, buffer_size, offset, &obj->value.ipa_euicc_data_response_error);
    default:
        LOGE("[esipa_tlv_generator__ipa_euicc_data_response_value] Unknown choice %d", obj->choice);
        return -eBadArg;
    }
}

static int32_t esipa_tlv_generator__ipa_euicc_data(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const ipa_euicc_data_t* obj) {
    int32_t buffer_offset;

    // ipaEuiccData VALUE
    if ((buffer_offset = esipa_tlv_generator__ipa_euicc_data_value(buffer, buffer_size, offset, obj)) < 0) {
        LOGE("[esipa_tlv_generator__ipa_euicc_data] Error on ipaEuiccData VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__ipa_euicc_data] ipaEuiccData VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap ipaEuiccData VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, CONTEXT_CONSTRUCTED_0)) < 0) {
        LOGE("[esipa_tlv_generator__ipa_euicc_data] Error on wrapping the ipaEuiccData VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__ipa_euicc_data] ipaEuiccData TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

static int32_t esipa_tlv_generator__ipa_euicc_data_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const ipa_euicc_data_t* obj) {
    int32_t buffer_offset = (int32_t) offset;

    /** ipaEuiccData children TLVs */
    // notificationsList
    if (obj->field_is_present.notifications_list) {
        if ((buffer_offset = tlv_generator__add_tlv_full_bytes(buffer, buffer_size, (uint32_t) buffer_offset, obj->notifications_list, obj->notifications_list_size)) < 0) {
            LOGE("[esipa_tlv_generator__ipa_euicc_data_value] Error on notificationsList TLV, rc %ld", buffer_offset);
            return buffer_offset;
        }
        LOGT("[esipa_tlv_generator__ipa_euicc_data_value] Buffer offset after notificationsList: %u", buffer_offset);
    }
    // defaultSmdpAddress
    if (obj->field_is_present.default_smdp_address) {
        if ((buffer_offset = tlv_generator__add_tlv_cstring_value(buffer, buffer_size, (uint32_t) buffer_offset, (unsigned short) IPA_EUICC_DATA_DEFAULT_SMDP, obj->default_smdp_address.fqdn)) < 0) {
            LOGE("[esipa_tlv_generator__ipa_euicc_data_value] Error on defaultSmdpAddress TLV, rc %ld", buffer_offset);
            return buffer_offset;
        }
        LOGT("[esipa_tlv_generator__ipa_euicc_data_value] Buffer offset after defaultSmdpAddress: %u", buffer_offset);
    }
    // euiccPackageResultList
    if (obj->field_is_present.euicc_package_result_list) {
        if ((buffer_offset = tlv_generator__add_tlv_full_bytes(buffer, buffer_size, (uint32_t) buffer_offset, obj->euicc_package_result_list, obj->euicc_package_result_list_size)) < 0) {
            LOGE("[esipa_tlv_generator__ipa_euicc_data_value] Error on euiccPackageResultList TLV, rc %ld", buffer_offset);
            return buffer_offset;
        }
        LOGT("[esipa_tlv_generator__ipa_euicc_data_value] Buffer offset after euiccPackageResultList: %u", buffer_offset);
    }
    // euiccInfo1
    if (obj->field_is_present.euicc_info_1) {
        if ((buffer_offset = tlv_generator__add_tlv_full_bytes(buffer, buffer_size, (uint32_t) buffer_offset, obj->euicc_info_1, obj->euicc_info_1_size)) < 0) {
            LOGE("[esipa_tlv_generator__ipa_euicc_data_value] Error on euiccInfo1 TLV, rc %ld", buffer_offset);
            return buffer_offset;
        }
        LOGT("[esipa_tlv_generator__ipa_euicc_data_value] Buffer offset after euiccInfo1: %u", buffer_offset);
    }
    // euiccInfo2
    if (obj->field_is_present.euicc_info_2) {
        if ((buffer_offset = tlv_generator__add_tlv_full_bytes(buffer, buffer_size, (uint32_t) buffer_offset, obj->euicc_info_2, obj->euicc_info_2_size)) < 0) {
            LOGE("[esipa_tlv_generator__ipa_euicc_data_value] Error on euiccInfo2 TLV, rc %ld", buffer_offset);
            return buffer_offset;
        }
        LOGT("[esipa_tlv_generator__ipa_euicc_data_value] Buffer offset after euiccInfo2: %u", buffer_offset);
    }
    // rootSmdsAddress
    if (obj->field_is_present.root_smds_address) {
        if ((buffer_offset = tlv_generator__add_tlv_cstring_value(buffer, buffer_size, (uint32_t) buffer_offset, (unsigned short) IPA_EUICC_DATA_ROOT_SMDS, obj->root_smds_address.fqdn)) < 0) {
            LOGE("[esipa_tlv_generator__ipa_euicc_data_value] Error on rootSmdsAddress TLV, rc %ld", buffer_offset);
            return buffer_offset;
        }
        LOGT("[esipa_tlv_generator__ipa_euicc_data_value] Buffer offset after rootSmdsAddress: %u", buffer_offset);
    }
    // associationToken
    if (obj->field_is_present.association_token) {
        if ((buffer_offset = tlv_generator__add_tlv_integer_value(buffer, buffer_size, (uint32_t) buffer_offset, (unsigned short) IPA_EUICC_DATA_ASSOCIATION_TOKEN, obj->association_token)) < 0) {
            LOGE("[esipa_tlv_generator__ipa_euicc_data_value] Error on associationToken TLV, rc %ld", buffer_offset);
            return buffer_offset;
        }
        LOGT("[esipa_tlv_generator__ipa_euicc_data_value] Buffer offset after associationToken: %u", buffer_offset);
    }
    // eumCertificate
    if (obj->field_is_present.eum_cert) {
        if ((buffer_offset = tlv_generator__add_tlv_full_bytes(buffer, buffer_size, (uint32_t) buffer_offset, obj->eum_certificate, obj->eum_certificate_size)) < 0) {
            LOGE("[esipa_tlv_generator__ipa_euicc_data_value] Error on eumCertificate TLV, rc %ld", buffer_offset);
            return buffer_offset;
        }
        LOGT("[esipa_tlv_generator__ipa_euicc_data_value] Buffer offset after eumCertificate: %u", buffer_offset);
    }
    // euiccCertificate
    if (obj->field_is_present.euicc_cert) {
        if ((buffer_offset = tlv_generator__add_tlv_full_bytes(buffer, buffer_size, (uint32_t) buffer_offset, obj->euicc_certificate, obj->euicc_certificate_size)) < 0) {
            LOGE("[esipa_tlv_generator__ipa_euicc_data_value] Error on euiccCertificate TLV, rc %ld", buffer_offset);
            return buffer_offset;
        }
        LOGT("[esipa_tlv_generator__ipa_euicc_data_value] Buffer offset after euiccCertificate: %u", buffer_offset);
    }
    // eimTransactionId 
    if (obj->field_is_present.eim_transaction_id) {
        if ((buffer_offset = tlv_generator__add_tlv(buffer, buffer_size, (uint32_t) buffer_offset, (unsigned short) IPA_EUICC_DATA_EIM_TRANSACTION_ID, obj->eim_transaction_id.transaction_id, obj->eim_transaction_id.transaction_id_size)) < 0) {
            LOGE("[esipa_tlv_generator__ipa_euicc_data_value] Error adding the eimTransactionId TLV, rc %ld", buffer_offset);
            return buffer_offset;
        }
    }
    // ipaCapabilities
    if (obj->field_is_present.ipa_capabilities) {
        if ((buffer_offset = ipa_tlv_generator__ipa_capabilities(buffer, buffer_size, (uint32_t) buffer_offset, (unsigned short) IPA_EUICC_DATA_IPA_CAPABILITES, &obj->ipa_capabilities)) < 0) {
            LOGE("[esipa_tlv_generator__ipa_euicc_data_value] Error on ipaCapabilities TLV, rc %ld", buffer_offset);
            return buffer_offset;
        }
        LOGT("[esipa_tlv_generator__ipa_euicc_data_value] Buffer offset after ipaCapabilities: %u", buffer_offset);
    }
    // deviceInfo
    if (obj->field_is_present.device_information) {
        if ((buffer_offset = device_info__tlv_generator(buffer, buffer_size, (uint32_t) buffer_offset, false, (unsigned short) IPA_EUICC_DATA_DEVICE_INFO, obj->device_info)) < 0) {
            LOGE("[esipa_tlv_generator__ipa_euicc_data_value] Error on deviceInfo TLV, rc %ld", buffer_offset);
            return buffer_offset;
        }
        LOGT("[esipa_tlv_generator__ipa_euicc_data_value] Buffer offset after deviceInfo: %u", buffer_offset);
    }

    LOGT("[esipa_tlv_generator__ipa_euicc_data_value] ipaEuiccData TLV value size %u", buffer_offset);
    return buffer_offset;
}

static int32_t esipa_tlv_generator__ipa_euicc_data_response_error(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const ipa_euicc_data_response_error_t* obj) {
    int32_t buffer_offset;

    // IpaEuiccDataResponseError VALUE
    if ((buffer_offset = esipa_tlv_generator__ipa_euicc_data_response_error_value(buffer, buffer_size, offset, obj)) < 0) {
        LOGE("[esipa_tlv_generator__ipa_euicc_data] Error on IpaEuiccDataResponseError VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__ipa_euicc_data] IpaEuiccDataResponseError VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap IpaEuiccDataResponseError VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, CONTEXT_CONSTRUCTED_1)) < 0) {
        LOGE("[esipa_tlv_generator__ipa_euicc_data] Error on wrapping the IpaEuiccDataResponseError VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__ipa_euicc_data] IpaEuiccDataResponseError TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

static int32_t esipa_tlv_generator__ipa_euicc_data_response_error_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const ipa_euicc_data_response_error_t* obj) {
    int32_t buffer_offset = (int32_t) offset;

    /** IpaEuiccDataResponseError children TLVs */
    // eimTransactionId OPTIONAL
    if (obj->field_is_present.eim_transaction_id) {
        if ((buffer_offset = tlv_generator__add_tlv(buffer, buffer_size, (uint32_t) buffer_offset, (unsigned short) CONTEXT_PRIMITIVE_0, obj->eim_transaction_id.transaction_id, obj->eim_transaction_id.transaction_id_size)) < 0) {
            LOGE("[esipa_tlv_generator__ipa_euicc_data_response_error_value] Error adding the eimTransactionId TLV, rc %ld", buffer_offset);
            return buffer_offset;
        }
    }
    // ipaEuiccDataErrorCode
    if ((buffer_offset = esipa_tlv_generator__ipa_euicc_data_error_code(buffer, buffer_size, (uint32_t) buffer_offset, obj->ipa_euicc_data_error_code)) < 0) {
        LOGE("[esipa_tlv_generator__ipa_euicc_data_response_error_value] Error on ipaEuiccDataErrorCode TLV, rc %ld", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__ipa_euicc_data_response_error_value] Buffer offset after ipaEuiccDataErrorCode: %u", buffer_offset);

    return buffer_offset;
}

static int32_t esipa_tlv_generator__epr_and_notifications(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const epr_and_notifications_t* obj) {
    int32_t buffer_offset;

    // ePRAndNotifications VALUE
    if ((buffer_offset = esipa_tlv_generator__epr_and_notifications_value(buffer, buffer_size, offset, obj)) < 0) {
        LOGE("[esipa_tlv_generator__epr_and_notifications] Error on ePRAndNotifications VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__epr_and_notifications] ePRAndNotifications VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap ePRAndNotifications VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, ASN1_DER_SEQUENCE)) < 0) {
        LOGE("[esipa_tlv_generator__epr_and_notifications] Error on wrapping the ePRAndNotifications VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__epr_and_notifications] ePRAndNotifications TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

static int32_t esipa_tlv_generator__epr_and_notifications_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const epr_and_notifications_t* obj) {
    int32_t buffer_offset = (int32_t) offset;

    // euiccPackageResult
    if ((buffer_offset = tlv_generator__add_tlv_full_bytes(buffer, buffer_size, (uint32_t) buffer_offset, obj->euicc_package_result.tlv, obj->euicc_package_result.tlv_size)) < 0) {
        LOGE("[esipa_tlv_generator__epr_and_notifications_value] Error on euiccPackageResult TLV, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__epr_and_notifications_value] ePRAndNotifications VALUE size after euiccPackageResult: %u", buffer_offset - offset);

    // notificationList
    if ((buffer_offset = tlv_generator__add_tlv_full_bytes(buffer, buffer_size, (uint32_t) buffer_offset, obj->notification_list, obj->notification_list_size)) < 0) {
        LOGE("[esipa_tlv_generator__epr_and_notifications_value] Error on notificationList TLV, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__epr_and_notifications_value] ePRAndNotifications VALUE size after notificationList: %u", buffer_offset - offset);

    return buffer_offset;
}

static int32_t esipa_tlv_generator__eim_package_error(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const eim_package_error_from_ipa_to_eim_t error) {
    uint8_t tlv_value[1] = { error };
    return tlv_generator__add_tlv(buffer, buffer_size, offset, ASN1_DER_INTEGER, tlv_value, sizeof(tlv_value));
}

static int32_t esipa_tlv_generator__profile_download_error_reason(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const profile_download_error_reason_t error) {
    uint8_t tlv_value[1] = { error };
    return tlv_generator__add_tlv(buffer, buffer_size, offset, CONTEXT_PRIMITIVE_0, tlv_value, sizeof(tlv_value));
}

static int32_t esipa_tlv_generator__ipa_euicc_data_error_code(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const ipa_euicc_data_error_code_t error) {
    uint8_t tlv_value[1] = { error };
    return tlv_generator__add_tlv(buffer, buffer_size, offset, ASN1_DER_INTEGER, tlv_value, sizeof(tlv_value));
}

#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
static int32_t esipa_tlv_generator__initiate_authentication_request_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const initiate_authentication_request_esipa_t* obj) {
    int32_t buffer_offset = (int32_t) offset;

    // euiccChallenge
    if ((buffer_offset = tlv_generator__add_tlv(buffer, buffer_size, (uint32_t) buffer_offset, CONTEXT_PRIMITIVE_1, obj->euicc_challenge.challenge, sizeof(obj->euicc_challenge.challenge))) < 0) {
        LOGE("[esipa_tlv_generator__initiate_authentication_request_value] Error on euiccChallenge TLV, rc %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__initiate_authentication_request_value] InitiateAuthenticationRequestEsipa VALUE size after euiccChallenge: %u", buffer_offset - offset);

#if !defined (IPA_FEATURE_EIM_DOWNLOAD_DATA_HANDLING) && !defined (IPA_FEATURE_MINIMIZE_ESIPA_BYTES)
    // smdpAddress
    if ((buffer_offset = tlv_generator__add_tlv_cstring_value(buffer, buffer_size, (uint32_t) buffer_offset, CONTEXT_PRIMITIVE_3, obj->smdp_address.fqdn)) < 0) {
        LOGE("[esipa_tlv_generator__initiate_authentication_request_value] Error on smdpAddress TLV, rc %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__initiate_authentication_request_value] InitiateAuthenticationRequestEsipa VALUE size after smdpAddress: %u", buffer_offset - offset);
#endif
#ifndef IPA_FEATURE_MINIMIZE_ESIPA_BYTES
    // euiccInfo1
    if ((buffer_offset = tlv_generator__add_tlv_full_bytes(buffer, buffer_size, (uint32_t) buffer_offset, obj->euicc_info_1, obj->euicc_info_1_size)) < 0) {
        LOGE("[esipa_tlv_generator__initiate_authentication_request_value] Error on euiccInfo1 TLV, rc %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__initiate_authentication_request_value] InitiateAuthenticationRequestEsipa VALUE size after euiccInfo1: %u", buffer_offset - offset);
#endif

    // eimTransactionId
    if (obj->field_is_present.eim_transaction_id) {
        if ((buffer_offset = tlv_generator__add_tlv_transaction_id_value(buffer, buffer_size, (uint32_t) buffer_offset, CONTEXT_PRIMITIVE_2, &obj->eim_transaction_id)) < 0) {
            LOGE("[esipa_tlv_generator__initiate_authentication_request_value] Error on eimTransactionId TLV, rc %d", buffer_offset);
            return buffer_offset;
        }
        LOGT("[esipa_tlv_generator__initiate_authentication_request_value] InitiateAuthenticationRequestEsipa VALUE size after eimTransactionId: %u", buffer_offset - offset);
    }

    return buffer_offset;
}

static int32_t esipa_tlv_generator__authenticate_client_request_esipa_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const authenticate_client_request_esipa_t* obj) {
    int32_t buffer_offset = (int32_t) offset;

    // transactionId
    if ((buffer_offset = tlv_generator__add_tlv_transaction_id_value(buffer, buffer_size, (uint32_t) buffer_offset, CONTEXT_PRIMITIVE_0, &obj->transaction_id)) < 0) {
        LOGE("[esipa_tlv_generator__authenticate_client_request_esipa_value] Error on transactionId TLV, rc %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__authenticate_client_request_esipa_value] AuthenticateClientRequestEsipa VALUE size after transactionId: %u", buffer_offset - offset);
    
    // authenticateServerResponse
    if ((buffer_offset = tlv_generator__add_tlv_full_bytes(buffer, buffer_size, (uint32_t) buffer_offset, obj->authenticate_server_response, obj->authenticate_server_response_size)) < 0) {
        LOGE("[esipa_tlv_generator__authenticate_client_request_esipa_value] Error on authenticateServerResponse TLV, rc %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__authenticate_client_request_esipa_value] AuthenticateClientRequestEsipa VALUE size after authenticateServerResponse: %u", buffer_offset - offset);

    return buffer_offset;
}

static int32_t esipa_tlv_generator__get_bound_profile_package_request_esipa_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const get_bound_profile_package_request_esipa_t* obj) {
    int32_t buffer_offset = (int32_t)offset;

    // transactionId
    if ((buffer_offset = tlv_generator__add_tlv_transaction_id_value(buffer, buffer_size, (uint32_t)buffer_offset, CONTEXT_PRIMITIVE_0, &obj->transaction_id)) < 0) {
        LOGE("[esipa_tlv_generator__get_bound_profile_package_request_esipa_value] Error on transactionId TLV, rc %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__get_bound_profile_package_request_esipa_value] GetBoundProfilePackageRequest VALUE size after transactionId: %u", buffer_offset - offset);

    // prepareDownLoadResponse
    if ((buffer_offset = tlv_generator__add_tlv_full_bytes(buffer, buffer_size, (uint32_t)buffer_offset, obj->prepare_download_response, obj->prepare_download_response_size)) < 0) {
        LOGE("[esipa_tlv_generator__get_bound_profile_package_request_esipa_value] Error on prepareDownloadResponse TLV, rc %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__get_bound_profile_package_request_esipa_value] GetBoundProfilePackageRequest VALUE size after prepareDownloadResponse: %u", buffer_offset - offset);

    return buffer_offset;
}

static int32_t esipa_tlv_generator__cancel_session_request_esipa_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const cancel_session_request_esipa_t* obj) {
    int32_t buffer_offset = (int32_t)offset;

    // transactionId
    if ((buffer_offset = tlv_generator__add_tlv_transaction_id_value(buffer, buffer_size, (uint32_t) buffer_offset, CONTEXT_PRIMITIVE_0, &obj->transaction_id)) < 0) {
        LOGE("[esipa_tlv_generator__cancel_session_request_esipa_value] Error on transactionId TLV, rc %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__cancel_session_request_esipa_value] CancelSessionRequestEsipa VALUE size after transactionId: %u", buffer_offset - offset);

    // cancelSessionResponse
    if ((buffer_offset = tlv_generator__add_tlv(buffer, buffer_size, (uint32_t) buffer_offset, CONTEXT_CONSTRUCTED_1, obj->cancel_session_response, obj->cancel_session_response_size)) < 0) {
        LOGE("[esipa_tlv_generator__cancel_session_request_esipa_value] Error on cancelSessionResponse TLV, rc %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[esipa_tlv_generator__cancel_session_request_esipa_value] CancelSessionRequestEsipa VALUE size after cancelSessionResponse: %u", buffer_offset - offset);

    return buffer_offset;
}

#endif

#ifdef SGP22
/**
 * This function generate a EuiccPackageResult TLV.
 *  - The EuiccPackageResult will be always a CHOICE of euiccPackageResultSigned
 *  - The euiccSignEPR of the EuiccPackageResultSigned will be always a dummy data.
 *      5F 37 40 
 *        AD C9 C4 7F 1A ED 22 7F 27 A0 4B 71 A0 0B 16 97 7D 9F B5 44 04 6C B8 D0 6E 8B 09 84 6A CB F8 9A 
 *        D4 81 3F 4B A0 4B 28 D2 F2 35 1D C0 30 D0 0E F9 B6 0C 3D C1 B8 6C 52 CC 54 EF 9A C1 23 B5 40 1C
 *  - The seqNumber of the EuiccPackageResultDataSigned will be always a dummy data.
 *      83 01 
 *        00
 *
 * @param[in]  eim_id_tlv Pointer to a buffer with the eimId TLV.
 * @param[in]  eim_id_tlv_size Size of the eim_id_tlv buffer.
 * @param[in]  counter_value_tlv Pointer to a buffer with the counterValue TLV.
 * @param[in]  counter_value_tlv_size Size of the counter_value_tlv buffer.
 * @param[in]  transaction_id_tlv Pointer to a buffer with the transactionId TLV. If NULL, the transactionId TLV will not be added to the generated EuiccPackageResultDataSigned TLV.
 * @param[in]  transaction_id_tlv_size Size of the transaction_id_tlv buffer. If 0, the transactionId TLV will not be added to the generated EuiccPackageResultDataSigned TLV.
 * @param[in]  euicc_result_data_tlv Pointer to a buffer with the EuiccResultData TLV.
 * @param[in]  euicc_result_data_tlv_size Size of the euicc_result_data_tlv buffer.
 * @param[out] euicc_package_result Pointer that will point to a pointer that will point to a buffer with the generated EuiccPackageResult TLV in case that the function has been successfully executed.
 * The caller is the responsible for freeing the EuiccPackageResult TLV pointer.
 * @param[out] euicc_package_result_size Will point to the size of the EuiccPackageResult TLV in case that the function has been successfully executed.
 *
 * @return eOk in case the TLV generation has been done successfully. Otherwise, an error code is returned.
*/
int32_t esipa_tlv_generator__euicc_package_result(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const uint8_t* eim_id, const uint8_t eim_id_size, const uint8_t* counter_value, const uint32_t counter_value_size, 
    const uint8_t* transaction_id, const uint8_t transaction_id_size, const uint8_t* euicc_result_data, const uint32_t euicc_result_data_size) {

    int32_t euicc_package_result_signed_size;
    int32_t euicc_package_result_size;
    int32_t buffer_offset;

    //Calculate the size of the euiccPackageResultSigned
    euicc_package_result_signed_size = esipa_tlv_generator__euicc_package_result_signed(NULL, 0, 0, eim_id, eim_id_size, counter_value, counter_value_size, transaction_id, transaction_id_size, euicc_result_data, euicc_result_data_size);
    if (euicc_package_result_signed_size < 0) {
        LOGE("[esipa_tlv_generator__euicc_package_result] Error calculating the size of the euiccPackageResultSigned TLV, rc %ld", euicc_package_result_signed_size);
        return euicc_package_result_signed_size;
    }
    //Calculate the size of the EuiccPackageResult
    if ((euicc_package_result_size = tlv_generator__add_tlv(NULL, 0, 0, EUICC_PACKAGE, NULL, (uint32_t) euicc_package_result_signed_size)) < 0) {
        LOGE("[esipa_tlv_generator__euicc_package_result] Error calculating the size of the EuiccPackageResult TLV, rc %ld", euicc_package_result_size);
        return euicc_package_result_size;
    }

    //If no buffer is provided, return what would be the new offset
    if (!buffer) {
        return offset + euicc_package_result_size;
    }

    //Check if the space of the buffer is enough to add the EuiccPackageResultDataSigned
    if (offset + euicc_package_result_size > buffer_size) {
        LOGE("[esipa_tlv_generator__euicc_package_result] Not enough space to add the TLV to the buffer. Buffer size %lu, buffer size needed %lu", buffer_size, offset + euicc_package_result_size);
        return -eNotEnoughBuffer;
    }

    //Add EuiccPackageResult TAG
    if ((buffer_offset = tlv_generator__add_tag(buffer, buffer_size, offset, EUICC_PACKAGE)) < 0) {
        LOGE("[esipa_tlv_generator__euicc_package_result] Error adding the EuiccPackageResult TAG, rc %ld", buffer_offset);
        return buffer_offset;
    }
    LOG_DATA(eLogTrace, "[esipa_tlv_generator__euicc_package_result] EuiccPackageResult TAG", buffer, buffer_offset);
    //Add EuiccPackageResult LENGTH
    if ((buffer_offset = tlv_generator__add_length(buffer, buffer_size, (uint32_t) buffer_offset, (uint32_t) euicc_package_result_signed_size)) < 0) {
        LOGE("[esipa_tlv_generator__euicc_package_result] Error adding the EuiccPackageResult LENGTH, rc %ld", buffer_offset);
        return buffer_offset;
    }
    LOG_DATA(eLogTrace, "[esipa_tlv_generator__euicc_package_result] EuiccPackageResult TAG LENGTH", buffer, buffer_offset);
    //Add euiccPackageResultSigned
    buffer_offset = esipa_tlv_generator__euicc_package_result_signed(buffer, buffer_size, (uint32_t) buffer_offset, eim_id, eim_id_size, counter_value, counter_value_size, transaction_id, transaction_id_size, euicc_result_data, euicc_result_data_size);
    if (buffer_offset < 0) {
        LOGE("[esipa_tlv_generator__euicc_package_result] Error adding the euiccPackageResultSigned TLV, rc %ld", buffer_offset);
        return buffer_offset;
    }
    LOG_DATA(eLogTrace, "[esipa_tlv_generator__euicc_package_result] EuiccPackageResult TAG LENGTH euiccPackageResultSigned", buffer, buffer_offset);

    return buffer_offset;
}

/**
 * Add a EuiccPackageResultDataSigned TLV to a buffer.
 *  - The seqNumber will be always a dummy data.
 *      83 01 
 *        00
 *
 * @param[in, out] buffer Point to the buffer to which the EuiccPackageResultDataSigned will be added. If null, the function will only calculate the offset that the 
 * buffer would have had if the EuiccPackageResultDataSigned had been added.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] offset Offset of the buffer.
 * @param[in]  eim_id Pointer to a buffer with the eimId TLV.
 * @param[in]  eim_id_size Size of the eim_id_tlv buffer.
 * @param[in]  counter_value Pointer to a buffer with the counterValue TLV.
 * @param[in]  counter_value_size Size of the counter_value_tlv buffer.
 * @param[in]  transaction_id Pointer to a buffer with the transactionId TLV. If NULL, the transactionId TLV will not be added to the generated EuiccPackageResultDataSigned TLV.
 * @param[in]  transaction_id_size Size of the transaction_id_tlv buffer. If 0, the transactionId TLV will not be added to the generated EuiccPackageResultDataSigned TLV.
 * @param[in]  euicc_result_data Pointer to a buffer with the EuiccResultData TLV.
 * @param[in]  euicc_result_data_size Size of the euicc_result_data_tlv buffer.
 *
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
static int32_t esipa_tlv_generator__euicc_package_result_data_signed(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const uint8_t* eim_id, const uint8_t eim_id_size, const uint8_t* counter_value, 
    const uint32_t counter_value_size, const uint8_t* transaction_id, const uint8_t transaction_id_size, const uint8_t* euicc_result_data, const uint32_t euicc_result_data_size) {

    uint8_t sequence_number_dummy[] = {CONTEXT_PRIMITIVE_3, sizeof(uint8_t), 0x00};
    int32_t euicc_result_size;
    uint32_t euicc_package_result_data_signed_value_size;
    int32_t euicc_package_result_data_signed_size;
    int32_t buffer_offset;

    if (!eim_id || eim_id_size == 0 || !counter_value || counter_value_size == 0 || !euicc_result_data || euicc_result_data_size == 0) {
        return -eBadArg;
    }

    //Calculate the size of the euiccResult
    if ((euicc_result_size = tlv_generator__add_tlv(NULL, 0, 0, (unsigned short) ASN1_DER_SEQUENCE, NULL, euicc_result_data_size)) < 0) {
        LOGE("[esipa_tlv_generator__euicc_package_result_data_signed] Error calculating the size of the euiccResult TLV, rc %ld", euicc_result_size);
        return euicc_result_size;
    }

    //Calculate the size of the EuiccPackageResultDataSigned Value
    euicc_package_result_data_signed_value_size = (uint32_t) eim_id_size + (uint32_t) counter_value_size + (uint32_t) sizeof(sequence_number_dummy) + (uint32_t) euicc_result_size;
    if (transaction_id) {
        euicc_package_result_data_signed_value_size += transaction_id_size;
    }

    //Calculate the size of the EuiccPackageResultDataSigned
    if ((euicc_package_result_data_signed_size = tlv_generator__add_tlv(NULL, 0, 0, (unsigned short) ASN1_DER_SEQUENCE, NULL, euicc_package_result_data_signed_value_size)) < 0) {
        LOGE("[esipa_tlv_generator__euicc_package_result_data_signed] Error calculating the size of the EuiccPackageResultDataSigned TLV, rc %ld", euicc_package_result_data_signed_size);
        return euicc_package_result_data_signed_size;
    }

    //If no buffer is provided, return what would be the new offset
    if (!buffer) {
        return offset + euicc_package_result_data_signed_size;
    }

    //Check if the space of the buffer is enough to add the EuiccPackageResultDataSigned
    if (offset + euicc_package_result_data_signed_size > buffer_size) {
        LOGE("[esipa_tlv_generator__euicc_package_result_data_signed] Not enough space to add the TLV to the buffer. Buffer size %lu, buffer size needed %lu", buffer_size, offset + euicc_package_result_data_signed_size);
        return -eNotEnoughBuffer;
    }

    //Add EuiccPackageResultDataSigned TAG
    if ((buffer_offset = tlv_generator__add_tag(buffer, buffer_size, offset, (unsigned short) ASN1_DER_SEQUENCE)) < 0) {
        LOGE("[esipa_tlv_generator__euicc_package_result_data_signed] Error adding the EuiccPackageResultDataSigned TAG, rc %ld", buffer_offset);
        return buffer_offset;
    }
    LOG_DATA(eLogTrace, "[esipa_tlv_generator__euicc_package_result_data_signed] EuiccPackageResultDataSigned TAG", buffer, buffer_offset);
    //Add EuiccPackageResultDataSigned LENGTH
    if ((buffer_offset = tlv_generator__add_length(buffer, buffer_size, (uint32_t) buffer_offset, (uint32_t) euicc_package_result_data_signed_value_size)) < 0) {
        LOGE("[esipa_tlv_generator__euicc_package_result_data_signed] Error adding the EuiccPackageResultDataSigned LENGTH, rc %ld", buffer_offset);
        return buffer_offset;
    }
    LOG_DATA(eLogTrace, "[esipa_tlv_generator__euicc_package_result_data_signed] EuiccPackageResultDataSigned TAG LENGTH", buffer, buffer_offset);
    //Add eimId
    memcpy(buffer + buffer_offset, eim_id, eim_id_size);
    buffer_offset += eim_id_size;
    LOG_DATA(eLogTrace, "[esipa_tlv_generator__euicc_package_result_data_signed] EuiccPackageResultDataSigned TAG LENGTH eimId", buffer, buffer_offset);
    //Add counterValue
    memcpy(buffer + buffer_offset, counter_value, counter_value_size);
    buffer_offset += counter_value_size;
    LOG_DATA(eLogTrace, "[esipa_tlv_generator__euicc_package_result_data_signed] EuiccPackageResultDataSigned TAG LENGTH eimId counterValue", buffer, buffer_offset);
    //Add transactionId
    if (transaction_id && transaction_id_size > 0) {
        memcpy(buffer + buffer_offset, transaction_id, transaction_id_size);
        buffer_offset += transaction_id_size;
        LOG_DATA(eLogTrace, "[esipa_tlv_generator__euicc_package_result_data_signed] EuiccPackageResultDataSigned TAG LENGTH eimId counterValue transactionId", buffer, buffer_offset);
    }
    //Add seqNumber
    memcpy(buffer + buffer_offset, sequence_number_dummy, sizeof(sequence_number_dummy));
    buffer_offset += sizeof(sequence_number_dummy);
    LOG_DATA(eLogTrace, "[esipa_tlv_generator__euicc_package_result_data_signed] EuiccPackageResultDataSigned TAG LENGTH eimId counterValue (transactionId?) seqNumber", buffer, buffer_offset);
    //Add euiccResult
    if ((buffer_offset = tlv_generator__add_tlv(buffer, buffer_size, (uint32_t) buffer_offset, (unsigned short) ASN1_DER_SEQUENCE, euicc_result_data, euicc_result_data_size)) < 0) {
        LOGE("[esipa_tlv_generator__euicc_package_result_data_signed] Error calculating the size of the euiccResult TLV, rc %ld", buffer_offset);
        return buffer_offset;
    }
    LOG_DATA(eLogTrace, "[esipa_tlv_generator__euicc_package_result_data_signed] EuiccPackageResultDataSigned TAG LENGTH eimId counterValue (transactionId?) seqNumber euiccResult", buffer, buffer_offset);

    return buffer_offset;
}

/**
 * Add a EuiccPackageResultSigned TLV to a buffer.
 *  - The euiccSignEPR will be always a dummy data.
 *      5F 37 40 
 *        AD C9 C4 7F 1A ED 22 7F 27 A0 4B 71 A0 0B 16 97 7D 9F B5 44 04 6C B8 D0 6E 8B 09 84 6A CB F8 9A 
 *        D4 81 3F 4B A0 4B 28 D2 F2 35 1D C0 30 D0 0E F9 B6 0C 3D C1 B8 6C 52 CC 54 EF 9A C1 23 B5 40 1C
 *
 * @param[in, out] buffer Point to the buffer to which the EuiccPackageResultSigned will be added. If null, the function will only calculate the offset that the 
 * buffer would have had if the EuiccPackageResultSigned had been added.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] offset Offset of the buffer.
 * @param[in]  euicc_package_result_data_signed Pointer to a buffer with the euiccPackageResultDataSigned TLV.
 * @param[in]  euicc_package_result_data_signed_size Size of the euicc_package_result_data_signed buffer.
 *
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
static int32_t esipa_tlv_generator__euicc_package_result_signed(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const uint8_t* eim_id, const uint8_t eim_id_size, const uint8_t* counter_value, 
    const uint32_t counter_value_size, const uint8_t* transaction_id, const uint8_t transaction_id_size, const uint8_t* euicc_result_data, const uint32_t euicc_result_data_size) {
    int32_t euicc_package_result_signed_data_size;
    int32_t euicc_package_result_signed_size;
    int32_t buffer_offset;
    uint8_t euicc_sign_epr_tlv_dummy[] = {0x5F, 0x37, 0x40, 0xAD, 0xC9, 0xC4, 0x7F, 0x1A, 0xED, 0x22, 0x7F, 0x27, 0xA0, 0x4B, 0x71, 0xA0, 0x0B, 0x16, 0x97, 0x7D, 0x9F, 0xB5, 0x44, 0x04, 0x6C, 0xB8, 0xD0, 0x6E, 0x8B, 0x09, 0x84, 
                            0x6A, 0xCB, 0xF8, 0x9A, 0xD4, 0x81, 0x3F, 0x4B, 0xA0, 0x4B, 0x28, 0xD2, 0xF2, 0x35, 0x1D, 0xC0, 0x30, 0xD0, 0x0E, 0xF9, 0xB6, 0x0C, 0x3D, 0xC1, 0xB8, 0x6C, 0x52, 0xCC, 0x54, 0xEF, 0x9A, 
                            0xC1, 0x23, 0xB5, 0x40, 0x1C};

    //Calculate the size of the euiccPackageResultDataSigned
    euicc_package_result_signed_data_size = esipa_tlv_generator__euicc_package_result_data_signed(NULL, 0, 0, eim_id, eim_id_size, counter_value, counter_value_size, transaction_id, transaction_id_size, euicc_result_data, euicc_result_data_size);
    if (euicc_package_result_signed_data_size < 0) {
        LOGE("[esipa_tlv_generator__euicc_package_result_signed] Error calculating the size of the euiccPackageResultDataSigned TLV, rc %ld", euicc_package_result_signed_data_size);
    }
    //Calculate the size of the EuiccPackageResultSigned
    if ((euicc_package_result_signed_size = tlv_generator__add_tlv(NULL, 0, 0, (unsigned short) CONTEXT_CONSTRUCTED_0, NULL, euicc_package_result_signed_data_size + sizeof(euicc_sign_epr_tlv_dummy))) < 0) {
        LOGE("[esipa_tlv_generator__euicc_package_result_signed] Error calculating the size of the EuiccPackageResultSigned TLV, rc %ld", euicc_package_result_signed_size);
        return euicc_package_result_signed_size;
    }

    //If no buffer is provided, return what would be the new offset
    if (!buffer) {
        return offset + euicc_package_result_signed_size;
    }

    //Check if the space of the buffer is enough to add the EuiccPackageResultDataSigned
    if (offset + euicc_package_result_signed_size > buffer_size) {
        LOGE("[esipa_tlv_generator__euicc_package_result_signed] Not enough space to add the TLV to the buffer. Buffer size %lu, buffer size needed %lu", buffer_size, offset + euicc_package_result_signed_size);
        return -eNotEnoughBuffer;
    }

    //Add EuiccPackageResultSigned TAG
    if ((buffer_offset = tlv_generator__add_tag(buffer, buffer_size, offset, (unsigned short) CONTEXT_CONSTRUCTED_0)) < 0) {
        LOGE("[esipa_tlv_generator__euicc_package_result_signed] Error adding the EuiccPackageResultSigned TAG, rc %ld", buffer_offset);
        return buffer_offset;
    }
    LOG_DATA(eLogTrace, "[esipa_tlv_generator__euicc_package_result_signed] EuiccPackageResultSigned TAG", buffer, buffer_offset);
    //Add EuiccPackageResultSigned LENGTH
    if ((buffer_offset = tlv_generator__add_length(buffer, buffer_size, (uint32_t) buffer_offset, (uint32_t) euicc_package_result_signed_data_size + (uint32_t) sizeof(euicc_sign_epr_tlv_dummy))) < 0) {
        LOGE("[esipa_tlv_generator__euicc_package_result_signed] Error adding the EuiccPackageResultSigned LENGTH, rc %ld", buffer_offset);
        return buffer_offset;
    }
    LOG_DATA(eLogTrace, "[esipa_tlv_generator__euicc_package_result_signed] EuiccPackageResultSigned TAG LENGTH", buffer, buffer_offset);
    //Add euiccPackageResultDataSigned
    buffer_offset = esipa_tlv_generator__euicc_package_result_data_signed(buffer, buffer_size, (uint32_t) buffer_offset, eim_id, eim_id_size, counter_value, counter_value_size, transaction_id, transaction_id_size, euicc_result_data, euicc_result_data_size);
    if (buffer_offset < 0) {
        LOGE("[esipa_tlv_generator__euicc_package_result_signed] Error adding the euiccPackageResultDataSigned TLV, rc %ld", buffer_offset);
        return buffer_offset;
    }
    LOG_DATA(eLogTrace, "[esipa_tlv_generator__euicc_package_result_signed] EuiccPackageResultSigned TAG LENGTH euiccPackageResultDataSigned", buffer, buffer_offset);
    //Add euiccSignEPR
    memcpy(buffer + buffer_offset, euicc_sign_epr_tlv_dummy, sizeof(euicc_sign_epr_tlv_dummy));
    buffer_offset += sizeof(euicc_sign_epr_tlv_dummy);
    LOG_DATA(eLogTrace, "[esipa_tlv_generator__euicc_package_result_signed] EuiccPackageResultSigned TAG LENGTH euiccPackageResultDataSigned euiccSignEPR", buffer, buffer_offset);

    return buffer_offset;
}
#endif
