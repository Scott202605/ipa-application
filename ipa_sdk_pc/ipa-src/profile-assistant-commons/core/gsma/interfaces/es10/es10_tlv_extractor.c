/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include <malloc.h>
#include "es10_tlv_extractor.h"

#include "ber_tlv_parser.h"
#include "tlv_data_extractor.h"
#include "tlv_tags.h"
#include "log.h"

static ErrCode es10_tlv_extractor__profile_installation_result_data(const uint8_t* tlv, const uint32_t tlv_size, profile_installation_result_data_t* obj);
static ErrCode es10_tlv_extractor__final_result(const unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, final_result_t* obj);
static ErrCode es10_tlv_extractor__success_result(const unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, success_result_t* obj);
static ErrCode es10_tlv_extractor__error_result(const unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, error_result_t* obj);
static ErrCode es10_tlv_extractor__bpp_command_id(const unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, bpp_command_id_t* obj);
static ErrCode es10_tlv_extractor__error_reason(const unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, error_reason_t* obj);
static ErrCode es10_tlv_extractor__profile_info_list_error(const uint8_t* tlv, const uint32_t tlv_size, profile_info_list_error_t* obj);
static ErrCode es10_tlv_extractor__profile_info_prv(const unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, profile_info_t* obj);
static ErrCode es10_tlv_extractor__dp_propietary_data(const unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, dp_propietary_data_t* obj);
static ErrCode es10_tlv_extractor__ppr_ids(const unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, ppr_ids_t* obj);
static ErrCode es10_tlv_extractor__ppr_flags(const unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, ppr_flags_t* obj);
static ErrCode es10_tlv_extractor__notifications_list_result_error(const uint8_t* tlv, const uint32_t tlv_size, notifications_list_result_error_t* obj);
static ErrCode es10_tlv_extractor__notification_metadata_from_pir(const uint8_t* tlv, const uint32_t tlv_size, notification_metadata_t* obj);
static ErrCode es10_tlv_extractor__notification_metadata_from_other_signed_notification(const uint8_t* tlv, const uint32_t tlv_size, notification_metadata_t* obj);
static ErrCode es10_tlv_extractor__segmented_bound_profile_package_checksum(const uint8_t* tlv, const uint32_t tlv_size, segmented_bound_profile_package_t* obj);
#ifdef SGP32
static ErrCode es10_tlv_extractor__euicc_package_result_signed(const unsigned short tag, const uint8_t* buffer, const uint32_t buffer_size, euicc_package_result_signed_t* obj);
static ErrCode es10_tlv_extractor__euicc_package_error_signed(const unsigned short tag, const uint8_t* buffer, const uint32_t buffer_size, euicc_package_error_signed_t* obj);
static ErrCode es10_tlv_extractor__euicc_package_error_unsigned(const unsigned short tag, const uint8_t* buffer, const uint32_t buffer_size, euicc_package_error_unsigned_t* obj);
static ErrCode es10_tlv_extractor__euicc_package_result_data_signed(const unsigned short tag, const uint8_t* buffer, const uint32_t buffer_size, euicc_package_result_data_signed_t* obj);
static ErrCode es10_tlv_extractor__euicc_package_error_data_signed(const unsigned short tag, const uint8_t* buffer, const uint32_t buffer_size, euicc_package_error_data_signed_t* obj);
static ErrCode es10_tlv_extractor__euicc_package_error_code(const unsigned short tag, const uint8_t* buffer, const uint32_t buffer_size, euicc_package_error_code_t* error);
static ErrCode es10_tlv_extractor__add_initial_eim_ok(const uint8_t* tlv, const uint32_t tlv_size, add_initial_eim_ok_t* obj);
static ErrCode es10_tlv_extractor__add_initial_eim_error(const uint8_t* tlv, const uint32_t tlv_size, add_initial_eim_error_t* e);
static ErrCode es10_tlv_extractor__certs(const unsigned tag, const uint8_t* tlv, const uint32_t tlv_size, certs_t* certs);
static ErrCode es10_tlv_extractor__get_certs_error(const unsigned tag, const uint8_t* tlv, const uint32_t tlv_size, get_certs_error_t* e);
static ErrCode es10_tlv_extractor__profile_rollback_result(const unsigned tag, const uint8_t* tlv, const uint32_t tlv_size, profile_rollback_result_t* res);
static ErrCode es10_tlv_extractor__eim_supported_protocol(const uint8_t* tlv, const uint32_t tlv_size, eim_supported_protocol_t* obj);
#endif

ErrCode es10_tlv_extractor__server_signed_1(const uint8_t* tlv, const uint32_t tlv_size, server_signed_1_t* obj) {
    ErrCode rc;
    int tlv_offset;
    size_t tlv_value_offset;
    bool field_is_present;

    /* Check input parameters */
    if (!tlv || tlv_size == 0) {
        LOGE("[es10_tlv_extractor__server_signed_1] tlv is empty/null");
        return eBadArg;
    }

    LOG_DATA(eLogTrace, "[es10_tlv_extractor__server_signed_1] ServerSigned1", tlv, tlv_size);

    /* Search the ServerSigned1 */
    if ((tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, 0, ASN1_DER_SEQUENCE)) < 0) {
        LOGE("[es10_tlv_extractor__server_signed_1] ServerSigned1 TAG 0x%02X not found", ASN1_DER_SEQUENCE);
        return eFatal;
    }
    tlv_value_offset = ber_tlv_parser__get_value_offset(tlv, (size_t) tlv_offset);

    /* transactionId */
    if ((rc = tlv_data_extractor__transaction_id(CONTEXT_PRIMITIVE_0, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &field_is_present, &obj->transaction_id)) != eOk) {
        LOGE("[es10_tlv_extractor__server_signed_1] Error extracting the transactionId of the ServerSigned1, rc %d", rc);
        return rc;
    }
    if (!field_is_present) {
        LOGE("[es10_tlv_extractor__server_signed_1] The transactionId of the ServerSigned1 is not present");
        return eFatal;
    }
    LOG_DATA(eLogDebug, "[es10_tlv_extractor__server_signed_1] transactionId", obj->transaction_id.transaction_id, obj->transaction_id.transaction_id_size);

    /* euiccChallenge */
    if ((rc = tlv_data_extractor__challenge(CONTEXT_PRIMITIVE_1, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &obj->euicc_challenge)) != eOk) {
        LOGE("[es10_tlv_extractor__server_signed_1] Error extracting the euiccChallenge of the ServerSigned1, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogDebug, "[es10_tlv_extractor__server_signed_1] euiccChallenge", obj->euicc_challenge.challenge, sizeof(obj->euicc_challenge.challenge));

    /* serverAddress */
    if ((rc = tlv_data_extractor__fqdn(CONTEXT_PRIMITIVE_3, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &field_is_present, &obj->server_address)) != eOk) {
        LOGE("[es10_tlv_extractor__server_signed_1] Error extracting the serverAddress of the ServerSigned1, rc %d", rc);
        return rc;
    }
    if (!field_is_present) {
        LOGE("[es10_tlv_extractor__server_signed_1] The serverAddress of the ServerSigned1 is not present");
        return eFatal;
    }
    LOGD("[es10_tlv_extractor__server_signed_1] serverAddress: %s", obj->server_address.fqdn);

    /* serverChallenge */
    if ((rc = tlv_data_extractor__challenge(CONTEXT_PRIMITIVE_4, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &obj->server_challenge)) != eOk) {
        LOGE("[es10_tlv_extractor__server_signed_1] Error extracting the serverChallenge of the ServerSigned1, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogDebug, "[es10_tlv_extractor__server_signed_1] serverChallenge", obj->server_challenge.challenge, sizeof(obj->server_challenge.challenge));

    return eOk;
}

ErrCode es10_tlv_extractor__smdp_signed_2(const uint8_t* tlv, const uint32_t tlv_size, smdp_signed_2_t* obj) {
    ErrCode rc;
    int tlv_offset;
    size_t tlv_value_offset;
    bool field_is_present;
    _BerTlv bpp_euicc_ot_pk;

    if (!tlv || tlv_size == 0) {
        LOGE("[es10_tlv_extractor__smdp_signed_2] tlv is empty/null");
        return eBadArg;
    }

    LOG_DATA(eLogTrace, "[es10_tlv_extractor__smdp_signed_2] SmdpSigned2", tlv, tlv_size);

    // Search the SmdpSigned2 TLV
    if ((tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, 0, ASN1_DER_SEQUENCE)) < 0) {
        LOGE("[es10_tlv_extractor__smdp_signed_2] SmdpSigned2 TAG 0x%02X not found", ASN1_DER_SEQUENCE);
        return eFatal;
    }
    tlv_value_offset = ber_tlv_parser__get_value_offset(tlv, (size_t) tlv_offset);

    // transactionId
    if ((rc = tlv_data_extractor__transaction_id(CONTEXT_PRIMITIVE_0, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &field_is_present, &obj->transaction_id)) == eOk) {
        if (!field_is_present) {
            LOGE("[es10_tlv_extractor__smdp_signed_2] The field transactionId is not present in the SmdpSigned2");
            return eFatal;
        }
    } else {
        LOGE("[es10_tlv_extractor__smdp_signed_2] Error extracting the transactionId of the SmdpSigned2, rc %d", rc);
        return rc;
    }

    // ccRequiredFlag
    if ((rc = tlv_data_extractor__boolean(ASN1_DER_BOOLEAN, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, NULL, &obj->cc_required_flag)) != eOk) {
        LOGE("[es10_tlv_extractor__smdp_signed_2] Error extracting the ccRequiredFlag of the SmdpSigned2, rc %d", rc);
        return rc;
    }
    LOGD("[es10_tlv_extractor__smdp_signed_2] ccRequiredFlag: %s", obj->cc_required_flag ? "true" : "false");

    // bppEuiccOtpk
    if ((tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, tlv_value_offset, OT_PK_EUICC)) >= 0) {
        obj->field_is_present.bpp_euicc_ot_pk = true;
        if ((rc = ber_tlv_parser__ber_tlv_2(tlv, tlv_size, (size_t) tlv_offset, &bpp_euicc_ot_pk)) != eOk) {
            LOGE("[es10_tlv_extractor__smdp_signed_2] Error parsing the bppEuiccOtpk, rc %d", rc);
            return eFatal;
        }
        obj->bpp_euicc_ot_pk = tlv + tlv_offset + bpp_euicc_ot_pk.nTag + bpp_euicc_ot_pk.nLength;
        obj->bpp_euicc_ot_pk_size = (uint32_t) bpp_euicc_ot_pk.length;
        LOG_DATA(eLogDebug, "[es10_tlv_extractor__smdp_signed_2] bppEuiccOtpk", obj->bpp_euicc_ot_pk, obj->bpp_euicc_ot_pk_size);
    } else {
        obj->field_is_present.bpp_euicc_ot_pk = false;
        LOGD("[es10_tlv_extractor__smdp_signed_2] SmdpSigned2 bppEuiccOtpk is not present");
    }

    return eOk;
}

ErrCode es10_tlv_extractor__euicc_configured_addresses_response(const uint8_t* tlv, const uint32_t tlv_size, euicc_configured_addresses_response_t* obj) {
	ErrCode rc;
    int tlv_offset;
    size_t tlv_value_offset;
    bool field_is_present;

    if (!tlv || tlv_size == 0) {
        LOGE("[es10_tlv_extractor__euicc_configured_addresses_response] tlv is empty/null");
        return eBadArg;
    }
    LOG_DATA(eLogTrace, "[es10_tlv_extractor__euicc_configured_addresses_response] EuiccConfiguredAddressesResponse", tlv, tlv_size);

    // Search the EuiccConfiguredAddressesResponse TLV
    tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, 0, EUICC_CONFIGURED_ADDRESSES);
    LOGT("[es10_tlv_extractor__euicc_configured_addresses_response] EuiccConfiguredAddressesResponse TAG offset %d", tlv_offset);
    if (tlv_offset < 0) {
        LOGE("[es10_tlv_extractor__euicc_configured_addresses_response] TAG of EuiccConfiguredAddressesResponse (%04X) not found", EUICC_CONFIGURED_ADDRESSES);
        return eFatal;
    }
    tlv_value_offset = ber_tlv_parser__get_value_offset(tlv, (size_t) tlv_offset);
    LOGT("[es10_tlv_extractor__euicc_configured_addresses_response] EuiccConfiguredAddressesResponse VALUE offset %u", tlv_value_offset);

    // defaultDpAddress OPTIONAL
    if ((rc = tlv_data_extractor__fqdn(CONTEXT_PRIMITIVE_0, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &obj->field_is_present.default_dp_address, &obj->default_dp_address)) != eOk) {
        LOGE("[es10_tlv_extractor__euicc_configured_addresses_response] Error extracting the defaultDpAddress of the EuiccConfiguredAddressesResponse, rc %d", rc);
        return rc;
    }

    // rootDsAddress
    if ((rc = tlv_data_extractor__fqdn(CONTEXT_PRIMITIVE_1, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &field_is_present, &obj->root_ds_address)) == eOk) {
        if (false == field_is_present) {
            LOGE("[es10_tlv_extractor__euicc_configured_addresses_response] The rootDsAddress is not present in the EuiccConfiguredAddressesResponse");
            return eFatal;
        }
    } else {
        LOGE("[es10_tlv_extractor__euicc_configured_addresses_response] Error extracting the rootDsAddress of the EuiccConfiguredAddressesResponse, rc %d", rc);
        return rc;
    }

    if (obj->field_is_present.default_dp_address) {
        LOGD("[es10_tlv_extractor__euicc_configured_addresses_response] defaultDpAddress %s", obj->default_dp_address.fqdn);
    }
    LOGD("[es10_tlv_extractor__euicc_configured_addresses_response] rootDsAddress %s", obj->root_ds_address.fqdn);

    return eOk;
}

ErrCode es10_tlv_extractor__get_euicc_challenge_response(const uint8_t* tlv, const uint32_t tlv_size, get_euicc_challenge_response_t* obj) {
    ErrCode rc;
    int tlv_offset;
    size_t tlv_value_offset;

    if (!tlv || tlv_size == 0) {
        LOGE("[es10_tlv_extractor__get_euicc_challenge_response] tlv is empty/null");
        return eBadArg;
    }
    LOG_DATA(eLogDebug, "[es10_tlv_extractor__get_euicc_challenge_response] GetEuiccChallengeResponse", tlv, tlv_size);

    // Search the GetEuiccChallengeResponse TLV
    if ((tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, 0, GET_EUICC_CHALLENGE)) < 0) {
        LOGE("[es10_tlv_extractor__get_euicc_challenge_response] TAG of GetEuiccChallengeResponse (%04X) not found", GET_EUICC_CHALLENGE);
        return eFatal;
    }
    tlv_value_offset = ber_tlv_parser__get_value_offset(tlv, (size_t) tlv_offset);

    if ((rc = tlv_data_extractor__challenge(CONTEXT_PRIMITIVE_0, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &obj->euicc_challenge)) != eOk) {
        LOGE("[es10_tlv_extractor__get_euicc_challenge_response] Error extracting the euiccChallenge of the GetEuiccChallengeResponse, rc %d", rc);
        return rc;
    }

    LOG_DATA(eLogDebug, "[es10_tlv_extractor__get_euicc_challenge_response] euiccChallenge", obj->euicc_challenge.challenge, sizeof(obj->euicc_challenge.challenge));

    return eOk;
}

ErrCode es10_tlv_extractor__euicc_memory_reset_response(const uint8_t* tlv, const uint32_t tlv_size, euicc_memory_reset_response_t* obj) {
    ErrCode rc;
    int tlv_offset;
    size_t tlv_value_offset;
    uint8_t result;

    if (tlv == NULL || tlv_size == 0) {
        LOGE("[es10_tlv_extractor__euicc_memory_reset_response] tlv is empty/null");
        return eBadArg;
    }

    tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, 0, EUICC_MEMORY_RESET);
    if (tlv_offset < 0) {
        LOGE("[es10_tlv_extractor__euicc_memory_reset_response] TAG of EuiccMemoryResetResponse (%04X) not found", EUICC_MEMORY_RESET);
        return eFatal;
    }
    tlv_value_offset = ber_tlv_parser__get_value_offset(tlv, tlv_offset);

    // resetResult REQUIRED
    if ((rc = tlv_data_extractor__result_code(CONTEXT_PRIMITIVE_0, tlv + tlv_value_offset, tlv_size - tlv_value_offset, NULL, &result)) != eOk) {
        LOGE("[es10_tlv_extractor__euicc_memory_reset_response] Error extracting the resetResult, rc %d", rc);
        return rc;
    }

    switch (result) {
    case RESET_RESULT_OK:
    case RESET_RESULT_NOTHING_TO_DELETE:
    case RESET_RESULT_CAT_BUSY:
#ifdef SGP32
    case RESET_RESULT_ECALL_ACTIVE:
#endif
    case RESET_RESULT_UNDEFINED_ERROR:
        obj->reset_result = result;
        break;
    default:
        LOGE("[es10_tlv_extractor__euicc_memory_reset_response] Result %02X not defined in the resetResult", result);
        return eFatal;
    }

#ifdef SGP32
    // resetEimResult OPTIONAL
    if ((rc = tlv_data_extractor__result_code(CONTEXT_PRIMITIVE_1, tlv + tlv_value_offset, tlv_size - tlv_value_offset, &obj->field_is_present.reset_eim_result, &result)) != eOk) {
        LOGE("[es10_tlv_extractor__euicc_memory_reset_response] Error extracting the resetEimResult, rc %d", rc);
        return rc;
    }
    if (obj->field_is_present.reset_eim_result) {
        LOGD("[es10_tlv_extractor__euicc_memory_reset_response] resetEimResult: %02X", result);
        switch (result) {
            case RESET_EIM_RESULT_OK:
            case RESET_EIM_RESULT_NOTHING_TO_DELETE:
            case RESET_EIM_RESULT_EIM_RESET_NOT_SUPPORTED:
            case RESET_EIM_RESULT_UNDEFINED_ERROR:
                obj->reset_eim_result = result;
                break;
            default:
                LOGE("[es10_tlv_extractor__euicc_memory_reset_response] Result %02X not defined in the resetEimResult", result);
                return eFatal;
        }
    } else {
        LOGD("[es10_tlv_extractor__euicc_memory_reset_response] resetEimResult is not present");
    }
    // resetImmediateEnableConfigResult OPTIONAL
    if ((rc = tlv_data_extractor__result_code(CONTEXT_PRIMITIVE_2, tlv + tlv_value_offset, tlv_size - tlv_value_offset, &obj->field_is_present.reset_immediate_enable_config_result, &result)) != eOk) {
        LOGE("[es10_tlv_extractor__euicc_memory_reset_response] Error extracting the resetImmediateEnableConfigResult, rc %d", rc);
        return rc;
    }
    if (obj->field_is_present.reset_immediate_enable_config_result) {
        LOGD("[es10_tlv_extractor__euicc_memory_reset_response] resetImmediateEnableConfigResult: %02X", result);
        switch (result) {
            case RESET_IMMEDIATE_ENABLE_CONFIG_RESULT_OK:
            case RESET_IMMEDIATE_ENABLE_CONFIG_RESULT_IEC_NOT_SUPPORTED:
            case RESET_IMMEDIATE_ENABLE_CONFIG_RESULT_UNDEFINED_ERROR:
                obj->reset_immediate_enable_config_result = result;
                break;
            default:
                LOGE("[es10_tlv_extractor__euicc_memory_reset_response] Result %02X not defined in the resetImmediateEnableConfigResult", result);
                return eFatal;
        }
    } else {
        LOGD("[es10_tlv_extractor__euicc_memory_reset_response] resetImmediateEnableConfigResult is not present");
    }
#endif

    return eOk;
}

ErrCode es10_tlv_extractor__bound_profile_package(const uint8_t* tlv, const uint32_t tlv_size, bound_profile_package_t* obj) {
    ErrCode rc;
    uint8_t* tlv_value;
    uint32_t tlv_value_size;
    uint8_t* sub_tlv_value;
    uint32_t sub_tlv_value_size;
    LOGD("[es10_tlv_extractor__initialise_secure_channel] Extracting the BoundProfilePackage TLV");

    /* Extract the TLV value */
    if ((rc = tlv_data_extractor__tlv_value_big_size_ref(BOUND_PROFILE_PKG, tlv, tlv_size, NULL, &tlv_value, &tlv_value_size)) != eOk) {
        LOGE("[es10_tlv_extractor__bound_profile_package] Error extracting the BoundProfilePackage TLV value, rc %d", rc);
        return rc;
    }

    /* InitialiseSecureChannelRequest */
    if ((rc = tlv_data_extractor__tlv_big_size_ref(INIT_SECURE_CHANNEL, tlv_value, tlv_value_size, NULL, &obj->initialise_secure_channel_request, &obj->initialise_secure_channel_request_size)) != eOk) {
        LOGE("[es10_tlv_extractor__bound_profile_package] Error extracting the InitialiseSecureChannelRequest TLV value, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogDebug, "[es10_tlv_extractor__bound_profile_package] InitialiseSecureChannelRequest", obj->initialise_secure_channel_request, obj->initialise_secure_channel_request_size);

    /* first sequenceOf87 */
    if ((rc = tlv_data_extractor__tlv_value_big_size_ref(BPP_FIRST_SEQ_87, tlv_value, tlv_value_size, NULL, &sub_tlv_value, &sub_tlv_value_size)) != eOk) {
        LOGE("[es10_tlv_extractor__bound_profile_package] Error extracting the sequenceOf87 TLV value, rc %d", rc);
        return rc;
    }
    if ((rc = tlv_data_extractor__tlv_big_size_ref(SCP03T_PAYLOAD_CONF_ISDP, sub_tlv_value, sub_tlv_value_size, NULL, &obj->first_sequence_of_87, &obj->first_sequence_of_87_size)) != eOk) {
        LOGE("[es10_tlv_extractor__bound_profile_package] Error extracting the SCP03t segment containing ConfigureISDP, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogDebug, "[es10_tlv_extractor__bound_profile_package] firstSequenceOf87", obj->first_sequence_of_87, obj->first_sequence_of_87_size);

    /* sequenceOf88 */
    if ((rc = tlv_data_extractor__tlv_big_size_ref(BPP_SEQ_88, tlv_value, tlv_value_size, NULL, &sub_tlv_value, &sub_tlv_value_size)) != eOk) {
        LOGE("[es10_tlv_extractor__bound_profile_package] Error extracting the sequenceOf88 TLV value, rc %d", rc);
        return rc;
    }
    if ((rc = tlv_data_extractor__asn1_list_init(&obj->sequence_of_88, BPP_SEQ_88, SCP03T_PAYLOAD_STORE_METADATA, sub_tlv_value, sub_tlv_value_size)) != eOk) {
        LOGE("[es10_tlv_extractor__bound_profile_package] Error initializing the 88 TLV list, rc %d", rc);
        return rc;
    }

    /* second sequenceOf87 OPTIONAL */
    if ((rc = tlv_data_extractor__tlv_value_big_size_ref(BPP_SECOND_SEQ_87, tlv_value, tlv_value_size, &obj->field_is_present.second_sequence_of_87, &sub_tlv_value, &sub_tlv_value_size)) != eOk) {
        LOGE("[es10_tlv_extractor__bound_profile_package] Error extracting the sequenceOf87 TLV value, rc %d", rc);
        return rc;
    }
    if (obj->field_is_present.second_sequence_of_87) {
        if ((rc = tlv_data_extractor__tlv_big_size_ref(SCP03T_PAYLOAD_REPLACE_SESSION_KEYS, sub_tlv_value, sub_tlv_value_size, NULL, &obj->second_sequence_of_87, &obj->second_sequence_of_87_size)) != eOk) {
            LOGE("[es10_tlv_extractor__bound_profile_package] Error extracting the SCP03t segment containing the Profile Protection Keys, rc %d", rc);
            return rc;
        }
        LOG_DATA(eLogDebug, "[es10_tlv_extractor__bound_profile_package] secondSequenceOf87", obj->second_sequence_of_87, obj->second_sequence_of_87_size);
    } else {
        LOGD("[es10_tlv_extractor__bound_profile_package] The secondSequenceOf87 is absent");
    }

    /* sequenceOf86 */
    if ((rc = tlv_data_extractor__tlv_big_size_ref(BPP_SEQ_86, tlv_value, tlv_value_size, NULL, &sub_tlv_value, &sub_tlv_value_size)) != eOk) {
        LOGE("[es10_tlv_extractor__bound_profile_package] Error extracting the sequenceOf86 TLV value, rc %d", rc);
        return rc;
    }
    if ((rc = tlv_data_extractor__asn1_list_init(&obj->sequence_of_88, BPP_SEQ_86, SCP03T_PAYLOAD_LOAD_PROFILE_PACKAGE, sub_tlv_value, sub_tlv_value_size)) != eOk) {
        LOGE("[es10_tlv_extractor__bound_profile_package] Error initializing the 86 TLV list, rc %d", rc);
        return rc;
    }

    return eOk;
}

ErrCode es10_tlv_extractor__initialise_secure_channel(const uint8_t* tlv, const uint32_t tlv_size, initialise_secure_channel_request_t* obj) {
    ErrCode rc;
    uint8_t* tlv_value;
    uint32_t tlv_value_size;
    LOGD("[es10_tlv_extractor__initialise_secure_channel] Extracting the InitialiseSecureChannelRequest TLV");

    /* Extract the TLV value */
    if ((rc = tlv_data_extractor__tlv_value_big_size_ref(INIT_SECURE_CHANNEL, tlv, tlv_size, NULL, &tlv_value, &tlv_value_size)) != eOk) {
        LOGE("[es10_tlv_extractor__initialise_secure_channel] Error extracting the InitialiseSecureChannelRequest TLV value, rc %d", rc);
        return rc;
    }

    // RemoteOpId
    if ((rc = tlv_data_extractor__result_code(CONTEXT_PRIMITIVE_2, tlv_value, tlv_value_size, NULL, &obj->remote_op_id)) != eOk) {
        LOGE("[es10_tlv_extractor__initialise_secure_channel] Error extracting the RemoteOpId, rc %d", rc);
        return rc;
    }
    LOGD("[es10_tlv_extractor__initialise_secure_channel] RemoteOpId %02X", obj->remote_op_id);

    /* transactionId */
    if ((rc = tlv_data_extractor__transaction_id(CONTEXT_PRIMITIVE_0, tlv_value, tlv_value_size, NULL, &obj->transaction_id)) != eOk) {
        LOGE("[es10_tlv_extractor__initialise_secure_channel] Error extracting the transactionId, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogDebug, "[es10_tlv_extractor__initialise_secure_channel] transactionId", obj->transaction_id.transaction_id, obj->transaction_id.transaction_id_size);

    /* controlRefTemplate */
    if ((rc = tlv_data_extractor__tlv_big_size_ref(CONTROL_REF_TEMPLATE, tlv_value, tlv_value_size, NULL, &obj->control_ref_template, &obj->control_ref_template_size)) != eOk) {
        LOGE("[es10_tlv_extractor__initialise_secure_channel] Error extracting the controlRefTemplate TLV value, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogDebug, "[es10_tlv_extractor__initialise_secure_channel] controlRefTemplate", obj->control_ref_template, obj->control_ref_template_size);

    /* smdpOtpk */
    if ((rc = tlv_data_extractor__tlv_big_size_ref(OT_PK_EUICC, tlv_value, tlv_value_size, NULL, &obj->smdp_otpk, &obj->smdp_otpk_size)) != eOk) {
        LOGE("[es10_tlv_extractor__initialise_secure_channel] Error extracting the smdpOtpk TLV value, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogDebug, "[es10_tlv_extractor__initialise_secure_channel] smdpOtpk", obj->smdp_otpk, obj->smdp_otpk_size);

    /* smdpSign */
    if ((rc = tlv_data_extractor__tlv_big_size_ref(SIGNATURE, tlv_value, tlv_value_size, NULL, &obj->smdp_sign, &obj->smdp_sign_size)) != eOk) {
        LOGE("[es10_tlv_extractor__initialise_secure_channel] Error extracting the smdpSign TLV value, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogDebug, "[es10_tlv_extractor__initialise_secure_channel] smdpSign", obj->smdp_sign, obj->smdp_sign_size);

    return eOk;
}

ErrCode es10_tlv_extractor__store_metadata_request(const uint8_t* tlv, const uint32_t tlv_size, profile_info_t* obj) {
    return es10_tlv_extractor__profile_info_prv(STORE_METADATA, tlv, tlv_size, obj);
}

ErrCode es10_tlv_extractor__segmented_bound_profile_package(const uint8_t* tlv, const uint32_t tlv_size, segmented_bound_profile_package_t* obj) {
    ErrCode rc;
    int tlv_offset;
    size_t tlv_value_offset;
    size_t size;
    _BerTlv tlv_obj;

    /* Check input parameters */
    if (!tlv || tlv_size == 0) {
        LOGE("[es10_tlv_extractor__segmented_bound_profile_package] BoundProfilePackage is empty/null");
        return eBadArg;
    }
    if (!obj) {
        LOGE("[es10_tlv_extractor__segmented_bound_profile_package] Segmented BoundProfilePackage object is null");
        return eBadArg;
    }

    LOG_DATA(eLogTrace, "[es10_tlv_extractor__segmented_bound_profile_package] BoundProfilePackage", tlv, tlv_size);

    /* Search the BoundProfilePackage TLV */
    if ((tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, 0, BOUND_PROFILE_PKG)) < 0) {
        LOGE("[es10_tlv_extractor__segmented_bound_profile_package] TAG of BoundProfilePackage (%04X) not found", BOUND_PROFILE_PKG);
        return eFatal;
    }
    tlv_value_offset = ber_tlv_parser__get_value_offset(tlv, (size_t) tlv_offset);

    /* InitialiseSecureChannelRequest */
    if ((tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, tlv_value_offset, INIT_SECURE_CHANNEL)) < 0) {
        LOGE("[es10_tlv_extractor__segmented_bound_profile_package] TAG of InitialiseSecureChannelRequest (%04X) not found", INIT_SECURE_CHANNEL);
        return eFatal;
    }
    if ((rc = ber_tlv_parser__get_tlv_bytes_count(tlv, (size_t) tlv_offset, &size)) != eOk) {
        LOGE("[es10_tlv_extractor__segmented_bound_profile_package] Error extracting the size of the InitialiseSecureChannelRequest, rc %d", rc);
        return rc;
    }
    obj->tag_length_bpp_and_init_secure_channel_req = tlv;
    obj->tag_length_bpp_and_init_secure_channel_req_size = (uint32_t) (tlv_value_offset + size);
    LOG_DATA(eLogDebug, "[es10_tlv_extractor__segmented_bound_profile_package] Tag and length fields of the BoundProfilePackage TLV plus the initialiseSecureChannelRequest TLV", obj->tag_length_bpp_and_init_secure_channel_req, obj->tag_length_bpp_and_init_secure_channel_req_size);

    /* first sequenceOf87 */
    if ((tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, tlv_value_offset, BPP_FIRST_SEQ_87)) < 0) {
        LOGE("[es10_tlv_extractor__segmented_bound_profile_package] TAG of firstSequenceOf87 (%02X) not found", BPP_FIRST_SEQ_87);
        return eFatal;
    }
    if ((rc = ber_tlv_parser__get_tlv_bytes_count(tlv, (size_t) tlv_offset, &size)) != eOk) {
        LOGE("[es10_tlv_extractor__segmented_bound_profile_package] Error extracting the size of the firstSequenceOf87, rc %d", rc);
        return rc;
    }
    obj->first_sequence_of_87 = tlv + tlv_offset;
    obj->first_sequence_of_87_size = (uint32_t) size;
    LOG_DATA(eLogDebug, "[es10_tlv_extractor__segmented_bound_profile_package] Tag and length fields of the first sequenceOf87 TLV plus the first '87' TLV", obj->first_sequence_of_87, obj->first_sequence_of_87_size);

    /* sequenceOf88 */
    if ((tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, tlv_value_offset, BPP_SEQ_88)) < 0) {
        LOGE("[es10_tlv_extractor__segmented_bound_profile_package] TAG of sequenceOf88 (%02X) not found", BPP_SEQ_88);
        return eFatal;
    }
    if ((rc = ber_tlv_parser__ber_tlv_2(tlv, (size_t) tlv_size, (size_t) tlv_offset, &tlv_obj)) != eOk) {
        LOGE("[es10_tlv_extractor__segmented_bound_profile_package] Error parsing the sequenceOf88 TLV, rc %d", rc);
        return rc;
    }
    obj->tag_length_sequence_of_88 = tlv + tlv_offset;
    obj->tag_length_sequence_of_88_size = tlv_obj.nTag + tlv_obj.nLength;
    LOG_DATA(eLogDebug, "[es10_tlv_extractor__segmented_bound_profile_package] Tag and length fields of the sequenceOf88 TLV", obj->tag_length_sequence_of_88, obj->tag_length_sequence_of_88_size);

    if ((rc = tlv_data_extractor__asn1_list_init(&obj->elements_of_88, BPP_SEQ_88, SCP03T_PAYLOAD_STORE_METADATA, obj->tag_length_sequence_of_88, obj->tag_length_sequence_of_88_size + (uint32_t) tlv_obj.length)) != eOk) {
        LOGE("[es10_tlv_extractor__segmented_bound_profile_package] Error initializing the 88 TLV list, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogDebug, "[es10_tlv_extractor__segmented_bound_profile_package] Each of the '88' TLVs", obj->tag_length_sequence_of_88 + obj->tag_length_sequence_of_88_size, tlv_obj.length);

    /* second sequenceOf87 OPTIONAL */
    if ((tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, tlv_value_offset, BPP_SECOND_SEQ_87)) >= 0) {
        if ((rc = ber_tlv_parser__get_tlv_bytes_count(tlv, (size_t) tlv_offset, &size)) != eOk) {
            LOGE("[es10_tlv_extractor__segmented_bound_profile_package] Error extracting the size of the secondSequenceOf87, rc %d", rc);
            return rc;
        }
        obj->second_sequence_of_87 = tlv + tlv_offset;
        obj->second_sequence_of_87_size = (uint32_t) size;
        obj->field_is_present.second_sequence_of_87 = true;
        LOG_DATA(eLogDebug, "[es10_tlv_extractor__segmented_bound_profile_package] Tag and length fields of the sequenceOf87 TLV plus the first '87' TLV", obj->second_sequence_of_87, obj->second_sequence_of_87_size);
    } else {
        obj->field_is_present.second_sequence_of_87 = false;
        LOGD("[es10_tlv_extractor__segmented_bound_profile_package] The secondSequenceOf87 is absent");
    }

    /* sequenceOf86 */
    if ((tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, tlv_value_offset, BPP_SEQ_86)) < 0) {
        LOGE("[es10_tlv_extractor__segmented_bound_profile_package] TAG of sequenceOf86 (%02X) not found", BPP_SEQ_86);
        return eFatal;
    }
    if ((rc = ber_tlv_parser__ber_tlv_2(tlv, (size_t) tlv_size, (size_t) tlv_offset, &tlv_obj)) != eOk) {
        LOGE("[es10_tlv_extractor__segmented_bound_profile_package] Error parsing the sequenceOf86 TLV, rc %d", rc);
        return rc;
    }
    obj->tag_length_sequence_of_86 = tlv + tlv_offset;
    obj->tag_length_sequence_of_86_size = tlv_obj.nTag + tlv_obj.nLength;
    LOG_DATA(eLogDebug, "[es10_tlv_extractor__segmented_bound_profile_package] Tag and length fields of the sequenceOf86 TLV", obj->tag_length_sequence_of_86, obj->tag_length_sequence_of_86_size);

    if ((rc = tlv_data_extractor__asn1_list_init(&obj->elements_of_86, BPP_SEQ_86, SCP03T_PAYLOAD_LOAD_PROFILE_PACKAGE, obj->tag_length_sequence_of_86, obj->tag_length_sequence_of_86_size + (uint32_t) tlv_obj.length)) != eOk) {
        LOGE("[es10_tlv_extractor__segmented_bound_profile_package] Error initializing the 86 TLV list, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogDebug, "[es10_tlv_extractor__segmented_bound_profile_package] Each of the '86' TLVs", obj->tag_length_sequence_of_86 + obj->tag_length_sequence_of_86_size, tlv_obj.length);

    /* verify BPP checksum */
    if ((rc = es10_tlv_extractor__segmented_bound_profile_package_checksum(tlv, tlv_size, obj)) != eOk) {
        LOGE("[es10_tlv_extractor__segmented_bound_profile_package] Checksum of the Bound Profile Package failed, rc %d", rc);
        return rc;
    }

    return eOk;
}

ErrCode es10_tlv_extractor__notification_event(const unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, notification_event_t* obj) {
    ErrCode rc;
    uint8_t notification_event_plain[] = { 0, 0, 0, 0 };

    if ((rc = tlv_data_extractor__bit_string(tag, tlv, tlv_size, notification_event_plain, sizeof(notification_event_plain))) != eOk) {
        LOGE("[es10_tlv_extractor__notification_event] Error extracting the NotificationEvent BIT STRING, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogTrace, "[es10_tlv_extractor__notification_event] NotificationEvent BIT STRING", notification_event_plain, sizeof(notification_event_plain));

    if (notification_event_plain[0]) {
        *obj = NOTIFICATION_EVENT_INSTALL;
    } else if (notification_event_plain[1]) {
        *obj = NOTIFICATION_EVENT_ENABLE;
    } else if (notification_event_plain[2]) {
        *obj = NOTIFICATION_EVENT_DISABLE;
    } else if (notification_event_plain[3]) {
        *obj = NOTIFICATION_EVENT_DELETE;
    } else {
        LOGE("[es10_tlv_extractor__notification_event] Any bit is set to 1");
        return eFatal;
    }

    return eOk;
}

ErrCode es10_tlv_extractor__notification_metadata(const uint8_t* tlv, const uint32_t tlv_size, notification_metadata_t* obj) {
    ErrCode rc;
    int tlv_offset;
    size_t tlv_value_offset;
    bool field_is_present;

    if (!tlv || tlv_size == 0) {
        LOGE("[es10_tlv_extractor__notification_metadata] tlv is empty/null");
        return eBadArg;
    }

    LOG_DATA(eLogTrace, "[es10_tlv_extractor__notification_metadata] tlv", tlv, tlv_size);

    // Search the NotificationMetadata TLV
    tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, 0, NOTIFICATION_METADATA);
    if (tlv_offset < 0) {
        LOGE("[es10_tlv_extractor__notification_metadata] NotificationMetadata TAG 0x%04X not found", NOTIFICATION_METADATA);
        return eFatal;
    }
    tlv_value_offset = ber_tlv_parser__get_value_offset(tlv, tlv_offset);

    // seqNumber
    if ((rc = tlv_data_extractor__uint32(CONTEXT_PRIMITIVE_0, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, NULL, &obj->seq_number)) != eOk) {
        LOGE("[es10_tlv_extractor__notification_metadata] Error extracting the seqNumber of the NotificationMetadata, rc %d", rc);
        return rc;
    }
    LOGD("[es10_tlv_extractor__notification_metadata] NotificationMetadata seqNumber %u", obj->seq_number);

    // profileManagementOperation
    if ((rc = es10_tlv_extractor__notification_event(CONTEXT_PRIMITIVE_1, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &obj->profile_management_operation)) != eOk) {
        LOGE("[es10_tlv_extractor__notification_metadata] Error extracting the profileManagementOperation of the NotificationMetadata, rc %d", rc);
        return rc;
    }
    LOGD("[es10_tlv_extractor__notification_metadata] NotificationMetadata profileManagementOperation %d", obj->profile_management_operation);

    // notificationAddress
    if ((rc = tlv_data_extractor__fqdn(ASN1_DER_UTF8_STRING, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &field_is_present, &obj->notification_address)) == eOk) {
        if (false == field_is_present) {
            LOGE("[es10_tlv_extractor__notification_metadata] The notificationAddress is not present in the NotificationMetadata");
            return eFatal;
        }
    } else {
        LOGE("[es10_tlv_extractor__notification_metadata] Error extracting the notificationAddress of the NotificationMetadata, rc %d", rc);
        return rc;
    }
    LOGD("[es10_tlv_extractor__notification_metadata] NotificationMetadata notificationAddress %s", obj->notification_address.fqdn);

    // ICCID
    if ((rc = tlv_data_extractor__iccid(ICCID, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &obj->field_is_present.iccid, &obj->iccid)) != eOk) {
        LOGE("[es10_tlv_extractor__notification_metadata] Error extracting the ICCID of the NotificationMetadata, rc %d", rc);
        return rc;
    }
    if (obj->field_is_present.iccid) {
        LOGD("[es10_tlv_extractor__notification_metadata] NotificationMetadata ICCID %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X",
        obj->iccid.value[0], obj->iccid.value[1], obj->iccid.value[2], obj->iccid.value[3], obj->iccid.value[4], obj->iccid.value[5], obj->iccid.value[6], obj->iccid.value[7], obj->iccid.value[8], obj->iccid.value[9]);
    } else {
        LOGD("[es10_tlv_extractor__notification_metadata] NotificationMetadata ICCID is not present");
    }

    return eOk;
}

ErrCode es10_tlv_extractor__profile_installation_result(const uint8_t* tlv, const uint32_t tlv_size, profile_installation_result_t* obj) {
    ErrCode rc;
    int tlv_offset;
    size_t tlv_value_offset;
    _BerTlv euicc_sign_pir_tlv;

    if (!tlv || tlv_size == 0) {
        LOGE("[es10_tlv_extractor__profile_installation_result] tlv is empty/null");
        return eBadArg;
    }
    LOG_DATA(eLogTrace, "[es10_tlv_extractor__profile_installation_result] tlv", tlv, tlv_size);

    // Search the ProfileInstallationResult TLV
    tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, 0, PROFILE_INSTALLATION_RESULT);
    if (tlv_offset < 0) {
        LOGE("[es10_tlv_extractor__profile_installation_result] ProfileInstallationResult TAG 0x%04X not found", PROFILE_INSTALLATION_RESULT);
        return eFatal;
    }
    tlv_value_offset = ber_tlv_parser__get_value_offset(tlv, tlv_offset);

    // profileInstallationResultData
    if ((rc = es10_tlv_extractor__profile_installation_result_data(tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &obj->profile_installation_result_data)) != eOk) {
        LOGE("[es10_tlv_extractor__profile_installation_result] Error extracting the profileInstallationResultData of the ProfileInstallationResult, rc %d", rc);
        return rc;
    }

    // euiccSignPIR
    tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, tlv_value_offset, SIGNATURE);
    if (tlv_offset < 0) {
        LOGE("[es10_tlv_extractor__profile_installation_result] euiccSignPIR TAG 0x%04X not found", SIGNATURE);
        return eFatal;
    }

    if ((rc = ber_tlv_parser__ber_tlv_2(tlv, tlv_size, (size_t) tlv_offset, &euicc_sign_pir_tlv)) != eOk) {
        LOGE("[es10_tlv_extractor__profile_installation_result] Error parsing the euiccSignPIR TLV, rc %d", rc);
        return rc;
    }

    obj->euicc_sign_pir = tlv + tlv_offset + euicc_sign_pir_tlv.nTag + euicc_sign_pir_tlv.nLength;
    obj->euicc_sign_pir_size = (uint32_t) euicc_sign_pir_tlv.length;
    LOG_DATA(eLogDebug, "[es10_tlv_extractor__profile_installation_result] euiccSignPIR", obj->euicc_sign_pir, obj->euicc_sign_pir_size);

    return eOk;
}

ErrCode es10_tlv_extractor__retrieve_notifications_list_response(const uint8_t* tlv, const uint32_t tlv_size, retrieve_notifications_list_response_t* obj) {
    ErrCode rc;
    int tlv_offset;
    size_t tlv_value_offset;
    _BerTlv value;

    if (tlv == NULL || tlv_size == 0) {
        LOGE("[es10_tlv_extractor__retrieve_notifications_list_response] RetrieveNotificationsListResponse is empty");
        return eBadArg;
    }
    if (!obj) {
        LOGE("[es10_tlv_extractor__retrieve_notifications_list_response] RetrieveNotificationsListResponse object is null");
        return eBadArg;
    }

    tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, 0, RETRIEVE_NOTIF_LIST);
    if (tlv_offset < 0) {
        LOGE("[es10_tlv_extractor__retrieve_notifications_list_response] TAG of RetrieveNotificationsListResponse (%04X) not found", RETRIEVE_NOTIF_LIST);
        return eFatal;
    }

    tlv_value_offset = ber_tlv_parser__get_value_offset(tlv, tlv_offset);
    if ((rc = ber_tlv_parser__ber_tlv_2(tlv, tlv_size, tlv_value_offset, &value)) != eOk) {
        LOGE("[es10_tlv_extractor__retrieve_notifications_list_response] Error parsing the RetrieveNotificationsListResponse VALUE, rc %d", rc);
        return rc;
    }

    switch (value.tag)
    {
    case CONTEXT_CONSTRUCTED_0:
        obj->choice = NOTIFICATIONS_LIST_CHOICE;
        return tlv_data_extractor__asn1_list_init(&obj->value.notification_list, CONTEXT_CONSTRUCTED_0, 0, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset);
    case CONTEXT_PRIMITIVE_1:
        obj->choice = NOTIFICATIONS_LIST_RESULT_ERROR_CHOICE;
        return es10_tlv_extractor__notifications_list_result_error(tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &obj->value.notifications_list_result_error);
#ifdef SGP32
    case CONTEXT_CONSTRUCTED_2:
        obj->choice = EUICC_PACKAGE_RESULT_LIST_CHOICE;
        return tlv_data_extractor__asn1_list_init(&obj->value.euicc_package_result_list, CONTEXT_CONSTRUCTED_2, EUICC_PACKAGE, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset);
#endif
    default:
        LOGE("[es10_tlv_extractor__retrieve_notifications_list_response] Unknown CHOICE TAG %04X", value.tag);
        return eFatal;
    }
}

ErrCode es10_tlv_extractor__notifications_list_from_retrieve_notifications_list_response(const uint8_t* tlv, const uint32_t tlv_size, asn1_list_iterator_t* obj) {
    ErrCode rc;
    retrieve_notifications_list_response_t retrieve_notifications_list_response;

    if (!obj) {
        LOGE("[es10_tlv_extractor__notifications_list_from_retrieve_notifications_list_response] Notification List iterator object is null");
        return eBadArg;
    }

    if ((rc = es10_tlv_extractor__retrieve_notifications_list_response(tlv, tlv_size, &retrieve_notifications_list_response)) != eOk) {
        LOGE("[es10_tlv_extractor__notifications_list_from_retrieve_notifications_list_response] Error parsing the RetrieveNotificationsListResponse TLV, rc %d", rc);
        return rc;
    }

    switch (retrieve_notifications_list_response.choice)
    {
    case NOTIFICATIONS_LIST_CHOICE:
        memcpy(obj, &retrieve_notifications_list_response.value.notification_list, sizeof(asn1_list_iterator_t));
        break;
    default:
        LOGD("[es10_tlv_extractor__notifications_list_from_retrieve_notifications_list_response] The choice is not notificationList, choice %d", retrieve_notifications_list_response.choice);
        /* Lets populate the ASN.1 Notifications List object as if had no notification */
        obj->asn1_list_tlv = NULL;
        obj->asn1_list_tlv_size = 0;
        obj->init_offset = 0;
        obj->current_offset = 0;
        obj->elem_tag = 0;
        break;
    }

    return eOk;
}

ErrCode es10_tlv_extractor__notification_metadata_from_pending_notification(const uint8_t* tlv, const uint32_t tlv_size, notification_metadata_t* obj) {
    ErrCode rc;
    _BerTlv pending_notification;

    if (tlv == NULL || tlv_size == 0) {
        LOGE("[es10_tlv_extractor__notification_metadata_from_pending_notification] PendingNotification is empty");
        return eBadArg;
    }
    if (!obj) {
        LOGE("[es10_tlv_extractor__notification_metadata_from_pending_notification] NotificationMetadata object is null");
        return eBadArg;
    }

    if ((rc = ber_tlv_parser__ber_tlv_2(tlv, tlv_size, 0, &pending_notification)) != eOk) {
        LOGE("[es10_tlv_extractor__notification_metadata_from_pending_notification] Error parsing the PendingNotification, rc %d", rc);
        return rc;
    }

    switch (pending_notification.tag)
    {
    case ASN1_DER_SEQUENCE:
        return es10_tlv_extractor__notification_metadata_from_other_signed_notification(tlv, tlv_size, obj);
    case PROFILE_INSTALLATION_RESULT:
        return es10_tlv_extractor__notification_metadata_from_pir(tlv, tlv_size, obj);
    default:
        LOGE("[es10_tlv_extractor__notification_metadata_from_pending_notification] Unknown CHOICE TAG %04X", pending_notification.tag);
        return eFatal;
    }

    return eFatal;
}

ErrCode es10_tlv_extractor__notification_sent_response(const uint8_t* tlv, const uint32_t tlv_size, notification_sent_response_t* obj) {
    ErrCode rc;
    uint8_t result;

    if ((rc = tlv_data_extractor__result_code_with_parent_tlv(NOTIFICATION_SENT, CONTEXT_PRIMITIVE_0, tlv, tlv_size, &result)) != eOk) {
        LOGE("[es10_tlv_extractor__notification_sent_response] Error extracting the result of the TLV, rc %d", rc);
        return rc;
    }

    LOGD("[es10_tlv_extractor__notification_sent_response] NotificationSentResponse(deleteNotificationStatus=%02X)", result);

    if (result != DELETE_NOTIFICATION_STATUS_OK && result != DELETE_NOTIFICATION_STATUS_NOTHING_TO_DELETE && result != DELETE_NOTIFICATION_STATUS_UNDEFINED_ERROR) {
        LOGE("[es10_tlv_extractor__notification_sent_response] Result %02X not defined in the deleteNotificationStatus", result);
        return eFatal;
    }

    obj->delete_notification_status = result;
    return eOk;
}

ErrCode es10_tlv_extractor__profile_info_list_response(const uint8_t* tlv, uint32_t tlv_size, profile_info_list_response_t* obj) {
    ErrCode rc;
    int offset;
    size_t tlv_value_offset;
    _BerTlv profile_info_list_response_value;

    /* Check input parameters */
    if (!tlv || tlv_size == 0) {
        LOGE("[es10_tlv_extractor__profile_info_list_response] tlv is empty/null");
        return eBadArg;
    }
    if (!obj) {
        LOGE("[es10_tlv_extractor__profile_info_list_response] ProfileInfoListResponse object is null");
        return eBadArg;
    }

    LOG_DATA(eLogDebug, "[es10_tlv_extractor__profile_info_list_response] tlv", tlv, tlv_size);

    /* Search the ProfileInfoListResponse TLV */
    offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, 0, PROFILE_INFO_LIST);
    if (offset < 0) {
        LOGE("[es10_tlv_extractor__profile_info_list_response] ProfileInfoListResponse TAG (%04X) not found, err %d", PROFILE_INFO_LIST, offset);
        return eFatal;
    }
    LOGD("[es10_tlv_extractor__profile_info_list_response] ProfileInfoListResponse TAG found at %d", offset);

    /* Parse the ProfileInfoListResponse VALUE TLV */
    tlv_value_offset = ber_tlv_parser__get_value_offset(tlv, (size_t) offset);
    if ((rc = ber_tlv_parser__ber_tlv_2(tlv, tlv_size, tlv_value_offset, &profile_info_list_response_value)) != eOk) {
        LOGE("[es10_tlv_extractor__profile_info_list_response] Error parsing the ProfileInfoListResponse VALUE TLV, rc %d", rc);
        return rc;
    }

    switch (profile_info_list_response_value.tag)
    {
    case CONTEXT_CONSTRUCTED_0:
        LOGD("[es10_tlv_extractor__profile_info_list_response] The ProfileInfoListResponse is a profileInfoListOk");
        obj->choice = PROFILE_INFO_LIST_OK_CHOICE;
        return tlv_data_extractor__asn1_list_init(&obj->value.ok, CONTEXT_CONSTRUCTED_0, PROFILE_INFO, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset);
    case CONTEXT_PRIMITIVE_1:
        LOGD("[es10_tlv_extractor__profile_info_list_response] The ProfileInfoListResponse is a profileInfoListError");
        obj->choice = PROFILE_INFO_LIST_ERROR_CHOICE;
        return es10_tlv_extractor__profile_info_list_error(tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &obj->value.error);
    default:
        LOGE("[es10_tlv_extractor__profile_info_list_response] Unknown TAG %04X of ProfileInfoListResponse CHOICE", profile_info_list_response_value.tag);
        return eFatal;
    }
}

ErrCode es10_tlv_extractor__profile_info(const uint8_t* tlv, const uint32_t tlv_size, profile_info_t* obj) {
    return es10_tlv_extractor__profile_info_prv(PROFILE_INFO, tlv, tlv_size, obj);
}

ErrCode es10_tlv_extractor__notification_configuration_information(const uint8_t* tlv, const uint32_t tlv_size, notification_configuration_information_t* obj) {
    ErrCode rc;
    int tlv_offset;
    size_t tlv_value_offset;
    bool field_is_present;

    /* Check input parameters */
    if (!tlv || tlv_size == 0) {
        LOGE("[es10_tlv_extractor__notification_configuration_information] tlv is empty/null");
        return eBadArg;
    }
    if (!obj) {
        LOGE("[es10_tlv_extractor__notification_configuration_information] NotificationConfigurationInformation object is null");
        return eBadArg;
    }

    // Search the NotificationConfigurationInformation TLV
    tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, 0, ASN1_DER_SEQUENCE);
    if (tlv_offset < 0) {
        LOGE("[es10_tlv_extractor__notification_configuration_information] TAG of NotificationConfigurationInformation (%02X) not found, err %d", ASN1_DER_SEQUENCE, tlv_offset);
        return eFatal;
    }
    tlv_value_offset = ber_tlv_parser__get_value_offset(tlv, (size_t) tlv_offset);
    LOGT("[es10_tlv_extractor__notification_configuration_information] NotificationConfigurationInformation VALUE offset %u", tlv_value_offset);

    // profileManagementOperation
    if ((rc = es10_tlv_extractor__notification_event(CONTEXT_PRIMITIVE_0, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &obj->profile_management_operation)) != eOk) {
        LOGE("[es10_tlv_extractor__notification_configuration_information] Error parsing the profileManagementOperation, rc %d", rc);
        return rc;
    }
    LOGD("[es10_tlv_extractor__notification_configuration_information] profileManagementOperation(%d)", obj->profile_management_operation);

    // notificationAddress
    if ((rc = tlv_data_extractor__fqdn(CONTEXT_PRIMITIVE_1, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &field_is_present, &obj->notification_address)) != eOk) {
        LOGE("[es10_tlv_extractor__notification_configuration_information] Error parsing the notificationAddress, rc %d", rc);
        return rc;
    }
    if (!field_is_present) {
        LOGE("[es10_tlv_extractor__notification_configuration_information] notificationAddress not found");
        return eFatal;
    }
    LOGD("[es10_tlv_extractor__notification_configuration_information] notificationAddress(%s)", obj->notification_address.fqdn);

    return eOk;
}
ErrCode es10_tlv_extractor__get_all_profiles_info(const uint8_t* tlv, const uint32_t tlv_size, profile_info_t** profiles, uint32_t* num_profiles) {
    ErrCode rc;
    profile_info_list_response_t profile_info_list_response;
    uint8_t* profile_info_tlv;
    uint32_t profile_info_tlv_size;
    uint32_t count = 0;
    profile_info_t* temp_profiles = NULL;

    if (!tlv || tlv_size == 0) {
        LOGE("[es10_tlv_extractor__get_all_profiles_info] tlv is empty/null");
        return eBadArg;
    }
    if (!profiles || !num_profiles) {
        LOGE("[es10_tlv_extractor__get_all_profiles_info] Output parameters are null");
        return eBadArg;
    }
    *profiles = NULL;
    *num_profiles = 0;

    if ((rc = es10_tlv_extractor__profile_info_list_response(tlv, tlv_size, &profile_info_list_response)) != eOk) {
        LOGE("[es10_tlv_extractor__get_all_profiles_info] Error parsing the ProfileInfoListResponse TLV, rc %d", rc);
        return rc;
    }

    if (PROFILE_INFO_LIST_ERROR_CHOICE == profile_info_list_response.choice) {
        LOGE("[es10_tlv_extractor__get_all_profiles_info] The ProfileInfoListResponse has an profileInfoListError(%d).", profile_info_list_response.value.error);
        return eFatal;
    }

    while ((rc = tlv_data_extractor__asn1_list_get_next(&profile_info_list_response.value.ok, &profile_info_tlv, &profile_info_tlv_size)) == eOk && profile_info_tlv != NULL) {
        profile_info_t* new_profiles = realloc(temp_profiles, (count + 1) * sizeof(profile_info_t));
        if (new_profiles == NULL) {
            LOGE("[es10_tlv_extractor__get_all_profiles_info] Memory allocation failed");
            free(temp_profiles);
            return eNoMem;
        }
        temp_profiles = new_profiles;

        if ((rc = es10_tlv_extractor__profile_info(profile_info_tlv, profile_info_tlv_size, &temp_profiles[count])) != eOk) {
            LOGE("[es10_tlv_extractor__get_all_profiles_info] Error parsing the profileInfo TLV, rc %d", rc);
            free(temp_profiles);
            return rc;
        }
        count++;
    }

    if (rc != eOk) {
        LOGE("[es10_tlv_extractor__get_all_profiles_info] Error iterating over the profileInfoListOk, rc %d", rc);
        free(temp_profiles);
        return rc;
    }

    *profiles = temp_profiles;
    *num_profiles = count;

    return eOk;
}
ErrCode es10_tlv_extractor__profile_info_enabled_profile(const uint8_t* tlv, const uint32_t tlv_size, bool* is_profile_enabled, profile_info_t* obj) {
    ErrCode rc;
    uint8_t* profile_info_tlv;
    uint32_t profile_info_tlv_size;
    profile_info_list_response_t profile_info_list_response;

    /* Check input parameters */
    if (!tlv || tlv_size == 0) {
        LOGE("[es10_tlv_extractor__profile_info_enabled_profile] tlv is empty/null");
        return eBadArg;
    }
    if (!obj) {
        LOGE("[es10_tlv_extractor__profile_info_enabled_profile] ProfileInfo object is null");
        return eBadArg;
    }
    if (!is_profile_enabled) {
        LOGE("[es10_tlv_extractor__profile_info_enabled_profile] The is_profile_enabled is null");
        return eBadArg;
    }

    /* Parse the ProfileInfoListResponse */
    if ((rc = es10_tlv_extractor__profile_info_list_response(tlv, tlv_size, &profile_info_list_response)) != eOk) {
        LOGE("[es10_tlv_extractor__profile_info_enabled_profile] Error parsing the ProfileInfoListResponse TLV, rc %d", rc);
        return rc;
    }

    if (PROFILE_INFO_LIST_ERROR_CHOICE == profile_info_list_response.choice) {
        LOGE("[es10_tlv_extractor__profile_info_enabled_profile] The ProfileInfoListResponse has an profileInfoListError(%d).", profile_info_list_response.value.error);
        return eFatal;
    }

    /* Iterate over the Profile Info List until the profile enabled is found */
    while ((rc = tlv_data_extractor__asn1_list_get_next(&profile_info_list_response.value.ok, &profile_info_tlv, &profile_info_tlv_size)) == eOk && profile_info_tlv != NULL) {
        if ((rc = es10_tlv_extractor__profile_info(profile_info_tlv, profile_info_tlv_size, obj)) != eOk) {
            LOGE("[es10_tlv_extractor__profile_info_enabled_profile] Error parsing the profileInfo TLV, rc %d", rc);
            return rc;
        }
        if (obj->field_is_present.profile_state && PROFILE_STATE_ENABLED == obj->profile_state) {
            // The profile enabled is found
            *is_profile_enabled = true;
            return eOk;
        }
    }
    if (rc != eOk) {
        LOGE("[es10_tlv_extractor__profile_info_enabled_profile] Error iterating over the profileInfoListOk, rc %d", rc);
        return rc;
    }

    *is_profile_enabled = false; // Any profile is enabled
    memset(obj, 0, sizeof(profile_info_t));

    return eOk;
}

ErrCode es10_tlv_extractor__get_euicc_data_response(const uint8_t* tlv, uint32_t tlv_size, get_euicc_data_response_t* obj) {
    ErrCode rc;
    int tlv_offset;
    size_t tlv_value_offset;
    _BerTlv eid_value;

    if (!tlv || tlv_size == 0) {
        LOGE("[es10_tlv_extractor__get_euicc_data_response] tlv is empty/null");
        return eBadArg;
    }
    LOG_DATA(eLogDebug, "[es10_tlv_extractor__get_euicc_data_response] GetEuiccDataResponse", tlv, tlv_size);

    // Search the GetEuiccDataResponse TLV
    if ((tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, 0, GET_EUICC_DATA)) < 0) {
        LOGE("[es10_tlv_extractor__get_euicc_data_response] TAG of GetEuiccDataResponse (%04X) not found", GET_EUICC_DATA);
        return eFatal;
    }
    tlv_value_offset = ber_tlv_parser__get_value_offset(tlv, (size_t) tlv_offset);

    // Search the eidValue TLV
    if ((tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, tlv_value_offset, EID)) < 0) {
        LOGE("[es10_tlv_extractor__get_euicc_challenge_response] TAG of eidValue (%02X) not found", EID);
        return eFatal;
    }
    if ((rc = ber_tlv_parser__ber_tlv_2(tlv, tlv_size, (size_t) tlv_offset, &eid_value)) != eOk) {
        LOGE("[es10_tlv_extractor__get_euicc_data_response] Error parsing the eidValue TLV, rc %d", rc);
        return rc;
    }

    if (eid_value.length != sizeof(obj->eid_value.eid)) {
        LOGE("[es10_tlv_extractor__get_euicc_data_response] Unexpected length of eidValue. Expected: %u, current: %u", sizeof(obj->eid_value.eid), eid_value.length);
        return eFatal;
    }
    memcpy(obj->eid_value.eid, tlv + tlv_value_offset + eid_value.nTag + eid_value.nLength, sizeof(obj->eid_value.eid));
    LOG_DATA(eLogDebug, "[es10_tlv_extractor__get_euicc_data_response] eidValue", obj->eid_value.eid, sizeof(obj->eid_value.eid));

    return eOk;
}

ErrCode es10_tlv_extractor__get_rat_response(const uint8_t* tlv, uint32_t tlv_size, get_rat_response_t* obj) {
    int tlv_offset;
    size_t tlv_value_offset;
    ErrCode rc;

    /* Check input parameters */
    if (!tlv || tlv_size == 0) {
        LOGE("[es10_tlv_extractor__get_rat_response] tlv is empty/null");
        return eBadArg;
    }
    if (!obj) {
        LOGE("[es10_tlv_extractor__get_rat_response] GetRatResponse object is null");
        return eBadArg;
    }

    LOG_DATA(eLogDebug, "[es10_tlv_extractor__get_rat_response] tlv", tlv, tlv_size);

    /* Search the GetRatResponse TLV */
    tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, 0, GET_RAT);
    if (tlv_offset < 0) {
        LOGE("[es10_tlv_extractor__get_rat_response] GetRatResponse TAG (%04X) not found, err %d", GET_RAT, tlv_offset);
        return eFatal;
    }
    tlv_value_offset = ber_tlv_parser__get_value_offset(tlv, (size_t) tlv_offset);
    LOGT("[es10_tlv_extractor__get_rat_response] GetRatResponse VALUE offset %u", tlv_value_offset);

    // rat
    if ((rc = tlv_data_extractor__asn1_list_init(&obj->rat, CONTEXT_CONSTRUCTED_0, ASN1_DER_SEQUENCE, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset)) != eOk) {
        LOGE("[es10_tlv_extractor__get_rat_response] Error initializing the rat list, rc %d", rc);
        return rc;
    }

    return eOk;
}

ErrCode es10_tlv_extractor__profile_policy_authorisation_rule(const uint8_t* tlv, uint32_t tlv_size, profile_policy_authorisation_rule_t* obj) {
    int tlv_offset;
    size_t tlv_value_offset;
    ErrCode rc;

    /* Check input parameters */
    if (!tlv || tlv_size == 0) {
        LOGE("[es10_tlv_extractor__profile_policy_authorisation_rule] tlv is empty/null");
        return eBadArg;
    }
    if (!obj) {
        LOGE("[es10_tlv_extractor__profile_policy_authorisation_rule] ProfilePolicyAuthorisationRule object is null");
        return eBadArg;
    }

    LOG_DATA(eLogDebug, "[es10_tlv_extractor__profile_policy_authorisation_rule] tlv", tlv, tlv_size);

    /* Search the ProfilePolicyAuthorisationRule TLV */
    tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, 0, ASN1_DER_SEQUENCE);
    if (tlv_offset < 0) {
        LOGE("[es10_tlv_extractor__profile_policy_authorisation_rule] ProfilePolicyAuthorisationRule TAG (%02X) not found, err %d", ASN1_DER_SEQUENCE, tlv_offset);
        return eFatal;
    }
    tlv_value_offset = ber_tlv_parser__get_value_offset(tlv, (size_t) tlv_offset);
    LOGT("[es10_tlv_extractor__profile_policy_authorisation_rule] ProfilePolicyAuthorisationRule VALUE offset %u", tlv_value_offset);

    // pprIds
    if ((rc = es10_tlv_extractor__ppr_ids(CONTEXT_PRIMITIVE_0, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &obj->ppr_ids)) != eOk) {
        LOGE("[es10_tlv_extractor__profile_policy_authorisation_rule] Error parsing the pprIds, rc %d", rc);
        return rc;
    }

    // allowedOperators
    if ((rc = tlv_data_extractor__asn1_list_init(&obj->allowed_operators, CONTEXT_CONSTRUCTED_1, ASN1_DER_SEQUENCE, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset)) != eOk) {
        LOGE("[es10_tlv_extractor__profile_policy_authorisation_rule] Error initializing the allowedOperators list, rc %d", rc);
        return rc;
    }

    // pprFlags
    if ((rc = es10_tlv_extractor__ppr_flags(CONTEXT_PRIMITIVE_2, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &obj->ppr_flags)) != eOk) {
        LOGE("[es10_tlv_extractor__profile_policy_authorisation_rule] Error parsing the pprFlags, rc %d", rc);
        return rc;
    }

    return eOk;
}

ErrCode es10_tlv_extractor__set_default_dp_address_response(const uint8_t* tlv, const uint32_t tlv_size, set_default_dp_address_response_t* obj) {
    ErrCode rc;
    uint8_t result;

    if ((rc = tlv_data_extractor__result_code_with_parent_tlv(SET_DEFAULT_SMDP_ADDRESS, CONTEXT_PRIMITIVE_0, tlv, tlv_size, &result)) != eOk) {
        LOGE("[es10_tlv_extractor__set_default_dp_address_response] Error extracting the setDefaultDpAddressResult, rc %d", rc);
        return rc;
    }

    if (result != SET_DEFAULT_DP_ADDRESS_RESULT_OK &&
        result != SET_DEFAULT_DP_ADDRESS_RESULT_UNDEFINED_ERROR) {
        LOGE("[es10_tlv_extractor__set_default_dp_address_response] Result %02X not defined in the setDefaultDpAddressResult", result);
        return eFatal;
    }

    obj->set_default_dp_address_result = result;

    return eOk;
}

#ifdef SGP22
ErrCode es10_tlv_extractor__list_notification_response(const uint8_t* tlv, const uint32_t tlv_size, list_notification_response_t* obj) {
    ErrCode rc;
    int tlv_offset;
    size_t tlv_value_offset;
    _BerTlv list_notification_response;

    if (tlv == NULL || tlv_size == 0) {
        LOGE("[es10_tlv_extractor__list_notification_response] tlv is empty/null");
        return eBadArg;
    }
    LOG_DATA(eLogDebug, "[es10_tlv_extractor__list_notification_response] ListNotificationResponse", tlv, tlv_size);

    if ((tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, 0, LIST_NOTIFICATION)) < 0) {
        LOGE("[es10_tlv_extractor__list_notification_response] TAG of ListNotificationResponse (%04X) not found", LIST_NOTIFICATION);
        return eFatal;
    }
    tlv_value_offset = ber_tlv_parser__get_value_offset(tlv, (size_t) tlv_offset);

    if ((rc = ber_tlv_parser__ber_tlv_2(tlv, tlv_size, tlv_value_offset, &list_notification_response)) != eOk) {
        LOGE("[es10_tlv_extractor__list_notification_response] Error parsing the ListNotificationResponse TLV, rc %d", rc);
        return rc;
    }

    switch (list_notification_response.tag)
    {
    case CONTEXT_CONSTRUCTED_0:
        LOGD("[es10_tlv_extractor__list_notification_response] The ListNotificationResponse is a notificationMetadataList");
        obj->choice = NOTIFICATION_METADATA_LIST_CHOICE;
        return tlv_data_extractor__asn1_list_init(&obj->value.notification_metadata_list, CONTEXT_CONSTRUCTED_0, NOTIFICATION_METADATA, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset);
    case CONTEXT_PRIMITIVE_1:
        LOGD("[es10_tlv_extractor__list_notification_response] The ListNotificationResponse is a listNotificationsResultError");
        obj->choice = LIST_NOTIFICATION_RESULTS_ERROR_CHOICE;
        return es10_tlv_extractor__notifications_list_result_error(tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &obj->value.list_notifications_result_error);
    default:
        LOGE("[es10_tlv_extractor__list_notification_response] Unknown TAG %04X of ListNotificationResponse CHOICE", list_notification_response.tag);
        return eFatal;
    }
}

ErrCode es10_tlv_extractor__enable_profile_response(const uint8_t* tlv, const uint32_t tlv_size, enable_profile_response_t* obj) {
    ErrCode rc;
    uint8_t result;
    
    if ((rc = tlv_data_extractor__result_code_with_parent_tlv(ENABLE_PROFILE, CONTEXT_PRIMITIVE_0, tlv, tlv_size, &result)) != eOk) {
        LOGE("[es10_tlv_extractor__enable_profile_response] Error extracting the enableResult, rc %d", rc);
        return rc;
    }

    if (result != ENABLE_RESULT_OK && 
        result != ENABLE_RESULT_ICCID_OR_AID_NOT_FOUND && 
        result != ENABLE_RESULT_PROFILE_NOT_IN_DISABLED_STATE && 
        result != ENABLE_RESULT_DISALLOWED_BY_POLICY && 
        result != ENABLE_RESULT_WRONG_PROFILE_REENABLING && 
        result != ENABLE_RESULT_CAT_BUSY &&
        result != ENABLE_RESULT_UNDEFINED_ERROR) {
        LOGE("[es10_tlv_extractor__enable_profile_response] Result %02X not defined in the enableResult", result);
        return eFatal;
    }

    obj->enable_result = result;

    return eOk;
}

ErrCode es10_tlv_extractor__disable_profile_response(const uint8_t* tlv, const uint32_t tlv_size, disable_profile_response_t* obj) {
    ErrCode rc;
    uint8_t result;
    
    if ((rc = tlv_data_extractor__result_code_with_parent_tlv(DISABLE_PROFILE, CONTEXT_PRIMITIVE_0, tlv, tlv_size, &result)) != eOk) {
        LOGE("[es10_tlv_extractor__disable_profile_response] Error extracting the disableResult, rc %d", rc);
        return rc;
    }

    if (result != DISABLE_RESULT_OK && 
        result != DISABLE_RESULT_ICCID_OR_AID_NOT_FOUND && 
        result != DISABLE_RESULT_PROFILE_NOT_IN_ENABLED_STATE && 
        result != DISABLE_RESULT_DISALLOWED_BY_POLICY && 
        result != DISABLE_RESULT_CAT_BUSY && 
        result != DISABLE_RESULT_UNDEFINED_ERROR) {
        LOGE("[es10_tlv_extractor__disable_profile_response] Result %02X not defined in the disableResult", result);
        return eFatal;
    }

    obj->disable_result = result;

    return eOk;
}

ErrCode es10_tlv_extractor__delete_profile_response(const uint8_t* tlv, const uint32_t tlv_size, delete_profile_response_t* obj) {
    ErrCode rc;
    uint8_t result;
    
    if ((rc = tlv_data_extractor__result_code_with_parent_tlv(DELETE_PROFILE, CONTEXT_PRIMITIVE_0, tlv, tlv_size, &result)) != eOk) {
        LOGE("[es10_tlv_extractor__delete_profile_response] Error extracting the deleteResult, rc %d", rc);
        return rc;
    }

    if (result != DELETE_RESULT_OK && 
        result != DELETE_RESULT_ICCID_OR_AID_NOT_FOUND && 
        result != DELETE_RESULT_PROFILE_NOT_IN_DISABLED_STATE && 
        result != DELETE_RESULT_DISALLOWED_BY_POLICY && 
        result != DELETE_RESULT_UNDEFINED_ERROR) {
        LOGE("[es10_tlv_extractor__delete_profile_response] Result %02X not defined in the deleteResult", result);
        return eFatal;
    }

    obj->delete_result = result;

    return eOk;
}

ErrCode es10_tlv_extractor__set_nickname_response(const uint8_t* tlv, const uint32_t tlv_size, set_nickname_response_t* obj) {
    ErrCode rc;
    uint8_t result;
    
    if ((rc = tlv_data_extractor__result_code_with_parent_tlv(SET_NICKNAME, CONTEXT_PRIMITIVE_0, tlv, tlv_size, &result)) != eOk) {
        LOGE("[es10_tlv_extractor__set_nickname_response] Error extracting the setNicknameResult, rc %d", rc);
        return rc;
    }

    if (result != SET_NICKNAME_RESULT_OK && 
        result != SET_NICKNAME_RESULT_ICCID_NOT_FOUND && 
        result != SET_NICKNAME_RESULT_UNDEFINED_ERROR) {
        LOGE("[es10_tlv_extractor__set_nickname_response] Result %02X not defined in the setNicknameResult", result);
        return eFatal;
    }

    obj->set_nickname_result = result;

    return eOk;
}
#endif

#ifdef SGP32
ErrCode es10_tlv_extractor__euicc_package_result(const uint8_t* buffer, const uint32_t buffer_size, euicc_package_result_t* obj) {
    ErrCode rc;
    unsigned short child_tag;
    uint8_t* child_tlv;
    uint32_t child_tlv_size;

    if (!obj) {
        LOGE("[es10_tlv_extractor__euicc_package_result] EuiccPackageResult object is null");
        return eBadArg;
    }

    if ((rc = tlv_data_extractor__child_tag_tlv_big_size_ref(EUICC_PACKAGE, buffer, buffer_size, NULL, &child_tag, &child_tlv, &child_tlv_size)) != eOk) {
        LOGE("[es10_tlv_extractor__euicc_package_result] Error extracting the EuiccPackageResult child TLV, rc %d", rc);
        return rc;
    }

    switch (child_tag)
    {
    case CONTEXT_CONSTRUCTED_0:
        LOGD("[es10_tlv_extractor__euicc_package_result] The EuiccPackageResult is a EuiccPackageResultSigned");
        obj->choice = EUICC_PACKAGE_RESULT_SIGNED_CHOICE;
        return es10_tlv_extractor__euicc_package_result_signed(CONTEXT_CONSTRUCTED_0, child_tlv, child_tlv_size, &obj->value.euicc_package_result_signed);
    case CONTEXT_CONSTRUCTED_1:
        LOGD("[es10_tlv_extractor__euicc_package_result] The EuiccPackageResult is a EuiccPackageErrorSigned");
        obj->choice = EUICC_PACKAGE_ERROR_SIGNED_CHOICE;
        return es10_tlv_extractor__euicc_package_error_signed(CONTEXT_CONSTRUCTED_1, child_tlv, child_tlv_size, &obj->value.euicc_package_error_signed);
    case CONTEXT_CONSTRUCTED_2:
        LOGD("[es10_tlv_extractor__euicc_package_result] The EuiccPackageResult is a EuiccPackageErrorUnsigned");
        obj->choice = EUICC_PACKAGE_ERROR_UNSIGNED_CHOICE;
        return es10_tlv_extractor__euicc_package_error_unsigned(CONTEXT_CONSTRUCTED_2, child_tlv, child_tlv_size, &obj->value.euicc_package_error_unsigned);
    default:
        LOGE("[es10_tlv_extractor__euicc_package_result] Unknown EuiccPackageResult CHOICE, tag %04X", child_tag);
        return eFatal;
    }
}

ErrCode es10_tlv_extractor__add_initial_eim_response(const uint8_t* tlv, const uint32_t tlv_size, add_initial_eim_response_t* obj) {
    ErrCode rc;
    int tlv_offset;
    size_t tlv_value_offset;
    _BerTlv add_initial_eim_response;

    if (tlv == NULL || tlv_size == 0) {
        LOGE("[es10_tlv_extractor__add_initial_eim_response] tlv is empty/null");
        return eBadArg;
    }
    LOG_DATA(eLogDebug, "[es10_tlv_extractor__add_initial_eim_response] AddInitialEimResponse", tlv, tlv_size);

    if ((tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, 0, ADD_INITIAL_EIM)) < 0) {
        LOGE("[es10_tlv_extractor__add_initial_eim_response] TAG of AddInitialEimResponse (%04X) not found", ADD_INITIAL_EIM);
        return eFatal;
    }
    tlv_value_offset = ber_tlv_parser__get_value_offset(tlv, (size_t) tlv_offset);

    if ((rc = ber_tlv_parser__ber_tlv_2(tlv, tlv_size, tlv_value_offset, &add_initial_eim_response)) != eOk) {
        LOGE("[es10_tlv_extractor__add_initial_eim_response] Error parsing the AddInitialEimResponse VALUE TLV, rc %d", rc);
        return rc;
    }

    switch (add_initial_eim_response.tag)
    {
    case CONTEXT_CONSTRUCTED_0:
        LOGD("[es10_tlv_extractor__add_initial_eim_response] The AddInitialEimResponse is an addInitialEimOk");
        obj->choice = ADD_INITIAL_EIM_OK_CHOICE;
        return es10_tlv_extractor__add_initial_eim_ok(tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &obj->value.add_initial_eim_ok);
    case CONTEXT_PRIMITIVE_1:
        LOGD("[es10_tlv_extractor__add_initial_eim_response] The AddInitialEimResponse is an addInitialEimError");
        obj->choice = ADD_INITIAL_EIM_ERROR_CHOICE;
        return es10_tlv_extractor__add_initial_eim_error(tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &obj->value.add_initial_eim_error);
    default:
        LOGE("[es10_tlv_extractor__add_initial_eim_response] Unknown TAG %04X of AddInitialEimResponse CHOICE", add_initial_eim_response.tag);
        return eFatal;
    }
}

ErrCode es10_tlv_extractor__get_certs_response(const uint8_t* tlv, const uint32_t tlv_size, get_certs_response_t* obj) {
    ErrCode rc;
    unsigned short child_tag;
    uint8_t* child_tlv;
    uint32_t child_tlv_size;

    if (!obj) {
        LOGE("[es10_tlv_extractor__get_certs_response] GetCertsResponse object is null");
        return eBadArg;
    }

    if ((rc = tlv_data_extractor__child_tag_tlv_big_size_ref(GET_CERTS, tlv, tlv_size, NULL, &child_tag, &child_tlv, &child_tlv_size)) != eOk) {
        LOGE("[es10_tlv_extractor__get_certs_response] Error extracting the GetCertsResponse child TLV, rc %d", rc);
        return rc;
    }

    switch (child_tag)
    {
    case CONTEXT_CONSTRUCTED_0:
        obj->choice = CERTS_CHOICE;
        return es10_tlv_extractor__certs(CONTEXT_CONSTRUCTED_0, child_tlv, child_tlv_size, &obj->value.certs);
    case CONTEXT_PRIMITIVE_1:
        obj->choice = GET_CERTS_ERROR_CHOICE;
        return es10_tlv_extractor__get_certs_error(CONTEXT_PRIMITIVE_1, child_tlv, child_tlv_size, &obj->value.get_certs_error);
    default:
        LOGE("[es10_tlv_extractor__get_certs_response] Invalid GetCertsResponse CHOICE, tag %04X", child_tag);
        return eFatal;
    }
}

ErrCode es10_tlv_extractor__immediate_enable_response(const uint8_t* tlv, const uint32_t tlv_size, immediate_enable_response_t* obj) {
    ErrCode rc;
    uint8_t result;

    if ((rc = tlv_data_extractor__result_code_with_parent_tlv(IMMEDIATE_ENABLE, CONTEXT_PRIMITIVE_0, tlv, tlv_size, &result)) != eOk) {
        LOGE("[es10_tlv_extractor__immediate_enable_response] Error extracting the result of the TLV, rc %d", rc);
        return rc;
    }

    LOGD("[es10_tlv_extractor__immediate_enable_response] ImmediateEnableResponse(immediateEnableResult=%02X)", result);

    switch (result)
    {
    case IMMEDIATE_ENABLE_RESULT_OK:
    case IMMEDIATE_ENABLE_RESULT_IMMEDIATE_ENABLE_NOT_AVAILABLE:
    case IMMEDIATE_ENABLE_RESULT_NO_SESSION_CONTEXT:
    case IMMEDIATE_ENABLE_RESULT_CAT_BUSY:
    case IMMEDIATE_ENABLE_RESULT_UNDEFINED_ERROR:
        obj->immediate_enable_result = result;
        return eOk;
    default:
        LOGE("[es10_tlv_extractor__immediate_enable_response] Result %02X not defined in the immediateEnableResult", result);
        return eFatal;
    }
}

ErrCode es10_tlv_extractor__profile_rollback_response(const uint8_t* tlv, const uint32_t tlv_size, profile_rollback_response_t* obj) {
    uint8_t* value = NULL;
    uint32_t value_size = 0;
    ErrCode rc = eFatal;
    bool is_present = false;

    if (!obj) {
        LOGE("[es10_tlv_extractor__profile_rollback_response] The ProfileRollbackResponse object is null");
        return eBadArg;
    }

    // Get ProfileRollbackResponse value
    if ((rc = tlv_data_extractor__tlv_value_big_size_ref(PROFILE_ROLLBACK, tlv, tlv_size, NULL, &value, &value_size)) != eOk) {
        LOGE("[es10_tlv_extractor__profile_rollback_response] Error on extract the ProfileRollbackResponse value, rc %d", rc);
        return rc;
    }

    // Parse cmdResult
    if ((rc = es10_tlv_extractor__profile_rollback_result(ASN1_DER_INTEGER, value, value_size, &obj->cmd_result)) != eOk) {
        LOGE("[es10_tlv_extractor__profile_rollback_response] Error on extract the ProfileRollbackResponse value, rc %d", rc);
        return rc;
    }

    // Parse eUICCPackageResult
    if ((rc = tlv_data_extractor__tlv_big_size_ref(EUICC_PACKAGE, value, value_size, &is_present, &obj->euicc_package_result, &obj->euicc_package_result_size)) != eOk) {
        LOGE("[es10_tlv_extractor__profile_rollback_response] Error on extract the eUICCPackageResult, rc %d", rc);
        return rc;
    }
    if (is_present) {
        LOG_DATA(eLogTrace, "[es10_tlv_extractor__profile_rollback_response] eUICCPackageResult", obj->euicc_package_result, obj->euicc_package_result_size);
    } else {
        LOGD("[es10_tlv_extractor__profile_rollback_response] eUICCPackageResult is not present");
        obj->euicc_package_result = NULL;
        obj->euicc_package_result_size = 0;
    }

    return eOk;
}

ErrCode es10_tlv_extractor__configure_immediate_profile_enabling_response(const uint8_t* tlv, const uint32_t tlv_size, configure_immediate_profile_enabling_response_t* obj) {
    ErrCode rc;
    uint8_t result;

    if ((rc = tlv_data_extractor__result_code_with_parent_tlv(CONFIGURE_IMMEDIATE_PROFILE_ENABLING, CONTEXT_PRIMITIVE_0, tlv, tlv_size, &result)) != eOk) {
        LOGE("[es10_tlv_extractor__configure_immediate_profile_enabling_response] Error extracting the result of the TLV, rc %d", rc);
        return rc;
    }

    LOGD("[es10_tlv_extractor__configure_immediate_profile_enabling_response] ConfigureImmediateProfileEnablingResponse(configImmediateEnableResult=%02X)", result);

    if (result != CONFIG_IMMEDIATE_ENABLE_RESULT_OK && result != CONFIG_IMMEDIATE_ENABLE_RESULT_INSUFFICIENT_MEMORY && result != CONFIG_IMMEDIATE_ENABLE_RESULT_ASSOCIATED_EIM_ALREADY_EXISTS && result != CONFIG_IMMEDIATE_ENABLE_RESULT_UNDEFINED_ERROR) {
        LOGE("[es10_tlv_extractor__configure_immediate_profile_enabling_response] Result %02X not defined in the configImmediateEnableResult", result);
        return eFatal;
    }

    obj->config_immediate_enable_result = result;
    return eOk;
}

ErrCode es10_tlv_extractor__get_eim_configuration_data_response(const uint8_t* tlv, const uint32_t tlv_size, get_eim_configuration_data_response_t* obj) {
    int err = 0;
    uint8_t* child = NULL;
    uint32_t child_size = 0;

    if (!tlv || tlv_size == 0) {
        LOGE("[es10_tlv_extractor__get_eim_configuration_data_response] tlv is empty/null");
        return eBadArg;
    }
    if (!obj) {
        LOGE("[es10_tlv_extractor__get_eim_configuration_data_response] GetEimConfigurationDataResponse object is null");
        return eBadArg;
    }
    LOG_DATA(eLogTrace, "[es10_tlv_extractor__get_eim_configuration_data_response] GetEimConfigurationDataResponse", tlv, tlv_size);


    // Get the eimConfigurationDataList
    if ((err = tlv_data_extractor__tlv_value_big_size_ref(GET_EIM_CONFIGURATION_DATA, tlv, tlv_size, NULL, &child, &child_size)) != eOk) {
        LOGE("[es10_tlv_extractor__get_eim_configuration_data_response] Error extracting the eimConfigurationDataList TLV, err %d", err);
        return eFatal;
    }

    // Init the eimConfigurationDataList
    return tlv_data_extractor__asn1_list_init(&obj->eim_configuration_data_list_iterator, CONTEXT_CONSTRUCTED_0, ASN1_DER_SEQUENCE, child, child_size);
}

ErrCode es10_tlv_extractor__get_eim_configuration_data_response_list_size(const uint8_t* tlv, const uint32_t tlv_size, uint32_t* count) {
    ErrCode rc = eFatal;
    uint8_t* eim_configuration_data = NULL;
    uint32_t eim_configuration_data_size = 0;
    get_eim_configuration_data_response_t get_eim_configuration_data_response = { 0 };

    // Initialize the eimConfigurationDataList
    if ((rc = es10_tlv_extractor__get_eim_configuration_data_response(tlv, tlv_size, &get_eim_configuration_data_response)) != eOk) {
        LOGE("[es10_tlv_extractor__get_eim_configuration_data_response_list_size] Error initializing the eimConfigurationDataList of the GetEimConfigurationDataResponse, rc %d", rc);
        return rc;
    }

    *count = 0;
    // Iterate over the list and increment the count for each element found
    while ((rc = tlv_data_extractor__asn1_list_get_next(&get_eim_configuration_data_response.eim_configuration_data_list_iterator, &eim_configuration_data, &eim_configuration_data_size)) == eOk && eim_configuration_data != NULL) {
        LOGT("[es10_tlv_extractor__get_eim_configuration_data_response_list_size] %u EimConfigurationData in eimConfigurationDataList", *count);
        (*count)++;
        LOGT("[es10_tlv_extractor__get_eim_configuration_data_response_list_size] %u EimConfigurationData in eimConfigurationDataList", *count);
    }

    if (rc != eOk) {
        LOGE("[es10_tlv_extractor__get_eim_configuration_data_response_list_size] Error iterating over the eimConfigurationDataList, rc %d", rc);
        return rc;
    }

    LOGT("[es10_tlv_extractor__get_eim_configuration_data_response_list_size] %u EimConfigurationData in eimConfigurationDataList", *count);

    return eOk;
}

ErrCode es10_tlv_extractor__get_eim_configuration_data_response_assocation_token(const uint8_t* tlv, const uint32_t tlv_size, uint32_t* association_token) {
    ErrCode rc = eFatal;
    uint8_t* eim_configuration_data_tlv = NULL;
    uint32_t eim_configuration_data_tlv_size = 0;
    get_eim_configuration_data_response_t get_eim_configuration_data_response = { 0 };
    eim_configuration_data_t eim_configuration_data = { 0 };

    // Initialize the eimConfigurationDataList
    if ((rc = es10_tlv_extractor__get_eim_configuration_data_response(tlv, tlv_size, &get_eim_configuration_data_response)) != eOk) {
        LOGE("[es10_tlv_extractor__get_eim_configuration_data_response_assocation_token] Error initializing the eimConfigurationDataList of the GetEimConfigurationDataResponse, rc %d", rc);
        return rc;
    }

    // Iterate over the list to find if any EimConfigurationData has the association token configured
    while ((rc = tlv_data_extractor__asn1_list_get_next(&get_eim_configuration_data_response.eim_configuration_data_list_iterator, &eim_configuration_data_tlv, &eim_configuration_data_tlv_size)) == eOk && eim_configuration_data_tlv != NULL) {
        if ((rc = es10_tlv_extractor__eim_configuration_data(eim_configuration_data_tlv, eim_configuration_data_tlv_size, &eim_configuration_data)) == eOk) {
            if (eim_configuration_data.field_is_present.association_token) {
                LOGD("[es10_tlv_extractor__get_eim_configuration_data_response_assocation_token] Association token found. Association token value: %u", eim_configuration_data.association_token);
                *association_token = eim_configuration_data.association_token;
                return eOk;
            }
        } else {
            LOGE("[es10_tlv_extractor__get_eim_configuration_data_response_assocation_token] Error extracting the EimConfigurationData, rc %d", rc);
            return eFatal;
        }
    }
    if (rc != eOk) {
        LOGE("[es10_tlv_extractor__get_eim_configuration_data_response_assocation_token] Error iterating over the eimConfigurationDataList, rc %d", rc);
        return rc;
    }

    LOGD("[es10_tlv_extractor__get_eim_configuration_data_response_assocation_token] Association token not found. The association token value is the default (%u)", ASSOCIATION_TOKEN_DEFAULT_VALUE);
    *association_token = (uint32_t) ASSOCIATION_TOKEN_DEFAULT_VALUE;

    return eOk;
}

#ifdef EXTRA_FEATURE_EMERGENCY_PROFILE_MANAGMENT
ErrCode es10_tlv_extractor__enable_emergency_profile_response(const uint8_t* tlv, const uint32_t tlv_size, enable_emergency_profile_response_t* obj) {
    ErrCode rc;
    uint8_t result;

    if ((rc = tlv_data_extractor__result_code_with_parent_tlv(ENABLE_EMERGENCY_PROFILE, CONTEXT_PRIMITIVE_0, tlv, tlv_size, &result)) != eOk) {
        LOGE("[es10_tlv_extractor__enable_emergency_profile_response] Error extracting the result of the TLV, rc %d", rc);
        return rc;
    }

    LOGD("[es10_tlv_extractor__enable_emergency_profile_response] EnableEmergencyProfileResultResponse(EnableEmergencyProfile=%02X)", result);

    switch (result) {
    case ENABLE_EMERGENCY_PROFILE_RESULT_OK:
    case ENABLE_EMERGENCY_PROFILE_RESULT_PROFILE_NOT_IN_DISABLED_STATE:
    case ENABLE_EMERGENCY_PROFILE_RESULT_CAT_BUSY:
    case ENABLE_EMERGENCY_PROFILE_RESULT_ECALL_NOT_AVAILABLE:
    case ENABLE_EMERGENCY_PROFILE_RESULT_UNDEFINED_ERROR:
        break;
    default:
        LOGE("[es10_tlv_extractor__enable_emergency_profile_response] Result %02X not defined in the enableEmergencyProfileResult", result);
        return eFatal;
    }

    obj->enable_emergency_profile_result = result;
    return eOk;
}

ErrCode es10_tlv_extractor__disable_emergency_profile_response(const uint8_t* tlv, const uint32_t tlv_size, disable_emergency_profile_response_t* obj) {
    ErrCode rc;
    uint8_t result;

    if ((rc = tlv_data_extractor__result_code_with_parent_tlv(DISABLE_EMERGENCY_PROFILE, CONTEXT_PRIMITIVE_0, tlv, tlv_size, &result)) != eOk) {
        LOGE("[es10_tlv_extractor__disable_emergency_profile_response] Error extracting the result of the TLV, rc %d", rc);
        return rc;
    }

    LOGD("[es10_tlv_extractor__disable_emergency_profile_response] DisableEmergencyProfileResultResponse(DisableEmergencyProfile=%02X)", result);

    switch (result) {
    case DISABLE_EMERGENCY_PROFILE_RESULT_OK:
    case DISABLE_EMERGENCY_PROFILE_RESULT_PROFILE_NOT_IN_ENABLED_STATE:
    case DISABLE_EMERGENCY_PROFILE_RESULT_CAT_BUSY:
#ifdef PRE_CR
    case DISABLE_EMERGENCY_PROFILE_RESULT_ECALL_NOT_AVAILABLE:
#endif
    case DISABLE_EMERGENCY_PROFILE_RESULT_UNDEFINED_ERROR:
        break;
    default:
        LOGE("[es10_tlv_extractor__disable_emergency_profile_response] Result %02X not defined in the disableEmergencyProfileResult", result);
        return eFatal;
    }

    obj->disable_emergency_profile_result = result;
    return eOk;
}
#endif

#ifdef EXTRA_FEATURE_FALLBACK_MECHANISM
ErrCode es10_tlv_extractor__execute_fallback_mechanism_response(const uint8_t* tlv, const uint32_t tlv_size, execute_fallback_mechanism_response_t* obj) {
    ErrCode rc;
    uint8_t result;

    if ((rc = tlv_data_extractor__result_code_with_parent_tlv(EXECUTE_FALLBACK_MECHANISM, CONTEXT_PRIMITIVE_0, tlv, tlv_size, &result)) != eOk) {
        LOGE("[es10_tlv_extractor__execute_fallback_mechanism_response] Error extracting the result of the TLV, rc %d", rc);
        return rc;
    }

    LOGD("[es10_tlv_extractor__execute_fallback_mechanism_response] ExecuteFallbackMechanismResponse(executeFallbackMechanismResult=%02X)", result);

    if (result != EXECUTE_FALLBACK_MECHANISM_RESULT_OK &&
        result != EXECUTE_FALLBACK_MECHANISM_RESULT_PROFILE_NOT_IN_DISABLED_STATE &&
        result != EXECUTE_FALLBACK_MECHANISM_RESULT_CAT_BUSY &&
        result != EXECUTE_FALLBACK_MECHANISM_RESULT_FALLBACK_NOT_AVAILABLE &&
        result != EXECUTE_FALLBACK_MECHANISM_RESULT_COMMAND_ERROR &&
        result != EXECUTE_FALLBACK_MECHANISM_RESULT_ECALL_ACTIVE &&
        result != EXECUTE_FALLBACK_MECHANISM_RESULT_UNDEFINED_ERROR) {
        LOGE("[es10_tlv_extractor__execute_fallback_mechanism_response] Result %02X not defined in the executeFallbackMechanismResult", result);
        return eFatal;
    }

    obj->execute_fallback_mechanism_result = result;
    return eOk;
}

ErrCode es10_tlv_extractor__return_from_fallback_response(const uint8_t* tlv, const uint32_t tlv_size, return_from_fallback_response_t* obj) {
    ErrCode rc;
    uint8_t result;

    if ((rc = tlv_data_extractor__result_code_with_parent_tlv(RETURN_FROM_FALLBACK, CONTEXT_PRIMITIVE_0, tlv, tlv_size, &result)) != eOk) {
        LOGE("[es10_tlv_extractor__return_from_fallback_response] Error extracting the result of the TLV, rc %d", rc);
        return rc;
    }

    LOGD("[es10_tlv_extractor__return_from_fallback_response] ReturnFromFallbackResponse(returnFromFallbackResult=%02X)", result);

    if (result != RETURN_FROM_FALLBACK_RESULT_OK &&
        result != RETURN_FROM_FALLBACK_RESULT_CAT_BUSY &&
        result != RETURN_FROM_FALLBACK_RESULT_FALLBACK_NOT_AVAILABLE &&
        result != RETURN_FROM_FALLBACK_RESULT_COMMAND_ERROR &&
        result != RETURN_FROM_FALLBACK_RESULT_UNDEFINED_ERROR) {
        LOGE("[es10_tlv_extractor__return_from_fallback_response] Result %02X not defined in the returnFromFallbackResult", result);
        return eFatal;
    }

    obj->return_from_fallback_result = result;
    return eOk;
}
#endif
#endif

static ErrCode es10_tlv_extractor__profile_installation_result_data(const uint8_t* tlv, const uint32_t tlv_size, profile_installation_result_data_t* obj) {
    ErrCode rc;
    int tlv_offset;
    size_t tlv_value_offset;
    bool field_is_present;
    _BerTlv smdp_oid_tlv;

    if (!tlv || tlv_size == 0) {
        LOGE("[es10_tlv_extractor__profile_installation_result_data] tlv is empty/null");
        return eBadArg;
    }

    LOG_DATA(eLogTrace, "[es10_tlv_extractor__profile_installation_result_data] tlv", tlv, tlv_size);

    // Search the ProfileInstallationResultData TLV
    tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, 0, PROFILE_INSTALLATION_RESULT_DATA);
    if (tlv_offset < 0) {
        LOGE("[es10_tlv_extractor__profile_installation_result_data] ProfileInstallationResultData TAG 0x%04X not found", PROFILE_INSTALLATION_RESULT_DATA);
        return eFatal;
    }
    tlv_value_offset = ber_tlv_parser__get_value_offset(tlv, tlv_offset);

    // transactionId
    if ((rc = tlv_data_extractor__transaction_id(CONTEXT_PRIMITIVE_0, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &field_is_present, &obj->transaction_id)) == eOk) {
        if (!field_is_present) {
            LOGE("[es10_tlv_extractor__profile_installation_result_data] The field transactionId is not present in the ProfileInstallationResultData");
            return eFatal;
        }
    } else {
        LOGE("[es10_tlv_extractor__profile_installation_result_data] Error extracting the transactionId of the ProfileInstallationResultData, rc %d", rc);
        return rc;
    }

    // notificationMetadata
    if ((rc = es10_tlv_extractor__notification_metadata(tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &obj->notification_metadata)) != eOk) {
        LOGE("[es10_tlv_extractor__profile_installation_result_data] Error extracting the notificationMetadata of the ProfileInstallationResultData, rc %d", rc);
        return rc;
    }

    // finalResult
    if ((rc = es10_tlv_extractor__final_result(CONTEXT_CONSTRUCTED_2, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &obj->final_result)) != eOk) {
        LOGE("[es10_tlv_extractor__profile_installation_result_data] Error extracting the finalResult of the ProfileInstallationResultData, rc %d", rc);
        return rc;
    }

    // smdpOid
    tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, tlv_value_offset, ASN1_DER_OBJ_IDENTIFIER);
    if (tlv_offset < 0) {
        LOGE("[es10_tlv_extractor__profile_installation_result_data] smdpOid TAG 0x%02X not found", ASN1_DER_OBJ_IDENTIFIER);
        return eFatal;
    }

    if ((rc = ber_tlv_parser__ber_tlv_2(tlv, tlv_size, (size_t) tlv_offset, &smdp_oid_tlv)) != eOk) {
        LOGE("[es10_tlv_extractor__profile_installation_result_data] Error parsing the smdpOid TLV, rc %d", rc);
        return rc;
    }

    obj->smdp_oid = tlv + tlv_offset + smdp_oid_tlv.nTag + smdp_oid_tlv.nLength;
    obj->smdp_oid_size = (uint32_t) smdp_oid_tlv.length;
    LOG_DATA(eLogDebug, "[es10_tlv_extractor__profile_installation_result_data] smdpOid", obj->smdp_oid, obj->smdp_oid_size);

    return eOk;
}

static ErrCode es10_tlv_extractor__final_result(const unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, final_result_t* obj) {
    ErrCode rc;
    int tlv_offset;
    size_t tlv_value_offset;
    _BerTlv final_result_choice_tlv;

    if (!tlv || tlv_size == 0) {
        LOGE("[es10_tlv_extractor__final_result] tlv is empty/null");
        return eBadArg;
    }
    LOG_DATA(eLogTrace, "[es10_tlv_extractor__final_result] tlv", tlv, tlv_size);

    // Search the finalResult TLV
    tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, 0, tag);
    if (tlv_offset < 0) {
        LOGE("[es10_tlv_extractor__final_result] finalResult TAG 0x%04X not found", tag);
        return eFatal;
    }
    tlv_value_offset = ber_tlv_parser__get_value_offset(tlv, tlv_offset);

    // Parse the finalResult CHOICE TLV
    if ((rc = ber_tlv_parser__ber_tlv_2(tlv, tlv_size, tlv_value_offset, &final_result_choice_tlv)) != eOk) {
        LOGE("[es10_tlv_extractor__final_result] Error parsing the finalResult CHOICE TLV, rc %d", rc);
        return rc;
    }

    switch (final_result_choice_tlv.tag)
    {
    case CONTEXT_CONSTRUCTED_0:
        obj->choice = FINAL_RESULT_CHOICE_SUCCESS_RESULT;
        return es10_tlv_extractor__success_result(CONTEXT_CONSTRUCTED_0, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &obj->value.success_result);
    case CONTEXT_CONSTRUCTED_1:
        obj->choice = FINAL_RESULT_CHOICE_ERROR_RESULT;
        return es10_tlv_extractor__error_result(CONTEXT_CONSTRUCTED_1, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &obj->value.error_result);
    default:
        LOGE("[es10_tlv_extractor__final_result] Unknown TAG (%04X) of finalResult CHOICE TLV", final_result_choice_tlv.tag);
        return eFatal;
    }
}

static ErrCode es10_tlv_extractor__success_result(const unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, success_result_t* obj) {
    ErrCode rc;
    int tlv_offset;
    size_t tlv_value_offset;
    _BerTlv child_tlv;

    if (!tlv || tlv_size == 0) {
        LOGE("[es10_tlv_extractor__success_result] tlv is empty/null");
        return eBadArg;
    }
    LOG_DATA(eLogTrace, "[es10_tlv_extractor__success_result] tlv", tlv, tlv_size);

    // Search the SuccessResult TLV
    tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, 0, tag);
    if (tlv_offset < 0) {
        LOGE("[es10_tlv_extractor__success_result] finalResult TAG 0x%04X not found", tag);
        return eFatal;
    }
    tlv_value_offset = ber_tlv_parser__get_value_offset(tlv, tlv_offset);

    // aid
    tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, tlv_value_offset, AID);
    if (tlv_offset < 0) {
        LOGE("[es10_tlv_extractor__success_result] aid TAG 0x%02X not found", AID);
        return eFatal;
    }
    if ((rc = ber_tlv_parser__ber_tlv_2(tlv, tlv_size, (size_t) tlv_offset, &child_tlv)) != eOk) {
        LOGE("[es10_tlv_extractor__success_result] Error parsing the aid TLV, rc %d", rc);
        return rc;
    }
    if (child_tlv.length < 5 || child_tlv.length > 16) {
        LOGE("[es10_tlv_extractor__success_result] Bad aid length %u", child_tlv.length);
        return eFatal;
    }
    memcpy(obj->aid, tlv + tlv_offset + child_tlv.nTag + child_tlv.nLength, child_tlv.length);
    obj->aid_size = (uint8_t) child_tlv.length;
    LOG_DATA(eLogDebug, "[es10_tlv_extractor__success_result] SuccessResult aid", obj->aid, obj->aid_size);

    // simaResponse
    tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, tlv_value_offset, ASN1_DER_OCTET_STRING);
    if (tlv_offset < 0) {
        LOGE("[es10_tlv_extractor__success_result] simaResponse TAG 0x%02X not found", ASN1_DER_OCTET_STRING);
        return eFatal;
    }
    if ((rc = ber_tlv_parser__ber_tlv_2(tlv, tlv_size, (size_t) tlv_offset, &child_tlv)) != eOk) {
        LOGE("[es10_tlv_extractor__success_result] Error parsing the simaResponse TLV, rc %d", rc);
        return rc;
    }
    obj->sima_response = tlv + tlv_offset + child_tlv.nTag + child_tlv.nLength;
    obj->sima_response_size = (uint32_t) child_tlv.length;
    LOG_DATA(eLogDebug, "[es10_tlv_extractor__success_result] SuccessResult simaResponse", obj->sima_response, obj->sima_response_size);

    return eOk;
}

static ErrCode es10_tlv_extractor__error_result(const unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, error_result_t* obj) {
    ErrCode rc;
    int tlv_offset;
    size_t tlv_value_offset;
    _BerTlv sima_response_tlv;

    if (!tlv || tlv_size == 0) {
        LOGE("[es10_tlv_extractor__error_result] tlv is empty/null");
        return eBadArg;
    }
    LOG_DATA(eLogTrace, "[es10_tlv_extractor__error_result] tlv", tlv, tlv_size);

    // Search the errorResult TLV
    tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, 0, tag);
    if (tlv_offset < 0) {
        LOGE("[es10_tlv_extractor__error_result] finalResult TAG 0x%04X not found", tag);
        return eFatal;
    }
    tlv_value_offset = ber_tlv_parser__get_value_offset(tlv, tlv_offset);

    // bppCommandId
    if ((rc = es10_tlv_extractor__bpp_command_id(CONTEXT_PRIMITIVE_0, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &obj->bpp_command_id)) != eOk) {
        LOGE("[es10_tlv_extractor__error_result] Error extracting the bppCommandId of the errorResult, rc %d", rc);
        return rc;
    }
    LOGD("[es10_tlv_extractor__error_result] errorResult bppCommandId: %d", obj->bpp_command_id);

    // errorReason
    if ((rc = es10_tlv_extractor__error_reason(CONTEXT_PRIMITIVE_1, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &obj->error_reason)) != eOk) {
        LOGE("[es10_tlv_extractor__error_result] Error extracting the errorReason of the errorResult, rc %d", rc);
        return rc;
    }
    LOGD("[es10_tlv_extractor__error_result] errorResult errorReason: %d", obj->error_reason);

    // simaResponse
    if ((tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, tlv_value_offset, ASN1_DER_OCTET_STRING)) >= 0) {
        LOGD("[es10_tlv_extractor__error_result] errorResult simaResponse is present");
        obj->field_is_present.sima_response = true;
        if ((rc = ber_tlv_parser__ber_tlv_2(tlv, tlv_size, (size_t) tlv_offset, &sima_response_tlv)) != eOk) {
            LOGE("[es10_tlv_extractor__error_result] Error parsing the simaResponse TLV, rc %d", rc);
            return rc;
        }
        obj->sima_response = tlv + tlv_offset + sima_response_tlv.nTag + sima_response_tlv.nLength;
        obj->sima_response_size = (uint32_t) sima_response_tlv.length;
        LOG_DATA(eLogDebug, "[es10_tlv_extractor__error_result] ErrorResult simaResponse", obj->sima_response, obj->sima_response_size);
    } else {
        LOGD("[es10_tlv_extractor__error_result] errorResult simaResponse is not present");
        obj->field_is_present.sima_response = false;
    }

    return eOk;
}

static ErrCode es10_tlv_extractor__bpp_command_id(const unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, bpp_command_id_t* obj) {
    ErrCode rc;
    uint8_t result;

    if ((rc = tlv_data_extractor__result_code(tag, tlv, tlv_size, NULL, &result)) != eOk) {
        LOGE("[es10_tlv_extractor__bpp_command_id] Error extracting the bppCommandId, rc %d", rc);
        return rc;
    }

    if (result != BPP_COMMAND_ID_INITIALISE_SECURE_CHANNEL &&
        result != BPP_COMMAND_ID_CONFIGURE_ISDP &&
        result != BPP_COMMAND_ID_STORE_METADATA &&
        result != BPP_COMMAND_ID_STORE_METADATA_2 &&
        result != BPP_COMMAND_ID_REPLACE_SESSION_KEYS &&
        result != BPP_COMMAND_ID_LOAD_PROFILE_ELEMENTS) {
        LOGE("[es10_tlv_extractor__bpp_command_id] id %02X not defined in the bppCommandId", result);
        return eFatal;
    }

    *obj = result;

    return eOk;
}

static ErrCode es10_tlv_extractor__error_reason(const unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, error_reason_t* obj) {
    ErrCode rc;
    uint8_t result;

    if ((rc = tlv_data_extractor__result_code(tag, tlv, tlv_size, NULL, &result)) != eOk) {
        LOGE("[es10_tlv_extractor__error_reason] Error extracting the errorReason, rc %d", rc);
        return rc;
    }

    if (result != INCORRECT_INPUT_VALUES &&
        result != INVALID_SIGNATURE &&
        result != INVALID_TRANSACTION_ID &&
        result != UNSUPPORTED_CRT_VALUES &&
        result != UNSUPPORTED_REMOTE_OPERATION_TYPE &&
        result != UNSUPPORTED_PROFILE_CLASS &&
        result != SCP03T_STRUCTURE_ERROR &&
        result != SCP03T_SECURITY_ERROR &&
        result != INSTALL_FAILED_DUE_TO_ICCID_ALREADY_EXISTS_ON_EUICC &&
        result != INSTALL_FAILED_DUE_TO_INSUFFICIENT_MEMORY_FOR_PROFILE &&
        result != INSTALL_FAILED_DUE_TO_INTERRUPTION &&
        result != INSTALL_FAILED_DUE_TO_PE_PROCESSING_ERROR &&
        result != INSTALL_FAILED_DUE_TO_DATA_MISMATCH &&
        result != TEST_PROFILE_INSTALL_FAILED_DUE_TO_INVALID_NAA_KEY &&
        result != PPR_NOT_ALLOWED &&
        result != INSTALL_FAILED_DUE_TO_UNKNOWN_ERROR) {
        LOGE("[es10_tlv_extractor__error_reason] Error %02X not defined in the errorReason", result);
        return eFatal;
    }

    *obj = result;

    return eOk;
}

static ErrCode es10_tlv_extractor__profile_info_list_error(const uint8_t* tlv, const uint32_t tlv_size, profile_info_list_error_t* obj) {
    ErrCode rc;
    uint8_t result;

    if ((rc = tlv_data_extractor__result_code(CONTEXT_PRIMITIVE_1, tlv, tlv_size, NULL, &result)) != eOk) {
        LOGE("[es10_tlv_extractor__profile_info_list_error] Error extracting the profileInfoListError, rc %d", rc);
        return rc;
    }

    if (result != PROFILE_INFO_LIST_ERROR_INCORRECT_INPUT_VALUES &&
        result != PROFILE_INFO_LIST_ERROR_UNDEFINED_ERROR) {
        LOGE("[es10_tlv_extractor__profile_info_list_error] Error %02X not defined in the profileInfoListError", result);
        return eFatal;
    }

    *obj = result;

    return eOk;
}

static ErrCode es10_tlv_extractor__profile_info_prv(const unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, profile_info_t* obj) {
    ErrCode rc;
    int tlv_offset;
    size_t tlv_value_offset;
    uint8_t result;

    /* Check input parameters */
    if (!tlv || tlv_size == 0) {
        LOGE("[es10_tlv_extractor__profile_info_prv] tlv is empty/null");
        return eBadArg;
    }
    if (!obj) {
        LOGE("[es10_tlv_extractor__profile_info_prv] ProfileInfo object is null");
        return eBadArg;
    }

    // Search the profileInfo TLV
    tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, 0, tag);
    if (tlv_offset < 0) {
        LOGE("[es10_tlv_extractor__profile_info_prv] TAG of profileInfo (%04X) not found, err %d", tag, tlv_offset);
        return eFatal;
    }
    tlv_value_offset = ber_tlv_parser__get_value_offset(tlv, (size_t) tlv_offset);
    LOGT("[es10_tlv_extractor__profile_info_prv] profileInfo VALUE offset %u", tlv_value_offset);

    // iccid OPTIONAL
    if ((rc = tlv_data_extractor__tlv_value_big_size_copy(ICCID, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &obj->field_is_present.iccid, obj->iccid.value, (uint32_t) sizeof(obj->iccid.value), NULL)) != eOk) {
        LOGE("[es10_tlv_extractor__profile_info_prv] Error extracting the iccid, rc %d", rc);
        return rc;
    }
    if (obj->field_is_present.iccid) {
        LOG_DATA(eLogDebug, "[es10_tlv_extractor__profile_info_prv] iccid", obj->iccid.value, sizeof(obj->iccid.value));
    } else {
        LOGD("[es10_tlv_extractor__profile_info_prv] iccid is not present");
    }

    // isdpAid OPTIONAL
    if ((rc = tlv_data_extractor__tlv_value_big_size_copy(AID, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &obj->field_is_present.isdp_aid, obj->isdp_aid.value, (uint32_t) sizeof(obj->isdp_aid.value), NULL)) != eOk) {
        LOGE("[es10_tlv_extractor__profile_info_prv] Error extracting the isdpAid, rc %d", rc);
        return rc;
    }
    if (obj->field_is_present.isdp_aid) {
        LOG_DATA(eLogDebug, "[es10_tlv_extractor__profile_info_prv] isdpAid", obj->isdp_aid.value, sizeof(obj->isdp_aid.value));
    } else {
        LOGD("[es10_tlv_extractor__profile_info_prv] isdpAid is not present");
    }

    // profileState OPTIONAL
    if ((rc = tlv_data_extractor__result_code(PROFILE_INFO_STATE, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &obj->field_is_present.profile_state, &result)) != eOk) {
        LOGE("[es10_tlv_extractor__profile_info_prv] Error extracting the profileInfoState, rc %d", rc);
        return rc;
    }
    if (obj->field_is_present.profile_state) {
        if (result != PROFILE_STATE_DISABLED && result != PROFILE_STATE_ENABLED) {
            LOGE("[es10_tlv_extractor__profile_info_prv] State %02X not defined in the profileInfoState", result);
            return eFatal;
        }
        obj->profile_state = result;
        LOGD("[es10_tlv_extractor__profile_info_prv] profileState=%d", obj->profile_state);
    } else {
        LOGD("[es10_tlv_extractor__profile_info_prv] profileState is not present");
    }

    // profileNickname OPTIONAL
    if ((rc = tlv_data_extractor__tlv_value_small_size_copy(PROFILE_INFO_NICKNAME, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &obj->field_is_present.profile_nickname, obj->profile_nickname.value, (uint8_t) sizeof(obj->profile_nickname.value), &obj->profile_nickname.len)) != eOk) {
        LOGE("[es10_tlv_extractor__profile_info_prv] Error extracting the profileNickname, rc %d", rc);
        return rc;
    }
    if (obj->field_is_present.profile_nickname) {
        LOG_UTF8_DATA(eLogDebug, "[es10_tlv_extractor__profile_info_prv] profileNickname: ", obj->profile_nickname.value, obj->profile_nickname.len);
    } else {
        LOGD("[es10_tlv_extractor__profile_info_prv] profileNickname is not present");
    }

    // serviceProviderName OPTIONAL
    if ((rc = tlv_data_extractor__tlv_value_small_size_copy(PROFILE_INFO_PROV_NAME, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &obj->field_is_present.service_provider_name, obj->service_provider_name.value, (uint8_t) sizeof(obj->service_provider_name.value), &obj->service_provider_name.len)) != eOk) {
        LOGE("[es10_tlv_extractor__profile_info_prv] Error extracting the serviceProviderName, rc %d", rc);
        return rc;
    }
    if (obj->field_is_present.service_provider_name) {
        LOG_UTF8_DATA(eLogDebug, "[es10_tlv_extractor__profile_info_prv] serviceProviderName: ", obj->service_provider_name.value, obj->service_provider_name.len);
    } else {
        LOGD("[es10_tlv_extractor__profile_info_prv] serviceProviderName is not present");
    }

    // profileName OPTIONAL
    if ((rc = tlv_data_extractor__tlv_value_small_size_copy(PROFILE_INFO_NAME, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &obj->field_is_present.profile_name, obj->profile_name.value, (uint8_t) sizeof(obj->profile_name.value), &obj->profile_name.len)) != eOk) {
        LOGE("[es10_tlv_extractor__profile_info_prv] Error extracting the profileName, rc %d", rc);
        return rc;
    }
    if (obj->field_is_present.profile_name) {
        LOG_UTF8_DATA(eLogDebug, "[es10_tlv_extractor__profile_info_prv] profileName: ", obj->profile_name.value, obj->profile_name.len);
    } else {
        LOGD("[es10_tlv_extractor__profile_info_prv] profileName is not present");
    }

    // iconType OPTIONAL
    if ((rc = tlv_data_extractor__result_code(PROFILE_INFO_ICON_TYPE, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &obj->field_is_present.icon_type, &result)) != eOk) {
        LOGE("[es10_tlv_extractor__profile_info_prv] Error extracting the iconType, rc %d", rc);
        return rc;
    }
    if (obj->field_is_present.icon_type) {
        if (result != ICON_TYPE_JPG && result != ICON_TYPE_PNG) {
            LOGE("[es10_tlv_extractor__profile_info_prv] type %02X not defined in the iconType", result);
            return eFatal;
        }
        obj->icon_type = result;
        LOGD("[es10_tlv_extractor__profile_info_prv] iconType=%d", obj->icon_type);
    } else {
        LOGD("[es10_tlv_extractor__profile_info_prv] iconType is not present");
    }

    // icon OPTIONAL
    if ((rc = tlv_data_extractor__tlv_value_medium_size_copy(PROFILE_INFO_ICON, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &obj->field_is_present.icon, obj->icon.value, (uint16_t) sizeof(obj->icon.value), &obj->icon.size)) != eOk) {
        LOGE("[es10_tlv_extractor__profile_info_prv] Error extracting the icon, rc %d", rc);
        return rc;
    }
    if (obj->field_is_present.icon) {
        LOG_DATA(eLogDebug, "[es10_tlv_extractor__profile_info_prv] icon", obj->icon.value, obj->icon.size);
    } else {
        LOGD("[es10_tlv_extractor__profile_info_prv] icon is not present");
    }

    // profileClass OPTIONAL
    if ((rc = tlv_data_extractor__result_code(PROFILE_INFO_CLASS, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &obj->field_is_present.profile_class, &result)) != eOk) {
        LOGE("[es10_tlv_extractor__profile_info_prv] Error extracting the profileClass, rc %d", rc);
        return rc;
    }
    if (obj->field_is_present.profile_class) {
        if (result != PROFILE_CLASS_TEST && result != PROFILE_CLASS_PROVISIONING && result != PROFILE_CLASS_OPERATIONAL) {
            LOGE("[es10_tlv_extractor__profile_info_prv] class %02X not defined in the profileClass", result);
            return eFatal;
        }
        obj->profile_class = result;
        LOGD("[es10_tlv_extractor__profile_info_prv] profileClass=%d", obj->profile_class);
    } else {
        LOGD("[es10_tlv_extractor__profile_info_prv] profileClass is not present");
    }

    // notificationConfigurationInfo OPTIONAL
    if ((tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, tlv_value_offset, PROFILE_INFO_NOTIF_CONFIG)) >= 0) {
        if ((rc = tlv_data_extractor__asn1_list_init(&obj->notification_configuration_info, PROFILE_INFO_NOTIF_CONFIG, ASN1_DER_SEQUENCE, tlv + tlv_offset, tlv_size - tlv_offset)) != eOk) {
            LOGE("[es10_tlv_extractor__profile_info_prv] Error initializing the notificationConfigurationInfo list, rc %d", rc);
            return rc;
        }
        obj->field_is_present.notification_configuration_info = true;
    } else {
        LOGD("[es10_tlv_extractor__profile_info_prv] notificationConfigurationInfo is not present");
        obj->field_is_present.notification_configuration_info = false;
    }

    // profileOwner OPTIONAL
    if ((tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, tlv_value_offset, PROFILE_INFO_OWNER)) >= 0) {
        if ((rc = tlv_data_extractor__operator_id(PROFILE_INFO_OWNER, tlv + tlv_offset, tlv_size - tlv_offset, &obj->profile_owner)) != eOk) {
            LOGE("[es10_tlv_extractor__profile_info_prv] Error extracting the profileInfoOwner data, rc %d", rc);
            return rc;
        }
        obj->field_is_present.profile_owner = true;
    } else {
        LOGD("[es10_tlv_extractor__profile_info_prv] profileOwner is not present");
        obj->field_is_present.profile_owner = false;
    }

    // dpProprietaryData OPTIONAL
    if ((tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, tlv_value_offset, PROFILE_INFO_SMDP_DATA)) >= 0) {
        if ((rc = es10_tlv_extractor__dp_propietary_data(PROFILE_INFO_SMDP_DATA, tlv + tlv_offset, tlv_size - tlv_offset, &obj->dp_propietary_data)) != eOk) {
            LOGE("[es10_tlv_extractor__profile_info_prv] Error extracting the dpProprietaryData data, rc %d", rc);
            return rc;
        }
        obj->field_is_present.dp_propietary_data = true;
    } else {
        LOGD("[es10_tlv_extractor__profile_info_prv] dpProprietaryData is not present");
        obj->field_is_present.dp_propietary_data = false;
    }

    // profilePolicyRules OPTIONAL
    if ((tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, tlv_value_offset, PROFILE_INFO_PPRS)) >= 0) {
        if ((rc = es10_tlv_extractor__ppr_ids(PROFILE_INFO_PPRS, tlv + tlv_offset, tlv_size - tlv_offset, &obj->profile_policy_rules)) != eOk) {
            LOGE("[es10_tlv_extractor__profile_info_prv] Error extracting the profilePolicyRules data, rc %d", rc);
            return rc;
        }
        obj->field_is_present.profile_policy_rules = true;
    } else {
        LOGD("[es10_tlv_extractor__profile_info_prv] profilePolicyRules is not present");
        obj->field_is_present.profile_policy_rules = false;
    }

#ifdef SGP32
    // ecallIndication OPTIONAL
    if ((rc = tlv_data_extractor__boolean(PROFILE_INFO_ECALL_INDICATION, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &obj->field_is_present.ecall_indication, &obj->ecall_indication)) != eOk) {
        LOGE("[es10_tlv_extractor__profile_info_prv] Error extracting the ecallIndication data, rc %d", rc);
        return rc;
    }
    if (obj->field_is_present.ecall_indication) {
        LOGD("[es10_tlv_extractor__profile_info_prv] ecallIndication=%d", obj->ecall_indication);
    } else {
        LOGD("[es10_tlv_extractor__profile_info_prv] ecallIndication is not present");
    }

    // fallbackAttribute OPTIONAL
    if ((rc = tlv_data_extractor__boolean(PROFILE_INFO_FALLBACK_ATTRIBUTE, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &obj->field_is_present.fallback_attribute, &obj->fallback_attribute)) != eOk) {
        LOGE("[es10_tlv_extractor__profile_info_prv] Error extracting the fallbackAttribute data, rc %d", rc);
        return rc;
    }
    if (obj->field_is_present.fallback_attribute) {
        LOGD("[es10_tlv_extractor__profile_info_prv] fallbackAttribute=%d", obj->fallback_attribute);
    } else {
        LOGD("[es10_tlv_extractor__profile_info_prv] fallbackAttribute is not present");
    }

    // fallbackAllowed OPTIONAL
    if ((rc = tlv_data_extractor__boolean(PROFILE_INFO_FALLBACK_ALLOWED, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, &obj->field_is_present.fallback_allowed, &obj->fallback_allowed)) != eOk) {
        LOGE("[es10_tlv_extractor__profile_info_prv] Error extracting the fallbackAllowed data, rc %d", rc);
        return rc;
    }
    if (obj->field_is_present.fallback_allowed) {
        LOGD("[es10_tlv_extractor__profile_info_prv] fallbackAllowed=%d", obj->fallback_allowed);
    } else {
        LOGD("[es10_tlv_extractor__profile_info_prv] fallbackAllowed is not present");
    }
#endif

    return eOk;
}

static ErrCode es10_tlv_extractor__dp_propietary_data(const unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, dp_propietary_data_t* obj) {
    ErrCode rc;
    int tlv_offset;
    size_t tlv_value_offset;

    /* Check input parameters */
    if (!tlv || tlv_size == 0) {
        LOGE("[es10_tlv_extractor__dp_propietary_data] tlv is empty/null");
        return eBadArg;
    }
    if (!obj) {
        LOGE("[es10_tlv_extractor__dp_propietary_data] DpProprietaryData object is null");
        return eBadArg;
    }

    // Search the DpProprietaryData TLV
    tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, 0, tag);
    if (tlv_offset < 0) {
        LOGE("[es10_tlv_extractor__dp_propietary_data] TAG of DpProprietaryData (%04X) not found, err %d", tag, tlv_offset);
        return eFatal;
    }
    tlv_value_offset = ber_tlv_parser__get_value_offset(tlv, (size_t) tlv_offset);
    LOGT("[es10_tlv_extractor__dp_propietary_data] DpProprietaryData VALUE offset %u", tlv_value_offset);

    // dpOid
    if ((rc = tlv_data_extractor__tlv_value_small_size_copy(CONTEXT_PRIMITIVE_0, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, NULL, obj->dp_oid, (uint8_t) sizeof(obj->dp_oid), &obj->dp_oid_size)) != eOk) {
        LOGE("[es10_tlv_extractor__dp_propietary_data] Error extracting the dpOid, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogDebug, "[es10_tlv_extractor__dp_propietary_data] dpOid", obj->dp_oid, obj->dp_oid_size);

    /* More propietary data may be found on this TLV */

    return eOk;
}

static ErrCode es10_tlv_extractor__ppr_ids(const unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, ppr_ids_t* obj) {
    ErrCode rc;
    uint8_t ppr_ids_plain[] = { 0, 0, 0 };

    if ((rc = tlv_data_extractor__bit_string(tag, tlv, tlv_size, ppr_ids_plain, sizeof(ppr_ids_plain))) != eOk) {
        LOGE("[es10_tlv_extractor__ppr_ids] Error extracting the PprIds BIT STRING, rc %d", rc);
        return rc;
    }

    obj->ppr_update_control = (bool) ppr_ids_plain[0];
    obj->ppr1 = (bool) ppr_ids_plain[1];
    obj->ppr2 = (bool) ppr_ids_plain[2];

    LOGD("[es10_tlv_extractor__ppr_ids] pprUpdateControl=%u, ppr1=%u, ppr2=%u", obj->ppr_update_control, obj->ppr1, obj->ppr2);

    return eOk;
}

static ErrCode es10_tlv_extractor__ppr_flags(const unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, ppr_flags_t* obj) {
    ErrCode rc;
    uint8_t ppr_flags_plain[] = { 0 };

    if ((rc = tlv_data_extractor__bit_string(tag, tlv, tlv_size, ppr_flags_plain, sizeof(ppr_flags_plain))) != eOk) {
        LOGE("[es10_tlv_extractor__ppr_flags] Error extracting the pprFlags BIT STRING, rc %d", rc);
        return rc;
    }

    obj->consent_required = (bool) ppr_flags_plain[0];

    LOGD("[es10_tlv_extractor__ppr_flags] consentRequired=%u", obj->consent_required);

    return eOk;
}

static ErrCode es10_tlv_extractor__notifications_list_result_error(const uint8_t* tlv, const uint32_t tlv_size, notifications_list_result_error_t* obj) {
    ErrCode rc;
    uint8_t result;

    if ((rc = tlv_data_extractor__result_code(CONTEXT_PRIMITIVE_1, tlv, tlv_size, NULL, &result)) != eOk) {
        LOGE("[es10_tlv_extractor__notifications_list_result_error] Error extracting the notificationsListResultError, rc %d", rc);
        return rc;
    }

    if (result != NOTIFICATIONS_LIST_RESULT_ERROR_UNDEFINED_ERROR) {
        LOGE("[es10_tlv_extractor__notifications_list_result_error] Error %02X not defined in the notificationsListResultError", result);
        return eFatal;
    }

    *obj = result;

    return eOk;
}

static ErrCode es10_tlv_extractor__notification_metadata_from_pir(const uint8_t* tlv, const uint32_t tlv_size, notification_metadata_t* obj) {
    profile_installation_result_t pir;
    ErrCode rc;

    if ((rc = es10_tlv_extractor__profile_installation_result(tlv, tlv_size, &pir)) != eOk) {
        LOGE("[es10_tlv_extractor__notification_metadata_from_pir] Error parsing the ProfileInstallationResult, rc %d", rc);
        return rc;
    }

    memcpy(obj, &pir.profile_installation_result_data.notification_metadata, sizeof(notification_metadata_t));

    return eOk;
}

static ErrCode es10_tlv_extractor__notification_metadata_from_other_signed_notification(const uint8_t* tlv, const uint32_t tlv_size, notification_metadata_t* obj) {
    int tlv_offset;
    size_t tlv_value_offset;

    if (!tlv || tlv_size == 0) {
        LOGE("[es10_tlv_extractor__notification_metadata_from_other_signed_notification] tlv is empty/null");
        return eBadArg;
    }
    LOG_DATA(eLogTrace, "[es10_tlv_extractor__notification_metadata_from_other_signed_notification] OtherSignedNotification", tlv, tlv_size);

    // Search the OtherSignedNotification TLV
    if ((tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, 0, ASN1_DER_SEQUENCE)) < 0) {
        LOGE("[es10_tlv_extractor__notification_metadata_from_other_signed_notification] TAG of OtherSignedNotification (%02X) not found", ASN1_DER_SEQUENCE);
        return eFatal;
    }
    tlv_value_offset = ber_tlv_parser__get_value_offset(tlv, (size_t) tlv_offset);
    LOGT("[es10_tlv_extractor__notification_metadata_from_other_signed_notification] OtherSignedNotification VALUE offset %u", tlv_value_offset);

    return es10_tlv_extractor__notification_metadata(tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, obj);
}

static ErrCode es10_tlv_extractor__segmented_bound_profile_package_checksum(const uint8_t* tlv, const uint32_t tlv_size, segmented_bound_profile_package_t* obj) {
    ErrCode rc;
    uint32_t sum = 0;
    uint8_t* element;
    uint32_t element_size;

    /* Check input parameters */
    if (!tlv || tlv_size == 0) {
        LOGE("[es10_tlv_extractor__segmented_bound_profile_package_checksum] BoundProfilePackage is empty/null");
        return eBadArg;
    }
    if (!obj) {
        LOGE("[es10_tlv_extractor__segmented_bound_profile_package_checksum] Segmented BoundProfilePackage object is null");
        return eBadArg;
    }

    sum += obj->tag_length_bpp_and_init_secure_channel_req_size; //Tag and length fields of the BoundProfilePackage TLV plus the initialiseSecureChannelRequest TLV
    sum += obj->first_sequence_of_87_size; // Tag and length fields of the first sequenceOf87 TLV plus the first '87' TLV
    sum += obj->tag_length_sequence_of_88_size; // Tag and length fields of the sequenceOf88 TLV

    // Each of the '88' TLVs
    while ((rc = tlv_data_extractor__asn1_list_get_next(&obj->elements_of_88, &element, &element_size)) == eOk && element != NULL) {
        sum += element_size;
    }
    if (rc != eOk) {
        LOGE("[es10_tlv_extractor__segmented_bound_profile_package_checksum] Error iterating over the sequenceOf88 List, rc %d", rc);
        return rc;
    }
    tlv_data_extractor__asn1_list_reinit(&obj->elements_of_88);

    if (obj->field_is_present.second_sequence_of_87) {
        sum += obj->second_sequence_of_87_size; // Tag and length fields of the sequenceOf87 TLV plus the first '87' TLV
    }

    sum += obj->tag_length_sequence_of_86_size; // Tag and length fields of the sequenceOf86 TLV

    // Each of the '86' TLVs
    while ((rc = tlv_data_extractor__asn1_list_get_next(&obj->elements_of_86, &element, &element_size)) == eOk && element != NULL) {
        sum += element_size;
    }
    if (rc != eOk) {
        LOGE("[es10_tlv_extractor__segmented_bound_profile_package_checksum] Error iterating over the sequenceOf86 List, rc %d", rc);
        return rc;
    }
    tlv_data_extractor__asn1_list_reinit(&obj->elements_of_86);

    if (sum == tlv_size) {
        LOGD("[es10_tlv_extractor__segmented_bound_profile_package_checksum] Bound Profile Package Checksum match");
        return eOk;
    } else {
        LOGD("[es10_tlv_extractor__segmented_bound_profile_package_checksum] Bound Profile Package Checksum mismatch. BoundProfilePackage size %u, calculated sum %u", tlv_size, sum);
        return eFatal;
    }
}

#ifdef SGP32
static ErrCode es10_tlv_extractor__euicc_package_result_signed(const unsigned short tag, const uint8_t* buffer, const uint32_t buffer_size, euicc_package_result_signed_t* obj) {
    ErrCode rc;
    uint8_t* tlv_value;
    uint32_t tlv_value_size;

    if (!obj) {
        LOGE("[es10_tlv_extractor__euicc_package_result_signed] EuiccPackageResultSigned object is null");
        return eBadArg;
    }

    // Get EuiccPackageResultSigned value
    if ((rc = tlv_data_extractor__tlv_value_big_size_ref(tag, buffer, buffer_size, NULL, &tlv_value, &tlv_value_size)) != eOk) {
        LOGE("[es10_tlv_extractor__euicc_package_result_signed] Error extracting the EuiccPackageResultSigned TLV value");
        return rc;
    }

    // Parse euiccPackageResultDataSigned
    if ((rc = es10_tlv_extractor__euicc_package_result_data_signed(ASN1_DER_SEQUENCE, tlv_value, tlv_value_size, &obj->euicc_package_result_data_signed)) != eOk) {
        LOGE("[es10_tlv_extractor__euicc_package_result_signed] Error extracting the euiccPackageResultDataSigned, rc %d", rc);
        return rc;
    }

    // Parse euiccSignEPR
    if ((rc = tlv_data_extractor__tlv_value_big_size_ref(SIGNATURE, tlv_value, tlv_value_size, NULL, &obj->euicc_sign_epr, &obj->euicc_sign_epr_size)) != eOk) {
        LOGE("[es10_tlv_extractor__euicc_package_result_signed] Error extracting the euiccSignEPR, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogDebug, "[es10_tlv_extractor__euicc_package_result_signed] euiccSignEPR", obj->euicc_sign_epr, obj->euicc_sign_epr_size);

    return eOk;
}

static ErrCode es10_tlv_extractor__euicc_package_error_signed(const unsigned short tag, const uint8_t* buffer, const uint32_t buffer_size, euicc_package_error_signed_t* obj) {
    ErrCode rc;
    uint8_t* tlv_value;
    uint32_t tlv_value_size;

    if (!obj) {
        LOGE("[es10_tlv_extractor__euicc_package_error_signed] EuiccPackageErrorSigned object is null");
        return eBadArg;
    }

    // Get EuiccPackageErrorSigned value
    if ((rc = tlv_data_extractor__tlv_value_big_size_ref(tag, buffer, buffer_size, NULL, &tlv_value, &tlv_value_size)) != eOk) {
        LOGE("[es10_tlv_extractor__euicc_package_error_signed] Error extracting the EuiccPackageErrorSigned TLV value");
        return rc;
    }

    // Parse euiccPackageErrorDataSigned
    if ((rc = es10_tlv_extractor__euicc_package_error_data_signed(ASN1_DER_SEQUENCE, tlv_value, tlv_value_size, &obj->euicc_package_error_data_signed)) != eOk) {
        LOGE("[es10_tlv_extractor__euicc_package_error_signed] Error extracting the euiccPackageErrorDataSigned, rc %d", rc);
        return rc;
    }

    // Parse euiccSignEPE
    if ((rc = tlv_data_extractor__tlv_value_big_size_ref(SIGNATURE, tlv_value, tlv_value_size, NULL, &obj->euicc_sign_epe, &obj->euicc_sign_epe_size)) != eOk) {
        LOGE("[es10_tlv_extractor__euicc_package_error_signed] Error extracting the euiccSignEPE, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogDebug, "[es10_tlv_extractor__euicc_package_error_signed] euiccSignEPE", obj->euicc_sign_epe, obj->euicc_sign_epe_size);

    return eOk;
}

static ErrCode es10_tlv_extractor__euicc_package_error_unsigned(const unsigned short tag, const uint8_t* buffer, const uint32_t buffer_size, euicc_package_error_unsigned_t* obj) {
    ErrCode rc;
    uint8_t* tlv_value;
    uint32_t tlv_value_size;

    if (!obj) {
        LOGE("[es10_tlv_extractor__euicc_package_error_unsigned] EuiccPackageErrorUnsigned object is null");
        return eBadArg;
    }

    // Get EuiccPackageErrorUnsigned value
    if ((rc = tlv_data_extractor__tlv_value_big_size_ref(tag, buffer, buffer_size, NULL, &tlv_value, &tlv_value_size)) != eOk) {
        LOGE("[es10_tlv_extractor__euicc_package_error_unsigned] Error extracting the EuiccPackageErrorUnsigned TLV value");
        return rc;
    }

    // Parse eimId
    if ((rc = tlv_data_extractor__tlv_value_small_size_ref(CONTEXT_PRIMITIVE_0, tlv_value, tlv_value_size, NULL, &obj->eim_id, &obj->eim_id_size)) != eOk) {
        LOGE("[es10_tlv_extractor__euicc_package_error_unsigned] Error extracting the eimId, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogDebug, "[es10_tlv_extractor__euicc_package_error_unsigned] eimId", obj->eim_id, obj->eim_id_size);

    // Parse eimTransactionId OPTIONAL
    if ((rc = tlv_data_extractor__transaction_id(CONTEXT_PRIMITIVE_2, tlv_value, tlv_value_size, &obj->field_is_present.eim_transaction_id, &obj->eim_transaction_id)) != eOk) {
        LOGE("[es10_tlv_extractor__euicc_package_error_unsigned] Error extracting the eimTransactionId, rc %d", rc);
        return rc;
    }
    if (obj->field_is_present.eim_transaction_id) {
        LOG_DATA(eLogDebug, "[es10_tlv_extractor__euicc_package_error_unsigned] eimTransactionId", obj->eim_transaction_id.transaction_id, obj->eim_transaction_id.transaction_id_size);
    } else {
        LOGD("[es10_tlv_extractor__euicc_package_error_unsigned] The eimTransactionId is not present");
    }

    // Parse associationToken OPTIONAL
    if ((rc = tlv_data_extractor__uint32(CONTEXT_PRIMITIVE_4, tlv_value, tlv_value_size, &obj->field_is_present.association_token, &obj->association_token)) != eOk) {
        LOGE("[es10_tlv_extractor__euicc_package_error_unsigned] Error parsing the associationToken, rc %d", rc);
        return rc;
    }
    if (obj->field_is_present.association_token) {
        LOGD("[es10_tlv_extractor__euicc_package_error_unsigned] associationToken: %u", obj->association_token);
    } else {
        LOGD("[es10_tlv_extractor__euicc_package_error_unsigned] The associationToken is not present");
    }

    return eOk;
}

static ErrCode es10_tlv_extractor__euicc_package_result_data_signed(const unsigned short tag, const uint8_t* buffer, const uint32_t buffer_size, euicc_package_result_data_signed_t* obj) {
    ErrCode rc;
    uint8_t* tlv_value;
    uint32_t tlv_value_size;

    if (!obj) {
        LOGE("[es10_tlv_extractor__euicc_package_result_data_signed] EuiccPackageResultDataSigned object is null");
        return eBadArg;
    }

    // Get EuiccPackageResultDataSigned value
    if ((rc = tlv_data_extractor__tlv_value_big_size_ref(tag, buffer, buffer_size, NULL, &tlv_value, &tlv_value_size)) != eOk) {
        LOGE("[es10_tlv_extractor__euicc_package_result_data_signed] Error extracting the EuiccPackageResultDataSigned TLV value");
        return rc;
    }

    // Parse eimId
    if ((rc = tlv_data_extractor__tlv_value_small_size_ref(CONTEXT_PRIMITIVE_0, tlv_value, tlv_value_size, NULL, &obj->eim_id, &obj->eim_id_size)) != eOk) {
        LOGE("[es10_tlv_extractor__euicc_package_result_data_signed] Error extracting the eimId, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogDebug, "[es10_tlv_extractor__euicc_package_result_data_signed] eimId", obj->eim_id, obj->eim_id_size);

    // Parse counterValue
    if ((rc = tlv_data_extractor__uint32(CONTEXT_PRIMITIVE_1, tlv_value, tlv_value_size, NULL, &obj->counter_value)) != eOk) {
        LOGE("[es10_tlv_extractor__euicc_package_result_data_signed] Error parsing the counterValue, rc %d", rc);
        return rc;
    }
    LOGD("[es10_tlv_extractor__euicc_package_result_data_signed] counterValue: %u", obj->counter_value);

    // Parse eimTransactionId OPTIONAL
    if ((rc = tlv_data_extractor__transaction_id(CONTEXT_PRIMITIVE_2, tlv_value, tlv_value_size, &obj->field_is_present.eim_transaction_id, &obj->eim_transaction_id)) != eOk) {
        LOGE("[es10_tlv_extractor__euicc_package_result_data_signed] Error extracting the eimTransactionId, rc %d", rc);
        return rc;
    }
    if (obj->field_is_present.eim_transaction_id) {
        LOG_DATA(eLogDebug, "[es10_tlv_extractor__euicc_package_result_data_signed] eimTransactionId", obj->eim_transaction_id.transaction_id, obj->eim_transaction_id.transaction_id_size);
    } else {
        LOGD("[es10_tlv_extractor__euicc_package_result_data_signed] The eimTransactionId is not present");
    }

    // Parse seqNumber
    if ((rc = tlv_data_extractor__uint32(CONTEXT_PRIMITIVE_3, tlv_value, tlv_value_size, NULL, &obj->seq_number)) != eOk) {
        LOGE("[es10_tlv_extractor__euicc_package_result_data_signed] Error parsing the seqNumber, rc %d", rc);
        return rc;
    }
    LOGD("[es10_tlv_extractor__euicc_package_result_data_signed] seqNumber: %u", obj->seq_number);

    // Parse euiccResult
    if ((rc = tlv_data_extractor__asn1_list_init(&obj->euicc_result, ASN1_DER_SEQUENCE, 0, tlv_value, tlv_value_size)) != eOk) {
        LOGE("[es10_tlv_extractor__euicc_package_result_data_signed] Error parsing the euiccResult, rc %d", rc);
        return rc;
    }

    return eOk;
}

static ErrCode es10_tlv_extractor__euicc_package_error_data_signed(const unsigned short tag, const uint8_t* buffer, const uint32_t buffer_size, euicc_package_error_data_signed_t* obj) {
    ErrCode rc;
    uint8_t* tlv_value;
    uint32_t tlv_value_size;

    if (!obj) {
        LOGE("[es10_tlv_extractor__euicc_package_error_data_signed] EuiccPackageErrorDataSigned object is null");
        return eBadArg;
    }

    // Get EuiccPackageErrorDataSigned value
    if ((rc = tlv_data_extractor__tlv_value_big_size_ref(tag, buffer, buffer_size, NULL, &tlv_value, &tlv_value_size)) != eOk) {
        LOGE("[es10_tlv_extractor__euicc_package_error_data_signed] Error extracting the EuiccPackageErrorDataSigned TLV value");
        return rc;
    }

    // Parse eimId
    if ((rc = tlv_data_extractor__tlv_value_small_size_ref(CONTEXT_PRIMITIVE_0, tlv_value, tlv_value_size, NULL, &obj->eim_id, &obj->eim_id_size)) != eOk) {
        LOGE("[es10_tlv_extractor__euicc_package_error_data_signed] Error extracting the eimId, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogDebug, "[es10_tlv_extractor__euicc_package_error_data_signed] eimId", obj->eim_id, obj->eim_id_size);

    // Parse counterValue
    if ((rc = tlv_data_extractor__uint32(CONTEXT_PRIMITIVE_1, tlv_value, tlv_value_size, NULL, &obj->counter_value)) != eOk) {
        LOGE("[es10_tlv_extractor__euicc_package_error_data_signed] Error parsing the counterValue, rc %d", rc);
        return rc;
    }
    LOGD("[es10_tlv_extractor__euicc_package_error_data_signed] counterValue: %u", obj->counter_value);

    // Parse eimTransactionId OPTIONAL
    if ((rc = tlv_data_extractor__transaction_id(CONTEXT_PRIMITIVE_2, tlv_value, tlv_value_size, &obj->field_is_present.eim_transaction_id, &obj->eim_transaction_id)) != eOk) {
        LOGE("[es10_tlv_extractor__euicc_package_error_data_signed] Error extracting the eimTransactionId, rc %d", rc);
        return rc;
    }
    if (obj->field_is_present.eim_transaction_id) {
        LOG_DATA(eLogDebug, "[es10_tlv_extractor__euicc_package_error_data_signed] eimTransactionId", obj->eim_transaction_id.transaction_id, obj->eim_transaction_id.transaction_id_size);
    } else {
        LOGD("[es10_tlv_extractor__euicc_package_error_data_signed] The eimTransactionId is not present");
    }

    // Parse euiccPackageErrorCode
    if ((rc = es10_tlv_extractor__euicc_package_error_code(ASN1_DER_INTEGER, tlv_value, tlv_value_size, &obj->euicc_package_error_code)) != eOk) {
        LOGE("[es10_tlv_extractor__euicc_package_error_data_signed] Error extracting the euiccPackageErrorCode, rc %d", rc);
        return rc;
    }

    return eOk;
}

static ErrCode es10_tlv_extractor__euicc_package_error_code(const unsigned short tag, const uint8_t* buffer, const uint32_t buffer_size, euicc_package_error_code_t* error) {
    ErrCode rc;
    uint8_t euicc_package_error_code;

    if (!error) {
        LOGE("[es10_tlv_extractor__euicc_package_error_code] EuiccPackageErrorCode enum is null");
        return eBadArg;
    }

    if ((rc = tlv_data_extractor__result_code(tag, buffer, buffer_size, NULL, &euicc_package_error_code)) != eOk) {
        LOGE("[es10_tlv_extractor__euicc_package_error_code] Error extracting the EuiccPackageErrorCode, rc %d", rc);
        return rc;
    }

    switch (euicc_package_error_code)
    {
    case EUICC_PACKAGE_ERROR_CODE_INVALID_EID:
    case EUICC_PACKAGE_ERROR_CODE_REPLAY_ERROR:
    case EUICC_PACKAGE_ERROR_CODE_COUNTER_VALUE_OUT_OF_RANGE:
    case EUICC_PACKAGE_ERROR_CODE_SIZE_OVERFLOW:
    case EUICC_PACKAGE_ERROR_CODE_ECALL_ACTIVE:
    case EUICC_PACKAGE_ERROR_CODE_UNDEFINED_ERROR:
        *error = euicc_package_error_code;
        LOGD("[es10_tlv_extractor__euicc_package_error_code] euiccPackageErrorCode=%d", *error);
        return eOk;
    default:
        LOGE("[es10_tlv_extractor__euicc_package_error_code] euiccPackageErrorCode %02X not defined", euicc_package_error_code);
        return eFatal;
    }
}

static ErrCode es10_tlv_extractor__add_initial_eim_ok(const uint8_t* tlv, const uint32_t tlv_size, add_initial_eim_ok_t* obj) {
    ErrCode rc;
    int tlv_offset;
    size_t tlv_value_offset;
    _BerTlv add_initial_eim_ok;

    if (tlv == NULL || tlv_size == 0) {
        LOGE("[es10_tlv_extractor__add_initial_eim_ok] tlv is empty/null");
        return eBadArg;
    }
    LOG_DATA(eLogDebug, "[es10_tlv_extractor__add_initial_eim_ok] addInitialEimOk", tlv, tlv_size);

    if ((tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, 0, CONTEXT_CONSTRUCTED_0)) < 0) {
        LOGE("[es10_tlv_extractor__add_initial_eim_ok] TAG of addInitialEimOk (%02X) not found", CONTEXT_CONSTRUCTED_0);
        return eFatal;
    }

    tlv_value_offset = ber_tlv_parser__get_value_offset(tlv, (size_t) tlv_offset);

    if ((rc = ber_tlv_parser__ber_tlv_2(tlv, tlv_size, tlv_value_offset, &add_initial_eim_ok)) != eOk) {
        LOGE("[es10_tlv_extractor__add_initial_eim_ok] Error parsing the addInitialEimOk TLV, rc %d", rc);
        return rc;
    }

    switch (add_initial_eim_ok.tag)
    {
    case CONTEXT_PRIMITIVE_4:
        LOGD("[es10_tlv_extractor__add_initial_eim_ok] The addInitialEimOk is an associationToken");
        obj->choice = ASSOCATION_TOKEN_CHOICE;
        return tlv_data_extractor__uint32(CONTEXT_PRIMITIVE_4, tlv + tlv_value_offset, tlv_size - (uint32_t) tlv_value_offset, NULL, &obj->value.assocation_token);
    case ASN1_DER_NULL:
        LOGD("[es10_tlv_extractor__add_initial_eim_ok] The addInitialEimOk is an addOk");
        obj->choice = ADD_OK_CHOICE;
        return eOk;
    default:
        LOGE("[es10_tlv_extractor__add_initial_eim_ok] Unknown TAG %04X of addInitialEimOk CHOICE", add_initial_eim_ok.tag);
        return eFatal;
    }
}

static ErrCode es10_tlv_extractor__add_initial_eim_error(const uint8_t* tlv, const uint32_t tlv_size, add_initial_eim_error_t* e) {
    ErrCode rc;
    uint8_t result;

    if ((rc = tlv_data_extractor__result_code(CONTEXT_PRIMITIVE_1, tlv, tlv_size, NULL, &result)) != eOk) {
        LOGE("[es10_tlv_extractor__add_initial_eim_error] Error extracting the addInitialEimError, rc %d", rc);
        return rc;
    }

    if (result != ADD_INITIAL_EIM_ERROR_INSUFFICIENT_MEMORY &&
        result != ADD_INITIAL_EIM_ERROR_ASSOCIATED_EIM_ALREADY_EXISTS &&
        result != ADD_INITIAL_EIM_ERROR_CI_PK_UNKNOWN &&
        result != ADD_INITIAL_EIM_ERROR_INVALID_ASSOCIATION_TOKEN &&
        result != ADD_INITIAL_EIM_ERROR_COUNTER_VALUE_OUT_OF_RANGE &&
        result != ADD_INITIAL_EIM_ERROR_COMMAND_ERROR &&
        result != ADD_INITIAL_EIM_ERROR_UNDEFINED_ERROR) {
        LOGE("[es10_tlv_extractor__add_initial_eim_error] Error %02X not defined in the addInitialEimError", result);
        return eFatal;
    }

    *e = result;

    return eOk;
}

static ErrCode es10_tlv_extractor__certs(const unsigned tag, const uint8_t* tlv, const uint32_t tlv_size, certs_t* certs) {
    ErrCode rc;
    uint8_t* certs_value;
    uint32_t certs_value_size;

    // Get the certs value
    if ((rc = tlv_data_extractor__tlv_value_big_size_ref(tag, tlv, tlv_size, NULL, &certs_value, &certs_value_size)) != eOk) {
        LOGE("[es10_tlv_extractor__certs] Error on extract the certs value, rc %d", rc);
        return rc;
    }

    // Get the eumCertificate
    if ((rc = tlv_data_extractor__tlv_medium_size_ref(EUM_CERTIFICATE, certs_value, certs_value_size, NULL, &certs->eum_certificate, &certs->eum_certificate_size)) != eOk) {
        LOGE("[es10_tlv_extractor__certs] Error on extract the eumCertificate, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogDebug, "[es10_tlv_extractor__certs] eumCertificate", certs->eum_certificate, certs->eum_certificate_size);

    // Get the euiccCertificate
    if ((rc = tlv_data_extractor__tlv_medium_size_ref(EUICC_CERTIFICATE, certs_value, certs_value_size, NULL, &certs->euicc_certificate, &certs->euicc_certificate_size)) != eOk) {
        LOGE("[es10_tlv_extractor__certs] Error on extract the euiccCertificate, rc %d", rc);
        return rc;
    }
    LOG_DATA(eLogDebug, "[es10_tlv_extractor__certs] euiccCertificate", certs->euicc_certificate, certs->euicc_certificate_size);

    return eOk;
}

static ErrCode es10_tlv_extractor__get_certs_error(const unsigned tag, const uint8_t* tlv, const uint32_t tlv_size, get_certs_error_t* e) {
    ErrCode rc;
    uint8_t result;

    if ((rc = tlv_data_extractor__result_code(tag, tlv, tlv_size, NULL, &result)) != eOk) {
        LOGE("[es10_tlv_extractor__get_certs_error] Error extracting the addInitialEimError, rc %d", rc);
        return rc;
    }

    switch (result)
    {
    case GET_CERTS_ERROR_INVALID_CI_PK_ID:
    case GET_CERTS_ERROR_UNDEFINED_ERROR:
        *e = result;
        LOGD("[es10_tlv_extractor__get_certs_error] getCertsError(%d)", *e);
        break;
    default:
        LOGE("[es10_tlv_extractor__get_certs_error] Error %02X not defined in the getCertsError", result);
        return eFatal;
    }

    return eOk;
}


static ErrCode es10_tlv_extractor__profile_rollback_result(const unsigned tag, const uint8_t* tlv, const uint32_t tlv_size, profile_rollback_result_t* res) {
    ErrCode rc = eFatal;
    uint8_t result = 127;

    if ((rc = tlv_data_extractor__result_code(tag, tlv, tlv_size, NULL, &result)) != eOk) {
        LOGE("[es10_tlv_extractor__profile_rollback_result] Error extracting the cmdResult, rc %d", rc);
        return rc;
    }

    switch (result)
    {
    case PROFILE_ROLLBACK_RESULT_OK:
    case PROFILE_ROLLBACK_RESULT_ROLLBACK_NOT_ALLOWED:
    case PROFILE_ROLLBACK_RESULT_CAT_BUSY:
    case PROFILE_ROLLBACK_RESULT_COMMAND_ERROR:
    case PROFILE_ROLLBACK_RESULT_UNDEFINED_ERROR:
        *res = result;
        LOGD("[es10_tlv_extractor__profile_rollback_result] cmdResult(%d)", *res);
        return eOk;
    default:
        LOGE("[es10_tlv_extractor__profile_rollback_result] Result %02X not defined in the cmdResult", result);
        return eFatal;
    }
}

 ErrCode es10_tlv_extractor__eim_configuration_data(const uint8_t* tlv, const uint32_t tlv_size, eim_configuration_data_t* obj) {
    ErrCode rc;
    uint8_t* tlv_value;
    uint32_t tlv_value_size;
    unsigned short tag;
    uint8_t tag_size;
    uint8_t result;
    int tlv_offset;

    if (!tlv || tlv_size == 0) {
        LOGE("[es10_tlv_extractor__eim_configuration_data] tlv is empty/null");
        return eBadArg;
    }
    LOG_DATA(eLogTrace, "[es10_tlv_extractor__eim_configuration_data] EimConfigurationData", tlv, tlv_size);

    // Search the EimConfigurationData TLV
    if ((rc = tlv_data_extractor__tlv_value_big_size_ref(ASN1_DER_SEQUENCE, tlv, tlv_size, NULL, &tlv_value, &tlv_value_size)) != eOk) {
        LOGE("[es10_tlv_extractor__eim_configuration_data] Error extracting the EimConfigurationData value, rc %d", rc);
        return rc;
    }

    // eimId
    if ((rc = tlv_data_extractor__tlv_value_big_size_ref(EIM_CONF_EIM_ID, tlv_value, tlv_value_size, NULL, (uint8_t**) &obj->eim_id, &obj->eim_id_len)) != eOk) {
        LOGE("[es10_tlv_extractor__eim_configuration_data] Error parsing the eimId, rc %d", rc);
        return rc;
    }
    LOG_UTF8_DATA(eLogDebug, "[es10_tlv_extractor__eim_configuration_data] eimId: ", obj->eim_id, obj->eim_id_len);

    // eimFqdn OPTIONAL
    if ((rc = tlv_data_extractor__tlv_value_big_size_ref(EIM_CONF_EIM_FQDN, tlv_value, tlv_value_size, &obj->field_is_present.eim_fqdn, &obj->eim_fqdn, &obj->eim_fqdn_len)) != eOk) {
        LOGE("[es10_tlv_extractor__eim_configuration_data] Error parsing the eimFqdn, rc %d", rc);
        return rc;
    }
    if (obj->field_is_present.eim_fqdn) {
        LOG_UTF8_DATA(eLogDebug, "[es10_tlv_extractor__eim_configuration_data] eimFqdn: ", obj->eim_fqdn, obj->eim_fqdn_len);
    } else {
        LOGD("[es10_tlv_extractor__eim_configuration_data] eimFqdn is not present");
    }

    // eimIdType OPTIONAL
    if ((rc = tlv_data_extractor__result_code(EIM_CONF_EIM_ID_TYPE, tlv_value, tlv_value_size, &obj->field_is_present.eim_id_type, &result)) != eOk) {
        LOGE("[es10_tlv_extractor__eim_configuration_data] Error parsing the eimIdType, rc %d", rc);
        return rc;
    }
    if (obj->field_is_present.eim_id_type) {
        if (result != EIM_ID_TYPE_OID && result != EIM_ID_TYPE_FQDN && result != EIM_ID_TYPE_PROPIETARY) {
            LOGE("[es10_tlv_extractor__notification_sent_response] eimIdType %u not defined in the EimIdType", result);
            return eFatal;
        }
        LOGD("[es10_tlv_extractor__eim_configuration_data] eimIdType: %u", result);
        obj->eim_id_type = result;
    } else {
        LOGD("[es10_tlv_extractor__eim_configuration_data] eimIdType is not present");
    }

    // counterValue OPTIONAL
    if ((rc = tlv_data_extractor__uint32(EIM_CONF_COUNTER_VALUE, tlv_value, tlv_value_size, &obj->field_is_present.counter_value, &obj->counter_value)) != eOk) {
        LOGE("[es10_tlv_extractor__eim_configuration_data] Error parsing the counterValue, rc %d", rc);
        return rc;
    }
    if (obj->field_is_present.counter_value) {
        LOGD("[es10_tlv_extractor__eim_configuration_data] counterValue: %u", obj->counter_value);
    } else {
        LOGD("[es10_tlv_extractor__eim_configuration_data] counterValue is not present");
    }

    // associationToken OPTIONAL
    if ((rc = tlv_data_extractor__uint32(EIM_CONF_ASSOCIATION_TOKEN, tlv_value, tlv_value_size, &obj->field_is_present.association_token, &obj->association_token)) != eOk) {
        LOGE("[es10_tlv_extractor__eim_configuration_data] Error parsing the associationToken, rc %d", rc);
        return rc;
    }
    if (obj->field_is_present.association_token) {
        LOGD("[es10_tlv_extractor__eim_configuration_data] associationToken: %u", obj->association_token);
    } else {
        LOGD("[es10_tlv_extractor__eim_configuration_data] associationToken is not present");
    }

    // eimPublicKeyData OPTIONAL
    if ((rc = tlv_data_extractor__tlv_value_big_size_ref(EIM_CONF_EIM_PUBLIC_KEY_DATA, tlv_value, tlv_value_size, &obj->field_is_present.eim_public_key_data, &obj->eim_public_key_data.value, &obj->eim_public_key_data.value_size)) != eOk) {
        LOGE("[es10_tlv_extractor__eim_configuration_data] Error extracting the eimPublicKeyData value, rc %d", rc);
        return rc;
    }
    if (obj->field_is_present.eim_public_key_data) {
        if ((rc = ber_tlv_parser__get_tag_data(obj->eim_public_key_data.value, obj->eim_public_key_data.value_size, 0, &tag, &tag_size)) != eOk) {
            LOGE("[es10_tlv_extractor__eim_configuration_data] Error extracting the eimPublicKeyData CHOICE tag, rc %d", rc);
            return rc;
        }
        switch (tag) {
            case EIM_CONF_EIM_PUBLIC_KEY:
                obj->eim_public_key_data.choice = EIM_PUBLIC_KEY_CHOICE;
                break;
            case EIM_CONF_EIM_CERTIFICATE:
                obj->eim_public_key_data.choice = EIM_CERTIFICATE_CHOICE;
                break;
            default:
                LOGE("[es10_tlv_extractor__eim_configuration_data] Unknown eimPublicKeyData CHOICE tag %02X", tag);
                return eFatal;
        }
    } else {
        LOGD("[es10_tlv_extractor__eim_configuration_data] eimPublicKeyData is not present");
    }

    // trustedPublicKeyDataTls OPTIONAL
    if ((rc = tlv_data_extractor__tlv_value_big_size_ref(EIM_CONF_TRUSTED_PUBLIC_KEY_DATA_TLS, tlv_value, tlv_value_size, &obj->field_is_present.trusted_public_key_data_tls, &obj->trusted_public_key_data_tls.value, &obj->trusted_public_key_data_tls.value_size)) != eOk) {
        LOGE("[es10_tlv_extractor__eim_configuration_data] Error extracting the trustedPublicKeyDataTls value, rc %d", rc);
        return rc;
    }
    if (obj->field_is_present.trusted_public_key_data_tls) {
        if ((rc = ber_tlv_parser__get_tag_data(obj->trusted_public_key_data_tls.value, obj->trusted_public_key_data_tls.value_size, 0, &tag, &tag_size)) != eOk) {
            LOGE("[es10_tlv_extractor__eim_configuration_data] Error extracting the trustedPublicKeyDataTls CHOICE tag, rc %d", rc);
            return rc;
        }
        switch (tag) {
            case EIM_CONF_TRUSTED_EIM_PK_TLS:
                obj->trusted_public_key_data_tls.choice = TRUSTED_EIM_PK_TLS_CHOICE;
                break;
            case EIM_CONF_TRUSTED_CERTIFICATE_TLS:
                obj->trusted_public_key_data_tls.choice = TRUSTED_CERTIFICATE_TLS_CHOICE;
                break;
            default:
                LOGE("[es10_tlv_extractor__eim_configuration_data] Unknown trustedPublicKeyDataTls CHOICE tag %02X", tag);
                return eFatal;
        }
    } else {
        LOGD("[es10_tlv_extractor__eim_configuration_data] trustedPublicKeyDataTls is not present");
    }

    // eimSupportedProtocol OPTIONAL
    if ((tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv_value, tlv_value_size, 0, EIM_CONF_EIM_SUPPORTED_PROTOCOL)) >= 0) {
        if ((rc = es10_tlv_extractor__eim_supported_protocol(tlv_value + tlv_offset, tlv_value_size - tlv_offset, &obj->eim_supported_protocol)) == eOk) {
            LOGD("[es10_tlv_extractor__eim_configuration_data] eimSupportedProtocol(eimRetrieveHttps=%u, eimRetrieveCoaps=%u, eimInjectHttps=%u, eimInjectCoaps=%u, eimProprietary=%u)",
            obj->eim_supported_protocol.eim_retrieve_https, obj->eim_supported_protocol.eim_retrieve_coaps, obj->eim_supported_protocol.eim_inject_https, obj->eim_supported_protocol.eim_inject_coaps, obj->eim_supported_protocol.eim_proprietary);
            obj->field_is_present.eim_supported_protocol = true;
        } else {
            LOGE("[es10_tlv_extractor__eim_configuration_data] Error extracting the eimSupportedProtocol, rc %d", rc);
            return rc;
        }
    } else {
        LOGD("[es10_tlv_extractor__eim_configuration_data] eimSupportedProtocol is not present");
        obj->field_is_present.eim_supported_protocol = false;
    }

    // euiccCiPKId OPTIONAL
    if ((rc = tlv_data_extractor__subject_key_identifier(EIM_CONF_EUICC_CI_PK_ID, tlv_value, tlv_value_size, &obj->field_is_present.euicc_ci_pk_id, &obj->euicc_ci_pk_id)) != eOk) {
        LOGE("[es10_tlv_extractor__eim_configuration_data] Error parsing the euiccCiPKId, rc %d", rc);
        return rc;
    }
    if (obj->field_is_present.euicc_ci_pk_id){
        LOG_DATA(eLogDebug, "[es10_tlv_extractor__eim_configuration_data] euiccCiPKId", obj->euicc_ci_pk_id.value, sizeof(obj->euicc_ci_pk_id.value));
    } else {
        LOGD("[es10_tlv_extractor__eim_configuration_data] euiccCiPKId is not present");
    }

    // indirecteProfileDownload OPTIONAL
    if ((tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv_value, tlv_value_size, 0, EIM_CONF_INDIRECT_PROFILE_DOWNLOAD)) >= 0) {
        LOGD("[es10_tlv_extractor__eim_configuration_data] indirectProfileDownload is present");
        obj->field_is_present.indirect_profile_download = true;
    } else {
        LOGD("[es10_tlv_extractor__eim_configuration_data] indirectProfileDownload is not present");
        obj->field_is_present.indirect_profile_download = false;
    }

    return eOk;
}

static ErrCode es10_tlv_extractor__eim_supported_protocol(const uint8_t* tlv, const uint32_t tlv_size, eim_supported_protocol_t* obj) {
    ErrCode rc;
    uint8_t eim_supported_protocol_plain[] = { 0, 0, 0, 0, 0 };

    if ((rc = tlv_data_extractor__bit_string(EIM_CONF_EIM_SUPPORTED_PROTOCOL, tlv, tlv_size, eim_supported_protocol_plain, sizeof(eim_supported_protocol_plain))) != eOk) {
        LOGE("[es10_tlv_extractor__eim_supported_protocol] Error extracting the eimSupportedProtocol BIT STRING, rc %d", rc);
        return rc;
    }

    obj->eim_retrieve_https = (bool) eim_supported_protocol_plain[0];
    obj->eim_retrieve_coaps = (bool) eim_supported_protocol_plain[1];
    obj->eim_inject_https = (bool) eim_supported_protocol_plain[2];
    obj->eim_inject_coaps = (bool) eim_supported_protocol_plain[3];
    obj->eim_proprietary = (bool) eim_supported_protocol_plain[4];

    return eOk;
}
#endif
