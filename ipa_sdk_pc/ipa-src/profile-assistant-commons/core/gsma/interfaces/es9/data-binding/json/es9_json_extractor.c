/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include "es9_json_extractor.h"

#include "json_data_extractor.h"
#include "gsma_json_extractor.h"
#include "tlv_data_extractor.h"
#include "tlv_tags.h"
#include "base64.h"
#include "log.h"

#define SERVER_SIGNED_1_JSON_KEY            "serverSigned1"
#define SERVER_SIGNATURE_1_JSON_KEY         "serverSignature1"
#define EUICC_CI_PK_ID_TO_BE_USED_JSON_KEY  "euiccCiPKIdToBeUsed"
#define SERVER_CERTIFICATE_JSON_KEY         "serverCertificate"
#define PROFILE_METADATA_JSON_KEY           "profileMetadata"
#define SMDP_SIGNED_2_JSON_KEY              "smdpSigned2"
#define SMDP_SIGNATURE_2_JSON_KEY           "smdpSignature2"
#define SMDP_CERTIFICATE_JSON_KEY           "smdpCertificate"
#define BOUND_PROFILE_PACKAGE_JSON_KEY      "boundProfilePackage"

static ErrCode es9_json_extractor__initiate_authentication_ok(unsigned char* json, uint32_t json_len, initiate_authentication_ok_es9_t* obj, unsigned char** euicc_ci_pK_id_to_be_used, uint32_t* euicc_ci_pK_id_to_be_used_size);
static ErrCode es9_json_extractor__initiate_authentication_error(const gsma_json_response_header_t* header, initiate_authentication_error_t* obj);
static ErrCode es9_json_extractor__authenticate_client_ok(unsigned char* json, uint32_t json_len, authenticate_client_ok_t* obj);
static ErrCode es9_json_extractor__authenticate_client_error(const gsma_json_response_header_t* header, authenticate_client_error_t* obj);
static ErrCode es9_json_extractor__get_bound_profile_package_ok(unsigned char* json, uint32_t json_len, get_bound_profile_package_ok_t* obj);
static ErrCode es9_json_extractor__get_bound_profile_package_error(const gsma_json_response_header_t* header, get_bound_profile_package_error_t* obj);
static ErrCode es9_json_extractor__cancel_session_error(const gsma_json_response_header_t* header, cancel_session_error_t* obj);

ErrCode es9_json_extractor__initiate_authentication_response(unsigned char* json, uint32_t json_len, initiate_authentication_response_t* obj) {
    ErrCode rc;
    int32_t base64_written_bytes;
    gsma_json_response_header_t header;
    unsigned char* euicc_ci_pK_id_to_be_used;
    uint32_t euicc_ci_pK_id_to_be_used_size;

    /* Check input parameters */
    if (!json) {
        LOGE("[es9_json_extractor__initiate_authentication_response] JSON response is null");
        return eBadArg;
    }
    LOG_UTF8_DATA(eLogTrace, "[es9_json_extractor__initiate_authentication_response] ", json, json_len);

    /* Extract the JSON responseHeader */
    if ((rc = gsma_json_extractor__header(json, json_len, &header)) != eOk) {
        LOGE("[es9_json_extractor__initiate_authentication_response] Error extracting data from the JSON responseHeader, rc %d", rc);
        return rc;
    }

    /* Extract the JSON body */
    if (JSON_RESPONSE_STATUS_EXECUTED_SUCCESS == header.function_execution_status.status) {
        obj->choice = INITIATE_AUTHENTICATION_OK_CHOICE;
        if ((rc = es9_json_extractor__initiate_authentication_ok(json, json_len, &obj->value.ok, &euicc_ci_pK_id_to_be_used, &euicc_ci_pK_id_to_be_used_size)) != eOk) {
            LOGE("[es9_json_extractor__initiate_authentication_response] Error extracting the InitiateAuthenticationOkEs9 JSON body");
            return rc;
        }

        /* Parse the base64 in place, overwriting the json string buffer */
        // serverSigned1
        if ((base64_written_bytes = base64__decode((unsigned char*) obj->value.ok.server_signed_1, obj->value.ok.server_signed_1_size, (unsigned char*) obj->value.ok.server_signed_1, obj->value.ok.server_signed_1_size)) < 0) {
            LOGE("[es9_json_extractor__initiate_authentication_response] Error parsing the base64 serverSigned1, err %d", base64_written_bytes);
            return eFatal;
        }
        obj->value.ok.server_signed_1_size = (uint32_t) base64_written_bytes;
        LOG_DATA(eLogTrace, "[es9_json_extractor__initiate_authentication_response] serverSigned1", obj->value.ok.server_signed_1, obj->value.ok.server_signed_1_size);
        
        // serverSignature1
        if ((base64_written_bytes = base64__decode((unsigned char*) obj->value.ok.server_signature_1, obj->value.ok.server_signature_1_size, (unsigned char*) obj->value.ok.server_signature_1, obj->value.ok.server_signature_1_size)) < 0) {
            LOGE("[es9_json_extractor__initiate_authentication_response] Error parsing the base64 serverSignature1, err %d", base64_written_bytes);
            return eFatal;
        }
        obj->value.ok.server_signature_1_size = (uint32_t) base64_written_bytes;
        LOG_DATA(eLogTrace, "[es9_json_extractor__initiate_authentication_response] serverSignature1", obj->value.ok.server_signature_1, obj->value.ok.server_signature_1_size);
        
        // euiccCiPKIdToBeUsed
        if ((base64_written_bytes = base64__decode(euicc_ci_pK_id_to_be_used, euicc_ci_pK_id_to_be_used_size, euicc_ci_pK_id_to_be_used, euicc_ci_pK_id_to_be_used_size)) < 0) {
            LOGE("[es9_json_extractor__initiate_authentication_response] Error parsing the base64 euiccCiPKIdToBeUsed, err %d", base64_written_bytes);
            return eFatal;
        }
        euicc_ci_pK_id_to_be_used_size = (uint32_t) base64_written_bytes;
        LOG_DATA(eLogTrace, "[es9_json_extractor__initiate_authentication_response] euiccCiPKIdToBeUsed", euicc_ci_pK_id_to_be_used, euicc_ci_pK_id_to_be_used_size);
        
        // serverCertificate
        if ((base64_written_bytes = base64__decode((unsigned char*) obj->value.ok.server_certificate, obj->value.ok.server_certificate_size, (unsigned char*) obj->value.ok.server_certificate, obj->value.ok.server_certificate_size)) < 0) {
            LOGE("[es9_json_extractor__initiate_authentication_response] Error parsing the base64 serverCertificate, err %d", base64_written_bytes);
            return eFatal;
        }
        obj->value.ok.server_certificate_size = (uint32_t) base64_written_bytes;
        LOG_DATA(eLogTrace, "[es9_json_extractor__initiate_authentication_response] serverCertificate", obj->value.ok.server_certificate, obj->value.ok.server_certificate_size);
        
        /* Parse the euiccCiPKIdToBeUsed to a SubjectKeyIdentifier datatype */
        if ((rc = tlv_data_extractor__subject_key_identifier(ASN1_DER_OCTET_STRING, (uint8_t*) euicc_ci_pK_id_to_be_used, euicc_ci_pK_id_to_be_used_size, NULL, &obj->value.ok.euicc_ci_pk_id_to_be_used)) != eOk) {
            LOGE("[es9_json_extractor__initiate_authentication_response] Error parsing the euiccCiPKIdToBeUsed to a SubjectKeyIdentifier, rc %d", rc);
            return rc;
        }
        LOG_DATA(eLogTrace, "[es9_json_extractor__initiate_authentication_response] euiccCiPKIdToBeUsed SubjectKeyIdentifier", obj->value.ok.euicc_ci_pk_id_to_be_used.value, sizeof(obj->value.ok.euicc_ci_pk_id_to_be_used.value));

        return eOk;
    } else if (JSON_RESPONSE_STATUS_EXECUTED_FAILED == header.function_execution_status.status) {
        obj->choice = INITIATE_AUTHENTICATION_ERROR_CHOICE;
        return es9_json_extractor__initiate_authentication_error(&header, &obj->value.error);
    } else {
        LOGE("[es9_json_extractor__initiate_authentication_response] Status different than success or failed. Status: %d", header.function_execution_status.status);
        return eFatal;
    }
}

ErrCode es9_json_extractor__authenticate_client_response(unsigned char* json, uint32_t json_len, authenticate_client_response_es9_t* obj) {
    ErrCode rc;
    int32_t base64_written_bytes;
    gsma_json_response_header_t header;

    /* Check input parameters */
    if (!json) {
        LOGE("[es9_json_extractor__authenticate_client_response] JSON response is null");
        return eBadArg;
    }
    LOG_UTF8_DATA(eLogTrace, "[es9_json_extractor__authenticate_client_response] ", json, json_len);

    /* Extract the JSON responseHeader */
    if ((rc = gsma_json_extractor__header(json, json_len, &header)) != eOk) {
        LOGE("[es9_json_extractor__authenticate_client_response] Error extracting data from the JSON responseHeader, rc %d", rc);
        return rc;
    }

    /* Extract the JSON body */
    if (JSON_RESPONSE_STATUS_EXECUTED_SUCCESS == header.function_execution_status.status) {
        obj->choice = AUTHENTICATE_CLIENT_OK_CHOICE;
        if ((rc = es9_json_extractor__authenticate_client_ok(json, json_len, &obj->value.ok)) != eOk) {
            LOGE("[es9_json_extractor__authenticate_client_response] Error extracting the AuthenticateClientOk JSON body");
            return rc;
        }
        
        /* Parse the base64 in place, overwriting the json string buffer */
        // profileMetadata
        if ((base64_written_bytes = base64__decode((unsigned char*) obj->value.ok.profile_metadata, obj->value.ok.profile_metadata_size, (unsigned char*) obj->value.ok.profile_metadata, obj->value.ok.profile_metadata_size)) < 0) {
            LOGE("[es9_json_extractor__authenticate_client_response] Error parsing the base64 profileMetadata, err %d", base64_written_bytes);
            return eFatal;
        }
        obj->value.ok.profile_metadata_size = (uint32_t) base64_written_bytes;
        LOG_DATA(eLogTrace, "[es9_json_extractor__authenticate_client_response] profileMetadata", obj->value.ok.profile_metadata, obj->value.ok.profile_metadata_size);
        
        // smdpSigned2
        if ((base64_written_bytes = base64__decode((unsigned char*) obj->value.ok.smdp_signed_2, obj->value.ok.smdp_signed_2_size, (unsigned char*) obj->value.ok.smdp_signed_2, obj->value.ok.smdp_signed_2_size)) < 0) {
            LOGE("[es9_json_extractor__authenticate_client_response] Error parsing the base64 smdpSigned2, err %d", base64_written_bytes);
            return eFatal;
        }
        obj->value.ok.smdp_signed_2_size = (uint32_t) base64_written_bytes;
        LOG_DATA(eLogTrace, "[es9_json_extractor__authenticate_client_response] smdpSigned2", obj->value.ok.smdp_signed_2, obj->value.ok.smdp_signed_2_size);
        
        // smdpSignature2
        if ((base64_written_bytes = base64__decode((unsigned char*) obj->value.ok.smdp_signature_2, obj->value.ok.smdp_signature_2_size, (unsigned char*) obj->value.ok.smdp_signature_2, obj->value.ok.smdp_signature_2_size)) < 0) {
            LOGE("[es9_json_extractor__authenticate_client_response] Error parsing the base64 smdpSignature2, err %d", base64_written_bytes);
            return eFatal;
        }
        obj->value.ok.smdp_signature_2_size = (uint32_t) base64_written_bytes;
        LOG_DATA(eLogTrace, "[es9_json_extractor__authenticate_client_response] smdpSignature2", obj->value.ok.smdp_signature_2, obj->value.ok.smdp_signature_2_size);
        
        // smdpCertificate
        if ((base64_written_bytes = base64__decode((unsigned char*) obj->value.ok.smdp_certificate, obj->value.ok.smdp_certificate_size, (unsigned char*) obj->value.ok.smdp_certificate, obj->value.ok.smdp_certificate_size)) < 0) {
            LOGE("[es9_json_extractor__authenticate_client_response] Error parsing the base64 smdpCertificate, err %d", base64_written_bytes);
            return eFatal;
        }
        obj->value.ok.smdp_certificate_size = (uint32_t) base64_written_bytes;
        LOG_DATA(eLogTrace, "[es9_json_extractor__authenticate_client_response] smdpCertificate", obj->value.ok.smdp_certificate, obj->value.ok.smdp_certificate_size);
        
        return eOk;
    } else if (JSON_RESPONSE_STATUS_EXECUTED_FAILED == header.function_execution_status.status) {
        obj->choice = AUTHENTICATE_CLIENT_ERROR_CHOICE;
        return es9_json_extractor__authenticate_client_error(&header, &obj->value.error);
    } else {
        LOGE("[es9_json_extractor__authenticate_client_response] Status different than success or failed. Status: %d", header.function_execution_status.status);
        return eFatal;
    }
}

ErrCode es9_json_extractor__get_bound_profile_package_response(unsigned char* json, uint32_t json_len, get_bound_profile_package_response_t* obj) {
    ErrCode rc;
    int32_t base64_written_bytes;
    gsma_json_response_header_t header;

    /* Check input parameters */
    if (!json) {
        LOGE("[es9_json_extractor__get_bound_profile_package_response] JSON response is null");
        return eBadArg;
    }
    LOG_UTF8_DATA(eLogTrace, "[es9_json_extractor__get_bound_profile_package_response] ", json, json_len);

    /* Extract the JSON responseHeader */
    if ((rc = gsma_json_extractor__header(json, json_len, &header)) != eOk) {
        LOGE("[es9_json_extractor__get_bound_profile_package_response] Error extracting data from the JSON responseHeader, rc %d", rc);
        return rc;
    }

    /* Extract the JSON body */
    if (JSON_RESPONSE_STATUS_EXECUTED_SUCCESS == header.function_execution_status.status) {
        obj->choice = GET_BOUND_PROFILE_PACKAGE_OK;
        if ((rc = es9_json_extractor__get_bound_profile_package_ok(json, json_len, &obj->value.ok)) != eOk) {
            LOGE("[es9_json_extractor__get_bound_profile_package_response] Error extracting the GetBoundProfilePackageOk JSON body");
            return rc;
        }

        /* Parse the base64 in place, overwriting the json string buffer */
        // boundProfilePackage
        if ((base64_written_bytes = base64__decode((unsigned char*) obj->value.ok.bound_profile_package, obj->value.ok.bound_profile_package_size, (unsigned char*) obj->value.ok.bound_profile_package, obj->value.ok.bound_profile_package_size)) < 0) {
            LOGE("[es9_json_extractor__get_bound_profile_package_response] Error parsing the base64 boundProfilePackage, err %d", base64_written_bytes);
            return eFatal;
        }
        obj->value.ok.bound_profile_package_size = (uint32_t) base64_written_bytes;
        LOG_DATA(eLogTrace, "[es9_json_extractor__get_bound_profile_package_response] boundProfilePackage", obj->value.ok.bound_profile_package, obj->value.ok.bound_profile_package_size);
        
        return eOk;
    } else if (JSON_RESPONSE_STATUS_EXECUTED_FAILED == header.function_execution_status.status) {
        obj->choice = GET_BOUND_PROFILE_PACKAGE_ERROR;
        return es9_json_extractor__get_bound_profile_package_error(&header, &obj->value.error);
    } else {
        LOGE("[es9_json_extractor__get_bound_profile_package_response] Status different than success or failed. Status: %d", header.function_execution_status.status);
        return eFatal;
    }
}

ErrCode es9_json_extractor__cancel_session_response(unsigned char* json, uint32_t json_len, cancel_session_response_es9_t* obj) {
    ErrCode rc;
    gsma_json_response_header_t header;

    /* Check input parameters */
    if (!json) {
        LOGE("[es9_json_extractor__cancel_session_response] JSON response is null");
        return eBadArg;
    }
    LOG_UTF8_DATA(eLogTrace, "[es9_json_extractor__cancel_session_response] ", json, json_len);

    /* Extract the JSON responseHeader */
    if ((rc = gsma_json_extractor__header(json, json_len, &header)) != eOk) {
        LOGE("[es9_json_extractor__cancel_session_response] Error extracting data from the JSON responseHeader, rc %d", rc);
        return rc;
    }

    /* Extract the JSON body */
    if (JSON_RESPONSE_STATUS_EXECUTED_SUCCESS == header.function_execution_status.status) {
        obj->choice = CANCEL_SESSION_OK;
        return eOk;
    }  else if (JSON_RESPONSE_STATUS_EXECUTED_FAILED == header.function_execution_status.status) {
        obj->choice = CANCEL_SESSION_ERROR;
        return es9_json_extractor__cancel_session_error(&header, &obj->error);
    } else {
        LOGE("[es9_json_extractor__cancel_session_response] Status different than success or failed. Status: %d", header.function_execution_status.status);
        return eFatal;
    }
}

static ErrCode es9_json_extractor__initiate_authentication_ok(unsigned char* json, uint32_t json_len, initiate_authentication_ok_es9_t* obj, unsigned char** euicc_ci_pK_id_to_be_used, uint32_t* euicc_ci_pK_id_to_be_used_size) {
    ErrCode rc;

    // transactionId
    if ((rc = gsma_json_extractor__transaction_id(json, json_len, &obj->transaction_id)) != eOk) {
        LOGE("[es9_json_extractor__initiate_authentication_ok] Can not get the value of the transactionId, rc %d", rc);
        return rc;
    }

    // serverSigned1
    if ((rc = json_data_extractor__get_string_value(json, json_len, SERVER_SIGNED_1_JSON_KEY, (unsigned char**) &obj->server_signed_1, &obj->server_signed_1_size)) != eOk) {
        LOGE("[es9_json_extractor__initiate_authentication_ok] Can not get the value of %s, rc %d", SERVER_SIGNED_1_JSON_KEY, rc);
        return rc;
    }
    LOG_UTF8_DATA(eLogTrace, "[es9_json_extractor__initiate_authentication_ok] serverSigned1: ", obj->server_signed_1, obj->server_signed_1_size);
    
    // serverSignature1
    if ((rc = json_data_extractor__get_string_value(json, json_len, SERVER_SIGNATURE_1_JSON_KEY, (unsigned char**) &obj->server_signature_1, &obj->server_signature_1_size)) != eOk) {
        LOGE("[es9_json_extractor__initiate_authentication_ok] Can not get the value of %s, rc %d", SERVER_SIGNATURE_1_JSON_KEY, rc);
        return rc;
    }
    LOG_UTF8_DATA(eLogTrace, "[es9_json_extractor__initiate_authentication_ok] serverSignature1: ", obj->server_signature_1, obj->server_signature_1_size);
    
    // euiccCiPKIdToBeUsed
    if ((rc = json_data_extractor__get_string_value(json, json_len, EUICC_CI_PK_ID_TO_BE_USED_JSON_KEY, (unsigned char**) euicc_ci_pK_id_to_be_used, euicc_ci_pK_id_to_be_used_size)) != eOk) {
        LOGE("[es9_json_extractor__initiate_authentication_ok] Can not get the value of %s, rc %d", EUICC_CI_PK_ID_TO_BE_USED_JSON_KEY, rc);
        return rc;
    }
    LOG_UTF8_DATA(eLogTrace, "[es9_json_extractor__initiate_authentication_ok] euiccCiPKIdToBeUsed: ", *euicc_ci_pK_id_to_be_used, *euicc_ci_pK_id_to_be_used_size);
    
    // serverCertificate
    if ((rc = json_data_extractor__get_string_value(json, json_len, SERVER_CERTIFICATE_JSON_KEY, (unsigned char**) &obj->server_certificate, &obj->server_certificate_size)) != eOk) {
        LOGE("[es9_json_extractor__initiate_authentication_ok] Can not get the value of %s, rc %d", SERVER_CERTIFICATE_JSON_KEY, rc);
        return rc;
    }
    LOG_UTF8_DATA(eLogTrace, "[es9_json_extractor__initiate_authentication_ok] serverCertificate: ", obj->server_certificate, obj->server_certificate_size);

    return eOk;
}

static ErrCode es9_json_extractor__initiate_authentication_error(const gsma_json_response_header_t* header, initiate_authentication_error_t* obj) {
    if (header->function_execution_status.field_is_present.status_code_data) {
        LOG_UTF8_DATA(eLogTrace, "[es9_json_extractor__initiate_authentication_error] Subject Code: ", header->function_execution_status.status_code_data.subject_code, header->function_execution_status.status_code_data.subject_code_len);
        LOG_UTF8_DATA(eLogTrace, "[es9_json_extractor__initiate_authentication_error] Reason Code: ", header->function_execution_status.status_code_data.reason_code, header->function_execution_status.status_code_data.reason_code_len);
        // SM-DP+ Address 
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, SMDP_ADDRESS_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, REFUSED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[es9_json_extractor__initiate_authentication_error] Invalid SM-DP+ Address.");
            *obj = INITIATE_AUTHENTICATION_ERROR_ES9_INVALID_DP_ADDRESS;
        }
        // Security configuration
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, SMDP_SECURITY_CONFIG_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, UNSUPPORTED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[es9_json_extractor__initiate_authentication_error] None of the proposed Public Key Identifiers is supported by the SM-DP+.");
            *obj = INITIATE_AUTHENTICATION_ERROR_ES9_CI_PK_ID_NOT_SUPPORTED;
        }
        // Specification Version Number
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, SMDP_SVN_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, UNSUPPORTED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[es9_json_extractor__initiate_authentication_error] The Specification Version Number indicated by the eUICC is not supported by the SM-DP+.");
            *obj = INITIATE_AUTHENTICATION_ERROR_ES9_EUICC_VERSION_NOT_SUPPORTED_BY_DP;
        }
        // SM-DP+ Certificate
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, SMDP_CERTIFICATE_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, UNAVAILABLE_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[es9_json_extractor__initiate_authentication_error] The SM-DP+ has no CERT.DPAuth.ECDSA signed by one of the GSMA CI Public Key supported by the eUICC.");
            *obj = INITIATE_AUTHENTICATION_ERROR_ES9_CI_PK_ID_NOT_SUPPORTED;
        }
        
        /* To avoid code duplication in the ES11, check also the ES11 errors */
        // SM-DS Address 
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, SMDS_ADDRESS_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, REFUSED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[es9_json_extractor__initiate_authentication_error] Invalid SM-DS Address.");
            *obj = INITIATE_AUTHENTICATION_ERROR_ES9_INVALID_DP_ADDRESS;
        }
        // Security configuration
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, SMDS_SECURITY_CONFIG_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, UNSUPPORTED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[es9_json_extractor__initiate_authentication_error] None of the proposed Public Key Identifiers is supported by the SM-DS.");
            *obj = INITIATE_AUTHENTICATION_ERROR_ES9_CI_PK_ID_NOT_SUPPORTED;
        }
        // Specification Version Number
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, SMDS_SVN_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, UNSUPPORTED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[es9_json_extractor__initiate_authentication_error] The Specification Version Number indicated by the eUICC is not supported by the SM-DS.");
            *obj = INITIATE_AUTHENTICATION_ERROR_ES9_EUICC_VERSION_NOT_SUPPORTED_BY_DP;
        }
        // SM-DP+ Certificate
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, SMDS_CERTIFICATE_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, UNAVAILABLE_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[es9_json_extractor__initiate_authentication_error] The SM-DS has no CERT.DS.ECDSA signed by one of the GSMA CI Public Key supported by the eUICC.");
            *obj = INITIATE_AUTHENTICATION_ERROR_ES9_CI_PK_ID_NOT_SUPPORTED;
        }
    }
    LOGT("[es9_json_extractor__initiate_authentication_error] initiateAuthenticationError: %d", *obj);

    return eOk;
}

static ErrCode es9_json_extractor__authenticate_client_ok(unsigned char* json, uint32_t json_len, authenticate_client_ok_t* obj) {
    ErrCode rc;

    // transactionId
    if ((rc = gsma_json_extractor__transaction_id(json, json_len, &obj->transaction_id)) != eOk) {
        LOGE("[es9_json_extractor__authenticate_client_ok] Can not get the value of the transactionId, rc %d", rc);
        return rc;
    }

    // profileMetadata
    if ((rc = json_data_extractor__get_string_value(json, json_len, PROFILE_METADATA_JSON_KEY, (unsigned char**) &obj->profile_metadata, &obj->profile_metadata_size)) != eOk) {
        LOGE("[es9_json_extractor__authenticate_client_ok] Can not get the value of %s, rc %d", PROFILE_METADATA_JSON_KEY, rc);
        return rc;
    }
    LOG_UTF8_DATA(eLogTrace, "[es9_json_extractor__authenticate_client_ok] profileMetadata: ", obj->profile_metadata, obj->profile_metadata_size);
    
    // smdpSigned2
    if ((rc = json_data_extractor__get_string_value(json, json_len, SMDP_SIGNED_2_JSON_KEY, (unsigned char**) &obj->smdp_signed_2, &obj->smdp_signed_2_size)) != eOk) {
        LOGE("[es9_json_extractor__authenticate_client_ok] Can not get the value of %s, rc %d", SMDP_SIGNED_2_JSON_KEY, rc);
        return rc;
    }
    LOG_UTF8_DATA(eLogTrace, "[es9_json_extractor__authenticate_client_ok] smdpSigned2: ", obj->smdp_signed_2, obj->smdp_signed_2_size);
    
    // smdpSignature2
    if ((rc = json_data_extractor__get_string_value(json, json_len, SMDP_SIGNATURE_2_JSON_KEY, (unsigned char**) &obj->smdp_signature_2, &obj->smdp_signature_2_size)) != eOk) {
        LOGE("[es9_json_extractor__authenticate_client_ok] Can not get the value of %s, rc %d", SMDP_SIGNATURE_2_JSON_KEY, rc);
        return rc;
    }
    LOG_UTF8_DATA(eLogTrace, "[es9_json_extractor__authenticate_client_ok] smdpSignature2: ", obj->smdp_signature_2, obj->smdp_signature_2_size);
    
    // smdpCertificate
    if ((rc = json_data_extractor__get_string_value(json, json_len, SMDP_CERTIFICATE_JSON_KEY, (unsigned char**) &obj->smdp_certificate, &obj->smdp_certificate_size)) != eOk) {
        LOGE("[es9_json_extractor__authenticate_client_ok] Can not get the value of %s, rc %d", SMDP_CERTIFICATE_JSON_KEY, rc);
        return rc;
    }
    LOG_UTF8_DATA(eLogTrace, "[es9_json_extractor__authenticate_client_ok] smdpCertificate: ", obj->smdp_certificate, obj->smdp_certificate_size);

    return eOk;
}

static ErrCode es9_json_extractor__authenticate_client_error(const gsma_json_response_header_t* header, authenticate_client_error_t* obj) {
    *obj = AUTHENTICATE_CLIENT_ERROR_ES9_UNDEFINED_ERROR; // There are more JSON error codes than in ASN.1 and statusCodeData can be not present, so default is undefined
    if (header->function_execution_status.field_is_present.status_code_data) {
        LOG_UTF8_DATA(eLogTrace, "[es9_json_extractor__authenticate_client_error] Subject Code: ", header->function_execution_status.status_code_data.subject_code, header->function_execution_status.status_code_data.subject_code_len);
        LOG_UTF8_DATA(eLogTrace, "[es9_json_extractor__authenticate_client_error] Reason Code: ", header->function_execution_status.status_code_data.reason_code, header->function_execution_status.status_code_data.reason_code_len);
        // EUM Certificate
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, EUM_CERTIFICATE_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len)) {
            if (!strncmp((char*) header->function_execution_status.status_code_data.reason_code, VERIFICATION_FAILED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[es9_json_extractor__authenticate_client_error] EUM Certificate is invalid.");
                *obj = AUTHENTICATE_CLIENT_ERROR_ES9_EUM_CERTIFICATE_INVALID;
            } else if (!strncmp((char*) header->function_execution_status.status_code_data.reason_code, EXPIRED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[es9_json_extractor__authenticate_client_error] EUM Certificate has expired.");
                *obj = AUTHENTICATE_CLIENT_ERROR_ES9_EUM_CERTIFICATE_EXPIRED;
            }
        }
        // eUICC Certificate
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, EUICC_CERTIFICATE_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len)) {
            if (!strncmp((char*) header->function_execution_status.status_code_data.reason_code, VERIFICATION_FAILED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[es9_json_extractor__authenticate_client_error] eUICC Certificate is invalid.");
                *obj = AUTHENTICATE_CLIENT_ERROR_ES9_EUICC_CERTIFICATE_INVALID;
            } else if (!strncmp((char*) header->function_execution_status.status_code_data.reason_code, EXPIRED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[es9_json_extractor__authenticate_client_error] eUICC Certificate has expired.");
                *obj = AUTHENTICATE_CLIENT_ERROR_ES9_EUICC_CERTIFICATE_EXPIRED;
            }
        }
        // eUICC
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, EUICC_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len)) {
            if (!strncmp((char*) header->function_execution_status.status_code_data.reason_code, VERIFICATION_FAILED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[es9_json_extractor__authenticate_client_error] eUICC signature is invalid or serverChallenge is invalid.");
                *obj = AUTHENTICATE_CLIENT_ERROR_ES9_EUICC_SIGNATURE_INVALID;
            } else if (!strncmp((char*) header->function_execution_status.status_code_data.reason_code, INSUFFICIENT_MEMORY_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[es9_json_extractor__authenticate_client_error] eUICC does not have sufficient space for this Profile.");
                *obj = AUTHENTICATE_CLIENT_ERROR_ES9_INSUFFICIENT_MEMORY;
            }
        }
        // CI Public Key
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, CI_PUBLIC_KEY_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, UNKNOWN_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[es9_json_extractor__authenticate_client_error] Unknown CI Public Key. The CI used by the EUM Certificate is not a trusted root for the SM-DP+.");
            *obj = AUTHENTICATE_CLIENT_ERROR_ES9_CI_PK_UNKNOWN;
        }
        // Profile
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, PROFILE_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, NOT_ALLOWED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[es9_json_extractor__authenticate_client_error] Profile has not yet been released.");
            *obj = AUTHENTICATE_CLIENT_ERROR_ES9_NO_ELIGIBLE_PROFILE;
        }
        // TransactionId
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, TRANSACTION_ID_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, UNKNOWN_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[es9_json_extractor__authenticate_client_error] The RSP session identified by the TransactionID is unknown.");
            *obj = AUTHENTICATE_CLIENT_ERROR_ES9_INVALID_TRANSACTION_ID;
        }
        // MatchingID
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, MATCHING_ID_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, REFUSED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[es9_json_extractor__authenticate_client_error] MatchingID (AC_Token or EventID) is refused.");
            *obj = AUTHENTICATE_CLIENT_ERROR_ES9_MATCHING_ID_REFUSED;
        }
        // EID
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, EID_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, REFUSED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[es9_json_extractor__authenticate_client_error] EID doesn't match the expected value.");
            *obj = AUTHENTICATE_CLIENT_ERROR_ES9_EID_MISMATCH;
        }
        // Profile Type
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, PROFILE_TYPE_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, STOPPED_ON_WARNING_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[es9_json_extractor__authenticate_client_error] No eligible Profile for this eUICC/Device.");
            *obj = AUTHENTICATE_CLIENT_ERROR_ES9_NO_ELIGIBLE_PROFILE;
        }
        // Download order
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, DOWNLOAD_ORDER_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len)) {
            if (!strncmp((char*) header->function_execution_status.status_code_data.reason_code, TTL_EXPIRED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[es9_json_extractor__authenticate_client_error] The Download order has expired.");
                /* JSON Status code not defined in ASN.1 so will remain as undefined */
            } else if (!strncmp((char*) header->function_execution_status.status_code_data.reason_code, MAX_NUM_OF_RETRIES_EXCEEDED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[es9_json_extractor__authenticate_client_error] The maximum number of retries for the Profile download order has been exceeded.");
                /* JSON Status code not defined in ASN.1 so will remain as undefined */
            }
        }
    }
    LOGT("[es9_json_extractor__authenticate_client_error] authenticateClientError: %d", *obj);

    return eOk;
}

static ErrCode es9_json_extractor__get_bound_profile_package_ok(unsigned char* json, uint32_t json_len, get_bound_profile_package_ok_t* obj) {
    ErrCode rc;

    // transactionId
    if ((rc = gsma_json_extractor__transaction_id(json, json_len, &obj->transaction_id)) != eOk) {
        LOGE("[es9_json_extractor__get_bound_profile_package_ok] Can not get the value of the transactionId, rc %d", rc);
        return rc;
    }

    // boundProfilePackage
    if ((rc = json_data_extractor__get_string_value(json, json_len, BOUND_PROFILE_PACKAGE_JSON_KEY, (unsigned char**) &obj->bound_profile_package, &obj->bound_profile_package_size)) != eOk) {
        LOGE("[es9_json_extractor__get_bound_profile_package_ok] Can not get the value of %s, rc %d", BOUND_PROFILE_PACKAGE_JSON_KEY, rc);
        return rc;
    }
    LOG_UTF8_DATA(eLogTrace, "[es9_json_extractor__get_bound_profile_package_ok] boundProfilePackage: ", obj->bound_profile_package, obj->bound_profile_package_size);

    return eOk;
}

static ErrCode es9_json_extractor__get_bound_profile_package_error(const gsma_json_response_header_t* header, get_bound_profile_package_error_t* obj) {
    *obj = GET_BPP_ERROR_ES9_UNDEFINED_ERROR;
    if (header->function_execution_status.field_is_present.status_code_data) {
        LOG_UTF8_DATA(eLogTrace, "[es9_json_extractor__get_bound_profile_package_error] Subject Code: ", header->function_execution_status.status_code_data.subject_code, header->function_execution_status.status_code_data.subject_code_len);
        LOG_UTF8_DATA(eLogTrace, "[es9_json_extractor__get_bound_profile_package_error] Reason Code: ", header->function_execution_status.status_code_data.reason_code, header->function_execution_status.status_code_data.reason_code_len);
        // eUICC
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, EUICC_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, VERIFICATION_FAILED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[es9_json_extractor__get_bound_profile_package_error] eUICC signature is invalid.");
            *obj = GET_BPP_ERROR_ES9_EUICC_SIGNATURE_INVALID;
        }
        // Profile
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, PROFILE_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, UNAVAILABLE_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[es9_json_extractor__get_bound_profile_package_error] BPP is not available for a new binding.");
            *obj = GET_BPP_ERROR_ES9_BPP_REBINDING_REFUSED;
        }
        // TransactionId
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, TRANSACTION_ID_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, UNKNOWN_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[es9_json_extractor__get_bound_profile_package_error] The RSP session identified by the TransactionID is unknown.");
            *obj = GET_BPP_ERROR_ES9_INVALID_TRANSACTION_ID;
        }
        // Confirmation Code
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, CONFIRMATION_CODE_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len)) {
            if (!strncmp((char*) header->function_execution_status.status_code_data.reason_code, MANDATORY_ELEMENT_MISSING_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[es9_json_extractor__get_bound_profile_package_error] Confirmation Code is missing.");
                *obj = GET_BPP_ERROR_ES9_CONFIRMATION_CODE_MISSING;
            } else if (!strncmp((char*) header->function_execution_status.status_code_data.reason_code, REFUSED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[es9_json_extractor__get_bound_profile_package_error] Confirmation Code is refused.");
                *obj = GET_BPP_ERROR_ES9_CONFIRMATION_CODE_REFUSED;
            } else if (!strncmp((char*) header->function_execution_status.status_code_data.reason_code, MAX_NUM_OF_RETRIES_EXCEEDED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[es9_json_extractor__get_bound_profile_package_error] The maximum number of retries for the Confirmation Code has been exceeded.");
                *obj = GET_BPP_ERROR_ES9_CONFIRMATION_CODE_RETRIES_EXCEEDED;
            }
        }
        // Download order
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, DOWNLOAD_ORDER_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, TTL_EXPIRED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[es9_json_extractor__get_bound_profile_package_error] The Download order has expired.");
                *obj = GET_BPP_ERROR_ES9_DOWNLOAD_ORDER_EXPIRED;
        }
    }
    LOGT("[es9_json_extractor__get_bound_profile_package_error] getBoundProfilePackageError: %d", *obj);

    return eOk;
}

static ErrCode es9_json_extractor__cancel_session_error(const gsma_json_response_header_t* header, cancel_session_error_t* obj) {
    *obj = CANCEL_SESSION_ERROR_ES9_UNDEFINED_ERROR; // There are more JSON error codes than in ASN.1 and statusCodeData can be not present, so default is undefined
    if (header->function_execution_status.field_is_present.status_code_data) {
        LOG_UTF8_DATA(eLogTrace, "[es9_json_extractor__cancel_session_error] Subject Code: ", header->function_execution_status.status_code_data.subject_code, header->function_execution_status.status_code_data.subject_code_len);
        LOG_UTF8_DATA(eLogTrace, "[es9_json_extractor__cancel_session_error] Reason Code: ", header->function_execution_status.status_code_data.reason_code, header->function_execution_status.status_code_data.reason_code_len);
        // TransactionId
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, TRANSACTION_ID_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, UNKNOWN_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[es9_json_extractor__cancel_session_error] The RSP session identified by the TransactionID is unknown.");
            *obj = CANCEL_SESSION_ERROR_ES9_INVALID_TRANSACTION_ID;
        }
        // eUICC
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, EUICC_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, VERIFICATION_FAILED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[es9_json_extractor__cancel_session_error] eUICC signature is invalid.");
            *obj = CANCEL_SESSION_ERROR_ES9_EUICC_SIGNATURE_INVALID;
        }
        // SM-DP+
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, SMDP_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, INVALID_ASSOCIATION_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[es9_json_extractor__cancel_session_error] The provided SM-DP+ OID is invalid.");
            /* JSON Status code not defined in ASN.1 so will remain as undefined */
        }
    }
    LOGT("[es9_json_extractor__cancel_session_error] cancelSessionError: %d", *obj);

    return eOk;
}
