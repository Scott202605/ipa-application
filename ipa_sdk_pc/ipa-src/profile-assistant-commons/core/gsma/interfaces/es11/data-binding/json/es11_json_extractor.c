/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include "es11_json_extractor.h"
#include "gsma_json_extractor.h"
#include "json_data_extractor.h"
#include "tlv_data_extractor.h"
#include "base64.h"
#include "tlv_tags.h"
#include "log.h"

#define EVENT_ENTRIES_JSON_KEY      "eventEntries"
#define EVENT_ID_JSON_KEY           "eventId"
#define RSP_SERVER_ADDRESS_JSON_KEY "rspServerAddress"

static ErrCode es11_json_extractor__authenticate_client_ok(unsigned char* json, uint32_t json_len, authenticate_client_es11_ok_t* obj);
static ErrCode es11_json_extractor__authenticate_client_error(const gsma_json_response_header_t* header, authenticate_client_es11_error_t* obj);

ErrCode es11_json_extractor__authenticate_client_response(unsigned char* json, uint32_t json_len, authenticate_client_response_es11_t* obj) {
    ErrCode rc;
    gsma_json_response_header_t header;

    /* Check input parameters */
    if (!json) {
        LOGE("[es11_json_extractor__authenticate_client_response] JSON response is null");
        return eBadArg;
    }
    LOG_UTF8_DATA(eLogTrace, "[es11_json_extractor__authenticate_client_response] ", json, json_len);

    /* Extract the JSON responseHeader */
    if ((rc = gsma_json_extractor__header(json, json_len, &header)) != eOk) {
        LOGE("[es11_json_extractor__authenticate_client_response] Error extracting data from the JSON responseHeader, rc %d", rc);
        return rc;
    }

    /* Extract the JSON body */
    if (JSON_RESPONSE_STATUS_EXECUTED_SUCCESS == header.function_execution_status.status) {
        obj->choice = AUTHENTICATE_CLIENT_RESPONSE_ES11_OK;
        if ((rc = es11_json_extractor__authenticate_client_ok(json, json_len, &obj->value.ok)) != eOk) {
            LOGE("[es11_json_extractor__authenticate_client_response] Error extracting the AuthenticateClientOk JSON body");
            return rc;
        }
        
        return eOk;
    } else if (JSON_RESPONSE_STATUS_EXECUTED_FAILED == header.function_execution_status.status) {
        obj->choice = AUTHENTICATE_CLIENT_RESPONSE_ES11_ERROR;
        return es11_json_extractor__authenticate_client_error(&header, &obj->value.error);
    } else {
        LOGE("[es11_json_extractor__authenticate_client_response] Status different than success or failed. Status: %d", header.function_execution_status.status);
        return eFatal;
    }
}

ErrCode es11_json_extractor__get_next_event_entry(json_array_iterator_t* it, event_entry_t* obj) {
    unsigned char* event_entry;
    uint32_t event_entry_len;
    uint32_t len;
    ErrCode rc;

    /* Extract the next object of the array */
    if ((rc = json_data_extractor__get_next_object_element(it, &event_entry, &event_entry_len)) != eOk) {
        LOGE("[es11_json_extractor__get_next_event_entry] Error extracting the next event entry from the JSON string, rc %d", rc);
        return eFatal;
    }

    /* If there is no next object, return eNoData */
    if (!event_entry) {
        LOGD("[es11_json_extractor__get_next_event_entry] There is no next event entry");
        return eNoData;
    }

    /* If there is next object, extract the event entry data */
    // eventId
    if ((rc = json_data_extractor__get_string_value(event_entry, event_entry_len, EVENT_ID_JSON_KEY, (unsigned char**) &obj->event_id, &len)) != eOk) {
        LOGE("[es11_json_extractor__get_next_event_entry] Can not get the value of %s, rc %d", EVENT_ID_JSON_KEY, rc);
        return eFatal;
    }
    obj->event_id_len = (uint8_t) len;
    LOG_UTF8_DATA(eLogTrace, "[es11_json_extractor__authenticate_client_ok] eventId: ", obj->event_id, obj->event_id_len);

    // rspServerAddress
    if ((rc = json_data_extractor__get_string_value(event_entry, event_entry_len, RSP_SERVER_ADDRESS_JSON_KEY, (unsigned char**) &obj->rsp_server_address, &len)) != eOk) {
        LOGE("[es11_json_extractor__get_next_event_entry] Can not get the value of %s, rc %d", RSP_SERVER_ADDRESS_JSON_KEY, rc);
        return eFatal;
    }
    obj->rsp_server_address_len = (uint8_t) len;
    LOG_UTF8_DATA(eLogTrace, "[es11_json_extractor__authenticate_client_ok] rspServerAddress: ", obj->rsp_server_address, obj->rsp_server_address_len);

    return eOk;
}

ErrCode es11_json_extractor__get_event_entry_list_size(json_array_iterator_t* it, uint32_t* list_size) {
    return json_data_extractor__get_array_object_size(it, list_size);
}

static ErrCode es11_json_extractor__authenticate_client_ok(unsigned char* json, uint32_t json_len, authenticate_client_es11_ok_t* obj) {
    ErrCode rc;

    // transactionId
    if ((rc = gsma_json_extractor__transaction_id(json, json_len, &obj->transaction_id)) != eOk) {
        LOGE("[es11_json_extractor__authenticate_client_ok] Can not get the value of the transactionId, rc %d", rc);
        return rc;
    }

    // eventEntries
    if ((rc = json_data_extractor__init_array_iterator(json, json_len, EVENT_ENTRIES_JSON_KEY, &obj->event_entries.json_list_handler)) != eOk) {
        LOGE("[es11_json_extractor__authenticate_client_ok] Can not get the value of %s, rc %d", EVENT_ENTRIES_JSON_KEY, rc);
        return rc;
    }
    LOG_UTF8_DATA(eLogTrace, "[es11_json_extractor__authenticate_client_ok] eventEntries: ", obj->event_entries.json_list_handler.ptr, obj->event_entries.json_list_handler.size);

    return eOk;
}

static ErrCode es11_json_extractor__authenticate_client_error(const gsma_json_response_header_t* header, authenticate_client_es11_error_t* obj) {
    *obj = AUTHENTICATE_CLIENT_ES11_ERROR_UNDEFINED_ERROR; // There are more JSON error codes than in ASN.1 and statusCodeData can be not present, so default is undefined
    if (header->function_execution_status.field_is_present.status_code_data) {
        LOG_UTF8_DATA(eLogTrace, "[es11_json_extractor__authenticate_client_error] Subject Code: ", header->function_execution_status.status_code_data.subject_code, header->function_execution_status.status_code_data.subject_code_len);
        LOG_UTF8_DATA(eLogTrace, "[es11_json_extractor__authenticate_client_error] Reason Code: ", header->function_execution_status.status_code_data.reason_code, header->function_execution_status.status_code_data.reason_code_len);
        // EUM Certificate
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, EUM_CERTIFICATE_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len)) {
            if (!strncmp((char*) header->function_execution_status.status_code_data.reason_code, VERIFICATION_FAILED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[es11_json_extractor__authenticate_client_error] EUM Certificate is invalid.");
                *obj = AUTHENTICATE_CLIENT_ES11_ERROR_EUM_CERTIFICATE_INVALID;
            } else if (!strncmp((char*) header->function_execution_status.status_code_data.reason_code, EXPIRED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[es11_json_extractor__authenticate_client_error] EUM Certificate has expired.");
                *obj = AUTHENTICATE_CLIENT_ES11_ERROR_EUM_CERTIFICATE_EXPIRED;
            }
        }
        // eUICC Certificate
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, EUICC_CERTIFICATE_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len)) {
            if (!strncmp((char*) header->function_execution_status.status_code_data.reason_code, VERIFICATION_FAILED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[es11_json_extractor__authenticate_client_error] eUICC Certificate is invalid.");
                *obj = AUTHENTICATE_CLIENT_ES11_ERROR_EUICC_CERTIFICATE_INVALID;
            } else if (!strncmp((char*) header->function_execution_status.status_code_data.reason_code, EXPIRED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
                LOGW("[es11_json_extractor__authenticate_client_error] eUICC Certificate has expired.");
                *obj = AUTHENTICATE_CLIENT_ES11_ERROR_EUICC_CERTIFICATE_EXPIRED;
            }
        }
        // eUICC
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, EUICC_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, VERIFICATION_FAILED_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[es11_json_extractor__authenticate_client_error] eUICC signature is invalid or serverChallenge is invalid.");
            *obj = AUTHENTICATE_CLIENT_ES11_ERROR_EUICC_SIGNATURE_INVALID;
        }
        // TransactionId
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, TRANSACTION_ID_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, UNKNOWN_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[es11_json_extractor__authenticate_client_error] The RSP session identified by the TransactionID is unknown.");
            *obj = AUTHENTICATE_CLIENT_ES11_ERROR_INVALID_TRANSACTION_ID;
        }
        // CI Public Key
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, CI_PUBLIC_KEY_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, UNKNOWN_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[es11_json_extractor__authenticate_client_error] Unknown CI Public Key. The CI used by the EUM Certificate is not a trusted root for the SM-DS.");
            /* JSON Status code not defined in ASN.1 so will remain as undefined */
        }
        // Event Record
        if (!strncmp((char*) header->function_execution_status.status_code_data.subject_code, SMDS_EVENT_RECORD_SUBJECT_CODE_OID, header->function_execution_status.status_code_data.subject_code_len) &&
            !strncmp((char*) header->function_execution_status.status_code_data.reason_code, UNKNOWN_REASON_CODE_OID, header->function_execution_status.status_code_data.reason_code_len)) {
            LOGW("[es11_json_extractor__authenticate_client_error] No Event identified by the Event ID for the EID exists.");
            *obj = AUTHENTICATE_CLIENT_ES11_ERROR_EVENT_ID_UNKNOWN;
        }
    }
    LOGT("[es11_json_extractor__authenticate_client_error] authenticateClientError: %d", *obj);

    return eOk;
}
