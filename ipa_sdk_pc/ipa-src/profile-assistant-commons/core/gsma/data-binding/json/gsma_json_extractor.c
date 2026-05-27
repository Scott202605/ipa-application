/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include "gsma_json_extractor.h"
#include "json_data_extractor.h"
#include "byte_utils.h"
#include "log.h"

// JSON Keys
#define HEADER_JSON_KEY                     "\"header\""
#define FUNCTION_EXECUTION_STATUS_JSON_KEY  "\"functionExecutionStatus\""
#define STATUS_JSON_KEY                     "\"status\""
#define STATUS_CODE_DATA_JSON_KEY           "\"statusCodeData\""
#define SUBJECT_CODE_JSON_KEY               "\"subjectCode\""
#define REASON_CODE_JSON_KEY                "\"reasonCode\""
#define SUBJECT_IDENTIFIER_JSON_KEY         "\"subjectIdentifier\""
#define MESSAGE_JSON_KEY                    "\"message\""
#define TRANSACTION_ID_JSON_KEY             "\"transactionId\""

// JSON status values
#define STATUS_EXECUTED_SUCCESS         "Executed-Success"
#define STATUS_EXECUTED_WITH_WARNING    "Executed-WithWarning"
#define STATUS_EXECUTED_FAILED          "Failed"
#define STATUS_EXECUTED_EXPIRED         "Expired"

static ErrCode gsma_json_extractor__function_execution_status(const unsigned char* json, uint32_t json_len, function_execution_status_t* obj);
static ErrCode gsma_json_extractor__status_code_data_value(const unsigned char* json, uint32_t json_len, json_response_status_code_data_t* obj);

ErrCode gsma_json_extractor__header(const unsigned char* json, uint32_t json_len, gsma_json_response_header_t* obj) {
    ErrCode rc;
    unsigned char* header_value;
    uint32_t header_value_len;

    if ((rc = json_data_extractor__get_object_value(json, json_len, HEADER_JSON_KEY, &header_value, &header_value_len)) != eOk) {
        LOGE("[gsma_json_extractor__header] Can not get the value of %s, rc %d", HEADER_JSON_KEY, rc);
        return rc;
    }

    return gsma_json_extractor__function_execution_status(header_value, header_value_len, &obj->function_execution_status);
}

ErrCode gsma_json_extractor__transaction_id(const unsigned char* json, uint32_t json_len, transaction_id_t* obj) {
    ErrCode rc;
    unsigned char* hex_transaction_id;
    uint32_t hex_transaction_id_len;
    int32_t transaction_id_size;

    if ((rc = json_data_extractor__get_string_value(json, json_len, TRANSACTION_ID_JSON_KEY, &hex_transaction_id, &hex_transaction_id_len)) != eOk) {
        LOGD("[gsma_json_extractor__transaction_id] Can not get the value of %s, rc %d", TRANSACTION_ID_JSON_KEY, rc);
        return rc;
    }
    LOG_UTF8_DATA(eLogTrace, "[gsma_json_extractor__transaction_id] Hexadecimal transactionId: ", (unsigned char*) hex_transaction_id, hex_transaction_id_len);

    if ((transaction_id_size = byte_utils__hex_string_to_byte_array((unsigned char*) hex_transaction_id, hex_transaction_id_len, obj->transaction_id, sizeof(obj->transaction_id))) < 0) {
        LOGE("[gsma_json_extractor__transaction_id] Error parsing the %s from hexadecimal string to byte array, err %d", TRANSACTION_ID_JSON_KEY, transaction_id_size);
        return eFatal;
    } else {
        obj->transaction_id_size = (uint8_t) transaction_id_size;
    }
    LOG_DATA(eLogDebug, "[gsma_json_extractor__transaction_id] transactionId", obj->transaction_id, obj->transaction_id_size);

    return eOk;
}

static ErrCode gsma_json_extractor__function_execution_status(const unsigned char* json, uint32_t json_len, function_execution_status_t* obj) {
    ErrCode rc;
    unsigned char* parent_value;
    uint32_t parent_value_len;
    unsigned char* child_value;
    uint32_t child_value_len;

    if ((rc = json_data_extractor__get_object_value(json, json_len, FUNCTION_EXECUTION_STATUS_JSON_KEY, &parent_value, &parent_value_len)) != eOk) {
        LOGE("[gsma_json_extractor__function_execution_status] Can not get the value of %s, rc %d", FUNCTION_EXECUTION_STATUS_JSON_KEY, rc);
        return rc;
    }

    if ((rc = json_data_extractor__get_string_value(parent_value, parent_value_len, STATUS_JSON_KEY, &child_value, &child_value_len)) != eOk) {
        LOGE("[gsma_json_extractor__function_execution_status] Can not get the value of %s, rc %d", STATUS_JSON_KEY, rc);
        return rc;
    }

    if (!strncmp((char*) child_value, STATUS_EXECUTED_SUCCESS, child_value_len)) {
        obj->status = JSON_RESPONSE_STATUS_EXECUTED_SUCCESS;
        LOGT("[gsma_json_extractor__initiate_authentication_response] The status is %s", STATUS_EXECUTED_SUCCESS);
    } else if (!strncmp((char*) child_value, STATUS_EXECUTED_WITH_WARNING, child_value_len)) {
        obj->status = JSON_RESPONSE_STATUS_EXECUTED_WITH_WARNING;
        LOGT("[gsma_json_extractor__initiate_authentication_response] The status is %s", STATUS_EXECUTED_WITH_WARNING);
    } else if (!strncmp((char*) child_value, STATUS_EXECUTED_FAILED, child_value_len)) {
        obj->status = JSON_RESPONSE_STATUS_EXECUTED_FAILED;
        LOGT("[gsma_json_extractor__initiate_authentication_response] The status is %s", STATUS_EXECUTED_FAILED);
    } else if (!strncmp((char*) child_value, STATUS_EXECUTED_EXPIRED, child_value_len)) {
        obj->status = JSON_RESPONSE_STATUS_EXECUTED_EXPIRED;
        LOGT("[gsma_json_extractor__initiate_authentication_response] The status is %s", STATUS_EXECUTED_EXPIRED);
    } else {
        LOG_UTF8_DATA(eLogErr, "[gsma_json_extractor__function_execution_status] Unknown status ", (unsigned char*) child_value, child_value_len);
        return eFatal;
    }

    // OPTIONAL field
    if ((rc = json_data_extractor__get_object_value(parent_value, parent_value_len, STATUS_CODE_DATA_JSON_KEY, &child_value, &child_value_len)) == eOk) {
        if ((rc = gsma_json_extractor__status_code_data_value(child_value, child_value_len, &obj->status_code_data)) != eOk) {
            LOGE("[gsma_json_extractor__function_execution_status] Error extracting data from %s JSON object, rc %d", STATUS_CODE_DATA_JSON_KEY, rc);
            return rc;
        }
        obj->field_is_present.status_code_data = true;
    } else {
        obj->field_is_present.status_code_data = false;
    }

    return eOk;
}

static ErrCode gsma_json_extractor__status_code_data_value(const unsigned char* json, uint32_t json_len, json_response_status_code_data_t* obj) {
    ErrCode rc;

    if ((rc = json_data_extractor__get_string_value(json, json_len, SUBJECT_CODE_JSON_KEY, &obj->subject_code, &obj->subject_code_len)) != eOk) {
        LOGE("[gsma_json_extractor__status_code_data_value] Can not get the value of %s, rc %d", SUBJECT_CODE_JSON_KEY, rc);
        return rc;
    }
    LOG_UTF8_DATA(eLogWarn, "[gsma_json_extractor__status_code_data_value] subjectCode: ", obj->subject_code, obj->subject_code_len);

    if ((rc = json_data_extractor__get_string_value(json, json_len, REASON_CODE_JSON_KEY, &obj->reason_code, &obj->reason_code_len)) != eOk) {
        LOGE("[gsma_json_extractor__status_code_data_value] Can not get the value of %s, rc %d", REASON_CODE_JSON_KEY, rc);
        return rc;
    }
    LOG_UTF8_DATA(eLogWarn, "[gsma_json_extractor__status_code_data_value] reasonCode: ", obj->reason_code, obj->reason_code_len);

    // OPTIONAL field
    if ((rc = json_data_extractor__get_string_value(json, json_len, SUBJECT_IDENTIFIER_JSON_KEY, &obj->subject_identifier, &obj->subject_identifier_len)) == eOk) {
        obj->field_is_present.subject_identifier = true;
        LOG_UTF8_DATA(eLogWarn, "[gsma_json_extractor__status_code_data_value] subjectIdentifier: ", obj->subject_identifier, obj->subject_identifier_len);
    } else {
        LOGD("[gsma_json_extractor__status_code_data_value] %s is not present in statusCodeData", SUBJECT_IDENTIFIER_JSON_KEY);
        obj->field_is_present.subject_identifier = false;
        obj->subject_identifier = NULL;
        obj->subject_identifier_len = 0;
    }
    // OPTIONAL field
    if ((rc = json_data_extractor__get_string_value(json, json_len, MESSAGE_JSON_KEY, &obj->message, &obj->message_len)) == eOk) {
        obj->field_is_present.message = true;
        LOG_UTF8_DATA(eLogWarn, "[gsma_json_extractor__status_code_data_value] message: ", obj->message, obj->message_len);
    } else {
        LOGD("[gsma_json_extractor__status_code_data_value] %s is not present in statusCodeData", MESSAGE_JSON_KEY);
        obj->field_is_present.message = false;
        obj->message = NULL;
        obj->message_len = 0;
    }

    return eOk;
}
