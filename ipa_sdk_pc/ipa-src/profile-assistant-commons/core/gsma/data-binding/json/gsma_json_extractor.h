/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"

// Subject codes OID
#define EUICC_SUBJECT_CODE_OID                  "8.1"
#define EID_SUBJECT_CODE_OID                    "8.1.1"
#define EUM_CERTIFICATE_SUBJECT_CODE_OID        "8.1.2"
#define EUICC_CERTIFICATE_SUBJECT_CODE_OID      "8.1.3"
#define PROFILE_SUBJECT_CODE_OID                "8.2"
#define PROFILE_TYPE_SUBJECT_CODE_OID           "8.2.5"
#define MATCHING_ID_SUBJECT_CODE_OID            "8.2.6"
#define CONFIRMATION_CODE_SUBJECT_CODE_OID      "8.2.7"
#define PPR_SUBJECT_CODE_OID                    "8.2.8"
#define PROFILE_METADATA_SUBJECT_CODE_OID       "8.2.9"
#define SMDP_SUBJECT_CODE_OID                   "8.8"
#define SMDP_ADDRESS_SUBJECT_CODE_OID           "8.8.1"
#define SMDP_SECURITY_CONFIG_SUBJECT_CODE_OID   "8.8.2"
#define SMDP_SVN_SUBJECT_CODE_OID               "8.8.3"
#define SMDP_CERTIFICATE_SUBJECT_CODE_OID       "8.8.4"
#define DOWNLOAD_ORDER_SUBJECT_CODE_OID         "8.8.5"
#define SMDS_ADDRESS_SUBJECT_CODE_OID           "8.9.1"
#define SMDS_SECURITY_CONFIG_SUBJECT_CODE_OID   "8.9.2"
#define SMDS_SVN_SUBJECT_CODE_OID               "8.9.3"
#define SMDS_CERTIFICATE_SUBJECT_CODE_OID       "8.9.4"
#define SMDS_EVENT_RECORD_SUBJECT_CODE_OID      "8.9.5"
#define TRANSACTION_ID_SUBJECT_CODE_OID         "8.10.1"
#define CI_PUBLIC_KEY_SUBJECT_CODE_OID          "8.11.1"
#define EIM_TRANSACTION_ID_SUBJECT_CODE_OID     "8.31.2"

// Reason codes OID
#define NOT_ALLOWED_REASON_CODE_OID                 "1.2"
#define INVALID_REASON_CODE_OID                     "2.1"
#define MANDATORY_ELEMENT_MISSING_REASON_CODE_OID   "2.2"
#define UNSUPPORTED_REASON_CODE_OID                 "3.1"
#define UNAVAILABLE_REASON_CODE_OID                 "3.7"
#define REFUSED_REASON_CODE_OID                     "3.8"
#define UNKNOWN_REASON_CODE_OID                     "3.9"
#define INVALID_ASSOCIATION_REASON_CODE_OID         "3.10"
#define VALUE_HAS_CHANGED_REASON_CODE_OID           "3.11"
#define STOPPED_ON_WARNING_CODE_OID                 "4.3"
#define INSUFFICIENT_MEMORY_REASON_CODE_OID         "4.8"
#define TTL_EXPIRED_REASON_CODE_OID                 "4.10"
#define VERIFICATION_FAILED_REASON_CODE_OID         "6.1"
#define EXPIRED_REASON_CODE_OID                     "6.3"
#define MAX_NUM_OF_RETRIES_EXCEEDED_REASON_CODE_OID "6.4"

typedef enum json_response_status_e {
    JSON_RESPONSE_STATUS_EXECUTED_SUCCESS,
    JSON_RESPONSE_STATUS_EXECUTED_WITH_WARNING,
    JSON_RESPONSE_STATUS_EXECUTED_FAILED,
    JSON_RESPONSE_STATUS_EXECUTED_EXPIRED
} json_response_status_t;

typedef struct json_response_status_code_data_data_presence_s {
    bool subject_identifier;
    bool message;
} json_response_status_code_data_data_presence_t;

typedef struct json_response_status_code_data_s {
    unsigned char* subject_code;
    uint32_t subject_code_len;
    unsigned char* reason_code;
    uint32_t reason_code_len;
    unsigned char* subject_identifier;
    uint32_t subject_identifier_len;
    unsigned char* message;
    uint32_t message_len;
    json_response_status_code_data_data_presence_t field_is_present;
} json_response_status_code_data_t;

typedef struct function_execution_status_data_presence_s {
    bool status_code_data;
} function_execution_status_data_presence_t;

typedef struct function_execution_status_s {
    json_response_status_t status;
    json_response_status_code_data_t status_code_data;
    function_execution_status_data_presence_t field_is_present;
} function_execution_status_t;

typedef struct gsma_json_response_header_s {
    function_execution_status_t function_execution_status;
} gsma_json_response_header_t;

/**
 * This function extracts the <JSON responseHeader> defined in the SGP.22 from a JSON string.
 * 
 * @param[in]  json string in JSON format (can be not null-terminated).
 * @param[in]  json_len length of the json string (excluding the null-terminated character).
 * @param[out] obj Pointer to a gsma_json_response_header_t structure. The structure is populated following its 
 * documentation with the data from the json string if the function return is success. The structure data may be 
 * referencing data from the json string, do not deallocate the json string while using the structure.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned.
*/
ErrCode gsma_json_extractor__header(const unsigned char* json, uint32_t json_len, gsma_json_response_header_t* obj);

/**
 * This function extracts the transactionId defined in the SGP.22 from a JSON string.
 * 
 * @param[in]  json string in JSON format (can be not null-terminated).
 * @param[in]  json_len length of the json string (excluding the null-terminated character).
 * @param[out] obj Pointer to a transaction_id_t structure. The structure is populated following its documentation 
 * with the data from the json string if the function return is success. The structure data don't reference any data 
 * from the json string, so the json string can be deallocated after the execution of the function.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned.
*/
ErrCode gsma_json_extractor__transaction_id(const unsigned char* json, uint32_t json_len, transaction_id_t* obj);
