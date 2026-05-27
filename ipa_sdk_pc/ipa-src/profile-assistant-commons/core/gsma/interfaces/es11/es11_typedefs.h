/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"
#include "json_data_extractor.h"

typedef struct event_entry_s {
    uint8_t* event_id;
    uint8_t event_id_len;
    uint8_t* rsp_server_address;
    uint8_t rsp_server_address_len;
} event_entry_t;

typedef union event_entries_list_u {
    json_array_iterator_t json_list_handler;
    asn1_list_iterator_t asn1_list_handler;
} event_entries_list_t;

typedef struct authenticate_client_es11_ok_s {
    transaction_id_t transaction_id;
    event_entries_list_t event_entries;
} authenticate_client_es11_ok_t;

typedef enum authenticate_client_es11_error_e {
    AUTHENTICATE_CLIENT_ES11_ERROR_EUM_CERTIFICATE_INVALID = 1,
    AUTHENTICATE_CLIENT_ES11_ERROR_EUM_CERTIFICATE_EXPIRED = 2,
    AUTHENTICATE_CLIENT_ES11_ERROR_EUICC_CERTIFICATE_INVALID = 3,
    AUTHENTICATE_CLIENT_ES11_ERROR_EUICC_CERTIFICATE_EXPIRED = 4,
    AUTHENTICATE_CLIENT_ES11_ERROR_EUICC_SIGNATURE_INVALID = 5,
    AUTHENTICATE_CLIENT_ES11_ERROR_EVENT_ID_UNKNOWN = 6,
    AUTHENTICATE_CLIENT_ES11_ERROR_INVALID_TRANSACTION_ID = 7,
    AUTHENTICATE_CLIENT_ES11_ERROR_UNDEFINED_ERROR = 127
} authenticate_client_es11_error_t;

typedef union authenticate_client_response_es11_value_u {
    authenticate_client_es11_error_t error;
    authenticate_client_es11_ok_t ok;
} authenticate_client_response_es11_value_t;

typedef enum authenticate_client_response_es11_choice_e {
    AUTHENTICATE_CLIENT_RESPONSE_ES11_OK,
    AUTHENTICATE_CLIENT_RESPONSE_ES11_ERROR
} authenticate_client_response_es11_choice_t;

typedef struct authenticate_client_response_es11_s {
    void* context;
    authenticate_client_response_es11_choice_t choice;
    authenticate_client_response_es11_value_t value;
} authenticate_client_response_es11_t;
