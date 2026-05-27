/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include "es11_json_generator.h"
#include "json_generator.h"
#include "log.h"

#define EUICC_CHALLENGE_JSON_KEY    "euiccChallenge"
#define EUICC_INFO_1_JSON_KEY       "euiccInfo1"
#define SMDP_ADDRESS_JSON_KEY       "smdpAddress"
#define TRANSACTION_ID_JSON_KEY     "transactionId"
#define AUTHENTICATE_SERVER_RESPONSE_JSON_KEY "authenticateServerResponse"

int32_t es11_json_generator__initiate_authentication_request(uint8_t* buffer, const uint32_t buffer_size, const initiate_authentication_request_t* obj) {
    int32_t buffer_offset = 0;

    if ((buffer_offset = json_generator__add_base64_string_child(buffer, buffer_size, buffer_offset, true, false, EUICC_CHALLENGE_JSON_KEY, obj->euicc_challenge.challenge, sizeof(obj->euicc_challenge.challenge))) < 0) {
        LOGE("[es11_json_generator__initiate_authentication_request] Error on euiccChallenge, err %d", buffer_offset);
        return buffer_offset;
    }

    if ((buffer_offset = json_generator__add_base64_string_child(buffer, buffer_size, buffer_offset, false, false, EUICC_INFO_1_JSON_KEY, obj->euicc_info_1, obj->euicc_info_1_size)) < 0) {
        LOGE("[es11_json_generator__initiate_authentication_request] Error on euiccInfo1, err %d", buffer_offset);
        return buffer_offset;
    }

    if ((buffer_offset = json_generator__add_string_child(buffer, buffer_size, buffer_offset, false, true, SMDP_ADDRESS_JSON_KEY, (unsigned char*) obj->smdp_address.fqdn, (uint32_t) strlen(obj->smdp_address.fqdn))) < 0) {
        LOGE("[es11_json_generator__initiate_authentication_request] Error on smdpAddress, err %d", buffer_offset);
        return buffer_offset;
    }

    if (buffer && buffer_offset > 0) {
        LOG_UTF8_DATA(eLogDebug, "[es11_json_generator__initiate_authentication_request] ", buffer, buffer_offset);
    }

    return buffer_offset;
}

int32_t es11_json_generator__authenticate_client_request(uint8_t* buffer, const uint32_t buffer_size, const authenticate_client_request_t* obj) {
    int32_t buffer_offset = 0;

    if ((buffer_offset = json_generator__add_hexadecimal_string_child(buffer, buffer_size, buffer_offset, true, false, TRANSACTION_ID_JSON_KEY, obj->transaction_id.transaction_id, obj->transaction_id.transaction_id_size)) < 0) {
        LOGE("[es11_json_generator__authenticate_client_request] Error on transactionId, err %d", buffer_offset);
        return buffer_offset;
    }

    if ((buffer_offset = json_generator__add_base64_string_child(buffer, buffer_size, buffer_offset, false, true, AUTHENTICATE_SERVER_RESPONSE_JSON_KEY, obj->authenticate_server_response, obj->authenticate_server_response_size)) < 0) {
        LOGE("[es11_json_generator__authenticate_client_request] Error on authenticateServerResponse, err %d", buffer_offset);
        return buffer_offset;
    }

    if (buffer && buffer_offset > 0) {
        LOG_UTF8_DATA(eLogDebug, "[es11_json_generator__authenticate_client_request] ", buffer, buffer_offset);
    }

    return buffer_offset;
}
