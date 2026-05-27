/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include "network_utils.h"

bool network_utils__is_secure_protocol(const char* url) {
    return !strncmp(url, PROTOCOL_SSL, sizeof(PROTOCOL_SSL) - 1) || !strncmp(url, PROTOCOL_WSS, sizeof(PROTOCOL_WSS) - 1)  || !strncmp(url, PROTOCOL_MQTTS, sizeof(PROTOCOL_MQTTS) - 1);
}

bool network_utils__is_http_scheme(const char* url) {
    return !(strncmp(url, HTTP_SCHEME, sizeof(HTTP_SCHEME) - 1));
}

bool network_utils__is_https_scheme(const char* url) {
    return !(strncmp(url, HTTPS_SCHEME, sizeof(HTTPS_SCHEME) - 1));
}
