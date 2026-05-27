/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"

#define PROTOCOL_SSL    "ssl"
#define PROTOCOL_WSS    "wss"
#define PROTOCOL_MQTTS  "mqtts"
#define HTTP_SCHEME     "http://"
#define HTTPS_SCHEME    "https://"

/**
 * Checks if the Scheme of an URL is secure.
 * 
 * @param url null-terminated string with the URL to check.
 * 
 * @return true if the Scheme of the URL is secure or false otherwise.
 */
bool network_utils__is_secure_protocol(const char* url);

/**
 * Checks if the Scheme of an URL is http.
 * 
 * @param url null-terminated string with the URL to check.
 * 
 * @return true if the Scheme of the URL is http or false otherwise.
 */
bool network_utils__is_http_scheme(const char* url);

/**
 * Checks if the Scheme of an URL is https.
 * 
 * @param url null-terminated string with the URL to check.
 * 
 * @return true if the Scheme of the URL is https or false otherwise.
 */
bool network_utils__is_https_scheme(const char* url);
