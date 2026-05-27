/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include <stdio.h>

#include "network.h"
#include "log.h"
#include "memory_manager.h"
#include "http_client.h"

#define HTTPS_PROTOCOL  "https://"

#define HTTP_CONTENT_LENGTH_TEMPLATE    "Content-Length: %u"

ErrCode network__send_https_post_request(const char* fqdn, const char* path, const char** headers_list, uint32_t headers_list_size, unsigned char** request_body, uint32_t* request_body_size, unsigned char** response_body, uint32_t* response_body_size, int* http_status_code,uint32_t timeout) {
    int err;
    void* http_client_handle;
    void* headers_list_handle = NULL;
    struct memory_struct response_buffer;
    long http_status;
    char* url;
    size_t url_len;
    char content_length_header[27] = { 0 }; // Max value: "Content-Length: 4294967295" -> 26 bytes + null char
    int content_length_header_len;
    void* tmp = NULL;
    uint32_t i;

    /* Check input parameters */
    if (!fqdn) {
        LOGE("[network__send_https_post_request] The FQDN is null");
        return eBadArg;
    }
    if (!path) {
        LOGE("[network__send_https_post_request] The HTTP Path is null");
        return eBadArg;
    }
    if (!(*request_body) || *request_body_size == 0) {
        LOGE("[network__send_https_post_request] The HTTP Request Body is empty/null");
        return eBadArg;
    }
    if (!headers_list) {
        headers_list_size = 0; // Just in case
    }

    /* Initialize output parameters */
    *response_body = NULL;
    *response_body_size = 0;
    *http_status_code = 0;

    /* Generate the Content-Length Header*/
    content_length_header_len = snprintf(content_length_header, sizeof(content_length_header), HTTP_CONTENT_LENGTH_TEMPLATE, *request_body_size);
    if (content_length_header_len < 0) {
        LOGE("[network__send_https_post_request] Error generating the Content-Length Header, err %d", content_length_header_len);
        return eFatal;
    }

    /* Generate the URL */
    url_len = strlen(HTTPS_PROTOCOL) + strlen(fqdn) + strlen(path);
    url = (char*) M_malloc(sizeof(char) * (url_len + 1));
    if (!url) {
        LOGE("[network__send_https_post_request] Can not allocate data to URL");
        return eNoMem;
    }
    strcpy(url, HTTPS_PROTOCOL);
    strcpy(url + strlen(HTTPS_PROTOCOL), fqdn);
    strcpy(url + strlen(HTTPS_PROTOCOL) + strlen(fqdn), path);
    LOGD("[network__send_https_post_request] URL: %s", url);

    /* Initialize the HTTP client handler */
    http_client_handle = HTTP_initialize();
    if (!http_client_handle) {
        LOGE("[network__send_https_post_request] Error initializing the HTTP handler");
        M_free(url);
        return eFatal;
    }
    LOGD("[network__send_https_post_request] HTTP client initialized");

    /* Set the URL */
    err = HTTP_set_target_url(http_client_handle, url);
    M_free(url);
    url = NULL;
    if (err < 0) {
        LOGE("[network__send_https_post_request] Error setting the target URL, err %d", err);
        HTTP_cleanup(http_client_handle, headers_list_handle);
        return eFatal;
    }

    /* Set the Request body */
    if ((err = HTTP_set_body(http_client_handle, request_body, request_body_size)) < 0) {
        LOGE("[network__send_https_post_request] Error setting the request body, err %d", err);
        HTTP_cleanup(http_client_handle, headers_list_handle);
        return eFatal;
    }

    /* Set the Request headers */
    if ((tmp = HTTP_add_headers(headers_list_handle, content_length_header)) < 0) {
        LOGE("[network__send_https_post_request] Error setting the Content-Length Header, err %d", err);
        HTTP_cleanup(http_client_handle, headers_list_handle);
        return eFatal;
    }
    headers_list_handle = tmp;
    LOGD("[network__send_https_post_request] Header '%s' set", content_length_header);

    for (i = 0; i < headers_list_size; i++) {
        if ((tmp = HTTP_add_headers(headers_list_handle, headers_list[i])) < 0) {
            LOGE("[network__send_https_post_request] Error setting the Content-Length Header, err %d", err);
            HTTP_cleanup(http_client_handle, headers_list_handle);
            return eFatal;
        }
        headers_list_handle = tmp;
        LOGD("[network__send_https_post_request] Header '%s' set", headers_list[i]);
    }

    if ((err = HTTP_close_headers(http_client_handle, headers_list_handle)) < 0) {
        LOGE("[network__send_https_post_request] Error on close the headers list, err %d", err);
        HTTP_cleanup(http_client_handle, headers_list_handle);
        return eFatal;
    }

    /* Initialize the response buffer */
    response_buffer.memory = M_malloc(1);
    if (!response_buffer.memory) {
        LOGE("[network__send_https_post_request] Can not allocate data to the response buffer");
        HTTP_cleanup(http_client_handle, headers_list_handle);
        return eNoMem;
    }
    response_buffer.size = 0;

    /* Set the response buffer */
    if ((err = HTTP_set_read_callback(http_client_handle, &response_buffer)) < 0) {
        LOGE("[network__send_https_post_request] Error on set th read response callback, err %d", err);
        HTTP_cleanup(http_client_handle, headers_list_handle);
        M_free(response_buffer.memory);
        return eFatal;
    }

    /* Execute the HTTP POST Request */
    http_status =  HTTP_execute(http_client_handle,timeout);
    HTTP_cleanup(http_client_handle, headers_list_handle);
    if (http_status < 0)  {
        LOGE("[network__send_https_post_request] Error executing the post request, err %ld", http_status);
        M_free(response_buffer.memory);
        return eFatal;
    }

    /* Set the results on the output parameters */
    *http_status_code = (int) http_status;
    *response_body = response_buffer.memory;
    *response_body_size = (uint32_t) response_buffer.size;
    
    LOGI("HTTP response status code %ld", *http_status_code);
    LOGD("[network__send_https_post_request] response size: %u", *response_body_size);

    return eOk;
}