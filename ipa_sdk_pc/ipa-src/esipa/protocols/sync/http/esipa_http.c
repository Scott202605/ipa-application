#ifdef ENABLE_HTTP_ESIPA
#include "typedefs.h"
#include "esipa_http.h"
#include "esipa.h"
#include "network.h"
#include "memory_manager.h"
#include "log.h"

#define HTTP_GSMA_ASN1_PATH "/gsma/rsp2/asn1"

#define ESIPA_HTTP_USER_AGENT_HEADER          "User-Agent: gsma-rsp-ipad"
#define ESIPA_HTTP_X_ADMIN_PROTOCOL_HEADER    "X-Admin-Protocol: gsma/rsp/v2.1.0"
#define ESIPA_HTTP_CONTENT_TYPE_JSON_HEADER   "Content-Type: application/json;charset=UTF-8"
#define ESIPA_HTTP_CONTENT_TYPE_ASN1_HEADER   "Content-Type: application/x-gsma-rsp-asn1"

/* Subclass implementation of the parent virtual functions */
static ErrCode esipa_http__send_message(esipa_sync_t* const me, const char* path, uint8_t** request_body, uint32_t* request_body_size, uint8_t** response_body, uint32_t* response_body_size);

void esipa_http__ctor(esipa_http_t * const me, char* fqdn, uint32_t max_time_without_transmission, gsma_data_binding_t data_binding, uint32_t http_timeout, uint32_t sync_sleep_time) {
    static struct esipa_sync_vtbl_s const vtbl = {  /* vtbl of the ESipa Sync class */
        &esipa_http__send_message
    };
    esipa_sync__ctor(&me->super, NULL, 0, fqdn, NULL, 0, max_time_without_transmission, data_binding,sync_sleep_time);
    me->super.vptr = &vtbl; /* override the vptr */
    me->http_timeout = http_timeout;
}

void esipa_http__destroy(esipa_http_t * const me) {
    esipa_sync__destroy((esipa_sync_t*) me);
}

static ErrCode esipa_http__send_message(esipa_sync_t* const me, const char* path, uint8_t** request_body, uint32_t* request_body_size, uint8_t** response_body, uint32_t* response_body_size) {
    ErrCode rc;
    int http_status_code = 0;
    const gsma_data_binding_t data_binding = esipa__get_data_binding((esipa_t*) me);
    /* Create the headers list */
    const char* http_headers_list[] = { 
        ESIPA_HTTP_USER_AGENT_HEADER, 
        ESIPA_HTTP_X_ADMIN_PROTOCOL_HEADER, 
        ASN1_DATA_BINDING == data_binding ? ESIPA_HTTP_CONTENT_TYPE_ASN1_HEADER : ESIPA_HTTP_CONTENT_TYPE_JSON_HEADER 
    };
    /* Change the endpoint path in case of ASN.1 data binding */
    const char* real_path = ASN1_DATA_BINDING == data_binding ? HTTP_GSMA_ASN1_PATH : path;
    const char* fqdn = esipa__get_fqdn((esipa_t*) me);
    
    /* Check input parameters */
    if (!fqdn) {
        LOGE("[esipa_http__send_message] The FQDN is null");
        return eBadArg;
    }
    if (!path) {
        LOGE("[esipa_http__send_message] The HTTP Path is null");
        return eBadArg;
    }
    if (!request_body) {
        LOGE("[esipa_http__send_message] The HTTP request body pointer is null");
        return eBadArg;
    }
    if (!request_body_size) {
        LOGE("[esipa_http__send_message] The HTTP request body size pointer is null");
        return eBadArg;
    }
    if (!(*request_body) || *request_body_size == 0) {
        LOGE("[esipa_http__send_message] The HTTP Request Body is empty/null");
        return eBadArg;
    }
    if (!response_body) {
        LOGE("[esipa_http__send_message] The HTTP response body pointer is null");
        return eBadArg;
    }
    if (!response_body_size) {
        LOGE("[esipa_http__send_message] The HTTP response body size pointer is null");
        return eBadArg;
    }

    /* Initialize output parameters */
    *response_body = NULL;
    *response_body_size = 0;

    /* Log request data */
    LOGI("[HTTP] Sending an HTTP request to %s%s", fqdn, real_path);
    switch (data_binding)
    {
    case ASN1_DATA_BINDING:
#ifdef DEBUG_ESIPA
        LOG_DATA(eLogInfo, "ESipa >>", *request_body, *request_body_size);
#else
        LOG_DATA(eLogDebug, "[esipa_http__send_message] Request body", *request_body, *request_body_size);
#endif
        break;
    case JSON_DATA_BINDING:
#ifdef DEBUG_ESIPA
        LOG_UTF8_DATA(eLogInfo, "ESipa >>\n", *request_body, *request_body_size);
#else
        LOG_UTF8_DATA(eLogDebug, "[esipa_http__send_message] Request body\n", *request_body, *request_body_size);
#endif
        break;
    default:
        LOGE("[esipa_http__send_message] Unknown request data binding %d", data_binding);
        return eFatal;
    }

    /* Send the HTTP POST request */
    if ((rc = network__send_https_post_request(fqdn, real_path, http_headers_list, sizeof(http_headers_list) / sizeof(char*), (unsigned char**) request_body, request_body_size, (unsigned char**) response_body, response_body_size, &http_status_code,((esipa_http_t *)me)->http_timeout)) != eOk) {
        LOGE("[esipa_http__send_message] Error on send the ESipa HTTP POST request, rc %d", rc);
        return rc;
    }

    /* Log response data */
    LOGD("[esipa_http__send_message] HTTP Status code %d", http_status_code);
    switch (data_binding)
    {
    case ASN1_DATA_BINDING:
#ifdef DEBUG_ESIPA
        LOG_DATA(eLogInfo, "ESipa <<", *response_body, *response_body_size);
#else
        LOG_DATA(eLogDebug, "[esipa_http__send_message] Response body", *response_body, *response_body_size);
#endif
        break;
    case JSON_DATA_BINDING:
#ifdef DEBUG_ESIPA
        LOG_UTF8_DATA(eLogInfo, "ESipa <<\n", *response_body, *response_body_size);
#else
        LOG_UTF8_DATA(eLogDebug, "[esipa_http__send_message] Response body\n", *response_body, *response_body_size);
#endif
        break;
    default:
        LOGE("[esipa_http__send_message] Unknown response data binding %d", data_binding);
        M_free(*response_body);
        *response_body = NULL;
        *response_body_size = 0;
        return eFatal;
    }

    /* Check the HTTP Status Code */
    if (http_status_code != HTTP_STATUS_CODE_OK && http_status_code != HTTP_STATUS_CODE_NO_CONTENT) {
        LOGE("[esipa_http__send_message] The HTTP status code %d is neither %d nor %d.", http_status_code, HTTP_STATUS_CODE_OK, HTTP_STATUS_CODE_NO_CONTENT);
        M_free(*response_body);
        *response_body = NULL;
        *response_body_size = 0;
        return eFatal;
    }

    // Should we check that the "X-Admin-Protocol" header field SHALL be set to v2.1.0 in the HTTP response?

    return eOk;
}
#endif