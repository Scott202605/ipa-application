/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"

#define HTTP_STATUS_CODE_OK         200
#define HTTP_STATUS_CODE_NO_CONTENT 204

/**
 * This function will send a generic HTTP request. * 
 * 
 * @param[in]  fqdn null-terminated string with the FQDN from the server to which the request will be sent.
 * @param[in]  path null-terminated string with the path of the request.
 * @param[in]  headers_list list of null-terminated strings with HTTP headers of the request in format "<key>: <value>".
 * The Content-Length header is set automatically by the function, so it should not be passed as a parameter in the list.
 * @param[in]  headers_list_size Number of elements in the HTTP headers list.
 * @param[in]  request_body points to the body request. It is passed as a double pointer because in some implementations 
 * (hardware-specific) the memory of this pointer can be freed (with M_free()) to allocate memory for the request response. 
 * In case the request body pointer is freed, the request body pointer will point to null (to avoid a double free) after the 
 * funtion execution. Likewise, it is the caller's responsibility to ensure that this pointer is freed.
 * @param[in]  request_body_size points to the size of the request body. In case the request body pointer is freed, the 
 * request body size will point to 0.
 * @param[out] response_body Will point to a byte array with the response body of the request if the function return is success. 
 * The caller is the responsible for freeing the response body byte array by calling the M_free() function.
 * @param[out] response_body_size Will point to the size of the response body byte array if the function return is success.
 * @param[out] http_status_code Will point to the HTTP status code of the request if the function return is success.
 * 
 * @return eOk in case the HTTP request has been executed successfully (regardless of the HTTP status code received). 
 * Otherwise, an error code is returned.
*/
ErrCode network__send_https_post_request(const char* fqdn, const char* path, const char** headers_list, uint32_t headers_list_size, unsigned char** request_body, uint32_t* request_body_size, unsigned char** response_body, uint32_t* response_body_size, int* http_status_code,uint32_t timeout);