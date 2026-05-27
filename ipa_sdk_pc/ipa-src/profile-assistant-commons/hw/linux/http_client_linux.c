/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include <curl/curl.h>

#include "http_client.h"
#include "memory_manager.h"
#include "log.h"



static size_t write_memory_callback(void* contents, size_t size, size_t nmemb, void* userp);

void* HTTP_initialize() {
    curl_global_init(CURL_GLOBAL_ALL);
    return curl_easy_init();
}

int HTTP_set_target_url(void* handle, const char* url) {   
    CURLcode rc = curl_easy_setopt((CURL*) handle, CURLOPT_URL, url);
    if (rc != CURLE_OK) {
        LOGE("[HTTP_set_target_url] Error on set the URL, rc %d", rc);
        return -rc;
    }
    return 0;
}

void* HTTP_add_headers(void* headers_list, const char* header_value) {
    //Temporary variable to avoid overwriting an existing non-empty list
    struct curl_slist* updated_list = curl_slist_append((struct curl_slist*) headers_list, header_value);
    if (NULL == updated_list) {
        LOGE( "[HTTP_add_headers] Memory error when adding a HTTP header to the headers list");
    }
    return (void*) updated_list;
}

int HTTP_close_headers(void* handle, void* headers_list) {
    /* set our set of headers to the client handle */
    CURLcode rc = curl_easy_setopt((CURL*) handle, CURLOPT_HTTPHEADER, (struct curl_slist*) headers_list);
    if (rc != CURLE_OK) {
        LOGE("[HTTP_close_headers] Error on set the headers list, rc %d", rc);
        return -rc;
    }
    return 0;
}

int HTTP_set_body(void* handle, unsigned char** data, uint32_t* size) {
    CURLcode rc = curl_easy_setopt((CURL*) handle, CURLOPT_POSTFIELDS, *data);
    if (rc != CURLE_OK) {
        LOGE("[HTTP_set_body] Error on set the request body pointer, rc %d", rc);
        return -rc;
    }

    rc = curl_easy_setopt((CURL*) handle, CURLOPT_POSTFIELDSIZE,  (long)*size); // Also available CURLOPT_POSTFIELDSIZE_LARGE
    if (rc != CURLE_OK) {
        LOGE("[HTTP_set_body] Error on set the request body size, rc %d", rc);
        return -rc;
    }

    return 0;
}

int HTTP_set_read_callback(void* handle, struct memory_struct* chunk) {
    CURLcode rc = curl_easy_setopt((CURL*) handle, CURLOPT_WRITEFUNCTION, write_memory_callback);
    if (rc != CURLE_OK) {
        LOGE("[HTTP_set_read_callback] Error on set the response body write memory callback function, rc %d", rc);
        return -rc;
    }

    rc = curl_easy_setopt((CURL*) handle, CURLOPT_WRITEDATA, (void*) chunk);
    if (rc != CURLE_OK) {
        LOGE("[HTTP_set_read_callback] Error on set the write data buffer, rc %d", rc);
        return -rc;
    }

    return 0;
}

int HTTP_set_header_callback(void *handle, struct memory_struct* chunk) {
    CURLcode rc = curl_easy_setopt((CURL*) handle, CURLOPT_HEADERFUNCTION, write_memory_callback);
    if (rc != CURLE_OK) {
        LOGE("[HTTP_set_header_callback] Error on set the response headers write memory callback function, rc %d", rc);
        return -rc;
    }

    rc = curl_easy_setopt((CURL*) handle, CURLOPT_HEADERDATA, (void*) chunk);
    if (rc != CURLE_OK) {
        LOGE("[HTTP_set_header_callback] Error on set the header data buffer, rc %d", rc);
        return -rc;
    }

    return 0;
}

long HTTP_execute(void* handle,uint32_t timeout) {
    long code = -1;
    char errbuf[CURL_ERROR_SIZE] = { 0 };
    CURLcode rc;
    size_t len;

    /* Set a timeout */
    rc = curl_easy_setopt((CURL*) handle, CURLOPT_TIMEOUT,  timeout); // The default value is 0 which means it never times out during transfer.
    if (rc != CURLE_OK) {
        LOGE("[HTTP_execute] Error on set the timeout, rc %d", rc);
        return -rc;
    }

    /** TODO: Modify the HTTP interface to allow server authentication */
    rc = curl_easy_setopt((CURL*) handle, CURLOPT_SSL_VERIFYHOST, 0L); // The default value is 2
    if (rc != CURLE_OK) {
        LOGE("[HTTP_execute] Error on disable certificate's name verification against host, rc %d", rc);
        return -rc;
    }
    rc = curl_easy_setopt((CURL*) handle, CURLOPT_SSL_VERIFYPEER, 0L); // The default value is 1
    if (rc != CURLE_OK) {
        LOGE("[HTTP_execute] Error on disable peer's SSL certificate verification, rc %d", rc);
        return -rc;
    }

    rc = curl_easy_setopt((CURL*) handle, CURLOPT_ERRORBUFFER, errbuf);
    if (rc != CURLE_OK) {
        LOGE("[HTTP_execute] Error on set the error buffer for error messages, rc %d", rc);
        return -rc;
    }

    /* perform the request */
    rc = curl_easy_perform((CURL*) handle);
    /* if the request did not complete correctly, show the error
    information. if no detailed error information was written to errbuf
    show the more generic information from curl_easy_strerror instead.
    */
    if (rc != CURLE_OK) {
        LOGE("[HTTP_execute] curl_easy_perform failed: %d", rc);
        if ((len = strlen(errbuf))) {
            LOGE("[HTTP_execute] %s", errbuf, ((errbuf[len - 1] != '\n') ? "\n" : ""));
        }
        else {
            LOGE("[HTTP_execute] %s", curl_easy_strerror(rc));
        }
        return -rc;
    }

    /* Retrieve the response code */
    rc = curl_easy_getinfo((CURL*) handle, CURLINFO_RESPONSE_CODE, &code);
    if (rc != CURLE_OK) {
        LOGE("[HTTP_execute] Error retrieving the response code from the handle, rc %d", rc);
        return -rc;
    }

    return code;
}

__attribute__((__weak__)) int HTTP_tls_setup(int fd, int verify, const unsigned char *hostname) {
    // NOTE: When HTTP TLS is going to be use, this function should be implemented 
    return 0;
}

void HTTP_cleanup(void* client_handle, void* headers_list_handle) {
    curl_easy_cleanup((CURL*) client_handle);
    curl_slist_free_all(headers_list_handle);
}

static size_t write_memory_callback(void* contents, size_t size, size_t nmemb, void* userp) {
    size_t realsize = size * nmemb;
    struct memory_struct* mem = (struct memory_struct*) userp;

    unsigned char* ptr = M_realloc(mem->memory, mem->size + realsize);
    if (ptr == NULL) {
        /* out of memory! */
        LOGE("[write_memory_callback] Memory error when realloc ptr");
        return 0;
    }

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;

    return realsize;
}