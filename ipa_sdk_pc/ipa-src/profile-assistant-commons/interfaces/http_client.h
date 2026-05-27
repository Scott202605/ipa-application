/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 * 
 *  @file http_client.h
 *  @brief http client interface, used to perform all necessary http related functions
 *  
 *  The functions described in this interface needs to be implemented in for each hardware specific
 * 
 *  @author Giesecke+Devrient Mobile Security
 *  @bug No known bugs.
*/
#pragma once
#include "typedefs.h"

struct memory_struct {
    unsigned char* memory;
    size_t size;
};

/**
 * Initializes the http library.
 * 
 * @return The opaque pointer to the http client. It will be NULL if no more memory is available
*/
void* HTTP_initialize();

/**
 * Sets the url of the request into the current client.
 * 
 * @param handle Is the http client handle.
 * @param url Is the url to use.
 * 
 * @return Upon successful execution, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int HTTP_set_target_url(void* handle, const char* url);

/**
 * Adds a header to the header list.
 * 
 * @param headers_list Is the header list handle. If NULL, the header list handle will be created.
 * @param header_value The header to add to the list ("Key: Value").
 * 
 * @return The opaque pointer to the updated header list. It will be NULL if no more memory is available
*/
void* HTTP_add_headers(void* headers_list, const char* header_value);

/**
 * Frees the header list and writes it to the http client memory.
 * 
 * @param handle Is the http client handle.
 * @param headers_list Is the header list handle.
 * 
 * @return Upon successful execution, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int HTTP_close_headers(void* handle, void* headers_list);

/**
 * Writes the body contents to the http client memory.
 * @note to be more performant in embedded systems upon writting the value in to the body some implementations will free the value of the body, it's U.B. if the application uses the value of body again
 * 
 * @param handle Is the http client handle.
 * @param body The pointer to the body contents.
 * @param size The pointer to the size of the body.
 * 
 * @return Upon successful execution, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int HTTP_set_body(void* handle, unsigned char** data, uint32_t* size);

/**
 * Sets a pointer in to the http client memory of where to write the response.
 * 
 * @param handle Is the http client handle.
 * @param chunk The pointer to the response output.
 * 
 * @return Upon successful execution, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int HTTP_set_read_callback(void* handle, struct memory_struct* chunk);

/**
 * Sets a pointer in to the http client memory of where to write the response headers.
 * 
 * @param handle Is the http client handle.
 * @param chunk The pointer to the response output.
 * 
 * @return Upon successful execution, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int HTTP_set_header_callback(void *handle, struct memory_struct* chunk);

/**
 * Executes the POST request given the http client configuration.
 * 
 * @param handle Is the http client handle.
 * 
 * @return The result code.
*/
long HTTP_execute(void* handle,uint32_t timeout);

/**
 * Frees the memory of the http client handle and the headers list handle
 * 
 * @param client_handle Is the http client handle.
 * @param headers_list_handle Is the header list handle.
*/
void HTTP_cleanup(void* client_handle, void* headers_list_handle);

/**
 * Allows different platforms to load their client / server certificates or CA.
 * 
 * @param fd The socket. @note this is only currently used in nordics, but for other platforms this value may be changed
 * @param verify the level of verification.
 * @param hostname the hostname of the request(to set SNI verification).
 * 
 * @return 0 if success.
*/
int HTTP_tls_setup(int fd, int verify, const unsigned char *hostname);
