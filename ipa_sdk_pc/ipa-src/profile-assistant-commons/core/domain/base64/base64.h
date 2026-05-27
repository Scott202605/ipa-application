/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"

/**
 * Base64 encoder function
 * 
 * @param[in, out] buffer Pointer to a buffer in which the base64 encoded bytes will be written. If null, the function will only calculate the base64 encoded size.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] src Data to be encoded. Can be null if the function will only calculate the base64 encoded size.
 * @param[in] len Length of the data to be encoded.
 * 
 * @return Upon successful execution, will return the base64 encoded size.
 * If an output error is encountered, a negative value is returned.
 */
int32_t base64__encode(unsigned char* buffer, const uint32_t buffer_size, const unsigned char* src, const uint32_t len);

/**
 * Base64 decoder funtion
 * 
 * @param[in, out] buffer Pointer to a buffer in which the base64 decoded bytes will be written. If null, the function will only calculate the base64 decoded size.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] src Data to be decoded.
 * @param[in] len Length of the data to be decoded.
 * 
 * @return Upon successful execution, will return the base64 decoded size.
 * If an output error is encountered, a negative value is returned.
 */
int32_t base64__decode(unsigned char* buffer, const uint32_t buffer_size, const unsigned char* src, const uint32_t len);
