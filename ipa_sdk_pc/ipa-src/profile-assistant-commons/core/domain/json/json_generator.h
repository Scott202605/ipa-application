/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"

// Callback declaration to encode byte arrays before are converted to base64 strings
typedef int32_t(*json_generator__opaque_byte_array_encoder_callback_t)(unsigned char* buffer, const uint32_t buffer_size, const void* obj);

/**
 * Add a JSON child with string value to a buffer.
 * ('{'|',') + "<key>:" + "<string value>" + ['}']
 *
 * @param[in, out] buffer Point to the buffer to which the JSON child will be added. If null, the function will only
 * calculate the offset that the buffer would have had if the JSON child had been added.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] offset Offset of the buffer.
 * @param[in] is_first_child True if is the first JSON child to write into the buffer (of the same JSON object).
 * @param[in] is_last_child True if is the last JSON child to write into the buffer (of the same JSON object).
 * @param[in] key null-terminated string with the json key of the child to add.
 * @param[in] value Pointer to the string value of the child to add (can be not null-terminated).
 * @param[in] value_len length of the string value (excluding the null-terminated character).
 *
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t json_generator__add_string_child(unsigned char* buffer, const uint32_t buffer_size, const uint32_t offset, const bool is_first_child, const bool is_last_child, const char* key, const unsigned char* value, const uint32_t value_len);

/**
 * Add a JSON child with number value to a buffer.
 * ('{'|',') + "<key>:" + <numeric value> + ['}']
 *
 * @param[in, out] buffer Point to the buffer to which the JSON child will be added. If null, the function will only
 * calculate the offset that the buffer would have had if the JSON child had been added.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] offset Offset of the buffer.
 * @param[in] is_first_child True if is the first JSON child to write into the buffer (of the same JSON object).
 * @param[in] is_last_child True if is the last JSON child to write into the buffer (of the same JSON object).
 * @param[in] key null-terminated string with the json key of the child to add.
 * @param[in] value Number value of the child to add.
 *
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t json_generator__add_number_child(unsigned char* buffer, const uint32_t buffer_size, const uint32_t offset, const bool is_first_child, const bool is_last_child, const char* key, const int value);

/**
 * Add a JSON child with boolean value to a buffer.
 * ('{'|',') + "<key>:" + ("true"|"false") + ['}']
 *
 * @param[in, out] buffer Point to the buffer to which the JSON child will be added. If null, the function will only
 * calculate the offset that the buffer would have had if the JSON child had been added.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] offset Offset of the buffer.
 * @param[in] is_first_child True if is the first JSON child to write into the buffer (of the same JSON object).
 * @param[in] is_last_child True if is the last JSON child to write into the buffer (of the same JSON object).
 * @param[in] key null-terminated string with the json key of the child to add.
 * @param[in] value Boolean value of the child to add.
 *
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t json_generator__add_boolean_child(unsigned char* buffer, const uint32_t buffer_size, const uint32_t offset, const bool is_first_child, const bool is_last_child, const char* key, const bool value);

/**
 * Add a JSON child with null value to a buffer.
 * ('{'|',') + "<key>:null" + ['}']
 *
 * @param[in, out] buffer Point to the buffer to which the JSON child will be added. If null, the function will only
 * calculate the offset that the buffer would have had if the JSON child had been added.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] offset Offset of the buffer.
 * @param[in] is_first_child True if is the first JSON child to write into the buffer (of the same JSON object).
 * @param[in] is_last_child True if is the last JSON child to write into the buffer (of the same JSON object).
 * @param[in] key null-terminated string with the json key of the child to add.
 *
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t json_generator__add_null_child(unsigned char* buffer, const uint32_t buffer_size, const uint32_t offset, const bool is_first_child, const bool is_last_child, const char* key);

/**
 * Add a JSON child with base64 value to a buffer.
 * ('{'|',') + "<key>:" + "<base64 string value>" + ['}']
 *
 * @param[in, out] buffer Point to the buffer to which the JSON child will be added. If null, the function will only
 * calculate the offset that the buffer would have had if the JSON child had been added.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] offset Offset of the buffer.
 * @param[in] is_first_child True if is the first JSON child to write into the buffer (of the same JSON object).
 * @param[in] is_last_child True if is the last JSON child to write into the buffer (of the same JSON object).
 * @param[in] byte_array Pointer to a byte array that will be converted to a base64 string once written to the output buffer.
 * @param[in] byte_array_size size of the byte array
 *
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t json_generator__add_base64_string_child(unsigned char* buffer, const uint32_t buffer_size, const uint32_t offset, const bool is_first_child, const bool is_last_child, const char* key, const uint8_t* byte_array, const uint32_t byte_array_size);

int32_t json_generator__add_base64_string_child_with_custom_byte_array_encoder(unsigned char* buffer, const uint32_t buffer_size, const uint32_t offset, const bool is_first_child, const bool is_last_child, const char* key, const void* obj_to_encode, json_generator__opaque_byte_array_encoder_callback_t encoder);

/**
 * Add a JSON child with base64 value to a buffer.
 * ('{'|',') + "<key>:" + "<hexadecimal string value>" + ['}']
 * 
 * @param[in, out] buffer Point to the buffer to which the JSON child will be added. If null, the function will only 
 * calculate the offset that the buffer would have had if the JSON child had been added.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] offset Offset of the buffer.
 * @param[in] is_first_child True if is the first JSON child to write into the buffer (of the same JSON object).
 * @param[in] is_last_child True if is the last JSON child to write into the buffer (of the same JSON object).
 * @param[in] byte_array Pointer to a byte array that will be converted to a hexadecimal string once written to the output buffer.
 * @param[in] byte_array_size size of the byte array
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t json_generator__add_hexadecimal_string_child(unsigned char* buffer, const uint32_t buffer_size, const uint32_t offset, const bool is_first_child, const bool is_last_child, const char* key, const uint8_t* byte_array, const uint32_t byte_array_size);

/**
 * Add a JSON child with JSON Object value represented on a string to a buffer.
 * ('{'|',') + "<key>:" + <JSON object string> + ['}']
 * 
 * @param[in, out] buffer Point to the buffer to which the JSON child will be added. If null, the function will only 
 * calculate the offset that the buffer would have had if the JSON child had been added.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] offset Offset of the buffer.
 * @param[in] is_first_child True if is the first JSON child to write into the buffer (of the same JSON object).
 * @param[in] is_last_child True if is the last JSON child to write into the buffer (of the same JSON object).
 * @param[in] key null-terminated string with the json key of the child to add.
 * @param[in] value Pointer to the JSON Object value represented in a string (can be not null-terminated).
 * @param[in] value_len length of the JSON Object string value (excluding the null-terminated character).
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t json_generator__add_json_object_child(unsigned char* buffer, const uint32_t buffer_size, const uint32_t offset, const bool is_first_child, const bool is_last_child, const char* key, const unsigned char* value, const uint32_t value_len);
