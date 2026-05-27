/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"

typedef struct json_array_iterator_s {
    unsigned char* ptr;
    uint32_t size;
    uint32_t offset;
} json_array_iterator_t;

/**
 * This function extracts from a json string, the string value of a key.
 * 
 * @param[in]  str string in JSON format (can be not null-terminated).
 * @param[in]  str_len length of str (excluding the null-terminated character).
 * @param[in]  key null-terminated string with the json key of the value to found.
 * @param[out] value_ptr will point to the beginning of the key value if the function return is success. 
 * This pointer will be pointing inside the str string so do not deallocate the str string while using the pointer.
 * @param[out] value_len will point to the length of the value if the function return is success.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned.
*/
ErrCode json_data_extractor__get_string_value(const unsigned char* str, const uint32_t str_len, const char* key, unsigned char** value_ptr, uint32_t* value_len);

/**
 * This function extracts from a json string, the number value of a key.
 * 
 * @param[in]  str string in JSON format (can be not null-terminated).
 * @param[in]  str_len length of str (excluding the null-terminated character).
 * @param[in]  key null-terminated string with the json key of the value to found.
 * @param[out] value will point to the key value in int format if the function return is success.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned.
*/
ErrCode json_data_extractor__get_int_value(const unsigned char* str, const uint32_t str_len, const char* key, int* value);

/**
 * This function extracts from a json string, the boolean value of a key.
 * 
 * @param[in]  str string in JSON format (can be not null-terminated).
 * @param[in]  str_len length of str (excluding the null-terminated character).
 * @param[in]  key null-terminated string with the json key of the value to found.
 * @param[out] value will point to the key value in bool format if the function return is success.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned.
*/
ErrCode json_data_extractor__get_boolean_value(const unsigned char* str, const uint32_t str_len, const char* key, bool* value);

/**
 * This function extracts from a json string, the object value of a key.
 * 
 * @param[in]  str string in JSON format (can be not null-terminated).
 * @param[in]  str_len length of str (excluding the null-terminated character).
 * @param[in]  key null-terminated string with the json key of the value to found.
 * @param[out] obj_ptr will point to the beginning of the key value (including the '{' charater) if the function return is success. 
 * This pointer will be pointing inside the str string so do not deallocate the str string while using the pointer.
 * @param[out] obj_len will point to the length of the object value (including the '}' charater) if the function return is success.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned.
*/
ErrCode json_data_extractor__get_object_value(const unsigned char* str, const uint32_t str_len, const char* key, unsigned char** obj_ptr, uint32_t* obj_len);

/**
 * This function extracts from a json string, the array value of a key.
 * 
 * @param[in]  str string in JSON format (can be not null-terminated).
 * @param[in]  str_len length of str (excluding the null-terminated character).
 * @param[in]  key null-terminated string with the json key of the value to found.
 * @param[out] array_ptr will point to the beginning of the key value (including the '[' charater) if the function return is success. 
 * This pointer will be pointing inside the str string so do not deallocate the str string while using the pointer.
 * @param[out] array_len will point to the length of the array value (including the ']' charater) if the function return is success.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned.
*/
ErrCode json_data_extractor__get_array_value(const unsigned char* str, const uint32_t str_len, const char* key, unsigned char** array_ptr, uint32_t* array_len);

/**
 * This function initializes a json array iterator which allows to iterate through the different elements of a json array.
 * 
 * @param[in]  str string in JSON format (can be not null-terminated).
 * @param[in]  str_len length of str (excluding the null-terminated character).
 * @param[in]  key null-terminated string with the json key of the value to found.
 * @param[out] array_iterator will populate the json_array_iterator_t structure with the appropriate values to start iterating over 
 * the different elements of the json array if the function return is success. 
 * This pointer will be pointing inside the str string so do not deallocate the str string while using the pointer.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned.
*/
ErrCode json_data_extractor__init_array_iterator(const unsigned char* str, const uint32_t str_len, const char* key, json_array_iterator_t* array_iterator);

/**
 * This function gets the next object element of a json object array.
 * 
 * @param[in, out] array_iterator structure initialized with the funtion json_data_extractor__init_array_iterator(). 
 * If the return of the function is success, the iterator will be updated to take the next value from the array on 
 * the next json_data_extractor__get_next_object_element() call.
 * @param[out] obj_ptr will point to the beginning of the array object element (including the '{' charater) if the function return is success. 
 * This pointer will be pointing inside the initial json string so o not deallocate the json string while using the pointer.
 * This pointer will point to null if no more elements have been found in the array.
 * @param[out] obj_len will point to the length of the array object element (including the '}' charater) if the function return is success.
 * This pointer will point to 0 if no more elements have been found in the array.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned.
*/
ErrCode json_data_extractor__get_next_object_element(json_array_iterator_t* array_iterator, unsigned char** obj_ptr, uint32_t* obj_len);

/**
 * This function return the number of elements inside a json object array.
 * @note This function can be called regardless of whether it has been called before or after the json_data_extractor__get_next_object_element() funtion
 * 
 * @param[in, out] array_iterator structure initialized with the funtion json_data_extractor__init_array_iterator().
 * @param[out] array_size will point to the number of elements inside a json object array.
 * 
 * @return eOk in case the number of elements calculation has been done successfully. Otherwise, an error code is returned.
*/
ErrCode json_data_extractor__get_array_object_size(const json_array_iterator_t* array_iterator, uint32_t* array_size);
