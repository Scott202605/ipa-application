/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include <stdlib.h>

#include "json_data_extractor.h"
#include "log.h"

#define JSON_TRUE   "true"
#define JSON_FALSE  "false"

static unsigned char* json_data_extractor__find_key_value_ptr(const unsigned char* str, const uint32_t str_len, const char* key);
static ErrCode json_data_extractor__find_element_with_boundary_chars(const unsigned char* str, const uint32_t str_len, const char* key, const char c_open, const char c_close, unsigned char** elem_ptr, uint32_t* elem_len);
static unsigned char* json_data_extractor__find_end_quote(const unsigned char* str, const uint32_t str_len, unsigned char* first_quote);
static bool json_data_extractor__is_json_key(const unsigned char* str, const uint32_t str_len, const unsigned char* key_found, const size_t key_len);

ErrCode json_data_extractor__get_string_value(const unsigned char* str, const uint32_t str_len, const char* key, unsigned char** value_ptr, uint32_t* value_len) {
    unsigned char* ptr;
    ptr = json_data_extractor__find_key_value_ptr(str, str_len, key);
    if (!ptr) {
	    LOGD("[json_data_extractor__get_string_value] key '%s' not found", key);
	    return eFatal;
    }
    LOGT("[json_data_extractor__get_string_value] key '%s'", key);

    ptr = memchr(ptr, '\"',  str_len - (ptr - str));
    if (!ptr) {
	    LOGD("[json_data_extractor__get_string_value] character '\"' not found after the key '%s'", key);
	    return eFatal;
    }
    *value_ptr = ptr + 1; // We don't want to have the '"' character
    if (NULL == (ptr = json_data_extractor__find_end_quote(str, str_len, ptr))) {
        LOGD("[json_data_extractor__get_string_value] End quote not found");
        return eFatal;
    }
    *value_len = (uint32_t) (ptr - *value_ptr);
    LOG_UTF8_DATA(eLogTrace, "[json_data_extractor__get_string_value] Value: ", *value_ptr, *value_len);

    return eOk;
}

ErrCode json_data_extractor__get_int_value(const unsigned char* str, const uint32_t str_len, const char* key, int* value) {
    char number_buffer[20] = { 0 };
    uint8_t number_len = 0;
    unsigned char* ptr;
    
    ptr = json_data_extractor__find_key_value_ptr(str, str_len, key);
    if (!ptr) {
	    LOGD("[json_data_extractor__get_int_value] key '%s' not found", key);
	    return eFatal;
    }
    LOGT("[json_data_extractor__get_int_value] key '%s'", key);

    /* Find the first numeric character */
    while (ptr < str + str_len && *ptr != '-' && *ptr > '0' && *ptr < '9') {
        ptr++; 
    }

    /* Check boundaries*/
    if (ptr >= str + str_len) {
        LOGE("[json_data_extractor__get_int_value] First numeric character not found");
        return eFatal;
    }

    /* Copy the numeric characters until we find a non numberic character (exponent of 10 not supported and decimal not need it since the result is a integer) */
    do {
        number_buffer[number_len++] = *(ptr++);
    } while (number_len < sizeof(number_buffer) - 1 && ptr < str + str_len && *ptr >= '0' && *ptr <= '9');

    /* Check boundaries*/
    if (ptr >= str + str_len) {
        LOGE("[json_data_extractor__get_int_value] Last non numeric character is out of boundaries");
        return eFatal;
    }

    /* Parse the number string to integer */
    *value = atoi(number_buffer);
    LOGT("[json_data_extractor__get_int_value] Value: %d", *value);
    
    return eOk;
}

ErrCode json_data_extractor__get_boolean_value(const unsigned char* str, const uint32_t str_len, const char* key, bool* value) {
    unsigned char* ptr;
    
    ptr = json_data_extractor__find_key_value_ptr(str, str_len, key);
    if (!ptr) {
	    LOGD("[json_data_extractor__get_boolean_value] key '%s' not found", key);
	    return eFatal;
    }
    LOGT("[json_data_extractor__get_boolean_value] key '%s'", key);

    /* Find the first boolean character */
    while (ptr < str + str_len && *ptr != '0' && *ptr != '1' && *ptr != 'f' && *ptr != 't' ) {
        ptr++; 
    }

    /* Check boundaries*/
    if (ptr >= str + str_len) {
        LOGE("[json_data_extractor__get_boolean_value] First boolean character not found");
        return eFatal;
    }

    /* Handle the 4 options of boolean representation*/
    if ('0' == *ptr) {
        *value = false;
    } else if ('1' == *ptr) {
        *value = true;
    } else if ('t' == *ptr) {
        if (ptr + sizeof(JSON_TRUE) - 1 < str + str_len && 0 == memcmp(JSON_TRUE, ptr, sizeof(JSON_TRUE) - 1)) {
            *value = true;
        } else {
            LOGD("[json_data_extractor__get_boolean_value] '%s' string value not found", JSON_TRUE);
            return eFatal;
        }
    } else {
        if (ptr + sizeof(JSON_FALSE) - 1 < str + str_len && 0 == memcmp(JSON_FALSE, ptr, sizeof(JSON_FALSE) - 1)) {
            *value = false;
        } else {
            LOGD("[json_data_extractor__get_boolean_value] '%s' string value not found", JSON_FALSE);
            return eFatal;
        }
    }
    LOGT("[json_data_extractor__get_boolean_value] Value: %s", *value ? JSON_TRUE : JSON_FALSE);

    return eOk;
}

//Lets suppose that don't have '{' or '}' char inside a string
ErrCode json_data_extractor__get_object_value(const unsigned char* str, const uint32_t str_len, const char* key, unsigned char** obj_ptr, uint32_t* obj_len) {
    return json_data_extractor__find_element_with_boundary_chars(str, str_len, key, '{', '}', obj_ptr, obj_len);
}

ErrCode json_data_extractor__get_array_value(const unsigned char* str, const uint32_t str_len, const char* key, unsigned char** array_ptr, uint32_t* array_len) {
    return json_data_extractor__find_element_with_boundary_chars(str, str_len, key, '[', ']', array_ptr, array_len);
}

ErrCode json_data_extractor__init_array_iterator(const unsigned char* str, const uint32_t str_len, const char* key, json_array_iterator_t* array_iterator) {
    if (!array_iterator) {
        LOGE("[json_data_extractor__init_array_iterator] The JSON array iterator is NULL");
        return eBadArg;
    }
    array_iterator->offset = 0;
    return json_data_extractor__get_array_value(str, str_len, key, &array_iterator->ptr, &array_iterator->size);
}

ErrCode json_data_extractor__get_next_object_element(json_array_iterator_t* array_iterator, unsigned char** obj_ptr, uint32_t* obj_len) {
    if (!array_iterator) {
        LOGE("[json_data_extractor__get_next_object_element] The JSON array iterator is NULL");
        return eBadArg;
    }
    LOGT("[json_data_extractor__get_next_object_element] ptr(%p), size(%u), offset(%u)", array_iterator->ptr, array_iterator->size, array_iterator->offset);

    // Return NULL if there is no more elements in the list
    if (array_iterator->offset >= array_iterator->size) {
        *obj_ptr = NULL;
        *obj_len = 0;
        return eOk;
    }

    if (json_data_extractor__get_object_value(array_iterator->ptr + array_iterator->offset, array_iterator->size - array_iterator->offset, NULL, obj_ptr, obj_len) == eOk) {
        array_iterator->offset = (uint32_t) (*obj_ptr - array_iterator->ptr) + *obj_len; // Update the offset to serach the next object in the next call
        LOGT("[json_data_extractor__get_next_object_element] Element found, offset updated to %u", array_iterator->offset);
    } else {
        LOGT("[json_data_extractor__get_next_object_element] Next element not found");
        array_iterator->offset = array_iterator->size; // Update the offset to avoid search again if the funtion is recalled
        *obj_ptr = NULL;
        *obj_len = 0;
    }

    return eOk;
}

ErrCode json_data_extractor__get_array_object_size(const json_array_iterator_t* array_iterator, uint32_t* array_size) {
    json_array_iterator_t it;
    unsigned char* ptr;
    uint32_t size;
    ErrCode rc;
    *array_size = 0;

    if (!array_iterator) {
        LOGE("[json_data_extractor__get_array_object_size] The array iterator object is NULL");
        return eBadArg;
    }
    memcpy(&it, array_iterator, sizeof(json_array_iterator_t)); // Copy the input iterator to not modify it
    it.offset = 0;

    /* Count all the objects of the JSON array */
    while ((rc = json_data_extractor__get_next_object_element(&it, &ptr, &size)) == eOk && ptr && size > 0) {
        (*array_size)++;
    }

    if (rc != eOk) {
        LOGE("[json_data_extractor__get_array_object_size] Error on get the next element object, rc %d");
    }

    return rc;
}

// The return will point to the charachter after '"<key>" :' if find any, otherwise will return null
static unsigned char* json_data_extractor__find_key_value_ptr(const unsigned char* str, const uint32_t str_len, const char* key) {
    unsigned char* ptr;
    size_t key_len = strlen(key);

    // Search the key string
    if (NULL == (ptr = S_memmem(str, (size_t) str_len, key, key_len))) {
        LOGD("[json_data_extractor__find_key_value_ptr] Key '%s' not found", key);
        return NULL;
    }

    // Validate that has the JSON key format
    if (!json_data_extractor__is_json_key(str, str_len, ptr, key_len)) {
        LOGD("[json_data_extractor__find_key_value_ptr] The key found has not a valid format");
        return NULL;
    }

    // Search the ':' charcater after the key
    if (NULL == (ptr = memchr(ptr, ':',  str_len - (ptr - str)))) {
        LOGD("[json_data_extractor__find_key_value_ptr] ':' character not found");
        return NULL;
    }
    
    ptr++; // Discard the ':' character
    if (ptr >= str + str_len) {
        LOGD("[json_data_extractor__find_key_value_ptr] character after the ':' is out of boundaries");
        return NULL;
    }

    return ptr;
}

static ErrCode json_data_extractor__find_element_with_boundary_chars(const unsigned char* str, const uint32_t str_len, const char* key, const char c_open, const char c_close, unsigned char** elem_ptr, uint32_t* elem_len) {
    unsigned char* ptr = NULL;
    const unsigned char* last_ptr = str + str_len;
    uint32_t open_elem_count;
    
    if (key) {
        ptr = json_data_extractor__find_key_value_ptr(str, str_len, key);
        if (!ptr) {
            LOGD("[json_data_extractor__find_element_with_boundary_chars] key '%s' not found", key);
            return eFatal;
        }
        LOGT("[json_data_extractor__find_element_with_boundary_chars] key '%s'", key);
    }

    // Search the open charcater
    if (NULL == (ptr = memchr(key ? ptr : str, c_open,  key ? str_len - (ptr - str) : str_len))) {
        LOGD("[json_data_extractor__find_element_with_boundary_chars] open character '%c' not found", c_open);
        return eFatal;
    }

    *elem_ptr = ptr; //We want to have the open character
    open_elem_count = 1;
    for (ptr++; ptr < last_ptr; ptr++) {
        if (c_open == *ptr) {
            open_elem_count++;
        } else if (c_close == *ptr) {
            open_elem_count--;
            if (0 == open_elem_count) {
                *elem_len = (uint32_t) (ptr - *elem_ptr + 1); //We want to have the close character
                LOG_UTF8_DATA(eLogTrace, "[json_data_extractor__find_element_with_boundary_chars] Value: ", *elem_ptr, *elem_len);
                return eOk;
            } 
        }
    }
    LOGD("[json_data_extractor__find_element_with_boundary_chars] close character '%c' not found", c_close);

    return eFatal;
}

static unsigned char* json_data_extractor__find_end_quote(const unsigned char* str, const uint32_t str_len, unsigned char* start_quote) {
    unsigned char* ptr;
    
    if (!str || !start_quote || str_len == 0 || start_quote < str || start_quote >= str + str_len) {
	    return NULL;
    }
    
    ptr = start_quote;
    while (ptr != NULL) {
        ptr++; // Discard the current quote to search the next one
        LOGT("[json_data_extractor__find_end_quote] str %p, str_len %u, ptr %p", str, str_len, ptr);
        // Check that the boundaries are valid
        if (ptr >= str + str_len) {
            LOGD("[json_data_extractor__find_end_quote] End of the str buffer reached before found the end quote");
            return NULL;
        }
        //Search the next quote
        if (NULL != (ptr = memchr(ptr, '\"', str_len - (ptr - str)))) {
            //Check that is not an internal quote otherwise search for the next
            if ('\\' != *(ptr - 1)) {
                LOGT("[json_data_extractor__find_end_quote] Second quote found at %p", ptr);
                return ptr;
            }
        }
    }
    LOGD("[json_data_extractor__find_end_quote] End quote not found");
    
    return NULL;
}

static bool json_data_extractor__is_json_key(const unsigned char* str, const uint32_t str_len, const unsigned char* key_found, const size_t key_len) {
    LOGT("[json_data_extractor__is_json_key] str %p, str_len %u, key_found %p, key_len %u", str, str_len, key_found, key_len);
    /* Check bounds to avoid a segmentation fault on key quote checks*/
    if (key_found <= str || key_found + key_len >= str + str_len) {
        LOGD("[json_data_extractor__is_json_key] The key found is out of key check bounds");
        return false;
    }

    /* Check if the parameter key is already sorrounded by quotes */
    if ('\"' == key_found[0] && '\"' == key_found[key_len - 1]) {
        return true;
    }

    /* Check that the JSON key found is sorrounded by quotes */
    if (*(key_found - 1) != '\"' || key_found[key_len] != '\"') {
        LOGD("[json_data_extractor__is_json_key] The key found is not sorrounded by quotes");
        return false;
    }

    return true;
}
