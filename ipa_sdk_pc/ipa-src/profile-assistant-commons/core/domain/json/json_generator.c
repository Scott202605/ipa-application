/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include <stdio.h>
#include "json_generator.h"
#include "base64.h"
#include "byte_utils.h"
#include "log.h"
#include "memory_manager.h"

#define JSON_BOOLEAN_TRUE_VALUE		"true"
#define JSON_BOOLEAN_FALSE_VALUE	"false"
#define JSON_NULL_VALUE				"null"
#define JSON_NUMBER_MAX_CHARS		20

typedef int32_t(*json_generator__encode_value_callback_t)(unsigned char* buffer, const uint32_t buffer_size, const uint32_t offset, const unsigned char* value_to_encode, uint32_t value_to_encode_len); // Callback declaration to encode JSON values

static int32_t json_generator__add_child(unsigned char* buffer, const uint32_t buffer_size, uint32_t offset, const bool is_first_child, const bool is_last_child, const char* key, const unsigned char* value, const uint32_t value_len, const bool value_has_quotes, json_generator__encode_value_callback_t encode_function);
static int32_t json_generator__add_json_key(unsigned char* buffer, const uint32_t buffer_size, uint32_t offset, const char* key);
static int32_t json_generator__add_json_value(unsigned char* buffer, const uint32_t buffer_size, uint32_t offset, const unsigned char* value, const uint32_t value_len, const bool add_double_quotes, json_generator__encode_value_callback_t encode_function);
static int32_t json_generator__add_character(unsigned char* buffer, const uint32_t buffer_size, const uint32_t offset, const char c);
// Functions that encode values
static int32_t json_generator__encode_base64(unsigned char* buffer, const uint32_t buffer_size, const uint32_t offset, const unsigned char* value_to_encode, uint32_t value_to_encode_len);
static int32_t json_generator__encode_hexadecimal_string(unsigned char* buffer, const uint32_t buffer_size, const uint32_t offset, const unsigned char* value_to_encode, uint32_t value_to_encode_len);

int32_t json_generator__add_string_child(unsigned char* buffer, const uint32_t buffer_size, const uint32_t offset, const bool is_first_child, const bool is_last_child, const char* key, const unsigned char* value, const uint32_t value_len) {
	return json_generator__add_child(buffer, buffer_size, offset, is_first_child, is_last_child, key, value, value_len, true, NULL);
}

int32_t json_generator__add_number_child(unsigned char* buffer, const uint32_t buffer_size, const uint32_t offset, const bool is_first_child, const bool is_last_child, const char* key, const int value) {
	char value_str[JSON_NUMBER_MAX_CHARS] = { 0 }; // Max length value
	int value_str_len;

	value_str_len = snprintf(value_str, sizeof(value_str), "%d", value);
	if (value_str_len < 0) {
		LOGE("[json_generator__add_number_child] Error converting the integer to string, %d", value_str_len);
		return -eFatal;
	}

	return json_generator__add_child(buffer, buffer_size, offset, is_first_child, is_last_child, key, (unsigned char*) value_str, value_str_len, false, NULL);
}

int32_t json_generator__add_boolean_child(unsigned char* buffer, const uint32_t buffer_size, const uint32_t offset, const bool is_first_child, const bool is_last_child, const char* key, const bool value) {
	const char* value_str = value ? JSON_BOOLEAN_TRUE_VALUE : JSON_BOOLEAN_FALSE_VALUE;

	return json_generator__add_child(buffer, buffer_size, offset, is_first_child, is_last_child, key, (unsigned char*) value_str, (uint32_t) strlen(value_str), false, NULL);
}

int32_t json_generator__add_null_child(unsigned char* buffer, const uint32_t buffer_size, const uint32_t offset, const bool is_first_child, const bool is_last_child, const char* key) {
	const char* value_str = JSON_NULL_VALUE;

	return json_generator__add_child(buffer, buffer_size, offset, is_first_child, is_last_child, key, (unsigned char*) value_str, (uint32_t) strlen(value_str), false, NULL);
}

int32_t json_generator__add_base64_string_child(unsigned char* buffer, const uint32_t buffer_size, const uint32_t offset, const bool is_first_child, const bool is_last_child, const char* key, const uint8_t* byte_array, const uint32_t byte_array_size) {
    return json_generator__add_child(buffer, buffer_size, offset, is_first_child, is_last_child, key, (unsigned char*) byte_array, byte_array_size, true, &json_generator__encode_base64);
}

int32_t json_generator__add_base64_string_child_with_custom_byte_array_encoder(unsigned char* buffer, const uint32_t buffer_size, const uint32_t offset, const bool is_first_child, const bool is_last_child, const char* key, const void* obj_to_encode, json_generator__opaque_byte_array_encoder_callback_t encoder) {
	uint8_t* byte_array_buffer = NULL;
    int32_t byte_array_buffer_size = 0;
    int32_t buffer_offset = 0;

    // Calculate the size of the encoded byte array
    if ((byte_array_buffer_size = encoder(byte_array_buffer, byte_array_buffer_size, obj_to_encode)) < 0) {
        LOGE("[json_generator__add_base64_string_child_with_custom_byte_array_encoder] Error calculating the size of the encoded byte array buffer, err %ld", byte_array_buffer_size);
        return eFatal;
    }
    LOGD("[json_generator__add_base64_string_child_with_custom_byte_array_encoder] encoded byte array calculed size: %ld", byte_array_buffer_size);

    if (buffer) { // Encode in memory the ASN.1 byte array only in case we will write the JSON child
        LOGD("[json_generator__add_base64_string_child_with_custom_byte_array_encoder] Encoding the byte array to be added as a base64 JSON child");
        byte_array_buffer = M_malloc(byte_array_buffer_size);
        if (!byte_array_buffer) {
            LOGE("[json_generator__add_base64_string_child_with_custom_byte_array_encoder] Can not allocate data to the byte array buffer");
            return eNoMem;
        }

        if ((byte_array_buffer_size = encoder(byte_array_buffer, byte_array_buffer_size, obj_to_encode)) < 0) {
            LOGE("[json_generator__add_base64_string_child_with_custom_byte_array_encoder] Error on writing the byte array buffer content, err %ld", byte_array_buffer_size);
            M_free(byte_array_buffer);
            return eFatal;
        }
        LOG_DATA(eLogTrace, "[json_generator__add_base64_string_child_with_custom_byte_array_encoder] byte array buffer generated", byte_array_buffer, byte_array_buffer_size);
    }

    buffer_offset = json_generator__add_base64_string_child(buffer, buffer_size, offset, is_first_child, is_last_child, key, byte_array_buffer, byte_array_buffer_size);
    M_free(byte_array_buffer);
    if (buffer_offset < 0) {
        LOGE("[json_generator__add_base64_string_child_with_custom_byte_array_encoder] Error on add the base64 JSON child, err %ld", byte_array_buffer_size);
    }

    return buffer_offset;
}

int32_t json_generator__add_hexadecimal_string_child(unsigned char* buffer, const uint32_t buffer_size, const uint32_t offset, const bool is_first_child, const bool is_last_child, const char* key, const uint8_t* byte_array, const uint32_t byte_array_size) {
    return json_generator__add_child(buffer, buffer_size, offset, is_first_child, is_last_child, key, (unsigned char*) byte_array, byte_array_size, true, &json_generator__encode_hexadecimal_string);
}

int32_t json_generator__add_json_object_child(unsigned char* buffer, const uint32_t buffer_size, const uint32_t offset, const bool is_first_child, const bool is_last_child, const char* key, const unsigned char* value, const uint32_t value_len) {
	return json_generator__add_child(buffer, buffer_size, offset, is_first_child, is_last_child, key, value, value_len, false, NULL);
}

static int32_t json_generator__add_child(unsigned char* buffer, const uint32_t buffer_size, uint32_t offset, const bool is_first_child, const bool is_last_child, const char* key, const unsigned char* value, const uint32_t value_len, const bool value_has_quotes, json_generator__encode_value_callback_t encode_function) {
	int32_t buffer_offset = (int32_t) offset;

	if ((buffer_offset = json_generator__add_character(buffer, buffer_size, (uint32_t) buffer_offset, is_first_child ? '{' : ',')) < 0) {
		LOGE("[json_generator__add_child] Error on first character, err %d", buffer_offset);
		return buffer_offset;
	}
	LOGT("[json_generator__add_child] Offset after the first character %d", buffer_offset);

	if ((buffer_offset = json_generator__add_json_key(buffer, buffer_size, (uint32_t) buffer_offset, key)) < 0) {
		LOGE("[json_generator__add_child] Error on JSON key, err %d", buffer_offset);
		return buffer_offset;
	}
	LOGT("[json_generator__add_child] Offset after the key %d", buffer_offset);

	if ((buffer_offset = json_generator__add_json_value(buffer, buffer_size, (uint32_t) buffer_offset, value, value_len, value_has_quotes, encode_function)) < 0) {
		LOGE("[json_generator__add_child] Error on JSON value, err %d", buffer_offset);
		return buffer_offset;
	}
	LOGT("[json_generator__add_child] Offset after the value %d", buffer_offset);

	if (is_last_child) {
		if ((buffer_offset = json_generator__add_character(buffer, buffer_size, (uint32_t) buffer_offset, '}')) < 0) {
			LOGE("[json_generator__add_child] Error on close child character, err %d", buffer_offset);
			return buffer_offset;
		}
	}
	LOGT("[json_generator__add_child] final offset %d", buffer_offset);

	return buffer_offset;
}

static int32_t json_generator__add_json_key(unsigned char* buffer, const uint32_t buffer_size, uint32_t offset, const char* key) {
	int32_t buffer_offset = (int32_t) offset;
	size_t key_len;

	if (!key) {
		LOGE("[json_generator__add_json_key] The JSON key is NULL");
		return -eBadArg;
	}
	key_len = strlen(key);
	buffer_offset += (int32_t) key_len + 3; // 2 double quotes characters and one ':'

	// If no buffer is provided, return what would be the new offset
	if (!buffer) {
		return buffer_offset;
	}

	// Check if the space of the buffer is enough to add the character
	if ((uint32_t) buffer_offset > buffer_size) {
		LOGE("[json_generator__add_json_key] Not enough space to add the JSON key '%s' to the JSON buffer. Buffer size %u, buffer size needed %u", key, buffer_size, buffer_offset);
		return -eNotEnoughBuffer;
	}

	buffer[offset++] = '\"'; // Add first double quote
	memcpy(buffer + offset, key, key_len); // Add json key
	offset += (int32_t) key_len;
	buffer[offset++] = '\"'; // Add second double quote
	buffer[offset++] = ':'; // Add second double quote

	return (int32_t) offset;
}

static int32_t json_generator__add_json_value(unsigned char* buffer, const uint32_t buffer_size, uint32_t offset, const unsigned char* value, const uint32_t value_len, const bool add_double_quotes, json_generator__encode_value_callback_t encode_function) {
	int32_t buffer_offset = (int32_t) offset;
    int32_t real_value_len;

	if (add_double_quotes) {
		buffer_offset += 2;
	}
    if (encode_function) {
        /* Calculate the size of the encoded value */
        if ((real_value_len = encode_function(NULL, 0, 0, value, value_len)) < 0) {
            LOGE("[json_generator__add_json_value] Error calculating the size of the encoded value, err %d", real_value_len);
            return real_value_len;
        }
    } else {
	    real_value_len = (int32_t) value_len;
    }
    buffer_offset += real_value_len;

	// If no buffer is provided, return what would be the new offset
	if (!buffer) {
		return buffer_offset;
	}

	// Check if the space of the buffer is enough to add the character
	if ((uint32_t) buffer_offset > buffer_size) {
		LOGE("[json_generator__add_json_value] Not enough space to add the JSON value to the JSON buffer. Buffer size %u, buffer size needed %u", buffer_size, buffer_offset);
		return -eNotEnoughBuffer;
	}

	buffer_offset = (int32_t) offset;
	if (add_double_quotes) {
		buffer[buffer_offset++] = '\"'; // Add first double quote
	}
	if (encode_function) {
        /* Encode the value and add it to the buffer */
        if ((buffer_offset = encode_function(buffer, buffer_size, buffer_offset, value, value_len)) < 0) {
            LOGE("[json_generator__add_json_value] Error adding the encoded value, err %d", buffer_offset);
            return buffer_offset;
        }
    } else if (value && value_len > 0) {
		memcpy(buffer + buffer_offset, value, value_len); // Add json value in plain
		buffer_offset += value_len;
	}
	if (add_double_quotes) {
		buffer[buffer_offset++] = '\"'; // Add first double quote
	}

	return buffer_offset;
}

static int32_t json_generator__add_character(unsigned char* buffer, const uint32_t buffer_size, const uint32_t offset, const char c) {
	uint32_t buffer_offset = (int32_t) offset + 1;

	// If no buffer is provided, return what would be the new offset
	if (!buffer) {
		return buffer_offset;
	}

	// Check if the space of the buffer is enough to add the character
	if (buffer_offset > buffer_size) {
		LOGE("[json_generator__add_character] Not enough space to add the '%c' character to the JSON buffer. Buffer size %u, buffer size needed %u", c, buffer_size, buffer_offset);
		return -eNotEnoughBuffer;
	}

	// Add the char
	buffer[offset] = (unsigned char) c;

	return (int32_t) buffer_offset;
}

static int32_t json_generator__encode_base64(unsigned char* buffer, const uint32_t buffer_size, const uint32_t offset, const unsigned char* value_to_encode, uint32_t value_to_encode_len) {
    int32_t base64_encoded_len;

    if (buffer && offset > buffer_size) { // To avoid integer overflow on base64 function call
        LOGE("[json_generator__encode_base64] The buffer offset (%u) is bigger than the buffer size (%u)", offset, buffer_size);
        return -eNotEnoughBuffer;
    }
    if ((base64_encoded_len = base64__encode(buffer ? buffer + offset : NULL, buffer ? buffer_size - offset : buffer_size, value_to_encode, value_to_encode_len)) < 0) {
        LOGE("[json_generator__encode_base64] Error on base64 decode, err %d", base64_encoded_len);
        return base64_encoded_len;
    }

    return (int32_t) offset + base64_encoded_len;
}

static int32_t json_generator__encode_hexadecimal_string(unsigned char* buffer, const uint32_t buffer_size, const uint32_t offset, const unsigned char* value_to_encode, uint32_t value_to_encode_len) {
    int32_t hexadecimal_str_len;

    if (!buffer) {
        return (int32_t) (offset + value_to_encode_len * 2);
    }

    if (offset > buffer_size) { // To avoid integer overflow on byte utils function call
        LOGE("[json_generator__encode_hexadecimal_string] The buffer offset (%u) is bigger than the buffer size (%u)", offset, buffer_size);
        return -eNotEnoughBuffer;
    }

    if ((hexadecimal_str_len = byte_utils__byte_array_to_hex_string(value_to_encode, value_to_encode_len, buffer + offset, buffer_size - offset)) < 0) {
        LOGE("[json_generator__encode_hexadecimal_string] Error converting to hexadecimal string, err %d", hexadecimal_str_len);
        return hexadecimal_str_len;
    }

    return (int32_t) offset + hexadecimal_str_len;
}
