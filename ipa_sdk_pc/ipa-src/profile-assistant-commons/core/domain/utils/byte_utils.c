/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include <stdio.h>
#include <stdlib.h>

#include "byte_utils.h"
#include "log.h"

#define ICCID_FIRST_BYTE                (uint8_t) 0x89
#define ICCID_FIRST_BYTE_NIBBLE_SWAPED  (uint8_t) 0x98

static ErrCode byte_utils__hex_to_byte(unsigned char *in, unsigned char *out);
static int32_t byte_utils__get_next_oid_node_value(const unsigned char* oid, const uint32_t oid_len, const uint32_t offset, uint32_t* node_value);
static int32_t byte_utils__oid_encode_first_two_nodes(uint8_t* buffer, uint32_t buffer_size, uint8_t first_node, uint32_t second_node);
static int32_t byte_utils__oid_encode_node(uint8_t* buffer, uint32_t buffer_size, uint32_t offset, uint32_t node_value);
static ErrCode is_iccid_nibble_swaped(const iccid_t* iccid, bool* is_nibble_swaped);
static inline void uint32_to_byte_array_big_endian(uint32_t num, unsigned char* output);
static inline void byte_array_to_uint32_big_endian(const unsigned char* num, uint32_t* output);

ErrCode byte_utils__hex_string_to_byte(const char* hex, uint8_t* result) {
    *result = 0x00;
    if (!hex || strlen(hex) < sizeof(uint8_t) * 2) {
        return eBadArg;
    }
    *result = (hex[0] % 32 + 9) % 25 * 16 + (hex[1] % 32 + 9) % 25;
    return eOk;
}

int32_t byte_utils__byte_array_to_hex_string(const unsigned char *in, size_t in_size, unsigned char *out, size_t out_size) { 
    if ((in_size * 2) > out_size) {
        LOGE("[byte_utils__byte_array_to_hex_string] in_size %u, out_size %u", in_size, out_size);
        return -eBadArg;
    }

    unsigned char *pin = (unsigned char *)in;
    const char *hex = "0123456789ABCDEF";
    unsigned char *pout = out;
    for (; pin < in + in_size; pout += 2, pin++) {
        pout[0] = (unsigned char) hex[(*pin >> 4) & 0xF];
        pout[1] = (unsigned char) hex[*pin & 0xF];
    }
    return (int32_t) (pout - out);
}

int32_t byte_utils__hex_string_to_byte_array(const unsigned char *in, uint32_t in_size, unsigned char *out, uint32_t out_size) {
    if (in_size > (out_size * 2)) {
        return -eBadArg;
    }

    unsigned char *pin = (unsigned char *)in;
    unsigned char *pout = out;
    for (; pin < in + in_size; pout++, pin += 2) {
        if (eOk != byte_utils__hex_to_byte(pin, pout)) {
            return -eFatal;
        }
    }
    return (int32_t) (pout - out);
}

unsigned short byte_utils__bytes_to_short(const uint8_t high_byte, const uint8_t low_byte) {
    unsigned short result = 0x0000 | high_byte;
    result <<= 8;
    result |= 0x00FF & low_byte;

    return result;
}

ErrCode byte_utils__hex_string_to_short(const char* hex, unsigned short* result) {
    if (!hex || strlen(hex) < sizeof(short) * 2) {
        return eBadArg;
    }
    uint8_t high_byte = (hex[0] % 32 + 9) % 25 * 16 + (hex[1] % 32 + 9) % 25;
    uint8_t low_byte = (hex[2] % 32 + 9) % 25 * 16 + (hex[3] % 32 + 9) % 25;
    *result = byte_utils__bytes_to_short(high_byte, low_byte);

    return eOk;
}

int8_t byte_utils__uint_to_byte_array(uint8_t* buffer, const uint32_t buffer_size, const uint32_t value) {
    uint8_t val[sizeof(uint32_t)] = { 0 };
    uint8_t val_offset;
    uint8_t buffer_offset = 0;
    uint8_t int_value_size = sizeof(uint32_t);
    bool padding;

    LOGT("[byte_utils__uint_to_byte_array] value=%lu", value);

    //If the integer value is 0
    if (0 == value) {
        int_value_size = 1;
        //If no buffer is provided, return what would be the needed size
        if (!buffer) {
            return (int8_t)int_value_size;
        }
        //Check if the space of the buffer is enough to add the integer
        if (buffer_size < int_value_size) {
            LOGE("Not enough space to add the unsigned integer to the buffer. Buffer size %u, buffer size needed %u", buffer_size, int_value_size);
            return -eBadArg;
        }
        //Add the 0 value to the buffer
        if (buffer) {
            buffer[buffer_offset++] = 0x00;
        }
        return buffer_offset;
    }

    //If the integer > 0
    uint32_to_byte_array_big_endian(value, val);
    while (val[sizeof(val) - int_value_size] == 0 && int_value_size > 0) {
        int_value_size--;
    }
    val_offset = sizeof(uint32_t) - int_value_size;
    padding = (val[val_offset] & 0x80) > 0x00;
    if (padding) {
        int_value_size++;
    }
    LOGT("[byte_utils__uint_to_byte_array] int_value_size=%u", int_value_size);
    //If no buffer is provided, return what would be the needed size
    if (!buffer) {
        return (int8_t)int_value_size;
    }
    //Check if the space of the buffer is enough to add the integer
    if (int_value_size > buffer_size) {
        LOGE("Not enough space to add the unsigned integer to the buffer. Buffer size %u, buffer size needed %u", buffer_size, int_value_size);
        return -eBadArg;
    }
    if (padding) {
        buffer[buffer_offset++] = 0x00; //If the first bit is set, we will need to put the first byte to 0x00 to set the integer unsigned
        int_value_size--; // we want to use the real length without the padding
    }
    memcpy(&buffer[buffer_offset], &val[val_offset], int_value_size);
    buffer_offset += int_value_size;

    return (int32_t)buffer_offset;
}

ErrCode byte_utils__byte_array_to_uint(const uint8_t* buffer, const uint32_t buffer_size, uint32_t* value) {
    uint32_t int_value_size = buffer_size;

    if (!buffer || buffer_size == 0) {
        *value = 0;
        return eOk;
    }

    while (buffer[buffer_size - int_value_size] == 0 && int_value_size > 0) {
        int_value_size--;
    }

    if (int_value_size > sizeof(uint32_t)) {
        LOGE("[byte_utils__byte_array_to_uint] Cannot convert the value of this buffer to a uint32_t. Bytes of the uint32_t %u, bytes needed %lu", sizeof(uint32_t), int_value_size);
        return -eBadArg;
    }

    *value = 0;
    if (int_value_size > 0) {
        unsigned char tmp[4] = { 0 };
        memcpy(&tmp[sizeof(tmp) - int_value_size], &buffer[buffer_size - int_value_size], int_value_size);
        byte_array_to_uint32_big_endian(tmp, value);
    }
    return eOk;
}

uint8_t byte_utils__byte_nibble_swap(uint8_t b) {
    return ((b << 4) & 0xf0) | ((b >> 4) & 0x0f);
}

ErrCode byte_utils__iccid_parse_format(iccid_t* iccid, const bool to_nibble_swap) {
    ErrCode rc;
    uint8_t i;
    bool iccid_is_nibble_swaped;

    if ((rc = is_iccid_nibble_swaped(iccid, &iccid_is_nibble_swaped)) != eOk) {
        LOGE("[byte_utils__iccid_plain] The ICCID has an invalid format, rc %d", rc);
        return rc;
    }

    // If the current format is not the desired one, apply the nibble swap in each byte
    if (iccid_is_nibble_swaped ^ to_nibble_swap) {
        for (i = 0; i < sizeof(iccid->value); i++) {
            iccid->value[i] = byte_utils__byte_nibble_swap(iccid->value[i]);
        }
    }

    return eOk;
}

int32_t byte_utils__bit_string_encode(uint8_t* buffer, uint32_t buffer_size, const uint8_t* bit_string, const uint32_t bit_string_size) {
	uint32_t real_bit_string_size = bit_string_size;
    uint32_t bit_string_encoded_size;
	uint32_t i;

	//Don't count as bit string size the last zeros of the bit string
	while (real_bit_string_size > 0 && bit_string[real_bit_string_size - 1] == 0x00) {
		real_bit_string_size--;
	}

	//If bit string size is 0, return an empty encoded buffer
	if (real_bit_string_size == 0) {
		bit_string_encoded_size = 0;
	} else {
        bit_string_encoded_size = real_bit_string_size / 8 + 1;
        if (real_bit_string_size % 8 > 0) {
            bit_string_encoded_size++;
        }
    }

    //If no buffer is provided, return what would be the size
    if (!buffer) {
        return bit_string_encoded_size;
    }

	//Check if the space of the buffer is enough to add the encoded bit string
    if (bit_string_encoded_size > buffer_size) {
        LOGE("[byte_utils__bit_string_encode] Not enough space to add the encoded bit string to the buffer. Buffer size %lu, buffer size needed %lu", buffer_size, bit_string_encoded_size);
        return -eNotEnoughBuffer;
    }

	//Encode the bit string into the buffer
    if (bit_string_encoded_size == 0) {
        //If size is 0
        return 0;
    } else {
        //If size is greater than 0
        buffer[0] = 8 - real_bit_string_size % 8; //Calculate the padding of zeros bits of the last byte
        for (i = 0; i < real_bit_string_size; i++) {
            buffer[i / 8 + 1] <<= 1;
            if (bit_string[i] > 0) {
                buffer[i / 8 + 1] |= 0x01;
            }
        }
    }
    
	//Set the last zero bits of padding
	for (i = 0; i < buffer[0]; i++) {
		buffer[bit_string_encoded_size - 1] <<= 1;
	}
 
	return bit_string_encoded_size;
}

int32_t byte_utils__bit_string_decode(uint8_t* buffer, uint32_t buffer_size, const uint8_t* encoded_bit_string, const uint32_t encoded_bit_string_size) {
    uint32_t plain_bit_string_size = 0;
    uint32_t buffer_offset;
    // Check format
    if (!encoded_bit_string || encoded_bit_string_size < 0) {
        LOGE("[byte_utils__bit_string_decode] BIT STRING is empty or null");
        return -eBadArg;
    }
    LOG_DATA(eLogTrace, "[byte_utils__bit_string_decode] plain BIT STRING", encoded_bit_string, encoded_bit_string_size);
    if (encoded_bit_string_size == 1 && encoded_bit_string[0] != 0) {
        LOGE("[byte_utils__bit_string_decode] BIT STRING of size 1 SHALL be an empty BIT STRING. Expected value %u, current value %u", 0, encoded_bit_string[0]);
        return -eBadArg;
    }
    if (encoded_bit_string_size > 1 && encoded_bit_string[0] > 7) {
        LOGE("[byte_utils__bit_string_decode] The maximum value for the unused bits of a BIT STRING is 7, current value %u", encoded_bit_string[0]);
        return -eBadArg;
    }

    // Calculate the size of the decoded BIT STRING
    if (encoded_bit_string_size > 0) {
        plain_bit_string_size = (encoded_bit_string_size - 1) * 8 - encoded_bit_string[0];
    }

    // If no buffer is provided, return what would be the size
    if (!buffer) {
        return (int32_t) plain_bit_string_size;
    }

	// Check if the space of the buffer is enough to write the decoded bit string
    if (plain_bit_string_size > buffer_size) {
        LOGE("[byte_utils__bit_string_decode] Not enough space to write the decoded bit string to the buffer. Buffer size %lu, buffer size needed %lu", buffer_size, plain_bit_string_size);
        return -eNotEnoughBuffer;
    }

    // Decode the BIT STRING
    for (buffer_offset = 0; buffer_offset < plain_bit_string_size; buffer_offset++) {
        buffer[buffer_offset] = 0x01 & (encoded_bit_string[1 + buffer_offset / 8] >> (7 - buffer_offset % 8));
    }

    return (int32_t) buffer_offset;
}

int32_t byte_utils__oid_encode(uint8_t* buffer, uint32_t buffer_size, const unsigned char* oid, const uint32_t oid_len) {
    int32_t oid_offset;
    int32_t encode_size;
    uint32_t node_value;
    uint32_t aux;
    uint8_t node_count = 0;

    if (!oid || oid_len < 0) {
        LOGE("[byte_utils__oid_encode] OID is empty or null");
        return eBadArg;
    }
    LOG_UTF8_DATA(eLogDebug, "[byte_utils__oid_encode] OID: ", oid, oid_len);

    /* Get the first node value */
    if ((oid_offset = byte_utils__get_next_oid_node_value(oid, oid_len, 0, &node_value)) < 0) {
        LOGE("[byte_utils__oid_encode] Error extracting the first node, rc %d", oid_offset);
        return oid_offset;
    }
    /* Get the second node value */
    if ((oid_offset = byte_utils__get_next_oid_node_value(oid, oid_len, (uint32_t) oid_offset, &aux)) < 0) {
        LOGE("[byte_utils__oid_encode] Error extracting the second node, rc %d", oid_offset);
        return oid_offset;
    }
    /* Encode the first and the second node value*/
    if ((encode_size = byte_utils__oid_encode_first_two_nodes(buffer, buffer_size, (uint8_t) node_value, aux)) < 0) {
        LOGE("[byte_utils__oid_encode] Error encoding the fist two nodes, rc %d", encode_size);
        return encode_size;
    }
    aux = encode_size; // Aux will store all the written bytes in the buffer
    /* Encode the remaining nodes */
    while ((uint32_t) oid_offset < oid_len && node_count <= 128) {
        /* Get the next node value */
        if ((oid_offset = byte_utils__get_next_oid_node_value(oid, oid_len, (uint32_t) oid_offset, &node_value)) < 0) {
            LOGE("[byte_utils__oid_encode] Error extracting the %u node, rc %d", node_count, oid_offset);
            return oid_offset;
        }
        /* Encode the node value */
        if ((encode_size = byte_utils__oid_encode_node(buffer, buffer_size, (uint32_t) encode_size, node_value)) < 0) {
            LOGE("[byte_utils__oid_encode] Error encoding the %u node with value %u, rc %d", node_count, node_value, encode_size);
            return encode_size;
        }
        aux += encode_size;
        node_count++;
    }

    if (buffer) {
        LOG_DATA(eLogDebug, "[byte_utils__oid_encode] OID encoded", buffer, encode_size);
    }

    return encode_size;
}

/**
 * This function extract the next OID subID value 
 * 
 * @param[in] oid Point to a plain UTF-8 OID
 * @param[in] oid_len Length of the plain UTF-8 OID (null character not included if exists).
 * @param[in] offset Offset of the oid buffer
 * @param[out] node_value Pointer to a uint32_t. Will point to a copy of the next subID of the OID starting from the offset position.
 * 
 * @return Upon successful execution, will return the buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
static int32_t byte_utils__get_next_oid_node_value(const unsigned char* oid, const uint32_t oid_len, const uint32_t offset, uint32_t* node_value) {
    if (!oid || offset >= oid_len) {
        return -eBadArg;
    }
    LOG_UTF8_DATA(eLogTrace, "[byte_utils__get_next_oid_node_value] Remaning OID: ", oid + offset, oid_len - offset);
    char chunk[12] = { 0 }; // Max node value is 4294967295 (10 dec) + . +'\0'
    char* dot_location;

    /* Copy the node to the chunck */
    if (oid_len - offset < sizeof(chunk) - 1) {
        memcpy(chunk, oid + offset, oid_len - offset);
    } else {
        memcpy(chunk, oid + offset, sizeof(chunk) - 1);
    }
    LOGT("[byte_utils__get_next_oid_node_value] OID chunk: %s", chunk);

    /* If a '.' is in the chunk, cut the string of the chunk from the beggining to the dot (not included) */
    dot_location = strchr(chunk, '.');
    if (dot_location) {
        *dot_location = '\0';
    }
    LOGT("[byte_utils__get_next_oid_node_value] OID subId: %s", chunk);

    // Parse the chunk to a number
    *node_value = (uint32_t) strtoul(chunk, NULL, 10);
    

    return (int32_t) (offset + strlen(chunk) + 1);
}

/**
 * This function encode the 1st and 2nd subIDs of the OID
 * 
 * @param[in, out] buffer Point to the buffer to which the encoded 1st and 2nd subIDs will be added. If null, the function will only calculate the size that the 
 * buffer would need to add the encoded OID node.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] first_node Value of the first node (subID). The valid values of the first subID are 0, 1, or 2.
 * @param[in] second_node Value of the second node (subID). If the first subID has a value of 0 or 1, the second subID can have a value only of 0 through 39.
 * 
 * @return Upon successful execution, will return the buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
static int32_t byte_utils__oid_encode_first_two_nodes(uint8_t* buffer, uint32_t buffer_size, uint8_t first_node, uint32_t second_node) {
    LOGD("[byte_utils__oid_encode_first_two_nodes] First subID: %u, second subID: %u", first_node, second_node);

    if (first_node != 0 && first_node != 1 && first_node != 2) {
        LOGE("[byte_utils__oid_encode_first_two_nodes] The valid values of the first subID are 0, 1, or 2. First subID: %u", first_node);
        return -eBadArg;
    }

    if ((first_node == 0 || first_node == 1) && second_node > 39) {
        LOGE("[byte_utils__oid_encode_first_two_nodes] If the first subID has a value of 0 or 1, the second subID can have a value only of 0 through 39. First subID: %u, second subID: %u", first_node, second_node);
        return -eBadArg;
    }

    return byte_utils__oid_encode_node(buffer, buffer_size, 0, first_node * 40 + second_node);
}

/**
 * This function encode an OID node value (subID)
 * 
 * @param[in, out] buffer Point to the buffer to which the encoded OID node will be added. If null, the function will only calculate the size that the 
 * buffer would need to add the encoded OID node.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] node_value Value of the node (subID).
 * 
 * @return Upon successful execution, will return the buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
static int32_t byte_utils__oid_encode_node(uint8_t* buffer, uint32_t buffer_size, uint32_t offset, uint32_t node_value) {
    LOGD("[byte_utils__oid_encode_node] Node value: %u", node_value);
    uint8_t encoded_node[5] = { 0x80, 0x80, 0x80, 0x80, 0x00 }; // Max length of an encoded node (Max value is 4294967295)
    uint8_t i;
    uint8_t encoded_node_size = sizeof(encoded_node);

    /* Parse the value to 7-bit bytes */
    for (i = 0; i < sizeof(encoded_node); i++) {
        encoded_node[sizeof(encoded_node) - i - 1] |= 0x7F & node_value;
        node_value >>= 7;
    }

    /* Calculate the size of the encoded node in bytes */
    for (i = 0; i < sizeof(encoded_node) && encoded_node[i] == 0x80; i++) {
        encoded_node_size--;
    }

    LOG_DATA(eLogDebug, "[byte_utils__oid_encode_node] Node encoded", encoded_node + sizeof(encoded_node) - encoded_node_size, encoded_node_size);

    //If no buffer is provided, return what would be the new offset
    if (!buffer) {
        return offset + encoded_node_size;
    }

    //Check if the space of the buffer is enough to add the OID node
    if (offset + encoded_node_size > buffer_size) {
        LOGE("[byte_utils__oid_encode_node] Not enough space to add the OID node %u. Buffer size %lu, buffer size needed %lu", node_value, buffer_size, offset + encoded_node_size);
        return -eNotEnoughBuffer;
    }

    /* Copy the encoded node value to the buffer */
    memcpy(buffer + offset, encoded_node + sizeof(encoded_node) - encoded_node_size, encoded_node_size);

    return offset + encoded_node_size;
}

static ErrCode byte_utils__hex_to_byte(unsigned char *in, unsigned char *out) {
    *out = 0;
    for (unsigned char *pin = in; pin < in + 2; pin++) {
        unsigned char tmp = *pin;
        if ((tmp >= 0x30) && (tmp <= 0x39)) {
            *out |= tmp - 0x30;
        } else if ((tmp >= 0x41) && (tmp <= 0x46)) {
            *out |= tmp - 0x37;
        } else if ((tmp >= 0x61) && (tmp <= 0x66)) {
            *out |= tmp - 0x57;
        } else {
            *out = 0;
            return eFatal;
        }
        if (pin == in) {
            *out <<= 4;
        }
    }
    return eOk;
}

static ErrCode is_iccid_nibble_swaped(const iccid_t* iccid, bool* is_nibble_swaped) {
    if (iccid->value[0] != ICCID_FIRST_BYTE && iccid->value[0] != ICCID_FIRST_BYTE_NIBBLE_SWAPED) {
        LOGE("[is_iccid_nibble_swaped] The first byte of the ICCID is not correct. Expected: %02X or %02X, current: %02X", ICCID_FIRST_BYTE, ICCID_FIRST_BYTE_NIBBLE_SWAPED, iccid->value[0]);
        return eBadArg;
    }

    if (ICCID_FIRST_BYTE_NIBBLE_SWAPED == iccid->value[0]) {
        *is_nibble_swaped = true;
    } else {
        *is_nibble_swaped = false;
    }
    return eOk;
}

//Size of output SHALL be at least 4
static inline void uint32_to_byte_array_big_endian(uint32_t num, unsigned char* output) {
	output[0] = (uint8_t)(num >> 24);
	output[1] = (uint8_t)(num >> 16);
	output[2] = (uint8_t)(num >> 8);
	output[3] = (uint8_t)(num >> 0);
}

//Size of num SHALL be at least 4
static inline void byte_array_to_uint32_big_endian(const unsigned char* num, uint32_t* output) {
    *output = (num[0] << 24) | (num[1] << 16) | (num[2] << 8) | (num[3] << 0);
}
