/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include "tlv_generator.h"
#include "log.h"
#include "ber_tlv_parser.h"
#include "base64.h"
#include "byte_utils.h"
#include "tlv_tags.h"
#include "tlv_lengths.h"
#include "ber_tlv_parser.h"

int32_t tlv_generator__add_tag(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const unsigned short tag) {
    uint8_t tag_size = 1;
    uint32_t buffer_offset;

    // Calculate the size of the TAG field
    if ((uint8_t) ((tag >> 8) & 0x1F) == 0x1F) {
        tag_size++;
    }
    LOGT("[tlv_generator__add_tag] TAG 0x%04X, num bytes %u", tag, tag_size);

    // If no buffer is provided, return what would be the new offset
    if (!buffer) {
        return offset + tag_size;
    }

    // Check if the space of the buffer is enough to add the TAG
    if (offset + tag_size > buffer_size) {
        LOGE("[tlv_generator__add_tag] Not enough space to add the %04X to the buffer. Buffer size %u, buffer size needed %u", tag, buffer_size, offset + tag_size);
        return -eNotEnoughBuffer;
    }

    // Add the TAG to the buffer
    buffer_offset = offset;
    if (tag_size > 1) {
		buffer[buffer_offset++] = (uint8_t) (tag >> 8);
	}
	buffer[buffer_offset++] = (uint8_t) tag;
    LOG_DATA(eLogTrace, "[tlv_generator__add_tag] TAG", buffer + offset, buffer_offset - offset);

    // Return the new offset of the buffer
    return buffer_offset;
}

int32_t tlv_generator__add_length(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const uint32_t length) {
    uint32_t buffer_offset;
    uint8_t length_size;
    uint8_t i;

    // Calculate the size of the LENGTH field
    if (length < (uint32_t) 0x7F) {
		length_size = 1;
	} else if (length < (uint32_t) 0xFF) {
		length_size = 2;
	} else if (length < (uint32_t) 0xFFFF) {
		length_size = 3;
	} else if (length < (uint32_t) 0xFFFFFF) {
		length_size = 4;
    } else { // uint32_t is limited to 4 bytes, so there are no more possibilities
		length_size = 5;
	}
    LOGT("[tlv_generator__add_tag] LENGTH %u, num bytes %u", length, length_size);

    // If no buffer is provided, return what would be the new offset
    if (!buffer) {
        return offset + length_size;
    }

    // Check if the space of the buffer is enough to add the LENGTH
    if (offset + length_size > buffer_size) {
        LOGE("[tlv_generator__add_length] Not enough space to add the LENGTH to the buffer. Buffer size %u, buffer size needed %u", buffer_size, offset + length_size);
        return -eNotEnoughBuffer;
    }

    // Add the LENGTH to the buffer
    buffer_offset = offset;
	if (length_size > 1) {
		buffer[buffer_offset++] = (uint8_t) (0x80 | (length_size - 1)); // The first byte of the length indicate number of bytes of the length
		for (i = 1; i < length_size; i++) {
			buffer[buffer_offset++] = (uint8_t) (length >> (8 * (length_size - 1 - i))); // -1 because the first byte of the length don't indicate the length value
		}
	}
	else {
		buffer[buffer_offset++] = (uint8_t) length;
	}
    LOG_DATA(eLogTrace, "[tlv_generator__add_tag] LENGTH", buffer + offset, buffer_offset - offset);

    // Return the new offset of the buffer
    return buffer_offset;
}

int32_t tlv_generator__add_tag_and_length(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const unsigned short tag, const uint32_t length) {
    int32_t buffer_offset;

    // TAG
    if ((buffer_offset = tlv_generator__add_tag(buffer, buffer_size, offset, tag)) < 0) {
        LOGE("[tlv_generator__add_tag_and_length] Error on TAG, rc %d", buffer_offset);
        return buffer_offset;
    }

    // LENGTH
    if ((buffer_offset = tlv_generator__add_length(buffer, buffer_size, (uint32_t) buffer_offset, length)) < 0) {
        LOGE("[tlv_generator__add_tag_and_length] Error on LENGTH, rc %d", buffer_offset);
        return buffer_offset;
    }

    return buffer_offset;
}

int32_t tlv_generator__add_tlv(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const unsigned short tag, const uint8_t* value, const uint32_t value_size) {
    int32_t buffer_offset;

    // TAG and LENGTH
    if ((buffer_offset = tlv_generator__add_tag_and_length(buffer, buffer_size, offset, tag, value_size)) < 0) {
        LOGE("[tlv_generator__add_tlv] Error on TAG and LENGTH, rc %d", buffer_offset);
        return buffer_offset;
    }

    // If no buffer is provided, return what would be the new offset
    if (!buffer) {
        return buffer_offset + value_size;
    }

    // Check if the space of the buffer is enough to add the TLV
    if (buffer_offset + value_size > buffer_size) {
        LOGE("[tlv_generator__add_tlv] Not enough space to add the TLV to the buffer. Buffer size %u, buffer size needed %u", buffer_size, buffer_offset + value_size);
        return -eNotEnoughBuffer;
    }

	// Add the VALUE
	if (value && value_size > 0) {
		memcpy(buffer + buffer_offset, value, value_size);
        buffer_offset += value_size;
	}

	LOG_DATA(eLogTrace, "[tlv_generator__add_tlv] TLV", buffer + offset, buffer_offset - offset);

    return buffer_offset;
}

int32_t tlv_generator__add_wrap_tlv(uint8_t* buffer, const uint32_t buffer_size, const uint32_t value_offset, const uint32_t offset, const unsigned short tag) {
    int32_t tag_and_length_size;

    if (value_offset > offset) {
        LOGE("[tlv_generator__add_wrap_tlv] VALUE offset (%u) is bigger than offset (%u)", value_offset, offset);
        return -eBadArg;
    }

    //Calculate the size of the TAG and LENGTH
    if ((tag_and_length_size = tlv_generator__add_tag_and_length(NULL, 0, 0, tag, offset - value_offset)) < 0) {
        LOGE("[tlv_generator__add_wrap_tlv] Error calculating the number of bytes of the TAG and LENGTH, rc %ld", tag_and_length_size);
        return tag_and_length_size;
    }

    // If no buffer is provided, return what would be the new offset
    if (!buffer) {
        return offset + tag_and_length_size;
    }

    // Check if the space of the buffer is enough to wrap the TLV
    if (offset + tag_and_length_size > buffer_size) {
        LOGE("[tlv_generator__add_wrap_tlv] Not enough space to wrap the TLV on the buffer. Buffer size %lu, buffer size needed %lu", buffer_size, offset + tag_and_length_size);
        return -eNotEnoughBuffer;
    }

    LOG_DATA(eLogTrace, "[tlv_generator__add_wrap_tlv] Before wrap", buffer + value_offset, offset - value_offset);
    // Move the VALUE (TAG + LENGTH size positions)
    memmove(buffer + value_offset + tag_and_length_size, buffer + value_offset, offset - value_offset);

    // Write the TAG and the LENGTH at the beggining of the buffer (The available space in the buffer to do it is buffer_offset, since is the size of the buffer that we moved)
    if ((tag_and_length_size = tlv_generator__add_tag_and_length(buffer + value_offset, (uint32_t) tag_and_length_size, 0, tag, offset - value_offset)) < 0) {
        LOGE("[tlv_generator__add_wrap_tlv] Error writing the TAG and the LENGTH at the beggining of the buffer, rc %ld", tag_and_length_size);
        return tag_and_length_size;
    }
    LOG_DATA(eLogTrace, "[tlv_generator__add_wrap_tlv] After wrap", buffer + value_offset, offset - value_offset + tag_and_length_size);

    return offset + tag_and_length_size;
}

int32_t tlv_generator__add_tlv_full_bytes(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const uint8_t* tlv, const uint32_t tlv_size) {

    if (!tlv || tlv_size == 0) {
        LOGW("[tlv_generator__add_tlv_full_bytes] TLV is empty/null");
        return (int32_t) offset;
    }

    //If no buffer is provided, return what would be the new offset
    if (!buffer) {
        return offset + tlv_size;
    }

    //Check if the space of the buffer is enough to add the TLV
    if (offset + tlv_size > buffer_size) {
        LOGE("[tlv_generator__add_tlv_full_bytes] Not enough space to add the TLV to the buffer. Buffer size %lu, buffer size needed %lu", buffer_size, offset + tlv_size);
        return -eNotEnoughBuffer;
    }

    //Add the TLV
    memcpy(buffer + offset, tlv, tlv_size);

    return offset + tlv_size;
}

int32_t tlv_generator__add_tlv_full_bytes_overwrite_tag(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset,  const uint8_t* tlv, const uint32_t tlv_size, unsigned short new_tag) {
    ErrCode rc;
    unsigned short tag;
    uint8_t tag_size;
    int32_t new_tag_offset;

    if (!tlv || tlv_size == 0) {
        LOGW("[tlv_generator__add_tlv_full_bytes_overwrite_tag] TLV is empty/null");
        return -eBadArg;
    }

    // Calculate the tlv TAG size
    if ((rc = ber_tlv_parser__get_tag_data(tlv, (size_t) tlv_size, 0, &tag, &tag_size)) != eOk) {
        LOGE("[tlv_generator__add_tlv_full_bytes_overwrite_tag] Error getting the tag, rc %d", rc);
        return -rc;
    }

    // Calculate the TAG size to be overwritten
    if ((new_tag_offset = tlv_generator__add_tag(NULL, 0, 0, new_tag)) < 0) {
        LOGE("[tlv_generator__add_tlv_full_bytes_overwrite_tag] Error calculating the number of bytes of the TAG, rc %ld", new_tag_offset);
        return new_tag_offset;
    }

    if (!buffer) {
        return offset + tlv_size + new_tag_offset - tag_size;
    }

    // Check if the space of the buffer is enough to add the TLV
    if (offset + tlv_size + new_tag_offset - tag_size > buffer_size) {
        LOGE("[tlv_generator__add_tlv_full_bytes_overwrite_tag] Not enough space to add the TLV to the buffer. Buffer size %lu, buffer size needed %lu", buffer_size, offset + tlv_size + new_tag_offset - tag_size);
        return -eNotEnoughBuffer;
    }

	// Add the new TAG
    if ((new_tag_offset = tlv_generator__add_tag(buffer, buffer_size, offset, new_tag)) < 0) {
        LOGE("[tlv_generator__add_tlv_full_bytes_overwrite_tag] Error calculating the number of bytes of the TAG, rc %ld", new_tag_offset);
        return new_tag_offset;
    }

    // Add the rest of TLV
    memcpy(buffer + new_tag_offset, tlv + tag_size, tlv_size - tag_size);
    LOG_DATA(eLogTrace, "[tlv_generator__add_tlv_full_bytes_overwrite_tag] TLV with the TAG overwritten", buffer, buffer_size);

    return new_tag_offset + tlv_size - tag_size;
 }

int32_t tlv_generator__add_tlv_integer_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const unsigned short tag, const unsigned int value) {
    uint8_t tlv_value[5] = {0};
    int8_t tlv_value_size;

    // Parse integer to byte array
    if ((tlv_value_size = byte_utils__uint_to_byte_array(tlv_value, sizeof(tlv_value), value)) < 0) {
        LOGE("[tlv_generator__add_tlv_integer_value] Error parsing the integer to byte array, err %d", tlv_value_size);
        return (int32_t) tlv_value_size;
    }
    LOG_DATA(eLogTrace, "[tlv_generator__add_tlv_integer_value] Integer byte array", tlv_value, tlv_value_size);

    return tlv_generator__add_tlv(buffer, buffer_size, offset, tag, tlv_value, tlv_value_size);
}

int32_t tlv_generator__add_tlv_boolean_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const unsigned short tag, const bool value) {
    uint8_t tlv_value = value ? ASN1_DER_BOOL_TRUE : ASN1_DER_BOOL_FALSE;
    return tlv_generator__add_tlv(buffer, buffer_size, offset, tag, &tlv_value, sizeof(uint8_t));
}

int32_t tlv_generator__add_tlv_cstring_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const unsigned short tag, const char* value) {
    return tlv_generator__add_tlv(buffer, buffer_size, offset, tag, (uint8_t*) value, (uint32_t) strlen(value));
}

int32_t tlv_generator__add_tlv_base64_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const unsigned short tag, const unsigned char* b64_encoded, const uint32_t b64_encoded_len) {
    int32_t tlv_value_size;
    int32_t buffer_offset;

    // Calculate the size of the base64 decoded value
    if ((tlv_value_size = base64__decode(NULL, 0, b64_encoded, b64_encoded_len)) < 0) {
        LOGE("[tlv_generator__add_tlv_base64_value] Error calculating the size of the base 64 value, rc %ld", tlv_value_size);
        return tlv_value_size;
    }

    //Calculate the size base64 TLV
    if ((buffer_offset = tlv_generator__add_tlv(NULL, 0, 0, tag, NULL, tlv_value_size)) < 0) {
        LOGE("[tlv_generator__add_tlv_base64_value] Error calculating the size of the base64 TLV, rc %ld", buffer_offset);
        return buffer_offset;
    }

    //If no buffer is provided, return what would be the new offset
    if (!buffer) {
        return offset + buffer_offset;
    }

    //Check if the space of the buffer is enough to add the base64 TLV
    if (offset + buffer_offset > buffer_size) {
        LOGE("[tlv_generator__add_tlv_base64_value] Not enough space to add the TLV to the buffer. Buffer size %lu, buffer size needed %lu", buffer_size, offset + buffer_offset);
        return -eNotEnoughBuffer;
    }

    //Add base64 TAG LENGTH
    if ((buffer_offset = tlv_generator__add_tag_and_length(buffer, buffer_size, offset, tag, tlv_value_size)) < 0) {
        LOGE("[tlv_generator__add_tlv_base64_value] Error adding the base64 TAG LENGTH, rc %ld", buffer_offset);
        return buffer_offset;
    }
    //Add base64 VALUE
    if ((tlv_value_size = base64__decode(buffer + buffer_offset, buffer_size - buffer_offset, b64_encoded, b64_encoded_len)) < 0) {
        LOGE("[tlv_generator__add_tlv_base64_value] Error adding the base64 VALUE, rc %ld", tlv_value_size);
        return tlv_value_size;
    }

    return buffer_offset + tlv_value_size;
}

int32_t tlv_generator__add_tlv_bit_string_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const unsigned short tag, const uint8_t* bit_string, const uint32_t bit_string_count) {
    int32_t tlv_value_size;
    int32_t buffer_offset;

    // Calculate the size of the bit string encoded
    if ((tlv_value_size = byte_utils__bit_string_encode(NULL, 0, bit_string, bit_string_count)) < 0) {
        LOGE("[tlv_generator__add_tlv_bit_string_value] Error calculating the size of the bit string, rc %ld", tlv_value_size);
        return tlv_value_size;
    }

    //Calculate the size bit string TLV
    if ((buffer_offset = tlv_generator__add_tlv(NULL, 0, 0, tag, NULL, tlv_value_size)) < 0) {
        LOGE("[tlv_generator__add_tlv_bit_string_value] Error calculating the size of the bit string TLV, rc %ld", buffer_offset);
        return buffer_offset;
    }

    //If no buffer is provided, return what would be the new offset
    if (!buffer) {
        return offset + buffer_offset;
    }

    //Check if the space of the buffer is enough to add the bit string TLV
    if (offset + buffer_offset > buffer_size) {
        LOGE("[tlv_generator__add_tlv_bit_string_value] Not enough space to add the TLV to the buffer. Buffer size %lu, buffer size needed %lu", buffer_size, offset + buffer_offset);
        return -eNotEnoughBuffer;
    }

    //Add bit string TAG LENGTH
    if ((buffer_offset = tlv_generator__add_tag_and_length(buffer, buffer_size, offset, tag, tlv_value_size)) < 0) {
        LOGE("[tlv_generator__add_tlv_bit_string_value] Error adding the bit string TAG LENGTH, rc %ld", buffer_offset);
        return buffer_offset;
    }
    //Add bit string VALUE
    if ((tlv_value_size = byte_utils__bit_string_encode(buffer + buffer_offset, buffer_size - buffer_offset, bit_string, bit_string_count)) < 0) {
        LOGE("[tlv_generator__add_tlv_bit_string_value] Error adding the bit string VALUE, rc %ld", tlv_value_size);
        return tlv_value_size;
    }

    return buffer_offset + tlv_value_size;
}

int32_t tlv_generator__add_tlv_null_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const unsigned short tag) {
    return tlv_generator__add_tag_and_length(buffer, buffer_size, offset, tag, 0);
}

int32_t tlv_generator__add_tlv_oid_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const unsigned short tag, unsigned char* oid, uint32_t oid_len) {
    int32_t tlv_value_size;
    int32_t buffer_offset;

    // Calculate the size of the OID encoded value
    if ((tlv_value_size = byte_utils__oid_encode(NULL, 0, oid, oid_len)) < 0) {
        LOGE("[tlv_generator__add_tlv_oid_value] Error calculating the size of the OID, rc %ld", tlv_value_size);
        return tlv_value_size;
    }

    //Calculate the size OID TLV
    if ((buffer_offset = tlv_generator__add_tlv(NULL, 0, 0, tag, NULL, tlv_value_size)) < 0) {
        LOGE("[tlv_generator__add_tlv_oid_value] Error calculating the size of the OID TLV, rc %ld", buffer_offset);
        return buffer_offset;
    }

    //If no buffer is provided, return what would be the new offset
    if (!buffer) {
        return offset + buffer_offset;
    }

    //Check if the space of the buffer is enough to add the OID TLV
    if (offset + buffer_offset > buffer_size) {
        LOGE("[tlv_generator__add_tlv_oid_value] Not enough space to add the TLV to the buffer. Buffer size %lu, buffer size needed %lu", buffer_size, offset + buffer_offset);
        return -eNotEnoughBuffer;
    }

    //Add OID TAG LENGTH
    if ((buffer_offset = tlv_generator__add_tag_and_length(buffer, buffer_size, offset, tag, tlv_value_size)) < 0) {
        LOGE("[tlv_generator__add_tlv_oid_value] Error adding the OID TAG LENGTH, rc %ld", buffer_offset);
        return buffer_offset;
    }
    //Add OID VALUE
    if ((tlv_value_size = byte_utils__oid_encode(buffer + buffer_offset, buffer_size - buffer_offset, oid, oid_len)) < 0) {
        LOGE("[tlv_generator__add_tlv_oid_value] Error adding the OID VALUE, rc %ld", tlv_value_size);
        return tlv_value_size;
    }

    return buffer_offset + tlv_value_size;
}

int32_t tlv_generator__add_tlv_transaction_id_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const unsigned short tag, const transaction_id_t* transaction_id) {
    if (!transaction_id) {
        LOGE("[tlv_generator__add_tlv_transaction_id_value] TransactionId is null");
        return -eBadArg;
    }
    
    if (transaction_id->transaction_id_size < 1 || transaction_id->transaction_id_size > sizeof(transaction_id->transaction_id)) {
        LOGE("[tlv_generator__add_tlv_transaction_id_value] Invalid TransactionId size: %u, minimum size: 1, maximum size %u.", transaction_id->transaction_id_size, sizeof(transaction_id->transaction_id));
        return -eBadArg;
    }

    return tlv_generator__add_tlv(buffer, buffer_size, offset, tag, transaction_id->transaction_id, (uint32_t) transaction_id->transaction_id_size);
}

int32_t tlv_generator__add_tlv_version_type_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const unsigned short tag, const version_type_t* version) {
    uint8_t value[] = { 0, 0, 0 };

    if (!version) {
        LOGE("[tlv_generator__add_tlv_version_type_value] VersionType is null");
        return -eBadArg;
    }

    value[0] = version->major;
    value[1] = version->minor;
    value[2] = version->revision;

    return tlv_generator__add_tlv(buffer, buffer_size, offset, tag, value, (uint32_t) sizeof(value));
}

int32_t tlv_generator__add_tlv_iccid_nibble_swap_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const unsigned short tag, const iccid_t* iccid) {
    ErrCode rc;
    iccid_t iccid_nibbe_swap;

    if (buffer) {
        memcpy(&iccid_nibbe_swap.value, iccid->value, sizeof(iccid_nibbe_swap.value));
        if ((rc = byte_utils__iccid_parse_format(&iccid_nibbe_swap, true)) != eOk) {
            LOGE("[tlv_generator__add_tlv_iccid_nibble_swap_value] Error nibble swaping the ICCID, rc %d", rc);
            return rc;
        }
    }

    return tlv_generator__add_tlv(buffer, buffer_size, offset, tag, iccid_nibbe_swap.value, sizeof(iccid_nibbe_swap.value));
}
