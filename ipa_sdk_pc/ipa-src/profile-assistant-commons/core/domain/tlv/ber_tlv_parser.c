#include "ber_tlv_parser.h"

#include "log.h"

/**
 * @param	buffer	[IN]	data buffer
 * @param	offset	[IN]	data offset within bugger
 * @return number of bytes in TAG field
 */
uint8_t ber_tlv_parser__get_tag_bytes_count(const uint8_t* buffer, size_t offset) {
	if ((buffer[offset] & 0x1F) == 0x1F) { // see subsequent bytes
		uint8_t len = 2;
		size_t i;
		for (i = (offset + 1); i < (offset + 10); i++) {
			if ((buffer[i] & 0x80) != 0x80) {
				break;
			}
			len++;
		}
		return len;
	}
	else {
		return 1U;
	}
}

/**
 * @param	buffer	[IN]	data buffer
 * @param	offset	[IN]	offset in data buffer
 * @return size of length field
 */
uint8_t ber_tlv_parser__get_length_bytes_count(const uint8_t* buffer, size_t offset) {
	uint8_t len = (buffer[offset] & 0xff);
	if ((len & 0x80) == 0x80) {
		return (1 + (len & 0x7f));
	}
	else {
		return 1U;
	}
}

// get total length of TLV object
ErrCode ber_tlv_parser__get_tlv_bytes_count(const uint8_t* buffer, size_t offset, size_t *result) {
	size_t nTag = ber_tlv_parser__get_tag_bytes_count(buffer, offset);
	size_t nLen = ber_tlv_parser__get_length_bytes_count(buffer, offset+nTag);

	size_t valueLength;
	ErrCode ret = ber_tlv_parser__get_data_length(buffer, offset + nTag, &valueLength);
	if (ret != eOk) {
		LOGE("could not get the data length of the TLV, offset=%zu", offset + nTag);
		return ret;
	}

	(*result) = (nTag + nLen + valueLength);
	return eOk;
}

// only on TOP level
int ber_tlv_parser__find_tlv_by_tag_2(const uint8_t* buffer, size_t bufferSize, size_t offset, unsigned short tag) {
	LOGT("ber_tlv_parser__find_tlv_by_tag_2 [%02X] offset=%zu bufferSize=%zu", tag, offset, bufferSize);
	if (!buffer || bufferSize == 0 || offset > bufferSize) {
		return -1;
	}

	size_t _offset = offset;
	while(_offset<bufferSize) {
		size_t tlvSize = 0U;
		ErrCode ret = ber_tlv_parser__get_tlv_bytes_count(buffer, _offset, &tlvSize);
		if (ret != eOk) {
			LOGE("could not parse TLV, offset=%zu", _offset);
			return -1;
		}
		// check TAG
		if (tag == ber_tlv_parser__get_tlv_tag(buffer, _offset)) {
			return (int) _offset; //TODO Return a ErrCode and the offset result by param
		}
		_offset+=tlvSize;
	}
	return -1;
}

unsigned short ber_tlv_parser__get_tlv_tag(const uint8_t* buffer, size_t offset) {
	size_t length = ber_tlv_parser__get_tag_bytes_count(buffer, offset);
	LOGT("tag.len=%u", (unsigned int)length);
	if (length == 2) {
		return (unsigned short) ((buffer[offset] & 0xFF) << 8 | (buffer[offset + 1] & 0xFF));
	}
	else {
		return buffer[offset];
	}
}

// find value offset by TLV offset
size_t ber_tlv_parser__get_value_offset(const uint8_t* buffer, size_t tlvOffset) {
	size_t nTag = ber_tlv_parser__get_tag_bytes_count(buffer, tlvOffset);
	LOGT("nTag=%u", (unsigned int)nTag);
	size_t nLen = ber_tlv_parser__get_length_bytes_count(buffer, tlvOffset + nTag);
	LOGT("nLen=%u", (unsigned int)nLen);

	return (tlvOffset + nTag + nLen);
}

// find length offset by TLV offset
//Not used but good to have
size_t ber_tlv_parser__get_length_offset(const uint8_t* buffer, size_t tlvOffset) {
	size_t nTag = ber_tlv_parser__get_tag_bytes_count(buffer, tlvOffset);

	return (tlvOffset + nTag);
}

/**
 * Get data of a TLV TAG
 * 
 * @param[in]  buffer Pointer to a byte array that contains the bytes of the TLV TAG
 * @param[in]  buffer_size Size of the buffer byte array.
 * @param[in]  offset Offset of the buffer where the tag is located
 * @param[out] tag	Will point to the TAG value (the value is extracted, so is not a reference to the TAG located in the buffer)
 * @param[out] tag_size Size of the TAG
 * 
 * @return eOk in case the data of the TAG has been extracted successfully. Otherwise, an error code is returned.
*/
ErrCode ber_tlv_parser__get_tag_data(const uint8_t* buffer, const size_t buffer_size, const size_t offset, unsigned short* tag, uint8_t* tag_size) {
	if (!buffer || buffer_size == 0 || offset >= buffer_size) {
		return eBadArg;
	}

	*tag = ber_tlv_parser__get_tlv_tag(buffer, offset);
	*tag_size = (uint8_t) ber_tlv_parser__get_tag_bytes_count(buffer, offset);

	return eOk;
}

/**
 * Get data length
 * @param	buffer	[IN]	data buffer
 * @param	offset	[IN]	data offset in buffer
 * @param	result	[OUT]	output value
 * @return error code
 */
ErrCode ber_tlv_parser__get_data_length(const uint8_t* buffer, size_t offset, size_t *result) {
	size_t length = buffer[offset] & 0xff;
	if ((length & 0x80) == 0x80) {
		size_t numberOfBytes = length & 0x7f;
		if (numberOfBytes > 3) {
			LOGE( "At position %u the len is more then 3 [%u]", (unsigned int)offset, (unsigned int)numberOfBytes);
			return eFatal;
		}

		length = 0;
		size_t i;
		for (i = (offset + 1); i < (offset + 1 + numberOfBytes); i++) {
			length = length * 0x100 + (buffer[i] & 0xff);
		}

	}
	*result = length;
	return eOk;
}

ErrCode ber_tlv_parser__ber_tlv_2(const uint8_t* buffer, size_t bufferSize, size_t offset, _BerTlv *obj) {
	LOGT("ber_tlv_parser__ber_tlv_2 bufferSize=%u, offset=%u", (unsigned int)bufferSize, (unsigned int)offset);
	if (!obj) {
		return eFatal;
	}
	if (offset>=bufferSize) {
		return eFatal;
	}
	//LOG_DATA(eLogDebug, "ber_tlv_parser__ber_tlv", buffer);
	obj->tag = ber_tlv_parser__get_tlv_tag(buffer, offset);
	obj->nTag = ber_tlv_parser__get_tag_bytes_count(buffer, offset);

	ErrCode ret = ber_tlv_parser__get_data_length(buffer, offset + obj->nTag, &obj->length);
	if (ret != eOk) {
		LOGE("could not get the data length of the TLV, offset=%zu", offset + (size_t) obj->nTag);
		return ret;
	}

	obj->nLength = ber_tlv_parser__get_length_bytes_count(buffer, offset + obj->nTag);

	return eOk;
}
ErrCode tlv_data_extractor__ber_tlv_to_int(const uint8_t* value_ptr, size_t length, int32_t* out_int)
{

    if (value_ptr == NULL || out_int == NULL) {
        LOGE("[ber_tlv_to_int] Output pointer is NULL.");
        return eBadArg;
    }
    if (length == 0 || length > sizeof(int32_t)) {
        LOGE("[ber_tlv_to_int] Invalid length: %zu. Must be between 1 and %zu.", length, sizeof(int32_t));
        return eBadArg;
    }


    bool is_negative = (value_ptr[0] & 0x80) != 0;

    if (is_negative) {

        *out_int = -1;
    } else {
        *out_int = 0;
    }

    for (size_t i = 0; i < length; i++) {
        *out_int = (*out_int << 8) | value_ptr[i];
    }

    return eOk;
}

ErrCode ber_tlv_parser__get_full_tlv_length(const uint8_t* buffer, size_t offset, size_t *result) {
	size_t nTag = ber_tlv_parser__get_tag_bytes_count(buffer, offset);
	size_t nLen = ber_tlv_parser__get_length_bytes_count(buffer, offset + nTag);

	size_t len;
	ErrCode ret = ber_tlv_parser__get_data_length(buffer, offset+nTag, &len);
	if (ret != eOk) {
		LOGE("could not get the data length of the TLV, offset=%zu", offset + nTag);
		return ret;
	}

	*result = (nTag + nLen + len);
	return eOk;
}
