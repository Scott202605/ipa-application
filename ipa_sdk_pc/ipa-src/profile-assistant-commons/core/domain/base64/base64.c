/*
 * Base64 encoding/decoding (RFC1341)
 * Copyright (c) 2005-2011, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * 
 * Code adapted by Giesecke+Devrient Mobile Security GmbH
 */
#include "base64.h"

#include "log.h"
#define BASE64_TABLE_SIZE 65

#define PADDING_CHAR_ENCODED "\\u003d"
#define PADDING_CHAR_ENCODED_LEN 6

static const unsigned char base64_table[BASE64_TABLE_SIZE] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int32_t base64__decoded_size(const unsigned char* in, const uint32_t len);

int32_t base64__encode(unsigned char* buffer, const uint32_t buffer_size, const unsigned char* src, const uint32_t len) {
	const unsigned char *end, *in;
	uint32_t buffer_offset;

	if (0 == len) {
		LOGE("[base64__encode] The source buffer length is 0");
		return -eBadArg;
	}

	buffer_offset = ((len / 3) + ((len % 3) != 0)) * 4; /* 3-byte blocks to 4-byte, ceiling is needed for the padding */

	// Calculate the size of the encoded buffer
	if (buffer_offset < len) {
		LOGE("[base64__encode] Integer overflow");
		return -eFatal; /* integer overflow */
	}

	// If no buffer is provided, return what would be the len required
    if (!buffer) {
        return buffer_offset;
    }

    // Check if the space of the buffer is enough to add the decoded base64
    if (buffer_size < (uint32_t) buffer_offset) {
        LOGE("[base64__encode] Not enough space to encode the base64 to the buffer. Buffer size %lu, buffer size needed %lu", buffer_size, buffer_offset);
        return -eNotEnoughBuffer;
    }

	if (NULL == src) {
		LOGE("[base64__encode] The source buffer is null");
		return -eBadArg;
	}

	end = src + len;
	in = src;
	buffer_offset = 0;
	while (end - in >= 3) {
		buffer[buffer_offset++] = base64_table[in[0] >> 2];
		buffer[buffer_offset++] = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
		buffer[buffer_offset++] = base64_table[((in[1] & 0x0F) << 2) | (in[2] >> 6)];
		buffer[buffer_offset++] = base64_table[in[2] & 0x3F];
		in += 3;
	}

	if (end - in) {
		buffer[buffer_offset++] = base64_table[in[0] >> 2];
		if (end - in == 1) {
			buffer[buffer_offset++] = base64_table[(in[0] & 0x03) << 4];
			buffer[buffer_offset++] = '=';
		} else {
			buffer[buffer_offset++] = base64_table[((in[0] & 0x03) << 4) | (in[1] >> 4)];
			buffer[buffer_offset++] = base64_table[(in[1] & 0x0F) << 2];
		}
		buffer[buffer_offset++] = '=';
	}

	return buffer_offset--;
}

int32_t base64__decode(unsigned char* buffer, const uint32_t buffer_size, const unsigned char* src, const uint32_t len) {
	unsigned char dtable[256], block[4], tmp;
	uint32_t i;
	uint32_t count;
	int32_t buffer_offset;
	uint8_t pad = 0;

	if (src == NULL || len == 0) {
		LOGE("[base64__decode] The source buffer is empty/null");
		return -eBadArg;
	}

	// Calculate the size of the decoded buffer
	if ((buffer_offset = base64__decoded_size(src, len)) < 0) {
		LOGE("[base64__decode] Error calculating the size need it for decode, err %d", buffer_offset);
		return buffer_offset;
	}

	// If no buffer is provided, return what would be the len required
    if (!buffer) {
        return buffer_offset;
    }

    // Check if the space of the buffer is enough to add the decoded base64
    if (buffer_size < (uint32_t) buffer_offset) {
        LOGE("[base64__decode] Not enough space to decode the base64 to the buffer. Buffer size %lu, buffer size needed %lu", buffer_size, buffer_offset);
        return -eNotEnoughBuffer;
    }
	
	memset(dtable, 0x80, 256);
	for (i = 0; i < BASE64_TABLE_SIZE - 1; i++) {
		dtable[base64_table[i]] = (unsigned char) i;
	}
	dtable['='] = 0;
	dtable[(unsigned char)PADDING_CHAR_ENCODED[0]] = 0; /** Handle the possible bad encoding of the padding char */

	count = 0;
	buffer_offset = 0;
	for (i = 0; i < len; i++) {
		tmp = dtable[src[i]];
		if (tmp == 0x80) {
			continue;
		}

		if (src[i] == '=') {
			pad++;
		} else if (src[i] == PADDING_CHAR_ENCODED[0]) {
			/** Handle the possible bad encoding of the padding char */
			if (len - i >= PADDING_CHAR_ENCODED_LEN && !memcmp(&src[i], PADDING_CHAR_ENCODED, PADDING_CHAR_ENCODED_LEN)) {
				i += (PADDING_CHAR_ENCODED_LEN - 1); // Change the iterator as it had a '='
				pad++;
			} else {
				LOGE("[base64__decode] Wrong character found '%c' on decoding", src[i]);
			}
		}
		block[count] = tmp;
		count++;
		if (count == 4) {
			buffer[buffer_offset++] = (block[0] << 2) | (block[1] >> 4);
			if (pad == 0 || pad == 1) {
				buffer[buffer_offset++] = (block[1] << 4) | (block[2] >> 2);
			} 
			if (pad == 0) {
				buffer[buffer_offset++] = (block[2] << 6) | block[3];
			}
			count = 0;
		}
	}

	return buffer_offset;
}

static int32_t base64__decoded_size(const unsigned char* in, const uint32_t len) {
	uint32_t encoded_len = len;
	uint32_t decoded_size = 0;
	uint8_t padding = 0;
	
	if (in == NULL || len == 0) {
		LOGE("[base64__decoded_size] The input buffer is empty/null");
		return -eBadArg;
	}

	/** Handle the possible bad encoding of the last padding char */
	if (len >= PADDING_CHAR_ENCODED_LEN) {
        if (!memcmp(in + len - PADDING_CHAR_ENCODED_LEN, PADDING_CHAR_ENCODED, PADDING_CHAR_ENCODED_LEN)) {
            encoded_len -= (PADDING_CHAR_ENCODED_LEN - 1); // Calculate the length as it had a '='
			padding++;
        }
    }
	/** Handle the possible bad encoding of the penultimate padding char */
	if (len >= PADDING_CHAR_ENCODED_LEN * 2) {
        if (!memcmp(in + len - PADDING_CHAR_ENCODED_LEN * 2, PADDING_CHAR_ENCODED, PADDING_CHAR_ENCODED_LEN)) {
            encoded_len -= (PADDING_CHAR_ENCODED_LEN - 1); // Calculate the length as it had a '='
			padding++;
        }
    } 

	if (encoded_len % 4) {
		LOGE("[base64__decoded_size] Invalid Base64 encoded length %u", encoded_len);
		return -eBadArg;
	}

	decoded_size = encoded_len / 4 * 3;
	if (in[encoded_len - 1] == '=') padding++;
	if (in[encoded_len - 2] == '=') padding++;

	return decoded_size - padding;
}
