/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "smartcard_at.h"
#include "byte_utils.h"
#include "log.h"

#define CSIM_HEADER_REQ_TEMPLATE "AT+CSIM=%u,\""
#define CSIM_HEADER_RES "+CSIM:"
#define AT_COMMAND_LIST_SUPPORTED_CMEE "AT+CMEE=?\r"
#define AT_COMMAND_SUPPORTED_CMEE_POS   8
#define AT_CMEE_BUFFER_SIZE 32
/**
 * AT Command format: 'AT+CSIM=<length>,"<Hex Command APDU>"<CR>'
 *      8 -> 'AT+CSIM='
 *      3 -> Max 3 digits, max value:'522' (Max APDU Response data + SW1-SW2)
 *      2 -> ',\""
 *      522 -> Command APDU (CLA + INS + P1 + P2 + Lc + Command Data (Max 255) + Le)
 *      1 -> '\"'
 *      1 -> <CR>
 * AT Command max size = 537
 * 
 * AT Command Response format: '<CR><LF>+CSIM: <length>,"<response>"<CR><LF>OK<CR><LF>'
 *      2 -> <CR><LF>
 *      7 -> '+CSIM: '
 *      3 -> Max 3 digits, max value:'516' (Max APDU Response data + SW1-SW2)
 *      2 -> ',\""
 *      512 -> Max APDU Response data
 *      4 -> SW1-SW2
 *      1 -> '\"'
 *      2 -> <CR><LF>
 *      2 -> OK
 *      2 -> <CR><LF>
 * AT Command response max size = 537
*/
#define AT_CMD_MAX_BUFFER_SIZE  540

static int smartcard_at__init_driver(smartcard_t* const context);
static int smartcard_at__deinit_driver(smartcard_t* const context);
static int16_t smartcard_at__transceive_apdu(smartcard_t* const context, uint8_t* apdu_buffer, uint16_t apdu_buffer_size, uint16_t bytes_to_transmit);
static int16_t smartcard_at__transceive_at_command(smartcard_at_t* const context, uint8_t* at_buffer, uint16_t at_buffer_size, uint16_t bytes_to_transmit);
static void smartcard_at__set_higer_cmee(smartcard_at_t* const context);
static int16_t smartcard_at__apdu_to_at_command(uint8_t* buffer, const uint16_t buffer_size, uint8_t* const apdu, const uint16_t apdu_size);
static int16_t smartcard_at__response_at_command_to_response_apdu(uint8_t* buffer, const uint16_t buffer_size, const uint8_t* at_response, const uint16_t at_response_size);


void smartcard_at__ctor(smartcard_at_t* const context) {
	smartcard__ctor(&context->super);

    static struct smartcard_vtable_s const vtbl = {
        &smartcard_at__init_driver,
        &smartcard_at__deinit_driver,
        &smartcard_at__transceive_apdu
    };
    context->super.smartcard_vptr = &vtbl;
}

void smartcard_at__destory(smartcard_at_t* const context) {
	smartcard__destory(&context->super);
}

static int smartcard_at__init_driver(smartcard_t* const context) {
    int err;

    if ((err = ((smartcard_at_t*) context)->smartcard_at_vptr->init_driver((smartcard_at_t*) context)) < 0) {
        LOGE("[smartcard_at__init_driver] Init driver has been failed, err %d", err);
        return err;
    }
    smartcard_at__set_higer_cmee((smartcard_at_t*) context);

    return 0;
}

static int smartcard_at__deinit_driver(smartcard_t* const context) {
    return ((smartcard_at_t*)context)->smartcard_at_vptr->deinit_driver((smartcard_at_t*)context);
}

static int16_t smartcard_at__transceive_apdu(smartcard_t* const context, uint8_t* apdu_buffer, uint16_t apdu_buffer_size, uint16_t bytes_to_transmit) {
    uint8_t at_buffer[AT_CMD_MAX_BUFFER_SIZE];
    int16_t buffer_offset;

    if (apdu_buffer_size < bytes_to_transmit) {
		LOGE("[smartcard_at__transceive_apdu] The APDU buffer is smaller than the bytes to transmit. APDU buffer size: %u, bytes to transmit: %u", apdu_buffer_size, bytes_to_transmit);
		return -EINVAL;
	}

    // APDU to AT command
    if ((buffer_offset = smartcard_at__apdu_to_at_command(at_buffer, sizeof(at_buffer), apdu_buffer, bytes_to_transmit)) < 0) {
        LOGE("[smartcard_at__transceive_apdu] Error generating the AT Command, err %d", buffer_offset);
        return buffer_offset;
    }

    // Send the AT command and receive the response
    if ((buffer_offset = smartcard_at__transceive_at_command((smartcard_at_t*)context, at_buffer, sizeof(at_buffer), buffer_offset)) < 0) {
        LOGE("[smartcard_at__transceive_apdu] Error on transceive the AT Command, err %d", buffer_offset);
        return buffer_offset;
    }

    // response AT command response to response APDU
    if ((buffer_offset = smartcard_at__response_at_command_to_response_apdu(apdu_buffer, apdu_buffer_size, at_buffer, buffer_offset)) < 0) {
        LOGE("[smartcard_at__transceive_apdu] Error generating the response APDU, err %d", buffer_offset);
        return buffer_offset;
    }

    return buffer_offset;
}

static int16_t smartcard_at__transceive_at_command(smartcard_at_t* const context, uint8_t* at_buffer, uint16_t at_buffer_size, uint16_t bytes_to_transmit) {
    int16_t bytes_received;

    if (at_buffer_size < bytes_to_transmit) {
		LOGE("[smartcard_at__transceive_at_command] The AT buffer is smaller than the bytes to transmit. AT buffer size: %u, bytes to transmit: %u", at_buffer_size, bytes_to_transmit);
		return -EINVAL;
	}
    LOG_UTF8_DATA(eLogDebug, "[smartcard_at__transceive_at_command] AT Command:\n", at_buffer, bytes_to_transmit);

    if ((bytes_received = (*context->smartcard_at_vptr->transceive_at_command_to_driver) (context, at_buffer, at_buffer_size, bytes_to_transmit)) < 0) {
        LOGE("[smartcard_at__transceive_at_command] Error on transceive the AT Command to the driver, err %d", bytes_received);
        return -EIO;
    }

    LOG_UTF8_DATA(eLogDebug, "[smartcard_at__transceive_at_command] AT Command response: ", at_buffer, bytes_received);

    return bytes_received;
}

static void smartcard_at__set_higer_cmee(smartcard_at_t* const context) {
    int16_t response_bytes;
    int cmee_value = 0; // Default if the retrieval of the highest value fails
    uint8_t at_buffer[AT_CMEE_BUFFER_SIZE];
    char* end_list;

    strcpy((char*) at_buffer, AT_COMMAND_LIST_SUPPORTED_CMEE);

    if ((response_bytes = smartcard_at__transceive_at_command(context, at_buffer, sizeof(at_buffer), (uint16_t) strlen((char*)at_buffer))) >= 0) {
        LOG_DATA(eLogTrace, "[smartcard_at__set_higer_cmee] AT+CMEE list", at_buffer, response_bytes);
        if (NULL != (end_list = memchr(at_buffer, ')', response_bytes))) {
            cmee_value = atoi(end_list - 1) % 10;
            LOGD("[smartcard_at__set_higer_cmee] CMEE value %d", cmee_value);
        } else {
            LOGW("[smartcard_at__set_higer_cmee] End of AT+CMEE list not found");
        }
    } else {
        LOGW("[at_cmee] Error listing the supported values for AT+CMEE, err %d", response_bytes);
    }

    strcpy((char*) at_buffer, AT_COMMAND_LIST_SUPPORTED_CMEE);
    at_buffer[AT_COMMAND_SUPPORTED_CMEE_POS] = '0' + cmee_value;

    if ((response_bytes = smartcard_at__transceive_at_command(context, at_buffer, sizeof(at_buffer), (uint16_t) strlen((char*)at_buffer))) < 0) {
        LOGW("[smartcard_at__set_higer_cmee] Error setting the CMEE, err %d", response_bytes);
    }
}

// 'AT+CSIM=<length>,"<Hex Command APDU>"<CR>'
static int16_t smartcard_at__apdu_to_at_command(uint8_t* buffer, const uint16_t buffer_size, uint8_t* const apdu, const uint16_t apdu_size) {
    int16_t buffer_offset = 0;
    int32_t hex_apdu_size = apdu_size * 2;
    int aux;

    if (!apdu || apdu_size == 0) {
        LOGE("[smartcard_at__apdu_to_at_command] APDU buffer is empty/null");
        return -EINVAL;
    }

    /* Calculate the AT commang length */
    if ((aux = snprintf(NULL, 0, CSIM_HEADER_REQ_TEMPLATE, hex_apdu_size)) < 0) {
        LOGE("[smartcard_at__apdu_to_at_command] Error counting the number of bytes for the AT command header, err %d. APDU size: %u", aux, apdu_size);
        return -ECANCELED;
    }
    buffer_offset += aux;
    buffer_offset += hex_apdu_size;
    buffer_offset += 2; // " + <CR>

    // If no buffer is provided, return what would be the offset
    if (!buffer) {
        return buffer_offset;
    }

    // Check if the space of the buffer is enough to add the AT command
    if (buffer_offset > buffer_size) {
        LOGE("[smartcard_at__apdu_to_at_command] Not enough space to add the AT command to the buffer. Buffer size %u, buffer size needed %u", buffer_size, buffer_offset);
        return -ENOMEM;
    }

    /* Write the AT command to the buffer */
    buffer_offset = 0;
    if ((aux = snprintf((char*) buffer, buffer_size, CSIM_HEADER_REQ_TEMPLATE, hex_apdu_size)) < 0) {
        LOGE("[smartcard_at__apdu_to_at_command] Error writing the AT command header to the buffer, err %d. APDU size: %u", aux, hex_apdu_size);
        return -ECANCELED;
    }
    buffer_offset += aux;
    if ((hex_apdu_size = byte_utils__byte_array_to_hex_string(apdu, apdu_size, buffer + buffer_offset, buffer_size - buffer_offset)) < 0) {
        LOGE("[smartcard_at__apdu_to_at_command] Error writing the APDU in hexadecimal to the buffer, err %d", hex_apdu_size);
        return -ECANCELED;
    }
    buffer_offset += hex_apdu_size;
    buffer[buffer_offset++] = '\"';
    buffer[buffer_offset++] = '\r';

	return buffer_offset;
}

// '<CR><LF>+CSIM: <length>,"<response>"<CR><LF>OK<CR><LF>'
static int16_t smartcard_at__response_at_command_to_response_apdu(uint8_t* buffer, const uint16_t buffer_size, const uint8_t* at_response, const uint16_t at_response_size) {
    unsigned char* header;
    unsigned char* first_quote;
    unsigned char* second_quote;
    uint16_t hex_content_length;
    int16_t buffer_offset;
    
    if (!at_response || at_response_size == 0) {
        LOGE("[smartcard_at__response_at_command_to_response_apdu] AT Command response buffer is empty/null");
        return -EINVAL;
    }

    // Search the +CSIM:
    if (NULL == (header = S_memmem(at_response, at_response_size, CSIM_HEADER_RES, sizeof(CSIM_HEADER_RES) - 1))) {
        LOGE("[smartcard_at__response_at_command_to_response_apdu] '%s' not found", CSIM_HEADER_RES);
        return -ECANCELED;
    }

    // Search the first quote
    if (NULL == (first_quote = memchr(header, '\"', at_response_size - (header - at_response)))) {
        LOGE("[smartcard_at__response_at_command_to_response_apdu] First quote not found");
        return -ECANCELED;
    }
    first_quote++; // To point after the quote

    // Search the second quote
    if (NULL == (second_quote = memchr(first_quote, '\"', at_response_size - (first_quote - at_response)))) {
        LOGE("[smartcard_at__response_at_command_to_response_apdu] Second quote not found");
        return -ECANCELED;
    }

    hex_content_length = (uint16_t) (second_quote - first_quote);
    if (hex_content_length % 2 != 0) {
        LOGE("[smartcard_at__response_at_command_to_response_apdu] The CSIM AT command response characters are not even");
        return -ECANCELED;
    }
    buffer_offset = hex_content_length / 2;

    // If no buffer is provided, return what would be the offset
    if (!buffer) {
        return buffer_offset;
    }

    // Check if the space of the buffer is enough to add the APDU response
    if (buffer_offset > buffer_size) {
        LOGE("[smartcard_at__apdu_to_at_command] Not enough space to add the APDU response to the buffer. Buffer size %u, buffer size needed %u", buffer_size, buffer_offset);
        return -ENOMEM;
    }

    if ((buffer_offset = byte_utils__hex_string_to_byte_array(first_quote, hex_content_length, buffer, buffer_size)) < 0) {
        LOGE("[smartcard_at__apdu_to_at_command] Error writing the CSIM AT command response in byte array to the APDU buffer, err %d", buffer_offset);
        return buffer_offset;
    }

	return buffer_offset;
}
