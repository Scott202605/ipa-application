/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include <errno.h>
#include "smartcard_at_external.h"
#include "serial.h"
#include "log.h"

#define AT_COMMAND_RESPONSE_OK		"OK"
#define AT_COMMAND_RESPONSE_ERROR	"ERROR"

#define TEST_ECHO_AT_COMMAND "AT\r"
#define TEST_ECHO_RESPONSE_WITH_ECHO "AT\r\r\nOK\r\n"

static int smartcard_at_external__init_driver(smartcard_at_t* const context);
static int smartcard_at_external__deinit_driver(smartcard_at_t* const context);
static int16_t smartcard_at_external__transceive_at_command(smartcard_at_t* const context, uint8_t* at_buffer, uint16_t at_buffer_size, uint16_t bytes_to_transmit);
static int smartcard_at_external__write_at_command(smartcard_at_external_t* const context, uint8_t* at_buffer, const uint16_t at_buffer_size, uint16_t bytes_to_transmit);
static int32_t smartcard_at_external__read_at_response(smartcard_at_external_t* const context, uint8_t* at_buffer, const uint16_t at_buffer_size);
static int smartcard_at_external__read_echoing_bytes(smartcard_at_external_t* const context, uint8_t* at_buffer, const uint16_t at_buffer_size, uint16_t bytes_transmitted);
static int smartcard_at_external__set_at_commands_echoing(smartcard_at_external_t* const context);

int smartcard_at_external__ctor(smartcard_at_external_t* const context, const char* sp_name, const uint32_t baud_rate) {
	smartcard_at__ctor(&context->super);

	static struct smartcard_at_vtable_s const vtbl = {
		&smartcard_at_external__init_driver,
		&smartcard_at_external__deinit_driver,
		&smartcard_at_external__transceive_at_command
	};

	//binding functions for the parent
	context->super.smartcard_at_vptr = &vtbl;

	//configure baud rate
	context->baud_rate = baud_rate;

	//configure serial port
	if (strlen(sp_name) + 1 > sizeof(context->sp_name)) {
		LOGE("[smartcard_at_external__ctor] The length of the serial port name (%u) exceeds the maximum allowed length (%u)", strlen(sp_name), sizeof(context->sp_name) -1);
		return -ENOMEM;
	}
	
	strcpy(context->sp_name, sp_name);
	LOGD("[smartcard_at_external__ctor] The serial port name has been set to '%s'", context->sp_name);

	context->first_init_done = false; // First init not done yet
	context->at_commands_echoing = false; // Echo not tested yet (this will be done at the first initialization)

	return 0;
}

void smartcard_at_external__destory(smartcard_at_external_t* const context) {
	memset(context->sp_name, 0, sizeof(context->sp_name));
	context->baud_rate = 0;
	context->hw_context = NULL;
	context->first_init_done = false;
	context->at_commands_echoing = false;
	smartcard_at__destory(&context->super);
}

static int smartcard_at_external__init_driver(smartcard_at_t* const context) {
	int err;
	smartcard_at_external_t* const at_external_context = (smartcard_at_external_t*)context;

	/* Open the Serial Port */
	if (NULL == (at_external_context->hw_context = open_serial_port(at_external_context->sp_name, sizeof(at_external_context->sp_name), at_external_context->baud_rate))) {
		LOGE("[smartcard_at_external__init_driver] open serial port has been failed");
		return -EIO;
	}

	/* Test if the modem is echoing the AT commands */
	if (!at_external_context->first_init_done) {
		if ((err = smartcard_at_external__set_at_commands_echoing(at_external_context)) < 0) {
			LOGE("[smartcard_at_external__init_driver] Error testing if the modem is echoing, err %d", err);
			return err;
		}
	}

	at_external_context->first_init_done = true; // After the first initialization it will always be true

	return 0;
}

static int smartcard_at_external__deinit_driver(smartcard_at_t* const context) {
	int err;

	if ((err = close_serial_port(((smartcard_at_external_t*)context)->hw_context)) < 0) {
		LOGE("[smartcard_at_external__deinit_driver] close serial port has been failed, err %d", err);
		return -EIO;
	}

	return 0;
}


static int16_t smartcard_at_external__transceive_at_command(smartcard_at_t* const context, uint8_t* at_buffer, uint16_t at_buffer_size, uint16_t bytes_to_transmit) {
	smartcard_at_external_t* const external_context = (smartcard_at_external_t*)context;
	int16_t at_response_size;
	int err;

	if ((err = smartcard_at_external__write_at_command(external_context, at_buffer, at_buffer_size, bytes_to_transmit)) < 0) {
		LOGE("[smartcard_at_external__transceive_at_command] Error writing the AT command, err %d", err);
		return err;
	}

	if (external_context->at_commands_echoing) {
		if ((err = smartcard_at_external__read_echoing_bytes(external_context, at_buffer, at_buffer_size, bytes_to_transmit)) < 0) {
			LOGE("[smartcard_at_external__transceive_at_command] Error reading the echoing bytes, err %d", err);
			return err;
		}
	}
	
	if ((at_response_size = smartcard_at_external__read_at_response(external_context, at_buffer, at_buffer_size)) < 0) {
		LOGE("[smartcard_at_external__transceive_at_command] Error reading the AT command response, err %d", at_response_size);
		return at_response_size;
	}
	
	return at_response_size;
}

static int smartcard_at_external__write_at_command(smartcard_at_external_t* const context, uint8_t* at_buffer, const uint16_t at_buffer_size, uint16_t bytes_to_transmit) {
	uint16_t total_bytes_written = 0;
	int bytes_written = 0;

	if (at_buffer_size < bytes_to_transmit) {
		LOGE("[smartcard_at_external__write_at_command] The AT buffer is smaller than the bytes to transmit. AT buffer size: %u, bytes to transmit: %u", at_buffer_size, bytes_to_transmit);
		return -EINVAL;
	}

	LOGT("[smartcard_at_external__read_echoing_bytes] Writing AT command bytes");
	// We can consider to implement a timeout in the loop
	while (total_bytes_written < bytes_to_transmit) {
		/* Write remaining bytes to port */
		if ((bytes_written = write_serial_port(context->hw_context, at_buffer + total_bytes_written, (size_t) (bytes_to_transmit - total_bytes_written))) < 0) {
            LOGE("[smartcard_at_external__write_at_command] Error writing bytes to port, err %d", bytes_written);
            return -EIO;
        } else {
            total_bytes_written += bytes_written;
        }
	}

	return 0;
}

static int32_t smartcard_at_external__read_at_response(smartcard_at_external_t* const context, uint8_t* at_buffer, const uint16_t at_buffer_size) {
	int32_t total_bytes_read = 0;
	int bytes_read = 0;
	unsigned char flush;

	LOGT("[smartcard_at_external__read_echoing_bytes] Reading AT command response bytes");
	// We can consider to implement a timeout in the loop
	while (total_bytes_read < at_buffer_size) {
		/* Read one more byte from Port */
		if ((bytes_read = read_serial_port(context->hw_context, &at_buffer[total_bytes_read], 1)) < 0) {
            LOGE("[smartcard_at_external__read_at_response] Error reading bytes from port, err %d", bytes_read);
            return -EIO;
        } else {
            total_bytes_read += bytes_read;
        }
#ifdef DEBUG_SERIAL_PORT_RW
    	LOGT("[smartcard_at_external__read_at_response] Byte 0x%02X read from port", total_bytes_read > 0 ? at_buffer[total_bytes_read - 1] : 0);
#endif

		/* Check is the AT command response is fully read  */
		if (total_bytes_read >= 2 && at_buffer[total_bytes_read - 2] == '\r' && at_buffer[total_bytes_read - 1] == '\n') {
			if (S_memmem(at_buffer, total_bytes_read, AT_COMMAND_RESPONSE_OK, sizeof(AT_COMMAND_RESPONSE_OK) - 1) || S_memmem(at_buffer, total_bytes_read, AT_COMMAND_RESPONSE_ERROR, sizeof(AT_COMMAND_RESPONSE_ERROR) - 1)) {
				LOGT("[smartcard_at_external__read_at_response] 'OK' or 'ERROR' found");
				LOG_DATA(eLogTrace, "[smartcard_at_external__read_at_response] AT buffer", at_buffer, total_bytes_read);
				return total_bytes_read;
			}
		}
	}

	// This can be considered as an error case
	LOGW("[smartcard_at_external__read_at_response] Max AT buffer size reached. Flushing all the remaining bytes");
	LOG_DATA(eLogDebug, "[smartcard_at_external__read_at_response] AT buffer", at_buffer, at_buffer_size);
	while (read_serial_port(context->hw_context, &flush, 1) > 0);

	return -ENOMEM;
}

static int smartcard_at_external__read_echoing_bytes(smartcard_at_external_t* const context, uint8_t* at_buffer, const uint16_t at_buffer_size, uint16_t bytes_transmitted) {
	int bytes_read;

	if (at_buffer_size < bytes_transmitted) {
		LOGE("[smartcard_at_external__read_echoing_bytes] The AT buffer is smaller than the bytes transmitted. AT buffer size: %u, bytes transmitted: %u", at_buffer_size, bytes_transmitted);
		return -EINVAL;
	}

	LOGT("[smartcard_at_external__read_echoing_bytes] Reading echoing bytes");
	if ((bytes_read = read_serial_port(context->hw_context, (unsigned char*) at_buffer, (size_t) bytes_transmitted)) < 0) {
		LOGE("[smartcard_at_external__read_echoing_bytes] Error reading the echoing bytes, err %d", bytes_read);
		return -EIO;
	}

	if (bytes_read != bytes_transmitted) {
		LOGE("[smartcard_at_external__read_echoing_bytes] The number of bytes transmitted and bytes echoing mismatch. Bytes transmitted: %u, bytes echoing: %u", bytes_transmitted, bytes_read);
		return -ECANCELED;
	}

	LOG_DATA(eLogTrace, "[smartcard_at_external__read_echoing_bytes] Echoing bytes", at_buffer, bytes_read);

	return 0;
}

static int smartcard_at_external__set_at_commands_echoing(smartcard_at_external_t* const context) {
	uint8_t at_buffer[256]; // Allocate more data in case there are some remaining bytes in the buffer to flush
	int16_t response_bytes;

	memcpy(at_buffer, TEST_ECHO_AT_COMMAND, sizeof(TEST_ECHO_AT_COMMAND) - 1);

	LOG_UTF8_DATA(eLogTrace, "[smartcard_at_external__set_at_commands_echoing] AT Command to test the echo: ", at_buffer, sizeof(TEST_ECHO_AT_COMMAND) - 1);

	if ((response_bytes = smartcard_at_external__transceive_at_command((smartcard_at_t*) context, at_buffer, sizeof(at_buffer), sizeof(TEST_ECHO_AT_COMMAND) - 1)) < 0) {
		LOGE("[smartcard_at_external__set_at_commands_echoing] Error sending the 'AT' command to test the echoing");
		return -ECANCELED;
	}

	LOG_UTF8_DATA(eLogTrace, "[smartcard_at_external__set_at_commands_echoing] AT Command echo response: ", at_buffer, response_bytes);

	// Compare it with the lasts bytes of the buffer
	if (response_bytes >= sizeof(TEST_ECHO_RESPONSE_WITH_ECHO) - 1 && memcmp(at_buffer + response_bytes - (sizeof(TEST_ECHO_RESPONSE_WITH_ECHO) - 1), TEST_ECHO_RESPONSE_WITH_ECHO, sizeof(TEST_ECHO_RESPONSE_WITH_ECHO) - 1) == 0) {
		context->at_commands_echoing = true;
		LOGD("[smartcard_at_external__set_at_commands_echoing] The AT commands are echoing");
	} else {
		context->at_commands_echoing = false;
		LOGD("[smartcard_at_external__set_at_commands_echoing] The AT commands are not echoing");
	}

	return 0;
}
