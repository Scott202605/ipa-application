/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"

#define MAX_RESPONSE_APDU_SIZE 258
#define MAX_RESPONSE_DATA_APDU_SIZE 256
#define SW_SIZE 2

// Command Apdu Structure
typedef struct command_apdu_s {
	uint8_t cla;
	uint8_t ins;
	uint8_t p1;
	uint8_t p2;
	uint8_t lc;
	uint8_t* data_field;
	uint8_t le;
	bool is_le_present;
} command_apdu_t;

// Status Word Structure
typedef struct sw_s {
	uint8_t sw1;
	uint8_t sw2;
} sw_t;

// Response Apdu Structure
typedef struct response_apdu_s {
	uint8_t response_data[MAX_RESPONSE_DATA_APDU_SIZE];
	uint16_t response_data_size;
	sw_t sw;
} response_apdu_t;

// This functions writes a command APDU into a buffer. Returns the number of bytes written to the buffer or a negative error code.
int16_t apdu__command_apdu_to_buffer(const command_apdu_t* command_apdu, uint8_t* buffer, uint16_t buffer_size);

// This functions parse a byte array buffer to a response APDU structure. Returns 0 on success or a negative error code.
int apdu__buffer_to_reponse_apdu(const uint8_t* buffer, uint16_t buffer_size, response_apdu_t* response_apdu);

// This functions parse a byte array buffer to a SW structure. The last two bytes of the buffer will be the bytes read as SW. Returns 0 on success or a negative error code.
int apdu__buffer_to_sw(const uint8_t* buffer, uint16_t buffer_size, sw_t* sw);
