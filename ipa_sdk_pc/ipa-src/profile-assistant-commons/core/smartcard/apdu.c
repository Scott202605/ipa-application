/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2024-2024
 */
#include "apdu.h"
#include <errno.h>
#include "log.h"

int16_t apdu__command_apdu_to_buffer(const command_apdu_t* command_apdu, uint8_t* buffer, uint16_t buffer_size) {
	uint16_t buffer_offset = 4; // CLA INS P1 P2

	if (!command_apdu) {
		LOGE("[apdu__command_apdu_to_buffer] The command APDU object is null");
		return -EINVAL;
	}

    /* Calculate buffer required size */
    if (command_apdu->lc > 0) {
		buffer_offset++;
        buffer_offset += command_apdu->lc;
	}

	if (command_apdu->is_le_present) {
		buffer_offset++;
	}

	if (!buffer) {
		return (int16_t) buffer_offset;
	}

    /* Check if the buffer is big enough to write the APDU into it */
    if (buffer_offset > buffer_size) {
        LOGE("[apdu__command_apdu_to_buffer] Not enough space to write the command APDU to the buffer. Buffer size %u, buffer size needed %u", buffer_size, buffer_offset);
		return -EINVAL;
    }

    buffer_offset = 0;
	buffer[buffer_offset++] = command_apdu->cla;
	buffer[buffer_offset++] = command_apdu->ins;
	buffer[buffer_offset++] = command_apdu->p1;
	buffer[buffer_offset++] = command_apdu->p2;
	LOGT("[apdu__command_apdu_to_buffer] CLA: %02X, INS: %02X, P1: %02X, P2: %02X", command_apdu->cla, command_apdu->ins, command_apdu->p1, command_apdu->p2);

	if (command_apdu->lc > 0) {
		buffer[buffer_offset++] = command_apdu->lc;
		LOGT("[apdu__command_apdu_to_buffer] Lc %02X", command_apdu->lc);
		memcpy(buffer + buffer_offset, command_apdu->data_field, command_apdu->lc);
		buffer_offset += command_apdu->lc;
		LOG_DATA(eLogTrace, "[apdu__command_apdu_to_buffer] Data Field", command_apdu->data_field, command_apdu->lc);
	} else {
		LOGT("[apdu__command_apdu_to_buffer] Lc and Data Field not present");
	}

	if (command_apdu->is_le_present) {
		buffer[buffer_offset++] = command_apdu->le;
		LOGT("[apdu__command_apdu_to_buffer] Le", command_apdu->le);
	} else {
		LOGT("[apdu__command_apdu_to_buffer] Le not present");
	}

	return (int16_t) buffer_offset;
}

int apdu__buffer_to_reponse_apdu(const uint8_t* buffer, uint16_t buffer_size, response_apdu_t* response_apdu) {
	if (!response_apdu) {
		LOGE("[apdu__buffer_to_reponse_apdu] The response APDU object is null");
		return -EINVAL;
	}

	if (!buffer) {
		LOGE("[apdu__buffer_to_reponse_apdu] The buffer pointer is null");
		return -EINVAL;
	}

	if (buffer_size < SW_SIZE) {
		LOGE("[apdu__buffer_to_reponse_apdu] Wrong buffer length. Min: %u, current: %u", SW_SIZE, buffer_size);
		return -EINVAL;
	}

	if (buffer_size - SW_SIZE > sizeof(response_apdu->response_data)) {
		LOGE("[apdu__buffer_to_reponse_apdu] The response data buffer is not big enough to copy all the response bytes. Max: %u, current: %u", sizeof(response_apdu->response_data), buffer_size - 2);
		return -ENOMEM;
	}
	memcpy(response_apdu->response_data, buffer, buffer_size - SW_SIZE);
	response_apdu->response_data_size = buffer_size - SW_SIZE;
	LOG_DATA(eLogTrace, "[apdu__buffer_to_reponse_apdu] Response data", response_apdu->response_data, response_apdu->response_data_size);

	return apdu__buffer_to_sw(buffer, buffer_size, &response_apdu->sw);
}

int apdu__buffer_to_sw(const uint8_t* buffer, uint16_t buffer_size, sw_t* sw) {
	if (!sw) {
		LOGE("[apdu__buffer_to_sw] The SW object is null");
		return -EINVAL;
	}

	if (!buffer) {
		LOGE("[apdu__buffer_to_sw] The buffer pointer is null");
		return -EINVAL;
	}

	if (buffer_size < SW_SIZE) {
		LOGE("[apdu__buffer_to_sw] Wrong buffer length. Min: %u, current: %u", SW_SIZE, buffer_size);
		return -EINVAL;
	}

	sw->sw1 = buffer[buffer_size - 2];
	sw->sw2 = buffer[buffer_size - 1];
	LOGT("[apdu__buffer_to_sw] SW1-SW2: %02X %02X", sw->sw1, sw->sw2);
		
	return 0;
}
