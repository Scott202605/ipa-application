/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include <errno.h>
#include "smartcard.h"
#include "log.h"
#include "apdu_utils.h"

#define MAX_STORE_DATA_COMMAND_APDU_SIZE 240

#define CLA_PROPRIETARY		0x80
#define INS_STORE_DATA		0xE2
#define INS_GET_RESPONSE	0xC0
#define INS_SELECT			0xA4
#define P1_STORE_DATA_NOT_LAST_BER	0x10
#define P1_STORE_DATA_LAST_BER		0x90
#define LE					0x00

#define APDU_CLA_POS	0
#define APDU_INS_POS	1
#define APDU_P1_POS		2
#define APDU_P2_POS		3
#define APDU_LC_POS		4 /* It only works when APDU Command Case 3 or 4 */

#define MIN_LOGICAL_CHANNEL	1
#define MAX_SUPPLEMENTARY_LOGICAL_CHANNEL	19
#define MIN_SUPPLEMENTARY_LOGICAL_CHANNEL	4
#define MAX_BASIC_LOGICAL_CHANNEL	3

#define CHECK_SW_LOGICAL_CHANNEL_ALREADY_CLOSED(sw1,sw2) ((sw1 == 0x62 && sw2 == 0x00))

/**
 * Response Message from MANAGE CHANNEL Command
*/
typedef struct response_open_channel_s {
	uint8_t logical_channel;
	sw_t sw;
} response_open_channel_t;

static int16_t smartcard__transceive_txrx_buffer_to_driver(smartcard_t* const context, const uint16_t bytes_to_transmit);
static void smartcard__set_logical_channel_to_txrx_buffer(smartcard_t* const context);
/* Extract data from TXRX buffer functions */
static int smartcard__write_txrx_buffer_to_response_open_channel(smartcard_t* const context, response_open_channel_t* response_open_channel, uint16_t bytes_received);
/* Write APDU to TXRX buffer functions */
static uint16_t smartcard__write_manage_channel_open_command_to_txrx_buffer(smartcard_t* const context);
static uint16_t smartcard__write_manage_channel_close_command_to_txrx_buffer(smartcard_t* const context);
static uint16_t smartcard__write_get_response_command_to_txrx_buffer(smartcard_t* const context, uint8_t length_of_data_expected);
static int16_t smartcard__write_select_command_to_txrx_buffer(smartcard_t* const context, const uint8_t* aid, uint8_t aid_size);
static int16_t smartcard__write_store_data_to_txrx_buffer(smartcard_t* const context, const uint8_t apdu_count, const bool response_data_is_expected, const uint8_t* tlv, const uint32_t tlv_size);
/* Smartcard class virtual functions */
static int smartcard__init_driver(smartcard_t* const context);
static int smartcard__deinit_driver(smartcard_t* const context);
static int16_t smartcard__transceive_bytes_to_driver(smartcard_t* const context, uint8_t* txrx_buffer, uint16_t txrx_buffer_size, uint16_t bytes_to_transmit);

void smartcard__ctor(smartcard_t* const context) {
	LOGT("[smartcard__ctor] Creating the smartcard object");

	static struct smartcard_vtable_s const vtbl = {
		&smartcard__init_driver,
		&smartcard__deinit_driver,
		&smartcard__transceive_bytes_to_driver
	};
	/* This virtual function table SHALL be overrided from its child class */
	context->smartcard_vptr = &vtbl; 
	context->additional_init_steps = NULL;
	context->additional_init_steps_context = NULL;
	context->logical_channel = 0;
	memset(context->txrx_buffer, 0, sizeof(context->txrx_buffer));
	context->is_driver_init = false;
	LOGT("[smartcard__ctor] Smartcard object created");
}

void smartcard__destory(smartcard_t* const context) {
	int err = 0;
	LOGT("[smartcard__destory] Destroying the smartcard object");

	if (context->is_driver_init) {
		if ((err = smartcard__deinit(context)) < 0) {
			LOGW("[smartcard__destory] Error deinitializing the smartcard object on destroy, err %d", err);
		}
	}
	LOGT("[smartcard__destory] Smartcard object destroyed");
}

void smartcard__set_additional_init_steps(smartcard_t* const context, smartcard_additional_init_steps_callback_t func, void* func_context) {
	if (context) {
		context->additional_init_steps = func;
		context->additional_init_steps_context = func_context;
	}
}

int smartcard__init(smartcard_t* const context) {
	int err;
	LOGT("[smartcard__init] Initializing smartcard");

	if (context->is_driver_init) {
		if ((err = smartcard__deinit(context)) < 0) {
			LOGE("[smartcard__init] Deinit smartcard was not successful, err %d", err);
			return err;
		}
	}
	if ((err = smartcard__init_driver(context)) < 0) {
		LOGE("[smartcard__init] Init smartcard was not successful, err %d", err);
		return err;
	}
	LOGT("[smartcard__init] Smartcard driver initialized");
	context->is_driver_init = true;

	if (context->additional_init_steps) {
		LOGT("[smartcard__init] Executing additional init steps");
		if ((err = context->additional_init_steps(context->additional_init_steps_context)) < 0) {
			LOGE("[smartcard__init] Error on execute the additional init steps, err %d", err);
			// In this case we need to deinitialize the driver
			if ((err = smartcard__deinit_driver(context)) < 0) {
				LOGE("[smartcard__init] Error on deinitialize the Smartcard driver after a unsuccessful exection of additional init steps, err %d", err);
				return err;
			}
			context->is_driver_init = false;
			context->logical_channel = 0;
			return -ECANCELED;
		}
	}
	LOGT("[smartcard__init] Smartcard initialized");

	return 0;
}

int smartcard__deinit(smartcard_t* const context) {
	int err;
	LOGT("[smartcard__deinit] Deinitializing smartcard");

	if (!context->is_driver_init) {
		LOGT("[smartcard__deinit] The smartcard is already deinitialized");
		return 0;
	}

	if (context->logical_channel != 0) {
		if ((err = smartcard__close_channel(context)) < 0) {
			LOGE("[smartcard__deinit] Error on close the opened logical channel, err %d", err);
			return err;
		}
	}
	if ((err = smartcard__deinit_driver(context)) < 0) {
		LOGE("[smartcard__deinit] Deinit smartcard was not successful, err %d", err);
		return err;
	}

	context->is_driver_init = false;
	context->logical_channel = 0;
	LOGT("[smartcard__deinit] Smartcard deinitialized");

	return 0;
}

int smartcard__open_channel(smartcard_t * const context) {
	uint16_t written_bytes = 0;
	int16_t bytes_received = 0;
	response_open_channel_t rsp_open_channel = { 0 };

	if (context->logical_channel != 0 && smartcard__close_channel(context) < 0) {
		LOGE("[smartcard__open_channel] Error recovering the logical channel state");
		return -ECANCELED;
	}

	written_bytes = smartcard__write_manage_channel_open_command_to_txrx_buffer(context);

	if ((bytes_received = smartcard__transceive_txrx_buffer_to_driver(context, written_bytes)) < SW_SIZE) {
		LOGE("[smartcard__open_channel] Error on send the MANAGE CHANNEL command APDU to the smartcard driver, err %d", bytes_received);
		return -EIO;
	}

	if (smartcard__write_txrx_buffer_to_response_open_channel(context, &rsp_open_channel, (uint16_t) bytes_received) < 0) {
		LOGE("[smartcard__open_channel] Error extracting the Open Channel APDU response");
		return -ECANCELED;
	}

	if (!apdu_utils__sw_is_success(&rsp_open_channel.sw)) {
		LOGE("[smartcard__open_channel] Bad APDU response SW: 0x%02X%02X", rsp_open_channel.sw.sw1, rsp_open_channel.sw.sw2);
		return -ECANCELED;
	}

	if (rsp_open_channel.logical_channel >= MIN_LOGICAL_CHANNEL && rsp_open_channel.logical_channel <= MAX_SUPPLEMENTARY_LOGICAL_CHANNEL) {
		context->logical_channel = rsp_open_channel.logical_channel;
		LOGD("[smartcard__open_channel] Logical channel %u opened", context->logical_channel);
		return 0;
	}
	else {
		LOGE("[smartcard__open_channel] The logical channel value is out of the boundary : %02X", rsp_open_channel.logical_channel);
		return -ECANCELED;
	}
}

int smartcard__close_channel(smartcard_t* const context) {
	uint16_t written_bytes = 0;
	int16_t bytes_received = 0;
	sw_t sw = { 0 };

	if (context->logical_channel == 0) {
		LOGT("[smartcard__close_channel] None logical channel is opened");
		return 0;
	}

	written_bytes = smartcard__write_manage_channel_close_command_to_txrx_buffer(context);

	if ((bytes_received = smartcard__transceive_txrx_buffer_to_driver(context, written_bytes)) < 0) {
		LOGE("[smartcard__close_channel] Error on send the MANAGE CHANNEL command APDU to the smartcard driver, err %d", bytes_received);
		return -EIO;
	}

	if (apdu__buffer_to_sw(context->txrx_buffer, (uint16_t) bytes_received, &sw) < 0) {
		LOGE("[smartcard__close_channel] Error extracting data from the APDU response");
		return -ECANCELED;
	}

	if (apdu_utils__sw_is_success(&sw) || CHECK_SW_LOGICAL_CHANNEL_ALREADY_CLOSED(sw.sw1, sw.sw2)) {
		LOGD("[smartcard__close_channel] Logical channel %u closed sucessfully", context->logical_channel);
		context->logical_channel = 0;
		return 0;
	} else if (apdu_utils__sw_logical_channel_not_supported(&sw)) { // This error has been seen in some refresh cases
		LOGD("[smartcard__close_channel] Logical channel %u not supported, the logical channel is considered as closed", context->logical_channel);
		context->logical_channel = 0;
		return 0;
	} else {
		LOGE("[smartcard__close_channel] Bad APDU response SW: 0x%02X%02X", sw.sw1, sw.sw2);
		return -ECANCELED;
	}
}

int smartcard__send_get_response(smartcard_t* const context, uint8_t length_of_data_expected, response_apdu_t* response_apdu) {
	uint16_t written_bytes = 0;
	int16_t bytes_received = 0;

	if (!response_apdu) {
		LOGE("[smartcard__send_get_response] The response APDU object is null");
		return -EINVAL;
	}
	
	written_bytes = smartcard__write_get_response_command_to_txrx_buffer(context, length_of_data_expected);

	if ((bytes_received = smartcard__transceive_txrx_buffer_to_driver(context, written_bytes)) < 0) {
		LOGE("[smartcard__send_get_response] Error on send the GET RESPONSE command APDU to the smartcard driver, err %d", bytes_received);
		return -EIO;
	}

	if (apdu__buffer_to_reponse_apdu(context->txrx_buffer, (uint16_t) bytes_received, response_apdu) < 0) {
		LOGE("[smartcard__send_get_response] Error extracting data from the APDU response");
		return -ECANCELED;
	}

	return 0;
}

//Case 1 CLA | INS | P1 | P2
//Case 2 CLA | INS | P1 | P2 | Le
//Case 3 CLA | INS | P1 | P2 | Lc | Data Field
//Case 4 CLA | INS | P1 | P2 | Lc | Data Field | Le
int smartcard__send_apdu(smartcard_t* const context, const command_apdu_t* command_apdu, response_apdu_t* response_apdu) {
	int16_t buffer_offset;

	if (!command_apdu) {
		LOGE("[smartcard__send_apdu] The command APDU object is null");
		return -EINVAL;
	}

	if (!response_apdu) {
		LOGE("[smartcard__send_apdu] The response APDU object is null");
		return -EINVAL;
	}

	if ((buffer_offset = apdu__command_apdu_to_buffer(command_apdu, context->txrx_buffer, sizeof(context->txrx_buffer))) < 0) {
		LOGE("[smartcard__send_apdu] Error writing the Command APDU to the TXRX buffer, err %d", buffer_offset);
		return -ECANCELED;
	}	

	if ((buffer_offset = smartcard__transceive_txrx_buffer_to_driver(context, (uint16_t) buffer_offset)) < 0) {
		LOGE("[smartcard__send_apdu] Error on send the APDU to the smartcard driver, err %d", buffer_offset);
		return -EIO;
	}

	if (apdu__buffer_to_reponse_apdu(context->txrx_buffer, (uint16_t) buffer_offset, response_apdu) < 0) {
		LOGE("[smartcard__send_apdu] Error extracting data from the APDU response");
		return -ECANCELED;
	}

	return 0;
}

//Case 1 CLA | INS | P1 | P2
//Case 3 CLA | INS | P1 | P2 | Lc | Data Field
int smartcard__send_apdu_sw_response(smartcard_t* const context, const command_apdu_t* command_apdu, sw_t* sw) {
	int16_t buffer_offset;

	if (!command_apdu) {
		LOGE("[smartcard__send_apdu_sw_response] The command APDU object is null");
		return -EINVAL;
	}

	if (!sw) {
		LOGE("[smartcard__send_apdu_sw_response] The SW object is null");
		return -EINVAL;
	}


	if ((buffer_offset = apdu__command_apdu_to_buffer(command_apdu, context->txrx_buffer, sizeof(context->txrx_buffer))) < 0) {
		LOGE("[smartcard__send_apdu_sw_response] Error writing the Command APDU to the TXRX buffer, err %d", buffer_offset);
		return -ECANCELED;
	}

	if ((buffer_offset = smartcard__transceive_txrx_buffer_to_driver(context, buffer_offset)) < 0) {
		LOGE("[smartcard__send_apdu_sw_response] Error on send the APDU to the smartcard driver, err %d", buffer_offset);
		return -EIO;
	}

	if (apdu__buffer_to_sw(context->txrx_buffer, (uint16_t) buffer_offset, sw) < 0) {
		LOGE("[smartcard__send_apdu_sw_response] Error extracting data from the APDU response");
		return -ECANCELED;
	}

	return 0;
}

int smartcard__send_select(smartcard_t* const context, const uint8_t* aid, uint8_t aid_size, response_apdu_t* response_apdu) {
	int16_t buffer_offset;

	if (!aid || aid_size == 0) {
		LOGE("[smartcard__send_select] The AID is empty/null");
		return -EINVAL;
	}

	if (!response_apdu) {
		LOGE("[smartcard__send_select] The response APDU object is null");
		return -EINVAL;
	}

	LOG_DATA(eLogTrace, "[smartcard__send_select] AID", aid, aid_size);

	if ((buffer_offset = smartcard__write_select_command_to_txrx_buffer(context, aid, aid_size)) < 0) {
		LOGE("[smartcard__send_select] Error writing the SELECT Command APDU to the TXRX buffer, err %d", buffer_offset);
		return -ECANCELED;
	}

	if ((buffer_offset = smartcard__transceive_txrx_buffer_to_driver(context, buffer_offset)) < 0) {
		LOGE("[smartcard__send_select] Error on send the SELECT Command APDU to the smartcard driver, err %d", buffer_offset);
		return -EIO;
	}

	if (apdu__buffer_to_reponse_apdu(context->txrx_buffer, (uint16_t) buffer_offset, response_apdu) < 0) {
		LOGE("[smartcard__send_select] Error extracting data from the APDU response");
		return -ECANCELED;
	}

	return 0;
}

int smartcard__store_data(smartcard_t* const context, const uint8_t* store_data_tlv, uint32_t store_data_tlv_size, bool response_data_expected, response_apdu_t* response_apdu) {
	uint32_t unread_bytes = store_data_tlv_size;
	int16_t buffer_offset = 0;
	uint8_t apdu_count = 0;

	if (!store_data_tlv || store_data_tlv_size == 0) {
		LOGE("[smartcard__store_data] The BER-TLV to store is empty/null");
		return -EINVAL;
	}
	if (!response_apdu) {
		LOGE("[smartcard__store_data] The response APDU object is null");
		return -EINVAL;
	}
	LOG_DATA(eLogTrace, "[smartcard__store_data] STORE DATA", store_data_tlv, store_data_tlv_size);

	while (unread_bytes > 0) {
		if ((buffer_offset = smartcard__write_store_data_to_txrx_buffer(context, apdu_count, response_data_expected, store_data_tlv, store_data_tlv_size)) < 0) {
			LOGE("[smartcard__store_data] Error writing the STORE DATA Command APDU num %u to the TXRX buffer, err %d", apdu_count, buffer_offset);
			return -ECANCELED;
		}
		unread_bytes -= context->txrx_buffer[APDU_LC_POS];

		if ((buffer_offset = smartcard__transceive_txrx_buffer_to_driver(context, buffer_offset)) < 0) {
			LOGE("[smartcard__store_data] Error on send the STORE DATA Command APDU to the smartcard driver, err %d", buffer_offset);
			return -EIO;
		}

		apdu_count++;
	}

	if (apdu__buffer_to_reponse_apdu(context->txrx_buffer, (uint16_t) buffer_offset, response_apdu) < 0) {
		LOGE("[smartcard__store_data] Error extracting data from the APDU response");
		return -ECANCELED;
	}

	return 0;

}

static int16_t smartcard__transceive_txrx_buffer_to_driver(smartcard_t* const context, const uint16_t bytes_to_transmit) {
	int16_t response_apdu_bytes;
	if (!context->is_driver_init) {
		LOGE("[smartcard__transceive_txrx_buffer_to_driver] The driver is not initialized");
		return -EPERM;
	}
	smartcard__set_logical_channel_to_txrx_buffer(context);
	/* kepp the last cla, used for 61xx response to chain GET Response */
	context->last_cla = context->txrx_buffer[APDU_CLA_POS];
#ifdef DEBUG_APDU
	LOG_DATA(eLogInfo, "[smartcard__transceive_txrx_buffer_to_driver] Command APDU", context->txrx_buffer, bytes_to_transmit);
#else
	LOG_DATA(eLogDebug, "[smartcard__transceive_txrx_buffer_to_driver] Command APDU", context->txrx_buffer, bytes_to_transmit);
#endif
	if ((response_apdu_bytes = smartcard__transceive_bytes_to_driver(context, context->txrx_buffer, sizeof(context->txrx_buffer), bytes_to_transmit)) < 0) {
		LOGE("[smartcard__transceive_txrx_buffer_to_driver] Error in transceive the txrx buffer to the driver, err %d", response_apdu_bytes);
		return response_apdu_bytes;
	}
#ifdef DEBUG_APDU
	LOG_DATA(eLogInfo, "[smartcard__transceive_txrx_buffer_to_driver] Response APDU", context->txrx_buffer, response_apdu_bytes);
#else
	LOG_DATA(eLogDebug, "[smartcard__transceive_txrx_buffer_to_driver] Response APDU", context->txrx_buffer, response_apdu_bytes);
#endif
	return response_apdu_bytes;
}

/**
 * ref. GlobalPlatfrom Technology Card Specification Version 2.3.1 - 11.1.4 Class Byte Coding
 */
static void smartcard__set_logical_channel_to_txrx_buffer(smartcard_t* const context) {
	// Clean the CLA channel information as provided by the user, if secure channel is present more check are needed
    bool secure_messaging = 0;
    if ((context->txrx_buffer[APDU_CLA_POS] & 0x40) == 0x40) {
        secure_messaging = ((context->txrx_buffer[APDU_CLA_POS] & 0x20) == 0x20); // Bit 5(b6) in Extended logical channel means SM
    } else {
        secure_messaging = ((context->txrx_buffer[APDU_CLA_POS] & 0x04) == 0x04); // Bit 2(b3) in Extended logical channel means SM(we only care about GP SC, not ISO7816 SC)
    }
    context->txrx_buffer[APDU_CLA_POS] &= 0x90; // We only keep b8 and b5 of the original CLA
    // Set the correct logical channel
    if (context->logical_channel <= 3) {
        // b2 to b1 represent the channels 0 - 3
        context->txrx_buffer[APDU_CLA_POS] |= (context->logical_channel & 0x03) | (secure_messaging << 2); // Bit 2(b3) in Extended logical channel means SM(we only care about GP SC, not ISO7816 SC)
    } else {
        // b4 to b1 represent the channels 4 - 19
        context->txrx_buffer[APDU_CLA_POS] |= (((context->logical_channel - 4) & 0x0F) | 0x40) | (secure_messaging << 5); // Bit 5(b6) in Extended logical channel means SM
    }
}

static int smartcard__write_txrx_buffer_to_response_open_channel(smartcard_t* const context, response_open_channel_t* response_open_channel, uint16_t bytes_received) {
	if (!response_open_channel) {
		LOGE("[smartcard__write_txrx_buffer_to_response_open_channel] The response Open Channel object is null");
		return -EINVAL;
	}

	if (bytes_received < SW_SIZE || bytes_received > 3) {
		LOGE("[smartcard__write_txrx_buffer_to_response_open_channel] Bad number of bytes received. Min: %u, Max: 3, current: %u", SW_SIZE, bytes_received);
		return -EINVAL;
	}

	if (bytes_received == 3) {
		response_open_channel->logical_channel = context->txrx_buffer[0];
	}

	return apdu__buffer_to_sw(context->txrx_buffer, bytes_received, &response_open_channel->sw);
}

static uint16_t smartcard__write_manage_channel_open_command_to_txrx_buffer(smartcard_t* const context) {
	uint16_t buffer_length = 0;
	context->txrx_buffer[buffer_length++] = 0x00;
	context->txrx_buffer[buffer_length++] = 0x70;						//INS MANAGE CHANNEL
	context->txrx_buffer[buffer_length++] = 0x00;						//P1 OPEN
	context->txrx_buffer[buffer_length++] = 0x00;
	context->txrx_buffer[buffer_length++] = 0x01;

	return buffer_length;
}

static uint16_t smartcard__write_manage_channel_close_command_to_txrx_buffer(smartcard_t* const context) {
	uint16_t buffer_length = 0;
	context->txrx_buffer[buffer_length++] = 0x00;
	context->txrx_buffer[buffer_length++] = 0x70;						//INS MANAGE CHANNEL
	context->txrx_buffer[buffer_length++] = 0x80;						//P1 CLOSE
	context->txrx_buffer[buffer_length++] = context->logical_channel;
	context->txrx_buffer[buffer_length++] = 0x00;
	
	return buffer_length;
}

static uint16_t smartcard__write_get_response_command_to_txrx_buffer(smartcard_t* const context, uint8_t length_of_data_expected) {
	uint16_t buffer_length = 0;
	context->txrx_buffer[buffer_length++] = context->last_cla;			//CLA
	context->txrx_buffer[buffer_length++] = INS_GET_RESPONSE;			//INS GET RESPONSE
	context->txrx_buffer[buffer_length++] = 0x00;						//P1 RFU
	context->txrx_buffer[buffer_length++] = 0x00;						//P2 RFU
	context->txrx_buffer[buffer_length++] = length_of_data_expected;	//Le

	return buffer_length;
}

static int16_t smartcard__write_select_command_to_txrx_buffer(smartcard_t* const context, const uint8_t* aid, uint8_t aid_size) {
	uint16_t buffer_length = 0;

	if (!aid || aid_size == 0) {
		LOGE("[smartcard__write_select_command_to_txrx_buffer] The AID is empty/null");
		return -EINVAL;
	}

	context->txrx_buffer[buffer_length++] = 0x00;					//CLA
	context->txrx_buffer[buffer_length++] = INS_SELECT;				//INS SELECT
	context->txrx_buffer[buffer_length++] = 0x04;					//P1 Select by name
	context->txrx_buffer[buffer_length++] = 0x00;					//P2 First or only occurrence
	context->txrx_buffer[buffer_length++] = aid_size;				//Lc Length of AID
	memcpy(context->txrx_buffer + buffer_length, aid, aid_size);	//Data AID of Application to be selected
	buffer_length += aid_size;
	context->txrx_buffer[buffer_length++] = LE;					//Le


	return buffer_length;
}

static int16_t smartcard__write_store_data_to_txrx_buffer(smartcard_t* const context, const uint8_t apdu_count, const bool response_data_is_expected, const uint8_t* tlv, const uint32_t tlv_size) {
	uint32_t bytes_stored;
	uint32_t pending_bytes;
    uint16_t buffer_offset = 0;
    bool is_last_block;

	if (!tlv || tlv_size == 0) {
		LOGE("[smartcard__write_store_data_to_txrx_buffer] The TLV is empty/null");
		return -EINVAL;
	}

	bytes_stored = apdu_count * MAX_STORE_DATA_COMMAND_APDU_SIZE;
	if (bytes_stored > tlv_size) {
		LOGE("[smartcard__write_store_data_to_txrx_buffer] Bad APDU count, the bytes stored (%u) are higer than the TLV size (%u)", bytes_stored, tlv_size);
		return -EINVAL;
	}
	pending_bytes = tlv_size - bytes_stored;
	is_last_block = pending_bytes <= MAX_STORE_DATA_COMMAND_APDU_SIZE;
    
	context->txrx_buffer[buffer_offset++] = CLA_PROPRIETARY;
	context->txrx_buffer[buffer_offset++] = INS_STORE_DATA;
    /* Set P1 */
    if (is_last_block) {
        context->txrx_buffer[buffer_offset] = P1_STORE_DATA_LAST_BER; // P1: Overwrite to Last block
    } else {
		context->txrx_buffer[buffer_offset] = P1_STORE_DATA_NOT_LAST_BER;
	}
    if (response_data_is_expected) {
		context->txrx_buffer[buffer_offset] |= 0x01; // P1: ISO case 4 command (response data may be returned)
	}
    buffer_offset++;
    context->txrx_buffer[buffer_offset++] = apdu_count; // P2
    context->txrx_buffer[buffer_offset++] = is_last_block ? pending_bytes : MAX_STORE_DATA_COMMAND_APDU_SIZE; // Lc
    /* Set Data */
    memcpy(context->txrx_buffer + buffer_offset, tlv + bytes_stored, context->txrx_buffer[APDU_LC_POS]);
    buffer_offset += context->txrx_buffer[APDU_LC_POS];
    context->txrx_buffer[buffer_offset++] = LE; // Le
    
    return buffer_offset;
}

static int smartcard__init_driver(smartcard_t* const context) {
	return (*context->smartcard_vptr->init_driver) (context);
}

static int smartcard__deinit_driver(smartcard_t* const context) {
	return (*context->smartcard_vptr->deinit_driver) (context);
}

static int16_t smartcard__transceive_bytes_to_driver(smartcard_t* const context, uint8_t* txrx_buffer, uint16_t txrx_buffer_size, uint16_t bytes_to_transmit) {
	return (*context->smartcard_vptr->transceive_bytes_to_driver) (context, txrx_buffer, txrx_buffer_size, bytes_to_transmit);
}
