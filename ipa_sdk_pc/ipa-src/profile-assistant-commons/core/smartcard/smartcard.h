/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"
#include "apdu.h"

struct smartcard_vtable_s;

#define TXRX_MAX_BUFFER_SIZE 261

struct smartcard_vtable_s;

typedef int (*smartcard_additional_init_steps_callback_t) (void* const context);

/**
 * SmartCard.
*/
typedef struct smartcard_s {
	struct smartcard_vtable_s const *smartcard_vptr;
	uint8_t txrx_buffer[TXRX_MAX_BUFFER_SIZE];
	smartcard_additional_init_steps_callback_t additional_init_steps;
	void* additional_init_steps_context;
	uint8_t logical_channel;
	uint8_t last_cla; /* only needed when the response was 61XX */
	bool is_driver_init;
} smartcard_t;

/**
 * SmartCard Virtual Function Table.
*/
struct smartcard_vtable_s {
	int (*init_driver) (smartcard_t* const context);
	int (*deinit_driver) (smartcard_t* const context);
	int16_t (*transceive_bytes_to_driver) (smartcard_t* const context, uint8_t* txrx_buffer, uint16_t txrx_buffer_size, uint16_t bytes_to_transmit);
};

/**
 * @brief Constructor for the smartcard class, initializes its fields.
 * See smartcard__destory()
 * 
 * @param context access to the instance's data.
 */
void smartcard__ctor(smartcard_t* const context);

/**
 * @brief Allow additional steps to be added when initializing the Smartcard instance.
 * 
 * This functionality is useful for cases where the driver detects that a reset of the UICC has to be executed.
 * Once the UICC reset is detected, the driver will call the init function, and setting additional custom steps 
 * in the initialization we can leave the state of the UICC ready again (e.g. with an applet selected) so that 
 * it can be used from the outside without any extra handling.
 * 
 * @param context A Smartcard handle from a successful call to smartcard__ctor().
 * @param func Callback function with the additional steps to execute on Smartcard instance initialization.
 * @param func_context Context that will be passed as a parameter in the callback funcion call.
 */
void smartcard__set_additional_init_steps(smartcard_t* const context, smartcard_additional_init_steps_callback_t func, void* func_context);

/**
 * @brief Initializes the smartcard, opening the communication with the UICC.
 * See smartcard__deinit()
 * 
 * @param context A Smartcard handle from a successful call to smartcard__ctor().
 * 
 * @return Upon successful execution, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int smartcard__init(smartcard_t* const context);

/**
 * @brief Deinitializes the smartcard, closing the communication with the UICC.
 * 
 * @param context A initialized Smartcard handle from a successful call to smartcard__init().
 * 
 * @return Upon successful execution, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int smartcard__deinit(smartcard_t* const context);

/**
 * @brief Deinitializes the smartcard.
 * 
 * @param context A Smartcard handle from a successful call to smartcard__ctor().
*/
void smartcard__destory(smartcard_t* const context);

/**
 * @brief Opens a logical channel on the smartcard.
 * 
 * @param context A initialized Smartcard handle from a successful call to smartcard__init().
 * 
 * @return Upon successful execution, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int smartcard__open_channel(smartcard_t* const context);

/**
 * @brief Closes a logical channel on the smartcard.
 * 
 * @param context A initialized Smartcard handle from a successful call to smartcard__init().
 * 
 * @return Upon successful execution, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int smartcard__close_channel(smartcard_t* const context);

/**
 * If the value of SW1 has a value of 61xx, then it indicates that there is more data to be retrieved from the card. 
 * In this case, the GET RESPONSE command should be called again, with the Le (length xx) parameter set to the value of SW2 from the previous response. 
 * This will retrieve the remaining data from the card. 
 * @brief Sends a GET RESPONSE command to the smartcard and retrieves the response APDU.
 * 
 * @param context A initialized Smartcard handle from a successful call to smartcard__init().
 * @param length_of_data_expected length of data expected is extracted from SW2 value in response of command APDU. ref. ISO 7816-4 5.3.4 Response chaining
 * @param response_apdu	response APDU data from GET RESPONSE command. 
 * 
 * @return Upon successful execution, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int smartcard__send_get_response(smartcard_t* const context, uint8_t length_of_data_expected, response_apdu_t* response_apdu);

/**
 * @brief Sends an APDU command to the smartcard and retrieves the response APDU.
 * 
 * @param context A initialized Smartcard handle from a successful call to smartcard__init().
 * @param command_apdu Pointer to the command APDU to send to the smartcard.
 * @param response_apdu Pointer to the response APDU data received from the smartcard.
 * 
 * @return Upon successful execution, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int smartcard__send_apdu(smartcard_t* const context, const command_apdu_t* command_apdu, response_apdu_t* response_apdu);

/**
 * @brief Sends an APDU command to the smartcard and retrieves the status word.
 * 
 * @param context A initialized Smartcard handle from a successful call to smartcard__init().
 * @param command_apdu Pointer to the command APDU to send to the smartcard.
 * @param sw Pointer to STATUS WORD data received from the smartcard.
 * 
 * @return Upon successful execution, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int smartcard__send_apdu_sw_response(smartcard_t* const context, const command_apdu_t* command_apdu, sw_t* sw);

/**
 * @brief Sends a SELECT command to the smartcard and retrieves the response APDU.
 * 
 * @param context A initialized Smartcard handle from a successful call to smartcard__init().
 * @param aid Pointer to an array containing the Application Identifier (AID) to select on the smartcard.
 * @param aid_size Size of the AID array.
 * @param response_apdu Pointer to the response APDU data received from the smartcard.
 * 
 * @return Upon successful execution, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int smartcard__send_select(smartcard_t* const context, const uint8_t* aid, uint8_t aid_size, response_apdu_t* response_apdu);

/**
 * @brief Sends a STORE DATA command to the smartcard and retrieves the response APDU.
 * 
 * @param context A initialized Smartcard handle from a successful call to smartcard__init().
 * @param store_data_tlv Pointer to an array containing the data to store in Tag-Length-Value (TLV) format.
 * @param store_data_tlv_size Size of the store_data_tlv array
 * @param response_data_expected Boolean value indicating whether a response APDU is expected from the smartcard. (true - ISO case 4 / false - ISO case 3)
 * @param response_apdu Pointer to the response APDU data received from the smartcard. This parameter is only used if response_data_expected is true.
 * 
 * @return Upon successful execution, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int smartcard__store_data(smartcard_t* const context, const uint8_t* store_data_tlv, uint32_t store_data_tlv_size, bool response_data_expected, response_apdu_t* response_apdu);
