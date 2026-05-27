/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"
#include "smartcard_at.h"

#define SERIAL_PORT_NAME_MAX_SIZE 16

 /**
  * @brief Structure representing an external smartcard AT context.
  * 
  * @param super The base smartcard_at_t structure.
  * @param sp_name The name of the serial port.
  * @param baud_rate The baud rate for the serial port.
  * @param hw_context A pointer to the hardware context.
  * @param first_init_done Indicates if the first initialization of the instance is done. This allows us to perform a one-time test per instance to determine the value of at_command_echoing
  * @param at_commands_echoing Indicates if the AT commands are echoing. This value is set in the first initialization of the instance and is not modified until the destroy.
  */
typedef struct smartcard_at_external_s {
	smartcard_at_t super;
	char sp_name[SERIAL_PORT_NAME_MAX_SIZE];
	uint32_t baud_rate;
	void* hw_context;
  bool first_init_done;
  bool at_commands_echoing;
} smartcard_at_external_t;

/**
 * @brief Constructs and initializes the smartcard_at_external_t context.
 * See smartcard_at_external__destory()
 * 
 * @param context Pointer to the smartcard_at_external_t context to initialize.
 * @param serial_port Pointer to the name of the serial port, add c-string only
 * @param baud_rate The baud rate for the serial port.
 * 
 * @return Upon successful execution, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int smartcard_at_external__ctor(smartcard_at_external_t* const context, const char* sp_name, const uint32_t baud_rate);

/**
 * @brief Destroys and cleans up the smartcard_at_external_t context.
 *
 * @param context Pointer to the smartcard_at_external_t context to destroy.
 */
void smartcard_at_external__destory(smartcard_at_external_t* const context);

