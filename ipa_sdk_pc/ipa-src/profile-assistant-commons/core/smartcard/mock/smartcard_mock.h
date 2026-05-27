/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"
#include "smartcard.h"

struct smartcard_mock_vtable_s;

typedef struct apdu_mock_s {
    uint8_t* data;
    uint32_t size;
} apdu_mock_t;

typedef struct apdu_mock_dictionary_s {
    apdu_mock_t* apdu_command_list;
    apdu_mock_t* apdu_response_list;
    uint32_t list_size;
} apdu_mock_dictionary_t;

typedef struct smartcard_mock_s {
	smartcard_t super;
	struct smartcard_mock_vtable_s const* smartcard_mock_vptr;
	apdu_mock_dictionary_t apdu_mock_dict;
} smartcard_mock_t;

/*
 * for external or internal child class
 */ 
struct smartcard_mock_vtable_s {
	int (*init_driver) (smartcard_mock_t* const context);
	int (*deinit_driver) (smartcard_mock_t* const context);
	int16_t (*transceive_mock_command_to_driver) (smartcard_mock_t* const context, uint8_t* at_buffer, uint16_t at_buffer_size, uint16_t bytes_to_transmit);
};

/**
 * @brief Constructs and initializes the smartcard_mock_t context.
 * See smartcard_mock__destory()
 * 
 * @param context Pointer to the smartcard_mock_t to initialize its data.
 */
void smartcard_mock__ctor(smartcard_mock_t* const context);

/**
 * @brief Destroys and cleans up the smartcard_mock_t context.
 * 
 * @param context Pointer to the smartcard_mock_t to destory its data.
 */
void smartcard_mock__destory(smartcard_mock_t* const context);

/**
 * @brief Allows to store a mock APDU Command - APDU Response
 */
int smartcard_mock__store_apdu_command(smartcard_mock_t* const context, const uint8_t* apdu_command, const uint32_t apdu_command_size, const uint8_t* apdu_command_response, const uint32_t apdu_command_response_size);
