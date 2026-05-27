/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"
#include "smartcard.h"

struct smartcard_at_vtable_s;

typedef struct {
	smartcard_t super;
	struct smartcard_at_vtable_s const* smartcard_at_vptr;
} smartcard_at_t;

/*
 * for external or internal child class
 */ 
struct smartcard_at_vtable_s {
	int (*init_driver) (smartcard_at_t* const context);
	int (*deinit_driver) (smartcard_at_t* const context);
	int16_t (*transceive_at_command_to_driver) (smartcard_at_t* const context, uint8_t* at_buffer, uint16_t at_buffer_size, uint16_t bytes_to_transmit);
};

/**
 * @brief Constructs and initializes the smartcard_at_t context.
 * See smartcard_at__destory()
 * 
 * @param context Pointer to the smartcard_at_t to initialize its data.
 */
void smartcard_at__ctor(smartcard_at_t* const context);

/**
 * @brief Destroys and cleans up the smartcard_at_t context.
 * 
 * @param context Pointer to the smartcard_at_t to destory its data.
 */
void smartcard_at__destory(smartcard_at_t* const context);
