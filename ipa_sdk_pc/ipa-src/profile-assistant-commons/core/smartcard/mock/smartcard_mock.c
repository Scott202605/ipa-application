/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include <stdio.h>
#include <stdlib.h>
#include "smartcard_mock.h"
#include "memory_manager.h"
#include "log.h"
#include <errno.h>

static int smartcard_mock__init_driver(smartcard_t* const context);
static int smartcard_mock__deinit_driver(smartcard_t* const context);
static int16_t smartcard_mock__transceive_apdu(smartcard_t* const context, uint8_t* apdu_buffer, uint16_t apdu_buffer_size, uint16_t bytes_to_transmit);

void smartcard_mock__ctor(smartcard_mock_t* const context) {
	smartcard__ctor(&context->super);

    static struct smartcard_vtable_s const vtbl = {
        &smartcard_mock__init_driver,
        &smartcard_mock__deinit_driver,
        &smartcard_mock__transceive_apdu
    };
    context->super.smartcard_vptr = &vtbl;
    context->apdu_mock_dict.apdu_command_list = NULL;
    context->apdu_mock_dict.apdu_response_list = NULL;
    context->apdu_mock_dict.list_size = 0;
    LOGD("[smartcard_mock__ctor] Mock instance created");
}

void smartcard_mock__destory(smartcard_mock_t* const context) {
    for (uint32_t i = 0; i < context->apdu_mock_dict.list_size; i++) {
        /* Free all the keys and values */
        M_free(context->apdu_mock_dict.apdu_command_list[i].data);
        M_free(context->apdu_mock_dict.apdu_response_list[i].data);
        context->apdu_mock_dict.apdu_command_list[i].data = NULL;
        context->apdu_mock_dict.apdu_response_list[i].data = NULL;
        context->apdu_mock_dict.apdu_command_list[i].size = 0;
        context->apdu_mock_dict.apdu_response_list[i].size = 0;
    }
    /* Free the key and value lists */
    M_free(context->apdu_mock_dict.apdu_command_list);
    M_free(context->apdu_mock_dict.apdu_response_list);
    context->apdu_mock_dict.apdu_command_list = NULL;
    context->apdu_mock_dict.apdu_response_list = NULL;
    context->apdu_mock_dict.list_size = 0;

	smartcard__destory(&context->super);
}

int smartcard_mock__store_apdu_command(smartcard_mock_t* const context, const uint8_t* apdu_command, const uint32_t apdu_command_size, const uint8_t* apdu_command_response, const uint32_t apdu_command_response_size) {
    void* ptr_apdu_command_list;
    void* ptr_apdu_response_list;
    void* ptr_apdu_command;
    void* ptr_apdu_response;

    if (!apdu_command || apdu_command_size == 0) {
        return -EINVAL;
    }

    if (!apdu_command_response || apdu_command_response_size == 0) {
        return -EINVAL;
    }

    LOG_DATA(eLogTrace, "[smartcard_mock__store_apdu_command] APDU command to store", apdu_command, apdu_command_size);
    LOG_DATA(eLogTrace, "[smartcard_mock__store_apdu_command] APDU command responseto store", apdu_command_response, apdu_command_response_size);

    /* Allocate data for the key of the entry */
    ptr_apdu_command = M_malloc(apdu_command_size);
    if (!ptr_apdu_command) {
        return -ENOMEM;
    }

    /* Allocate data for the value of the entry */
    ptr_apdu_response = M_malloc(apdu_command_response_size);
    if (!ptr_apdu_response) {
        M_free(ptr_apdu_command);
        return -ENOMEM;
    }

    /* Increase the allocation of the key list to add the new entry */
    ptr_apdu_command_list = M_realloc(context->apdu_mock_dict.apdu_command_list, sizeof(apdu_mock_t) * (context->apdu_mock_dict.list_size + 1));
    if (!ptr_apdu_command_list) {
        M_free(ptr_apdu_command);
        M_free(ptr_apdu_response);
        return -ENOMEM;
    }
    context->apdu_mock_dict.apdu_command_list = ptr_apdu_command_list;

    /* Increase the allocation of the value list to add the new entry */
    ptr_apdu_response_list = M_realloc(context->apdu_mock_dict.apdu_response_list, sizeof(apdu_mock_t) * (context->apdu_mock_dict.list_size + 1));
    if (!ptr_apdu_response_list) {
        M_free(ptr_apdu_command);
        M_free(ptr_apdu_response);
        // M_free(ptr_apdu_response_list); We don't want to free all the list in case of failure (realloc can be done in the same pointer)
        return -ENOMEM;
    }
    context->apdu_mock_dict.apdu_response_list = ptr_apdu_response_list;

    /* Add the key of the new entry in the dict */
    context->apdu_mock_dict.apdu_command_list[context->apdu_mock_dict.list_size].data = ptr_apdu_command;
    memcpy(context->apdu_mock_dict.apdu_command_list[context->apdu_mock_dict.list_size].data, apdu_command, apdu_command_size);
    context->apdu_mock_dict.apdu_command_list[context->apdu_mock_dict.list_size].size = apdu_command_size;
    /* Add the value of the new entry in the dict */
    context->apdu_mock_dict.apdu_response_list[context->apdu_mock_dict.list_size].data = ptr_apdu_response;
    memcpy(context->apdu_mock_dict.apdu_response_list[context->apdu_mock_dict.list_size].data, apdu_command_response, apdu_command_response_size);
    context->apdu_mock_dict.apdu_response_list[context->apdu_mock_dict.list_size].size = apdu_command_response_size;
    /* Increment the dict elements size*/
    context->apdu_mock_dict.list_size++;

    return 0;
}

static int smartcard_mock__init_driver(smartcard_t* const context) {
    return 0;
}

static int smartcard_mock__deinit_driver(smartcard_t* const context) {
    return 0;
}

static int16_t smartcard_mock__transceive_apdu(smartcard_t* const context, uint8_t* apdu_buffer, uint16_t apdu_buffer_size, uint16_t bytes_to_transmit) {
    smartcard_mock_t* const context_mock = (smartcard_mock_t*) context;

    for (uint32_t i = 0; i < context_mock->apdu_mock_dict.list_size; i++) {
        /* Search if the APDU is in the dict */
        if (context_mock->apdu_mock_dict.apdu_command_list[i].size == bytes_to_transmit && 0 == memcmp(context_mock->apdu_mock_dict.apdu_command_list[i].data, apdu_buffer, bytes_to_transmit)) {
            /* Check if there is enough space to write the APDU response of the key in the buffer */
            if (context_mock->apdu_mock_dict.apdu_response_list[i].size > apdu_buffer_size) {
                return -ENOMEM;
            } else {
                memcpy(apdu_buffer, context_mock->apdu_mock_dict.apdu_response_list[i].data, context_mock->apdu_mock_dict.apdu_response_list[i].size);
                return context_mock->apdu_mock_dict.apdu_response_list[i].size;
            }
        }
    }

    return -ENODATA;
}
