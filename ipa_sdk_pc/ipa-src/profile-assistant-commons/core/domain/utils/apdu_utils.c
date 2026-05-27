/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include "apdu_utils.h"

#define SW1_OK						        0x90
#define SW2_OK						        0x00
#define SW_DATA_AVAILABLE_SW1		        0x61
#define SW1_LOGICAL_CHANNEL_NOT_SUPPORTED	0x68
#define SW2_LOGICAL_CHANNEL_NOT_SUPPORTED	0x81
#define SW1_CONDITIONS_NOT_SATISFIED	    0x69
#define SW2_CONDITIONS_NOT_SATISFIED	    0x85

bool apdu_utils__sw_is_success(const sw_t* sw) {
    return sw->sw1 == SW1_OK && sw->sw2 == SW2_OK;
}

bool apdu_utils__sw_data_available(const sw_t* sw) {
    return sw->sw1 == SW_DATA_AVAILABLE_SW1;
}

bool apdu_utils__sw_logical_channel_not_supported(const sw_t* sw) {
    return sw->sw1 == SW1_LOGICAL_CHANNEL_NOT_SUPPORTED && sw->sw2 == SW2_LOGICAL_CHANNEL_NOT_SUPPORTED;
}

bool apdu_utils__sw_conditions_not_satisfied(const sw_t* sw) {
    return sw->sw1 == SW1_CONDITIONS_NOT_SATISFIED && sw->sw2 == SW2_CONDITIONS_NOT_SATISFIED;
}
