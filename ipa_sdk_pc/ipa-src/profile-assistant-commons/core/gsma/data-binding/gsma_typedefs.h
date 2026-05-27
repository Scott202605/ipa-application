/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"

typedef enum http_gsma_data_binding_s {
    JSON_DATA_BINDING,
    ASN1_DATA_BINDING,
    UNDEFINED_DATA_BINDING // This case shall be treated as an error
} gsma_data_binding_t;
