/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#define _GNU_SOURCE // memmem is under this flag in the <string.h>
#include <string.h>
#include "string_ext.h"

void *S_memmem(const void* haystack, size_t haystacklen, const void* needle, size_t needlelen) {
    return memmem(haystack, haystacklen, needle, needlelen);
}