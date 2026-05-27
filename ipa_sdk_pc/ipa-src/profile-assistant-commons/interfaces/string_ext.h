/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"

/**
 * The memmem() function finds the start of the first occurrence of
 * the substring needle of length needlelen in the memory area
 * haystack of length haystacklen.
 * 
 * @return pointer to the beginning of the
 * substring, or NULL if the substring is not found.
*/
void *S_memmem(const void* haystack, size_t haystacklen, const void* needle, size_t needlelen);
