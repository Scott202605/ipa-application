/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 *  @file logger_linux.c
 *  @brief Implementation for Linux devices of the functions described in the file logger.h
 *  @author Giesecke+Devrient Mobile Security
 *  @bug No known bugs.
*/

#include <stdio.h>
#ifdef DEBUG_WITH_THREAD_ID
#include <stdint.h>
#include <pthread.h>
#include <inttypes.h>
#endif
#include "logger.h"

void hw_printf(const char *str) {
	printf("%s", str);
}

#ifdef DEBUG_WITH_THREAD_ID
uint64_t log__get_current_thread_id(void) {
    return (uint64_t)(uintptr_t)pthread_self();
}
#endif