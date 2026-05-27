/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 * 
 *  @file logger.h
 *  @brief logger interface, used to print out a string
 *  
 *  The functions described in this interface needs to be implemented in for each hardware specific
 * 
 *  @author Giesecke+Devrient Mobile Security
 *  @bug No known bugs.
*/
#pragma once

#ifdef DEBUG_WITH_THREAD_ID
#include <stdint.h>
#endif

/**
 * Function that logs a String.
 * @param str is the string to be logged.
 * @return This function does not return any value.
 */
void hw_printf(const char *str);

#ifdef DEBUG_WITH_THREAD_ID
uint64_t log__get_current_thread_id(void);
#endif
