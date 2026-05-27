/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 * 
 *  @file timer.h
 *  @brief timer interface, used to use time functions
 *  
 *  The functions described in this interface needs to be implemented in for each hardware specific
 * 
 *  @author Giesecke+Devrient Mobile Security
 *  @bug No known bugs.
*/
#pragma once
#include "typedefs.h"


typedef struct {
    uint8_t second; // seconds after the minute - [0, 60] including leap second
    uint8_t minute; // minutes after the hour - [0, 59]
    uint8_t hour;   // hours since midnight - [0, 23]
    uint8_t day;    // day of the month - [1, 31]
    uint8_t month;  // months of the year - [1, 12]
    uint16_t year;  // actual year
} time_data;

typedef struct {
    int64_t tv_sec; // Seconds of the clock
    int64_t tv_nsec;   // Nanoseconds of the clock
} clock_data_t; 

/**
 * This function retieve the current date time
 * 
 * @return time_data structure with the current date time
*/
time_data timer__get_time_data(); 

/**
 * This function retieve the clock data
 * 
 * @param[out] clock_data A pointer to a clock_data_t structure. The structure is populated 
 * following its documentation with the data of the current clock.
 * 
 * @return Upon successful execution, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int timer__get_clock_data(clock_data_t *clock_data); 

/**
 * Causes the calling thread to sleep until the number of real-time seconds 
 * specified in seconds have elapsed
 * 
 * @param seconds number of seconds to sleep
 * 
 * @return This function does not return any value.
*/
void timer__sleep(unsigned int seconds);
