/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"
#include "smartcard.h"

/**
 * Checks if a Status Word is success or not.
 * 
 * @param sw Status Word response to check.
 * 
 * @return true if the SW1 is 90 and SW2 is 00 or false otherwise.
 */
bool apdu_utils__sw_is_success(const sw_t* sw);

/**
 * Checks if a Status Word is more data available or not.
 * 
 * @param sw Status Word response to check.
 * 
 * @return true if the SW1 is 61 or false otherwise.
 */
bool apdu_utils__sw_data_available(const sw_t* sw);

/**
 * Checks if a Status Word is logical channel not supported or not.
 * 
 * @param sw Status Word response to check.
 * 
 * @return true if the SW1 is 68 and SW2 is 81 or false otherwise.
 */
bool apdu_utils__sw_logical_channel_not_supported(const sw_t* sw);

/**
 * Checks if a Status Word is conditions not satisfied or not.
 * 
 * @param sw Status Word response to check.
 * 
 * @return true if the SW1 is 69 and SW2 is 85 or false otherwise.
 */
bool apdu_utils__sw_conditions_not_satisfied(const sw_t* sw);
