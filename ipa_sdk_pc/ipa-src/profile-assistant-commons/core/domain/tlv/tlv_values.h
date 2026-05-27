/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"

#define OPERATION_RESULT_OK					(uint8_t)0x00
#define OPERATION_RESULT_NOT_FOUND			(uint8_t)0x01
#define OPERATION_RESULT_INVALID_STATE		(uint8_t)0x02
#define OPERATION_RESULT_UNDEFINED_ERROR	(uint8_t)0x7F

//Load CRL error results
#define LOAD_CRL_INVALID_SIG				(uint8_t)0x01
#define LOAD_CRL_INVALID_FORMAT				(uint8_t)0x02
#define LOAD_CRL_NOT_ENOUGH_SPACE			(uint8_t)0x03
#define LOAD_CRL_VERIF_KEY_NOT_FOUND		(uint8_t)0x04
#define LOAD_CRL_FRESHER_CRL_LOADED			(uint8_t)0x05
#define LOAD_CRL_BASE_CLR_MISSING			(uint8_t)0x06
#define LOAD_CRL_UNDEFINED_ERROR			(uint8_t)0x7F

#define RESULT_SUCCESS						(short)0x0000
#define RESULT_SUCCESS_WARNING				(short)0x0001
#define RESULT_ICCID_ALREADY_EXISTS			(short)0x0101
#define RESULT_INSUFFICIENT_MEMORY			(short)0x0102
#define RESULT_INSTALL_FAILED_INTERRUPTED	(short)0x0103

//eimPackageError 
#define EIM_PACKAGE_ERROR_INVALID_PACKAGE_FORMAT    (uint8_t) 0x01
#define EIM_PACKAGE_ERROR_UNKNOWN_PACKAGE           (uint8_t) 0x02
#define EIM_PACKAGE_ERROR_UNDEFINED_ERROR           (uint8_t) 0xFF
#define EIM_PACKAGE_ERROR_NO_EIM_PACKAGE_AVAILABLE  (uint8_t) 0x01

#define ASSOCIATION_TOKEN_DEFAULT_VALUE 0

// Terminal Capability
#ifndef SKIP_TERMINAL_CAPABILITY
#if defined(FORCE_TERMINAL_CAPABILITY_SGP22)
#define EUICC_RELATED_CAPABILITIES_VALUE   (uint8_t)0x07
#elif defined(FORCE_TERMINAL_CAPABILITY_SGP32)
#define EUICC_RELATED_CAPABILITIES_VALUE   (uint8_t)0x01
#elif defined(SGP22)
#define EUICC_RELATED_CAPABILITIES_VALUE   (uint8_t)0x07
#elif defined(SGP32)
#define EUICC_RELATED_CAPABILITIES_VALUE   (uint8_t)0x01
#else
#error "Only SGP22 or SGP32 are supported"
#endif
#endif
