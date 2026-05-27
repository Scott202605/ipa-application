/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include <stdarg.h>
#include "typedefs.h"

#define MAX_LOG_LEN		8196
#define MAX_DATA_LEN	8196

enum LogLevel {
	eLogErr = 1,
	eLogWarn = 2,
	eLogInfo = 3,
	eLogDebug = 4,
	eLogTrace = 5
};

/**
 * Macros for global logger
 */
#define LOG_INIT				log__set_log_level
#define LOG_DATA(...)			log__data(__VA_ARGS__)
#define LOG_CSTRING				log__cstring
#define LOG_UTF8_DATA			log__utf8_data

#define LOGE(...)	log__string(eLogErr, __VA_ARGS__)
#define LOGW(...)	log__string(eLogWarn, __VA_ARGS__)
#define LOGI(...)	log__string(eLogInfo, __VA_ARGS__)
#define LOGD(...)	log__string(eLogDebug, __VA_ARGS__)
#define LOGT(...)	log__string(eLogTrace, __VA_ARGS__)

void	log__set_log_level(const int level);
int		log__get_log_level();
void	log__string(const int level, const char* format, ...);
void	log__cstring(const int level, const char *str);
void	log__data(const int level, const char *title, const uint8_t* data, const size_t len);
void	log__utf8_data(const int level, const char *title, const unsigned char* data, const size_t len);