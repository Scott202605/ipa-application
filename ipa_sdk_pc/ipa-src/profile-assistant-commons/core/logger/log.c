/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include <stdio.h>
#ifdef DEBUG_WITH_THREAD_ID
#include <inttypes.h>
#endif

#include "log.h"
#include "logger.h"

#if defined (DEBUG_WITH_TIME) || defined (DEBUG_WITH_ELAPSED)
    #include "timer.h"
#endif

#ifdef DEBUG_WITH_ELAPSED
clock_data_t g_clock_data;
#endif

#define PRINTED_BYTES_PER_LINE  16
#define LOG_STRING_CHUNK_SIZE   256

#define HEX_DATA_LINE "%02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X"
#ifdef DEBUG_WITH_TIME
#define TIME_TEMPLATE "[%02d/%02d/%04d %02d:%02d:%02d]"
#endif
#ifdef DEBUG_WITH_LOGLEVEL
#define LOGLEVEL_ERROR  "[ERROR]"
#define LOGLEVEL_WARN   "[WARN] "
#define LOGLEVEL_INFO   "[INFO] "
#define LOGLEVEL_DEBUG  "[DEBUG]"
#define LOGLEVEL_TRACE  "[TRACE]"
#endif
#ifdef DEBUG_WITH_THREAD_ID
#define THREAD_ID_TEMPLATE "[TID:%" PRIu64 "]"
#endif

//definition of loglevel
int g_log_level = 0;
static int16_t log__add_log_headers(char* buffer, const uint16_t buffer_size, const uint16_t buffer_offset, const int log_level);
static void print_string_by_chunks(char* chunk, const uint16_t chunk_size, uint16_t chunk_offset, const unsigned char* str, const size_t str_len, const bool end_with_newline);

void log__set_log_level(const int loglevel) {
    g_log_level = loglevel;

#ifdef DEBUG_WITH_ELAPSED
    if (timer__get_clock_data(&g_clock_data) != 0) {
        g_clock_data.tv_sec = 0;
        g_clock_data.tv_nsec = 0;
    }
#endif
}

int log__get_log_level() {
    return g_log_level;
}

void log__string(const int loglevel, const char *format, ...) {
    char buf[MAX_LOG_LEN + 1];
    int16_t offset = 0;
    int nchars;
    va_list args;

    if (g_log_level < loglevel) { 
        return; 
    }

    if ((offset = log__add_log_headers(buf, sizeof(buf), (uint16_t) offset, loglevel)) < 0) {
        // initialize a buf char array and fill it with 0s 
	    memset(buf, 0, sizeof(buf));
        offset = 0;
    } else {
        memset(buf + offset, 0, sizeof(buf) - offset);
    }

    va_start(args, format); 
    nchars = vsnprintf(&buf[offset], MAX_LOG_LEN - offset, format, args); 
    va_end(args);
    if (nchars < 0) {
        return;
    } else if (offset + nchars >= MAX_LOG_LEN) {
        //If we don't have enough space to add the \n char, we will replace it for the last no null terminate character of the buffer
        buf[MAX_LOG_LEN - 1] = '\n';
    } else {
        //We have space in the buffer to add the \n char
        buf[offset + nchars] = '\n';
    }

    hw_printf(buf);
}

void log__data(const int level,  const char *title, const uint8_t* data, const size_t len) {
    if ( g_log_level < level ) {
        return;
    }
	//Log title
	log__string(level, title);
    //Max number of hexadecimal characters needed to print per line
    //16*2 because each hexa value need 2 chars to be printed, + 16 because each value is separeted by a space, +1 for the null char
    char byte_hex[PRINTED_BYTES_PER_LINE*3+1];
	int pos_hex = 0;
	size_t data_size = len;
    size_t i;

    if (!data) {
        data_size = 0;
    }

    for (i = 0; i < data_size; i += PRINTED_BYTES_PER_LINE) {
        if (i + PRINTED_BYTES_PER_LINE <= data_size) {
            //16 byte line is completed and gets printed, both in hexadecimal and in characters
            log__string(level, HEX_DATA_LINE, data[i], data[i+1], data[i+2], data[i+3], data[i+4], data[i+5], data[i+6], data[i+7], data[i+8],
            data[i+9], data[i+10], data[i+11], data[i+12], data[i+13], data[i+14], data[i+15]);
        } else {
            while(i < data_size) {
                //strings are being built and counters uploaded
                int n_hex = sprintf(&byte_hex[pos_hex], "%02X ", data[i]);
                if (n_hex < 0) {
                    return;
                } else {
                    pos_hex += n_hex;
                }
                i++;
            }
            log__string(level, "%s", byte_hex);
        }
    }
}

void log__cstring(const int level, const char *str) {
    char buf[LOG_STRING_CHUNK_SIZE + 1];
    int16_t buffer_offset = 0;

    if (g_log_level < level) { 
        return; 
    }

    buffer_offset = log__add_log_headers(buf, sizeof(buf), (uint16_t) buffer_offset, level);
    if (buffer_offset >= 0 && buffer_offset < sizeof(buf)) {
        memset(buf + buffer_offset, 0, sizeof(buf) - buffer_offset);	    
    } else {
        //If fails, no headers will be printed
        memset(buf, 0, sizeof(buf));
        buffer_offset = 0;
    }

    print_string_by_chunks(buf, sizeof(buf), 0, (unsigned char*) str, strlen(str), true);
}

void log__utf8_data(const int level, const char *title, const unsigned char* utf8, const size_t len) {
    char buf[LOG_STRING_CHUNK_SIZE + 1];
    int16_t buffer_offset = 0;

    if (g_log_level < level) { 
        return; 
    }

    buffer_offset = log__add_log_headers(buf, sizeof(buf), (uint16_t) buffer_offset, level);
    if (buffer_offset >= 0 && buffer_offset < sizeof(buf)) {
        memset(buf + buffer_offset, 0, sizeof(buf) - buffer_offset);	    
    } else {
        //If fails, no headers will be printed
        memset(buf, 0, sizeof(buf));
        buffer_offset = 0;
    }

    //Print the title
    print_string_by_chunks(buf, sizeof(buf), buffer_offset, (unsigned char*) title, strlen(title), false);

    //Print the UTF8 string
    print_string_by_chunks(buf, sizeof(buf), 0, utf8, len, true);
}


static int16_t log__add_log_headers(char* buffer, const uint16_t buffer_size, const uint16_t buffer_offset, const int log_level) {
    int16_t offset = buffer_offset;

#ifdef DEBUG_WITH_TIME 
    if (offset + 21 + 1 > buffer_size) {
        return -1;
    }
    time_data td = timer__get_time_data(); 
    int tmp_time = sprintf(&buffer[offset], TIME_TEMPLATE, td.day, td.month, td.year, td.hour, td.minute, td.second);
    if (tmp_time < 0) {
        return -1;
    } else {
        offset += tmp_time; 
        buffer[offset++] = ' '; 
    }
#endif

#ifdef DEBUG_WITH_LOGLEVEL 
    if (offset + sizeof(LOGLEVEL_ERROR) + 1 > buffer_size) {
        return -1;
    }
    switch (log_level) {
        case 1: 
            strcpy(&buffer[offset], LOGLEVEL_ERROR); 
            break; 
        case 2:
            strcpy(&buffer[offset], LOGLEVEL_WARN); 
            break; 
        case 3:
            strcpy(&buffer[offset], LOGLEVEL_INFO); 
            break; 
        case 4:
            strcpy(&buffer[offset], LOGLEVEL_DEBUG); 
            break; 
        case 5:
            strcpy(&buffer[offset], LOGLEVEL_TRACE); 
            break; 
        default: 
            return -1; 
    }
    offset += 7;
    buffer[offset++] = ' '; 
#endif

#ifdef DEBUG_WITH_THREAD_ID
    int tmp_thread_id = snprintf(&buffer[offset], buffer_size - offset, THREAD_ID_TEMPLATE, log__get_current_thread_id());
    if (tmp_thread_id < 0 || offset + tmp_thread_id + 1 > buffer_size) {
        return -1;
    }
    offset += tmp_thread_id;
    buffer[offset++] = ' ';
#endif

#ifdef DEBUG_WITH_ELAPSED
    clock_data_t current_clock_data;

    if (offset + 17 + 1 > buffer_size) {
        return -1;
    }
    int tmp_elapsed; 
    if (timer__get_clock_data(&current_clock_data) != 0) {
        return -eFatal;
    }
    int64_t elapsed_nanoseconds = current_clock_data.tv_nsec - g_clock_data.tv_nsec;
    int64_t elapsed_seconds = current_clock_data.tv_sec - g_clock_data.tv_sec; 
    if (elapsed_nanoseconds < 0) {
        elapsed_seconds--;
        elapsed_nanoseconds += 1000000000; //1 seconds is 1000000000 nanoseconds
    }
    tmp_elapsed = sprintf(&buffer[offset], "[%03lld.", elapsed_seconds);
    if (tmp_elapsed < 0) {
        return -1;
    }
    offset += tmp_elapsed; 
    tmp_elapsed = sprintf(&buffer[offset], "%09lld s]", elapsed_nanoseconds);
    if (tmp_elapsed < 0) {
        return -1;
    } else {
        offset += tmp_elapsed;
        buffer[offset++] = ' '; 
        memcpy(&g_clock_data, &current_clock_data, sizeof(clock_data_t));
    }
#endif

    if (offset > buffer_offset) {
        buffer[offset-1] = '\t'; 
    }

    return offset;
}

//Minumum chunk size is 2
static void print_string_by_chunks(char* chunk, const uint16_t chunk_size, uint16_t chunk_offset, const unsigned char* str, const size_t str_len, const bool end_with_newline) {
    uint32_t str_offset = 0;

    if (!chunk || chunk_size < 2 || chunk_offset >= chunk_size) {
        return;
    }
    memset(chunk + chunk_offset, 0, chunk_size - chunk_offset); //Clean the non used bytes of the chunk
    
    do {
        if (str_len - str_offset <= chunk_size - 1 - chunk_offset) {
            //Last line
            memcpy(&chunk[chunk_offset], &str[str_offset], str_len - str_offset);
            chunk_offset += (uint16_t) (str_len - str_offset);
            str_offset += chunk_offset;
            if (end_with_newline) {
                //Check if the new line character fit in the current chunk
                if (chunk_offset == chunk_size - 1) {
                    hw_printf(chunk); //If the new line does not fit in the chunk, print the current chunk conent
                    memset(chunk, 0, chunk_size); //Clean chunk
                    chunk[0] = '\n'; //Add in the new chunk the new line character
                } else {
                    chunk[chunk_offset] = '\n'; //If the new line character fit in the chunk add it
                    chunk_offset++;
                }
            }
        } else {
            memcpy(&chunk[chunk_offset], &str[str_offset], chunk_size - 1 - chunk_offset);
            str_offset += chunk_size - 1 - chunk_offset;
        }
        hw_printf(chunk);
        memset(chunk, 0, chunk_size);
        chunk_offset = 0;
    } while (str_offset < str_len);
}
