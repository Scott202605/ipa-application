#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>

// 简单的日志模块实现

typedef enum {
    LOG_LEVEL_ERROR = 0,
    LOG_LEVEL_WARN = 1,
    LOG_LEVEL_INFO = 2,
    LOG_LEVEL_DEBUG = 3,
    LOG_LEVEL_TRACE = 4
} log_level_t;

static const char* LOG_LEVEL_STR[] = {"ERROR", "WARN", "INFO", "DEBUG", "TRACE"};
static log_level_t g_current_log_level = LOG_LEVEL_INFO;
static FILE *g_log_file = NULL;

// 初始化日志
int log_init(const char *log_path, log_level_t level) {
    g_current_log_level = level;
    
    if (log_path) {
        g_log_file = fopen(log_path, "a");
        if (!g_log_file) {
            return -1;
        }
    }
    
    return 0;
}

// 反初始化日志
void log_deinit(void) {
    if (g_log_file) {
        fclose(g_log_file);
        g_log_file = NULL;
    }
}

// 设置日志级别
void log_set_level(log_level_t level) {
    g_current_log_level = level;
}

// 日志记录
void log_write(log_level_t level, const char *format, ...) {
    if (level > g_current_log_level) return;
    
    // 获取时间
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_buffer[32];
    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", tm_info);
    
    // 构建日志消息
    char message[2048];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    
    // 输出到控制台
    printf("[%s] %s: %s\n", time_buffer, LOG_LEVEL_STR[level], message);
    
    // 输出到文件
    if (g_log_file) {
        fprintf(g_log_file, "[%s] %s: %s\n", time_buffer, LOG_LEVEL_STR[level], message);
        fflush(g_log_file);
    }
}

// 简单的 hex dump
void log_hex_dump(const char *prefix, const uint8_t *data, size_t len) {
    if (!data || len == 0) return;
    
    printf("[%s] Hex dump (%zu bytes):\n", prefix ? prefix : "DATA", len);
    
    for (size_t i = 0; i < len; i += 16) {
        printf("  %04zx: ", i);
        
        // Hex 部分
        for (size_t j = 0; j < 16 && (i + j) < len; j++) {
            printf("%02X ", data[i + j]);
        }
        
        // ASCII 部分
        printf("  ");
        for (size_t j = 0; j < 16 && (i + j) < len; j++) {
            char c = data[i + j];
            printf("%c", (c >= 32 && c <= 126) ? c : '.');
        }
        
        printf("\n");
    }
}
