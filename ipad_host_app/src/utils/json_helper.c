#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

// 简单的 JSON 辅助函数

// 构建 JSON 字符串（简单实现）
char* json_build_string(const char *format, ...) {
    va_list args;
    va_start(args, format);
    
    // 估算大小
    size_t size = 1024;
    char *buffer = malloc(size);
    if (!buffer) return NULL;
    
    vsnprintf(buffer, size, format, args);
    
    va_end(args);
    return buffer;
}

// 解析 JSON 字符串中的字段值（简单实现）
int json_get_string_value(const char *json, const char *key, 
                          char *out_value, size_t out_size) {
    if (!json || !key || !out_value) return -1;
    
    char search_key[256];
    snprintf(search_key, sizeof(search_key), "\"%s\"", key);
    
    const char *key_pos = strstr(json, search_key);
    if (!key_pos) return -1;
    
    // 查找冒号
    const char *colon = strchr(key_pos, ':');
    if (!colon) return -1;
    
    // 跳过空白和引号
    const char *value_start = colon + 1;
    while (*value_start == ' ' || *value_start == '"') value_start++;
    
    // 找到值结束
    const char *value_end = strchr(value_start, '"');
    if (!value_end) return -1;
    
    size_t value_len = value_end - value_start;
    if (value_len >= out_size) return -1;
    
    strncpy(out_value, value_start, value_len);
    out_value[value_len] = '\0';
    
    return 0;
}

// 提取 Hex 字符串
char* extract_hex_string(const char *data, size_t len) {
    if (!data || len == 0) return NULL;
    
    // 每个字节需要 2 个字符表示
    char *hex_buffer = malloc(len * 2 + 1);
    if (!hex_buffer) return NULL;
    
    for (size_t i = 0; i < len; i++) {
        sprintf(hex_buffer + i * 2, "%02X", data[i]);
    }
    hex_buffer[len * 2] = '\0';
    
    return hex_buffer;
}

// 将 Hex 字符串转换为字节数组
size_t hex_to_bytes(const char *hex, uint8_t *out_bytes, size_t max_len) {
    if (!hex || !out_bytes) return 0;
    
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return 0;
    
    size_t byte_len = hex_len / 2;
    if (byte_len > max_len) return 0;
    
    for (size_t i = 0; i < byte_len; i++) {
        char byte_str[3] = {hex[i*2], hex[i*2+1], '\0'};
        out_bytes[i] = (uint8_t)strtol(byte_str, NULL, 16);
    }
    
    return byte_len;
}

// Base64 编码（简单实现，使用现有库）
char* base64_encode(const uint8_t *data, size_t len) {
    // 使用 Glib 的 base64 编码
    char *encoded = NULL;
    
    size_t out_len;
    #if defined(__GLIB_2_0__)
        // 如果使用 glib，可以调用 g_base64_encode
        // encoded = g_base64_encode(data, len);
    #endif
    
    // 如果没有 glib，返回空
    (void)data;
    (void)len;
    return encoded;
}

// Base64 解码
uint8_t* base64_decode(const char *base64, size_t *out_len) {
    // 类似 base64 编码实现
    (void)base64;
    (void)out_len;
    return NULL;
}

// 生成时间戳字符串
char* generate_timestamp(void) {
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    
    char *buffer = malloc(32);
    if (!buffer) return NULL;
    
    strftime(buffer, 32, "%Y%m%d%H%M%S", tm_info);
    return buffer;
}

// 验证 JSON 格式（简单实现）
int is_valid_json(const char *json) {
    if (!json) return 0;
    
    // 简单检查：是否以 '{' 开头和 '}' 结尾
    size_t len = strlen(json);
    if (len < 2) return 0;
    
    const char *start = json;
    while (*start == ' ' || *start == '\t' || *start == '\n') start++;
    
    const char *end = json + len - 1;
    while (end > start && (*end == ' ' || *end == '\t' || *end == '\n')) end--;
    
    return (*start == '{' && *end == '}');
}
