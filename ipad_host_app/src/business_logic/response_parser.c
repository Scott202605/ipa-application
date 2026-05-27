#include "response_parser.h"
#include "command_builder.h"
#include <string.h>
#include <stdio.h>
#include <time.h>

// 解析 API 调用结果
int parse_api_result(
    int sdk_result,
    const char *api_name,
    api_call_result_t *out_result)
{
    if (!out_result) {
        return -1;
    }
    
    memset(out_result, 0, sizeof(*out_result));
    out_result->timestamp = (uint64_t)time(NULL);
    
    if (sdk_result == 0 || sdk_result == eOk) {
        out_result->status = API_RESULT_SUCCESS;
        snprintf(out_result->error_message, sizeof(out_result->error_message), 
                 "API %s 调用成功", api_name ? api_name : "未知");
    } else {
        out_result->status = API_RESULT_ERROR;
        out_result->error_code = sdk_result;
        snprintf(out_result->error_message, sizeof(out_result->error_message),
                 "API %s 调用失败：%s", 
                 api_name ? api_name : "未知",
                 format_error_code((ErrCode)sdk_result));
    }
    
    return 0;
}

// 解析 TLV 数据
int parse_tlv_data(
    const uint8_t *tlv_buffer,
    uint32_t buffer_size,
    char *output,
    size_t output_size)
{
    if (!tlv_buffer || !output || buffer_size == 0) {
        return -1;
    }
    
    size_t offset = 0;
    size_t out_offset = 0;
    
    while (offset < buffer_size && out_offset < output_size - 3) {
        uint8_t tag = tlv_buffer[offset++];
        
        // 解析长度
        uint8_t len_byte = tlv_buffer[offset++];
        uint32_t length = len_byte;
        
        // 处理长格式长度
        if (len_byte & 0x80) {
            int num_bytes = len_byte & 0x7F;
            length = 0;
            for (int i = 0; i < num_bytes && offset < buffer_size; i++) {
                length = (length << 8) | tlv_buffer[offset++];
            }
        }
        
        // 添加标签
        int written = snprintf(output + out_offset, output_size - out_offset,
                              "Tag: %02X, Len: %d, Value: ", tag, length);
        if (written > 0 && out_offset + written < output_size) {
            out_offset += written;
        }
        
        // 添加值（十六进制）
        for (uint32_t i = 0; i < length && offset < buffer_size && 
             out_offset < output_size - 3; i++) {
            written = snprintf(output + out_offset, output_size - out_offset,
                              "%02X", tlv_buffer[offset++]);
            if (written > 0) {
                out_offset += written;
            }
        }
        
        if (out_offset < output_size - 2) {
            output[out_offset++] = '\n';
        }
    }
    
    if (out_offset < output_size) {
        output[out_offset] = '\0';
    }
    
    return 0;
}

// 解析 JSON 响应
int parse_json_response(
    const char *json_str,
    char *key,
    char *value_out,
    size_t value_size)
{
    if (!json_str || !key || !value_out) {
        return -1;
    }
    
    // 构建搜索字符串 "key"
    char search_key[256];
    snprintf(search_key, sizeof(search_key), "\"%s\"", key);
    
    // 查找 key
    const char *key_pos = strstr(json_str, search_key);
    if (!key_pos) {
        return -1;
    }
    
    // 查找冒号
    const char *colon = strchr(key_pos, ':');
    if (!colon) {
        return -1;
    }
    
    // 跳过空白和引号
    const char *value_start = colon + 1;
    while (*value_start == ' ' || *value_start == '\t' || *value_start == '"') {
        value_start++;
    }
    
    // 找到值结束
    const char *value_end = value_start;
    if (*value_start == '"') {
        value_start++;  // 跳过开始引号
        value_end = strchr(value_start, '"');
    } else {
        // 数字或布尔值
        while (*value_end && *value_end != ',' && *value_end != '}' && 
               *value_end != ' ' && *value_end != '\n') {
            value_end++;
        }
    }
    
    if (!value_end) {
        return -1;
    }
    
    // 复制值
    size_t value_len = value_end - value_start;
    if (value_len >= value_size) {
        value_len = value_size - 1;
    }
    
    strncpy(value_out, value_start, value_len);
    value_out[value_len] = '\0';
    
    return 0;
}
