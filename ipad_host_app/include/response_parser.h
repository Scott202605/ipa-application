#ifndef RESPONSE_PARSER_H
#define RESPONSE_PARSER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// API 调用结果结构
// ============================================================================

typedef enum {
    API_RESULT_SUCCESS = 0,
    API_RESULT_ERROR = 1,
    API_RESULT_TIMEOUT = 2,
    API_RESULT_CANCELLED = 3
} api_result_status_t;

typedef struct {
    api_result_status_t status;
    int error_code;
    char error_message[256];
    char result_data[1024];
    uint64_t timestamp;
    uint32_t execution_time_ms;
} api_call_result_t;

// ============================================================================
// 解析函数
// ============================================================================

// 解析 API 调用结果
int parse_api_result(
    int sdk_result,
    const char *api_name,
    api_call_result_t *out_result);

// 解析 TLV 数据
int parse_tlv_data(
    const uint8_t *tlv_buffer,
    uint32_t buffer_size,
    char *output,
    size_t output_size);

// 解析 JSON 响应
int parse_json_response(
    const char *json_str,
    char *key,
    char *value_out,
    size_t value_size);

#ifdef __cplusplus
}
#endif

#endif // RESPONSE_PARSER_H
