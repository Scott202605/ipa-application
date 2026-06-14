#ifndef JSON_HELPER_H
#define JSON_HELPER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

char* json_build_string(const char *format, ...);
int json_get_string_value(const char *json, const char *key,
                          char *out_value, size_t out_size);
char* extract_hex_string(const char *data, size_t len);
size_t hex_to_bytes(const char *hex, uint8_t *out_bytes, size_t max_len);
char* base64_encode(const uint8_t *data, size_t len);
uint8_t* base64_decode(const char *base64, size_t *out_len);
char* generate_timestamp(void);
int is_valid_json(const char *json);

#ifdef __cplusplus
}
#endif

#endif // JSON_HELPER_H
