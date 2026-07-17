#ifndef IPAD_JSON_H
#define IPAD_JSON_H

#include <stddef.h>
#include "ipad_errors.h"

int ipad_json_get_string(const char *json, const char *key, char *out, size_t out_size);
int ipad_json_get_int(const char *json, const char *key, int *out);
int ipad_json_write_error(char *out, size_t out_size, int id, ipad_error_t error, const char *message);
int ipad_json_write_result(char *out, size_t out_size, int id, const char *result_json);

#endif
