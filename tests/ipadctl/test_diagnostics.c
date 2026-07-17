#include "diagnostics.h"

#include <string.h>

int main(void) {
    diagnostic_check_t check;
    char json[512];

    diagnostic_check_set(&check, "config.parse", 1, "info", "config loaded", "");
    if (diagnostic_write_check_json(&check, json, sizeof(json)) != 0) return 1;
    if (!strstr(json, "\"name\":\"config.parse\"")) return 1;
    if (!strstr(json, "\"ok\":true")) return 1;
    return 0;
}
