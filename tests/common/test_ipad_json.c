#include "ipad_json.h"

#include <stdio.h>
#include <string.h>

static int require(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "%s\n", message);
        return 1;
    }
    return 0;
}

int main(void) {
    char value[32];
    int id = 0;
    char out[256];

    if (require(ipad_json_get_string("{\"method\":\"system.status\"}", "method", value, sizeof(value)) == 0, "method missing")) return 1;
    if (require(strcmp(value, "system.status") == 0, "method mismatch")) return 1;
    if (require(ipad_json_get_int("{\"id\":42}", "id", &id) == 0, "id missing")) return 1;
    if (require(id == 42, "id mismatch")) return 1;
    if (require(ipad_json_write_result(out, sizeof(out), 42, "{\"ok\":true}") == 0, "result write failed")) return 1;
    if (require(strstr(out, "\"result\":{\"ok\":true}") != NULL, "result json mismatch")) return 1;
    if (require(ipad_json_write_error(out, sizeof(out), 42, IPAD_ERR_WORKER_UNAVAILABLE, "worker offline") == 0, "error write failed")) return 1;
    if (require(strstr(out, "worker_unavailable") != NULL, "error name mismatch")) return 1;

    return 0;
}
