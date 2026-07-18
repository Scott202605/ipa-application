#include "diagnostics.h"

#include <string.h>

static int test_check_json_contract(void) {
    diagnostic_check_t check;
    char json[512];

    diagnostic_check_set(&check, "config.parse", 1, "info", "config loaded", "");
    if (diagnostic_write_check_json(&check, json, sizeof(json)) != 0) return 1;
    if (!strstr(json, "\"name\":\"config.parse\"")) return 1;
    if (!strstr(json, "\"ok\":true")) return 1;
    return 0;
}

static int test_report_json_contract(void) {
    diagnostic_check_t checks[2];
    char out[2048];

    diagnostic_check_set(&checks[0], "platform.arch", 1, "info", "architecture is x86_64", "Run: ipadctl doctor");
    diagnostic_check_set(&checks[1], "daemon.socket", 0, "error", "cannot connect to daemon socket", "Run: sudo systemctl restart ipad-managerd");

    if (diagnostic_write_report_json("daemon is not reachable", "Run: sudo systemctl restart ipad-managerd", checks, 2, out, sizeof(out)) != 0) return 1;
    if (!strstr(out, "\"ok\":false")) return 1;
    if (!strstr(out, "\"summary\":\"daemon is not reachable\"")) return 1;
    if (!strstr(out, "\"next_action\":\"Run: sudo systemctl restart ipad-managerd\"")) return 1;
    if (!strstr(out, "\"checks\":[")) return 1;
    if (!strstr(out, "\"name\":\"daemon.socket\"")) return 1;
    return 0;
}

int main(void) {
    if (test_check_json_contract() != 0) return 1;
    if (test_report_json_contract() != 0) return 1;
    return 0;
}
