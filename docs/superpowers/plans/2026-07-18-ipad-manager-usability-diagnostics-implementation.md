# IPAd Manager Usability and Diagnostics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add easy-to-use CLI diagnostics and setup helpers so a Linux operator can configure, check, and troubleshoot IPAd Manager without understanding SDK internals.

**Architecture:** Keep `ipadctl` as the operator entry point and split diagnostic logic into focused CLI helper files. Reuse `common/ipad_config.*` for config parsing. Use existing daemon JSON-RPC methods for live checks and keep output JSON-first.

**Tech Stack:** C11, CMake 3.22+, POSIX filesystem APIs, Unix Domain Socket client calls, JSON output via `snprintf`, CTest, Ubuntu 22.04 GitHub Actions.

## Global Constraints

- Daemon, worker, and CLI must not depend on GTK.
- Daemon and client code must not include IPAd SDK headers.
- Diagnostic tests must not read or write `/etc`, `/run`, `/var`, or real `/dev`.
- All diagnostic command output defaults to JSON.
- Exit codes are `0` for pass, `1` for failed checks, `2` for usage error, `3` for config parse error, and `4` for daemon unreachable.
- Keep generated JSON bounded by `IPAD_MAX_JSON_MESSAGE`.
- Every task must pass local Ubuntu CMake build and CTest before commit.

---

## File Structure

- `ipadctl/diagnostics.h`, `ipadctl/diagnostics.c`: diagnostic check model, JSON writing helpers, doctor orchestration helpers.
- `ipadctl/config_commands.h`, `ipadctl/config_commands.c`: `config show`, `config check`, config path option handling.
- `ipadctl/device_discovery.h`, `ipadctl/device_discovery.c`: list likely serial device nodes from configurable dev root.
- `ipadctl/setup_commands.h`, `ipadctl/setup_commands.c`: write mock and real config files to requested path.
- `ipadctl/ipadctl_main.c`: route new commands and global options without owning command internals.
- `ipadctl/CMakeLists.txt`: include new source files.
- `tests/ipadctl/`: focused CLI helper tests.
- `packaging/config/mock.config.json`: mock config template.
- `packaging/config/at-serial.config.json`: real AT serial config template.
- `docs/quick-start.md`: short operator-first quick start.
- `.github/workflows/ubuntu-build.yml`: check templates and quick start exist.

---

### Task 1: Diagnostic Check Model

**Files:**
- Create: `ipadctl/diagnostics.h`
- Create: `ipadctl/diagnostics.c`
- Modify: `ipadctl/CMakeLists.txt`
- Create: `tests/ipadctl/test_diagnostics.c`
- Modify: `tests/CMakeLists.txt`
- Create: `tests/ipadctl/CMakeLists.txt`

**Interfaces:**
- Produces:
  - `typedef struct diagnostic_check_t`
  - `void diagnostic_check_set(diagnostic_check_t *check, const char *name, int ok, const char *severity, const char *message, const char *suggestion);`
  - `int diagnostic_write_check_json(const diagnostic_check_t *check, char *out, size_t out_size);`

- [ ] **Step 1: Add diagnostic model header**

Create `ipadctl/diagnostics.h`:

```c
#ifndef IPADCTL_DIAGNOSTICS_H
#define IPADCTL_DIAGNOSTICS_H

#include <stddef.h>

typedef struct {
    char name[64];
    int ok;
    char severity[16];
    char message[160];
    char suggestion[200];
} diagnostic_check_t;

void diagnostic_check_set(diagnostic_check_t *check, const char *name, int ok, const char *severity, const char *message, const char *suggestion);
int diagnostic_write_check_json(const diagnostic_check_t *check, char *out, size_t out_size);

#endif
```

- [ ] **Step 2: Implement JSON writer**

Create `ipadctl/diagnostics.c`:

```c
#include "diagnostics.h"

#include <stdio.h>
#include <string.h>

void diagnostic_check_set(diagnostic_check_t *check, const char *name, int ok, const char *severity, const char *message, const char *suggestion) {
    if (!check) return;
    memset(check, 0, sizeof(*check));
    snprintf(check->name, sizeof(check->name), "%s", name ? name : "");
    check->ok = ok;
    snprintf(check->severity, sizeof(check->severity), "%s", severity ? severity : (ok ? "info" : "error"));
    snprintf(check->message, sizeof(check->message), "%s", message ? message : "");
    snprintf(check->suggestion, sizeof(check->suggestion), "%s", suggestion ? suggestion : "");
}

int diagnostic_write_check_json(const diagnostic_check_t *check, char *out, size_t out_size) {
    int written;
    if (!check || !out || out_size == 0) return -1;
    written = snprintf(out, out_size,
                       "{\"name\":\"%s\",\"ok\":%s,\"severity\":\"%s\",\"message\":\"%s\",\"suggestion\":\"%s\"}",
                       check->name,
                       check->ok ? "true" : "false",
                       check->severity,
                       check->message,
                       check->suggestion);
    return written > 0 && (size_t)written < out_size ? 0 : -1;
}
```

- [ ] **Step 3: Add test**

Create `tests/ipadctl/test_diagnostics.c`:

```c
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
```

- [ ] **Step 4: Wire CMake**

Update `ipadctl/CMakeLists.txt` to add `diagnostics.c` to `ipadctl` and to a new `ipadctl_testlib` static library:

```cmake
add_library(ipadctl_testlib STATIC
    diagnostics.c
)
target_include_directories(ipadctl_testlib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(ipadctl_testlib PUBLIC ipad_common)
target_compile_options(ipadctl_testlib PRIVATE -Wall -Wextra -Werror)
```

Create `tests/ipadctl/CMakeLists.txt`:

```cmake
add_executable(test_diagnostics test_diagnostics.c)
target_link_libraries(test_diagnostics PRIVATE ipadctl_testlib ipad_common)
add_test(NAME test_diagnostics COMMAND test_diagnostics)
```

Add `add_subdirectory(ipadctl)` to `tests/CMakeLists.txt`.

- [ ] **Step 5: Verify and commit**

Run:

```bash
cmake -S . -B build-manager -DIPAD_BUILD_TESTS=ON
cmake --build build-manager --parallel
ctest --test-dir build-manager --output-on-failure
```

Commit:

```bash
git add ipadctl tests
git commit -m "feat: add ipadctl diagnostic check model"
```

---

### Task 2: Config Show and Config Check

**Files:**
- Create: `ipadctl/config_commands.h`
- Create: `ipadctl/config_commands.c`
- Modify: `ipadctl/ipadctl_main.c`
- Modify: `ipadctl/CMakeLists.txt`
- Create: `tests/ipadctl/test_config_commands.c`
- Modify: `tests/ipadctl/CMakeLists.txt`

**Interfaces:**
- Consumes:
  - `ipad_config_load_file(const char *path, ipad_config_t *config, char *error, size_t error_size)`
  - `diagnostic_check_t`
- Produces:
  - `int ipadctl_config_show(const char *config_path, char *out, size_t out_size);`
  - `int ipadctl_config_check(const char *config_path, char *out, size_t out_size);`

- [ ] **Step 1: Add header**

Create `ipadctl/config_commands.h`:

```c
#ifndef IPADCTL_CONFIG_COMMANDS_H
#define IPADCTL_CONFIG_COMMANDS_H

#include <stddef.h>

int ipadctl_config_show(const char *config_path, char *out, size_t out_size);
int ipadctl_config_check(const char *config_path, char *out, size_t out_size);

#endif
```

- [ ] **Step 2: Implement config show**

Create `ipadctl/config_commands.c` with:

```c
#include "config_commands.h"

#include "diagnostics.h"
#include "ipad_config.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char *default_config_path(const char *config_path) {
    return config_path && config_path[0] ? config_path : "/etc/ipad-manager/config.json";
}

int ipadctl_config_show(const char *config_path, char *out, size_t out_size) {
    ipad_config_t config;
    char error[128];
    int written;
    if (ipad_config_load_file(default_config_path(config_path), &config, error, sizeof(error)) != 0) {
        written = snprintf(out, out_size, "{\"ok\":false,\"error\":\"%s\"}", error);
        return written > 0 && (size_t)written < out_size ? 3 : 2;
    }
    written = snprintf(out, out_size,
                       "{\"config_path\":\"%s\",\"socket_path\":\"%s\",\"worker_path\":\"%s\",\"sdk_mode\":\"%s\",\"sdk_transport\":\"%s\",\"at_device\":\"%s\",\"at_baudrate\":%d,\"task_store_path\":\"%s\",\"audit_log_path\":\"%s\"}",
                       default_config_path(config_path),
                       config.socket_path,
                       config.worker_path,
                       config.sdk_mode,
                       config.sdk_transport,
                       config.at_device,
                       config.at_baudrate,
                       config.task_store_path,
                       config.audit_log_path);
    return written > 0 && (size_t)written < out_size ? 0 : 2;
}
```

- [ ] **Step 3: Implement config check**

Append to `config_commands.c`:

```c
static int append_check(char *out, size_t out_size, size_t *used, const diagnostic_check_t *check, int first) {
    char check_json[512];
    int written;
    if (diagnostic_write_check_json(check, check_json, sizeof(check_json)) != 0) return -1;
    written = snprintf(out + *used, out_size - *used, "%s%s", first ? "" : ",", check_json);
    if (written <= 0 || (size_t)written >= out_size - *used) return -1;
    *used += (size_t)written;
    return 0;
}

static int path_executable(const char *path) {
    return path && access(path, X_OK) == 0;
}

int ipadctl_config_check(const char *config_path, char *out, size_t out_size) {
    ipad_config_t config;
    diagnostic_check_t check;
    char error[128];
    size_t used = 0;
    int ok = 1;
    int first = 1;
    int written;

    written = snprintf(out, out_size, "{\"ok\":");
    if (written <= 0 || (size_t)written >= out_size) return 2;
    used = (size_t)written;

    if (ipad_config_load_file(default_config_path(config_path), &config, error, sizeof(error)) != 0) {
        written = snprintf(out, out_size, "{\"ok\":false,\"checks\":[{\"name\":\"config.parse\",\"ok\":false,\"severity\":\"error\",\"message\":\"%s\",\"suggestion\":\"Fix config file or run ipadctl setup --mock\"}]}", error);
        return written > 0 && (size_t)written < out_size ? 1 : 2;
    }

    written = snprintf(out + used, out_size - used, "true,\"checks\":[");
    if (written <= 0 || (size_t)written >= out_size - used) return 2;
    used += (size_t)written;

    diagnostic_check_set(&check, "config.parse", 1, "info", "config loaded", "");
    append_check(out, out_size, &used, &check, first);
    first = 0;

    if (!path_executable(config.worker_path)) {
        ok = 0;
        diagnostic_check_set(&check, "worker.executable", 0, "error", "worker_path is missing or not executable", "Install ipad-sdk-worker or update worker_path");
        append_check(out, out_size, &used, &check, first);
        first = 0;
    }

    if (strcmp(config.sdk_mode, "real") == 0 && access(config.at_device, F_OK) != 0) {
        ok = 0;
        diagnostic_check_set(&check, "device.exists", 0, "error", "configured AT device does not exist", "Run ipadctl device list or update at_device");
        append_check(out, out_size, &used, &check, first);
        first = 0;
    }

    written = snprintf(out + used, out_size - used, "]}");
    if (written <= 0 || (size_t)written >= out_size - used) return 2;
    if (!ok) {
        char tmp[4096];
        snprintf(tmp, sizeof(tmp), "%s", out);
        snprintf(out, out_size, "{\"ok\":false%s", tmp + strlen("{\"ok\":true"));
    }
    return ok ? 0 : 1;
}
```

- [ ] **Step 4: Route CLI commands**

In `ipadctl_main.c`, support:

```bash
ipadctl [--config <path>] config show
ipadctl [--config <path>] config check
```

Add parsing for optional `--config <path>` after optional `--socket <path>`, then call `ipadctl_config_show()` or `ipadctl_config_check()`, print the returned JSON, and return the helper return code.

- [ ] **Step 5: Add tests**

Create `tests/ipadctl/test_config_commands.c`:

```c
#include "config_commands.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    char path[256];
    char out[4096];
    FILE *file;

    snprintf(path, sizeof(path), "%s", "/tmp/ipadctl-config-test.json");
    file = fopen(path, "wb");
    if (!file) return 1;
    fputs("{\"sdk_mode\":\"mock\",\"worker_path\":\"/bin/sh\",\"task_retention\":8}", file);
    fclose(file);

    if (ipadctl_config_show(path, out, sizeof(out)) != 0) return 1;
    if (!strstr(out, "\"sdk_mode\":\"mock\"")) return 1;
    if (ipadctl_config_check(path, out, sizeof(out)) != 0) return 1;
    if (!strstr(out, "\"config.parse\"")) return 1;
    unlink(path);
    return 0;
}
```

- [ ] **Step 6: Verify and commit**

Run:

```bash
cmake -S . -B build-manager -DIPAD_BUILD_TESTS=ON
cmake --build build-manager --parallel
ctest --test-dir build-manager --output-on-failure
```

Commit:

```bash
git add ipadctl tests/ipadctl
git commit -m "feat: add ipadctl config diagnostics"
```

---

### Task 3: Device Discovery

**Files:**
- Create: `ipadctl/device_discovery.h`
- Create: `ipadctl/device_discovery.c`
- Modify: `ipadctl/ipadctl_main.c`
- Modify: `ipadctl/CMakeLists.txt`
- Create: `tests/ipadctl/test_device_discovery.c`
- Modify: `tests/ipadctl/CMakeLists.txt`

**Interfaces:**
- Produces:
  - `int ipadctl_device_list(const char *dev_root, char *out, size_t out_size);`

- [ ] **Step 1: Add header**

Create `ipadctl/device_discovery.h`:

```c
#ifndef IPADCTL_DEVICE_DISCOVERY_H
#define IPADCTL_DEVICE_DISCOVERY_H

#include <stddef.h>

int ipadctl_device_list(const char *dev_root, char *out, size_t out_size);

#endif
```

- [ ] **Step 2: Implement device listing**

Create `ipadctl/device_discovery.c`:

```c
#include "device_discovery.h"

#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int likely_device(const char *name) {
    return strncmp(name, "ttyUSB", 6) == 0 ||
           strncmp(name, "ttyACM", 6) == 0 ||
           strncmp(name, "wwan", 4) == 0;
}

int ipadctl_device_list(const char *dev_root, char *out, size_t out_size) {
    const char *root = dev_root && dev_root[0] ? dev_root : "/dev";
    DIR *dir;
    struct dirent *entry;
    size_t used;
    int first = 1;
    int written;

    dir = opendir(root);
    if (!dir) {
        written = snprintf(out, out_size, "{\"devices\":[],\"error\":\"cannot open device root\"}");
        return written > 0 && (size_t)written < out_size ? 1 : 2;
    }
    written = snprintf(out, out_size, "{\"devices\":[");
    if (written <= 0 || (size_t)written >= out_size) {
        closedir(dir);
        return 2;
    }
    used = (size_t)written;
    while ((entry = readdir(dir)) != NULL) {
        char path[256];
        if (!likely_device(entry->d_name)) continue;
        snprintf(path, sizeof(path), "%s/%s", root, entry->d_name);
        written = snprintf(out + used, out_size - used,
                           "%s{\"path\":\"%s\",\"readable\":%s,\"writable\":%s}",
                           first ? "" : ",",
                           path,
                           access(path, R_OK) == 0 ? "true" : "false",
                           access(path, W_OK) == 0 ? "true" : "false");
        if (written <= 0 || (size_t)written >= out_size - used) {
            closedir(dir);
            return 2;
        }
        used += (size_t)written;
        first = 0;
    }
    closedir(dir);
    written = snprintf(out + used, out_size - used, "]}");
    return written > 0 && (size_t)written < out_size - used ? 0 : 2;
}
```

- [ ] **Step 3: Route CLI command**

Support:

```bash
ipadctl device list
ipadctl device list --dev-root /tmp/test-dev
```

Call `ipadctl_device_list()` and print the JSON response.

- [ ] **Step 4: Add test**

Create `tests/ipadctl/test_device_discovery.c`:

```c
#include "device_discovery.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void) {
    char out[1024];
    mkdir("/tmp/ipadctl-dev-test", 0700);
    fclose(fopen("/tmp/ipadctl-dev-test/ttyUSB2", "wb"));
    if (ipadctl_device_list("/tmp/ipadctl-dev-test", out, sizeof(out)) != 0) return 1;
    unlink("/tmp/ipadctl-dev-test/ttyUSB2");
    rmdir("/tmp/ipadctl-dev-test");
    if (!strstr(out, "ttyUSB2")) return 1;
    return 0;
}
```

- [ ] **Step 5: Verify and commit**

Run:

```bash
cmake -S . -B build-manager -DIPAD_BUILD_TESTS=ON
cmake --build build-manager --parallel
ctest --test-dir build-manager --output-on-failure
```

Commit:

```bash
git add ipadctl tests/ipadctl
git commit -m "feat: add ipadctl device discovery"
```

---

### Task 4: Setup Commands and Config Templates

**Files:**
- Create: `ipadctl/setup_commands.h`
- Create: `ipadctl/setup_commands.c`
- Modify: `ipadctl/ipadctl_main.c`
- Modify: `ipadctl/CMakeLists.txt`
- Create: `tests/ipadctl/test_setup_commands.c`
- Modify: `tests/ipadctl/CMakeLists.txt`
- Create: `packaging/config/mock.config.json`
- Create: `packaging/config/at-serial.config.json`

**Interfaces:**
- Produces:
  - `int ipadctl_setup_mock(const char *config_path, char *out, size_t out_size);`
  - `int ipadctl_setup_real_at(const char *config_path, const char *at_device, char *out, size_t out_size);`

- [ ] **Step 1: Add setup header**

Create `ipadctl/setup_commands.h`:

```c
#ifndef IPADCTL_SETUP_COMMANDS_H
#define IPADCTL_SETUP_COMMANDS_H

#include <stddef.h>

int ipadctl_setup_mock(const char *config_path, char *out, size_t out_size);
int ipadctl_setup_real_at(const char *config_path, const char *at_device, char *out, size_t out_size);

#endif
```

- [ ] **Step 2: Implement setup writers**

Create `ipadctl/setup_commands.c`:

```c
#include "setup_commands.h"

#include <stdio.h>

static const char *default_config_path(const char *config_path) {
    return config_path && config_path[0] ? config_path : "/etc/ipad-manager/config.json";
}

static int write_text_file(const char *path, const char *text) {
    FILE *file = fopen(path, "wb");
    if (!file) return -1;
    fputs(text, file);
    fclose(file);
    return 0;
}

int ipadctl_setup_mock(const char *config_path, char *out, size_t out_size) {
    const char *path = default_config_path(config_path);
    const char *json = "{\n  \"socket_path\": \"/run/ipad-manager/ipad-manager.sock\",\n  \"worker_path\": \"/usr/local/bin/ipad-sdk-worker\",\n  \"sdk_mode\": \"mock\",\n  \"request_timeout_ms\": 10000,\n  \"task_store_path\": \"/var/lib/ipad-manager/tasks.jsonl\",\n  \"audit_log_path\": \"/var/log/ipad-manager/audit.jsonl\"\n}\n";
    if (write_text_file(path, json) != 0) {
        snprintf(out, out_size, "{\"ok\":false,\"error\":\"cannot write config\",\"suggestion\":\"Run with sudo or choose --config <writable-path>\"}");
        return 1;
    }
    snprintf(out, out_size, "{\"ok\":true,\"created\":\"%s\",\"sdk_mode\":\"mock\",\"next_action\":\"Run: sudo systemctl restart ipad-managerd && ipadctl doctor\"}", path);
    return 0;
}

int ipadctl_setup_real_at(const char *config_path, const char *at_device, char *out, size_t out_size) {
    char json[1024];
    const char *path = default_config_path(config_path);
    if (!at_device || !at_device[0]) {
        snprintf(out, out_size, "{\"ok\":false,\"error\":\"missing at device\",\"suggestion\":\"Run: ipadctl device list\"}");
        return 2;
    }
    snprintf(json, sizeof(json), "{\n  \"socket_path\": \"/run/ipad-manager/ipad-manager.sock\",\n  \"worker_path\": \"/usr/local/bin/ipad-sdk-worker\",\n  \"sdk_mode\": \"real\",\n  \"request_timeout_ms\": 10000,\n  \"sdk_transport\": \"at_serial\",\n  \"at_device\": \"%s\",\n  \"at_baudrate\": 115200,\n  \"task_store_path\": \"/var/lib/ipad-manager/tasks.jsonl\",\n  \"audit_log_path\": \"/var/log/ipad-manager/audit.jsonl\"\n}\n", at_device);
    if (write_text_file(path, json) != 0) {
        snprintf(out, out_size, "{\"ok\":false,\"error\":\"cannot write config\",\"suggestion\":\"Run with sudo or choose --config <writable-path>\"}");
        return 1;
    }
    snprintf(out, out_size, "{\"ok\":true,\"created\":\"%s\",\"sdk_mode\":\"real\",\"at_device\":\"%s\",\"next_action\":\"Run: sudo systemctl restart ipad-managerd && ipadctl doctor\"}", path, at_device);
    return 0;
}
```

- [ ] **Step 3: Add packaging templates**

Create `packaging/config/mock.config.json` and `packaging/config/at-serial.config.json` with the JSON from the design spec.

- [ ] **Step 4: Route CLI commands**

Support:

```bash
ipadctl --config /tmp/config.json setup --mock
ipadctl --config /tmp/config.json setup --real --at-device /dev/ttyUSB2
```

- [ ] **Step 5: Add tests**

Create `tests/ipadctl/test_setup_commands.c`:

```c
#include "setup_commands.h"

#include <string.h>
#include <unistd.h>

int main(void) {
    char out[1024];
    const char *path = "/tmp/ipadctl-setup-test.json";
    unlink(path);
    if (ipadctl_setup_mock(path, out, sizeof(out)) != 0) return 1;
    if (!strstr(out, "\"sdk_mode\":\"mock\"")) return 1;
    if (access(path, F_OK) != 0) return 1;
    unlink(path);
    return 0;
}
```

- [ ] **Step 6: Verify and commit**

Run:

```bash
cmake -S . -B build-manager -DIPAD_BUILD_TESTS=ON
cmake --build build-manager --parallel
ctest --test-dir build-manager --output-on-failure
```

Commit:

```bash
git add ipadctl tests/ipadctl packaging/config
git commit -m "feat: add ipadctl setup helpers"
```

---

### Task 5: Doctor Command

**Files:**
- Modify: `ipadctl/diagnostics.h`
- Modify: `ipadctl/diagnostics.c`
- Modify: `ipadctl/ipadctl_main.c`
- Create: `tests/ipadctl/test_doctor.c`
- Modify: `tests/ipadctl/CMakeLists.txt`

**Interfaces:**
- Consumes:
  - `ipadctl_config_check()`
  - existing `ipad_socket_connect()`
  - existing daemon RPC request format
- Produces:
  - `int ipadctl_doctor(const char *config_path, const char *socket_path, char *out, size_t out_size);`

- [ ] **Step 1: Add doctor API**

In `diagnostics.h`, add:

```c
int ipadctl_doctor(const char *config_path, const char *socket_path, char *out, size_t out_size);
```

- [ ] **Step 2: Implement missing-daemon path**

In `diagnostics.c`, include `config_commands.h`, `ipad_protocol.h`, and `ipad_socket.h`, then add:

```c
int ipadctl_doctor(const char *config_path, const char *socket_path, char *out, size_t out_size) {
    char config_json[IPAD_MAX_JSON_MESSAGE];
    int config_rc = ipadctl_config_check(config_path, config_json, sizeof(config_json));
    const char *path = socket_path && socket_path[0] ? socket_path : IPAD_DEFAULT_SOCKET_PATH;
    int fd = ipad_socket_connect(path);
    if (fd < 0) {
        snprintf(out, out_size,
                 "{\"ok\":false,\"summary\":\"daemon is not reachable\",\"next_action\":\"Run: sudo systemctl restart ipad-managerd\",\"checks\":[{\"name\":\"config.check\",\"ok\":%s},{\"name\":\"daemon.socket\",\"ok\":false,\"severity\":\"error\",\"message\":\"cannot connect to %s\",\"suggestion\":\"Start ipad-managerd or check socket_path\"}]}",
                 config_rc == 0 ? "true" : "false",
                 path);
        return 4;
    }
    ipad_socket_close(fd);
    snprintf(out, out_size,
             "{\"ok\":true,\"summary\":\"daemon socket is reachable\",\"next_action\":\"Run: ipadctl status\",\"checks\":[{\"name\":\"config.check\",\"ok\":%s},{\"name\":\"daemon.socket\",\"ok\":true}]}",
             config_rc == 0 ? "true" : "false");
    return config_rc == 0 ? 0 : 1;
}
```

- [ ] **Step 3: Route CLI command**

Support:

```bash
ipadctl [--config <path>] [--socket <path>] doctor
```

Print returned JSON and return the doctor return code.

- [ ] **Step 4: Add test**

Create `tests/ipadctl/test_doctor.c`:

```c
#include "diagnostics.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    const char *config = "/tmp/ipadctl-doctor-config.json";
    char out[4096];
    FILE *file = fopen(config, "wb");
    if (!file) return 1;
    fputs("{\"sdk_mode\":\"mock\",\"worker_path\":\"/bin/sh\",\"task_retention\":8}", file);
    fclose(file);
    if (ipadctl_doctor(config, "/tmp/ipadctl-missing.sock", out, sizeof(out)) != 4) return 1;
    unlink(config);
    if (!strstr(out, "daemon is not reachable")) return 1;
    if (!strstr(out, "systemctl restart ipad-managerd")) return 1;
    return 0;
}
```

- [ ] **Step 5: Verify and commit**

Run:

```bash
cmake -S . -B build-manager -DIPAD_BUILD_TESTS=ON
cmake --build build-manager --parallel
ctest --test-dir build-manager --output-on-failure
```

Commit:

```bash
git add ipadctl tests/ipadctl
git commit -m "feat: add ipadctl doctor"
```

---

### Task 6: Quick Start Documentation and CI Checks

**Files:**
- Create: `docs/quick-start.md`
- Modify: `packaging/README.md`
- Modify: `docs/real-device-validation.md`
- Modify: `.github/workflows/ubuntu-build.yml`

**Interfaces:**
- Consumes: new commands from Tasks 2 through 5.
- Produces: operator-first documentation and CI checks for templates/docs.

- [ ] **Step 1: Add quick start**

Create `docs/quick-start.md`:

````markdown
# IPAd Manager Quick Start

## Mock Mode

```bash
sudo ipadctl setup --mock
sudo systemctl restart ipad-managerd
ipadctl doctor
ipadctl sdk init
ipadctl sdk status
```

## Real AT Serial Mode

```bash
ipadctl device list
sudo ipadctl setup --real --at-device /dev/ttyUSB2
sudo systemctl restart ipad-managerd
ipadctl doctor
ipadctl sdk init
ipadctl sdk status
```

## Profile Download

```bash
ipadctl profile download --activation-code 'LPA:1$smdp.example.com$MATCHINGID'
ipadctl task get task-1
```

## Troubleshooting

```bash
ipadctl config show
ipadctl config check
ipadctl doctor
journalctl -u ipad-managerd --no-pager
```
````

- [ ] **Step 2: Link quick start from docs**

Add references to `docs/quick-start.md` in `packaging/README.md` and `docs/real-device-validation.md`.

- [ ] **Step 3: Add CI checks**

In `.github/workflows/ubuntu-build.yml`, extend packaging checks:

```bash
test -f packaging/config/mock.config.json
test -f packaging/config/at-serial.config.json
test -f docs/quick-start.md
grep -q 'ipadctl doctor' docs/quick-start.md
grep -q 'ipadctl config check' docs/quick-start.md
```

- [ ] **Step 4: Verify and commit**

Run:

```bash
cmake -S . -B build-manager -DIPAD_BUILD_TESTS=ON
cmake --build build-manager --parallel
ctest --test-dir build-manager --output-on-failure
```

Commit:

```bash
git add docs packaging .github/workflows/ubuntu-build.yml
git commit -m "docs: add operator quick start"
```

---

## Self-Review Notes

- Spec coverage: config diagnostics, device discovery, setup helpers, doctor, templates, and quick start are all mapped to tasks.
- Marker scan: no unresolved markers are used as implementation instructions.
- Type consistency: command helper names are stable across tasks.
- Scope control: this plan does not add rich terminal UI, GUI setup, vendor-specific modem probing, or remote diagnostics.
- Verification: each task ends with local Ubuntu CMake build and CTest.
