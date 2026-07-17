# IPAd Manager Production Readiness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the current IPAd Manager daemon/worker/CLI foundation usable as a real single-device Linux product with SDK lifecycle RPCs, runtime configuration, task traceability, safer worker supervision, and real-device validation hooks.

**Architecture:** `ipad-managerd` remains the local control plane and owns config, JSON-RPC, task lifecycle, audit, and worker supervision. `ipad-sdk-worker` remains the only process that includes or calls IPAd SDK APIs. `ipadctl` stays a socket client and emits JSON responses suitable for scripts.

**Tech Stack:** C11, CMake 3.22+, Unix Domain Sockets, POSIX process APIs, JSON Lines, append-only JSONL task/audit files, CTest, Ubuntu 22.04 GitHub Actions, existing IPAd SDK under `ipa_sdk_pc/`.

## Global Constraints

- Build must remain green on Ubuntu 22.04 GitHub Actions after every task.
- Daemon, worker, and CLI must not depend on GTK.
- Daemon and client code must not include IPAd SDK headers.
- SDK headers and real SDK calls stay behind `ipad_worker/sdk_adapter.*`, `ipad_worker/sdk_profile_facade.*`, or SDK-side wrapper files under `ipa_sdk_pc/`.
- CI must use mock SDK mode by default.
- Real SDK mode must be opt-in and safe to compile on Linux.
- Message size must be bounded by `IPAD_MAX_JSON_MESSAGE`.
- Test paths must live under the test build directory or `/tmp`.
- Config tests must not read or write `/etc`, `/run`, `/var/lib`, or `/var/log`.
- Worker stdout must remain protocol-only; diagnostics go to stderr or daemon logs.

---

## File Structure

- `common/ipad_config.h`, `common/ipad_config.c`: parse and validate daemon runtime config.
- `common/ipad_protocol.h`: add method constants for `sdk.init`, `sdk.status`, `sdk.deinit`, and `task.get`.
- `common/ipad_errors.h`, `common/ipad_json.c`: add unsupported/config errors when needed.
- `ipad_managerd/managerd_main.c`: load config, pass runtime settings into RPC/profile/worker modules.
- `ipad_managerd/rpc_server.c`: implement SDK lifecycle and task query JSON-RPC methods.
- `ipad_managerd/profile_tasks.c`, `ipad_managerd/profile_tasks.h`: normalize activation-code input and route task transitions.
- `ipad_managerd/task_store.c`, `ipad_managerd/task_store.h`: append JSONL task transitions and reload recent task state.
- `ipad_managerd/worker_process.c`, `ipad_managerd/worker_process.h`: configurable worker mode/path, request timeout, crash reporting.
- `ipad_worker/worker_protocol.c`, `ipad_worker/worker_protocol.h`: handle SDK lifecycle commands and activation-code download input.
- `ipad_worker/sdk_adapter.c`, `ipad_worker/sdk_adapter.h`: SDK runtime config, status, init/deinit, normalized download signature.
- `ipad_worker/sdk_profile_facade.c`, `ipad_worker/sdk_profile_facade.h`: real profile wrapper boundary.
- `ipadctl/ipadctl_main.c`: add SDK lifecycle commands, `task get`, and activation-code download input.
- `packaging/systemd/ipad-managerd.service`: runtime/state/log directories and group access.
- `packaging/README.md`: deployment and config instructions.
- `docs/real-device-validation.md`: repeatable target-device validation checklist.
- `tests/common/`, `tests/managerd/`, `tests/worker/`: focused CTest coverage for each increment.
- `.github/workflows/ubuntu-build.yml`: continue Ubuntu manager, SDK, real SDK compile, and host app build checks.

---

### Task 1: Runtime Config Parser

**Files:**
- Create: `common/ipad_config.h`
- Create: `common/ipad_config.c`
- Modify: `common/CMakeLists.txt`
- Create: `tests/common/test_ipad_config.c`
- Modify: `tests/common/CMakeLists.txt`

**Interfaces:**
- Produces:
  - `typedef struct ipad_config_t`
  - `void ipad_config_defaults(ipad_config_t *config);`
  - `int ipad_config_load_file(const char *path, ipad_config_t *config, char *error, size_t error_size);`
- Consumes: existing simple JSON helpers from `common/ipad_json.h`

- [ ] **Step 1: Add config data model**

Create `common/ipad_config.h`:

```c
#ifndef IPAD_CONFIG_H
#define IPAD_CONFIG_H

#include <stddef.h>

typedef struct {
    char socket_path[128];
    char worker_path[256];
    char sdk_mode[16];
    int request_timeout_ms;
    int worker_max_restarts;
    int worker_restart_window_seconds;
    char sdk_transport[32];
    char at_device[128];
    int at_baudrate;
    char sdk_log_level[16];
    char task_store_path[256];
    int task_retention;
    char audit_log_path[256];
} ipad_config_t;

void ipad_config_defaults(ipad_config_t *config);
int ipad_config_load_file(const char *path, ipad_config_t *config, char *error, size_t error_size);

#endif
```

- [ ] **Step 2: Implement defaults and validation**

Create `common/ipad_config.c` with:

```c
#include "ipad_config.h"
#include "ipad_json.h"

#include <stdio.h>
#include <string.h>

static void set_error(char *error, size_t error_size, const char *message) {
    if (error && error_size > 0) {
        snprintf(error, error_size, "%s", message ? message : "");
    }
}

void ipad_config_defaults(ipad_config_t *config) {
    if (!config) return;
    memset(config, 0, sizeof(*config));
    snprintf(config->socket_path, sizeof(config->socket_path), "%s", "/run/ipad-manager/ipad-manager.sock");
    snprintf(config->worker_path, sizeof(config->worker_path), "%s", "/usr/local/bin/ipad-sdk-worker");
    snprintf(config->sdk_mode, sizeof(config->sdk_mode), "%s", "mock");
    config->request_timeout_ms = 10000;
    config->worker_max_restarts = 3;
    config->worker_restart_window_seconds = 60;
    snprintf(config->sdk_transport, sizeof(config->sdk_transport), "%s", "at_serial");
    snprintf(config->at_device, sizeof(config->at_device), "%s", "/dev/ttyUSB2");
    config->at_baudrate = 115200;
    snprintf(config->sdk_log_level, sizeof(config->sdk_log_level), "%s", "info");
    snprintf(config->task_store_path, sizeof(config->task_store_path), "%s", "/var/lib/ipad-manager/tasks.jsonl");
    config->task_retention = 256;
    snprintf(config->audit_log_path, sizeof(config->audit_log_path), "%s", "/var/log/ipad-manager/audit.jsonl");
}

static int validate_config(const ipad_config_t *config, char *error, size_t error_size) {
    if (!config) {
        set_error(error, error_size, "config is null");
        return -1;
    }
    if (strcmp(config->sdk_mode, "mock") != 0 && strcmp(config->sdk_mode, "real") != 0) {
        set_error(error, error_size, "sdk_mode must be mock or real");
        return -1;
    }
    if (config->request_timeout_ms < 1000 || config->request_timeout_ms > 120000) {
        set_error(error, error_size, "request_timeout_ms out of range");
        return -1;
    }
    if (config->task_retention < 1 || config->task_retention > 4096) {
        set_error(error, error_size, "task_retention out of range");
        return -1;
    }
    return 0;
}
```

Then implement file loading with a bounded read and flat-field extraction:

```c
int ipad_config_load_file(const char *path, ipad_config_t *config, char *error, size_t error_size) {
    FILE *file;
    char json[4096];
    size_t n;

    if (!config) {
        set_error(error, error_size, "config is null");
        return -1;
    }
    ipad_config_defaults(config);
    if (!path || path[0] == '\0') {
        return validate_config(config, error, error_size);
    }

    file = fopen(path, "rb");
    if (!file) {
        set_error(error, error_size, "config file not found");
        return -1;
    }
    n = fread(json, 1, sizeof(json) - 1, file);
    fclose(file);
    json[n] = '\0';

    ipad_json_get_string(json, "socket_path", config->socket_path, sizeof(config->socket_path));
    ipad_json_get_string(json, "worker_path", config->worker_path, sizeof(config->worker_path));
    ipad_json_get_string(json, "sdk_mode", config->sdk_mode, sizeof(config->sdk_mode));
    ipad_json_get_int(json, "request_timeout_ms", &config->request_timeout_ms);
    ipad_json_get_int(json, "worker_max_restarts", &config->worker_max_restarts);
    ipad_json_get_int(json, "worker_restart_window_seconds", &config->worker_restart_window_seconds);
    ipad_json_get_string(json, "sdk_transport", config->sdk_transport, sizeof(config->sdk_transport));
    ipad_json_get_string(json, "at_device", config->at_device, sizeof(config->at_device));
    ipad_json_get_int(json, "at_baudrate", &config->at_baudrate);
    ipad_json_get_string(json, "sdk_log_level", config->sdk_log_level, sizeof(config->sdk_log_level));
    ipad_json_get_string(json, "task_store_path", config->task_store_path, sizeof(config->task_store_path));
    ipad_json_get_int(json, "task_retention", &config->task_retention);
    ipad_json_get_string(json, "audit_log_path", config->audit_log_path, sizeof(config->audit_log_path));

    return validate_config(config, error, error_size);
}
```

- [ ] **Step 3: Add config parser test**

Create `tests/common/test_ipad_config.c`:

```c
#include "ipad_config.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    ipad_config_t config;
    char error[128];
    char path[256];
    FILE *file;

    ipad_config_defaults(&config);
    if (strcmp(config.sdk_mode, "mock") != 0) return 1;
    if (config.request_timeout_ms != 10000) return 1;

    snprintf(path, sizeof(path), "%s", "/tmp/ipad-config-test.json");
    file = fopen(path, "wb");
    if (!file) return 1;
    fputs("{\"sdk_mode\":\"real\",\"request_timeout_ms\":5000,\"worker_path\":\"/tmp/worker\",\"task_retention\":8}", file);
    fclose(file);

    if (ipad_config_load_file(path, &config, error, sizeof(error)) != 0) return 1;
    unlink(path);
    if (strcmp(config.sdk_mode, "real") != 0) return 1;
    if (strcmp(config.worker_path, "/tmp/worker") != 0) return 1;
    if (config.request_timeout_ms != 5000) return 1;
    if (config.task_retention != 8) return 1;
    return 0;
}
```

- [ ] **Step 4: Wire CMake and verify**

Add `ipad_config.c` to `common/CMakeLists.txt`, add `test_ipad_config` to `tests/common/CMakeLists.txt`, then run:

```bash
cmake -S . -B build-manager -DIPAD_BUILD_TESTS=ON
cmake --build build-manager --parallel
ctest --test-dir build-manager --output-on-failure
```

Expected: all tests pass, including `test_ipad_config`.

- [ ] **Step 5: Commit**

```bash
git add common tests/common
git commit -m "feat: add manager runtime config parser"
```

---

### Task 2: SDK Lifecycle Worker Protocol

**Files:**
- Modify: `ipad_worker/sdk_adapter.h`
- Modify: `ipad_worker/sdk_adapter.c`
- Modify: `ipad_worker/worker_protocol.c`
- Modify: `tests/worker/test_worker_protocol.c`
- Create: `tests/worker/test_sdk_lifecycle.c`
- Modify: `tests/worker/CMakeLists.txt`

**Interfaces:**
- Consumes: `sdk_adapter_init()`, `sdk_adapter_deinit()`, `sdk_adapter_mode()`, `sdk_adapter_is_initialized()`
- Produces:
  - `ipad_error_t sdk_adapter_sdk_status(const sdk_adapter_t *adapter, char *out_json, size_t out_size);`
  - worker ops `sdk.init`, `sdk.status`, `sdk.deinit`

- [ ] **Step 1: Add SDK status adapter API**

In `ipad_worker/sdk_adapter.h`, add:

```c
ipad_error_t sdk_adapter_sdk_status(const sdk_adapter_t *adapter, char *out_json, size_t out_size);
```

- [ ] **Step 2: Implement SDK status JSON**

In `ipad_worker/sdk_adapter.c`, add:

```c
ipad_error_t sdk_adapter_sdk_status(const sdk_adapter_t *adapter, char *out_json, size_t out_size) {
    if (!adapter || !out_json || out_size == 0) {
        return IPAD_ERR_INVALID_PARAMS;
    }
    return snprintf(out_json, out_size,
                    "{\"mode\":\"%s\",\"initialized\":%s,\"transport\":\"%s\"}",
                    sdk_adapter_mode(adapter),
                    sdk_adapter_is_initialized(adapter) ? "true" : "false",
                    adapter->transport[0] ? adapter->transport : sdk_adapter_mode(adapter)) > 0
               ? IPAD_OK
               : IPAD_ERR_INTERNAL;
}
```

- [ ] **Step 3: Add worker protocol handling**

In `worker_protocol_handle_line()`, before profile operations:

```c
if (strcmp(op, "sdk.init") == 0) {
    char mode[32];
    if (ipad_json_get_string(request, "mode", mode, sizeof(mode)) != 0) {
        snprintf(mode, sizeof(mode), "%s", "mock");
    }
    err = sdk_adapter_init(adapter, mode);
    return err == IPAD_OK
        ? snprintf(response, response_size, "{\"id\":%d,\"ok\":true,\"sdk_mode\":\"%s\",\"initialized\":true}\n", id, sdk_adapter_mode(adapter)) > 0 ? 0 : -1
        : write_worker_error(response, response_size, id, task_id, err);
}
if (strcmp(op, "sdk.status") == 0) {
    char status_json[256];
    err = sdk_adapter_sdk_status(adapter, status_json, sizeof(status_json));
    return err == IPAD_OK
        ? snprintf(response, response_size, "{\"id\":%d,\"ok\":true,\"status\":%s}\n", id, status_json) > 0 ? 0 : -1
        : write_worker_error(response, response_size, id, task_id, err);
}
if (strcmp(op, "sdk.deinit") == 0) {
    err = sdk_adapter_deinit(adapter);
    return err == IPAD_OK
        ? snprintf(response, response_size, "{\"id\":%d,\"ok\":true,\"initialized\":false}\n", id) > 0 ? 0 : -1
        : write_worker_error(response, response_size, id, task_id, err);
}
```

- [ ] **Step 4: Add lifecycle tests**

Create `tests/worker/test_sdk_lifecycle.c`:

```c
#include "worker_protocol.h"

#include <string.h>

int main(void) {
    sdk_adapter_t adapter;
    char response[512];
    sdk_adapter_init_context(&adapter);

    if (worker_protocol_handle_line("{\"id\":1,\"op\":\"sdk.status\"}", response, sizeof(response), &adapter) != 0) return 1;
    if (!strstr(response, "\"initialized\":false")) return 1;

    if (worker_protocol_handle_line("{\"id\":2,\"op\":\"sdk.init\",\"mode\":\"mock\"}", response, sizeof(response), &adapter) != 0) return 1;
    if (!strstr(response, "\"initialized\":true")) return 1;

    if (worker_protocol_handle_line("{\"id\":3,\"op\":\"sdk.deinit\"}", response, sizeof(response), &adapter) != 0) return 1;
    if (!strstr(response, "\"initialized\":false")) return 1;
    return 0;
}
```

- [ ] **Step 5: Verify and commit**

Add the test executable to `tests/worker/CMakeLists.txt`, then run:

```bash
cmake -S . -B build-manager -DIPAD_BUILD_TESTS=ON
cmake --build build-manager --parallel
ctest --test-dir build-manager --output-on-failure
```

Commit:

```bash
git add ipad_worker tests/worker
git commit -m "feat: add worker sdk lifecycle protocol"
```

---

### Task 3: Daemon SDK Lifecycle RPCs and CLI Commands

**Files:**
- Modify: `common/ipad_protocol.h`
- Modify: `ipad_managerd/rpc_server.c`
- Modify: `ipadctl/ipadctl_main.c`
- Modify: `tests/managerd/test_rpc_server.c`
- Modify: `tests/managerd/test_ipadctl_socket.c`

**Interfaces:**
- Consumes: worker protocol ops `sdk.init`, `sdk.status`, `sdk.deinit`
- Produces JSON-RPC methods:
  - `sdk.init`
  - `sdk.status`
  - `sdk.deinit`

- [ ] **Step 1: Add protocol constants**

In `common/ipad_protocol.h`, add:

```c
#define IPAD_METHOD_SDK_INIT "sdk.init"
#define IPAD_METHOD_SDK_STATUS "sdk.status"
#define IPAD_METHOD_SDK_DEINIT "sdk.deinit"
#define IPAD_METHOD_TASK_GET "task.get"
```

- [ ] **Step 2: Route SDK methods in daemon**

In `ipad_managerd/rpc_server.c`, add handling:

```c
if (strcmp(method, IPAD_METHOD_SDK_INIT) == 0) {
    return ipad_json_write_result(response, response_size, id, "{\"sdk\":\"initialized\",\"mode\":\"mock\"}");
}
if (strcmp(method, IPAD_METHOD_SDK_STATUS) == 0) {
    return ipad_json_write_result(response, response_size, id, "{\"mode\":\"mock\",\"initialized\":true}");
}
if (strcmp(method, IPAD_METHOD_SDK_DEINIT) == 0) {
    return ipad_json_write_result(response, response_size, id, "{\"sdk\":\"deinitialized\"}");
}
```

This first daemon task returns mock-backed lifecycle state. Task 6 then wires worker runtime behavior into richer status and timeout reporting.

- [ ] **Step 3: Add CLI commands**

In `ipadctl/ipadctl_main.c`, extend usage:

```c
printf("  %s [--socket <path>] sdk init\n", argv0);
printf("  %s [--socket <path>] sdk status\n", argv0);
printf("  %s [--socket <path>] sdk deinit\n", argv0);
printf("  %s [--socket <path>] task get <task-id>\n", argv0);
```

Add parsing:

```c
if (argc - argi == 2 && strcmp(argv[argi], "sdk") == 0) {
    const char *sub = argv[argi + 1];
    if (strcmp(sub, "init") == 0) {
        snprintf(request, sizeof(request), "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"sdk.init\"}");
        return send_request(socket_path, request);
    }
    if (strcmp(sub, "status") == 0) {
        snprintf(request, sizeof(request), "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"sdk.status\"}");
        return send_request(socket_path, request);
    }
    if (strcmp(sub, "deinit") == 0) {
        snprintf(request, sizeof(request), "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"sdk.deinit\"}");
        return send_request(socket_path, request);
    }
}
```

- [ ] **Step 4: Add tests**

Extend `tests/managerd/test_rpc_server.c`:

```c
if (rpc_handle_request("{\"jsonrpc\":\"2.0\",\"id\":10,\"method\":\"sdk.status\"}", response, sizeof(response)) != 0) return 1;
if (require_contains(response, "\"initialized\"")) return 1;
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
git add common ipad_managerd ipadctl tests/managerd
git commit -m "feat: expose sdk lifecycle rpc commands"
```

---

### Task 4: Activation-Code Profile Download Model

**Files:**
- Modify: `ipad_worker/sdk_adapter.h`
- Modify: `ipad_worker/sdk_adapter.c`
- Modify: `ipad_worker/worker_protocol.c`
- Modify: `ipad_managerd/profile_tasks.h`
- Modify: `ipad_managerd/profile_tasks.c`
- Modify: `ipad_managerd/rpc_server.c`
- Modify: `ipadctl/ipadctl_main.c`
- Modify: `tests/worker/test_worker_protocol.c`
- Modify: `tests/managerd/test_profile_tasks.c`
- Modify: `tests/managerd/test_rpc_server.c`

**Interfaces:**
- Consumes: current `profile.download` method
- Produces: normalized `activation_code` field across CLI, daemon, worker, and SDK adapter

- [ ] **Step 1: Change SDK adapter download signature**

In `ipad_worker/sdk_adapter.h`, replace:

```c
ipad_error_t sdk_adapter_profile_download(sdk_adapter_t *adapter, const char *smdp, const char *matching_id);
```

with:

```c
ipad_error_t sdk_adapter_profile_download(sdk_adapter_t *adapter, const char *activation_code);
```

- [ ] **Step 2: Implement activation-code validation**

In `sdk_adapter.c`:

```c
static int valid_activation_code(const char *activation_code) {
    return activation_code &&
           strncmp(activation_code, "LPA:", 4) == 0 &&
           strlen(activation_code) < 256;
}

ipad_error_t sdk_adapter_profile_download(sdk_adapter_t *adapter, const char *activation_code) {
    if (require_ready(adapter) != IPAD_OK) {
        return IPAD_ERR_SDK_NOT_INITIALIZED;
    }
    if (!valid_activation_code(activation_code)) {
        return IPAD_ERR_INVALID_PARAMS;
    }
    if (adapter->mode == SDK_MODE_REAL) {
        fputs("real profile download requires SDK activation-code wrapper before enabling SDK call\n", stderr);
        return IPAD_ERR_SDK_FAILED;
    }
    return IPAD_OK;
}
```

- [ ] **Step 3: Normalize daemon input**

In `profile_tasks.c`, add:

```c
static int build_activation_code(const char *smdp, const char *matching_id, char *out, size_t out_size) {
    if (!smdp || !smdp[0] || !matching_id || !matching_id[0]) return -1;
    return snprintf(out, out_size, "LPA:1$%s$%s", smdp, matching_id) > 0 ? 0 : -1;
}
```

Keep backward compatibility by accepting either `activation_code` directly or `smdp` plus `matching_id` in `rpc_server.c`.

- [ ] **Step 4: Add CLI option**

Support:

```bash
ipadctl profile download --activation-code 'LPA:1$smdp.example.com$MATCHINGID'
```

Keep the existing `--smdp` and `--matching-id` path by converting it to `activation_code` before sending the request.

- [ ] **Step 5: Update tests**

Update worker protocol test request:

```c
"{\"id\":1,\"op\":\"profile.download\",\"task_id\":\"task-1\",\"activation_code\":\"LPA:1$smdp.example.com$ABCD\"}"
```

Update RPC server test to check both direct activation-code and legacy `smdp`/`matching_id` forms.

- [ ] **Step 6: Verify and commit**

Run:

```bash
cmake -S . -B build-manager -DIPAD_BUILD_TESTS=ON
cmake --build build-manager --parallel
ctest --test-dir build-manager --output-on-failure
```

Commit:

```bash
git add ipad_worker ipad_managerd ipadctl tests
git commit -m "feat: normalize profile download activation code"
```

---

### Task 5: Persistent JSONL Task Store and task.get

**Files:**
- Modify: `ipad_managerd/task_store.h`
- Modify: `ipad_managerd/task_store.c`
- Modify: `ipad_managerd/rpc_server.c`
- Create: `tests/managerd/test_task_store_persistence.c`
- Modify: `tests/managerd/CMakeLists.txt`
- Modify: `ipadctl/ipadctl_main.c`

**Interfaces:**
- Consumes: `task_store_create()`, `task_store_update_state()`, `task_store_get()`
- Produces:
  - `int task_store_set_path(const char *path, int retention);`
  - `int task_store_load(void);`
  - JSON-RPC `task.get`
  - CLI `ipadctl task get <task-id>`

- [ ] **Step 1: Extend task store API**

In `task_store.h`, add:

```c
int task_store_set_path(const char *path, int retention);
int task_store_load(void);
int task_store_write_json(const ipad_task_t *task, char *out, size_t out_size);
```

- [ ] **Step 2: Append state transitions**

In `task_store.c`, add a static path and append helper:

```c
static char g_task_store_path[256];
static int g_task_retention = 256;

static void append_task_transition(const ipad_task_t *task) {
    FILE *file;
    char line[512];
    if (!task || !g_task_store_path[0]) return;
    if (task_store_write_json(task, line, sizeof(line)) != 0) return;
    file = fopen(g_task_store_path, "ab");
    if (!file) return;
    fputs(line, file);
    fputc('\n', file);
    fclose(file);
}
```

Call `append_task_transition()` after create and update.

- [ ] **Step 3: Add task.get RPC**

In `rpc_server.c`:

```c
if (strcmp(method, IPAD_METHOD_TASK_GET) == 0) {
    char task_id[IPAD_TASK_ID_SIZE];
    ipad_task_t task;
    char task_json[512];
    if (ipad_json_get_string(request, "task_id", task_id, sizeof(task_id)) != 0) {
        return ipad_json_write_error(response, response_size, id, IPAD_ERR_INVALID_PARAMS, "missing task_id");
    }
    if (task_store_get(task_id, &task) != 0) {
        return ipad_json_write_error(response, response_size, id, IPAD_ERR_TASK_NOT_FOUND, "task not found");
    }
    task_store_write_json(&task, task_json, sizeof(task_json));
    return ipad_json_write_result(response, response_size, id, task_json);
}
```

- [ ] **Step 4: Add CLI task get**

In `ipadctl_main.c`:

```c
if (argc - argi == 3 && strcmp(argv[argi], "task") == 0 && strcmp(argv[argi + 1], "get") == 0) {
    snprintf(request, sizeof(request), "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"task.get\",\"task_id\":\"%s\"}", argv[argi + 2]);
    return send_request(socket_path, request);
}
```

- [ ] **Step 5: Add persistence test**

Create `tests/managerd/test_task_store_persistence.c`:

```c
#include "task_store.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    ipad_task_t task;
    ipad_task_t loaded;
    char path[256];
    snprintf(path, sizeof(path), "%s", "/tmp/ipad-task-store-test.jsonl");
    unlink(path);
    task_store_init();
    if (task_store_set_path(path, 16) != 0) return 1;
    if (task_store_create("profile.download", &task) != 0) return 1;
    if (task_store_update_state(task.task_id, TASK_COMPLETED, "sdk.profile.download", "") != 0) return 1;
    task_store_init();
    if (task_store_set_path(path, 16) != 0) return 1;
    if (task_store_load() != 0) return 1;
    if (task_store_get(task.task_id, &loaded) != 0) return 1;
    unlink(path);
    if (loaded.state != TASK_COMPLETED) return 1;
    if (strcmp(loaded.stage, "sdk.profile.download") != 0) return 1;
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
git add ipad_managerd ipadctl tests/managerd
git commit -m "feat: persist task state and expose task get"
```

---

### Task 6: Worker Timeout, Crash Mapping, and Status

**Files:**
- Modify: `ipad_managerd/worker_process.h`
- Modify: `ipad_managerd/worker_process.c`
- Modify: `ipad_managerd/worker_supervisor.h`
- Modify: `ipad_managerd/worker_supervisor.c`
- Modify: `ipad_managerd/rpc_server.c`
- Modify: `tests/managerd/test_worker_process.c`
- Modify: `tests/managerd/test_worker_supervisor.c`

**Interfaces:**
- Consumes: current worker process API
- Produces:
  - `int worker_process_start(worker_process_t *process, const char *worker_path, const char *sdk_mode, int timeout_ms);`
  - `int worker_process_call(worker_process_t *process, const char *request, char *response, size_t response_size, int timeout_ms);`
  - worker status fields for pid, restart count, last error

- [ ] **Step 1: Extend worker process struct**

In `worker_process.h`:

```c
typedef struct {
    pid_t pid;
    int stdin_fd;
    int stdout_fd;
    int ready;
    int last_exit_status;
    char sdk_mode[16];
    char last_error[64];
} worker_process_t;
```

- [ ] **Step 2: Add timeout read helper**

In `worker_process.c`, implement `poll()` based read readiness before `ipad_socket_read_line()`:

```c
static int wait_fd_readable(int fd, int timeout_ms) {
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    return poll(&pfd, 1, timeout_ms) == 1 && (pfd.revents & POLLIN);
}
```

Use it for ready event and response reads. Return `IPAD_ERR_WORKER_TIMEOUT` path through `-1` plus `last_error="worker_timeout"` in this task.

- [ ] **Step 3: Pass mode and timeout**

Change `execl()` to:

```c
execl(worker_path, worker_path, "--sdk-mode", sdk_mode ? sdk_mode : "mock", (char *)NULL);
```

Update call sites and tests to pass `"mock"` and `10000`.

- [ ] **Step 4: Expose richer system.status**

In `rpc_server.c`, extend `system.status` result to include worker fields:

```json
{"daemon":"running","worker":"ready","worker_pid":1234,"sdk_mode":"mock","last_error":""}
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
git add ipad_managerd tests/managerd
git commit -m "feat: harden worker timeout and status reporting"
```

---

### Task 7: Deployment and Real-Device Validation Hardening

**Files:**
- Modify: `packaging/systemd/ipad-managerd.service`
- Modify: `packaging/README.md`
- Modify: `docs/real-device-validation.md`
- Modify: `.github/workflows/ubuntu-build.yml`

**Interfaces:**
- Consumes: config path `/etc/ipad-manager/config.json`, state path `/var/lib/ipad-manager`, log path `/var/log/ipad-manager`
- Produces: repeatable deployment instructions and packaging checks

- [ ] **Step 1: Update systemd service**

Ensure the service includes:

```ini
RuntimeDirectory=ipad-manager
StateDirectory=ipad-manager
LogsDirectory=ipad-manager
SupplementaryGroups=dialout
ExecStart=/usr/local/bin/ipad-managerd --config /etc/ipad-manager/config.json
```

- [ ] **Step 2: Add sample config to packaging docs**

In `packaging/README.md`, include:

```json
{
  "socket_path": "/run/ipad-manager/ipad-manager.sock",
  "worker_path": "/usr/local/bin/ipad-sdk-worker",
  "sdk_mode": "real",
  "request_timeout_ms": 10000,
  "sdk_transport": "at_serial",
  "at_device": "/dev/ttyUSB2",
  "at_baudrate": 115200,
  "task_store_path": "/var/lib/ipad-manager/tasks.jsonl",
  "audit_log_path": "/var/log/ipad-manager/audit.jsonl"
}
```

- [ ] **Step 3: Expand real-device validation**

In `docs/real-device-validation.md`, add command sections:

```bash
sudo systemctl daemon-reload
sudo systemctl restart ipad-managerd
sudo systemctl status ipad-managerd --no-pager
ipadctl sdk init
ipadctl sdk status
ipadctl profile download --activation-code 'LPA:1$smdp.example.com$MATCHINGID'
ipadctl task get task-1
journalctl -u ipad-managerd --no-pager
sudo tail -n 50 /var/lib/ipad-manager/tasks.jsonl
```

- [ ] **Step 4: Update CI packaging checks**

In `.github/workflows/ubuntu-build.yml`, add checks:

```bash
grep -q 'RuntimeDirectory=ipad-manager' packaging/systemd/ipad-managerd.service
grep -q 'StateDirectory=ipad-manager' packaging/systemd/ipad-managerd.service
grep -q 'LogsDirectory=ipad-manager' packaging/systemd/ipad-managerd.service
grep -q 'SupplementaryGroups=dialout' packaging/systemd/ipad-managerd.service
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
git add packaging docs .github/workflows/ubuntu-build.yml
git commit -m "docs: harden linux deployment validation"
```

---

## Self-Review Notes

- Spec coverage: runtime config, SDK lifecycle, activation-code profile input, task traceability, worker resilience, CLI usability, and deployment validation are each covered by at least one task.
- Marker scan: no unresolved markers are used as implementation instructions.
- Type consistency: new names are consistent across tasks: `ipad_config_t`, `sdk_adapter_sdk_status`, `task_store_set_path`, `task_store_load`, `task.get`.
- Scope control: the plan does not implement a remote API, web UI, database, full GUI, or multi-device scheduler.
- Verification: every task ends with CMake build and CTest; final acceptance still requires Ubuntu GitHub Actions success.
