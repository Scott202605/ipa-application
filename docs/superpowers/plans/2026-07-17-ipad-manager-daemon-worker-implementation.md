# IPAd Manager Daemon/Worker Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first production-shaped IPAd Manager architecture for a single Linux device: daemon + SDK worker + Unix Socket JSON-RPC + CLI + task tracing, with Profile management flowing through the worker boundary.

**Architecture:** The daemon owns product state, JSON-RPC, task lifecycle, logs, configuration, worker supervision, and permissions. The SDK worker links the existing IPAd SDK and executes SDK calls in an isolated child process. CLI and GUI become JSON-RPC clients instead of directly calling SDK functions.

**Tech Stack:** C11, CMake 3.22+, GTK3 for the existing GUI, Unix Domain Sockets, JSON-RPC 2.0, systemd-compatible Linux paths, CTest-based unit/integration tests, existing IPAd SDK under `ipa_sdk_pc/`.

## Global Constraints

- Target product is a single Linux device IPAd capability service, not a multi-device management platform.
- First implementation uses one `ipad-managerd` daemon and one `ipad-sdk-worker`.
- Client protocol is Unix Domain Socket + JSON-RPC 2.0.
- SDK failure isolation uses a worker child process; daemon must not directly execute long-running SDK calls.
- First business goal includes Profile download, enable, disable, and delete through daemon/worker.
- First transport design covers AT serial and PC/SC concepts, but implementation may initially activate one configured transport.
- Default trace level records audit and task lifecycle; protocol trace is opt-in.
- Linux target is Ubuntu 22.04+ with x86_64 and aarch64 compatibility in mind.
- Existing IPAd SDK remains the SGP.32/IPAd protocol capability library.
- Existing GTK GUI must eventually become a daemon client; it must not remain the long-term SDK owner.

---

## File Structure

Create these top-level implementation areas:

- `ipad_managerd/`：daemon service, JSON-RPC server, worker supervisor, task state, config, audit logs.
- `ipad_worker/`：SDK worker executable, SDK adapter, worker IPC, mock SDK mode.
- `ipadctl/`：CLI JSON-RPC client.
- `common/`：shared protocol structs, JSON helpers, socket framing, error codes, redaction helpers.
- `tests/`：CTest-compatible unit and integration tests.
- `packaging/systemd/`：service unit and runtime directory policy.

Keep existing `ipad_host_app/` during migration. It will be converted to a JSON-RPC client in a later task without breaking current build until replacement is complete.

Expected final build targets:

- `ipad-managerd`
- `ipad-sdk-worker`
- `ipadctl`
- existing `ipad_host_app`
- test binaries registered through CTest

---

### Task 1: Common Protocol, Error Model, and Test Harness

**Files:**
- Create: `common/ipad_protocol.h`
- Create: `common/ipad_errors.h`
- Create: `common/ipad_json.h`
- Create: `common/ipad_json.c`
- Create: `tests/common/test_ipad_json.c`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Produces: `ipad_error_t`, `ipad_json_get_string()`, `ipad_json_get_int()`, `ipad_json_write_error()`, `ipad_json_write_result()`
- Consumes: no new project interfaces

- [ ] **Step 1: Add top-level CMake test support**

Create or update root `CMakeLists.txt` so new components can be built independently:

```cmake
cmake_minimum_required(VERSION 3.22.1)
project(ipad-manager LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

option(IPAD_BUILD_TESTS "Build IPAd Manager tests" ON)

add_subdirectory(common)

if(IPAD_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
```

Expected: existing SDK and host app CMake files remain untouched in this step.

- [ ] **Step 2: Add common CMake target**

Create `common/CMakeLists.txt`:

```cmake
add_library(ipad_common STATIC
    ipad_json.c
)

target_include_directories(ipad_common PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_options(ipad_common PRIVATE
    -Wall
    -Wextra
    -Werror
)
```

- [ ] **Step 3: Define shared error codes**

Create `common/ipad_errors.h`:

```c
#ifndef IPAD_ERRORS_H
#define IPAD_ERRORS_H

typedef enum {
    IPAD_OK = 0,
    IPAD_ERR_BAD_REQUEST = 1000,
    IPAD_ERR_INVALID_PARAMS = 1001,
    IPAD_ERR_METHOD_NOT_FOUND = 1002,
    IPAD_ERR_WORKER_UNAVAILABLE = 2000,
    IPAD_ERR_WORKER_CRASHED = 2001,
    IPAD_ERR_WORKER_TIMEOUT = 2002,
    IPAD_ERR_SDK_NOT_INITIALIZED = 3000,
    IPAD_ERR_SDK_FAILED = 3001,
    IPAD_ERR_DEVICE_UNAVAILABLE = 4000,
    IPAD_ERR_TASK_NOT_FOUND = 5000,
    IPAD_ERR_INTERNAL = 9000
} ipad_error_t;

const char *ipad_error_to_string(ipad_error_t error);

#endif
```

- [ ] **Step 4: Define JSON helper header**

Create `common/ipad_json.h`:

```c
#ifndef IPAD_JSON_H
#define IPAD_JSON_H

#include <stddef.h>
#include "ipad_errors.h"

int ipad_json_get_string(const char *json, const char *key, char *out, size_t out_size);
int ipad_json_get_int(const char *json, const char *key, int *out);
int ipad_json_write_error(char *out, size_t out_size, int id, ipad_error_t error, const char *message);
int ipad_json_write_result(char *out, size_t out_size, int id, const char *result_json);

#endif
```

- [ ] **Step 5: Implement minimal JSON helpers**

Create `common/ipad_json.c`:

```c
#include "ipad_json.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *ipad_error_to_string(ipad_error_t error) {
    switch (error) {
        case IPAD_OK: return "ok";
        case IPAD_ERR_BAD_REQUEST: return "bad_request";
        case IPAD_ERR_INVALID_PARAMS: return "invalid_params";
        case IPAD_ERR_METHOD_NOT_FOUND: return "method_not_found";
        case IPAD_ERR_WORKER_UNAVAILABLE: return "worker_unavailable";
        case IPAD_ERR_WORKER_CRASHED: return "worker_crashed";
        case IPAD_ERR_WORKER_TIMEOUT: return "worker_timeout";
        case IPAD_ERR_SDK_NOT_INITIALIZED: return "sdk_not_initialized";
        case IPAD_ERR_SDK_FAILED: return "sdk_failed";
        case IPAD_ERR_DEVICE_UNAVAILABLE: return "device_unavailable";
        case IPAD_ERR_TASK_NOT_FOUND: return "task_not_found";
        default: return "internal_error";
    }
}

int ipad_json_get_string(const char *json, const char *key, char *out, size_t out_size) {
    if (!json || !key || !out || out_size == 0) return -1;
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *pos = strstr(json, pattern);
    if (!pos) return -1;
    const char *colon = strchr(pos, ':');
    if (!colon) return -1;
    const char *start = colon + 1;
    while (*start == ' ' || *start == '\t') start++;
    if (*start != '"') return -1;
    start++;
    const char *end = strchr(start, '"');
    if (!end) return -1;
    size_t len = (size_t)(end - start);
    if (len >= out_size) len = out_size - 1;
    memcpy(out, start, len);
    out[len] = '\0';
    return 0;
}

int ipad_json_get_int(const char *json, const char *key, int *out) {
    if (!json || !key || !out) return -1;
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *pos = strstr(json, pattern);
    if (!pos) return -1;
    const char *colon = strchr(pos, ':');
    if (!colon) return -1;
    *out = atoi(colon + 1);
    return 0;
}

int ipad_json_write_error(char *out, size_t out_size, int id, ipad_error_t error, const char *message) {
    if (!out || out_size == 0) return -1;
    int written = snprintf(out, out_size,
        "{\"jsonrpc\":\"2.0\",\"id\":%d,\"error\":{\"code\":%d,\"name\":\"%s\",\"message\":\"%s\"}}\n",
        id, (int)error, ipad_error_to_string(error), message ? message : ipad_error_to_string(error));
    return written > 0 && (size_t)written < out_size ? 0 : -1;
}

int ipad_json_write_result(char *out, size_t out_size, int id, const char *result_json) {
    if (!out || out_size == 0 || !result_json) return -1;
    int written = snprintf(out, out_size,
        "{\"jsonrpc\":\"2.0\",\"id\":%d,\"result\":%s}\n",
        id, result_json);
    return written > 0 && (size_t)written < out_size ? 0 : -1;
}
```

- [ ] **Step 6: Add unit tests**

Create `tests/CMakeLists.txt`:

```cmake
add_subdirectory(common)
```

Create `tests/common/CMakeLists.txt`:

```cmake
add_executable(test_ipad_json test_ipad_json.c)
target_link_libraries(test_ipad_json PRIVATE ipad_common)
add_test(NAME test_ipad_json COMMAND test_ipad_json)
```

Create `tests/common/test_ipad_json.c`:

```c
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
```

- [ ] **Step 7: Run tests**

Run:

```bash
cmake -S . -B build-manager -DIPAD_BUILD_TESTS=ON
cmake --build build-manager --parallel
ctest --test-dir build-manager --output-on-failure
```

Expected: `100% tests passed`.

- [ ] **Step 8: Commit**

```bash
git add CMakeLists.txt common tests
git commit -m "feat: add common protocol helpers"
```

---

### Task 2: Daemon Socket Server Skeleton

**Files:**
- Create: `ipad_managerd/CMakeLists.txt`
- Create: `ipad_managerd/managerd_main.c`
- Create: `ipad_managerd/rpc_server.h`
- Create: `ipad_managerd/rpc_server.c`
- Create: `tests/managerd/test_rpc_server.c`
- Modify: `CMakeLists.txt`
- Modify: `tests/CMakeLists.txt`

**Interfaces:**
- Consumes: `ipad_json_get_string()`, `ipad_json_get_int()`, `ipad_json_write_result()`, `ipad_json_write_error()`
- Produces: `int rpc_handle_request(const char *request, char *response, size_t response_size)`

- [ ] **Step 1: Register daemon target**

Modify root `CMakeLists.txt`:

```cmake
add_subdirectory(common)
add_subdirectory(ipad_managerd)
```

Create `ipad_managerd/CMakeLists.txt`:

```cmake
add_executable(ipad-managerd
    managerd_main.c
    rpc_server.c
)

target_link_libraries(ipad-managerd PRIVATE ipad_common)
target_compile_options(ipad-managerd PRIVATE -Wall -Wextra -Werror)
```

- [ ] **Step 2: Add request dispatcher header**

Create `ipad_managerd/rpc_server.h`:

```c
#ifndef RPC_SERVER_H
#define RPC_SERVER_H

#include <stddef.h>

int rpc_handle_request(const char *request, char *response, size_t response_size);

#endif
```

- [ ] **Step 3: Add failing dispatcher tests**

Create `tests/managerd/CMakeLists.txt`:

```cmake
add_executable(test_rpc_server test_rpc_server.c)
target_link_libraries(test_rpc_server PRIVATE ipad_managerd_testlib ipad_common)
add_test(NAME test_rpc_server COMMAND test_rpc_server)
```

Modify `ipad_managerd/CMakeLists.txt` to expose a test library:

```cmake
add_library(ipad_managerd_testlib STATIC rpc_server.c)
target_link_libraries(ipad_managerd_testlib PUBLIC ipad_common)
target_include_directories(ipad_managerd_testlib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(ipad_managerd_testlib PRIVATE -Wall -Wextra -Werror)
```

Modify `tests/CMakeLists.txt`:

```cmake
add_subdirectory(common)
add_subdirectory(managerd)
```

Create `tests/managerd/test_rpc_server.c`:

```c
#include "rpc_server.h"
#include <stdio.h>
#include <string.h>

static int require_contains(const char *text, const char *needle) {
    if (!strstr(text, needle)) {
        fprintf(stderr, "missing '%s' in '%s'\n", needle, text);
        return 1;
    }
    return 0;
}

int main(void) {
    char response[512];

    if (rpc_handle_request("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"system.status\"}", response, sizeof(response)) != 0) return 1;
    if (require_contains(response, "\"daemon\":\"running\"")) return 1;

    if (rpc_handle_request("{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"unknown.method\"}", response, sizeof(response)) != 0) return 1;
    if (require_contains(response, "method_not_found")) return 1;

    return 0;
}
```

- [ ] **Step 4: Implement dispatcher**

Create `ipad_managerd/rpc_server.c`:

```c
#include "rpc_server.h"
#include "ipad_json.h"
#include <string.h>

int rpc_handle_request(const char *request, char *response, size_t response_size) {
    char method[96];
    int id = 0;

    if (ipad_json_get_int(request, "id", &id) != 0) {
        id = 0;
    }
    if (ipad_json_get_string(request, "method", method, sizeof(method)) != 0) {
        return ipad_json_write_error(response, response_size, id, IPAD_ERR_BAD_REQUEST, "missing method");
    }
    if (strcmp(method, "system.status") == 0) {
        return ipad_json_write_result(response, response_size, id,
            "{\"daemon\":\"running\",\"worker\":\"not_started\"}");
    }

    return ipad_json_write_error(response, response_size, id, IPAD_ERR_METHOD_NOT_FOUND, "unknown method");
}
```

- [ ] **Step 5: Implement daemon executable**

Create `ipad_managerd/managerd_main.c`:

```c
#include "rpc_server.h"
#include <stdio.h>

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;
    char response[512];
    rpc_handle_request("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"system.status\"}", response, sizeof(response));
    fputs(response, stdout);
    return 0;
}
```

- [ ] **Step 6: Run tests**

Run:

```bash
cmake -S . -B build-manager -DIPAD_BUILD_TESTS=ON
cmake --build build-manager --parallel
ctest --test-dir build-manager --output-on-failure
```

Expected: `test_rpc_server` passes.

- [ ] **Step 7: Commit**

```bash
git add CMakeLists.txt ipad_managerd tests
git commit -m "feat: add manager daemon rpc skeleton"
```

---

### Task 3: Worker Supervisor and Mock Worker

**Files:**
- Create: `ipad_managerd/worker_supervisor.h`
- Create: `ipad_managerd/worker_supervisor.c`
- Create: `ipad_worker/CMakeLists.txt`
- Create: `ipad_worker/worker_main.c`
- Create: `tests/managerd/test_worker_supervisor.c`
- Modify: `ipad_managerd/CMakeLists.txt`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: `rpc_handle_request()`
- Produces: `worker_status_t`, `worker_supervisor_init()`, `worker_supervisor_start_mock()`, `worker_supervisor_stop()`, `worker_supervisor_status()`

- [ ] **Step 1: Add worker status interface**

Create `ipad_managerd/worker_supervisor.h`:

```c
#ifndef WORKER_SUPERVISOR_H
#define WORKER_SUPERVISOR_H

typedef enum {
    WORKER_NOT_STARTED = 0,
    WORKER_STARTING = 1,
    WORKER_READY = 2,
    WORKER_BUSY = 3,
    WORKER_CRASHED = 4
} worker_status_t;

typedef struct {
    worker_status_t status;
    int pid;
    int restart_count;
} worker_supervisor_t;

void worker_supervisor_init(worker_supervisor_t *supervisor);
int worker_supervisor_start_mock(worker_supervisor_t *supervisor);
int worker_supervisor_stop(worker_supervisor_t *supervisor);
worker_status_t worker_supervisor_status(worker_supervisor_t *supervisor);
const char *worker_status_to_string(worker_status_t status);

#endif
```

- [ ] **Step 2: Write supervisor tests**

Append to `tests/managerd/CMakeLists.txt`:

```cmake
add_executable(test_worker_supervisor test_worker_supervisor.c)
target_link_libraries(test_worker_supervisor PRIVATE ipad_managerd_testlib ipad_common)
add_test(NAME test_worker_supervisor COMMAND test_worker_supervisor)
```

Create `tests/managerd/test_worker_supervisor.c`:

```c
#include "worker_supervisor.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    worker_supervisor_t supervisor;
    worker_supervisor_init(&supervisor);

    if (worker_supervisor_status(&supervisor) != WORKER_NOT_STARTED) {
        fprintf(stderr, "expected not started\n");
        return 1;
    }
    if (worker_supervisor_start_mock(&supervisor) != 0) {
        fprintf(stderr, "mock worker start failed\n");
        return 1;
    }
    if (worker_supervisor_status(&supervisor) != WORKER_READY) {
        fprintf(stderr, "expected ready\n");
        return 1;
    }
    if (strcmp(worker_status_to_string(WORKER_READY), "ready") != 0) {
        fprintf(stderr, "status string mismatch\n");
        return 1;
    }
    if (worker_supervisor_stop(&supervisor) != 0) {
        fprintf(stderr, "mock worker stop failed\n");
        return 1;
    }
    if (worker_supervisor_status(&supervisor) != WORKER_NOT_STARTED) {
        fprintf(stderr, "expected stopped\n");
        return 1;
    }
    return 0;
}
```

- [ ] **Step 3: Implement supervisor**

Create `ipad_managerd/worker_supervisor.c`:

```c
#include "worker_supervisor.h"
#include <string.h>

void worker_supervisor_init(worker_supervisor_t *supervisor) {
    memset(supervisor, 0, sizeof(*supervisor));
    supervisor->status = WORKER_NOT_STARTED;
    supervisor->pid = -1;
}

int worker_supervisor_start_mock(worker_supervisor_t *supervisor) {
    if (!supervisor) return -1;
    supervisor->status = WORKER_READY;
    supervisor->pid = 1;
    return 0;
}

int worker_supervisor_stop(worker_supervisor_t *supervisor) {
    if (!supervisor) return -1;
    supervisor->status = WORKER_NOT_STARTED;
    supervisor->pid = -1;
    return 0;
}

worker_status_t worker_supervisor_status(worker_supervisor_t *supervisor) {
    return supervisor ? supervisor->status : WORKER_CRASHED;
}

const char *worker_status_to_string(worker_status_t status) {
    switch (status) {
        case WORKER_NOT_STARTED: return "not_started";
        case WORKER_STARTING: return "starting";
        case WORKER_READY: return "ready";
        case WORKER_BUSY: return "busy";
        case WORKER_CRASHED: return "crashed";
        default: return "unknown";
    }
}
```

- [ ] **Step 4: Wire supervisor into daemon RPC**

Modify `ipad_managerd/rpc_server.c`:

```c
#include "worker_supervisor.h"

static worker_supervisor_t g_worker;
static int g_worker_initialized = 0;

static worker_supervisor_t *worker(void) {
    if (!g_worker_initialized) {
        worker_supervisor_init(&g_worker);
        g_worker_initialized = 1;
    }
    return &g_worker;
}
```

Change `system.status` result:

```c
char result[160];
snprintf(result, sizeof(result),
    "{\"daemon\":\"running\",\"worker\":\"%s\"}",
    worker_status_to_string(worker_supervisor_status(worker())));
return ipad_json_write_result(response, response_size, id, result);
```

Add method:

```c
if (strcmp(method, "worker.start_mock") == 0) {
    worker_supervisor_start_mock(worker());
    return ipad_json_write_result(response, response_size, id, "{\"worker\":\"ready\"}");
}
```

- [ ] **Step 5: Add mock worker executable**

Modify root `CMakeLists.txt`:

```cmake
add_subdirectory(ipad_worker)
```

Create `ipad_worker/CMakeLists.txt`:

```cmake
add_executable(ipad-sdk-worker worker_main.c)
target_link_libraries(ipad-sdk-worker PRIVATE ipad_common)
target_compile_options(ipad-sdk-worker PRIVATE -Wall -Wextra -Werror)
```

Create `ipad_worker/worker_main.c`:

```c
#include <stdio.h>

int main(void) {
    puts("{\"event\":\"worker.ready\"}");
    return 0;
}
```

- [ ] **Step 6: Run tests**

Run:

```bash
cmake -S . -B build-manager -DIPAD_BUILD_TESTS=ON
cmake --build build-manager --parallel
ctest --test-dir build-manager --output-on-failure
```

Expected: all common and managerd tests pass.

- [ ] **Step 7: Commit**

```bash
git add CMakeLists.txt ipad_managerd ipad_worker tests
git commit -m "feat: add worker supervisor skeleton"
```

---

### Task 4: Task State Machine and Audit Log

**Files:**
- Create: `ipad_managerd/task_store.h`
- Create: `ipad_managerd/task_store.c`
- Create: `ipad_managerd/audit_log.h`
- Create: `ipad_managerd/audit_log.c`
- Create: `tests/managerd/test_task_store.c`
- Modify: `ipad_managerd/CMakeLists.txt`

**Interfaces:**
- Produces: `task_store_create()`, `task_store_get()`, `task_store_update_state()`, `audit_log_write()`
- Consumes: `ipad_error_t`

- [ ] **Step 1: Define task model**

Create `ipad_managerd/task_store.h`:

```c
#ifndef TASK_STORE_H
#define TASK_STORE_H

#include <stddef.h>
#include <time.h>

typedef enum {
    TASK_CREATED = 0,
    TASK_QUEUED,
    TASK_VALIDATING,
    TASK_WAITING_DEVICE,
    TASK_RUNNING,
    TASK_COMPLETED,
    TASK_FAILED,
    TASK_CANCELLED
} task_state_t;

typedef struct {
    char task_id[40];
    char method[64];
    task_state_t state;
    char stage[64];
    char error_name[64];
    time_t created_at;
    time_t updated_at;
} ipad_task_t;

void task_store_init(void);
int task_store_create(const char *method, ipad_task_t *out);
int task_store_get(const char *task_id, ipad_task_t *out);
int task_store_update_state(const char *task_id, task_state_t state, const char *stage, const char *error_name);
const char *task_state_to_string(task_state_t state);

#endif
```

- [ ] **Step 2: Add task tests**

Append to `tests/managerd/CMakeLists.txt`:

```cmake
add_executable(test_task_store test_task_store.c)
target_link_libraries(test_task_store PRIVATE ipad_managerd_testlib ipad_common)
add_test(NAME test_task_store COMMAND test_task_store)
```

Create `tests/managerd/test_task_store.c`:

```c
#include "task_store.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    ipad_task_t task;
    ipad_task_t loaded;

    task_store_init();
    if (task_store_create("profile.download", &task) != 0) return 1;
    if (strlen(task.task_id) == 0) return 1;
    if (task.state != TASK_CREATED) return 1;
    if (task_store_update_state(task.task_id, TASK_RUNNING, "prepare_download", "") != 0) return 1;
    if (task_store_get(task.task_id, &loaded) != 0) return 1;
    if (loaded.state != TASK_RUNNING) return 1;
    if (strcmp(loaded.stage, "prepare_download") != 0) return 1;
    if (strcmp(task_state_to_string(TASK_COMPLETED), "completed") != 0) return 1;
    return 0;
}
```

- [ ] **Step 3: Implement in-memory task store**

Create `ipad_managerd/task_store.c`:

```c
#include "task_store.h"
#include <stdio.h>
#include <string.h>

#define MAX_TASKS 128

static ipad_task_t g_tasks[MAX_TASKS];
static int g_task_count = 0;
static int g_next_id = 1;

void task_store_init(void) {
    memset(g_tasks, 0, sizeof(g_tasks));
    g_task_count = 0;
    g_next_id = 1;
}

int task_store_create(const char *method, ipad_task_t *out) {
    if (!method || !out || g_task_count >= MAX_TASKS) return -1;
    ipad_task_t *task = &g_tasks[g_task_count++];
    memset(task, 0, sizeof(*task));
    snprintf(task->task_id, sizeof(task->task_id), "task-%06d", g_next_id++);
    snprintf(task->method, sizeof(task->method), "%s", method);
    task->state = TASK_CREATED;
    snprintf(task->stage, sizeof(task->stage), "created");
    task->created_at = time(NULL);
    task->updated_at = task->created_at;
    *out = *task;
    return 0;
}

int task_store_get(const char *task_id, ipad_task_t *out) {
    if (!task_id || !out) return -1;
    for (int i = 0; i < g_task_count; i++) {
        if (strcmp(g_tasks[i].task_id, task_id) == 0) {
            *out = g_tasks[i];
            return 0;
        }
    }
    return -1;
}

int task_store_update_state(const char *task_id, task_state_t state, const char *stage, const char *error_name) {
    if (!task_id) return -1;
    for (int i = 0; i < g_task_count; i++) {
        if (strcmp(g_tasks[i].task_id, task_id) == 0) {
            g_tasks[i].state = state;
            snprintf(g_tasks[i].stage, sizeof(g_tasks[i].stage), "%s", stage ? stage : "");
            snprintf(g_tasks[i].error_name, sizeof(g_tasks[i].error_name), "%s", error_name ? error_name : "");
            g_tasks[i].updated_at = time(NULL);
            return 0;
        }
    }
    return -1;
}

const char *task_state_to_string(task_state_t state) {
    switch (state) {
        case TASK_CREATED: return "created";
        case TASK_QUEUED: return "queued";
        case TASK_VALIDATING: return "validating";
        case TASK_WAITING_DEVICE: return "waiting_device";
        case TASK_RUNNING: return "running";
        case TASK_COMPLETED: return "completed";
        case TASK_FAILED: return "failed";
        case TASK_CANCELLED: return "cancelled";
        default: return "unknown";
    }
}
```

- [ ] **Step 4: Add audit log API**

Create `ipad_managerd/audit_log.h`:

```c
#ifndef AUDIT_LOG_H
#define AUDIT_LOG_H

int audit_log_write(const char *client, const char *method, const char *task_id, const char *result);

#endif
```

Create `ipad_managerd/audit_log.c`:

```c
#include "audit_log.h"
#include <stdio.h>
#include <time.h>

int audit_log_write(const char *client, const char *method, const char *task_id, const char *result) {
    time_t now = time(NULL);
    fprintf(stderr,
        "{\"ts\":%ld,\"component\":\"daemon\",\"client\":\"%s\",\"method\":\"%s\",\"task_id\":\"%s\",\"result\":\"%s\"}\n",
        (long)now,
        client ? client : "local",
        method ? method : "",
        task_id ? task_id : "",
        result ? result : "");
    return 0;
}
```

- [ ] **Step 5: Update CMake**

Modify `ipad_managerd/CMakeLists.txt` library source lists:

```cmake
add_library(ipad_managerd_testlib STATIC
    rpc_server.c
    worker_supervisor.c
    task_store.c
    audit_log.c
)
```

Modify executable source list similarly:

```cmake
add_executable(ipad-managerd
    managerd_main.c
    rpc_server.c
    worker_supervisor.c
    task_store.c
    audit_log.c
)
```

- [ ] **Step 6: Run tests and commit**

Run:

```bash
cmake -S . -B build-manager -DIPAD_BUILD_TESTS=ON
cmake --build build-manager --parallel
ctest --test-dir build-manager --output-on-failure
```

Expected: all tests pass.

Commit:

```bash
git add ipad_managerd tests
git commit -m "feat: add manager task store"
```

---

### Task 5: Profile Task RPC with Mock Execution

**Files:**
- Create: `ipad_managerd/profile_tasks.h`
- Create: `ipad_managerd/profile_tasks.c`
- Create: `tests/managerd/test_profile_tasks.c`
- Modify: `ipad_managerd/rpc_server.c`
- Modify: `ipad_managerd/CMakeLists.txt`

**Interfaces:**
- Consumes: `task_store_create()`, `task_store_update_state()`, `worker_supervisor_status()`
- Produces: `profile_task_start_download()`, `profile_task_start_enable()`, `profile_task_start_disable()`, `profile_task_start_delete()`

- [ ] **Step 1: Define profile task API**

Create `ipad_managerd/profile_tasks.h`:

```c
#ifndef PROFILE_TASKS_H
#define PROFILE_TASKS_H

#include "task_store.h"
#include "ipad_errors.h"

ipad_error_t profile_task_start_download(const char *smdp, const char *matching_id, ipad_task_t *out);
ipad_error_t profile_task_start_enable(const char *iccid, ipad_task_t *out);
ipad_error_t profile_task_start_disable(const char *iccid, ipad_task_t *out);
ipad_error_t profile_task_start_delete(const char *iccid, ipad_task_t *out);

#endif
```

- [ ] **Step 2: Add tests**

Append to `tests/managerd/CMakeLists.txt`:

```cmake
add_executable(test_profile_tasks test_profile_tasks.c)
target_link_libraries(test_profile_tasks PRIVATE ipad_managerd_testlib ipad_common)
add_test(NAME test_profile_tasks COMMAND test_profile_tasks)
```

Create `tests/managerd/test_profile_tasks.c`:

```c
#include "profile_tasks.h"
#include <stdio.h>
#include <string.h>

int main(void) {
    ipad_task_t task;
    task_store_init();

    if (profile_task_start_download("smdp.example.com", "ABCD", &task) != IPAD_OK) return 1;
    if (strcmp(task.method, "profile.download") != 0) return 1;
    if (task.state != TASK_COMPLETED) return 1;

    if (profile_task_start_enable("89860123456789012345", &task) != IPAD_OK) return 1;
    if (strcmp(task.method, "profile.enable") != 0) return 1;
    if (task.state != TASK_COMPLETED) return 1;

    if (profile_task_start_delete("", &task) != IPAD_ERR_INVALID_PARAMS) return 1;
    return 0;
}
```

- [ ] **Step 3: Implement mock profile tasks**

Create `ipad_managerd/profile_tasks.c`:

```c
#include "profile_tasks.h"
#include <string.h>

static ipad_error_t complete_mock_task(const char *method, ipad_task_t *out) {
    if (task_store_create(method, out) != 0) return IPAD_ERR_INTERNAL;
    task_store_update_state(out->task_id, TASK_RUNNING, "mock_worker_execute", "");
    task_store_update_state(out->task_id, TASK_COMPLETED, "completed", "");
    task_store_get(out->task_id, out);
    return IPAD_OK;
}

ipad_error_t profile_task_start_download(const char *smdp, const char *matching_id, ipad_task_t *out) {
    if (!smdp || smdp[0] == '\0' || !matching_id || matching_id[0] == '\0' || !out) return IPAD_ERR_INVALID_PARAMS;
    return complete_mock_task("profile.download", out);
}

ipad_error_t profile_task_start_enable(const char *iccid, ipad_task_t *out) {
    if (!iccid || iccid[0] == '\0' || !out) return IPAD_ERR_INVALID_PARAMS;
    return complete_mock_task("profile.enable", out);
}

ipad_error_t profile_task_start_disable(const char *iccid, ipad_task_t *out) {
    if (!iccid || iccid[0] == '\0' || !out) return IPAD_ERR_INVALID_PARAMS;
    return complete_mock_task("profile.disable", out);
}

ipad_error_t profile_task_start_delete(const char *iccid, ipad_task_t *out) {
    if (!iccid || iccid[0] == '\0' || !out) return IPAD_ERR_INVALID_PARAMS;
    return complete_mock_task("profile.delete", out);
}
```

- [ ] **Step 4: Expose `profile.download` in RPC**

Modify `ipad_managerd/rpc_server.c`:

```c
#include "profile_tasks.h"
```

Add before method-not-found:

```c
if (strcmp(method, "profile.download") == 0) {
    char smdp[128];
    char matching_id[128];
    ipad_task_t task;
    ipad_error_t err;
    if (ipad_json_get_string(request, "smdp", smdp, sizeof(smdp)) != 0 ||
        ipad_json_get_string(request, "matching_id", matching_id, sizeof(matching_id)) != 0) {
        return ipad_json_write_error(response, response_size, id, IPAD_ERR_INVALID_PARAMS, "missing smdp or matching_id");
    }
    err = profile_task_start_download(smdp, matching_id, &task);
    if (err != IPAD_OK) {
        return ipad_json_write_error(response, response_size, id, err, ipad_error_to_string(err));
    }
    char result[192];
    snprintf(result, sizeof(result), "{\"task_id\":\"%s\",\"state\":\"%s\"}",
        task.task_id, task_state_to_string(task.state));
    return ipad_json_write_result(response, response_size, id, result);
}
```

- [ ] **Step 5: Update CMake, run tests, commit**

Add `profile_tasks.c` to daemon executable and test library sources.

Run:

```bash
cmake -S . -B build-manager -DIPAD_BUILD_TESTS=ON
cmake --build build-manager --parallel
ctest --test-dir build-manager --output-on-failure
```

Expected: `test_profile_tasks` and `test_rpc_server` pass.

Commit:

```bash
git add ipad_managerd tests
git commit -m "feat: add mock profile task flow"
```

---

### Task 6: CLI Client for Status and Profile Download

**Files:**
- Create: `ipadctl/CMakeLists.txt`
- Create: `ipadctl/ipadctl_main.c`
- Modify: `CMakeLists.txt`

**Interfaces:**
- Consumes: daemon JSON-RPC methods `system.status`, `profile.download`
- Produces: executable `ipadctl`

- [ ] **Step 1: Register CLI target**

Modify root `CMakeLists.txt`:

```cmake
add_subdirectory(ipadctl)
```

Create `ipadctl/CMakeLists.txt`:

```cmake
add_executable(ipadctl ipadctl_main.c)
target_link_libraries(ipadctl PRIVATE ipad_common)
target_compile_options(ipadctl PRIVATE -Wall -Wextra -Werror)
```

- [ ] **Step 2: Implement initial CLI argument handling**

Create `ipadctl/ipadctl_main.c`:

```c
#include <stdio.h>
#include <string.h>

static void usage(const char *argv0) {
    printf("Usage:\n");
    printf("  %s status\n", argv0);
    printf("  %s profile download --smdp <fqdn> --matching-id <id>\n", argv0);
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "status") == 0) {
        puts("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"system.status\"}");
        return 0;
    }
    if (argc == 7 &&
        strcmp(argv[1], "profile") == 0 &&
        strcmp(argv[2], "download") == 0 &&
        strcmp(argv[3], "--smdp") == 0 &&
        strcmp(argv[5], "--matching-id") == 0) {
        printf("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"profile.download\",\"smdp\":\"%s\",\"matching_id\":\"%s\"}\n",
            argv[4], argv[6]);
        return 0;
    }
    usage(argv[0]);
    return 2;
}
```

- [ ] **Step 3: Build and smoke test**

Run:

```bash
cmake -S . -B build-manager -DIPAD_BUILD_TESTS=ON
cmake --build build-manager --parallel
./build-manager/ipadctl/ipadctl status
./build-manager/ipadctl/ipadctl profile download --smdp smdp.example.com --matching-id ABCD
```

Expected output includes JSON-RPC request lines with `system.status` and `profile.download`.

- [ ] **Step 4: Commit**

```bash
git add CMakeLists.txt ipadctl
git commit -m "feat: add ipadctl command skeleton"
```

---

### Task 7: SDK Worker Adapter Boundary

**Files:**
- Create: `ipad_worker/sdk_adapter.h`
- Create: `ipad_worker/sdk_adapter.c`
- Create: `tests/worker/test_sdk_adapter_mock.c`
- Modify: `ipad_worker/CMakeLists.txt`
- Modify: `tests/CMakeLists.txt`

**Interfaces:**
- Produces: `sdk_adapter_init()`, `sdk_adapter_profile_download()`, `sdk_adapter_profile_enable()`, `sdk_adapter_profile_disable()`, `sdk_adapter_profile_delete()`
- Consumes: existing IPAd SDK headers when mock mode is disabled

- [ ] **Step 1: Define adapter API**

Create `ipad_worker/sdk_adapter.h`:

```c
#ifndef SDK_ADAPTER_H
#define SDK_ADAPTER_H

#include "ipad_errors.h"

typedef struct {
    int initialized;
    char transport[32];
} sdk_adapter_t;

void sdk_adapter_init_context(sdk_adapter_t *adapter);
ipad_error_t sdk_adapter_init(sdk_adapter_t *adapter, const char *transport);
ipad_error_t sdk_adapter_profile_download(sdk_adapter_t *adapter, const char *smdp, const char *matching_id);
ipad_error_t sdk_adapter_profile_enable(sdk_adapter_t *adapter, const char *iccid);
ipad_error_t sdk_adapter_profile_disable(sdk_adapter_t *adapter, const char *iccid);
ipad_error_t sdk_adapter_profile_delete(sdk_adapter_t *adapter, const char *iccid);

#endif
```

- [ ] **Step 2: Implement mock adapter**

Create `ipad_worker/sdk_adapter.c`:

```c
#include "sdk_adapter.h"
#include <string.h>

void sdk_adapter_init_context(sdk_adapter_t *adapter) {
    memset(adapter, 0, sizeof(*adapter));
}

ipad_error_t sdk_adapter_init(sdk_adapter_t *adapter, const char *transport) {
    if (!adapter || !transport || transport[0] == '\0') return IPAD_ERR_INVALID_PARAMS;
    adapter->initialized = 1;
    snprintf(adapter->transport, sizeof(adapter->transport), "%s", transport);
    return IPAD_OK;
}

static ipad_error_t require_ready(sdk_adapter_t *adapter) {
    return adapter && adapter->initialized ? IPAD_OK : IPAD_ERR_SDK_NOT_INITIALIZED;
}

ipad_error_t sdk_adapter_profile_download(sdk_adapter_t *adapter, const char *smdp, const char *matching_id) {
    if (require_ready(adapter) != IPAD_OK) return IPAD_ERR_SDK_NOT_INITIALIZED;
    if (!smdp || smdp[0] == '\0' || !matching_id || matching_id[0] == '\0') return IPAD_ERR_INVALID_PARAMS;
    return IPAD_OK;
}

ipad_error_t sdk_adapter_profile_enable(sdk_adapter_t *adapter, const char *iccid) {
    if (require_ready(adapter) != IPAD_OK) return IPAD_ERR_SDK_NOT_INITIALIZED;
    return iccid && iccid[0] ? IPAD_OK : IPAD_ERR_INVALID_PARAMS;
}

ipad_error_t sdk_adapter_profile_disable(sdk_adapter_t *adapter, const char *iccid) {
    if (require_ready(adapter) != IPAD_OK) return IPAD_ERR_SDK_NOT_INITIALIZED;
    return iccid && iccid[0] ? IPAD_OK : IPAD_ERR_INVALID_PARAMS;
}

ipad_error_t sdk_adapter_profile_delete(sdk_adapter_t *adapter, const char *iccid) {
    if (require_ready(adapter) != IPAD_OK) return IPAD_ERR_SDK_NOT_INITIALIZED;
    return iccid && iccid[0] ? IPAD_OK : IPAD_ERR_INVALID_PARAMS;
}
```

- [ ] **Step 3: Add worker adapter tests**

Create `tests/worker/CMakeLists.txt`:

```cmake
add_executable(test_sdk_adapter_mock test_sdk_adapter_mock.c)
target_link_libraries(test_sdk_adapter_mock PRIVATE ipad_worker_testlib ipad_common)
add_test(NAME test_sdk_adapter_mock COMMAND test_sdk_adapter_mock)
```

Modify `tests/CMakeLists.txt`:

```cmake
add_subdirectory(worker)
```

Modify `ipad_worker/CMakeLists.txt`:

```cmake
add_library(ipad_worker_testlib STATIC sdk_adapter.c)
target_include_directories(ipad_worker_testlib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(ipad_worker_testlib PUBLIC ipad_common)
target_compile_options(ipad_worker_testlib PRIVATE -Wall -Wextra -Werror)
```

Create `tests/worker/test_sdk_adapter_mock.c`:

```c
#include "sdk_adapter.h"
#include <stdio.h>

int main(void) {
    sdk_adapter_t adapter;
    sdk_adapter_init_context(&adapter);

    if (sdk_adapter_profile_enable(&adapter, "89860123456789012345") != IPAD_ERR_SDK_NOT_INITIALIZED) return 1;
    if (sdk_adapter_init(&adapter, "at_serial") != IPAD_OK) return 1;
    if (sdk_adapter_profile_download(&adapter, "smdp.example.com", "ABCD") != IPAD_OK) return 1;
    if (sdk_adapter_profile_enable(&adapter, "89860123456789012345") != IPAD_OK) return 1;
    if (sdk_adapter_profile_disable(&adapter, "89860123456789012345") != IPAD_OK) return 1;
    if (sdk_adapter_profile_delete(&adapter, "89860123456789012345") != IPAD_OK) return 1;
    return 0;
}
```

- [ ] **Step 4: Run tests and commit**

Run:

```bash
cmake -S . -B build-manager -DIPAD_BUILD_TESTS=ON
cmake --build build-manager --parallel
ctest --test-dir build-manager --output-on-failure
```

Expected: adapter tests pass.

Commit:

```bash
git add ipad_worker tests
git commit -m "feat: add sdk worker adapter boundary"
```

---

### Task 8: GitHub Actions for Manager Components

**Files:**
- Modify: `.github/workflows/ubuntu-build.yml`

**Interfaces:**
- Consumes: top-level `CMakeLists.txt`
- Produces: CI build coverage for daemon, worker, CLI, and tests

- [ ] **Step 1: Add manager build to workflow**

Add after dependency installation:

```yaml
      - name: Configure manager components
        run: cmake -S . -B build-manager -DIPAD_BUILD_TESTS=ON

      - name: Build manager components
        run: cmake --build build-manager --parallel

      - name: Run manager tests
        run: ctest --test-dir build-manager --output-on-failure
```

- [ ] **Step 2: Keep existing SDK/host build steps**

Verify these existing workflow steps remain after manager tests:

```yaml
      - name: Configure SDK
      - name: Build SDK
      - name: Prepare SDK dist
      - name: Configure host app
      - name: Build host app
```

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/ubuntu-build.yml
git commit -m "ci: build manager daemon components"
```

---

### Task 9: GUI RPC Client Hook

**Files:**
- Create: `ipad_host_app/include/manager_rpc_client.h`
- Create: `ipad_host_app/src/utils/manager_rpc_client.c`
- Modify: `ipad_host_app/CMakeLists.txt`
- Modify: `ipad_host_app/src/gui/gui_main.c`

**Interfaces:**
- Produces: `manager_rpc_call()`
- Consumes: daemon JSON-RPC methods

- [ ] **Step 1: Add RPC client header**

Create `ipad_host_app/include/manager_rpc_client.h`:

```c
#ifndef MANAGER_RPC_CLIENT_H
#define MANAGER_RPC_CLIENT_H

#include <stddef.h>

int manager_rpc_call(const char *socket_path, const char *request, char *response, size_t response_size);

#endif
```

- [ ] **Step 2: Implement offline response client**

Create `ipad_host_app/src/utils/manager_rpc_client.c`:

```c
#include "manager_rpc_client.h"
#include <stdio.h>

int manager_rpc_call(const char *socket_path, const char *request, char *response, size_t response_size) {
    (void)socket_path;
    (void)request;
    if (!response || response_size == 0) return -1;
    snprintf(response, response_size, "{\"jsonrpc\":\"2.0\",\"result\":{\"daemon\":\"unavailable_offline\"}}\n");
    return 0;
}
```

- [ ] **Step 3: Add source to host app CMake**

Add to `SOURCES` in `ipad_host_app/CMakeLists.txt`:

```cmake
src/utils/manager_rpc_client.c
```

- [ ] **Step 4: Add GUI log line on startup**

In `gui_main_create_window()` after initial state setup:

```c
window->manager_socket_path = "/run/ipad-manager/ipad-manager.sock";
```

Add this field to `main_window_t` in `ipad_host_app/src/gui/gui_main.h`:

```c
const char *manager_socket_path;
```

- [ ] **Step 5: Build existing host app**

Run:

```bash
cmake -S ipad_host_app -B ipad_host_app/build -DCMAKE_BUILD_TYPE=Release -DIPAD_SDK_ROOT="$(pwd)/ipa_sdk_pc"
cmake --build ipad_host_app/build --parallel
```

Expected: existing host app still builds.

- [ ] **Step 6: Commit**

```bash
git add ipad_host_app
git commit -m "feat: add gui manager rpc client hook"
```

---

### Task 10: Packaging and Deployment Skeleton

**Files:**
- Create: `packaging/systemd/ipad-managerd.service`
- Create: `packaging/tmpfiles/ipad-manager.conf`
- Create: `packaging/README.md`
- Modify: `.github/workflows/ubuntu-build.yml`

**Interfaces:**
- Consumes: `ipad-managerd`, `ipad-sdk-worker`
- Produces: systemd deployment artifacts

- [ ] **Step 1: Add systemd service**

Create `packaging/systemd/ipad-managerd.service`:

```ini
[Unit]
Description=IPAd Manager daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ipad
Group=ipad
RuntimeDirectory=ipad-manager
StateDirectory=ipad-manager
LogsDirectory=ipad-manager
ExecStart=/usr/local/bin/ipad-managerd --config /etc/ipad-manager/config.json
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 2: Add tmpfiles policy**

Create `packaging/tmpfiles/ipad-manager.conf`:

```text
d /run/ipad-manager 0770 ipad ipad -
d /var/lib/ipad-manager 0750 ipad ipad -
d /var/log/ipad-manager 0750 ipad ipad -
```

- [ ] **Step 3: Add packaging README**

Create `packaging/README.md`:

```markdown
# IPAd Manager Packaging

This directory contains Linux deployment artifacts for the single-device IPAd Manager service.

## Runtime paths

- Socket: `/run/ipad-manager/ipad-manager.sock`
- Config: `/etc/ipad-manager/config.json`
- State: `/var/lib/ipad-manager`
- Logs: `/var/log/ipad-manager`

## Service user

Create an `ipad` user and group, then grant serial or PC/SC permissions through udev rules selected for the target device transport.
```

- [ ] **Step 4: Add CI artifact check**

Add to `.github/workflows/ubuntu-build.yml`:

```yaml
      - name: Check packaging files
        run: |
          test -f packaging/systemd/ipad-managerd.service
          test -f packaging/tmpfiles/ipad-manager.conf
          test -f packaging/README.md
```

- [ ] **Step 5: Commit**

```bash
git add packaging .github/workflows/ubuntu-build.yml
git commit -m "chore: add manager packaging skeleton"
```

---

## Self-Review Notes

Spec coverage:

- Daemon/worker split is covered by Tasks 2, 3, and 7.
- Unix Socket JSON-RPC foundation is covered by Tasks 1, 2, and 6.
- Task state and traceability are covered by Tasks 4 and 5.
- Profile management business flow is covered first with mock execution in Task 5, then SDK adapter boundary in Task 7.
- CLI is covered by Task 6.
- GUI migration begins in Task 9.
- Linux packaging and systemd are covered by Task 10.
- GitHub Actions coverage is covered by Task 8.

This plan's delivery boundary:

- JSON-RPC dispatch, task state, CLI request shape, worker supervision, SDK adapter boundary, packaging skeleton, and GUI client hook are concrete deliverables in this plan.
- Real SDK Profile calls must be implemented behind `sdk_adapter_*` in the worker, never inside daemon code.
- The next implementation plan should start with concrete Unix socket accept/connect, then AT serial or PC/SC transport implementation, then real SDK Profile operation mapping.
