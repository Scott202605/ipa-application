# IPAd Manager IPC, Worker IPC, and SDK Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the next three IPAd Manager stages in order: client-to-daemon Unix Socket JSON-RPC, daemon-to-worker IPC and supervision, then real SDK Profile integration inside the worker.

**Architecture:** `ipad-managerd` becomes the local daemon that owns the external Unix Socket API and task lifecycle. `ipad-sdk-worker` becomes a private child process that receives framed JSON commands from the daemon and owns SDK runtime state. SDK calls remain isolated in the worker; CLI and GUI stay JSON-RPC clients.

**Tech Stack:** C11, CMake 3.22+, Unix Domain Sockets, POSIX process APIs, JSON Lines framing, CTest, Ubuntu 22.04 GitHub Actions, existing IPAd SDK under `ipa_sdk_pc/`.

## Global Constraints

- Build must remain green on Ubuntu 22.04 GitHub Actions after every task.
- Daemon, worker, and CLI must not depend on GTK.
- Daemon and client code must not include IPAd SDK headers.
- SDK headers and real SDK calls stay behind `ipad_worker/sdk_adapter.*` or worker-only files.
- CI must use mock SDK mode by default.
- Real SDK mode must be opt-in and safe to compile on Linux.
- Message size must be bounded by `IPAD_MAX_JSON_MESSAGE`.
- Socket paths used by tests must live under the test build directory or `/tmp`.
- Stale socket cleanup must only unlink existing socket files, never regular files.

---

## File Structure

Create or modify these areas:

- `common/ipad_socket.h`, `common/ipad_socket.c`: Unix Socket connect/listen and JSON Line read/write helpers.
- `common/ipad_json.c`, `common/ipad_json.h`: add boolean and field helpers only when needed by worker messages.
- `ipad_managerd/managerd_main.c`: daemon CLI options, socket serving mode, signal handling.
- `ipad_managerd/rpc_server.c`: route profile calls through worker service after worker IPC lands.
- `ipad_managerd/worker_process.h`, `ipad_managerd/worker_process.c`: child process lifecycle, stdin/stdout IPC, timeouts.
- `ipad_worker/worker_protocol.h`, `ipad_worker/worker_protocol.c`: worker command parsing and response generation.
- `ipad_worker/worker_main.c`: worker loop, runtime mode parsing, stdout protocol discipline.
- `ipad_worker/sdk_adapter.h`, `ipad_worker/sdk_adapter.c`: mock and real SDK mode, SDK init/status/deinit/Profile calls.
- `ipadctl/ipadctl_main.c`: command construction plus socket request/response behavior.
- `tests/common/`: socket framing tests.
- `tests/managerd/`: daemon socket and worker process tests.
- `tests/worker/`: worker protocol and SDK adapter mode tests.
- `.github/workflows/ubuntu-build.yml`: keep manager build/test coverage before SDK and host app builds.
- `docs/real-device-validation.md`: manual hardware validation for real SDK mode.

---

### Task 1: Common Unix Socket and JSON Line Helpers

**Files:**
- Create: `common/ipad_socket.h`
- Create: `common/ipad_socket.c`
- Modify: `common/CMakeLists.txt`
- Create: `tests/common/test_ipad_socket.c`
- Modify: `tests/common/CMakeLists.txt`

**Interfaces:**
- Produces:
  - `int ipad_socket_listen(const char *path, int backlog);`
  - `int ipad_socket_connect(const char *path);`
  - `int ipad_socket_write_line(int fd, const char *message);`
  - `int ipad_socket_read_line(int fd, char *out, size_t out_size);`
  - `int ipad_socket_close(int fd);`
- Consumes: `IPAD_MAX_JSON_MESSAGE`, `IPAD_DEFAULT_SOCKET_PATH`

- [ ] **Step 1: Add the socket helper header**

Create `common/ipad_socket.h`:

```c
#ifndef IPAD_SOCKET_H
#define IPAD_SOCKET_H

#include <stddef.h>

int ipad_socket_listen(const char *path, int backlog);
int ipad_socket_connect(const char *path);
int ipad_socket_write_line(int fd, const char *message);
int ipad_socket_read_line(int fd, char *out, size_t out_size);
int ipad_socket_close(int fd);

#endif
```

- [ ] **Step 2: Implement POSIX Unix Socket helpers**

Create `common/ipad_socket.c` with these behaviors:

```c
#include "ipad_socket.h"

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static int prepare_addr(const char *path, struct sockaddr_un *addr) {
    if (!path || !addr || strlen(path) >= sizeof(addr->sun_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memset(addr, 0, sizeof(*addr));
    addr->sun_family = AF_UNIX;
    snprintf(addr->sun_path, sizeof(addr->sun_path), "%s", path);
    return 0;
}

static int unlink_stale_socket(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) {
        return errno == ENOENT ? 0 : -1;
    }
    if (!S_ISSOCK(st.st_mode)) {
        errno = EEXIST;
        return -1;
    }
    return unlink(path);
}

int ipad_socket_listen(const char *path, int backlog) {
    int fd;
    struct sockaddr_un addr;
    if (prepare_addr(path, &addr) != 0) return -1;
    if (unlink_stale_socket(path) != 0) return -1;
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, backlog) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int ipad_socket_connect(const char *path) {
    int fd;
    struct sockaddr_un addr;
    if (prepare_addr(path, &addr) != 0) return -1;
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int ipad_socket_write_line(int fd, const char *message) {
    size_t len;
    ssize_t written;
    if (fd < 0 || !message) return -1;
    len = strlen(message);
    written = write(fd, message, len);
    if (written < 0 || (size_t)written != len) return -1;
    if (len == 0 || message[len - 1] != '\n') {
        written = write(fd, "\n", 1);
        if (written != 1) return -1;
    }
    return 0;
}

int ipad_socket_read_line(int fd, char *out, size_t out_size) {
    size_t used = 0;
    if (fd < 0 || !out || out_size == 0) return -1;
    while (used + 1 < out_size) {
        char ch;
        ssize_t n = read(fd, &ch, 1);
        if (n == 0) break;
        if (n < 0) return -1;
        out[used++] = ch;
        if (ch == '\n') break;
    }
    out[used] = '\0';
    return used > 0 ? 0 : -1;
}

int ipad_socket_close(int fd) {
    return fd >= 0 ? close(fd) : 0;
}
```

- [ ] **Step 3: Wire the helper into CMake**

Modify `common/CMakeLists.txt`:

```cmake
add_library(ipad_common STATIC
    ipad_json.c
    ipad_socket.c
)
```

- [ ] **Step 4: Add socket unit tests**

Create `tests/common/test_ipad_socket.c`:

```c
#include "ipad_socket.h"

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int require(int condition, const char *message) {
    if (!condition) {
        fprintf(stderr, "%s\n", message);
        return 1;
    }
    return 0;
}

int main(void) {
    int pair[2];
    char buffer[128];
    if (require(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0, "socketpair failed")) return 1;
    if (require(ipad_socket_write_line(pair[0], "{\"ok\":true}") == 0, "write failed")) return 1;
    if (require(ipad_socket_read_line(pair[1], buffer, sizeof(buffer)) == 0, "read failed")) return 1;
    if (require(strcmp(buffer, "{\"ok\":true}\n") == 0, "line mismatch")) return 1;
    close(pair[0]);
    close(pair[1]);
    return 0;
}
```

Modify `tests/common/CMakeLists.txt`:

```cmake
add_executable(test_ipad_socket test_ipad_socket.c)
target_link_libraries(test_ipad_socket PRIVATE ipad_common)
add_test(NAME test_ipad_socket COMMAND test_ipad_socket)
```

- [ ] **Step 5: Verify**

Run:

```bash
cmake -S . -B build-manager -DIPAD_BUILD_TESTS=ON
cmake --build build-manager --parallel
ctest --test-dir build-manager --output-on-failure
```

Expected: all existing tests plus `test_ipad_socket` pass.

- [ ] **Step 6: Commit**

```bash
git add common tests/common
git commit -m "feat: add unix socket helpers"
```

---

### Task 2: Daemon Socket Serving Mode

**Files:**
- Modify: `ipad_managerd/managerd_main.c`
- Modify: `ipad_managerd/CMakeLists.txt`
- Create: `tests/managerd/test_managerd_socket.c`
- Modify: `tests/managerd/CMakeLists.txt`

**Interfaces:**
- Consumes: `rpc_handle_request()`, `ipad_socket_listen()`, `ipad_socket_read_line()`, `ipad_socket_write_line()`
- Produces: `ipad-managerd --socket <path> --once`

- [ ] **Step 1: Refactor daemon main into serve-once helper**

In `ipad_managerd/managerd_main.c`, add:

```c
static int serve_once(int listen_fd) {
    int client_fd;
    char request[IPAD_MAX_JSON_MESSAGE];
    char response[IPAD_MAX_JSON_MESSAGE];

    client_fd = accept(listen_fd, NULL, NULL);
    if (client_fd < 0) return 1;
    if (ipad_socket_read_line(client_fd, request, sizeof(request)) != 0) {
        ipad_socket_close(client_fd);
        return 1;
    }
    if (rpc_handle_request(request, response, sizeof(response)) != 0) {
        ipad_socket_close(client_fd);
        return 1;
    }
    ipad_socket_write_line(client_fd, response);
    ipad_socket_close(client_fd);
    return 0;
}
```

Also include:

```c
#include "ipad_protocol.h"
#include "ipad_socket.h"
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
```

- [ ] **Step 2: Add command-line parsing**

Support:

```c
const char *socket_path = IPAD_DEFAULT_SOCKET_PATH;
bool once = false;

for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--once") == 0) {
        once = true;
    } else if (strcmp(argv[i], "--socket") == 0 && i + 1 < argc) {
        socket_path = argv[++i];
    } else {
        fprintf(stderr, "Usage: %s [--once] [--socket <path>]\n", argv[0]);
        return 2;
    }
}
```

Main should:

```c
int listen_fd = ipad_socket_listen(socket_path, 8);
if (listen_fd < 0) {
    perror("ipad_socket_listen");
    return 1;
}
if (once) {
    int rc = serve_once(listen_fd);
    ipad_socket_close(listen_fd);
    return rc;
}
for (;;) {
    if (serve_once(listen_fd) != 0) {
        break;
    }
}
ipad_socket_close(listen_fd);
return 0;
```

- [ ] **Step 3: Add a daemon socket integration test**

Create `tests/managerd/test_managerd_socket.c`:

```c
#include "ipad_socket.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *managerd_path;
    const char *socket_path;
    pid_t pid;
    int fd;
    char response[512];

    if (argc != 3) return 2;
    managerd_path = argv[1];
    socket_path = argv[2];

    pid = fork();
    if (pid == 0) {
        execl(managerd_path, managerd_path, "--once", "--socket", socket_path, (char *)NULL);
        _exit(127);
    }
    usleep(200000);
    fd = ipad_socket_connect(socket_path);
    if (fd < 0) {
        perror("connect");
        return 1;
    }
    if (ipad_socket_write_line(fd, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"system.status\"}") != 0) return 1;
    if (ipad_socket_read_line(fd, response, sizeof(response)) != 0) return 1;
    ipad_socket_close(fd);
    waitpid(pid, NULL, 0);
    unlink(socket_path);

    if (!strstr(response, "\"daemon\":\"running\"")) {
        fprintf(stderr, "unexpected response: %s\n", response);
        return 1;
    }
    return 0;
}
```

Modify `tests/managerd/CMakeLists.txt`:

```cmake
add_executable(test_managerd_socket test_managerd_socket.c)
target_link_libraries(test_managerd_socket PRIVATE ipad_common)
add_test(NAME test_managerd_socket
  COMMAND test_managerd_socket
    $<TARGET_FILE:ipad-managerd>
    ${CMAKE_CURRENT_BINARY_DIR}/ipad-manager-test.sock)
```

- [ ] **Step 4: Verify**

Run:

```bash
cmake -S . -B build-manager -DIPAD_BUILD_TESTS=ON
cmake --build build-manager --parallel
ctest --test-dir build-manager --output-on-failure
```

Expected: `test_managerd_socket` passes and removes its test socket.

- [ ] **Step 5: Commit**

```bash
git add ipad_managerd tests/managerd
git commit -m "feat: serve daemon json rpc over unix socket"
```

---

### Task 3: CLI Socket Client

**Files:**
- Modify: `ipadctl/ipadctl_main.c`
- Modify: `tests/managerd/test_managerd_socket.c` or create `tests/managerd/test_ipadctl_socket.c`
- Modify: `tests/managerd/CMakeLists.txt`

**Interfaces:**
- Consumes: `ipad_socket_connect()`, `ipad_socket_write_line()`, `ipad_socket_read_line()`
- Produces: `ipadctl --socket <path> status`

- [ ] **Step 1: Add `--socket` parsing before commands**

In `ipadctl/ipadctl_main.c`, add:

```c
const char *socket_path = IPAD_DEFAULT_SOCKET_PATH;
int argi = 1;

if (argc >= 3 && strcmp(argv[argi], "--socket") == 0) {
    socket_path = argv[argi + 1];
    argi += 2;
}
```

Then treat `argv[argi]` as the command root instead of hard-coded `argv[1]`.

- [ ] **Step 2: Split request construction from send**

Add:

```c
static int send_request(const char *socket_path, const char *request) {
    int fd;
    char response[IPAD_MAX_JSON_MESSAGE];
    fd = ipad_socket_connect(socket_path);
    if (fd < 0) {
        fprintf(stderr, "failed to connect to %s\n", socket_path);
        return 1;
    }
    if (ipad_socket_write_line(fd, request) != 0 ||
        ipad_socket_read_line(fd, response, sizeof(response)) != 0) {
        fprintf(stderr, "failed to exchange request with daemon\n");
        ipad_socket_close(fd);
        return 1;
    }
    ipad_socket_close(fd);
    fputs(response, stdout);
    return 0;
}
```

Every command should build a JSON request string and call `send_request()`.

- [ ] **Step 3: Keep offline request generation out of the CLI default path**

Remove the previous behavior where commands only `puts()` request JSON. The normal CLI should now require a daemon socket.

- [ ] **Step 4: Add CLI integration test**

Create `tests/managerd/test_ipadctl_socket.c` similar to `test_managerd_socket.c`, but after starting `ipad-managerd --once`, run:

```c
execl(ipadctl_path, ipadctl_path, "--socket", socket_path, "status", (char *)NULL);
```

The parent should wait for `ipadctl` and assert exit status `0`. Use `fork()` and `waitpid()`.

Modify `tests/managerd/CMakeLists.txt`:

```cmake
add_executable(test_ipadctl_socket test_ipadctl_socket.c)
target_link_libraries(test_ipadctl_socket PRIVATE ipad_common)
add_test(NAME test_ipadctl_socket
  COMMAND test_ipadctl_socket
    $<TARGET_FILE:ipad-managerd>
    $<TARGET_FILE:ipadctl>
    ${CMAKE_CURRENT_BINARY_DIR}/ipadctl-test.sock)
```

- [ ] **Step 5: Verify**

Run:

```bash
cmake -S . -B build-manager -DIPAD_BUILD_TESTS=ON
cmake --build build-manager --parallel
ctest --test-dir build-manager --output-on-failure
```

Expected: `test_ipadctl_socket` passes.

- [ ] **Step 6: Commit**

```bash
git add ipadctl tests/managerd
git commit -m "feat: make ipadctl call daemon socket"
```

---

### Task 4: Worker Protocol Parser and Mock Command Loop

**Files:**
- Create: `ipad_worker/worker_protocol.h`
- Create: `ipad_worker/worker_protocol.c`
- Modify: `ipad_worker/CMakeLists.txt`
- Modify: `ipad_worker/worker_main.c`
- Create: `tests/worker/test_worker_protocol.c`
- Modify: `tests/worker/CMakeLists.txt`

**Interfaces:**
- Produces:
  - `int worker_protocol_handle_line(const char *request, char *response, size_t response_size, sdk_adapter_t *adapter);`
- Consumes: `sdk_adapter_profile_*()`

- [ ] **Step 1: Add worker protocol header**

Create `ipad_worker/worker_protocol.h`:

```c
#ifndef WORKER_PROTOCOL_H
#define WORKER_PROTOCOL_H

#include <stddef.h>
#include "sdk_adapter.h"

int worker_protocol_handle_line(const char *request, char *response, size_t response_size, sdk_adapter_t *adapter);

#endif
```

- [ ] **Step 2: Implement command dispatch**

Create `ipad_worker/worker_protocol.c`:

```c
#include "worker_protocol.h"
#include "ipad_json.h"

#include <stdio.h>
#include <string.h>

static int write_worker_ok(char *response, size_t response_size, int id, const char *task_id) {
    return snprintf(response, response_size,
                    "{\"id\":%d,\"ok\":true,\"task_id\":\"%s\",\"state\":\"completed\"}\n",
                    id, task_id ? task_id : "") > 0 ? 0 : -1;
}

static int write_worker_error(char *response, size_t response_size, int id, const char *task_id, ipad_error_t err) {
    return snprintf(response, response_size,
                    "{\"id\":%d,\"ok\":false,\"task_id\":\"%s\",\"error\":\"%s\"}\n",
                    id, task_id ? task_id : "", ipad_error_to_string(err)) > 0 ? 0 : -1;
}

int worker_protocol_handle_line(const char *request, char *response, size_t response_size, sdk_adapter_t *adapter) {
    int id = 0;
    char op[96];
    char task_id[32];
    char smdp[128];
    char matching_id[128];
    char iccid[64];
    ipad_error_t err = IPAD_ERR_METHOD_NOT_FOUND;

    if (ipad_json_get_int(request, "id", &id) != 0) id = 0;
    if (ipad_json_get_string(request, "task_id", task_id, sizeof(task_id)) != 0) task_id[0] = '\0';
    if (ipad_json_get_string(request, "op", op, sizeof(op)) != 0) {
        return write_worker_error(response, response_size, id, task_id, IPAD_ERR_BAD_REQUEST);
    }
    if (strcmp(op, "profile.download") == 0) {
        if (ipad_json_get_string(request, "smdp", smdp, sizeof(smdp)) != 0 ||
            ipad_json_get_string(request, "matching_id", matching_id, sizeof(matching_id)) != 0) {
            err = IPAD_ERR_INVALID_PARAMS;
        } else {
            err = sdk_adapter_profile_download(adapter, smdp, matching_id);
        }
    } else if (strcmp(op, "profile.enable") == 0) {
        err = ipad_json_get_string(request, "iccid", iccid, sizeof(iccid)) == 0
            ? sdk_adapter_profile_enable(adapter, iccid)
            : IPAD_ERR_INVALID_PARAMS;
    } else if (strcmp(op, "profile.disable") == 0) {
        err = ipad_json_get_string(request, "iccid", iccid, sizeof(iccid)) == 0
            ? sdk_adapter_profile_disable(adapter, iccid)
            : IPAD_ERR_INVALID_PARAMS;
    } else if (strcmp(op, "profile.delete") == 0) {
        err = ipad_json_get_string(request, "iccid", iccid, sizeof(iccid)) == 0
            ? sdk_adapter_profile_delete(adapter, iccid)
            : IPAD_ERR_INVALID_PARAMS;
    }
    return err == IPAD_OK
        ? write_worker_ok(response, response_size, id, task_id)
        : write_worker_error(response, response_size, id, task_id, err);
}
```

- [ ] **Step 3: Update worker main**

Change `ipad_worker/worker_main.c` so it:

1. Initializes `sdk_adapter_t`.
2. Calls `sdk_adapter_init(&adapter, "mock")`.
3. Writes `{"event":"worker.ready","protocol":1,"sdk_mode":"mock"}` to stdout.
4. Reads request lines from stdin.
5. Calls `worker_protocol_handle_line()`.
6. Writes responses to stdout.

- [ ] **Step 4: Update worker CMake**

Add `worker_protocol.c` to `ipad-sdk-worker` and `ipad_worker_testlib`.

- [ ] **Step 5: Add worker protocol tests**

Create `tests/worker/test_worker_protocol.c`:

```c
#include "worker_protocol.h"
#include <string.h>

int main(void) {
    sdk_adapter_t adapter;
    char response[512];
    sdk_adapter_init_context(&adapter);
    if (sdk_adapter_init(&adapter, "mock") != IPAD_OK) return 1;
    if (worker_protocol_handle_line("{\"id\":1,\"op\":\"profile.download\",\"task_id\":\"task-1\",\"smdp\":\"smdp.example.com\",\"matching_id\":\"ABCD\"}", response, sizeof(response), &adapter) != 0) return 1;
    if (!strstr(response, "\"ok\":true")) return 1;
    if (worker_protocol_handle_line("{\"id\":2,\"op\":\"profile.delete\",\"task_id\":\"task-2\",\"iccid\":\"\"}", response, sizeof(response), &adapter) != 0) return 1;
    if (!strstr(response, "\"ok\":false")) return 1;
    return 0;
}
```

Update `tests/worker/CMakeLists.txt`:

```cmake
add_executable(test_worker_protocol test_worker_protocol.c)
target_link_libraries(test_worker_protocol PRIVATE ipad_worker_testlib ipad_common)
add_test(NAME test_worker_protocol COMMAND test_worker_protocol)
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
git add ipad_worker tests/worker
git commit -m "feat: add worker protocol loop"
```

---

### Task 5: Daemon Worker Process IPC

**Files:**
- Create: `ipad_managerd/worker_process.h`
- Create: `ipad_managerd/worker_process.c`
- Modify: `ipad_managerd/CMakeLists.txt`
- Create: `tests/managerd/test_worker_process.c`
- Modify: `tests/managerd/CMakeLists.txt`

**Interfaces:**
- Produces:
  - `int worker_process_start(worker_process_t *process, const char *worker_path);`
  - `int worker_process_call(worker_process_t *process, const char *request, char *response, size_t response_size);`
  - `int worker_process_stop(worker_process_t *process);`
- Consumes: `ipad-sdk-worker` executable

- [ ] **Step 1: Add process interface**

Create `ipad_managerd/worker_process.h`:

```c
#ifndef WORKER_PROCESS_H
#define WORKER_PROCESS_H

#include <stddef.h>
#include <sys/types.h>

typedef struct {
    pid_t pid;
    int stdin_fd;
    int stdout_fd;
    int ready;
} worker_process_t;

void worker_process_init(worker_process_t *process);
int worker_process_start(worker_process_t *process, const char *worker_path);
int worker_process_call(worker_process_t *process, const char *request, char *response, size_t response_size);
int worker_process_stop(worker_process_t *process);

#endif
```

- [ ] **Step 2: Implement fork/exec with pipes**

Create `worker_process.c` using:

- `pipe()`
- `fork()`
- `dup2()`
- `execl(worker_path, worker_path, "--sdk-mode", "mock", NULL)`
- `ipad_socket_read_line()` for the ready event and responses
- `ipad_socket_write_line()` for requests

The ready event must contain `worker.ready`.

- [ ] **Step 3: Add process test**

Create `tests/managerd/test_worker_process.c`:

```c
#include "worker_process.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    worker_process_t process;
    char response[512];
    if (argc != 2) return 2;
    worker_process_init(&process);
    if (worker_process_start(&process, argv[1]) != 0) {
        fprintf(stderr, "worker start failed\n");
        return 1;
    }
    if (worker_process_call(&process, "{\"id\":1,\"op\":\"profile.enable\",\"task_id\":\"task-1\",\"iccid\":\"89860123456789012345\"}", response, sizeof(response)) != 0) return 1;
    worker_process_stop(&process);
    if (!strstr(response, "\"ok\":true")) {
        fprintf(stderr, "unexpected response: %s\n", response);
        return 1;
    }
    return 0;
}
```

Update `tests/managerd/CMakeLists.txt`:

```cmake
add_executable(test_worker_process test_worker_process.c)
target_link_libraries(test_worker_process PRIVATE ipad_managerd_testlib ipad_common)
add_test(NAME test_worker_process COMMAND test_worker_process $<TARGET_FILE:ipad-sdk-worker>)
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
git add ipad_managerd tests/managerd
git commit -m "feat: add daemon worker process ipc"
```

---

### Task 6: Route Profile Tasks Through Worker IPC

**Files:**
- Modify: `ipad_managerd/profile_tasks.h`
- Modify: `ipad_managerd/profile_tasks.c`
- Modify: `ipad_managerd/rpc_server.c`
- Modify: `tests/managerd/test_profile_tasks.c`
- Modify: `tests/managerd/test_rpc_server.c`

**Interfaces:**
- Consumes: `worker_process_call()`
- Produces: profile tasks that execute through worker IPC when a worker path is configured

- [ ] **Step 1: Add worker-backed task helpers**

Add to `profile_tasks.h`:

```c
typedef struct {
    const char *worker_path;
} profile_task_runtime_t;

void profile_task_set_runtime(profile_task_runtime_t runtime);
```

`profile_tasks.c` should store runtime in a static variable.

- [ ] **Step 2: Build worker command JSON in profile task functions**

For download:

```c
snprintf(request, sizeof(request),
         "{\"id\":1,\"op\":\"profile.download\",\"task_id\":\"%s\",\"smdp\":\"%s\",\"matching_id\":\"%s\"}",
         out->task_id, smdp, matching_id);
```

For enable/disable/delete use `iccid`.

- [ ] **Step 3: Keep mock fallback when no worker path is configured**

If `g_runtime.worker_path == NULL`, preserve the current complete-mock-task behavior so unit tests that do not start a worker remain stable.

- [ ] **Step 4: Add worker-backed integration test**

Extend `test_profile_tasks.c` so it receives an optional worker path argument. When provided, call:

```c
profile_task_set_runtime((profile_task_runtime_t){ .worker_path = argv[1] });
```

Then run the existing profile download/enable/delete assertions.

Update CTest:

```cmake
add_test(NAME test_profile_tasks_worker
  COMMAND test_profile_tasks $<TARGET_FILE:ipad-sdk-worker>)
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
git commit -m "feat: route profile tasks through worker"
```

---

### Task 7: SDK Adapter Runtime Modes and SDK Lifecycle

**Files:**
- Modify: `ipad_worker/sdk_adapter.h`
- Modify: `ipad_worker/sdk_adapter.c`
- Modify: `ipad_worker/worker_main.c`
- Modify: `tests/worker/test_sdk_adapter_mock.c`

**Interfaces:**
- Produces:
  - `ipad_error_t sdk_adapter_deinit(sdk_adapter_t *adapter);`
  - `const char *sdk_adapter_mode(const sdk_adapter_t *adapter);`
  - `int sdk_adapter_is_initialized(const sdk_adapter_t *adapter);`
- Consumes: existing mock adapter state

- [ ] **Step 1: Extend adapter struct**

Change `sdk_adapter_t`:

```c
typedef enum {
    SDK_MODE_MOCK = 0,
    SDK_MODE_REAL = 1
} sdk_mode_t;

typedef struct {
    int initialized;
    sdk_mode_t mode;
    char transport[32];
} sdk_adapter_t;
```

- [ ] **Step 2: Update init behavior**

`sdk_adapter_init(adapter, "mock")` sets mock mode and initialized true.

`sdk_adapter_init(adapter, "real")` initially returns `IPAD_ERR_SDK_FAILED` until Task 8 wires compile-time real SDK support.

- [ ] **Step 3: Add lifecycle functions**

Implement:

```c
ipad_error_t sdk_adapter_deinit(sdk_adapter_t *adapter);
const char *sdk_adapter_mode(const sdk_adapter_t *adapter);
int sdk_adapter_is_initialized(const sdk_adapter_t *adapter);
```

- [ ] **Step 4: Parse worker mode**

`ipad-sdk-worker --sdk-mode mock` starts mock mode.

`ipad-sdk-worker --sdk-mode real` attempts real mode and exits non-zero if unavailable.

- [ ] **Step 5: Verify and commit**

Run:

```bash
cmake -S . -B build-manager -DIPAD_BUILD_TESTS=ON
cmake --build build-manager --parallel
ctest --test-dir build-manager --output-on-failure
```

Commit:

```bash
git add ipad_worker tests/worker
git commit -m "feat: add sdk adapter runtime modes"
```

---

### Task 8: Real SDK Compile Path and Error Mapping

**Files:**
- Modify: `ipad_worker/CMakeLists.txt`
- Modify: `ipad_worker/sdk_adapter.c`
- Modify: `ipad_worker/sdk_adapter.h`
- Modify: `tests/worker/CMakeLists.txt`
- Create: `tests/worker/test_sdk_error_mapping.c`

**Interfaces:**
- Consumes: `ipa_sdk_pc/include/ipa_core.h`, `ipa_sdk_pc/include/ipa.h`, `ipa_sdk_pc/include/typedefs.h`
- Produces:
  - `ipad_error_t sdk_adapter_map_errcode(int sdk_error);`
  - real SDK mode compile path guarded by `IPAD_WORKER_ENABLE_REAL_SDK`

- [ ] **Step 1: Add CMake option**

In `ipad_worker/CMakeLists.txt`:

```cmake
option(IPAD_WORKER_ENABLE_REAL_SDK "Compile worker real SDK adapter path" ON)

if(IPAD_WORKER_ENABLE_REAL_SDK)
  target_compile_definitions(ipad_worker_testlib PUBLIC IPAD_WORKER_ENABLE_REAL_SDK=1)
  target_compile_definitions(ipad-sdk-worker PRIVATE IPAD_WORKER_ENABLE_REAL_SDK=1)
  target_include_directories(ipad_worker_testlib PUBLIC ${PROJECT_SOURCE_DIR}/ipa_sdk_pc/include)
  target_include_directories(ipad-sdk-worker PRIVATE ${PROJECT_SOURCE_DIR}/ipa_sdk_pc/include)
endif()
```

Do not link `libipa` in this task. This task only ensures headers and mapping compile.

- [ ] **Step 2: Implement error mapping**

In `sdk_adapter.c`:

```c
#ifdef IPAD_WORKER_ENABLE_REAL_SDK
#include "typedefs.h"
#endif

ipad_error_t sdk_adapter_map_errcode(int sdk_error) {
#ifdef IPAD_WORKER_ENABLE_REAL_SDK
    switch (sdk_error) {
        case eOk: return IPAD_OK;
        case eBadArg: return IPAD_ERR_INVALID_PARAMS;
        case eNoMem: return IPAD_ERR_INTERNAL;
        case eFatal: return IPAD_ERR_SDK_FAILED;
        default: return IPAD_ERR_SDK_FAILED;
    }
#else
    return sdk_error == 0 ? IPAD_OK : IPAD_ERR_SDK_FAILED;
#endif
}
```

- [ ] **Step 3: Add mapping test**

Create `tests/worker/test_sdk_error_mapping.c`:

```c
#include "sdk_adapter.h"

int main(void) {
    if (sdk_adapter_map_errcode(0) != IPAD_OK) return 1;
    if (sdk_adapter_map_errcode(4) != IPAD_ERR_INVALID_PARAMS) return 1;
    if (sdk_adapter_map_errcode(1) != IPAD_ERR_SDK_FAILED) return 1;
    return 0;
}
```

Update `tests/worker/CMakeLists.txt`:

```cmake
add_executable(test_sdk_error_mapping test_sdk_error_mapping.c)
target_link_libraries(test_sdk_error_mapping PRIVATE ipad_worker_testlib ipad_common)
add_test(NAME test_sdk_error_mapping COMMAND test_sdk_error_mapping)
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
git add ipad_worker tests/worker
git commit -m "feat: add real sdk compile path"
```

---

### Task 9: Real SDK Init and Profile Download Adapter

**Files:**
- Modify: `ipad_worker/CMakeLists.txt`
- Modify: `ipad_worker/sdk_adapter.c`
- Modify: `ipad_worker/sdk_adapter.h`
- Create: `docs/real-device-validation.md`

**Interfaces:**
- Consumes:
  - `ipa_init_library(cl_config_t *config, ipa_event_cb_t event_cb)`
  - `ipa_deinit_library(void)`
  - `ipa__profile_download_trigger(...)`
- Produces: real-mode init/deinit and direct download adapter path

- [ ] **Step 1: Link the worker to SDK library when real SDK mode is enabled**

Use the same SDK library locations as `ipad_host_app/CMakeLists.txt`:

```cmake
find_library(IPA_LIBRARY
    NAMES ipa
    PATHS
        "${PROJECT_SOURCE_DIR}/ipa_sdk_pc/build/ipa-src/hw/linux"
        "${PROJECT_SOURCE_DIR}/ipa_sdk_pc/dist/lib"
)

if(IPAD_WORKER_ENABLE_REAL_SDK AND IPA_LIBRARY)
  target_link_libraries(ipad-sdk-worker PRIVATE ${IPA_LIBRARY})
  target_link_libraries(ipad_worker_testlib PUBLIC ${IPA_LIBRARY})
endif()
```

If `IPA_LIBRARY` is not found during manager-only configure, CMake must continue and build mock mode.

- [ ] **Step 2: Add real init implementation**

In `sdk_adapter_init()`:

```c
if (strcmp(transport, "real") == 0) {
#ifdef IPAD_WORKER_ENABLE_REAL_SDK
    cl_config_t config = {0};
    int rc = ipa_init_library(&config, NULL);
    ipad_error_t mapped = sdk_adapter_map_errcode(rc);
    if (mapped != IPAD_OK) return mapped;
    adapter->mode = SDK_MODE_REAL;
    adapter->initialized = 1;
    snprintf(adapter->transport, sizeof(adapter->transport), "%s", "real");
    return IPAD_OK;
#else
    return IPAD_ERR_SDK_FAILED;
#endif
}
```

- [ ] **Step 3: Add real deinit implementation**

In `sdk_adapter_deinit()`:

```c
if (adapter->mode == SDK_MODE_REAL) {
#ifdef IPAD_WORKER_ENABLE_REAL_SDK
    ipa_deinit_library();
#endif
}
adapter->initialized = 0;
return IPAD_OK;
```

- [ ] **Step 4: Add conservative download mapping**

Implement real download only if the required SDK struct fields can be populated from `smdp` and `matching_id` without guessing. If the current SDK structs require activation-code binary formatting not yet represented by manager API, return `IPAD_ERR_INVALID_PARAMS` with worker stderr explaining the missing input shape.

The code path must compile either way:

```c
if (adapter->mode == SDK_MODE_REAL) {
#ifdef IPAD_WORKER_ENABLE_REAL_SDK
    return IPAD_ERR_SDK_FAILED;
#else
    return IPAD_ERR_SDK_FAILED;
#endif
}
```

Then add a comment in the function explaining the exact SDK struct that must be populated before enabling the real call.

- [ ] **Step 5: Add real-device validation doc**

Create `docs/real-device-validation.md`:

````markdown
# Real Device Validation

## Prerequisites

- Ubuntu 22.04+ target device.
- Built `ipa_sdk_pc` SDK library.
- eUICC/modem access configured for the service user.
- `ipad-managerd`, `ipad-sdk-worker`, and `ipadctl` built from the same commit.

## Commands

```bash
cmake -S ipa_sdk_pc -B ipa_sdk_pc/build -DCMAKE_BUILD_TYPE=Release
cmake --build ipa_sdk_pc/build --parallel
cmake -S . -B build-manager -DIPAD_BUILD_TESTS=ON -DIPAD_WORKER_ENABLE_REAL_SDK=ON
cmake --build build-manager --parallel
./build-manager/ipad_worker/ipad-sdk-worker --sdk-mode real
```

Expected: worker starts or prints a concrete SDK initialization error.
```
````

- [ ] **Step 6: Verify and commit**

Run:

```bash
cmake -S . -B build-manager -DIPAD_BUILD_TESTS=ON
cmake --build build-manager --parallel
ctest --test-dir build-manager --output-on-failure
```

Commit:

```bash
git add ipad_worker docs
git commit -m "feat: add real sdk init adapter path"
```

---

### Task 10: SDK Facade for Enable, Disable, and Delete

**Files:**
- Create: `ipad_worker/sdk_profile_facade.h`
- Create: `ipad_worker/sdk_profile_facade.c`
- Modify: `ipad_worker/sdk_adapter.c`
- Modify: `ipad_worker/CMakeLists.txt`
- Create: `tests/worker/test_sdk_profile_facade.c`
- Modify: `tests/worker/CMakeLists.txt`

**Interfaces:**
- Produces:
  - `ipad_error_t sdk_profile_facade_enable(const char *iccid);`
  - `ipad_error_t sdk_profile_facade_disable(const char *iccid);`
  - `ipad_error_t sdk_profile_facade_delete(const char *iccid);`
- Consumes: ES10 internal functions when real mode is compiled and safe to call

- [ ] **Step 1: Add facade header**

Create `ipad_worker/sdk_profile_facade.h`:

```c
#ifndef SDK_PROFILE_FACADE_H
#define SDK_PROFILE_FACADE_H

#include "ipad_errors.h"

ipad_error_t sdk_profile_facade_enable(const char *iccid);
ipad_error_t sdk_profile_facade_disable(const char *iccid);
ipad_error_t sdk_profile_facade_delete(const char *iccid);

#endif
```

- [ ] **Step 2: Add safe initial facade implementation**

Create `sdk_profile_facade.c`:

```c
#include "sdk_profile_facade.h"

static ipad_error_t validate_iccid(const char *iccid) {
    return iccid && iccid[0] ? IPAD_OK : IPAD_ERR_INVALID_PARAMS;
}

ipad_error_t sdk_profile_facade_enable(const char *iccid) {
    ipad_error_t err = validate_iccid(iccid);
    if (err != IPAD_OK) return err;
    return IPAD_ERR_SDK_FAILED;
}

ipad_error_t sdk_profile_facade_disable(const char *iccid) {
    ipad_error_t err = validate_iccid(iccid);
    if (err != IPAD_OK) return err;
    return IPAD_ERR_SDK_FAILED;
}

ipad_error_t sdk_profile_facade_delete(const char *iccid) {
    ipad_error_t err = validate_iccid(iccid);
    if (err != IPAD_OK) return err;
    return IPAD_ERR_SDK_FAILED;
}
```

This first facade creates a stable compile boundary. A follow-up can move the code from `ipa.c` around `es10__enable_profile`, `es10__disable_profile`, and `es10__delete_profile` into public SDK wrapper functions if the SDK maintainers accept that API surface.

- [ ] **Step 3: Wire adapter to facade only in real mode**

In `sdk_adapter_profile_enable()`:

```c
if (adapter->mode == SDK_MODE_REAL) {
    return sdk_profile_facade_enable(iccid);
}
```

Do the same for disable and delete.

- [ ] **Step 4: Add facade tests**

Create `tests/worker/test_sdk_profile_facade.c`:

```c
#include "sdk_profile_facade.h"

int main(void) {
    if (sdk_profile_facade_enable("") != IPAD_ERR_INVALID_PARAMS) return 1;
    if (sdk_profile_facade_disable("") != IPAD_ERR_INVALID_PARAMS) return 1;
    if (sdk_profile_facade_delete("") != IPAD_ERR_INVALID_PARAMS) return 1;
    if (sdk_profile_facade_enable("89860123456789012345") != IPAD_ERR_SDK_FAILED) return 1;
    return 0;
}
```

Update worker CMake and tests CMake to include the facade source and test.

- [ ] **Step 5: Verify and commit**

Run:

```bash
cmake -S . -B build-manager -DIPAD_BUILD_TESTS=ON
cmake --build build-manager --parallel
ctest --test-dir build-manager --output-on-failure
```

Commit:

```bash
git add ipad_worker tests/worker
git commit -m "feat: add sdk profile facade boundary"
```

---

### Task 11: GitHub Actions and Documentation Hardening

**Files:**
- Modify: `.github/workflows/ubuntu-build.yml`
- Modify: `docs/real-device-validation.md`

**Interfaces:**
- Consumes: all previous tasks
- Produces: CI coverage for socket IPC, worker IPC, mock SDK mode, and compile-safe real SDK boundary

- [ ] **Step 1: Keep manager tests before host app build**

Verify workflow still runs:

```yaml
- name: Configure manager components
- name: Build manager components
- name: Run manager tests
```

before SDK/host app build.

- [ ] **Step 2: Add a real SDK compile-only configure**

After SDK build and dist prep, add:

```yaml
      - name: Configure manager components with real SDK headers
        run: cmake -S . -B build-manager-real-sdk -DIPAD_BUILD_TESTS=ON -DIPAD_WORKER_ENABLE_REAL_SDK=ON

      - name: Build manager components with real SDK headers
        run: cmake --build build-manager-real-sdk --parallel
```

If linking requires SDK dist first, place this after `Prepare SDK dist`.

- [ ] **Step 3: Expand real-device documentation**

Add sections for:

- service user/group permissions
- AT serial device path
- expected worker mock command
- expected worker real command
- collecting `journalctl -u ipad-managerd`

- [ ] **Step 4: Verify through GitHub Actions**

Run locally if available:

```bash
cmake -S . -B build-manager -DIPAD_BUILD_TESTS=ON
cmake --build build-manager --parallel
ctest --test-dir build-manager --output-on-failure
```

Then push branch and confirm GitHub Actions run is green.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/ubuntu-build.yml docs/real-device-validation.md
git commit -m "ci: validate ipc worker sdk continuation"
```

---

## Self-Review Notes

Spec coverage:

- Stage 1 client-to-daemon Unix Socket IPC is covered by Tasks 1 through 3.
- Stage 2 daemon-to-worker IPC and supervision is covered by Tasks 4 through 6.
- Stage 3 real SDK boundary and Profile integration path is covered by Tasks 7 through 10.
- CI and documentation hardening is covered by Task 11.

Known implementation guardrails:

- The plan does not let daemon include SDK headers.
- The plan keeps CI on mock mode.
- The plan gives real SDK mode an explicit compile path and a conservative runtime path.
- Enable, disable, and delete use a worker-only facade boundary because the current public `ipa_sdk_pc/include/ipa.h` does not expose simple product-level wrappers for ordinary profile state changes.
- The real Profile download operation must only be fully enabled when `profile_download_trigger_request_t` can be populated from product API inputs without guessing hidden activation-code formatting.

Verification:

- Each task ends with CMake build plus CTest.
- Final acceptance requires GitHub Actions success on Ubuntu 22.04.
