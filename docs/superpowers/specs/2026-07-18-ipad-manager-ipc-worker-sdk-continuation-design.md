# IPAd Manager IPC, Worker IPC, and SDK Integration Design

Date: 2026-07-18

## 1. Purpose

This design continues the phase 1 IPAd Manager skeleton into three ordered implementation stages:

1. Client-to-daemon Unix Domain Socket JSON-RPC.
2. Daemon-to-worker child process IPC and supervision.
3. Real IPAd SDK Profile operation integration inside the worker.

The product remains focused on one Linux device. IPAd Manager is a local capability service that hides direct SDK complexity from device application developers while preserving traceability, failure isolation, and Linux deployment compatibility.

## 2. Current Baseline

The current phase 1 branch already provides:

- `common/`: error codes, protocol constants, simple JSON helpers.
- `ipad_managerd/`: RPC dispatcher, worker supervisor skeleton, task store, audit log, mock profile tasks.
- `ipad_worker/`: worker executable and mock SDK adapter boundary.
- `ipadctl/`: CLI argument parser that currently emits JSON-RPC request lines.
- `ipad_host_app/`: GTK host app hook for future manager RPC client use.
- `packaging/`: systemd and tmpfiles skeleton.
- GitHub Actions Ubuntu build and manager CTest coverage.

This continuation must preserve the current successful Ubuntu CI path.

## 3. Architecture Direction

The final shape after these three stages is:

```text
ipadctl / GTK GUI / local device app
        |
        | Unix Domain Socket JSON-RPC
        v
ipad-managerd
        |
        | child process IPC, framed JSON messages
        v
ipad-sdk-worker
        |
        | SDK adapter
        v
IPAd SDK
        |
        v
eUICC / modem / AT serial / PCSC / network dependencies
```

The daemon is the only long-running product service. It owns external API semantics, task lifecycle, audit logs, worker supervision, and client-facing error mapping. It never directly links or calls the IPAd SDK.

The worker owns SDK runtime state and executes SDK operations. It may crash, hang, or be killed without taking down the daemon. This is the main failure isolation boundary.

The CLI and GUI are clients only. They do not link the SDK and do not own business state.

## 4. Stage 1: Client to Daemon Unix Socket IPC

### 4.1 Goal

Make `ipad-managerd` listen on a Unix Domain Socket and make `ipadctl` send real JSON-RPC requests to that socket.

### 4.2 Scope

This stage implements:

- `common/ipad_socket.h` and `common/ipad_socket.c`.
- A newline-delimited JSON framing helper for local RPC messages.
- Daemon socket listen, accept-one-request loop, and graceful shutdown on SIGINT/SIGTERM.
- CLI socket connect, send request, read response, print response.
- Configurable socket path through CLI options and daemon options.
- CTest integration tests using a temporary socket path under the build or test directory.

This stage does not implement daemon-to-worker real IPC yet. Profile operations may still complete through the existing mock task path.

### 4.3 Message Framing

Use newline-delimited JSON for phase 2:

```text
{"jsonrpc":"2.0","id":1,"method":"system.status"}\n
```

Reasons:

- Easy to debug with shell tools.
- Simple to implement in C11.
- Sufficient for local IPC messages below `IPAD_MAX_JSON_MESSAGE`.
- Can be replaced later by length-prefix framing without changing JSON-RPC method semantics.

Rules:

- One request per connection in the first implementation.
- One response per request.
- Maximum message size is `IPAD_MAX_JSON_MESSAGE`.
- Empty messages return `IPAD_ERR_BAD_REQUEST`.
- Oversized messages return `IPAD_ERR_BAD_REQUEST` or cause connection close with an audit entry.

### 4.4 Daemon Runtime Behavior

`ipad-managerd` supports:

```bash
ipad-managerd --socket /tmp/ipad-manager.sock
ipad-managerd --once --socket /tmp/ipad-manager.sock
```

`--once` is for integration tests. It accepts exactly one request, sends one response, and exits.

Default socket path remains:

```text
/run/ipad-manager/ipad-manager.sock
```

The daemon removes a stale socket file before bind only when the path is a socket or does not exist. It must not unlink arbitrary regular files.

### 4.5 CLI Behavior

`ipadctl` supports:

```bash
ipadctl --socket /tmp/ipad-manager.sock status
ipadctl --socket /tmp/ipad-manager.sock profile download --smdp smdp.example.com --matching-id ABCD
```

By default it connects to `/run/ipad-manager/ipad-manager.sock`.

When the daemon is unavailable, `ipadctl` exits non-zero and prints a concise error to stderr.

## 5. Stage 2: Daemon to Worker IPC and Supervision

### 5.1 Goal

Make `ipad-managerd` start `ipad-sdk-worker`, exchange framed JSON messages with it, and route profile task execution through the worker boundary.

### 5.2 Scope

This stage implements:

- `ipad_managerd/worker_process.h` and `.c`.
- `ipad_worker/worker_protocol.h` if protocol constants are worker-specific, or shared additions under `common/`.
- Worker stdin/stdout framed JSON IPC for the first production-shaped implementation.
- Worker startup handshake.
- Worker request/response commands for profile download, enable, disable, and delete in mock mode.
- Worker timeout handling.
- Worker crash/error mapping into task state.
- CTest integration tests using the worker executable in mock mode.

### 5.3 IPC Transport Choice

Use child stdin/stdout JSON Lines for the first worker IPC implementation.

Rationale:

- Portable across Linux x86_64 and aarch64.
- Simple to test under CTest.
- Keeps worker private to the daemon.
- Avoids managing a second socket namespace before we need it.

The daemon launches the worker with pipes:

```text
daemon write pipe -> worker stdin
worker stdout -> daemon read pipe
worker stderr -> daemon log capture or inherited stderr in phase 2
```

### 5.4 Worker Handshake

On start, worker writes:

```json
{"event":"worker.ready","protocol":1,"sdk_mode":"mock"}
```

Daemon treats the worker as ready only after receiving this event.

If no ready event arrives before timeout, daemon marks worker as unhealthy and returns `IPAD_ERR_WORKER_TIMEOUT` for worker-dependent calls.

### 5.5 Worker Commands

Daemon sends:

```json
{"id":1,"op":"profile.download","task_id":"task-1","params":{"smdp":"smdp.example.com","matching_id":"ABCD"}}
```

Worker replies:

```json
{"id":1,"ok":true,"task_id":"task-1","state":"completed"}
```

For errors:

```json
{"id":1,"ok":false,"task_id":"task-1","error":"sdk_failed","message":"mock SDK failure"}
```

### 5.6 Task Flow

Profile methods become:

1. Daemon validates client parameters.
2. Daemon creates task.
3. Daemon ensures worker is ready.
4. Daemon sends worker command.
5. Daemon maps worker reply to task state.
6. Daemon returns task id and state to client.

Longer-running progress events can be added after the request/response path is stable.

## 6. Stage 3: Real SDK Profile Integration

### 6.1 Goal

Replace worker mock Profile execution with real calls into the submitted IPAd SDK while preserving mock mode for CI.

### 6.2 Scope

This stage implements:

- Worker runtime mode selection: mock by default in CI, real SDK mode when explicitly configured.
- SDK initialization command and state handling.
- Real SDK adapter mappings for Profile download, enable, disable, and delete where the SDK exposes stable APIs.
- SDK error mapping to `ipad_error_t` and client-facing messages.
- Manual workflow or documented hardware test flow for real device validation.

This stage does not require the daemon to link SDK headers. SDK headers remain inside `ipad_worker/` implementation boundaries.

### 6.3 Runtime Modes

Worker supports:

```bash
ipad-sdk-worker --sdk-mode mock
ipad-sdk-worker --sdk-mode real --config /etc/ipad-manager/config.json
```

CI uses mock mode.

Real hardware testing uses real mode with target-device configuration.

### 6.4 SDK Initialization

The daemon exposes:

```text
sdk.init
sdk.status
sdk.deinit
```

The worker owns actual SDK initialized state.

`sdk.init` should accept or load transport configuration:

```json
{
  "transport": "at_serial",
  "at_serial": {
    "device": "/dev/ttyUSB2",
    "baudrate": 115200
  }
}
```

If the current SDK initialization API cannot accept full transport configuration yet, the adapter must make that limitation explicit in the returned error instead of silently pretending success.

### 6.5 Profile Operation Mapping

The adapter exposes stable product-level functions:

```c
ipad_error_t sdk_adapter_profile_download(sdk_adapter_t *adapter, const char *smdp, const char *matching_id);
ipad_error_t sdk_adapter_profile_enable(sdk_adapter_t *adapter, const char *iccid);
ipad_error_t sdk_adapter_profile_disable(sdk_adapter_t *adapter, const char *iccid);
ipad_error_t sdk_adapter_profile_delete(sdk_adapter_t *adapter, const char *iccid);
```

Implementation rules:

- Validate parameters before SDK calls.
- Return `IPAD_ERR_SDK_NOT_INITIALIZED` if SDK is not initialized.
- Map known SDK error codes to stable manager errors.
- Keep raw SDK details in worker logs, not in daemon public API unless safe.
- Do not expose SDK internal structs through daemon/client headers.

## 7. Testing Strategy

### 7.1 Stage 1 Tests

- Unit tests for socket read/write framing.
- Integration test: start `ipad-managerd --once --socket <temp>`, run client request, assert `system.status` response.
- Integration test: `ipadctl --socket <temp> status` prints daemon status.
- Failure test: `ipadctl` against missing socket exits non-zero.

### 7.2 Stage 2 Tests

- Unit tests for worker command building and response parsing.
- Integration test: daemon starts worker mock and `system.status` reports ready.
- Integration test: `profile.download` flows through worker mock and returns completed task.
- Failure test: missing or non-executable worker maps to `worker_unavailable`.

### 7.3 Stage 3 Tests

- CI continues mock mode tests.
- Build test ensures real SDK mode compiles when SDK headers/libraries are available.
- Manual hardware test document covers:
  - `sdk.init`
  - `sdk.status`
  - `profile.download`
  - `profile.enable`
  - `profile.disable`
  - `profile.delete`
  - worker crash recovery

## 8. Deployment and Compatibility

The systemd packaging remains daemon-centric:

- systemd starts only `ipad-managerd`.
- daemon starts and supervises `ipad-sdk-worker`.
- socket path is under `/run/ipad-manager`.
- runtime directory permissions are controlled by systemd `RuntimeDirectory` and tmpfiles.

Linux compatibility targets:

- Ubuntu 22.04 and later.
- x86_64 and aarch64.
- C11 and CMake 3.22+.
- No dependency on desktop GUI libraries for daemon, worker, or CLI.

## 9. Non-Goals

These stages do not include:

- Multi-device scheduling.
- Remote HTTP management API.
- Web UI.
- Cloud management.
- Full GUI migration beyond the existing hook.
- Persistent database migration beyond the current in-memory task store unless needed by the implementation plan.

## 10. Risks and Mitigations

| Risk | Impact | Mitigation |
| --- | --- | --- |
| Socket stale file handling removes the wrong file | Local data loss | Only unlink when `lstat` confirms socket path is a socket |
| Daemon blocks on a stuck worker | Product appears frozen | Use worker request timeout and kill/restart path |
| Worker stdout logs corrupt IPC | Protocol parse failures | Worker sends structured protocol only on stdout; logs go to stderr |
| SDK API shape is incomplete or unstable | Real Profile integration blocked | Keep adapter boundary stable; return explicit unsupported/SDK failed errors |
| Real hardware is unavailable in CI | CI cannot validate real operations | Keep mock mode in CI and add manual hardware validation workflow |
| JSON helper is too simple for complex nested params | Bad parsing | Keep phase 2 params flat; introduce a real JSON parser only if nested parsing becomes necessary |

## 11. Success Criteria

After stage 1:

- `ipad-managerd --once --socket <temp>` handles a real socket request.
- `ipadctl --socket <temp> status` receives and prints daemon response.
- Ubuntu CI runs socket integration tests.

After stage 2:

- daemon launches `ipad-sdk-worker` in mock mode.
- `system.status` reports meaningful worker state.
- Profile task RPCs execute through worker IPC, not direct daemon mock functions.
- Worker timeout/crash failures are mapped to stable errors.

After stage 3:

- worker can run in real SDK mode on target Linux device.
- SDK initialization is explicit and inspectable.
- Profile download, enable, disable, and delete call the SDK through `sdk_adapter_*`.
- CI still passes in mock mode.
- Real device validation steps are documented.

## 12. Spec Self-Review

- Marker scan: no unresolved markers remain.
- Scope check: the work is intentionally split into three ordered stages, each independently testable.
- Boundary check: SDK remains isolated in `ipad-sdk-worker`; daemon and clients do not link SDK internals.
- Testability check: CI can validate stages 1 and 2 in mock mode; stage 3 has mock CI plus manual hardware validation.
- Risk check: stale socket files, worker blocking, stdout protocol corruption, and missing real hardware are explicitly handled.
