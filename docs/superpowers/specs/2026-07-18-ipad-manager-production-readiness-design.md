# IPAd Manager Production Readiness Design

Date: 2026-07-18

## 1. Purpose

This design defines the next product-readiness stage for IPAd Manager after the daemon, worker, CLI, and mock SDK IPC foundation. The goal is to move from a compile-tested and mock-usable system to a practical single-device Linux product that can coordinate with the submitted IPAd SDK on real hardware.

The target user is a Linux device or application team that does not want to understand the internal IPAd SDK. IPAd Manager should expose a small local control plane, keep SDK complexity inside the worker, provide clear diagnostics, and make real-device validation repeatable.

## 2. Current Baseline

The current branch already has:

- `ipad-managerd` listening on a Unix Domain Socket and serving JSON-RPC.
- `ipadctl` connecting to the daemon socket.
- `ipad-sdk-worker` as a private daemon child process using JSON Lines over stdin/stdout.
- Worker mock mode that can execute profile task flows.
- Real SDK compile and link path guarded by `IPAD_WORKER_ENABLE_REAL_SDK`.
- `sdk_adapter` lifecycle helpers and SDK error mapping.
- A worker-only `sdk_profile_facade` boundary for future real profile calls.
- Ubuntu 22.04 GitHub Actions coverage for manager tests, SDK build, real SDK compile path, and host app build.

This baseline is a strong engineering foundation, but it is not yet a complete real-device product.

## 3. Product Readiness Gap

The remaining gap is not mainly IPC structure. The important missing pieces are:

- Real SDK operation inputs are not productized. `profile.download` still accepts `smdp` and `matching_id`, while the SDK may require activation-code or SDK-specific request structures.
- `profile.enable`, `profile.disable`, and `profile.delete` have a facade boundary but do not call real SDK profile APIs.
- The daemon does not yet expose complete `sdk.init`, `sdk.status`, or `sdk.deinit` RPC methods.
- Runtime configuration is not centralized. Worker mode, worker path, serial device, log level, timeout, and SDK transport settings need a stable config file.
- Task state is in memory only. A service restart loses task history and makes traceability weak.
- Worker supervision is functional but not production-grade. It needs request timeouts, restart policy, crash reason mapping, and health reporting.
- Logs and audit records are basic. Operators need structured failure reason, task id, SDK mode, worker pid, and source method.
- Real-device validation is documented but not executable enough for repeated bring-up.

## 4. Design Direction

The next stage should keep the existing architecture:

```text
ipadctl / local app / future GUI
        |
        | Unix Domain Socket JSON-RPC
        v
ipad-managerd
        |
        | private worker IPC
        v
ipad-sdk-worker
        |
        | sdk_adapter + sdk_profile_facade
        v
IPAd SDK
        |
        v
eUICC / modem / AT serial / network
```

The daemon remains the product control plane. The worker remains the SDK boundary. The SDK is never exposed to clients or daemon headers.

The next stage should be implemented in five increments:

1. Runtime config and status model.
2. SDK lifecycle RPCs and worker protocol commands.
3. Product-level profile input model and real SDK mapping boundary.
4. Worker resilience, task traceability, and observability.
5. Real-device validation harness and deployment hardening.

## 5. Runtime Configuration

IPAd Manager should load a simple JSON config from:

```text
/etc/ipad-manager/config.json
```

The daemon also supports:

```bash
ipad-managerd --config /path/to/config.json --socket /tmp/ipad-manager.sock
```

For tests, config path can point inside the build directory.

Initial config schema:

```json
{
  "socket_path": "/run/ipad-manager/ipad-manager.sock",
  "worker_path": "/usr/local/bin/ipad-sdk-worker",
  "sdk_mode": "mock",
  "request_timeout_ms": 10000,
  "worker_restart": {
    "max_restarts": 3,
    "window_seconds": 60
  },
  "sdk": {
    "transport": "at_serial",
    "at_serial": {
      "device": "/dev/ttyUSB2",
      "baudrate": 115200
    },
    "log_level": "info"
  },
  "task_store": {
    "path": "/var/lib/ipad-manager/tasks.jsonl",
    "retention": 256
  },
  "audit_log": {
    "path": "/var/log/ipad-manager/audit.jsonl"
  }
}
```

Config rules:

- Missing config file is allowed only for developer mode. Defaults must be explicit in code.
- Invalid config returns a startup error with the failing field name.
- Tests must not read or write `/etc`, `/var`, or `/run`; they use temp paths.
- `sdk_mode` accepts only `mock` or `real`.
- `request_timeout_ms` must be between `1000` and `120000`.

## 6. Public JSON-RPC Methods

The daemon should expose these stable methods:

```text
system.status
sdk.init
sdk.status
sdk.deinit
task.get
profile.download
profile.enable
profile.disable
profile.delete
```

### 6.1 system.status

Returns daemon, worker, config, and task-store health:

```json
{
  "daemon": "running",
  "socket_path": "/run/ipad-manager/ipad-manager.sock",
  "worker": {
    "state": "ready",
    "pid": 1234,
    "sdk_mode": "mock",
    "restarts": 0
  },
  "task_store": {
    "backend": "jsonl",
    "available": true
  }
}
```

### 6.2 sdk.init

Initializes the worker SDK runtime. In mock mode it marks the adapter initialized. In real mode it calls `ipa_init_library()` with config-derived SDK settings.

The method accepts no parameters in the first productized version. It uses daemon config as the source of truth. This keeps CLI usage simple and avoids sending sensitive or device-specific configuration through every request.

### 6.3 sdk.status

Returns inspectable SDK state:

```json
{
  "mode": "real",
  "initialized": true,
  "transport": "at_serial",
  "device": "/dev/ttyUSB2",
  "last_error": ""
}
```

### 6.4 sdk.deinit

Stops SDK runtime in the worker. The daemon keeps running. The worker may either keep its process alive with SDK deinitialized or restart cleanly after deinit, but the behavior must be documented and stable.

### 6.5 task.get

Fetches a task by id:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "task.get",
  "task_id": "task-12"
}
```

Response:

```json
{
  "task_id": "task-12",
  "method": "profile.download",
  "state": "failed",
  "stage": "sdk.profile.download",
  "error": "sdk_failed",
  "created_at": 1784300000,
  "updated_at": 1784300004
}
```

## 7. Worker Protocol Commands

The daemon-to-worker protocol should add lifecycle commands:

```json
{"id":1,"op":"sdk.init"}
{"id":2,"op":"sdk.status"}
{"id":3,"op":"sdk.deinit"}
```

Profile commands remain:

```json
{"id":4,"op":"profile.download","task_id":"task-1","activation_code":"LPA:1$smdp.example.com$MATCHINGID"}
{"id":5,"op":"profile.enable","task_id":"task-2","iccid":"89860123456789012345"}
{"id":6,"op":"profile.disable","task_id":"task-3","iccid":"89860123456789012345"}
{"id":7,"op":"profile.delete","task_id":"task-4","iccid":"89860123456789012345"}
```

Worker replies must include:

- `id`
- `ok`
- `error` when failed
- `message` only when safe and useful
- `sdk_mode` for SDK lifecycle responses
- `initialized` for `sdk.status`

Worker stdout remains protocol-only. Logs go to stderr.

## 8. Profile Download Input Model

The product should accept activation-code as the primary profile download input:

```bash
ipadctl profile download --activation-code 'LPA:1$smdp.example.com$MATCHINGID'
```

For convenience, the CLI may still accept:

```bash
ipadctl profile download --smdp smdp.example.com --matching-id MATCHINGID
```

The CLI converts this into an activation-code-shaped product request before sending JSON-RPC. The daemon also accepts both forms for compatibility but normalizes them into one internal field:

```c
char activation_code[256];
```

Rules:

- Activation code must start with `LPA:`.
- `smdp` must be a non-empty hostname-like string.
- `matching_id` must be non-empty and bounded.
- The manager must not guess binary SDK structs. If the submitted SDK needs a structure not represented by public headers, the facade returns `IPAD_ERR_UNSUPPORTED` or `IPAD_ERR_SDK_FAILED` with a precise audit message.

## 9. Real SDK Profile Mapping

The worker should expose product-level adapter calls:

```c
ipad_error_t sdk_adapter_sdk_init(sdk_adapter_t *adapter, const sdk_runtime_config_t *config);
ipad_error_t sdk_adapter_sdk_status(const sdk_adapter_t *adapter, sdk_status_t *out);
ipad_error_t sdk_adapter_sdk_deinit(sdk_adapter_t *adapter);
ipad_error_t sdk_adapter_profile_download(sdk_adapter_t *adapter, const char *activation_code);
ipad_error_t sdk_adapter_profile_enable(sdk_adapter_t *adapter, const char *iccid);
ipad_error_t sdk_adapter_profile_disable(sdk_adapter_t *adapter, const char *iccid);
ipad_error_t sdk_adapter_profile_delete(sdk_adapter_t *adapter, const char *iccid);
```

The current `sdk_profile_facade` should either call public SDK APIs or remain a narrow compatibility layer that wraps SDK-internal ES10 entry points only when those calls are safe and buildable.

If the SDK does not expose a public function for a profile operation, this stage should add a small SDK-side wrapper under `ipa_sdk_pc/` rather than leaking SDK internals into manager code.

## 10. Task Traceability

Task records should be persisted to JSON Lines:

```json
{"task_id":"task-1","method":"profile.download","state":"created","stage":"created","created_at":1784300000,"updated_at":1784300000}
{"task_id":"task-1","method":"profile.download","state":"running","stage":"worker.call","created_at":1784300000,"updated_at":1784300001}
{"task_id":"task-1","method":"profile.download","state":"completed","stage":"sdk.profile.download","created_at":1784300000,"updated_at":1784300004}
```

Initial persistence can be append-only JSONL with bounded in-memory index. This is enough for traceability without introducing a database.

The task store must:

- Load recent tasks at daemon startup.
- Retain at most `retention` tasks in memory.
- Append every state transition.
- Return stable `task_not_found` for missing task ids.
- Avoid corrupting existing logs on partial writes by writing one complete line per transition.

## 11. Worker Resilience

The daemon should own worker health and restart policy.

States:

```text
not_started
starting
ready
busy
unhealthy
crashed
restart_limited
```

Request behavior:

- If worker is not started, daemon starts it lazily on first worker-dependent method.
- If worker does not emit `worker.ready` before timeout, request fails with `worker_timeout`.
- If worker exits during a request, request fails with `worker_crashed`.
- If restart limit is exceeded, daemon returns `worker_unavailable` until manual restart or service restart.
- `system.status` exposes worker state, pid, restart count, last error, and sdk mode.

## 12. Deployment Hardening

Systemd packaging should be updated so the service can run on a single Linux device:

- `RuntimeDirectory=ipad-manager`
- `StateDirectory=ipad-manager`
- `LogsDirectory=ipad-manager`
- `SupplementaryGroups=dialout`
- Config path `/etc/ipad-manager/config.json`
- Socket path `/run/ipad-manager/ipad-manager.sock`

The service should not require GTK or a desktop session.

## 13. CLI Usability

CLI commands should become the primary operator interface:

```bash
ipadctl status
ipadctl sdk init
ipadctl sdk status
ipadctl sdk deinit
ipadctl task get task-1
ipadctl profile download --activation-code 'LPA:1$smdp.example.com$MATCHINGID'
ipadctl profile enable --iccid 89860123456789012345
ipadctl profile disable --iccid 89860123456789012345
ipadctl profile delete --iccid 89860123456789012345
```

CLI output remains JSON by default so scripts can consume it. Human-friendly formatting is outside this stage and can be designed as a separate operator-experience improvement.

## 14. Testing Strategy

CI tests:

- Config parser accepts valid config and rejects invalid fields.
- `sdk.init`, `sdk.status`, and `sdk.deinit` work in mock mode.
- CLI sends SDK lifecycle methods through the daemon socket.
- `profile.download --activation-code` reaches the worker protocol in mock mode.
- `task.get` returns persisted task state.
- Worker timeout and crashed-worker failures map to stable errors.
- Real SDK compile path remains covered after SDK build.

Manual target-device validation:

- Build SDK and manager on Ubuntu device.
- Start `ipad-managerd` through systemd.
- Confirm socket permissions.
- Run `ipadctl sdk init`.
- Run `ipadctl sdk status`.
- Run profile operation against a test eUICC.
- Collect `journalctl -u ipad-managerd`.
- Preserve task JSONL and audit JSONL as validation artifacts.

## 15. Non-Goals

This stage does not add:

- Remote HTTP API.
- Multi-device scheduling.
- Cloud management.
- Web UI.
- Full GUI redesign.
- Database dependency.
- Automatic modem discovery across all vendors.

## 16. Success Criteria

This stage is complete when:

- A Linux operator can configure one device through `/etc/ipad-manager/config.json`.
- `ipadctl sdk init/status/deinit` works through daemon and worker.
- `profile.download` accepts activation-code input and reaches the SDK adapter through one normalized field.
- Real SDK profile operations either succeed on target hardware or fail with precise unsupported/SDK errors that identify the missing SDK wrapper.
- Tasks survive daemon restart through JSONL reload.
- Worker crash and timeout behavior is visible through `system.status`.
- GitHub Actions remains green on Ubuntu 22.04.
- Real-device validation steps are precise enough for another engineer to repeat.

## 17. Spec Self-Review

- Marker scan: no unresolved markers remain.
- Scope check: this is one coherent product-readiness stage, not a rewrite.
- Boundary check: SDK code remains isolated in the worker and SDK-side wrappers.
- Compatibility check: daemon, worker, and CLI remain Linux-first and GUI-free.
- Product fit check: the design serves a single Linux device whose application team should not need direct IPAd SDK knowledge.
