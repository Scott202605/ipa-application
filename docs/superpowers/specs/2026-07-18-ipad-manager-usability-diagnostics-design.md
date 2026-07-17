# IPAd Manager Usability and Diagnostics Design

Date: 2026-07-18

## 1. Purpose

This design adds an operator-friendly usability layer on top of the existing IPAd Manager daemon, worker, CLI, runtime config, and task traceability work. The goal is to help a Linux device integrator get from "fresh install" to "known-good or clearly diagnosed state" without needing to understand IPAd SDK internals.

The target user is not an IPAd SDK developer. They are likely an embedded Linux engineer or device application developer who needs clear commands, safe defaults, and actionable failure messages.

## 2. Current Baseline

The current product already provides:

- `ipadctl status`
- `ipadctl sdk init`
- `ipadctl sdk status`
- `ipadctl sdk deinit`
- `ipadctl task get <task-id>`
- `ipadctl profile download --activation-code <code>`
- `ipadctl profile download --smdp <fqdn> --matching-id <id>`
- `ipadctl profile enable|disable|delete --iccid <iccid>`
- Runtime config parsing through `ipad_config_t`.
- Systemd packaging with runtime, state, and log directories.
- JSONL task persistence.
- Basic real-device validation documentation.

The usability gap is that users still need to know which file to edit, which permissions matter, which serial device is likely correct, and how to interpret low-level failures.

## 3. Product Experience Principle

The CLI should become an operator cockpit:

- Show current state.
- Check whether configuration is valid.
- Explain why the daemon or SDK is not usable.
- Suggest the next command.
- Keep JSON output by default so automated scripts can consume it.

Every diagnostic command should answer four questions:

1. What was checked?
2. Did it pass?
3. Why did it fail?
4. What should the operator do next?

## 4. Proposed Commands

### 4.1 `ipadctl config show`

Prints resolved config as JSON. It should include defaulted values, not only fields from the file.

Example:

```json
{
  "config_path": "/etc/ipad-manager/config.json",
  "socket_path": "/run/ipad-manager/ipad-manager.sock",
  "worker_path": "/usr/local/bin/ipad-sdk-worker",
  "sdk_mode": "real",
  "sdk_transport": "at_serial",
  "at_device": "/dev/ttyUSB2",
  "at_baudrate": 115200,
  "task_store_path": "/var/lib/ipad-manager/tasks.jsonl",
  "audit_log_path": "/var/log/ipad-manager/audit.jsonl"
}
```

### 4.2 `ipadctl config check`

Checks local configuration and filesystem/device readiness from the client side.

Checks:

- Config file exists and parses.
- `sdk_mode` is `mock` or `real`.
- `worker_path` exists and is executable.
- Socket parent directory exists.
- Task store parent directory exists and is writable when run with enough permissions.
- Audit log parent directory exists and is writable when run with enough permissions.
- In real AT serial mode, configured AT device exists.
- In real AT serial mode, current user has access to the configured device.

Output:

```json
{
  "ok": false,
  "checks": [
    {
      "name": "config.parse",
      "ok": true,
      "message": "config loaded"
    },
    {
      "name": "worker.executable",
      "ok": false,
      "message": "/usr/local/bin/ipad-sdk-worker is missing or not executable",
      "suggestion": "Install ipad-sdk-worker or update worker_path in /etc/ipad-manager/config.json"
    }
  ]
}
```

### 4.3 `ipadctl doctor`

Runs an end-to-end diagnosis that combines local config checks with daemon RPC checks.

Checks:

- Config check summary.
- Socket connect.
- `system.status`.
- `sdk.status`.
- Worker state.
- Last worker error.
- Recent task store availability.
- Real-mode device readiness.

Output:

```json
{
  "ok": false,
  "summary": "daemon is reachable, but SDK is not initialized",
  "next_action": "Run: ipadctl sdk init",
  "checks": [
    {"name":"config.parse","ok":true},
    {"name":"daemon.socket","ok":true},
    {"name":"daemon.status","ok":true,"worker":"ready"},
    {"name":"sdk.status","ok":false,"message":"SDK is not initialized","suggestion":"Run: ipadctl sdk init"}
  ]
}
```

### 4.4 `ipadctl device list`

Lists likely local device nodes for AT serial integration.

Initial scope:

- `/dev/ttyUSB*`
- `/dev/ttyACM*`
- `/dev/wwan*`

Output:

```json
{
  "devices": [
    {"path":"/dev/ttyUSB0","readable":true,"writable":true},
    {"path":"/dev/ttyUSB2","readable":false,"writable":false,"suggestion":"Add service user to dialout or adjust udev rules"}
  ]
}
```

This does not try to auto-identify a vendor-specific AT port. It simply makes likely candidates visible and points out permission problems.

### 4.5 `ipadctl setup --mock`

Creates a development config for mock mode.

Output:

```json
{
  "created": "/etc/ipad-manager/config.json",
  "sdk_mode": "mock",
  "next_action": "Run: sudo systemctl restart ipad-managerd && ipadctl doctor"
}
```

### 4.6 `ipadctl setup --real --at-device /dev/ttyUSB2`

Creates a real-mode AT serial config using a specified device.

The command must not guess the device. If `--at-device` is missing, return a clear error and suggest `ipadctl device list`.

## 5. Output Contract

All new usability commands default to JSON output. This keeps automation stable and avoids adding terminal formatting dependencies.

Common diagnostic check object:

```json
{
  "name": "worker.executable",
  "ok": false,
  "severity": "error",
  "message": "worker executable is missing",
  "suggestion": "Install ipad-sdk-worker or update worker_path"
}
```

Severity values:

- `info`
- `warning`
- `error`

Exit codes:

- `0`: all required checks pass.
- `1`: command ran, at least one required check failed.
- `2`: command usage error.
- `3`: config parse error.
- `4`: daemon unreachable.

## 6. Implementation Boundaries

New code should be split so `ipadctl_main.c` does not become a large pile of command logic.

Recommended files:

- `ipadctl/diagnostics.h`
- `ipadctl/diagnostics.c`
- `ipadctl/config_commands.h`
- `ipadctl/config_commands.c`
- `ipadctl/device_discovery.h`
- `ipadctl/device_discovery.c`
- `ipadctl/setup_commands.h`
- `ipadctl/setup_commands.c`

The daemon does not need new dependencies for this stage. Most checks are client-side and use existing RPCs.

## 7. Example Config Templates

Add:

```text
packaging/config/mock.config.json
packaging/config/at-serial.config.json
```

Mock template:

```json
{
  "socket_path": "/run/ipad-manager/ipad-manager.sock",
  "worker_path": "/usr/local/bin/ipad-sdk-worker",
  "sdk_mode": "mock",
  "request_timeout_ms": 10000,
  "task_store_path": "/var/lib/ipad-manager/tasks.jsonl",
  "audit_log_path": "/var/log/ipad-manager/audit.jsonl"
}
```

AT serial template:

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

## 8. Quick Start Documentation

Add `docs/quick-start.md` with two paths:

1. Mock mode: fastest local confidence check.
2. Real AT serial mode: target-device setup.

The document should start with commands, then explain details. It should avoid requiring the reader to understand daemon/worker internals before first success.

## 9. Testing Strategy

CI should cover:

- `ipadctl config show --config <test-file>` prints resolved config.
- `ipadctl config check --config <valid-test-file>` passes.
- `ipadctl config check --config <bad-test-file>` fails with check details.
- `ipadctl device list --dev-root <test-dir>` lists fake `ttyUSB` nodes.
- `ipadctl doctor --socket <missing-socket> --config <test-file>` exits `4` and suggests starting daemon.
- `ipadctl setup --mock --config <test-output>` writes mock config.
- Packaging templates exist and parse with `ipad_config_load_file()`.

Tests must not write `/etc`, `/run`, `/var`, or real `/dev`.

## 10. Non-Goals

This stage does not add:

- Rich terminal tables or colors.
- Interactive prompts.
- Automatic modem vendor detection.
- Automatic udev rule generation.
- GUI setup wizard.
- Remote web diagnostics.

These can be designed later after the JSON command surface is stable.

## 11. Success Criteria

This stage is complete when:

- A new user can run `ipadctl doctor` and receive a concise next action.
- A new user can create a mock config without hand-writing JSON.
- A target-device operator can list likely AT serial devices.
- Configuration errors include field-specific messages.
- Missing worker, missing socket, invalid config, missing device, and permission problems produce distinct suggestions.
- CI validates the diagnostic commands without touching host system directories.

## 12. Spec Self-Review

- Marker scan: no unresolved markers remain.
- Scope check: the stage is focused on CLI usability and diagnostics, not SDK feature completion.
- Boundary check: diagnostic helpers live under `ipadctl/`; shared config parsing remains under `common/`.
- Product fit check: the design helps non-SDK users configure, validate, and troubleshoot one Linux device.
