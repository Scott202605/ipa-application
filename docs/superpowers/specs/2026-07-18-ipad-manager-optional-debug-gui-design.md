# IPAd Manager Optional Debug GUI Design

Date: 2026-07-18

## 1. Purpose

This design adds an optional GUI-assisted debugging and configuration experience for IPAd Manager. The product still targets a single Linux device where the operator may not understand IPAd SDK internals. The GUI exists to make setup, diagnostics, fault explanation, and evidence collection easier during development, integration, factory validation, and field support.

The GUI must not become a runtime dependency. IPAd Manager must remain fully usable on headless Linux devices through `ipad-managerd`, `ipad-sdk-worker`, and `ipadctl`.

## 2. Product Positioning

The GUI is a debug console, not the control plane of record.

- The daemon, worker, and CLI remain the authoritative runtime path.
- Every GUI action must map to a documented `ipadctl` command or daemon IPC/API call.
- Devices without display servers, browsers, GTK, Qt, Node.js, or Python must still run the core product.
- The GUI package is optional and can be omitted from embedded production images.
- The GUI should help an operator understand what to do next, not hide the underlying command model.

## 3. Current Baseline

The current product already provides:

- `ipadctl config show`
- `ipadctl config check`
- `ipadctl device list`
- `ipadctl setup --mock`
- `ipadctl setup --real --at-device <path>`
- `ipadctl doctor`
- `ipadctl platform check`
- `ipadctl bootstrap check`
- Systemd, OpenRC, SysV init, and manual packaging guidance.
- Real-device validation, installation delivery, troubleshooting, and evidence documentation.
- An older `ipad_host_app` with GUI-related files, which should be treated as a legacy/reference host tool rather than the new manager runtime UX.

The remaining gap is that users still need to read JSON and command output manually. A visual debug console can reduce first-use friction, make failure causes easier to scan, and create a better support workflow without adding burden to headless devices.

## 4. Recommended Approach

Use a local Web Debug Console as the primary GUI direction.

Architecture:

```text
Browser or debug workstation
        |
        | HTTP on 127.0.0.1 or SSH tunnel
        v
optional ipad-debug-console backend
        |
        | shells out to ipadctl --json or calls manager IPC
        v
ipadctl / ipad-managerd / ipad-sdk-worker / IPAd SDK
```

This approach is recommended because it works for both display-capable and headless devices:

- On a desktop Linux development kit, the browser can run locally.
- On a headless device, the operator can use SSH port forwarding and open the console on their workstation.
- On constrained devices, the GUI backend can be omitted entirely.
- The core C/POSIX manager path stays dependency-light.

Alternative approaches considered:

- Native GTK/Qt application: better desktop integration, but adds heavier target-side dependencies and is less suitable for Yocto, Buildroot, Alpine, OpenWrt, or no-display devices.
- Terminal UI: best over SSH and very lightweight, but less friendly for guided configuration and support evidence browsing.
- Existing `ipad_host_app` extension: useful as reference, but it currently mixes host-app concerns with SDK wrapper behavior and should not become the manager's new operational surface without separation.

## 5. User Experience

### 5.1 Overview

The first screen should answer:

- Is this platform usable?
- Is `ipad-managerd` reachable?
- Is the config valid?
- Is the worker executable present?
- Is the SDK initialized?
- Is the selected AT device present and accessible?
- What is the next recommended action?

The screen should show a compact status summary with severity colors and short operator-oriented messages.

### 5.2 Configuration Wizard

The wizard should support:

- Mock mode setup for local confidence checks.
- Real AT serial mode setup with explicit device selection.
- Display of equivalent commands before applying changes.
- Dry-run validation before writing a config file.
- Clear warning when a chosen path needs root privileges.

The wizard must not guess the AT port. It may show candidates from `ipadctl device list`, but the operator must select one.

### 5.3 Diagnostics

The diagnostics view should run and present:

- `ipadctl platform check`
- `ipadctl config check`
- `ipadctl doctor`
- `ipadctl bootstrap check`

Each failed check should show:

- Check name.
- Severity.
- Plain-language cause.
- Suggested action.
- Equivalent command to run manually.

### 5.4 Logs and Traceability

The GUI should expose read-only views for:

- Recent task records.
- Audit log entries.
- Daemon reachability.
- Worker lifecycle state.
- Last SDK or device-facing error where available.

The GUI must avoid showing secrets in full. Activation codes, tokens, and credentials should be redacted by default.

### 5.5 Support Bundle

The GUI should provide a one-click support bundle action after the CLI has a stable support-bundle command.

The bundle should contain:

- Platform report.
- Resolved config with secrets redacted.
- Diagnostic reports.
- Recent daemon and task logs if accessible.
- Version and build metadata.

The bundle should be generated by `ipadctl`, not by GUI-specific logic, so support workflows stay usable without the GUI.

## 6. Interface Contract

Before building a full GUI, the command/API contract must be stable enough for automation.

Required CLI/API capabilities:

- Explicit `--json` output mode for GUI-consumed commands.
- Stable check object fields: `name`, `ok`, `severity`, `message`, `suggestion`.
- Stable top-level fields: `ok`, `summary`, `next_action`, `checks`.
- Redacted config output mode.
- Support bundle generation command.
- Version endpoint or command output with manager, worker, SDK facade, and build information.

The GUI backend may initially call `ipadctl --json`. Later it may use the daemon's Unix domain socket directly when RPC methods are stable.

## 7. Security and Safety

The debug console must be local-only by default:

- Bind to `127.0.0.1`, not `0.0.0.0`.
- Prefer SSH tunneling for remote access.
- Never expose write actions without explicit confirmation.
- Show the equivalent command before applying a change.
- Redact activation codes, credentials, and device-specific secrets.
- Do not enable unauthenticated remote access by default.

For production images, the GUI package should be excluded unless explicitly selected.

## 8. Packaging and Build

Add an optional build/package boundary:

- Core package: `ipad-managerd`, `ipad-sdk-worker`, `ipadctl`, service files, config templates.
- Optional debug package: `ipad-debug-console`.
- Build option: `IPAD_BUILD_DEBUG_GUI=OFF` by default.
- Documentation should state that embedded/headless deployments do not need the GUI.

The debug console should be separable from the C manager build. If implemented as a small local web app, its static assets and backend should live under a clearly optional path such as `tools/debug-console/`.

## 9. Documentation Updates

Add documentation for:

- When to use the GUI and when to use CLI only.
- How to run the console locally on a development kit.
- How to use SSH port forwarding from a headless target.
- How to generate the same diagnostics from CLI.
- How to disable or omit the GUI package in production.

The quick start should remain CLI-first. The GUI should be introduced as an easier debug path, not as a prerequisite.

## 10. Testing Strategy

Testing should happen in layers:

- CLI contract tests validate JSON fields consumed by the GUI.
- Support-bundle tests validate secret redaction and expected file contents.
- Backend tests validate command invocation, parsing, and error translation.
- Frontend tests validate status rendering for pass, warning, and failure states.
- Headless compatibility tests validate that the core build still succeeds with `IPAD_BUILD_DEBUG_GUI=OFF`.

The GUI test suite must not require access to real `/etc`, `/run`, `/var`, or `/dev`.

## 11. Non-Goals

This stage does not add:

- Mandatory GUI dependencies to the daemon, worker, CLI, or SDK path.
- Remote multi-device fleet management.
- Browser-based direct SDK control.
- Automatic AT-port selection.
- Public network exposure of the debug console.
- Replacement of `ipadctl` as the documented operational interface.

## 12. Success Criteria

This design is successful when:

- A headless device can still install, configure, diagnose, and run IPAd Manager without GUI components.
- A development or support user can open a GUI debug console and understand platform, config, daemon, worker, SDK, and device readiness at a glance.
- Every GUI action has an equivalent CLI command or daemon API path.
- Diagnostics shown in the GUI match `ipadctl` JSON output.
- Support evidence can be exported without hand-copying logs.
- Production packaging can omit the GUI cleanly.

## 13. Spec Self-Review

- Marker scan: no unresolved markers remain.
- Scope check: this stage is focused on optional GUI-assisted debugging and setup, not full fleet management or SDK feature expansion.
- Boundary check: GUI depends on `ipadctl`/manager APIs; daemon, worker, and CLI do not depend on GUI code.
- Product fit check: the design improves ease of use for non-SDK users while preserving compatibility with no-display and constrained Linux devices.
