# IPAd Manager Linux Compatibility Design

Date: 2026-07-18

## 1. Purpose

This design extends IPAd Manager from an Ubuntu-friendly product into a Linux-device-friendly product. The target remains a single Linux device using IPAd Manager together with the submitted IPAd SDK, but the device may run Ubuntu, Debian, Alpine, OpenWrt, Yocto, Buildroot, or a vendor derivative with different libc, init, filesystem, kernel, and compiler assumptions.

The compatibility layer must not make daily usage harder. The operator should still start with `ipadctl doctor`, `ipadctl setup`, and a short quick start. Platform differences should be detected and translated into clear next actions.

## 2. Current Baseline

The current product already provides:

- `ipadctl config show`
- `ipadctl config check`
- `ipadctl device list`
- `ipadctl setup --mock`
- `ipadctl setup --real --at-device <path>`
- `ipadctl doctor`
- Systemd packaging and tmpfiles definitions.
- Mock and AT serial config templates.
- Ubuntu GitHub Actions build and tests.
- Quick-start and real-device validation documentation.

The gap is that current diagnostics still assume a fairly standard Linux host: systemd exists, `/run` behaves normally, service paths match Debian-style layouts, glibc is likely, and the compiler environment can build everything. Embedded Linux variants may violate those assumptions.

## 3. Product Principle

Compatibility should be handled as a "platform envelope" around the existing daemon, worker, SDK, and CLI:

- Detect platform facts locally.
- Classify platform support as `supported`, `degraded`, or `unsupported`.
- Keep setup commands simple.
- Make `doctor` platform-aware so it suggests the right service and filesystem action.
- Keep output JSON-first for automation.
- Avoid mandatory external dependencies such as `lsb_release`, `systemctl`, `udevadm`, or `pkg-config` in the diagnostic path.

The operator should not need to know whether the device uses glibc or musl before receiving a useful diagnosis.

## 4. Compatibility Targets

Initial targets:

- Ubuntu or Debian with glibc and systemd.
- Alpine with musl and OpenRC or manual process supervision.
- Yocto, Buildroot, or OpenWrt-style systems with BusyBox userland and no systemd.
- x86_64 and aarch64 as primary architectures.
- armv7 and riscv64 as detectable but not fully validated targets.

Non-goals for this stage:

- Full package generation for every distribution.
- Automatic service installation on non-systemd systems.
- Vendor-specific modem AT-port identification.
- Kernel driver installation.
- Remote diagnostics collection.

## 5. New Command: `ipadctl platform check`

`ipadctl platform check` prints a local platform report:

```json
{
  "ok": true,
  "support": "supported",
  "platform": {
    "sysname": "Linux",
    "release": "6.5.0",
    "machine": "x86_64",
    "libc": "glibc",
    "init": "systemd",
    "has_systemd": true,
    "has_run_dir": true,
    "has_tmp_dir": true
  },
  "checks": [
    {
      "name": "platform.arch",
      "ok": true,
      "severity": "info",
      "message": "architecture is x86_64"
    }
  ],
  "next_action": "Run: ipadctl doctor"
}
```

Checks:

- Kernel family from `uname`.
- Architecture from `uname.machine`.
- libc type by compile-time macros and runtime hints.
- Init system by checking `/run/systemd/system`, `/sbin/openrc-run`, `/etc/init.d`, and `/proc/1/comm`.
- Writable runtime candidates: `/run`, `/tmp`.
- Writable state/log parent candidates if configured.
- Availability of Unix domain sockets is treated as a build/runtime assumption; failures are diagnosed through daemon socket checks.
- Service-management advice should be derived from detected init.

The command must support `--json` implicitly by default. No table mode is required.

## 6. Doctor Integration

`ipadctl doctor` should become a layered diagnosis:

1. Platform layer: `ipadctl platform check` equivalent summary.
2. Config layer: existing `config check`.
3. Filesystem layer: runtime, state, log directories.
4. Init layer: service manager and restart command.
5. Device layer: AT serial candidate and permission checks.
6. Daemon layer: socket reachable.
7. Worker and SDK layer: existing daemon RPC checks when reachable.

The first implementation may continue to use socket reachability instead of full RPC checks, but its messages must become platform-aware.

Examples:

- On systemd: `Run: sudo systemctl restart ipad-managerd`
- On OpenRC: `Run: sudo rc-service ipad-managerd restart after installing an OpenRC service file`
- On manual/unknown init: `Run: ipad-managerd --config <path> --socket <path> in your supervisor`

## 7. One-Command Deployment Guidance

The current `setup` command writes config. The compatibility stage adds a safe dry-run style command:

```bash
ipadctl bootstrap check --mock
ipadctl bootstrap check --real --at-device /dev/ttyUSB2
```

It should not automatically modify `/etc`, install services, or restart daemons. It returns a deployment checklist tailored to platform detection:

```json
{
  "ok": true,
  "mode": "real",
  "init": "openrc",
  "steps": [
    "Run: sudo ipadctl setup --real --at-device /dev/ttyUSB2",
    "Install packaging/openrc/ipad-managerd",
    "Run: sudo rc-service ipad-managerd restart",
    "Run: ipadctl doctor"
  ]
}
```

This preserves ease of use without creating risky cross-distro side effects.

## 8. Packaging Profiles

Add packaging profiles:

```text
packaging/manual/README.md
packaging/sysvinit/ipad-managerd
packaging/openrc/ipad-managerd
```

Responsibilities:

- `systemd/`: production default for Ubuntu/Debian.
- `openrc/`: Alpine-style service wrapper.
- `sysvinit/`: broad legacy fallback.
- `manual/`: command examples for Yocto, Buildroot, OpenWrt, containers, and custom supervisors.

The quick start should remain short and link to these profiles only when needed.

## 9. CMake Compatibility Options

Add or document build options:

- `IPAD_BUILD_HOST_APP=ON/OFF`
- `IPAD_BUILD_MANAGER=ON/OFF`
- `IPAD_BUILD_TESTS=ON/OFF`
- `IPAD_WORKER_ENABLE_REAL_SDK=ON/OFF`
- `IPAD_STRICT_WARNINGS=ON/OFF`

The manager/worker/CLI path should build with minimal POSIX dependencies. GUI host app and SDK-specific options should be separable so embedded targets can build only what they need.

## 10. CI Compatibility Matrix

Extend CI beyond Ubuntu:

- Ubuntu glibc build and full tests.
- Debian glibc build and full manager tests.
- Alpine musl build of manager components and tests where packages are available.
- ARM64 cross-compile smoke check for manager components.

The first implementation may use container jobs for Debian and Alpine. If SDK dependencies are unavailable in Alpine, the Alpine job should validate manager components with mock SDK mode and skip host app.

## 11. Output and Error Contract

All compatibility diagnostics use the existing check object:

```json
{
  "name": "platform.init",
  "ok": false,
  "severity": "warning",
  "message": "systemd is not available",
  "suggestion": "Use packaging/manual or packaging/openrc for this platform"
}
```

Support levels:

- `supported`: expected to work with documented flow.
- `degraded`: usable with manual packaging or limited automation.
- `unsupported`: required kernel/userland capability is missing.

Exit codes remain:

- `0`: all required checks pass.
- `1`: command ran, at least one required check failed.
- `2`: usage error.
- `3`: config parse error.
- `4`: daemon unreachable.

## 12. Testing Strategy

Tests must avoid host-specific writes to `/etc`, `/run`, `/var`, or real `/dev`. Platform detection must be injectable enough to test with fake roots and fake process files.

CI should cover:

- Platform model can classify systemd, OpenRC, sysvinit, and unknown/manual init.
- `ipadctl platform check` produces JSON with `support`, `platform`, `checks`, and `next_action`.
- `ipadctl doctor` suggests `systemctl`, `rc-service`, or manual commands depending on detected init.
- `ipadctl bootstrap check` produces setup steps without writing privileged paths.
- Packaging profile files exist.
- CMake options allow manager-only builds.

## 13. Success Criteria

This stage is complete when:

- A non-Ubuntu user can run `ipadctl platform check` and understand whether the platform is supported or degraded.
- `ipadctl doctor` no longer assumes systemd in its next action.
- A user can get a safe bootstrap checklist for mock or real mode.
- Packaging profiles exist for systemd, OpenRC, SysV init, and manual supervision.
- CI has at least one glibc job and one musl-oriented manager build path.
- The default Ubuntu quick start remains simple.

## 14. Spec Self-Review

- Marker scan: no unresolved markers remain.
- Scope check: this stage is compatibility diagnostics and deployment guidance, not automatic installation.
- Boundary check: platform detection belongs to `ipadctl`; shared runtime config remains in `common`.
- Product fit check: the design improves heterogeneous Linux compatibility without adding required user complexity.
