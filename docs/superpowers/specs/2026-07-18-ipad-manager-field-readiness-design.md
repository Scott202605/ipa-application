# IPAd Manager Field Readiness Design

Date: 2026-07-18

## 1. Purpose

This design adds the missing field-readiness layer for IPAd Manager: real-device validation, installable delivery artifacts, and a troubleshooting manual. The target user is a Linux device team that may not know IPAd SDK internals but needs to trial IPAd Manager on one device with a real module, real eUICC path, and a reproducible support package.

This stage does not claim that real hardware validation has already passed. It creates the procedures, package layout, evidence template, and failure guide needed to run and record that validation.

## 2. Current Baseline

The product already has:

- Daemon, worker, and CLI binaries.
- Runtime config and diagnostic commands.
- `ipadctl platform check`, `config check`, `device list`, `doctor`, and `bootstrap check`.
- Mock and real AT serial setup commands.
- Systemd, OpenRC, SysV init, and manual packaging profiles.
- Ubuntu, Debian, and Alpine-oriented CI checks.

The remaining gap is field execution: a device team still needs a clear "what to ship", "how to validate", and "what to do when it fails" layer.

## 3. Product Experience

The field flow should be:

1. Build or receive a release tarball.
2. Copy the tarball to one Linux device.
3. Pick a service profile with `ipadctl platform check`.
4. Configure mock mode first, then real AT serial mode.
5. Run a real-device acceptance checklist.
6. Save evidence files for support and traceability.
7. Use a troubleshooting guide that maps symptoms to commands and next actions.

The operator should not need to read daemon or worker source code to complete this flow.

## 4. Release Package Shape

Add a safe packaging script:

```bash
packaging/make-release-tarball.sh <build-dir> <output-dir>
```

The script creates:

```text
ipad-manager-release/
  bin/ipad-managerd
  bin/ipad-sdk-worker
  bin/ipadctl
  config/mock.config.json
  config/at-serial.config.json
  packaging/systemd/
  packaging/openrc/
  packaging/sysvinit/
  packaging/manual/
  docs/quick-start.md
  docs/install-delivery.md
  docs/real-device-acceptance.md
  docs/troubleshooting-guide.md
  VERSION
  MANIFEST.txt
```

The script must not install files into `/usr`, `/etc`, `/run`, or `/var`. It only stages files into an output directory and creates a tarball.

## 5. Install Delivery Guide

Add `docs/install-delivery.md` with:

- How to build manager components.
- How to produce the release tarball.
- How to inspect `MANIFEST.txt`.
- How to copy files manually.
- How to choose systemd/OpenRC/SysV/manual profile.
- How to validate install with `ipadctl platform check`, `config check`, and `doctor`.

The guide should be conservative: copy examples are shown, but automatic privileged install is not introduced in this stage.

## 6. Real Device Acceptance

Add `docs/real-device-acceptance.md` as a field checklist. It should cover:

- Device and image identity.
- Binary versions and commit.
- Platform report.
- Config report.
- Device list.
- Daemon status.
- SDK init/status.
- Profile download task id.
- Task store evidence.
- Audit log evidence.
- Pass/fail sign-off.

Add `docs/templates/real-device-evidence.md` so testers can record a run consistently.

Acceptance flow:

```bash
ipadctl platform check
ipadctl device list
sudo ipadctl setup --real --at-device /dev/ttyUSB2
ipadctl config check
sudo systemctl restart ipad-managerd
ipadctl doctor
ipadctl sdk init
ipadctl sdk status
ipadctl profile download --activation-code 'LPA:1$smdp.example.com$MATCHINGID'
ipadctl task get <task-id>
```

For non-systemd systems, replace restart command using `ipadctl bootstrap check`.

## 7. Troubleshooting Manual

Add `docs/troubleshooting-guide.md` with a symptom-to-action matrix:

- Build fails.
- Release package missing binaries.
- `platform check` reports degraded.
- `config check` fails.
- No candidate device.
- Serial permission denied.
- Daemon socket unreachable.
- Worker missing or not executable.
- SDK init fails.
- Profile download returns a failed task.
- Audit/task logs missing.

Each row should include:

- Symptom.
- Likely cause.
- Confirm with.
- Fix.
- Evidence to collect.

## 8. CI and Verification

CI should verify:

- Field docs exist.
- Evidence template exists.
- Troubleshooting guide references key commands.
- Release tarball script exists and is syntax-checkable.
- Release package script can stage from a local build directory.

Local verification should run CMake, CTest, and the packaging script against `build-manager`.

## 9. Non-Goals

This stage does not add:

- Debian `.deb` generation.
- OpenWrt `.ipk` generation.
- Automatic privileged installer.
- Real hardware pass claims.
- Remote support upload.
- Secret redaction tooling beyond documentation.

## 10. Success Criteria

This stage is complete when:

- A release tarball can be generated from built manager binaries.
- A device tester can follow one acceptance checklist.
- A tester can record evidence in a consistent template.
- A first-line support engineer can map common failures to commands and fixes.
- CI protects these docs and the release package script.

## 11. Spec Self-Review

- Marker scan: no unresolved markers remain.
- Scope check: focused on real-device validation procedure, install delivery, and troubleshooting.
- Boundary check: no automatic privileged installation is added.
- Product fit check: this directly supports a device team trying IPAd Manager on a single Linux device.
