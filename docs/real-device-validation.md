# Real Device Validation

For the shorter operator-first flow, start with `docs/quick-start.md`.

For field acceptance sign-off, use `docs/real-device-acceptance.md` and record output in `docs/templates/real-device-evidence.md`.

## Prerequisites

- Ubuntu 22.04+ target device.
- Built `ipa_sdk_pc` SDK library.
- eUICC or modem access configured for the service user.
- `ipad-managerd`, `ipad-sdk-worker`, and `ipadctl` built from the same commit.
- The runtime user is in the group that can access the selected AT serial or PC/SC device.
- On non-systemd systems, choose a profile from `packaging/openrc/`, `packaging/sysvinit/`, or `packaging/manual/`.

## Build

```bash
cmake -S ipa_sdk_pc -B ipa_sdk_pc/build -DCMAKE_BUILD_TYPE=Release
cmake --build ipa_sdk_pc/build --parallel
cmake -S . -B build-manager -DIPAD_BUILD_TESTS=ON -DIPAD_WORKER_ENABLE_REAL_SDK=ON
cmake --build build-manager --parallel
```

## Worker Smoke Tests

Mock mode:

```bash
./build-manager/ipad_worker/ipad-sdk-worker --sdk-mode mock
```

Expected: the worker prints a `worker.ready` JSON event.

Real mode:

```bash
./build-manager/ipad_worker/ipad-sdk-worker --sdk-mode real
```

Expected: the worker starts or prints a concrete SDK initialization error. If it fails, collect stderr and confirm the configured device transport is available.

## Daemon and CLI Smoke Test

```bash
./build-manager/ipad_managerd/ipad-managerd --once --socket /tmp/ipad-manager-test.sock &
./build-manager/ipadctl/ipadctl --socket /tmp/ipad-manager-test.sock status
```

Expected: the CLI prints a JSON-RPC response containing `"daemon":"running"`.

Before using the installed system service, validate local configuration and device candidates:

```bash
ipadctl device list
ipadctl platform check
ipadctl bootstrap check --real --at-device /dev/ttyUSB2
ipadctl config show
ipadctl config check
ipadctl doctor
```

## Service Diagnostics

When running through systemd:

```bash
sudo systemctl daemon-reload
sudo systemctl restart ipad-managerd
sudo systemctl status ipad-managerd --no-pager
journalctl -u ipad-managerd --no-pager
ls -l /run/ipad-manager
groups
```

Confirm:

- `/run/ipad-manager/ipad-manager.sock` exists.
- The socket group matches the configured `ipad` service group.
- The user running `ipadctl` belongs to that group.
- The AT serial path or PC/SC reader is accessible to the service user.
- `ipadctl doctor` reports the daemon socket as reachable after the service starts.

For OpenRC, use `packaging/openrc/ipad-managerd` and validate with:

```bash
sudo rc-service ipad-managerd restart
ipadctl doctor
```

For custom supervisors, use `packaging/manual/README.md`.

## End-to-End CLI Validation

Use the installed `ipadctl` against the default daemon socket:

```bash
ipadctl status
ipadctl sdk init
ipadctl sdk status
ipadctl profile download --activation-code 'LPA:1$smdp.example.com$MATCHINGID'
ipadctl task get task-1
```

Collect task and service artifacts:

```bash
journalctl -u ipad-managerd --no-pager
sudo tail -n 50 /var/lib/ipad-manager/tasks.jsonl
sudo tail -n 50 /var/log/ipad-manager/audit.jsonl
```

## Profile Validation Checklist

- `sdk.init` returns a JSON-RPC result.
- `sdk.status` reports initialized state and mock or real mode.
- `profile.download` returns a task id and stable failure when real activation-code mapping is incomplete.
- `profile.enable`, `profile.disable`, and `profile.delete` return explicit SDK facade errors until public SDK wrappers are completed.
- Worker crash or timeout does not terminate `ipad-managerd`.
