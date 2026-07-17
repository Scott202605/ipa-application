# Real Device Validation

## Prerequisites

- Ubuntu 22.04+ target device.
- Built `ipa_sdk_pc` SDK library.
- eUICC or modem access configured for the service user.
- `ipad-managerd`, `ipad-sdk-worker`, and `ipadctl` built from the same commit.
- The runtime user is in the group that can access the selected AT serial or PC/SC device.

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

## Service Diagnostics

When running through systemd:

```bash
journalctl -u ipad-managerd --no-pager
ls -l /run/ipad-manager
groups
```

Confirm:

- `/run/ipad-manager/ipad-manager.sock` exists.
- The socket group matches the configured `ipad` service group.
- The user running `ipadctl` belongs to that group.
- The AT serial path or PC/SC reader is accessible to the service user.

## Profile Validation Checklist

- `sdk.init` reports initialized once the RPC method is wired.
- `sdk.status` reports mock or real mode.
- `profile.download` returns a task id and stable failure when real activation-code mapping is incomplete.
- `profile.enable`, `profile.disable`, and `profile.delete` return explicit SDK facade errors until public SDK wrappers are completed.
- Worker crash or timeout does not terminate `ipad-managerd`.
