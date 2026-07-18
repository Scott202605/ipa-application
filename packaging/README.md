# IPAd Manager Packaging

This directory contains Linux deployment artifacts for the single-device IPAd Manager service.

For first-run commands, see `docs/quick-start.md`.

Run `ipadctl platform check` before choosing a service profile on non-Ubuntu devices.

## Runtime paths

- Socket: `/run/ipad-manager/ipad-manager.sock`
- Config: `/etc/ipad-manager/config.json`
- State: `/var/lib/ipad-manager`
- Logs: `/var/log/ipad-manager`

## Service profiles

- `packaging/systemd/`: default Ubuntu and Debian profile.
- `packaging/openrc/`: Alpine and OpenRC-style systems.
- `packaging/sysvinit/`: legacy SysV init systems.
- `packaging/manual/`: Yocto, Buildroot, OpenWrt, containers, and custom supervisors.

Preview the recommended flow:

```bash
ipadctl platform check
ipadctl bootstrap check --mock
ipadctl bootstrap check --real --at-device /dev/ttyUSB2
```

## Service user

Create an `ipad` user and group, then grant serial or PC/SC permissions through udev rules selected for the target device transport.

For AT serial devices, add the service user to the group that owns the modem node. On Ubuntu this is commonly `dialout`, which is also declared in `packaging/systemd/ipad-managerd.service`:

```bash
sudo useradd --system --home /var/lib/ipad-manager --shell /usr/sbin/nologin ipad
sudo usermod -aG dialout ipad
```

## Sample config

Install the runtime config at `/etc/ipad-manager/config.json`, or generate it with:

```bash
sudo ipadctl setup --mock
ipadctl device list
sudo ipadctl setup --real --at-device /dev/ttyUSB2
```

Template files are also available in `packaging/config/`.

Real AT serial example:

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

For CI or development without hardware, set `"sdk_mode": "mock"`.

Validate the final configuration with:

```bash
ipadctl config show
ipadctl config check
ipadctl platform check
ipadctl doctor
```
