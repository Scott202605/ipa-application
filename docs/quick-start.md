# IPAd Manager Quick Start

This guide is for a single Linux device that uses IPAd Manager with the submitted IPAd SDK. Start with mock mode when you want to verify the service path without hardware, then switch to real AT serial mode on the target device.

For release handoff, see `docs/install-delivery.md`. For field sign-off, see `docs/real-device-acceptance.md`.

## Mock Mode

```bash
sudo ipadctl setup --mock
sudo systemctl restart ipad-managerd
ipadctl doctor
ipadctl sdk init
ipadctl sdk status
```

Expected result: `ipadctl doctor` reports the daemon socket as reachable, and `ipadctl sdk status` reports mock SDK state.

## Real AT Serial Mode

```bash
ipadctl device list
sudo ipadctl setup --real --at-device /dev/ttyUSB2
sudo systemctl restart ipad-managerd
ipadctl doctor
ipadctl sdk init
ipadctl sdk status
```

Choose the `--at-device` value from `ipadctl device list`. The setup command does not guess the device path because different modules expose different serial ports.

## Profile Download

```bash
ipadctl profile download --activation-code 'LPA:1$smdp.example.com$MATCHINGID'
ipadctl task get task-1
```

Use the returned task id from the download response instead of the example `task-1` value.

## Configuration Checks

```bash
ipadctl platform check
ipadctl config show
ipadctl config check
ipadctl doctor
```

Use `--config <path>` when validating a non-default config file. Use `--socket <path>` with `doctor` when the daemon is running on a test socket.

## Optional Debug Console

The GUI debug console is optional. It is useful during integration and support, but headless devices can use the CLI commands in this guide directly.

Start with CLI diagnostics:

```bash
ipadctl platform check
ipadctl config check
ipadctl doctor
```

See `tools/debug-console/README.md` for the planned GUI-assisted flow and SSH forwarding model.

## Compatibility Bootstrap

On non-Ubuntu or embedded Linux variants, preview the deployment steps before installing service files:

```bash
ipadctl platform check
ipadctl bootstrap check --mock
ipadctl bootstrap check --real --at-device /dev/ttyUSB2
```

Use `packaging/openrc/`, `packaging/sysvinit/`, or `packaging/manual/` when `platform check` reports a degraded non-systemd platform.

## Troubleshooting

```bash
journalctl -u ipad-managerd --no-pager
sudo tail -n 50 /var/lib/ipad-manager/tasks.jsonl
sudo tail -n 50 /var/log/ipad-manager/audit.jsonl
```

Common next actions:

- Missing daemon socket: restart `ipad-managerd` or check `socket_path`.
- Non-systemd platform: run `ipadctl bootstrap check --mock` or choose a matching packaging profile.
- Missing worker: install `ipad-sdk-worker` or update `worker_path`.
- Serial permission failure: add the service user to `dialout` or install matching udev rules.
- Missing AT device: run `ipadctl device list` after the module is connected.

For a symptom-by-symptom matrix, see `docs/troubleshooting-guide.md`.
