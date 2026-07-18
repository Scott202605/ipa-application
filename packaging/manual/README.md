# Manual Supervision Profile

Use this profile for Yocto, Buildroot, OpenWrt, containers, or vendor Linux systems where systemd, OpenRC, and SysV init are not the right integration point.

## Runtime Preparation

Create the runtime directories selected by your image policy:

```bash
mkdir -p /run/ipad-manager /var/lib/ipad-manager /var/log/ipad-manager
```

Generate a config:

```bash
ipadctl bootstrap check --mock
sudo ipadctl setup --mock
```

For real AT serial mode:

```bash
ipadctl device list
ipadctl bootstrap check --real --at-device /dev/ttyUSB2
sudo ipadctl setup --real --at-device /dev/ttyUSB2
```

## Foreground Commands

Run the daemon under your supervisor:

```bash
/usr/local/bin/ipad-managerd --config /etc/ipad-manager/config.json
```

Run the worker directly only for smoke tests:

```bash
/usr/local/bin/ipad-sdk-worker --sdk-mode mock
```

## Validation

```bash
ipadctl platform check
ipadctl config check
ipadctl doctor
```

If the daemon socket is not reachable, configure your supervisor to restart `ipad-managerd` and preserve `/run/ipad-manager`.
