# IPAd Manager Real Device Acceptance

Use this checklist when validating IPAd Manager on one Linux device with a real module, real eUICC path, and the submitted IPAd SDK.

Do not mark this checklist as passed unless command output has been saved in `docs/templates/real-device-evidence.md` or an equivalent project record.

## 1. Device Identity

Record:

- Device model.
- Linux distribution or image name.
- Kernel version.
- CPU architecture.
- Module model and firmware version.
- eUICC or SIM path.
- IPAd Manager commit from `VERSION` or `git rev-parse --short HEAD`.

Commands:

```bash
uname -a
ipadctl platform check
```

Pass criteria:

- Platform is `supported` or documented as `degraded` with an accepted service profile.
- Architecture matches the release package.

## 2. Config and Device Readiness

```bash
ipadctl device list
ipadctl bootstrap check --real --at-device /dev/ttyUSB2
sudo ipadctl setup --real --at-device /dev/ttyUSB2
ipadctl config show
ipadctl config check
```

Pass criteria:

- Selected AT device appears in `device list`.
- `config check` passes or has only accepted environment warnings.
- The service user can read and write the selected serial node.

## 3. Daemon and Worker Readiness

Restart with the platform-specific command from `ipadctl bootstrap check`.

Systemd example:

```bash
sudo systemctl restart ipad-managerd
ipadctl doctor
ipadctl status
```

OpenRC example:

```bash
sudo rc-service ipad-managerd restart
ipadctl doctor
ipadctl status
```

Pass criteria:

- `doctor` reports daemon socket reachable.
- `status` reports daemon running.
- No repeated worker restart loop appears in service logs.

## 4. SDK Lifecycle

```bash
ipadctl sdk init
ipadctl sdk status
```

Pass criteria:

- `sdk init` returns a JSON-RPC result or a documented SDK-specific failure.
- `sdk status` reports initialized state when SDK init succeeds.

## 5. Profile Download Task

```bash
ipadctl profile download --activation-code 'LPA:1$smdp.example.com$MATCHINGID'
ipadctl task get <task-id>
```

Pass criteria:

- Download returns a task id.
- `task get` returns a stable terminal state.
- Any failure includes an actionable SDK or network error.

## 6. Traceability Evidence

Collect:

```bash
journalctl -u ipad-managerd --no-pager
sudo tail -n 100 /var/lib/ipad-manager/tasks.jsonl
sudo tail -n 100 /var/log/ipad-manager/audit.jsonl
```

Pass criteria:

- Task store records the profile operation.
- Audit log records operator-visible actions.
- Sensitive fields such as activation code are not copied into public bug reports.

## 7. Sign-Off

Acceptance can be marked passed when:

- Platform/config/device checks are recorded.
- Daemon and worker lifecycle is recorded.
- SDK lifecycle is recorded.
- At least one profile operation task is recorded.
- Known limitations are written in the evidence file.
