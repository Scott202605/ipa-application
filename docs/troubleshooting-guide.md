# IPAd Manager Troubleshooting Guide

Use this guide after running:

```bash
ipadctl platform check
ipadctl config check
ipadctl doctor
```

## Symptom Matrix

| Symptom | Likely cause | Confirm with | Fix | Evidence to collect |
| --- | --- | --- | --- | --- |
| Build fails on Linux | Missing compiler, CMake, or SDK dependency | `cmake -S . -B build-manager -DIPAD_BUILD_TESTS=ON` | Install build dependencies from `README.md`; retry with `-DIPAD_STRICT_WARNINGS=OFF` only for compatibility diagnosis | Full CMake and compiler output |
| Release package is missing binaries | Manager components were not built before packaging | `ls build-manager/ipadctl/ipadctl build-manager/ipad_managerd/ipad-managerd build-manager/ipad_worker/ipad-sdk-worker` | Run the build commands in `docs/install-delivery.md` before `packaging/make-release-tarball.sh` | `MANIFEST.txt` and build log |
| `platform check` reports `degraded` | Non-systemd or embedded Linux platform | `ipadctl platform check` | Use `ipadctl bootstrap check` and select `packaging/openrc`, `packaging/sysvinit`, or `packaging/manual` | Platform check JSON |
| `config check` reports config parse failure | Invalid JSON or unsupported field value | `ipadctl config show --config <path>` | Regenerate with `sudo ipadctl setup --mock` or `sudo ipadctl setup --real --at-device <path>` | Config file with secrets removed |
| No candidate AT device appears | Module not attached, driver missing, or different device naming | `ipadctl device list` and `ls -l /dev/ttyUSB* /dev/ttyACM* /dev/wwan*` | Reconnect module, load driver, or confirm vendor-specific AT port mapping | `dmesg` excerpt and device list JSON |
| Serial permission denied | Service user lacks device group permission | `ipadctl config check` and `ls -l /dev/ttyUSB2` | Add service user to the owning group such as `dialout`, or install target udev rules | Device node permissions and `groups ipad` |
| `doctor` says daemon socket unreachable | Service not running, wrong socket path, or runtime directory missing | `ipadctl doctor`, `ls -l /run/ipad-manager` | Restart using the command from `ipadctl bootstrap check`; verify `socket_path` | Doctor JSON and service logs |
| Worker missing or not executable | `worker_path` points to absent binary or wrong permissions | `ipadctl config check` | Install `ipad-sdk-worker` to configured path or update `worker_path` | `config check` JSON and `ls -l` output |
| SDK init fails | SDK dependency, module, network, certificate, or eUICC access problem | `ipadctl sdk init`, `ipadctl sdk status`, service logs | Check SDK-specific error mapping, module access, network, and certificate configuration | SDK init response and worker logs |
| `profile download` returns failed task | Activation code, SM-DP+ network, SDK facade, or eUICC failure | `ipadctl profile download --activation-code '<redacted>'` and `ipadctl task get <task-id>` | Verify activation code format, network reachability, and SDK real-mode capability | Task JSON and audit log with activation code redacted |
| Audit or task logs are missing | State/log directories missing or not writable | `ipadctl config check`, `ls -ld /var/lib/ipad-manager /var/log/ipad-manager` | Create directories and grant service user write permission | Directory listing and config check JSON |

## Evidence Bundle

For unresolved issues, collect:

```bash
ipadctl platform check
ipadctl config show
ipadctl config check
ipadctl device list
ipadctl doctor
journalctl -u ipad-managerd --no-pager
sudo tail -n 100 /var/lib/ipad-manager/tasks.jsonl
sudo tail -n 100 /var/log/ipad-manager/audit.jsonl
```

Redact activation codes, ICCIDs when required by policy, network credentials, certificates, and customer identifiers before sharing evidence outside the device team.
