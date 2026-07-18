# IPAd Manager Debug Console

The debug console is an optional GUI-assisted troubleshooting surface for development, integration, and support. It is not required for production runtime.

## Use Cases

- Inspect platform, config, daemon, worker, SDK, and AT-device readiness.
- Run diagnostics without memorizing every `ipadctl` command.
- Export a redacted support bundle.
- Guide a new operator from first setup to a known-good state.

## Headless Devices

On devices without a GUI, keep using `ipadctl` directly:

```bash
ipadctl platform check
ipadctl config check
ipadctl doctor
ipadctl support bundle --output /tmp/ipad-support
```

When a web debug console backend is installed later, bind it to `127.0.0.1` and use SSH forwarding:

```bash
ssh -L 8765:127.0.0.1:8765 root@target-device
```

Then open `http://127.0.0.1:8765` on the workstation.

## Local Backend

The prototype backend uses Node.js built-in modules only. It is optional and is not part of the core daemon, worker, or CLI build.

```bash
sh tools/debug-console/server/ipad_debug_console.sh
```

Environment variables:

- `IPADCTL_BIN`: path to `ipadctl`; default is `ipadctl`.
- `IPAD_CONFIG`: optional config path passed as `--config`.
- `IPAD_SOCKET`: optional socket path passed as `--socket`.
- `IPAD_SUPPORT_DIR`: support bundle output directory; default is `/tmp/ipad-support`.
- `IPAD_DEBUG_CONSOLE_HOST`: bind host; default is `127.0.0.1`.
- `IPAD_DEBUG_CONSOLE_PORT`: bind port; default is `8765`.

Routes:

- `GET /api/status`: returns `ipadctl --json doctor`.
- `POST /api/support-bundle`: runs `ipadctl --json support bundle --output <dir>`.

If `ipadctl` is not installed, `/api/status` falls back to sample diagnostics so the static UI can still be inspected.

For local UI inspection on a development workstation, open `http://127.0.0.1:8765` after starting the backend. The backend refuses non-local bind addresses by default.

## Safety Rules

- The console must be optional.
- The console must not call the IPAd SDK directly.
- The console must show the equivalent `ipadctl` command for write actions.
- The console must redact activation codes, tokens, and credentials.
- The console must bind to `127.0.0.1` by default.
