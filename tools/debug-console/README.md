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

## Safety Rules

- The console must be optional.
- The console must not call the IPAd SDK directly.
- The console must show the equivalent `ipadctl` command for write actions.
- The console must redact activation codes, tokens, and credentials.
- The console must bind to `127.0.0.1` by default.
