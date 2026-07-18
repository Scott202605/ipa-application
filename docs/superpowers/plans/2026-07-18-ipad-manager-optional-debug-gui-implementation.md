# IPAd Manager Optional Debug GUI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an optional GUI-ready debug-console path for IPAd Manager without making GUI components required on headless Linux devices.

**Architecture:** Stabilize the CLI JSON/support-bundle contract first, then add an optional local Web Debug Console under `tools/debug-console/` that consumes `ipadctl --json`. The daemon, worker, and CLI remain the authoritative headless runtime.

**Tech Stack:** C11, CMake 3.22+, POSIX shell, JSON output from `ipadctl`, optional local web console assets, CTest, GitHub Actions Ubuntu/Debian/Alpine compatibility checks.

## Global Constraints

- The GUI must be optional and disabled by default through `IPAD_BUILD_DEBUG_GUI=OFF`.
- Daemon, worker, and CLI must not depend on GUI libraries, browser runtimes, Node.js, Python, GTK, or Qt.
- Every GUI-visible operation must have an equivalent `ipadctl` command or daemon IPC/API path.
- Debug console access must bind to `127.0.0.1` by default.
- Diagnostic and support-bundle tests must not read or write real `/etc`, `/run`, `/var`, or `/dev`.
- Secrets such as activation codes, tokens, and credentials must be redacted in GUI-facing output.
- Headless build and test paths must continue to pass without building GUI components.

---

## File Structure

- `docs/superpowers/specs/2026-07-18-ipad-manager-optional-debug-gui-design.md`: product and architecture design for optional GUI debugging.
- `docs/superpowers/plans/2026-07-18-ipad-manager-optional-debug-gui-implementation.md`: this implementation plan.
- `ipadctl/diagnostics.h`, `ipadctl/diagnostics.c`: extend diagnostic helpers with stable JSON mode and support-bundle orchestration.
- `ipadctl/support_bundle.h`, `ipadctl/support_bundle.c`: support-bundle file generation and redaction helpers.
- `tests/ipadctl/test_support_bundle.c`: validates bundle contents and redaction behavior.
- `tools/debug-console/README.md`: debug-console usage, headless tunneling, and packaging notes.
- `tools/debug-console/static/`: static web UI assets if the console is implemented as a web UI.
- `tools/debug-console/server/`: optional local-only backend that invokes `ipadctl --json`.
- `CMakeLists.txt`: top-level optional build switch for debug GUI packaging hooks.
- `.github/workflows/ubuntu-build.yml`: verifies default headless build still excludes GUI requirements.
- `docs/quick-start.md`, `docs/troubleshooting-guide.md`, `docs/install-delivery.md`: link the optional GUI as a debug aid, not a prerequisite.

---

### Task 1: Define GUI-Ready CLI JSON Contract

**Files:**
- Modify: `ipadctl/diagnostics.h`
- Modify: `ipadctl/diagnostics.c`
- Modify: `ipadctl/ipadctl_main.c`
- Modify: `tests/ipadctl/test_diagnostics.c`
- Modify: `tests/ipadctl/test_platform_command.c`
- Modify: `tests/ipadctl/test_config_commands.c`

**Interfaces:**
- Consumes: existing `ipadctl platform check`, `ipadctl config check`, `ipadctl doctor`, and diagnostic check model.
- Produces:
  - `int diagnostic_write_report_json(const char *summary, const char *next_action, const diagnostic_check_t *checks, size_t check_count, char *out, size_t out_size);`
  - CLI commands accept explicit `--json` while preserving JSON as the default output mode.

- [ ] **Step 1: Add a failing diagnostic report JSON test**

Add to `tests/ipadctl/test_diagnostics.c`:

```c
static int test_report_json_contract(void) {
    diagnostic_check_t checks[2];
    char out[2048];

    diagnostic_check_set(&checks[0], "platform.arch", 1, "info", "architecture is x86_64", "Run: ipadctl doctor");
    diagnostic_check_set(&checks[1], "daemon.socket", 0, "error", "cannot connect to daemon socket", "Run: sudo systemctl restart ipad-managerd");

    if (diagnostic_write_report_json("daemon is not reachable", "Run: sudo systemctl restart ipad-managerd", checks, 2, out, sizeof(out)) != 0) return 1;
    if (!strstr(out, "\"ok\":false")) return 1;
    if (!strstr(out, "\"summary\":\"daemon is not reachable\"")) return 1;
    if (!strstr(out, "\"next_action\":\"Run: sudo systemctl restart ipad-managerd\"")) return 1;
    if (!strstr(out, "\"checks\":[")) return 1;
    if (!strstr(out, "\"name\":\"daemon.socket\"")) return 1;
    return 0;
}
```

Call `test_report_json_contract()` from `main()`.

- [ ] **Step 2: Run the focused test and confirm failure**

Run:

```bash
cmake -S . -B build-manager -DIPAD_BUILD_TESTS=ON
cmake --build build-manager --parallel
ctest --test-dir build-manager -R test_diagnostics --output-on-failure
```

Expected: build or test fails because `diagnostic_write_report_json` is not defined.

- [ ] **Step 3: Add the report writer interface**

Add to `ipadctl/diagnostics.h`:

```c
int diagnostic_write_report_json(const char *summary,
                                 const char *next_action,
                                 const diagnostic_check_t *checks,
                                 size_t check_count,
                                 char *out,
                                 size_t out_size);
```

- [ ] **Step 4: Implement bounded JSON report writing**

Add to `ipadctl/diagnostics.c`:

```c
static int append_text(char *out, size_t out_size, size_t *used, const char *text) {
    int written = snprintf(out + *used, out_size - *used, "%s", text);
    if (written <= 0 || (size_t)written >= out_size - *used) return -1;
    *used += (size_t)written;
    return 0;
}

int diagnostic_write_report_json(const char *summary,
                                 const char *next_action,
                                 const diagnostic_check_t *checks,
                                 size_t check_count,
                                 char *out,
                                 size_t out_size) {
    size_t used = 0;
    size_t i;
    int ok = 1;
    int written;

    if (!out || out_size == 0) return -1;
    for (i = 0; i < check_count; ++i) {
        if (!checks[i].ok && strcmp(checks[i].severity, "warning") != 0) ok = 0;
    }

    written = snprintf(out, out_size,
                       "{\"ok\":%s,\"summary\":\"%s\",\"next_action\":\"%s\",\"checks\":[",
                       ok ? "true" : "false",
                       summary ? summary : "",
                       next_action ? next_action : "");
    if (written <= 0 || (size_t)written >= out_size) return -1;
    used = (size_t)written;

    for (i = 0; i < check_count; ++i) {
        char check_json[512];
        if (diagnostic_write_check_json(&checks[i], check_json, sizeof(check_json)) != 0) return -1;
        if (i > 0 && append_text(out, out_size, &used, ",") != 0) return -1;
        if (append_text(out, out_size, &used, check_json) != 0) return -1;
    }
    if (append_text(out, out_size, &used, "]}") != 0) return -1;
    return 0;
}
```

- [ ] **Step 5: Accept explicit `--json` as a no-op global option**

Update `ipadctl/ipadctl_main.c` argument parsing so these invocations are accepted and return the same JSON as before:

```bash
ipadctl --json platform check
ipadctl --json config check --config /tmp/config.json
ipadctl --json doctor --socket /tmp/missing.sock
```

The implementation should not add table output. `--json` exists to make GUI consumption explicit.

- [ ] **Step 6: Verify and commit**

Run:

```bash
cmake -S . -B build-manager -DIPAD_BUILD_TESTS=ON
cmake --build build-manager --parallel
ctest --test-dir build-manager --output-on-failure
```

Commit:

```bash
git add ipadctl tests/ipadctl
git commit -m "feat: stabilize ipadctl json diagnostics contract"
```

---

### Task 2: Add Redacted Support Bundle Command

**Files:**
- Create: `ipadctl/support_bundle.h`
- Create: `ipadctl/support_bundle.c`
- Modify: `ipadctl/CMakeLists.txt`
- Modify: `ipadctl/ipadctl_main.c`
- Create: `tests/ipadctl/test_support_bundle.c`
- Modify: `tests/ipadctl/CMakeLists.txt`

**Interfaces:**
- Consumes:
  - `ipadctl_config_show()`
  - `ipadctl_config_check()`
  - `ipadctl_platform_check()`
  - `ipadctl_doctor()`
- Produces:
  - `int ipadctl_support_bundle_create(const char *config_path, const char *socket_path, const char *output_dir, char *out, size_t out_size);`
  - CLI: `ipadctl support bundle --output <dir>`

- [ ] **Step 1: Write failing support bundle test**

Create `tests/ipadctl/test_support_bundle.c`:

```c
#include "support_bundle.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void) {
    const char *config = "/tmp/ipadctl-support-config.json";
    const char *out_dir = "/tmp/ipadctl-support-bundle";
    char out[2048];
    FILE *file = fopen(config, "wb");
    if (!file) return 1;
    fputs("{\"sdk_mode\":\"mock\",\"worker_path\":\"/bin/sh\",\"activation_code\":\"LPA:1$secret.example$TOKEN\"}", file);
    fclose(file);

    if (ipadctl_support_bundle_create(config, "/tmp/missing-ipad.sock", out_dir, out, sizeof(out)) != 0) return 1;
    if (!strstr(out, "\"ok\":true")) return 1;
    if (strstr(out, "TOKEN")) return 1;
    unlink(config);
    return 0;
}
```

- [ ] **Step 2: Run focused test and confirm failure**

Run:

```bash
cmake -S . -B build-manager -DIPAD_BUILD_TESTS=ON
cmake --build build-manager --parallel
ctest --test-dir build-manager -R test_support_bundle --output-on-failure
```

Expected: build fails because support-bundle code is not present.

- [ ] **Step 3: Add support bundle interface**

Create `ipadctl/support_bundle.h`:

```c
#ifndef IPADCTL_SUPPORT_BUNDLE_H
#define IPADCTL_SUPPORT_BUNDLE_H

#include <stddef.h>

int ipadctl_support_bundle_create(const char *config_path,
                                  const char *socket_path,
                                  const char *output_dir,
                                  char *out,
                                  size_t out_size);

#endif
```

- [ ] **Step 4: Implement minimal bundle generation**

Create `ipadctl/support_bundle.c`:

```c
#include "support_bundle.h"

#include "config_commands.h"
#include "diagnostics.h"
#include "platform_check.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static void redact_in_place(char *text) {
    char *activation = strstr(text, "activation_code");
    if (activation) {
        char *value = strchr(activation, ':');
        char *end = value ? strchr(value, ',') : NULL;
        if (!end && value) end = strchr(value, '}');
        if (value && end && end > value) {
            memmove(value + 2, "\"<redacted>\"", strlen(end) + 1);
        }
    }
}

static int write_file(const char *path, const char *body) {
    FILE *file = fopen(path, "wb");
    if (!file) return -1;
    fputs(body, file);
    fclose(file);
    return 0;
}

int ipadctl_support_bundle_create(const char *config_path,
                                  const char *socket_path,
                                  const char *output_dir,
                                  char *out,
                                  size_t out_size) {
    char path[512];
    char config_show[4096];
    char config_check[4096];
    char platform[4096];
    char doctor[4096];
    const char *dir = output_dir && output_dir[0] ? output_dir : "/tmp/ipad-manager-support";

    mkdir(dir, 0700);

    ipadctl_config_show(config_path, config_show, sizeof(config_show));
    ipadctl_config_check(config_path, config_check, sizeof(config_check));
    ipadctl_platform_check(NULL, platform, sizeof(platform));
    ipadctl_doctor(config_path, socket_path, doctor, sizeof(doctor));

    redact_in_place(config_show);
    redact_in_place(config_check);
    redact_in_place(platform);
    redact_in_place(doctor);

    snprintf(path, sizeof(path), "%s/config-show.json", dir);
    if (write_file(path, config_show) != 0) return 1;
    snprintf(path, sizeof(path), "%s/config-check.json", dir);
    if (write_file(path, config_check) != 0) return 1;
    snprintf(path, sizeof(path), "%s/platform-check.json", dir);
    if (write_file(path, platform) != 0) return 1;
    snprintf(path, sizeof(path), "%s/doctor.json", dir);
    if (write_file(path, doctor) != 0) return 1;

    snprintf(out, out_size,
             "{\"ok\":true,\"bundle_dir\":\"%s\",\"files\":[\"config-show.json\",\"config-check.json\",\"platform-check.json\",\"doctor.json\"],\"redacted\":true}",
             dir);
    redact_in_place(out);
    return 0;
}
```

- [ ] **Step 5: Route CLI command**

Support:

```bash
ipadctl support bundle --output /tmp/ipad-support
ipadctl --config /tmp/config.json --socket /tmp/missing.sock support bundle --output /tmp/ipad-support
```

Print JSON with `bundle_dir`, `files`, and `redacted`.

- [ ] **Step 6: Wire CMake tests**

Add `support_bundle.c` to `ipadctl_testlib` and the `ipadctl` executable sources. Add `test_support_bundle` to `tests/ipadctl/CMakeLists.txt`.

- [ ] **Step 7: Verify and commit**

Run:

```bash
cmake -S . -B build-manager -DIPAD_BUILD_TESTS=ON
cmake --build build-manager --parallel
ctest --test-dir build-manager --output-on-failure
```

Commit:

```bash
git add ipadctl tests/ipadctl
git commit -m "feat: add ipadctl support bundle"
```

---

### Task 3: Document Optional Debug Console UX and Headless Flow

**Files:**
- Create: `tools/debug-console/README.md`
- Modify: `docs/quick-start.md`
- Modify: `docs/troubleshooting-guide.md`
- Modify: `docs/install-delivery.md`

**Interfaces:**
- Consumes: CLI JSON contract and support-bundle command from Tasks 1 and 2.
- Produces: operator documentation that keeps CLI-first and GUI-optional positioning.

- [ ] **Step 1: Create debug-console README**

Create `tools/debug-console/README.md`:

```markdown
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
```

- [ ] **Step 2: Link from quick start**

Add a short optional section to `docs/quick-start.md`:

```markdown
## Optional Debug Console

The GUI debug console is optional. It is useful during integration and support, but headless devices can use the CLI commands in this guide directly.

Start with CLI diagnostics:

```bash
ipadctl platform check
ipadctl config check
ipadctl doctor
```

See `tools/debug-console/README.md` for the planned GUI-assisted flow and SSH forwarding model.
```

- [ ] **Step 3: Link from troubleshooting and delivery docs**

In `docs/troubleshooting-guide.md`, add the support flow:

```markdown
For GUI-assisted troubleshooting, use the optional debug console when installed. The same evidence can always be collected with:

```bash
ipadctl support bundle --output /tmp/ipad-support
```
```

In `docs/install-delivery.md`, add:

```markdown
The debug console is an optional package. Production headless images may omit it as long as `ipadctl` and the support-bundle command are present.
```

- [ ] **Step 4: Verify and commit**

Run:

```bash
git diff --check
```

Commit:

```bash
git add docs tools/debug-console
git commit -m "docs: describe optional debug console flow"
```

---

### Task 4: Add Optional Build Switch Placeholder Without GUI Dependency

**Files:**
- Modify: `CMakeLists.txt`
- Modify: `.github/workflows/ubuntu-build.yml`
- Create: `tests/cmake/test_debug_gui_default.ps1` or document equivalent shell check in CI.

**Interfaces:**
- Consumes: debug-console documentation.
- Produces:
  - CMake option `IPAD_BUILD_DEBUG_GUI`.
  - Default headless build remains unchanged.

- [ ] **Step 1: Add CMake option**

In top-level `CMakeLists.txt`, add:

```cmake
option(IPAD_BUILD_DEBUG_GUI "Build optional IPAd Manager debug GUI assets" OFF)
```

If no implementation exists yet, add only a status line:

```cmake
if(IPAD_BUILD_DEBUG_GUI)
    message(STATUS "IPAD_BUILD_DEBUG_GUI is enabled; debug console implementation is not built by the core C target")
endif()
```

- [ ] **Step 2: Add CI guard for default-off behavior**

In `.github/workflows/ubuntu-build.yml`, add a check after CMake configure:

```bash
grep -q 'IPAD_BUILD_DEBUG_GUI:BOOL=OFF' build/CMakeCache.txt
```

Use the actual build directory name used by the workflow.

- [ ] **Step 3: Verify and commit**

Run:

```bash
cmake -S . -B build-manager -DIPAD_BUILD_TESTS=ON
cmake --build build-manager --parallel
ctest --test-dir build-manager --output-on-failure
```

Commit:

```bash
git add CMakeLists.txt .github/workflows/ubuntu-build.yml
git commit -m "build: add optional debug gui switch"
```

---

### Task 5: Build Minimal Read-Only Debug Console Prototype

**Files:**
- Create: `tools/debug-console/static/index.html`
- Create: `tools/debug-console/static/styles.css`
- Create: `tools/debug-console/static/app.js`
- Create: `tools/debug-console/server/ipad_debug_console.sh`
- Create: `tools/debug-console/server/sample-status.json`
- Modify: `tools/debug-console/README.md`

**Interfaces:**
- Consumes:
  - `ipadctl --json platform check`
  - `ipadctl --json config check`
  - `ipadctl --json doctor`
  - `ipadctl support bundle --output <dir>`
- Produces:
  - A local-only read-only debug console prototype.

- [ ] **Step 1: Create sample status fixture**

Create `tools/debug-console/server/sample-status.json`:

```json
{
  "ok": false,
  "summary": "daemon is reachable, SDK is not initialized",
  "next_action": "Run: ipadctl sdk init",
  "checks": [
    {"name":"platform.check","ok":true,"severity":"info","message":"platform is supported","suggestion":"Run: ipadctl doctor"},
    {"name":"config.check","ok":true,"severity":"info","message":"config loaded","suggestion":""},
    {"name":"sdk.status","ok":false,"severity":"warning","message":"SDK is not initialized","suggestion":"Run: ipadctl sdk init"}
  ]
}
```

- [ ] **Step 2: Create static HTML**

Create `tools/debug-console/static/index.html`:

```html
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>IPAd Manager Debug Console</title>
  <link rel="stylesheet" href="./styles.css">
</head>
<body>
  <main class="shell">
    <header>
      <h1>IPAd Manager</h1>
      <p id="summary">Loading diagnostics...</p>
    </header>
    <section class="toolbar">
      <button id="refresh">Refresh</button>
      <button id="bundle">Support Bundle</button>
    </section>
    <section id="checks" class="checks"></section>
    <section class="next">
      <h2>Next Action</h2>
      <code id="next-action"></code>
    </section>
  </main>
  <script src="./app.js"></script>
</body>
</html>
```

- [ ] **Step 3: Create CSS**

Create `tools/debug-console/static/styles.css`:

```css
:root {
  color-scheme: light;
  font-family: Arial, sans-serif;
  background: #f4f6f8;
  color: #15202b;
}

body {
  margin: 0;
}

.shell {
  max-width: 1040px;
  margin: 0 auto;
  padding: 24px;
}

header {
  border-bottom: 1px solid #d7dde5;
  margin-bottom: 16px;
}

h1 {
  font-size: 28px;
  margin: 0 0 8px;
}

.toolbar {
  display: flex;
  gap: 8px;
  margin-bottom: 16px;
}

button {
  min-height: 36px;
  padding: 0 14px;
}

.checks {
  display: grid;
  gap: 8px;
}

.check {
  background: #ffffff;
  border: 1px solid #d7dde5;
  border-left-width: 6px;
  padding: 12px;
}

.check.info {
  border-left-color: #238636;
}

.check.warning {
  border-left-color: #b7791f;
}

.check.error {
  border-left-color: #c62828;
}

.next {
  margin-top: 16px;
  background: #ffffff;
  border: 1px solid #d7dde5;
  padding: 12px;
}
```

- [ ] **Step 4: Create JavaScript renderer**

Create `tools/debug-console/static/app.js`:

```javascript
async function loadStatus() {
  const response = await fetch('/api/status');
  const data = await response.json();
  document.getElementById('summary').textContent = data.summary || 'No summary available';
  document.getElementById('next-action').textContent = data.next_action || '';
  const checks = document.getElementById('checks');
  checks.innerHTML = '';
  for (const check of data.checks || []) {
    const item = document.createElement('article');
    item.className = `check ${check.severity || 'info'}`;
    item.innerHTML = `<strong>${check.name}</strong><p>${check.message || ''}</p><small>${check.suggestion || ''}</small>`;
    checks.appendChild(item);
  }
}

document.getElementById('refresh').addEventListener('click', loadStatus);
document.getElementById('bundle').addEventListener('click', async () => {
  const response = await fetch('/api/support-bundle', {method: 'POST'});
  const data = await response.json();
  alert(data.bundle_dir ? `Support bundle: ${data.bundle_dir}` : 'Support bundle failed');
});

loadStatus();
```

- [ ] **Step 5: Add local-only shell backend prototype**

Create `tools/debug-console/server/ipad_debug_console.sh`:

```sh
#!/bin/sh
set -eu

HOST="${IPAD_DEBUG_CONSOLE_HOST:-127.0.0.1}"
PORT="${IPAD_DEBUG_CONSOLE_PORT:-8765}"

case "$HOST" in
  127.0.0.1|localhost) ;;
  *) echo "Refusing to bind non-local host by default: $HOST" >&2; exit 2 ;;
esac

echo "Debug console static files are in tools/debug-console/static"
echo "Bind address: $HOST:$PORT"
echo "Backend implementation should proxy /api/status to ipadctl --json doctor"
```

- [ ] **Step 6: Verify and commit**

Run:

```bash
sh tools/debug-console/server/ipad_debug_console.sh
git diff --check
```

Commit:

```bash
git add tools/debug-console
git commit -m "feat: add optional debug console prototype"
```

---

## Self-Review Notes

- Spec coverage: optional GUI positioning, CLI/API contract, support bundle, documentation, build switch, and prototype are all mapped to tasks.
- Placeholder scan: no unresolved implementation placeholders are used as requirements; the backend prototype explicitly scopes what it will and will not do in this stage.
- Type consistency: new function names are stable across task interfaces and code snippets.
- Scope control: the plan does not add mandatory GUI dependencies, remote fleet management, public web exposure, or direct SDK access from GUI.
- Verification: tasks preserve the existing headless CMake/CTest path and add focused checks for GUI-facing contracts.
