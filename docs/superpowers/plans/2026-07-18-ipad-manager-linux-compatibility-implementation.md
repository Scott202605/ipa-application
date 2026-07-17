# IPAd Manager Linux Compatibility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add platform-aware compatibility diagnostics and deployment guidance so IPAd Manager remains easy to operate across Ubuntu, Debian, Alpine, OpenRC, SysV init, and manual embedded Linux environments.

**Architecture:** Keep `ipadctl` as the single operator entry point. Add focused platform and bootstrap helper modules under `ipadctl/`, reuse the existing diagnostic check object, and keep packaging-specific behavior as data and documentation rather than hardcoded installation side effects.

**Tech Stack:** C11/POSIX, CMake, CTest, GitHub Actions, shell service templates, JSON-first CLI output.

## Global Constraints

- Keep new operator commands JSON-first.
- Do not write `/etc`, `/run`, `/var`, or real `/dev` in tests.
- Do not require `systemctl`, `lsb_release`, `udevadm`, or distro-specific commands in `ipadctl` diagnostics.
- Keep automatic deployment as dry-run guidance only in this stage.
- Preserve the default Ubuntu quick-start path.
- Continue validating with local WSL Ubuntu when available.

---

## File Structure

- Create `ipadctl/platform_check.h`: platform facts, support levels, init enum, and public platform APIs.
- Create `ipadctl/platform_check.c`: platform detection, fake-root capable init detection, JSON report writer.
- Create `ipadctl/bootstrap_commands.h`: bootstrap dry-run command APIs.
- Create `ipadctl/bootstrap_commands.c`: mode parsing and platform-aware checklist generation.
- Modify `ipadctl/diagnostics.c`: call platform checks and make doctor next actions init-aware.
- Modify `ipadctl/ipadctl_main.c`: route `platform check` and `bootstrap check`.
- Modify `ipadctl/CMakeLists.txt`: build new modules into `ipadctl` and `ipadctl_testlib`.
- Add tests under `tests/ipadctl/` for platform, doctor guidance, and bootstrap.
- Add `packaging/openrc/ipad-managerd`, `packaging/sysvinit/ipad-managerd`, and `packaging/manual/README.md`.
- Modify `.github/workflows/ubuntu-build.yml`: add packaging checks and manager-only compatibility build jobs.
- Modify docs: `docs/quick-start.md`, `docs/real-device-validation.md`, and `packaging/README.md`.

---

### Task 1: Platform Detection Model

**Files:**
- Create: `ipadctl/platform_check.h`
- Create: `ipadctl/platform_check.c`
- Modify: `ipadctl/CMakeLists.txt`
- Create: `tests/ipadctl/test_platform_check.c`
- Modify: `tests/ipadctl/CMakeLists.txt`

**Interfaces:**
- Produces:
  - `typedef enum ipadctl_init_system_t`
  - `typedef enum ipadctl_support_level_t`
  - `typedef struct ipadctl_platform_info_t`
  - `void ipadctl_platform_detect(const char *root, ipadctl_platform_info_t *info);`
  - `const char *ipadctl_init_system_name(ipadctl_init_system_t init);`
  - `const char *ipadctl_restart_hint(ipadctl_init_system_t init);`
  - `int ipadctl_platform_report(const char *root, char *out, size_t out_size);`

- [ ] **Step 1: Add failing platform tests**

Create `tests/ipadctl/test_platform_check.c`:

```c
#include "platform_check.h"

#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int touch_file(const char *path) {
    FILE *file = fopen(path, "wb");
    if (!file) return -1;
    fclose(file);
    return 0;
}

int main(void) {
    const char *root = "/tmp/ipadctl-platform-test";
    char out[4096];
    ipadctl_platform_info_t info;

    mkdir(root, 0700);
    mkdir("/tmp/ipadctl-platform-test/run", 0700);
    mkdir("/tmp/ipadctl-platform-test/run/systemd", 0700);
    mkdir("/tmp/ipadctl-platform-test/run/systemd/system", 0700);

    ipadctl_platform_detect(root, &info);
    if (info.init_system != IPADCTL_INIT_SYSTEMD) return 1;
    if (strcmp(ipadctl_init_system_name(info.init_system), "systemd") != 0) return 1;
    if (!strstr(ipadctl_restart_hint(info.init_system), "systemctl")) return 1;
    if (ipadctl_platform_report(root, out, sizeof(out)) != 0) return 1;
    if (!strstr(out, "\"init\":\"systemd\"")) return 1;
    if (!strstr(out, "\"support\":\"supported\"")) return 1;

    rmdir("/tmp/ipadctl-platform-test/run/systemd/system");
    rmdir("/tmp/ipadctl-platform-test/run/systemd");
    mkdir("/tmp/ipadctl-platform-test/sbin", 0700);
    if (touch_file("/tmp/ipadctl-platform-test/sbin/openrc-run") != 0) return 1;

    ipadctl_platform_detect(root, &info);
    if (info.init_system != IPADCTL_INIT_OPENRC) return 1;
    if (!strstr(ipadctl_restart_hint(info.init_system), "rc-service")) return 1;

    unlink("/tmp/ipadctl-platform-test/sbin/openrc-run");
    rmdir("/tmp/ipadctl-platform-test/sbin");
    rmdir("/tmp/ipadctl-platform-test/run");
    rmdir(root);
    return 0;
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
cmake -S . -B build-manager -DIPAD_BUILD_TESTS=ON
cmake --build build-manager --parallel
```

Expected: fails because `platform_check.h` does not exist.

- [ ] **Step 3: Implement platform module**

Create `ipadctl/platform_check.h` and `ipadctl/platform_check.c` with root-injectable init detection, architecture/libc detection, support classification, restart hints, and JSON report output.

- [ ] **Step 4: Wire CMake and tests**

Add `platform_check.c` to `ipadctl_testlib` and `ipadctl`. Add `test_platform_check` to `tests/ipadctl/CMakeLists.txt`.

- [ ] **Step 5: Verify and commit**

Run:

```bash
cmake -S . -B build-manager -DIPAD_BUILD_TESTS=ON
cmake --build build-manager --parallel
ctest --test-dir build-manager --output-on-failure
```

Commit:

```bash
git add ipadctl tests/ipadctl
git commit -m "feat: add platform compatibility detection"
```

---

### Task 2: `ipadctl platform check`

**Files:**
- Modify: `ipadctl/platform_check.h`
- Modify: `ipadctl/platform_check.c`
- Modify: `ipadctl/ipadctl_main.c`
- Modify: `tests/ipadctl/CMakeLists.txt`
- Create: `tests/ipadctl/test_platform_command.c`

**Interfaces:**
- Consumes:
  - `int ipadctl_platform_report(const char *root, char *out, size_t out_size);`
- Produces:
  - `int ipadctl_platform_command(int argc, char **argv);`

- [ ] **Step 1: Add failing command test**

Create `tests/ipadctl/test_platform_command.c` that calls `ipadctl_platform_command()` with `{"platform","check","--root","/tmp/ipadctl-platform-command"}` and verifies JSON includes `platform`, `checks`, and `next_action`.

- [ ] **Step 2: Implement command parser**

Support:

```bash
ipadctl platform check
ipadctl platform check --root <test-root>
```

`--root` is hidden test support and should not be emphasized in user docs.

- [ ] **Step 3: Route command in `ipadctl_main.c`**

Call `ipadctl_platform_command(argc - argi, argv + argi)` before daemon RPC commands.

- [ ] **Step 4: Verify and commit**

Run CMake build and CTest. Commit:

```bash
git add ipadctl tests/ipadctl
git commit -m "feat: add ipadctl platform check"
```

---

### Task 3: Platform-Aware Doctor Guidance

**Files:**
- Modify: `ipadctl/diagnostics.c`
- Modify: `tests/ipadctl/test_doctor.c`

**Interfaces:**
- Consumes:
  - `void ipadctl_platform_detect(const char *root, ipadctl_platform_info_t *info);`
  - `const char *ipadctl_restart_hint(ipadctl_init_system_t init);`
- Produces:
  - `ipadctl_doctor()` output with platform init and init-specific `next_action`.

- [ ] **Step 1: Extend doctor tests**

In `tests/ipadctl/test_doctor.c`, add fake root cases for systemd and OpenRC and verify doctor output suggests `systemctl` or `rc-service`.

- [ ] **Step 2: Add optional doctor root hook**

Add an internal helper:

```c
int ipadctl_doctor_with_root(const char *config_path, const char *socket_path, const char *root, char *out, size_t out_size);
```

Keep public `ipadctl_doctor()` calling it with `/`.

- [ ] **Step 3: Make next action platform-aware**

Use `ipadctl_restart_hint()` for daemon-unreachable output.

- [ ] **Step 4: Verify and commit**

Run CMake build and CTest. Commit:

```bash
git add ipadctl tests/ipadctl
git commit -m "feat: make doctor platform aware"
```

---

### Task 4: Bootstrap Check Guidance

**Files:**
- Create: `ipadctl/bootstrap_commands.h`
- Create: `ipadctl/bootstrap_commands.c`
- Modify: `ipadctl/CMakeLists.txt`
- Modify: `ipadctl/ipadctl_main.c`
- Create: `tests/ipadctl/test_bootstrap_commands.c`
- Modify: `tests/ipadctl/CMakeLists.txt`

**Interfaces:**
- Consumes:
  - `ipadctl_platform_detect()`
  - `ipadctl_restart_hint()`
- Produces:
  - `int ipadctl_bootstrap_check(const char *root, const char *mode, const char *at_device, char *out, size_t out_size);`
  - `int ipadctl_bootstrap_command(int argc, char **argv);`

- [ ] **Step 1: Add failing bootstrap tests**

Test mock and real mode:

- `bootstrap check --mock --root <systemd-root>` includes `setup --mock`, `systemctl`, and `ipadctl doctor`.
- `bootstrap check --real --at-device /dev/ttyUSB2 --root <openrc-root>` includes `setup --real --at-device /dev/ttyUSB2`, `rc-service`, and `ipadctl doctor`.
- Missing `--at-device` in real mode returns usage error `2`.

- [ ] **Step 2: Implement bootstrap check**

Return JSON with `ok`, `mode`, `init`, `steps`, and `next_action`. Do not write any config or service files.

- [ ] **Step 3: Route CLI command**

Support:

```bash
ipadctl bootstrap check --mock
ipadctl bootstrap check --real --at-device /dev/ttyUSB2
```

- [ ] **Step 4: Verify and commit**

Run CMake build and CTest. Commit:

```bash
git add ipadctl tests/ipadctl
git commit -m "feat: add bootstrap compatibility guidance"
```

---

### Task 5: Packaging Profiles and Operator Docs

**Files:**
- Create: `packaging/manual/README.md`
- Create: `packaging/openrc/ipad-managerd`
- Create: `packaging/sysvinit/ipad-managerd`
- Modify: `packaging/README.md`
- Modify: `docs/quick-start.md`
- Modify: `docs/real-device-validation.md`

**Interfaces:**
- Consumes:
  - `ipadctl platform check`
  - `ipadctl bootstrap check`
- Produces:
  - Packaging profile docs used by diagnostics and CI checks.

- [ ] **Step 1: Add packaging profile files**

Add OpenRC and SysV service examples using `/usr/local/bin/ipad-managerd --config /etc/ipad-manager/config.json`. Add manual README with foreground commands for custom supervisors.

- [ ] **Step 2: Update operator docs**

Keep quick start short. Add compatibility section:

```bash
ipadctl platform check
ipadctl bootstrap check --mock
ipadctl bootstrap check --real --at-device /dev/ttyUSB2
```

- [ ] **Step 3: Verify docs and commit**

Run:

```bash
test -f packaging/openrc/ipad-managerd
test -f packaging/sysvinit/ipad-managerd
test -f packaging/manual/README.md
```

Commit:

```bash
git add docs packaging
git commit -m "docs: add linux compatibility packaging profiles"
```

---

### Task 6: CMake Compatibility Options and CI Matrix

**Files:**
- Modify: `CMakeLists.txt`
- Modify: `ipadctl/CMakeLists.txt`
- Modify: `.github/workflows/ubuntu-build.yml`

**Interfaces:**
- Produces:
  - `IPAD_STRICT_WARNINGS` option controlling `-Werror` usage for portability.
  - CI checks for packaging profiles and compatibility commands.

- [ ] **Step 1: Add strict warnings option**

Add top-level option:

```cmake
option(IPAD_STRICT_WARNINGS "Treat compiler warnings as errors" ON)
```

Use it to guard `-Werror` in touched CMake targets where portability jobs may use different compilers.

- [ ] **Step 2: Extend CI packaging checks**

Add checks for:

```bash
test -f packaging/openrc/ipad-managerd
test -f packaging/sysvinit/ipad-managerd
test -f packaging/manual/README.md
grep -q 'ipadctl platform check' docs/quick-start.md
grep -q 'ipadctl bootstrap check' docs/quick-start.md
```

- [ ] **Step 3: Add compatibility build jobs**

Add at least:

- Debian container manager build and tests.
- Alpine container manager build and tests with `IPAD_STRICT_WARNINGS=OFF` if needed.

- [ ] **Step 4: Verify and commit**

Run local Ubuntu CMake build and CTest. Commit:

```bash
git add CMakeLists.txt ipadctl/CMakeLists.txt .github/workflows/ubuntu-build.yml
git commit -m "ci: add linux compatibility build checks"
```

---

## Self-Review Notes

- Spec coverage: platform check, doctor integration, bootstrap guidance, packaging profiles, CMake compatibility, CI matrix, and docs are all mapped to tasks.
- Placeholder scan: no TODO/TBD placeholders are present.
- Type consistency: platform and bootstrap APIs are named consistently across tasks.
- Scope control: automatic cross-distro installation and vendor modem probing are intentionally outside this plan.
- Verification: each code task ends with CMake build and CTest; docs and CI tasks include file checks.
