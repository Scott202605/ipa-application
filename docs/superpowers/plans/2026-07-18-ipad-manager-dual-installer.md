# IPAd Manager Dual Installer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and verify one versioned IPAd Manager Linux payload delivered as an Ubuntu amd64 `.deb` and embedded in a Windows x64 `.exe` installer.

**Architecture:** CMake installs Manager against the gated private SDK into a staging root. A deterministic Debian packager creates the canonical product artifact; health and diagnostic commands validate it after installation. An Inno Setup bootstrapper embeds that exact `.deb`, prepares an explicitly named WSL `Ubuntu`, installs the package through `apt`, and never unregisters a distribution.

**Tech Stack:** C11, CMake/CTest, POSIX shell, Debian `dpkg-deb`/`apt`, Python 3 standard library, PowerShell 5+, Inno Setup 6, WSL2/WSLg.

## Global Constraints

- First release targets Ubuntu amd64 and Windows x64 with WSL2 distribution name exactly `Ubuntu`.
- Missing WSL, Ubuntu, and Linux dependencies may be downloaded from the network.
- The `.deb` is the only canonical application payload; the Windows installer embeds it unchanged.
- Manager must load `/usr/lib/ipad-manager/libipa.so` without source paths or `LD_LIBRARY_PATH`.
- Existing WSL distributions must never be unregistered, overwritten, imported over, or deleted.
- All WSL calls explicitly select `--distribution Ubuntu --user root`.
- Existing public SDK headers, SONAME `libipa.so`, and the 32-symbol ABI baseline must not change.
- Profile download, enable, disable, and delete remain documented as `eNotImpl`.
- User configuration is retained by remove and deleted only by purge.
- Logs and diagnostics must redact secrets.

---

## File Map

- `ipad_host_app/CMakeLists.txt`: relocatable Manager build/install contract and private SDK RPATH.
- `ipad_host_app/src/main.c`: headless version/help/health-safe command behavior.
- `packaging/linux/ipad-manager-health`: installed-product health checks.
- `packaging/linux/ipad-manager-diagnostics`: redacted diagnostic export.
- `packaging/linux/ipad-manager-launch`: GUI launcher with actionable WSLg/display errors.
- `packaging/linux/ipad-manager.desktop`: Linux desktop integration.
- `packaging/linux/config.json`: shipped default configuration.
- `packaging/linux/build-deb.sh`: deterministic staging and Debian package creation.
- `packaging/linux/debian/control.in`: Debian metadata and runtime dependencies.
- `packaging/linux/debian/conffiles`: configuration retention declaration.
- `packaging/linux/debian/postinst`, `prerm`, `postrm`: lifecycle integration restricted to this product.
- `packaging/windows/IPAd-Manager.iss`: Windows installer definition embedding the canonical `.deb`.
- `packaging/windows/install-ipad-manager.ps1`: WSL detection, installation, health check, and logging.
- `packaging/windows/uninstall-ipad-manager.ps1`: remove/purge product without modifying WSL.
- `packaging/windows/launch-ipad-manager.cmd`: explicit Ubuntu/WSLg launcher.
- `packaging/build-release.sh`: top-level build orchestrator and SHA-256 manifest.
- `packaging/tests/`: unit, policy, package-layout, install, and launcher tests.
- `docs/installation/Ubuntu.md`, `docs/installation/Windows.md`, `docs/installation/Capability_Matrix.md`: operator documentation.

### Task 1: Establish Package Policy Tests

**Files:**
- Create: `packaging/tests/test_packaging_policy.py`
- Create: `packaging/tests/fixtures/expected_deb_layout.txt`

**Interfaces:**
- Consumes: repository files and future package scripts as text.
- Produces: executable policy tests used by every later task.

- [ ] **Step 1: Write failing tests for immutable delivery rules**

```python
def test_windows_scripts_always_select_ubuntu_root(repo):
    text = (repo / "packaging/windows/install-ipad-manager.ps1").read_text()
    assert "--distribution" in text
    assert "Ubuntu" in text
    assert "--user" in text
    assert "root" in text

def test_windows_scripts_never_unregister_or_delete_distro(repo):
    text = "\n".join(p.read_text() for p in (repo / "packaging/windows").glob("*"))
    lowered = text.lower()
    assert "wsl --unregister" not in lowered
    assert "wsl.exe --unregister" not in lowered

def test_deb_uses_private_sdk_path(repo):
    expected = (repo / "packaging/tests/fixtures/expected_deb_layout.txt").read_text()
    assert "/usr/lib/ipad-manager/libipa.so" in expected
    assert "/usr/lib/libipa.so" not in expected
```

- [ ] **Step 2: Run tests and verify RED**

Run: `python3 -m unittest packaging.tests.test_packaging_policy -v`

Expected: FAIL because the packaging files and fixtures do not exist.

- [ ] **Step 3: Add the repository fixture and test loader**

Fixture content:

```text
/etc/ipad-manager/config.json
/usr/bin/ipad-manager
/usr/bin/ipad-manager-diagnostics
/usr/bin/ipad-manager-health
/usr/lib/ipad-manager/libipa.so
/usr/share/applications/ipad-manager.desktop
/usr/share/ipad-manager/BUILD_METADATA.txt
/usr/share/ipad-manager/DEPENDENCIES.lock.txt
/usr/share/ipad-manager/install-manifest.json
```

The test module resolves `repo = Path(__file__).resolve().parents[2]` and uses only Python standard library `unittest`.

- [ ] **Step 4: Re-run tests**

Run: `python3 -m unittest packaging.tests.test_packaging_policy -v`

Expected: fixture test passes; Windows-script tests remain skipped only when their task files do not yet exist, with explicit skip messages.

- [ ] **Step 5: Commit**

```bash
git add packaging/tests
git commit -m "test: define installer delivery policy"
```

### Task 2: Make Manager Relocatable and Headless-Verifiable

**Files:**
- Modify: `ipad_host_app/CMakeLists.txt`
- Modify: `ipad_host_app/src/main.c`
- Create: `packaging/tests/test_manager_cli.py`

**Interfaces:**
- Consumes: `IPAD_SDK_ROOT`, exact `IPA_LIBRARY`, and `IPAD_PRIVATE_LIBDIR` CMake cache values.
- Produces: installed `/usr/bin/ipad-manager` with RUNPATH `$ORIGIN/../lib/ipad-manager`, plus `--version` and `--check-config PATH` commands that do not initialize GTK.

- [ ] **Step 1: Write failing CLI contract tests**

```python
def test_help_and_version_do_not_require_display(self):
    self.assertEqual(run_manager("--help", env={"DISPLAY": ""}).returncode, 0)
    version = run_manager("--version", env={"DISPLAY": ""})
    self.assertEqual(version.returncode, 0)
    self.assertRegex(version.stdout, r"IPAd Manager 1\.1\.0")

def test_invalid_config_fails_without_opening_gui(self):
    result = run_manager("--check-config", self.invalid_config, env={"DISPLAY": ""})
    self.assertNotEqual(result.returncode, 0)
```

- [ ] **Step 2: Build and run the focused test to verify RED**

Run: `python3 -m unittest packaging.tests.test_manager_cli -v`

Expected: FAIL because `--version` and `--check-config` are not implemented.

- [ ] **Step 3: Implement minimal pre-GTK CLI handling**

Add argument handling before `gtk_init_check`:

```c
if (strcmp(argv[i], "--version") == 0) {
    printf("IPAd Manager 1.1.0\n");
    return EXIT_SUCCESS;
}
if (strcmp(argv[i], "--check-config") == 0) {
    if (i + 1 >= argc) return EXIT_FAILURE;
    return config_init(argv[++i]) == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
```

Set the installed target name and private RPATH:

```cmake
set_target_properties(ipad_host_app PROPERTIES
    OUTPUT_NAME ipad-manager
    INSTALL_RPATH "$ORIGIN/../lib/ipad-manager"
    BUILD_WITH_INSTALL_RPATH OFF)
install(TARGETS ipad_host_app RUNTIME DESTINATION bin)
```

- [ ] **Step 4: Rebuild and verify GREEN**

Run: `python3 -m unittest packaging.tests.test_manager_cli -v`

Expected: all CLI tests pass without DISPLAY.

- [ ] **Step 5: Verify linked SDK source and warnings**

Run: `readelf -d <build>/ipad-manager | grep -E 'NEEDED|RUNPATH'`

Expected: `libipa.so` in NEEDED and `$ORIGIN/../lib/ipad-manager` in installed RUNPATH; build output has no new warnings.

- [ ] **Step 6: Commit**

```bash
git add ipad_host_app/CMakeLists.txt ipad_host_app/src/main.c packaging/tests/test_manager_cli.py
git commit -m "build: make Manager relocatable and headless-verifiable"
```

### Task 3: Add Installed Health and Diagnostic Tools

**Files:**
- Create: `packaging/linux/ipad-manager-health`
- Create: `packaging/linux/ipad-manager-diagnostics`
- Create: `packaging/tests/test_health_tool.py`
- Create: `packaging/tests/test_diagnostics_redaction.py`

**Interfaces:**
- Consumes: optional `IPAD_ROOT` for tests, installed manifest, Manager, SDK, metadata, and configuration.
- Produces: `ipad-manager-health [--json]` and `ipad-manager-diagnostics OUTPUT.tar.gz`.

- [ ] **Step 1: Write failing behavior tests**

```python
def test_health_json_reports_required_checks(self):
    result = run_health(self.root, "--json")
    data = json.loads(result.stdout)
    self.assertEqual(data["schema_version"], 1)
    self.assertEqual({c["id"] for c in data["checks"]},
                     {"files", "manifest", "architecture", "linkage", "abi", "config", "gui"})

def test_diagnostics_redacts_secrets(self):
    archive = run_diagnostics(config={"password": "secret", "activation_code": "LPA:1$secret"})
    text = unpack_text(archive)
    self.assertNotIn("secret", text)
    self.assertIn("<redacted>", text)
```

- [ ] **Step 2: Run focused tests and verify RED**

Run: `python3 -m unittest packaging.tests.test_health_tool packaging.tests.test_diagnostics_redaction -v`

Expected: FAIL because both commands are absent.

- [ ] **Step 3: Implement health checks with stable result schema**

Use a POSIX shell front end and Python standard library JSON emission. Each check returns `pass`, `warn`, or `fail`; missing GUI/hardware is `warn`, while missing payload, bad hash, wrong SDK resolution, ABI drift, or invalid config is `fail`. `--json` writes only JSON to stdout.

- [ ] **Step 4: Implement redacted diagnostics**

Copy only product metadata, health JSON, dpkg status, sanitized configuration, and product logs. Replace values for case-insensitive keys matching `password`, `secret`, `token`, `activation_code`, `confirmation_code`, `private_key`, and `client_key` with `<redacted>`.

- [ ] **Step 5: Re-run focused tests**

Run: `python3 -m unittest packaging.tests.test_health_tool packaging.tests.test_diagnostics_redaction -v`

Expected: all tests pass and archive inspection contains no seeded secrets.

- [ ] **Step 6: Commit**

```bash
git add packaging/linux packaging/tests
git commit -m "feat: add installed health and diagnostic tools"
```

### Task 4: Build the Canonical Debian Package

**Files:**
- Create: `packaging/linux/build-deb.sh`
- Create: `packaging/linux/debian/control.in`
- Create: `packaging/linux/debian/conffiles`
- Create: `packaging/linux/debian/postinst`
- Create: `packaging/linux/debian/prerm`
- Create: `packaging/linux/debian/postrm`
- Create: `packaging/linux/ipad-manager-launch`
- Create: `packaging/linux/ipad-manager.desktop`
- Create: `packaging/linux/config.json`
- Create: `packaging/tests/test_deb_package.py`

**Interfaces:**
- Consumes: gated SDK Release build directory, Manager source, Git commit, package version, and `SOURCE_DATE_EPOCH`.
- Produces: `dist/ipad-manager_<version>_amd64.deb`, `install-manifest.json`, and package-local checksums.

- [ ] **Step 1: Write failing package-layout tests**

```python
def test_deb_contains_exact_required_layout(self):
    files = set(dpkg_contents(self.deb))
    for expected in EXPECTED_LAYOUT:
        self.assertIn("." + expected, files)

def test_control_declares_runtime_dependencies(self):
    control = dpkg_control(self.deb)
    for dep in ("libgtk-3-0", "libcurl4", "libssl3", "libpcsclite1", "libpaho-mqtt1.3"):
        self.assertIn(dep, control["Depends"])

def test_config_is_a_conffile(self):
    self.assertIn("/etc/ipad-manager/config.json", dpkg_conffiles(self.deb))
```

- [ ] **Step 2: Run package tests and verify RED**

Run: `python3 -m unittest packaging.tests.test_deb_package -v`

Expected: FAIL because no `.deb` exists.

- [ ] **Step 3: Implement deterministic staging and package metadata**

`build-deb.sh` must use `set -eu`, reject non-amd64 hosts, accept `--sdk-build`, `--output`, and `--version`, build Manager with the exact SDK path, install into a clean staging root, copy private `libipa.so`, generate sorted SHA-256 entries, set normalized ownership and timestamps, and invoke `dpkg-deb --root-owner-group --build`.

Control template:

```text
Package: ipad-manager
Version: @VERSION@
Architecture: amd64
Maintainer: IPAd Manager Team
Depends: libgtk-3-0, libcurl4, libssl3, libpcsclite1, libpaho-mqtt1.3
Section: utils
Priority: optional
Description: IPAd Manager with private ABI-locked IPAd SDK
```

- [ ] **Step 4: Build package and verify GREEN**

Run: `packaging/linux/build-deb.sh --sdk-build ipa_sdk_pc/build-release-gates/release --output dist --version 1.1.0+git.$(git rev-parse --short HEAD)`

Expected: `.deb` created and all package tests pass.

- [ ] **Step 5: Verify reproducibility**

Run the build twice with identical `SOURCE_DATE_EPOCH`; compare `sha256sum`.

Expected: hashes are identical.

- [ ] **Step 6: Commit**

```bash
git add packaging/linux packaging/tests
git commit -m "build: produce canonical IPAd Manager deb"
```

### Task 5: Test Install, Upgrade, Remove, and Purge

**Files:**
- Create: `packaging/tests/deb_lifecycle.sh`
- Create: `packaging/tests/deb_upgrade.sh`

**Interfaces:**
- Consumes: `.deb`, optional previous `.deb`, and a disposable Ubuntu test root/container.
- Produces: machine-readable lifecycle test log and zero exit only when package semantics pass.

- [ ] **Step 1: Write failing lifecycle assertions**

```sh
apt-get install -y "$deb"
ipad-manager-health --json | python3 -c 'import json,sys; assert not any(x["status"] == "fail" for x in json.load(sys.stdin)["checks"])'
printf '%s\n' '{"user_marker":true}' >> /etc/ipad-manager/config.json
apt-get remove -y ipad-manager
test -f /etc/ipad-manager/config.json
apt-get install -y "$deb"
grep -q 'user_marker' /etc/ipad-manager/config.json
apt-get purge -y ipad-manager
test ! -e /etc/ipad-manager/config.json
```

- [ ] **Step 2: Run on a disposable Ubuntu root and verify RED**

Expected: lifecycle fails until maintainer scripts and conffile behavior are correct.

- [ ] **Step 3: Correct only package lifecycle defects**

Maintainer scripts may create `/var/log/ipad-manager`, refresh desktop databases when available, and remove empty product-owned directories on purge. They must not modify WSL or non-product files.

- [ ] **Step 4: Re-run lifecycle and upgrade tests**

Expected: install, repeat install, upgrade, remove, reinstall, and purge all pass; configuration retention matches the spec.

- [ ] **Step 5: Commit**

```bash
git add packaging/linux packaging/tests
git commit -m "test: gate Debian package lifecycle"
```

### Task 6: Implement Safe Windows WSL Bootstrapper

**Files:**
- Create: `packaging/windows/install-ipad-manager.ps1`
- Create: `packaging/windows/uninstall-ipad-manager.ps1`
- Create: `packaging/windows/launch-ipad-manager.cmd`
- Create: `packaging/tests/Test-WindowsInstallerPolicy.ps1`

**Interfaces:**
- Consumes: embedded `.deb` path, SHA-256, distribution `Ubuntu`, `-Resume`, and `-LogPath`.
- Produces: installed Linux package, JSON health result, Windows log, and stable exit codes.

- [ ] **Step 1: Write failing PowerShell policy tests**

```powershell
Describe 'WSL installer safety' {
  It 'always selects Ubuntu and root' {
    $script | Should -Match '--distribution.+Ubuntu'
    $script | Should -Match '--user.+root'
  }
  It 'contains no destructive distribution commands' {
    $script | Should -Not -Match '(?i)--unregister|wslconfig.+/u|Remove-Item.+\\wsl'
  }
  It 'verifies the embedded package hash before WSL installation' {
    $script | Should -Match 'Get-FileHash'
  }
}
```

- [ ] **Step 2: Run policy tests and verify RED**

Run: `Invoke-Pester packaging/tests/Test-WindowsInstallerPolicy.ps1`

Expected: FAIL because scripts do not exist.

- [ ] **Step 3: Implement staged installation with stable exit codes**

Define exit codes for unsupported OS, elevation required, reboot required, WSL failure, Ubuntu failure, hash mismatch, apt failure, and health failure. Discover distributions only through elevated real-user `wsl.exe --list --quiet`; install Ubuntu with supported `wsl.exe --install --distribution Ubuntu`; copy the package through a no-space Windows temporary path; execute a generated Linux wrapper to avoid quote splitting; and call `apt-get install -y` followed by `ipad-manager-health --json`.

- [ ] **Step 4: Implement non-destructive remove/purge and launcher**

Uninstall accepts `-Purge`; default executes `apt-get remove -y ipad-manager`, purge executes only `apt-get purge -y ipad-manager`. Launcher executes `wsl.exe --distribution Ubuntu --user <interactive-user> -- /usr/bin/ipad-manager` and reports missing WSLg/display.

- [ ] **Step 5: Run policy and mocked process-boundary tests**

Run: `Invoke-Pester packaging/tests/Test-WindowsInstallerPolicy.ps1`

Expected: all policy cases pass, including a scan proving no unregister command exists.

- [ ] **Step 6: Commit**

```bash
git add packaging/windows packaging/tests
git commit -m "feat: add safe Windows WSL bootstrapper"
```

### Task 7: Build the Windows EXE Around the Verified DEB

**Files:**
- Create: `packaging/windows/IPAd-Manager.iss`
- Create: `packaging/windows/build-installer.ps1`
- Create: `packaging/tests/Test-WindowsInstallerArtifact.ps1`

**Interfaces:**
- Consumes: verified `.deb`, its expected SHA-256, version, PowerShell scripts, and Inno Setup 6 `ISCC.exe`.
- Produces: `dist/IPAd-Manager-Setup-<version>-x64.exe` containing the exact input `.deb`.

- [ ] **Step 1: Write failing artifact tests**

```powershell
It 'embeds the canonical deb hash in generated installer metadata' {
  $metadata.DebSha256 | Should -Be (Get-FileHash $Deb -Algorithm SHA256).Hash.ToLowerInvariant()
}
It 'is a signed-or-explicitly-unsigned PE x64 installer' {
  Test-Path $Installer | Should -BeTrue
  $metadata.Architecture | Should -Be 'x64'
}
```

- [ ] **Step 2: Run artifact tests and verify RED**

Expected: FAIL because `.iss` and `.exe` do not exist.

- [ ] **Step 3: Implement Inno Setup definition and build wrapper**

The installer requires admin privileges, includes `.deb`, install/uninstall scripts, launcher, hash metadata, license/readme, and start-menu shortcuts. It runs the PowerShell installer hidden but exposes progress and the log path. Reboot-required exit schedules a resume command without repeating completed destructive steps.

- [ ] **Step 4: Build and inspect the EXE**

Run: `powershell -File packaging/windows/build-installer.ps1 -Deb dist/ipad-manager_<version>_amd64.deb -Version <version> -Output dist`

Expected: `ISCC.exe` exits 0 and artifact tests pass. If Inno Setup is absent, the script prints the official install prerequisite and exits with a distinct tool-missing code; installing Inno Setup is an explicit environment preparation action.

- [ ] **Step 5: Commit**

```bash
git add packaging/windows packaging/tests
git commit -m "build: package IPAd Manager Windows installer"
```

### Task 8: Add Unified Release Gate and Documentation

**Files:**
- Create: `packaging/build-release.sh`
- Create: `packaging/tests/run-installer-gates.sh`
- Create: `docs/installation/Ubuntu.md`
- Create: `docs/installation/Windows.md`
- Create: `docs/installation/Capability_Matrix.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: current Git tree, SDK release gates, packaging tools, and optional previous `.deb`.
- Produces: versioned `dist/` directory with both installers, metadata, dependency lock, install manifest, checksums, logs, and operator documentation.

- [ ] **Step 1: Write failing release-manifest test**

```python
required = {
    f"ipad-manager_{version}_amd64.deb",
    f"IPAd-Manager-Setup-{version}-x64.exe",
    "SHA256SUMS",
    "BUILD_METADATA.txt",
    "DEPENDENCIES.lock.txt",
    "install-manifest.json",
}
self.assertTrue(required.issubset({p.name for p in dist.iterdir()}))
```

- [ ] **Step 2: Run release manifest test and verify RED**

Expected: FAIL until the orchestrator copies every required artifact.

- [ ] **Step 3: Implement the unified gate**

The gate runs SDK release tests, Manager CLI tests, packaging policy tests, health/diagnostic tests, deterministic `.deb` build, Debian lifecycle tests, Windows policy tests, Windows EXE build, and artifact inspection. It generates sorted SHA-256 entries last and fails if the tree commit in metadata differs from `git rev-parse HEAD`.

- [ ] **Step 4: Write operator documentation and honest capability matrix**

Document Ubuntu `apt install ./...deb`, Windows wizard usage, upgrade, remove, purge, log locations, WSLg requirements, and recovery commands. Mark each capability as `Available`, `Environment-dependent`, or `Not implemented`; explicitly list the four `eNotImpl` Manager Profile operations.

- [ ] **Step 5: Run full fresh verification**

Run in Ubuntu: `packaging/tests/run-installer-gates.sh`

Run in Windows: `Invoke-Pester packaging/tests/Test-WindowsInstallerPolicy.ps1,packaging/tests/Test-WindowsInstallerArtifact.ps1`

Expected: zero failures. Inspect `.deb` with `dpkg-deb --info` and `dpkg-deb --contents`; inspect Manager with `ldd` and `readelf`; install into a disposable Ubuntu environment and run `ipad-manager-health --json`.

- [ ] **Step 6: Smoke-test the Windows installer**

Test both an existing `Ubuntu` and a Windows test environment without Ubuntu. Verify installation, WSLg launch, repeat install, default uninstall, purge, network failure, health failure, and reboot-resume. Record evidence that Ubuntu remains registered on every failure and uninstall path.

- [ ] **Step 7: Commit**

```bash
git add packaging docs/installation README.md
git commit -m "build: gate unified IPAd Manager installers"
```

## Final Verification Checklist

- [ ] `git diff --check` reports no errors.
- [ ] SDK public header and ABI baselines are unchanged.
- [ ] SDK Release, sanitizer, legacy Manager, and selected Valgrind gates pass.
- [ ] Manager clean Release build has no new warnings.
- [ ] Manager `--help`, `--version`, and `--check-config` run without a display.
- [ ] Installed Manager resolves the private packaged `libipa.so`.
- [ ] Debian package is reproducible and lifecycle tests pass.
- [ ] Health JSON has no failed checks in a clean supported installation.
- [ ] Diagnostic fixture secrets do not appear in the exported archive.
- [ ] Windows scripts contain no distribution deletion/unregister behavior.
- [ ] Windows installer embeds the exact verified `.deb` hash.
- [ ] Existing Ubuntu remains registered after install, failure, and uninstall cases.
- [ ] `SHA256SUMS` verifies every final artifact.
- [ ] Capability documentation identifies all `eNotImpl` operations.
