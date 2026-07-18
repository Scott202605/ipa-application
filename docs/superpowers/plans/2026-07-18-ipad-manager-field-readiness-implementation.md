# IPAd Manager Field Readiness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add release packaging, real-device acceptance, and troubleshooting materials so IPAd Manager can be handed to a Linux device team for controlled field validation.

**Architecture:** Keep delivery safe and explicit: generate a tarball into a chosen output directory, provide service profiles as examples, and document real-device acceptance without claiming hardware success. Use CI checks to keep field docs and packaging script present and usable.

**Tech Stack:** POSIX shell, CMake/CTest, Markdown docs, GitHub Actions.

## Global Constraints

- Do not add an automatic privileged installer in this stage.
- Do not write `/usr`, `/etc`, `/run`, or `/var` from packaging tests.
- Keep docs operator-first and command-first.
- Do not claim real hardware validation has passed until evidence exists.
- Preserve existing `ipadctl` command behavior.

---

## Task 1: Release Tarball Builder

**Files:**
- Create: `packaging/make-release-tarball.sh`
- Create: `docs/install-delivery.md`
- Modify: `packaging/README.md`

**Interfaces:**
- Produces:
  - `packaging/make-release-tarball.sh <build-dir> <output-dir>`
  - `docs/install-delivery.md`

- [ ] **Step 1: Add release script**

Create a POSIX shell script that checks for `ipad-managerd`, `ipad-sdk-worker`, and `ipadctl` under the build directory and stages release contents into `<output-dir>/ipad-manager-release`.

- [ ] **Step 2: Add install delivery guide**

Document build, tarball generation, manual install, service profile choice, and validation commands.

- [ ] **Step 3: Verify**

Run:

```bash
sh -n packaging/make-release-tarball.sh
```

After a local build, run:

```bash
packaging/make-release-tarball.sh build-manager /tmp/ipad-release-test
test -f /tmp/ipad-release-test/ipad-manager-release/MANIFEST.txt
```

- [ ] **Step 4: Commit**

```bash
git add packaging docs/install-delivery.md
git commit -m "feat: add release tarball packaging"
```

---

## Task 2: Real Device Acceptance Evidence

**Files:**
- Create: `docs/real-device-acceptance.md`
- Create: `docs/templates/real-device-evidence.md`
- Modify: `docs/real-device-validation.md`
- Modify: `docs/quick-start.md`

**Interfaces:**
- Produces:
  - Field acceptance checklist.
  - Evidence capture template.

- [ ] **Step 1: Add acceptance checklist**

Create a command-first checklist covering platform, config, device list, daemon, SDK lifecycle, profile task, task store, audit log, and sign-off.

- [ ] **Step 2: Add evidence template**

Create a structured Markdown template with placeholders for command outputs and pass/fail decisions.

- [ ] **Step 3: Link docs**

Link the acceptance checklist from quick start and real-device validation.

- [ ] **Step 4: Commit**

```bash
git add docs
git commit -m "docs: add real device acceptance checklist"
```

---

## Task 3: Troubleshooting Manual

**Files:**
- Create: `docs/troubleshooting-guide.md`
- Modify: `docs/quick-start.md`
- Modify: `packaging/README.md`

**Interfaces:**
- Produces:
  - Symptom-to-action matrix for support.

- [ ] **Step 1: Add troubleshooting matrix**

Include symptom, likely cause, confirm command, fix, and evidence columns for common build, install, daemon, SDK, and profile failures.

- [ ] **Step 2: Link guide**

Link troubleshooting from quick start and packaging docs.

- [ ] **Step 3: Commit**

```bash
git add docs packaging/README.md
git commit -m "docs: add troubleshooting guide"
```

---

## Task 4: CI Checks and Final Verification

**Files:**
- Modify: `.github/workflows/ubuntu-build.yml`

**Interfaces:**
- Consumes:
  - `packaging/make-release-tarball.sh`
  - field readiness docs
- Produces:
  - CI checks that protect release package and docs.

- [ ] **Step 1: Extend CI packaging checks**

Add checks for:

```bash
test -f packaging/make-release-tarball.sh
test -f docs/install-delivery.md
test -f docs/real-device-acceptance.md
test -f docs/templates/real-device-evidence.md
test -f docs/troubleshooting-guide.md
grep -q 'ipadctl doctor' docs/troubleshooting-guide.md
grep -q 'profile download' docs/real-device-acceptance.md
sh -n packaging/make-release-tarball.sh
```

- [ ] **Step 2: Add release packaging smoke**

After manager build, run:

```bash
packaging/make-release-tarball.sh build-manager /tmp/ipad-release
test -f /tmp/ipad-release/ipad-manager-release/MANIFEST.txt
```

- [ ] **Step 3: Final local verification**

Run:

```bash
cmake -S . -B build-manager -DIPAD_BUILD_TESTS=ON
cmake --build build-manager --parallel
ctest --test-dir build-manager --output-on-failure
packaging/make-release-tarball.sh build-manager /tmp/ipad-release-test
```

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/ubuntu-build.yml
git commit -m "ci: check field readiness package"
```

---

## Self-Review Notes

- Spec coverage: release package, install delivery, acceptance checklist, evidence template, troubleshooting guide, and CI checks are mapped to tasks.
- Placeholder scan: no unresolved implementation placeholders remain.
- Scope control: no privileged installer or real hardware success claim is included.
