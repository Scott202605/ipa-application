# Codex WSL Bridge Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a durable project rule that makes Codex access the existing `Ubuntu` distribution through the real Windows user instead of misreading the sandbox account's empty WSL registry.

**Architecture:** A root-level `AGENTS.md` documents the Windows per-user WSL boundary and mandates permission escalation for every WSL call. Verification checks both identities explicitly, runs a Linux probe through the real user, and confirms that only the intended `Ubuntu` WSL 2 distribution remains registered.

**Tech Stack:** Codex project guidance (`AGENTS.md`), Windows PowerShell, `wsl.exe`, Ubuntu 26.04 LTS

## Global Constraints

- Keep the Codex sandbox enabled.
- Reuse the existing distribution named exactly `Ubuntu`.
- Do not install, import, copy, or unregister any WSL distribution.
- All WSL commands from Codex must use permission escalation to run as the real Windows user.
- Permission escalation does not authorize destructive Linux operations.

---

### Task 1: Add and verify the project WSL bridge rule

**Files:**
- Create: `AGENTS.md`
- Reference: `docs/superpowers/specs/2026-07-18-codex-wsl-bridge-design.md`

**Interfaces:**
- Consumes: Codex project-guidance discovery for a root-level `AGENTS.md`.
- Produces: A durable command policy for invoking `wsl.exe --distribution Ubuntu --user root -- ...` through the permission escalation mechanism.

- [ ] **Step 1: Record the failing sandbox-only probe**

Run without permission escalation:

```powershell
whoami.exe
wsl.exe --list --verbose
```

Expected: identity is `milight\codexsandboxoffline`, and `wsl.exe` reports that no distributions are installed. This records the account boundary; it is not evidence that the real user's Ubuntu is missing.

- [ ] **Step 2: Create the root guidance file**

Create `AGENTS.md` with exactly this content:

```markdown
# Project Agent Guidance

## WSL access on Windows

- WSL distributions are registered per Windows user. The normal Codex Windows sandbox runs as `MILIGHT\codexsandboxoffline`, while the project's usable `Ubuntu` distribution is registered under the real user `MILIGHT\61004`.
- Never treat `wsl.exe --list --verbose` from the normal sandbox account as authoritative for the real user's WSL installation.
- Every command that needs WSL, including read-only probes, must request Codex permission escalation and run as the real Windows user.
- Explicitly select the existing distribution and user. For a single Linux program, use `wsl.exe --distribution Ubuntu --user root -- PROGRAM ARGUMENTS`.
- For pipelines, redirection, or multiple Linux commands, use `wsl.exe --distribution Ubuntu --user root -- sh -lc 'LINUX COMMANDS'` and quote it so PowerShell does not expand Linux variables or command substitutions.
- If an escalated call returns `WSL_E_DISTRO_NOT_FOUND`, run escalated `wsl.exe --list --verbose` before proposing repairs. Do not install, import, copy, unregister, or delete a distribution based on the sandbox account's list.
- Permission escalation only changes the Windows identity used for the command. It does not authorize destructive Linux operations, package installation, network access, or system changes beyond the user's request.
```

- [ ] **Step 3: Verify the guidance is complete and unambiguous**

Run:

```powershell
rg -n "codexsandboxoffline|MILIGHT\\61004|--distribution Ubuntu|permission escalation|WSL_E_DISTRO_NOT_FOUND|Do not install" AGENTS.md
```

Expected: matches are returned for the account boundary, explicit distribution, escalation requirement, error handling, and prohibition on duplicate distribution operations.

- [ ] **Step 4: Verify the real-user WSL bridge**

Run with Codex permission escalation:

```powershell
wsl.exe --distribution Ubuntu --user root -- sh -lc 'set -eu; grep -q "^ID=ubuntu$" /etc/os-release; touch /tmp/codex_wsl_bridge_probe; test -f /tmp/codex_wsl_bridge_probe; rm -f /tmp/codex_wsl_bridge_probe; echo WSL_BRIDGE_OK'
```

Expected: exit code `0` and output `WSL_BRIDGE_OK`.

- [ ] **Step 5: Verify the registered distribution set**

Run with Codex permission escalation:

```powershell
wsl.exe --list --verbose
```

Expected: exactly one distribution named `Ubuntu`, marked as the default with `*`, using version `2`.

- [ ] **Step 6: Commit the guidance**

```powershell
git add -- AGENTS.md
git commit -m "chore: document Codex WSL access"
```

Expected: the commit contains only `AGENTS.md`; local installation artifacts such as `install_wsl.ps1` and `wsl-install.log` remain untracked.
