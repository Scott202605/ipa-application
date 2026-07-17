# Project Agent Guidance

## WSL access on Windows

- WSL distributions are registered per Windows user. The normal Codex Windows sandbox runs as `MILIGHT\codexsandboxoffline`, while the project's usable `Ubuntu` distribution is registered under the real user `MILIGHT\61004`.
- Never treat `wsl.exe --list --verbose` from the normal sandbox account as authoritative for the real user's WSL installation.
- Every command that needs WSL, including read-only probes, must request Codex permission escalation and run as the real Windows user.
- Explicitly select the existing distribution and user. For a single Linux program, use `wsl.exe --distribution Ubuntu --user root -- PROGRAM ARGUMENTS`.
- For pipelines, redirection, or multiple Linux commands, use `wsl.exe --distribution Ubuntu --user root -- sh -lc 'LINUX COMMANDS'` and quote it so PowerShell does not expand Linux variables or command substitutions.
- If an escalated call returns `WSL_E_DISTRO_NOT_FOUND`, run escalated `wsl.exe --list --verbose` before proposing repairs. Do not install, import, copy, unregister, or delete a distribution based on the sandbox account's list.
- Permission escalation only changes the Windows identity used for the command. It does not authorize destructive Linux operations, package installation, network access, or system changes beyond the user's request.
