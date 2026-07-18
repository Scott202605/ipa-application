# Real Device Evidence

## Run Identity

- Date:
- Tester:
- Device model:
- Linux image:
- Kernel:
- Architecture:
- Module model:
- Module firmware:
- eUICC path:
- IPAd Manager commit:
- IPAd SDK version or commit:

## Platform Check

Command:

```bash
ipadctl platform check
```

Output:

```json
```

Result: PASS / FAIL

## Device Discovery

Command:

```bash
ipadctl device list
```

Output:

```json
```

Selected AT device:

Result: PASS / FAIL

## Bootstrap and Config

Command:

```bash
ipadctl bootstrap check --real --at-device <device>
sudo ipadctl setup --real --at-device <device>
ipadctl config show
ipadctl config check
```

Output:

```json
```

Result: PASS / FAIL

## Daemon and Worker

Command:

```bash
ipadctl doctor
ipadctl status
```

Output:

```json
```

Service log excerpt:

```text
```

Result: PASS / FAIL

## SDK Lifecycle

Command:

```bash
ipadctl sdk init
ipadctl sdk status
```

Output:

```json
```

Result: PASS / FAIL

## Profile Operation

Command:

```bash
ipadctl profile download --activation-code '<redacted>'
ipadctl task get <task-id>
```

Output:

```json
```

Task id:

Result: PASS / FAIL

## Traceability

Task store excerpt:

```json
```

Audit log excerpt:

```json
```

Result: PASS / FAIL

## Known Limitations

- 

## Final Decision

Decision: PASS / FAIL / BLOCKED

Reason:

Next action:
