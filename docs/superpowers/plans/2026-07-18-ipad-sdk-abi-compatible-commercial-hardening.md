# IPAd SDK ABI-Compatible Commercial Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在旧 IPAd Manager 二进制无需重新编译的前提下，将 IPAd SDK 内部实现加固为可管理线程、确定生命周期、严格资源所有权和安全网络默认值的商用共享库。

**Architecture:** 保留现有 C 导出符号、公开类型布局、枚举、错误码、回调和所有权语义，以 ABI Compatibility Facade 转发到私有 `ipa_runtime_t`。Runtime 内部使用生命周期状态机、Task Supervisor、配置快照、eUICC Executor、EIM Session Registry 和统一诊断，迁移期保留 legacy runtime 构建开关。

**Tech Stack:** C11、CMake 3.22.1、pthread、libcurl、Paho MQTT C、Wakaama/LwM2M、AT/serialport、ELF ABI 工具（`nm`/`readelf`）、CTest、ASan/UBSan/TSan、Valgrind、Ubuntu/WSL。

## Global Constraints

- 旧 IPAd Manager 二进制必须能够直接替换并加载新 `libipa.so`。
- 不修改 `ipa_sdk_pc/include/*.h` 的公开函数、类型字段、枚举值和回调声明。
- 不新增默认导出符号；内部符号保持 hidden。
- 不改变 Profile 下载、启用、禁用、删除当前 `eNotImpl` 语义。
- 不修改 `ipad_host_app` 的源码或接口使用方式。
- 初始化仍保持“线程成功启动后返回 0，最终结果通过原事件回调通知”的可观察语义。
- `stop_eim_service()` 和 `ipa_deinit_library()` 继续返回 `void`。
- 所有 WSL 构建和测试命令必须按仓库 `AGENTS.md` 以真实 Windows 用户提权执行，并显式使用 `wsl.exe --distribution Ubuntu --user root -- ...`。
- 每个阶段必须先通过 ABI 基线和旧 Manager 二进制回归，再进入下一阶段。
- 用户现有未跟踪文件和无关工作树变更必须保留。

---

## File Structure

### Public files kept byte-for-byte stable

- Preserve: `ipa_sdk_pc/include/ipa_core.h`
- Preserve: `ipa_sdk_pc/include/ipa.h`
- Preserve: `ipa_sdk_pc/include/ipa_local.h`
- Preserve: `ipa_sdk_pc/include/typedefs.h`
- Preserve: `ipa_sdk_pc/include/es10_typedefs.h`
- Preserve: `ipa_sdk_pc/include/linux_typedefs.h`

### Build and ABI guard files

- Modify: `ipa_sdk_pc/ipa-src/hw/linux/CMakeLists.txt` — library versioning, tests, private sources, sanitizer options and export map。
- Create: `ipa_sdk_pc/ipa-src/hw/linux/ipa.exports.map` — approved public ELF exports。
- Create: `ipa_sdk_pc/tests/abi/abi_layout_probe.c` — records public type sizes, alignment, offsets and enum values。
- Create: `ipa_sdk_pc/tests/abi/check_abi.py` — compares symbols and type layout against baseline。
- Create: `ipa_sdk_pc/tests/abi/baseline/linux-x86_64.symbols.txt` — current exported-symbol baseline。
- Create: `ipa_sdk_pc/tests/abi/baseline/linux-x86_64.layout.json` — current public-layout baseline。
- Create: `ipa_sdk_pc/tests/CMakeLists.txt` — SDK test targets and CTest registration。

### Private runtime files

- Create: `ipa_sdk_pc/ipa-src/hw/linux/runtime/ipa_runtime.h` — private Runtime interface and opaque state。
- Create: `ipa_sdk_pc/ipa-src/hw/linux/runtime/ipa_runtime.c` — lifecycle state machine and Facade target。
- Create: `ipa_sdk_pc/ipa-src/hw/linux/runtime/ipa_task_supervisor.h`
- Create: `ipa_sdk_pc/ipa-src/hw/linux/runtime/ipa_task_supervisor.c`
- Create: `ipa_sdk_pc/ipa-src/hw/linux/runtime/ipa_config_snapshot.h`
- Create: `ipa_sdk_pc/ipa-src/hw/linux/runtime/ipa_config_snapshot.c`
- Create: `ipa_sdk_pc/ipa-src/hw/linux/runtime/ipa_euicc_executor.h`
- Create: `ipa_sdk_pc/ipa-src/hw/linux/runtime/ipa_euicc_executor.c`
- Create: `ipa_sdk_pc/ipa-src/hw/linux/runtime/ipa_eim_registry.h`
- Create: `ipa_sdk_pc/ipa-src/hw/linux/runtime/ipa_eim_registry.c`
- Create: `ipa_sdk_pc/ipa-src/hw/linux/runtime/ipa_diagnostics.h`
- Create: `ipa_sdk_pc/ipa-src/hw/linux/runtime/ipa_diagnostics.c`
- Modify: `ipa_sdk_pc/ipa-src/hw/linux/ipa_core.c` — ABI Facade and legacy runtime switch。
- Modify: `ipa_sdk_pc/ipa-src/hw/linux/ipa_core.h` — remove duplicate public definitions; include canonical public header and keep only private declarations。

### Tests

- Create: `ipa_sdk_pc/tests/runtime/test_runtime_lifecycle.c`
- Create: `ipa_sdk_pc/tests/runtime/test_task_supervisor.c`
- Create: `ipa_sdk_pc/tests/runtime/test_config_snapshot.c`
- Create: `ipa_sdk_pc/tests/runtime/test_eim_registry.c`
- Create: `ipa_sdk_pc/tests/runtime/test_error_cleanup.c`
- Create: `ipa_sdk_pc/tests/integration/legacy_manager_smoke.sh`
- Create: `ipa_sdk_pc/tests/integration/fault_injection_smoke.c`

## Task 1: Freeze the Current ABI and Detect Header Drift

**Files:**
- Create: `ipa_sdk_pc/tests/abi/abi_layout_probe.c`
- Create: `ipa_sdk_pc/tests/abi/check_abi.py`
- Create: `ipa_sdk_pc/tests/abi/baseline/linux-x86_64.symbols.txt`
- Create: `ipa_sdk_pc/tests/abi/baseline/linux-x86_64.layout.json`
- Create: `ipa_sdk_pc/tests/CMakeLists.txt`
- Modify: `ipa_sdk_pc/CMakeLists.txt`

**Interfaces:**
- Consumes: current `libipa.so` and canonical public headers under `ipa_sdk_pc/include/`。
- Produces: reproducible ABI baseline and `check_ipa_abi` test target。

- [ ] **Step 1: Build the untouched shared library in Ubuntu**

Run:

```powershell
wsl.exe --distribution Ubuntu --user root -- sh -lc 'cd "/mnt/c/Users/61004/Documents/IPAd Mamager/ipa_sdk_pc" && cmake -S . -B build-abi-baseline -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=RelWithDebInfo && cmake --build build-abi-baseline -j2'
```

Expected: `build-abi-baseline/ipa-src/hw/linux/libipa.so` exists and links successfully.

- [ ] **Step 2: Capture the current dynamic symbol baseline**

Run:

```powershell
wsl.exe --distribution Ubuntu --user root -- sh -lc 'readelf -Ws "/mnt/c/Users/61004/Documents/IPAd Mamager/ipa_sdk_pc/build-abi-baseline/ipa-src/hw/linux/libipa.so" | awk '$4=="FUNC" && $5=="GLOBAL" && $7!="UND" {print $8}' | sort -u'
```

Expected: sorted list is reviewed, then saved exactly to `baseline/linux-x86_64.symbols.txt`.

- [ ] **Step 3: Write a public-layout probe**

`abi_layout_probe.c` must print JSON using the canonical public headers, including at minimum:

```c
printf("\"cl_config_t\":{\"size\":%zu,\"align\":%zu,\"driver_id\":%zu,\"log_level\":%zu}",
       sizeof(cl_config_t), _Alignof(cl_config_t),
       offsetof(cl_config_t, driver_id), offsetof(cl_config_t, log_level));
printf(",\"ErrCode.eNotImpl\":%d", eNotImpl);
printf(",\"ipa_event_type_t.success\":%d", IPA_EVENT_INITIALIZATION_SUCCESS);
```

Include every public structure field and every public enum constant, not just the examples.

- [ ] **Step 4: Compile and record the layout baseline**

Run:

```powershell
wsl.exe --distribution Ubuntu --user root -- sh -lc 'cc -std=c11 -I "/mnt/c/Users/61004/Documents/IPAd Mamager/ipa_sdk_pc/include" "/mnt/c/Users/61004/Documents/IPAd Mamager/ipa_sdk_pc/tests/abi/abi_layout_probe.c" -o /tmp/ipa_abi_layout && /tmp/ipa_abi_layout'
```

Expected: valid JSON saved as `baseline/linux-x86_64.layout.json`.

- [ ] **Step 5: Make the checker fail on a deliberate mismatch**

Temporarily copy the baseline to `/tmp`, change one size, and run:

```powershell
wsl.exe --distribution Ubuntu --user root -- python3 "/mnt/c/Users/61004/Documents/IPAd Mamager/ipa_sdk_pc/tests/abi/check_abi.py" --library "/mnt/c/Users/61004/Documents/IPAd Mamager/ipa_sdk_pc/build-abi-baseline/ipa-src/hw/linux/libipa.so" --symbols "/tmp/ipa-symbols.txt" --layout "/tmp/ipa-layout.json"
```

Expected: non-zero exit and a precise mismatch such as `cl_config_t.size`.

- [ ] **Step 6: Restore baseline and make the checker pass**

Expected: exit 0, `ABI compatible: symbols and public layouts match baseline`.

- [ ] **Step 7: Record the duplicate-header drift as a failing test**

Add a compile probe that includes `ipa_sdk_pc/include/ipa_core.h` and the internal header in separate translation units and compares generated layout JSON. Expected initial failure because the internal header conditionally adds fields and uses a different event constant.

- [ ] **Step 8: Commit ABI guardrails**

```bash
git add ipa_sdk_pc/tests ipa_sdk_pc/CMakeLists.txt
git commit -m "test: freeze IPAd SDK ABI baseline"
```

## Task 2: Establish Canonical Public Types and Export Policy

**Files:**
- Modify: `ipa_sdk_pc/ipa-src/hw/linux/ipa_core.h`
- Create: `ipa_sdk_pc/ipa-src/hw/linux/ipa.exports.map`
- Modify: `ipa_sdk_pc/ipa-src/hw/linux/CMakeLists.txt`

**Interfaces:**
- Consumes: ABI baseline from Task 1。
- Produces: one canonical public type source and controlled ELF exports without changing the baseline。

- [ ] **Step 1: Make the header-drift test fail against current internal definitions**

Expected: failure reports at least `cl_config_t`, protocol configuration layouts, or `ipa_event_type_t` mismatch.

- [ ] **Step 2: Replace duplicate internal public definitions**

Internal `ipa_core.h` must include the canonical public header by an unambiguous path and only declare private state:

```c
#ifndef IPA_CORE_INTERNAL_H
#define IPA_CORE_INTERNAL_H
#include "../../../include/ipa_core.h"
#include "es9.h"
#include "es10.h"
extern es10_t g_es10;
extern es9_t g_es9;
void notify_app(ipa_event_type_t event_type, void *event_data);
#endif
```

Any internal-only `gsma_data_binding_t` data moves to private configuration snapshots rather than public structs.

- [ ] **Step 3: Run layout and SDK builds**

Expected: header-drift test passes; current SDK build succeeds; ABI checker remains green.

- [ ] **Step 4: Add export version script and SONAME**

Extend `check_abi.py` with `--write-version-script PATH`. It reads every non-empty symbol from `linux-x86_64.symbols.txt`, writes each as an exact `global` entry under `IPA_1.0`, and finishes with `local: *`. Run:

```powershell
wsl.exe --distribution Ubuntu --user root -- python3 "/mnt/c/Users/61004/Documents/IPAd Mamager/ipa_sdk_pc/tests/abi/check_abi.py" --symbols "/mnt/c/Users/61004/Documents/IPAd Mamager/ipa_sdk_pc/tests/abi/baseline/linux-x86_64.symbols.txt" --write-version-script "/mnt/c/Users/61004/Documents/IPAd Mamager/ipa_sdk_pc/ipa-src/hw/linux/ipa.exports.map"
```

Review and commit the expanded exact-name list. The committed map must not contain a wildcard except `local: *`.

CMake sets `VERSION 1.0.0`, `SOVERSION 1`, and links the version script on Linux.

- [ ] **Step 5: Re-run ABI checker**

Expected: no baseline symbol lost or added; SONAME is `libipa.so.1` only if the current deployment loader contract is updated without breaking the existing `libipa.so` symlink. If old binaries require a different SONAME, preserve the observed baseline value instead.

- [ ] **Step 6: Commit canonical ABI surface**

```bash
git add ipa_sdk_pc/ipa-src/hw/linux/ipa_core.h ipa_sdk_pc/ipa-src/hw/linux/ipa.exports.map ipa_sdk_pc/ipa-src/hw/linux/CMakeLists.txt
git commit -m "build: lock IPAd SDK public ABI"
```

## Task 3: Fix Proven Defects Before Refactoring

**Files:**
- Modify: `ipa_sdk_pc/ipa-src/hw/linux/ipa_core.c`
- Create: `ipa_sdk_pc/tests/runtime/test_error_cleanup.c`

**Interfaces:**
- Consumes: current legacy implementation。
- Produces: isolated defect fixes with regression tests and unchanged ABI。

- [ ] **Step 1: Add a failing LwM2M disconnect regression test**

Provide fake MQTT and LwM2M objects. Start only LwM2M, call `stop_eim_service()`, and assert the LwM2M object's disconnect counter becomes 1 while MQTT remains 0.

- [ ] **Step 2: Fix the incorrect protocol object**

```c
static void disconnect_lwm2m_service(void) {
  if (g_esipa_lwm2m) {
    esipa_async__disconnect(&g_esipa_lwm2m->super);
    g_esipa_lwm2m = NULL;
  }
}
```

- [ ] **Step 3: Add a failing driver-destruction regression test**

Initialize with `ES10_DRIVER_AT`, inject a later initialization failure, and assert the AT destructor is invoked exactly once.

- [ ] **Step 4: Synchronize selected driver state**

Store the selected driver immediately after validation and reset it only after destruction. Do not add a public field or enum.

- [ ] **Step 5: Run defect tests, ABI check and build**

Expected: regression tests pass and ABI checker remains green.

- [ ] **Step 6: Commit proven fixes**

```bash
git add ipa_sdk_pc/ipa-src/hw/linux/ipa_core.c ipa_sdk_pc/tests/runtime/test_error_cleanup.c
git commit -m "fix: correct SDK service and driver cleanup"
```

## Task 4: Introduce Configuration Snapshots

**Files:**
- Create: `ipa_sdk_pc/ipa-src/hw/linux/runtime/ipa_config_snapshot.h`
- Create: `ipa_sdk_pc/ipa-src/hw/linux/runtime/ipa_config_snapshot.c`
- Create: `ipa_sdk_pc/tests/runtime/test_config_snapshot.c`
- Modify: `ipa_sdk_pc/ipa-src/hw/linux/CMakeLists.txt`

**Interfaces:**
- Produces private functions `ipa_core_config_snapshot_create/destroy`, `ipa_mqtt_config_snapshot_create/destroy`, `ipa_lwm2m_config_snapshot_create/destroy`, `ipa_http_config_snapshot_create/destroy`。

- [ ] **Step 1: Write failing deep-copy tests**

Create each public config on the stack, snapshot it, mutate and zero the original, then assert all strings and scalars in the snapshot retain original values.

- [ ] **Step 2: Define private snapshot types**

```c
typedef struct {
  es10_driver_type_t driver_type;
  char *driver_id;
  enum LogLevel log_level;
  int initial_refresh_sleep;
  int refresh_max_sleep;
  int esipa_sync_package_retrieval_time;
} ipa_core_config_snapshot_t;
```

Protocol snapshots include private data-binding and security material without changing public layouts.

- [ ] **Step 3: Implement checked allocation and secure destruction**

Every constructor returns `ErrCode` and leaves output `NULL` on failure. Destructors accept `NULL`, clear credentials with a non-optimizable secure-zero helper, then free.

- [ ] **Step 4: Run unit tests under ASan**

Expected: deep-copy and allocation-failure tests pass with no leaks.

- [ ] **Step 5: Commit snapshots**

```bash
git add ipa_sdk_pc/ipa-src/hw/linux/runtime/ipa_config_snapshot.* ipa_sdk_pc/tests/runtime/test_config_snapshot.c ipa_sdk_pc/ipa-src/hw/linux/CMakeLists.txt
git commit -m "feat: add private SDK configuration snapshots"
```

## Task 5: Add Task Supervisor

**Files:**
- Create: `ipa_sdk_pc/ipa-src/hw/linux/runtime/ipa_task_supervisor.h`
- Create: `ipa_sdk_pc/ipa-src/hw/linux/runtime/ipa_task_supervisor.c`
- Create: `ipa_sdk_pc/tests/runtime/test_task_supervisor.c`

**Interfaces:**
- Produces private `ipa_task_supervisor_init/start/request_stop/join_all/destroy`。

- [ ] **Step 1: Write failing lifecycle tests**

Assert task start/end callbacks each fire once, `join_all` waits for completion, stop wakes a blocked fake worker, and thread-create failure leaves zero registered tasks.

- [ ] **Step 2: Implement bounded task registry**

Use named slots for init, MQTT, LwM2M and HTTP. Each slot stores `pthread_t`, running flag, stop flag, task id and worker context. Do not expose this structure publicly.

- [ ] **Step 3: Remove detached-thread behavior from tests**

The supervisor creates joinable threads. Callbacks execute outside the supervisor mutex.

- [ ] **Step 4: Run TSan tests**

Expected: no data race in start, stop, callback registration or join.

- [ ] **Step 5: Commit supervisor**

```bash
git add ipa_sdk_pc/ipa-src/hw/linux/runtime/ipa_task_supervisor.* ipa_sdk_pc/tests/runtime/test_task_supervisor.c
git commit -m "feat: supervise SDK background tasks"
```

## Task 6: Implement Runtime Lifecycle and Compatibility Facade

**Files:**
- Create: `ipa_sdk_pc/ipa-src/hw/linux/runtime/ipa_runtime.h`
- Create: `ipa_sdk_pc/ipa-src/hw/linux/runtime/ipa_runtime.c`
- Create: `ipa_sdk_pc/tests/runtime/test_runtime_lifecycle.c`
- Modify: `ipa_sdk_pc/ipa-src/hw/linux/ipa_core.c`
- Modify: `ipa_sdk_pc/ipa-src/hw/linux/CMakeLists.txt`

**Interfaces:**
- Produces private singleton accessor and lifecycle methods; preserves every existing exported function exactly。

- [ ] **Step 1: Write failing public-behavior tests**

Cover initial state, initialization-start return 0, success/failure callback, duplicate initialization, deinit during initialization, repeated deinit and successful reinitialization.

- [ ] **Step 2: Implement private state machine**

```c
typedef enum {
  IPA_RUNTIME_UNINITIALIZED,
  IPA_RUNTIME_INITIALIZING,
  IPA_RUNTIME_READY,
  IPA_RUNTIME_STOPPING
} ipa_runtime_state_t;
```

`ipa_runtime_t` owns mutex, condition variable, snapshots, supervisor, callbacks, driver and protocol objects.

- [ ] **Step 3: Preserve old asynchronous initialization semantics**

`ipa_init_library()` validates and snapshots synchronously, transitions to INITIALIZING, starts the supervisor task and returns 0. The worker sends the unchanged event callback after releasing locks.

- [ ] **Step 4: Implement deterministic reverse cleanup**

Record construction flags and destroy only constructed resources in reverse order. Initialization failure returns to UNINITIALIZED before callback.

- [ ] **Step 5: Add migration switch**

CMake option `IPA_USE_LEGACY_RUNTIME` defaults `OFF` in development migration builds only; it is private and does not alter installed headers.

- [ ] **Step 6: Run lifecycle tests, TSan and ABI check**

Expected: all pass; no public symbol/layout changes.

- [ ] **Step 7: Commit Runtime Facade**

```bash
git add ipa_sdk_pc/ipa-src/hw/linux/runtime/ipa_runtime.* ipa_sdk_pc/ipa-src/hw/linux/ipa_core.c ipa_sdk_pc/tests/runtime/test_runtime_lifecycle.c ipa_sdk_pc/ipa-src/hw/linux/CMakeLists.txt
git commit -m "refactor: route SDK lifecycle through private runtime"
```

## Task 7: Add eUICC Executor

**Files:**
- Create: `ipa_sdk_pc/ipa-src/hw/linux/runtime/ipa_euicc_executor.h`
- Create: `ipa_sdk_pc/ipa-src/hw/linux/runtime/ipa_euicc_executor.c`
- Create: `ipa_sdk_pc/tests/runtime/test_euicc_executor.c`
- Modify: SDK call sites in `ipa_sdk_pc/ipa-src/ipa.c` only where synchronization is required。

**Interfaces:**
- Produces private serialized execution seam; public `ipa__*` behavior remains unchanged。

- [ ] **Step 1: Write concurrent-call failing test**

Two threads invoke fake ES10 operations; assert the fake driver observes maximum concurrency 1 and each result maps to its original caller.

- [ ] **Step 2: Implement executor mutex and stop checks**

Acquire before ES10/APDU transaction, reject new work while Runtime is stopping, and release before invoking application callbacks.

- [ ] **Step 3: Add TLV length and overflow guards**

Create shared checked-size helpers for addition/multiplication and use them before allocation/copy in touched call paths.

- [ ] **Step 4: Run concurrency, malformed TLV and ABI tests**

Expected: serialized driver access, clean errors, no ABI change.

- [ ] **Step 5: Commit executor**

```bash
git add ipa_sdk_pc/ipa-src/hw/linux/runtime/ipa_euicc_executor.* ipa_sdk_pc/tests/runtime/test_euicc_executor.c ipa_sdk_pc/ipa-src/ipa.c
git commit -m "refactor: serialize SDK eUICC execution"
```

## Task 8: Migrate MQTT, LwM2M and HTTP to EIM Session Registry

**Files:**
- Create: `ipa_sdk_pc/ipa-src/hw/linux/runtime/ipa_eim_registry.h`
- Create: `ipa_sdk_pc/ipa-src/hw/linux/runtime/ipa_eim_registry.c`
- Create: `ipa_sdk_pc/tests/runtime/test_eim_registry.c`
- Modify: `ipa_sdk_pc/ipa-src/hw/linux/ipa_core.c`

**Interfaces:**
- Preserves `connect_*_service()` and `stop_eim_service()`; produces private per-protocol session slots。

- [ ] **Step 1: Write failing per-protocol ownership tests**

Start each fake protocol independently and in combination. Assert stop targets the correct object, repeated stop is safe, and original caller configs may be destroyed immediately after connect returns.

- [ ] **Step 2: Implement independent session slots**

Each slot stores state, snapshot, joinable task, protocol object and last internal error. No protocol may access another slot.

- [ ] **Step 3: Route legacy exports through registry**

Exports validate public parameters, create snapshots, start the correct slot and return the same `ErrCode` category as before.

- [ ] **Step 4: Make stop deterministic and idempotent**

Signal each running protocol, call its protocol-specific disconnect, join its task, destroy object and snapshot, then mark STOPPED. Since the public return is void, cleanup failures are diagnostics only.

- [ ] **Step 5: Run TSan, ASan, repeated start/stop and ABI tests**

Expected: no cross-protocol pointer use, race, leak or ABI drift.

- [ ] **Step 6: Commit registry migration**

```bash
git add ipa_sdk_pc/ipa-src/hw/linux/runtime/ipa_eim_registry.* ipa_sdk_pc/tests/runtime/test_eim_registry.c ipa_sdk_pc/ipa-src/hw/linux/ipa_core.c
git commit -m "refactor: manage SDK EIM sessions deterministically"
```

## Task 9: Add Internal Diagnostics and Secure Logging

**Files:**
- Create: `ipa_sdk_pc/ipa-src/hw/linux/runtime/ipa_diagnostics.h`
- Create: `ipa_sdk_pc/ipa-src/hw/linux/runtime/ipa_diagnostics.c`
- Create: `ipa_sdk_pc/tests/runtime/test_diagnostics.c`
- Modify: touched lifecycle and session files only。

**Interfaces:**
- Produces private error context and ring buffer; public errors remain unchanged。

- [ ] **Step 1: Write redaction and bounded-buffer tests**

Feed EID, ICCID, password, PSK and certificate material. Assert ordinary log output contains redacted tokens and ring buffer overwrites oldest entries at fixed capacity.

- [ ] **Step 2: Implement private error context**

Store module, phase, native code, errno, task, protocol, retryable flag and cleanup status using fixed-size fields and no allocation in error reporting.

- [ ] **Step 3: Add correlation IDs without changing public callbacks**

Generate internal task/transaction IDs and include them in log prefixes only.

- [ ] **Step 4: Run tests and ABI guard**

Expected: sensitive fixtures absent from captured logs; ABI unchanged.

- [ ] **Step 5: Commit diagnostics**

```bash
git add ipa_sdk_pc/ipa-src/hw/linux/runtime/ipa_diagnostics.* ipa_sdk_pc/tests/runtime/test_diagnostics.c ipa_sdk_pc/ipa-src/hw/linux/runtime
git commit -m "feat: add secure SDK runtime diagnostics"
```

## Task 10: Enforce TLS/DTLS and Input Safety

**Files:**
- Modify: `ipa_sdk_pc/ipa-src/profile-assistant-commons/hw/linux/http_client_linux.c`
- Modify: MQTT and LwM2M security setup files identified by `rg "SSL_VERIFY|TLS|DTLS|PSK"`。
- Create: `ipa_sdk_pc/tests/integration/test_tls_policy.c`
- Create: `ipa_sdk_pc/tests/runtime/test_checked_sizes.c`

**Interfaces:**
- Preserves public configuration types; changes unsafe internal defaults to secure failure。

- [ ] **Step 1: Write failing HTTPS verification tests**

Run against a local TLS server with valid certificate, wrong hostname and untrusted certificate. Expected current implementation incorrectly accepts invalid cases.

- [ ] **Step 2: Enable peer and hostname verification**

Set curl verification to enabled, load configured trust material, and fail closed when verification material is invalid. Do not add a public bypass parameter.

- [ ] **Step 3: Verify MQTT TLS and LwM2M DTLS fail closed**

Add equivalent local fixtures for invalid identity/trust. Credentials must come from snapshots and be zeroed after session destruction.

- [ ] **Step 4: Replace unsafe formatting in SDK-owned paths**

Replace touched `sprintf` calls with capacity-aware formatting and verify exact required length before writing.

- [ ] **Step 5: Run TLS, malformed input, ASan/UBSan and ABI tests**

Expected: valid secure connections pass; invalid certificates fail; no memory errors; ABI unchanged.

- [ ] **Step 6: Commit security hardening**

```bash
git add ipa_sdk_pc/ipa-src/profile-assistant-commons/hw/linux ipa_sdk_pc/tests
git commit -m "security: enforce SDK transport verification"
```

## Task 11: Verify the Unmodified Legacy Manager Binary

**Files:**
- Create: `ipa_sdk_pc/tests/integration/legacy_manager_smoke.sh`
- Create: `ipa_sdk_pc/tests/integration/fault_injection_smoke.c`
- Modify: `ipa_sdk_pc/tests/CMakeLists.txt`

**Interfaces:**
- Consumes: preserved old Manager executable and new `libipa.so`。
- Produces: release-blocking binary compatibility evidence。

- [ ] **Step 1: Archive a baseline Manager binary and dependency manifest**

Record executable hash, `readelf -d`, `ldd` and expected `libipa.so` resolution. Do not rebuild this binary for compatibility tests.

- [ ] **Step 2: Run old binary with new library**

Use a controlled `LD_LIBRARY_PATH` pointing only to the new SDK build. Verify process startup and dynamic resolution with `LD_DEBUG=libs` or `ldd`.

- [ ] **Step 3: Execute non-destructive smoke sequence**

Initialize, wait for callback, query EID/EuiccInfo/certs/profiles/EIM configuration, stop services and deinitialize. Hardware-dependent steps must support a fake AT adapter in CI and a real-device lane.

- [ ] **Step 4: Verify old placeholder behavior**

Call the existing Manager profile lifecycle wrapper path and confirm it still receives `eNotImpl`.

- [ ] **Step 5: Run fault injection**

Inject thread creation, allocation, AT disconnect, malformed TLV, TLS failure and deinit-during-init. After every case, a second initialization must succeed.

- [ ] **Step 6: Commit integration gate**

```bash
git add ipa_sdk_pc/tests/integration ipa_sdk_pc/tests/CMakeLists.txt
git commit -m "test: gate SDK releases with legacy Manager binary"
```

## Task 12: Add Release-Quality Build Gates and Remove Migration Risk

**Files:**
- Modify: `ipa_sdk_pc/ipa-src/hw/linux/CMakeLists.txt`
- Modify: `ipa_sdk_pc/tests/CMakeLists.txt`
- Create: `ipa_sdk_pc/tests/run_release_gates.sh`
- Create: `ipa_sdk_pc/DEPENDENCIES.lock.txt`
- Create: `ipa_sdk_pc/BUILD_METADATA.txt.in`

**Interfaces:**
- Produces one reproducible release-gate command and build metadata without changing SDK Interface。

- [ ] **Step 1: Add sanitizer build presets/options**

Create mutually exclusive internal options for ASan+UBSan and TSan. Release builds keep sanitizers off but CI runs both configurations.

- [ ] **Step 2: Add dependency and build metadata generation**

Record compiler, C flags, SGP mode, protocol flags, dependency versions, SONAME and git commit. Do not include secrets or machine-specific credentials.

- [ ] **Step 3: Implement the release gate script**

The script executes in order: clean release build, CTest, ABI comparison, ASan/UBSan tests, TSan tests, Valgrind tests, legacy Manager smoke and package hash generation. It stops on first failure.

- [ ] **Step 4: Run the full release gate twice**

Run once with new Runtime and once with `IPA_USE_LEGACY_RUNTIME=ON`. Expected: both pass ABI and behavior; new Runtime additionally passes deterministic thread/resource assertions.

- [ ] **Step 5: Perform a 24-hour long-run stability test**

Run for 24 continuous hours with repeated init/query/service-stop/deinit cycles. Record memory high-water mark, thread count and failure count. Acceptance is zero leaked threads, zero sanitizer findings, zero unrecoverable states, zero crashes and no monotonic resident-memory growth after the first warm-up hour.

- [ ] **Step 6: Review migration switch removal criteria**

Keep legacy implementation until the new Runtime completes two stable releases. Do not delete it in this plan unless both release records already exist and the user approves a separate deletion plan.

- [ ] **Step 7: Commit release gates**

```bash
git add ipa_sdk_pc/ipa-src/hw/linux/CMakeLists.txt ipa_sdk_pc/tests ipa_sdk_pc/DEPENDENCIES.lock.txt ipa_sdk_pc/BUILD_METADATA.txt.in
git commit -m "build: add commercial SDK release gates"
```

## Final Verification

- [ ] Run `git diff <base>...HEAD -- ipa_sdk_pc/include` and confirm no public header changes.
- [ ] Run the ABI checker against the original baseline and confirm zero symbol/layout differences.
- [ ] Run old Manager binary against the new SDK without recompilation.
- [ ] Run all CTest suites and confirm zero failures.
- [ ] Run ASan/UBSan, TSan and Valgrind gates and confirm zero findings.
- [ ] Confirm `eNotImpl` behavior for unimplemented Profile lifecycle functions.
- [ ] Confirm HTTPS/MQTT TLS/LwM2M DTLS invalid credentials fail closed.
- [ ] Confirm repeated initialization, protocol start/stop and deinitialization leave zero background threads.
- [ ] Confirm build metadata and rollback copy of the previous `.so` are present.
- [ ] Review `git status --short` and ensure unrelated user files or deletions were not staged.
