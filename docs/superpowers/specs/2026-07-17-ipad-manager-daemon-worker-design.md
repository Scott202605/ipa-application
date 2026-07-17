# IPAd Manager Daemon/Worker 重构设计

日期：2026-07-17

## 1. 目标与定位

IPAd Manager 的目标是在单个 Linux 设备上，把已提交的 IPAd SDK 产品化为稳定、易用、可追溯的本地能力服务。设备侧开发者不需要直接理解复杂的 SGP.32/IPAd SDK API，也不需要把 SDK 嵌入自己的业务进程；他们通过本机 CLI、GUI 或 JSON-RPC 接口即可完成设备检测、SDK 初始化、Profile 下载、启用、禁用、删除、通知处理、Fallback、应急 Profile 等操作。

本设计不是多设备平台化管理系统。第一阶段明确聚焦单台 Linux 主机、单个当前活动模组/eUICC 通道，架构保留多 transport 和未来多设备扩展点，但不把多设备调度作为首版目标。

核心定位：

```text
IPAd SDK = SGP.32/IPAd 协议能力库
SDK worker = SDK 调用适配与故障隔离进程
IPAd Manager daemon = 产品化管理、任务、状态、配置、审计与恢复层
CLI/GUI = 本机用户操作与调试入口
```

## 2. 总体架构

```text
设备应用 / ipadctl CLI / GTK GUI
        |
        | Unix Domain Socket + JSON-RPC
        v
ipad-managerd
  - API server
  - task state machine
  - config manager
  - audit logger
  - device/transport registry
  - worker supervisor
        |
        | 本地 worker IPC
        v
ipad-sdk-worker
  - links libipa
  - owns SDK runtime context
  - executes blocking SDK calls
  - reports progress/events
        |
        v
IPAd SDK
        |
        v
AT / PCSC / HTTP / MQTT / LwM2M / eUICC / SM-DP+
```

### 2.1 进程职责

`ipad-managerd` 是常驻 systemd 服务。它负责对外接口、任务生命周期、配置、审计、状态持久化、健康检查、worker 重启和权限控制。daemon 不直接持有 SDK 全局状态，不直接执行长时间 SDK 调用。

`ipad-sdk-worker` 是 SDK 执行进程。它链接已提交的 IPAd SDK，负责初始化 SDK、持有 SDK runtime context、执行真实 IPAd 操作，并把阶段进度和结果回报给 daemon。worker 崩溃、卡死或被重启时，daemon 仍可保留任务记录并给出清晰失败原因。

### 2.2 首版进程模型

第一阶段采用单 daemon + 单 worker：

- daemon 启动后读取配置并监听 Unix socket。
- daemon 按需启动 worker，或者在服务启动时预热 worker。
- worker 绑定一个当前活动 transport，例如 AT 或 PC/SC。
- daemon 对长任务做串行互斥，避免同一 eUICC 上并发执行互斥 SDK 流程。

未来可扩展为多 worker，但首版不实现多设备调度。

## 3. 对外接口设计

### 3.1 Unix Socket + JSON-RPC

首版主协议为 Unix Domain Socket 上的 JSON-RPC 2.0。默认 socket：

```text
/run/ipad-manager/ipad-manager.sock
```

权限建议：

```text
owner: root
group: ipad
mode: 0660
```

设备应用、CLI 和 GUI 都通过同一个 JSON-RPC 接口访问 daemon。这样 GUI 不再直接链接 SDK，而是成为 daemon 的客户端。

### 3.2 API 分类

建议首版 API：

```text
system.status
system.health
system.version

device.detect
device.status
device.reset

sdk.init
sdk.deinit
sdk.status

profile.download
profile.enable
profile.disable
profile.delete
profile.list

notification.deliver_all
notification.deliver_one
notification.remove
notification.remove_all

fallback.execute
fallback.return
fallback.report_rollback

emergency.enable
emergency.disable

task.get
task.list
task.cancel
task.logs

trace.set_level
trace.export
```

### 3.3 CLI

`ipadctl` 是首版最重要的人机入口，比 GUI 更适合 SSH、产线脚本和故障排查：

```bash
ipadctl status
ipadctl device detect
ipadctl sdk init
ipadctl profile download --smdp smdp.example.com --matching-id ABCD
ipadctl profile enable --iccid 8986...
ipadctl task get <task_id>
ipadctl logs export --task <task_id>
```

GUI 保留为本机调试控制台，通过同一 JSON-RPC 调用 daemon。

## 4. SDK Worker 设计

### 4.1 Worker 职责

worker 负责：

- 链接 `libipa`；
- 调用 `ipa_init_library()` 和其他已提交 SDK API；
- 管理 SDK 初始化状态；
- 执行 Profile 管理、信息查询、通知、Fallback、应急 Profile 等真实操作；
- 将 SDK 错误码、阶段进度、底层日志转换为 daemon 可理解的结构化事件；
- 在进程边界内隔离 SDK 崩溃、阻塞和内存问题。

worker 不负责：

- 对外暴露 socket；
- 长期保存任务数据库；
- 管理用户权限；
- 做复杂 UI/CLI 表达；
- 决定业务重试策略。

### 4.2 Worker IPC

daemon 与 worker 之间可使用私有 Unix socket 或 stdin/stdout framed JSON。首版推荐私有 Unix socket 或 socketpair，消息格式保持与 JSON-RPC 类似，但只在内部使用。

内部命令示例：

```json
{
  "op": "sdk.profile.download",
  "task_id": "20260717-000001",
  "params": {
    "smdp": "smdp.example.com",
    "matching_id": "ABCD",
    "confirmation_code": null
  }
}
```

worker 阶段事件示例：

```json
{
  "event": "task.progress",
  "task_id": "20260717-000001",
  "stage": "load_bound_profile_package",
  "message": "Loading BPP into eUICC"
}
```

### 4.3 Worker 健康与恢复

daemon 维护 worker 状态：

```text
not_started
starting
ready
busy
unhealthy
crashed
restarting
```

恢复策略：

- worker 启动失败：daemon 标记健康检查失败，保留错误日志。
- worker 崩溃：当前 running task 标记为 `failed_worker_crashed`，daemon 记录 exit code/signal，然后按限流策略重启。
- worker 超时：daemon 先发送 cancel/terminate，超时后 kill，任务标记为 `failed_worker_timeout`。
- SDK 初始化失败：worker 不退出，回报结构化错误，daemon 给出配置/设备建议。

## 5. 任务状态机

Profile 下载、启用、禁用、删除等操作都按 task 管理，不做“一次 RPC 阻塞到底”的裸调用。

状态建议：

```text
created
queued
validating
waiting_device
running
retrying
completed
failed
cancelled
```

Profile 下载阶段建议：

```text
validate_params
ensure_sdk_initialized
check_device_ready
connect_smdp
prepare_download
download_bound_profile_package
load_bound_profile_package
verify_profile
finalize
completed
```

每个 task 保存：

- task_id；
- method；
- client identity；
- 参数摘要和敏感字段脱敏；
- 当前状态；
- 当前阶段；
- SDK 错误码；
- human-readable error；
- started_at / updated_at / finished_at；
- worker pid；
- trace/log 路径。

## 6. 设备与 Transport 适配

第一阶段设计双通道抽象，但只要求先实现当前最可验证的一种 transport。

抽象接口：

```text
transport.detect()
transport.open()
transport.health()
transport.reset()
transport.close()
transport.describe()
```

Transport 类型：

- `at_serial`：`/dev/ttyUSB*`、baudrate、AT command channel、重连恢复；
- `pcsc`：`pcscd`、reader name、card present、APDU channel。

配置示例：

```json
{
  "device": {
    "transport": "at_serial",
    "at_serial": {
      "device": "/dev/ttyUSB2",
      "baudrate": 115200
    },
    "pcsc": {
      "reader": "auto"
    }
  }
}
```

daemon 负责 transport 配置和健康检查策略，worker 负责把 transport 配置应用到 SDK 初始化。

## 7. 配置、权限与部署

### 7.1 配置路径

建议：

```text
/etc/ipad-manager/config.json
/var/lib/ipad-manager/state.db
/var/log/ipad-manager/manager.log
/var/log/ipad-manager/tasks/<task_id>.log
/run/ipad-manager/ipad-manager.sock
```

### 7.2 systemd

服务：

```text
ipad-managerd.service
```

建议能力：

- 自动重启 daemon；
- worker 由 daemon 管理，不单独暴露 systemd 服务；
- service user 可使用 `ipad`；
- udev 规则授予串口/PCSC 访问权限；
- 日志进入 journald，同时落地结构化日志文件。

### 7.3 权限

首版以本机权限为主：

- Unix socket group 控制访问；
- CLI 运行用户必须在 `ipad` group；
- 敏感参数在审计日志中脱敏；
- debug trace 默认关闭。

## 8. 追溯性与日志

分级追溯：

1. 审计日志：默认开启，记录客户端、方法、参数摘要、结果、耗时。
2. 任务日志：默认开启，记录 task 状态机、阶段、错误码和恢复动作。
3. 协议 trace：按需开启，记录 AT/APDU/HTTP/MQTT/LwM2M/ES10 级细节。

日志输出格式建议 JSON Lines，便于后续导出和机器解析：

```json
{
  "ts": "2026-07-17T10:00:00Z",
  "level": "info",
  "task_id": "20260717-000001",
  "component": "worker",
  "stage": "prepare_download",
  "message": "PrepareDownload started"
}
```

错误解释层应把 SDK 错误码映射为用户可操作建议，例如：

```text
SDK error: eSimBusy
解释：eUICC 当前忙，可能存在未完成事务。
建议：等待 30 秒后重试；若持续失败，执行 device.status 并导出 task trace。
```

## 9. GUI 设计原则

GTK GUI 不再直接调用 SDK，而是 JSON-RPC 客户端。首版 GUI 目标是调试和运维，不追求复杂工作台。

主要视图：

- 状态页：daemon、worker、SDK、transport、eUICC 状态；
- Profile 页：列表、下载、启用、禁用、删除；
- 任务页：任务列表、阶段进度、错误详情；
- 日志页：审计/任务日志查看和导出；
- 配置页：transport、SM-DP+/EIM、日志级别。

GUI 不直接持久化业务状态，所有状态来自 daemon。

## 10. 兼容性目标

Linux 目标：

- Ubuntu 22.04+ 优先；
- systemd 环境优先；
- x86_64 与 aarch64 作为主要架构；
- CMake 构建；
- SDK worker 与 daemon 尽量保持 C/C99 或 C11；
- CLI 可用 C 或 Python/Rust 实现，首版建议 C 或 Python 轻量实现，最终随产品部署策略确定。

兼容性原则：

- SDK 头文件和内部实现不要泄露到 daemon/client 公共接口；
- JSON-RPC API 使用稳定的产品级 schema；
- transport 配置中保留 `type` 和 `driver` 字段，便于适配模组差异；
- worker 可以通过编译选项选择 SDK feature，例如 MQTT/LwM2M/PCSC。

## 11. 测试策略

### 11.1 CI 编译

GitHub Actions 保持 Ubuntu 编译：

- SDK build；
- worker build；
- daemon build；
- CLI build；
- host GUI build；
- CMake install dry-run。

### 11.2 单元测试

重点：

- JSON-RPC parser；
- config validation；
- task state machine；
- error mapping；
- transport config parsing；
- log redaction。

### 11.3 集成测试

提供 mock worker 和 mock SDK：

- daemon 不依赖真实 eUICC 即可测试任务状态机；
- worker 可用 mock SDK 模拟 eOk/eBadArg/eSimBusy/timeout/crash；
- CI 中跑 mock integration；
- 真机测试单独作为 manual workflow。

### 11.4 真机验收

真机验收用例：

- SDK 初始化；
- 获取 EID；
- 获取 euiccInfo；
- Profile 下载；
- Profile 启用；
- Profile 禁用；
- Profile 删除；
- worker 崩溃恢复；
- 日志导出和问题定位。

## 12. 阶段任务分解

### Phase 0：架构准备

- 固化目录结构：`managerd/`、`sdk_worker/`、`cli/`、`common/`。
- 定义 JSON-RPC schema 和错误码。
- 定义 task/state 数据结构。
- 定义配置 schema。
- 更新 CMake 顶层构建。

交付物：可编译空骨架、schema 文档、CI 通过。

### Phase 1：daemon + worker 基础链路

- 实现 Unix socket JSON-RPC server。
- 实现 worker supervisor。
- 实现 daemon/worker 内部 IPC。
- 实现 worker heartbeat。
- 实现 `system.status`、`sdk.status`。
- 实现 mock worker，用于 CI。

交付物：CLI 可查询 daemon/worker 状态，worker 可被 daemon 拉起和重启。

### Phase 2：SDK 初始化与设备检测

- 接入配置加载。
- 实现 AT/PCSC transport 配置抽象。
- 实现 `device.detect`、`device.status`。
- worker 接入 `ipa_init_library()`。
- 实现 `sdk.init`、`sdk.deinit`。
- 加入初始化失败错误解释。

交付物：在目标 Linux 设备上可初始化 SDK 并报告设备状态。

### Phase 3：Profile 管理业务闭环

- 实现 `profile.download` task。
- 实现 `profile.enable` task。
- 实现 `profile.disable` task。
- 实现 `profile.delete` task。
- 实现任务阶段进度。
- 实现长任务超时、取消、失败记录。
- 对接已有 IPAd SDK 的 Profile/ES10 能力。

交付物：通过 CLI 在真机上完成 Profile 下载、启用、禁用、删除。

### Phase 4：追溯与运维能力

- 实现审计日志。
- 实现任务日志。
- 实现协议 trace 开关。
- 实现 `task.get`、`task.list`、`task.logs`。
- 实现 `trace.export`。
- 实现敏感字段脱敏。

交付物：每个失败任务可导出定位包。

### Phase 5：GUI 客户端重构

- 移除 GUI 对 SDK wrapper 的直接依赖。
- GUI 改为 JSON-RPC 客户端。
- 实现状态页、Profile 页、任务页、日志页。
- 保留手动响应/模拟功能，但通过 daemon mock mode 暴露。

交付物：GTK GUI 作为 daemon 运维控制台可用。

### Phase 6：打包与部署

- systemd unit。
- 默认配置文件。
- udev/group 权限说明。
- 安装脚本或 CPack 包。
- GitHub Actions install 验证。

交付物：新设备可按文档安装、启动、验证。

## 13. 非目标

首版不做：

- 多设备并发调度；
- 远程 HTTP 管理接口；
- Web UI；
- 云端管理平台；
- 多租户权限；
- 插件市场；
- 对 SDK 协议栈做大规模改写。

这些能力可以作为后续扩展，但不进入第一阶段闭环。

## 14. 主要风险与应对

| 风险 | 影响 | 应对 |
| --- | --- | --- |
| SDK Profile API 尚未完整封装 | Phase 3 受阻 | 先用 worker command 边界固定输入输出；必要时补 SDK adapter，而不是让 daemon 依赖 SDK 内部结构 |
| 底层模组差异大 | 初始化和下载不稳定 | transport config 明确化；日志中记录 transport、driver、设备路径 |
| 长任务阻塞 | 用户体验差 | task 状态机 + worker timeout + cancel/kill |
| worker 崩溃 | 业务中断 | daemon 保留任务状态并可重启 worker |
| 协议 trace 日志过大 | 存储压力 | 默认关闭，按 task 开启，设置大小上限 |
| GUI 与 daemon 状态不一致 | 操作误导 | GUI 全部状态从 daemon 拉取，不本地保存业务状态 |

## 15. 成功标准

第一阶段成功标准：

- `ipad-managerd` 可由 systemd 启动并监听 Unix socket；
- `ipad-sdk-worker` 由 daemon 管理，崩溃后 daemon 不退出；
- `ipadctl status` 能显示 daemon、worker、SDK、transport 状态；
- `ipadctl profile download/enable/disable/delete` 在真机上跑通；
- 每个 Profile 任务都有 task id、阶段记录、错误解释和日志导出；
- GTK GUI 不再直接链接 SDK，而是作为 JSON-RPC 客户端；
- GitHub Actions 能完成 Linux 编译和 mock integration 测试。

