# IPAd SDK ABI 兼容商用加固设计

## 1. 目标

在不修改现有外部调用、不要求 IPAd Manager 重新编译的前提下，对 IPAd SDK 内部实现进行稳定性、安全性和产品化加固。

交付后的 SDK 共享库必须能够直接替换旧版本 `.so`，旧版 IPAd Manager 二进制继续使用原有函数、公开类型、错误码和回调方式运行。

本设计只调整 SDK Implementation，不修改 Manager，不扩展业务功能，也不改变现有用户文档描述的接口使用方式。

## 2. 当前代码事实与主要风险

当前 SDK 已形成公开 C Interface、ES10/eUICC 执行链、AT 驱动及 MQTT、LwM2M、HTTP 会话能力，但内部实现存在影响商用稳定性的风险：

- 初始化线程使用 `pthread_detach`，反初始化无法可靠等待其结束；
- MQTT、LwM2M、HTTP 线程直接使用调用方传入的配置指针，存在调用方内存失效风险；
- `g_ipa_state`、协议对象、任务回调和事件回调等全局状态缺少统一并发保护；
- LwM2M 停止逻辑误用 `g_esipa_mqtt`；
- 初始化分支读取 `config->es10_driver_selected`，销毁分支依赖另一个未同步的 `es10_driver_selected`；
- 部分 HTTP 实现关闭证书和主机名验证，不满足生产安全要求；
- 当前构建没有明确的 ABI 基线、导出符号白名单、类型布局检查和 SONAME 策略；
- 公开头文件暴露较多结构体，字段大小、顺序、对齐和枚举值均属于 ABI；
- 初始化、停止、失败清理和重复调用的状态语义分散在多个全局函数中；
- 日志、错误码和底层失败上下文之间缺少统一关联；
- 内存所有权规则分散，错误路径和重复调用容易产生泄漏或重复释放。

## 3. 兼容性等级与 ABI 红线

本项目采用二进制兼容等级，而不仅是源码兼容。以下内容必须冻结：

1. 导出符号的名称、类型、可见性和调用约定；
2. 所有现有公开函数的参数、返回类型和参数顺序；
3. 公开结构体的 `sizeof`、`alignof`、字段顺序和 `offsetof`；
4. 公开枚举和错误码的数值；
5. 回调函数类型、参数及可观察调用顺序；
6. 调用方与 SDK 之间的内存分配、所有权和释放规则；
7. 初始化、重复初始化、停止和反初始化的可观察行为；
8. 共享库 SONAME 及旧二进制动态链接所依赖的符号集合；
9. 旧 Manager 所依赖的默认构建功能和运行配置语义。

内部可增加私有类型、静态函数、隐藏符号、线程同步对象、状态和诊断信息，但不得进入公开头文件或默认导出表。

## 4. 总体架构

采用“ABI Compatibility Facade + Private Runtime”结构：

```text
旧 IPAd Manager 二进制
        │ 原符号、原参数、原返回值、原回调
        ▼
ABI Compatibility Facade
        │ 参数验证、配置快照、状态检查、错误映射
        ▼
Private ipa_runtime_t
 ├─ Runtime Lifecycle
 ├─ Task Supervisor
 ├─ Configuration Snapshot
 ├─ eUICC Executor
 ├─ EIM Session Registry
 └─ Resource and Diagnostics
        │
        ▼
ES10 / APDU / AT / MQTT / LwM2M / HTTP / eUICC
```

公开函数继续作为唯一外部 Interface。它们不再直接操作零散全局状态，而是把行为转交给私有 Runtime。

这是一个深层 Module：旧调用方需要理解的 Interface 不增加，线程、状态、资源、安全和错误处理复杂度集中在 Implementation 内，产生更高的 Leverage 和 Locality。

## 5. 内部 Module 设计

### 5.1 ABI Compatibility Facade

现有导出函数组成外部 seam，包括：

- `ipa_init_library()`；
- `ipa_deinit_library()`；
- `ipa_register_task_callbacks()`；
- `connect_mqtt_service()`；
- `connect_lwm2m_service()`；
- `connect_http_service()`；
- `stop_eim_service()`；
- 所有现有 `ipa__*` 和 `ipa_local__*` 函数。

Facade 的职责限定为：

1. 校验旧参数；
2. 将调用方数据转换为内部快照；
3. 调用 Runtime；
4. 把内部结果映射为现有返回值、输出参数或回调。

Facade 不拥有业务线程、网络对象、驱动对象或复杂清理逻辑。

### 5.2 Runtime Lifecycle

私有 `ipa_runtime_t` 维护以下状态：

```text
UNINITIALIZED → INITIALIZING → READY → STOPPING → UNINITIALIZED
```

状态由 mutex 和 condition variable 保护。所有生命周期操作和业务调用都经过统一状态校验。

要求：

- 重复初始化保持旧版可观察行为；
- 初始化中发生反初始化时能够安全取消和等待；
- 失败后必须完整回到 `UNINITIALIZED`；
- 反初始化可重复调用且保持幂等；
- 回调必须在释放 Runtime 内部锁后执行，允许旧调用方重入而不死锁；
- Runtime 不向公开头文件暴露。

### 5.3 Task Supervisor

Task Supervisor 是线程创建、登记、停止和等待的唯一位置。

要求：

- 不再创建无法管理的裸 detached thread；
- 记录初始化、MQTT、LwM2M 和 HTTP 线程句柄；
- 使用取消标志、condition variable 或协议自身停止机制结束任务；
- `ipa_deinit_library()` 在释放依赖前等待线程退出；
- 继续调用现有 task start/end 回调，不改变类型；
- 线程创建失败必须返回旧错误语义并清理已创建资源。

### 5.4 Configuration Snapshot

所有异步任务在启动前深拷贝所需配置：

- 驱动标识和串口配置；
- MQTT Broker、Client ID、用户名、密码、TLS 配置和代理信息；
- LwM2M endpoint、服务器、Bootstrap、DTLS 身份与密钥；
- HTTP URL、超时和证书配置。

调用方返回后，后台线程不再访问调用方栈或可变内存。

包含凭据的快照在释放前显式清零。结构体布局只在内部扩展，公开结构体保持原样。

### 5.5 eUICC Executor

ES10/APDU/eUICC 操作通过单一执行器串行化。

职责：

- 管理 ES9、ES10、ES11 和驱动的初始化/销毁顺序；
- 串行化不支持并发的 eUICC 命令；
- 统一 TLV 输入长度、输出长度和结构校验；
- 为操作设置内部超时和取消检查；
- 维护当前驱动的真实选择状态；
- 在失败时按构造顺序逆序清理。

不新增公开排队接口；旧同步函数仍以原方式返回。

### 5.6 EIM Session Registry

MQTT、LwM2M、HTTP 使用独立会话槽：

```text
session[type] = {
  state,
  configuration snapshot,
  thread handle,
  protocol object,
  stop signal,
  last internal error
}
```

要求：

- 各协议对象不得交叉引用；
- 重复启动按旧返回语义处理；
- `stop_eim_service()` 逐一停止全部已运行会话；
- 停止后等待线程，不在后台继续访问 Runtime；
- 协议关闭和对象销毁顺序固定；
- `stop_eim_service()` 保持 `void`，内部失败写入诊断日志；
- 服务配置全部来自内部快照。

### 5.7 Resource and Diagnostics

统一资源所有权和内部诊断。

要求：

- 每类对象定义唯一 owner 和释放位置；
- 所有构造函数具有对应销毁函数；
- 部分构造失败也必须可安全销毁；
- 公开返回对象继续遵守旧内存所有权规则；
- 内部错误对象记录 Module、阶段、底层错误、`errno`、任务、协议、事务和可重试性；
- 对外仍映射为原有 `ErrCode` 或整数返回值；
- 增加进程内有限容量的诊断环形缓冲区，不新增公开读取函数；
- 严格控制日志中的敏感字段。

## 6. 生命周期与数据流

### 6.1 初始化

`ipa_init_library()` 保持异步完成语义：成功创建初始化任务后返回 `0`，最终成功或失败继续通过原事件回调通知。

内部流程：

```text
参数与状态校验
  → 深拷贝配置
  → 状态切换为 INITIALIZING
  → Task Supervisor 创建初始化线程
  → 初始化日志、驱动、ES10、ES9、ES11
  → 执行 ipa__init
  → 状态切换为 READY
  → 在锁外发送原成功回调
```

失败时按相反顺序释放已构造对象，状态恢复为 `UNINITIALIZED`，在锁外发送原失败回调。

### 6.2 业务调用

```text
旧导出函数
  → Facade 校验状态与参数
  → eUICC Executor 或 EIM Session Registry
  → 底层驱动/协议
  → 内部错误归一化
  → 映射为旧输出和 ErrCode
```

### 6.3 反初始化

固定顺序：

1. 切换为 `STOPPING`，拒绝新的内部任务；
2. 停止 MQTT、LwM2M、HTTP 会话；
3. 等待会话和初始化线程退出；
4. 反初始化 IPA；
5. 销毁 ES10、ES9、ES11 和当前驱动；
6. 清零敏感配置和运行状态；
7. 回到 `UNINITIALIZED`。

## 7. 错误语义

外部错误语义保持不变：

- 不增加旧调用方必须识别的新错误码；
- 不更改枚举数值；
- 不把内部超时、TLS 或线程错误直接暴露为新类型；
- 继续使用原返回值和回调。

内部错误对象补充诊断信息：

- 来源 Module；
- 生命周期阶段；
- 底层返回码；
- 系统错误；
- 协议状态；
- 是否可重试；
- 清理是否完成；
- 任务及事务标识。

只有明确无副作用且可恢复的传输错误允许有限重试。不得自动重放具有副作用的 eUICC 操作。

## 8. 商用安全要求

### 8.1 网络安全

- HTTPS 默认验证对端证书；
- HTTPS 默认验证主机名；
- MQTT TLS 和 LwM2M DTLS 使用配置中的信任材料；
- 证书、PSK、密码和身份数据不得以明文写入日志；
- 证书加载或验证失败必须终止连接，不得静默降级；
- 对重定向、代理和超时建立明确内部限制。

如果旧环境依赖不安全 TLS 行为，应通过发布迁移说明和内部受控构建处理，不通过新增公开参数改变 Interface。

### 8.2 输入与内存安全

- 校验所有指针、长度、计数和嵌套 TLV；
- 检查长度加法、乘法和类型转换溢出；
- 所有字符串保证终止符和容量；
- 使用有界格式化替换不受限的 `sprintf`；
- 检查 `memcpy` 的源长度和目标容量；
- 内存分配失败必须走完整清理路径；
- 敏感缓冲区释放前显式清零。

### 8.3 权限与供应链

- 串口和 PCSC 使用最小权限；
- 证书与配置文件检查权限和所有者；
- 记录 curl、MQTT、Wakaama/tinydtls 等依赖版本；
- 生成依赖和漏洞清单；
- 构建产物记录编译器、功能开关和源码提交。

## 9. 产品化与运维体验

Product Design 视角不改变 SDK Interface，而是约束部署和问题处理体验：

- 错误日志必须回答“哪个 Module、哪个阶段、什么原因、是否可恢复”；
- 初始化和服务启停必须有一致、可预测的状态；
- 重复操作不得导致崩溃或悬挂；
- 日志需支持等级、脱敏、轮转和关联标识；
- 安装包提供依赖版本、构建选项和兼容性清单；
- 升级包保留上一版共享库和校验值；
- 现场故障能够通过现有日志获得最近关键事件；
- 默认配置优先安全，错误配置应尽早失败并给出明确原因；
- WSL/Ubuntu、串口权限、证书加载和网络连接问题应能被分层诊断。

## 10. ABI 与行为测试门禁

### 10.1 导出符号

- 使用 `nm -D`、`readelf -Ws` 或等价工具保存当前共享库导出基线；
- 比较符号名称、类型、绑定、可见性和版本；
- 使用 linker version script 或显式可见性控制默认导出；
- 内部 Runtime 符号保持隐藏；
- 设置并固定兼容 SONAME。

### 10.2 类型布局

编译 ABI 探针并记录：

- 公开结构体 `sizeof`；
- 公开结构体 `alignof`；
- 每个公开字段 `offsetof`；
- 公开枚举和错误码数值；
- 回调类型和函数指针大小；
- 目标架构和编译器 ABI 信息。

每次构建与基线比较，任何变化都阻断发布。

### 10.3 旧 Manager 二进制回归

直接使用未经重新编译的旧 IPAd Manager：

- 动态加载新 `.so`；
- 初始化与接收回调；
- 查询 EID、EuiccInfo1/2、证书、Profile 和 EIM 配置；
- 执行已接入的 Fallback、应急和通知操作；
- 启动/停止已有协议会话；
- 重复初始化、停止和退出；
- 验证原 `eNotImpl` 行为保持不变。

### 10.4 稳定性与故障注入

- ASan：越界、释放后使用、重复释放；
- UBSan：未定义行为；
- TSan：状态和回调数据竞争；
- Valgrind：泄漏和错误访问；
- 长稳测试：重复查询、协议重连、初始化/反初始化循环；
- 故障注入：线程创建失败、内存分配失败、串口断开、非法 TLV、超时、TLS 失败、初始化中退出；
- 测试断言只通过公开 Interface 观察结果，不依赖 Runtime 私有结构。

## 11. 分阶段实施

### 阶段 1：ABI 基线与测试护栏

不改变运行逻辑，先完成：

- 共享库构建基线；
- 导出符号清单；
- 类型布局探针；
- SONAME 与版本策略；
- 旧 Manager 二进制冒烟测试；
- 现有生命周期和错误行为快照。

### 阶段 2：明确缺陷修复

修复：

- LwM2M 停止引用错误对象；
- 驱动选择状态不同步；
- 明确的失败清理遗漏；
- 空指针、边界和格式化风险；
- 可复现的资源泄漏。

每个修复必须有独立回归测试，不混入架构重构。

### 阶段 3：生命周期 Runtime

- 引入私有 `ipa_runtime_t`；
- 引入状态机和同步；
- 引入 Configuration Snapshot；
- 引入 Task Supervisor；
- 将生命周期导出函数转发到 Runtime；
- 保留 legacy implementation 作为内部构建期回退。

### 阶段 4：协议会话与资源治理

- 建立 EIM Session Registry；
- 迁移 MQTT、LwM2M、HTTP 线程和对象；
- 建立 eUICC Executor；
- 明确所有资源 owner；
- 完成可靠停止、等待、超时和故障注入。

### 阶段 5：商用安全与发布门禁

- 启用严格 TLS/DTLS 验证；
- 完成敏感日志脱敏；
- 固化依赖清单和构建元数据；
- 接入 ABI、Sanitizer、Valgrind 和长稳测试；
- 使用旧 Manager 二进制完成发布验收。

## 12. 回滚设计

- 每个阶段形成独立、可回退提交；
- 迁移期提供内部构建开关 `IPA_USE_LEGACY_RUNTIME`；
- 开关不进入公开头文件，不构成新 Interface；
- 新 Runtime 未通过全部门禁前不删除 legacy implementation；
- 生产包保留上一版 `.so` 和文件校验值；
- ABI 或旧 Manager 回归失败立即阻断发布；
- 新 Runtime 连续完成两个稳定发布周期后，单独评审 legacy implementation 的删除。

## 13. 明确不在范围内

- 不修改 IPAd Manager；
- 不修改公开头文件；
- 不新增公开函数；
- 不改变公开结构体和枚举；
- 不改变 Profile 下载、启用、禁用、删除当前的 `eNotImpl` 语义；
- 不引入新的远程管理或业务协议；
- 不把本轮内部设计直接写入现有用户接口文档；
- 不以性能优化为理由改变回调时序或错误语义。

## 14. 验收标准

满足以下条件才可认定为商用加固完成：

1. 旧 IPAd Manager 二进制无需重新编译即可加载新 SDK；
2. 导出符号、SONAME、公开类型布局和枚举值与基线一致；
3. 现有调用序列、错误码、回调和内存所有权行为兼容；
4. Profile 占位接口仍保持原 `eNotImpl` 行为；
5. 初始化、反初始化、服务启停和重复调用无未管理线程；
6. ASan、UBSan、TSan 和 Valgrind 门禁通过；
7. 故障注入后资源完整释放并可重新初始化；
8. HTTPS、MQTT TLS、LwM2M DTLS 默认执行严格验证；
9. 敏感数据不进入普通日志；
10. 长稳测试期间无泄漏、数据竞争、死锁和不可恢复状态；
11. 升级和上一版 `.so` 回滚均经过验证；
12. SDK、Manager 和现有接口使用文档无需同步修改。
