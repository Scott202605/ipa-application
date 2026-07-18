# IPAd Manager 双安装器设计

## 1. 目标

为 IPAd Manager 与加固版 IPAd SDK 提供统一、可升级、可卸载、可诊断的商用交付方式：

- Ubuntu x86-64 原生 Debian 安装包；
- Windows x64 安装程序，负责准备 WSL2 Ubuntu 并安装同一 Debian 包；
- 两种入口共用同一套 Linux 产品载荷、版本信息和验收门禁；
- 安装后不依赖源码目录或人工设置 `LD_LIBRARY_PATH`。

Windows 安装过程允许联网安装缺失的 WSL、Ubuntu 和 Linux 系统依赖。

## 2. 支持范围

首版支持：

- Ubuntu x86-64；
- Windows x64、WSL2 和发行版名称 `Ubuntu`；
- WSLg 图形界面启动。

首版不支持：

- Linux ARM64；
- Windows ARM64；
- 非 Ubuntu Linux 发行版；
- 无 WSLg 环境中的 Windows 原生 GUI；
- 完全离线安装。

## 3. 能力边界

安装成功只表示 Manager、SDK、配置和运行依赖正确部署，不代表所有业务接口已经实现。

### 3.1 已有真实调用链

- SDK 初始化和反初始化；
- 已实现的信息查询、通知处理、Fallback 和 Emergency Profile 能力；
- 已实现的 HTTP、MQTT 和 LwM2M 通信入口；
- Manager 配置解析和 SDK 包装层调用。

### 3.2 依赖外部环境的能力

- eUICC、PC/SC 或 AT 串口交互；
- SM-DP+、eIM、MQTT、LwM2M 和 HTTP 服务；
- 真实证书、网络和设备权限。

这些能力在安装验收中只验证依赖探测和调用入口，完整业务结果必须在真实设备或测试平台中验收。

### 3.3 尚未实现的 Manager 能力

Manager 的 Profile 下载、启用、禁用和删除包装接口当前返回 `eNotImpl`。安装器、健康检查和用户文档必须明确展示该状态，不得将其描述为可用功能。

## 4. 总体架构

`.deb` 是唯一真实产品包。Windows 安装器不维护第二套应用载荷，只负责环境准备、校验、复制和调用 Ubuntu 中的 `apt` 安装内置 `.deb`。

```text
Windows Setup.exe
  ├─ 检查 Windows、管理员权限和虚拟化/WSL 状态
  ├─ 检查或联网安装 WSL2 与官方 Ubuntu
  ├─ 校验内置 .deb 的 SHA-256
  ├─ 将 .deb 复制到 Ubuntu 临时目录
  ├─ 显式调用 wsl.exe --distribution Ubuntu --user root
  ├─ 通过 apt 安装依赖和 .deb
  ├─ 调用 ipad-manager-health
  └─ 创建 Windows 开始菜单入口
                              │
Ubuntu 用户 ─ apt install ───┘
                              ▼
                    ipad-manager.deb
                      ├─ Manager 可执行文件
                      ├─ 私有 libipa.so
                      ├─ 默认配置与示例
                      ├─ Linux 桌面入口
                      ├─ 健康检查工具
                      └─ 诊断日志导出工具
```

## 5. Ubuntu 包设计

### 5.1 包身份

- Debian 包名：`ipad-manager`；
- 版本来源：项目版本加 Git 提交，例如 `1.1.0+git.e7a433a`；
- 架构：`amd64`；
- 系统依赖由 Debian `Depends` 声明并交给 `apt` 解析。

### 5.2 安装布局

```text
/usr/bin/ipad-manager
/usr/bin/ipad-manager-health
/usr/bin/ipad-manager-diagnostics
/usr/lib/ipad-manager/libipa.so
/etc/ipad-manager/config.json
/usr/share/ipad-manager/ipad_config.example.json
/usr/share/ipad-manager/BUILD_METADATA.txt
/usr/share/ipad-manager/DEPENDENCIES.lock.txt
/usr/share/ipad-manager/install-manifest.json
/usr/share/applications/ipad-manager.desktop
/var/log/ipad-manager/
```

Manager 使用 `$ORIGIN/../lib/ipad-manager` 或等价的固定安装 RPATH 加载私有 SDK，不修改全局 `/usr/lib/libipa.so`，避免与其他应用冲突。

### 5.3 配置生命周期

- 首次安装时从示例生成 `/etc/ipad-manager/config.json`；
- 配置作为 Debian conffile 管理；
- 升级默认保留用户配置；
- 新默认配置由 dpkg 以标准配置冲突机制提供；
- 普通卸载保留配置，purge 才删除产品配置；
- 运行日志与程序文件分离。

### 5.4 安装后检查

安装后脚本执行快速、无硬件依赖的健康检查：

- 必需文件和权限；
- manifest 与 SHA-256；
- Manager 的 ELF 架构；
- 动态库解析必须指向 `/usr/lib/ipad-manager/libipa.so`；
- SDK SONAME 与 ABI 基线；
- Manager `--help`；
- 默认配置语法和范围；
- 可选硬件与 GUI 环境只报告状态，不导致基础安装失败。

关键载荷或 ABI 检查失败时，安装返回失败并写入诊断日志。

## 6. Windows 安装器设计

### 6.1 环境准备

安装器依次检查：

1. Windows x64 和支持 WSL2 的系统版本；
2. 管理员权限；
3. 虚拟化、WSL 和 Virtual Machine Platform 状态；
4. 真实 Windows 用户下的 WSL 发行版列表；
5. 名为 `Ubuntu` 的发行版是否可启动；
6. WSLg 是否可用于 GUI。

不存在 Ubuntu 时，安装器联网安装官方 Ubuntu。若系统变更要求重启，安装器保存阶段状态，重启后可继续，不重复破坏已有步骤。

### 6.2 WSL 操作约束

- 所有命令显式使用 `wsl.exe --distribution Ubuntu --user root -- ...`；
- 不依据其他 Windows 账户的发行版列表做修复；
- 不注销、不导入覆盖、不删除任何现有发行版；
- 不删除用户的 WSL、Ubuntu 或非本产品文件；
- Linux 管道或多命令通过受控脚本执行，避免 Windows 与 Linux 引号混淆。

### 6.3 安装流程

1. 校验安装器内置 `.deb` 与 manifest；
2. 将 `.deb` 复制到 Ubuntu 的产品临时目录；
3. 运行 `apt-get update` 和依赖安装；
4. 使用 `apt install` 安装或升级 `.deb`；
5. 执行 `ipad-manager-health --json`；
6. 将健康结果回传 Windows 安装器；
7. 创建开始菜单中的启动、健康检查、日志导出和卸载入口；
8. 保存 Windows 与 Ubuntu 两侧的安装日志。

开始菜单启动器使用指定 Ubuntu 发行版启动 `/usr/bin/ipad-manager`。WSLg 不可用时不伪造成功，而是显示明确的环境修复提示。

### 6.4 卸载行为

- 默认 Windows 卸载调用 Ubuntu 的 `apt remove ipad-manager`；
- 默认保留 `/etc/ipad-manager` 用户配置；
- 可选“彻底清理”调用 purge 删除本产品配置；
- 永远不卸载 WSL、不注销 Ubuntu、不删除其他 Linux 数据。

## 7. 升级和回滚

- SDK 与 Manager 在同一 `.deb` 中原子升级；
- 发布目录保留当前和前一已验证版本的 `.deb`、SHA-256 和构建元数据；
- 升级前记录已安装版本；
- 安装失败时只回滚 `ipad-manager` 包，不回滚或删除 WSL 基础环境；
- 用户配置由 conffile 机制保护；
- 回滚后重新执行健康检查；
- 回滚失败时保留完整日志并给出可复制的人工恢复命令。

## 8. 错误处理和可诊断性

健康检查输出同时支持人类可读文本和稳定 JSON。每项结果包含检查 ID、状态、说明和修复建议。

错误分类：

- Windows 前置条件错误；
- WSL/Ubuntu 状态错误；
- 网络或 apt 错误；
- 包完整性错误；
- 动态链接或 ABI 错误；
- GUI/WSLg 环境错误；
- 可选硬件或外部服务缺失。

日志不得记录密码、激活码、完整证书私钥或其他敏感配置。诊断导出在打包前执行敏感字段脱敏。

## 9. 联合验收矩阵

### 9.1 构建验收

- SDK Release 构建和既有发布门禁通过；
- Manager Release 构建成功；
- Manager 链接本次 `.deb` 内的 SDK；
- 关键编译警告为零。

### 9.2 Ubuntu 安装验收

- 干净 Ubuntu 上联网安装；
- 重复安装；
- 从前一版本升级；
- 安装失败后的产品级回滚；
- remove 后保留配置；
- purge 后删除产品配置；
- 动态依赖、RPATH、ABI、配置和健康检查通过。

### 9.3 Manager 与 SDK 联动验收

- Manager `--help` 无图形环境也能执行；
- 在图形环境中创建窗口；
- SDK 初始化和反初始化；
- 安装版 `libipa.so` 的 SONAME 和 32 个兼容导出符号；
- 配置加载；
- 已实现入口的无硬件 smoke test；
- `eNotImpl` 功能保持明确且不崩溃。

### 9.4 Windows 安装验收

- 已有可用 Ubuntu；
- 没有 Ubuntu、联网安装 Ubuntu；
- WSL 功能未启用且需要重启；
- WSLg 可用与不可用；
- 重复安装、升级、默认卸载和彻底清理；
- 网络中断、apt 失败、校验失败和健康检查失败；
- 确认任何失败路径均不注销或删除 Ubuntu。

真实 eUICC 与远端服务的端到端业务验证作为独立硬件集成验收，不阻塞基础安装包生成，但阻塞相应业务能力被标记为“生产可用”。

## 10. 构建方案

构建流水线只生成一次 Linux 产品载荷：

1. 构建并门禁 SDK；
2. 使用该 SDK 构建 Manager；
3. 在 staging 根目录执行 CMake install；
4. 生成 manifest、元数据和 `.deb`；
5. 在干净 Ubuntu 环境安装测试 `.deb`；
6. 将已验证 `.deb` 嵌入 Windows 安装器；
7. 构建 Windows `.exe`；
8. 输出总 SHA-256 清单。

Windows 安装器优先使用可在当前环境中稳定自动化构建和静默测试的 Inno Setup；若构建环境只能可靠提供 NSIS，则允许采用 NSIS，但安装行为和验收标准不变。

## 11. 交付物

- `ipad-manager_<version>_amd64.deb`；
- `IPAd-Manager-Setup-<version>-x64.exe`；
- `SHA256SUMS`；
- `BUILD_METADATA.txt`；
- `DEPENDENCIES.lock.txt`；
- `install-manifest.json`；
- Ubuntu 与 Windows 安装、升级、卸载说明；
- 健康检查和诊断导出工具；
- 自动化构建、打包和安装测试脚本；
- 已实现、环境依赖、未实现功能矩阵。

## 12. 成功标准

- 两个安装入口安装完全相同版本的 Manager 和 SDK；
- 安装后不需要源码目录或手工库路径；
- 安装、升级、卸载和产品级回滚可重复执行；
- 健康检查能够准确定位环境、依赖、ABI 和配置问题；
- Windows 安装失败不会破坏已有 WSL/Ubuntu；
- 文档不将 `eNotImpl` 或依赖真实硬件的能力误报为已可用；
- 所有交付物具备可验证的版本、构建来源和 SHA-256。
