# IPAd SDK 与 Manager README 更新设计

## 目标

将仓库根目录 README 从早期、乱码且以旧 GUI 原型为中心的说明，更新为与当前 `main` 一致的项目入口。README 同时服务产品使用/部署人员和 SDK 集成开发者，让读者能快速安装验证，也能准确理解 SDK、Manager、兼容性和交付边界。

## 信息架构

README 采用分层综合结构：

1. 项目定位、当前版本与 CI 状态。
2. 已交付能力摘要。
3. Ubuntu DEB 与 Windows EXE 快速安装。
4. 安装后的健康检查和脱敏诊断。
5. SDK 与 Manager 分层架构及外部调用链。
6. 按状态区分的能力矩阵。
7. 外部 C API 生命周期、最小调用示例和资源释放约束。
8. Manager GUI、配置与 CLI 使用方式。
9. Ubuntu、Windows/WSL 兼容性和环境边界。
10. 源码构建、测试和统一发布流程。
11. 发布产物、完整性校验与签名状态。
12. 专题文档索引、许可证和当前限制。

首页先解决“如何获得并验证可运行产品”，后续章节回答“如何集成、如何工作、哪些能力可用”。详细 API 和运维说明仍由专题文档承载，README 不复制整份手册。

## 架构与调用说明

README 使用 Mermaid 图表达两条入口：

- 外部 C 应用通过稳定公开头文件和 C API 调用 SDK。
- 用户或运维人员通过 Manager GUI/CLI，经业务逻辑层与 SDK Wrapper 调用同一 SDK。

SDK 内部只展示理解调用链所需的 Runtime、协议能力与 HAL 边界，并将 eUICC、SM-DP+、eIM 标记为外部环境。最小 C 示例覆盖初始化、可用性检查、业务查询、配套释放函数和反初始化，不依赖私有实现头文件。

## 能力与产品边界

所有能力使用统一状态：

- `Available`：仓库实现且有自动化验证覆盖。
- `Environment-dependent`：接口与调用链存在，最终结果需要真实 eUICC、远端服务或桌面环境验证。
- `Not implemented`：接口存在但当前明确返回 `eNotImpl` 或没有端到端实现。

README 必须明确 Manager 的 Profile 下载、启用、禁用和删除仍未实现。安装成功只代表产品及依赖就绪，不代表外部硬件、凭据、网络服务或图形会话已经就绪。

## 安装与交付

Ubuntu 以 `ipad-manager_<version>_amd64.deb` 为标准安装路径，Windows 以 `IPAd-Manager-Setup-<version>-x64.exe` 为标准入口。Windows 安装器复用同一 canonical DEB，并通过 WSL2、名为 `Ubuntu` 的发行版和 WSLg 承载 Linux 运行环境。

README 展示安装、启动、`ipad-manager-health --json` 和脱敏诊断命令。源码构建放在开发者章节，避免继续把早期 `quickstart.sh` 当成产品交付主路径。

发布章节列出 DEB、EXE、元数据、健康报告、清单与 `SHA256SUMS`，并明确 Windows EXE 当前未代码签名，商用外发前需要组织证书。

## 事实来源

README 内容以以下可执行或受测试约束的来源为准：

- `docs/installation/Capability_Matrix.md`
- `docs/installation/Ubuntu.md`
- `docs/installation/Windows.md`
- `ipa_sdk_pc/include/` 公开头文件
- `ipad_host_app/src/main.c` 与 Manager CMake 配置
- `packaging/build-release.sh`、Linux/Windows 打包脚本和打包测试
- `.github/workflows/ubuntu-build.yml`

若旧专题文档与代码或测试冲突，以当前代码、安装策略和验证结果为准；README 不传播无法从仓库确认的商用承诺。

## 验证与提交范围

实施时增加 README 静态回归测试，至少验证：

- README 可按 UTF-8 正确读取，且不存在已知乱码标记。
- 使用当前二进制和工具名，例如 `ipad-manager`、`ipad-manager-health`。
- 同时包含 Ubuntu、Windows/WSL、SDK 外部调用、能力状态和当前限制。
- README 中的仓库内相对链接均指向真实文件。
- 不再把旧启动脚本描述为推荐产品安装方式。

同时运行现有 CI workflow 回归测试和 Markdown 基础检查。README 变更单独提交并推送 `main`，不暂存或修改用户现有的 PPT 删除、`install_wsl.ps1` 和 `wsl-install.log`。
