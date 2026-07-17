# Codex WSL 调用桥接设计

## 背景

Windows 上的 WSL 发行版按 Windows 用户注册。当前可用的 `Ubuntu` 注册在真实用户 `MILIGHT\61004` 下，而 Codex 的普通沙箱命令运行在 `MILIGHT\codexsandboxoffline` 下。因此，沙箱内直接执行 `wsl.exe` 会错误地报告“没有已安装的分发”。经用户批准提升权限后，命令会以真实用户身份运行，并能正常访问现有的 Ubuntu。

## 目标

- 后续 Codex 任务需要 Linux 环境时，稳定复用现有的 `Ubuntu`。
- 不为沙箱账户复制发行版。
- 不全局关闭 Codex 沙箱。
- 避免把“沙箱账户看不到发行版”误判成 WSL 未安装。

## 方案

在项目根目录添加 `AGENTS.md`，声明以下持久规则：

1. Windows 沙箱中的普通 `wsl.exe` 棧测结果不能代表真实用户的 WSL 状态。
2. 所有需要访问 WSL 的命令必须通过 Codex 的权限提升机制，以真实 Windows 用户身份执行。
3. 显式指定发行版 `Ubuntu`，不依赖调用账户的默认发行版：

   ```powershell
   wsl.exe --distribution Ubuntu --user root -- uname -a
   ```

4. 只读检测也遵循同一规则；不得因为普通沙箱返回“无发行版”而安装或注册新的发行版。
5. 破坏性 Linux 操作仍需单独确认，权限提升不等于扩大用户授权范围。

## 调用与错误处理

- 首选直接传递单个 Linux 程序及其参数，减少 PowerShell 与 Linux shell 的双重转义。
- 需要管道、重定向或多条 Linux 命令时，使用：

  ```powershell
  wsl.exe --distribution Ubuntu --user root -- sh -lc 'uname -a; id'
  ```

- 若提升后的命令返回 `WSL_E_DISTRO_NOT_FOUND`，先以同一提升身份运行 `wsl.exe --list --verbose`，再决定是否修复；不得依据沙箱账户的列表进行删除或安装。
- 网络、系统包安装和系统级变更继续遵循 Codex 审批规则。

## 验证

实施后进行两层验证：

1. 普通沙箱身份仍为 `MILIGHT\codexsandboxoffline`，确认问题边界没有被掩盖。
2. 按 `AGENTS.md` 规则提升执行以下探针并要求退出码为 0：

   ```powershell
   wsl.exe --distribution Ubuntu --user root -- sh -lc 'grep -q "^ID=ubuntu$" /etc/os-release && echo WSL_BRIDGE_OK'
   ```

成功标准是输出 `WSL_BRIDGE_OK`，且真实账户下仍仅注册一个名为 `Ubuntu` 的 WSL 2 发行版。

## 非目标

- 不修改全局 Codex 沙箱模式。
- 不在 WSL 内安装另一套 Codex。
- 不创建、导入或复制新的 WSL 发行版。
- 不在本次工作中创建 Linux 普通用户或安装项目依赖。
