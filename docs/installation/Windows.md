# Windows 安装与维护

支持 Windows x64、WSL2、名为 `Ubuntu` 的发行版和 WSLg。安装过程允许联网补齐缺失环境与依赖。

运行 `IPAd-Manager-Setup-<version>-x64.exe`。安装器会校验内置 `.deb`，检测或安装 WSL/Ubuntu，显式通过 `Ubuntu/root` 调用 apt，运行健康检查并创建开始菜单入口。

安装器和卸载器不会注销、覆盖或删除 WSL 发行版。

开始菜单提供启动、健康检查、诊断导出和卸载。无 WSLg 时会报告图形环境缺失。

Windows 卸载默认保留 Ubuntu 中的用户配置。彻底清理可在 Ubuntu 中执行：

```bash
sudo apt purge ipad-manager
```

日志位于 `%LOCALAPPDATA%\IPAd Manager\install.log` 和 `/var/log/ipad-manager/install-health.json`。

当前 Windows EXE 未进行代码签名，发布元数据会明确记录 `Signed=false`。商用外发前应配置组织的 Windows 代码签名证书。
