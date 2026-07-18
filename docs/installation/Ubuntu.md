# Ubuntu 安装与维护

支持 Ubuntu x86-64，并允许联网安装依赖。图形运行需要桌面会话；WSL 环境需要 WSLg。

## 安装与启动

```bash
sudo apt install ./ipad-manager_<version>_amd64.deb
ipad-manager-health
ipad-manager-launch
```

安装内容包括 Manager、私有 `libipa.so`、默认配置、桌面入口、健康检查和诊断工具。无需设置 `LD_LIBRARY_PATH`。

配置位于 `/etc/ipad-manager/config.json`，升级不会静默覆盖用户配置。

## 升级与卸载

```bash
sudo apt install ./ipad-manager_<new-version>_amd64.deb
sudo apt remove ipad-manager   # 保留配置
sudo apt purge ipad-manager    # 删除本产品配置与日志
```

## 诊断

```bash
ipad-manager-health --json
ipad-manager-diagnostics ~/ipad-manager-diagnostics.tar.gz
```

诊断导出会脱敏密码、令牌、激活码、确认码和密钥字段。
