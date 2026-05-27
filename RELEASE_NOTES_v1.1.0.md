# Release v1.1.0

## 🎉 新增功能

### 1. Profile 管理 API

实现了完整的 Profile 生命周期管理：

- ✅ `ipad_wrapper_profile_download()` - 从 SM-DP+ 服务器下载 Profile
- ✅ `ipad_wrapper_profile_enable()` - 启用 Profile
- ✅ `ipad_wrapper_profile_disable()` - 禁用 Profile
- ✅ `ipad_wrapper_profile_delete()` - 删除 Profile

**技术实现**:
- 基于 ES10 接口实现 ES10a/ES10b 规范
- 支持通过 AC Token 或匹配 ID 下载
- 需要 smartcard 实例支持
- 框架代码已就绪

### 2. 会话管理 API

实现了多种通信协议支持：

- ✅ `ipad_wrapper_connect_mqtt()` - 连接 MQTT 服务（支持 TLS）
- ✅ `ipad_wrapper_connect_lwm2m()` - 连接 LwM2M 服务（支持 DTLS）
- ✅ `ipad_wrapper_connect_http()` - 连接 HTTP 服务
- ✅ `ipad_wrapper_stop_eim_service()` - 停止所有 EIM 服务

**支持特性**:
- MQTT: TLS 加密、用户名密码认证
- LwM2M: DTLS 加密、Bootstrap 支持
- HTTP: 超时配置、重传机制

### 3. 配置文件支持

实现了完整的配置管理系统：

**配置模块**:
- ✅ 新增 `config_manager.h/c` 配置管理模块
- ✅ JSON 格式配置文件
- ✅ 自动验证配置有效性
- ✅ 默认值回退机制

**配置项**:
- IPA 核心配置（驱动、日志、设备 ID）
- 网络配置（MQTT、LwM2M、HTTP）
- UI 配置（窗口大小、字体大小）
- 调试配置（模拟响应、调试日志）

**示例配置**:
```json
{
  "config_version": "1.0.0",
  "mqtt_enabled": true,
  "mqtt_hostname": "mqtt.example.com",
  "mqtt_port": 8883,
  "mqtt_use_tls": true,
  "http_timeout": 30,
  "http_fqdn": "smdp.example.com",
  "window_width": 1920,
  "window_height": 1080,
  "log_level": 4,
  "enable_debug_logging": true
}
```

## 📦 新增文件

| 文件 | 说明 |
|------|------|
| `config_manager.h` | 配置管理接口定义 |
| `config_manager.c` | 配置管理实现（450+ 行） |
| `ipad_config.example.json` | 示例配置文件 |
| `docs/CONFIG_GUIDE.md` | 配置使用指南（200+ 行） |
| `RELEASE_NOTES_v1.0.0.md` | v1.0.0 发布说明 |

## 📝 更新文件

| 文件 | 说明 |
|------|------|
| `ipad_wrapper.h` | 新增 Profile 和会话管理 API（+80 行） |
| `ipad_wrapper.c` | 实现 Profile 和会话管理 API（+200 行） |
| `CMakeLists.txt` | 版本更新至 v1.1.0，添加配置管理模块 |
| `README.md` | 添加 v1.1.0 功能说明 |

## 📖 文档

- [配置使用指南](ipad_host_app/docs/CONFIG_GUIDE.md) - 详细配置项说明、配置示例
- [更新总结](UPDATE_SUMMARY_v1.1.0.md) - 完整更新报告
- [v1.0.0 发布说明](RELEASE_NOTES_v1.0.0.md) - v1.0.0 完整功能说明

## 🔧 技术栈

- **开发语言**: C (C99/C11)
- **GUI 框架**: GTK3
- **配置文件**: JSON (cJSON)
- **通信协议**: HTTP, MQTT, LwM2M
- **构建系统**: CMake 3.22+

## 📊 变更统计

- **新增文件**: 5 个
- **变更文件**: 4 个
- **新增代码**: 1,250+ 行
- **新增 API**: 9 个
- **新增文档**: 3 篇

## ⚠️ 注意事项

### Profile 管理功能
框架代码已实现，需要与硬件设备联调完成完整功能。需要初始化 smartcard 实例后才能调用 ES10 接口。

### 配置文件位置
- **系统级**: `/etc/ipad_host_app/config.json`
- **用户级**: `$HOME/.config/ipad_host_app/config.json`
- **开发级**: `./config.json` (相对于程序运行目录)

### 会话管理
启用 TLS/DTLS 需要额外的证书配置文件支持。

## 🚀 使用示例

### 使用配置文件启动

```bash
# 复制示例配置
cp config/ipad_config.example.json config/ipad_config.json

# 编辑配置
vim config/ipad_config.json

# 启动程序（自动加载配置）
./ipad_host_app
```

### 动态连接 MQTT

```c
ErrCode ret = ipad_wrapper_connect_mqtt(
    "mqtt.example.com",    // 主机名
    8883,                  // 端口
    "username",            // 用户名
    "password",            // 密码
    true                   // 使用 TLS
);

if (ret == eOK) {
    printf("MQTT 连接成功\n");
}
```

### 管理 Profile

```c
// 下载 Profile
ErrCode ret = ipad_wrapper_profile_download(
    "89860123456789012345",  // ICCID
    "smdp.example.com",      // SM-DP+ 服务器
    "CONF123",               // 确认码
    NULL                     // 激活码（可选）
);

// 启用 Profile
ret = ipad_wrapper_profile_enable("89860123456789012345");

// 禁用 Profile
ret = ipad_wrapper_profile_disable("89860123456789012345");

// 删除 Profile
ret = ipad_wrapper_profile_delete("89860123456789012345");
```

## 📋 后续计划

- [ ] Profile 管理 API 硬件联调
- [ ] TLS 证书配置支持
- [ ] 配置热更新机制
- [ ] 异步 API 调用优化
- [ ] 批量操作功能
- [ ] 自动化测试用例

## 📄 许可证

- SDK 源码：Copyright (c) Giesecke+Devrient Mobile Security GmbH
- 上位机程序代码：根据项目 LICENSE 文件

## 👥 技术支持

- 仓库地址：https://github.com/Scott202605/ipa-application
- 问题反馈：https://github.com/Scott202605/ipa-application/issues
- 配置指南：[CONFIG_GUIDE.md](ipad_host_app/docs/CONFIG_GUIDE.md)

---

**Full Changelog**: https://github.com/Scott202605/ipa-application/compare/v1.0.0...v1.1.0  
**Commit Hash**: 4f66319  
**Release Date**: 2026-02-04
