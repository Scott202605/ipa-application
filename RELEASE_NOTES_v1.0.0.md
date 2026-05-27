# IPA 上位机程序 v1.0.0 发布说明

## 发布信息

- **版本**: v1.0.0
- **发布日期**: 2026-02-04
- **仓库**: https://github.com/Scott202605/ipa-application
- **提交**: 0838a99

## 🎉 项目介绍

IPA 上位机程序是基于 Giesecke+Devrient IPAd SDK 开发的 Linux 桌面应用程序，提供图形界面用于调用 SDK API 实现 GSMA SGP.32 规范中定义的 IPAd（IoT Profile Assistant Distance）能力。

## ✨ 核心功能

### 已实现功能

1. **信息获取 API**
   - ✅ 获取 eUICC EID
   - ✅ 获取 euiccInfo1
   - ✅ 获取 euiccInfo2
   - ✅ 获取 eUICC 证书信息
   - ✅ 获取所有 Profile 信息
   - ✅ 获取 eIM 配置信息

2. **Fallback 机制**
   - ✅ 执行 Fallback Profile 启用
   - ✅ 从 Fallback 返回
   - ✅ 报告 Profile 回滚结果

3. **应急功能**
   - ✅ 启用应急 Profile
   - ✅ 禁用应急 Profile

4. **通知处理**
   - ✅ 发送所有待处理通知
   - ✅ 发送单个通知
   - ✅ 移除通知（单个/全部）

5. **调试功能**
   - ✅ 手动响应参数注入（模拟错误场景）
   - ✅ 实时日志显示
   - ✅ 日志导出

## 📦 项目结构

```
ipa-application/
├── ipa_sdk_pc/              # IPAd SDK 源码 (100K+ 行)
│   ├── include/            # SDK 头文件
│   ├── ipa-src/            # SDK 实现
│   └── main_app/           # SDK 示例程序
├── ipad_host_app/          # 上位机应用程序
│   ├── src/                # 源代码
│   │   ├── gui/            # GTK3 GUI 模块
│   │   ├── sdk_wrapper/    # SDK 封装层
│   │   ├── business_logic/ # 业务逻辑层
│   │   ├── utils/          # 工具模块
│   │   └── debug/          # 调试模块
│   ├── include/            # 头文件
│   └── docs/               # 文档
└── docs/                   # 项目文档
```

## 🔧 技术栈

- **开发语言**: C (C99/C11)
- **GUI 框架**: GTK3
- **构建系统**: CMake 3.22+
- **编译工具**: GCC 7+
- **网络通信**: libcurl
- **加密库**: OpenSSL

## 📖 文档

| 文档 | 说明 |
|------|------|
| [README.md](README.md) | 项目总览、快速开始 |
| [User_Guide.md](ipad_host_app/docs/User_Guide.md) | 用户操作指南 (10 页) |
| [API_Reference.md](ipad_host_app/docs/API_Reference.md) | API 参考文档 (15 页) |
| [Architecture_Design.md](ipad_host_app/docs/Architecture_Design.md) | 架构设计文档 (12 页) |
| [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md) | 项目结构说明 (8 页) |

## 🚀 快速开始

### 1. 安装依赖

```bash
sudo apt-get update
sudo apt-get install -y cmake gcc libgtk-3-dev libcurl4-openssl-dev libssl-dev pkg-config
```

### 2. 编译 SDK

```bash
./build_sdk.sh
```

### 3. 编译上位机程序

```bash
cd ipad_host_app
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
```

### 4. 运行程序

```bash
./ipad_host_app
```

或使用快速启动脚本：

```bash
./quickstart.sh
```

## 📊 代码统计

| 类别 | 数量 |
|------|------|
| 源代码文件 (.c/.h) | 300+ 个 |
| 代码总行数 | 120K+ 行 |
| 文档文件 | 6 个 |
| 构建脚本 | 3 个 |
| CMake 配置 | 50+ 个 |

## 🎯 使用示例

### 获取 EID

1. 启动程序
2. 在左侧 API 树中选择「信息获取」→「获取 EID」
3. 点击「调用 API」按钮
4. 查看底部日志区显示 EID

### 查看 Profile 列表

1. 选择「信息获取」→「获取所有 Profile 信息」
2. 点击「调用 API」
3. 查看返回的 Profile 列表

### 测试错误处理

1. 勾选「启用手动响应参数注入」
2. 选择错误码（如 `eFatal`）
3. 调用任意 API
4. 观察错误处理流程

## 📝 变更日志

### v1.0.0 (2026-02-04)

**新增**
- ✅ 完整的 IPAd SDK 集成
- ✅ 基于 GTK3 的图形用户界面
- ✅ SDK 封装层（15+ API 包装函数）
- ✅ 业务逻辑层（参数验证、命令组装、响应解析）
- ✅ 工具模块（日志、JSON 处理、模拟响应）
- ✅ 完整的文档体系

**已知问题**
- Profile 下载/启用/禁用/删除 API 的完整参数输入待扩展
- 异步 API 调用待实现（目前为同步调用）
- 配置文件支持待完善

## 🔮 后续计划

### v1.1.0 (计划)
- [ ] Profile 管理 API 完整实现
- [ ] 异步 API 调用支持
- [ ] 配置文件支持

### v1.2.0 (计划)
- [ ] 会话管理 API（MQTT/LwM2M）
- [ ] 批量操作功能
- [ ] 单元测试

## 📄 许可证

- SDK 源码：Copyright (c) Giesecke+Devrient Mobile Security GmbH
- 上位机程序：根据项目 LICENSE

## 👥 技术支持

- 问题反馈：https://github.com/Scott202605/ipa-application/issues
- 详细文档：查看 `docs/` 目录

---

**发布信息**: v1.0.0  
**提交 Hash**: 0838a99  
**仓库**: https://github.com/Scott202605/ipa-application
