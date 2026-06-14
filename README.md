# IPA 上位机程序 (IPA Host Application)

基于 Giesecke+Devrient IPAd SDK 开发的 Linux 桌面应用程序，用于实现 GSMA SGP.32 规范中定义的 IPAd（IoT Profile Assistant Distance）能力。

![平台](https://img.shields.io/badge/平台-Linux%20Ubuntu%2018.04+-blue)
![语言](https://img.shields.io/badge/语言-C%20(C99)-orange)
![GUI](https://img.shields.io/badge/GUI-GTK3-green)
![许可证](https://img.shields.io/badge/许可证-Proprietary-red)

## 📋 项目概述

本项目提供了一个图形化界面，用于：
- 调用 IPAd SDK API 实现 eSIM Profile 管理
- 与 eUICC 设备交互（通过 PC/SC 或 AT 命令）
- 与 SM-DP+ 服务器通信（通过 HTTP/MQTT/LwM2M）
- 处理 Profile 下载、安装、启用、禁用、删除等操作
- 支持 Fallback Profile 机制和应急 Profile 功能

## 🏗️ 项目结构

```
<project-root>/
├── README.md                    # 本文件
├── quickstart.sh                # 快速启动脚本
├── build_sdk.sh                 # SDK 编译脚本
├── PROJECT_STRUCTURE.md         # 详细项目结构
├── ipa_sdk_pc/                  # IPAd SDK 源码
│   ├── include/                # SDK 头文件
│   ├── ipa-src/                # SDK 实现
│   └── build/                  # 编译输出
└── ipad_host_app/              # 上位机应用程序
    ├── src/                    # 源代码
    ├── include/                # 头文件
    ├── docs/                   # 文档
    └── build/                  # 编译输出
```

## ✨ 主要功能

### 1. 信息获取
- ✅ 获取 eUICC EID
- ✅ 获取 euiccInfo1 / euiccInfo2
- ✅ 获取 eUICC 证书信息
- ✅ 获取所有 Profile 信息
- ✅ 获取 eIM 配置信息

### 2. Profile 管理 (v1.1.0 框架)
- ⚠️ 已声明 wrapper 接口和 GUI 分类
- ⚠️ 下载、启用、禁用、删除当前仍返回 `eNotImpl`
- 🔧 待补齐 ES10、SM-DP+ 通信和参数输入链路

### 3. 会话管理 (v1.1.0 新增)
- ✅ MQTT 连接（支持 TLS）
- ✅ LwM2M 连接（支持 DTLS）
- ✅ HTTP 连接
- ✅ EIM 服务控制

### 4. Fallback 机制
- ✅ 执行 Fallback Profile 启用
- ✅ 从 Fallback 返回
- ✅ 报告 Profile 回滚结果

### 5. 应急功能
- ✅ 启用应急 Profile
- ✅ 禁用应急 Profile

### 6. 通知处理
- ✅ 发送所有待处理通知
- ✅ 发送单个通知
- ✅ 移除通知（单个/全部）

### 7. 配置管理 (v1.1.0 部分完成)
- ✅ JSON 配置结构、示例文件、解析和验证模块
- ⚠️ 主程序尚未按文档中的加载顺序接入配置文件
- 🔧 待把配置值应用到 SDK 初始化、GUI 尺寸和通信参数

### 8. 调试功能
- ✅ 手动响应参数注入（模拟错误场景）
- ✅ 实时日志显示
- ✅ 日志导出

## 🚀 快速开始

### 一键启动

```bash
cd <project-root>
./quickstart.sh
```

此脚本会自动：
1. 检查并安装系统依赖
2. 编译 IPAd SDK
3. 编译上位机程序
4. 启动应用程序

### 手动步骤

#### 1. 安装依赖

```bash
sudo apt-get update
sudo apt-get install -y cmake gcc libgtk-3-dev libcurl4-openssl-dev libssl-dev pkg-config
```

#### 2. 编译 SDK

```bash
cd <project-root>
./build_sdk.sh
```

#### 3. 编译上位机程序

```bash
cd <project-root>/ipad_host_app
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j$(nproc)
```

#### 4. 运行程序

```bash
./ipad_host_app
```

## 📖 文档

| 文档 | 内容 |
|------|------|
| [用户操作指南](ipad_host_app/docs/User_Guide.md) | 使用方法、界面说明、操作步骤 |
| [API 参考文档](ipad_host_app/docs/API_Reference.md) | 所有 API 的详细定义和示例 |
| [架构设计文档](ipad_host_app/docs/Architecture_Design.md) | 技术架构、设计模式、扩展性 |
| [配置使用指南](ipad_host_app/docs/CONFIG_GUIDE.md) | 配置文件详解、配置项说明（v1.1.0） |
| [项目结构](PROJECT_STRUCTURE.md) | 目录结构、模块划分、依赖关系 |

## 🎯 API 分类

### 信息获取类
| API | 功能 |
|-----|------|
| `ipa__get_eid_cstring()` | 获取 eUICC EID |
| `ipa__get_euicc_info_1()` | 获取 euiccInfo1 |
| `ipa__get_euicc_info_2()` | 获取 euiccInfo2 |
| `ipa__get_certs()` | 获取证书信息 |
| `ipa__get_all_profiles_info()` | 获取 Profile 列表 |
| `ipa__get_eim_configuration()` | 获取 eIM 配置 |

### Profile 管理 (v1.1.0)
| API | 功能 |
|-----|------|
| `ipad_wrapper_profile_download()` | 从 SM-DP+ 下载 Profile |
| `ipad_wrapper_profile_enable()` | 启用 Profile |
| `ipad_wrapper_profile_disable()` | 禁用 Profile |
| `ipad_wrapper_profile_delete()` | 删除 Profile |

### 会话管理 (v1.1.0)
| API | 功能 |
|-----|------|
| `ipad_wrapper_connect_mqtt()` | 连接 MQTT 服务 |
| `ipad_wrapper_connect_lwm2m()` | 连接 LwM2M 服务 |
| `ipad_wrapper_connect_http()` | 连接 HTTP 服务 |
| `ipad_wrapper_stop_eim_service()` | 停止 EIM 服务 |

### Fallback 机制
| API | 功能 |
|-----|------|
| `ipa__execute_fallback_mechanism()` | 执行 Fallback |
| `ipa__return_from_fallback()` | 从 Fallback 返回 |
| `ipa__execute_profile_rollback_result()` | 报告回滚结果 |

### 应急功能
| API | 功能 |
|-----|------|
| `ipa__enable_emergency_profile()` | 启用应急 Profile |
| `ipa__disable_emergency_profile()` | 禁用应急 Profile |

### 通知处理
| API | 功能 |
|-----|------|
| `ipa__notifications_delivery__all_notifications()` | 发送所有通知 |
| `ipa__notifications_delivery__seq_number_single_notification_delivery()` | 发送单个通知 |
| `ipa__notifications_delivery__remove_notification()` | 移除通知 |
| `ipa__notifications_delivery__remove_all_notifications()` | 移除所有通知 |

## 🔧 界面特性

- **API 树形选择**: 左侧显示所有可用 API，支持展开/折叠
- **动态参数输入**: 根据选中的 API 自动显示对应参数框
- **手动响应注入**: 支持模拟错误码，用于测试错误处理
- **实时日志显示**: 底部显示 API 调用日志和响应信息
- **状态监控**: 顶部显示设备连接状态和 eUICC 状态

## 🛠️ 技术栈

- **开发语言**: C (C99/C11)
- **GUI 框架**: GTK3
- **构建系统**: CMake 3.22+
- **编译工具**: GCC 7+
- **网络通信**: libcurl
- **加密库**: OpenSSL
- **多线程**: pthread

## 📦 依赖项

| 依赖 | 用途 | 安装命令 |
|------|------|----------|
| `libgtk-3-dev` | GUI 框架 | `sudo apt-get install libgtk-3-dev` |
| `libcurl4-openssl-dev` | HTTP 通信 | `sudo apt-get install libcurl4-openssl-dev` |
| `libssl-dev` | 加密库 | `sudo apt-get install libssl-dev` |
| `pkg-config` | 构建配置 | `sudo apt-get install pkg-config` |

## 🎨 界面截图

```
┌──────────────────────────────────────────────────────────┐
│  IPA 上位机程序 - IPAd SDK Controller               [×]  │
├──────────────────────────────────────────────────────────┤
│  设备状态：● 已连接    eUICC 状态：正常                   │
├────────────────┬─────────────────────────────────────────┤
│  可用 API      │  参数设置                                 │
│               │                                         │
│  └─信息获取    │  获取 EID                               │
│    ├─获取证书  │  [无参数]                              │
│    ├─获取 EID  │                                         │
│    └─获取所有 Profile │                                 │
│               │                                         │
│  └─Fallback  │  [调用 API] [清除参数] ☐ 模拟响应       │
├────────────────┴─────────────────────────────────────────┤
│  日志/响应                                                │
│  ───────────────────────────────────────────────────      │
│  [2026-02-04 15:23:45] INFO IPA 上位机程序已启动           │
│  [2026-02-04 15:24:01] INFO 调用 API: 获取 EID           │
│  [2026-02-04 15:24:02] INFO EID: 89033110123456789012345  │
└──────────────────────────────────────────────────────────┘
```

## 🔍 测试与调试

### 单元测试（待添加）

```bash
cd ipad_host_app/build
ctest --verbose
```

### 调试模式

```bash
cd ipad_host_app
mkdir build && cd build
cmake -DENABLE_DEBUG=ON -DCMAKE_BUILD_TYPE=Debug ..
make -j$(nproc)
```

### 内存检查

```bash
valgrind --leak-check=full --show-leak-kinds=all ./ipad_host_app
```

## 📝 开发计划

### 已实现/接入状态 (v1.1.0)

- ✅ 信息查询、Fallback、应急 Profile、通知处理等 wrapper 已接入
- ⚠️ Profile 管理 API 仍为框架代码，当前返回 `eNotImpl`
- ⚠️ 会话管理 wrapper 已声明，GUI 参数化调用仍需补齐
- ⚠️ 配置文件模块已实现基础解析，主程序加载和应用尚未完整接入
- ✅ 配置文档和使用指南已提供，但需随实现继续同步

### 待实现功能

- [ ] 批量操作功能
- [ ] 多语言支持 (i18n)
- [ ] 日志检索和过滤
- [ ] 自动化测试用例
- [ ] TLS 证书配置支持
- [ ] 配置热更新机制

---

**版本**: V1.1.0  
**发布日期**: 2026-02-04  
**下载**: [Release v1.1.0](https://github.com/Scott202605/ipa-application/releases/tag/v1.1.0)
