# IPA 上位机程序 - 项目结构

## 目录结构

```
/workspace/
├── README.md                      # 项目说明文档
├── PROJECT_STRUCTURE.md           # 本文件
├── build_sdk.sh                   # SDK 编译脚本
├── build_all.sh                   # 完整构建脚本
│
├── ipa_sdk_pc/                    # IPAd SDK 源码目录
│   ├── CMakeLists.txt            # SDK 主构建配置
│   ├── include/                   # SDK 头文件
│   │   ├── ipa.h                 # 主 API 头文件
│   │   ├── ipa_core.h            # 核心功能头文件
│   │   ├── ipa_local.h           # 本地功能头文件
│   │   ├── es10_typedefs.h       # ES10+ 类型定义
│   │   ├── typedefs.h            # 通用类型定义
│   │   ├── linux_typedefs.h      # Linux 平台类型定义
│   │   └── tlv_lengths.h         # TLV 长度定义
│   ├── ipa-src/                   # SDK 源代码
│   │   ├── ipa.c                 # IPA 主实现
│   │   ├── ipa.h                 # IPA 头文件
│   │   ├── profiles-assistant-commons/  # 通用功能
│   │   ├── esipa/                # eSIPa 协议栈
│   │   └── hw/linux/             # Linux 硬件抽象层
│   └── main_app/                  # SDK 自带示例程序
│
├── ipad_host_app/                 # IPA 上位机应用程序
│   ├── CMakeLists.txt            # 主机构建配置
│   ├── src/                       # 源代码目录
│   │   ├── main.c                # 程序入口点
│   │   ├── gui/                  # GUI 界面模块
│   │   │   ├── gui_main.c/h      # 主窗口实现
│   │   │   ├── gui_api_tree.c/h  # API 树形视图
│   │   │   ├── gui_param_input.c/h # 参数输入面板
│   │   │   └── gui_log_display.c/h # 日志显示面板
│   │   ├── sdk_wrapper/          # SDK 封装层
│   │   │   └── ipad_wrapper.c/h  # IPA API 包装实现
│   │   ├── business_logic/       # 业务逻辑层
│   │   │   ├── param_validator.c # 参数验证实现
│   │   │   ├── command_builder.c # 命令组装（待实现）
│   │   │   └── response_parser.c # 响应解析（待实现）
│   │   ├── utils/                # 工具模块
│   │   │   ├── logger.c          # 日志记录模块
│   │   │   └── json_helper.c     # JSON 处理辅助
│   │   └── debug/                # 调试模块
│   │       └── mock_response.c   # 模拟响应注入
│   ├── include/                   # 头文件目录
│   │   ├── ipad_app_types.h      # 应用类型定义
│   │   ├── ipad_wrapper.h        # SDK 封装头文件
│   │   └── app_api_definitions.h # API 定义列表
│   ├── resources/                # 资源文件
│   │   └── icons/                # 界面图标
│   ├── tests/                     # 测试代码（待添加）
│   ├── docs/                      # 文档目录
│   │   ├── User_Guide.md         # 用户操作指南
│   │   └── API_Reference.md      # API 参考文档
│   └── build/                     # 构建输出目录（编译后生成）
```

## 模块化设计

### 1. GUI 层 (gui/)

负责用户界面显示和交互：

- **gui_main.c**: 主窗口创建和管理
- **gui_api_tree.c**: API 树形视图组件
- **gui_param_input.c**: 动态参数输入面板
- **gui_log_display.c**: 日志和响应显示组件

### 2. SDK 封装层 (sdk_wrapper/)

封装底层 IPAd SDK API，提供统一的调用接口：

- **ipad_wrapper.c**: 所有 SDK API 的包装实现
- 功能包括：
  - SDK 初始化/反初始化
  - 设备信息查询
  - Profile 管理
  - 通知处理
  - Fallback 机制

### 3. 业务逻辑层 (business_logic/)

实现业务逻辑和数据处理：

- **param_validator.c**: 参数验证逻辑
- **command_builder.c**: 命令组装（待实现）
- **response_parser.c**: 响应数据解析（待实现）

### 4. 工具模块 (utils/)

通用工具函数：

- **logger.c**: 日志记录功能
- **json_helper.c**: JSON 数据解析和生成

### 5. 调试模块 (debug/)

调试和测试功能：

- **mock_response.c**: 模拟响应注入（用于测试）

## 数据流

```
用户操作
   ↓
GUI 层 (接收输入，显示结果)
   ↓
SDK 封装层 (调用包装后的 API)
   ↓
IPAd SDK (底层实现)
   ↓
硬件/网络 (eUICC 设备，SM-DP+ 服务器)
```

## 构建流程

### 1. 编译 SDK

```bash
cd /workspace/ipa_sdk_pc
mkdir build && cd build
cmake ..
make -j$(nproc)
```

输出：
- `build/libipa-core.a` (静态库)
- `build/libipa-core.so` (动态库)
- `dist/include/` (头文件)

### 2. 编译上位机程序

```bash
cd /workspace/ipad_host_app
mkdir build && cd build
cmake ..
make -j$(nproc)
```

输出：
- `build/ipad_host_app` (可执行文件)

## 依赖关系

```
ipad_host_app
├── GTK3 (GUI 框架)
├── libcurl (HTTP 通信)
├── OpenSSL (加密)
├── pthread (多线程)
└── ipa-core (SDK 核心库)
```

## 文件说明

| 文件 | 说明 | 行数（约） |
|------|------|------------|
| `ipa_sdk_pc/include/ipa.h` | SDK 主 API 头文件 | 320 |
| `ipa_sdk_pc/ipa-src/ipa.c` | SDK 主实现 | 4551 |
| `ipad_host_app/src/main.c` | 上位机入口 | 70 |
| `ipad_host_app/src/gui/gui_main.c` | GUI 主窗口 | 200 |
| `ipad_host_app/src/sdk_wrapper/ipad_wrapper.c` | SDK 封装 | 200 |
| `ipad_host_app/src/business_logic/param_validator.c` | 参数验证 | 120 |

## 后续扩展

### 待实现功能

1. **Profile 管理 API** (完整实现下载、启用、禁用、删除)
2. **会话管理 API** (MQTT/LwM2M/HTTP 通信)
3. **完整的错误处理和重试机制**
4. **配置文件支持** (JSON/YAML 格式)
5. **批量操作支持** (批量导入/导出 Profile)
6. **日志过滤和搜索功能**
7. **多语言支持** (i18n)

### 测试计划

- 单元测试 (使用 CMocka 或类似框架)
- 集成测试 (与真实 eUICC 设备联调)
- UI 自动化测试 (使用 LDTP 或 Dogtail)

