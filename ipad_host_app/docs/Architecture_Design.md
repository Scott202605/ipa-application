# IPA 上位机程序 - 架构设计文档

## 1. 概述

本文档描述 IPA 上位机程序的整体架构设计，包括系统分层、模块划分、数据流和控制流。

## 2. 系统架构

### 2.1 分层架构

```
┌─────────────────────────────────────────────────────────┐
│              表示层 (Presentation Layer)                 │
│         GUI 界面 | 用户交互 | 状态显示 | 日志显示         │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│              业务逻辑层 (Business Logic Layer)           │
│    参数验证 | 命令组装 | 响应解析 | 状态管理             │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│              SDK 封装层 (SDK Wrapper Layer)              │
│      API 包装 | 错误处理 | 内存管理 | 回调处理           │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│              IPAd SDK Layer                              │
│   IPA 核心 | eSIPa | GSMA ES10+/ES9/ES11 | eUICC 通信    │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│              硬件抽象层 (HAL)                            │
│    卡读写 | 网络通信 | 加密 | 日志 | 定时器              │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│              操作系统/硬件 (Linux / eUICC)               │
└─────────────────────────────────────────────────────────┘
```

### 2.2 模块划分

```
ipad_host_app
│
├── GUI 层 (gui/)
│   ├── gui_main.c/h
│   │   └── 主窗口管理，事件循环，状态更新
│   ├── gui_api_tree.c/h
│   │   └── API 树形视图，选择处理
│   ├── gui_param_input.c/h
│   │   └── 动态参数输入，输入验证
│   └── gui_log_display.c/h
│       └── 日志显示，自动滚动，格式化输出
│
├── SDK 封装层 (sdk_wrapper/)
│   └── ipad_wrapper.c/h
│       ├── 初始化/反初始化
│       ├── 信息查询 API 包装
│       ├── Profile 管理 API 包装
│       ├── 通知管理 API 包装
│       └── 工具函数（错误码转换，资源释放）
│
├── 业务逻辑层 (business_logic/)
│   ├── param_validator.c
│   │   └── 参数格式验证，边界检查
│   ├── command_builder.c (待实现)
│   │   └── 命令构建，参数序列化
│   └── response_parser.c (待实现)
│       └── 响应解析，数据提取
│
├── 工具模块 (utils/)
│   ├── logger.c
│   │   └── 日志记录，级别控制
│   └── json_helper.c
│       └── JSON 数据解析和生成
│
└── 调试模块 (debug/)
    └── mock_response.c
        └── 模拟响应注入，测试模式
```

## 3. 数据流

### 3.1 API 调用流程

```
用户选择 API → GUI 显示参数 → 用户输入 → 参数验证
                                           ↓
← GUI 更新状态 ← SDK 封装调用 ← 业务逻辑处理 ← 验证通过
        ↓                                  ↓
  显示结果                            验证失败
        ↓                                  ↓
  记录日志                            显示错误
```

### 3.2 异步事件处理

```
IPA SDK 事件 → 事件回调 → GUI 主线程 → 状态更新
                  ↓
             日志记录
                  ↓
             界面刷新
```

## 4. 关键技术点

### 4.1 动态参数输入

根据选中的 API 自动创建参数输入框：

```c
// 伪代码
void create_param_inputs(const api_descriptor_t *api) {
    for (int i = 0; i < api->param_count; i++) {
        param_descriptor_t *param = &api->params[i];
        
        switch (param->type) {
            case PARAM_TYPE_STRING:
                widget = gtk_entry_new();
                break;
            case PARAM_TYPE_ENUM:
                widget = gtk_combo_box_text_new();
                // 添加枚举选项
                break;
            // ... 其他类型
        }
        
        gtk_grid_attach(param_grid, label, widget, ...);
    }
}
```

### 4.2 模拟响应注入

用于测试错误处理和边界情况：

```c
// mock_response.c
if (g_debug_config.mock_enabled) {
    LOGI("[MOCK] 跳过真实 SDK 调用，返回模拟错误码");
    return g_debug_config.mock_error_code;
}

// 正常调用 SDK
return ipa__get_eid_cstring(buffer, buffer_size);
```

### 4.3 异步 API 调用（待实现）

避免长时间操作阻塞 GUI：

```c
typedef struct {
    const char *api_name;
    void *params;
    GtkWidget *progress_dialog;
} async_call_context_t;

void start_async_api_call(const char *api_name, void *params) {
    GThread *thread = g_thread_new("api_call", 
                                   api_call_worker, 
                                   context);
    // 显示进度对话框
}

gpointer api_call_worker(gpointer data) {
    async_call_context_t *ctx = data;
    int result = invoke_sdk_api(ctx->api_name, ctx->params);
    
    // 返回主线程更新 UI
    g_idle_add((GSourceFunc)update_ui_with_result, result);
    return NULL;
}
```

### 4.4 线程安全日志

```c
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

void log_write(log_level_t level, const char *format, ...) {
    pthread_mutex_lock(&log_mutex);
    
    // 写入日志
    pthread_mutex_unlock(&log_mutex);
}
```

## 5. 内存管理策略

### 5.1 SDK 内存分配/释放

```c
// SDK 返回的内存需要明确释放
profile_info_t *profiles;
uint32_t num_profiles;

ErrCode ret = ipa__get_all_profiles_info(&profiles, &num_profiles, NULL);
if (ret == eOk) {
    // 使用 profiles...
    
    // 释放分配的内存
    for (uint32_t i = 0; i < num_profiles; i++) {
        // 释放动态分配的字段
    }
    free(profiles);
}
```

### 5.2 GUI 内存管理

```c
// GTK 部件自动引用计数
GtkWidget *widget = gtk_button_new();
gtk_container_add(GTK_CONTAINER(window), widget);
// GTK 会自动管理 widget 的生命周期

// 手动释放的资源
g_free(string_data);
g_list_free(widget_list);
```

## 6. 错误处理机制

### 6.1 错误码转换

```c
const char* ipad_wrapper_strerror(ErrCode error_code) {
    switch (error_code) {
        case eOk: return "成功";
        case eFatal: return "致命错误";
        case eBadArg: return "参数错误";
        // ...
        default: return "未知错误";
    }
}
```

### 6.2 错误处理流程

```c
ErrCode call_api(void) {
    // 1. 参数验证
    if (!validate_params()) {
        return eBadArg;
    }
    
    // 2. 调用 SDK
    ErrCode ret = ipa__some_api(...);
    
    // 3. 处理错误
    if (ret != eOk) {
        // 3.1 记录日志
        log_error("API 调用失败：%s", ipad_wrapper_strerror(ret));
        
        // 3.2 显示错误
        show_error_dialog(ipad_wrapper_strerror(ret));
        
        // 3.3 清理资源
        cleanup();
    }
    
    return ret;
}
```

## 7. 配置管理（待实现）

### 7.1 配置文件格式

```json
{
    "ipa_config": {
        "log_level": "info",
        "es10_driver": "at",
        "driver_id": "/dev/ttyUSB0"
    },
    "network_config": {
        "http_timeout": 30,
        "retry_count": 3
    },
    "ui_config": {
        "window_width": 1200,
        "window_height": 800,
        "font_size": 10
    }
}
```

### 7.2 配置加载

```c
int load_config(const char *config_path) {
    // 1. 读取文件
    // 2. 解析 JSON
    // 3. 填充配置结构
    // 4. 应用配置
    return 0;
}
```

## 8. 性能优化建议

### 8.1 GUI 响应性

- 长时间操作在后台线程执行
- 使用 g_idle_add() 更新 UI
- 避免在事件处理中进行阻塞操作

### 8.2 内存使用

- 及时释放不再使用的内存
- 使用对象池复用频繁创建/销毁的对象
- 避免内存泄漏（使用 valgrind 检查）

### 8.3 日志性能

- 异步写入日志文件
- 控制日志文件大小（轮转）
- 减少不必要的 DEBUG 日志

## 9. 扩展性设计

### 9.1 新 API 支持

添加新 API 只需：

1. 在 `app_api_definitions.h` 中添加 API 定义
2. 在 `ipad_wrapper.c` 中添加包装函数
3. 在参数输入模块中添加对应的输入处理

### 9.2 多语言支持（待实现）

```c
// 使用 gettext 框架
#include <libintl.h>
#include <locale.h>

setlocale(LC_ALL, "");
bindtextdomain("ipad_host_app", "/usr/share/locale");
textdomain("ipad_host_app");

// 使用
printf(_("Initializing IPA SDK..."));
```

### 9.3 插件架构（未来扩展）

```c
typedef struct {
    int (*init)(void);
    int (*deinit)(void);
    int (*handle_api_call)(const char *api_name, void *params);
} plugin_interface_t;

// 动态加载插件
void *handle = dlopen("plugin.so", RTLD_LAZY);
plugin_interface_t *plugin = dlsym(handle, "plugin_interface");
```

---

**文档版本**: V1.0  
**最后更新**: 2026-02-04

