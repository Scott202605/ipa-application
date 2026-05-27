# 配置文件使用指南

## 配置文件位置

配置文件默认位置：
- 系统级：`/etc/ipad_host_app/config.json`
- 用户级：`$HOME/.config/ipad_host_app/config.json`
- 开发级：`./config/ipad_config.json`（相对于程序运行目录）

## 配置文件格式

配置文件采用 JSON 格式，示例如下：

```json
{
  "config_version": "1.0.0",
  "es10_driver": 0,
  "driver_id": "/dev/ttyUSB0",
  "log_level": 3,
  "initial_refresh_sleep": 1,
  "refresh_max_sleep": 64,
  
  "mqtt_enabled": false,
  "mqtt_hostname": "mqtt.example.com",
  "mqtt_port": 1883,
  "mqtt_use_tls": false,
  
  "lwm2m_enabled": false,
  "lwm2m_hostname": "lwm2m.example.com",
  "lwm2m_port": 5684,
  "lwm2m_client_name": "ipa-client-001",
  "lwm2m_use_dtls": true,
  
  "http_enabled": true,
  "http_fqdn": "smdp.example.com",
  "http_timeout": 30,
  "http_max_timeout": 3600,
  
  "window_width": 1200,
  "window_height": 800,
  "font_size": 10,
  "auto_save_logs": true,
  "log_file_path": "/var/log/ipad/ipad_host_app.log",
  
  "enable_mock_response": false,
  "enable_debug_logging": false,
  "mock_error_code": 0
}
```

## 配置项说明

### IPA 核心配置

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `es10_driver` | int | 0 | ES10 驱动类型：0=AT, 1=NONE |
| `driver_id` | string | /dev/ttyUSB0 | 设备 ID（串口设备路径） |
| `log_level` | int | 3 | 日志级别：1=Err, 2=Warn, 3=Info, 4=Debug, 5=Trace |
| `initial_refresh_sleep` | int | 1 | 初始刷新睡眠（秒） |
| `refresh_max_sleep` | int | 64 | 最大刷新睡眠（秒） |

### MQTT 配置

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `mqtt_enabled` | bool | false | 是否启用 MQTT |
| `mqtt_hostname` | string | - | MQTT 服务器主机名 |
| `mqtt_port` | int | 1883 | MQTT 端口 |
| `mqtt_use_tls` | bool | false | 是否使用 TLS 加密 |
| `mqtt_username` | string | - | 用户名 |
| `mqtt_password` | string | - | 密码 |

### LwM2M 配置

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `lwm2m_enabled` | bool | false | 是否启用 LwM2M |
| `lwm2m_hostname` | string | - | LwM2M 服务器主机名 |
| `lwm2m_port` | int | 5684 | LwM2M 端口 |
| `lwm2m_client_name` | string | ipa-client | 客户端名称 |
| `lwm2m_use_dtls` | bool | true | 是否使用 DTLS 加密 |
| `lwm2m_bootstrap` | bool | false | 是否使用 Bootstrap |

### HTTP 配置

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `http_enabled` | bool | true | 是否启用 HTTP |
| `http_fqdn` | string | - | HTTP 服务器域名 |
| `http_timeout` | int | 30 | HTTP 超时时间（秒） |
| `http_max_timeout` | int | 3600 | 最大无传输时间（秒） |

### UI 配置

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `window_width` | int | 1200 | 窗口宽度 |
| `window_height` | int | 800 | 窗口高度 |
| `font_size` | int | 10 | 字体大小 |
| `auto_save_logs` | bool | true | 是否自动保存日志 |
| `log_file_path` | string | /var/log/ipad/ipad_host_app.log | 日志文件路径 |

### 调试配置

| 配置项 | 类型 | 默认值 | 说明 |
|--------|------|--------|------|
| `enable_mock_response` | bool | false | 是否启用模拟响应 |
| `enable_debug_logging` | bool | false | 是否启用调试日志 |
| `mock_error_code` | int | 0 | 模拟错误码 |

## 使用示例

### 示例 1: 启用 MQTT 通信

```json
{
  "mqtt_enabled": true,
  "mqtt_hostname": "mqtt.example.com",
  "mqtt_port": 8883,
  "mqtt_use_tls": true
}
```

### 示例 2: 配置日志级别为 Debug

```json
{
  "log_level": 4,
  "enable_debug_logging": true,
  "log_file_path": "/home/user/ipad_debug.log"
}
```

### 示例 3: 配置窗口大小

```json
{
  "window_width": 1920,
  "window_height": 1080,
  "font_size": 12
}
```

## 配置文件加载顺序

程序启动时按以下顺序查找配置文件：

1. 命令行参数指定的路径（`-c` 或 `--config`）
2. 当前目录的 `config.json`
3. 用户目录的 `$HOME/.config/ipad_host_app/config.json`
4. 系统目录的 `/etc/ipad_host_app/config.json`

如果所有位置都找不到配置文件，将使用内置默认值。

## 验证配置文件

配置文件会自动验证，无效的配置项将使用默认值。

验证失败时会在日志中输出警告信息。

## 注意事项

1. **路径配置**: 确保 `log_file_path` 指向的目录存在且可写
2. **端口配置**: MQTT(1883/8883)、LwM2M(5683/5684) 使用标准端口
3. **TLS/DTLS**: 启用加密时需要额外的证书配置
4. **设备路径**: `driver_id` 必须是有效的串口设备路径
5. **调试功能**: `enable_mock_response` 仅用于测试，生产环境应禁用

## 配置文件示例

完整的示例配置文件位于：
```
/workspace/ipad_host_app/config/ipad_config.example.json
```

可以复制该文件并根据实际需求修改后使用。

