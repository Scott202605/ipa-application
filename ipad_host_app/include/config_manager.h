#ifndef CONFIG_MANAGER_H
#define CONFIG_MANAGER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================================
// 配置结构定义
// ============================================================================

// IPA 核心配置
typedef struct {
    int es10_driver;           // 0=AT, 1=NONE
    char driver_id[128];       // 设备 ID（如/dev/ttyUSB0）
    int log_level;             // 1=Err, 2=Warn, 3=Info, 4=Debug, 5=Trace
    int initial_refresh_sleep; // 初始刷新睡眠（秒）
    int refresh_max_sleep;     // 最大刷新睡眠（秒）
    int esipa_sync_package_retrieval_time; // eSIPa 同步包获取时间（秒）
} ipa_core_config_t;

// MQTT 配置
typedef struct {
    bool enabled;
    char hostname[256];
    int port;
    char username[64];
    char password[64];
    bool use_tls;
    char ca_cert_path[256];
    char client_cert_path[256];
    char client_key_path[256];
} mqtt_config_t;

// LwM2M 配置
typedef struct {
    bool enabled;
    char hostname[256];
    int port;
    char client_name[64];
    bool use_dtls;
    bool bootstrap;
    bool use_ipv4;
} lwm2m_config_t;

// HTTP 配置
typedef struct {
    bool enabled;
    char fqdn[256];
    uint32_t max_time_without_transmission;
    uint32_t http_timeout;
    uint32_t sync_sleep_time;
} http_config_t;

// UI 配置
typedef struct {
    int window_width;
    int window_height;
    int font_size;
    char log_file_path[256];
    bool auto_save_logs;
} ui_config_t;

// 调试配置
typedef struct {
    bool enable_mock_response;
    int mock_error_code;
    bool enable_debug_logging;
} debug_config_t;

// 主配置结构
typedef struct {
    char config_version[16];
    ipa_core_config_t ipa_core;
    mqtt_config_t mqtt;
    lwm2m_config_t lwm2m;
    http_config_t http;
    ui_config_t ui;
    debug_config_t debug;
} ipad_config_t;

// ============================================================================
// 配置管理函数
// ============================================================================

/**
 * @brief 初始化配置管理器
 * @param config_path 配置文件路径
 * @return 0 成功，-1 失败
 */
int config_init(const char *config_path);

/**
 * @brief 反初始化配置管理器
 */
void config_deinit(void);

/**
 * @brief 加载配置文件
 * @param config_path 配置文件路径
 * @param config 配置结构指针
 * @return 0 成功，-1 失败
 */
int config_load(const char *config_path, ipad_config_t *config);

/**
 * @brief 保存配置到文件
 * @param config_path 配置文件路径
 * @param config 配置结构指针
 * @return 0 成功，-1 失败
 */
int config_save(const char *config_path, ipad_config_t *config);

/**
 * @brief 使用默认配置初始化
 * @param config 配置结构指针
 */
void config_set_defaults(ipad_config_t *config);

/**
 * @brief 获取当前配置
 * @return 当前配置结构指针
 */
const ipad_config_t* config_get_current(void);

/**
 * @brief 验证配置有效性
 * @param config 配置结构指针
 * @return 0 有效，-1 无效
 */
int config_validate(const ipad_config_t *config);

/**
 * @brief 配置结构转 JSON 字符串
 * @param config 配置结构指针
 * @param json_out JSON 字符串输出缓冲区
 * @param json_size 缓冲区大小
 * @return 0 成功，-1 失败
 */
int config_to_json(const ipad_config_t *config, char *json_out, size_t json_size);

/**
 * @brief 从 JSON 字符串解析配置
 * @param json_str JSON 字符串
 * @param config 配置结构指针
 * @return 0 成功，-1 失败
 */
int config_from_json(const char *json_str, ipad_config_t *config);

#ifdef __cplusplus
}
#endif

#endif // CONFIG_MANAGER_H
