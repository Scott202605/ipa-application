#include "config_manager.h"
#include "json_helper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static ipad_config_t g_current_config;
static bool g_config_initialized = false;

// 默认配置值
static void config_set_defaults_impl(ipad_config_t *config) {
    memset(config, 0, sizeof(*config));
    strncpy(config->config_version, "1.0.0", sizeof(config->config_version) - 1);
    
    // IPA 核心默认配置
    config->ipa_core.es10_driver = 0; // AT
    config->ipa_core.log_level = 3;   // Info
    config->ipa_core.initial_refresh_sleep = 1;
    config->ipa_core.refresh_max_sleep = 64;
    config->ipa_core.esipa_sync_package_retrieval_time = 30;
    
    // MQTT 默认配置
    config->mqtt.enabled = false;
    config->mqtt.port = 1883;
    config->mqtt.use_tls = false;
    
    // LwM2M 默认配置
    config->lwm2m.enabled = false;
    config->lwm2m.port = 5684;
    config->lwm2m.use_dtls = true;
    config->lwm2m.bootstrap = false;
    config->lwm2m.use_ipv4 = true;
    strncpy(config->lwm2m.client_name, "ipa-client", sizeof(config->lwm2m.client_name) - 1);
    
    // HTTP 默认配置
    config->http.enabled = true;
    config->http.max_time_without_transmission = 3600;
    config->http.http_timeout = 30;
    config->http.sync_sleep_time = 10;
    
    // UI 默认配置
    config->ui.window_width = 1200;
    config->ui.window_height = 800;
    config->ui.font_size = 10;
    config->ui.auto_save_logs = true;
    
    // 调试默认配置
    config->debug.enable_mock_response = false;
    config->debug.mock_error_code = 0;
    config->debug.enable_debug_logging = false;
}

void config_set_defaults(ipad_config_t *config) {
    if (config) {
        config_set_defaults_impl(config);
    }
}

// 解析 JSON 中的整数值
static int json_get_int(const char *json, const char *key, int default_val) {
    char value[64] = {0};
    if (json_get_string_value(json, key, value, sizeof(value)) == 0) {
        return atoi(value);
    }
    // 尝试查找不含引号的值
    const char *key_pos = strstr(json, key);
    if (key_pos) {
        const char *colon = strchr(key_pos, ':');
        if (colon) {
            return atoi(colon + 1);
        }
    }
    return default_val;
}

// 解析 JSON 中的布尔值
static bool json_get_bool(const char *json, const char *key, bool default_val) {
    const char *key_pos = strstr(json, key);
    if (key_pos) {
        const char *colon = strchr(key_pos, ':');
        if (colon) {
            const char *val = colon + 1;
            while (*val == ' ') val++;
            if (strncmp(val, "true", 4) == 0) return true;
            if (strncmp(val, "false", 5) == 0) return false;
        }
    }
    return default_val;
}

int config_load(const char *config_path, ipad_config_t *config) {
    if (!config) {
        return -1;
    }
    
    // 先设置默认值
    config_set_defaults_impl(config);

    if (!config_path || config_path[0] == '\0') {
        return 0;
    }
    
    // 检查文件是否存在
    struct stat st;
    if (stat(config_path, &st) != 0) {
        printf("配置文件不存在：%s, 使用默认配置\n", config_path);
        return 0;
    }
    
    // 读取文件
    FILE *fp = fopen(config_path, "r");
    if (!fp) {
        printf("无法打开配置文件：%s\n", config_path);
        return -1;
    }
    
    // 获取文件大小
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    if (file_size < 0) {
        fclose(fp);
        return -1;
    }
    fseek(fp, 0, SEEK_SET);
    
    // 读取内容
    char *json_str = malloc(file_size + 1);
    if (!json_str) {
        fclose(fp);
        return -1;
    }
    
    size_t bytes_read = fread(json_str, 1, (size_t)file_size, fp);
    if (bytes_read != (size_t)file_size && ferror(fp)) {
        free(json_str);
        fclose(fp);
        return -1;
    }
    json_str[file_size] = '\0';
    fclose(fp);
    
    // 解析 JSON
    if (config_from_json(json_str, config) != 0) {
        printf("解析配置文件失败\n");
        free(json_str);
        return -1;
    }
    
    free(json_str);
    printf("配置文件加载成功：%s\n", config_path);
    return 0;
}

int config_from_json(const char *json_str, ipad_config_t *config) {
    if (!json_str || !config) {
        return -1;
    }
    
    // 设置默认值
    config_set_defaults_impl(config);
    
    // 解析版本
    char version[16] = {0};
    if (json_get_string_value(json_str, "config_version", version, sizeof(version)) == 0) {
        strncpy(config->config_version, version, sizeof(config->config_version) - 1);
    }
    
    // 解析 IPA 核心配置
    config->ipa_core.es10_driver = json_get_int(json_str, "es10_driver", config->ipa_core.es10_driver);
    config->ipa_core.log_level = json_get_int(json_str, "log_level", config->ipa_core.log_level);
    config->ipa_core.initial_refresh_sleep = json_get_int(json_str, "initial_refresh_sleep", config->ipa_core.initial_refresh_sleep);
    config->ipa_core.refresh_max_sleep = json_get_int(json_str, "refresh_max_sleep", config->ipa_core.refresh_max_sleep);
    
    json_get_string_value(json_str, "driver_id", config->ipa_core.driver_id, sizeof(config->ipa_core.driver_id));
    
    // 解析 MQTT 配置
    config->mqtt.enabled = json_get_bool(json_str, "mqtt_enabled", config->mqtt.enabled);
    config->mqtt.port = json_get_int(json_str, "mqtt_port", config->mqtt.port);
    config->mqtt.use_tls = json_get_bool(json_str, "mqtt_use_tls", config->mqtt.use_tls);
    json_get_string_value(json_str, "mqtt_hostname", config->mqtt.hostname, sizeof(config->mqtt.hostname));
    json_get_string_value(json_str, "mqtt_username", config->mqtt.username, sizeof(config->mqtt.username));
    json_get_string_value(json_str, "mqtt_password", config->mqtt.password, sizeof(config->mqtt.password));
    
    // 解析 LwM2M 配置
    config->lwm2m.enabled = json_get_bool(json_str, "lwm2m_enabled", config->lwm2m.enabled);
    config->lwm2m.port = json_get_int(json_str, "lwm2m_port", config->lwm2m.port);
    config->lwm2m.use_dtls = json_get_bool(json_str, "lwm2m_use_dtls", config->lwm2m.use_dtls);
    config->lwm2m.bootstrap = json_get_bool(json_str, "lwm2m_bootstrap", config->lwm2m.bootstrap);
    json_get_string_value(json_str, "lwm2m_hostname", config->lwm2m.hostname, sizeof(config->lwm2m.hostname));
    json_get_string_value(json_str, "lwm2m_client_name", config->lwm2m.client_name, sizeof(config->lwm2m.client_name));
    
    // 解析 HTTP 配置
    config->http.enabled = json_get_bool(json_str, "http_enabled", config->http.enabled);
    config->http.http_timeout = json_get_int(json_str, "http_timeout", config->http.http_timeout);
    config->http.max_time_without_transmission = json_get_int(json_str, "http_max_timeout", config->http.max_time_without_transmission);
    json_get_string_value(json_str, "http_fqdn", config->http.fqdn, sizeof(config->http.fqdn));
    
    // 解析 UI 配置
    config->ui.window_width = json_get_int(json_str, "window_width", config->ui.window_width);
    config->ui.window_height = json_get_int(json_str, "window_height", config->ui.window_height);
    config->ui.font_size = json_get_int(json_str, "font_size", config->ui.font_size);
    config->ui.auto_save_logs = json_get_bool(json_str, "auto_save_logs", config->ui.auto_save_logs);
    json_get_string_value(json_str, "log_file_path", config->ui.log_file_path, sizeof(config->ui.log_file_path));
    
    // 解析调试配置
    config->debug.enable_mock_response = json_get_bool(json_str, "enable_mock_response", config->debug.enable_mock_response);
    config->debug.enable_debug_logging = json_get_bool(json_str, "enable_debug_logging", config->debug.enable_debug_logging);
    config->debug.mock_error_code = json_get_int(json_str, "mock_error_code", config->debug.mock_error_code);
    
    return 0;
}

int config_to_json(const ipad_config_t *config, char *json_out, size_t json_size) {
    if (!config || !json_out || json_size < 1024) {
        return -1;
    }
    
    snprintf(json_out, json_size,
        "{\n"
        "  \"config_version\": \"%s\",\n"
        "  \"es10_driver\": %d,\n"
        "  \"driver_id\": \"%s\",\n"
        "  \"log_level\": %d,\n"
        "  \"initial_refresh_sleep\": %d,\n"
        "  \"refresh_max_sleep\": %d,\n"
        "  \"mqtt_enabled\": %s,\n"
        "  \"mqtt_hostname\": \"%s\",\n"
        "  \"mqtt_port\": %d,\n"
        "  \"mqtt_use_tls\": %s,\n"
        "  \"lwm2m_enabled\": %s,\n"
        "  \"lwm2m_hostname\": \"%s\",\n"
        "  \"lwm2m_port\": %d,\n"
        "  \"lwm2m_client_name\": \"%s\",\n"
        "  \"lwm2m_use_dtls\": %s,\n"
        "  \"http_enabled\": %s,\n"
        "  \"http_fqdn\": \"%s\",\n"
        "  \"http_timeout\": %d,\n"
        "  \"window_width\": %d,\n"
        "  \"window_height\": %d,\n"
        "  \"font_size\": %d,\n"
        "  \"auto_save_logs\": %s,\n"
        "  \"log_file_path\": \"%s\",\n"
        "  \"enable_mock_response\": %s,\n"
        "  \"enable_debug_logging\": %s,\n"
        "  \"mock_error_code\": %d\n"
        "}\n",
        config->config_version,
        config->ipa_core.es10_driver,
        config->ipa_core.driver_id[0] ? config->ipa_core.driver_id : "/dev/ttyUSB0",
        config->ipa_core.log_level,
        config->ipa_core.initial_refresh_sleep,
        config->ipa_core.refresh_max_sleep,
        config->mqtt.enabled ? "true" : "false",
        config->mqtt.hostname,
        config->mqtt.port,
        config->mqtt.use_tls ? "true" : "false",
        config->lwm2m.enabled ? "true" : "false",
        config->lwm2m.hostname,
        config->lwm2m.port,
        config->lwm2m.client_name,
        config->lwm2m.use_dtls ? "true" : "false",
        config->http.enabled ? "true" : "false",
        config->http.fqdn,
        config->http.http_timeout,
        config->ui.window_width,
        config->ui.window_height,
        config->ui.font_size,
        config->ui.auto_save_logs ? "true" : "false",
        config->ui.log_file_path,
        config->debug.enable_mock_response ? "true" : "false",
        config->debug.enable_debug_logging ? "true" : "false",
        config->debug.mock_error_code
    );
    
    return 0;
}

int config_save(const char *config_path, ipad_config_t *config) {
    if (!config_path || !config) {
        return -1;
    }
    
    char json_str[4096] = {0};
    if (config_to_json(config, json_str, sizeof(json_str)) != 0) {
        return -1;
    }
    
    FILE *fp = fopen(config_path, "w");
    if (!fp) {
        return -1;
    }
    
    fwrite(json_str, 1, strlen(json_str), fp);
    fclose(fp);
    
    printf("配置文件保存成功：%s\n", config_path);
    return 0;
}

int config_validate(const ipad_config_t *config) {
    if (!config) {
        return -1;
    }
    
    // 验证版本号
    if (strlen(config->config_version) == 0) {
        return -1;
    }
    
    // 验证 log level
    if (config->ipa_core.log_level < 1 || config->ipa_core.log_level > 5) {
        return -1;
    }
    
    // 验证窗口大小
    if (config->ui.window_width < 800 || config->ui.window_width > 3840) {
        return -1;
    }
    if (config->ui.window_height < 600 || config->ui.window_height > 2160) {
        return -1;
    }
    
    // 验证超时时间
    if (config->http.http_timeout < 1 || config->http.http_timeout > 300) {
        return -1;
    }
    
    return 0;
}

int config_init(const char *config_path) {
    // 加载配置
    if (config_load(config_path, &g_current_config) != 0) {
        printf("加载配置失败，使用默认配置\n");
        config_set_defaults_impl(&g_current_config);
    }
    
    // 验证配置
    if (config_validate(&g_current_config) != 0) {
        printf("配置验证失败，使用默认配置\n");
        config_set_defaults_impl(&g_current_config);
    }
    
    g_config_initialized = true;
    return 0;
}

void config_deinit(void) {
    g_config_initialized = false;
}

const ipad_config_t* config_get_current(void) {
    return &g_current_config;
}
