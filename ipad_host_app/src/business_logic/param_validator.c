#include <stdio.h>
#include <string.h>

// ============================================================================
// 参数验证函数实现
// ============================================================================

// ICCID 格式验证（19-20 位数字）
int validate_iccid(const char *iccid) {
    if (!iccid) return 0;
    
    size_t len = strlen(iccid);
    if (len < 19 || len > 20) return 0;
    
    // 检查是否全部为数字
    for (size_t i = 0; i < len; i++) {
        if (iccid[i] < '0' || iccid[i] > '9') return 0;
    }
    
    return 1;
}

// SM-DP+ 地址验证（URL 格式）
int validate_smdp_address(const char *address) {
    if (!address) return 0;
    
    // 简单验证：至少包含一个 '.'
    if (!strchr(address, '.')) return 0;
    
    // 检查长度
    size_t len = strlen(address);
    if (len < 4 || len > 255) return 0;
    
    return 1;
}

// 确认码验证（4-8 位字母数字）
int validate_confirmation_code(const char *code) {
    if (!code) return 1;  // 确认码是可选的
    
    size_t len = strlen(code);
    if (len < 4 || len > 8) return 0;
    
    // 检查是否为字母数字
    for (size_t i = 0; i < len; i++) {
        char c = code[i];
        if (!((c >= '0' && c <= '9') ||
              (c >= 'A' && c <= 'Z') ||
              (c >= 'a' && c <= 'z'))) {
            return 0;
        }
    }
    
    return 1;
}

// Transaction ID 验证（最大 16 字节十六进制）
int validate_transaction_id(const char *trans_id) {
    if (!trans_id) return 0;
    
    size_t len = strlen(trans_id);
    if (len == 0 || len > 32) return 0;  // 16 字节的十六进制是 32 个字符
    
    for (size_t i = 0; i < len; i++) {
        char c = trans_id[i];
        if (!((c >= '0' && c <= '9') ||
              (c >= 'A' && c <= 'F') ||
              (c >= 'a' && c <= 'f'))) {
            return 0;
        }
    }
    
    return 1;
}

// FQDN 格式验证
int validate_fqdn(const char *fqdn) {
    if (!fqdn) return 0;
    
    size_t len = strlen(fqdn);
    if (len < 4 || len > 255) return 0;
    
    // 至少包含一个 '.'
    if (!strchr(fqdn, '.')) return 0;
    
    // 不能以 '.' 开头或结尾
    if (fqdn[0] == '.' || fqdn[len-1] == '.') return 0;
    
    return 1;
}

// PKID 验证（20 字节二进制，通常表示为 40 个十六进制字符）
int validate_pkid(const char *pkid) {
    if (!pkid) return 0;
    
    size_t len = strlen(pkid);
    if (len != 40) return 0;  // 20 字节的十六进制表示
    
    for (size_t i = 0; i < len; i++) {
        char c = pkid[i];
        if (!((c >= '0' && c <= '9') ||
              (c >= 'A' && c <= 'F') ||
              (c >= 'a' && c <= 'f'))) {
            return 0;
        }
    }
    
    return 1;
}

// 十六进制字符串验证
int validate_hex_string(const char *hex) {
    if (!hex) return 0;
    
    size_t len = strlen(hex);
    if (len == 0 || len % 2 != 0) return 0;  // 必须是偶数
    
    for (size_t i = 0; i < len; i++) {
        char c = hex[i];
        if (!((c >= '0' && c <= '9') ||
              (c >= 'A' && c <= 'F') ||
              (c >= 'a' && c <= 'f'))) {
            return 0;
        }
    }
    
    return 1;
}

// 整数范围验证
int validate_int_range(int value, int min, int max) {
    return (value >= min && value <= max);
}
