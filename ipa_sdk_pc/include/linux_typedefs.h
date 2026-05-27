/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include <linux/limits.h>

typedef struct mqtt_tls_config_s {
    char server_cert_absolute_pem_path[PATH_MAX];
    char client_cert_absolute_pem_path[PATH_MAX];
    char private_key_absolute_pem_path[PATH_MAX];
}mqtt_tls_config_t;

typedef struct mqtt_proxy_config_s {
    char url[256];
}mqtt_proxy_config_t;

