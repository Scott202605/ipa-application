#ifndef IPADCTL_CONFIG_COMMANDS_H
#define IPADCTL_CONFIG_COMMANDS_H

#include <stddef.h>

int ipadctl_config_show_to_buffer(const char *config_path, char *out, size_t out_size);
int ipadctl_config_check_to_buffer(const char *config_path, char *out, size_t out_size);
int ipadctl_config_command(int argc, char **argv, const char *default_config_path);

#endif
