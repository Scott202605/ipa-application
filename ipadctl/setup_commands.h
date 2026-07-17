#ifndef IPADCTL_SETUP_COMMANDS_H
#define IPADCTL_SETUP_COMMANDS_H

#include <stddef.h>

int ipadctl_setup_mock(const char *config_path, char *out, size_t out_size);
int ipadctl_setup_real_at(const char *config_path, const char *at_device, char *out, size_t out_size);
int ipadctl_setup_command(int argc, char **argv, const char *default_config_path);

#endif
