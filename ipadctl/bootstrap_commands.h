#ifndef IPADCTL_BOOTSTRAP_COMMANDS_H
#define IPADCTL_BOOTSTRAP_COMMANDS_H

#include <stddef.h>

int ipadctl_bootstrap_check(const char *root, const char *mode, const char *at_device, char *out, size_t out_size);
int ipadctl_bootstrap_command(int argc, char **argv);

#endif
