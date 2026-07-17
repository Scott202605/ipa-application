#ifndef IPADCTL_DEVICE_DISCOVERY_H
#define IPADCTL_DEVICE_DISCOVERY_H

#include <stddef.h>

int ipadctl_device_list(const char *dev_root, char *out, size_t out_size);
int ipadctl_device_command(int argc, char **argv);

#endif
