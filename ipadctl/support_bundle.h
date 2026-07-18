#ifndef IPADCTL_SUPPORT_BUNDLE_H
#define IPADCTL_SUPPORT_BUNDLE_H

#include <stddef.h>

int ipadctl_support_bundle_create(const char *config_path,
                                  const char *socket_path,
                                  const char *output_dir,
                                  char *out,
                                  size_t out_size);
int ipadctl_support_command(int argc, char **argv, const char *config_path, const char *socket_path);

#endif
