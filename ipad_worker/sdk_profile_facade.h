#ifndef SDK_PROFILE_FACADE_H
#define SDK_PROFILE_FACADE_H

#include "ipad_errors.h"

ipad_error_t sdk_profile_facade_enable(const char *iccid);
ipad_error_t sdk_profile_facade_disable(const char *iccid);
ipad_error_t sdk_profile_facade_delete(const char *iccid);

#endif
