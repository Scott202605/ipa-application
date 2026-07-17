#include "sdk_profile_facade.h"

static ipad_error_t validate_iccid(const char *iccid) {
    return iccid && iccid[0] ? IPAD_OK : IPAD_ERR_INVALID_PARAMS;
}

ipad_error_t sdk_profile_facade_enable(const char *iccid) {
    ipad_error_t err = validate_iccid(iccid);
    if (err != IPAD_OK) return err;
    return IPAD_ERR_SDK_FAILED;
}

ipad_error_t sdk_profile_facade_disable(const char *iccid) {
    ipad_error_t err = validate_iccid(iccid);
    if (err != IPAD_OK) return err;
    return IPAD_ERR_SDK_FAILED;
}

ipad_error_t sdk_profile_facade_delete(const char *iccid) {
    ipad_error_t err = validate_iccid(iccid);
    if (err != IPAD_OK) return err;
    return IPAD_ERR_SDK_FAILED;
}
