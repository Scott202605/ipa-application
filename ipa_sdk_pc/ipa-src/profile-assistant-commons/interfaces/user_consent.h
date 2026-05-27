#pragma once
#ifdef SUPPORT_USER_CONSENT_INTERFACE
#include "typedefs.h"

typedef enum user_consent_result_e {
    USER_CONSENT_TIMEOUT,
    USER_CONSENT_ACCEPTED,
    USER_CONSENT_REJECTED,
    USER_CONSENT_POSTPONED,
} user_consent_result_t;

user_consent_result_t user_consent__request(const char* title, unsigned int timeout);
#endif
