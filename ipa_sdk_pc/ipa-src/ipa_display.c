/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include "ipa_display.h"

#include <stdio.h>
#include "log.h"

#define RESULT_OK                   "Ok"
#define RESULT_NOTHING_TO_DELETE    "Nothing to delete"

#define ERROR_CAT_BUSY                          "Cat busy"
#define ERROR_NOT_SUPPORTED                     "Not supported"
#define ERROR_CI_PK_UNKNOWN                     "CI Public Key unknown"
#define ERROR_INSUFFICIENT_MEMORY               "Insufficient memory"
#define ERROR_COMMAND_ERROR                     "Command error"
#define ERROR_UNDEFINED_ERROR                   "Undefined error"
#define ERROR_UNKNOWN                           "Unknown"
#ifdef SGP32
#define ERROR_INVALID_ASSOCIATION_TOKEN                 "Invalid association token"
#define ERROR_COUNTER_VALUE_OUT_OF_RANGE                "Counter value out of range"
#define ERROR_ASSOCIATED_EIM_ALREADY_EXISTS             "Associated eIM already exists"
#define ERROR_UNSIGNED_AUTO_ENABLE_CONFIG_DISALLOWED    "Unsigned auto enable configuration disallowed (eIM Configuration Data is already present in the eUICC)"
#define ERROR_ECALL_ACTIVE                              "Emergency call active"
#ifdef EXTRA_FEATURE_EMERGENCY_PROFILE_MANAGMENT
#define ERROR_EMERGENCY_PROFILE_NOT_IN_DISABLED_STATE   "The selected Emergency Profile is not disabled"
#define ERROR_ECALL_NOT_AVAILABLE                       "Emergency Profile does not exist"
#define ERROR_EMERGENCY_PROFILE_NOT_IN_ENABLED_STATE    "The selected Emergency Profile is not enabled"
#endif
#define ADD_INITIAL_SUCCESS "The initial eIM has been successfully added to the UICC"
#ifdef EXTRA_FEATURE_FALLBACK_MECHANISM
#define ERROR_PROFILE_NOT_IN_DISABLED_STATE "Profile not in disabled state"
#define ERROR_FALLBACK_NOT_AVAILABLE        "Fallback not available"
#endif
#ifdef TEST_FEATURE_PROFILE_ROLLBACK
#define ERROR_ROLLBACK_NOT_ALLOWED "Usage of rollback was not granted by the eIM"
#endif
#endif

#define STR_DELETE_NOTIFICATION_STATUS(R)                                           \
((R) == DELETE_NOTIFICATION_STATUS_OK ? RESULT_OK :                                 \
((R) == DELETE_NOTIFICATION_STATUS_NOTHING_TO_DELETE ? RESULT_NOTHING_TO_DELETE :   \
((R) == DELETE_NOTIFICATION_STATUS_UNDEFINED_ERROR ? ERROR_UNDEFINED_ERROR :        \
ERROR_UNKNOWN)))

#ifdef SGP22
#define STR_RESET_RESULT(R)                                         \
((R) == RESET_RESULT_OK ? RESULT_OK :                               \
((R) == RESET_RESULT_NOTHING_TO_DELETE ? RESULT_NOTHING_TO_DELETE : \
((R) == RESET_RESULT_CAT_BUSY ? ERROR_CAT_BUSY :                    \
((R) == RESET_RESULT_UNDEFINED_ERROR ? ERROR_UNDEFINED_ERROR :      \
ERROR_UNKNOWN))))
#elif defined(SGP32)
#define STR_RESET_RESULT(R)                                         \
((R) == RESET_RESULT_OK ? RESULT_OK :                               \
((R) == RESET_RESULT_NOTHING_TO_DELETE ? RESULT_NOTHING_TO_DELETE : \
((R) == RESET_RESULT_CAT_BUSY ? ERROR_CAT_BUSY :                    \
((R) == RESET_RESULT_ECALL_ACTIVE ? ERROR_ECALL_ACTIVE :            \
((R) == RESET_RESULT_UNDEFINED_ERROR ? ERROR_UNDEFINED_ERROR :      \
ERROR_UNKNOWN)))))
#else
#error "Only SGP22 or SGP32 are supported" 
#endif

#define STR_SET_DEFAULT_DP_ADDRESS_RESULT(R)                                     \
((R) == SET_DEFAULT_DP_ADDRESS_RESULT_OK ? RESULT_OK :                           \
((R) == SET_DEFAULT_DP_ADDRESS_RESULT_UNDEFINED_ERROR ? ERROR_UNDEFINED_ERROR :  \
ERROR_UNKNOWN))

#ifdef SGP32
#define STR_RESET_EIM_RESULT(R)                                             \
((R) == RESET_EIM_RESULT_OK ? RESULT_OK :                                   \
((R) == RESET_EIM_RESULT_NOTHING_TO_DELETE ? RESULT_NOTHING_TO_DELETE :     \
((R) == RESET_EIM_RESULT_EIM_RESET_NOT_SUPPORTED ? ERROR_NOT_SUPPORTED :    \
((R) == RESET_EIM_RESULT_UNDEFINED_ERROR ? ERROR_UNDEFINED_ERROR :          \
ERROR_UNKNOWN))))

#define STR_RESET_IMMEDIATE_ENABLE_CONFIG_RESULT(R)                                     \
((R) == RESET_IMMEDIATE_ENABLE_CONFIG_RESULT_OK ? RESULT_OK :                           \
((R) == RESET_IMMEDIATE_ENABLE_CONFIG_RESULT_IEC_NOT_SUPPORTED ? ERROR_NOT_SUPPORTED :  \
((R) == RESET_IMMEDIATE_ENABLE_CONFIG_RESULT_UNDEFINED_ERROR ? ERROR_UNDEFINED_ERROR :  \
ERROR_UNKNOWN)))

#define STR_ADD_INITIAL_EIM_ERROR(R)                                                                    \
((R) == ADD_INITIAL_EIM_ERROR_INSUFFICIENT_MEMORY ? RESULT_OK :                                         \
((R) == ADD_INITIAL_EIM_ERROR_ASSOCIATED_EIM_ALREADY_EXISTS ? ERROR_ASSOCIATED_EIM_ALREADY_EXISTS :     \
((R) == ADD_INITIAL_EIM_ERROR_CI_PK_UNKNOWN ? ERROR_CI_PK_UNKNOWN :                                     \
((R) == ADD_INITIAL_EIM_ERROR_INVALID_ASSOCIATION_TOKEN ? ERROR_INVALID_ASSOCIATION_TOKEN :             \
((R) == ADD_INITIAL_EIM_ERROR_COUNTER_VALUE_OUT_OF_RANGE ? ERROR_COUNTER_VALUE_OUT_OF_RANGE :           \
((R) == ADD_INITIAL_EIM_ERROR_COMMAND_ERROR ? ERROR_COMMAND_ERROR :                                     \
((R) == ADD_INITIAL_EIM_ERROR_UNDEFINED_ERROR ? ERROR_UNDEFINED_ERROR :                                 \
ERROR_UNKNOWN)))))))
#define STR_CONFIG_IMMEDIATE_ENABLE_RESULT(R)                                                                                    \
((R) == CONFIG_IMMEDIATE_ENABLE_RESULT_OK ? RESULT_OK :                                                                          \
((R) == CONFIG_IMMEDIATE_ENABLE_RESULT_INSUFFICIENT_MEMORY ? ERROR_INSUFFICIENT_MEMORY :                                         \
((R) == CONFIG_IMMEDIATE_ENABLE_RESULT_ASSOCIATED_EIM_ALREADY_EXISTS ? ERROR_ASSOCIATED_EIM_ALREADY_EXISTS :   \
((R) == CONFIG_IMMEDIATE_ENABLE_RESULT_UNDEFINED_ERROR ? ERROR_UNDEFINED_ERROR :                                                 \
ERROR_UNKNOWN))))
#ifdef EXTRA_FEATURE_EMERGENCY_PROFILE_MANAGMENT
#define STR_ENABLE_EMERGENCY_PROFILE(R)                                                                         \
((R) == ENABLE_EMERGENCY_PROFILE_RESULT_OK ? RESULT_OK :                                                        \
((R) == ENABLE_EMERGENCY_PROFILE_RESULT_PROFILE_NOT_IN_DISABLED_STATE ? ERROR_EMERGENCY_PROFILE_NOT_IN_DISABLED_STATE :   \
((R) == ENABLE_EMERGENCY_PROFILE_RESULT_CAT_BUSY ? ERROR_CAT_BUSY :                                             \
((R) == ENABLE_EMERGENCY_PROFILE_RESULT_ECALL_NOT_AVAILABLE ? ERROR_ECALL_NOT_AVAILABLE :                       \
((R) == ENABLE_EMERGENCY_PROFILE_RESULT_UNDEFINED_ERROR ? ERROR_UNDEFINED_ERROR :                               \
ERROR_UNKNOWN)))))
#ifdef PRE_CR
#define STR_DISABLE_EMERGENCY_PROFILE(R)                                                                        \
((R) == DISABLE_EMERGENCY_PROFILE_RESULT_OK ? RESULT_OK :                                                       \
((R) == DISABLE_EMERGENCY_PROFILE_RESULT_PROFILE_NOT_IN_ENABLED_STATE ? ERROR_EMERGENCY_PROFILE_NOT_IN_ENABLED_STATE :    \
((R) == DISABLE_EMERGENCY_PROFILE_RESULT_CAT_BUSY ? ERROR_CAT_BUSY :                                            \
((R) == DISABLE_EMERGENCY_PROFILE_RESULT_ECALL_NOT_AVAILABLE ? ERROR_ECALL_NOT_AVAILABLE :                      \
((R) == DISABLE_EMERGENCY_PROFILE_RESULT_UNDEFINED_ERROR ? ERROR_UNDEFINED_ERROR :                              \
ERROR_UNKNOWN)))))
#else
#define STR_DISABLE_EMERGENCY_PROFILE(R)                                                                        \
((R) == DISABLE_EMERGENCY_PROFILE_RESULT_OK ? RESULT_OK :                                                       \
((R) == DISABLE_EMERGENCY_PROFILE_RESULT_PROFILE_NOT_IN_ENABLED_STATE ? ERROR_EMERGENCY_PROFILE_NOT_IN_ENABLED_STATE :    \
((R) == DISABLE_EMERGENCY_PROFILE_RESULT_CAT_BUSY ? ERROR_CAT_BUSY :                                            \
((R) == DISABLE_EMERGENCY_PROFILE_RESULT_UNDEFINED_ERROR ? ERROR_UNDEFINED_ERROR :                              \
ERROR_UNKNOWN))))
#endif
#endif
#ifdef EXTRA_FEATURE_FALLBACK_MECHANISM
#define STR_EXECUTE_FALLBACK_MECHANISM_RESULT(R) \
((R) == EXECUTE_FALLBACK_MECHANISM_RESULT_OK ? RESULT_OK : \
((R) == EXECUTE_FALLBACK_MECHANISM_RESULT_PROFILE_NOT_IN_DISABLED_STATE ? ERROR_PROFILE_NOT_IN_DISABLED_STATE : \
((R) == EXECUTE_FALLBACK_MECHANISM_RESULT_CAT_BUSY ? ERROR_CAT_BUSY : \
((R) == EXECUTE_FALLBACK_MECHANISM_RESULT_FALLBACK_NOT_AVAILABLE ? ERROR_FALLBACK_NOT_AVAILABLE : \
((R) == EXECUTE_FALLBACK_MECHANISM_RESULT_COMMAND_ERROR ? ERROR_COMMAND_ERROR : \
((R) == EXECUTE_FALLBACK_MECHANISM_RESULT_ECALL_ACTIVE ? ERROR_ECALL_ACTIVE : \
((R) == EXECUTE_FALLBACK_MECHANISM_RESULT_UNDEFINED_ERROR ? ERROR_UNDEFINED_ERROR : \
ERROR_UNKNOWN)))))))
#define STR_RETURN_FROM_FALLBACK_RESULT(R) \
((R) == RETURN_FROM_FALLBACK_RESULT_OK ? RESULT_OK : \
((R) == RETURN_FROM_FALLBACK_RESULT_CAT_BUSY ? ERROR_CAT_BUSY : \
((R) == RETURN_FROM_FALLBACK_RESULT_FALLBACK_NOT_AVAILABLE ? ERROR_FALLBACK_NOT_AVAILABLE : \
((R) == RETURN_FROM_FALLBACK_RESULT_COMMAND_ERROR ? ERROR_COMMAND_ERROR : \
((R) == RETURN_FROM_FALLBACK_RESULT_UNDEFINED_ERROR ? ERROR_UNDEFINED_ERROR : \
ERROR_UNKNOWN)))))
#endif
#ifdef TEST_FEATURE_PROFILE_ROLLBACK
#define STR_PROFILE_ROLLBACK_RESULT(R) \
((R) == PROFILE_ROLLBACK_RESULT_OK ? RESULT_OK : \
((R) == PROFILE_ROLLBACK_RESULT_ROLLBACK_NOT_ALLOWED ? ERROR_ROLLBACK_NOT_ALLOWED : \
((R) == PROFILE_ROLLBACK_RESULT_CAT_BUSY ? ERROR_CAT_BUSY : \
((R) == PROFILE_ROLLBACK_RESULT_COMMAND_ERROR ? ERROR_COMMAND_ERROR : \
((R) == PROFILE_ROLLBACK_RESULT_UNDEFINED_ERROR ? ERROR_UNDEFINED_ERROR : \
ERROR_UNKNOWN)))))
#endif
#endif

#ifdef SGP32
static void ipa_display__add_initial_eim_ok(const add_initial_eim_ok_t* obj);
#endif

void ipa_display__notification_sent_response(const uint32_t seq_number, const notification_sent_response_t* obj) {
    if (obj->delete_notification_status == DELETE_NOTIFICATION_STATUS_OK || obj->delete_notification_status == DELETE_NOTIFICATION_STATUS_NOTHING_TO_DELETE) {
        LOGI("Notification with SequenceNumber %u has been removed successfully", seq_number);
    } else {
        LOGE("Error on remove the notification with SequenceNumber %u, deleteNotificationStatus: %s", seq_number, STR_DELETE_NOTIFICATION_STATUS(obj->delete_notification_status));
    }
}

void ipa_display__euicc_memory_reset_response(const euicc_memory_reset_request_t* request, const euicc_memory_reset_response_t* obj) {
    LOGI("Euicc Memory Reset Response:");
    if (obj->reset_result == RESET_RESULT_OK || obj->reset_result == RESET_RESULT_NOTHING_TO_DELETE) {
        if (request->delete_operational_profiles) {
            LOGI("  - The installed Operational Profiles have been successfully removed");
        }
        if (request->delete_field_loaded_test_profiles) {
            LOGI("  - The installed Test Profiles have been successfully removed");
        }
        if (request->reset_default_smdp_address) {
            LOGI("  - The default SM-DP+ address has been reset successfully to its initial value");
        }
#if defined(SGP22)
    } else {
        LOGE("  - Error on reset the Operational Profiles, Test Profiles and default SM-DP+ address: %s", STR_RESET_RESULT(obj->reset_result));
    }
#elif defined(SGP32)
        if (request->delete_preloaded_test_profiles) {
            LOGI("  - The preloaded Test Profiles have been successfully removed");
        }
        if (request->delete_provisioning_profiles) {
            LOGI("  - The provisioning Profiles have been successfully removed");
        }
    } else {
        LOGE("  - Error on reset the Operational Profiles, Fieldloaded Test Profiles, default SM-DP+ address, Preloaded Test Profile and Provisioning Profiles %s", STR_RESET_RESULT(obj->reset_result));
    }
#else
#error "Only SGP22 or SGP32 are supported"
#endif

#ifdef SGP32
    if (obj->field_is_present.reset_eim_result) {
        if (obj->reset_eim_result == RESET_EIM_RESULT_OK || obj->reset_eim_result == RESET_EIM_RESULT_NOTHING_TO_DELETE) {
            LOGI("  - All the eIM Configuration Data has been successfully removed");
        } else {
            LOGE("  - Error on reset the eIM Configuration Data: %s", STR_RESET_EIM_RESULT(obj->reset_eim_result));
        }
    }
    if (obj->field_is_present.reset_immediate_enable_config_result) {
        if (obj->reset_immediate_enable_config_result == RESET_IMMEDIATE_ENABLE_CONFIG_RESULT_OK) {
            LOGI("  - The configuration of the immediate Profile enabling has been reset successfully");
        } else {
            LOGE("  - Error on reset the configuration of the immediate Profile enabling: %s", STR_RESET_IMMEDIATE_ENABLE_CONFIG_RESULT(obj->reset_immediate_enable_config_result));
        }
    }
#endif
}

void ipa_display__set_default_dp_address_response(const set_default_dp_address_request_t* request, const set_default_dp_address_response_t* obj) {
    if (SET_DEFAULT_DP_ADDRESS_RESULT_OK == obj->set_default_dp_address_result) {
        LOGI("The default Dp Address has been successfully set up");
    } else {
        LOGE("Error on setting the default Dp Address: %s", STR_SET_DEFAULT_DP_ADDRESS_RESULT(obj->set_default_dp_address_result));
    }
}

#ifdef SGP32
void ipa_display__add_initial_eim_response(const add_initial_eim_response_t* obj) {
    switch (obj->choice)
    {
    case ADD_INITIAL_EIM_OK_CHOICE:
        ipa_display__add_initial_eim_ok(&obj->value.add_initial_eim_ok);
        break;
    case ADD_INITIAL_EIM_ERROR_CHOICE:
        LOGE("Error on add the initial eIM to the UICC: %s", STR_ADD_INITIAL_EIM_ERROR(obj->value.add_initial_eim_error));
        break;
    default:
        LOGE("[ipa_display__add_initial_eim_response] Unknown choice %d", obj->choice);
        break;
    }
}

void ipa_display__configure_immediate_profile_enabling_response(const configure_immediate_profile_enabling_response_t* obj) {
    if (obj->config_immediate_enable_result == CONFIG_IMMEDIATE_ENABLE_RESULT_OK) {
        LOGI("The immediate Profile enabling has been successfully configured");
    } else {
        LOGE("Error on configure the immediate Profile enabling: %s", STR_CONFIG_IMMEDIATE_ENABLE_RESULT(obj->config_immediate_enable_result));
    }
}

#ifdef EXTRA_FEATURE_FALLBACK_MECHANISM
void ipa_display__execute_fallback_mechanism_response(const execute_fallback_mechanism_response_t* obj) {
    if (EXECUTE_FALLBACK_MECHANISM_RESULT_OK == obj->execute_fallback_mechanism_result) {
        LOGI("The Fallback Profile has been enabled");
    } else {
        LOGE("Error on enable the Fallback Profile: %s", STR_EXECUTE_FALLBACK_MECHANISM_RESULT(obj->execute_fallback_mechanism_result));
    }
}

void ipa_display__return_from_fallback_response(const return_from_fallback_response_t* obj) {
    if (RETURN_FROM_FALLBACK_RESULT_OK == obj->return_from_fallback_result) {
        LOGI("The return from the Fallback Profile has been done successfully");
    } else {
        LOGE("Error on return from the Fallback Profile: %s", STR_RETURN_FROM_FALLBACK_RESULT(obj->return_from_fallback_result));
    }
}
#endif

#ifdef EXTRA_FEATURE_EMERGENCY_PROFILE_MANAGMENT
void ipa_display__enable_emergency_profile_response(const enable_emergency_profile_response_t* obj) {
    if (ENABLE_EMERGENCY_PROFILE_RESULT_OK == obj->enable_emergency_profile_result) {
        LOGI("The Emergency Profile has been enabled");
    }
    else {
        LOGE("Error on enable the Emergency Profile: %s", STR_ENABLE_EMERGENCY_PROFILE(obj->enable_emergency_profile_result));
    }

}

void ipa_display__disable_emergency_profile_response(const disable_emergency_profile_response_t* obj) {
    if (DISABLE_EMERGENCY_PROFILE_RESULT_OK == obj->disable_emergency_profile_result) {
        LOGI("The Emergency Profile has been disabled");
    }
    else {
        LOGE("Error on disable the Emergency Profile: %s", STR_DISABLE_EMERGENCY_PROFILE(obj->disable_emergency_profile_result));
    }
}
#endif

#ifdef TEST_FEATURE_PROFILE_ROLLBACK
void ipa_display__profile_rollback_response(const profile_rollback_response_t* obj) {
    if (PROFILE_ROLLBACK_RESULT_OK == obj->cmd_result) {
        LOGI("The Profile has been rolled back");
    }
    else {
        LOGW("Error on rollback the Profile: %s", STR_PROFILE_ROLLBACK_RESULT(obj->cmd_result));
    }
}
#endif

static void ipa_display__add_initial_eim_ok(const add_initial_eim_ok_t* obj) {
    switch (obj->choice)
    {
    case ASSOCATION_TOKEN_CHOICE:
        LOGI("%s. Association token: %u", ADD_INITIAL_SUCCESS, obj->value.assocation_token);
        break;
    case ADD_OK_CHOICE:
        LOGI("%s", ADD_INITIAL_SUCCESS);
        break;
    default:
        LOGE("[ipa_display__add_initial_eim_ok] Unknown choice %d", obj->choice);
        break;
    }
}
#endif
