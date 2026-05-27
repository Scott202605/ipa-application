/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"
#define IPA_VERSION "2.1.0"

#ifdef SUPPORT_USER_CONSENT_INTERFACE
#error "IPA cannot support the user consent interface. CPP flag SUPPORT_USER_CONSENT_INTERFACE must be disabled"
#endif

typedef struct ipa_features_s {
    bool direct_rsp_server_communication;
    bool indirect_rsp_server_communication;
    bool eim_download_data_handling;
    bool eim_ctx_params_1_generation;
    bool eim_profile_metadata_verification;
    bool minimize_esipa_bytes;
} ipa_features_t;

typedef struct ipa_supported_protocols_s {
    bool ipa_retrieve_https;
    bool ipa_retrieve_coaps;
    bool ipa_inject_https;
    bool ipa_inject_coaps;
    bool ipa_proprietary;
} ipa_supported_protocols_t;

typedef struct ipa_capabilities_data_presence_s {
    bool ipa_supported_protocols;
} ipa_capabilities_data_presence_t;

typedef struct ipa_capabilities_s {
    ipa_features_t ipa_features;
    ipa_supported_protocols_t ipa_supported_protocols;
    ipa_capabilities_data_presence_t field_is_present;
} ipa_capabilities_t;
