/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "es10_typedefs.h"

void ipa_display__euicc_memory_reset_response(const euicc_memory_reset_request_t* request, const euicc_memory_reset_response_t* obj);
void ipa_display__set_default_dp_address_response(const set_default_dp_address_request_t* request, const set_default_dp_address_response_t* obj);
void ipa_display__notification_sent_response(const uint32_t seq_number, const notification_sent_response_t* obj);
#ifdef SGP32
void ipa_display__add_initial_eim_response(const add_initial_eim_response_t* obj);
void ipa_display__configure_immediate_profile_enabling_response(const configure_immediate_profile_enabling_response_t* obj);
#ifdef EXTRA_FEATURE_EMERGENCY_PROFILE_MANAGMENT
void ipa_display__enable_emergency_profile_response(const enable_emergency_profile_response_t* obj);
void ipa_display__disable_emergency_profile_response(const disable_emergency_profile_response_t* obj);
#endif
#ifdef EXTRA_FEATURE_FALLBACK_MECHANISM
void ipa_display__execute_fallback_mechanism_response(const execute_fallback_mechanism_response_t* obj);
void ipa_display__return_from_fallback_response(const return_from_fallback_response_t* obj);
#endif
#ifdef TEST_FEATURE_PROFILE_ROLLBACK
void ipa_display__profile_rollback_response(const profile_rollback_response_t* obj);
#endif
#endif
