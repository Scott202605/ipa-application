/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "es10_typedefs.h"

void es10_display__euicc_memory_reset_request(const euicc_memory_reset_request_t* obj);
void es10_display__cancel_session_request(const cancel_session_request_t* obj);
void es10_display__retrieve_notifications_list_request(const retrieve_notifications_list_request_t* obj);
void es10_display__notification_sent_request(const notification_sent_request_t* obj);
void es10_display__profile_info_list_request(const profile_info_list_request_t* obj);
void es10_display__profile_info(profile_info_t* obj);
void es10_display__set_default_dp_address_request(const set_default_dp_address_request_t* obj);
#ifdef SGP22
void es10_display__list_notification_request(const list_notification_request_t* obj);
void es10_display__enable_profile_request(const enable_profile_request_t* obj);
void es10_display__disable_profile_request(const disable_profile_request_t* obj);
void es10_display__delete_profile_request(const delete_profile_request_t* obj);
void es10_display__set_nickname_request(const set_nickname_request_t* obj);
#endif
#ifdef SGP32
void es10_display__add_initial_eim_request(const eim_configuration_data_t* obj);
void es10_display__get_certs_request(const get_certs_request_t* obj);
void es10_display__immediate_enable_request(const immediate_enable_request_t* obj);
void es10_display__profile_rollback_request(const profile_rollback_request_t* obj);
void es10_display__configure_immediate_profile_enabling_request(const configure_immediate_profile_enabling_request_t* obj);
void es10_display__get_eim_configuration_data_request(const get_eim_configuration_data_request_t* obj);
#ifdef EXTRA_FEATURE_EMERGENCY_PROFILE_MANAGMENT
void es10_display__enable_emergency_profile_request(const enable_emergency_profile_request_t* obj);
void es10_display__disable_emergency_profile_request(const disable_emergency_profile_request_t* obj);
#endif
#ifdef EXTRA_FEATURE_FALLBACK_MECHANISM
void es10_display__execute_fallback_mechanism_request(const execute_fallback_mechanism_request_t* obj);
void es10_display__return_from_fallback_request(const return_from_fallback_request_t* obj);
#endif
#endif
