/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "esipa_typedefs.h"
#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
void esipa_display__initiate_authentication_request_esipa(const initiate_authentication_request_esipa_t* obj);
void esipa_display__initiate_authentication_response_esipa(const initiate_authentication_response_esipa_t* obj);
void esipa_display__authenticate_client_request_esipa(const authenticate_client_request_esipa_t* obj);
void esipa_display__authenticate_client_response_esipa(const authenticate_client_response_esipa_t* obj);
void esipa_display__get_bound_profile_package_response_esipa(const get_bound_profile_package_response_esipa_t* obj);
void esipa_display__get_bound_profile_package_request_esipa(const get_bound_profile_package_request_esipa_t* obj);
void esipa_display__cancel_session_request_esipa(const cancel_session_request_esipa_t* obj);
void esipa_display__cancel_session_response_esipa(const cancel_session_response_esipa_t* obj);
#endif
void esipa_display__handle_notification_esipa(const handle_notification_esipa_t* obj);
void esipa_display__get_eim_package_request(const get_eim_package_request_t* obj);
void esipa_display__get_eim_package_response(const get_eim_package_response_t* obj);
void esipa_display__provide_eim_package_result(const provide_eim_package_result_t* obj);
void esipa_display__provide_eim_package_result_response(const provide_eim_package_result_response_t* obj);
void esipa_display__transfer_eim_package_request(const transfer_eim_package_request_t* obj);
void esipa_display__transfer_eim_package_response(const transfer_eim_package_response_t* obj);
