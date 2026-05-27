/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"
#include "es9.h"
#include "es11.h"

/**
 * This function executes the Mutual Authentication process against a SM-DP+.
 * 
 * @param[in]  es9 A valid ES9 handle from a successful call to es9__ctor().
 * @param[in]  es10 A valid ES10 handle from a successful call to es10__ctor().
 * @param[in]  smdp_address Points to a fqdn_t structure with the SM-DP+ Address.
 * @param[in]  matching_id Points to the MatchingId of the profile to download. Can be NULL.
 * @param[in]  matching_id_size Size of the MatchingId.
 * @param[out] authenticate_client_response Ponits to an authenticate_client_response_es9_t structure that will be populated with the AuthenticateClientResponse 
 * received on last request of the mutual authentication processif the function return is success. . The caller is the responsible for freeing this structure if 
 * the function return is success by calling the es9__free_authenticate_client_response() funtion.
 * 
 * @return eOk in case the mutual authentication procedure has been executed successfully. Otherwise, an error code is returned.
*/
ErrCode mutual_authentication__smdp(es9_t* const es9, es10_t* const es10, const fqdn_t* smdp_address, const uint8_t* matching_id, const uint8_t matching_id_size, authenticate_client_response_es9_t* authenticate_client_response);

/**
 * This function executes the Mutual Authentication process against a SM-DS.
 * 
 * @param[in]  es10 A valid ES10 handle from a successful call to es10__ctor().
 * @param[in]  es11 A valid ES11 handle from a successful call to es11__ctor().
 * @param[in]  smds_address Points to a fqdn_t structure with the SM-DS Address.
 * @param[out] authenticate_client_response Ponits to an authenticate_client_response_es11_t structure that will be populated with the AuthenticateClientResponse 
 * received on last request of the mutual authentication process if the function return is success. . The caller is the responsible for freeing this structure if 
 * the function return is success by calling the es11__free_authenticate_client_response() funtion.
 * 
 * @return eOk in case the mutual authentication procedure has been executed successfully. Otherwise, an error code is returned.
*/
ErrCode mutual_authentication__smds(es10_t* const es10, es11_t* const es11, const fqdn_t* smds_address, authenticate_client_response_es11_t* authenticate_client_response);
