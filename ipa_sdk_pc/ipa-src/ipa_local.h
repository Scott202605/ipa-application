/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"
#include "ipa_core.h"


/**
 * @brief   Performs a memory reset on the eUICC.
 * @details This function sends a command to the eUICC to delete profiles and/or other
 *          file systems based on the options specified in the request.
 *
 * @param[in] euicc_memory_reset_request   A pointer to the request structure, specifying
 *                                         which memory areas to reset (e.g., operational
 *                                         profiles, all profiles).
 * @return `eOk` on success, or an error code on failure.
 */
IPA_PUBLIC ErrCode ipa_local__euicc_memory_reset( const euicc_memory_reset_request_t* euicc_memory_reset_request);

/**
 * @brief   Sets the default SM-DP+ address on the eUICC.
 * @details This address is used for profile download operations when no other
 *          SM-DP+ address is specified.
 *
 * @param[in] set_default_dp_address_request   A pointer to the request structure,
 *                                             containing the FQDN of the default SM-DP+.
 * @return `eOk` on success, or an error code on failure.
 */
IPA_PUBLIC ErrCode ipa_local__set_default_dp_address( const set_default_dp_address_request_t* set_default_dp_address_request);

#ifdef SGP32

/**
 * @brief   Adds an initial eIM (eSIM Issuer Management) configuration to the eUICC.
 * @details This function is used to provision the eUICC with the necessary details
 *          to communicate with an eIM.
 *
 * @param[in] eim_config_t   A pointer to the eIM configuration data, including
 *                           its ID, FQDN, and public key.
 * @return `eOk` on success, or an error code on failure.
 */
IPA_PUBLIC ErrCode ipa_local__add_initial_eim( const eim_config_t* eim_config_t);

/**
 * @brief   Configures the eUICC's behavior for immediate profile enabling.
 * @details This allows enabling or disabling the feature where a newly downloaded
 *          profile is automatically enabled. It can also be restricted to a specific
 *          SM-DP+.
 *
 * @param[in] profile_enabling_config   A pointer to the configuration structure,
 *                                      specifying whether to enable the feature and
 *                                      optionally providing a default SM-DP+ address/OID.
 * @return `eOk` on success, or an error code on failure.
 */
IPA_PUBLIC ErrCode ipa_local__configure_immediate_profile_enabling( const profile_enabling_config_t* profile_enabling_config);

#endif
