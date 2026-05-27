/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"
#include "es9.h"
#include "es10.h"
#include "es11.h"

typedef struct pir_s {
    uint8_t* pir;
    uint32_t pir_size;
#if defined(SGP32) && defined(EXTRA_FEATURE_IMMEDIATE_PROFILE_ENABLING)
    bool immediate_profile_enabled;
#endif
} pir_t;

typedef struct activation_code_s {
    const uint8_t* smdp_address;
    const uint8_t* ac_token;
    const uint8_t* smdp_oid;
    uint8_t smdp_address_size;
    uint8_t ac_token_size;
    uint8_t smdp_oid_size;
    bool ccrf;
} activation_code_t;

/**
 * This function executes the Profile Download and Installation procedure using an Activation Code.
 * 
 * @param[in]  es9 A valid ES9 handle from a successful call to es9__ctor().
 * @param[in]  es10 A valid ES10 handle from a successful call to es10__ctor().
 * @param[in]  activation_code string with the Activation Code of the profile to download (can be not null-terminated).
 * @param[in]  activation_code_len length of activation_code (excluding the null-terminated character).
 * @param[in]  confirmation_code string with the Confirmation Code of the profile to download (can be not null-terminated). Can be NULL.
 * @param[in]  confirmation_code_len length of confirmation_code (excluding the null-terminated character).
 * @param[out] pir Ponits to a pir_t structure that will be populated with the ProfileInstallationResult if the function return is success. 
 * The caller is the responsible for freeing this structure if the function return is success by calling the rsp__free_pir() funtion.
 * 
 * @return eOk in case the Profile Download and Installation procedure using an Activation Code has been executed successfully. Otherwise, an error code is returned.
*/
ErrCode rsp__activation_code(es9_t* const es9, es10_t* const es10, const uint8_t* activation_code, const uint32_t activation_code_len, const uint8_t* confirmation_code, const uint32_t confirmation_code_len, pir_t* pir);

/**
 * This function executes the Profile Download and Installation procedure.
 * 
 * @param[in]  es9 A valid ES9 handle from a successful call to es9__ctor().
 * @param[in]  es10 A valid ES10 handle from a successful call to es10__ctor().
 * @param[in]  smdp_address Points to a fqdn_t structure with the SM-DP+ Address.
 * @param[in]  matching_id Points to the MatchingId of the profile to download. Can be NULL.
 * @param[in]  matching_id_size Size of the MatchingId.
 * @param[in]  ccrf Indicates if confirmation code is required or not.
 * @param[in]  confirmation_code string with the Confirmation Code of the profile to download (can be not null-terminated). Can be NULL if the ccrf is false.
 * @param[in]  confirmation_code_len length of confirmation_code (excluding the null-terminated character).
 * @param[out] pir Ponits to a pir_t structure that will be populated with the ProfileInstallationResult if the function return is success. 
 * The caller is the responsible for freeing this structure if the function return is success by calling the rsp__free_pir() funtion.
 * 
 * @return eOk in case the Profile Download and Installation procedure has been executed successfully. Otherwise, an error code is returned.
*/
ErrCode rsp__smdp(es9_t* const es9, es10_t* const es10, fqdn_t* smdp_address, const uint8_t* matching_id, const uint8_t matching_id_len, const bool ccrf, const uint8_t* confirmation_code, const uint32_t confirmation_code_len, pir_t* pir);

/**
 * This function executes the Profile Download and Installation procedure using the Default SM-DP+.
 * 
 * @param[in]  es9 A valid ES9 handle from a successful call to es9__ctor().
 * @param[in]  es10 A valid ES10 handle from a successful call to es10__ctor().
 * @param[out] pir Ponits to a pir_t structure that will be populated with the ProfileInstallationResult if the function return is success. 
 * The caller is the responsible for freeing this structure if the function return is success by calling the rsp__free_pir() funtion.
 * 
 * @return eOk in case the Profile Download and Installation procedure using the Default SM-DP+ has been executed successfully. Otherwise, an error code is returned.
*/
ErrCode rsp__default_smdp(es9_t* const es9, es10_t* const es10, pir_t* pir);

/**
 * This function executes the Event Retrieval procedure.
 * 
 * @param[in]  es9 A valid ES9 handle from a successful call to es9__ctor().
 * @param[in]  es10 A valid ES10 handle from a successful call to es10__ctor().
 * @param[in]  es11 A valid ES11 handle from a successful call to es11__ctor().
 * @param[in]  smds_address Points to a fqdn_t structure with the SM-DS Address.
 * @param[out] pir_list Will point to an array of pir_t structures populated each with the ProfileInstallationResult of each event retrieval if the function 
 * return is success. Can point to NULL if no events are found in the SM-DS.
 * The caller is the responsible for freeing this list if the function return is success by calling the rsp__free_pir_list() funtion.
 * @param[out] pir_list_size Will point to the number of ProfileInstallationResults inside the pir_list.
 * 
 * @return eOk in case the Event Retrieval procedure has been executed successfully. Otherwise, an error code is returned.
*/
ErrCode rsp__smds(es9_t* const es9, es10_t* const es10, es11_t* const es11, fqdn_t* smds_address, pir_t** pir_list, uint32_t* pir_list_size);

/**
 * This function executes the Event Retrieval procedure using the Root SM-DS.
 * 
 * @param[in]  es9 A valid ES9 handle from a successful call to es9__ctor().
 * @param[in]  es10 A valid ES10 handle from a successful call to es10__ctor().
 * @param[in]  es11 A valid ES11 handle from a successful call to es11__ctor().
 * @param[out] pir_list Will point to an array of pir_t structures populated each with the ProfileInstallationResult of each event retrieval if the function 
 * return is success. Can point to NULL if no events are found in the SM-DS.
 * The caller is the responsible for freeing this list if the function return is success by calling the rsp__free_pir_list() funtion.
 * @param[out] pir_list_size Will point to the number of ProfileInstallationResults inside the pir_list.
 * 
 * @return eOk in case the Event Retrieval procedure has been executed successfully. Otherwise, an error code is returned.
*/
ErrCode rsp__root_smds(es9_t* const es9, es10_t* const es10, es11_t* const es11, pir_t** pir_list, uint32_t* pir_list_size);

/**
 * This function parse an Activation Code.
 * 
 * @param[in]  activation_code Points to a byte array that contains the Activation Code.
 * @param[in]  activation_code_len Size of the Activation Code.
 * @param[out] ac A pointer to a activation_code_t structure. The structure is populated with the data from the activation_code buffer if the function return is success. 
 * The structure will be pointing inside the activation_code buffer so do not deallocate the activation_code buffer while using the structure.
 * 
 * @return eOk in case the parsing has been done successfully. Otherwise, an error code is returned.
*/
ErrCode rsp__parse_activation_code(const uint8_t* activation_code, const uint32_t activation_code_len, activation_code_t* ac);

/**
 * This function parse an FQDN.
 * 
 * @param[in]  ptr Points to a byte array that contains the FQDN.
 * @param[in]  size Size of the FQDN.
 * @param[out] ac A pointer to a fqdn_t structure. The structure is populated with the data from the activation_code buffer if the function return is success. 
 * The structure won't reference any data from the ptr buffer, so the ptr buffer can be deallocated after the execution of the function.
 * 
 * @return eOk in case the parsing has been done successfully. Otherwise, an error code is returned.
*/
ErrCode rsp__utf8_to_fqdn(const uint8_t* ptr, uint32_t size, fqdn_t* fqdn);

#if defined(SGP32) && defined(EXTRA_FEATURE_IMMEDIATE_PROFILE_ENABLING)
ErrCode rsp__immediate_profile_enabling(es10_t* const es10);
#endif

/** Free datatypes functions according the allocations made in the rsp.c file */
void rsp__free_pir(pir_t* pir);
void rsp__free_pir_list(pir_t** pir_list, uint32_t* pir_list_size);
