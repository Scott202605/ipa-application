/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include "ppr_verification.h"
#include "tlv_lengths.h"
#include "es10_tlv_extractor.h"
#include "tlv_data_extractor.h"
#include "log.h"

#define MCC_MNC_WILDCARD_RIGHT_NIBBLE (uint8_t) 0x0E
#define MCC_MNC_WILDCARD_LEFT_NIBBLE (uint8_t) 0xE0

typedef enum ppr_e {
    PPR1 = 1,
    PPR2 = 2
} ppr_t;

static ErrCode ppr_verfication__is_profile_ppr_allowed_in_rat(const operator_id_t* profile_owner, const ppr_t ppr, get_rat_response_t* euicc_rat, bool* is_profile_ppr_allowed, bool* user_consent);
static bool ppr_verfication__is_profile_ppr_in_ppar(const ppr_t ppr, profile_policy_authorisation_rule_t* ppar);
static ErrCode ppr_verfication__is_profile_owner_allowed_in_ppar(const operator_id_t* profile_owner, const ppr_t ppr, profile_policy_authorisation_rule_t* ppar, bool* is_profile_owner_allowed);
static bool ppr_verfication__operator_ids_match(const operator_id_t* profile_owner, const operator_id_t* allowed_operator);
static bool ppr_verfication__mcc_mnc_match(const mcc_mnc_t* profile_owner_mcc_mnc, const mcc_mnc_t* allowed_operator_mcc_mnc);
static bool ppr_verfication__gid_match(bool profile_owner_gid_is_present, const uint8_t* profile_owner_gid, uint32_t profile_owner_gid_size, bool allowed_operator_gid_is_present, const uint8_t* allowed_operator_gid, uint32_t ppar_operator_size);

ErrCode ppr_verfication__verify_profile_pprs(const operator_id_t* profile_owner, const ppr_ids_t* profile_pprs, get_rat_response_t* euicc_rat, ppr_verification_result_t* ppr_verification_result) {
    ErrCode rc = eOk;
    bool is_profile_ppr_allowed;
    
    /* Check input parameters */
    if (!profile_owner) {
        LOGE("[ppr_verfication__verify_profile_pprs] Profile Owner object is null");
        return eBadArg;
    }
    if (!profile_pprs) {
        LOGE("[ppr_verfication__verify_profile_pprs] Profile PprIds object is null");
        return eBadArg;
    }
    if (!euicc_rat) {
        LOGE("[ppr_verfication__verify_profile_pprs] GetRatResponse object is null");
        return eBadArg;
    }
    if (!ppr_verification_result) {
        LOGE("[ppr_verfication__verify_profile_pprs] PPR verfication result object is null");
        return eBadArg;
    }

    // Default result (if any PPR needs to be verified)
    ppr_verification_result->choice = PPR_VERIFICATION_RESULT_CHOICE_OK;
    ppr_verification_result->ok.ppr1_user_consent_required = false;
    ppr_verification_result->ok.ppr2_user_consent_required = false;

    // Verify PPR1 against RAT
    if (profile_pprs->ppr1) {
        if ((rc = ppr_verfication__is_profile_ppr_allowed_in_rat(profile_owner, PPR1, euicc_rat, &is_profile_ppr_allowed, &ppr_verification_result->ok.ppr1_user_consent_required)) != eOk) {
            LOGE("[ppr_verfication__verify_profile_pprs] Verification error for the PPR1, rc %d", rc);
            return rc;
        }
        if (!is_profile_ppr_allowed) {
            ppr_verification_result->choice = PPR_VERIFICATION_RESULT_CHOICE_ERROR_PPR_NOT_ALLOWED;
            LOGE("[ppr_verfication__verify_profile_pprs] PPR1 not allowed");
            return eOk;
        }
        LOGD("[ppr_verfication__verify_profile_pprs] PPR1 allowed with user consent %u", ppr_verification_result->ok.ppr1_user_consent_required);

        // Reinit RAT list iterator (may be reused for other verification)
        /** TODO: Maybe this is not the best place to do this, review it */
        tlv_data_extractor__asn1_list_reinit(&euicc_rat->rat);
    }
    
    // Verify PPR2 against RAT
    if (profile_pprs->ppr2) {
        if ((rc = ppr_verfication__is_profile_ppr_allowed_in_rat(profile_owner, PPR2, euicc_rat, &is_profile_ppr_allowed, &ppr_verification_result->ok.ppr2_user_consent_required)) != eOk) {
            LOGE("[ppr_verfication__verify_profile_pprs] Verification error for the PPR2, rc %d", rc);
            return rc;
        }
        if (!is_profile_ppr_allowed) {
            ppr_verification_result->choice = PPR_VERIFICATION_RESULT_CHOICE_ERROR_PPR_NOT_ALLOWED;
            LOGE("[ppr_verfication__verify_profile_pprs] PPR2 not allowed");
            return eOk;
        }
        LOGD("[ppr_verfication__verify_profile_pprs] PPR2 allowed with user consent %u", ppr_verification_result->ok.ppr2_user_consent_required);
    }

    return eOk;
}

static ErrCode ppr_verfication__is_profile_ppr_allowed_in_rat(const operator_id_t* profile_owner, const ppr_t ppr, get_rat_response_t* euicc_rat, bool* is_profile_ppr_allowed, bool* user_consent) {
    ErrCode rc;
    uint8_t* rat_tlv;
    uint32_t rat_tlv_size;
    profile_policy_authorisation_rule_t ppar;

    // Step 1: Is PPR known?
    if (ppr != PPR1 && ppr != PPR2) {
        LOGE("[ppr_verfication__is_profile_ppr_allowed_in_rat] The PPR %d is unknown", ppr);
        return eFatal;
    }

    // Step 2: Evaluate PPR authorisation
    while ((rc = tlv_data_extractor__asn1_list_get_next(&euicc_rat->rat, &rat_tlv, &rat_tlv_size)) == eOk && rat_tlv != NULL) {
        if ((rc = es10_tlv_extractor__profile_policy_authorisation_rule(rat_tlv, rat_tlv_size, &ppar)) != eOk) {
            LOGE("[ppr_verfication__is_profile_ppr_allowed_in_rat] Error parsing the ProfilePolicyAuthorisationRule, rc %d", rc);
            return rc;
        }
        LOGD("[ppr_verfication__is_profile_ppr_allowed_in_rat] PPAR PPRid (pprUpdateControl=%u, ppr1=%u, ppr2=%u)", ppar.ppr_ids.ppr_update_control, ppar.ppr_ids.ppr1, ppar.ppr_ids.ppr2);
        LOGD("[ppr_verfication__is_profile_ppr_allowed_in_rat] PPAR End User Consent Required: %u", ppar.ppr_flags.consent_required);
        if (ppr_verfication__is_profile_ppr_in_ppar(ppr, &ppar)) {
            LOGD("[ppr_verfication__is_profile_ppr_allowed_in_rat] The PPR %d match with the PPRid of the current PPAR", ppr);
            if ((rc = ppr_verfication__is_profile_owner_allowed_in_ppar(profile_owner, ppr, &ppar, is_profile_ppr_allowed)) == eOk) {
                if (*is_profile_ppr_allowed) {
                    *user_consent = ppar.ppr_flags.consent_required;
                    LOGD("[ppr_verfication__is_profile_ppr_allowed_in_rat] The Profile PPR %d is authorised against RAT, End User Consent Required: %u", ppr, *user_consent);
                    return eOk;
                }
            } else {
                LOGD("[ppr_verfication__is_profile_ppr_allowed_in_rat] The Profile Owner is not allowed in the current PPAR");
            }
        } else {
            LOGD("[ppr_verfication__is_profile_ppr_allowed_in_rat] The PPR %d does not match with the PPRid of the current PPAR", ppr);
        }
    }

    if (rc != eOk) {
        LOGE("[ppr_verfication__is_profile_ppr_allowed_in_rat] Error iterating over the PPAR of the RAT, rc %d", rc);
        return rc;
    }

    LOGW("[ppr_verfication__is_profile_ppr_allowed_in_rat] The Profile Owner PPR %d is not authorised in any of the PPAR of the RAT", ppr);
    *is_profile_ppr_allowed = false;
    return eOk; // Verification was successful but the Profile PPR is not allowed
}

static bool ppr_verfication__is_profile_ppr_in_ppar(const ppr_t ppr, profile_policy_authorisation_rule_t* ppar) {
    // Check if the PPR of the Profile Owner is in the PPRid of the PPAR
    return (PPR1 == ppr && ppar->ppr_ids.ppr1) || (PPR2 == ppr && ppar->ppr_ids.ppr2);
}

static ErrCode ppr_verfication__is_profile_owner_allowed_in_ppar(const operator_id_t* profile_owner, const ppr_t ppr, profile_policy_authorisation_rule_t* ppar, bool* is_profile_owner_allowed) {
    ErrCode rc;
    uint8_t* operator_id_tlv;
    uint32_t operator_id_tlv_size;
    operator_id_t allowed_operator;

    // Check if any Allowed Operators match with the profile Operator
    while ((rc = tlv_data_extractor__asn1_list_get_next(&ppar->allowed_operators, &operator_id_tlv, &operator_id_tlv_size)) == eOk && operator_id_tlv != NULL) {
        // Parse the Allowed Operator
        if ((rc = tlv_data_extractor__operator_id(ppar->allowed_operators.elem_tag, operator_id_tlv, operator_id_tlv_size, &allowed_operator)) != eOk) {
            LOGE("[ppr_verfication__is_profile_owner_allowed_in_ppar] Error parsing the allowed OperatorId, rc %d", rc);
            return rc;
        }
        if (ppr_verfication__operator_ids_match(profile_owner, &allowed_operator)) {
            LOGD("[ppr_verfication__is_profile_owner_allowed_in_ppar] The Profile Owner match with the current Allowed Operator of the current PPAR for the PPR %d", ppr);
            *is_profile_owner_allowed = true;
            return eOk;
        }
    }

    if (rc != eOk) {
        LOGE("[ppr_verfication__is_profile_owner_allowed_in_ppar] Error iterating over the Allowed Operators of the PPAR, rc %d", rc);
        return rc;
    }

    LOGD("[ppr_verfication__is_profile_owner_allowed_in_ppar] The PPR %d does not match with any Allowed Operator of the current PPAR", ppr);
    *is_profile_owner_allowed =  false;
    return eOk;
}

static bool ppr_verfication__operator_ids_match(const operator_id_t* profile_owner, const operator_id_t* allowed_operator) {
    // Check if the mccMnc match
    if (!ppr_verfication__mcc_mnc_match(&profile_owner->mcc_mnc, &allowed_operator->mcc_mnc)) {
        LOGD("[ppr_verfication__operator_ids_match] MccMnc mismatch");
        return false;
    }

    // Check if the gid1 match
    LOGD("[ppr_verfication__operator_ids_match] Evaluate gid1");
    if (!ppr_verfication__gid_match(profile_owner->field_is_present.gid1, profile_owner->gid1, profile_owner->gid1_size, allowed_operator->field_is_present.gid1, allowed_operator->gid1, allowed_operator->gid1_size)) {
        LOGD("[ppr_verfication__operator_ids_match] gid1 mismatch");
        return false;
    }

    // Check if the gid2 match
    LOGD("[ppr_verfication__operator_ids_match] Evaluate gid2");
    if (!ppr_verfication__gid_match(profile_owner->field_is_present.gid2, profile_owner->gid2, profile_owner->gid2_size, allowed_operator->field_is_present.gid2, allowed_operator->gid2, allowed_operator->gid2_size)) {
        LOGD("[ppr_verfication__operator_ids_match] gid1 mismatch");
        return false;
    }

    LOGD("[ppr_verfication__operator_ids_match] The Profile Owner match with the current Allowed Operator of the current PPAR");
    return true;
}

static bool ppr_verfication__mcc_mnc_match(const mcc_mnc_t* profile_owner_mcc_mnc, const mcc_mnc_t* allowed_operator_mcc_mnc) {
    mcc_mnc_t profile_owner_mcc_mnc_wildcarded;
    uint8_t i;
    uint8_t aux_byte;

    /* Check input parameters */
    if (!profile_owner_mcc_mnc) {
        LOGD("[ppr_verfication__mcc_mnc_match] The Profile Owner MccMnc is null");
        return false;
    }
    if (!allowed_operator_mcc_mnc) {
        LOGD("[ppr_verfication__mcc_mnc_match] The PPAR Allowed Operator MccMnc is null");
        return false;
    }

    LOG_DATA(eLogDebug, "[ppr_verfication__mcc_mnc_match] Profile Owner MccMnc", profile_owner_mcc_mnc->value, sizeof(profile_owner_mcc_mnc->value));
    LOG_DATA(eLogDebug, "[ppr_verfication__mcc_mnc_match] PPAR Allowed Operator MccMnc", allowed_operator_mcc_mnc->value, sizeof(allowed_operator_mcc_mnc->value));

    // Apply the wilcard digits to the profile MccMnc
    memcpy(&profile_owner_mcc_mnc_wildcarded, profile_owner_mcc_mnc, sizeof(mcc_mnc_t));
    for (i = 0; i < MCC_MNC_SIZE; i++) {
        // Left nibble
        aux_byte = allowed_operator_mcc_mnc->value[i] & 0xF0;
        if (MCC_MNC_WILDCARD_LEFT_NIBBLE == aux_byte) {
            profile_owner_mcc_mnc_wildcarded.value[i] &= 0x0F; // Clean nibble
            profile_owner_mcc_mnc_wildcarded.value[i] |= MCC_MNC_WILDCARD_LEFT_NIBBLE; // Set nibble
        }
        // Right nibble
        aux_byte = allowed_operator_mcc_mnc->value[i] & 0x0F;
        if (MCC_MNC_WILDCARD_RIGHT_NIBBLE == aux_byte) {
            profile_owner_mcc_mnc_wildcarded.value[i] &= 0xF0; // Clean nibble
            profile_owner_mcc_mnc_wildcarded.value[i] |= MCC_MNC_WILDCARD_RIGHT_NIBBLE;
        }
    }

    LOG_DATA(eLogDebug, "[ppr_verfication__mcc_mnc_match] Wildcarded Profile Owner MccMnc", profile_owner_mcc_mnc_wildcarded.value, sizeof(profile_owner_mcc_mnc_wildcarded.value));

    // Compare MccMnc
    if (0 == memcmp(&allowed_operator_mcc_mnc->value, &profile_owner_mcc_mnc_wildcarded.value, sizeof(allowed_operator_mcc_mnc->value))) {
        LOGD("[ppr_verfication__mcc_mnc_match] Profile Owner MccMnc match with the current PPAR Allowed Operator");
        return true;
    } else {
        LOGD("[ppr_verfication__mcc_mnc_match] Profile Owner MccMnc mismatch with the current PPAR Allowed Operator");
        return false;
    }
}

static bool ppr_verfication__gid_match(bool profile_owner_gid_is_present, const uint8_t* profile_owner_gid, uint32_t profile_owner_gid_size, bool allowed_operator_gid_is_present, const uint8_t* allowed_operator_gid, uint32_t allowed_operator_gid_size) {
    // An omitted gid1 or gid2 value in the PPAR SHALL only match a profileOwner field where the corresponding gid1 or gid2 value is absent
    if (!allowed_operator_gid_is_present) {
        LOGD("[ppr_verfication__gid_match] The PPAR Allowed Operator gid is not present");
        if (profile_owner_gid_is_present) {
            LOGD("[ppr_verfication__gid_match] The Profile Owner gid is present, mismatch found");
            return false;
        } else {
            LOGD("[ppr_verfication__gid_match] The Profile Owner gid is not present, match found");
            return true;
        }
    }
    LOGD("[ppr_verfication__gid_match] The PPAR Allowed Operator gid is present");

    // Check that profileOwner gid is present and non-empty
    if (!profile_owner_gid_is_present || 0 == profile_owner_gid_size) {
        LOGD("[ppr_verfication__gid_match] The Profile Owner gid is not present or empty, mismatch found");
        return false;
    }
    
    // The gid1 or gid2 data objects can be wildcard-ed by setting an empty value (length zero).
    if (0 == allowed_operator_gid_size) {
        LOGD("[ppr_verfication__gid_match] The PPAR Allowed Operator gid has 0-length, wildcard applied and match found");
        return true;
    }

    LOG_DATA(eLogDebug, "[ppr_verfication__gid_match] Profile Owner gid", profile_owner_gid, profile_owner_gid_size);
    LOG_DATA(eLogDebug, "[ppr_verfication__gid_match] PPAR Allowed Operator gid", allowed_operator_gid, allowed_operator_gid_size);

    // Compare gid
    if (allowed_operator_gid_size != profile_owner_gid_size) {
        LOGD("[ppr_verfication__gid_match] PPAR Allowed Operator gid length (%u) mismatch with the Profile Owner length(%u)", allowed_operator_gid_size, profile_owner_gid_size);
        return false;
    }
    if (0 == memcmp(allowed_operator_gid, profile_owner_gid, allowed_operator_gid_size)) {
        LOGD("[ppr_verfication__gid_match] Profile Owner gid match with the current PPAR Allowed Operator");
        return true;
    } else {
        LOGD("[ppr_verfication__gid_match] Profile Owner gid mismatch with the current PPAR Allowed Operator");
        return false;
    }

}
