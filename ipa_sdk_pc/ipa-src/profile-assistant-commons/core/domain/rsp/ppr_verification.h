/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"
#include "es10_typedefs.h"

typedef enum ppr_verification_result_choice_e {
    PPR_VERIFICATION_RESULT_CHOICE_OK,
    PPR_VERIFICATION_RESULT_CHOICE_ERROR_PPR_NOT_ALLOWED    // In case the profile Owner is not allowed
} ppr_verification_result_choice_t;

typedef struct ppr_verification_result_ok_s {
    bool ppr1_user_consent_required;
    bool ppr2_user_consent_required;
} ppr_verification_result_ok_t;

typedef struct ppr_verification_result_s {
    ppr_verification_result_choice_t choice;
    ppr_verification_result_ok_t ok; // Should be used only in case the choice is PPR_VERIFICATION_RESULT_CHOICE_OK
} ppr_verification_result_t;

ErrCode ppr_verfication__verify_profile_pprs(const operator_id_t* profile_owner, const ppr_ids_t* profile_pprs, get_rat_response_t* euicc_rat, ppr_verification_result_t* ppr_verification_result);
