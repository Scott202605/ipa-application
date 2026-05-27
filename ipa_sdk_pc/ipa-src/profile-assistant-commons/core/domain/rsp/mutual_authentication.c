/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include "es10.h"
#include "mutual_authentication.h"
#include "log.h"
#include "memory_manager.h"
#include "tlv_generator.h"
#include "tlv_data_extractor.h"
#include "tlv_lengths.h"
#include "es9.h"
#include "es10_tlv_extractor.h"
#include "device_info.h"
//TODO review includes

static ErrCode initiate_authentication_es9(es9_t* const es9, es10_t* const es10, const fqdn_t* smdp_address, initiate_authentication_response_t* initiate_authentication_response);
static ErrCode initiate_authentication_es11(es10_t* const es10, es11_t* const es11, const fqdn_t* smds_address, initiate_authentication_response_t* initiate_authentication_response);
static ErrCode prepare_initiate_authentication_request(es10_t* const es10, const fqdn_t* smdp_address, initiate_authentication_request_t* initiate_authentication_request);
static ErrCode prepare_authenticate_client_request(es10_t* const es10, const uint8_t* matching_id, const uint8_t matching_id_size, initiate_authentication_response_t* initiate_authentication_response, authenticate_client_request_t* authenticate_client_request);
static ErrCode authenticate_server(es10_t* const es10, const uint8_t* matching_id, const uint8_t matching_id_size, initiate_authentication_response_t* initiate_authentication_response, uint8_t** auth_server_response, uint32_t* auth_server_response_size);
static ErrCode verify_server_address(const fqdn_t* expected_address, const uint8_t* server_signed_1_tlv, const uint32_t server_signed_1_tlv_size);

ErrCode mutual_authentication__smdp(es9_t* const es9, es10_t* const es10, const fqdn_t* smdp_address, const uint8_t* matching_id, const uint8_t matching_id_size, authenticate_client_response_es9_t* authenticate_client_response) {
    ErrCode rc;
    initiate_authentication_response_t initiate_authentication_response;
    authenticate_client_request_t authenticate_client_request;
    
    /* Inititate authentication */
    if ((rc = initiate_authentication_es9(es9, es10, smdp_address, &initiate_authentication_response)) != eOk) {
        LOGE("[mutual_authentication__smdp] Error on initiate authentication, rc %d", rc);
        return rc;
    }

    /* Prepare the Autenthicate Client Request (Authenticate Server) */
    rc = prepare_authenticate_client_request(es10, matching_id, matching_id_size, &initiate_authentication_response, &authenticate_client_request);
    es9__free_initiate_authentication_response(&initiate_authentication_response);
    if (rc != eOk) {
        LOGE("[mutual_authentication__smdp] Error on prepare the AuthenticateClientRequest, rc %d", rc);
        return rc;
    }

    /* Authenticate Client */
    rc = es9__authenticate_client(es9, smdp_address->fqdn, &authenticate_client_request, authenticate_client_response);
    M_free(authenticate_client_request.authenticate_server_response);
    authenticate_client_request.authenticate_server_response = NULL;
    if (rc != eOk) {
        LOGE("[mutual_authentication__smdp] Error on authenticate client, rc %d", rc);
    }

    return rc;
}

ErrCode mutual_authentication__smds(es10_t* const es10, es11_t* const es11, const fqdn_t* smdp_address, authenticate_client_response_es11_t* authenticate_client_response) {
    ErrCode rc;
    initiate_authentication_response_t initiate_authentication_response;
    authenticate_client_request_t authenticate_client_request;
    
    /* Inititate authentication */
    if ((rc = initiate_authentication_es11(es10, es11, smdp_address, &initiate_authentication_response)) != eOk) {
        LOGE("[mutual_authentication__smds] Error on initiate authentication, rc %d", rc);
        return rc;
    }

    /* Prepare the Autenthicate Client Request (Authenticate Server) */
    rc = prepare_authenticate_client_request(es10, NULL, 0, &initiate_authentication_response, &authenticate_client_request);
    es11__free_initiate_authentication_response(&initiate_authentication_response);
    if (rc != eOk) {
        LOGE("[mutual_authentication__smds] Error on prepare the AuthenticateClientRequest, rc %d", rc);
        return rc;
    }

    /* Authenticate Client */
    rc = es11__authenticate_client(es11, smdp_address->fqdn, &authenticate_client_request, authenticate_client_response);
    M_free(authenticate_client_request.authenticate_server_response);
    authenticate_client_request.authenticate_server_response = NULL;
    if (rc != eOk) {
        LOGE("[mutual_authentication__smds] Error on authenticate client, rc %d", rc);
    }

    return rc;
}

static ErrCode initiate_authentication_es9(es9_t* const es9, es10_t* const es10, const fqdn_t* smdp_address, initiate_authentication_response_t* initiate_authentication_response) {
    initiate_authentication_request_t initiate_authentication_request;
    ErrCode rc;

    /* Prepare the InitiateAuthenticationRequest */
    if ((rc = prepare_initiate_authentication_request(es10, smdp_address, &initiate_authentication_request)) != eOk) {
        LOGE("[initiate_authentication_es9] Error preparing the InitiateAuthenticationRequest, rc %d", rc);
        return rc;
    }

    /* Execute the ES9.InitiateAuthentication */
    rc = es9__initiate_authentication(es9, smdp_address->fqdn, &initiate_authentication_request, initiate_authentication_response);
    M_free(initiate_authentication_request.euicc_info_1);
    if (rc != eOk) {
        LOGE("[initiate_authentication_es9] ES9+.InitiateAuthentication failed, rc %d", rc);
        return rc;
    }

    if (INITIATE_AUTHENTICATION_ERROR_CHOICE == initiate_authentication_response->choice) {
        LOGE("[initiate_authentication_es9] The InitiateAuthenticationResponse is a initiateAuthenticationError(%d)", initiate_authentication_response->value.error);
        es9__free_initiate_authentication_response(initiate_authentication_response);
        return eFatal;
    }
    
    /* Verify that the SM-DP+ Address returned by the SM-DP+ matches */
    if ((rc = verify_server_address(smdp_address, initiate_authentication_response->value.ok.server_signed_1, initiate_authentication_response->value.ok.server_signed_1_size)) != eOk) {
        LOGE("[initiate_authentication_es9] Error verifying the SM-DP+ Address, rc %d", rc);
        es9__free_initiate_authentication_response(initiate_authentication_response);
        return rc;
    }
    
    return eOk;
}

static ErrCode initiate_authentication_es11(es10_t* const es10, es11_t* const es11, const fqdn_t* smds_address, initiate_authentication_response_t* initiate_authentication_response) {
    initiate_authentication_request_t initiate_authentication_request;
    ErrCode rc;

    /* Prepare the InitiateAuthenticationRequest */
    if ((rc = prepare_initiate_authentication_request(es10, smds_address, &initiate_authentication_request)) != eOk) {
        LOGE("[initiate_authentication_es11] Error preparing the InitiateAuthenticationRequest, rc %d", rc);
        return rc;
    }

    /* Execute the ES11.InitiateAuthentication */
    rc = es11__initiate_authentication(es11, smds_address->fqdn, &initiate_authentication_request, initiate_authentication_response);
    M_free(initiate_authentication_request.euicc_info_1);
    if (rc != eOk) {
        LOGE("[initiate_authentication_es11] ES11.InitiateAuthentication failed, rc %d", rc);
        return rc;
    }

    if (INITIATE_AUTHENTICATION_ERROR_CHOICE == initiate_authentication_response->choice) {
        LOGE("[initiate_authentication_es11] The InitiateAuthenticationResponse is a initiateAuthenticationError(%d)", initiate_authentication_response->value.error);
        es11__free_initiate_authentication_response(initiate_authentication_response);
        return eFatal;
    }
    
    /* Verify that the SM-DS Address returned by the SM-DS matches */
    if ((rc = verify_server_address(smds_address, initiate_authentication_response->value.ok.server_signed_1, initiate_authentication_response->value.ok.server_signed_1_size)) != eOk) {
        LOGE("[initiate_authentication_es11] Error verifying the SM-DS Address, rc %d", rc);
        es11__free_initiate_authentication_response(initiate_authentication_response);
        return rc;
    }
    
    return eOk;
}

static ErrCode prepare_initiate_authentication_request(es10_t* const es10, const fqdn_t* smdp_address, initiate_authentication_request_t* initiate_authentication_request) {
    ErrCode rc;
    int err;
    get_euicc_challenge_response_t get_euicc_challenge_response_obj; 
    uint8_t* get_euicc_challenge_response = NULL;
    uint32_t get_euicc_challenge_response_size;

    /* Check input parameters */
    if (!smdp_address) {
        LOGE("[prepare_initiate_authentication_request] The SMDP Address FQDN Object is NULL");
        return eBadArg;
    }
    if (!initiate_authentication_request) {
        LOGE("[prepare_initiate_authentication_request] The InitiateAuthenticationRequest Object is NULL");
        return eBadArg;
    }

    /* Retrieve the data from the UICC */
    if ((err = es10__init(es10)) < 0) {
        LOGE("[prepare_initiate_authentication_request] Error initializing the ES10 interface, err %d", err);
        return eFatal;
    }

    if ((err = es10__get_euicc_info_1(es10, &initiate_authentication_request->euicc_info_1, &initiate_authentication_request->euicc_info_1_size)) < 0) {
        LOGE("[prepare_initiate_authentication_request] ES10.GetEUICCInfo failed, err %d", err);
        goto prepare_initiate_authentication_request_deinit_es10;
    }
    LOG_DATA(eLogDebug, "[prepare_initiate_authentication_request] GetEUICCInfo1", initiate_authentication_request->euicc_info_1, initiate_authentication_request->euicc_info_1_size);

    if ((err = es10__get_euicc_challenge(es10, &get_euicc_challenge_response, &get_euicc_challenge_response_size)) < 0) {
        LOGE("[prepare_initiate_authentication_request] ES10.GetEUICCChallenge failed, err %d", err);
        M_free(initiate_authentication_request->euicc_info_1);
        initiate_authentication_request->euicc_info_1 = NULL;
        goto prepare_initiate_authentication_request_deinit_es10;
    }
    LOG_DATA(eLogDebug, "[prepare_initiate_authentication_request] GetEuiccChallengeResponse", get_euicc_challenge_response, get_euicc_challenge_response_size);

prepare_initiate_authentication_request_deinit_es10:
    if (es10__deinit(es10) < 0) {
        LOGE("[prepare_initiate_authentication_request] Error deinitializing the ES10 interface");
    }

    if (err < 0) {
        LOGE("[prepare_initiate_authentication_request] Error retrieving data from the UICC the prepare the InitiateAuthenticationRequest");
        return eFatal;
    }

    /* Extract the UICC data */
    rc = es10_tlv_extractor__get_euicc_challenge_response(get_euicc_challenge_response, get_euicc_challenge_response_size, &get_euicc_challenge_response_obj);
    M_free(get_euicc_challenge_response);
    get_euicc_challenge_response = NULL;
    if (rc != eOk) {
        LOGE("[prepare_initiate_authentication_request] tlv_data_extractor__euicc_challenge failed, rc %d", rc);
        M_free(initiate_authentication_request->euicc_info_1);
        return rc;
    }

    /* Prepare the InitiateAuthenticationRequest */
    memcpy(&initiate_authentication_request->euicc_challenge, &get_euicc_challenge_response_obj.euicc_challenge, sizeof(challenge_t));
    LOG_DATA(eLogDebug, "[prepare_initiate_authentication_request] euiccChallenge", initiate_authentication_request->euicc_challenge.challenge, sizeof(initiate_authentication_request->euicc_challenge.challenge));
    memcpy(&initiate_authentication_request->smdp_address, smdp_address, sizeof(fqdn_t));
    LOGD("[prepare_initiate_authentication_request] smdpAddress: %s", initiate_authentication_request->smdp_address.fqdn);

    return eOk;
}

static ErrCode prepare_authenticate_client_request(es10_t* const es10, const uint8_t* matching_id, const uint8_t matching_id_size, initiate_authentication_response_t* initiate_authentication_response, authenticate_client_request_t* authenticate_client_request) {
    ErrCode rc;

    /* Check input parameters */
    if (!initiate_authentication_response) {
        LOGE("[prepare_authenticate_client_request] The InitiateAuthenticationResponse Object is NULL");
        return eBadArg;
    }
    if (!authenticate_client_request) {
        LOGE("[prepare_authenticate_client_request] The AuthenticateClientRequest Object is NULL");
        return eBadArg;
    }
    if (initiate_authentication_response->choice != INITIATE_AUTHENTICATION_OK_CHOICE) {
        LOGE("[prepare_authenticate_client_request] The InitiateAuthenticationResponse CHOICE is not Ok, choice %d", initiate_authentication_response->choice);
        return eBadArg;
    }

    /* Send the Authenticate Server against the UICC */
    if ((rc = authenticate_server(es10, matching_id, matching_id_size, initiate_authentication_response, &authenticate_client_request->authenticate_server_response, &authenticate_client_request->authenticate_server_response_size)) != eOk) {
        LOGE("[prepare_authenticate_client_request] Error on AuthenticateServer, rc %d", rc);
        return rc;
    }

    memcpy(&authenticate_client_request->transaction_id, &initiate_authentication_response->value.ok.transaction_id, sizeof(transaction_id_t)); // Copy the TransactionId

    return eOk;
}

static ErrCode authenticate_server(es10_t* const es10, const uint8_t* matching_id, const uint8_t matching_id_size, initiate_authentication_response_t* initiate_authentication_response, uint8_t** auth_server_response, uint32_t* auth_server_response_size) {
    int err;
    authenticate_server_request_t authenticate_server_request;

    /* Check input parameters */
    if (!initiate_authentication_response) {
        LOGE("[authenticate_server] InitiateAuthenticationResponse object is null");
        return eBadArg;
    }
    if (initiate_authentication_response->choice != INITIATE_AUTHENTICATION_OK_CHOICE) {
        LOGE("[authenticate_server] The InitiateAuthenticationResponse CHOICE is not Ok, choice %d", initiate_authentication_response->choice);
        return eBadArg;
    }

    /* Prepare the AuthenticateServerRequest */
    // serverSigned1
    authenticate_server_request.server_signed_1 = initiate_authentication_response->value.ok.server_signed_1;
    authenticate_server_request.server_signed_1_size = initiate_authentication_response->value.ok.server_signed_1_size;
    // serverSignature1
    authenticate_server_request.server_signature_1 = initiate_authentication_response->value.ok.server_signature_1;
    authenticate_server_request.server_signature_1_size = initiate_authentication_response->value.ok.server_signature_1_size;
    // euiccCiPKIdToBeUsed
    memcpy(&authenticate_server_request.euicc_ci_pk_id_to_be_used, &initiate_authentication_response->value.ok.euicc_ci_pk_id_to_be_used, sizeof(subject_key_identifier_t));
    // serverCertificate
    authenticate_server_request.server_certificate = initiate_authentication_response->value.ok.server_certificate;
    authenticate_server_request.server_certificate_size = initiate_authentication_response->value.ok.server_certificate_size;
    // ctxParams1
    authenticate_server_request.ctx_params_1.type = CTX_PARAMS_1_OBJ;
    authenticate_server_request.ctx_params_1.value.ctx_params_1_obj.ctx_params_for_common_authentication.device_info = device_info__get_instance();
    if (matching_id && matching_id_size > 0) {
        authenticate_server_request.ctx_params_1.value.ctx_params_1_obj.ctx_params_for_common_authentication.matching_id = matching_id;
        authenticate_server_request.ctx_params_1.value.ctx_params_1_obj.ctx_params_for_common_authentication.matching_id_size = matching_id_size;
        authenticate_server_request.ctx_params_1.value.ctx_params_1_obj.ctx_params_for_common_authentication.field_is_present.matching_id = true;
    } else {
        authenticate_server_request.ctx_params_1.value.ctx_params_1_obj.ctx_params_for_common_authentication.field_is_present.matching_id = false;
    }

    /* Send the AuthenticateServerRequest against the UICC */
    if ((err = es10__init(es10)) < 0) {
        LOGE("[authenticate_server] Error initializing the ES10 interface, err %d", err);
        return eFatal;
    }

    if ((err = es10__authenticate_server(es10, &authenticate_server_request, auth_server_response, auth_server_response_size)) < 0) {
        LOGE("[authenticate_server] ES10.AuthenticateServer failed, err %d", err);
    }

    if (es10__deinit(es10) < 0) {
        LOGE("[prepare_initiate_authentication_request] Error deinitializing the ES10 interface");
    }

    if (err < 0) {
        LOGE("[prepare_initiate_authentication_request] Error on Authenticate Server");
        return eFatal;
    }

    return eOk;
}

static ErrCode verify_server_address(const fqdn_t* expected_address, const uint8_t* server_signed_1_tlv, const uint32_t server_signed_1_tlv_size) {
    ErrCode rc;
    server_signed_1_t server_signed_1;

    if (!expected_address) {
        LOGE("[verify_server_address] The expected address is null");
        return eBadArg;
    }

    if ((rc = es10_tlv_extractor__server_signed_1(server_signed_1_tlv, server_signed_1_tlv_size, &server_signed_1)) != eOk) {
        LOGE("[verify_server_address] Error extracting the ServerSigned1, rc %d", rc);
        return rc;
    }

    if (strcmp(expected_address->fqdn, server_signed_1.server_address.fqdn) != 0) {
        LOGE("[verify_server_address] The SM-XX Address returned by the SM-XX in the ServerSigned1 mismatch. Expected='%s', provided='%s'", expected_address->fqdn, server_signed_1.server_address.fqdn);
        return eFatal;
    }

    return eOk;
}
