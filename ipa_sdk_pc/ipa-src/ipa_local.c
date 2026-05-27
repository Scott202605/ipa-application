/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include <malloc.h>
#include "ipa_local.h"
#include "log.h"
#include "memory_manager.h"
#include "es10.h"
#include "es10_tlv_extractor.h"
#include "ipa.h"
#include "ipa_display.h"
#include "ipa_core.h"
#include "base64.h"

ErrCode ipa_local__euicc_memory_reset(
    const euicc_memory_reset_request_t *euicc_memory_reset_request) {
    ErrCode rc;
    int err;
    uint8_t *euicc_memory_reset_response_tlv;
    uint32_t euicc_memory_reset_response_tlv_size;
    euicc_memory_reset_response_t euicc_memory_reset_response;
    LOGI("Restarting memory from the eUICC of the IoT device");

    if ((err = es10__init(&g_es10)) < 0) {
        LOGE("[ipa_local__euicc_memory_reset] Error initializing the ES10, err %d", err);
        return eFatal;
    }

    if ((err = es10__euicc_memory_reset(&g_es10, euicc_memory_reset_request,
                                        &euicc_memory_reset_response_tlv,
                                        &euicc_memory_reset_response_tlv_size)) < 0) {
        LOGE("[ipa_local__euicc_memory_reset] ES10.eUICCMemoryReset failed, err %d", err);
        rc = eFatal;
        goto ipa_local_euicc_memory_reset_es10_deinit;
    }

    /* Extract data from the EuiccMemoryResetResponse */
    rc = es10_tlv_extractor__euicc_memory_reset_response(euicc_memory_reset_response_tlv,
                                                         euicc_memory_reset_response_tlv_size,
                                                         &euicc_memory_reset_response);
    M_free(euicc_memory_reset_response_tlv);
    euicc_memory_reset_response_tlv = NULL;
    euicc_memory_reset_response_tlv_size = 0;
    if (rc != eOk) {
        LOGE("[ipa_local__euicc_memory_reset] Error extracting data from the EuiccMemoryResetResponse, rc %d",
             rc);
        goto ipa_local_euicc_memory_reset_es10_deinit;
    }

    /* Print the result */
    ipa_display__euicc_memory_reset_response(euicc_memory_reset_request,
                                             &euicc_memory_reset_response);

ipa_local_euicc_memory_reset_es10_deinit:

    if ((err = es10__deinit(&g_es10)) < 0) {
        LOGE("[ipa_local__euicc_memory_reset] Error deinitializing the ES10, err %d", err);
    }

    return rc;
}

ErrCode ipa_local__set_default_dp_address(
    const set_default_dp_address_request_t *set_default_dp_address_request) {
    ErrCode rc;
    int err;
    uint8_t *set_default_dp_address_response_tlv;
    uint32_t set_default_dp_address_response_tlv_size;
    set_default_dp_address_response_t set_default_dp_address_response;
    LOGI("Setting default Dp Address on the eUICC of the IoT device");

    if ((err = es10__init(&g_es10)) < 0) {
        LOGE("[ipa_local__set_default_dp_address] Error initializing the ES10, err %d",
             err);
        return eFatal;
    }

    if ((err = es10__set_default_dp_address(&g_es10, set_default_dp_address_request,
                                            &set_default_dp_address_response_tlv,
                                            &set_default_dp_address_response_tlv_size)) < 0) {
        LOGE("[ipa_local__set_default_dp_address] ES10.SetDefaultDpAddress failed, err %d",
             err);
        rc = eFatal;
        goto ipa_local_set_default_dp_address_es10_deinit;
    }

    /* Extract data from the SetDefaultDpAddressResponse */
    rc = es10_tlv_extractor__set_default_dp_address_response(set_default_dp_address_response_tlv,
                                                             set_default_dp_address_response_tlv_size,
                                                             &set_default_dp_address_response);
    M_free(set_default_dp_address_response_tlv);
    set_default_dp_address_response_tlv = NULL;
    set_default_dp_address_response_tlv_size = 0;
    if (rc != eOk) {
        LOGE(
            "[ipa_local__set_default_dp_address] Error extracting data from the SetDefaultDpAddressResponse, rc %d",
            rc);
        goto ipa_local_set_default_dp_address_es10_deinit;
    }

    /* Print the result */
    ipa_display__set_default_dp_address_response(set_default_dp_address_request,
                                                 &set_default_dp_address_response);

ipa_local_set_default_dp_address_es10_deinit:

    if ((err = es10__deinit(&g_es10)) < 0) {
        LOGE("[ipa_local__set_default_dp_address] Error deinitializing the ES10, err %d",
             err);
    }

    return rc;
}

#ifdef SGP32

ErrCode
ipa_local__add_initial_eim(const eim_config_t *eim_config_t) {
    eim_configuration_data_t eim_configuration_data = {0};


    eim_configuration_data.eim_id = (unsigned char*)eim_config_t->eim_id;
    eim_configuration_data.eim_id_len = (uint32_t)strlen(eim_config_t->eim_id);


    eim_configuration_data.eim_fqdn = (unsigned char*)eim_config_t->eim_fqdn;
    eim_configuration_data.eim_fqdn_len = (uint32_t)strlen(eim_config_t->eim_fqdn);
    eim_configuration_data.field_is_present.eim_fqdn = true;
    eim_configuration_data.counter_value = eim_config_t->counter_value;
    eim_configuration_data.field_is_present.counter_value = true;

    int32_t decoded_size = base64__decode(NULL, 0,
                                          (const unsigned char*)eim_config_t->eim_public_key_base64,
                                          strlen(eim_config_t->eim_public_key_base64));

    if (decoded_size < 0) {
        return eBadArg;
    }

    unsigned char *decoded_pk_buffer = (unsigned char*)malloc(decoded_size);
    if (!decoded_pk_buffer) {
        return eNoMem;
    }

    int32_t written_bytes = base64__decode(decoded_pk_buffer, decoded_size,
                                           (const unsigned char*)eim_config_t->eim_public_key_base64,
                                           strlen(eim_config_t->eim_public_key_base64));

    if (written_bytes < 0) {
        free(decoded_pk_buffer);
        return eBadArg;
    }

    eim_configuration_data.eim_public_key_data.choice = eim_config_t->choice;
    eim_configuration_data.eim_public_key_data.value = decoded_pk_buffer;
    eim_configuration_data.eim_public_key_data.value_size = (uint32_t)written_bytes;
    eim_configuration_data.field_is_present.eim_public_key_data = true;


    eim_configuration_data.eim_id_type = (eim_config_t->eim_id_type > 0)
                                             ? eim_config_t->eim_id_type
                                             : 1;
    eim_configuration_data.field_is_present.eim_id_type = true;

    if (eim_config_t->eim_supported_protocol.eim_retrieve_https) {
        eim_configuration_data.eim_supported_protocol.eim_retrieve_https = true;
    }
    if (eim_config_t->eim_supported_protocol.eim_inject_https) {
        eim_configuration_data.eim_supported_protocol.eim_inject_https = true;
    }
    if (eim_config_t->eim_supported_protocol.eim_retrieve_coaps) {
        eim_configuration_data.eim_supported_protocol.eim_retrieve_coaps = true;
    }
    if (eim_config_t->eim_supported_protocol.eim_inject_coaps) {
        eim_configuration_data.eim_supported_protocol.eim_inject_coaps = true;
    }
    if (eim_config_t->eim_supported_protocol.eim_proprietary) {
        eim_configuration_data.eim_supported_protocol.eim_proprietary = true;
    }
    eim_configuration_data.field_is_present.eim_supported_protocol =
    (eim_config_t->eim_supported_protocol.eim_retrieve_https || eim_config_t->eim_supported_protocol.
                                                                              eim_proprietary);

    if (eim_config_t->indirect_profile_download) {
        eim_configuration_data.field_is_present.indirect_profile_download = true;
    }

    ErrCode rc;
    int err;
    uint8_t *add_initial_eim_response_tlv;
    uint32_t add_initial_eim_response_tlv_size;
    add_initial_eim_response_t add_initial_eim_response;
    LOGI("Adding a Initial eIM on the eUICC of the IoT device");

    if ((err = es10__init(&g_es10)) < 0) {
        LOGE("[ipa_local__add_initial_eim] Error initializing the ES10, err %d", err);
        return eFatal;
    }

    if ((err = es10__add_initial_eim(&g_es10, &eim_configuration_data,
                                     &add_initial_eim_response_tlv,
                                     &add_initial_eim_response_tlv_size)) != eOk) {
        LOGE("[ipa_local__add_initial_eim] ES10.AddInitialEim failed, err %d", err);
        rc = eFatal;
        goto ipa_local__add_initial_eim_es10_deinit;
    }

    /* Extract data from the EuiccMemoryResetResponse */
    rc = es10_tlv_extractor__add_initial_eim_response(add_initial_eim_response_tlv,
                                                      add_initial_eim_response_tlv_size,
                                                      &add_initial_eim_response);
    M_free(add_initial_eim_response_tlv);
    add_initial_eim_response_tlv = NULL;
    add_initial_eim_response_tlv_size = 0;
    if (rc != eOk) {
        LOGE("[ipa_local__add_initial_eim] Error extracting data from the AddInitialEimResponse, rc %d",
             rc);
        goto ipa_local__add_initial_eim_es10_deinit;
    }

    /* Print the result */
    ipa_display__add_initial_eim_response(&add_initial_eim_response);

    if (g_ipa_state == IPA_STATE_WAITING_FOR_PROVISIONING) {
        LOGI("[add_initial_eim] eIM successfully provisioned. Triggering IPA initialization to continue...");
        g_ipa_state = IPA_STATE_INITIALIZING;
    } else {
        LOGI("[add_initial_eim] eIM added successfully.");
    }

ipa_local__add_initial_eim_es10_deinit:

    if ((err = es10__deinit(&g_es10)) < 0) {
        LOGE("[ipa_local__add_initial_eim] Error deinitializing the ES10, err %d", err);
    }

    return rc;
}

ErrCode ipa_local__configure_immediate_profile_enabling(
    const profile_enabling_config_t *profile_enabling_config) {
    if (!profile_enabling_config) {
        return eBadArg;
    }
    configure_immediate_profile_enabling_request_t configure_immediate_profile_enabling_request = {0};
    if (profile_enabling_config->smdp_address != NULL) {
        configure_immediate_profile_enabling_request.field_is_present.default_smdp_address = true;
        configure_immediate_profile_enabling_request.default_smdp_address_len = strlen(
            profile_enabling_config->smdp_address);
    }

    if (profile_enabling_config->smdp_oid != NULL) {
        configure_immediate_profile_enabling_request.field_is_present.default_smdp_oid = true;
        configure_immediate_profile_enabling_request.default_smdp_oid_len = strlen(profile_enabling_config->smdp_oid);
    }
    configure_immediate_profile_enabling_request.field_is_present.immediate_enable_flag = profile_enabling_config->
        immediate_enable_flag;
    configure_immediate_profile_enabling_request.default_smdp_address = (unsigned char*)profile_enabling_config->
        smdp_address;
    configure_immediate_profile_enabling_request.default_smdp_oid = (unsigned char*)profile_enabling_config->smdp_oid;

    ErrCode rc;
    int err;
    uint8_t *configure_immediate_profile_enabling_response_tlv;
    uint32_t configure_immediate_profile_enabling_response_tlv_size;
    configure_immediate_profile_enabling_response_t configure_immediate_profile_enabling_response;
    LOGI("Configuring the immediate profile enabling with the following seetings:");
    if (configure_immediate_profile_enabling_request.field_is_present.immediate_enable_flag) {
        LOGI("\t- Activate immediate Profile enabling");
    } else {
        LOGI("\t- Deactivate immediate Profile enabling");
    }
    if (configure_immediate_profile_enabling_request.field_is_present.default_smdp_oid) {
        LOG_UTF8_DATA(eLogInfo, "\t- SMDP+ OID: ",
                      configure_immediate_profile_enabling_request.default_smdp_oid,
                      configure_immediate_profile_enabling_request.default_smdp_oid_len);
    }
    if (configure_immediate_profile_enabling_request.field_is_present.default_smdp_address) {
        LOG_UTF8_DATA(eLogInfo, "\t- SMDP+ Address: ",
                      configure_immediate_profile_enabling_request.default_smdp_address,
                      configure_immediate_profile_enabling_request.default_smdp_address_len);
    }

    if ((err = es10__init(&g_es10)) < 0) {
        LOGE("[ipa_local__configure_immediate_profile_enabling] Error initializing the ES10, err %d",
             err);
        return eFatal;
    }

    if ((err = es10__configure_immediate_profile_enabling(&g_es10,
                                                          &configure_immediate_profile_enabling_request,
                                                          &configure_immediate_profile_enabling_response_tlv,
                                                          &configure_immediate_profile_enabling_response_tlv_size)) <
        0) {
        LOGE(
            "[ipa_local__configure_immediate_profile_enabling] ES10.ConfigureImmediateProfileEnabling failed, err %d",
            err);
        rc = eFatal;
        goto ipa_local__configure_immediate_profile_enabling_es10_deinit;
    }

    /* Extract data from the EuiccMemoryResetResponse */
    rc = es10_tlv_extractor__configure_immediate_profile_enabling_response(
        configure_immediate_profile_enabling_response_tlv,
        configure_immediate_profile_enabling_response_tlv_size,
        &configure_immediate_profile_enabling_response);
    M_free(configure_immediate_profile_enabling_response_tlv);
    configure_immediate_profile_enabling_response_tlv = NULL;
    configure_immediate_profile_enabling_response_tlv_size = 0;
    if (rc != eOk) {
        LOGE(
            "[ipa_local__configure_immediate_profile_enabling] Error extracting data from the ConfigureAutoProfileEnablingResponse, rc %d",
            rc);
        goto ipa_local__configure_immediate_profile_enabling_es10_deinit;
    }

    /* Print the result */
    ipa_display__configure_immediate_profile_enabling_response(
        &configure_immediate_profile_enabling_response);

ipa_local__configure_immediate_profile_enabling_es10_deinit:

    if ((err = es10__deinit(&g_es10)) < 0) {
        LOGE("[ipa_local__configure_immediate_profile_enabling] Error deinitializing the ES10, err %d",
             err);
    }
    return rc;
}

#endif
