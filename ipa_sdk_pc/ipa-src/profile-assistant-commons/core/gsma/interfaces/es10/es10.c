/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include "es10.h"

#include "es10_tlv_generator.h"
#include "es10_tlv_extractor.h"
#include "es10_display.h"
#include "log.h"
#include "memory_manager.h"
#include "smartcard.h"
#include "timer.h"
#include "apdu_utils.h"
#include "tlv_tags.h"
#include <errno.h>

#define DEFAULT_INITIAL_REFRESH_SLEEP   1
#define DEFAULT_MAX_REFRESH_SLEEP       60
#define STORE_DATA_MAX_ATTEMPTS 2

#define RSP_DEV_CAPS_INS	(uint8_t) 0xAA
#define RSP_DEV_CAPS_P		(uint8_t) 0x00

static const uint8_t isdr_aid[] = {0xA0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0x89, 0x00, 0x00, 0x01, 0x00};

#ifndef SKIP_TERMINAL_CAPABILITY
static uint8_t terminal_capability_data[] = {TERMINAL_CAPABILITY, 0x05, 0x81, 0x00, EUICC_RELATED_CAPABILITIES, 0x01, EUICC_RELATED_CAPABILITIES_VALUE};

static const command_apdu_t terminal_capability_apdu = {
    .cla = 0x80,
    .ins = RSP_DEV_CAPS_INS,
    .p1 = RSP_DEV_CAPS_P,
    .p2 = RSP_DEV_CAPS_P,
    .lc = sizeof(terminal_capability_data),
    .data_field = terminal_capability_data,
    .le = 0x00
};
#endif

static int es10__smartcard_additional_init_steps(void* const context);
static int es10__init_rec(es10_t * const es10, uint32_t sleep);
static int es10__select_isdr_application(es10_t * const es10);
#ifndef SKIP_TERMINAL_CAPABILITY
static int es10__terminal_capability(es10_t * const es10);
#endif
static int es10__store_data(es10_t * const es10, const uint8_t* tlv_bytes, const uint32_t tlv_bytes_size, uint8_t** response, uint32_t* response_size);
static int es10__store_data_rec(es10_t * const es10, const uint8_t* tlv_bytes, const uint32_t tlv_bytes_size, uint8_t attempt, uint8_t** response, uint32_t* response_size);
static int es10__append_response_data(uint8_t** buffer, uint32_t* buffer_size, const uint8_t* response_data, const uint16_t response_data_size);

int es10__ctor(es10_t * const es10, smartcard_t* smart_card) {
    LOGT("[es10__ctor] es10 constructor call");

    if (!smart_card) {
        LOGE("[es10__ctor] The Smartcard object is null");
        return -EINVAL;
    }

    if (!es10) {
        LOGE("[es10__ctor] The ES10 object is null");
        return -EINVAL;
    }

    es10->smart_card = smart_card;
    es10->initial_refresh_sleep = DEFAULT_INITIAL_REFRESH_SLEEP;
    es10->max_refresh_sleep = DEFAULT_MAX_REFRESH_SLEEP;

    smartcard__set_additional_init_steps(es10->smart_card, es10__smartcard_additional_init_steps, (void*) es10);

    return 0;
}

int es10__init(es10_t * const es10) {
    LOGT("[es10__init] es10 initialize call");
    if (es10->initial_refresh_sleep > es10->max_refresh_sleep) {
        LOGE("[es10__init] The init refresh sleep can not be bigger than the max refresh sleep");
        return -EINVAL;
    }
    return es10__init_rec(es10, (uint32_t) es10->initial_refresh_sleep);
}

int es10__deinit(es10_t * const es10) {
    int err; 
    LOGT("[es10__deinit] es10 deinitialize call");

    if (!es10) {
        LOGE("[es10__deinit] The ES10 object is null");
        return -EINVAL;
    }

    if ((err = smartcard__close_channel(es10->smart_card)) < 0) {
        LOGE("[es10__deinit] Error closing the channel, err %d", err);
    }

    if ((err = smartcard__deinit(es10->smart_card)) < 0) {
        LOGE("[es10__deinit] Error deinitializing the es10 instance, err %d", err);
    }

    return err;
}

int es10__destroy(es10_t * const es10) {
    LOGT("[es10__destroy] es10 destroy call");

    if (!es10) {
        LOGE("[es10__destroy] The ES10 object is null");
        return -EINVAL;
    }
    
    es10->smart_card = NULL;

    return 0;
}

void es10__set_initial_refresh_sleep(es10_t * const es10, const uint8_t seconds) {
    es10->initial_refresh_sleep = seconds;
    LOGD("[es10__set_initial_refresh_sleep] The initial refresh sleep has been changed to %u", es10->initial_refresh_sleep);
}

void es10__set_max_refresh_sleep(es10_t * const es10, const uint8_t seconds) {
    es10->max_refresh_sleep = seconds;
    LOGD("[es10__set_initial_refresh_sleep] The max refresh sleep has been changed to %u", es10->max_refresh_sleep);
}

int es10__get_euicc_configured_addresses(es10_t * const es10, uint8_t** response, uint32_t* response_size) {
    static const uint8_t tlv[] = { (uint8_t) (EUICC_CONFIGURED_ADDRESSES >> 8), (uint8_t) EUICC_CONFIGURED_ADDRESSES, 0x00};
    LOGI("ES10.GetEuiccConfiguredAddresses");
    LOG_DATA(eLogDebug, "Sending a EuiccConfiguredAddressesRequest", tlv, sizeof(tlv));

    return es10__store_data(es10, tlv, sizeof(tlv), response, response_size);
}

int es10__get_euicc_info_1(es10_t * const es10, uint8_t** response, uint32_t* response_size) {
    static const uint8_t tlv[] = { (uint8_t) (EUICC_INFO_1 >> 8), (uint8_t) EUICC_INFO_1, 0x00 };
    LOGI("ES10.GetEUICCInfo1");
    LOG_DATA(eLogDebug, "Sending a GetEuiccInfo1Request", tlv, sizeof(tlv));

    return es10__store_data(es10, tlv, sizeof(tlv), response, response_size);
}

int es10__get_euicc_info_2(es10_t * const es10, uint8_t** response, uint32_t* response_size) {
    static const uint8_t tlv[] = { (uint8_t) (EUICC_INFO_2 >> 8), (uint8_t) EUICC_INFO_2, 0x00 };
    LOGI("ES10.GetEUICCInfo2");
    LOG_DATA(eLogDebug, "Sending a GetEuiccInfo2Request", tlv, sizeof(tlv));

    return es10__store_data(es10, tlv, sizeof(tlv), response, response_size);
}

int es10__get_euicc_challenge(es10_t * const es10, uint8_t** response, uint32_t* response_size) {
    static const uint8_t tlv[] = { (uint8_t) (GET_EUICC_CHALLENGE >> 8), (uint8_t) GET_EUICC_CHALLENGE, 0x00 };
    LOGI("ES10.GetEUICCChallenge");
    LOG_DATA(eLogDebug, "Sending a GetEuiccChallengeRequest", tlv, sizeof(tlv));

    return es10__store_data(es10, tlv, sizeof(tlv), response, response_size);
}

int es10__euicc_memory_reset(es10_t * const es10, const euicc_memory_reset_request_t* request_obj, uint8_t** response, uint32_t* response_size) {
    uint8_t tlv[7];
    int32_t tlv_size;
    es10_display__euicc_memory_reset_request(request_obj);

    if ((tlv_size = es10_tlv_generator__euicc_memory_reset(tlv, sizeof(tlv), 0, request_obj)) < 0) {
        LOGE("[es10__euicc_memory_reset] Error on write the EuiccMemoryResetRequest TLV, err %d", tlv_size);
        return -ECANCELED;
    }

    LOG_DATA(eLogDebug, "Sending a EuiccMemoryResetRequest", tlv, (size_t) tlv_size);
    
    return es10__store_data(es10, tlv, tlv_size, response, response_size);
}

int es10__authenticate_server(es10_t * const es10, const authenticate_server_request_t* request_obj, uint8_t** response, uint32_t* response_size) {
    int err;
    uint8_t* tlv;
    int32_t tlv_size;
    LOGI("ES10.AuthenticateServer");

    //Calculate the size of the AuthenticateServerRequest
    if ((tlv_size = es10_tlv_generator__authenticate_server_request(NULL, 0, 0, request_obj)) < 0) {
        LOGE("[es10__authenticate_server] Error on calculate the size of the AuthenticateServerRequest TLV, err %d", tlv_size);
        return -ECANCELED;
    }
    //Allocate data for the AuthenticateServerRequest
    tlv = M_malloc(tlv_size);
    if (!tlv) {
        LOGE("[es10__authenticate_server] Can not allocate data for the AuthenticateServerRequest TLV");
        return -ENOMEM;
    }
    //Add the AuthenticateServerRequest to the allocated buffer
    if ((tlv_size = es10_tlv_generator__authenticate_server_request(tlv, tlv_size, 0, request_obj)) < 0) {
        LOGE("[es10__authenticate_server] Error on write the AuthenticateServerRequest TLV, err %d", tlv_size);
        M_free(tlv);
        return -ECANCELED;
    }

    LOG_DATA(eLogDebug, "Sending a AuthenticateServerRequest", tlv, (size_t) tlv_size);

    err = es10__store_data(es10, tlv, tlv_size, response, response_size);
    M_free(tlv);

    return err;
}

int es10__prepare_download(es10_t * const es10, const prepare_download_request_t* request_obj, uint8_t** response, uint32_t* response_size) {
    int err;
    uint8_t* tlv;
    int32_t tlv_size;
    LOGI("ES10.PrepareDownload");

    //Calculate the size of the PrepareDownloadRequest
    if ((tlv_size = es10_tlv_generator__prepare_download_request(NULL, 0, 0, request_obj)) < 0) {
        LOGE("[es10__prepare_download] Error on calculate the size of the PrepareDownloadRequest TLV, err %d", tlv_size);
        return -ECANCELED;
    }
    //Allocate data for the PrepareDownloadRequest
    tlv = (uint8_t*) M_malloc(tlv_size);
    if (!tlv) {
        LOGE("[es10__prepare_download] Can not allocate data for the PrepareDownloadRequest TLV");
        return -ENOMEM;
    }
    //Add the PrepareDownloadRequest to the allocated buffer
    if ((tlv_size = es10_tlv_generator__prepare_download_request(tlv, (uint32_t) tlv_size, 0, request_obj)) < 0) {
        LOGE("[es10__prepare_download] Error on write the size of the PrepareDownloadRequest TLV, err %d", tlv_size);
        M_free(tlv);
        return -ECANCELED;
    }

    LOG_DATA(eLogDebug, "Sending a PrepareDownloadRequest", tlv, (size_t) tlv_size);

    err = es10__store_data(es10, tlv, tlv_size, response, response_size);
    M_free(tlv);

    return err;
}

int es10__load_bound_profile_package(es10_t * const es10, const uint8_t* bpp, const uint32_t bpp_size, uint8_t** response, uint32_t* response_size) {
    ErrCode rc;
    int err;
    segmented_bound_profile_package_t segmented_bpp;
    uint8_t* element;
    uint32_t element_size;
    uint32_t element_count;
    uint32_t num_of_elements;

    /* Segment the Bound Profile Package */
    if ((rc = es10_tlv_extractor__segmented_bound_profile_package(bpp, bpp_size, &segmented_bpp)) != eOk) {
        LOGE("[es10__load_bound_profile_package] Error segmenting the Bound Profile Package, rc %d", rc);
        return -ECANCELED;
    }
    
    LOGI("ES10.LoadBoundProfilePackage");

    /* InitialiseSecureChannel */
    LOGI("\tES8+.InitialiseSecureChannel");
    if ((err = es10__store_data(es10, segmented_bpp.tag_length_bpp_and_init_secure_channel_req, segmented_bpp.tag_length_bpp_and_init_secure_channel_req_size, response, response_size)) < 0) {
        LOGE("[es10__load_bound_profile_package] Error on ES8+.InitialiseSecureChannel, err %d", err);
        return err;
    }
    if (*response_size > 0) {
        goto early_profile_installation_result;
    }

    /* ConfigureISDP */
    LOGI("\tES8+.ConfigureISDP");
    if ((err = es10__store_data(es10, segmented_bpp.first_sequence_of_87, segmented_bpp.first_sequence_of_87_size, response, response_size)) < 0) {
        LOGE("[es10__load_bound_profile_package] Error on ES8+.ConfigureISDP, err %d", err);
        return err;
    }
    if (*response_size > 0) {
        goto early_profile_installation_result;
    }

    /* StoreMetadata */
    if ((rc = tlv_data_extractor__asn1_list_size(&segmented_bpp.elements_of_88, &num_of_elements)) != eOk) { // Optional, used only to log the iterations
        LOGE("[es10__load_bound_profile_package] Error counting the number of '88' TLVs, %d", rc);
        return -ECANCELED;
    }
    LOGI("\tES8+.StoreMetadata(0/%u)", num_of_elements);  // Tag and Length sequenceOf88
    element_count = 1;
    if ((err = es10__store_data(es10, segmented_bpp.tag_length_sequence_of_88, segmented_bpp.tag_length_sequence_of_88_size, response, response_size)) < 0) {
        LOGE("[es10__load_bound_profile_package] Error on ES8+.StoreMetadata, while sending the tag and length fields of the sequenceOf88 TLV, err %d", err);
        return err;
    }
    if (*response_size > 0) {
        goto early_profile_installation_result;
    }
    while ((rc = tlv_data_extractor__asn1_list_get_next(&segmented_bpp.elements_of_88, &element, &element_size)) == eOk && element != NULL) {
        LOGI("\tES8+.StoreMetadata(%u/%u)", element_count, num_of_elements);
        if ((err = es10__store_data(es10, element, element_size, response, response_size)) < 0) {
            LOGE("[es10__load_bound_profile_package] Error on ES8+.StoreMetadata, err %d", err);
            return err;
        }
        if (*response_size > 0) {
            goto early_profile_installation_result;
        }
        element_count++;
    }
    if (rc != eOk) {
        LOGE("[es10__load_bound_profile_package] Error iterating over the sequenceOf88 List, rc %d", rc);
        return -ECANCELED;
    }

    /* ReplaceSessionKeys */
    if (segmented_bpp.field_is_present.second_sequence_of_87) {
        LOGI("\tES8+.ReplaceSessionKeys");
        if ((err = es10__store_data(es10, segmented_bpp.second_sequence_of_87, segmented_bpp.second_sequence_of_87_size, response, response_size)) < 0) {
            LOGE("[es10__load_bound_profile_package] Error on ES8+.ReplaceSessionKeys, err %d", err);
            return err;
        }
        if (*response_size > 0) {
            goto early_profile_installation_result;
        }
    }

    /* LoadProfileElements */
    if ((rc = tlv_data_extractor__asn1_list_size(&segmented_bpp.elements_of_86, &num_of_elements)) != eOk) { // Optional, used only to log the iterations
        LOGE("[es10__load_bound_profile_package] Error counting the number of '86' TLVs, rc %d", rc);
        return -ECANCELED;
    }
    LOGI("\tES8+.LoadProfileElements(0/%u)", num_of_elements); // Tag and Length sequenceOf88
    element_count = 1;
    if ((err = es10__store_data(es10, segmented_bpp.tag_length_sequence_of_86, segmented_bpp.tag_length_sequence_of_86_size, response, response_size)) < 0) {
        LOGE("[es10__load_bound_profile_package] Error on ES8+.LoadProfileElements, while sending the tag and length fields of the sequenceOf86 TLV, err %d", err);
        return err;
    }
    if (*response_size > 0) {
        goto early_profile_installation_result;
    }
    while ((rc = tlv_data_extractor__asn1_list_get_next(&segmented_bpp.elements_of_86, &element, &element_size)) == eOk && element != NULL) {
        LOGI("\tES8+.LoadProfileElements(%u/%u)", element_count, num_of_elements);
        if ((err = es10__store_data(es10, element, element_size, response, response_size)) < 0) {
            LOGE("[es10__load_bound_profile_package] Error on ES8+.LoadProfileElements, err %d", err);
            return err;
        }
        if (*response_size > 0 && element_count < num_of_elements) {
            goto early_profile_installation_result;
        }
        element_count++;
    }
    if (rc != eOk) {
        LOGE("[es10__load_bound_profile_package] Error iterating over the sequenceOf86 List, rc %d", rc);
        return -ECANCELED;
    }
    
    return 0;

early_profile_installation_result:
    LOGW("\tProfileInstallationResult received prior to completion of the LoadBoundProfilePackage");
    return 0;
}

int es10__cancel_session(es10_t * const es10, const cancel_session_request_t* request_obj, uint8_t** response, uint32_t* response_size) {
    uint8_t tlv[24];
    int32_t tlv_size;
    es10_display__cancel_session_request(request_obj);

    if ((tlv_size = es10_tlv_generator__cancel_session_request(tlv, sizeof(tlv), 0, request_obj)) < 0) {
        LOGE("[es10__cancel_session] Error on write the CancelSessionRequest TLV, err %d", tlv_size);
        return -ECANCELED;
    }
    LOG_DATA(eLogDebug, "Sending a CancelSessionRequest", tlv, tlv_size);

    return es10__store_data(es10, tlv, (size_t) tlv_size, response, response_size);
}

int es10__retrieve_notifications_list(es10_t * const es10, const retrieve_notifications_list_request_t* request_obj, uint8_t** response, uint32_t* response_size) {
    uint8_t tlv[12];
    int32_t tlv_size;
    es10_display__retrieve_notifications_list_request(request_obj);

    if ((tlv_size = es10_tlv_generator__retrieve_notifications_list_request(tlv, sizeof(tlv), 0, request_obj)) < 0) {
        LOGE("[es10__retrieve_notifications_list] Error on write the RetrieveNotificationsListRequest TLV, err %d", tlv_size);
        return -ECANCELED;
    }
    LOG_DATA(eLogDebug, "Sending a RetrieveNotificationsListRequest", tlv, tlv_size);

    return es10__store_data(es10, tlv, tlv_size, response, response_size);
}

int es10__remove_notification_from_list(es10_t * const es10, const notification_sent_request_t* request_obj, uint8_t** response, uint32_t* response_size) {
    uint8_t tlv[10]; 
    int32_t tlv_size; 
    es10_display__notification_sent_request(request_obj);

    if ((tlv_size = es10_tlv_generator__notification_sent_request(tlv, sizeof(tlv), 0, request_obj)) < 0) {
        LOGE("[es10__remove_notification_from_list] Error on write the NotificationSentRequest TLV, err %d", tlv_size);
        return -ECANCELED;
    }
    LOG_DATA(eLogDebug, "Sending a NotificationSentRequest", tlv, tlv_size);

    return es10__store_data(es10, tlv, tlv_size, response, response_size);
}

int es10__get_rat(es10_t * const es10, uint8_t** response, uint32_t* response_size) {
    static const uint8_t tlv[] = { (uint8_t) (GET_RAT >> 8), (uint8_t) GET_RAT, 0x00};
    LOGI("ES10.GetRAT");
    LOG_DATA(eLogDebug, "Sending a GetRatRequest", tlv, sizeof(tlv));

    return es10__store_data(es10, tlv, sizeof(tlv), response, response_size);
}

int es10__get_profiles_info(es10_t * const es10, const profile_info_list_request_t* request_obj, uint8_t** response, uint32_t* response_size) {
    uint8_t tlv[45]; 
    int32_t tlv_size; 
    es10_display__profile_info_list_request(request_obj);

    if ((tlv_size = es10_tlv_generator__profile_info_list_request(tlv, sizeof(tlv), 0, request_obj)) < 0) {
        LOGE("[es10__get_profiles_info] Error on write the ProfileInfoListRequest TLV, err %d", tlv_size);
        return -ECANCELED;
    }
    LOG_DATA(eLogDebug, "Sending a ProfileInfoListRequest", tlv, tlv_size);

    return es10__store_data(es10, tlv, tlv_size, response, response_size);
}

int es10__get_eid(es10_t * const es10, uint8_t** response, uint32_t* response_size) {
    static const uint8_t tlv[] = { (uint8_t) (GET_EUICC_DATA >> 8), (uint8_t)GET_EUICC_DATA, 0x03, TAG_LIST, sizeof(EID), EID };
    LOGI("ES10.GetEID");
    LOG_DATA(eLogDebug, "Sending a GetEuiccDataRequest", tlv, sizeof(tlv));

    return es10__store_data(es10, tlv, sizeof(tlv), response, response_size);
}

int es10__set_default_dp_address(es10_t * const es10, const set_default_dp_address_request_t* request_obj, uint8_t** response, uint32_t* response_size) {
    int err;
    uint8_t* tlv;
    int32_t tlv_size;
    es10_display__set_default_dp_address_request(request_obj);

    //Calculate the size of the SetDefaultDpAddressRequest
    if ((tlv_size = es10_tlv_generator__set_default_dp_address_request(NULL, 0, 0, request_obj)) < 0) {
        LOGE("[es10__set_default_dp_address] Error on calculate the size of the SetDefaultDpAddressRequest TLV, err %d", tlv_size);
        return -ECANCELED;
    }
    //Allocate data for the SetDefaultDpAddressRequest
    tlv = (uint8_t*) M_malloc(tlv_size);
    if (!tlv) {
        LOGE("[es10__set_default_dp_address] Can not allocate data for the SetDefaultDpAddressRequest TLV");
        return -ENOMEM;
    }
    //Add the SetDefaultDpAddressRequest to the allocated buffer
    if ((tlv_size = es10_tlv_generator__set_default_dp_address_request(tlv, (uint32_t) tlv_size, 0, request_obj)) < 0) {
        LOGE("[es10__set_default_dp_address] Error on write the size of the SetDefaultDpAddressRequest TLV, err %d", tlv_size);
        M_free(tlv);
        return -ECANCELED;
    }

    LOG_DATA(eLogDebug, "Sending a SetDefaultDpAddressRequest", tlv, (size_t) tlv_size);

    err = es10__store_data(es10, tlv, tlv_size, response, response_size);
    M_free(tlv);

    return err;
}

#ifdef SGP22
int es10__list_notification(es10_t * const es10, const list_notification_request_t* request_obj, uint8_t** response, uint32_t* response_size) {
    uint8_t tlv[7]; 
    int32_t tlv_size;
    es10_display__list_notification_request(request_obj);

    if ((tlv_size = es10_tlv_generator__list_notification_request(tlv, sizeof(tlv), 0, request_obj)) < 0) {
        LOGE("[es10__list_notification] Error on write the ListNotificationRequest TLV, err %d", tlv_size);
        return -ECANCELED;
    }
    LOG_DATA(eLogDebug, "Sending a ListNotificationRequest", tlv, tlv_size);

    return es10__store_data(es10, tlv, tlv_size, response, response_size);
}

int es10__enable_profile(es10_t * const es10, const enable_profile_request_t* request_obj, uint8_t** response, uint32_t* response_size) {
    uint8_t tlv[26]; 
    int32_t tlv_size;
    es10_display__enable_profile_request(request_obj);

    if ((tlv_size = es10_tlv_generator__enable_profile_request(tlv, sizeof(tlv), 0, request_obj)) < 0) {
        LOGE("[es10__enable_profile] Error on write the EnableProfileRequest TLV, err %d", tlv_size);
        return -ECANCELED;
    }
    LOG_DATA(eLogDebug, "Sending a EnableProfileRequest", tlv, tlv_size);

    return es10__store_data(es10, tlv, tlv_size, response, response_size);
}

int es10__disable_profile(es10_t * const es10, const disable_profile_request_t* request_obj, uint8_t** response, uint32_t* response_size) {
    uint8_t tlv[26]; 
    int32_t tlv_size;
    es10_display__disable_profile_request(request_obj);

    if ((tlv_size = es10_tlv_generator__disable_profile_request(tlv, sizeof(tlv), 0, request_obj)) < 0) {
        LOGE("[es10__disable_profile] Error on write the DisableProfileRequest TLV, err %d", tlv_size);
        return -ECANCELED;
    }
    LOG_DATA(eLogDebug, "Sending a DisableProfileRequest", tlv, tlv_size);

    return es10__store_data(es10, tlv, tlv_size, response, response_size);
}

int es10__delete_profile(es10_t * const es10, const delete_profile_request_t* request_obj, uint8_t** response, uint32_t* response_size) {
    uint8_t tlv[21]; 
    int32_t tlv_size;
    es10_display__delete_profile_request(request_obj);

    if ((tlv_size = es10_tlv_generator__delete_profile_request(tlv, sizeof(tlv), 0, request_obj)) < 0) {
        LOGE("[es10__delete_profile] Error on write the DeleteProfileRequest TLV, err %d", tlv_size);
        return -ECANCELED;
    }
    LOG_DATA(eLogDebug, "Sending a DeleteProfileRequest", tlv, tlv_size);

    return es10__store_data(es10, tlv, tlv_size, response, response_size);
}

int es10__set_nickname(es10_t * const es10, const set_nickname_request_t* request_obj, uint8_t** response, uint32_t* response_size) {
    uint8_t tlv[81]; 
    int32_t tlv_size;
    es10_display__set_nickname_request(request_obj);

    if ((tlv_size = es10_tlv_generator__set_nickname_request(tlv, sizeof(tlv), 0, request_obj)) < 0) {
        LOGE("[es10__set_nickname] Error on write the SetNicknameRequest TLV, err %d", tlv_size);
        return -ECANCELED;
    }
    LOG_DATA(eLogDebug, "Sending a SetNicknameRequest", tlv, tlv_size);

    return es10__store_data(es10, tlv, tlv_size, response, response_size);   
}
#endif
#ifdef SGP32
int es10__load_euicc_package(es10_t * const es10, const uint8_t* request, const uint32_t request_size, uint8_t** response, uint32_t* response_size) {
    LOGI("ES10.LoadEuiccPackage");
    LOG_DATA(eLogDebug, "Sending a EuiccPackageRequest", request, request_size);
    
    return es10__store_data(es10, request, request_size, response, response_size);
}

int es10__add_initial_eim(es10_t * const es10, const eim_configuration_data_t* request_obj, uint8_t** response, uint32_t* response_size) {
    int err;
    uint8_t* tlv;
    int32_t tlv_size;
    es10_display__add_initial_eim_request(request_obj);

    if (!request_obj->eim_id || request_obj->eim_id_len == 0) {
        LOGE("[es10__add_initial_eim] The eimId is empty/null. This is a required field for the AddInitialEim function.");
        return -EINVAL;
    }

    if (!request_obj->field_is_present.counter_value) {
        LOGE("[es10__add_initial_eim] The counterValue is missing. This is a required field for the AddInitialEim function.");
        return -EINVAL;
    }

    if (!request_obj->field_is_present.eim_public_key_data || !request_obj->eim_public_key_data.value || request_obj->eim_public_key_data.value_size == 0) {
        LOGE("[es10__add_initial_eim] The eimPublicKeyData is missing. This is a required field for the AddInitialEim function.");
        return -EINVAL;
    }

    if ((tlv_size = es10_tlv_generator__add_initial_eim_request(NULL, 0, 0, request_obj)) < 0) {
        LOGE("[es10__add_initial_eim] Error on calculate the size of AddInitialEimRequest TLV, err %d", tlv_size);
        return -ECANCELED;
    }

    tlv = M_malloc((uint32_t) tlv_size);
    if (!tlv) {
        LOGE("[es10__add_initial_eim] Can not allocate data for the AddInitialEimRequest TLV");
        return -ENOMEM;
    }

    if ((tlv_size = es10_tlv_generator__add_initial_eim_request(tlv, (uint32_t) tlv_size, 0, request_obj)) < 0) {
        LOGE("[es10__add_initial_eim] Error on write the AddInitialEimRequest TLV, err %d", tlv_size);
        M_free(tlv);
        return -ECANCELED;
    }

    LOG_DATA(eLogDebug, "Sending a AddInitialEimRequest", tlv, (uint32_t) tlv_size);

    err = es10__store_data(es10, tlv, (uint32_t) tlv_size, response, response_size);
    M_free(tlv);
    return err;
}

int es10__get_certs(es10_t * const es10, const get_certs_request_t* request_obj, uint8_t** response, uint32_t* response_size) {
    uint8_t tlv[25];
    int32_t tlv_size;
    es10_display__get_certs_request(request_obj);

    if ((tlv_size = es10_tlv_generator__get_certs_request(tlv, sizeof(tlv), 0, request_obj)) < 0) {
        LOGE("[es10__get_certs] Error on write the GetCertsRequest TLV, err %d", tlv_size);
        return -ECANCELED;
    }

    LOG_DATA(eLogDebug, "Sending a GetCertsRequest", tlv, tlv_size);

    return es10__store_data(es10, tlv, tlv_size, response, response_size);
}

int es10__immediate_enable(es10_t * const es10, const immediate_enable_request_t* request_obj, uint8_t** response, uint32_t* response_size) {
    uint8_t tlv[6];
    int32_t tlv_size;
    es10_display__immediate_enable_request(request_obj);

    if ((tlv_size = es10_tlv_generator__immediate_enable_request(tlv, sizeof(tlv), 0, request_obj)) < 0) {
        LOGE("[es10__immediate_enable] Error on write the ImmediateEnableRequest TLV, err %d", tlv_size);
        return -ECANCELED;
    }

    LOG_DATA(eLogDebug, "Sending a ImmediateEnableRequest", tlv, tlv_size);

    return es10__store_data(es10, tlv, tlv_size, response, response_size);
}

int es10__profile_rollback(es10_t * const es10, const profile_rollback_request_t* request_obj, uint8_t** response, uint32_t* response_size) {
    uint8_t tlv[6];
    int32_t tlv_size;
    es10_display__profile_rollback_request(request_obj);

    if ((tlv_size = es10_tlv_generator__profile_rollback_request(tlv, sizeof(tlv), 0, request_obj)) < 0) {
        LOGE("[es10__profile_rollback] Error on write the ProfileRollbackRequest TLV, err %d", tlv_size);
        return -ECANCELED;
    }

    LOG_DATA(eLogDebug, "Sending a ProfileRollbackRequest", tlv, tlv_size);

    return es10__store_data(es10, tlv, tlv_size, response, response_size);
}

int es10__configure_immediate_profile_enabling(es10_t * const es10, const configure_immediate_profile_enabling_request_t* request_obj, uint8_t** response, uint32_t* response_size) {
    int err;
    uint8_t* tlv;
    int32_t tlv_size;
    es10_display__configure_immediate_profile_enabling_request(request_obj);

    if ((tlv_size = es10_tlv_generator__configure_immediate_profile_enabling_request(NULL, 0, 0, request_obj)) < 0) {
        LOGE("[es10__configure_immediate_profile_enabling] Error on calculate the size of ConfigureAutoProfileEnablingRequest TLV, err %d", tlv_size);
        return -ECANCELED;
    }

    tlv = M_malloc((uint32_t) tlv_size);
    if (!tlv) {
        LOGE("[es10__configure_immediate_profile_enabling] Can not allocate data for the ConfigureAutoProfileEnablingRequest TLV");
        return -ENOMEM;
    }

    if ((tlv_size = es10_tlv_generator__configure_immediate_profile_enabling_request(tlv, (uint32_t) tlv_size, 0, request_obj)) < 0) {
        LOGE("[es10__configure_immediate_profile_enabling] Error on write the ConfigureAutoProfileEnablingRequest TLV, err %d", tlv_size);
        M_free(tlv);
        return -ECANCELED;
    }

    LOG_DATA(eLogDebug, "Sending a ConfigureImmediateProfileEnablingRequest", tlv, (uint32_t) tlv_size);

    err = es10__store_data(es10, tlv, (uint32_t) tlv_size, response, response_size);
    M_free(tlv);
    return err;
}

int es10__get_eim_configuration_data(es10_t * const es10, const get_eim_configuration_data_request_t* request_obj, uint8_t** response, uint32_t* response_size) {
    int err;
    uint8_t* tlv;
    int32_t tlv_size;
    es10_display__get_eim_configuration_data_request(request_obj);

    if ((tlv_size = es10_tlv_generator__get_eim_configuration_data_request(NULL, 0, 0, request_obj)) < 0) {
        LOGE("[es10__get_eim_configuration_data] Error on calculate the size of GetEimConfigurationDataRequest TLV, err %d", tlv_size);
        return -ECANCELED;
    }

    tlv = M_malloc((uint32_t) tlv_size);
    if (!tlv) {
        LOGE("[es10__get_eim_configuration_data] Can not allocate data for the GetEimConfigurationDataRequest TLV");
        return -ENOMEM;
    }

    if ((tlv_size = es10_tlv_generator__get_eim_configuration_data_request(tlv, (uint32_t) tlv_size, 0, request_obj)) < 0) {
        LOGE("[es10__get_eim_configuration_data] Error on write the GetEimConfigurationDataRequest TLV, err %d", tlv_size);
        M_free(tlv);
        return -ECANCELED;
    }

    LOG_DATA(eLogDebug, "Sending a GetEimConfigurationDataRequest", tlv, (uint32_t) tlv_size);

    err = es10__store_data(es10, tlv, tlv_size, response, response_size);
    M_free(tlv);
    return err;
}

#ifdef EXTRA_FEATURE_EMERGENCY_PROFILE_MANAGMENT
int es10__enable_emergency_profile(es10_t* const es10, const enable_emergency_profile_request_t* request_obj, uint8_t** response, uint32_t* response_size) {
    uint8_t tlv[6];
    int32_t tlv_size;
    es10_display__enable_emergency_profile_request(request_obj);

    if ((tlv_size = es10_tlv_generator__enable_emergency_profile_request(tlv, sizeof(tlv), 0, request_obj)) < 0) {
        LOGE("[es10__enable_emergency_profile] Error on write the EnableEmergencyProfile TLV, err %d", tlv_size);
        return -ECANCELED;
    }

    LOG_DATA(eLogDebug, "Sending a EnableEmergencyProfile", tlv, tlv_size);

    return es10__store_data(es10, tlv, tlv_size, response, response_size);
}

int es10__disable_emergency_profile(es10_t* const es10, const disable_emergency_profile_request_t* request_obj, uint8_t** response, uint32_t* response_size) {
    uint8_t tlv[6];
    int32_t tlv_size;
    es10_display__disable_emergency_profile_request(request_obj);

    if ((tlv_size = es10_tlv_generator__disable_emergency_profile_request(tlv, sizeof(tlv), 0, request_obj)) < 0) {
        LOGE("[es10__disable_emergency_profile] Error on write the DisableEmergencyProfile TLV, err %d", tlv_size);
        return -ECANCELED;
    }

    LOG_DATA(eLogDebug, "Sending a DisableEmergencyProfile", tlv, tlv_size);

    return es10__store_data(es10, tlv, tlv_size, response, response_size);
}
#endif

#ifdef EXTRA_FEATURE_FALLBACK_MECHANISM
int es10__execute_fallback_mechanism(es10_t * const es10, const execute_fallback_mechanism_request_t* request_obj, uint8_t** response, uint32_t* response_size) {
    uint8_t tlv[6];
    int32_t tlv_size;
    es10_display__execute_fallback_mechanism_request(request_obj);

    if ((tlv_size = es10_tlv_generator__execute_fallback_mechanism_request(tlv, sizeof(tlv), 0, request_obj)) < 0) {
        LOGE("[es10__execute_fallback_mechanism] Error on write the ExecuteFallbackMechanismRequest TLV, err %d", tlv_size);
        return -ECANCELED;
    }

    LOG_DATA(eLogDebug, "Sending a ExecuteFallbackMechanismRequest", tlv, tlv_size);

    return es10__store_data(es10, tlv, tlv_size, response, response_size);
}

int es10__return_from_fallback(es10_t * const es10, const return_from_fallback_request_t* request_obj, uint8_t** response, uint32_t* response_size) {
    uint8_t tlv[6];
    int32_t tlv_size;
    es10_display__return_from_fallback_request(request_obj);

    if ((tlv_size = es10_tlv_generator__return_from_fallback_request(tlv, sizeof(tlv), 0, request_obj)) < 0) {
        LOGE("[es10__return_from_fallback] Error on write the ReturnFromFallbackRequest TLV, err %d", tlv_size);
        return -ECANCELED;
    }

    LOG_DATA(eLogDebug, "Sending a ReturnFromFallbackRequest", tlv, tlv_size);

    return es10__store_data(es10, tlv, tlv_size, response, response_size);
}
#endif
#endif

static int es10__smartcard_additional_init_steps(void* const context) {
    int err;
    es10_t* const es10 = (es10_t*) context;

    LOGD("[es10__smartcard_additional_init_steps] Opening a Logical Channel");
    if ((err = smartcard__open_channel(es10->smart_card)) < 0) {
        LOGE("[es10__smartcard_additional_init_steps] Error opening the channel, err %d", err);
        return err;
    }

#ifndef SKIP_TERMINAL_CAPABILITY
    LOGD("[es10__smartcard_additional_init_steps] Sending the Terminal Capabilities");
    if ((err = es10__terminal_capability(es10)) < 0) {
        LOGE("[es10__smartcard_additional_init_steps] Error executing the terminal capability function, err %d", err);
        goto additional_init_steps_close_channel_on_error;
    }
#endif

    LOGD("[es10__smartcard_additional_init_steps] Selecting the ISD-R");
    if ((err = es10__select_isdr_application(es10)) < 0) {
        LOGE("[es10__smartcard_additional_init_steps] Error selecting the ISDR application function, err %d", err);
        goto additional_init_steps_close_channel_on_error;
    }

    return 0;

additional_init_steps_close_channel_on_error:
    if ((err = smartcard__close_channel(es10->smart_card)) < 0) {
        LOGE("[es10__smartcard_additional_init_steps] Error closing the opened channel, err %d", err);
        return err;
    }
    return -ECANCELED;
}

static int es10__init_rec(es10_t * const es10, uint32_t sleep) {
    int err; 
    LOGT("[es10__init_rec] es10 initialize call");

    if (!es10) {
        LOGE("[es10__init_rec] The ES10 object is null");
        return -EINVAL;
    }

    if (sleep > es10->max_refresh_sleep) {
        // End of recursion
        LOGE("[es10__init_rec] Max attempts on ES10 initilization reached");
        return -ECANCELED;
    }

    LOGD("[es10__init_rec] Initializing the Smartcard");
    if ((err = smartcard__init(es10->smart_card)) < 0) {
        LOGE("[es10__init_rec] Error initializing the ES10 instance, err %d", err);
        if (0 == sleep) {
            LOGE("[es10__init_rec] No sleep configured to retry the ES10 initialization on faiure");
            return -ECANCELED;
        } else {
            LOGI("Sleeping %us before retry the ES10 initialization", sleep);
            timer__sleep(sleep);
            return es10__init_rec(es10, sleep * 2);
        }
    }

    return 0; 
}

static int es10__select_isdr_application(es10_t * const es10) {
    response_apdu_t response_apdu;
    int err;

    if (!es10) {
        LOGE("[es10__select_isdr_application] The ES10 object is null");
        return -EINVAL;
    }

    if ((err = smartcard__send_select(es10->smart_card, isdr_aid, sizeof(isdr_aid), &response_apdu)) < 0) {
        LOGE("[es10__select_isdr_application] Error executing Send Select, err %d", err);
        return err;
    }

    while (apdu_utils__sw_data_available(&response_apdu.sw)) {
        if ((err = smartcard__send_get_response(es10->smart_card, response_apdu.sw.sw2, &response_apdu)) < 0) {
            LOGE("[es10__select_isdr_application] Error executing Send Get Data, err %d", err);
            return err;
        }
    }

    if (!apdu_utils__sw_is_success(&response_apdu.sw)) {
        LOGE("[es10__select_isdr_application] Wrong Select ISDR Application SW %02X%02X", response_apdu.sw.sw1, response_apdu.sw.sw2);
        return -ECANCELED;
    }

    return 0;
}

#ifndef SKIP_TERMINAL_CAPABILITY
static int es10__terminal_capability(es10_t * const es10) {
    sw_t sw;
    int err;

    if (!es10) {
        LOGE("[es10__terminal_capability] The ES10 object is null");
        return -EINVAL;
    }

    if ((err = smartcard__send_apdu_sw_response(es10->smart_card, &terminal_capability_apdu, &sw)) < 0) {
        LOGE("[es10__terminal_capability] Error sending Terminal Capability APDU, err %d", err);
        return err;
    }

    if (!apdu_utils__sw_is_success(&sw)) {
        LOGE("[es10__terminal_capability] Wrong Terminal Capability SW %02X%02X", sw.sw1, sw.sw2);
        return -ECANCELED;
    }

    return 0;
}
#endif

static int es10__store_data(es10_t * const es10, const uint8_t* tlv_bytes, const uint32_t tlv_bytes_size, uint8_t** response, uint32_t* response_size) {
    if (!es10) {
        LOGE("[es10__store_data] The ES10 object is null");
        return -EINVAL;
    }
#ifdef DEBUG_ES10
    LOG_DATA(eLogInfo, "ES10 >>", tlv_bytes, tlv_bytes_size);
#endif

    return es10__store_data_rec(es10, tlv_bytes, tlv_bytes_size, 1, response, response_size);
}

static int es10__store_data_rec(es10_t * const es10, const uint8_t* tlv_bytes, const uint32_t tlv_bytes_size, uint8_t attempt, uint8_t** response, uint32_t* response_size) {
    response_apdu_t response_apdu;
    int err;
    *response = NULL;
    *response_size = 0;

    if (attempt > STORE_DATA_MAX_ATTEMPTS) {
        // End of recursion
        LOGE("[es10__store_data_rec] Max attempts on store data reached");
        return -ECANCELED;
    }

    if (!es10 || tlv_bytes == NULL || tlv_bytes_size == 0) {
        return -EINVAL;
    }

    if ((err = smartcard__store_data(es10->smart_card, tlv_bytes, tlv_bytes_size, true, &response_apdu)) < 0) {
        LOGD("[es10__store_data_rec] Error executing Store Data, err %d. reinitializing the UICC to retry the store data", err);
        if ((err = es10__init(es10)) < 0) {
            LOGE("[es10__store_data_rec] Error reinitializing the ES10 instance, err %d", err);
            return err;
        }
        LOGD("[es10__store_data_rec] Trying to restore the data on attempt %u", attempt);
        return es10__store_data_rec(es10, tlv_bytes, tlv_bytes_size, attempt + 1, response, response_size);
    }

    if (apdu_utils__sw_is_success(&response_apdu.sw)) {
        if ((err = es10__append_response_data(response, response_size, response_apdu.response_data, response_apdu.response_data_size)) < 0) {
            LOGE("[es10__store_data_rec] Error appending the Response Data, err %d", err);
            return err;
        }
    } else {
        while (apdu_utils__sw_data_available(&response_apdu.sw)) {
            if ((err = smartcard__send_get_response(es10->smart_card, response_apdu.sw.sw2, &response_apdu)) < 0) {
                LOGE("[es10__store_data_rec] Error executing Send Get Data, err %d", err);
                goto store_data_rec_clean_up_and_return_err;
            }
            if ((err = es10__append_response_data(response, response_size, response_apdu.response_data, response_apdu.response_data_size)) < 0) {
                LOGE("[es10__store_data_rec] Error appending the Response Data, err %d", err);
                goto store_data_rec_clean_up_and_return_err;
            }
        }
    }

    if (apdu_utils__sw_is_success(&response_apdu.sw)) {
#ifdef DEBUG_ES10
    LOG_DATA(eLogInfo, "ES10 <<", *response, *response_size);
#endif
        return 0;
    } else if (apdu_utils__sw_conditions_not_satisfied(&response_apdu.sw) || apdu_utils__sw_logical_channel_not_supported(&response_apdu.sw)) { // The logical channel not supported error has been seen in some refresh error cases
        M_free(*response);
        *response = NULL;
        *response_size = 0;
        LOGD("[es10__store_data_rec] The store data has returned SW 0x%02X%02X. Trying to reinitialize the ES10.", response_apdu.sw.sw1, response_apdu.sw.sw2);
        if ((err = es10__init(es10)) < 0) {
            LOGE("[es10__store_data_rec] Error reinitializing the ES10 instance, err %d", err);
            return err;
        }
        LOGD("[es10__store_data_rec] Trying to restore the data on attempt %u", attempt);
        return es10__store_data_rec(es10, tlv_bytes, tlv_bytes_size, attempt + 1, response, response_size);
    } else {
        LOGE("[es10__store_data_rec] Error executing Store Data SW %02X%02X", response_apdu.sw.sw1, response_apdu.sw.sw2);
        err = -ECANCELED;
        goto store_data_rec_clean_up_and_return_err;
    }

    return 0;

store_data_rec_clean_up_and_return_err:
    M_free(*response);
    *response = NULL;
    *response_size = 0;
    return err;
}

static int es10__append_response_data(uint8_t** buffer, uint32_t* buffer_size, const uint8_t* response_data, const uint16_t response_data_size) {
    uint8_t* ptr;

    if (!response_data || response_data_size == 0) {
        LOGD("[es10__append_response_data] Nothing to append");
        return 0;
    }

    LOG_DATA(eLogTrace, "[es10__append_response_data] Input buffer", *buffer, *buffer_size);
    LOG_DATA(eLogTrace, "[es10__append_response_data] Response to append", response_data, response_data_size);

    ptr = M_realloc(*buffer, *buffer_size + (uint32_t) response_data_size);
    if (ptr == NULL) {
        /* out of memory! */
        LOGE("[es10__append_response_data] Error reallocating memory");
        M_free(*buffer);
        *buffer = NULL;
        *buffer_size = 0;
        return -ENOMEM;
    }
    *buffer = ptr;
    memcpy(*buffer + *buffer_size, response_data, response_data_size);
    (*buffer_size) += response_data_size;

    LOG_DATA(eLogTrace, "[es10__append_response_data] Output buffer", *buffer, *buffer_size);

    return 0;
}
