/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include "ipa_tlv_generator.h"
#include "tlv_generator.h"
#include "tlv_tags.h"
#include "byte_utils.h"
#include "log.h"

static int32_t ipa_tlv_generator__ipa_capabilities_value(uint8_t* buffer, const uint32_t buffer_size, uint32_t const offset, const ipa_capabilities_t* ipa_capabilities);
static int32_t ipa_tlv_generator__ipa_features(uint8_t* buffer, const uint32_t buffer_size, uint32_t const offset, const ipa_features_t* ipa_features);
static int32_t ipa_tlv_generator__ipa_supported_protocols(uint8_t* buffer, const uint32_t buffer_size, uint32_t const offset, const ipa_supported_protocols_t* ipa_supported_protocols);

int32_t ipa_tlv_generator__ipa_capabilities(uint8_t* buffer, const uint32_t buffer_size, uint32_t const offset, unsigned short tag, const ipa_capabilities_t* ipa_capabilities) {
    int32_t buffer_offset;

    // IpaCapabilities VALUE
    if ((buffer_offset = ipa_tlv_generator__ipa_capabilities_value(buffer, buffer_size, offset, ipa_capabilities)) < 0) {
        LOGE("[ipa_tlv_generator__ipa_capabilities] Error on IpaCapabilities VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[ipa_tlv_generator__ipa_capabilities] IpaCapabilities VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap IpaCapabilities VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, tag)) < 0) {
        LOGE("[ipa_tlv_generator__ipa_capabilities] Error on wrapping the IpaCapabilities VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[ipa_tlv_generator__ipa_capabilities] IpaCapabilities TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

static int32_t ipa_tlv_generator__ipa_capabilities_value(uint8_t* buffer, const uint32_t buffer_size, uint32_t const offset, const ipa_capabilities_t* ipa_capabilities) {
    int32_t buffer_offset;

    // ipaFeatures TLV
    if ((buffer_offset = ipa_tlv_generator__ipa_features(buffer, buffer_size, offset, &ipa_capabilities->ipa_features)) < 0) {
        LOGE("[ipa_tlv_generator__ipa_capabilities_value] Error on ipaFeatures TLV, err %d", buffer_offset);
        return buffer_offset;
    }

    // ipaSupportedProtocols TLV
    if (ipa_capabilities->field_is_present.ipa_supported_protocols) {
        if ((buffer_offset = ipa_tlv_generator__ipa_supported_protocols(buffer, buffer_size, (uint32_t) buffer_offset, &ipa_capabilities->ipa_supported_protocols)) < 0) {
            LOGE("[ipa_tlv_generator__ipa_capabilities_value] Error on ipaSupportedProtocols TLV, err %d", buffer_offset);
            return buffer_offset;
        }
    }

    return buffer_offset;
}

static int32_t ipa_tlv_generator__ipa_features(uint8_t* buffer, const uint32_t buffer_size, uint32_t const offset, const ipa_features_t* ipa_features) {
    uint8_t ipa_features_bit_string[6] =  { 
        ipa_features->direct_rsp_server_communication,
        ipa_features->indirect_rsp_server_communication,
        ipa_features->eim_download_data_handling,
        ipa_features->eim_ctx_params_1_generation,
        ipa_features->eim_profile_metadata_verification,
        ipa_features->minimize_esipa_bytes,
    };

    return tlv_generator__add_tlv_bit_string_value(buffer, buffer_size, offset, CONTEXT_PRIMITIVE_0, ipa_features_bit_string, sizeof(ipa_features_bit_string));
}

static int32_t ipa_tlv_generator__ipa_supported_protocols(uint8_t* buffer, const uint32_t buffer_size, uint32_t const offset, const ipa_supported_protocols_t* ipa_supported_protocols) {
    uint8_t ipa_suported_protocols_bit_string[5] =  {
        ipa_supported_protocols->ipa_retrieve_https,
        ipa_supported_protocols->ipa_retrieve_coaps,
        ipa_supported_protocols->ipa_inject_https,
        ipa_supported_protocols->ipa_inject_coaps,
        ipa_supported_protocols->ipa_proprietary,
    };

    return tlv_generator__add_tlv_bit_string_value(buffer, buffer_size, offset, CONTEXT_PRIMITIVE_1, ipa_suported_protocols_bit_string, sizeof(ipa_suported_protocols_bit_string));
}
