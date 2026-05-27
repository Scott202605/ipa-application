/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include "device_info.h"
#include <errno.h>

#include "tlv_generator.h"
#include "tlv_tags.h"
#include "log.h"

#define TAC_DEFAULT_VALUE { 0, 0, 0, 0 }

typedef struct device_capabilities_data_presence_s {
    bool gsm_supported_release;
    bool utran_supported_release;
    bool cdma_2000_onex_supported_release;
    bool cdma_2000_hrpd_supported_release;
    bool cdma_2000_ehrpd_supported_release;
    bool eutran_epc_supported_release;
    bool contactless_supported_release;
    bool rsp_crl_supported_version;
    bool nr_epc_supported_release;
    bool nr_5gc_supported_release;
    bool eutran_5gc_supported_release;
} device_capabilities_data_presence_t;

typedef struct device_capabilities_s {
    version_type_t gsm_supported_release;
    version_type_t utran_supported_release;
    version_type_t cdma_2000_onex_supported_release;
    version_type_t cdma_2000_hrpd_supported_release;
    version_type_t cdma_2000_ehrpd_supported_release;
    version_type_t eutran_epc_supported_release;
    version_type_t contactless_supported_release;
    version_type_t rsp_crl_supported_version;
    version_type_t nr_epc_supported_release;
    version_type_t nr_5gc_supported_release;
    version_type_t eutran_5gc_supported_release;
    device_capabilities_data_presence_t field_is_present;
} device_capabilities_t;

typedef struct device_info_data_presence_s {
    bool imei;
} device_info_data_presence_t;

struct device_info_s {
    tac_t tac;
    device_capabilities_t device_capabilities;
    imei_t imei;
    device_info_data_presence_t field_is_present;
};

/** Singleton instance */
static device_info_t g_device_info = {
    .tac = {
        .value = TAC_DEFAULT_VALUE
    },
    .device_capabilities = {
        .field_is_present = {
            .gsm_supported_release = false,
            .utran_supported_release = false,
            .cdma_2000_onex_supported_release = false,
            .cdma_2000_hrpd_supported_release = false,
            .cdma_2000_ehrpd_supported_release = false,
            .eutran_epc_supported_release = false,
            .contactless_supported_release = false,
            .rsp_crl_supported_version = false,
            .nr_epc_supported_release = false,
            .nr_5gc_supported_release = false,
            .eutran_5gc_supported_release = false
        }
    },
    .field_is_present = {
        .imei = false
    }
};

static int32_t device_info__tlv_generator_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, bool extensibility_support, const device_info_t* obj);
static int32_t device_info__tlv_generator_device_capabilities(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, bool extensibility_support, const unsigned short tag, const device_capabilities_t* obj);
static int32_t device_info__tlv_generator_device_capabilities_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, bool extensibility_support, const device_capabilities_t* obj);

device_info_t* device_info__get_instance() {
    return &g_device_info;
}

int device_info__set_tac(const tac_t* tac) {
    if (!tac) {
        LOGE("[device_info__set_tac] TAC is null");
        return -EINVAL;
    }

    memcpy(&g_device_info.tac, tac, sizeof(tac_t));

    return 0;
}

void device_info__set_imei(const imei_t* imei) {
    if (imei) {
        memcpy(&g_device_info.imei, imei, sizeof(imei_t));
        g_device_info.field_is_present.imei = true;
    } else {
        memset(&g_device_info.imei, 0, sizeof(imei_t));
        g_device_info.field_is_present.imei = false;
    }
}

void device_info__set_gsm_supported_release(const uint8_t version) {
    g_device_info.device_capabilities.gsm_supported_release.major = version;
    g_device_info.device_capabilities.gsm_supported_release.minor = 0;
    g_device_info.device_capabilities.gsm_supported_release.revision = 0;
    g_device_info.device_capabilities.field_is_present.gsm_supported_release = true;
}

void device_info__set_utran_supported_release(const uint8_t version) {
    g_device_info.device_capabilities.utran_supported_release.major = version;
    g_device_info.device_capabilities.utran_supported_release.minor = 0;
    g_device_info.device_capabilities.utran_supported_release.revision = 0;
    g_device_info.device_capabilities.field_is_present.utran_supported_release = true;
}

void device_info__set_cdma_2000_onex_supported_release() {
    g_device_info.device_capabilities.cdma_2000_onex_supported_release.major = 1;
    g_device_info.device_capabilities.cdma_2000_onex_supported_release.minor = 0;
    g_device_info.device_capabilities.cdma_2000_onex_supported_release.revision = 0;
    g_device_info.device_capabilities.field_is_present.cdma_2000_onex_supported_release = true;

}

void device_info__set_cdma_2000_hrpd_supported_release(const evdo_revision_t revision) {
    g_device_info.device_capabilities.cdma_2000_hrpd_supported_release.major = (uint8_t) revision;
    g_device_info.device_capabilities.cdma_2000_hrpd_supported_release.minor = 0;
    g_device_info.device_capabilities.cdma_2000_hrpd_supported_release.revision = 0;
    g_device_info.device_capabilities.field_is_present.cdma_2000_hrpd_supported_release = true;
}

void device_info__set_cdma_2000_ehrpd_supported_release(const uint8_t version) {
    g_device_info.device_capabilities.cdma_2000_ehrpd_supported_release.major = version;
    g_device_info.device_capabilities.cdma_2000_ehrpd_supported_release.minor = 0;
    g_device_info.device_capabilities.cdma_2000_ehrpd_supported_release.revision = 0;
    g_device_info.device_capabilities.field_is_present.cdma_2000_ehrpd_supported_release = true;
}

void device_info__set_eutran_epc_supported_release(const uint8_t version) {
    g_device_info.device_capabilities.eutran_epc_supported_release.major = version;
    g_device_info.device_capabilities.eutran_epc_supported_release.minor = 0;
    g_device_info.device_capabilities.eutran_epc_supported_release.revision = 0;
    g_device_info.device_capabilities.field_is_present.eutran_epc_supported_release = true;
}

void device_info__set_contactless_supported_release(const uint8_t version, const uint8_t revision) {
    g_device_info.device_capabilities.contactless_supported_release.major = version;
    g_device_info.device_capabilities.contactless_supported_release.minor = revision;
    g_device_info.device_capabilities.contactless_supported_release.revision = 0;
    g_device_info.device_capabilities.field_is_present.contactless_supported_release = true;
}

void device_info__set_rsp_crl_supported_version(const version_type_t* version) {
    if (version) {
        memcpy(&g_device_info.device_capabilities.rsp_crl_supported_version, version, sizeof(version_type_t));
        g_device_info.device_capabilities.field_is_present.rsp_crl_supported_version = true;
    } else {
        memset(&g_device_info.device_capabilities.rsp_crl_supported_version, 0, sizeof(version_type_t));
        g_device_info.device_capabilities.field_is_present.rsp_crl_supported_version = false;
    }
}

void device_info__set_nr_epc_supported_release(const uint8_t version) {
    g_device_info.device_capabilities.nr_epc_supported_release.major = version;
    g_device_info.device_capabilities.nr_epc_supported_release.minor = 0;
    g_device_info.device_capabilities.nr_epc_supported_release.revision = 0;
    g_device_info.device_capabilities.field_is_present.nr_epc_supported_release = true;
}

void device_info__set_nr_5gc_supported_release(const uint8_t version) {
    g_device_info.device_capabilities.nr_5gc_supported_release.major = version;
    g_device_info.device_capabilities.nr_5gc_supported_release.minor = 0;
    g_device_info.device_capabilities.nr_5gc_supported_release.revision = 0;
    g_device_info.device_capabilities.field_is_present.nr_5gc_supported_release = true;
}

void device_info__set_eutran_5gc_supported_release(const uint8_t version) {
    g_device_info.device_capabilities.eutran_5gc_supported_release.major = version;
    g_device_info.device_capabilities.eutran_5gc_supported_release.minor = 0;
    g_device_info.device_capabilities.eutran_5gc_supported_release.revision = 0;
    g_device_info.device_capabilities.field_is_present.eutran_5gc_supported_release = true;
}

int32_t device_info__tlv_generator(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, bool extensibility_support, const unsigned short tag, const device_info_t* obj) {
    int32_t buffer_offset;

    // DeviceInfo VALUE
    if ((buffer_offset = device_info__tlv_generator_value(buffer, buffer_size, offset, extensibility_support, obj)) < 0) {
        LOGE("[device_info__tlv_generator] Error on DeviceInfo VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[device_info__tlv_generator] DeviceInfo VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap DeviceInfo VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, tag)) < 0) {
        LOGE("[device_info__tlv_generator] Error on wrapping the DeviceInfo VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[device_info__tlv_generator] DeviceInfo TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

static int32_t device_info__tlv_generator_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, bool extensibility_support, const device_info_t* obj) {
    int32_t buffer_offset = (int32_t) offset;

    // tac
    if ((buffer_offset = tlv_generator__add_tlv(buffer, buffer_size, (uint32_t) buffer_offset, CONTEXT_PRIMITIVE_0, obj->tac.value, sizeof(obj->tac.value))) < 0) {
        LOGE("[device_info__tlv_generator_value] Error on tac TLV, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[device_info__tlv_generator_value] DeviceInfo VALUE size after tac: %u", (uint32_t) buffer_offset - offset);

    // deviceCapabilities
    if ((buffer_offset = device_info__tlv_generator_device_capabilities(buffer, buffer_size, (uint32_t) buffer_offset, extensibility_support, CONTEXT_CONSTRUCTED_1, &obj->device_capabilities)) < 0) {
        LOGE("[device_info__tlv_generator_value] Error on deviceCapabilities TLV, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[device_info__tlv_generator_value] DeviceInfo VALUE size after deviceCapabilities: %u", (uint32_t) buffer_offset - offset);

    // imei OPTIONAL
    if (obj->field_is_present.imei) {
        if ((buffer_offset = tlv_generator__add_tlv(buffer, buffer_size, (uint32_t) buffer_offset, CONTEXT_PRIMITIVE_2, obj->imei.value, sizeof(obj->imei.value))) < 0) {
            LOGE("[device_info__tlv_generator_value] Error on imei TLV, err %d", buffer_offset);
            return buffer_offset;
        }
        LOGT("[device_info__tlv_generator_value] DeviceInfo VALUE size after imei: %u", (uint32_t) buffer_offset - offset);
    }

    return buffer_offset;
}

static int32_t device_info__tlv_generator_device_capabilities(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, bool extensibility_support, const unsigned short tag, const device_capabilities_t* obj) {
    int32_t buffer_offset;

    // DeviceCapabilities VALUE
    if ((buffer_offset = device_info__tlv_generator_device_capabilities_value(buffer, buffer_size, offset, extensibility_support, obj)) < 0) {
        LOGE("[device_info__tlv_generator_device_capabilities] Error on DeviceCapabilities VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[device_info__tlv_generator_device_capabilities] DeviceCapabilities VALUE size: %u", (uint32_t) buffer_offset - offset);

    // Wrap DeviceCapabilities VALUE
    if ((buffer_offset = tlv_generator__add_wrap_tlv(buffer, buffer_size, offset, (uint32_t) buffer_offset, tag)) < 0) {
        LOGE("[device_info__tlv_generator_device_capabilities] Error on wrapping the DeviceCapabilities VALUE, err %d", buffer_offset);
        return buffer_offset;
    }
    LOGT("[device_info__tlv_generator_device_capabilities] DeviceCapabilities TLV size: %u", (uint32_t) buffer_offset - offset);

    return buffer_offset;
}

static int32_t device_info__tlv_generator_device_capabilities_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, bool extensibility_support, const device_capabilities_t* obj) {
    int32_t buffer_offset = (int32_t) offset;

    // gsmSupportedRelease
    if (obj->field_is_present.gsm_supported_release) {
        if ((buffer_offset = tlv_generator__add_tlv_version_type_value(buffer, buffer_size, (uint32_t) buffer_offset, CONTEXT_PRIMITIVE_0, &obj->gsm_supported_release)) < 0) {
            LOGE("[device_info__tlv_generator_device_capabilities_value] Error on gsmSupportedRelease TLV, err %d", buffer_offset);
            return buffer_offset;
        }
        LOGT("[device_info__tlv_generator_device_capabilities_value] DeviceCapabilities VALUE size after gsmSupportedRelease: %u", buffer_offset - offset);
    }

    // utranSupportedRelease
    if (obj->field_is_present.utran_supported_release) {
        if ((buffer_offset = tlv_generator__add_tlv_version_type_value(buffer, buffer_size, (uint32_t) buffer_offset, CONTEXT_PRIMITIVE_1, &obj->utran_supported_release)) < 0) {
            LOGE("[device_info__tlv_generator_device_capabilities_value] Error on utranSupportedRelease TLV, err %d", buffer_offset);
            return buffer_offset;
        }
        LOGT("[device_info__tlv_generator_device_capabilities_value] DeviceCapabilities VALUE size after utranSupportedRelease: %u", buffer_offset - offset);
    }

    // cdma2000onexSupportedRelease
    if (obj->field_is_present.cdma_2000_onex_supported_release) {
        if ((buffer_offset = tlv_generator__add_tlv_version_type_value(buffer, buffer_size, (uint32_t) buffer_offset, CONTEXT_PRIMITIVE_2, &obj->cdma_2000_onex_supported_release)) < 0) {
            LOGE("[device_info__tlv_generator_device_capabilities_value] Error on cdma2000onexSupportedRelease TLV, err %d", buffer_offset);
            return buffer_offset;
        }
        LOGT("[device_info__tlv_generator_device_capabilities_value] DeviceCapabilities VALUE size after cdma2000onexSupportedRelease: %u", buffer_offset - offset);
    }

    // cdma2000hrpdSupportedRelease
    if (obj->field_is_present.cdma_2000_hrpd_supported_release) {
        if ((buffer_offset = tlv_generator__add_tlv_version_type_value(buffer, buffer_size, (uint32_t) buffer_offset, CONTEXT_PRIMITIVE_3, &obj->cdma_2000_hrpd_supported_release)) < 0) {
            LOGE("[device_info__tlv_generator_device_capabilities_value] Error on cdma2000hrpdSupportedRelease TLV, err %d", buffer_offset);
            return buffer_offset;
        }
        LOGT("[device_info__tlv_generator_device_capabilities_value] DeviceCapabilities VALUE size after cdma2000hrpdSupportedRelease: %u", buffer_offset - offset);
    }

    // cdma2000ehrpdSupportedRelease
    if (obj->field_is_present.cdma_2000_ehrpd_supported_release) {
        if ((buffer_offset = tlv_generator__add_tlv_version_type_value(buffer, buffer_size, (uint32_t) buffer_offset, CONTEXT_PRIMITIVE_4, &obj->cdma_2000_ehrpd_supported_release)) < 0) {
            LOGE("[device_info__tlv_generator_device_capabilities_value] Error on cdma2000ehrpdSupportedRelease TLV, err %d", buffer_offset);
            return buffer_offset;
        }
        LOGT("[device_info__tlv_generator_device_capabilities_value] DeviceCapabilities VALUE size after cdma2000ehrpdSupportedRelease: %u", buffer_offset - offset);
    }

    // eutranEpcSupportedRelease
    if (obj->field_is_present.eutran_epc_supported_release) {
        if ((buffer_offset = tlv_generator__add_tlv_version_type_value(buffer, buffer_size, (uint32_t) buffer_offset, (unsigned short) (CONTEXT_PRIMITIVE_0 | 5), &obj->eutran_epc_supported_release)) < 0) {
            LOGE("[device_info__tlv_generator_device_capabilities_value] Error on eutranEpcSupportedRelease TLV, err %d", buffer_offset);
            return buffer_offset;
        }
        LOGT("[device_info__tlv_generator_device_capabilities_value] DeviceCapabilities VALUE size after eutranEpcSupportedRelease: %u", buffer_offset - offset);
    }

    // contactlessSupportedRelease
    if (obj->field_is_present.contactless_supported_release) {
        if ((buffer_offset = tlv_generator__add_tlv_version_type_value(buffer, buffer_size, (uint32_t) buffer_offset, (unsigned short) (CONTEXT_PRIMITIVE_0 | 6), &obj->contactless_supported_release)) < 0) {
            LOGE("[device_info__tlv_generator_device_capabilities_value] Error on contactlessSupportedRelease TLV, err %d", buffer_offset);
            return buffer_offset;
        }
        LOGT("[device_info__tlv_generator_device_capabilities_value] DeviceCapabilities VALUE size after contactlessSupportedRelease: %u", buffer_offset - offset);
    }

    // rspCrlSupportedVersion
    if (obj->field_is_present.rsp_crl_supported_version) {
        if ((buffer_offset = tlv_generator__add_tlv_version_type_value(buffer, buffer_size, (uint32_t) buffer_offset, (unsigned short) (CONTEXT_PRIMITIVE_0 | 7), &obj->rsp_crl_supported_version)) < 0) {
            LOGE("[device_info__tlv_generator_device_capabilities_value] Error on rspCrlSupportedVersion TLV, err %d", buffer_offset);
            return buffer_offset;
        }
        LOGT("[device_info__tlv_generator_device_capabilities_value] DeviceCapabilities VALUE size after rspCrlSupportedVersion: %u", buffer_offset - offset);
    }

    if (extensibility_support) {
        // nrEpcSupportedRelease
        if (obj->field_is_present.nr_epc_supported_release) {
            if ((buffer_offset = tlv_generator__add_tlv_version_type_value(buffer, buffer_size, (uint32_t) buffer_offset, (unsigned short) (CONTEXT_PRIMITIVE_0 | 8), &obj->nr_epc_supported_release)) < 0) {
                LOGE("[device_info__tlv_generator_device_capabilities_value] Error on nrEpcSupportedRelease TLV, err %d", buffer_offset);
                return buffer_offset;
            }
            LOGT("[device_info__tlv_generator_device_capabilities_value] DeviceCapabilities VALUE size after nrEpcSupportedRelease: %u", buffer_offset - offset);
        }

        // nr5gcSupportedRelease
        if (obj->field_is_present.nr_5gc_supported_release) {
            if ((buffer_offset = tlv_generator__add_tlv_version_type_value(buffer, buffer_size, (uint32_t) buffer_offset, (unsigned short) (CONTEXT_PRIMITIVE_0 | 9), &obj->nr_5gc_supported_release)) < 0) {
                LOGE("[device_info__tlv_generator_device_capabilities_value] Error on nr5gcSupportedRelease TLV, err %d", buffer_offset);
                return buffer_offset;
            }
            LOGT("[device_info__tlv_generator_device_capabilities_value] DeviceCapabilities VALUE size after nr5gcSupportedRelease: %u", buffer_offset - offset);
        }

        // eutran5gcSupportedRelease
        if (obj->field_is_present.eutran_5gc_supported_release) {
            if ((buffer_offset = tlv_generator__add_tlv_version_type_value(buffer, buffer_size, (uint32_t) buffer_offset, (unsigned short) (CONTEXT_PRIMITIVE_0 | 10), &obj->eutran_5gc_supported_release)) < 0) {
                LOGE("[device_info__tlv_generator_device_capabilities_value] Error on eutran5gcSupportedRelease TLV, err %d", buffer_offset);
                return buffer_offset;
            }
            LOGT("[device_info__tlv_generator_device_capabilities_value] DeviceCapabilities VALUE size after eutran5gcSupportedRelease: %u", buffer_offset - offset);
        }       
    }

    return buffer_offset;
}
