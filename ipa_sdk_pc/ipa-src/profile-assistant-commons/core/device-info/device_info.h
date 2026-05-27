/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"

typedef struct tac_s {
    uint8_t value[OCTET4];
} tac_t;

typedef struct imei_s {
    uint8_t value[OCTET8];
} imei_t;

typedef enum evdo_revision_e {
    REV_0 = 1,
    REV_A = 2,
    REV_B = 3
} evdo_revision_t;

/* Opaque DeviceInfo struct */
typedef struct device_info_s device_info_t;

/**
 * This function returns the DeviceInfo instance.
 * The DeviceInfo instance can be used to generate a DeviceInfo TLV.
 * 
 * @return Pointer to the DeviceInfo instance.
*/
device_info_t* device_info__get_instance();

/**
 * This function sets the TAC (Device type allocation code) in the DeviceInfo instance.
 * 
 * @param[in] tac represented as a string of 4 octets that is coded as a Telephony Binary Coded Decimal String as defined in 3GPP TS 29.002
 * 
 * @return Upon successful execution, will return 0.
 * If an output error is encountered, a negative value is returned.
*/
int device_info__set_tac(const tac_t* tac);

/**
 * This function sets the IMEI in the DeviceInfo instance.
 * 
 * @param[in] imei represented as a string of 8 octets that is coded as a Telephony Binary Coded Decimal String as defined in 3GPP TS 29.002,
 * except that the last octet contains the check digit (in high nibble) and an 'F' filler (in low nibble). It SHOULD be present if the Device contains a non-removable eUICC.
 * If null, the function will unset the IMEI from the DeviceInfo instance.
 * 
 * @return This function does not return any value.
*/
void device_info__set_imei(const imei_t* imei);

/**
 * This function sets the gsmSupportedRelease in the DeviceInfo instance.
 * If GSM/GERAN is not supported this funtion SHALL not be called.
 * 
 * @param[in] version if GSM/GERAN is supported, this SHALL be the highest 3GPP release fully supported by the device.
 * 
 * @return This function does not return any value.
*/
void device_info__set_gsm_supported_release(const uint8_t version);

/**
 * This function sets the utranSupportedRelease in the DeviceInfo instance.
 * If UMTS/UTRAN is not supported this funtion SHALL not be called.
 * 
 * @param[in] version if UMTS/UTRAN is supported, this SHALL be the highest 3GPP release fully supported by the device.
 * 
 * @return This function does not return any value.
*/
void device_info__set_utran_supported_release(const uint8_t version);

/**
 * This function sets the cdma2000onexSupportedRelease in the DeviceInfo instance.
 * If cdma2000 1X is not supported this funtion SHALL not be called.
 * 
 * @return This function does not return any value.
*/
void device_info__set_cdma_2000_onex_supported_release();

/**
 * This function sets the cdma2000hrpdSupportedRelease in the DeviceInfo instance.
 * If cdma2000 HRPD is not supported this funtion SHALL not be called.
 * 
 * @param[in] revision EVDO revision (Rev 0, Rev A or Rev B).
 * 
 * @return This function does not return any value.
*/
void device_info__set_cdma_2000_hrpd_supported_release(const evdo_revision_t revision);

/**
 * This function sets the cdma2000ehrpdSupportedRelease in the DeviceInfo instance.
 * If cdma2000 eHRPD is not supported this funtion SHALL not be called.
 * 
 * @param[in] version if cdma2000 eHRPD is supported, this SHALL be the highest 3GPP release fully supported by the device.
 * 
 * @return This function does not return any value.
*/
void device_info__set_cdma_2000_ehrpd_supported_release(const uint8_t version);

/**
 * This function sets the eutranEpcSupportedRelease in the DeviceInfo instance.
 * If LTE/E-UTRAN is not supported this funtion SHALL not be called.
 * 
 * @param[in] version if LTE/E-UTRANusing a 4G core network (Evolved Package Core) is supported, this SHALL be the highest 3GPP release fully supported by the device.
 * 
 * @return This function does not return any value.
*/
void device_info__set_eutran_epc_supported_release(const uint8_t version);

/**
 * This function sets the contactlessSupportedRelease in the DeviceInfo instance.
 * If NFC is not supported this funtion SHALL not be called.
 * 
 * @param[in] version – if NFC is supported, this SHALL be the highest version number of TS.26 supported by the device.
 * @param[in] revision – if NFC is supported, this SHALL be the highest revision number (of the version) of TS.26 supported by the device.
 * 
 * @return This function does not return any value.
*/
void device_info__set_contactless_supported_release(const uint8_t version, const uint8_t revision);

/**
 * This function sets the rspCrlSupportedVersion in the DeviceInfo instance.
 * If load eUICC CRL (as defined in SGP.22 section 5.7.12) is not supported this funtion SHALL not be called.
 * 
 * @param[in] version if load eUICC CRL (as defined in SGP.22 section 5.7.12) is supported, this SHALL be the highest SGP.22 release number supported by the device.
 * If null, the function will unset the rspCrlSupportedVersion from the DeviceInfo instance.
 * 
 * @return This function does not return any value.
*/
void device_info__set_rsp_crl_supported_version(const version_type_t* version);

/**
 * This function sets the nrEpcSupportedRelease in the DeviceInfo instance.
 * If NR using a 4G core network is not supported this funtion SHALL not be called.
 * 
 * @param[in] version if NR (5G New Radio) using a 4G core network (Evolved Packet Core) is supported, this SHALL be the highest 3GPP release fully supported by the device.
 * 
 * @return This function does not return any value.
*/
void device_info__set_nr_epc_supported_release(const uint8_t version);

/**
 * This function sets the nr5gcSupportedRelease in the DeviceInfo instance.
 * If NR using a 5G core network is not supported this funtion SHALL not be called.
 * 
 * @param[in] version if NR using a 5G core network is supported, this SHALL be the highest 3GPP release fully supported by the device.
 * 
 * @return This function does not return any value.
*/
void device_info__set_nr_5gc_supported_release(const uint8_t version);

/**
 * This function sets the eutran5gcSupportedRelease in the DeviceInfo instance.
 * If LTE/E-UTRAN using a 5G core network is not supported this funtion SHALL not be called.
 * 
 * @param[in] version if LTE/E-UTRAN using a 5G core network is supported, this SHALL be the highest 3GPP release fully supported by the device.
 * 
 * @return This function does not return any value.
*/
void device_info__set_eutran_5gc_supported_release(const uint8_t version);

/**
 * This function generates a DeviceInfo TLV.
 * 
 * @param[in, out] buffer Points to a buffer where the DeviceInfo TLV will be written. If null, the function will only calculate the offset that the 
 * buffer would have had in case the TLV has been written.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] offset Offset of the buffer. Where the TLV will start to be written.
 * @param[out] extensibility_support SHALL be false, unless the eUICC indicates deviceInfoExtensibilitySupport.
 * @param[in] tag ASN.1 TAG of the DeviceInfo TLV.
 * @param[in] obj Point to a DeviceInfo instance (see device_info__get_instance()).
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t device_info__tlv_generator(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, bool extensibility_support, const unsigned short tag, const device_info_t* obj);
