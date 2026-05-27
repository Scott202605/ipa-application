/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "ipa_typedefs.h"

/**
 * Generate a IpaCapabilities TLV
 * 
 * @param[in, out] buffer Pointer to the buffer to where the IpaCapabilities TLV will be generated. If null, the function will only calculate the offset that the 
 * buffer would have had if the IpaCapabilities TLV had been appended.
 * @param[in] buffer_size Size of the buffer
 * @param[in] offset Offset of the buffer where the IpaCapabilities TLV will be appended.
 * @param[in] tag TAG of the IpaCapabilities TLV
 * @param[in] ipa_capabilities Pointer to a ipa_capabilities_t structure populated with the data needed to generate the TLV. The structure is populated following its documentation.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t ipa_tlv_generator__ipa_capabilities(uint8_t* buffer, const uint32_t buffer_size, uint32_t const offset, unsigned short tag, const ipa_capabilities_t* ipa_capabilities);
