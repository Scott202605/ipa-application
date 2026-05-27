/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"

/**
 * Add an ASN.1 TAG to a buffer.
 * 
 * @param[in, out] buffer Point to the buffer to which the ASN.1 TAG will be added. If null, the function will only calculate the offset that the 
 * buffer would have had if the TAG had been added.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] offset Offset of the buffer.
 * @param[in] tag ASN.1 TAG of a TLV.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t tlv_generator__add_tag(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const unsigned short tag);

/**
 * Add an ASN.1 LENGTH to a buffer.
 * 
 * @param[in, out] buffer Point to the buffer to which the ASN.1 LENGTH will be added. If null, the function will only calculate the offset that the 
 * buffer would have had if the LENGTH had been added.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] offset Offset of the buffer.
 * @param[in] length Length of a TLV value.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t tlv_generator__add_length(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const uint32_t length);

/**
 * Add an ASN.1 TAG and LENGTH to a buffer.
 * 
 * @param[in, out] buffer Point to the buffer to which the ASN.1 TAG and LENGTH will be added. If null, the function will only calculate the offset that the 
 * buffer would have had if the TAG and LENGTH had been added.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] offset Offset of the buffer.
 * @param[in] tag ASN.1 TAG of a TLV.
 * @param[in] length Length of a TLV value.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t tlv_generator__add_tag_and_length(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const unsigned short tag, const uint32_t length);

/**
 * Add a TLV to a buffer.
 * 
 * @param[in, out] buffer Point to the buffer to which the TLV will be added. If null, the function will only calculate the offset that the 
 * buffer would have had if the TLV had been added.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] offset Offset of the buffer.
 * @param[in] tag ASN.1 TAG of a TLV.
 * @param[in] value Point to a buffer with the VALUE of the TLV, if the TLV has no value, the pointer must be null. 
 * If buffer parameter is null, the value pointer can be also null. 
 * @param[in] value_size Size of the value buffer.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t tlv_generator__add_tlv(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const unsigned short tag, const uint8_t* value, const uint32_t value_size);

/**
 * Wrap into a TLV a VALUE present in the buffer.
 * This function will move the data of the VALUE present on the buffer and wrap it with a TAG and LENGTH.
 *  
 * @param[in, out] buffer Point to the buffer to which the TLV will be wrapped. If null, the function will only calculate the offset that the 
 * buffer would have had if the TLV wrap has been done.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] value_offset Offset where the VALUE to wrap starts.
 * @param[in] offset Offset where the VALUE to wrap ends. After this position, all remaining buffer data must be garbage (will be overwritten).
 * @param[in] tag ASN.1 TAG of the wrapped TLV.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t tlv_generator__add_wrap_tlv(uint8_t* buffer, const uint32_t buffer_size, const uint32_t value_offset, const uint32_t offset, const unsigned short tag);

/**
 * Add a TLV to a buffer.
 * 
 * @param[in, out] buffer Point to the buffer to which the TLV will be added. If null, the function will only calculate the offset that the 
 * buffer would have had if the TLV had been added.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] offset Offset of the buffer.
 * @param[in] tlv Pointer to a byte array with the content of the TLV to add.
 * @param[in] tlv_size The size of the tlv byte array in bytes.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t tlv_generator__add_tlv_full_bytes(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const uint8_t* tlv, const uint32_t tlv_size);

/**
 * Add a TLV to a buffer replacing the TAG.
 * 
 * @param[in, out] buffer Point to the buffer to which the TLV with a replace TAG will be added. If null, the function will only calculate the offset that the 
 * buffer would have had if the TLV with the replace TAG had been added.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] offset Offset of the buffer.
 * @param[in] tlv Pointer to a byte array with the TLV content (the TAG of this TLV will be relaced on the buffer)
 * @param[in] tlv_size The size of the tlv byte array in bytes.
 * @param[in] new_tag ASN.1 TAG to be overwritten.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t tlv_generator__add_tlv_full_bytes_overwrite_tag(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset,  const uint8_t* tlv, const uint32_t tlv_size, unsigned short new_tag);

/**
 * Add a TLV to a buffer with an INTEGER value.
 * 
 * @param[in, out] buffer Point to the buffer to which the TLV will be added. If null, the function will only calculate the offset that the 
 * buffer would have had if the TLV had been added.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] offset Offset of the buffer.
 * @param[in] tag ASN.1 TAG of the TLV.
 * @param[in] value Unsigned integer value of the TLV
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t tlv_generator__add_tlv_integer_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const unsigned short tag, const unsigned int value);

/**
 * Add a TLV to a buffer with a BOOLEAN value.
 * 
 * @param[in, out] buffer Point to the buffer to which the TLV will be added. If null, the function will only calculate the offset that the 
 * buffer would have had if the TLV had been added.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] offset Offset of the buffer.
 * @param[in] tag ASN.1 TAG of the TLV.
 * @param[in] value boolean value of the TLV
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t tlv_generator__add_tlv_boolean_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const unsigned short tag, const bool value);

/**
 * Add a TLV to a buffer with a UTF-8 value.
 * 
 * @param[in, out] buffer Point to the buffer to which the TLV will be added. If null, the function will only calculate the offset that the 
 * buffer would have had if the TLV had been added.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] offset Offset of the buffer.
 * @param[in] tag ASN.1 TAG of the TLV.
 * @param[in] value null-terminated string with the VALUE of the TLV to add (the null-terminated character will not be included in the buffer TLV).
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t tlv_generator__add_tlv_cstring_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const unsigned short tag, const char* value);

/**
 * Add a TLV to a buffer with a base64 value.
 * 
 * @param[in, out] buffer Point to the buffer to which the TLV will be added. If null, the function will only calculate the offset that the 
 * buffer would have had if the TLV had been added.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] offset Offset of the buffer.
 * @param[in] tag ASN.1 TAG of the TLV.
 * @param[in] b64_encoded Pointer to a byte array with the VALUE of the TLV encoded in base64
 * @param[in] b64_encoded_len Size of the b64_encoded byte array
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t tlv_generator__add_tlv_base64_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const unsigned short tag, const unsigned char* b64_encoded, const uint32_t b64_encoded_len);

/**
 * Add a TLV to a buffer with a BIT STRING value.
 * 
 * @param[in, out] buffer Point to the buffer to which the TLV will be added. If null, the function will only calculate the offset that the 
 * buffer would have had if the TLV had been added.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] offset Offset of the buffer.
 * @param[in] tag ASN.1 TAG of the TLV.
 * @param[in] bit_string Pointer to a byte array with a plain bit string (e.g. {0, 1, 1, 0, 1, 1}).
 * @param[in] bit_string_size Size of the bit_string byte array.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t tlv_generator__add_tlv_bit_string_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const unsigned short tag, const uint8_t* bit_string, const uint32_t bit_string_count);

/**
 * Add a TLV to a buffer with a NULL value.
 * 
 * @param[in, out] buffer Point to the buffer to which the TLV will be added. If null, the function will only calculate the offset that the 
 * buffer would have had if the TLV had been added.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] offset Offset of the buffer.
 * @param[in] tag ASN.1 TAG of the TLV.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t tlv_generator__add_tlv_null_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const unsigned short tag);

/**
 * Add a TLV to a buffer with a OID value.
 * 
 * @param[in, out] buffer Point to the buffer to which the TLV will be added. If null, the function will only calculate the offset that the 
 * buffer would have had if the TLV had been added.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] offset Offset of the buffer.
 * @param[in] tag ASN.1 TAG of the TLV.
 * @param[in] oid Pointer to a plain UTF-8 OID (e.g. '2.999').
 * @param[in] oid_len Length of the oid (null character not included if exists).
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t tlv_generator__add_tlv_oid_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const unsigned short tag, unsigned char* oid, uint32_t oid_len);

/**
 * Add a TLV to a buffer with a TransactionId value.
 * 
 * @param[in, out] buffer Point to the buffer to which the TLV will be added. If null, the function will only calculate the offset that the 
 * buffer would have had if the TLV had been added.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] offset Offset of the buffer.
 * @param[in] tag ASN.1 TAG of the TLV.
 * @param[in] transaction_id Pointer to a transaction_id_t structre with the TransactionId VALUE of the TLV to add.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t tlv_generator__add_tlv_transaction_id_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const unsigned short tag, const transaction_id_t* transaction_id);

/**
 * Add a TLV to a buffer with a VersionType value.
 * 
 * @param[in, out] buffer Point to the buffer to which the TLV will be added. If null, the function will only calculate the offset that the 
 * buffer would have had if the TLV had been added.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] offset Offset of the buffer.
 * @param[in] tag ASN.1 TAG of the TLV.
 * @param[in] version_type Pointer to a version_type_t structre with the VersionType VALUE of the TLV to add.
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t tlv_generator__add_tlv_version_type_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const unsigned short tag, const version_type_t* version_type);

/**
 * Add a TLV to a buffer with a Iccid nibble swapped value.
 * 
 * @param[in, out] buffer Point to the buffer to which the TLV will be added. If null, the function will only calculate the offset that the 
 * buffer would have had if the TLV had been added.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] offset Offset of the buffer.
 * @param[in] tag ASN.1 TAG of the TLV.
 * @param[in] iccid Pointer to a iccid_t structre with the Iccid VALUE of the TLV to add. The Iccid can be or not nibble swapped, 
 * the function will make the nibble swap in case it is not nibble swapped (without modifying the input structure).
 * 
 * @return Upon successful execution, will return the updated buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t tlv_generator__add_tlv_iccid_nibble_swap_value(uint8_t* buffer, const uint32_t buffer_size, const uint32_t offset, const unsigned short tag, const iccid_t* iccid);
