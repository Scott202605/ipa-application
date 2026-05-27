/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"

/**
 * Parse the 2 first characters of a hexadecimal string to a byte.
 * 
 * @param hex Hexadecimal string to parse, required to have 2 characters or more.
 * @param result byte that will have as its value the first 2 characters of the hexadecimal string in binary.
 * 
 * @return eOk in case the parsing has been done successfully. Otherwise, an error code is returned. 
 */
ErrCode byte_utils__hex_string_to_byte(const char *hex, uint8_t* result);

/**
 * Convert byte array to hex string. 
 * @note This function doesn't add a null character at the end and is the responsability of the calling function to do so.
 *
 * @param in byte array to convert.
 * @param in_size Size of the byte array to convert.
 * @param out Pointer of the hex string output buffer.
 * @param out_size Size of the hex string output buffer. (Atleast should be x 2 the in_size as byte array to hex string conversion doubles the size)
 *
 * @return Upon successful execution, will return the number of bytes written in the output buffer.
 * If an output error is encountered, a negative value is returned.
 */
int32_t byte_utils__byte_array_to_hex_string(const unsigned char *in, size_t in_size, unsigned char *out, size_t out_size);

/**
 * Convert hex string to byte array.
 * @note This function expects in_size to not include the null character so if it's a string literal or already has null character, pass size - 1 as in_size.
 *
 * @param in Pointer to hex string to convert.
 * @param in_size Size of the hex string to convert.
 * @param out Pointer of the byte array output buffer.
 * @param out_size Size of the byte array output buffer. (Should be / 2 the in_size as hex string to byte array halves in size)
 *
 * @return Upon successful execution, will return the number of bytes written in the output buffer.
 * If an output error is encountered, a negative value is returned.
 */
int32_t byte_utils__hex_string_to_byte_array(const unsigned char *in, uint32_t in_size, unsigned char *out, uint32_t out_size);

/**
 * Parse two bytes to a short
 * 
 * @param[in] high_byte High byte of the short
 * @param[in] low_byte Low byte of the short
 * 
 * @return The parsed short value
*/
unsigned short byte_utils__bytes_to_short(const uint8_t high_byte, const uint8_t low_byte);

/**
 * Parse the 4 first characters of a hexadecimal string to a short.
 * 
 * @param hex Hexadecimal string to parse, required to have 4 characters or more.
 * @param result short that will have as its value the first 4 characters of the hexadecimal string in binary.
 * 
 * @return eOk in case the parsing has been done successfully. Otherwise, an error code is returned. 
 */
ErrCode byte_utils__hex_string_to_short(const char* hex, unsigned short* result);

/**
 * Convert a unsigned integer to a byte array.
 * 
 * @param buffer Pointer of the byte array output buffer.If null, the function will only calculate the offset that the 
 * buffer would have had if the unsigned integer had been write into the buffer.
 * @param buffer_size Size of the byte array output buffer (should be >= 5 to cover all the cases). Can be 0 if buffer pointer is NULL.
 * @param value unsigned integer to be converted.
 * 
 * @return Upon successful execution, will return the number of bytes written in the output buffer.
 * If an output error is encountered, a negative value is returned.
*/
int8_t byte_utils__uint_to_byte_array(uint8_t* buffer, const uint32_t buffer_size, const uint32_t value);

/**
 * Convert a byte array to a unsigned integer.
 * 
 * @param buffer Pointer of the byte array input buffer.
 * @param buffer_size Size of the byte array input buffer.
 * @param value Pointer to the result value.
 * 
 * @return eOk in case the parsing has been done successfully. Otherwise, an error code is returned if the value of the buffer does't fit in 
 * the unsigned integer (Most Significant Byte of the byte array input buffer is not in the last 4 positions). 
*/
ErrCode byte_utils__byte_array_to_uint(const uint8_t* buffer, const uint32_t buffer_size, uint32_t* value);

/**
 * Swap the first 4 bits of the byte with the last 4 bits of the byte.
 * 
 * @param b byte to be bit-swapped
 * 
 * @return byte bit-swapped
 */
uint8_t byte_utils__byte_nibble_swap(uint8_t b);

/**
 * Parse an ICCID to nibble swap or plain format
 * 
 * @param[in, out] iccid ICCID to parse. The ICCID will be modified to the parsed format in case that the function has been successfully executed.
 * @param[in] to_nibble_swap true to parse the ICCID to nibble swap format or false to parse the ICCID to plain format.
 * 
 * @return eOk in case the parsing has been done successfully. Otherwise, an error code is returned
*/
ErrCode byte_utils__iccid_parse_format(iccid_t* iccid, const bool to_nibble_swap);

/**
 * Encode a plain bit string to an ASN.1 BIT STRING and put it into a buffer.
 * 
 * @param[in, out] buffer Point to the buffer to which the ASN.1 BIT STRING will be added. If null, the function will only calculate the size that the 
 * buffer would need to add the ASN.1 BIT STRING.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] bit_string Point to a plain bit string buffer (e.g. {0, 1, 1, 0, 1, 1}).
 * @param[in] bit_string_size Size of the bit_string buffer.
 * 
 * @return Upon successful execution, will return the number of bytes written in the output buffer.
 * If an output error is encountered, a negative value is returned.
*/
int32_t byte_utils__bit_string_encode(uint8_t* buffer, uint32_t buffer_size, const uint8_t* bit_string, const uint32_t bit_string_size);

/**
 * Decode an ASN.1 BIT STRING to a plain bit string (e.g. {0, 1, 1, 0, 1, 1}) to and put it into a buffer.
 * 
 * @param[in, out] buffer Point to the buffer to which the plain bit string will be added. If null, the function will only calculate the size that the 
 * buffer would need to add the plain bit string.
 * @param[in] buffer_size Size of the plain bit string buffer.
 * @param[in] bit_string Point to an ASN.1 encoded BIT STRING.
 * @param[in] bit_string_size Size of the ASN.1 encoded BIT STRING.
 * 
 * @return Upon successful execution, will return the number of bytes written in the output buffer.
 * If an output error is encountered, a negative value is returned.
*/
int32_t byte_utils__bit_string_decode(uint8_t* buffer, uint32_t buffer_size, const uint8_t* encoded_bit_string, const uint32_t encoded_bit_string_size);

/**
 * This function encode a plain UTF-8 OID and put it into a buffer.
 * 
 * Format rules:
 *  - The object ID consists of 1 to 128 subIDs, which are separated by periods.
 *  - Each subID is a positive number. No negative numbers are allowed.
 *  - The value of each number cannot exceed 4294967295.
 *  - The valid values of the first subID are 0, 1, or 2.
 *  - If the first subID has a value of 0 or 1, the second subID can have a value only of 0 through 39.
 * 
 * Example: 1.3.6.1.4.1.33459.503.1.1.2.4.97.118.115.50
 * 
 * @param[in, out] buffer Point to the buffer to which the encoded OID will be added. If null, the function will only calculate the size that the 
 * buffer would need to add the encoded OID.
 * @param[in] buffer_size Size of the buffer.
 * @param[in] oid Point to a plain UTF-8 OID (e.g. '2.999').
 * @param[in] oid_len Length of the plain UTF-8 OID (null character not included if exists).
 * 
 * @return Upon successful execution, will return the buffer offset.
 * If an output error is encountered, a negative value is returned.
*/
int32_t byte_utils__oid_encode(uint8_t* buffer, uint32_t buffer_size, const unsigned char* oid, const uint32_t oid_len);
