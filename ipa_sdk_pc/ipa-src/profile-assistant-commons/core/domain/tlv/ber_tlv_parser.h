#pragma once
#include "typedefs.h"

/**
 * BER-TLV parser
 * @author QuanTag IT Solutions GmbH
 */

uint8_t ber_tlv_parser__get_tag_bytes_count(const uint8_t* buffer, size_t offset);
uint8_t ber_tlv_parser__get_length_bytes_count(const uint8_t* buffer, size_t offset);
ErrCode ber_tlv_parser__get_tlv_bytes_count(const uint8_t* buffer, size_t offset, size_t *result);

int ber_tlv_parser__find_tlv_by_tag_2(const uint8_t* buffer, size_t bufferSize, size_t offset, unsigned short tag);

unsigned short ber_tlv_parser__get_tlv_tag(const uint8_t* buffer, size_t offset);
size_t ber_tlv_parser__get_value_offset(const uint8_t* response, size_t tlvOffset);
size_t ber_tlv_parser__get_length_offset(const uint8_t* response, size_t tlvOffset);

ErrCode ber_tlv_parser__get_tag_data(const uint8_t* buffer, const size_t buffer_size, size_t offset, unsigned short* tag, uint8_t* tag_size);
ErrCode ber_tlv_parser__get_data_length(const uint8_t* buffer, size_t offset, size_t* result);

ErrCode ber_tlv_parser__ber_tlv_2(const uint8_t* buffer, size_t bufferSize, size_t offset, _BerTlv *obj);
ErrCode tlv_data_extractor__ber_tlv_to_int(const uint8_t* value_ptr, size_t length, int32_t* out_int);
ErrCode ber_tlv_parser__get_full_tlv_length(const uint8_t* buffer, size_t offset, size_t *result);
