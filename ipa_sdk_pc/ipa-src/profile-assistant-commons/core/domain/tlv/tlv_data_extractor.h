/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"
#include "es10_typedefs.h"

/**
 * Extracts the VALUE of the TLV which the VALUE has size of 1 byte.
 * 
 * @param[in]  tag TAG of the TLV which has the VALUE of 1 byte
 * @param[in]  tlv Pointer to a byte array with the TLV
 * @param[in]  tlv_size Size of the tlv byte array
 * @param[in, out] tlv_is_present Pointer to a boolean that will indicate if the TLV was found or not in case the function return is success.
 * If a NULL value is passed, an error will be returned in case the TLV is not found (useful for non-optional TLVs).
 * @param[out] result Pointer to a byte. Will point to a copy of the TLV VALUE if the function return is success.
 * 
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode tlv_data_extractor__result_code(unsigned short tag, const uint8_t* tlv, const size_t tlv_size, bool* tlv_is_present, uint8_t* result);

/**
 * Extracts the VALUE of the TLV wraped by another TLV which the VALUE has size of 1 byte.
 * 
 * @param[in]  parent_tag TAG of the parent TLV .
 * @param[in]  result_tag TAG of children TLV which has the VALUE of 1 byte. 
 * @param[in]  tlv Pointer to a byte array with the TLV
 * @param[in]  tlv_size Size of the tlv byte array
 * @param[out] result Pointer to a byte. Will point to a copy of the TLV VALUE if the function return is success.
 * 
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode tlv_data_extractor__result_code_with_parent_tlv(unsigned short parent_tag, unsigned short result_tag, const uint8_t* tlv, const size_t tlv_size, uint8_t* result);

/**
 * Extracts the VALUE of the TLV which the VALUE is an unsigned integer.
 * 
 * @param[in]  tag TAG of the TLV which has the unsigned integer VALUE
 * @param[in]  tlv Pointer to a byte array with the TLV
 * @param[in]  tlv_size Size of the tlv byte array
 * @param[in, out] tlv_is_present Pointer to a boolean that will indicate if the TLV was found or not in case the function return is success.
 * If a NULL value is passed, an error will be returned in case the TLV is not found (useful for non-optional TLVs).
 * @param[out] result Pointer to a uint32_t. Will point to a copy of the TLV VALUE if the function return is success.
 * 
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode tlv_data_extractor__uint32(unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, bool* tlv_is_present, uint32_t* result);

/**
 * Extracts the VALUE of the TLV which the VALUE is a boolean.
 * 
 * @param[in]  tag TAG of the TLV which has the boolean VALUE
 * @param[in]  tlv Pointer to a byte array with the TLV
 * @param[in]  tlv_size Size of the tlv byte array
 * @param[in, out] tlv_is_present Pointer to a boolean that will indicate if the TLV was found or not in case the function return is success.
 * If a NULL value is passed, an error will be returned in case the TLV is not found (useful for non-optional TLVs).
 * @param[out] value Pointer to a boolean. Will point to a copy of the TLV VALUE if the function return is success.
 * 
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode tlv_data_extractor__boolean(unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, bool* tlv_is_present, bool* value);

/**
 * Extracts the VALUE of the TLV which the VALUE is a BIT STRING
 * 
 * @param[in]  tag TAG of the TLV which has the VALUE is a Challenge
 * @param[in]  tlv Pointer to a byte array with the TLV
 * @param[in]  tlv_size Size of the TLV byte array
 * @param[in, out] plain_bit_string_buffer Pointer to preallocated byte array that will be filled with the content of the BIT STRING (with {0, 1} values per position)
 * if the function return is success. The plain_bit_string_buffer won't reference any data from the buffer, so the buffer can be deallocated after the execution of the function.
 * @param[in] plain_bit_string_buffer_size Size of the preallocated BIT STRING byte array.
 * 
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode tlv_data_extractor__bit_string(unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, uint8_t* plain_bit_string_buffer, const uint32_t plain_bit_string_buffer_size);

/**
 * This function initializes a ASN.1 List iterator which allows to iterate through the different TLVs of a ASN.1 List (SEQUENCE OF TLVs which each sub-TLV (element) has the same TAG).
 * 
 * @param[out] iterator will populate the asn1_list_iterator_t structure with the appropriate values to start iterating over the different elements of the ASN.1 List if the 
 * function return is success. This pointer will be pointing inside the tlv buffer so do not deallocate the tlv buffer while using the pointer.
 * @param[in]  list_tag ASN.1 TAG of the SEQUENCE
 * @param[in]  elem_tag ASN.1 TAG of the TLVs inside the SEQUENCE. 0 if no specific tag is to be searched for.
 * @param[in]  tlv Pointer to a byte array with the TLV
 * @param[in]  tlv_size Size of the TLV byte array
 * 
 * @return eOk in case the ASN.1 List iterator has been initialized successfully. Otherwise, an error code is returned.
*/
ErrCode tlv_data_extractor__asn1_list_init(asn1_list_iterator_t* iterator, const unsigned short list_tag, const unsigned short elem_tag, const uint8_t* tlv, const uint32_t tlv_size);

/**
 * This function gets the next TLV of an ASN.1 List
 * 
 * @param[in, out] iterator structure initialized with the funtion tlv_data_extractor__asn1_list_init(). 
 * If the return of the function is success, the iterator will be updated to take the next value from the SEQUENCE on 
 * the next json_data_extractor__get_next_object_element() call.
 * @param[out] tlv_element will point to the next element of the list (including the TAG) if the function return is success. 
 * This pointer will be pointing inside the initial tlv buffer so o not deallocate the tlv buffer while using the pointer.
 * This pointer will point to null if no more elements have been found in the array.
 * @param[out] tlv_element_size will point to the size of the element if the function return is success.
 * This pointer will point to 0 if no more elements have been found in the array.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned.
*/
ErrCode tlv_data_extractor__asn1_list_get_next(asn1_list_iterator_t* iterator, uint8_t** tlv_element, uint32_t* tlv_element_size);

/**
 * This function return the number of elements inside a ASN.1 List.
 * 
 * @param[in, out] array_iterator structure initialized with the funtion json_data_extractor__init_array_iterator().
 * @param[out] num_elements will point to the number of elements inside a ASN.1 List.
 * 
 * @return eOk in case the number of elements calculation has been done successfully. Otherwise, an error code is returned.
*/
ErrCode tlv_data_extractor__asn1_list_size(const asn1_list_iterator_t* iterator, uint32_t* num_elements);

/**
 * This function return if the ASN.1 List is an empty list or not.
 * 
 * @param[in, out] array_iterator structure initialized with the funtion json_data_extractor__init_array_iterator().
 * @param[out] num_elements will point to true if the ASN.1 List is an empty list and will point to false if is not
 * in case the funtion return is success.
 * 
 * @return eOk in case the function has been executed successfully. Otherwise, an error code is returned.
*/
ErrCode tlv_data_extractor__asn1_list_is_empty(const asn1_list_iterator_t* iterator, bool* is_empty);

/**
 * This function reset the ASN.1 iterator list to point again to the first element of the ASN.1 list.
 * 
 * @param[in, out] iterator structure initialized with the funtion tlv_data_extractor__asn1_list_init().
*/
void tlv_data_extractor__asn1_list_reinit(asn1_list_iterator_t* iterator);

/**
 * This function search a TLV in a buffer (only top level) and copies the value of the TLV into a buffer.
 * 
 * @param[in] tag TAG of the TLV to find.
 * @param[in] tlv Pointer to a buffer where the TLV will be searched (only TLVs in the top level will be searched).
 * @param[in] tlv_size Size of the tlv buffer.
 * @param[in, out] tlv_is_present Pointer to a boolean that will indicate if the TLV was found or not in case the function return is success.
 * If a NULL value is passed, an error will be returned in case the TLV is not found (useful for non-optional TLVs).
 * @param[out] out Pointer to a pre-allocated buffer where the value of the tlv found will be copied in case the function return is success.
 * @param[in] out_size Size of the out buffer (so max size of the TLV value to copy). If the size of the TLV value to copy is bigger than out_size, an error will be returned.
 * @param[in, out] var_size Pointer to an integer that will indicate the number of bytes copied into the out buffer in case the function return is success.
 * If a NULL value is passed, an error will be returned in case the TLV value size not match the out_size (useful for length-fixed TLV values).
 * 
 * @return eOk in case the function execution is success. Otherwise, an error code is returned.
*/
ErrCode tlv_data_extractor__tlv_value_small_size_copy(unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, bool* tlv_is_present, uint8_t* out, uint8_t out_size, uint8_t* var_size);

/** Same documentation as the function tlv_data_extractor__tlv_value_small_size_copy() */
ErrCode tlv_data_extractor__tlv_value_medium_size_copy(unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, bool* tlv_is_present, uint8_t* out, uint16_t out_size, uint16_t* var_size);

/** Same documentation as the function tlv_data_extractor__tlv_value_small_size_copy() */
ErrCode tlv_data_extractor__tlv_value_big_size_copy(unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, bool* tlv_is_present, uint8_t* out, uint32_t out_size, uint32_t* var_size);

/**
 * This function search a TLV in a buffer (only top level) and copy a reference of the TLV value in a pointer.
 * 
 * @param[in] tag TAG of the TLV to find.
 * @param[in] tlv Pointer to a buffer where the TLV will be searched (only TLVs in the top level will be searched).
 * @param[in] tlv_size Size of the tlv buffer.
 * @param[in, out] tlv_is_present Pointer to a boolean that will indicate if the TLV was found or not in case the function return is success.
 * If a NULL value is passed, an error will be returned in case the TLV is not found (useful for non-optional TLVs).
 * @param[out] out Pointer that will point to the value of the tlv found (inside the tlv buffer) in case the function return is success.
 * @param[out] out_size Pointer to an integer that will indicate the length of the tlv found in case the function return is success.
 * 
 * @return eOk in case the function execution is success. Otherwise, an error code is returned.
*/
ErrCode tlv_data_extractor__tlv_value_small_size_ref(unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, bool* tlv_is_present, uint8_t** out, uint8_t* out_size);

/** Same documentation as the function tlv_data_extractor__tlv_value_small_size_ref() */
ErrCode tlv_data_extractor__tlv_value_medium_size_ref(unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, bool* tlv_is_present, uint8_t** out, uint16_t* out_size);

/** Same documentation as the function tlv_data_extractor__tlv_value_small_size_ref() */
ErrCode tlv_data_extractor__tlv_value_big_size_ref(unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, bool* tlv_is_present, uint8_t** out, uint32_t* out_size);

/**
 * This function search a TLV in a buffer (only top level) and copy a reference of the TLV in a pointer.
 * 
 * @param[in] tag TAG of the TLV to find.
 * @param[in] tlv Pointer to a buffer where the TLV will be searched (only TLVs in the top level will be searched).
 * @param[in] tlv_size Size of the tlv buffer.
 * @param[in, out] tlv_is_present Pointer to a boolean that will indicate if the TLV was found or not in case the function return is success.
 * If a NULL value is passed, an error will be returned in case the TLV is not found (useful for non-optional TLVs).
 * @param[out] out Pointer that will point to the tlv found (inside the tlv buffer), including the TAG and the LENGTH bytes in case the function return is success.
 * @param[out] out_size Pointer to an integer that will indicate the size of the tlv found in case the function return is success.
 * 
 * @return eOk in case the function execution is success. Otherwise, an error code is returned.
*/
ErrCode tlv_data_extractor__tlv_small_size_ref(unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, bool* tlv_is_present, uint8_t** out,uint8_t* out_size);

/** Same documentation as the function tlv_data_extractor__tlv_small_size_ref() */
ErrCode tlv_data_extractor__tlv_medium_size_ref(unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, bool* tlv_is_present, uint8_t** out, uint16_t* out_size);

/** Same documentation as the function tlv_data_extractor__tlv_small_size_ref() */
ErrCode tlv_data_extractor__tlv_big_size_ref(unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, bool* tlv_is_present, uint8_t** out, uint32_t* out_size);

/**
 * This function search a TLV in a buffer (only top level) and copy the child TLV tag and a reference of the child TLV value.
 * This funtion is useful to parse CHOICE TLVs.
 * 
 * @param[in] parent_tag parent TAG of the TLV to find.
 * @param[in] tlv Pointer to a buffer where the parent TLV will be searched (only TLVs in the top level will be searched).
 * @param[in] tlv_size Size of the tlv buffer.
 * @param[in, out] tlv_is_present Pointer to a boolean that will indicate if the parent TLV was found or not in case the function return is success.
 * If a NULL value is passed, an error will be returned in case the parent TLV is not found (useful for non-optional TLVs).
 * @param[out] child_tag Will point to the child tag in case the function return is success.
 * @param[out] child_tlv Pointer that will point to the child tlv found (inside the tlv buffer), including the TAG and the LENGTH bytes in case the function return is success.
 * @param[out] child_tlv_size Pointer to an integer that will indicate the size of the child tlv found in case the function return is success.
 * 
 * @return eOk in case the function execution is success. Otherwise, an error code is returned.
*/
ErrCode tlv_data_extractor__child_tag_tlv_small_size_ref(unsigned short parent_tag, const uint8_t* tlv, const uint32_t tlv_size, bool* tlv_is_present, unsigned short* child_tag, uint8_t** child_tlv, uint8_t* child_tlv_size);

/** Same documentation as the function tlv_data_extractor__child_tlv_tag_value_small_size_ref() */
ErrCode tlv_data_extractor__child_tag_tlv_medium_size_ref(unsigned short parent_tag, const uint8_t* tlv, const uint32_t tlv_size, bool* tlv_is_present, unsigned short* child_tag, uint8_t** child_tlv, uint16_t* child_tlv_size);

/** Same documentation as the function tlv_data_extractor__child_tlv_tag_value_small_size_ref() */
ErrCode tlv_data_extractor__child_tag_tlv_big_size_ref(unsigned short parent_tag, const uint8_t* tlv, const uint32_t tlv_size, bool* tlv_is_present, unsigned short* child_tag, uint8_t** child_tlv, uint32_t* child_tlv_size);

/**
 * This function return if the value of the TLV is empty or not
 * 
 * @param[in]  tag TAG of the TLV which has the VALUE to check.
 * @param[in]  tlv Pointer to a byte array with the TLV
 * @param[in]  tlv_size Size of the TLV byte array
 * @param[out] value_is_empty Pointer to a boolean that will indicate if the TLV value is empty or not in case the function return is success.
 * 
 * @return eOk in case that it has been possible to successfully determine whether the TLV value is empty or not, otherwise an error code is returned.
*/
ErrCode tlv_data_extractor__tlv_value_is_empty(const unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, bool* value_is_empty);

/**
 * Extracts the VALUE of the TLV which the VALUE is a SubjectKeyIdentifier
 * 
 * @param[in]  tag TAG of the TLV which has the VALUE is a SubjectKeyIdentifier
 * @param[in]  tlv Pointer to a byte array with the TLV
 * @param[in]  tlv_size Size of the TLV byte array
 * @param[in, out] tlv_is_present Pointer to a boolean that will indicate if the TLV was found or not in case the function return is success.
 * If a NULL value is passed, an error will be returned in case the TLV is not found (useful for non-optional TLVs).
 * @param[out] obj Pointer to a subject_key_identifier_t structure. The structure is populated following its documentation with the data 
 * from the tlv buffer if the function return is success. The structure data don't reference any data from the buffer, so the buffer can be 
 * deallocated after the execution of the function.
 * 
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode tlv_data_extractor__subject_key_identifier(const unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, bool* tlv_is_present, subject_key_identifier_t* obj);

/**
 * Extracts the VALUE of the TLV which the VALUE is a Iccid
 * 
 * @param[in]  tag TAG of the TLV which has the VALUE is a Iccid
 * @param[in]  tlv Pointer to a byte array with the TLV
 * @param[in]  tlv_size Size of the TLV byte array
 * @param[in, out] tlv_is_present Pointer to a boolean that will indicate if the Iccid TLV was found or not in case the function return is success.
 * If a NULL value is passed, an error will be returned in case the TLV is not found (useful for non-optional TLVs).
 * @param[out] obj Pointer to a iccid_t structure. The structure is populated following its documentation with the data from the tlv buffer if the function 
 * return is success. The structure data don't reference any data from the buffer, so the buffer can be deallocated after the execution of the function.
 * 
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode tlv_data_extractor__iccid(unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, bool* tlv_is_present, iccid_t* obj);

/**
 * Extracts the VALUE of the TLV which the VALUE is a FQDN
 * 
 * @param[in]  tag TAG of the TLV which has the VALUE is a FQDN
 * @param[in]  tlv Pointer to a byte array with the TLV
 * @param[in]  tlv_size Size of the TLV byte array
 * @param[in, out] tlv_is_present Pointer to a boolean that will indicate if the FQDN TLV was found or not in case the function return is success.
 * If a NULL value is passed, an error will be returned in case the TLV is not found (useful for non-optional TLVs).
 * @param[out] obj Pointer to a fqdn_t structure. The structure is populated following its documentation with the data from the tlv buffer if the function 
 * return is success. The structure data don't reference any data from the buffer, so the buffer can be deallocated after the execution of the function.
 * 
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode tlv_data_extractor__fqdn(unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, bool* tlv_is_present, fqdn_t* obj);

/**
 * Extracts the VALUE of the TLV which the VALUE is a Challenge
 * 
 * @param[in]  tag TAG of the TLV which has the VALUE is a Challenge
 * @param[in]  tlv Pointer to a byte array with the TLV
 * @param[in]  tlv_size Size of the TLV byte array
 * @param[out] obj Pointer to a challenge_t structure. The structure is populated following its documentation with the data from the tlv buffer if the function 
 * return is success. The structure data don't reference any data from the buffer, so the buffer can be deallocated after the execution of the function.
 * 
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode tlv_data_extractor__challenge(unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, challenge_t* obj);

/**
 * Extracts the VALUE of the TLV which the VALUE is a TransactionId
 * 
 * @param[in]  tag TAG of the TLV which has the VALUE is a TransactionId
 * @param[in]  tlv Pointer to a byte array with the TLV
 * @param[in]  tlv_size Size of the TLV byte array
 * @param[in, out] tlv_is_present Pointer to a boolean that will indicate if the TransactionId TLV was found or not in case the function return is success.
 * If a NULL value is passed, an error will be returned in case the TLV is not found (useful for non-optional TLVs).
 * @param[out] transaction_id_t Pointer to a transaction_id_t structure. The structure is populated following its documentation with the data 
 * from the tlv buffer if the function return is success. The structure data don't reference any data from the buffer, so the buffer can be 
 * deallocated after the execution of the function.
 * 
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode tlv_data_extractor__transaction_id(unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, bool* tlv_is_present, transaction_id_t* obj);

/**
 * Extracts the VALUE of the TLV which the VALUE is an OperatorId
 * 
 * @param[in] tag TAG of the TLV which has the VALUE is an OperatorId
 * @param[in] tlv Pointer to a byte array with the TLV
 * @param[in] tlv_size Size of the tlv byte array
 * @param[out] operator_id Pointer to a operator_id structure. The structure is populated following its documentation with the data 
 * from the tlv buffer if the function return is success. The structure data may be referencing tlv buffer data, do not deallocate the 
 * tlv buffer while using the structure.
 * 
 * @return eOk in case the data extraction has been done successfully, otherwise an error code is returned.
*/
ErrCode tlv_data_extractor__operator_id(unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, operator_id_t* operator_id);
