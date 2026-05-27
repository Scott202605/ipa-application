/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include "tlv_data_extractor.h"
#include "log.h"
#include "tlv_tags.h"
#include "ber_tlv_parser.h"
#include "tlv_lengths.h"
#include "byte_utils.h"

static ErrCode tlv_data_extractor__ref(unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, const bool value, bool* tlv_is_present, uint8_t** out, uint32_t* out_size);

ErrCode tlv_data_extractor__result_code(unsigned short tag, const uint8_t* tlv, const size_t tlv_size, bool* tlv_is_present, uint8_t* result) {
    return tlv_data_extractor__tlv_value_small_size_copy(tag, tlv, (uint32_t) tlv_size, tlv_is_present, result, sizeof(uint8_t), NULL);
}

ErrCode tlv_data_extractor__result_code_with_parent_tlv(unsigned short parent_tag, unsigned short result_tag, const uint8_t* tlv, const size_t tlv_size, uint8_t* result) {
    int offset;
    size_t value_offset;

    if (!tlv || tlv_size == 0) {
        LOGE("[tlv_data_extractor__result_code_with_parent_tlv] tlv is empty/null");
        return eBadArg;
    }

    LOG_DATA(eLogTrace, "[tlv_data_extractor__result_code_with_parent_tlv] TLV", tlv, tlv_size);

    offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, 0, parent_tag);
    if (offset < 0) {
        LOGE("[tlv_data_extractor__result_code_with_parent_tlv] Parent TAG %04X not found", parent_tag);
		return eFatal;
    }

    value_offset = ber_tlv_parser__get_value_offset(tlv, offset);

    return tlv_data_extractor__result_code(result_tag, tlv + value_offset, tlv_size - value_offset, NULL, result);
}

ErrCode tlv_data_extractor__uint32(unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, bool* tlv_is_present, uint32_t* result) {
    ErrCode rc; 
    uint8_t* tlv_value_ref;
    uint32_t tlv_value_ref_size;

    if (!tlv || tlv_size == 0) {
        LOGE("[tlv_data_extractor__uint32] tlv is empty/null");
        return eBadArg;
    }
    LOG_DATA(eLogDebug, "[tlv_data_extractor__uint32] INTEGER TLV", tlv, tlv_size); 

    /* Extract the TLV value */
    if ((rc = tlv_data_extractor__tlv_value_big_size_ref(tag, tlv, tlv_size, tlv_is_present, &tlv_value_ref, &tlv_value_ref_size)) != eOk) {
        LOGE("[tlv_data_extractor__uint32] Error extracting the TLV value, rc %d", rc);
        return rc;
    }
    
    if (!tlv_is_present || (tlv_is_present && *tlv_is_present)) {
        /* Parse the TLV value to an integer */
        if ((rc = byte_utils__byte_array_to_uint(tlv_value_ref, tlv_value_ref_size, result)) != eOk) {
            LOGE("[tlv_data_extractor__uint32] Error parsing the TLV value to an integer, rc %d", rc);
            return rc;
        }

        LOGD("[tlv_data_extractor__uint32] INTEGER %u", *result);
    }

    return eOk;
}

ErrCode tlv_data_extractor__boolean(unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, bool* tlv_is_present, bool* value) {
    ErrCode rc;
    uint8_t asn1_boolan_value;

    if ((rc = tlv_data_extractor__result_code(tag, tlv, (size_t) tlv_size, tlv_is_present, &asn1_boolan_value)) != eOk) {
        LOGE("[tlv_data_extractor__boolean] Error extracting the BOOLEAN from the TLV, rc %d", rc);
        return rc;
    }

    if (!tlv_is_present || (tlv_is_present && *tlv_is_present)) {
        if (ASN1_DER_BOOL_TRUE == asn1_boolan_value) {
            *value = true;
        } else if (ASN1_DER_BOOL_FALSE == asn1_boolan_value) {
            *value = false;
        } else {
            LOGE("[tlv_data_extractor__boolean] Wrong BOOLEAN value %02X", asn1_boolan_value);
            return eFatal;
        }
    }

    return eOk;
}

ErrCode tlv_data_extractor__bit_string(unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, uint8_t* plain_bit_string_buffer, const uint32_t plain_bit_string_buffer_size) {
    ErrCode rc;
    int32_t err;
    uint8_t* tlv_value_ref;
    uint32_t tlv_value_ref_size;

    if (!tlv || tlv_size == 0) {
        LOGE("[tlv_data_extractor__bit_string] tlv is empty/null");
        return eBadArg;
    }
    LOG_DATA(eLogDebug, "[tlv_data_extractor__bit_string] BIT STRING TLV", tlv, tlv_size); 
    
    /* Extract the TLV value */
    if ((rc = tlv_data_extractor__tlv_value_big_size_ref(tag, tlv, tlv_size, NULL, &tlv_value_ref, &tlv_value_ref_size)) != eOk) {
        LOGE("[tlv_data_extractor__bit_string] Error extracting the TLV value, rc %d", rc);
        return rc;
    }

    /* Parse the TLV value to a plain BIT STRING */
    if ((err = byte_utils__bit_string_decode(plain_bit_string_buffer, plain_bit_string_buffer_size, tlv_value_ref, tlv_value_ref_size)) < 0) {
        LOGE("[tlv_data_extractor__bit_string] Error decoding the BIT STRING, rc %d", err);
        return eFatal;
    }

    LOG_DATA(eLogDebug, "[tlv_data_extractor__bit_string] Plain BIT STRING", plain_bit_string_buffer, err);

    return eOk;
}

ErrCode tlv_data_extractor__asn1_list_init(asn1_list_iterator_t* iterator, const unsigned short list_tag, const unsigned short elem_tag, const uint8_t* tlv, const uint32_t tlv_size) {
    ErrCode rc;
    int tlv_offset;
    _BerTlv tlv_obj;

    /* Check input params */
    if (!iterator) {
        LOGE("[tlv_data_extractor__asn1_list_init] The iterator object is null");
        return eBadArg;
    }

    /* Extract the ASN.1 List TLV */
    if ((tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, 0, list_tag)) < 0) {
        LOGE("[tlv_data_extractor__asn1_list_init] List TAG 0x%04X not found", list_tag);
        return eFatal;
    }

    if ((rc = ber_tlv_parser__ber_tlv_2(tlv, tlv_size, (size_t) tlv_offset, &tlv_obj)) != eOk) {
        LOGE("[tlv_data_extractor__asn1_list_init] Error parsing the List TLV, rc %d", rc);
        return rc;
    }

    /* Initialize the iterator object */
    iterator->asn1_list_tlv = (uint8_t*) tlv + tlv_offset;
    iterator->init_offset = (uint32_t) tlv_obj.nTag + (uint32_t) tlv_obj.nLength;
    iterator->asn1_list_tlv_size = iterator->init_offset + (uint32_t) tlv_obj.length;
    iterator->current_offset = iterator->init_offset;
    iterator->elem_tag = elem_tag;

    LOG_DATA(eLogTrace, "[tlv_data_extractor__asn1_list_init] ASN.1 List TLV", iterator->asn1_list_tlv, iterator->asn1_list_tlv_size);
    LOGT("[tlv_data_extractor__asn1_list_init] init_offset=%u, current_offset=%u, elem_tag=%04X", iterator->init_offset, iterator->current_offset, iterator->elem_tag);

    return eOk;
}

ErrCode tlv_data_extractor__asn1_list_get_next(asn1_list_iterator_t* iterator, uint8_t** tlv_element, uint32_t* tlv_element_size) {
    ErrCode rc;
    int tlv_offset;
    size_t element_size;

    /* Check input params */
    if (!iterator) {
        LOGE("[tlv_data_extractor__asn1_list_get_next] The iterator object is null");
        return eBadArg;
    }

    LOGT("[tlv_data_extractor__asn1_list_get_next] current_offset=%u", iterator->current_offset);

    // Return NULL if there is no more elements in the list
    if (iterator->current_offset >= iterator->asn1_list_tlv_size) {
        *tlv_element = NULL;
        *tlv_element_size = 0;
        return eOk;
    }

    // Find the next element
    if (0 == iterator->elem_tag) {
        tlv_offset = (int) iterator->current_offset; // No search for a specific TAG, just get the next TLV
    } else {
        if ((tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(iterator->asn1_list_tlv, iterator->asn1_list_tlv_size, iterator->current_offset, iterator->elem_tag)) < 0) {
            LOGE("[tlv_data_extractor__asn1_list_get_next] Element TAG 0x%04X not found", iterator->elem_tag);
            return eFatal;
        }
    }
    
    // Calculate the size of the element
    if ((rc = ber_tlv_parser__get_full_tlv_length(iterator->asn1_list_tlv, (size_t) tlv_offset, &element_size)) != eOk) {
        LOGE("[tlv_data_extractor__asn1_list_get_next] Error calculating the size of the ASN.1 list element, rc %d", rc);
        return eFatal;
    }

    // Update the iterator struct to point to the next element in the next function call
    iterator->current_offset = (uint32_t) (tlv_offset + element_size);

    // Set the result
    *tlv_element = iterator->asn1_list_tlv + tlv_offset;
    *tlv_element_size = (uint32_t) element_size;

    return eOk;
}

ErrCode tlv_data_extractor__asn1_list_size(const asn1_list_iterator_t* iterator, uint32_t* num_elements) {
    ErrCode rc;
    asn1_list_iterator_t it; // To avoid increase the input iterator
    uint8_t* element;
    uint32_t element_size;

    /* Check input parameters */
    if (!iterator) {
        LOGE("[tlv_data_extractor__asn1_list_size] The List iterator is null");
        return eBadArg;
    }

    if (!num_elements) {
        LOGE("[tlv_data_extractor__asn1_list_size] The elements counter is null");
        return eBadArg;
    }

    // Iterate over List
    *num_elements = 0;
    memcpy(&it, iterator, sizeof(asn1_list_iterator_t));
    tlv_data_extractor__asn1_list_reinit(&it); // To calculate the full numbers of elements
    while ((rc = tlv_data_extractor__asn1_list_get_next(&it, &element, &element_size)) == eOk && element != NULL) {
        (*num_elements)++;
    }

    if (rc != eOk) {
        LOGE("[tlv_data_extractor__asn1_list_size] Error iterating over the List, rc %d", rc);
    }

    return rc;
}

ErrCode tlv_data_extractor__asn1_list_is_empty(const asn1_list_iterator_t* iterator, bool* is_empty) {
    ErrCode rc;
    uint32_t num_elements;

    /* Check input parameters */
    if (!is_empty) {
        LOGE("[tlv_data_extractor__asn1_list_is_empty] The is empty parameter is null");
        return eBadArg;
    }

    // Get the number of elements of the list
    if ((rc = tlv_data_extractor__asn1_list_size(iterator, &num_elements)) != eOk) {
        LOGE("[tlv_data_extractor__asn1_list_is_empty] Error retrieving the number of elements og the List, rc %d", rc);
        return rc;
    }

    // Set the result
    *is_empty = 0 == num_elements;

    return eOk;
}

void tlv_data_extractor__asn1_list_reinit(asn1_list_iterator_t* iterator) {
    if (iterator) {
        iterator->current_offset = iterator->init_offset;
    }
}

ErrCode tlv_data_extractor__tlv_value_small_size_copy(unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, bool* tlv_is_present, uint8_t* out, uint8_t out_size, uint8_t* var_size) {
    uint32_t aux_var_size = 0;
    ErrCode rc;

    if (eOk == (rc = tlv_data_extractor__tlv_value_big_size_copy(tag, tlv, tlv_size, tlv_is_present, out, (uint32_t) out_size, var_size ? &aux_var_size : NULL))) {
        if (var_size) {
            *var_size = (uint8_t) aux_var_size;
        }
    }

    return rc;
}

ErrCode tlv_data_extractor__tlv_value_medium_size_copy(unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, bool* tlv_is_present, uint8_t* out, uint16_t out_size, uint16_t* var_size) {
    uint32_t aux_var_size = 0;
    ErrCode rc;

    if (eOk == (rc = tlv_data_extractor__tlv_value_big_size_copy(tag, tlv, tlv_size, tlv_is_present, out, (uint32_t) out_size, var_size ? &aux_var_size : NULL))) {
        if (var_size) {
            *var_size = (uint16_t) aux_var_size;
        }
    }
    
    return rc;
}

ErrCode tlv_data_extractor__tlv_value_big_size_copy(unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, bool* tlv_is_present, uint8_t* out, uint32_t out_size, uint32_t* var_size) {
    ErrCode rc;
    uint8_t* tlv_value_ref;
    uint32_t tlv_value_ref_size;

    /* Check input parameters */
    if (!out || 0 == out_size) {
        LOGE("[tlv_data_extractor__tlv_value_big_size_copy] out buffer is empty/null");
        return eBadArg;
    }

    /* Extract the TLV value */
    if ((rc = tlv_data_extractor__tlv_value_big_size_ref(tag, tlv, tlv_size, tlv_is_present, &tlv_value_ref, &tlv_value_ref_size)) != eOk) {
        LOGE("[tlv_data_extractor__tlv_value_big_size_copy] Error extracting the TLV value, rc %d", rc);
        return rc;
    }

    /* Check if the tlv is present */
    if (tlv_is_present && !(*tlv_is_present)) {
        return eOk; // If the tlv is not present we don't need to copy anything
    }

    /* Check lengths before copy */
    if (tlv_value_ref_size > out_size) {
        LOGE("[tlv_data_extractor__tlv_value_big_size_copy] TLV LENGTH (%u) is too large. Maximum length %u", tlv_value_ref_size, out_size);
        return eFatal;
    }

    if (var_size) {
        // The length to copy is variable
        *var_size = tlv_value_ref_size;
    } else {
        // The length to copy is fixed
        if (out_size != tlv_value_ref_size) {
            LOGE("[tlv_data_extractor__tlv_value_big_size_copy] The TLV LENGTH (%u) is not the expected. Expected length %u", tlv_value_ref_size, out_size);
            return eFatal;
        }
    }

    /* Copy the value */
    memcpy(out, tlv_value_ref, tlv_value_ref_size);

    return eOk;
}

ErrCode tlv_data_extractor__tlv_value_small_size_ref(unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, bool* tlv_is_present, uint8_t** out, uint8_t* out_size) {
    uint32_t aux_out_size;
    ErrCode rc;

    if (eOk == (rc = tlv_data_extractor__tlv_value_big_size_ref(tag, tlv, tlv_size, tlv_is_present, out, &aux_out_size))) {
        *out_size = (uint8_t) aux_out_size;
    }

    return rc;
}

ErrCode tlv_data_extractor__tlv_value_medium_size_ref(unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, bool* tlv_is_present, uint8_t** out, uint16_t* out_size) {
    uint32_t aux_out_size;
    ErrCode rc;

    if (eOk == (rc = tlv_data_extractor__tlv_value_big_size_ref(tag, tlv, tlv_size, tlv_is_present, out, &aux_out_size))) {
        *out_size = (uint16_t) aux_out_size;
    }

    return rc;
}

ErrCode tlv_data_extractor__tlv_value_big_size_ref(unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, bool* tlv_is_present, uint8_t** out, uint32_t* out_size) {
    return tlv_data_extractor__ref(tag, tlv, tlv_size, true, tlv_is_present, out, out_size);
}

ErrCode tlv_data_extractor__tlv_small_size_ref(unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, bool* tlv_is_present, uint8_t** out, uint8_t* out_size) {
    uint32_t aux_out_size;
    ErrCode rc;

    if (eOk == (rc = tlv_data_extractor__tlv_big_size_ref(tag, tlv, tlv_size, tlv_is_present, out, &aux_out_size))) {
        *out_size = (uint8_t) aux_out_size;
    }

    return rc;
}

ErrCode tlv_data_extractor__tlv_medium_size_ref(unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, bool* tlv_is_present, uint8_t** out, uint16_t* out_size) {
    uint32_t aux_out_size;
    ErrCode rc;

    if (eOk == (rc = tlv_data_extractor__tlv_big_size_ref(tag, tlv, tlv_size, tlv_is_present, out, &aux_out_size))) {
        *out_size = (uint16_t) aux_out_size;
    }

    return rc;
}

ErrCode tlv_data_extractor__tlv_big_size_ref(unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, bool* tlv_is_present, uint8_t** out, uint32_t* out_size) {
    return tlv_data_extractor__ref(tag, tlv, tlv_size, false, tlv_is_present, out, out_size);
}

ErrCode tlv_data_extractor__child_tag_tlv_small_size_ref(unsigned short parent_tag, const uint8_t* tlv, const uint32_t tlv_size, bool* tlv_is_present, unsigned short* child_tag, uint8_t** child_tlv, uint8_t* child_tlv_size) {
    uint32_t aux_child_tlv_size;
    ErrCode rc;

    if (eOk == (rc = tlv_data_extractor__child_tag_tlv_big_size_ref(parent_tag, tlv, tlv_size, tlv_is_present, child_tag, child_tlv, &aux_child_tlv_size))) {
        *child_tlv_size = (uint8_t) aux_child_tlv_size;
    }

    return rc;
}

ErrCode tlv_data_extractor__child_tag_tlv_medium_size_ref(unsigned short parent_tag, const uint8_t* tlv, const uint32_t tlv_size, bool* tlv_is_present, unsigned short* child_tag, uint8_t** child_tlv, uint16_t* child_tlv_size) {
    uint32_t aux_child_tlv_size;
    ErrCode rc;

    if (eOk == (rc = tlv_data_extractor__child_tag_tlv_big_size_ref(parent_tag, tlv, tlv_size, tlv_is_present, child_tag, child_tlv, &aux_child_tlv_size))) {
        *child_tlv_size = (uint16_t) aux_child_tlv_size;
    }

    return rc;
}

ErrCode tlv_data_extractor__tlv_value_is_empty(const unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, bool* value_is_empty) {
    ErrCode rc;
    uint8_t* tlv_value;
    uint32_t tlv_value_size;

    if ((rc = tlv_data_extractor__tlv_value_big_size_ref(tag, tlv, tlv_size, NULL, &tlv_value, &tlv_value_size)) != eOk) {
        LOGE("[tlv_data_extractor__tlv_value_is_empty] Error on extract the value of the TLV, rc %d", rc);
        return rc;
    }

    *value_is_empty = 0 == tlv_value_size;
    return eOk;
}

ErrCode tlv_data_extractor__child_tag_tlv_big_size_ref(unsigned short parent_tag, const uint8_t* tlv, const uint32_t tlv_size, bool* tlv_is_present, unsigned short* child_tag, uint8_t** child_tlv, uint32_t* child_tlv_size) {
    ErrCode rc;
    int tlv_offset;
    size_t tlv_value_offset;
    _BerTlv tlv_obj;

    /* Check input parameters */
    if (!tlv) {     // 0 tlv_size is a valid value only if the TLV to search is OPTIONAL, handled in the find function
        LOGE("[tlv_data_extractor__child_tlv_tag_value_big_size_ref] tlv is null");
        return eBadArg;
    }
    if (!child_tag) {
        LOGE("[tlv_data_extractor__child_tlv_tag_value_big_size_ref] child tag pointer is null");
        return eBadArg;
    }
    if (!child_tlv) {
        LOGE("[tlv_data_extractor__child_tlv_tag_value_big_size_ref] out buffer pointer is null");
        return eBadArg;
    }
    if (!child_tlv_size) {
        LOGE("[tlv_data_extractor__child_tlv_tag_value_big_size_ref] out buffer size pointer is null");
        return eBadArg;
    }
    LOG_DATA(eLogDebug, "[tlv_data_extractor__child_tlv_tag_value_big_size_ref] TLV", tlv, tlv_size);

    /* Search the parent TLV */
    tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, 0, parent_tag);
    if (tlv_offset < 0) {
        if (tlv_is_present) {
            // In this case the parent TLV is OPTIONAL we return ok
            LOGD("[tlv_data_extractor__child_tlv_tag_value_big_size_ref] TAG %04X is not present", parent_tag);
            *tlv_is_present = false;
            return eOk;
        } else {
            // In this case the parent TLV is REQUIRED we return an error
            LOGE("[tlv_data_extractor__child_tlv_tag_value_big_size_ref] TAG %04X not found", parent_tag);
            return eFatal;
        }
    }

    if (tlv_is_present) {
        *tlv_is_present = true; // If is a OPTIONAL TLV we put that we find it
    }

    /* Parse the child TLV */
    tlv_value_offset = ber_tlv_parser__get_value_offset(tlv, (size_t) tlv_offset);
    if ((rc = ber_tlv_parser__ber_tlv_2(tlv, tlv_size, tlv_value_offset, &tlv_obj)) != eOk) {
        LOGE("[tlv_data_extractor__child_tlv_tag_value_big_size_ref] Error parsing the child TLV, rc %d", rc);
        return rc;
    }

    /* Set the return parameters */
    *child_tag = tlv_obj.tag;
    *child_tlv = (uint8_t*) tlv + tlv_value_offset; // With the cast we lose the const qualifier in the out pointer, we need to see the implications of this
    *child_tlv_size = (uint32_t) tlv_obj.nTag + (uint32_t) tlv_obj.nLength + (uint32_t) tlv_obj.length;

    return eOk;
}

ErrCode tlv_data_extractor__subject_key_identifier(const unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, bool* tlv_is_present, subject_key_identifier_t* obj) {
    return tlv_data_extractor__tlv_value_small_size_copy(tag, tlv, tlv_size, tlv_is_present, obj->value, sizeof(obj->value), NULL);
}

ErrCode tlv_data_extractor__iccid(unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, bool* tlv_is_present, iccid_t* obj) {
    return tlv_data_extractor__tlv_value_small_size_copy(tag, tlv, tlv_size, tlv_is_present, obj->value, sizeof(obj->value), NULL);
}

ErrCode tlv_data_extractor__fqdn(unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, bool* tlv_is_present, fqdn_t* obj) {
    ErrCode rc;
    uint16_t fdqn_len;

    if ((rc = tlv_data_extractor__tlv_value_medium_size_copy(tag, tlv, tlv_size, tlv_is_present, (uint8_t*) obj->fqdn, sizeof(obj->fqdn) - 1, &fdqn_len)) != eOk) {
        LOGE("[tlv_data_extractor__fqdn] Error extracting the FQDN, rc %d", rc);
        return rc;
    }

    if (tlv_is_present && !(*tlv_is_present)) {
        LOGT("[tlv_data_extractor__fqdn] The FQDN TLV is not present");
    } else {
        obj->fqdn[fdqn_len] = '\0';
        LOGT("[tlv_data_extractor__fqdn] FQDN: '%s'", obj->fqdn);
    }

    return eOk;
}

ErrCode tlv_data_extractor__challenge(unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, challenge_t* obj) {
    return tlv_data_extractor__tlv_value_small_size_copy(tag, tlv, tlv_size, NULL, obj->challenge, sizeof(obj->challenge), NULL);
}

ErrCode tlv_data_extractor__transaction_id(unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, bool* tlv_is_present, transaction_id_t* obj) {
    return tlv_data_extractor__tlv_value_small_size_copy(tag, tlv, tlv_size, tlv_is_present, obj->transaction_id, sizeof(obj->transaction_id), &obj->transaction_id_size);
}

ErrCode tlv_data_extractor__operator_id(unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, operator_id_t* operator_id) {
    ErrCode rc;
    uint8_t* tlv_value;
    uint32_t tlv_value_size;

    /* Extract the TLV value */
    if ((rc = tlv_data_extractor__tlv_value_big_size_ref(tag, tlv, tlv_size, NULL, &tlv_value, &tlv_value_size)) != eOk) {
        LOGE("[tlv_data_extractor__operator_id] Error extracting the TLV value, rc %d", rc);
        return rc;
    }

    // Get mccMnc
    if ((rc = tlv_data_extractor__tlv_value_small_size_copy(CONTEXT_PRIMITIVE_0, tlv_value, tlv_value_size, NULL, operator_id->mcc_mnc.value, sizeof(operator_id->mcc_mnc.value), NULL)) != eOk) {
        LOGE("[tlv_data_extractor__operator_id] Error extracting the mccMnc of the OperatorId");
        return rc;
    }
    LOG_DATA(eLogDebug, "[tlv_data_extractor__operator_id] mccMnc", operator_id->mcc_mnc.value, sizeof(operator_id->mcc_mnc.value));

    // Get gid1
    if ((rc = tlv_data_extractor__tlv_value_big_size_ref(CONTEXT_PRIMITIVE_1, tlv_value, tlv_value_size, &operator_id->field_is_present.gid1, &operator_id->gid1, &operator_id->gid1_size)) != eOk) {
        LOGE("[tlv_data_extractor__operator_id] Error extracting the gid1 value, rc %d", rc);
        return rc;
    }
    if (operator_id->field_is_present.gid1) {
        LOG_DATA(eLogDebug, "[tlv_data_extractor__operator_id] gid1", operator_id->gid1, operator_id->gid1_size);
    } else {
        LOGD("[tlv_data_extractor__operator_id] gid1 TLV is not present in the OperatorId");
    }

    // Get gid2
    if ((rc = tlv_data_extractor__tlv_value_big_size_ref(CONTEXT_PRIMITIVE_2, tlv_value, tlv_value_size, &operator_id->field_is_present.gid2, &operator_id->gid2, &operator_id->gid2_size)) != eOk) {
        LOGE("[tlv_data_extractor__operator_id] Error extracting the gid2 value, rc %d", rc);
        return rc;
    }
    if (operator_id->field_is_present.gid2) {
        LOG_DATA(eLogDebug, "[tlv_data_extractor__operator_id] gid2", operator_id->gid2, operator_id->gid2_size);
    } else {
        LOGD("[tlv_data_extractor__operator_id] gid2 TLV is not present in the OperatorId");
    }

    return eOk;

}

/**
 * This function search a TLV in a buffer (only top level) and copy a reference of the full TLV or only the value in a pointer.
 * 
 * @param[in] tag TAG of the TLV to find.
 * @param[in] tlv Pointer to a buffer where the TLV will be searched (only TLVs in the top level will be searched).
 * @param[in] tlv_size Size of the tlv buffer.
 * @param[in] value True if only the value of the TLV to be searched will be extracted, false if all the TLV (including tag and length) to be searched will be extracted.
 * @param[in, out] tlv_is_present Pointer to a boolean that will indicate if the TLV was found or not in case the function return is success.
 * If a NULL value is passed, an error will be returned in case the TLV is not found (useful for non-optional TLVs).
 * @param[out] out Pointer that will point to the full tlv or the tlv value of the tlv found (inside the tlv buffer) in case the function return is success.
 * @param[out] out_size Pointer to an integer that will indicate the length of the out data in case the function return is success.
 * 
 * @return eOk in case the function execution is success. Otherwise, an error code is returned.
*/
static ErrCode tlv_data_extractor__ref(unsigned short tag, const uint8_t* tlv, const uint32_t tlv_size, const bool value, bool* tlv_is_present, uint8_t** out, uint32_t* out_size) {
    ErrCode rc;
    int tlv_offset;
    _BerTlv tlv_obj;

    /* Check input parameters */
    if (!tlv) {     // 0 tlv_size is a valid value only if the TLV to search is OPTIONAL, handled in the find function
        LOGE("[tlv_data_extractor__ref] tlv is null");
        return eBadArg;
    }
    if (!out) {
        LOGE("[tlv_data_extractor__ref] out buffer pointer is null");
        return eBadArg;
    }
    if (!out_size) {
        LOGE("[tlv_data_extractor__ref] out buffer size pointer is null");
        return eBadArg;
    } 

    LOG_DATA(eLogDebug, "[tlv_data_extractor__ref] TLV", tlv, tlv_size);

    /* Search the TLV */
    tlv_offset = ber_tlv_parser__find_tlv_by_tag_2(tlv, tlv_size, 0, tag);
    if (tlv_offset < 0) {
        if (tlv_is_present) {
            // In this case the TLV is OPTIONAL we return ok
            LOGD("[tlv_data_extractor__ref] TAG %04X is not present", tag);
            *tlv_is_present = false;
            return eOk;
        } else {
            // In this case the TLV is REQUIRED we return an error
            LOGE("[tlv_data_extractor__ref] TAG %04X not found", tag);
            return eFatal;
        }
    }

    /* Parse the TLV */
    if (tlv_is_present) {
        *tlv_is_present = true; // If is a OPTIONAL TLV we put that we find it
    }
    if ((rc = ber_tlv_parser__ber_tlv_2(tlv, tlv_size, (size_t) tlv_offset, &tlv_obj)) != eOk) {
        LOGE("[tlv_data_extractor__ref] Error parsing the TLV with TAG %04X, rc %d", tag, rc);
        return rc;
    }

    /* Set the reference to return, the value or the full tlv */
    if (value) {
        // In case we want to return the value
        *out = (uint8_t*) tlv + tlv_offset + tlv_obj.nTag + tlv_obj.nLength; // With the cast we lose the const qualifier in the out pointer, we need to see the implications of this
        *out_size = (uint32_t) tlv_obj.length;
    } else {
        // In case we want to return the full tlv
        *out = (uint8_t*) tlv + tlv_offset; // With the cast we lose the const qualifier in the out pointer, we need to see the implications of this
        *out_size = (uint32_t) tlv_obj.nTag + (uint32_t) tlv_obj.nLength + (uint32_t) tlv_obj.length;
    }

    return eOk;
}