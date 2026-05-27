/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"
#include "es9_typedefs.h"
#include "es11_typedefs.h"

/**
 * This function extracts the ES11.AuthenticateClient JSON response.
 * 
 * @param[in]  json string in JSON format (can be not null-terminated).
 * @param[in]  json_len length of the json string (excluding the null-terminated character).
 * @param[out] obj Pointer to a authenticate_client_response_es11_t structure. The structure is populated following its 
 * documentation with the data from the json string if the function return is success. The structure data may be 
 * referencing data from the json string, do not deallocate the json string while using the structure.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, an error code is returned.
*/
ErrCode es11_json_extractor__authenticate_client_response(unsigned char* json, uint32_t json_len, authenticate_client_response_es11_t* obj);

/**
 * This function gets the next element of the EventEntries List.
 * 
 * @param[in]  it Pointer to a json_array_iterator_t structure initialized in the es11_json_extractor__authenticate_client_response() call.
 * @param[out] obj Pointer to a event_entry_t structure. This structure will be populated with the next EventEntry from the 
 * EventEntries List if the function return is success. The structure data may be referencing data from the main json string, 
 * do not deallocate the json string while using the structure.
 * 
 * @return eOk in case the extraction has been done successfully. 
 * eNoData in case there is no next EventEntry in the EventEntries List.
 * Otherwise, another error code is returned.
*/
ErrCode es11_json_extractor__get_next_event_entry(json_array_iterator_t* it, event_entry_t* obj);

/**
 * This function returns the number of elements in the EventEntries List.
 * 
 * @param[in]  it Pointer to a json_array_iterator_t structure initialized in the es11_json_extractor__authenticate_client_response() call.
 * @param[out] list_size Will point to the number of elements of the EventEntries List if the function return is success.
 * 
 * @return eOk in case the extraction has been done successfully. Otherwise, another error code is returned.
*/
ErrCode es11_json_extractor__get_event_entry_list_size(json_array_iterator_t* it, uint32_t* list_size);
