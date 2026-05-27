/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 * 
 *  @file esipa.h
 *  @brief This file implements the common behavior of the interface ESipa.
 *  
 *  This file contains the representation of the ESipa class. This class must be inherited by other 
 *  subclasses that implement and manage a specific ESipa communication protocol. 
 * 
 *  All procedures not related to a specific communication protocol or sync/async behaviours, must be executed in this file.
 * 
 *  @author Giesecke+Devrient Mobile Security
 *  @bug No known bugs.
 */
#pragma once
#include "typedefs.h"
#include "esipa_typedefs.h"
#include "timer.h"

struct esipa_vtbl_s; /* forward declaration */

/* ESipa attributes */
typedef struct {
    struct esipa_vtbl_s const *vptr; // ESipa Virtual Pointer to abstract functions
    uint8_t* eim_id;        // Not used in this version
    uint8_t eim_id_size;    // Not used in this version
    char* fqdn; // eIM hostname
    int port;       // eIM port
    gsma_data_binding_t data_binding;
    uint8_t* trusted_certificate_tls;       // Not used in this version 
    uint32_t trusted_certificate_tls_size;  // Not used in this version
    clock_data_t last_transmission;
    esipa_message_from_ipa_to_eim_choice_t last_message_sent;
} esipa_t;

// Esipa Virtual table with the pointers to the virtual functions (interface) of ESipa
struct esipa_vtbl_s {
    // Function to initialize the ESipa instance
    ErrCode(*esipa_init) (esipa_t* const me);
};

/**
 * This function creates an ESipa instance.
 * This function should be called only by an ESipa subclass.
 * See also esipa__destroy().
 * 
 * @param[out] me A pointer to a esipa_t structure. The object is populated with a valid ESipa instance.
 * @param[in] eim_id Points to a byte array with the eimId of the eIM. Not used in this version.
 * @param[in] eim_id_size Size of the eim_id byte array.
 * @param[in] fqdn A null-terminated string with the FQDN of eIM or intermediate server.
 * @param[in] port Port of the eIM or intermediate server.
 * @param[in] data_binding Format to be used to exchange data with the eIM. Currently only ASN.1 is supported.
 * @param[in] trusted_certificate_tls Points to a byte array with either the certificate of eIM, used for (D)TLS, 
 * or the certificate of the CA, where the encoding follows X.509 standard.
 * @param[in] trusted_certificate_tls_size Size of the trusted_certificate_tls byte array.
 * 
 * @return This function does not return any value.
*/
void esipa__ctor(esipa_t * const me, uint8_t* eim_id, uint8_t eim_id_size, char* fqdn, int port, gsma_data_binding_t data_binding, uint8_t* trusted_certificate_tls, uint32_t trusted_certificate_tls_size);

/**
 * This function is used to deallocate possible memory allocations made in esipa__destroy().
 * This function SHALL be called if the esipa__ctor() function has been called previously.
 * This function should be called only by an ESipa subclass.
 * 
 * @param[in] me A valid ESipa handle from a successful call to esipa__ctor().
 * 
 * @return This function does not return any value.
*/
void esipa__destroy(esipa_t * const me);

/**
 * This function initialize the Esipa instance.
 * 
 * @param[in] me A valid ESipa handle from a successful call to esipa__ctor().
 * 
 * @return eOk in case the init flow has been executed correctly. Otherwise, an error code is returned.
*/
ErrCode esipa__init(esipa_t* const me);

/**
 * This function updates the value of the last ESipa transmission to the current time.
 * This function must be called just after sending/receiving a message to the eIM.
 * This function should be called only by an ESipa subclass.
 * 
 * @param[in] me A valid ESipa handle from a successful call to esipa__ctor().
 * 
 * @return eOk in case the last transmission clock is updated successfully. Otherwise, an error code is returned.
*/
ErrCode esipa__update_last_transmission(esipa_t* const me);

/**
 * This function returns the clock value of the last ESipa transmission.
 * 
 * @param[in] me A valid ESipa handle from a successful call to esipa__ctor().
 * @param[out] last_transmission A pointer to a clock_data_t structure. The object is populated with 
 * the last ESipa transmission value if the function return is success.
 * 
 * @return eOk in case the last transmission structure is populated successfully. Otherwise, an error code is returned.
*/
ErrCode esipa__get_last_transmission(esipa_t* const me, clock_data_t* last_transmission);

/**
 * This function returns the data binding configured in the ESipa instance.
 * 
 * @param[in] me A valid ESipa handle from a successful call to esipa__ctor().
 * 
 * @return The data binding configured in the ESipa instance.
*/
gsma_data_binding_t esipa__get_data_binding(esipa_t* const me);

/**
 * This function returns the fqdn configured in the ESipa instance.
 * 
 * @param[in] me A valid ESipa handle from a successful call to esipa__ctor().
 * 
 * @return The fqdn configured in the ESipa instance.
 * The returned pointer is the same as the one passed in the constructor, so the function is not returning a copy in a new memory allocation.
*/
const char* esipa__get_fqdn(esipa_t* const me);

/**
 * This function updates the last ESipa message type sent.
 * This function must be called just after sending a message to the eIM.
 * This function should be called only by an ESipa subclass.
 * 
 * @param[in] me A valid ESipa handle from a successful call to esipa__ctor().
 * @param[in] last_message_sent Last message type sent through ESipa interface.
 * 
 * @return This function does not return any value.
*/
void esipa__set_last_message_sent(esipa_t* const me, esipa_message_from_ipa_to_eim_choice_t last_message_sent);

/**
 * This function returns the last ESipa message type sent.
 * 
 * @param[in] me A valid ESipa handle from a successful call to esipa__ctor().
 * 
 * @return last ESipa message type sent.
*/
esipa_message_from_ipa_to_eim_choice_t esipa__get_last_message_sent(esipa_t* const me);

/**
 * This function populates the structure used to send a GetEimPackageRequest message to the eIM.
 * 
 * @param[in] me A valid ESipa handle from a successful call to esipa__ctor().
 * @param[out] out A pointer to a get_eim_package_request_t structure. The object is populated with 
 * the appropriate data to send a GetEimPackageRequest message to the eIM configured in the ESipa instance.
 * 
 * @return eOk in case the GetEimPackageRequest structure is populated successfully. Otherwise, an error code is returned.
*/
ErrCode esipa__get_eim_package_request(esipa_t* const me, get_eim_package_request_t* out);

/**
 * This function process a ProvideEimPackageResultResponse message.
 * @note This function is defined in this class because the content of the message received does not affect the content of the message to be sent.
 * 
 * @param[in] in A pointer to a provide_eim_package_result_response_t structure from a successful call to esipa_data_binding__extract_provide_eim_package_result_response().
 * 
 * @return eOk in case the ProvideEimPackageResultResponse is processed successfully. Otherwise, an error code is returned.
*/
ErrCode esipa__execute_provide_eim_package_result_response(provide_eim_package_result_response_t* in);

#ifdef IPA_FEATURE_INDIRECT_DOWNLOAD
/**
 * This function process a CancelSessionResponseEsipa message.
 * @note This function is defined in this class because the content of the message received does not affect the content of the message to be sent.
 * 
 * @param[in] me A valid ESipa handle from a successful call to esipa__ctor().
 * @param[in] message Points to a byte array with the content of the CancelSessionResponseEsipa message.
 * @param[in] message_size Size of the message byte array.
 * 
 * @return eOk in case the CancelSessionResponseEsipa is processed successfully. Otherwise, an error code is returned.
*/
ErrCode esipa__execute_cancel_session_response_esipa(esipa_t* const me, const uint8_t* message, const uint32_t message_size);
#endif

/**
 * This function populates the EimPackageResult structure with an error.
 * Therefore, the choice of the EimPackageResult will be either eimPackageResultErrorCode or eimPackageResultResponseError 
 * depending on whether the transactionId appears in the request.
 * 
 * @param[in] request Points to a valid get_eim_package_response_t structure from a successful call to esipa_data_binding__extract_get_eim_package_response().
 * @param[in] error EimPackageResultErrorCode to set in the EimPackageResult.
 * @param[out] out A pointer to a eim_package_result_t structure. The object is populated with 
 * the appropriate data to send a EimPackageResult message with an error to the eIM if the function return is success.
 * 
 * @return eOk in case the EimPackageResult is processed successfully. Otherwise, an error code is returned.
*/
ErrCode esipa__set_eim_package_result_response_error(const get_eim_package_response_t* request, const eim_package_error_from_ipa_to_eim_t error, eim_package_result_t* out);

/**
 * This function updates the ProvideEimPackageResult by adding the EID if necessary.
 * 
 * @param[in, out] in Points to a valid provide_eim_package_result_t structure.
 * 
 * @return eOk in case the eidValue (OPTIONAL) is set into the ProvideEimPackageResult (whether the eidValue is present or not) successfully. Otherwise, an error code is returned.
*/
ErrCode esipa__set_provide_eim_package_result_eid_value(provide_eim_package_result_t* obj);
