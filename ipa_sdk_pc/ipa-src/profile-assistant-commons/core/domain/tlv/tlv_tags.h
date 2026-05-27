/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"

#define  ASN1_DER_BOOLEAN				(uint8_t)0x01
#define  ASN1_DER_INTEGER				(uint8_t)0x02
#define  ASN1_DER_BIT_STRING			(uint8_t)0x03
#define  ASN1_DER_OCTET_STRING			(uint8_t)0x04
#define  ASN1_DER_NULL					(uint8_t)0x05
#define  ASN1_DER_OBJ_IDENTIFIER		(uint8_t)0x06
#define  ASN1_DER_SEQUENCE				(uint8_t)0x30
#define  ASN1_DER_UTF8_STRING			(uint8_t)0x0C
#define  ASN1_DER_PRNT_STRING			(uint8_t)0x13
#define  ASN1_CLASS_CONTEXT_SPECIFIC 	(uint8_t)0x80
#define  ASN1_CLASS_APP_SPECIFIC		(uint8_t)0x40
#define  ASN1_TYPE_CONSTRUCTED			(uint8_t)0x20
#define  ASN1_DER_BOOL_TRUE				(uint8_t)0xFF
#define  ASN1_DER_BOOL_FALSE			(uint8_t)0x00

#define CONTEXT_PRIMITIVE_0  		ASN1_CLASS_CONTEXT_SPECIFIC
#define CONTEXT_PRIMITIVE_1  		(uint8_t)(ASN1_CLASS_CONTEXT_SPECIFIC | 1)
#define CONTEXT_PRIMITIVE_2  		(uint8_t)(ASN1_CLASS_CONTEXT_SPECIFIC | 2)
#define CONTEXT_PRIMITIVE_3  		(uint8_t)(ASN1_CLASS_CONTEXT_SPECIFIC | 3)
#define CONTEXT_PRIMITIVE_4  		(uint8_t)(ASN1_CLASS_CONTEXT_SPECIFIC | 4)

#define CONTEXT_CONSTRUCTED_0  		(uint8_t)(ASN1_CLASS_CONTEXT_SPECIFIC | ASN1_TYPE_CONSTRUCTED)
#define CONTEXT_CONSTRUCTED_1  		(uint8_t)(ASN1_CLASS_CONTEXT_SPECIFIC | ASN1_TYPE_CONSTRUCTED | 1)
#define CONTEXT_CONSTRUCTED_2  		(uint8_t)(ASN1_CLASS_CONTEXT_SPECIFIC | ASN1_TYPE_CONSTRUCTED | 2)
#define CONTEXT_CONSTRUCTED_3  		(uint8_t)(ASN1_CLASS_CONTEXT_SPECIFIC | ASN1_TYPE_CONSTRUCTED | 3)

#ifndef SKIP_TERMINAL_CAPABILITY
#define TERMINAL_CAPABILITY          (uint8_t)0xA9
#if defined(FORCE_TERMINAL_CAPABILITY_SGP22)
#define EUICC_RELATED_CAPABILITIES   (uint8_t)0x83
#elif defined(FORCE_TERMINAL_CAPABILITY_SGP32)
#define EUICC_RELATED_CAPABILITIES   (uint8_t)0x84
#elif defined(SGP22)
#define EUICC_RELATED_CAPABILITIES   (uint8_t)0x83
#elif defined(SGP32) 
#define EUICC_RELATED_CAPABILITIES   (uint8_t)0x84
#else
#error "Only SGP22 or SGP32 are supported"
#endif
#endif
#define ISDR_PROPR_APP_TEMPLATE      (uint8_t)0xE0

#define EUICC_INFO_1					    (unsigned short)0xBF20
#define PREPARE_DOWNLOAD_REQUEST 		    (unsigned short)0xBF21
#define EUICC_INFO_2					    (unsigned short)0xBF22
#define INIT_SECURE_CHANNEL				    (unsigned short)0xBF23
#define CONFIGURE_ISDP					    (unsigned short)0xBF24
#define STORE_METADATA					    (unsigned short)0xBF25
#define REPLACE_SESSION_KEY_RESP  		    (unsigned short)0xBF26
#define PROFILE_INSTALLATION_RESULT_DATA    (unsigned short)0xBF27
#define LIST_NOTIFICATION				    (unsigned short)0xBF28
#define SET_NICKNAME					    (unsigned short)0xBF29
#define UPDATE_METADATA					    (unsigned short)0xBF2A
#define RETRIEVE_NOTIF_LIST				    (unsigned short)0xBF2B
#define PROFILE_INFO_LIST				    (unsigned short)0xBF2D
#define GET_EUICC_CHALLENGE				    (unsigned short)0xBF2E
#define NOTIFICATION_METADATA			    (unsigned short)0xBF2F
#define NOTIFICATION_SENT				    (unsigned short)0xBF30
#define ENABLE_PROFILE					    (unsigned short)0xBF31
#define DISABLE_PROFILE					    (unsigned short)0xBF32
#define DELETE_PROFILE					    (unsigned short)0xBF33
#if defined(SGP22)
#define EUICC_MEMORY_RESET				    (unsigned short)0xBF34
#elif defined(SGP32) 
#define EUICC_MEMORY_RESET				    (unsigned short)0xBF64
#else
#error "Only SGP22 or SGP32 are supported"
#endif
#define LOAD_CRL						    (unsigned short)0xBF35
#define BOUND_PROFILE_PKG				    (unsigned short)0xBF36
#define PROFILE_INSTALLATION_RESULT         (unsigned short)0xBF37
#define AUTHENTICATE_SERVER				    (unsigned short)0xBF38
#define INITIATE_AUTHENTICATION			    (unsigned short)0xBF39
#define GET_BOUND_PROFILE_PACKAGE		    (unsigned short)0xBF3A
#define AUTHENTICATE_CLIENT				    (unsigned short)0xBF3B
#define EUICC_CONFIGURED_ADDRESSES  	    (unsigned short)0xBF3C
#define HANDLE_NOTIFICATION				    (unsigned short)0xBF3D
#define GET_EUICC_DATA					    (unsigned short)0xBF3E
#if defined(SGP22)
#define SET_DEFAULT_SMDP_ADDRESS		    (unsigned short)0xBF3F
#elif defined(SGP32) 
#define SET_DEFAULT_SMDP_ADDRESS		    (unsigned short)0xBF65
#else
#error "Only SGP22 or SGP32 are supported"
#endif
#define AUTHENTICATE_CLIENT_RESPONSE_ES11       (unsigned short)0xBF40
#define CANCEL_SESSION					        (unsigned short)0xBF41
#define GET_RAT							        (unsigned short)0xBF43
#define TRANSFER_EIM_PACKAGE                    (unsigned short)0xBF4E
#define GET_EIM_PACKAGE                         (unsigned short)0xBF4F
#define PROVIDE_EIM_PACKAGE_RESULT              (unsigned short)0xBF50
#define EUICC_PACKAGE                           (unsigned short)0xBF51
#define IPA_EUICC_DATA                          (unsigned short)0xBF52
#define EIM_ACKNOWLEDGEMENTS                    (unsigned short)0xBF53
#define PROFILE_DOWNLOAD_TRIGGER                (unsigned short)0xBF54
#define GET_EIM_CONFIGURATION_DATA              (unsigned short)0xBF55
#define GET_CERTS                               (unsigned short)0xBF56
#define ADD_INITIAL_EIM                         (unsigned short)0xBF57
#define PROFILE_ROLLBACK                        (unsigned short)0xBF58
#define CONFIGURE_IMMEDIATE_PROFILE_ENABLING    (unsigned short)0xBF59
#define IMMEDIATE_ENABLE                        (unsigned short)0xBF5A
#define ENABLE_EMERGENCY_PROFILE                (unsigned short)0xBF5B
#define DISABLE_EMERGENCY_PROFILE               (unsigned short)0xBF5C
#define EXECUTE_FALLBACK_MECHANISM              (unsigned short)0xBF5D
#define RETURN_FROM_FALLBACK                    (unsigned short)0xBF5E
#define PROFILE_INFO					        (unsigned short)0xE3

#define REPLACE_SESSION_KEY_CMD			(unsigned short)0x9F26
#define ERROR_CODE_UNPROTECTED			(unsigned short)0x9F47
#define ERROR_CODE						(unsigned short)0x9F46
#define SIGNATURE					    (unsigned short)0x5F37
#define OT_PK_EUICC					    (unsigned short)0x5F49

#define PROFILE_INFO_STATE				(unsigned short)0x9F70
#define PROFILE_INFO_NICKNAME			(uint8_t)0x90
#define PROFILE_INFO_PROV_NAME			(uint8_t)0x91
#define PROFILE_INFO_NAME				(uint8_t)0x92
#define PROFILE_INFO_ICON_TYPE			(uint8_t)0x93
#define PROFILE_INFO_ICON				(uint8_t)0x94
#define PROFILE_INFO_CLASS				(uint8_t)0x95
#define PROFILE_INFO_NOTIF_CONFIG		(uint8_t)0xB6
#define PROFILE_INFO_OWNER				(uint8_t)0xB7
#define PROFILE_INFO_SMDP_DATA			(uint8_t)0xB8
#define PROFILE_INFO_PPRS				(uint8_t)0x99
#ifdef SGP32
#define PROFILE_INFO_ECALL_INDICATION	(unsigned short)0x9F7B
#define PROFILE_INFO_FALLBACK_ATTRIBUTE	(unsigned short)0x9F26
#define PROFILE_INFO_FALLBACK_ALLOWED	(unsigned short)0x9F67
#endif

#define TAG_LIST						(uint8_t)0x5C
#define EID								(uint8_t)0x5A

#define TRANSACTION_ID				(uint8_t)0x80
#define REMOTE_OPERATION_ID			(uint8_t)0x82
#define SMDP_OID					(uint8_t)0x06
#define CONTROL_REF_TEMPLATE		(uint8_t)0xA6
#define AID					        (uint8_t)0x4F
#define ICCID						(uint8_t)0x5A
#define MEMORY_RESET_OPTIONS 		(uint8_t)0x82
#define PROFILE_INFO_TAG			(uint8_t)0xE3
#define PROFILE_INFO_TAG_NO			(uint8_t)0x03

#define SCP03T_PAYLOAD_LOAD_PROFILE_PACKAGE		(uint8_t)0x86
#define SCP03T_PAYLOAD_CONF_ISDP				(uint8_t)0x87
#define SCP03T_PAYLOAD_REPLACE_SESSION_KEYS		(uint8_t)0x87
#define SCP03T_PAYLOAD_STORE_METADATA			(uint8_t)0x88

#define BPP_FIRST_SEQ_87					(uint8_t)0xA0
#define BPP_SEQ_88							(uint8_t)0xA1
#define BPP_SECOND_SEQ_87					(uint8_t)0xA2
#define BPP_SEQ_86							(uint8_t)0xA3

// EUICCINFO1
#define CIPKID_LIST_FOR_VERIFICATION		(uint8_t)0xA9
#define CIPKID_LIST_FOR_SIGNING				(uint8_t)0xAA

// EUICCINFO2
#define EXT_CARD_RES					(uint8_t)0x84
#define UICC_CAPABILITY					(uint8_t)0x85
#define JAVACARD_VER					(uint8_t)0x86
#define GP_VERSION						(uint8_t)0x87
#define RSP_CAPABILITY					(uint8_t)0x88
#define EUICC_CATEGORY					(uint8_t)0x8B
#define FORBIDDEN_PPRS					(uint8_t)0x99
#define CERT_DATA_OBJECT				(uint8_t)0xAC

#define REMOTE_PROF_PROV_REQUEST		(uint8_t)0xA2

//PSMO
#define PSMO_ENABLE     (uint8_t)(ASN1_CLASS_CONTEXT_SPECIFIC | ASN1_TYPE_CONSTRUCTED | 3)
#define PSMO_DISABLE    (uint8_t)(ASN1_CLASS_CONTEXT_SPECIFIC | ASN1_TYPE_CONSTRUCTED | 4)
#define PSMO_DELETE     (uint8_t)(ASN1_CLASS_CONTEXT_SPECIFIC | ASN1_TYPE_CONSTRUCTED | 5)
#define PSMO_GET_RAT    (uint8_t)(ASN1_CLASS_CONTEXT_SPECIFIC | ASN1_TYPE_CONSTRUCTED | 6)

//IpaEuiccData
#define IPA_EUICC_DATA_LIST_OF_NOTIF        (uint8_t)0xA0
#define IPA_EUICC_DATA_DEFAULT_SMDP         (uint8_t)0x81
#define IPA_EUICC_DATA_EUICC_PKG_RESULTS    (uint8_t)0xA2
#define IPA_EUICC_DATA_ROOT_SMDS            (uint8_t)0x83
#define IPA_EUICC_DATA_ASSOCIATION_TOKEN    (uint8_t)0x84
#define IPA_EUICC_DATA_EUM_CERT             (uint8_t)0xA5
#define IPA_EUICC_DATA_EUICC_CERT           (uint8_t)0xA6
#define IPA_EUICC_DATA_EIM_TRANSACTION_ID   (uint8_t)0x87
#define IPA_EUICC_DATA_IPA_CAPABILITES      (uint8_t)0xA8
#define IPA_EUICC_DATA_DEVICE_INFO          (uint8_t)0xA9

//ProfileDownloadTrigger
#define PROFILE_DOWNLOAD_TRIGGER_EIM_TRANSACTION_ID     (uint8_t)0x82
#define PROFILE_DOWNLOAD_DATA                           (uint8_t)0xA0
#define PROFILE_DOWNLOAD_DATA_ACTIVATION_CODE           (uint8_t)0x80
#define PROFILE_DOWNLOAD_DATA_CONTACT_DEFAULT_SMDP      (uint8_t)0x81
#define PROFILE_DOWNLOAD_DATA_CONTACT_SMDS              (uint8_t)0xA2

//InitiateAuthentication
#define INITIATE_AUTHENTICATION_OK_ESIPA                    (uint8_t)0xA0
#define INITIATE_AUTHENTICATION_OK_ESIPA_TRANSACTION_ID     (uint8_t)0x80
#define INITIATE_AUTHENTICATION_ERROR_ESIPA                 (uint8_t)0x81
#define EUICC_CI_PK_ID                                      (uint8_t)0x04

//AuthenticateClient
#define AUTHENTICATE_CLIENT_OK_DP_ESIPA                     (uint8_t)0xA0
#define AUTHENTICATE_CLIENT_OK_DS_ESIPA                     (uint8_t)0xA1
#define AUTHENTICATE_CLIENT_ERROR_ESIPA                     (uint8_t)0x82
#define AUTHENTICATE_CLIENT_OK_ESIPA_TRANSACTION_ID         (uint8_t)0x80
#define HASH_CC				                                (uint8_t)0x04

//GetBoundProfilePackage
#define GET_BOUND_PROFILE_PACKAGE_OK_ESIPA                  (uint8_t)0xA0
#define GET_BOUND_PROFILE_PACKAGE_ERROR_ESIPA               (uint8_t)0x81

//CtxParams1
#define CTX_PARAMS_1                (uint8_t)0xA0
#define CTX_PARAMS_1_MATCHING_ID    (uint8_t)0x80
#define CTX_PARAMS_1_DEVICE_INFO    (uint8_t)0xA1

#ifdef SGP32
//Certificates
#define EUM_CERTIFICATE             (uint8_t)0xA5
#define EUICC_CERTIFICATE           (uint8_t)0xA6

// EimConfigurationData
#define EIM_CONF_EIM_ID                         (uint8_t) 0x80
#define EIM_CONF_EIM_FQDN                       (uint8_t) 0x81
#define EIM_CONF_EIM_ID_TYPE                    (uint8_t) 0x82
#define EIM_CONF_COUNTER_VALUE                  (uint8_t) 0x83
#define EIM_CONF_ASSOCIATION_TOKEN              (uint8_t) 0x84
#define EIM_CONF_EIM_PUBLIC_KEY_DATA            (uint8_t) 0xA5
#define EIM_CONF_EIM_PUBLIC_KEY                 (uint8_t) 0xA0
#define EIM_CONF_EIM_CERTIFICATE                 (uint8_t) 0xA1
#define EIM_CONF_TRUSTED_PUBLIC_KEY_DATA_TLS    (uint8_t) 0xA6
#define EIM_CONF_TRUSTED_EIM_PK_TLS             (uint8_t) 0xA0
#define EIM_CONF_TRUSTED_CERTIFICATE_TLS        (uint8_t) 0xA1
#define EIM_CONF_EIM_SUPPORTED_PROTOCOL         (uint8_t) 0x87
#define EIM_CONF_EUICC_CI_PK_ID                 (uint8_t) 0x88
#define EIM_CONF_INDIRECT_PROFILE_DOWNLOAD      (uint8_t) 0x89
#endif
