/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "typedefs.h"
#include "tlv_lengths.h"
#define FQDN_MAX_LEN 255
#define nullptr 	NULL
#define REFRESH_FLAG true

typedef enum  {
	eOk = 0,
	eFatal = 1,
	eNotSupported = 2,
	eNotImpl = 3,
	eBadArg = 4,
	eJsonParseError = 5,
	eSessionCancelled = 6,
	eNotEnoughBuffer = 7,
	eNoData = 8,
	eNoMem = 9,
	eSimBusy = 10,
	eInvalidFormat = 11
} ErrCode;


typedef struct asn1_list_iterator_s {
    unsigned short elem_tag;
    uint8_t* asn1_list_tlv;
    uint32_t asn1_list_tlv_size;
    uint32_t init_offset;
    uint32_t current_offset;
} asn1_list_iterator_t;

typedef struct version_type_s {
	uint8_t major;
	uint8_t minor;
	uint8_t revision;
} version_type_t;

typedef struct fqdn_s {
	char fqdn[FQDN_MAX_LEN + 1];
} fqdn_t;

typedef struct subject_key_identifier_s {
	uint8_t value[SUBJECT_KEY_IDENTIFIER_SIZE];
} subject_key_identifier_t;

typedef struct transaction_id_s {
	uint8_t transaction_id[TRANSACION_ID_MAX_SIZE];
	uint8_t transaction_id_size;
} transaction_id_t;

typedef struct isdp_aid_s {
	uint8_t value[ISDP_AID_SIZE];
} isdp_aid_t;

typedef struct iccid_s {
	uint8_t value[ICCID_SIZE];
} iccid_t;

typedef struct eid_s {
    uint8_t eid[OCTET16];
} eid_t;

typedef struct challenge_s {
    uint8_t challenge[OCTET16];
} challenge_t;
