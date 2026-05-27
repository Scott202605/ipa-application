/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#pragma once
#include "typedefs.h"
/****************************** MACROS ******************************/
#define SHA256_BLOCK_SIZE 32            // SHA256 outputs a 32 byte digest

/**************************** DATA TYPES ****************************/
typedef struct sha256_hash_s {
	uint8_t hash[SHA256_BLOCK_SIZE];
} sha256_hash_t;

typedef struct sha_256_ctx_s {
	uint8_t data[64];
	uint32_t datalen;
	unsigned long long bitlen;
	uint32_t state[8];
} sha_256_ctx_t;

/*********************** FUNCTION DECLARATIONS **********************/
/**
 * Initialise SHA-256 algorithm.
 * 
 * @param[in, out] ctx SHA-256 context.
*/
void sha256_init(sha_256_ctx_t* ctx);

/**
 * Accumulate data with SHA-256 algorithm.
 * 
 * @param[in] ctx SHA-256 context from a successful call to sha256_init().
 * @param[in] data Pointer to the data to accumulate.
 * @param[in] len Size of the data to accumulate.
*/
void sha256_update(sha_256_ctx_t* ctx, const uint8_t data[], size_t len);

/**
 * Calculate SHA-256 digest of accumulated data.
 * 
 * @param[in]  ctx SHA-256 context from a successful call to sha256_update().
 * @param[out] hash Pointer to a sha256_hash_t structure with the output buffer of the hash.
*/
void sha256_final(sha_256_ctx_t* ctx, sha256_hash_t* hash);
