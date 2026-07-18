#ifndef IPA_EUICC_EXECUTOR_H
#define IPA_EUICC_EXECUTOR_H

#include <stdbool.h>
#include <stddef.h>

typedef struct ipa_euicc_executor ipa_euicc_executor_t;

int ipa_euicc_executor_create(ipa_euicc_executor_t **out);
int ipa_euicc_executor_begin(ipa_euicc_executor_t *executor);
void ipa_euicc_executor_end(ipa_euicc_executor_t *executor);
void ipa_euicc_executor_request_stop(ipa_euicc_executor_t *executor);
void ipa_euicc_executor_reset(ipa_euicc_executor_t *executor);
void ipa_euicc_executor_destroy(ipa_euicc_executor_t *executor);

bool ipa_checked_size_add(size_t left, size_t right, size_t *out);
bool ipa_checked_size_multiply(size_t left, size_t right, size_t *out);

#endif
