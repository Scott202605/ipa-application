#ifndef IPA_DIAGNOSTICS_H
#define IPA_DIAGNOSTICS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define IPA_DIAGNOSTICS_CAPACITY 32
#define IPA_DIAGNOSTICS_TEXT_SIZE 32

typedef enum {
  IPA_SENSITIVE_NONE,
  IPA_SENSITIVE_EID,
  IPA_SENSITIVE_ICCID,
  IPA_SENSITIVE_PASSWORD,
  IPA_SENSITIVE_PSK,
  IPA_SENSITIVE_CERTIFICATE
} ipa_sensitive_kind_t;

typedef struct {
  uint64_t correlation_id;
  char module[IPA_DIAGNOSTICS_TEXT_SIZE];
  char phase[IPA_DIAGNOSTICS_TEXT_SIZE];
  int native_code;
  int system_errno;
  uint32_t task_id;
  int protocol;
  bool retryable;
  bool cleanup_complete;
} ipa_diagnostic_entry_t;

typedef struct ipa_diagnostics ipa_diagnostics_t;

int ipa_diagnostics_create(ipa_diagnostics_t **out);
uint64_t ipa_diagnostics_next_correlation_id(ipa_diagnostics_t *diagnostics);
void ipa_diagnostics_record(ipa_diagnostics_t *diagnostics,
                            const ipa_diagnostic_entry_t *entry);
size_t ipa_diagnostics_snapshot(ipa_diagnostics_t *diagnostics,
                                ipa_diagnostic_entry_t *out, size_t capacity);
void ipa_diagnostics_destroy(ipa_diagnostics_t *diagnostics);
int ipa_diagnostics_redact(const char *input, ipa_sensitive_kind_t kind,
                           char *output, size_t output_size);

void ipa_diagnostics_global_record(const char *module, const char *phase,
                                   int native_code, int system_errno,
                                   uint32_t task_id, int protocol,
                                   bool retryable, bool cleanup_complete);

#endif
