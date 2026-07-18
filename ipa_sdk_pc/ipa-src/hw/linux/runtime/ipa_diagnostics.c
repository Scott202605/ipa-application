#include "ipa_diagnostics.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct ipa_diagnostics {
  pthread_mutex_t mutex;
  ipa_diagnostic_entry_t entries[IPA_DIAGNOSTICS_CAPACITY];
  size_t next;
  size_t count;
  uint64_t next_correlation_id;
};

static ipa_diagnostics_t *global_diagnostics;
static pthread_once_t global_once = PTHREAD_ONCE_INIT;

static void copy_text(char destination[IPA_DIAGNOSTICS_TEXT_SIZE],
                      const char *source) {
  if (!source) source = "";
  snprintf(destination, IPA_DIAGNOSTICS_TEXT_SIZE, "%s", source);
}

int ipa_diagnostics_create(ipa_diagnostics_t **out) {
  ipa_diagnostics_t *diagnostics;
  if (!out) return EINVAL;
  *out = NULL;
  diagnostics = calloc(1, sizeof(*diagnostics));
  if (!diagnostics) return ENOMEM;
  if (pthread_mutex_init(&diagnostics->mutex, NULL) != 0) {
    free(diagnostics);
    return EAGAIN;
  }
  diagnostics->next_correlation_id = 1;
  *out = diagnostics;
  return 0;
}

uint64_t ipa_diagnostics_next_correlation_id(ipa_diagnostics_t *diagnostics) {
  uint64_t result;
  if (!diagnostics) return 0;
  pthread_mutex_lock(&diagnostics->mutex);
  result = diagnostics->next_correlation_id++;
  if (diagnostics->next_correlation_id == 0)
    diagnostics->next_correlation_id = 1;
  pthread_mutex_unlock(&diagnostics->mutex);
  return result;
}

void ipa_diagnostics_record(ipa_diagnostics_t *diagnostics,
                            const ipa_diagnostic_entry_t *entry) {
  if (!diagnostics || !entry) return;
  pthread_mutex_lock(&diagnostics->mutex);
  diagnostics->entries[diagnostics->next] = *entry;
  diagnostics->next = (diagnostics->next + 1) % IPA_DIAGNOSTICS_CAPACITY;
  if (diagnostics->count < IPA_DIAGNOSTICS_CAPACITY) diagnostics->count++;
  pthread_mutex_unlock(&diagnostics->mutex);
}

size_t ipa_diagnostics_snapshot(ipa_diagnostics_t *diagnostics,
                                ipa_diagnostic_entry_t *out, size_t capacity) {
  size_t count;
  size_t first;
  size_t index;
  if (!diagnostics || !out || capacity == 0) return 0;
  pthread_mutex_lock(&diagnostics->mutex);
  count = diagnostics->count < capacity ? diagnostics->count : capacity;
  first = (diagnostics->next + IPA_DIAGNOSTICS_CAPACITY -
           diagnostics->count) % IPA_DIAGNOSTICS_CAPACITY;
  for (index = 0; index < count; ++index)
    out[index] = diagnostics->entries[(first + index) % IPA_DIAGNOSTICS_CAPACITY];
  pthread_mutex_unlock(&diagnostics->mutex);
  return count;
}

void ipa_diagnostics_destroy(ipa_diagnostics_t *diagnostics) {
  if (!diagnostics) return;
  pthread_mutex_destroy(&diagnostics->mutex);
  memset(diagnostics, 0, sizeof(*diagnostics));
  free(diagnostics);
}

int ipa_diagnostics_redact(const char *input, ipa_sensitive_kind_t kind,
                           char *output, size_t output_size) {
  static const char *labels[] = {"", "EID", "ICCID", "PASSWORD", "PSK",
                                 "CERTIFICATE"};
  int written;
  if (!input || !output || output_size == 0 || kind < IPA_SENSITIVE_NONE ||
      kind > IPA_SENSITIVE_CERTIFICATE)
    return EINVAL;
  written = kind == IPA_SENSITIVE_NONE
                ? snprintf(output, output_size, "%s", input)
                : snprintf(output, output_size, "[REDACTED:%s]", labels[kind]);
  return written < 0 || (size_t)written >= output_size ? ENOSPC : 0;
}

static void initialize_global(void) {
  if (ipa_diagnostics_create(&global_diagnostics) != 0)
    global_diagnostics = NULL;
}

void ipa_diagnostics_global_record(const char *module, const char *phase,
                                   int native_code, int system_errno,
                                   uint32_t task_id, int protocol,
                                   bool retryable, bool cleanup_complete) {
  ipa_diagnostic_entry_t entry = {0};
  pthread_once(&global_once, initialize_global);
  if (!global_diagnostics) return;
  entry.correlation_id =
      ipa_diagnostics_next_correlation_id(global_diagnostics);
  copy_text(entry.module, module);
  copy_text(entry.phase, phase);
  entry.native_code = native_code;
  entry.system_errno = system_errno;
  entry.task_id = task_id;
  entry.protocol = protocol;
  entry.retryable = retryable;
  entry.cleanup_complete = cleanup_complete;
  ipa_diagnostics_record(global_diagnostics, &entry);
}
