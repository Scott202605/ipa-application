#include <assert.h>
#include <string.h>

#include "ipa_diagnostics.h"

int main(void) {
  ipa_diagnostics_t *diagnostics = NULL;
  ipa_diagnostic_entry_t entries[IPA_DIAGNOSTICS_CAPACITY];
  ipa_diagnostic_entry_t entry = {0};
  char redacted[64];
  const char *secrets[] = {"89049032000000000000000000000001",
                           "8944500101234567890", "s3cret", "a1b2c3d4",
                           "-----BEGIN CERTIFICATE-----"};
  ipa_sensitive_kind_t kinds[] = {IPA_SENSITIVE_EID, IPA_SENSITIVE_ICCID,
                                  IPA_SENSITIVE_PASSWORD, IPA_SENSITIVE_PSK,
                                  IPA_SENSITIVE_CERTIFICATE};
  size_t index;

  assert(ipa_diagnostics_create(&diagnostics) == 0);
  for (index = 0; index < sizeof(secrets) / sizeof(secrets[0]); ++index) {
    assert(ipa_diagnostics_redact(secrets[index], kinds[index], redacted,
                                  sizeof(redacted)) == 0);
    assert(strstr(redacted, secrets[index]) == NULL);
    assert(strstr(redacted, "REDACTED") != NULL);
  }
  assert(ipa_diagnostics_redact("ordinary", IPA_SENSITIVE_NONE, redacted,
                                sizeof(redacted)) == 0);
  assert(strcmp(redacted, "ordinary") == 0);

  for (index = 0; index < IPA_DIAGNOSTICS_CAPACITY + 3; ++index) {
    entry.correlation_id = ipa_diagnostics_next_correlation_id(diagnostics);
    entry.native_code = (int)index;
    ipa_diagnostics_record(diagnostics, &entry);
  }
  assert(ipa_diagnostics_snapshot(diagnostics, entries,
                                  IPA_DIAGNOSTICS_CAPACITY) ==
         IPA_DIAGNOSTICS_CAPACITY);
  assert(entries[0].native_code == 3);
  assert(entries[IPA_DIAGNOSTICS_CAPACITY - 1].native_code ==
         IPA_DIAGNOSTICS_CAPACITY + 2);
  ipa_diagnostics_destroy(diagnostics);
  return 0;
}
