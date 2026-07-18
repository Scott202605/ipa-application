#include <assert.h>
#include <stdint.h>

#include "ipa_euicc_executor.h"

int main(void) {
  size_t result = 0;
  assert(ipa_checked_size_add(0, 0, &result) && result == 0);
  assert(ipa_checked_size_add(SIZE_MAX - 1, 1, &result) && result == SIZE_MAX);
  assert(!ipa_checked_size_add(SIZE_MAX, 1, &result));
  assert(ipa_checked_size_multiply(0, SIZE_MAX, &result) && result == 0);
  assert(ipa_checked_size_multiply(SIZE_MAX, 1, &result) && result == SIZE_MAX);
  assert(!ipa_checked_size_multiply(SIZE_MAX, 2, &result));
  assert(!ipa_checked_size_add(1, 1, NULL));
  assert(!ipa_checked_size_multiply(1, 1, NULL));
  return 0;
}
