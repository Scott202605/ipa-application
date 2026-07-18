#include <assert.h>
#include <sched.h>
#include <stdatomic.h>

#include "ipa_core.h"
#include "ipa_runtime.h"

static ipa_runtime_t *runtime;
static atomic_int allow_completion;

static void *successful_worker(void *config) {
  (void)config;
  ipa_runtime_complete_initialization(runtime, true);
  return NULL;
}

static void *stoppable_worker(void *config) {
  (void)config;
  while (!ipa_runtime_stop_requested(runtime) && !atomic_load(&allow_completion))
    sched_yield();
  ipa_runtime_complete_initialization(runtime, false);
  return NULL;
}

int main(void) {
  char driver[] = "/dev/test";
  cl_config_t config = {ES10_DRIVER_AT, driver, eLogInfo, 1, 2, 60};

  assert(ipa_runtime_create(&runtime, NULL, NULL) == 0);
  assert(ipa_runtime_state(runtime) == IPA_RUNTIME_UNINITIALIZED);
  assert(ipa_runtime_start(runtime, &config, successful_worker) == 0);
  assert(ipa_runtime_start(runtime, &config, successful_worker) == 0);
  while (ipa_runtime_state(runtime) == IPA_RUNTIME_INITIALIZING) sched_yield();
  assert(ipa_runtime_state(runtime) == IPA_RUNTIME_READY);
  assert(ipa_runtime_stop(runtime));
  assert(ipa_runtime_state(runtime) == IPA_RUNTIME_UNINITIALIZED);
  assert(!ipa_runtime_stop(runtime));

  assert(ipa_runtime_start(runtime, &config, stoppable_worker) == 0);
  assert(!ipa_runtime_stop(runtime));
  assert(ipa_runtime_state(runtime) == IPA_RUNTIME_UNINITIALIZED);

  assert(ipa_runtime_start(runtime, &config, successful_worker) == 0);
  while (ipa_runtime_state(runtime) == IPA_RUNTIME_INITIALIZING) sched_yield();
  assert(ipa_runtime_stop(runtime));
  ipa_runtime_destroy(runtime);
  return 0;
}
