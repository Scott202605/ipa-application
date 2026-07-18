#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <unistd.h>

#include "ipa_euicc_executor.h"

typedef struct {
  ipa_euicc_executor_t *executor;
  int input;
  int output;
} call_context_t;

static atomic_int concurrency;
static atomic_int maximum_concurrency;

static void *fake_es10_call(void *opaque) {
  call_context_t *context = opaque;
  int current;
  int observed;
  assert(ipa_euicc_executor_begin(context->executor) == 0);
  current = atomic_fetch_add(&concurrency, 1) + 1;
  observed = atomic_load(&maximum_concurrency);
  while (current > observed &&
         !atomic_compare_exchange_weak(&maximum_concurrency, &observed, current)) {
  }
  usleep(20000);
  context->output = context->input * 10;
  atomic_fetch_sub(&concurrency, 1);
  ipa_euicc_executor_end(context->executor);
  return NULL;
}

int main(void) {
  ipa_euicc_executor_t *executor = NULL;
  call_context_t first;
  call_context_t second;
  pthread_t first_thread;
  pthread_t second_thread;
  size_t size;

  assert(ipa_euicc_executor_create(&executor) == 0);
  first = (call_context_t){executor, 7, 0};
  second = (call_context_t){executor, 9, 0};
  assert(pthread_create(&first_thread, NULL, fake_es10_call, &first) == 0);
  assert(pthread_create(&second_thread, NULL, fake_es10_call, &second) == 0);
  assert(pthread_join(first_thread, NULL) == 0);
  assert(pthread_join(second_thread, NULL) == 0);
  assert(atomic_load(&maximum_concurrency) == 1);
  assert(first.output == 70);
  assert(second.output == 90);

  ipa_euicc_executor_request_stop(executor);
  assert(ipa_euicc_executor_begin(executor) == ECANCELED);
  ipa_euicc_executor_reset(executor);
  assert(ipa_euicc_executor_begin(executor) == 0);
  ipa_euicc_executor_end(executor);

  assert(ipa_checked_size_add(10, 20, &size) && size == 30);
  assert(!ipa_checked_size_add(SIZE_MAX, 1, &size));
  assert(ipa_checked_size_multiply(10, 20, &size) && size == 200);
  assert(!ipa_checked_size_multiply(SIZE_MAX, 2, &size));
  ipa_euicc_executor_destroy(executor);
  return 0;
}
