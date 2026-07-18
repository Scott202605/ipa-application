#include "ipa_euicc_executor.h"

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>

struct ipa_euicc_executor {
  pthread_mutex_t execution_mutex;
  pthread_mutex_t state_mutex;
  bool stopping;
};

int ipa_euicc_executor_create(ipa_euicc_executor_t **out) {
  ipa_euicc_executor_t *executor;
  if (!out) return EINVAL;
  *out = NULL;
  executor = calloc(1, sizeof(*executor));
  if (!executor) return ENOMEM;
  if (pthread_mutex_init(&executor->execution_mutex, NULL) != 0) {
    free(executor);
    return EAGAIN;
  }
  if (pthread_mutex_init(&executor->state_mutex, NULL) != 0) {
    pthread_mutex_destroy(&executor->execution_mutex);
    free(executor);
    return EAGAIN;
  }
  *out = executor;
  return 0;
}

int ipa_euicc_executor_begin(ipa_euicc_executor_t *executor) {
  bool stopping;
  if (!executor) return EINVAL;
  pthread_mutex_lock(&executor->state_mutex);
  stopping = executor->stopping;
  pthread_mutex_unlock(&executor->state_mutex);
  if (stopping) return ECANCELED;
  pthread_mutex_lock(&executor->execution_mutex);
  pthread_mutex_lock(&executor->state_mutex);
  stopping = executor->stopping;
  pthread_mutex_unlock(&executor->state_mutex);
  if (stopping) {
    pthread_mutex_unlock(&executor->execution_mutex);
    return ECANCELED;
  }
  return 0;
}

void ipa_euicc_executor_end(ipa_euicc_executor_t *executor) {
  if (executor) pthread_mutex_unlock(&executor->execution_mutex);
}

void ipa_euicc_executor_request_stop(ipa_euicc_executor_t *executor) {
  if (!executor) return;
  pthread_mutex_lock(&executor->state_mutex);
  executor->stopping = true;
  pthread_mutex_unlock(&executor->state_mutex);
}

void ipa_euicc_executor_reset(ipa_euicc_executor_t *executor) {
  if (!executor) return;
  pthread_mutex_lock(&executor->state_mutex);
  executor->stopping = false;
  pthread_mutex_unlock(&executor->state_mutex);
}

void ipa_euicc_executor_destroy(ipa_euicc_executor_t *executor) {
  if (!executor) return;
  ipa_euicc_executor_request_stop(executor);
  pthread_mutex_lock(&executor->execution_mutex);
  pthread_mutex_unlock(&executor->execution_mutex);
  pthread_mutex_destroy(&executor->state_mutex);
  pthread_mutex_destroy(&executor->execution_mutex);
  free(executor);
}

bool ipa_checked_size_add(size_t left, size_t right, size_t *out) {
  if (!out || left > SIZE_MAX - right) return false;
  *out = left + right;
  return true;
}

bool ipa_checked_size_multiply(size_t left, size_t right, size_t *out) {
  if (!out || (right != 0 && left > SIZE_MAX / right)) return false;
  *out = left * right;
  return true;
}
