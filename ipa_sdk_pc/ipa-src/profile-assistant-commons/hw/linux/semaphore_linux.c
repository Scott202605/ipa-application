/**
 * Copyright (c) Giesecke+Devrient Mobile Security GmbH 2023-2024
 */
#include <pthread.h>

#include "semaphore_manager.h"
#include "memory_manager.h"
#include "log.h"

struct semaphore_s {
  bool available;
  pthread_mutex_t mutex;
};

semaphore_t *make_semaphore() {
  semaphore_t* semaphore = (semaphore_t *) M_malloc(sizeof(semaphore_t));
  if (!semaphore) {
    LOGE("[SEMAPHORE]\t[make_semaphore] Can't allocate data to semaphore");
    return NULL;
  }
  semaphore->available = true;
  if (pthread_mutex_init(&semaphore->mutex, NULL) != 0) {
    LOGE("[SEMAPHORE]\t[make_semaphore] Mutex initalization failed");
    M_free(semaphore);
    return NULL;
  }
  return semaphore;
}

int semaphore_take(semaphore_t *semaphore) {
  if (NULL == semaphore) {
    LOGE("[SEMAPHORE]\t[semaphore_take] semaphore instance is null");
    return -1;
  }

  int rc;
  int ret;
  
  if ((rc = pthread_mutex_lock(&semaphore->mutex)) != 0) {
    LOGE("[SEMAPHORE]\t[semaphore_take] Mutex lock failed, rc %d", rc);
  }

  if (semaphore->available) {
    semaphore->available = false;
    ret = 0;
  } else {
    ret = -1;
  }

  if ((rc = pthread_mutex_unlock(&semaphore->mutex)) != 0) {
      LOGE("[SEMAPHORE]\t[semaphore_take] Mutex unlock failed, rc %d", rc);
    }

  return ret;
}

void semaphore_give(semaphore_t *semaphore) {
  if (NULL == semaphore) {
    LOGE("[SEMAPHORE]\t[semaphore_give] semaphore instance is null");
    return;
  }

  int rc;

  if ((rc = pthread_mutex_lock(&semaphore->mutex)) != 0) {
    LOGE("[SEMAPHORE]\t[semaphore_give] Mutex lock failed, rc %d", rc);
  }

   semaphore->available = true;

  if ((rc = pthread_mutex_unlock(&semaphore->mutex)) != 0) {
    LOGE("[SEMAPHORE]\t[semaphore_give] Mutex unlock failed, rc %d", rc);
  }
}

void semaphore_destroy(semaphore_t *semaphore) {
  if (NULL == semaphore) {
    LOGE("[SEMAPHORE]\t[semaphore_destroy] semaphore instance is null");
    return;
  }

  int rc;

  if ((rc = pthread_mutex_destroy(&semaphore->mutex)) != 0) {
    LOGE("[MUTEX]\tMutex destroy failed, rc %d", rc);
  }
  M_free(semaphore);
}