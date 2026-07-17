#ifndef TASK_STORE_H
#define TASK_STORE_H

#include <time.h>

#define IPAD_TASK_ID_SIZE 32
#define IPAD_TASK_METHOD_SIZE 96
#define IPAD_TASK_STAGE_SIZE 64
#define IPAD_TASK_ERROR_SIZE 64

typedef enum {
    TASK_CREATED = 0,
    TASK_QUEUED = 1,
    TASK_VALIDATING = 2,
    TASK_WAITING_DEVICE = 3,
    TASK_RUNNING = 4,
    TASK_COMPLETED = 5,
    TASK_FAILED = 6,
    TASK_CANCELLED = 7
} task_state_t;

typedef struct {
    char task_id[IPAD_TASK_ID_SIZE];
    char method[IPAD_TASK_METHOD_SIZE];
    task_state_t state;
    char stage[IPAD_TASK_STAGE_SIZE];
    char error_name[IPAD_TASK_ERROR_SIZE];
    time_t created_at;
    time_t updated_at;
} ipad_task_t;

void task_store_init(void);
int task_store_create(const char *method, ipad_task_t *out);
int task_store_get(const char *task_id, ipad_task_t *out);
int task_store_update_state(const char *task_id, task_state_t state, const char *stage, const char *error_name);
const char *task_state_to_string(task_state_t state);

#endif
