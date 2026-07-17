#include "task_store.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#define MAX_TASKS 64

static ipad_task_t g_tasks[MAX_TASKS];
static int g_task_count = 0;
static int g_next_task_id = 1;

void task_store_init(void) {
    memset(g_tasks, 0, sizeof(g_tasks));
    g_task_count = 0;
    g_next_task_id = 1;
}

int task_store_create(const char *method, ipad_task_t *out) {
    ipad_task_t *task;
    time_t now;

    if (!method || !out || g_task_count >= MAX_TASKS) {
        return -1;
    }

    task = &g_tasks[g_task_count++];
    memset(task, 0, sizeof(*task));
    snprintf(task->task_id, sizeof(task->task_id), "task-%d", g_next_task_id++);
    snprintf(task->method, sizeof(task->method), "%s", method);
    task->state = TASK_CREATED;
    snprintf(task->stage, sizeof(task->stage), "%s", "created");
    now = time(NULL);
    task->created_at = now;
    task->updated_at = now;
    *out = *task;
    return 0;
}

int task_store_get(const char *task_id, ipad_task_t *out) {
    int i;

    if (!task_id || !out) {
        return -1;
    }
    for (i = 0; i < g_task_count; i++) {
        if (strcmp(g_tasks[i].task_id, task_id) == 0) {
            *out = g_tasks[i];
            return 0;
        }
    }
    return -1;
}

int task_store_update_state(const char *task_id, task_state_t state, const char *stage, const char *error_name) {
    int i;

    if (!task_id) {
        return -1;
    }
    for (i = 0; i < g_task_count; i++) {
        if (strcmp(g_tasks[i].task_id, task_id) == 0) {
            g_tasks[i].state = state;
            snprintf(g_tasks[i].stage, sizeof(g_tasks[i].stage), "%s", stage ? stage : "");
            snprintf(g_tasks[i].error_name, sizeof(g_tasks[i].error_name), "%s", error_name ? error_name : "");
            g_tasks[i].updated_at = time(NULL);
            return 0;
        }
    }
    return -1;
}

const char *task_state_to_string(task_state_t state) {
    switch (state) {
        case TASK_CREATED: return "created";
        case TASK_QUEUED: return "queued";
        case TASK_VALIDATING: return "validating";
        case TASK_WAITING_DEVICE: return "waiting_device";
        case TASK_RUNNING: return "running";
        case TASK_COMPLETED: return "completed";
        case TASK_FAILED: return "failed";
        case TASK_CANCELLED: return "cancelled";
        default: return "unknown";
    }
}
