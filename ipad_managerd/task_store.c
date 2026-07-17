#include "task_store.h"

#include "ipad_json.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#define MAX_TASKS 64

static ipad_task_t g_tasks[MAX_TASKS];
static int g_task_count = 0;
static int g_next_task_id = 1;
static char g_task_store_path[256];
static int g_task_retention = 256;

void task_store_init(void) {
    memset(g_tasks, 0, sizeof(g_tasks));
    g_task_count = 0;
    g_next_task_id = 1;
    g_task_store_path[0] = '\0';
    g_task_retention = 256;
}

int task_store_set_path(const char *path, int retention) {
    if (!path || path[0] == '\0' || retention < 1 || retention > MAX_TASKS) {
        return -1;
    }
    snprintf(g_task_store_path, sizeof(g_task_store_path), "%s", path);
    g_task_retention = retention;
    return 0;
}

static task_state_t task_state_from_string(const char *state) {
    if (!state) return TASK_CREATED;
    if (strcmp(state, "queued") == 0) return TASK_QUEUED;
    if (strcmp(state, "validating") == 0) return TASK_VALIDATING;
    if (strcmp(state, "waiting_device") == 0) return TASK_WAITING_DEVICE;
    if (strcmp(state, "running") == 0) return TASK_RUNNING;
    if (strcmp(state, "completed") == 0) return TASK_COMPLETED;
    if (strcmp(state, "failed") == 0) return TASK_FAILED;
    if (strcmp(state, "cancelled") == 0) return TASK_CANCELLED;
    return TASK_CREATED;
}

int task_store_write_json(const ipad_task_t *task, char *out, size_t out_size) {
    int written;
    if (!task || !out || out_size == 0) {
        return -1;
    }
    written = snprintf(out, out_size,
                       "{\"task_id\":\"%s\",\"method\":\"%s\",\"state\":\"%s\",\"stage\":\"%s\",\"error\":\"%s\",\"created_at\":%ld,\"updated_at\":%ld}",
                       task->task_id,
                       task->method,
                       task_state_to_string(task->state),
                       task->stage,
                       task->error_name,
                       (long)task->created_at,
                       (long)task->updated_at);
    return written > 0 && (size_t)written < out_size ? 0 : -1;
}

static void append_task_transition(const ipad_task_t *task) {
    FILE *file;
    char line[512];
    if (!task || !g_task_store_path[0]) {
        return;
    }
    if (task_store_write_json(task, line, sizeof(line)) != 0) {
        return;
    }
    file = fopen(g_task_store_path, "ab");
    if (!file) {
        return;
    }
    fputs(line, file);
    fputc('\n', file);
    fclose(file);
}

static int task_index(const char *task_id) {
    int i;
    for (i = 0; i < g_task_count; i++) {
        if (strcmp(g_tasks[i].task_id, task_id) == 0) {
            return i;
        }
    }
    return -1;
}

static void upsert_loaded_task(const ipad_task_t *task) {
    int idx;
    if (!task || !task->task_id[0]) {
        return;
    }
    idx = task_index(task->task_id);
    if (idx >= 0) {
        g_tasks[idx] = *task;
        return;
    }
    if (g_task_count >= g_task_retention || g_task_count >= MAX_TASKS) {
        memmove(&g_tasks[0], &g_tasks[1], sizeof(g_tasks[0]) * (MAX_TASKS - 1));
        g_task_count--;
    }
    g_tasks[g_task_count++] = *task;
}

static void update_next_task_id(const char *task_id) {
    int n;
    if (sscanf(task_id, "task-%d", &n) == 1 && n >= g_next_task_id) {
        g_next_task_id = n + 1;
    }
}

int task_store_load(void) {
    FILE *file;
    char line[512];
    if (!g_task_store_path[0]) {
        return 0;
    }
    file = fopen(g_task_store_path, "rb");
    if (!file) {
        return 0;
    }
    while (fgets(line, sizeof(line), file)) {
        ipad_task_t task;
        char state[32];
        int created_at = 0;
        int updated_at = 0;

        memset(&task, 0, sizeof(task));
        if (ipad_json_get_string(line, "task_id", task.task_id, sizeof(task.task_id)) != 0 ||
            ipad_json_get_string(line, "method", task.method, sizeof(task.method)) != 0 ||
            ipad_json_get_string(line, "state", state, sizeof(state)) != 0) {
            continue;
        }
        ipad_json_get_string(line, "stage", task.stage, sizeof(task.stage));
        ipad_json_get_string(line, "error", task.error_name, sizeof(task.error_name));
        ipad_json_get_int(line, "created_at", &created_at);
        ipad_json_get_int(line, "updated_at", &updated_at);
        task.state = task_state_from_string(state);
        task.created_at = (time_t)created_at;
        task.updated_at = (time_t)updated_at;
        update_next_task_id(task.task_id);
        upsert_loaded_task(&task);
    }
    fclose(file);
    return 0;
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
    append_task_transition(task);
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
            append_task_transition(&g_tasks[i]);
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
