#include "audit_log.h"

#include <stdio.h>
#include <time.h>

int audit_log_write(const char *client, const char *method, const char *task_id, const char *result) {
    time_t now = time(NULL);

    fprintf(stderr,
            "{\"ts\":%ld,\"component\":\"daemon\",\"client\":\"%s\",\"method\":\"%s\",\"task_id\":\"%s\",\"result\":\"%s\"}\n",
            (long)now,
            client ? client : "local",
            method ? method : "",
            task_id ? task_id : "",
            result ? result : "");
    return 0;
}
