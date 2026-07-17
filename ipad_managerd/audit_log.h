#ifndef AUDIT_LOG_H
#define AUDIT_LOG_H

int audit_log_write(const char *client, const char *method, const char *task_id, const char *result);

#endif
