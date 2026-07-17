#ifndef IPAD_PROTOCOL_H
#define IPAD_PROTOCOL_H

#define IPAD_JSONRPC_VERSION "2.0"
#define IPAD_DEFAULT_SOCKET_PATH "/run/ipad-manager/ipad-manager.sock"
#define IPAD_MAX_JSON_MESSAGE 4096
#define IPAD_MAX_METHOD_NAME 96
#define IPAD_MAX_TASK_ID 32

#define IPAD_METHOD_SYSTEM_STATUS "system.status"
#define IPAD_METHOD_WORKER_START_MOCK "worker.start_mock"
#define IPAD_METHOD_SDK_INIT "sdk.init"
#define IPAD_METHOD_SDK_STATUS "sdk.status"
#define IPAD_METHOD_SDK_DEINIT "sdk.deinit"
#define IPAD_METHOD_TASK_GET "task.get"
#define IPAD_METHOD_PROFILE_DOWNLOAD "profile.download"
#define IPAD_METHOD_PROFILE_ENABLE "profile.enable"
#define IPAD_METHOD_PROFILE_DISABLE "profile.disable"
#define IPAD_METHOD_PROFILE_DELETE "profile.delete"

#endif
