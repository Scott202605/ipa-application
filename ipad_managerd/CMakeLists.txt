set(IPAD_MANAGERD_SOURCES
    rpc_server.c
    worker_supervisor.c
    worker_process.c
    task_store.c
    audit_log.c
    profile_tasks.c
)

add_library(ipad_managerd_testlib STATIC
    ${IPAD_MANAGERD_SOURCES}
)
target_link_libraries(ipad_managerd_testlib PUBLIC ipad_common)
target_include_directories(ipad_managerd_testlib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
ipad_target_warnings(ipad_managerd_testlib)

add_executable(ipad-managerd
    managerd_main.c
    ${IPAD_MANAGERD_SOURCES}
)
target_link_libraries(ipad-managerd PRIVATE ipad_common)
ipad_target_warnings(ipad-managerd)
