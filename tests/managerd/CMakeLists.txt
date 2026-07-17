add_executable(test_rpc_server test_rpc_server.c)
target_link_libraries(test_rpc_server PRIVATE ipad_managerd_testlib ipad_common)
add_test(NAME test_rpc_server COMMAND test_rpc_server)

add_executable(test_worker_supervisor test_worker_supervisor.c)
target_link_libraries(test_worker_supervisor PRIVATE ipad_managerd_testlib ipad_common)
add_test(NAME test_worker_supervisor COMMAND test_worker_supervisor)

add_executable(test_task_store test_task_store.c)
target_link_libraries(test_task_store PRIVATE ipad_managerd_testlib ipad_common)
add_test(NAME test_task_store COMMAND test_task_store)

add_executable(test_task_store_persistence test_task_store_persistence.c)
target_link_libraries(test_task_store_persistence PRIVATE ipad_managerd_testlib ipad_common)
add_test(NAME test_task_store_persistence COMMAND test_task_store_persistence)

add_executable(test_profile_tasks test_profile_tasks.c)
target_link_libraries(test_profile_tasks PRIVATE ipad_managerd_testlib ipad_common)
add_test(NAME test_profile_tasks COMMAND test_profile_tasks)
add_test(NAME test_profile_tasks_worker COMMAND test_profile_tasks $<TARGET_FILE:ipad-sdk-worker>)

add_executable(test_managerd_socket test_managerd_socket.c)
target_link_libraries(test_managerd_socket PRIVATE ipad_common)
add_test(NAME test_managerd_socket
  COMMAND test_managerd_socket
    $<TARGET_FILE:ipad-managerd>
    /tmp/ipad-manager-test.sock)

add_executable(test_ipadctl_socket test_ipadctl_socket.c)
target_link_libraries(test_ipadctl_socket PRIVATE ipad_common)
add_test(NAME test_ipadctl_socket
  COMMAND test_ipadctl_socket
    $<TARGET_FILE:ipad-managerd>
    $<TARGET_FILE:ipadctl>
    /tmp/ipadctl-test.sock)

add_executable(test_worker_process test_worker_process.c)
target_link_libraries(test_worker_process PRIVATE ipad_managerd_testlib ipad_common)
add_test(NAME test_worker_process COMMAND test_worker_process $<TARGET_FILE:ipad-sdk-worker>)
