add_library(ipad_worker_testlib STATIC
    sdk_adapter.c
    worker_protocol.c
)
target_include_directories(ipad_worker_testlib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(ipad_worker_testlib PUBLIC ipad_common)
target_compile_options(ipad_worker_testlib PRIVATE -Wall -Wextra -Werror)

add_executable(ipad-sdk-worker
    worker_main.c
    sdk_adapter.c
    worker_protocol.c
)
target_link_libraries(ipad-sdk-worker PRIVATE ipad_common)
target_compile_options(ipad-sdk-worker PRIVATE -Wall -Wextra -Werror)
