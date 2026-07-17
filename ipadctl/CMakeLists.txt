add_library(ipadctl_testlib STATIC
    diagnostics.c
)
target_include_directories(ipadctl_testlib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(ipadctl_testlib PUBLIC ipad_common)
target_compile_options(ipadctl_testlib PRIVATE -Wall -Wextra -Werror)

add_executable(ipadctl
    ipadctl_main.c
    diagnostics.c
)
target_link_libraries(ipadctl PRIVATE ipad_common)
target_compile_options(ipadctl PRIVATE -Wall -Wextra -Werror)
