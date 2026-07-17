add_executable(ipadctl ipadctl_main.c)
target_link_libraries(ipadctl PRIVATE ipad_common)
target_compile_options(ipadctl PRIVATE -Wall -Wextra -Werror)
