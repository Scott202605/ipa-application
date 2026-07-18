add_library(ipadctl_testlib STATIC
    bootstrap_commands.c
    config_commands.c
    device_discovery.c
    diagnostics.c
    platform_check.c
    setup_commands.c
    support_bundle.c
)
target_include_directories(ipadctl_testlib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(ipadctl_testlib PUBLIC ipad_common)
ipad_target_warnings(ipadctl_testlib)

add_executable(ipadctl
    ipadctl_main.c
    bootstrap_commands.c
    config_commands.c
    device_discovery.c
    diagnostics.c
    platform_check.c
    setup_commands.c
    support_bundle.c
)
target_link_libraries(ipadctl PRIVATE ipad_common)
ipad_target_warnings(ipadctl)
