option(IPAD_WORKER_ENABLE_REAL_SDK "Compile worker real SDK adapter path" OFF)

add_library(ipad_worker_testlib STATIC
    sdk_adapter.c
    sdk_profile_facade.c
    worker_protocol.c
)
target_include_directories(ipad_worker_testlib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(ipad_worker_testlib PUBLIC ipad_common)
target_compile_options(ipad_worker_testlib PRIVATE -Wall -Wextra -Werror)

add_executable(ipad-sdk-worker
    worker_main.c
    sdk_adapter.c
    sdk_profile_facade.c
    worker_protocol.c
)
target_link_libraries(ipad-sdk-worker PRIVATE ipad_common)
target_compile_options(ipad-sdk-worker PRIVATE -Wall -Wextra -Werror)

if(IPAD_WORKER_ENABLE_REAL_SDK)
    target_compile_definitions(ipad_worker_testlib PUBLIC IPAD_WORKER_ENABLE_REAL_SDK=1)
    target_compile_definitions(ipad-sdk-worker PRIVATE IPAD_WORKER_ENABLE_REAL_SDK=1)
    target_include_directories(ipad_worker_testlib PUBLIC ${PROJECT_SOURCE_DIR}/ipa_sdk_pc/include)
    target_include_directories(ipad-sdk-worker PRIVATE ${PROJECT_SOURCE_DIR}/ipa_sdk_pc/include)

    find_library(IPA_LIBRARY
        NAMES ipa
        PATHS
            "${PROJECT_SOURCE_DIR}/ipa_sdk_pc/build/ipa-src/hw/linux"
            "${PROJECT_SOURCE_DIR}/ipa_sdk_pc/dist/lib"
    )

    if(IPA_LIBRARY)
        target_compile_definitions(ipad_worker_testlib PUBLIC IPAD_WORKER_HAVE_REAL_SDK=1)
        target_compile_definitions(ipad-sdk-worker PRIVATE IPAD_WORKER_HAVE_REAL_SDK=1)
        target_link_libraries(ipad_worker_testlib PUBLIC ${IPA_LIBRARY} curl serialport pthread paho-mqtt3cs)
        target_link_libraries(ipad-sdk-worker PRIVATE ${IPA_LIBRARY} curl serialport pthread paho-mqtt3cs)
    endif()
endif()
