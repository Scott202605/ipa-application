cmake_minimum_required(VERSION 3.22.1)
project(ipad_host_app
        VERSION 1.1.0
        LANGUAGES C
        DESCRIPTION "IPA Host Application with GUI"
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 编译选项
option(BUILD_SHARED_LIBS "构建共享库" OFF)
option(ENABLE_DEBUG "启用调试功能" ON)

# 查找依赖包
find_package(PkgConfig REQUIRED)
find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)
pkg_check_modules(GTK3 REQUIRED gtk+-3.0)

# IPAd SDK 路径。这里需要指向 SDK 源码根目录，而不是 dist 目录，
# 因为当前 host app 还直接依赖 SDK 源码树中的内部头文件。
set(IPAD_SDK_ROOT "${CMAKE_SOURCE_DIR}/../ipa_sdk_pc" CACHE PATH "IPAd SDK source root")
if(NOT EXISTS "${IPAD_SDK_ROOT}/include/ipa.h")
    message(FATAL_ERROR "IPAD_SDK_ROOT must point to the ipa_sdk_pc source directory: ${IPAD_SDK_ROOT}")
endif()

find_library(IPA_LIBRARY
    NAMES ipa
    PATHS
        "${IPAD_SDK_ROOT}/build/ipa-src/hw/linux"
        "${IPAD_SDK_ROOT}/dist/lib"
    REQUIRED
)

# 添加头文件搜索路径
include_directories(
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src
    ${PROJECT_SOURCE_DIR}/src/utils
    ${IPAD_SDK_ROOT}/include
    ${IPAD_SDK_ROOT}/ipa-src/profile-assistant-commons/core
    ${IPAD_SDK_ROOT}/ipa-src/profile-assistant-commons/interfaces
    ${IPAD_SDK_ROOT}/ipa-src/profile-assistant-commons/core/gsma/interfaces
    ${GTK3_INCLUDE_DIRS}
)

link_directories(${GTK3_LIBRARY_DIRS})

# 源文件列表
set(SOURCES
    src/main.c
    src/gui/gui_main.c
    src/gui/gui_api_tree.c
    src/gui/gui_param_input.c
    src/gui/gui_log_display.c
    src/sdk_wrapper/ipad_wrapper.c
    src/business_logic/param_validator.c
    src/business_logic/command_builder.c
    src/business_logic/response_parser.c
    src/utils/logger.c
    src/utils/json_helper.c
    src/utils/config_manager.c
    src/debug/mock_response.c
)

# 生成可执行文件
add_executable(ipad_host_app ${SOURCES})

# 链接库
target_link_libraries(ipad_host_app
    ${IPA_LIBRARY}
    ${GTK3_LIBRARIES}
    CURL::libcurl
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

set_target_properties(ipad_host_app PROPERTIES
    BUILD_RPATH "${IPAD_SDK_ROOT}/build/ipa-src/hw/linux;${IPAD_SDK_ROOT}/dist/lib"
    INSTALL_RPATH "$ORIGIN/../lib"
)

# 编译选项
target_compile_options(ipad_host_app PRIVATE
    ${GTK3_CFLAGS_OTHER}
    -Wall
    -Wextra
    -Wno-unused-parameter
)

# 启用调试标志
if(ENABLE_DEBUG)
    target_compile_definitions(ipad_host_app PRIVATE
        DEBUG=1
        ENABLE_MOCK_RESPONSE=1
    )
    target_compile_options(ipad_host_app PRIVATE -g -O0)
else()
    target_compile_options(ipad_host_app PRIVATE -O2)
endif()

# 安装规则
install(TARGETS ipad_host_app DESTINATION bin)
if(EXISTS "${CMAKE_SOURCE_DIR}/resources")
    install(DIRECTORY resources/ DESTINATION share/ipad_host_app)
endif()
install(FILES config/ipad_config.example.json DESTINATION share/ipad_host_app)
