cmake_minimum_required(VERSION 3.22.1)
project(ipa-core
        VERSION 1.0.0
        LANGUAGES C
        DESCRIPTION "IPA Core Library"
)

option(IPA_ENABLE_ASAN_UBSAN "Enable AddressSanitizer and UBSan" OFF)
option(IPA_ENABLE_TSAN "Enable ThreadSanitizer" OFF)
if(IPA_ENABLE_ASAN_UBSAN AND IPA_ENABLE_TSAN)
    message(FATAL_ERROR "IPA_ENABLE_ASAN_UBSAN and IPA_ENABLE_TSAN are mutually exclusive")
endif()
if(IPA_ENABLE_ASAN_UBSAN)
    add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
    add_link_options(-fsanitize=address,undefined)
elseif(IPA_ENABLE_TSAN)
    add_compile_options(-fsanitize=thread -fno-omit-frame-pointer)
    add_link_options(-fsanitize=thread)
endif()

if(NOT DEFINED IPA_BUILD_GIT_COMMIT)
  execute_process(COMMAND git rev-parse --verify HEAD
      WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
      OUTPUT_VARIABLE IPA_BUILD_GIT_COMMIT
      OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
endif()
if(NOT IPA_BUILD_GIT_COMMIT)
    set(IPA_BUILD_GIT_COMMIT unknown)
endif()
set(IPA_BUILD_SONAME "libipa.so")
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/BUILD_METADATA.txt.in
               ${CMAKE_CURRENT_BINARY_DIR}/BUILD_METADATA.txt @ONLY)

option(BUILD_SHARED_LIBS "构建共享库" ON) #OFF ->构建静态库

add_subdirectory(ipa-src/hw/linux)
add_subdirectory(main_app)

include(CTest)
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/BUILD_METADATA.txt DESTINATION share/ipa)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/include/ DESTINATION include/ipa)
