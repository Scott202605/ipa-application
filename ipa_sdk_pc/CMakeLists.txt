cmake_minimum_required(VERSION 3.22.1)
project(ipa-core
        VERSION 1.0.0
        LANGUAGES C
        DESCRIPTION "IPA Core Library"
)

option(BUILD_SHARED_LIBS "构建共享库" ON) #OFF ->构建静态库

add_subdirectory(ipa-src/hw/linux)
add_subdirectory(main_app)
