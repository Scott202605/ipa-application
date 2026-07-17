add_library(ipad_common STATIC
    ipad_json.c
)

target_include_directories(ipad_common PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_options(ipad_common PRIVATE
    -Wall
    -Wextra
    -Werror
)
