target_include_directories(${PROJECT_NAME} PRIVATE .)

target_sources(${PROJECT_NAME} PRIVATE es11.c)

add_subdirectory(data-binding data-binding)
