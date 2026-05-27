target_include_directories(${PROJECT_NAME} PRIVATE .)

target_sources(${PROJECT_NAME} PRIVATE es11_data_binding.c)

add_subdirectory(json json)
