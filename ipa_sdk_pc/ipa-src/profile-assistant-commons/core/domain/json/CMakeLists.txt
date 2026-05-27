target_include_directories(${PROJECT_NAME} PRIVATE .)

target_sources(${PROJECT_NAME} PRIVATE json_data_extractor.c)
target_sources(${PROJECT_NAME} PRIVATE json_generator.c)