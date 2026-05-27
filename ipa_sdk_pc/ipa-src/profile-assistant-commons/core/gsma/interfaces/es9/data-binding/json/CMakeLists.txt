target_include_directories(${PROJECT_NAME} PRIVATE .)

target_sources(${PROJECT_NAME} PRIVATE es9_json_extractor.c)
target_sources(${PROJECT_NAME} PRIVATE es9_json_generator.c)