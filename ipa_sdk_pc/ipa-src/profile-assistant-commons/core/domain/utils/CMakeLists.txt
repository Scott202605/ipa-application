target_include_directories(${PROJECT_NAME} PRIVATE .)

target_sources(${PROJECT_NAME} PRIVATE apdu_utils.c)
target_sources(${PROJECT_NAME} PRIVATE byte_utils.c)
target_sources(${PROJECT_NAME} PRIVATE network_utils.c)