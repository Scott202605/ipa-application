target_include_directories(${PROJECT_NAME} PRIVATE .)

target_sources(${PROJECT_NAME} PRIVATE es10.c)
target_sources(${PROJECT_NAME} PRIVATE es10_tlv_extractor.c)
target_sources(${PROJECT_NAME} PRIVATE es10_tlv_generator.c)
target_sources(${PROJECT_NAME} PRIVATE es10_display.c)