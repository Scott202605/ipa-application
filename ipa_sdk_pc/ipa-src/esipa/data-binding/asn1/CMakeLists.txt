target_include_directories(${PROJECT_NAME} PRIVATE .)

target_sources(${PROJECT_NAME} PRIVATE esipa_tlv_extractor.c)
target_sources(${PROJECT_NAME} PRIVATE esipa_tlv_generator.c)
