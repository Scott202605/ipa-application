target_include_directories(${PROJECT_NAME} PRIVATE .)

target_sources(${PROJECT_NAME} PRIVATE ber_tlv_parser.c)
target_sources(${PROJECT_NAME} PRIVATE tlv_data_extractor.c)
target_sources(${PROJECT_NAME} PRIVATE tlv_generator.c)
