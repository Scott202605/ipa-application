target_include_directories(${PROJECT_NAME} PRIVATE .)
target_include_directories(${PROJECT_NAME} PRIVATE include)

target_sources(${PROJECT_NAME} PRIVATE ipa.c)
target_sources(${PROJECT_NAME} PRIVATE ipa_json_extractor.c)
target_sources(${PROJECT_NAME} PRIVATE ipa_tlv_generator.c)
target_sources(${PROJECT_NAME} PRIVATE ipa_display.c)
target_sources(${PROJECT_NAME} PRIVATE ipa_local.c)




add_subdirectory(profile-assistant-commons profile-assistant-commons)
add_subdirectory(esipa esipa)
add_subdirectory(interfaces interfaces)
