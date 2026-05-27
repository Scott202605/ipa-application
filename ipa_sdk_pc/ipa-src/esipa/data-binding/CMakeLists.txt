target_include_directories(${PROJECT_NAME} PRIVATE .)

target_sources(${PROJECT_NAME} PRIVATE esipa_data_binding.c)

add_subdirectory(asn1 asn1)
add_subdirectory(json json)
