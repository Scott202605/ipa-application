target_include_directories(${PROJECT_NAME} PRIVATE .)

target_sources(${PROJECT_NAME} PRIVATE lwm2m_client_linux.c)

add_subdirectory(objects objects)