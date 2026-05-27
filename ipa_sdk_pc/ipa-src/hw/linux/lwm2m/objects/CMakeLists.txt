target_include_directories(${PROJECT_NAME} PRIVATE .)

target_sources(${PROJECT_NAME} PRIVATE object_security.c)
target_sources(${PROJECT_NAME} PRIVATE object_server.c)
target_sources(${PROJECT_NAME} PRIVATE object_device.c)
target_sources(${PROJECT_NAME} PRIVATE object_esim_iot.c)