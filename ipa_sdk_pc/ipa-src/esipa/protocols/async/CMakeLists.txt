target_include_directories(${PROJECT_NAME} PRIVATE .)

target_sources(${PROJECT_NAME} PRIVATE esipa_async.c)

add_subdirectory(lwm2m lwm2m)
add_subdirectory(mqtt mqtt)
