target_include_directories(${PROJECT_NAME} PRIVATE .)

target_sources(${PROJECT_NAME} PRIVATE esipa_display.c)
target_sources(${PROJECT_NAME} PRIVATE esipa.c)

add_subdirectory(protocols protocols)
add_subdirectory(data-binding data-binding)
