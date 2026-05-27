target_include_directories(${PROJECT_NAME} PRIVATE .)

target_sources(${PROJECT_NAME} PRIVATE smartcard.c)
target_sources(${PROJECT_NAME} PRIVATE apdu.c)

add_subdirectory(at at)
add_subdirectory(mock mock)