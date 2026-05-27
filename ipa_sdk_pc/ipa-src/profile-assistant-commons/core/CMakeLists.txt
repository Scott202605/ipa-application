target_include_directories(${PROJECT_NAME} PRIVATE .)

add_subdirectory(device-info device-info)
add_subdirectory(domain domain)
add_subdirectory(gsma gsma)
add_subdirectory(logger logger)
add_subdirectory(network network)
add_subdirectory(smartcard smartcard)
