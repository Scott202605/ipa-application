target_include_directories(${PROJECT_NAME} PRIVATE .)

add_subdirectory(base64 base64)
add_subdirectory(json json)
add_subdirectory(notifications notifications)
add_subdirectory(rsp rsp)
add_subdirectory(tlv tlv)
add_subdirectory(utils utils)
