add_executable(desktop_app desktop_app.c)
message("Building executable (file)")
target_include_directories(desktop_app PRIVATE ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(desktop_app PRIVATE ipa-core)