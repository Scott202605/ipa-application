# Runtime tests use assert as their minimal test harness. Keep assertions active
# even when the SDK itself is built as RelWithDebInfo or Release.
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
  add_compile_options(-UNDEBUG)
endif()

add_executable(ipa_abi_layout_probe abi/abi_layout_probe.c)
target_compile_features(ipa_abi_layout_probe PRIVATE c_std_11)
target_include_directories(ipa_abi_layout_probe PRIVATE ${PROJECT_SOURCE_DIR}/include)

find_package(Python3 COMPONENTS Interpreter REQUIRED)
add_test(
  NAME ipa_abi_compatibility
  COMMAND ${Python3_EXECUTABLE}
          ${CMAKE_CURRENT_SOURCE_DIR}/abi/check_abi.py
          --library $<TARGET_FILE:ipa-core>
          --probe $<TARGET_FILE:ipa_abi_layout_probe>
          --symbols ${CMAKE_CURRENT_SOURCE_DIR}/abi/baseline/linux-x86_64.symbols.txt
          --layout ${CMAKE_CURRENT_SOURCE_DIR}/abi/baseline/linux-x86_64.layout.json
          --expected-soname libipa.so
)

add_test(
  NAME ipa_public_internal_header_compatibility
  COMMAND ${Python3_EXECUTABLE}
          ${CMAKE_CURRENT_SOURCE_DIR}/abi/check_header_drift.py
          --public ${PROJECT_SOURCE_DIR}/include/ipa_core.h
          --internal ${PROJECT_SOURCE_DIR}/ipa-src/hw/linux/ipa_core.h
)

add_test(
  NAME ipa_core_cleanup_regressions
  COMMAND ${Python3_EXECUTABLE}
          ${CMAKE_CURRENT_SOURCE_DIR}/runtime/test_core_regressions.py
          --source ${PROJECT_SOURCE_DIR}/ipa-src/hw/linux/ipa_core.c
)

add_executable(ipa_config_snapshot_test
  runtime/test_config_snapshot.c
  ${PROJECT_SOURCE_DIR}/ipa-src/hw/linux/runtime/ipa_config_snapshot.c)
target_compile_features(ipa_config_snapshot_test PRIVATE c_std_11)
target_include_directories(ipa_config_snapshot_test PRIVATE
  ${PROJECT_SOURCE_DIR}/include
  ${PROJECT_SOURCE_DIR}/ipa-src/hw/linux/runtime
  ${PROJECT_SOURCE_DIR}/ipa-src/hw/linux
  ${PROJECT_SOURCE_DIR}/ipa-src/profile-assistant-commons/core
  ${PROJECT_SOURCE_DIR}/ipa-src/profile-assistant-commons/core/logger
  ${PROJECT_SOURCE_DIR}/ipa-src/profile-assistant-commons/hw/linux)
target_compile_definitions(ipa_config_snapshot_test PRIVATE
  SGP32 ENABLE_MQTT ENABLE_LWM2M ENABLE_HTTP_ESIPA)
add_test(NAME ipa_config_snapshot COMMAND ipa_config_snapshot_test)

add_executable(ipa_task_supervisor_test
  runtime/test_task_supervisor.c
  ${PROJECT_SOURCE_DIR}/ipa-src/hw/linux/runtime/ipa_task_supervisor.c)
target_compile_features(ipa_task_supervisor_test PRIVATE c_std_11)
target_include_directories(ipa_task_supervisor_test PRIVATE
  ${PROJECT_SOURCE_DIR}/ipa-src/hw/linux/runtime)
target_link_libraries(ipa_task_supervisor_test PRIVATE pthread)
add_test(NAME ipa_task_supervisor COMMAND ipa_task_supervisor_test)

add_executable(ipa_runtime_lifecycle_test
  runtime/test_runtime_lifecycle.c
  ${PROJECT_SOURCE_DIR}/ipa-src/hw/linux/runtime/ipa_runtime.c
  ${PROJECT_SOURCE_DIR}/ipa-src/hw/linux/runtime/ipa_config_snapshot.c
  ${PROJECT_SOURCE_DIR}/ipa-src/hw/linux/runtime/ipa_task_supervisor.c)
target_compile_features(ipa_runtime_lifecycle_test PRIVATE c_std_11)
target_include_directories(ipa_runtime_lifecycle_test PRIVATE
  ${PROJECT_SOURCE_DIR}/include
  ${PROJECT_SOURCE_DIR}/ipa-src/hw/linux/runtime)
target_link_libraries(ipa_runtime_lifecycle_test PRIVATE pthread)
add_test(NAME ipa_runtime_lifecycle COMMAND ipa_runtime_lifecycle_test)

add_executable(ipa_euicc_executor_test
  runtime/test_euicc_executor.c
  ${PROJECT_SOURCE_DIR}/ipa-src/hw/linux/runtime/ipa_euicc_executor.c)
target_compile_features(ipa_euicc_executor_test PRIVATE c_std_11)
target_include_directories(ipa_euicc_executor_test PRIVATE
  ${PROJECT_SOURCE_DIR}/ipa-src/hw/linux/runtime)
target_link_libraries(ipa_euicc_executor_test PRIVATE pthread)
add_test(NAME ipa_euicc_executor COMMAND ipa_euicc_executor_test)
