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
  NAME ipa_internal_header_drift_known_debt
  COMMAND ${Python3_EXECUTABLE}
          ${CMAKE_CURRENT_SOURCE_DIR}/abi/check_header_drift.py
          --internal ${PROJECT_SOURCE_DIR}/ipa-src/hw/linux/ipa_core.h
)
set_tests_properties(ipa_internal_header_drift_known_debt PROPERTIES WILL_FAIL TRUE)
