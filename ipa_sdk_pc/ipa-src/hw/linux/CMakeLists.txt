if (BUILD_SHARED_LIBS)
    add_library(${PROJECT_NAME} SHARED ipa_core.c)
    message("Building shared library (.so)")
else ()
    add_library(${PROJECT_NAME} STATIC ipa_core.c)
    message("Building static library (.a)")
endif ()
target_include_directories(${PROJECT_NAME} PRIVATE .)
target_sources(${PROJECT_NAME} PRIVATE ipa_core.c)
set_target_properties(${PROJECT_NAME} PROPERTIES OUTPUT_NAME "ipa")

target_compile_options(${PROJECT_NAME} PUBLIC -g -Wall  -Wno-error -fvisibility=hidden)
# Only for Jenkins (MACOS)
if (APPLE)
    include_directories(/usr/local/include)
    target_link_directories(${PROJECT_NAME} PUBLIC /usr/local/lib)
    #    target_compile_options(${PROJECT_NAME} PUBLIC -Wno-error=nullability-completeness -Wno-error=expansion-to-defined -Wno-error=enum-conversion)
endif ()

# eUICC Options
option(SGP22 "For an SGP.22 eUICC" OFF)
option(SGP32 "For an SGP.32 eUICC" ON)

# Protocol Options
option(ENABLE_MQTT "Enable the MQTT ESipa protocol" ON)
option(ENABLE_LWM2M "Enable the LWM2M ESipa protocol" ON)
option(ENABLE_HTTP_ESIPA "Enable the HTTP ESipa protocol" ON)

# PCSC Options
option(ENABLE_PCSC "Enable the PCSC interface" OFF)
# IPA features options
option(INDIRECT_DOWNLOAD "For an IPA with indirect download" OFF)
option(EIM_DOWNLOAD_DATA_HANDLING "For an IPA with eimDownloadDataHandling capability" OFF)
option(EIM_CTX_PARAMS1_GENERATION "For an IPA with eimCtxParams1Generation capability" ON)
option(EIM_PROFILE_METADATA_VERIFICATION "For an IPA with eimProfileMetadataVerification capability" OFF)
option(MINIMIZE_ESIPA_BYTES "For an IPA with minimizeEsipaBytes capability" OFF)

# Logger Flags: DEBUG_WITH_TIME, DEBUG_WITH_LOGLEVEL, DEBUG_WITH_ELAPSED, DEBUG_ALLOCATIONS, DEBUG_SERIAL_PORT_RW, DEBUG_WITH_THREAD_ID
target_compile_definitions(${PROJECT_NAME} PRIVATE DEBUG_WITH_TIME DEBUG_WITH_LOGLEVEL DEBUG_ALLOCATIONS DEBUG_WITH_THREAD_ID)
# Esipa features
target_compile_definitions(${PROJECT_NAME} PRIVATE ENABLE_ESIPA_JSON)

if (ENABLE_PCSC)
    message("IPA compiled with the PCSC interface")
    find_library(PCSC_LIBRARIES NAMES pcsclite)
    find_path(PCSC_INCLUDE_DIRS NAMES pcsclite.h PATH_SUFFIXES PCSC)
    if(NOT PCSC_LIBRARIES)
        message(FATAL_ERROR "PCSCLite library not found")
    endif()
    if(NOT PCSC_INCLUDE_DIRS)
        message(FATAL_ERROR "PCSCLite include directory not found")
    endif()

    include_directories(${PCSC_INCLUDE_DIRS})

    target_link_libraries(${PROJECT_NAME} PUBLIC ${PCSC_LIBRARIES})
endif()
# eUICC Flags
if (SGP32)
    message("IPA compiled for a eUICC SGP.32")
    target_compile_definitions(${PROJECT_NAME} PRIVATE SGP32)
else ()
    message("IPA compiled for a eUICC SGP.22")
    target_compile_definitions(${PROJECT_NAME} PRIVATE SGP22)
endif ()

# Protocol Flags
if (ENABLE_MQTT)
    message("IPA compiled with the MQTT ESipa protocol")
    target_compile_definitions(${PROJECT_NAME} PRIVATE ENABLE_MQTT)
endif ()
if (ENABLE_LWM2M)
    message("IPA compiled with the LWM2M ESipa protocol")
    target_compile_definitions(${PROJECT_NAME} PRIVATE ENABLE_LWM2M)
endif ()
if (ENABLE_HTTP_ESIPA)
    message("IPA compiled with the HTTP ESipa protocol")
    target_compile_definitions(${PROJECT_NAME} PRIVATE ENABLE_HTTP_ESIPA)
endif ()
if (ENABLE_PCSC)
    message("IPA compiled with the PCSC interface")
    target_compile_definitions(${PROJECT_NAME} PRIVATE ENABLE_PCSC)
endif()




# IPA features
if (INDIRECT_DOWNLOAD)
    message("IPA compiled with indirect download")
    target_compile_definitions(${PROJECT_NAME} PRIVATE IPA_FEATURE_INDIRECT_DOWNLOAD)
    if (EIM_DOWNLOAD_DATA_HANDLING)
        message("IPA capability eimDownloadDataHandling activated")
        target_compile_definitions(${PROJECT_NAME} PRIVATE IPA_FEATURE_EIM_DOWNLOAD_DATA_HANDLING)
    endif ()
    if (EIM_CTX_PARAMS1_GENERATION)
        message("IPA capability eimCtxParams1Generation activated")
        target_compile_definitions(${PROJECT_NAME} PRIVATE IPA_FEATURE_EIM_CTX_PARAMS1_GENERATION)
    endif ()
    if (EIM_PROFILE_METADATA_VERIFICATION)
        message("IPA capability eimProfileMetadataVerification activated")
        target_compile_definitions(${PROJECT_NAME} PRIVATE IPA_FEATURE_EIM_PROFILE_METADATA_VERIFICATION)
    endif()
    if (MINIMIZE_ESIPA_BYTES)
        message("IPA capability minimizeEsipaBytes activated")
        target_compile_definitions(${PROJECT_NAME} PRIVATE IPA_FEATURE_MINIMIZE_ESIPA_BYTES)
    endif()
else ()
    message("IPA compiled with direct download")
endif ()

# IPA extra features enabled by default
target_compile_definitions(${PROJECT_NAME} PRIVATE PRE_CR EXTRA_FEATURE_IMMEDIATE_PROFILE_ENABLING EXTRA_FEATURE_FALLBACK_MECHANISM EXTRA_FEATURE_EMERGENCY_PROFILE_MANAGMENT)

# IPA test features for internal test purposes only
target_compile_definitions(${PROJECT_NAME} PRIVATE TEST_FEATURE_PROFILE_ROLLBACK)
# Libraries
target_link_libraries(${PROJECT_NAME} PUBLIC curl)
target_link_libraries(${PROJECT_NAME} PUBLIC c)
target_link_libraries(${PROJECT_NAME} PUBLIC serialport)
target_link_libraries(${PROJECT_NAME} PUBLIC pthread)


if (ENABLE_MQTT)
    target_link_libraries(${PROJECT_NAME} PUBLIC paho-mqtt3cs)
endif ()
if (ENABLE_LWM2M)
    include(external/wakaama/wakaama.cmake)
    target_include_directories(${PROJECT_NAME} PUBLIC external/wakaama/include)
    target_include_directories(${PROJECT_NAME} PUBLIC external/wakaama/examples/shared)
    target_compile_definitions(${PROJECT_NAME} PRIVATE LWM2M_CLIENT_MODE LWM2M_BOOTSTRAP LWM2M_SUPPORT_SENML_JSON LWM2M_SUPPORT_TLV)
    target_sources_wakaama(${PROJECT_NAME})
    target_sources_shared(${PROJECT_NAME})
    add_subdirectory(./lwm2m lwm2m)
endif ()
# Recursive include for IPA-C
add_subdirectory(../../. ipa_dir)
add_subdirectory(../../profile-assistant-commons/hw/linux hw)
