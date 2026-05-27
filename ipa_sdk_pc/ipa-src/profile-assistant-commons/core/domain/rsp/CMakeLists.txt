target_include_directories(${PROJECT_NAME} PRIVATE .)

target_sources(${PROJECT_NAME} PRIVATE mutual_authentication.c)
target_sources(${PROJECT_NAME} PRIVATE ppr_verification.c)
target_sources(${PROJECT_NAME} PRIVATE rsp.c)
