add_executable(oqse_test oqse_test.c)

target_include_directories(oqse_test PRIVATE ${PROJECT_SOURCE_DIR}/src
                                     PRIVATE ${LIBOQS_INCLUDE_DIR}
                                     PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(oqse_test PRIVATE oqse)

add_custom_target(
    run_tests
    COMMAND env OPENSSL_ENGINES=${PROJECT_BINARY_DIR}/lib ./tests/oqse_test
    WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
    DEPENDS oqse oqse_test
    USES_TERMINAL)
