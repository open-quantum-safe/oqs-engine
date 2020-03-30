add_library(oqse SHARED oqse.c
                        oqse_ameth.c
                        oqse_pmeth.c
                        oqse_utils.c
                        oqse_err.c)

target_include_directories(oqse PUBLIC ${LIBOQS_INCLUDE_DIR}
                                PUBLIC ${OPENSSL_INCLUDE_DIR})

if(WIN32)
    target_link_libraries(oqse PUBLIC ${LIBOQS_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})
    set(CMAKE_SHARED_LIBRARY_PREFIX "lib")
else()
    target_link_libraries(oqse PUBLIC ${LIBOQS_LIBRARY} m ${OPENSSL_CRYPTO_LIBRARY})
endif()

set_target_properties(oqse
    PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
    VERSION 0.0.0
    SOVERSION 0
    # For Windows DLLs
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

install(TARGETS oqse
        LIBRARY DESTINATION lib
        ARCHIVE DESTINATION lib)
