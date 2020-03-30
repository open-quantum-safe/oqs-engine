configure_file(${CMAKE_CURRENT_LIST_DIR}/CMakeLists.txt.in ${CMAKE_CURRENT_BINARY_DIR}/liboqs-download/CMakeLists.txt)

execute_process(COMMAND ${CMAKE_COMMAND} -G ${CMAKE_GENERATOR} .
    RESULT_VARIABLE LIBOQS_STEP_RESULT
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/liboqs-download)
if(LIBOQS_STEP_RESULT)
    message(FATAL_ERROR "liboqs download failed: ${LIBOQS_STEP_RESULT}")
endif()
execute_process(COMMAND ${CMAKE_COMMAND} --build .
    RESULT_VARIABLE LIBOQS_STEP_RESULT
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/liboqs-download)
if(LIBOQS_STEP_RESULT)
    message(FATAL_ERROR "liboqs build failed: ${LIBOQS_STEP_RESULT}")
endif()

set(LIBOQS_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}/liboqs-build/include")
find_library(LIBOQS_LIBRARY
    NAMES oqs
    PATHS "${CMAKE_CURRENT_BINARY_DIR}/liboqs-build/lib"
    NO_DEFAULT_PATH)
add_library(OQS::oqs UNKNOWN IMPORTED GLOBAL)
set_target_properties(OQS::oqs PROPERTIES IMPORTED_LOCATION "${LIBOQS_LIBRARY}")
