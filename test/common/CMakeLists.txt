
# Adds a test for common.
# Usage: add_common_test(name srcs...)
function(add_common_test name)
    cmake_parse_arguments(ADD_COMMON_TEST "HEADER_ONLY;MODULE" "" "" ${ARGN})
    
    set(sources ${name}.cpp ${ADD_COMMON_TEST_UNPARSED_ARGUMENTS})
    set(libs common gtest_main)
    
    add_executable(${name} ${sources})
    target_link_libraries(${name} ${libs})
    target_include_directories(${name} PRIVATE ${RA_INCLUDE_DIRS})
    message(STATUS "Adding common test ${name} with sources ${sources}")
    add_test(NAME ${name} COMMAND ${name})
endfunction()


add_common_test(utilities_test)
