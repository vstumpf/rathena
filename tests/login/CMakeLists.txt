
# Adds a test for login.
# Usage: add_login_test(name srcs...)
function(add_login_test name)
    cmake_parse_arguments(ADD_LOGIN_TEST "HEADER_ONLY;MODULE" "" "" ${ARGN})
    
    set(sources ${name}.cpp ../ServerTests.cpp ${ADD_LOGIN_TEST_UNPARSED_ARGUMENTS})
    set(libs login gtest_main)
    
    add_executable(${name} ${sources})
    target_link_libraries(${name} ${libs})
    target_include_directories(${name} PRIVATE ${RA_INCLUDE_DIRS})
    add_test(NAME ${name} COMMAND ${name})
endfunction()


add_login_test(accountdbsql_test)
