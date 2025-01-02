add_library(accountdb)


target_sources(accountdb PRIVATE
    "accountdbsql.cpp")

target_link_libraries(accountdb PUBLIC
    common)
