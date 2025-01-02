add_library(login)
target_sources(login PRIVATE
	"ipban.cpp"
	"login.cpp"
	"logincnslif.cpp"
	"loginchrif.cpp"
	"loginclif.cpp"
	"loginlog.cpp"
)

if(WIN32)
	target_sources(login PRIVATE
		"ipban.hpp"
		"login.hpp"
		"loginchrif.hpp"
		"loginclif.hpp"
		"logincnslif.hpp"
		"login.hpp"
		"loginlog.hpp"
	)

	set_target_properties(login PROPERTIES FOLDER "Servers")
endif()

target_link_libraries(login PUBLIC
	common
	accountdb
)

add_executable(login-server "LoginServer.cpp")
target_link_libraries(login-server PRIVATE login)

add_subdirectory(accountdb)
