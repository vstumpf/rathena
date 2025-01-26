#include "login.hpp"

using rathena::server_login::LoginServer;

int32 main(int32 argc, char *argv[]) {
	return main_core<LoginServer>(argc, argv);
}
