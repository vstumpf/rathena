// Copyright (c) rAthena Dev Teams - Licensed under GNU GPL
// For more information, see LICENCE in the main folder

#ifndef CONTROLLER_HPP
#define CONTROLLER_HPP

#include <string>

#include "http.hpp"

class Controller {
public:
	Controller(const Request &req, Response &res) : request(req), response(res) {};

protected:
	bool isAuthorized();
	bool isGuildLeader();
	bool hasField(const char * key);
	int getAccountId(const char * key = "AID");
	int getCharId(const char * key = "GID");
	int getGuildId(const char * key = "GDID");
	std::string& getData(const char * key = "data");
	std::string& getToken(const char * key = "AuthToken");
	std::string& getWorldName(const char * key = "WorldName");

	void makeError(std::string msg = "Error", int code = 400);
	void makeResponse(std::string msg, int code = 200);

	int account_id{0};
	int char_id{0};
	int guild_id{0};
	std::string auth_token{};
	std::string world_name{};
	std::string data{};


	const Request &request;
	Response &response;
};

#endif
