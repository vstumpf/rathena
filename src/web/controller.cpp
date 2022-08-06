// Copyright (c) rAthena Dev Teams - Licensed under GNU GPL
// For more information, see LICENCE in the main folder

#include "controller.hpp"

#include <string>

#include "../common/showmsg.hpp"
#include "../common/sql.hpp"

#include "http.hpp"
#include "sqllock.hpp"
#include "web.hpp"

bool Controller::isAuthorized() {
	if (!hasField("AuthToken") || !hasField("AID"))
		return false;

	getToken();
	getAccountId();

	SQLLock loginlock(LOGIN_SQL_LOCK);
	loginlock.lock();
	auto handle = loginlock.getHandle();
	SqlStmt * stmt = SqlStmt_Malloc(handle);

	if (SQL_SUCCESS != SqlStmt_Prepare(stmt,
			"SELECT `account_id` FROM `%s` WHERE (`account_id` = ? AND `web_auth_token` = ? AND `web_auth_token_enabled` = '1')",
			login_table)
		|| SQL_SUCCESS != SqlStmt_BindParam(stmt, 0, SQLDT_INT, &account_id, sizeof(account_id))
		|| SQL_SUCCESS != SqlStmt_BindParam(stmt, 1, SQLDT_STRING, (void *)auth_token.c_str(), auth_token.length())
		|| SQL_SUCCESS != SqlStmt_Execute(stmt)
	) {
		SqlStmt_ShowDebug(stmt);
		SqlStmt_Free(stmt);
		loginlock.unlock();
		return false;
	}

	if (SqlStmt_NumRows(stmt) <= 0) {
		ShowWarning("Request with AID %d and token %s unverified\n", account_id, auth_token.c_str());
		SqlStmt_Free(stmt);
		loginlock.unlock();
		return false;
	}

	SqlStmt_Free(stmt);
	loginlock.unlock();
	return true;
}

bool Controller::isGuildLeader() {
	if (!hasField("AuthToken") || !hasField("AID") || !hasField("GDID"))
		return false;

	getToken();
	getAccountId();
	getGuildId();

	SQLLock charlock(CHAR_SQL_LOCK);
	charlock.lock();
	auto handle = charlock.getHandle();
	auto stmt = SqlStmt_Malloc(handle);

	if (SQL_SUCCESS != SqlStmt_Prepare(stmt,
		"SELECT `account_id` FROM `%s` LEFT JOIN `%s` using (`char_id`) WHERE (`%s`.`account_id` = ? AND `%s`.`guild_id` = ?) LIMIT 1",
		guild_db_table, char_db_table, char_db_table, guild_db_table)
		|| SQL_SUCCESS != SqlStmt_BindParam(stmt, 0, SQLDT_INT, &account_id, sizeof(account_id))
		|| SQL_SUCCESS != SqlStmt_BindParam(stmt, 1, SQLDT_INT, &guild_id, sizeof(guild_id))
		|| SQL_SUCCESS != SqlStmt_Execute(stmt)
	) {
		SqlStmt_ShowDebug(stmt);
		SqlStmt_Free(stmt);
		charlock.unlock();
		return false;
	}

	if (SqlStmt_NumRows(stmt) <= 0) {
		ShowDebug("Request with AID %d GDID %d and token %s unverified\n", account_id, guild_id, auth_token.c_str());
		SqlStmt_Free(stmt);
		charlock.unlock();
		return false;
	}
	SqlStmt_Free(stmt);
	charlock.unlock();
	return true;

}

int Controller::getAccountId(const char * key) {
	if (!account_id)
		account_id = std::stoi(request.get_file_value(key).content);

	return account_id;
}

int Controller::getCharId(const char * key) {
	if (!char_id)
		char_id = std::stoi(request.get_file_value(key).content);

	return char_id;
}

int Controller::getGuildId(const char * key) {
	if (!guild_id)
		guild_id = std::stoi(request.get_file_value(key).content);

	return guild_id;
}

std::string& Controller::getToken(const char * key) {
	if (auth_token.empty())
		auth_token = request.get_file_value(key).content;

	return auth_token;
}

std::string& Controller::getWorldName(const char * key) {
	if (world_name.empty())
		world_name = request.get_file_value(key).content;

	return world_name;
}

void Controller::makeError(std::string msg, int code) {
	response.status = code;
	response.set_content(msg, "text/plain");
}

void Controller::makeResponse(std::string msg, int code) {
	response.status = code;
	response.set_content(msg, "application/json");
}
