// Copyright (c) rAthena Dev Teams - Licensed under GNU GPL
// For more information, see LICENCE in the main folder

#include "charconfig.hpp"

#include <string>

#include "../common/showmsg.hpp"
#include "../common/sql.hpp"

#include "auth.hpp"
#include "http.hpp"
#include "sqllock.hpp"
#include "webutils.hpp"
#include "web.hpp"

void CharConfigController::saveCharConfig() {
	if (!isAuthorized()) {
		makeError();
		return;
	}
	
	if (!hasField("AuthToken") || !hasField("AID") || !hasField("GID") || !hasField("WorldName")) {
		makeError();
		return;
	}

	getAccountId();
	getCharId();
	getWorldName();

	if (hasField("data")) {
		getData();
		addToJsonObject(data, "\"Type\": 1");
	} else {
		data = "{\"Type\": 1}";
	}
	SQLLock sl(WEB_SQL_LOCK);
	sl.lock();
	auto handle = sl.getHandle();
	SqlStmt * stmt = SqlStmt_Malloc(handle);
	if (SQL_SUCCESS != SqlStmt_Prepare(stmt,
			"SELECT `account_id` FROM `%s` WHERE (`account_id` = ? AND `char_id` = ? AND `world_name` = ?) LIMIT 1",
			char_configs_table)
		|| SQL_SUCCESS != SqlStmt_BindParam(stmt, 0, SQLDT_INT, &account_id, sizeof(account_id))
		|| SQL_SUCCESS != SqlStmt_BindParam(stmt, 1, SQLDT_INT, &char_id, sizeof(char_id))
		|| SQL_SUCCESS != SqlStmt_BindParam(stmt, 2, SQLDT_STRING, (void *)world_name.c_str(), world_name.length())
		|| SQL_SUCCESS != SqlStmt_Execute(stmt)
	) {
		SqlStmt_ShowDebug(stmt);
		SqlStmt_Free(stmt);
		sl.unlock();
		makeError();
		return;
	}

	if (SqlStmt_NumRows(stmt) <= 0) {
		if (SQL_SUCCESS != SqlStmt_Prepare(stmt,
				"INSERT INTO `%s` (`account_id`, `char_id`, `world_name`, `data`) VALUES (?, ?, ?, ?)",
				char_configs_table)
			|| SQL_SUCCESS != SqlStmt_BindParam(stmt, 0, SQLDT_INT, &account_id, sizeof(account_id))
			|| SQL_SUCCESS != SqlStmt_BindParam(stmt, 1, SQLDT_INT, &char_id, sizeof(char_id))
			|| SQL_SUCCESS != SqlStmt_BindParam(stmt, 2, SQLDT_STRING, (void *)world_name.c_str(), world_name.length())
			|| SQL_SUCCESS != SqlStmt_BindParam(stmt, 3, SQLDT_STRING, (void *)data.c_str(), data.length())
			|| SQL_SUCCESS != SqlStmt_Execute(stmt)
		) {
			SqlStmt_ShowDebug(stmt);
			SqlStmt_Free(stmt);
			sl.unlock();
			makeError();
			return;
		}
	} else {
		if (SQL_SUCCESS != SqlStmt_Prepare(stmt,
				"UPDATE `%s` SET `data` = ? WHERE (`account_id` = ? AND `char_id` = ? AND `world_name` = ?)",
				char_configs_table)
			|| SQL_SUCCESS != SqlStmt_BindParam(stmt, 0, SQLDT_STRING, (void *)data.c_str(), strlen(data.c_str()))
			|| SQL_SUCCESS != SqlStmt_BindParam(stmt, 1, SQLDT_INT, &account_id, sizeof(account_id))
			|| SQL_SUCCESS != SqlStmt_BindParam(stmt, 2, SQLDT_INT, &char_id, sizeof(char_id))
			|| SQL_SUCCESS != SqlStmt_BindParam(stmt, 3, SQLDT_STRING, (void *)world_name.c_str(), world_name.length())
			|| SQL_SUCCESS != SqlStmt_Execute(stmt)
		) {
			SqlStmt_ShowDebug(stmt);
			SqlStmt_Free(stmt);
			sl.unlock();
			makeError();
			return;
		}
	}

	SqlStmt_Free(stmt);
	sl.unlock();
	makeResponse(data);
}

void CharConfigController::save(const Request &req, Response &res) {
	CharConfigController c(req, res);
	c.saveCharConfig();
}