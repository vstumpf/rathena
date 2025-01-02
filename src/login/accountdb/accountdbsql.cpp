// Copyright (c) rAthena Dev Teams - Licensed under GNU GPL
// For more information, see LICENCE in the main folder

#include "accountdbsql.hpp"

#include <algorithm>
#include <charconv>
#include <memory>
#include <string>

#include <config/core.hpp>

#include <common/cbasetypes.hpp>
#include <common/mmo.hpp>
#include <common/showmsg.hpp>
#include <common/sql.hpp>
#include <common/strlib.hpp>

#include "accountdb.hpp"
#include "mmo_account.hpp"

constexpr std::string_view LOGIN_SERVER_PROPERTY_PREFIX = "login_server_";
constexpr std::string_view LOGIN_PROPERTY_PREFIX = "login_";

AccountDbSql::~AccountDbSql() {
	if (accounts_ == nullptr) {
		return;
	}
	if (SQL_ERROR == Sql_Query(accounts_, "UPDATE `%s` SET `web_auth_token` = NULL", account_table_.c_str())) {
		Sql_ShowDebug(accounts_);
	}

	Sql_Free(accounts_);
	accounts_ = nullptr;
}

bool AccountDbSql::init() {

	accounts_ = Sql_Malloc();
	if (SQL_ERROR == Sql_Connect(accounts_, db_username_.c_str(), db_password_.c_str(), db_hostname_.c_str(), db_port_, db_database_.c_str())) {
		ShowError("Couldn't connect with uname: %s, host: %s, port: %hu, db: %s\n", db_username_.c_str(), db_hostname_.c_str(), db_port_, db_database_.c_str());
		Sql_ShowDebug(accounts_);
		Sql_Free(accounts_);
		accounts_ = nullptr;
		return false;
	}

	if (codepage_.empty() == false && SQL_ERROR == Sql_SetEncoding(accounts_, codepage_.c_str())) {
		ShowWarning("Couldn't set encoding to %s\n", codepage_.c_str());
		Sql_ShowDebug(accounts_);
	}

	removeAllWebTokens();
	return true;
}

bool AccountDbSql::setProperty(std::string_view key, std::string_view value) {
	ShowInfo("Setting property %s to %s\n", key.data(), value.data());
	if (key.rfind(LOGIN_SERVER_PROPERTY_PREFIX, 0) == 0) {
		key.remove_prefix(LOGIN_SERVER_PROPERTY_PREFIX.length());
		if (key == "ip") {
			db_hostname_ = value;
		}
		else if (key == "port") {
			std::from_chars(value.data(), value.data() + value.size(), db_port_);
		}
		else if (key == "id") {
			db_username_ = value;
		}
		else if (key == "pw") {
			db_password_ = value;
		}
		else if (key == "db") {
			db_database_ = value;
		}
		else if (key == "account_db") {
			account_table_ = value;
		}
		else if (key == "global_acc_reg_str_table") {
			global_acc_reg_str_table_ = value;
		}
		else if (key == "global_acc_reg_num_table") {
			global_acc_reg_num_table_ = value;
		}
		else {
			return false;
		}
		return true;
	}

	if (key.rfind(LOGIN_PROPERTY_PREFIX, 0) == 0) {
		key.remove_prefix(LOGIN_PROPERTY_PREFIX.length());
		if (key == "codepage") {
			codepage_ = value;
		}
		else if (key == "case_sensitive") {
			case_sensitive_ = config_switch(value.data());
		}
		else {
			return false;
		}
		return true;
	}

	return false;
}

bool AccountDbSql::create(MmoAccount& acc) {
	uint32 account_id;
	if (acc.account_id != -1) {
		account_id = acc.account_id;
	}
	else {
		// TODO: We should let the INSERT create a new account_id instead of doing it manually.
		// possible race condition
		if (SQL_SUCCESS != Sql_Query(accounts_, "SELECT MAX(`account_id`)+1 FROM `%s`", account_table_.c_str())) {
			Sql_ShowDebug(accounts_);
			return false;
		}
		if (SQL_SUCCESS != Sql_NextRow(accounts_)) {
			Sql_ShowDebug(accounts_);
			Sql_FreeResult(accounts_);
			return false;
		}

		char* data;
		size_t len;
		Sql_GetData(accounts_, 0, &data, &len);
		account_id = (data != nullptr) ? atoi(data) : 0;
		Sql_FreeResult(accounts_);
		account_id = std::max<uint32>(START_ACCOUNT_NUM, account_id);
	}

	if (account_id == 0 || account_id > END_ACCOUNT_NUM) {
		return false;
	}

	acc.account_id = account_id;
	return save(acc, true /* is_new */);
}

bool AccountDbSql::remove(const uint32 account_id) {
	bool result = false;

	if (SQL_SUCCESS != Sql_QueryStr(accounts_, "START TRANSACTION") ||
		SQL_SUCCESS !=
			Sql_Query(accounts_, "DELETE FROM `%s` WHERE `account_id` = %d", account_table_.c_str(), account_id) ||
		SQL_SUCCESS !=
			Sql_Query(
				accounts_, "DELETE FROM `%s` WHERE `account_id` = %d", global_acc_reg_num_table_.c_str(), account_id) ||
		SQL_SUCCESS !=
			Sql_Query(
				accounts_, "DELETE FROM `%s` WHERE `account_id` = %d", global_acc_reg_str_table_.c_str(), account_id)) {
		Sql_ShowDebug(accounts_);
	}
	else {
		result = true;
	}

	result &= (SQL_SUCCESS == Sql_QueryStr(accounts_, (result == true) ? "COMMIT" : "ROLLBACK"));

	return result;
}

bool AccountDbSql::enableWebToken(const uint32 account_id) {
	if (SQL_ERROR == Sql_Query(accounts_,
							   "UPDATE `%s` SET `web_auth_token_enabled` = "
							   "'1' WHERE `account_id` = %d",
							   account_table_.c_str(),
							   account_id)) {
		Sql_ShowDebug(accounts_);
		return false;
	}
	return true;
}

bool AccountDbSql::disableWebToken(const uint32 account_id) {
	if (SQL_ERROR == Sql_Query(accounts_,
							   "UPDATE `%s` SET `web_auth_token_enabled` = "
							   "'0' WHERE `account_id` = %d",
							   account_table_.c_str(),
							   account_id)) {
		Sql_ShowDebug(accounts_);
		return false;
	}
	return true;
}

bool AccountDbSql::removeAllWebTokens() {
	if (SQL_ERROR == Sql_Query(accounts_,
							   "UPDATE `%s` SET `web_auth_token` = NULL, "
							   "`web_auth_token_enabled` = '0'",
							   account_table_.c_str())) {
		Sql_ShowDebug(accounts_);
		return false;
	}
	return true;
}

bool AccountDbSql::refreshWebToken(MmoAccount& acc) {
	static bool initialized = false;
	static const char* query;

	if (SQL_SUCCESS == Sql_Query(accounts_, "SELECT SHA2( 'test', 256 )")) {
		query =
			"UPDATE `%s` SET `web_auth_token` = LEFT( "
			"SHA2( CONCAT( UUID(), RAND() ), 256 ), %d ), "
			"`web_auth_token_enabled` = '1' WHERE "
			"`account_id` = '%d'";
		initialized = true;
	}
	else if (SQL_SUCCESS == Sql_Query(accounts_, "SELECT MD5( 'test' )")) {
		query =
			"UPDATE `%s` SET `web_auth_token` = LEFT( MD5( "
			"CONCAT( UUID(), RAND() ) ), %d ), "
			"`web_auth_token_enabled` = '1' WHERE "
			"`account_id` = '%d'";
		initialized = true;
	}
	else {
		ShowWarning(
			"Your MySQL does not support SHA2 and MD5 - no "
			"hashing will be used for login token creation.\n");
		ShowWarning(
			"If you are using an old version of MySQL consider "
			"upgrading to a newer release.\n");
		query =
			"UPDATE `%s` SET `web_auth_token` = LEFT( CONCAT( "
			"UUID(), RAND() ), %d ), `web_auth_token_enabled` = "
			"'1' WHERE `account_id` = '%d'";
		initialized = true;
	}

	const int32 MAX_RETRIES = 20;
	int32 i = 0;

	// Retry it for a maximum number of retries
	do {
		if (SQL_SUCCESS == Sql_Query(accounts_, query, account_table_.c_str(), WEB_AUTH_TOKEN_LENGTH - 1, acc.account_id)) {
			char* data;
			if (SQL_SUCCESS != Sql_Query(accounts_,
										 "SELECT `web_auth_token` FROM `%s` WHERE `account_id` = %d",
										 account_table_.c_str(),
										 acc.account_id) ||
				SQL_SUCCESS != Sql_NextRow(accounts_) || SQL_SUCCESS != Sql_GetData(accounts_, 0, &data, nullptr)) {
				break;
			}
			safestrncpy(acc.web_auth_token, data, sizeof(acc.web_auth_token));
			return true;
		}
	} while (i < MAX_RETRIES && Sql_GetError(accounts_) == 1062);

	if (i == MAX_RETRIES) {
		ShowError("Failed to generate a unique web_auth_token with %d retries...\n", i);
	}
	else {
		Sql_ShowDebug(accounts_);
	}

	return false;
}

bool AccountDbSql::save(const MmoAccount& acc) {
	return save(acc, false);
}

bool AccountDbSql::loadFromAccountId(MmoAccount& acc, const uint32 account_id) {
	return load(acc, account_id);
}

bool AccountDbSql::loadFromUsername(MmoAccount& acc, const char* userid) {
	if (SQL_SUCCESS != Sql_Query(accounts_,
								 "SELECT `account_id` FROM `%s` WHERE `userid` = %s '%s'",
								 account_table_.c_str(),
								 case_sensitive_ ? "BINARY" : "",
								 userid)) {
		Sql_ShowDebug(accounts_);
		return false;
	}
	if (Sql_NumRows(accounts_) > 1) {
		ShowError("account_db_sql_load_str: multiple accounts found when retrieving data for account '%s'!\n", userid);
		Sql_FreeResult(accounts_);
		return false;
	}
	if (SQL_SUCCESS != Sql_NextRow(accounts_)) {
		Sql_FreeResult(accounts_);
		return false;
	}
	char* data;
	Sql_GetData(accounts_, 0, &data, nullptr);
	return load(acc, atoi(data));
}

std::vector<AccountRegVesselStr> AccountDbSql::loadGlobalAccRegStr(uint32 account_id) {
	if (SQL_SUCCESS != Sql_Query(accounts_,
								 "SELECT `key`, `index`, `value` FROM `%s` WHERE `account_id` = %d",
								 global_acc_reg_num_table_.c_str(),
								 account_id)) {
		Sql_ShowDebug(accounts_);
		return {};
	}

	std::vector<AccountRegVesselStr> regs;

	while (SQL_SUCCESS == Sql_NextRow(accounts_)) {
		AccountRegVesselStr reg;
		char* data;

		Sql_GetData(accounts_, 0, &data, nullptr);
		reg.key = data;
		Sql_GetData(accounts_, 1, &data, nullptr);
		reg.index = atoi(data);
		Sql_GetData(accounts_, 2, &data, nullptr);
		reg.value = data;
		regs.push_back(reg);
	}
	Sql_FreeResult(accounts_);
	return regs;
}

std::vector<AccountRegVesselNum> AccountDbSql::loadGlobalAccRegNum(uint32 account_id) {
	if (SQL_SUCCESS != Sql_Query(accounts_,
								 "SELECT `key`, `index`, `value` FROM `%s` WHERE `account_id` = %d",
								 global_acc_reg_num_table_.c_str(),
								 account_id)) {
		Sql_ShowDebug(accounts_);
		return {};
	}

	std::vector<AccountRegVesselNum> regs;

	while (SQL_SUCCESS == Sql_NextRow(accounts_)) {
		AccountRegVesselNum reg;
		char* data;

		Sql_GetData(accounts_, 0, &data, nullptr);
		reg.key = data;
		Sql_GetData(accounts_, 1, &data, nullptr);
		reg.index = atoi(data);
		Sql_GetData(accounts_, 2, &data, nullptr);
		reg.value = atoi(data);
		regs.push_back(reg);
	}

	Sql_FreeResult(accounts_);
	return regs;
}

void AccountDbSql::saveGlobalAccRegNum(uint32 account_id, std::string_view key, uint32 index, uint64 value) {
	std::string esc_key = Sql_GetEscapeString(accounts_, key);

	if (value) {
		if (SQL_ERROR == Sql_Query(accounts_,
								   "REPLACE INTO `%s` (`account_id`, `key`, `index`, "
								   "`value`) VALUES (%d, '%s', %d, %d)",
								   global_acc_reg_num_table_.c_str(),
								   account_id,
								   esc_key.c_str(),
								   index,
								   value)) {
			Sql_ShowDebug(accounts_);
		}
	}
	else {
		if (SQL_ERROR == Sql_Query(accounts_,
								   "DELETE FROM `%s` WHERE `account_id` = %d "
								   "AND `key` = '%s' AND `index` = %d LIMIT 1",
								   global_acc_reg_num_table_.c_str(),
								   account_id,
								   esc_key.c_str(),
								   index)) {
			Sql_ShowDebug(accounts_);
		}
	}
}

void AccountDbSql::saveGlobalAccRegStr(uint32 account_id, std::string_view key, uint32 index, std::string_view value) {
	std::string esc_key = Sql_GetEscapeString(accounts_, key);

	if (value.empty()) {
		if (SQL_ERROR == Sql_Query(accounts_,
								   "DELETE FROM `%s` WHERE `account_id` = %d "
								   "AND `key` = '%s' AND `index` = %d LIMIT 1",
								   global_acc_reg_str_table_.c_str(),
								   account_id,
								   esc_key.c_str(),
								   index)) {
			Sql_ShowDebug(accounts_);
		}
	}
	else {
		std::string esc_value = Sql_GetEscapeString(accounts_, esc_value);
		if (SQL_ERROR == Sql_Query(accounts_,
								   "REPLACE INTO `%s` (`account_id`, `key`, `index`, "
								   "`value`) VALUES (%d, '%s', %d, '%s')",
								   global_acc_reg_str_table_.c_str(),
								   account_id,
								   esc_key.c_str(),
								   index,
								   esc_value.c_str())) {
			Sql_ShowDebug(accounts_);
		}
	}
}

void AccountDbSql::deleteGlobalAccRegNum(uint32 account_id, std::string_view key, uint32 index) {
	std::string esc_key = Sql_GetEscapeString(accounts_, key);

	if (SQL_ERROR == Sql_Query(accounts_,
							   "DELETE FROM `%s` WHERE `account_id` = %d AND "
							   "`key` = '%s' AND `index` = %d LIMIT 1",
							   global_acc_reg_num_table_.c_str(),
							   account_id,
							   esc_key.c_str(),
							   index)) {
		Sql_ShowDebug(accounts_);
	}
}

void AccountDbSql::deleteGlobalAccRegStr(uint32 account_id, std::string_view key, uint32 index) {
	std::string esc_key = Sql_GetEscapeString(accounts_, key);

	if (SQL_ERROR == Sql_Query(accounts_,
							   "DELETE FROM `%s` WHERE `account_id` = %d AND "
							   "`key` = '%s' AND `index` = %d LIMIT 1",
							   global_acc_reg_str_table_.c_str(),
							   account_id,
							   esc_key.c_str(),
							   index)) {
		Sql_ShowDebug(accounts_);
	}
}

bool AccountDbSql::load(MmoAccount& acc, uint32 account_id) {
	if (SQL_ERROR == Sql_Query(accounts_,
#ifdef VIP_ENABLE
							   "SELECT "
							   "`account_id`,`userid`,`user_pass`,`sex`,`email`,`group_id`,`state`"
							   ",`unban_time`,`expiration_time`,`logincount`,`lastlogin`,`last_ip`"
							   ",`birthdate`,`character_slots`,`pincode`, `pincode_change`, "
							   "`vip_time`, `old_group` FROM `%s` WHERE `account_id` = %d",
#else
							   "SELECT "
							   "`account_id`,`userid`,`user_pass`,`sex`,`email`,`group_id`,`state`"
							   ",`unban_time`,`expiration_time`,`logincount`,`lastlogin`,`last_ip`"
							   ",`birthdate`,`character_slots`,`pincode`, `pincode_change` FROM "
							   "`%s` WHERE `account_id` = %d",
#endif
							   account_table_.c_str(),
							   account_id)) {
		Sql_ShowDebug(accounts_);
		return false;
	}

	if (SQL_SUCCESS != Sql_NextRow(accounts_)) {
		Sql_FreeResult(accounts_);
		return false;
	}

	char* data;
	Sql_GetData(accounts_, 0, &data, nullptr);
	acc.account_id = atoi(data);
	Sql_GetData(accounts_, 1, &data, nullptr);
	safestrncpy(acc.userid, data, sizeof(acc.userid));
	Sql_GetData(accounts_, 2, &data, nullptr);
	safestrncpy(acc.pass, data, sizeof(acc.pass));
	Sql_GetData(accounts_, 3, &data, nullptr);
	acc.sex = data[0];
	Sql_GetData(accounts_, 4, &data, nullptr);
	safestrncpy(acc.email, data, sizeof(acc.email));
	Sql_GetData(accounts_, 5, &data, nullptr);
	acc.group_id = strtoul(data, nullptr, 10);
	Sql_GetData(accounts_, 6, &data, nullptr);
	acc.state = strtoul(data, nullptr, 10);
	Sql_GetData(accounts_, 7, &data, nullptr);
	acc.unban_time = strtoull(data, nullptr, 10);
	Sql_GetData(accounts_, 8, &data, nullptr);
	acc.expiration_time = strtoull(data, nullptr, 10);
	Sql_GetData(accounts_, 9, &data, nullptr);
	acc.logincount = strtoul(data, nullptr, 10);
	Sql_GetData(accounts_, 10, &data, nullptr);
	safestrncpy(acc.lastlogin, data ? data : "", sizeof(acc.lastlogin));
	Sql_GetData(accounts_, 11, &data, nullptr);
	safestrncpy(acc.last_ip, data, sizeof(acc.last_ip));
	Sql_GetData(accounts_, 12, &data, nullptr);
	safestrncpy(acc.birthdate, data ? data : "", sizeof(acc.birthdate));
	Sql_GetData(accounts_, 13, &data, nullptr);
	acc.char_slots = atoi(data);
	Sql_GetData(accounts_, 14, &data, nullptr);
	safestrncpy(acc.pincode, data, sizeof(acc.pincode));
	Sql_GetData(accounts_, 15, &data, nullptr);
	acc.pincode_change = strtoull(data, nullptr, 10);
#ifdef VIP_ENABLE
	Sql_GetData(accounts_, 16, &data, nullptr);
	acc.vip_time = strtoull(data, nullptr, 10);
	Sql_GetData(accounts_, 17, &data, nullptr);
	acc.old_group = atoi(data);
#endif
	Sql_FreeResult(accounts_);
	acc.web_auth_token[0] = '\0';

	return true;
}

bool AccountDbSql::save(const MmoAccount& acc, bool is_new) {
	SqlStmt stmt{*accounts_};

	if (is_new) {
		if (SQL_SUCCESS != stmt.Prepare(
#ifdef VIP_ENABLE
							   "INSERT INTO `%s` (`account_id`, `userid`, `user_pass`, `sex`, `email`, `group_id`, "
							   "`state`, `unban_time`, `expiration_time`, `logincount`, `lastlogin`, `last_ip`, "
							   "`birthdate`, `character_slots`, `pincode`, `pincode_change`, `vip_time`, `old_group` ) "
							   "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
#else
							   "INSERT INTO `%s` (`account_id`, `userid`, `user_pass`, `sex`, `email`, `group_id`, "
							   "`state`, `unban_time`, `expiration_time`, `logincount`, `lastlogin`, `last_ip`, "
							   "`birthdate`, `character_slots`, `pincode`, `pincode_change`) VALUES (?, ?, ?, ?, ?, ?, "
							   "?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
#endif
							   account_table_.c_str()) ||
			SQL_SUCCESS != stmt.BindParam(0, SQLDT_INT, (void*)&acc.account_id, sizeof(acc.account_id)) ||
			SQL_SUCCESS != stmt.BindParam(1, SQLDT_STRING, (void*)acc.userid, strlen(acc.userid)) ||
			SQL_SUCCESS != stmt.BindParam(2, SQLDT_STRING, (void*)acc.pass, strlen(acc.pass)) ||
			SQL_SUCCESS != stmt.BindParam(3, SQLDT_ENUM, (void*)&acc.sex, sizeof(acc.sex)) ||
			SQL_SUCCESS != stmt.BindParam(4, SQLDT_STRING, (void*)&acc.email, strlen(acc.email)) ||
			SQL_SUCCESS != stmt.BindParam(5, SQLDT_INT, (void*)&acc.group_id, sizeof(acc.group_id)) ||
			SQL_SUCCESS != stmt.BindParam(6, SQLDT_UINT, (void*)&acc.state, sizeof(acc.state)) ||
			SQL_SUCCESS != stmt.BindParam(7, SQLDT_LONG, (void*)&acc.unban_time, sizeof(acc.unban_time)) ||
			SQL_SUCCESS != stmt.BindParam(8, SQLDT_INT, (void*)&acc.expiration_time, sizeof(acc.expiration_time)) ||
			SQL_SUCCESS != stmt.BindParam(9, SQLDT_UINT, (void*)&acc.logincount, sizeof(acc.logincount)) ||
			SQL_SUCCESS !=
				stmt.BindParam(
					10, acc.lastlogin[0] ? SQLDT_STRING : SQLDT_NULL, (void*)acc.lastlogin, strlen(acc.lastlogin)) ||
			SQL_SUCCESS != stmt.BindParam(11, SQLDT_STRING, (void*)acc.last_ip, strlen(acc.last_ip)) ||
			SQL_SUCCESS !=
				stmt.BindParam(
					12, acc.birthdate[0] ? SQLDT_STRING : SQLDT_NULL, (void*)acc.birthdate, strlen(acc.birthdate)) ||
			SQL_SUCCESS != stmt.BindParam(13, SQLDT_UCHAR, (void*)&acc.char_slots, sizeof(acc.char_slots)) ||
			SQL_SUCCESS != stmt.BindParam(14, SQLDT_STRING, (void*)acc.pincode, strlen(acc.pincode)) ||
			SQL_SUCCESS != stmt.BindParam(15, SQLDT_LONG, (void*)&acc.pincode_change, sizeof(acc.pincode_change))
#ifdef VIP_ENABLE

			|| SQL_SUCCESS != stmt.BindParam(16, SQLDT_LONG, (void*)&acc.vip_time, sizeof(acc.vip_time)) ||
			SQL_SUCCESS != stmt.BindParam(17, SQLDT_INT, (void*)&acc.old_group, sizeof(acc.old_group))
#endif
			|| SQL_SUCCESS != stmt.Execute()) {
			SqlStmt_ShowDebug(stmt);
			return false;
		}
	}
	else {
		if (SQL_SUCCESS !=
				stmt.Prepare(
#ifdef VIP_ENABLE
					"UPDATE `%s` SET "
					"`userid`=?,`user_pass`=?,`sex`=?,`email`=?,`group_id`=?,`state`=?,`unban_time`=?,`expiration_time`"
					"=?,`logincount`=?,`lastlogin`=?,`last_ip`=?,`birthdate`=?,`character_slots`=?,`pincode`=?, "
					"`pincode_change`=?, `vip_time`=?, `old_group`=? WHERE `account_id` = '%d'",
#else
					"UPDATE `%s` SET "
					"`userid`=?,`user_pass`=?,`sex`=?,`email`=?,`group_id`=?,`state`=?,`unban_time`=?,`expiration_time`"
					"=?,`logincount`=?,`lastlogin`=?,`last_ip`=?,`birthdate`=?,`character_slots`=?,`pincode`=?, "
					"`pincode_change`=? WHERE `account_id` = '%d'",
#endif
					account_table_.c_str(),
					acc.account_id) ||
			SQL_SUCCESS != stmt.BindParam(0, SQLDT_STRING, (void*)acc.userid, strlen(acc.userid)) ||
			SQL_SUCCESS != stmt.BindParam(1, SQLDT_STRING, (void*)acc.pass, strlen(acc.pass)) ||
			SQL_SUCCESS != stmt.BindParam(2, SQLDT_ENUM, (void*)&acc.sex, sizeof(acc.sex)) ||
			SQL_SUCCESS != stmt.BindParam(3, SQLDT_STRING, (void*)acc.email, strlen(acc.email)) ||
			SQL_SUCCESS != stmt.BindParam(4, SQLDT_INT, (void*)&acc.group_id, sizeof(acc.group_id)) ||
			SQL_SUCCESS != stmt.BindParam(5, SQLDT_UINT, (void*)&acc.state, sizeof(acc.state)) ||
			SQL_SUCCESS != stmt.BindParam(6, SQLDT_LONG, (void*)&acc.unban_time, sizeof(acc.unban_time)) ||
			SQL_SUCCESS != stmt.BindParam(7, SQLDT_LONG, (void*)&acc.expiration_time, sizeof(acc.expiration_time)) ||
			SQL_SUCCESS != stmt.BindParam(8, SQLDT_UINT, (void*)&acc.logincount, sizeof(acc.logincount)) ||
			SQL_SUCCESS !=
				stmt.BindParam(
					9, acc.lastlogin[0] ? SQLDT_STRING : SQLDT_NULL, (void*)&acc.lastlogin, strlen(acc.lastlogin)) ||
			SQL_SUCCESS != stmt.BindParam(10, SQLDT_STRING, (void*)&acc.last_ip, strlen(acc.last_ip)) ||
			SQL_SUCCESS !=
				stmt.BindParam(
					11, acc.birthdate[0] ? SQLDT_STRING : SQLDT_NULL, (void*)&acc.birthdate, strlen(acc.birthdate)) ||
			SQL_SUCCESS != stmt.BindParam(12, SQLDT_UCHAR, (void*)&acc.char_slots, sizeof(acc.char_slots)) ||
			SQL_SUCCESS != stmt.BindParam(13, SQLDT_STRING, (void*)&acc.pincode, strlen(acc.pincode)) ||
			SQL_SUCCESS != stmt.BindParam(14, SQLDT_LONG, (void*)&acc.pincode_change, sizeof(acc.pincode_change))
#ifdef VIP_ENABLE
			|| SQL_SUCCESS != stmt.BindParam(15, SQLDT_LONG, (void*)&acc.vip_time, sizeof(acc.vip_time)) ||
			SQL_SUCCESS != stmt.BindParam(16, SQLDT_INT, (void*)&acc.old_group, sizeof(acc.old_group))
#endif
			|| SQL_SUCCESS != stmt.Execute()) {
			SqlStmt_ShowDebug(stmt);
			return false;
		}
	}

	return true;
}
