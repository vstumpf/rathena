// Copyright (c) rAthena Dev Teams - Licensed under GNU GPL
// For more information, see LICENCE in the main folder

#pragma once

#include <memory>
#include <string>

#include <config/core.hpp>

#include <common/cbasetypes.hpp>
#include <common/sql.hpp>

#include "accountdb.hpp"
#include "mmo_account.hpp"

class AccountDbSql : public AccountDb {
public:
	// Destroys this database, releasing all allocated memory (including itself).
	~AccountDbSql();

	bool init() override;

	// Sets a property in this database.
	//
	// @param key Property name
	// @param value Property value
	// @return true if successful
	bool setProperty(std::string_view key, std::string_view value) override;

	// Creates a new account in this database.
	// If acc->account_id is not -1, the provided value will be used.
	// Otherwise the account_id will be auto-generated and written to acc->account_id.
	//
	// @param acc Account data
	// @return true if successful
	bool create(MmoAccount& acc) override;

	// Removes an account from this database.
	//
	// @param account_id Account id
	// @return true if successful
	bool remove(const uint32 account_id) override;

	// Enables the web auth token for the given account id
	bool enableWebToken(const uint32 account_id) override;

	// Actually disable the web auth token for the given account id
	bool disableWebToken(const uint32 account_id) override;

	// Removes the web auth token for all accounts
	bool removeAllWebTokens() override;

	// Modifies the data of an existing account.
	// Uses acc->account_id to identify the account.
	//
	// @param acc Account data
	// @return true if successful
	bool save(const MmoAccount& acc) override;

	// Finds an account with account_id and copies it to acc.
	//
	// @param acc Pointer that receives the account data
	// @param account_id Target account id
	// @return true if successful
	bool loadFromAccountId(MmoAccount& acc, const uint32 account_id) override;

	// Finds an account with userid and copies it to acc.
	//
	// @param acc Pointer that receives the account data
	// @param userid Target username
	// @return true if successful
	bool loadFromUsername(MmoAccount& acc, const char* userid) override;

	bool refreshWebToken(MmoAccount& acc) override;

	std::vector<AccountRegVesselNum> loadGlobalAccRegNum(uint32 account_id) override;
	std::vector<AccountRegVesselStr> loadGlobalAccRegStr(uint32 account_id) override;
	void saveGlobalAccRegNum(uint32 account_id, std::string_view key, uint32 index, uint64 value) override;
	void saveGlobalAccRegStr(uint32 account_id, std::string_view key, uint32 index, std::string_view value) override;
	void deleteGlobalAccRegNum(uint32 account_id, std::string_view key, uint32 index) override;
	void deleteGlobalAccRegStr(uint32 account_id, std::string_view key, uint32 index) override;

private:
	Sql* accounts_{nullptr}; // SQL handle accounts storage
	std::string db_hostname_{"127.0.0.1"};
	uint16 db_port_{3306};
	std::string db_username_{"ragnarok"};
	std::string db_password_{""};
	std::string db_database_{"ragnarok"};
	std::string codepage_{""};
	// other settings
	bool case_sensitive_{false};
	// table name
	std::string account_table_{"login"};
	std::string global_acc_reg_num_table_{"global_acc_reg_num"};
	std::string global_acc_reg_str_table_{"global_acc_reg_str"};

	bool load(MmoAccount& acc, uint32 account_id);
	bool save(const MmoAccount& acc, bool is_new);
};
