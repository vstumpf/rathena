// Copyright (c) rAthena Dev Teams - Licensed under GNU GPL
// For more information, see LICENCE in the main folder

#pragma once

#include <memory>
#include <string>
#include <vector>

#include <config/core.hpp>

#include <common/cbasetypes.hpp>

#include "mmo_account.hpp"

struct AccountRegVesselStr {
	std::string key;
	uint32 index;
	std::string value;
};

struct AccountRegVesselNum {
	std::string key;
	uint32 index;
	uint64 value;
};

class AccountDb {
public:
	virtual ~AccountDb(){};

	virtual bool init() = 0;

	// Sets a property in this database.
	//
	// @param key Property name
	// @param value Property value
	// @return true if successful
	virtual bool setProperty(std::string_view key, std::string_view value) = 0;

	// Creates a new account in this database.
	// If acc->account_id is not -1, the provided value will be used.
	// Otherwise the account_id will be auto-generated and written to acc->account_id.
	//
	// @param acc Account data
	// @return true if successful
	virtual bool create(MmoAccount& acc) = 0;

	// Removes an account from this database.
	//
	// @param account_id Account id
	// @return true if successful
	virtual bool remove(const uint32 account_id) = 0;

	// Enables the web auth token for the given account id
	virtual bool enableWebToken(const uint32 account_id) = 0;

	// Actually disable the web auth token for the given account id
	virtual bool disableWebToken(const uint32 account_id) = 0;

	// Removes the web auth token for all accounts
	virtual bool removeAllWebTokens() = 0;

	// Modifies the data of an existing account.
	// Uses acc->account_id to identify the account.
	//
	// @param acc Account data
	// @return true if successful
	virtual bool save(const MmoAccount& acc) = 0;

	// Finds an account with account_id and copies it to acc.
	//
	// @param acc Pointer that receives the account data
	// @param account_id Target account id
	// @return true if successful
	virtual bool loadFromAccountId(MmoAccount& acc, const uint32 account_id) = 0;

	// Finds an account with userid and copies it to acc.
	//
	// @param acc Pointer that receives the account data
	// @param userid Target username
	// @return true if successful
	virtual bool loadFromUsername(MmoAccount& acc, const char* userid) = 0;

	// Refreshes the web auth token for the given account
	virtual bool refreshWebToken(MmoAccount& acc) = 0;

	virtual std::vector<AccountRegVesselNum> loadGlobalAccRegNum(uint32 account_id) = 0;
	virtual std::vector<AccountRegVesselStr> loadGlobalAccRegStr(uint32 account_id) = 0;
	virtual void saveGlobalAccRegNum(uint32 account_id, std::string_view key, uint32 index, uint64 value) = 0;
	virtual void saveGlobalAccRegStr(uint32 account_id, std::string_view key, uint32 index, std::string_view value) = 0;
	virtual void deleteGlobalAccRegNum(uint32 account_id, std::string_view key, uint32 index) = 0;
	virtual void deleteGlobalAccRegStr(uint32 account_id, std::string_view key, uint32 index) = 0;
};
