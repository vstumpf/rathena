// Copyright (c) rAthena Dev Teams - Licensed under GNU GPL
// For more information, see LICENCE in the main folder

#pragma once

#include <common/cbasetypes.hpp>
#include <common/mmo.hpp> // ACCOUNT_REG2_NUM, WEB_AUTH_TOKEN_LENGTH
// #include <config/core.hpp>

struct MmoAccount {
	uint32 account_id;
	char userid[NAME_LENGTH];
	char pass[32 + 1]; // 23+1 for plaintext, 32+1 for md5-ed passwords
	char sex; // gender (M/F/S)
	char email[40]; // e-mail (by default: a@a.com)
	uint32 group_id; // player group id
	uint8 char_slots; // this accounts maximum character slots (maximum is limited to MAX_CHARS define in char server)
	uint32 state; // packet 0x006a value + 1 (0: compte OK)
	time_t unban_time; // (timestamp): ban time limit of the account (0 = no ban)
	time_t expiration_time; // (timestamp): validity limit of the account (0 = unlimited)
	uint32 logincount; // number of successful auth attempts
	char lastlogin[24]; // date+time of last successful login
	char last_ip[16]; // save of last IP of connection
	char birthdate[10 + 1]; // assigned birth date (format: YYYY-MM-DD)
	char pincode[PINCODE_LENGTH + 1]; // pincode system
	time_t pincode_change; // (timestamp): last time of pincode change
	char web_auth_token[WEB_AUTH_TOKEN_LENGTH]; // web authentication token (randomized on each login)
#ifdef VIP_ENABLE
	int32 old_group;
	time_t vip_time;
#endif
};
