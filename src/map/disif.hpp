#pragma once

#include <string>

#include "../config/core.hpp"
#include "../common/core.hpp" // CORE_ST_LAST
#include "../common/msg_conf.hpp"
#include "../common/mmo.hpp"

#include "channel.hpp"

#define TOKEN_LENGTH 32 + 1

enum class DiscordState {
	disconnected,
	connencting,
	connected,
	stopped,
};

// must be below 10
#define MAX_CHANNELS 5

struct discord_channel {
	uint64 disc_channel_id;
	Channel *channel;
};

struct mmo_dis_server {
	int fd;
	uint32 ip;
	uint16 port;
	uint64 server_id;
	char token[TOKEN_LENGTH];
	DiscordState state{DiscordState::disconnected};

	int connect_timer;
	// the amount of seconds to wait before next connect attempt
	int connect_seconds;
	int accept_timer;

	struct discord_channel channels[MAX_CHANNELS];
	uint64 request_channel_id;
	uint64 request_category_id;
};


int disif_parse_loginack(int fd);
int disif_parse_message_from_disc(int fd);
int disif_send_message_to_disc(struct Channel *channel, char *msg);
int disif_send_request_to_disc(const map_session_data &sd, const char *message);
int disif_send_message_tochan(uint64 cid, const char *msg, uint16 len);

int disif_send_conf();
int disif_send_request_category(uint64 cid);

int disif_setdiscchannel(const char * w1, const char * w2);
int disif_setrochannel(const char * w1, const char * w2);
int disif_setrequestchannel(const char * w2);

int disif_discord_wis(const map_session_data &sd, const char *target, const char *msg);

std::string parse_item_link(const std::string &msg);

void do_init_disif(void);
void do_final_disif(void);
int disif_parse(int fd);
void disif_on_disconnect();
void reload_disif(void);
void stop_disif(void);
