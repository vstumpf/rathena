#pragma once

#include "../config/core.hpp"
#include "../common/core.hpp" // CORE_ST_LAST
#include "../common/msg_conf.hpp"
#include "../common/mmo.hpp"

#include "channel.hpp"

enum class DiscordState {
	disconnected,
	connencting,
	connected
};

struct mmo_dis_server {
	int fd;
	uint32 ip;
	uint16 port;
	char username[NAME_LENGTH];
	char token[NAME_LENGTH];
	DiscordState state{DiscordState::disconnected};

	int connect_timer;
	// the amount of seconds to wait before next connect attempt
	int connect_seconds;
	int accept_timer;
};


int disif_parse_loginack(int fd);
int disif_parse_message_from_disc(int fd);
int disif_send_message_to_disc(struct Channel *channel, char *msg);


void disif_connectack(int fd, uint8 errCode);
void do_init_disif(void);
void do_final_disif(void);
int disif_parse(int fd);
void disif_on_disconnect();
