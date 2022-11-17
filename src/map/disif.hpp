#pragma once

#include "../config/core.hpp"
#include "../common/core.hpp" // CORE_ST_LAST
#include "../common/msg_conf.hpp"
#include "../common/mmo.hpp"

#include "channel.hpp"

struct mmo_dis_server {
	int fd;
};

int disif_parse_login(int fd);
int disif_parse_message_from_disc(int fd);
int disif_send_message_to_disc(struct Channel *channel, char *msg);


void disif_connectack(int fd, uint8 errCode);
void disif_setport(uint16 port);
void do_init_disif(void);
void do_final_disif(void);
int disif_parse(int fd);
void disif_setuserid(char *id);
void disif_setpasswd(char *pwd);
void disif_on_disconnect();