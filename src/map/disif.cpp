#include "disif.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdarg>
#include <ctime>

#include "../common/cbasetypes.hpp"
#include "../common/socket.hpp"
#include "../common/timer.hpp"
#include "../common/malloc.hpp"
#include "../common/showmsg.hpp"
#include "../common/strlib.hpp"
#include "../common/utils.hpp"
#include "../common/conf.hpp"

#include "clif.hpp"
#include "channel.hpp"

struct mmo_dis_server discord_server;
static uint32 bind_ip = INADDR_ANY;
static uint32 dis_port = 5131;
static char userid[NAME_LENGTH];
static char passwd[NAME_LENGTH];

int discord_fd;

// Received packet Lengths from discord-server
int dis_recv_packet_length[] = {
	0, 50, 3, -1, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //0D00
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //0D10
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //0D20
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  //0D30
};

/**
* Parse discord server login attempt 
* @param fd : file descriptor to parse, (link to discord)
* 0D01 <user id>.24B <password>.24B (DZ_ENTER)
*/
int disif_parse_login(int fd) {
	if (RFIFOREST(fd) < 50)
		return 0;
	else {
		int i;
		char* l_user = RFIFOCP(fd, 2);
		char* l_pass = RFIFOCP(fd, 26);
		l_user[23] = '\0';
		l_pass[23] = '\0';
		RFIFOSKIP(fd, 50);
		if (runflag != MAPSERVER_ST_RUNNING ||
			strcmp(l_user, userid) != 0 ||
			strcmp(l_pass, passwd) != 0) {
			ShowInfo("Rejected Discord server connection attempt\n");
			disif_connectack(fd, 3); //fail
		}
		else {
			disif_connectack(fd, 0); //success

			discord_server.fd = fd;
			ShowInfo("Discord server has connected\n");

			session[fd]->func_parse = disif_parse;
			session[fd]->flag.server = 1;
			realloc_fifo(fd, FIFOSIZE_SERVERLINK, FIFOSIZE_SERVERLINK);
		}
	}
	return 0;
}

/**
* Parse discord server message and send to chat channel
* @param fd : file descriptor to parse
* 0D03 <packet len>.W <channel name>.20B <user name>.24B <message>.?B
*/

int disif_parse_message_from_disc(int fd) {
	int len;
	struct Channel * channel;
	char channel_name[CHAN_NAME_LENGTH];
	char username[NAME_LENGTH];
	char msg[CHAT_SIZE_MAX];
	char output[CHAT_SIZE_MAX];

	if (RFIFOREST(fd) < 4)
		return 0;

	len = RFIFOW(fd, 2);

	if (RFIFOREST(fd) < len)
		return 0;

	safestrncpy(channel_name, RFIFOCP(fd, 4), CHAN_NAME_LENGTH);

	channel = channel_name2channel(channel_name, NULL, 0);

	if (channel == NULL) {
		ShowInfo("Discord server sending to non-existing channel %s\n", channel_name);
		return 1;
	}
	
	safestrncpy(username, RFIFOCP(fd, 24), NAME_LENGTH);
	safestrncpy(msg, RFIFOCP(fd, 48), CHAT_SIZE_MAX - 4 - strlen(channel->alias) - strlen(username));

	safesnprintf(output, CHAT_SIZE_MAX, "%s %s : %s", channel->alias, username, msg);
	clif_channel_msg(channel, output, channel->color);


	return 1;
}


/**
* Send channel message to discord server
* @param channel : channel that sent the message
* @param msg : message that was sent
* 0D04 <packet len>.W <channel name>.20B <message>.?B
*/
int disif_send_message_to_disc(struct Channel *channel, char *msg) {
	unsigned short msg_len = 0, len = 0;

	if (!channel || !msg || discord_server.fd == -1)
		return 0;
	msg_len = (unsigned short)(strlen(msg) + 1);

	if (msg_len > CHAT_SIZE_MAX - 24) {
		msg_len = CHAT_SIZE_MAX - 24;
	}

	len = msg_len + 24;

	WFIFOHEAD(discord_server.fd, len);
	WFIFOW(discord_server.fd, 0) = 0xD04;
	WFIFOW(discord_server.fd, 2) = len;
	WFIFOB(discord_server.fd, 4) = '#';
	safestrncpy(WFIFOCP(discord_server.fd, 5), channel->name, 19);
	safestrncpy(WFIFOCP(discord_server.fd, 24), msg, msg_len);
	WFIFOSET(discord_server.fd, len);
	return 0;
}

// sets map-server's user id
void disif_setuserid(char *id) {
	memcpy(userid, id, NAME_LENGTH);
}

// sets map-server's password
void disif_setpasswd(char *pwd) {
	memcpy(passwd, pwd, NAME_LENGTH);
}


/**
* Inform the discord server whether his login attempt to us was a success or not
* @param fd : file descriptor to parse, (link to discord)
* @param errCode 0:success, 3:fail
* 0D02 <error code>.B 
*/
void disif_connectack(int fd, uint8 errCode) {
	WFIFOHEAD(fd, 3);
	WFIFOW(fd, 0) = 0x0d02;
	WFIFOB(fd, 2) = errCode;
	WFIFOSET(fd, 3);
}


/** Returns the length of the next complete packet to process,
* or 0 if no complete packet exists in the queue.
*
* @param length The minimum allowed length, or -1 for dynamic lookup
*/
int dis_check_length(int fd, int length)
{
	if (length == -1)
	{// variable-length packet
		if (RFIFOREST(fd) < 4)
			return 0;
		length = RFIFOW(fd, 2);
	}

	if ((int)RFIFOREST(fd) < length)
		return 0;

	return length;
}

/**
* Entry point from discord server to map-server.
* Function that checks incoming command, then splits it to the correct handler.
* If not found any hander here transmis packet to inter
* @param fd: file descriptor to parse, (link to discord server)
* @return 0=invalid server,marked for disconnection,unknow packet; 1=success
*/
int disif_parse(int fd) {
	if (discord_server.fd != fd) {
		ShowDebug("disif_parse: Disconnecting invalid session #%d (is not a discord-server)\n", fd);
		do_close(fd);
		return 0;
	}
	if (session[fd]->flag.eof)
	{
		do_close(fd);
		discord_server.fd = -1;
		disif_on_disconnect();
		return 0;
	}

	if (RFIFOREST(fd) < 2)
		return 0;

	int cmd;
	int len = 0;
	cmd = RFIFOW(fd, 0);
	// Check is valid packet entry
	if (cmd < 0x0D00 || cmd >= 0x0D00 + ARRAYLENGTH(dis_recv_packet_length) || dis_recv_packet_length[cmd - 0x0D00] == 0) {
		//invalid cmd, just close it
		ShowError("Unknown packet 0x%04x from discord server, disconnecting.\n", RFIFOW(fd, 0));
		set_eof(fd);
		return 0;
	}

	while (RFIFOREST(fd) >= 2) {
		int next = 1;

		// Check packet length
		if ((len = dis_check_length(fd, dis_recv_packet_length[cmd - 0x0D00])) == 0) {
			//invalid cmd, just close it
			ShowError("Unknown packet 0x%04x from discord server, disconnecting.\n", RFIFOW(fd, 0));
			set_eof(fd);
			return 0;
		}

		if (len == -1) { // variable-length packet
			if (RFIFOREST(fd) < 4)
				return 0;

			len = RFIFOW(fd, 2);
			if (len < 4 || len > 32768) {
				ShowWarning("disif_parse: Received packet 0x%04x specifies invalid packet_len (%d), disconnecting discord server #%d.\n", cmd, len, fd);
#ifdef DUMP_INVALID_PACKET
				ShowDump(RFIFOP(fd, 0), RFIFOREST(fd));
#endif
				set_eof(fd);
				return 0;
			}
		}
		if ((int)RFIFOREST(fd) < len)
			return 0; // not enough data received to form the packet

		switch (RFIFOW(fd, 0)) {
		case 0x0d01: next = disif_parse_login(fd); return 0;
		case 0x0d03: next = disif_parse_message_from_disc(fd); break;
		default:
			ShowError("Unknown packet 0x%04x from discord server, disconnecting.\n", RFIFOW(fd, 0));
			set_eof(fd);
			return 0;
		}
		if (next == 0) return 0; //avoid processing rest of packet
		RFIFOSKIP(fd, len);
	}
	return 1;
}


/**
* Called when the connection to discord Server is disconnected.
*/
void disif_on_disconnect() {
	ShowStatus("Discord-server has disconnected.\n");
}


/*==========================================
* Sets discord port to 'port'
*------------------------------------------*/
void disif_setport(uint16 port)
{
	dis_port = port;
}

void do_init_disif(void) {
	if ((discord_fd = make_listen_bind(bind_ip, dis_port)) == -1) {
		ShowFatalError("Failed to bind to port '" CL_WHITE "%d" CL_RESET "'\n", dis_port);
		exit(EXIT_FAILURE);
	}
}

void do_final_disif(void) {
	
}

