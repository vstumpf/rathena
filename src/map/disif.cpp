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

struct mmo_dis_server discord;

static TIMER_FUNC(check_connect_discord_server);
static TIMER_FUNC(check_accept_discord_server);

// Received packet Lengths from discord-server
int dis_recv_packet_length[] = {
	0, 50, 3, -1, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //0D00
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //0D10
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, //0D20
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  //0D30
};

// says whether the discord server is connected or not
int disif_isconnected(void) {
	return (session_isValid(discord.fd) && discord.state == DiscordState::connected);
}


/**
 * Map-serv request to login into discord-server
 * @param fd : discord-server fd to log into
 * @return 0:request sent
 * 0D01 <user id>.24B <password>.24B (DZ_ENTER)
 */
int disif_connect(int fd) {
	ShowStatus("Logging in to discord server...\n");
	WFIFOHEAD(fd, 50);
	WFIFOW(fd,0) = 0xd01;
	memcpy(WFIFOP(fd,2), discord.username, NAME_LENGTH);
	memcpy(WFIFOP(fd,26), discord.token, NAME_LENGTH);
	WFIFOSET(fd,50);

	return 0;
}

/**
* Parse discord server login attempt ack
* @param fd : file descriptor to parse, (link to discord)
* 0D02 <error code>.B
*/
int disif_parse_loginack(int fd) {
	if (RFIFOREST(fd) < 3)
		return 0;
	char error = RFIFOB(fd, 2);
	RFIFOSKIP(fd, 3);
	if (error) {
		ShowInfo("Discord server rejected connection\n");
		return 1;
	}

	ShowInfo("Discord server has connected\n");
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

	if (!channel || !msg || discord.fd == -1)
		return 0;
	msg_len = (unsigned short)(strlen(msg) + 1);

	if (msg_len > CHAT_SIZE_MAX - 24) {
		msg_len = CHAT_SIZE_MAX - 24;
	}

	len = msg_len + 24;

	WFIFOHEAD(discord.fd, len);
	WFIFOW(discord.fd, 0) = 0xD04;
	WFIFOW(discord.fd, 2) = len;
	WFIFOB(discord.fd, 4) = '#';
	safestrncpy(WFIFOCP(discord.fd, 5), channel->name, 19);
	safestrncpy(WFIFOCP(discord.fd, 24), msg, msg_len);
	WFIFOSET(discord.fd, len);
	return 0;
}

// sets map-server's username for discord
void disif_setusername(char *id) {
	memcpy(discord.username, id, NAME_LENGTH);
}

// sets map-server's token for discord
void disif_settoken(char *pwd) {
	memcpy(discord.token, pwd, NAME_LENGTH);
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
	if (discord.fd != fd) {
		ShowDebug("disif_parse: Disconnecting invalid session #%d (is not a discord-server)\n", fd);
		do_close(fd);
		return 0;
	}
	if (session[fd]->flag.eof)
	{
		do_close(fd);
		discord.fd = -1;
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
		case 0x0d02: next = disif_parse_loginack(fd); return 0;
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


int disif_setip(const char* ip) {
	char ip_str[16];

	if (!(discord.ip = host2ip(ip))) {
		ShowWarning("Failed to Resolve Discord Server Address! (%s)\n", ip);

		return 0;
	}

	ShowInfo("Discord Server IP Address : '" CL_WHITE "%s" CL_RESET "' -> '" CL_WHITE "%s" CL_RESET "'.\n", ip, ip2str(discord.ip, ip_str));
	return 1;
}

void disif_setport(uint16 port) {
	discord.port = port;
}

/**
* Called when the connection to discord Server is disconnected.
*/
void disif_on_disconnect() {
	ShowStatus("Discord-server has disconnected.\n");

	add_timer(gettick() + 1000, check_connect_discord_server, 0, 0);
}

/*==========================================
 * timerFunction
  * Chk the connection to discord server, (if it down)
 *------------------------------------------*/
static TIMER_FUNC(check_connect_discord_server){
	static int displayed = 0;
	if (discord.fd <= 0 || session[discord.fd] == NULL) {
		if (!displayed) {
			ShowStatus("Attempting to connect to Discord Server. Please wait.\n");
			displayed = 1;
		}

		if (discord.state == DiscordState::connencting) {
			// after 10 seconds, just close
			ShowError("10 seconds waiting for accept from discord server, restarting connection\n");
			do_close(discord.fd);
			delete_timer(discord.accept_timer, check_accept_discord_server);
			discord.state = DiscordState::disconnected;
		}

		discord.fd = make_connection(discord.ip, discord.port, false, 10, true);

		if (discord.fd == -1) { // Attempt to connect later. [Skotlex]
			ShowInfo("make_connection failed, will retry in 10 seconds\n");
			return 0;
		}

		discord.state = DiscordState::connencting;
		discord.accept_timer = add_timer(gettick() + 1000, check_accept_discord_server, 0, 0);
	}

	if (disif_isconnected())
		displayed = 0;

	return 0;
}

/**
 * Use a non-blocking select to check if discord fd is connected
 */
static TIMER_FUNC(check_accept_discord_server) {
	discord.accept_timer = 0;
	if (discord.fd <= 0) {
		ShowError("Discord Server fd invalid, can't accept\n");
		return 0;
	}

	fd_set dfd;
	FD_ZERO(&dfd);
	FD_SET(discord.fd, &dfd);

	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 0;

	auto ret = select(discord.fd + 1, nullptr, &dfd, nullptr, &tv);
	if (ret < 0) {
		ShowError("Select failed!\n");
		discord.fd = 0;
		discord.state = DiscordState::disconnected;
		return 0;
	} else if (ret == 0) {
		ShowInfo("Still haven't connected to discord server, will retry in 1s\n");
		discord.accept_timer = add_timer(gettick() + 1000, check_accept_discord_server, 0, 0);
		return 0;
	}
	ShowInfo("Discord server connection was accepted!\n");
	add_readfd(discord.fd, discord.ip);
	discord.state = DiscordState::connected;
	session[discord.fd]->func_parse = disif_parse;
	session[discord.fd]->flag.server = 1;
	realloc_fifo(discord.fd, FIFOSIZE_SERVERLINK, FIFOSIZE_SERVERLINK);

	disif_connect(discord.fd);
	return 0;
}

/*==========================================
 * Read discord server configuration files (conf/discord_athena.conf...)
 *------------------------------------------*/
int discord_config_read(const char *cfgName)
{
	char line[1024], w1[32], w2[1024];
	FILE *fp;

	fp = fopen(cfgName,"r");
	if(fp == NULL) {
		ShowError("Discord configuration file not found at: %s\n", cfgName);
		return 1;
	}

	while(fgets(line, sizeof(line), fp)) {
		char* ptr;

		if( line[0] == '/' && line[1] == '/' )
			continue;
		if( (ptr = strstr(line, "//")) != NULL )
			*ptr = '\n'; //Strip comments
		if( sscanf(line, "%31[^:]: %1023[^\t\r\n]", w1, w2) < 2 )
			continue;

		//Strip trailing spaces
		ptr = w2 + strlen(w2);
		while (--ptr >= w2 && *ptr == ' ');
		ptr++;
		*ptr = '\0';

		if (strcmpi(w1, "username") == 0) {
			disif_setusername(w2);
		}
		else if (strcmpi(w1, "token") == 0) {
			disif_settoken(w2);
		}
		else if (strcmpi(w1, "discord_ip") == 0)
			disif_setip(w2);
		else if (strcmpi(w1, "discord_port") == 0)
			disif_setport(atoi(w2));
		else if (strcmpi(w1, "import") == 0)
			discord_config_read(w2);
		else
			ShowWarning("Unknown setting '%s' in file %s\n", w1, cfgName);
	}

	fclose(fp);
	return 0;
}

void do_init_disif(void) {
	discord_config_read("conf/discord_athena.conf");

	add_timer_func_list(check_connect_discord_server, "check_connect_discord_server");

	// establish map-discord connection if not present
	add_timer_interval(gettick() + 1000, check_connect_discord_server, 0, 0, 10 * 1000);
}

void do_final_disif(void) {
	
}

