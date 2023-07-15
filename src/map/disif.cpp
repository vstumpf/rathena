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

struct mmo_dis_server discord{};

static TIMER_FUNC(check_connect_discord_server);
static TIMER_FUNC(check_accept_discord_server);

// Received packet Lengths from discord-server
int dis_recv_packet_length[] = {
	0, 43, 3, -1, -1, -1, -1, 2, 2, 0, 0, 0, 0, 0, 0, 0, //0D00
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
 * 0D01 <server_id>.Q <token>.24B (DZ_CONNECT)
 */
int disif_connect(int fd) {
	ShowStatus("Logging in to discord server...\n");
	WFIFOHEAD(fd, 50);
	WFIFOW(fd,0) = 0xd01;
	WFIFOQ(fd,2) = discord.server_id;
	memcpy(WFIFOP(fd,10), discord.token, TOKEN_LENGTH);
	WFIFOSET(fd, 43);

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
		ShowError("Discord server rejected connection, contact nitrous for the reason\n");
		discord.state = DiscordState::stopped;
		return 1;
	}

	ShowInfo("Discord server has connected\n");
	discord.connect_seconds = 10;
	disif_send_conf();
	return 0;
}

/**
 * Send keepalive to discord server
*/
void disif_keepalive(int fd) {
	WFIFOHEAD(fd,2);
	WFIFOW(fd,0) = 0xd07;
	WFIFOSET(fd,2);
}


/**
 * Parse keepalive ack from discord server
*/
int disif_parse_keepaliveack(int fd) {
	session[fd]->flag.ping = 0;
	return 1;
}


/**
* Parse discord server message and send to chat channel
* @param fd : file descriptor to parse
* 0D03 <packet len>.W <channel id>.Q <user name>.24B <message>.?B
*/

int disif_parse_message_from_disc(int fd) {
	int len;
	struct Channel * channel = nullptr;
	char username[NAME_LENGTH];
	char msg[CHAT_SIZE_MAX];
	char output[CHAT_SIZE_MAX];

	if (RFIFOREST(fd) < 4)
		return 0;

	len = RFIFOW(fd, 2);

	if (RFIFOREST(fd) < len)
		return 0;

	auto channel_id = RFIFOQ(fd, 4);

	for (int i = 0; i < MAX_CHANNELS; i++) {
		auto &chn = discord.channels[i];
		if (chn.disc_channel_id == channel_id) {
			channel = chn.channel;
		}
	}

	if (channel == nullptr) {
		ShowWarning("Discord server sending to non-existing channel %llu, REPORT THIS!\n", channel_id);
		return 1;
	}
	
	safestrncpy(username, RFIFOCP(fd, 12), NAME_LENGTH);
	safestrncpy(msg, RFIFOCP(fd, 36), CHAT_SIZE_MAX - 4 - strlen(channel->alias) - strlen(username));

	safesnprintf(output, CHAT_SIZE_MAX, "%s %s : %s", channel->alias, username, msg);
	clif_channel_msg(channel, output, channel->color);

	return 1;
}


/**
* Send channel message to discord server
* @param channel : channel that sent the message
* @param msg : message that was sent
* 0D04 <packet len>.W <channel id>.Q <message>.?B
*/
int disif_send_message_to_disc(struct Channel *channel, char *msg) {
	unsigned short msg_len = 0, len = 0;

	if (!channel || !msg || discord.fd == -1)
		return 0;
	msg_len = (unsigned short)(strlen(msg) + 1);

	if (msg_len > CHAT_SIZE_MAX - 12) {
		msg_len = CHAT_SIZE_MAX - 12;
	}

	len = msg_len + 12;

	WFIFOHEAD(discord.fd, len);
	WFIFOW(discord.fd, 0) = 0xD04;
	WFIFOW(discord.fd, 2) = len;
	WFIFOQ(discord.fd, 4) = channel->discord_id;
	safestrncpy(WFIFOCP(discord.fd, 12), msg, msg_len);
	WFIFOSET(discord.fd, len);
	return 0;
}

int disif_send_request_to_disc(char * name, char * message) {
	if (!name || !message || discord.fd == -1)
		return 0;

	char output[CHAT_SIZE_MAX + NAME_LENGTH + 3];
	auto msg_len = safesnprintf(output, sizeof(output), "%s : %s", name, message);
	auto len = msg_len + 12;

	WFIFOHEAD(discord.fd, len);
	WFIFOW(discord.fd, 0) = 0xD04;
	WFIFOW(discord.fd, 2) = len;
	WFIFOQ(discord.fd, 4) = discord.request_channel_id;
	safestrncpy(WFIFOCP(discord.fd, 12), output, msg_len);
	WFIFOSET(discord.fd, len);
	return 0;
}


/**
 * Send the channels to listen to
 * 0D05 <packet len>.W <count>.W {<channel id>.Q}*count
*/
int disif_send_conf() {
	if (discord.fd == -1)
		return 0;
	
	uint16 count = 0;

	WFIFOHEAD(discord.fd, 6 + (MAX_CHANNELS + 1) * 8);
	WFIFOW(discord.fd, 0) = 0xD05;
	for (int i = 0; i < MAX_CHANNELS; i++) {
		auto &chn = discord.channels[i];
		if (chn.disc_channel_id && chn.channel) {
			WFIFOQ(discord.fd, 6 + count * 8) = chn.disc_channel_id;
			count++;
		}
	}

	if (discord.request_channel_id) {
		WFIFOQ(discord.fd, 6 + count * 8) = discord.request_channel_id;
		count++;
	}

	WFIFOW(discord.fd, 2) = 6 + count * 8;
	WFIFOW(discord.fd, 4) = count;
	WFIFOSET(discord.fd, 6 + count * 8);
	return 1;
}

/**
 * List of channels that have errors
 * If count is 0, no errors!
 * 0D06 <packet len>.W <count>.W {<channel id>.Q}*count
*/
int disif_parse_conf_ack(int fd) {
	if (RFIFOREST(fd) < 4)
		return 0;
	
	int len = RFIFOW(fd, 2);

	if (RFIFOREST(fd) < len)
		return 0;

	int count = RFIFOW(fd, 4);
	for (int i = 0; i < count; i++) {
		auto id = RFIFOQ(fd, 6 + i * 8);
		for (int j = 0; j < MAX_CHANNELS; j++) {
			auto &chn = discord.channels[j];
			if (id == chn.disc_channel_id) {
				ShowError("Discord channel with id [%llu](%s) does not exist, ignoring\n", id, chn.channel->name);
				chn.disc_channel_id = 0;
				chn.channel->discord_id = 0;
				chn.channel = nullptr;
			}
		}
	}

	for (int i = 0; i < MAX_CHANNELS; i++) {
		auto & chn = discord.channels[i];
		if (!chn.disc_channel_id || !chn.channel)
			continue;
		chn.channel->discord_id = chn.disc_channel_id;
	}
	return 1;
}

// sets map-server's username for discord
void disif_setserverid(char *id) {
	discord.server_id = strtoull(id, nullptr, 10);
}

// sets map-server's token for discord
void disif_settoken(char *pwd) {
	memcpy(discord.token, pwd, TOKEN_LENGTH);
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
	} else if (session[fd]->flag.ping) {
		if (DIFF_TICK(last_tick, session[fd]->rdata_tick) > (stall_time * 2)) {
			set_eof(fd);
			return 0;
		} else if (session[fd]->flag.ping != 2) {
			disif_keepalive(fd);
			session[fd]->flag.ping = 2;
		}
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
		case 0x0d06: next = disif_parse_conf_ack(fd); break;
		case 0x0d08: next = disif_parse_keepaliveack(fd); break;
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

void disif_setenabled(const char *opt) {
	if (!config_switch(opt))
		discord.state = DiscordState::stopped;
}

int disif_setdiscchannel(const char * w1, const char * w2) {
	w1 = w1 + strlen("discord_channel");
	int n = strtoul(w1, nullptr, 10);
	uint64 id = strtoull(w2, nullptr, 10);
	if (n > MAX_CHANNELS)
		return 0;

	discord.channels[n].disc_channel_id = id;
	ShowInfo("Set channel #%d to id %llu\n", n, id);
	return 1;
}

int disif_setrochannel(const char * w1, const char * w2) {
	w1 = w1 + strlen("ro_channel");
	int n = strtoul(w1, nullptr, 10);
	if (n >= MAX_CHANNELS)
		return 0;

	char channel_name[CHAN_NAME_LENGTH];

	safestrncpy(channel_name, w2, sizeof(channel_name));
	auto * channel = channel_name2channel(channel_name, nullptr, 0);
	if (!channel) {
		ShowError("Channel with name %s does not exist, ignoring for discord\n", w2);
		return 0;
	}

	discord.channels[n].channel = channel;
	ShowInfo("Set channel #%d to name %s\n", n, channel_name);
	return 1;
}

int disif_setrequestchannel(const char * w2) {
	uint64 id = strtoull(w2, nullptr, 10);
	discord.request_channel_id = id;
	ShowInfo("Set request channel to id %llu\n", id);
	return 1;
}

/**
* Called when the connection to discord Server is disconnected.
*/
void disif_on_disconnect() {
	ShowStatus("Discord-server has disconnected.\n");
	if (discord.connect_timer)
		delete_timer(discord.connect_timer, check_connect_discord_server);

	if (discord.state == DiscordState::stopped)
		return;
	discord.connect_timer =
		add_timer(gettick() + (discord.connect_seconds * 1000), check_connect_discord_server, 0, 0);
}

#ifdef WIN32
#define sErrno WSAGetLastError()
#define S_EINTR WSAEINTR
#define sFD_SET(fd, set) FD_SET(fd2sock_ext(fd), set)
#else
#define sErrno errno
#define S_EINTR EINTR
#define sFD_SET(fd, set) FD_SET(fd, set)
#endif

/*==========================================
 * timerFunction
  * Chk the connection to discord server, (if it down)
 *------------------------------------------*/
static TIMER_FUNC(check_connect_discord_server){
	discord.connect_timer = 0;
	discord.connect_seconds += 5;

	if (discord.state == DiscordState::stopped)
		return 0;

	if (discord.fd <= 0 || session[discord.fd] == NULL) {
		ShowStatus("Attempting to connect to Discord Server. Please wait.\n");

		if (discord.state == DiscordState::connencting) {
			// after 10 seconds, just close
			ShowError("10 seconds waiting for accept from discord server, restarting connection\n");
			do_close(discord.fd);
			delete_timer(discord.accept_timer, check_accept_discord_server);
			discord.state = DiscordState::disconnected;
			discord.connect_timer = add_timer(gettick() + 1000, check_connect_discord_server, 0, 0);
			return 0;
		}

		discord.fd = make_connection(discord.ip, discord.port, false, 10, true);

		if (discord.fd == -1) { // Attempt to connect later. [Skotlex]
			ShowInfo("make_connection failed, will retry in %s seconds\n", discord.connect_seconds);
			discord.connect_timer = add_timer(gettick() + (discord.connect_seconds * 1000), check_connect_discord_server, 0, 0);
			return 0;
		}

		discord.state = DiscordState::connencting;
		discord.accept_timer = add_timer(gettick() + 1000, check_accept_discord_server, 0, 0);
	}

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
	sFD_SET(discord.fd, &dfd);

	struct timeval tv;
	tv.tv_sec = 0;
	tv.tv_usec = 0;

	auto ret = select(discord.fd + 1, nullptr, &dfd, nullptr, &tv);
	if (ret < 0) {
		ShowError("Discord select failed [%d], retrying in %d seconds\n", sErrno, discord.connect_seconds);
		discord.fd = 0;
		discord.state = DiscordState::disconnected;
		if (!discord.connect_timer) {
			discord.connect_timer = add_timer(gettick() + (discord.connect_seconds * 1000), check_connect_discord_server, 0, 0);
		}
		return 0;
	} else if (ret == 0) {
		// ShowInfo("Still haven't connected to discord server, will retry in 1s\n");
		discord.accept_timer = add_timer(gettick() + 1000, check_accept_discord_server, 0, 0);
		return 0;
	}
#ifdef WIN32
	int err = 0;
	int err_len = sizeof(err);
	if (getsockopt(fd2sock_ext(discord.fd), SOL_SOCKET, SO_ERROR, (char *)&err, &err_len)) {
		ShowError("getsockopt failed!?\n");
	}
#else
	int err = 0;
	socklen_t err_len = sizeof(err);
	if (getsockopt(discord.fd, SOL_SOCKET, SO_ERROR, &err, &err_len)) {
		ShowError("getsockopt failed!?\n");
	}
#endif
	if (err) {
		ShowError("Discord connect failed, retrying in %d seconds\n", discord.connect_seconds);
		discord.fd = 0;
		discord.state = DiscordState::disconnected;
		if (!discord.connect_timer) {
			discord.connect_timer = add_timer(gettick() + (discord.connect_seconds * 1000), check_connect_discord_server, 0, 0);
		}
		return 0;
	}
	ShowInfo("Discord server connection was accepted!\n");
	add_readfd(discord.fd, discord.ip);
	discord.state = DiscordState::connected;
	session[discord.fd]->func_parse = disif_parse;
	session[discord.fd]->flag.server = 1;
	realloc_fifo(discord.fd, FIFOSIZE_SERVERLINK, FIFOSIZE_SERVERLINK);

	if (discord.connect_timer) {
		delete_timer(discord.connect_timer, check_connect_discord_server);
		discord.connect_timer = 0;
	}

	// only do this when we ack
	// discord.connect_seconds = 10;
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

		if (strcmpi(w1, "server_id") == 0) {
			disif_setserverid(w2);
		}
		else if (strcmpi(w1, "token") == 0) {
			disif_settoken(w2);
		}
		else if (strcmpi(w1, "discord_ip") == 0)
			disif_setip(w2);
		else if (strcmpi(w1, "discord_port") == 0)
			disif_setport(atoi(w2));
		else if (strncmpi(w1, "discord_channel", strlen("discord_channel")) == 0)
			disif_setdiscchannel(w1, w2);
		else if (strncmpi(w1, "ro_channel", strlen("ro_channel")) == 0)
			disif_setrochannel(w1, w2);
		else if (strcmpi(w1, "import") == 0)
			discord_config_read(w2);
		else if (strcmpi(w1, "enable") == 0)
			disif_setenabled(w2);
		else if (strcmpi(w1, "discord_request_channel") == 0)
			disif_setrequestchannel(w2);
		else
			ShowWarning("Unknown setting '%s' in file %s\n", w1, cfgName);
	}

	fclose(fp);
	return 0;
}

void do_init_disif(void) {
	discord_config_read("conf/discord_athena.conf");

	for (int i = 0; i < MAX_CHANNELS; i++) {
		auto &chn = discord.channels[i];
		if (!chn.disc_channel_id || !chn.channel) {
			chn.disc_channel_id = 0;
			chn.channel = nullptr;
		}
	}

	add_timer_func_list(check_connect_discord_server, "check_connect_discord_server");
	add_timer_func_list(check_accept_discord_server, "check_accept_discord_server");

	// establish map-discord connection if not present
	discord.connect_timer = add_timer(gettick() + 1000, check_connect_discord_server, 0, 0);
	discord.connect_seconds = 10;
}

void do_final_disif(void) {
	
}

void reload_disif(void) {
	set_eof(discord.fd);

	if (discord.connect_timer) {
		delete_timer(discord.connect_timer, check_connect_discord_server);
		discord.connect_timer = 0;
	}

	if (discord.accept_timer) {
		delete_timer(discord.accept_timer, check_accept_discord_server);
		discord.accept_timer = 0;
	}

	discord_config_read("conf/discord_athena.conf");

	for (int i = 0; i < MAX_CHANNELS; i++) {
		auto &chn = discord.channels[i];
		if (!chn.disc_channel_id || !chn.channel) {
			chn.disc_channel_id = 0;
			chn.channel = nullptr;
		}
	}

	discord.state = DiscordState::disconnected;
	// establish map-discord connection if not present
	discord.connect_timer = add_timer(gettick() + 10000, check_connect_discord_server, 0, 0);
}


void stop_disif(void) {
	set_eof(discord.fd);
	discord.state = DiscordState::stopped;
}