#include "disif.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdarg>
#include <ctime>
#include <regex>

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
#include "pc.hpp"

struct mmo_dis_server discord{};

static TIMER_FUNC(check_connect_discord_server);
static TIMER_FUNC(check_accept_discord_server);

static std::string parse_item_link(const std::string &msg);

// Received packet Lengths from discord-server
int dis_recv_packet_length[] = {
	0, 43, 3, -1, -1, -1, -1, 2, 2, -1, -1, 10, 4, 0, 0, 0, //0D00
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
int disif_send_message_to_disc(struct Channel *channel, const char *msg) {
	unsigned short msg_len = 0, len = 0;

	if (!channel || !msg || discord.fd == -1 || discord.state != DiscordState::connected)
		return 0;

	auto newmsg = parse_item_link(msg);

	msg_len = (unsigned short)(newmsg.length() + 1);

	return disif_send_message_tochan(channel->discord_id, newmsg.c_str(), msg_len);
}

/**
 * Send a message to discord to the request category/channel from a player
 * Either 0D04 packet or 0D09
 */
int disif_send_request_to_disc(const map_session_data& sd, const char * message) {
	if (!message || discord.fd == -1 || discord.state != DiscordState::connected)
		return 0;

	char output[CHAT_SIZE_MAX + NAME_LENGTH + 3];
	auto msg_len = safesnprintf(output, sizeof(output), "%s : %s", sd.status.name, message) + 1;
	if (!discord.request_category_id) {
		// we're not premium, use normal message
		return disif_send_message_tochan(discord.request_channel_id, output, msg_len);
	}

	WFIFOHEAD(discord.fd, 8 + msg_len);
	WFIFOW(discord.fd, 0) = 0xD09;
	WFIFOW(discord.fd, 2) = 8 + msg_len;
	WFIFOL(discord.fd, 4) = sd.status.account_id;
	safestrncpy(WFIFOCP(discord.fd, 8), output, msg_len);
	WFIFOSET(discord.fd, 8 + msg_len);
	return 1;
}

/**
 * Send a whisper to the user from a discord channel
 * 0d0a <packet len>.W <account id>.L <message>.?B
*/
int disif_parse_send_message_toplayer(int fd) {
	if (RFIFOREST(fd) < 4)
		return 0;
	
	int len = RFIFOW(fd, 2);

	if (RFIFOREST(fd) < len)
		return 0;

	int accid = RFIFOL(fd, 4);
	char *msg = RFIFOCP(fd, 8);

	map_session_data *sd = map_id2sd(accid);
	if (!sd) {
		return 1;
	}

	clif_wis_message(sd, "@discord", msg, strlen(msg) + 1, 99);
	return 1;
}

int disif_send_message_tochan(uint64 cid, const char *msg, uint16 len) {
	if (discord.fd == -1 || discord.state != DiscordState::connected)
		return 0;

	WFIFOHEAD(discord.fd, len + 12);
	WFIFOW(discord.fd, 0) = 0xD04;
	WFIFOW(discord.fd, 2) = len + 12;
	WFIFOQ(discord.fd, 4) = cid;
	safestrncpy(WFIFOCP(discord.fd, 12), msg, len);
	WFIFOSET(discord.fd, len + 12);
	return 0;
}


/**
 * Send the channels to listen to
 * 0D05 <packet len>.W <count>.W {<channel id>.Q}*count
*/
int disif_send_conf() {
	if (discord.fd == -1 || discord.state != DiscordState::connected)
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

	if (discord.request_category_id) {
		disif_send_request_category(discord.request_category_id);
	}
	return 1;
}

/** 
 * Send the request category to discord
 * 0D0B <packet len>.W <category id>.Q
*/
int disif_send_request_category(uint64 cid) {
	if (discord.fd == -1 || discord.state != DiscordState::connected)
		return 0;

	WFIFOHEAD(discord.fd, 10);
	WFIFOW(discord.fd, 0) = 0xD0B;
	WFIFOQ(discord.fd, 2) = cid;
	WFIFOSET(discord.fd, 10);
	return 1;
}

/**
 * Parse the request category ack
 *	0 - ok
 *	1 - chn doesn't exist
 *	2 - chn not in guild
 *	3 - chn not a category
 *	4 - we don't have manage channel permissions
 *	5 - you aint premium

 * 0D0C <error code>.W
*/
int disif_parse_request_category_ack(int fd) {
	if (RFIFOREST(fd) < 4)
		return 0;
	uint16 err = RFIFOW(fd, 2);
	switch(err) {
	case 0:
		ShowInfo("Discord request category set\n");
		return 1;
	case 1:
		ShowWarning("Discord request category does not exist\n");
		break;
	case 2:
		ShowWarning("Discord request category not in guild\n");
		break;
	case 3:	
		ShowWarning("Discord request category is not a category\n");
		break;
	case 4:
		ShowWarning("Discord request category we don't have manage channel permissions\n");
		break;
	case 5:
		ShowWarning("Discord request category is a premium feature\n");
		break;
	default:
		ShowWarning("Unknown Error for Discord Request Category, please report %hu\n", err);
		break;
	}
	// if we got here, there must have been an error, so unset it
	discord.request_category_id = 0;
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
const char base62_dictionary[] = {
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
	'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
	'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
	'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z'};

uint32 base62_decode(const std::string &msg) {
	uint32 result = 0;
	for (size_t i = 0; i < msg.length(); i++) {
		for (size_t j = 0; j < 62; j++) {
			if (msg[i] == base62_dictionary[j]) {
				result = result * 62 + j;
				break;
			}
		}
	}
	return result;
}

/**
 * Parse an item link string
 */
static std::string parse_item_link(const std::string &msg) {
#if PACKETVER >= 20160113
	const std::string start_tag = R"(<ITEML>)";
	const std::string closing_tag = R"(</ITEML>)";
#else  // PACKETVER >= 20151104
	const std::string start_tag = "<ITEM>";
	const std::string closing_tag = "</ITEM>";
#endif

	static std::regex item_regex(start_tag + R"!(((\w{5})(\d)(\w+)[^<]*))!" + closing_tag);

	std::smatch match;
	std::string retstr = msg;
	while (std::regex_search(retstr, match, item_regex)) {
		auto itemdb = item_db.find(base62_decode(match[4].str()));
		if (!itemdb) {
			ShowError("Tried to parse itemlink for unknown item %s.\n", match[4].str().c_str());
			return msg;
		}

		retstr = std::regex_replace(retstr, item_regex, "!<!<" + match[1].str() + ">!>![" + itemdb->name + "]",
									std::regex_constants::format_first_only);
	}
	return retstr;
}

/**

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
		case 0x0d0a: next = disif_parse_send_message_toplayer(fd); break;
		case 0x0d0c: next = disif_parse_request_category_ack(fd); break;
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

int disif_setrequestcategory(const char * w2) {
	uint64 id = strtoull(w2, nullptr, 10);
	discord.request_category_id = id;
	ShowInfo("Set request category to id %llu\n", id);
	return 1;
}

/**
 * A player PMed @discord, send the message to discord request category
 * Premium only
*/
int disif_discord_wis(const map_session_data &sd, const char *target, const char *msg) {
	if (!msg || !*msg || !discord.request_category_id)
		return 0;

	return disif_send_request_to_disc(sd, msg);
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
			ShowInfo("make_connection failed, will retry in %d seconds\n", discord.connect_seconds);
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
		else if (strcmpi(w1, "discord_request_category") == 0)
			disif_setrequestcategory(w2);
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