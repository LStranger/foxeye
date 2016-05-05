#define RPL_WELCOME		  1, ":Welcome to the Internet Relay Network %#!%L@%@"
#define RPL_YOURHOST		  2, ":Your host is %#, running version %V"
#define RPL_CREATED		  3, ":This server was created %*"
#define RPL_MYINFO		  4, "%# %V %*"
#define RPL_ISUPPORT		  5, "%* :are supported by this server"
#define RPL_BOUNCE		 10, "%# %P :Please use this Server/Port instead"
/* 015 reserved */
/* 017-018 reserved */
#define RPL_HELLO		 20, ":Welcome to %#! Please wait until checks are done."
/* 042-043 reserved */
#define RPL_TRACELINK		200, "Link %V%?P.d%P?? %# %*"
#define RPL_TRACECONNECTING	201, "Try. %* %#"
#define RPL_TRACEHANDSHAKE	202, "H.S. %* %#"
#define RPL_TRACEUNKNOWN	203, "???? %* %?I%I??"
#define RPL_TRACEOPERATOR	204, "Oper %* %#"
#define RPL_TRACEUSER		205, "User %* %#"
#define RPL_TRACESERVER		206, "Serv %*"
#define RPL_TRACESERVICE	207, "Service %*"
#define RPL_TRACENEWTYPE	208, "%* 0 %#"
#define RPL_TRACECLASS		209, "Class %* %P"
/* 210 reserved */
#define RPL_STATSLINKINFO	211, "%*"
#define RPL_STATSCOMMANDS	212, "%*"
#define RPL_STATSCLINE		213, "%*"
#define RPL_STATSNLINE		214, "%*"
#define RPL_STATSILINE		215, "%*"
#define RPL_STATSKLINE		216, "%*"
#define RPL_STATSQLINE		217, "%*"
#define RPL_STATSYLINE		218, "%*"
#define RPL_ENDOFSTATS		219, "%* :End of STATS report"
#define RPL_UMODEIS		221, "+%*"
#if IRCD_USES_ICONV
# define RPL_CODEPAGE		222, "%* :is your charset now"
#endif
/* 231-233 reserved */
#define RPL_SERVLIST		234, "%# %*"
#define RPL_SERVLISTEND		235, "%@ %* :End of service listing"
/* 239 reserved */
#define RPL_STATSVLINE		240, "%*"
#define RPL_STATSLLINE		241, "%*"
#define RPL_STATSUPTIME		242, ":%*"
#define RPL_STATSOLINE		243, "O %@ * %L"
#define RPL_STATSHLINE		244, "%*"
#define RPL_STATSSLINE		245, "%*"
/* 246 reserved */
#define RPL_STATSBLINE		247, "%*"
/* 248-249 reserved */
#define RPL_STATSDLINE		250, "%*"
#define RPL_LUSERCLIENT		251, ":%*"
#define RPL_LUSEROP		252, "%?P%P?0? :operator(s) online"
#define RPL_LUSERUNKNOWN	253, "%?P%P?0? :unknown connection(s)"
#define RPL_LUSERCHANNELS	254, "%?P%P?0? :channels formed"
#define RPL_LUSERME		255, ":%*"
#define RPL_ADMINME		256, "%= :Administrative info"
#define RPL_ADMINLOC1		257, ":%*"
#define RPL_ADMINLOC2		258, ":%*"
#define RPL_ADMINEMAIL		259, ":%*"
#define RPL_TRACELOG		261, "%*"
#define RPL_TRACEEND		262, "%= %V%?P.d%P?? :End of TRACE"
#define RPL_TRYAGAIN		263, "%* :Please wait a while and try again."
/* 264-266 reserved */
/* 300 reserved */
#define RPL_AWAY		301, "%# :%*"
#define RPL_USERHOST		302, ":%*"
#define RPL_ISON		303, ":%*"
/* 304 reserved */
#define RPL_UNAWAY		305, ":You are no longer marked as being away"
#define RPL_NOWAWAY		306, ":You have been marked as being away"
#define RPL_WHOISUSER		311, "%# %L %@ * :%*"
#define RPL_WHOISSERVER		312, "%* %# :%@"
#define RPL_WHOISOPERATOR	313, "%# :is an IRC operator"
#define RPL_WHOWASUSER		314, "%# %L %@ * :%*"
#define RPL_ENDOFWHO		315, "%* :End of WHO list"
/* 316 reserved */
#define RPL_WHOISIDLE		317, "%# %* :seconds idle"
#define RPL_ENDOFWHOIS		318, "%* :End of WHOIS list"
#define RPL_WHOISCHANNELS	319, "%# :%*"
#if IRCD_USES_ICONV
# define RPL_WHOISCHARSET	320, "%# :charset is %*"
#endif
#define RPL_LISTSTART		321, "Channel :Users  Name"
#define RPL_LIST		322, "%# %?P%P?0? :%*"
#define RPL_LISTEND		323, ":End of LIST"
#define RPL_CHANNELMODEIS	324, "%# +%*"
#define RPL_UNIQOPIS		325, "%# %*"
/* 327 reserved */
#define RPL_NOTOPIC		331, "%# :No topic is set"
#define RPL_TOPIC		332, "%# :%*"
#ifdef TOPICWHOTIME
# define RPL_TOPICWHOTIME	333, "%# %*"
#endif
#define RPL_WHOISSECURE		336, "%# :is using encrypted connection"
#define RPL_INVITING		341, "%# %*"
#define RPL_SUMMONING		342, "%# :Summoning user to IRC"
/* 344-345 reserved */
#define RPL_INVITELIST		346, "%# %*"
#define RPL_ENDOFINVITELIST	347, "%# :End of channel invite list"
#define RPL_EXCEPTLIST		348, "%# %*"
#define RPL_ENDOFEXCEPTLIST	349, "%# :End of channel exception list"
#define RPL_VERSION		351, "%V%?P.d%P?? %= :%*"
#define RPL_WHOREPLY		352, "%*"
#define RPL_NAMREPLY		353, "%*"
#define RPL_ENDOFNAMES		366, "%* :End of NAMES list"
/* 361-363 reserved */
#define RPL_LINKS		364, "%# %* :%?P%P?0? %@"
#define RPL_ENDOFLINKS		365, "%* :End of LINKS list"
#define RPL_BANLIST		367, "%# %*"
#define RPL_ENDOFBANLIST	368, "%# :End of channel ban list"
#define RPL_ENDOFWHOWAS		369, "%* :End of WHOWAS"
#define RPL_INFO		371, ":%*"
#define RPL_MOTD		372, ":- %*"
/* 373 reserved */
#define RPL_ENDOFINFO		374, ":End of INFO list"
#define RPL_MOTDSTART		375, ":- %= Message of the day - "
#define RPL_ENDOFMOTD		376, ":End of MOTD command"
#define RPL_YOUREOPER		381, ":You are now an IRC operator"
#define RPL_REHASHING		382, "%* :Rehashing"
#define RPL_YOURESERVICE	383, "You are service %#"
/* 384-385 reserved */
#define RPL_TIME		391, "%= :%*"
#define RPL_USERSSTART		392, ":UserID   Terminal  Host" /* RFC1459 */
#define RPL_USERS		393, ":%L %P %@" /* RFC1459 */
#define RPL_ENDOFUSERS		394, ":End of users" /* RFC1459 */
#define RPL_NOUSERS		395, ":Nobody logged in" /* RFC1459 */
#define ERR_NOSUCHNICK		401, "%* :No such nick/channel"
#define ERR_NOSUCHSERVER	402, "%* :No such server"
#define ERR_NOSUCHCHANNEL	403, "%* :No such channel"
#define ERR_CANNOTSENDTOCHAN	404, "%# :Cannot send to channel"
#define ERR_TOOMANYCHANNELS	405, "%# :You have joined too many channels"
#define ERR_WASNOSUCHNICK	406, "%* :There was no such nickname"
#define ERR_TOOMANYTARGETS	407, "%# :Too many recipients. %*"
#define ERR_NOSUCHSERVICE	408, "%* :No such service"
#define ERR_NOORIGIN		409, ":No origin specified"
#define ERR_NORECIPIENT		411, ":No recipient given (%*)"
#define ERR_NOTEXTTOSEND	412, ":No text to send"
#define ERR_NOTOPLEVEL		413, "%* :No toplevel domain specified"
#define ERR_WILDTOPLEVEL	414, "%* :Wildcard in toplevel domain"
#define ERR_BADMASK		415, "%* :Bad Server/host mask"
#define ERR_TOOMANYMATCHES	416, "%* :Output too long (try locally)"
#define ERR_UNKNOWNCOMMAND	421, "%* :Unknown command"
#define ERR_NOMOTD		422, ":MOTD File is missing"
#define ERR_NOADMININFO		423, "%= :No administrative info available"
#define ERR_FILEERROR		424, ":File error doing %*"
#define ERR_NONICKNAMEGIVEN	431, ":No nickname given"
#define ERR_ERRONEUSNICKNAME	432, "%* :Erroneous nickname"
#define ERR_NICKNAMEINUSE	433, "%# :Nickname is already in use"
/* 434-435 reserved */
#define ERR_NICKCOLLISION	436, "%N :Nickname collision KILL from %L@%@"
#define ERR_UNAVAILRESOURCE	437, "%* :Nick/channel is temporarily unavailable"
/* 438 reserved */
#define ERR_USERNOTINCHANNEL	441, "%* %# :They aren't on that channel"
#define ERR_NOTONCHANNEL	442, "%* :You're not on that channel"
#define ERR_USERONCHANNEL	443, "%* %# :is already on channel"
#define ERR_NOLOGIN		444, "%* :User not logged in"
#define ERR_SUMMONDISABLED	445, ":SUMMON has been disabled"
#define ERR_USERSDISABLED	446, ":USERS has been disabled" /* RFC1459 */
#define ERR_NOTREGISTERED	451, ":You have not registered"
#define ERR_NEEDMOREPARAMS	461, "%* :Not enough parameters"
#define ERR_ALREADYREGISTRED	462, ":Unauthorized command (already registered)"
#define ERR_NOPERMFORHOST	463, ":Your host isn't among the privileged"
#define ERR_PASSWDMISMATCH	464, ":Password incorrect"
#define ERR_YOUREBANNEDCREEP	465, ":You are banned from this server%?*: %*??"
#define ERR_YOUWILLBEBANNED	466, ""
#define ERR_KEYSET		467, "%# :Channel key already set"
#if IRCD_USES_ICONV
# define ERR_NOCODEPAGE		468, "%* :Invalid charset"
#endif
/* 470 reserved */
#define ERR_CHANNELISFULL	471, "%# :Cannot join channel (+l)"
#define ERR_UNKNOWNMODE		472, "%* :is unknown mode char to me for %#"
#define ERR_INVITEONLYCHAN	473, "%# :Cannot join channel (+i)"
#define ERR_BANNEDFROMCHAN	474, "%# :Cannot join channel (+b)"
#define ERR_BADCHANNELKEY	475, "%# :Cannot join channel (+k)"
#define ERR_BADCHANMASK		476, "%# :Bad Channel Mask"
#define ERR_NOCHANMODES		477, "%# :Channel doesn't support modes"
#define ERR_BANLISTFULL		478, "%# %* :Channel list is full"
/* 479-480 reserved */
#define ERR_NOPRIVILEGES	481, ":Permission Denied- You're not an IRC operator"
#define ERR_CHANOPRIVSNEEDED	482, "%# :You're not channel operator"
#define ERR_CANTKILLSERVER	483, ":You can't kill a server!"
#define ERR_RESTRICTED		484, ":Your connection is restricted!"
#define ERR_UNIQOPPRIVSNEEDED	485, ":You're not the original channel operator"
/* 486 reserved */
#define ERR_NOOPERHOST		491, ":No O-lines for your host"
/* 492 reserved */
/* 499-500 reserved */
#define ERR_UMODEUNKNOWNFLAG	501, ":Unknown MODE flag"
#define ERR_USERSDONTMATCH	502, ":Cannot change mode for other users"
