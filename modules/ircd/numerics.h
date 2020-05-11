#define RPL_WELCOME		  1, N_(":Welcome to the Internet Relay Network %#!%L@%@")
#define RPL_YOURHOST		  2, N_(":Your host is %#, running version %V")
#define RPL_CREATED		  3, N_(":This server was created %*")
#define RPL_MYINFO		  4, "%# %V %*"
#define RPL_ISUPPORT		  5, N_("%* :are supported by this server")
#define RPL_BOUNCE		 10, N_("%# %P :Please use this Server/Port instead")
/* 015 reserved */
/* 017-018 reserved */
#define RPL_HELLO		 20, N_(":Welcome to %#! Please wait until checks are done.")
/* 042-043 reserved */
#define RPL_TRACELINK		200, N_("Link %V%?P.d%P?? %# %*")
#define RPL_TRACECONNECTING	201, N_("Try. %* %#")
#define RPL_TRACEHANDSHAKE	202, N_("H.S. %* %#")
#define RPL_TRACEUNKNOWN	203, N_("???? - %*")
#define RPL_TRACEOPERATOR	204, N_("Oper %* %#")
#define RPL_TRACEUSER		205, N_("User %* %#")
#define RPL_TRACESERVER		206, N_("Serv %*")
#define RPL_TRACESERVICE	207, N_("Service %*")
#define RPL_TRACENEWTYPE	208, N_("%* 0 %#")
#define RPL_TRACECLASS		209, N_("Class %* %P")
/* 210 reserved */
#define RPL_STATSLINKINFO	211, "%*"
#define RPL_STATSCOMMANDS	212, "%*"
#define RPL_STATSCLINE		213, "c %@ * %# %?P%P?0? 0"
#define RPL_STATSNLINE		214, "%*"
#define RPL_STATSILINE		215, "%*"
#define RPL_STATSKLINE		216, "%*"
#define RPL_STATSQLINE		217, "%*"
#define RPL_STATSYLINE		218, "%*"
#define RPL_ENDOFSTATS		219, N_("%* :End of STATS report")
#define RPL_UMODEIS		221, "+%*"
#if IRCD_USES_ICONV
# define RPL_CODEPAGE		222, N_("%* :is your charset now")
#endif
/* 231-233 reserved */
#define RPL_SERVLIST		234, "%# %*"
#define RPL_SERVLISTEND		235, N_("%@ %* :End of service listing")
/* 239 reserved */
#define RPL_STATSVLINE		240, "%*"
#define RPL_STATSLLINE		241, "%*"
#define RPL_STATSUPTIME		242, ":%*"
#define RPL_STATSOLINE		243, "O %@ * %# 0 0"
#define RPL_STATSHLINE		244, "H %* * %# 0 0"
#define RPL_STATSSLINE		245, "%*"
/* 246 reserved */
#define RPL_STATSBLINE		247, "%*"
/* 248-249 reserved */
#define RPL_STATSDLINE		250, "%*"
#define RPL_LUSERCLIENT		251, ":%*"
#define RPL_LUSEROP		252, N_("%?P%P?0? :operator(s) online")
#define RPL_LUSERUNKNOWN	253, N_("%?P%P?0? :unknown connection(s)")
#define RPL_LUSERCHANNELS	254, N_("%?P%P?0? :channels formed")
#define RPL_LUSERME		255, ":%*"
#define RPL_ADMINME		256, N_("%= :Administrative info")
#define RPL_ADMINLOC1		257, ":%*"
#define RPL_ADMINLOC2		258, ":%*"
#define RPL_ADMINEMAIL		259, ":%*"
#define RPL_TRACELOG		261, "%*"
#define RPL_TRACEEND		262, N_("%= %V%?P.d%P?? :End of TRACE")
#define RPL_TRYAGAIN		263, N_("%* :Please wait a while and try again.")
/* 264 reserved */
#define RPL_LOCALUSERS		265, N_(":Current local users: %P  Max: %*")
#define RPL_GLOBALUSERS		266, N_(":Current global users: %P  Max: %*")
/* 300 reserved */
#define RPL_AWAY		301, "%# :%*"
#define RPL_USERHOST		302, ":%*"
#define RPL_ISON		303, ":%*"
/* 304 reserved */
#define RPL_UNAWAY		305, N_(":You are no longer marked as being away")
#define RPL_NOWAWAY		306, N_(":You have been marked as being away")
#define RPL_WHOISUSER		311, "%# %L %@ * :%*"
#define RPL_WHOISSERVER		312, "%* %# :%@"
#define RPL_WHOISOPERATOR	313, N_("%# :is an IRC operator")
#define RPL_WHOWASUSER		314, "%# %L %@ * :%*"
#define RPL_ENDOFWHO		315, N_("%* :End of WHO list")
/* 316 reserved */
#define RPL_WHOISIDLE		317, N_("%# %* :seconds idle")
#define RPL_ENDOFWHOIS		318, N_("%* :End of WHOIS list")
#define RPL_WHOISCHANNELS	319, "%# :%*"
#if IRCD_USES_ICONV
# define RPL_WHOISCHARSET	320, N_("%# :charset is %*")
#endif
#define RPL_LISTSTART		321, N_("Channel :Users  Name")
#define RPL_LIST		322, "%# %?P%P?0? :%*"
#define RPL_LISTEND		323, N_(":End of LIST")
#define RPL_CHANNELMODEIS	324, "%# +%*"
#define RPL_UNIQOPIS		325, "%# %*"
/* 327 reserved */
#define RPL_NOTOPIC		331, N_("%# :No topic is set")
#define RPL_TOPIC		332, "%# :%*"
#ifdef TOPICWHOTIME
# define RPL_TOPICWHOTIME	333, "%# %*"
#endif
#define RPL_WHOISSECURE		336, N_("%# :is using encrypted connection")
#define RPL_INVITING		341, "%# %*"
#define RPL_SUMMONING		342, N_("%# :Summoning user to IRC")
/* 344-345 reserved */
#define RPL_INVITELIST		346, "%# %*"
#define RPL_ENDOFINVITELIST	347, N_("%# :End of channel invite list")
#define RPL_EXCEPTLIST		348, "%# %*"
#define RPL_ENDOFEXCEPTLIST	349, N_("%# :End of channel exception list")
#define RPL_VERSION		351, "%V%?P.d%P?? %= :%*"
#define RPL_WHOREPLY		352, "%*"
#define RPL_NAMREPLY		353, "%*"
#define RPL_ENDOFNAMES		366, N_("%* :End of NAMES list")
/* 361-363 reserved */
#define RPL_LINKS		364, "%# %* :%?P%P?0? %@"
#define RPL_ENDOFLINKS		365, N_("%* :End of LINKS list")
#define RPL_BANLIST		367, "%# %*"
#define RPL_ENDOFBANLIST	368, N_("%# :End of channel ban list")
#define RPL_ENDOFWHOWAS		369, N_("%* :End of WHOWAS")
#define RPL_INFO		371, ":%*"
#define RPL_MOTD		372, ":- %*"
/* 373 reserved */
#define RPL_ENDOFINFO		374, N_(":End of INFO list")
#define RPL_MOTDSTART		375, N_(":- %= Message of the day - ")
#define RPL_ENDOFMOTD		376, N_(":End of MOTD command")
#define RPL_YOUREOPER		381, N_(":You are now an IRC operator")
#define RPL_REHASHING		382, N_("%* :Rehashing")
#define RPL_YOURESERVICE	383, N_("You are service %#")
/* 384-385 reserved */
#define RPL_TIME		391, "%= :%*"
#define RPL_USERSSTART		392, N_(":UserID   Terminal  Host") /* RFC1459 */
#define RPL_USERS		393, N_(":%L %P %@") /* RFC1459 */
#define RPL_ENDOFUSERS		394, N_(":End of users") /* RFC1459 */
#define RPL_NOUSERS		395, N_(":Nobody logged in") /* RFC1459 */
#define ERR_NOSUCHNICK		401, N_("%* :No such nick/channel")
#define ERR_NOSUCHSERVER	402, N_("%* :No such server")
#define ERR_NOSUCHCHANNEL	403, N_("%* :No such channel")
#define ERR_CANNOTSENDTOCHAN	404, N_("%# :Cannot send to channel")
#define ERR_TOOMANYCHANNELS	405, N_("%# :You have joined too many channels")
#define ERR_WASNOSUCHNICK	406, N_("%* :There was no such nickname")
#define ERR_TOOMANYTARGETS	407, N_("%# :Too many recipients. %*")
#define ERR_NOSUCHSERVICE	408, N_("%* :No such service")
#define ERR_NOORIGIN		409, N_(":No origin specified")
#define ERR_NORECIPIENT		411, N_(":No recipient given (%*)")
#define ERR_NOTEXTTOSEND	412, N_(":No text to send")
#define ERR_NOTOPLEVEL		413, N_("%* :No toplevel domain specified")
#define ERR_WILDTOPLEVEL	414, N_("%* :Wildcard in toplevel domain")
#define ERR_BADMASK		415, N_("%* :Bad Server/host mask")
#define ERR_TOOMANYMATCHES	416, N_("%* :Output too long (try locally)")
#define ERR_UNKNOWNCOMMAND	421, N_("%* :Unknown command")
#define ERR_NOMOTD		422, N_(":MOTD File is missing")
#define ERR_NOADMININFO		423, N_("%= :No administrative info available")
#define ERR_FILEERROR		424, N_(":File error doing %*")
#define ERR_NONICKNAMEGIVEN	431, N_(":No nickname given")
#define ERR_ERRONEUSNICKNAME	432, N_("%* :Erroneous nickname")
#define ERR_NICKNAMEINUSE	433, N_("%# :Nickname is already in use")
/* 434-435 reserved */
#define ERR_NICKCOLLISION	436, N_("%N :Nickname collision KILL from %L@%@")
#define ERR_UNAVAILRESOURCE	437, N_("%* :Nick/channel is temporarily unavailable")
/* 438 reserved */
#define ERR_USERNOTINCHANNEL	441, N_("%* %# :They aren't on that channel")
#define ERR_NOTONCHANNEL	442, N_("%* :You're not on that channel")
#define ERR_USERONCHANNEL	443, N_("%* %# :is already on channel")
#define ERR_NOLOGIN		444, N_("%* :User not logged in")
#define ERR_SUMMONDISABLED	445, N_(":SUMMON has been disabled")
#define ERR_USERSDISABLED	446, N_(":USERS has been disabled") /* RFC1459 */
#define ERR_NOTREGISTERED	451, N_(":You have not registered")
#define ERR_NEEDMOREPARAMS	461, N_("%* :Not enough parameters")
#define ERR_ALREADYREGISTRED	462, N_(":Unauthorized command (already registered)")
#define ERR_NOPERMFORHOST	463, N_(":Your host isn't among the privileged")
#define ERR_PASSWDMISMATCH	464, N_(":Password incorrect")
#define ERR_YOUREBANNEDCREEP	465, N_(":You are banned from this server%?*: %*??")
#define ERR_YOUWILLBEBANNED	466, ""
#define ERR_KEYSET		467, N_("%# :Channel key already set")
#if IRCD_USES_ICONV
# define ERR_NOCODEPAGE		468, N_("%* :Invalid charset")
#endif
/* 470 reserved */
#define ERR_CHANNELISFULL	471, N_("%# :Cannot join channel (+l)")
#define ERR_UNKNOWNMODE		472, N_("%* :is unknown mode char to me for %#")
#define ERR_INVITEONLYCHAN	473, N_("%# :Cannot join channel (+i)")
#define ERR_BANNEDFROMCHAN	474, N_("%# :Cannot join channel (+b)")
#define ERR_BADCHANNELKEY	475, N_("%# :Cannot join channel (+k)")
#define ERR_BADCHANMASK		476, N_("%# :Bad Channel Mask")
#define ERR_NOCHANMODES		477, N_("%# :Channel doesn't support modes")
#define ERR_BANLISTFULL		478, N_("%# %* :Channel list is full")
/* 479-480 reserved */
#define ERR_NOPRIVILEGES	481, N_(":Permission Denied - You're not an IRC operator")
#define ERR_CHANOPRIVSNEEDED	482, N_("%# :You're not channel operator")
#define ERR_CANTKILLSERVER	483, N_(":You can't kill a server!")
#define ERR_RESTRICTED		484, N_(":Your connection is restricted!")
#define ERR_UNIQOPPRIVSNEEDED	485, N_(":You're not the original channel operator")
/* 486 reserved */
#define ERR_NOOPERHOST		491, N_(":No O-lines for your host")
/* 492 reserved */
/* 499-500 reserved */
#define ERR_UMODEUNKNOWNFLAG	501, N_(":Unknown MODE flag")
#define ERR_USERSDONTMATCH	502, N_(":Cannot change mode for other users")
#define ERR_CANTSENDTOUSER	531, N_("%# :User does not accept private messages%?* (%*)??")
#define RPL_HELPTXT		705, "%*"
#define RPL_ENDOFHELP		706, N_("%* :End of /HELP.")
