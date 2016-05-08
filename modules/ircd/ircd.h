/*
 * Copyright (C) 2010-2011  Andrej N. Gritsenko <andrej@rep.kiev.ua>
 *
 *     This program is free software; you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation; either version 2 of the License, or
 *     (at your option) any later version.
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License along
 *     with this program; if not, write to the Free Software Foundation, Inc.,
 *     51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * This file is a part of FoxEye IRCd module.
 */

/* these are used in structures below */
#include <direct.h>
#include <tree.h>

	/* "modes" for internal usage */
#define A_ISON		(1<<0)
#define A_PINGED	(1<<3)
	/* user-only internal modes */
#define A_AWAY		(1<<1)	/* +a	user is away */
#define A_WALLOP	(1<<2)	/* +w	can get wallop messages */
	/* server-only internal modes */
#define A_UPLINK	(1<<1)	/*	valid on registering or for server */
#if IRCD_MULTICONNECT
#define A_MULTI		(1<<2)	/*	I option granted (new mode) */
#endif
	/* channel-only internal modes */
#define A_LIMIT		(1<<1)	/* +-l	channel modelock flag */
#define A_KEYSET	(1<<2)	/* +-k	channel keylock flag */

#if ! IRCD_USES_ICONV
# undef IRCD_STRICT_NAMES
#endif

/* normalize IRCD_ID_HISTORY to be power of 2 */
#if IRCD_ID_HISTORY < 2048
# undef IRCD_ID_HISTORY
# define IRCD_ID_HISTORY 1024
#elif IRCD_ID_HISTORY < 4096
# undef IRCD_ID_HISTORY
# define IRCD_ID_HISTORY 2048
#elif IRCD_ID_HISTORY < 8192
# undef IRCD_ID_HISTORY
# define IRCD_ID_HISTORY 4096
#elif IRCD_ID_HISTORY < 16384
# undef IRCD_ID_HISTORY
# define IRCD_ID_HISTORY 8192
#elif IRCD_ID_HISTORY < 32768
# undef IRCD_ID_HISTORY
# define IRCD_ID_HISTORY 16384
#elif IRCD_ID_HISTORY < 65536
# undef IRCD_ID_HISTORY
# define IRCD_ID_HISTORY 32768
#else
# undef IRCD_ID_HISTORY
# define IRCD_ID_HISTORY 65536
#endif

typedef struct CLASS CLASS;		/* internally defined in ircd.c */
typedef struct CLIENT CLIENT;		/* defined below */
typedef struct MEMBER MEMBER;

typedef struct MASK
{
  struct MASK *next;
//  time_t since;
  char what[HOSTMASKLEN+1];
//  char by[HOSTMASKLEN+1];
} MASK;

typedef struct CHANNEL
{
  MEMBER *users;
  MEMBER *creator;			/* creator of ! channels if online */
  MEMBER *invited;
  MASK *bans, *exempts, *invites;
  time_t hold_upto;			/* it's on hold if set and count == 0 */
  time_t noop_since;
  modeflag mode;
  unsigned short count, limit;
#if IRCD_MULTICONNECT
  int on_ack; /* waiting for acks from servers (references counter) */
#endif
  char fc[2];
#ifdef TOPICWHOTIME
  char topic_by[HOSTMASKLEN+1];
  time_t topic_since;
#endif
  char topic[MB_LEN_MAX*TOPICLEN+1];
  char key[KEYLEN+1];
  char name[MB_LEN_MAX*CHANNAMELEN+1];
  char lcname[MB_LEN_MAX*CHANNAMELEN+1];
} CHANNEL;

#if IRCD_MULTICONNECT
/* note: ACK will come in sequential order but may interfere in random
   who is target of ACK (user, service, or server) can be NULL only if it's
   result of KILL for invalid NICK
   where is NULL if it's QUIT, SQUIT, KILL, or name change and isn't NULL
   if it's PART or KICK
   any activity on who (at where) should be ignored until we get all acks
   but if who->hold_upto != 0 and who->cs != NULL then we follow who->cs
   *** if we sent SERVER, SERVICE, USER, JOIN then we cannot get anything else
   *** anyway because other side can send us only USER/SERVER/SERVICE ATM
   note also we can get the same QUIT/etc. back before ACK due to network
   delays so we should count that case as delayed and not ignore activity
   after that backfired QUIT/etc. (but QUIT/etc. itself should be ignored)
   *** unfortunately I could not find a way to check channel ACK from outside
   *** of "ircd" module so let live with that, global ACKs are checked still */
typedef struct ACK
{
  struct ACK *next;
  CLIENT *who;				/* should be locked by counter */
  CHANNEL *where;			/* the same thing */
  int contrary;				/* we got it back so ignore this */
} ACK;
#endif

/* client link instance: prev is CLASS->local or IRCD->servers list for us
   or CLIENT->cs for other servers
   cl is client data
   where is where it seen, never NULL */
typedef struct LINK
{
  struct LINK *prev;
  CLIENT *cl, *where;
  int flags;
} LINK;

/* flags for field flags above */
#if IRCD_MULTICONNECT
#define LINK_FL_GOT_ID 0x1
#endif

/* pcl is CLASS->glob thru all servers including us or NULL if it's server
   everything is valid only when via->s.state != P_DISCONNECTED
   via is valid only if it's local client or any server
   and if it's remote server then it's the shortest way to send message
   alt contains second shortest path and is valid only if it's a server
   both via and alt (tree) should be recalculated after any SQUIT for
   A_MULTI (in case of multiconnect is allowed of course)
   via->cl is this instance only if this is a local client
   cs points to CLIENT itself if it's a server or local client
   so cs->via always is the shortest way and cs->alt is alternate one
   via->s.iface is interface only for local clients, remote clients
   cannot be addressed directly but only by sending a message to lcnick
   last_id is checked in servers.c - last_id[0] is current newest and
   last_id[1]...last_id[2] may be missed ones after new connect...
   rfr is always some nick on hold: if this one is active user and
   rfr->cs points to this then rfr is who referenced for nick (i.e. this
   is a nick holder) or else rfr points to 'renamed from' structure
   for any nick on hold cs points to a nick holder, pcl is tailed list
   of collision for this nick, and x.rto is 'renamed to' structure
   if collision isn't behind A_MULTI link then delay as in RFC2813
   in case of we sent back NICK or KILL for collided user away contains
   server name where we sent that command (for tracking purpose)
   host contains host of client while client is alive and if client
   is on hold due to network split then host contains name of server
   *** if CLIENT is online user then it is in lists:
   - class - via pcl - reference is x.class
   - channel members - via list c.hannels
   - server clients - reference is cs
   *** as soon user gone offline it should be deleted from each of those */
/* while registering, fields have another values: ->fname has input from
   USER, ->lcnick is empty, ->away and ->vhost are filled by PASS input */
struct CLIENT
{
  CLIENT *pcl;				/* list in class */
  struct peer_priv *via;		/* the way to this link */
#if IRCD_MULTICONNECT
  struct peer_priv *alt;		/* second shortest (link instance) */
  int on_ack;				/* references from ACK on me */
  int last_id;				/* last seen originated message id */
  char id_cache[IRCD_ID_HISTORY/8];	/* bitmap for ids */
#endif
  union {
    CLASS *class;			/* user's class */
    CLIENT *rto;			/* 'renamed to' if nick is on hold */
    struct _CLIENT_x_a {
      unsigned short int token;		/* server's token, unique */
      unsigned short int uc;		/* users count, for statistics */
    } a;
  } x;
  union {
    MEMBER *hannels;			/* user's channels list */
    LINK *lients;			/* server's clients list */
  } c;
  CLIENT *cs;				/* client's server */
  CLIENT *rfr;				/* 'renamed from' or collision list */
  time_t hold_upto;			/* not 0 if on hold */
  modeflag umode;			/* A_ISON, A_SERVER, etc. */
  unsigned short int hops;		/* shortest distance to client */
#if MB_LEN_MAX*AWAYLEN > SERVEROPTIONLEN && MB_LEN_MAX*AWAYLEN > SERVERNAMELEN
  char away[MB_LEN_MAX*AWAYLEN+1];	/* user's away message / service type */
#else
# if SERVEROPTIONLEN > SERVERNAMELEN
  char away[SERVEROPTIONLEN+1];		/* since it's used as version storage */
# else
  char away[SERVERNAMELEN+1];		/* and it's used for tracking nicks */
# endif
#endif
#if MB_LEN_MAX*NICKLEN > SERVERNAMELEN
  char nick[MB_LEN_MAX*NICKLEN+1];	/* registration nick */
  char lcnick[MB_LEN_MAX*NICKLEN+1];	/* LC(lower case) nick / server name */
#else
  char nick[SERVERNAMELEN+1];
  char lcnick[SERVERNAMELEN+1];
#endif
  char fname[MB_LEN_MAX*REALNAMELEN+1];	/* full name (description) */
  char user[IDENTLEN+1];		/* ident - from connection */
  char host[HOSTLEN+1];			/* host ; LC ; split server if on hold
						       empty if hold by acks */
					/* and it's used for service distrib. */
  char vhost[HOSTLEN+1];		/* "visible host" to show to users */
};

/* channel's member data */
struct MEMBER
{
  CLIENT *who;
  CHANNEL *chan;
  modeflag mode;
  MEMBER *prevchan;
  MEMBER *prevnick;
};

/* this struct is main interface data and is managed by ircd.c
   but channels member which is managed by channels.c
   it is data member of INTERFACE *srv passed to bindings */
typedef struct IRCD
{
  INTERFACE *iface;	/* has network name */
  INTERFACE *sub;	/* I_CLIENT with name @network to collect messages */
  NODE *clients;	/* clients list (name->CLIENT) */
  unsigned int lu, gu;	/* max users count for statistics */
  NODE *channels;	/* channels list (name->CHANNEL) */
  CLASS *users;		/* local users lists */
  LINK *servers;	/* local servers list */
  CLIENT **token;	/* global servers list (allocated) */
  unsigned short int s;	/* size of the allocated list */
} IRCD;

struct peer_priv
{
  struct peer_t p;	/* p.dname points to nick, p.parse isn't used */
  LINK *link;		/* it has nick, valid if p.state != P_DISCONNECTED */
  time_t noidle;	/* last message but ping */
  size_t bs, br, ms, mr; /* statistics */
  time_t started;	/* when connection was started */
  struct {
    CLIENT **token;	/* server: token[i] list (allocated) */
    MEMBER *nvited;	/* user: invitations */
  } i;
  unsigned short int t; /* server: tokens list size (see above) */
  short penalty;	/* traffic penalty (server: corrections, user: delay) */
#if IRCD_MULTICONNECT
  ACK *acks;		/* server: list of waiting acks */
#endif
  pthread_t th;		/* thread ID if p.state == P_DISCONNECTED */
};

/*
 * client               ->via   ->cs    ->hold
 * ME                   NULL    NULL    0
 * local client         peer    CLIENT  0
 * local server         peer    CLIENT  0
 * remote client        NULL    (path)  0
 * remote server        (path)  CLIENT  0
 * dying                peer    (smth)  >0
 * phantom              NULL    holder  >0
 *
 * client                       ->cs        ->rfr       ->x.rto
 * active alone                 CLIENT      NULL        --
 * active (new nick)            CLIENT      old         --
 * kept on collision            CLIENT      clones      --
 * killed on collision          keeper      (old)       NULL
 * killed (keeper)              CLIENT      clones      NULL
 * died (splitted) alone        CLIENT      (old)       NULL
 * renamed on collision         keeper      (old)       new nick
 * renamed (keeper)             CLIENT      clones      new nick
 * renamed (old nick)           CLIENT      (old)       new nick
 */

/* test for ME : valid always */
#define CLIENT_IS_ME(x) ((x)->cs == NULL)
/* test for local clients/servers : crashes on ME, invalid on phantoms */
#define CLIENT_IS_LOCAL(x) ((x)->cs->via->link->cl == x)
/* test for remote clients : invalid on ME or phantoms */
#define CLIENT_IS_REMOTE(x) ((x)->via == NULL)
/* test for any server : valid always */
#define CLIENT_IS_SERVER(x) ((x)->umode & A_SERVER)
/* test for any service : valid always */
#define CLIENT_IS_SERVICE(x) ((x)->umode & A_SERVICE)

#ifdef USE_SERVICES
#define SERVICE_WANT_SERVICE	0x00000001 /* other services signing on/off */
#define SERVICE_WANT_OPER	0x00000002 /* operators, included in umodes too */
#define SERVICE_WANT_UMODE	0x00000004 /* user modes, iow + local modes */
#define SERVICE_WANT_AWAY	0x00000008 /* away isn't propaged anymore.. */
#define SERVICE_WANT_KILL	0x00000010 /* KILLs */
#define SERVICE_WANT_NICK	0x00000020 /* all NICKs (new user, change) */
#define SERVICE_WANT_USER	0x00000040 /* USER signing on */
#define SERVICE_WANT_QUIT	0x00000080 /* all QUITs (users signing off) */
#define SERVICE_WANT_SERVER	0x00000100 /* servers signing on */
#define SERVICE_WANT_WALLOP	0x00000200 /* wallops */
#define SERVICE_WANT_SQUIT	0x00000400 /* servers signing off */
#define SERVICE_WANT_RQUIT	0x00000800 /* regular user QUITs (these which are also sent between servers) */
#define SERVICE_WANT_MODE	0x00001000 /* channel modes (not +ov) */
#define SERVICE_WANT_CHANNEL	0x00002000 /* channel creations/destructions */
#define SERVICE_WANT_VCHANNEL	0x00004000 /* channel joins/parts */
#define SERVICE_WANT_TOPIC	0x00008000 /* channel topics */

#define SERVICE_WANT_PREFIX	0x00010000 /* to receive n!u@h instead of n */
#define SERVICE_WANT_TOKEN	0x00020000 /* use serv token instead of name */
#define SERVICE_WANT_EXTNICK	0x00040000 /* user extended NICK syntax */

#define SERVICE_WANT_ERRORS	0x01000000 /* &ERRORS */
#define SERVICE_WANT_NOTICES	0x02000000 /* &NOTICES */
#define SERVICE_WANT_LOCAL	0x04000000 /* &LOCAL */
#define SERVICE_WANT_NUMERICS	0x08000000 /* &NUMERICS */

#define SERVICE_WANT_USERLOG	0x10000000 /* FNAME_USERLOG */
#define SERVICE_WANT_CONNLOG	0x20000000 /* FNAME_CONNLOG */

#define SERVICE_IS_TRUSTED	0x80000000 /* cannot be set by services */

#define SERVICE_FLAGS(x) (((uint32_t *)(x)->away)[1])
#endif

	/* ircd.c common functions */
/* args: replyto, RPL_* / ERR_*, target, ping, message ; returns 1 */
/* example:  ircd_do_numeric (clp, RPL_VERSION, NULL, 0, version_string); */
int ircd_do_unumeric (CLIENT *, int, const char *, CLIENT *, unsigned short,
		      const char *);
/* the same but target is channel and no ping arg */
int ircd_do_cnumeric (CLIENT *, int, const char *, CHANNEL *, unsigned short,
		      const char *);
/* manages lists, prepares to notify local users about that quit (I_PENDING),
   resets away message, and shedules kill of peer if it's local
   converts collision list into phantom so caller have to set 'hold_upto'
   caller should manage 'host' field after this for nick tracking purposes
   args: client, sender, reason */
void ircd_prepare_quit (CLIENT *, struct peer_priv *, const char *);
/* we got informed about lost server; args: who, source, reason */
void ircd_do_squit (LINK *, struct peer_priv *, const char *);
/* main seek engine: nick/name to structure; returns ME by NULL */
CLIENT *ircd_find_client (const char *, struct peer_priv *);
/* the same but does not do traverse to current nick */
CLIENT *ircd_find_client_nt (const char *, struct peer_priv *);
/* tries drop client structure on hold; should be called only if no acks left */
void ircd_drop_nick (CLIENT *);
/* get token by sender (server or remote user only) */
static inline unsigned short int client2token (CLIENT *cl)
{
  if (cl != NULL && !cl->hold_upto &&
      (CLIENT_IS_SERVER(cl) || !CLIENT_IS_LOCAL(cl)))
    return cl->cs->x.a.token;
  return 0;
}
/* should be called after correction and error message;
   either sends ERROR message to peer or SQUIT the link
   returns 1 on success or returns 0 if link squitted */
int ircd_recover_done (struct peer_priv *, const char *);
/* marks local +w users to send WALLOPS, returns own server name */
const char *ircd_mark_wallops(void);

#if IRCD_MULTICONNECT
/* args: link, who, where */
void ircd_add_ack (struct peer_priv *, CLIENT *, CHANNEL *);
/* removes the oldest ack from link, doesn't check for NULL */
void ircd_drop_ack (IRCD *, struct peer_priv *);
/* args: link, who, where */
ACK *ircd_check_ack (struct peer_priv *, CLIENT *, CHANNEL *);
/* removes all acks from link */
#define ircd_clear_acks(I,pp) while (pp->acks) ircd_drop_ack (I,pp)
/* generates new id for new type commands from my clients or me */
int ircd_new_id (void);
/* if id isn't received yet then register it and return 1, else return 0 */
int ircd_test_id (CLIENT *, int);
#endif

#define NOSUCHCHANNEL ((MEMBER *)1) /* may be returned by ircd_find_member */
#define CHANNEL0 ((CHANNEL *)1)     /* for ircd_check_ack */

	/* channel.c common functions */
/* manage CHANNEL list - adds user to channel and informs local users
   no checks (but duplicates), no network broadcasts
   args: ircd, by_server, channel, user, user_channelmode */
MEMBER *ircd_new_to_channel (IRCD *, struct peer_priv *, const char *,
			     CLIENT *, modeflag);
MEMBER *ircd_add_to_channel (IRCD *, struct peer_priv *, CHANNEL *, CLIENT *,
			     modeflag);
/* args: ircd, member, tohold; should be called after broadcast */
void ircd_del_from_channel (IRCD *, MEMBER *, int);
/* args: ircd, channel, user; may return NULL or NOSUCHCHANNEL */
MEMBER *ircd_find_member (IRCD *, const char *, CLIENT *);
/* args: ircd, client, tohold, isquit; should be called after broadcast */
void ircd_quit_all_channels (IRCD *, CLIENT *, int, int);
/* adds invite for local client to existing channel */
void ircd_add_invited (CLIENT *, CHANNEL *);
/* args: ircd, channel; should be called only if no acks left */
void ircd_drop_channel (IRCD *, CHANNEL *);
/* args: buf, umode, sizeof(buf); returns buf */
char *ircd_make_umode (char *, modeflag, size_t);
/* returns whochar for first appropriate mode */
char ircd_mode2whochar (modeflag);
/* does backward conversion */
modeflag ircd_whochar2mode(char);
/* args: ircd, servername, nick, channame, mode char
   used only when some remote user joins channel
   returns starting channel mode for '\0' or user-on-channel mode */
modeflag ircd_char2mode(INTERFACE *, const char *, const char *, const char *, char);
/* args: ircd, servername, mode char, user; returns umode for server modechange */
modeflag ircd_char2umode(INTERFACE *, const char *, char, CLIENT *);

	/* calls to channel.c from ircd.c */
void ircd_channels_flush (IRCD *, char *, size_t);
void ircd_burst_channels (INTERFACE *, NODE *);
void ircd_channels_report (INTERFACE *);
void ircd_channels_chreop (IRCD *, CLIENT *);
void send_isupport (IRCD *, CLIENT *);

	/* calls to client.c from channel.c */
int ircd_names_reply (CLIENT *, CLIENT *, CHANNEL *, int);

	/* calls to ircd.c from queries.c */
int ircd_try_connect (CLIENT *, const char *, const char *);
int ircd_show_trace (CLIENT *, CLIENT *);
int ircd_lusers_unknown (void);

	/* channel.c bindings */
void ircd_channel_proto_start (IRCD *);
void ircd_channel_proto_end (NODE **);
	/* client.c bindings */
void ircd_client_proto_start (void);
void ircd_client_proto_end (void);
	/* server.c bindings */
void ircd_server_proto_start (void);
void ircd_server_proto_end (void);
	/* queries.c bindings + variables */
void ircd_queries_proto_start (void);
void ircd_queries_proto_end (void);
void ircd_queries_register (void);
	/* messages.c bindings */
void ircd_message_proto_start (void);
void ircd_message_proto_end (void);

#include "sendto.h"
