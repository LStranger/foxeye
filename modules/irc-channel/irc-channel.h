/*
 * Copyright (C) 2005-2011  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 *     You should have received a copy of the GNU General Public License
 *     along with this program; if not, write to the Free Software
 *     Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * The FoxEye "irc-channel" module: internal structures definitions and
 *   internal functions declarations.
 */

/* IRC-specific modes for modeflag */
#define A_ISON		(1<<0)	/*	user (or me) is on the channel */
	/* user-only modes */
#define A_AWAY		(1<<1)	/* +a	user is away */
#define A_WALLOP	(1<<2)	/* +w	can get wallop messages */
	/* channel-only modes */
#define A_LIMIT		(1<<1)	/* +-l	channel modelock flag */
#define A_KEYSET	(1<<2)	/* +-k	channel modelock flag */

/* server features */
#define L_NOUSERHOST	(1<<0)
#define L_NOEXEMPTS	(1<<1)
#define L_HASHALFOP	(1<<2)
#define L_HASADMIN	(1<<3)
#define L_HASREGMODE	(1<<4)

typedef struct
{
  pthread_t th;
  char *chname;
  char *who;
  bool defl;
} invited_t;

typedef struct SplitMember
{
  struct SplitMember *next;
  struct LINK *member;
} SplitMember;

typedef struct netsplit
{
  struct netsplit *prev;
  char *servers;		/* "left gone" string */
  SplitMember *members;		/* nicks@channels in this split */
  SplitMember *njlast;		/* for netsplit and netjoin reporting */
  time_t at;			/* when started */
  time_t njlastact;
  int stage;			/* stage of netsplit */
} netsplit;

typedef struct LIST
{
  struct LIST *next;
  char *what;
  time_t since;
  char by[1];			/* WARNING: structure of variable size! */
} __attribute__ ((packed)) LIST;

typedef struct LINK
{
  struct CHANNEL *chan;
  struct LINK *prevnick;	/* chrec->nicks => link->prevnick ... */
  struct NICK *nick;
  struct LINK *prevchan;	/* nick->channels => link->prevchan... */
  modeflag mode;
  time_t activity;
  time_t lmct;			/* last modechange time by me */
  char joined[20];
  short count;
} LINK;

typedef struct CHANNEL
{
  INTERFACE *chi;		/* name "channel@network", lower case, short */
  char *real;			/* Channel from our JOIN as is */
  LINK *nicks;
  char *key;
  LIST *topic, *bans, *exempts, *invites;
  modeflag mode;		/* current mode, +A_ME when not fully synced */
  modeflag mlock, munlock;	/* from config */
  unsigned short limit;		/* if 0 then unlimited, -1 = modeunlock +l */
  lid_t id;
  tid_t tid;			/* for bans enforcer */
} CHANNEL;

typedef struct NICK
{
  char *name;			/* "nick", lower case - for lnames and masks */
  char *lname;			/* only once */
  struct NICK *prev_TSL;	/* previous "The Same Lname" */
  char *host;			/* nick!user@host */
//  char *nick;			/* nick\0user@host */
//  char *uhost;		/* pointer into above after prefix */
  LINK *channels;
  netsplit *split;		/* not NULL if it's on netsplit or netjoined */
  struct IRC *net;
  modeflag umode;
  lid_t id;			/* valid only if lname != NULL */
} NICK;

typedef struct IRC
{
  char *name;			/* "@network" */
  INTERFACE *neti;
  size_t (*lc) (char *, const char *, size_t);
  NODE *channels;
  NODE *nicks;
  NODE *lnames;			/* referenced data is last NICK */
  NICK *me;
  netsplit *splits;
  invited_t *invited;
  time_t last_rejoin;
  int maxmodes, maxbans, maxtargets;
  char features;		/* L_NOUSERHOST, etc. */
  char modechars[3];		/* restricted,registered,hidehost */
} IRC;

CHANNEL *ircch_find_service (const char *, IRC **);
LINK *ircch_find_link (IRC *, char *, CHANNEL *);
NICK *ircch_retry_nick (IRC *, const char *);
int ircch_add_mask (LIST **, char *, size_t, char *);
LIST *ircch_find_mask (LIST *, char *);
void ircch_remove_mask (LIST **, LIST *);

void ircch_recheck_modes (IRC *, LINK *, userflag, userflag, char *, int);
void ircch_recheck_channel_modes (IRC *, CHANNEL *);
	/* bindtables: irc-modechg, keychange */
int ircch_parse_modeline (IRC *, CHANNEL *, LINK *, char *, userflag,
				struct bindtable_t *, struct bindtable_t *,
				int, char **);
void ircch_parse_configmodeline (IRC *, CHANNEL *, struct clrec_t *, char *);
void ircch_enforcer (IRC *, CHANNEL *);
void ircch_expire (IRC *, CHANNEL *);

void ircch_set_ss (void);
void ircch_unset_ss (void);
