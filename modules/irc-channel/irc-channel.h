/*
 * Copyright (C) 2005-2006  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 */

/* IRC-specific modes for modeflag */
#define A_ISON		(1<<0)	/*	user is on the channel */
#define A_AWAY		(1<<1)	/* +a	user is away */
#define A_WALLOP	(1<<2)	/* +w	can get wallop messages */

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

/* netsplit: create ===> netjoin: send ping ===> fake: undo || ok: destroy */
typedef struct netsplit_t
{
  struct netsplit_t *next;
  char *servers;		/* "left gone" string */
  time_t at;			/* when started */
  time_t ping;			/* when ping sent */
  NODE *nicks;			/* referenced data is nick_t */
  NODE *channels;		/* referenced data is ch_t */
  struct ch_t *lastch;		/* for netjoins */
} netsplit_t;

typedef struct list_t
{
  struct list_t *next;
  time_t since;
  char *what;
  char by[1];			/* WARNING: structure of variable size! */
} list_t;

typedef struct link_t
{
  struct ch_t *chan;
  struct link_t *prevnick;	/* chrec->nicks => link->prevnick ... */
  struct nick_t *nick;
  struct link_t *prevchan;	/* nick->channels => link->prevchan... */
  modeflag mode;
  time_t activity;
  time_t lmct;			/* last modechange time by me */
  char joined[13];
  short count;
} link_t;

typedef struct ch_t
{
  INTERFACE *chi;		/* with name "channel@network", lower case */
  link_t *nicks;
  char *key;
  list_t *topic, *bans, *exempts, *invites;
  unsigned short limit;		/* if 0 then unlimited, -1 = modeunlock +l */
  unsigned short n;		/* number of users on channel */
  lid_t id;
  tid_t tid;			/* for bans enforcer */
  modeflag mode;		/* current mode */
  modeflag mlock, munlock;	/* from config */
} ch_t;

typedef struct nick_t
{
  char *name;			/* "nick", lower case */
  char *lname;			/* only once */
  struct nick_t *prev_TSL;	/* previous "The Same Lname" */
  char *host;			/* nick!user@host */
  link_t *channels;
  netsplit_t *split;		/* not NULL if it's on netsplit or netjoined */
  struct net_t *net;
  modeflag umode;
  lid_t id;
} nick_t;

typedef struct net_t
{
  char *name;			/* "@network" */
  INTERFACE *neti;
  char *(*lc) (char *, const char *, size_t);
  NODE *channels;
  NODE *nicks;
  NODE *lnames;			/* referenced data is last nick_t */
  nick_t *me;
  netsplit_t *splits;
  invited_t *invited;
  int maxmodes, maxbans, maxtargets;
  char features;		/* L_NOUSERHOST, etc. */
  char modechars[3];		/* restricted,registered,hidehost */
} net_t;

ch_t *ircch_find_service (INTERFACE *, net_t **);
link_t *ircch_find_link (net_t *, char *, ch_t *);
int ircch_add_mask (list_t **, char *, size_t, char *);
list_t *ircch_find_mask (list_t *, char *);
void ircch_remove_mask (list_t **, list_t *);

void ircch_recheck_modes (net_t *, link_t *, userflag, userflag, char *, int);
	/* bindtables: irc-modechg, keychange */
int ircch_parse_modeline (net_t *, ch_t *, link_t *, char *, userflag, \
				bindtable_t *, bindtable_t *, int, char **);
void ircch_parse_configmodeline (net_t *, ch_t *, char *);
void ircch_enforcer (net_t *, ch_t *);
void ircch_expire (net_t *, ch_t *);

void ircch_set_ss (void);
void ircch_unset_ss (void);
