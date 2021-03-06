/*
 * Copyright (C) 2010-2020  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 * This file is a part of FoxEye IRCd module: user queries (RFC2812).
 */

#include <foxeye.h>
#if IRCD_USES_ICONV == 0 || (defined(HAVE_ICONV) && (IRCD_NEEDS_TRANSLIT == 0 || defined(HAVE_CYRILLIC_TRANSLIT)))
#include <modules.h>
#include <list.h>
#include <init.h>
#include <conversion.h>

#include <fcntl.h>
#include <errno.h>

#include "ircd.h"
#include "numerics.h"

static char _ircd_motd_file[PATH_MAX+1] = "ircd.motd";
static char _ircd_admin_info[SHORT_STRING] = "Not configured.";
static char _ircd_admin_email[SHORT_STRING] = "lame@lame.org";
extern char _ircd_description_string[]; /* in ircd.c */
static long int _ircd_max_matches = 500;
static long int _ircd_max_whois = 3;

static struct bindtable_t *BTIrcdStatsReply;
static struct bindtable_t *BTIrcdWhois;

/* ---------------------------------------------------------------------------
 * Common internal functions.
 */
#define _ircd_find_client_lc(I,X) Find_Key ((I)->clients, X)

static inline MEMBER *_ircd_is_on_channel (CLIENT *cl, CHANNEL *ch)
{
  register MEMBER *m;

  for (m = ch->users; m; m = m->prevnick)
    if (m->who == cl)
      break;
  return m;
}

static inline int _ircd_is_on_the_same_channel (CLIENT *one, CLIENT *two)
{
  register MEMBER *m1, *m2;

  for (m1 = one->c.hannels; m1; m1 = m1->prevchan)
    if (!(m1->chan->mode & (A_ANONYMOUS | A_QUIET)))
      for (m2 = m1->chan->users; m2; m2 = m2->prevnick)
	if (m2->who == two)
	  return 1;
  return 0;
}

/* returns either server or local client */
static inline CLIENT *_ircd_find_by_mask (IRCD *ircd, struct peer_priv *p,
					  const char *m)
{
  size_t i;
  register CLIENT *cl;

  if (!strpbrk (m, "*?"))
  {
    if ((cl = ircd_find_client (m, p)) == NULL)
      return (cl);
    if (CLIENT_IS_SERVER(cl))
      return (cl->via != p) ? cl : NULL;
    return (cl->cs);
  }
  for (i = 1; i < ircd->s; i++)
    if ((cl = ircd->token[i]) &&
	cl->via != p && simple_match_ic (m, cl->nick) >= 0)
      return cl;
  return NULL;
}

static void (*_ircd_list_receiver_show) (INTERFACE *, char *);

static int _ircd_qlist_r (INTERFACE *tmp, REQUEST *r)
{
  void (*f)(INTERFACE *, char *) = _ircd_list_receiver_show;

  if (r)
  {
    if (tmp->qsize)			/* do recursion to consume queue */
      Get_Request();
    { /* brackets just for variables */
      char *c = r->string;
      while (*c)
      {
	char *cnext = gettoken (c, NULL);
	f (tmp, c);
	c = cnext;
      }
    }
  }
  return REQ_OK;
}


/* ---------------------------------------------------------------------------
 * Client protocol bindings.
 */

int ircd_names_reply (CLIENT *me, CLIENT *cl, CHANNEL *ch, int done)
{
  MEMBER *cm = ch->users, *here;
  size_t p, s, x;
  char buf[IRCMSGLEN-24]; /* :myname INUM xxxxxx 353 Nick = #chan :@some */

  if (ch->mode & (A_QUIET | A_ANONYMOUS)) /* no listing */
    return done;
  if (!(here = _ircd_is_on_channel (cl, ch)) &&
      (ch->mode & A_SECRET))		/* hidden for outsiders */
    return done;
  x = sizeof(buf) - strlen (me->nick) - strlen (cl->nick);
  p = snprintf (buf, sizeof(buf), "%c %s :",
		(ch->mode & A_SECRET) ? '@' :
			(cm->chan->mode & A_PRIVATE) ? '*' : '=',
		cm->chan->name);
  s = 0;
  do {
    if (!here && (cm->who->umode & A_INVISIBLE))
      continue;
    if (p + s + strlen (cm->who->nick) > x)
    {
      buf[p+s] = '\0';
      ircd_do_cnumeric (cl, RPL_NAMREPLY, ch, 0, buf);
      if (done >= 0 && ++done >= _ircd_max_matches)
      {
	ircd_do_unumeric (cl, ERR_TOOMANYMATCHES, cl, 0, ch->name);
	return done;
      }
      s = 0;
    }
    if (cm->mode & A_ADMIN) {
      buf[p+s] = '@';
      s++;
    } else
      s += strlen(ircd_mode2whochar (cm->mode, &buf[p+s], sizeof(buf)-p-s));
    s += snprintf (&buf[p+s], x - p - s, "%s ", cm->who->nick);
  } while ((cm = cm->prevnick));
  if (s)
  {
    ircd_do_cnumeric (cl, RPL_NAMREPLY, ch, 0, buf);
    if (done >= 0)
      done++;
  }
  return done;
}

static int _ircd_names_reply_all (IRCD *ircd, CLIENT *me, CLIENT *cl, int i)
{
  LEAF *l = NULL;
  CHANNEL *ch;
  CLIENT *tgt;
  MEMBER *mm;
  size_t s, x;
  char buf[IRCMSGLEN-24]; /* :myname INUM xxxxxx 353 Nick = * :some */

  /* list all visible channel members */
  while ((l = Next_Leaf (ircd->channels, l, NULL)))
  {
    ch = l->s.data;
    if (ch->users)
      i = ircd_names_reply (me, cl, ch, i);
    if (i >= _ircd_max_matches)
      return ircd_do_unumeric (cl, RPL_ENDOFNAMES, cl, 0, "*");
  }
  /* list all visible users not on visible channels */
  x = sizeof(buf) - strlen (me->nick) - strlen (cl->nick);
  strfcpy (buf, "= * :", sizeof(buf));
  s = 5;
  while ((l = Next_Leaf (ircd->clients, l, NULL)))
  {
    tgt = l->s.data;
    if (tgt->umode & (A_INVISIBLE | A_SERVICE | A_SERVER)) /* skip */
      continue;
    for (mm = tgt->c.hannels; mm; mm = mm->prevchan)
    {
      if (mm->chan->mode & (A_QUIET | A_ANONYMOUS)) /* no listing */
	continue;
      if (_ircd_is_on_channel (cl, mm->chan) || /* on the same channel or */
	  !(mm->chan->mode & (A_PRIVATE | A_SECRET))) /* visible for outsiders */
	break;
    }
    if (!mm)
    {
      if (s + strlen (tgt->nick) > x)
      {
	ircd_do_unumeric (cl, RPL_NAMREPLY, cl, 0, buf);
	if (i >= 0 && ++i >= _ircd_max_matches)
	{
	  ircd_do_unumeric (cl, ERR_TOOMANYMATCHES, cl, 0, "*");
	  return ircd_do_unumeric (cl, RPL_ENDOFNAMES, cl, 0, "*");
	}
	s = 5;
      }
      s += snprintf (&buf[s], x - s, "%s ", tgt->nick);
    }
  }
  if (s > 5)
    ircd_do_unumeric (cl, RPL_NAMREPLY, cl, 0, buf);
  return ircd_do_unumeric (cl, RPL_ENDOFNAMES, cl, 0, "*");
}

static inline int _ircd_query_names (IRCD *ircd, CLIENT *cl, struct peer_priv *via,
				     int argc, const char **argv)
{ /* args: [<channel>[,<channel> ...] [<target>]] */
  CLIENT *me;
  register MEMBER *cm;
  char *c, *cnext;
  int done = 0;

  if (argc > 1)
  {
    me = _ircd_find_by_mask (ircd, via, argv[1]);
    if (!me)
      return ircd_do_unumeric (cl, ERR_NOSUCHSERVER, cl, 0, argv[1]);
    if (CLIENT_IS_ME(me) || !CLIENT_IS_SERVER(me))
      return _ircd_query_names (ircd, cl, via, 1, argv);
    New_Request (me->via->p.iface, 0, ":%s NAMES %s %s", cl->nick, argv[0],
		 me->nick);
    return 1;
  }
  me = ircd_find_client (NULL, NULL);
  if (argc == 0)			/* NAMES "*" */
    return _ircd_names_reply_all (ircd, me, cl, done);
  c = (char *)argv[0];
  do {
    if ((cnext = strchr (c, ',')))
      *cnext++ = 0;
    if ((cm = ircd_find_member (ircd, c, NULL)) != NOSUCHCHANNEL)
      done = ircd_names_reply (me, cl, cm->chan, done);
    ircd_do_unumeric (cl, RPL_ENDOFNAMES, cl, 0, c);
  } while ((c = cnext) && (done < _ircd_max_matches));
  return 1;
}

/* works with unified BINDING_TYPE_ircd_client_cmd parameters */
//TODO: check and forbid services to query
#define DO_CLIENT_QUERY(F) \
  return F ((IRCD *)srv->data, ((struct peer_priv *)peer->iface->data)->link->cl, \
	    peer->iface->data, argc, argv)

BINDING_TYPE_ircd_client_cmd(ircd_names_cb);
static int ircd_names_cb(INTERFACE *srv, struct peer_t *peer, const char *lcnick,
			 const char *user, const char *host, const char *vhost,
			 modeflag eum, int argc, const char **argv)
{
  DO_CLIENT_QUERY (_ircd_query_names);
}

/* works with unified BINDING_TYPE_ircd_server_cmd parameters */
//TODO: check and forbid services to query
#define DO_SERVER_QUERY(F) \
  register CLIENT *cl; \
  if (peer == NULL) \
  { \
    ERROR ("ircd:%s: Invalid internal query", __FUNCTION__); \
    return 0; \
  } \
  cl = _ircd_find_client_lc ((IRCD *)srv->data, lcsender); \
  if (cl == NULL || CLIENT_IS_SERVER(cl) || !CLIENT_IS_REMOTE(cl)) \
  { \
    ERROR ("ircd:Invalid query source %s from %s", sender, peer->dname); \
    return ircd_recover_done (peer->iface->data, "Invalid query source"); \
  } \
  return F ((IRCD *)srv->data, cl, peer->iface->data, argc, argv)

/* the same but for PING and PONG as servers can send them too */
#define DO_SERVER2_QUERY(F) \
  register CLIENT *cl; \
  if (peer == NULL) \
  { \
    ERROR ("ircd:%s: Invalid internal query", __FUNCTION__); \
    return 0; \
  } \
  cl = _ircd_find_client_lc ((IRCD *)srv->data, lcsender); \
  if (cl == NULL || cl->hold_upto != 0) \
  { \
    ERROR ("ircd:Invalid query source %s from %s", sender, peer->dname); \
    return ircd_recover_done (peer->iface->data, "Invalid query source"); \
  } \
  return F ((IRCD *)srv->data, cl, peer->iface->data, argc, argv)

BINDING_TYPE_ircd_server_cmd(ircd_names_sb);
static int ircd_names_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			 const char *sender, const char *lcsender,
			 int argc, const char **argv)
{
  DO_SERVER_QUERY (_ircd_query_names);
}

static inline void _ircd_list_reply (CLIENT *cl, CHANNEL *ch)
{
  if (!ch->users) /* on hold */
    return;
  if ((ch->mode & A_SECRET) && !_ircd_is_on_channel (cl, ch)) /* hidden for outsiders */
    return;
  ircd_do_cnumeric (cl, RPL_LIST, ch, (ch->mode & A_ANONYMOUS) ? 0 : ch->count,
		    ch->topic);
}

static inline int _ircd_query_list (IRCD *ircd, CLIENT *cl, struct peer_priv *via,
				    int argc, const char **argv)
{ /* args: [<channel>[,<channel> ...] [<target>]] */
  CLIENT *me;
  register MEMBER *cm;
  char *c, *cnext;
  int done = 0;

  if (argc > 1)
  {
    me = _ircd_find_by_mask (ircd, via, argv[1]);
    if (!me)
      return ircd_do_unumeric (cl, ERR_NOSUCHSERVER, cl, 0, argv[1]);
    if (CLIENT_IS_ME(me) || !CLIENT_IS_SERVER(me))
      return _ircd_query_list (ircd, cl, via, 1, argv);
    New_Request (me->via->p.iface, 0, ":%s LIST %s %s", cl->nick, argv[0],
		 me->nick);
    return 1;
  }
//  me = ircd_find_client (NULL, NULL);
  ircd_do_unumeric (cl, RPL_LISTSTART, cl, 0, NULL);
  if (argc == 0)			/* LIST "*" */
  {
    LEAF *l = NULL;

    while ((l = Next_Leaf (ircd->channels, l, NULL)))
      if (!(((CHANNEL *)l->s.data)->mode & A_PRIVATE)) /* hidden for listing */
      {
	_ircd_list_reply (cl, l->s.data);
	if (++done >= _ircd_max_matches)
	{
	  ircd_do_unumeric (cl, ERR_TOOMANYMATCHES, cl, 0, "*");
	  break;
	}
      }
    return ircd_do_unumeric (cl, RPL_LISTEND, cl, 0, NULL);
  }
  c = (char *)argv[0];
  do {
    if ((cnext = strchr (c, ',')))
      *cnext++ = 0;
    if ((cm = ircd_find_member (ircd, c, NULL)) != NOSUCHCHANNEL)
      _ircd_list_reply (cl, cm->chan);
  } while ((c = cnext));
  return ircd_do_unumeric (cl, RPL_LISTEND, cl, 0, NULL);
}

BINDING_TYPE_ircd_client_cmd(ircd_list_cb);
static int ircd_list_cb(INTERFACE *srv, struct peer_t *peer, const char *lcnick,
			const char *user, const char *host, const char *vhost,
			modeflag eum, int argc, const char **argv)
{
  DO_CLIENT_QUERY (_ircd_query_list);
}

BINDING_TYPE_ircd_server_cmd(ircd_list_sb);
static int ircd_list_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			const char *sender, const char *lcsender,
			int argc, const char **argv)
{
  DO_SERVER_QUERY (_ircd_query_list);
}

static char *IrcdMotd = NULL;
static size_t IrcdMotdSize = 0;
static time_t IrcdMotdTime = 0;
static char IrcdMotdTimeStr[64];

static size_t _ircd_check_motd (void)
{
  int fd;
  size_t i;
  struct stat st;
  struct tm tm;

  if (stat(_ircd_motd_file, &st) < 0) {
    /* we are in main chain now so strerror() should be safe */
    dprint(3, "ircd: cannot stat MOTD file: %s", strerror(errno));
    return 0;
  }
  if (IrcdMotdTime == st.st_mtime)
    return IrcdMotdSize;
  IrcdMotdTime = st.st_mtime;
  if (st.st_size > MOTDMAXSIZE)		/* it should be reasonable */
  {
    FREE (&IrcdMotd);
    IrcdMotdSize = 0;
    return 0;
  }
  fd = open (_ircd_motd_file, O_RDONLY);
  if (fd < 0)				/* no access, keep old */
    return IrcdMotdSize;
  safe_realloc ((void **)&IrcdMotd, st.st_size + 1);
  IrcdMotdSize = read (fd, IrcdMotd, st.st_size);
  close (fd);
  localtime_r (&IrcdMotdTime, &tm);
  strftime (IrcdMotdTimeStr, sizeof(IrcdMotdTimeStr), "%c", &tm);
  /* TODO: support charset definition as ##$charset <name> in first line ? */
  for (i = 0; i < IrcdMotdSize; i++)
  {
    if (IrcdMotd[i] == '\r')
    {
      if (i < IrcdMotdSize - 1 && IrcdMotd[i+1] == '\n')
	IrcdMotd[i] = ' ';
      else
	IrcdMotd[i] = '\0';
    }
    else if (IrcdMotd[i] == '\n')
      IrcdMotd[i] = '\0';
  }
  IrcdMotd[IrcdMotdSize] = '\0';
  return IrcdMotdSize;
}

static inline int _ircd_query_motd (IRCD *ircd, CLIENT *cl, struct peer_priv *via,
				    int argc, const char **argv)
{ /* args: [<target>] */
  size_t ptr, got;

  if (argc > 0)
  {
    register CLIENT *tgt = _ircd_find_by_mask (ircd, via, argv[0]);

    if (!tgt)
      return ircd_do_unumeric (cl, ERR_NOSUCHSERVER, cl, 0, argv[0]);
    if (CLIENT_IS_ME(tgt) || !CLIENT_IS_SERVER(tgt))
      return _ircd_query_motd (ircd, cl, via, 0, argv);
    New_Request (tgt->via->p.iface, 0, ":%s MOTD :%s", cl->nick, tgt->nick);
    return 1;
  }
  got = _ircd_check_motd();
  if (got == 0)
    return ircd_do_unumeric (cl, ERR_NOMOTD, cl, 0, NULL);
  ptr = 0;
  ircd_do_unumeric (cl, RPL_MOTDSTART, cl, 0, NULL);
  ircd_do_unumeric (cl, RPL_MOTD, cl, 0, IrcdMotdTimeStr);
  while (ptr < got)
  {
    ircd_do_unumeric (cl, RPL_MOTD, cl, 0, &IrcdMotd[ptr]);
    ptr += (strlen (&IrcdMotd[ptr]) + 1);
  }
  return ircd_do_unumeric (cl, RPL_ENDOFMOTD, cl, 0, NULL);
}

BINDING_TYPE_ircd_client_cmd(ircd_motd_cb);
static int ircd_motd_cb(INTERFACE *srv, struct peer_t *peer, const char *lcnick,
			const char *user, const char *host, const char *vhost,
			modeflag eum, int argc, const char **argv)
{
  DO_CLIENT_QUERY (_ircd_query_motd);
}

BINDING_TYPE_ircd_server_cmd(ircd_motd_sb);
static int ircd_motd_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			const char *sender, const char *lcsender,
			int argc, const char **argv)
{
  DO_SERVER_QUERY (_ircd_query_motd);
}

static inline int _ircd_query_lusers (IRCD *ircd, CLIENT *cl, struct peer_priv *via,
				      int argc, const char **argv)
{ /* args: [<mask>[ <target>]] */
  const char *smask;
  LINK *l;
  LEAF *leaf;
  int lu = 0, ls = 0, ll = 0, gu = 0, gs = 0, gl = 0, op = 0, x = 0, i = 0;
  char buff[STRING];

  if (argc > 1)
  {
    register CLIENT *tgt = _ircd_find_by_mask (ircd, via, argv[1]);

    if (!tgt)
      return ircd_do_unumeric (cl, ERR_NOSUCHSERVER, cl, 0, argv[1]);
    if (CLIENT_IS_ME(tgt) || !CLIENT_IS_SERVER(tgt))
      return _ircd_query_lusers (ircd, cl, via, 1, argv);
    New_Request (tgt->via->p.iface, 0, ":%s LUSERS %s :%s", cl->nick, argv[0],
		 tgt->nick);
    return 1;
  }
  if (argc == 0)
    smask = "*";
  else
    smask = argv[0];
#define COUNT_USERS(A,B,C,D) \
  for (l = A; l; l = l->prev) \
    COUNT_USERS_CHECK_STATE \
    COUNT_USERS_CHECK_PATH \
    if (CLIENT_IS_SERVER(l->cl)) D++; \
    else if (CLIENT_IS_SERVICE(l->cl)) C++; \
    else if (l->cl->umode & (A_OP | A_HALFOP)) op++; \
    else B++
#define COUNT_USERS_CHECK_STATE if (l->cl->via->p.state != P_TALK) continue; else
#define COUNT_USERS_CHECK_PATH 
  COUNT_USERS (ircd->token[0]->c.lients, lu, ls, ll);
#undef COUNT_USERS_CHECK_STATE
#undef COUNT_USERS_CHECK_PATH
  /* recheck counters */
  if (ircd->token[0]->x.a.uc != (unsigned)(lu + op))
  {
    ERROR("ircd:/lusers: local users count mismatch on recount: %u != %d, fixing it",
	  ircd->token[0]->x.a.uc, lu + op);
    ircd->token[0]->x.a.uc = lu + op;
  }
  if (ll != 0)
  {
    ERROR("ircd:/lusers: found servers in clients on ME: %u != 0", ll);
    ll = 0;
  }
  for (l = ircd->servers; l; l = l->prev)
    if (CLIENT_IS_SERVER(l->cl))
      ll++;
    else
      ERROR("ircd:/lusers: client %s in local servers list isn't a server",
	    l->cl->nick);
  if (simple_match_ic (smask, ircd->token[0]->nick) >= 0)
    gu = lu, gs = ls, gl = ll, lu += op, x = 1;
  else
    op = 0;
  ll = 0;
  for (i = 1; i < ircd->s; i++)
    if (ircd->token[i] && simple_match_ic (smask, ircd->token[i]->nick) >= 0)
    {
      unsigned int su = 0, op_save = op;
      if (!CLIENT_IS_SERVER(ircd->token[i]))
      {
	ERROR("ircd:token %d isn't a server but %s!!!", i, ircd->token[i]->nick);
	ircd->token[i] = NULL;
	continue;
      }
#define COUNT_USERS_CHECK_STATE 
#if IRCD_MULTICONNECT
# define COUNT_USERS_CHECK_PATH if (l->cl->via != NULL && l->cl->via != ircd->token[i]->via) continue; else
#else
# define COUNT_USERS_CHECK_PATH 
#endif
      COUNT_USERS (ircd->token[i]->c.lients, su, gs, gl);
#undef COUNT_USERS_CHECK_STATE
#undef COUNT_USERS_CHECK_PATH
      if (CLIENT_IS_LOCAL(ircd->token[i]))
	ll++;
      x++;
      gu += su;
      if (ircd->token[i]->x.a.uc != (su + op - op_save))
      {
	ERROR("ircd:/lusers: users count on %s mismatch on recount: %u != %u, fixing it",
	      ircd->token[i]->nick, ircd->token[i]->x.a.uc, su + op - op_save);
	ircd->token[i]->x.a.uc = su + op - op_save;
      }
    }
#undef COUNT_USERS
  snprintf (buff, sizeof(buff), "There are %d users and %d services on %d servers",
	    gu + op, gs, x);
  ircd_do_unumeric (cl, RPL_LUSERCLIENT, cl, 0, buff);
  if (op)
    ircd_do_unumeric (cl, RPL_LUSEROP, cl, op, NULL);
  i = ircd_lusers_unknown();
  if (i > 0)
    ircd_do_unumeric (cl, RPL_LUSERUNKNOWN, cl, (unsigned short)i, NULL);
  i = 0;
  leaf = NULL;
  while ((leaf = Next_Leaf (ircd->channels, leaf, NULL)))
    i++;
  if (i > 0)
    ircd_do_unumeric (cl, RPL_LUSERCHANNELS, cl, (unsigned short)i, NULL);
  snprintf (buff, sizeof(buff), "I have %d clients and %d servers", lu, ll);
  ircd_do_unumeric (cl, RPL_LUSERME, cl, 0, buff);
  if (argc > 0)
    return 1;
  snprintf (buff, sizeof(buff), "%u", ircd->lu);
  ircd_do_unumeric (cl, RPL_LOCALUSERS, cl, (unsigned short)lu, buff);
  snprintf (buff, sizeof(buff), "%u", ircd->gu);
  return ircd_do_unumeric (cl, RPL_GLOBALUSERS, cl, (unsigned short)(gu + op), buff);
}

BINDING_TYPE_ircd_client_cmd(ircd_lusers_cb);
static int ircd_lusers_cb(INTERFACE *srv, struct peer_t *peer, const char *lcnick,
			  const char *user, const char *host, const char *vhost,
			  modeflag eum, int argc, const char **argv)
{
  DO_CLIENT_QUERY (_ircd_query_lusers);
}

BINDING_TYPE_ircd_server_cmd(ircd_lusers_sb);
static int ircd_lusers_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			  const char *sender, const char *lcsender,
			  int argc, const char **argv)
{
  DO_SERVER_QUERY (_ircd_query_lusers);
}

const char *ircd_version_flags =
#ifdef ALLOW_NOOP_CHANMGMT
"A"
#endif
#ifdef IRCD_ENABLE_REHASH
"E"
#endif
#if IRCD_USES_ICONV
"i"
#endif
#ifdef IRCD_ENABLE_DIE
"J"
#endif
#ifdef IRCD_ENABLE_KILL
"K"
#endif
#if IRCD_MULTICONNECT
"o"
#endif
#if COLLISION_RESOLVING
"O"
#endif
#ifdef IRCD_ENABLE_RESTART
"R"
#endif
#ifdef USE_SERVICES
"s"
#endif
#ifdef IRCD_ENABLE_SUMMON
"S"
#endif
#ifdef TOPICWHOTIME
"T"
#endif
#ifdef IRCD_ENABLE_USERS
"U"
#endif
#ifdef SEND_WHOIS_NOTICE
"W"
#endif
#ifdef ENABLE_IPV6
"6"
#endif
#if ! IRCD_STRICT_NAMES
"8"
#endif
;

static inline int _ircd_query_version (IRCD *ircd, CLIENT *cl, struct peer_priv *via,
				       int argc, const char **argv)
{ /* args: [<target>] */
  if (argc > 0)
  {
    register CLIENT *tgt = _ircd_find_by_mask (ircd, via, argv[0]);

    if (!tgt)
      return ircd_do_unumeric (cl, ERR_NOSUCHSERVER, cl, 0, argv[0]);
    if (CLIENT_IS_ME(tgt) || !CLIENT_IS_SERVER(tgt))
      return _ircd_query_version (ircd, cl, via, 0, argv);
    New_Request (tgt->via->p.iface, 0, ":%s VERSION %s", cl->nick, tgt->nick);
    return 1;
  }
  return ircd_do_unumeric (cl, RPL_VERSION, cl, O_DLEVEL, ircd_version_flags);
}

BINDING_TYPE_ircd_client_cmd(ircd_version_cb);
static int ircd_version_cb(INTERFACE *srv, struct peer_t *peer, const char *lcnick,
			   const char *user, const char *host, const char *vhost,
			   modeflag eum, int argc, const char **argv)
{
  DO_CLIENT_QUERY (_ircd_query_version);
}

BINDING_TYPE_ircd_server_cmd(ircd_version_sb);
static int ircd_version_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			   const char *sender, const char *lcsender,
			   int argc, const char **argv)
{
  DO_SERVER_QUERY (_ircd_query_version);
}

static CLIENT *_ircd_stats_client;

static inline int _ircd_query_stats (IRCD *ircd, CLIENT *cl, struct peer_priv *via,
				     int argc, const char **argv)
{ /* [<query>[ <target>]] */
  struct binding_t *b;

  if (argc > 0)
  {
    if (argc > 1)
    {
      register CLIENT *tgt = _ircd_find_by_mask (ircd, via, argv[1]);

      if (!tgt)
	return ircd_do_unumeric (cl, ERR_NOSUCHSERVER, cl, 0, argv[1]);
      if (CLIENT_IS_ME(tgt) || !CLIENT_IS_SERVER(tgt))
	return _ircd_query_stats (ircd, cl, via, 1, argv);
      New_Request (tgt->via->p.iface, 0, ":%s STATS %s %s", cl->nick, argv[0],
		   tgt->nick);
      return 1;
    }
    _ircd_stats_client = cl;		/* used by bindings below */
    b = Check_Bindtable (BTIrcdStatsReply, argv[0], 0, 0, NULL);
    if (b && !b->name)
      b->func (ircd->iface, cl->nick, cl->umode);
  }
  return ircd_do_unumeric (cl, RPL_ENDOFSTATS, cl, 0, argv[0]);
}

BINDING_TYPE_ircd_client_cmd(ircd_stats_cb);
static int ircd_stats_cb(INTERFACE *srv, struct peer_t *peer, const char *lcnick,
			 const char *user, const char *host, const char *vhost,
			 modeflag eum, int argc, const char **argv)
{
  DO_CLIENT_QUERY (_ircd_query_stats);
}

BINDING_TYPE_ircd_server_cmd(ircd_stats_sb);
static int ircd_stats_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			 const char *sender, const char *lcsender,
			 int argc, const char **argv)
{
  DO_SERVER_QUERY (_ircd_query_stats);
}

static void _ircd_tell_links(CLIENT *cl, CLIENT *server, char *where,
			     const char *smask, struct peer_priv *via)
{
  LINK *tgt;

  ircd_do_unumeric (cl, RPL_LINKS, server, server->hops, where);
  for (tgt = server->c.lients; tgt; tgt = tgt->prev)
    if (CLIENT_IS_SERVER(tgt->cl) &&
#if IRCD_MULTICONNECT
	(tgt->cl->pcl == server) && /* ignore backlink */
#endif
	simple_match_ic (smask, tgt->cl->nick) >= 0)
      _ircd_tell_links(cl, tgt->cl, server->nick, smask, via);
}

static inline int _ircd_query_links (IRCD *ircd, CLIENT *cl, struct peer_priv *via,
				     int argc, const char **argv)
{ /* [[<remote server> ]<server mask>] */
  const char *smask;
  LINK *tgt;
  register CLIENT *s;

  if (argc > 1)
  {
    s = _ircd_find_by_mask (ircd, via, argv[0]);
    if (!s)
      return ircd_do_unumeric (cl, ERR_NOSUCHSERVER, cl, 0, argv[0]);
    if (CLIENT_IS_ME(s) || !CLIENT_IS_SERVER(s))
      return _ircd_query_links (ircd, cl, via, 1, &argv[1]);
    New_Request (s->via->p.iface, 0, ":%s LINKS %s :%s", cl->nick, s->nick,
		 argv[1]);
    return 1;
  }
  if (argc == 0)
    smask = "*";
  else
    smask = argv[0];
  s = ircd->token[0]; /* ME */
  ircd_do_unumeric (cl, RPL_LINKS, s, 0, s->nick);
  for (tgt = ircd->servers; tgt; tgt = tgt->prev)
    if (simple_match_ic (smask, tgt->cl->nick) >= 0)
      _ircd_tell_links(cl, tgt->cl, tgt->where->nick, smask, tgt->cl->via);
  return ircd_do_unumeric (cl, RPL_ENDOFLINKS, cl, 0, smask);
}

BINDING_TYPE_ircd_client_cmd(ircd_links_cb);
static int ircd_links_cb(INTERFACE *srv, struct peer_t *peer, const char *lcnick,
			 const char *user, const char *host, const char *vhost,
			 modeflag eum, int argc, const char **argv)
{
  DO_CLIENT_QUERY (_ircd_query_links);
}

BINDING_TYPE_ircd_server_cmd(ircd_links_sb);
static int ircd_links_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			 const char *sender, const char *lcsender,
			 int argc, const char **argv)
{
  DO_SERVER_QUERY (_ircd_query_links);
}

static inline int _ircd_query_time (IRCD *ircd, CLIENT *cl, struct peer_priv *via,
				    int argc, const char **argv)
{ /* args : [<target>] */
  struct tm tm;
  char timestr[SHORT_STRING];

  if (argc > 0)
  {
    register CLIENT *tgt = _ircd_find_by_mask (ircd, via, argv[0]);

    if (!tgt)
      return ircd_do_unumeric (cl, ERR_NOSUCHSERVER, cl, 0, argv[0]);
    if (CLIENT_IS_ME(tgt) || !CLIENT_IS_SERVER(tgt))
      return _ircd_query_time (ircd, cl, via, 0, argv);
    New_Request (tgt->via->p.iface, 0, ":%s TIME %s", cl->nick, tgt->nick);
    return 1;
  }
  localtime_r (&Time, &tm);
  strftime (timestr, sizeof(timestr), "%c", &tm);
  return ircd_do_unumeric (cl, RPL_TIME, cl, 0, timestr);
}

BINDING_TYPE_ircd_client_cmd(ircd_time_cb);
static int ircd_time_cb(INTERFACE *srv, struct peer_t *peer, const char *lcnick,
			const char *user, const char *host, const char *vhost,
			modeflag eum, int argc, const char **argv)
{
  DO_CLIENT_QUERY (_ircd_query_time);
}

BINDING_TYPE_ircd_server_cmd(ircd_time_sb);
static int ircd_time_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			const char *sender, const char *lcsender,
			int argc, const char **argv)
{
  DO_SERVER_QUERY (_ircd_query_time);
}

static inline int _ircd_query_connect (IRCD *ircd, CLIENT *cl, struct peer_priv *via,
				       int argc, const char **argv)
{ /* args: <target server> <port> [<remote server>] */
  if (argc < 2)
    return ircd_do_unumeric (cl, ERR_NEEDMOREPARAMS, cl, 0, "CONNECT");
  if (argc > 2)
  {
    register CLIENT *tgt = _ircd_find_by_mask (ircd, via, argv[2]);

    if (!tgt)
      return ircd_do_unumeric (cl, ERR_NOSUCHSERVER, cl, 0, argv[2]);
    if (CLIENT_IS_ME(tgt) || !CLIENT_IS_SERVER(tgt))
      return _ircd_query_connect (ircd, cl, via, 2, argv);
    if (!(cl->umode & A_OP))
      return ircd_do_unumeric (cl, ERR_NOPRIVILEGES, cl, 0, NULL);
    New_Request (tgt->via->p.iface, 0, ":%s CONNECT %s %s :%s", cl->nick,
		 argv[0], argv[1], tgt->nick);
    return 1;
  }
  if (!(cl->umode & (A_OP | A_HALFOP)))
    return ircd_do_unumeric (cl, ERR_NOPRIVILEGES, cl, 0, NULL);
  return ircd_try_connect (cl, argv[0], argv[1]);
}

BINDING_TYPE_ircd_client_cmd(ircd_connect_cb);
static int ircd_connect_cb(INTERFACE *srv, struct peer_t *peer, const char *lcnick,
			   const char *user, const char *host, const char *vhost,
			   modeflag eum, int argc, const char **argv)
{
  DO_CLIENT_QUERY (_ircd_query_connect);
}

BINDING_TYPE_ircd_server_cmd(ircd_connect_sb);
static int ircd_connect_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			   const char *sender, const char *lcsender,
			   int argc, const char **argv)
{
  DO_SERVER_QUERY (_ircd_query_connect);
}

static inline int _ircd_query_trace (IRCD *ircd, CLIENT *cl, struct peer_priv *via,
				     int argc, const char **argv)
{ /* args: [<target>] */
  if (argc > 0)				/* transit trace */
  {
    CLIENT *tgt = ircd_find_client (argv[0], via), *next;
    size_t p;
    char flags[8];
    char tstr[IRCMSGLEN];

    if (!tgt)
      tgt = _ircd_find_by_mask (ircd, via, argv[0]);
    if (!tgt)				/* no target found */
      return ircd_do_unumeric (cl, ERR_NOSUCHSERVER, cl, 0, argv[0]);
    if (CLIENT_IS_ME(tgt))
      return _ircd_query_trace (ircd, cl, via, 0, argv);
    if (!CLIENT_IS_SERVER(tgt) && CLIENT_IS_LOCAL(tgt)) /* local client here */
    {
      ircd_show_trace (cl, tgt);
      return ircd_do_unumeric (cl, RPL_TRACEEND, cl, O_DLEVEL, NULL);
    }
    next = tgt->cs->via->link->cl;
    p = 0;
    if (next->umode & A_UPLINK)
      flags[p++] = 'c';
#if IRCD_MULTICONNECT
    if (next->umode & A_MULTI)
      flags[p++] = 'm';
#endif
#if IRCD_USES_ICONV
    if (!strcasecmp(Conversion_Charset(tgt->cs->via->p.iface->conv),
		    CHARSET_UNICODE))
      flags[p++] = 'u';
#endif
    /* special support for Zlib connection */
    if (Connchain_Check(&tgt->cs->via->p, 'Z') < 0)
      flags[p++] = 'z';
    flags[p] = '\0';
    snprintf (tstr, sizeof(tstr), "%s V%c%s %d %d %d", next->nick, next->away[3],
	      flags, (int)(Time - tgt->cs->via->started), via->p.iface->qsize,
	      tgt->cs->via->p.iface->qsize);
    ircd_do_unumeric (cl, RPL_TRACELINK, tgt, O_DLEVEL, tstr);
    New_Request (tgt->cs->via->p.iface, 0, ":%s TRACE :%s", cl->nick, argv[0]);
    return 1;
  }
  ircd_show_trace (cl, NULL); //FIXME: don't show my links to remote?
  return ircd_do_unumeric (cl, RPL_TRACEEND, cl, O_DLEVEL, NULL);
}

BINDING_TYPE_ircd_client_cmd(ircd_trace_cb);
static int ircd_trace_cb(INTERFACE *srv, struct peer_t *peer, const char *lcnick,
			 const char *user, const char *host, const char *vhost,
			 modeflag eum, int argc, const char **argv)
{
  DO_CLIENT_QUERY (_ircd_query_trace);
}

BINDING_TYPE_ircd_server_cmd(ircd_trace_sb);
static int ircd_trace_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			 const char *sender, const char *lcsender,
			 int argc, const char **argv)
{
  DO_SERVER_QUERY (_ircd_query_trace);
}

static inline int _ircd_query_admin (IRCD *ircd, CLIENT *cl, struct peer_priv *via,
				     int argc, const char **argv)
{ /* args: [<target>] */
  if (argc > 0)
  {
    CLIENT *tgt = _ircd_find_by_mask (ircd, via, argv[0]);

    if (!tgt)				/* no target found */
      return ircd_do_unumeric (cl, ERR_NOSUCHSERVER, cl, 0, argv[0]);
    if (CLIENT_IS_ME(tgt) || !CLIENT_IS_SERVER(tgt))
      return _ircd_query_admin (ircd, cl, via, 0, argv);
    New_Request (tgt->cs->via->p.iface, 0, ":%s ADMIN %s", cl->nick, tgt->nick);
    return 1;
  }
  ircd_do_unumeric (cl, RPL_ADMINME, ircd_find_client(NULL, NULL), 0, NULL);
  ircd_do_unumeric (cl, RPL_ADMINLOC1, cl, 0, _ircd_description_string);
  ircd_do_unumeric (cl, RPL_ADMINLOC2, cl, 0, _ircd_admin_info);
  return ircd_do_unumeric (cl, RPL_ADMINEMAIL, cl, 0, _ircd_admin_email);
}

BINDING_TYPE_ircd_client_cmd(ircd_admin_cb);
static int ircd_admin_cb(INTERFACE *srv, struct peer_t *peer, const char *lcnick,
			 const char *user, const char *host, const char *vhost,
			 modeflag eum, int argc, const char **argv)
{
  DO_CLIENT_QUERY (_ircd_query_admin);
}

BINDING_TYPE_ircd_server_cmd(ircd_admin_sb);
static int ircd_admin_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			 const char *sender, const char *lcsender,
			 int argc, const char **argv)
{
  DO_SERVER_QUERY (_ircd_query_admin);
}

static time_t _ircd_time_started;

static inline int _ircd_query_info (IRCD *ircd, CLIENT *cl, struct peer_priv *via,
				    int argc, const char **argv)
{ /* args: [<target>] */
  struct tm tm;
  char buf[SHORT_STRING];

  if (argc > 0)
  {
    CLIENT *tgt = _ircd_find_by_mask (ircd, via, argv[0]);

    if (!tgt)				/* no target found */
      return ircd_do_unumeric (cl, ERR_NOSUCHSERVER, cl, 0, argv[0]);
    if (CLIENT_IS_ME(tgt) || !CLIENT_IS_SERVER(tgt))
      return _ircd_query_info (ircd, cl, via, 0, argv);
    New_Request (tgt->via->p.iface, 0, ":%s INFO %s", cl->nick, tgt->nick);
    return 1;
  }
  /* version, patchlevel, compilation time */
  ircd_do_unumeric (cl, RPL_INFO, cl, 0, "Module \"ircd\" of " PACKAGE " "
		    VERSION ".");
  ircd_do_unumeric (cl, RPL_INFO, cl, 0, "Designed in compliance with RFC2812"
		    " using few extensions to improve usability.");
  ircd_do_unumeric (cl, RPL_INFO, cl, 0, "Birth date: " COMPILETIME ".");
  /* other info */
  ircd_do_unumeric (cl, RPL_INFO, cl, 0, "Copyright 1999 - 2017 "
		    "Andriy Grytsenko and others.");
  ircd_do_unumeric (cl, RPL_INFO, cl, 0, "This program is free software;"
		    " you can redistribute it and/or modify it under the terms"
		    " of the GNU General Public License as published by the"
		    " Free Software Foundation; either version 2, or"
		    " (at your option) any later version.");
  /* starting time */
  localtime_r (&_ircd_time_started, &tm);
  strftime (buf, sizeof(buf), "Running since %c.", &tm);
  ircd_do_unumeric (cl, RPL_INFO, cl, 0, buf);
  return ircd_do_unumeric (cl, RPL_ENDOFINFO, cl, 0, NULL);
}

BINDING_TYPE_ircd_client_cmd(ircd_info_cb);
static int ircd_info_cb(INTERFACE *srv, struct peer_t *peer, const char *lcnick,
			const char *user, const char *host, const char *vhost,
			modeflag eum, int argc, const char **argv)
{
  DO_CLIENT_QUERY (_ircd_query_info);
}

BINDING_TYPE_ircd_server_cmd(ircd_info_sb);
static int ircd_info_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			const char *sender, const char *lcsender,
			int argc, const char **argv)
{
  DO_SERVER_QUERY (_ircd_query_info);
}

static void _ircd_do_whois (IRCD *ircd, CLIENT *cl, CLIENT *tgt, CLIENT *me)
{
  MEMBER *m;
  size_t ptr;
  char buf[IRCMSGLEN];
  register struct binding_t *b = NULL;
#define static register
  BINDING_TYPE_ircd_whois ((*f));
#undef static

  ircd_do_unumeric (cl, RPL_WHOISUSER, tgt, 0, tgt->fname);
  ptr = 0;
  for (m = tgt->c.hannels; m; m = m->prevchan)
  {
    if (cl != tgt && !(cl->umode & (A_OP | A_HALFOP)))
    {
      if (m->chan->mode & (A_ANONYMOUS | A_QUIET))
	continue;
      if (m->chan->mode & (A_PRIVATE | A_SECRET))
	if (!_ircd_is_on_channel (cl, m->chan))
	  continue;
    }
    if (ptr + strlen (m->chan->name) > sizeof(buf) - 3) /* reserved for " +" */
    {
      ircd_do_unumeric (cl, RPL_WHOISCHANNELS, tgt, 0, buf);
      ptr = 0;
    }
    if (ptr)
      buf[ptr++] = ' ';
    if (m->mode & A_ADMIN)
      buf[ptr++] = '@';
    else
      ptr += strlen(ircd_mode2whochar(m->mode, &buf[ptr], sizeof(buf) - ptr));
    ptr += strfcpy (&buf[ptr], m->chan->name, sizeof(buf) - ptr);
  }
  if (ptr)
    ircd_do_unumeric (cl, RPL_WHOISCHANNELS, tgt, 0, buf);
  if (!CLIENT_IS_REMOTE (tgt))
    ircd_do_unumeric (cl, RPL_WHOISSERVER, me, 0, tgt->nick);
  else
    ircd_do_unumeric (cl, RPL_WHOISSERVER, tgt->cs, 0, tgt->nick);
  if (tgt->umode & (A_OP | A_HALFOP))
  {
    ircd_do_unumeric (cl, RPL_WHOISOPERATOR, tgt, 0, NULL);
#ifdef SEND_WHOIS_NOTICE
    /* notify target about whois on them, unless it's on itself */
    if (tgt != cl)
      New_Request (tgt->cs->via->p.iface, 0,
		   ":%s NOTICE %s :WHOIS on YOU requested by %s (%s@%s) [%s]",
		   me->lcnick, tgt->nick, cl->nick, cl->user, cl->host,
		   CLIENT_IS_LOCAL(cl) ? me->lcnick : cl->cs->nick);
#endif
  }
  if (tgt->umode & A_AWAY) /* FIXME: make a message "Use /WHOIS %s %s" ? */
    ircd_do_unumeric (cl, RPL_AWAY, tgt, 0, tgt->away[0] ? tgt->away : "Gone");
#if IRCD_USES_ICONV
  if (!CLIENT_IS_REMOTE (tgt))
    ircd_do_unumeric (cl, RPL_WHOISCHARSET, tgt, 0,
		      Conversion_Charset (tgt->via->p.iface->conv));
#endif
  /* special support for SSL client connections */
  if (tgt->umode & A_SSL)
    ircd_do_unumeric (cl, RPL_WHOISSECURE, tgt, 0, NULL);
  while ((b = Check_Bindtable (BTIrcdWhois, tgt->nick, U_ALL, U_ANYCH, b)))
    if (b->name == NULL)
    {
      f = (void(*)())b->func;
      f(ircd->iface, cl->nick, cl->umode, tgt->nick, tgt->host, tgt->vhost, tgt->umode);
    }
  /* binding might send some message, deliver it to user before RPL_ENDOFWHOIS */
  Set_Iface(ircd->iface);
  while(Get_Request());
  Unset_Iface();
  /*  */
  if (!CLIENT_IS_REMOTE (tgt)) {
    //TODO: ifdef WHOIS_SIGNON_TIME => tgt->via->started
    snprintf (buf, sizeof(buf), "%u", (unsigned int)(Time - tgt->via->noidle));
    ircd_do_unumeric (cl, RPL_WHOISIDLE, tgt, 0, buf);
  }
}

static inline int _ircd_query_whois (IRCD *ircd, CLIENT *cl, struct peer_priv *via,
				     int argc, const char **argv)
{ /* args: [<target>] <mask>[,<mask>...] */
  CLIENT *tgt, *me = ircd_find_client(NULL, NULL);
  char *c, *cnext;
  int n;

  if (argc == 0)
    return ircd_do_unumeric (cl, ERR_NONICKNAMEGIVEN, cl, 0, NULL);
  if (argc > 1)
  {
    tgt = _ircd_find_by_mask (ircd, via, argv[0]);
    if (!tgt)				/* no target found */
      return ircd_do_unumeric (cl, ERR_NOSUCHSERVER, cl, 0, argv[0]);
    if (CLIENT_IS_ME(tgt) || !CLIENT_IS_SERVER(tgt))
      return _ircd_query_whois (ircd, cl, via, 1, &argv[1]);
    New_Request (tgt->via->p.iface, 0, ":%s WHOIS %s :%s", cl->nick,
		 tgt->nick, argv[1]);
    return 1;
  }
  n = 0;
  c = (char *)argv[0];
  while (c)
  {
    cnext = strchr (c, ',');
    if (cnext)
      *cnext = '\0';
    tgt = ircd_find_client (c, via);
    if (tgt && !CLIENT_IS_SERVER(tgt))
    {
      if (n++ >= _ircd_max_whois)
	ircd_do_unumeric (cl, ERR_TOOMANYTARGETS, tgt, 0, "Ignoring request.");
      else
	_ircd_do_whois (ircd, cl, tgt, me);
    }
    else if (strpbrk (c, "*?"))
    {
      if (!CLIENT_IS_REMOTE(cl))	/* cl cannot be ME */
      {
	NODE *t = ircd->clients;
	LEAF *l = NULL;

	while (n < _ircd_max_whois && (l = Next_Leaf (t, l, NULL)))
	{
	  tgt = l->s.data;
	  if ((tgt->umode & (A_SERVER | A_SERVICE)) | tgt->hold_upto)
	    continue;
	  if ((cl->umode & (A_OP | A_HALFOP)) || !(tgt->umode & A_INVISIBLE) ||
	      _ircd_is_on_the_same_channel (cl, tgt))
	    if (simple_match_ic (c, tgt->nick) >= 0)
	    {
	      _ircd_do_whois (ircd, cl, tgt, me);
	      n++;
	    }
	}
      }
      else				/* wildcards from remote are forbidden */
	ircd_do_unumeric (cl, ERR_TOOMANYMATCHES, cl, 0, c);
    }
    else
      ircd_do_unumeric (cl, ERR_NOSUCHNICK, cl, 0, c);
    if (cnext)
      *cnext++ = ',';
    c = cnext;
  }
  return ircd_do_unumeric (cl, RPL_ENDOFWHOIS, cl, 0, argv[0]);
}

BINDING_TYPE_ircd_client_cmd(ircd_whois_cb);
static int ircd_whois_cb(INTERFACE *srv, struct peer_t *peer, const char *lcnick,
			 const char *user, const char *host, const char *vhost,
			 modeflag eum, int argc, const char **argv)
{
  DO_CLIENT_QUERY (_ircd_query_whois);
}

BINDING_TYPE_ircd_server_cmd(ircd_whois_sb);
static int ircd_whois_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			 const char *sender, const char *lcsender,
			 int argc, const char **argv)
{
  DO_SERVER_QUERY (_ircd_query_whois);
}

typedef struct whowas_t {
  struct whowas_t *prev, *next;		/* two-side vectors in history of that nick */
  time_t wason;
  char nick[MB_LEN_MAX*NICKLEN+1];	/* registration nick */
  char lcnick[MB_LEN_MAX*NICKLEN+1];	/* nick (lower case) - for search */
  char fname[MB_LEN_MAX*REALNAMELEN+1];	/* full name */
  char user[IDENTLEN+1];		/* ident - from connection */
  char host[HOSTLEN+1];			/* host (lower case) */
  char fromsrv[HOSTLEN+1];		/* server name of user */
} whowas_t;

ALLOCATABLE_TYPE (whowas_t, WW_, next) /* alloc_whowas_t, free_whowas_t */

static NODE *IrcdWhowasTree = NULL;
static whowas_t **IrcdWhowasArray = NULL; /* array of whowas_t * */
static unsigned int IrcdWhowasSize = 0;
static unsigned int IrcdWhowasPtr = 0;

static inline int _ircd_query_whowas (IRCD *ircd, CLIENT *cl, struct peer_priv *via,
				      int argc, const char **argv)
{ /* args: <nickname>[,<nickname>...] [<count>[ <target>]] */
  CLIENT *tgt;
  char *c, *cnext;
  whowas_t *ww;
  int n, max;
  char targets[MESSAGEMAX];
  struct tm tmp;
  CLIENT dummy;

  if (argc == 0)
    return ircd_do_unumeric (cl, ERR_NONICKNAMEGIVEN, cl, 0, NULL);
  if (argc > 2)
  {
    tgt = _ircd_find_by_mask (ircd, via, argv[2]);
    if (!tgt)				/* no target found */
      return ircd_do_unumeric (cl, ERR_NOSUCHSERVER, cl, 0, argv[2]);
    if (CLIENT_IS_ME(tgt) || !CLIENT_IS_SERVER(tgt))
      return _ircd_query_whowas (ircd, cl, via, 2, argv);
    New_Request (tgt->via->p.iface, 0, ":%s WHOWAS %s %s %s", cl->nick,
		 argv[0], argv[1], tgt->nick);
    return 1;
  }
  if (argc < 2 || (max = atoi (argv[1])) < 0 || max > 2 * _ircd_max_whois)
    max = 2 * _ircd_max_whois;
  unistrlower (targets, argv[0], sizeof(targets));
  for (c = targets; c; c = cnext)
  {
    cnext = strchr (c, ',');
    if (cnext)
      *cnext++ = '\0';
    if (IrcdWhowasSize > 0)
      ww = Find_Key (IrcdWhowasTree, c);
    else
      ww = NULL;
    for (n = 0; ww && n < max; ww = ww->prev)
    {
      strfcpy (dummy.user, ww->user, sizeof(dummy.user));
      strfcpy (dummy.nick, ww->nick, sizeof(dummy.nick));
      strfcpy (dummy.vhost, ww->host, sizeof(dummy.vhost));
      dummy.via = NULL;
      dummy.umode = 0;
      ircd_do_unumeric (cl, RPL_WHOWASUSER, &dummy, 0, ww->fname);
      //TODO: whowas time!
      strfcpy (dummy.nick, ww->fromsrv, sizeof(dummy.nick));
      localtime_r(&ww->wason, &tmp);
      strftime(dummy.vhost, sizeof(dummy.vhost), "%c", &tmp);
      ircd_do_unumeric (cl, RPL_WHOISSERVER, &dummy, 0, ww->nick);
      n++;
      DBG("ircd:whowas reply on %s: done %p, prev %p, %d of %d", dummy.nick, ww, ww->prev, n, max);
    }
    if (n)
      ircd_do_unumeric (cl, RPL_ENDOFWHOWAS, cl, 0, c);
    else
      ircd_do_unumeric (cl, ERR_WASNOSUCHNICK, cl, 0, c);
  }
  return 1;
}

BINDING_TYPE_ircd_client_cmd(ircd_whowas_cb);
static int ircd_whowas_cb(INTERFACE *srv, struct peer_t *peer, const char *lcnick,
			  const char *user, const char *host, const char *vhost,
			  modeflag eum, int argc, const char **argv)
{
  DO_CLIENT_QUERY (_ircd_query_whowas);
}

BINDING_TYPE_ircd_server_cmd(ircd_whowas_sb);
static int ircd_whowas_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			  const char *sender, const char *lcsender,
			  int argc, const char **argv)
{
  DO_SERVER_QUERY (_ircd_query_whowas);
}

static inline int _ircd_query_ping (IRCD *ircd, CLIENT *cl, struct peer_priv *via,
				    int argc, const char **argv)
{ /* args: <server1> [<server2>] */
  CLIENT *tgt;
  const char *origin;

  if (argc == 0)
    return ircd_do_unumeric (cl, ERR_NOORIGIN, cl, 0, NULL);
  if (argc > 1) {
    tgt = ircd_find_client (argv[1], via);
    if (!tgt)
      return ircd_do_unumeric (cl, ERR_NOSUCHSERVER, cl, 0, argv[1]);
    origin = argv[0];
  } else {
    tgt = ircd_find_client (argv[0], via);
    origin = cl->nick;
  }
  /* stupid clients may send any trash here instead of target name */
  if (tgt == NULL || tgt == cl || CLIENT_IS_ME(tgt)) {
    register CLIENT *me = ircd_find_client(NULL, NULL);

    if (!CLIENT_IS_SERVER(cl) && !CLIENT_IS_REMOTE(cl))
      /* few of clients are broken and wait prefix here ignoring RFC */
      ircd_sendto_one (cl, ":%s PONG %s %s", me->lcnick, me->lcnick, argv[0]);
    else
      ircd_sendto_one (cl, "PONG %s %s", me->lcnick, argv[0]);
  } else
//    New_Request (tgt->cs->via->p.iface, 0, ":%s PING %s %s", cl->nick, origin,
//		 tgt->nick);
    New_Request (tgt->cs->via->p.iface, 0, "PING %s %s", origin, tgt->nick);
  return (-1);			/* don't reset idle time */
}

BINDING_TYPE_ircd_client_cmd(ircd_ping_cb);
static int ircd_ping_cb(INTERFACE *srv, struct peer_t *peer, const char *lcnick,
			const char *user, const char *host, const char *vhost,
			modeflag eum, int argc, const char **argv)
{
  DO_CLIENT_QUERY (_ircd_query_ping);
}

BINDING_TYPE_ircd_server_cmd(ircd_ping_sb);
static int ircd_ping_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			const char *sender, const char *lcsender,
			int argc, const char **argv)
{
  DO_SERVER2_QUERY (_ircd_query_ping);
}

static inline int _ircd_query_pong (IRCD *ircd, CLIENT *cl, struct peer_priv *via,
				    int argc, const char **argv)
{ /* args: <server1> [<server2>] */
  CLIENT *tgt;

  if (argc == 0)
    return ircd_do_unumeric (cl, ERR_NOORIGIN, cl, 0, NULL);
  via->link->cl->umode &= ~A_PINGED;
  if (argc > 1)
  {
    tgt = ircd_find_client (argv[1], via);
    if (!tgt)
      return ircd_do_unumeric (cl, ERR_NOSUCHSERVER, cl, 0, argv[1]);
    if (!CLIENT_IS_ME(tgt))
      New_Request (tgt->cs->via->p.iface, 0, ":%s PONG %s %s", cl->nick,
		   argv[0], tgt->nick);
  }
  return (-1);			/* don't reset idle time */
}

BINDING_TYPE_ircd_client_cmd(ircd_pong_cb);
static int ircd_pong_cb(INTERFACE *srv, struct peer_t *peer, const char *lcnick,
			const char *user, const char *host, const char *vhost,
			modeflag eum, int argc, const char **argv)
{
  DO_CLIENT_QUERY (_ircd_query_pong);
}

BINDING_TYPE_ircd_server_cmd(ircd_pong_sb);
static int ircd_pong_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			const char *sender, const char *lcsender,
			int argc, const char **argv)
{
  DO_SERVER2_QUERY (_ircd_query_pong);
}

static inline int _ircd_query_summon(IRCD *ircd, CLIENT *cl, struct peer_priv *via,
				     int argc, const char **argv)
{ /* args: <user> [<target> [<channel>]] */
  CLIENT *tgt;

  if (argc < 1)
    return ircd_do_unumeric(cl, ERR_NORECIPIENT, cl, 0, NULL);
  if (argc > 1)
  {
    tgt = ircd_find_client (argv[1], via);
    if (!tgt)
      return ircd_do_unumeric (cl, ERR_NOSUCHSERVER, cl, 0, argv[1]);
    if (!CLIENT_IS_ME(tgt)) {
      New_Request(tgt->cs->via->p.iface, 0, ":%s SUMMON %s %s %s", cl->nick,
		  argv[0], tgt->nick, NONULL(argv[2]));
      return 1;
    }
  }
#ifdef IRCD_ENABLE_SUMMON
  //TODO
//   The SUMMON command can be used to give users who are on a host
//   running an IRC server a message asking them to please join IRC.  This
//   message is only sent if the target server (a) has SUMMON enabled, (b)
//   the user is logged in and (c) the server process can write to the
//   user's tty (or similar).

//   Numeric Replies:
//           ERR_FILEERROR           ERR_NOLOGIN           RPL_SUMMONING
#else
  return ircd_do_unumeric(cl, ERR_SUMMONDISABLED, cl, 0, NULL);
#endif
}

BINDING_TYPE_ircd_client_cmd(ircd_summon_cb);
static int ircd_summon_cb(INTERFACE *srv, struct peer_t *peer, const char *lcnick,
			  const char *user, const char *host, const char *vhost,
			  modeflag eum, int argc, const char **argv)
{
  DO_CLIENT_QUERY (_ircd_query_summon);
}

BINDING_TYPE_ircd_server_cmd(ircd_summon_sb);
static int ircd_summon_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			  const char *sender, const char *lcsender,
			  int argc, const char **argv)
{
  DO_SERVER_QUERY (_ircd_query_summon);
}

static inline int _ircd_query_users(IRCD *ircd, CLIENT *cl, struct peer_priv *via,
				    int argc, const char **argv)
{ /* args: [<target>] */
  CLIENT *tgt;

  if (argc > 0)
  {
    tgt = ircd_find_client(argv[0], via);
    if (!tgt)
      return ircd_do_unumeric(cl, ERR_NOSUCHSERVER, cl, 0, argv[0]);
    if (CLIENT_IS_ME(tgt))
      return _ircd_query_users(ircd, cl, via, 0, argv);
    New_Request(tgt->cs->via->p.iface, 0, ":%s USERS %s", cl->nick, tgt->nick);
    return 1;
  }
#ifdef IRCD_ENABLE_USERS
  //TODO
//   The USERS command returns a list of users logged into the server in a
//   format similar to the UNIX commands who(1), rusers(1) and finger(1).
//   If disabled, the correct numeric MUST be returned to indicate this.

//   Because of the security implications of such a command, it SHOULD be
//   disabled by default in server implementations.  Enabling it SHOULD
//   require recompiling the server or some equivalent change rather than
//   simply toggling an option and restarting the server.  The procedure
//   to enable this command SHOULD also include suitable large comments.

//   Numeric Replies:
//           ERR_FILEERROR
//           RPL_USERSSTART                RPL_USERS
//           RPL_NOUSERS                   RPL_ENDOFUSERS
#else
  return ircd_do_unumeric(cl, ERR_USERSDISABLED, cl, 0, NULL);
#endif
}

BINDING_TYPE_ircd_client_cmd(ircd_users_cb);
static int ircd_users_cb(INTERFACE *srv, struct peer_t *peer, const char *lcnick,
			 const char *user, const char *host, const char *vhost,
			 modeflag eum, int argc, const char **argv)
{
  DO_CLIENT_QUERY (_ircd_query_users);
}

BINDING_TYPE_ircd_server_cmd(ircd_users_sb);
static int ircd_users_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			 const char *sender, const char *lcsender,
			 int argc, const char **argv)
{
  DO_SERVER_QUERY (_ircd_query_users);
}


/* ---------------------------------------------------------------------------
   "ircd-local-client" binding for user connection start */
BINDING_TYPE_ircd_local_client(_igotc_lu_mo);
static void _igotc_lu_mo (INTERFACE *srv, struct peer_t *peer, modeflag um)
{
  ircd_lusers_cb (srv, peer, NULL, NULL, NULL, NULL, A_ISON, 0, NULL);
  ircd_motd_cb (srv, peer, NULL, NULL, NULL, NULL, A_ISON, 0, NULL);
}


/* ---------------------------------------------------------------------------
   "ircd-client" binding for user connection stop or nickchange */
BINDING_TYPE_ircd_client(_icchg_ww);
static void _icchg_ww(INTERFACE *srv, const char *from, const char *lcnick,
		      const char *nick, const char *nn, const char *user,
		      const char *host, const char *fname, modeflag um, unsigned int left)
{
  whowas_t *ww, *wwp;

  if (um & (A_SERVER|A_SERVICE))
    return;
  if (nick == NULL)
    return;
  dprint(5, "ircd:queries.c:_icchg_ww: %s (%s@%s)", nick, user, host);
  /* check if we are at end of array and want to grow it */
  if (IrcdWhowasPtr == IrcdWhowasSize && left < (INT_MAX / 2 - SOCKETMAX) &&
      left<<1 > IrcdWhowasSize) {
    IrcdWhowasSize += 2 * SOCKETMAX;
    safe_realloc((void **)&IrcdWhowasArray, IrcdWhowasSize * sizeof(whowas_t *));
  }
  if (IrcdWhowasSize == 0) {		/* some bug catched, cannot continue! */
    ERROR("ircd:_ilostc_ww: internal error!");
    return;
  }
  if (IrcdWhowasPtr == IrcdWhowasSize)	/* start over */
    IrcdWhowasPtr = 0;
  if (IrcdWhowasPtr < WW_num)		{ /* unset this element */
    ww = IrcdWhowasArray[IrcdWhowasPtr];
    if (ww->next != NULL)
      ww->next->prev = NULL;
    else if (Delete_Key(IrcdWhowasTree, ww->lcnick, ww))
      ERROR("ircd:_ilostc_ww: tree error on removing %s from whowas list",
	    ww->lcnick);
      //TODO: isn't it fatal?
    if (ww->prev != NULL)
      ERROR("ircd:_ilostc_ww: %s has previous data but it's tail", ww->lcnick);
  } else				/* new allocation needed */
    IrcdWhowasArray[IrcdWhowasPtr] = ww = alloc_whowas_t(); /* WW_num++ */
  IrcdWhowasPtr++;			/* advance in list */
  wwp = Find_Key(IrcdWhowasTree, lcnick);
  if (wwp != NULL) {			/* it's last one in chain */
    if (Delete_Key(IrcdWhowasTree, wwp->lcnick, wwp))
      ERROR("ircd:_ilostc_ww: tree error on removing %s from whowas list",
	    wwp->lcnick);
      //TODO: isn't it fatal?
    wwp->next = ww;
  }
  ww->next = NULL;
  ww->prev = wwp;
  DBG("ircd:_ilostc_ww: adding %s: %p after %p, %u of %u", nick, ww, ww->prev,
      IrcdWhowasPtr, WW_num);
  strfcpy(ww->nick, nick, sizeof(ww->nick));
  strfcpy(ww->lcnick, lcnick, sizeof(ww->lcnick));
  if (Insert_Key(&IrcdWhowasTree, ww->lcnick, ww, 1))
    ERROR("ircd:_ilostc_ww: tree error on adding %s to whowas list", ww->lcnick);
    //TODO: isn't it fatal?
  strfcpy(ww->fname, fname, sizeof(ww->fname));
  strfcpy(ww->user, user, sizeof(ww->user));
  strfcpy(ww->host, host, sizeof(ww->host));
  strfcpy(ww->fromsrv, from, sizeof(ww->fromsrv));
  ww->wason = Time;
  /* done */
}


/* ---------------------------------------------------------------------------
   "ircd-stat-reply" bindings for STATS command */
static CLIENT _istats_dummy_client = { .nick = "", .via = NULL };

static void _istats_o_show_host (INTERFACE *tmp, char *host)
{
  strfcpy (_istats_dummy_client.vhost, host, sizeof(_istats_dummy_client.vhost));
  ircd_do_unumeric (_ircd_stats_client, RPL_STATSOLINE, &_istats_dummy_client,
		    0, NULL);
}

static void _istats_o_show_O (INTERFACE *tmp, char *oper)
{
  lid_t lid = FindLID (oper);

  strfcpy (_istats_dummy_client.nick, oper, sizeof(_istats_dummy_client.nick));
  _ircd_list_receiver_show = &_istats_o_show_host;
  if (Get_Hostlist (tmp, lid))
    Get_Request();
}

BINDING_TYPE_ircd_stats_reply(_istats_o);
static void _istats_o (INTERFACE *srv, const char *rq, modeflag umode)
{
  const char *n = ((IRCD *)srv->data)->sub->name;
  INTERFACE *tmp;

  tmp = Add_Iface (I_TEMP, NULL, NULL, &_ircd_qlist_r, NULL);
  _ircd_list_receiver_show = &_istats_o_show_O;
  Set_Iface (tmp);
  if (Get_Clientlist (tmp, (U_OP | U_HALFOP), n, "*"))
    Get_Request(); /* it will do recurse itself */
  Unset_Iface();
  tmp->ift = I_DIED;
}

BINDING_TYPE_ircd_stats_reply(_istats_u);
static void _istats_u (INTERFACE *srv, const char *rq, modeflag umode)
{
  int days, hours, mins, seconds;
  char buf[SHORT_STRING];

  seconds = Time - _ircd_time_started;
  mins = seconds / 60;
  seconds -= mins * 60;
  hours = mins / 60;
  mins -= hours * 60;
  days = hours / 24;
  hours -= days * 24;
  snprintf (buf, sizeof(buf), "Server Up %d days %d:%02d:%02d", days, hours,
	    mins, seconds);
  ircd_do_unumeric (_ircd_stats_client, RPL_STATSUPTIME, _ircd_stats_client,
		    0, buf);
}

/* RFC1459 mentions also stats c, h, i, k, y but those are optional */
static void _istats_c_show_host (INTERFACE *tmp, char *host)
{
  char *c = strchr (host, ':');
  unsigned short port = 0;

  if (c == NULL)
    c = strchr (host, '@');
  if (c)
  {
    size_t hs = c - host;
    if (hs >= sizeof(_istats_dummy_client.vhost))
      hs = sizeof(_istats_dummy_client.vhost) - 1;
    strfcpy (_istats_dummy_client.vhost, host, hs + 1);
    if (*c == ':')
      c = strchr (c, '@');
    if (!_istats_dummy_client.vhost[0])
      strcpy (_istats_dummy_client.vhost, "*");
  }
  else
  {
    c = host;
    strcpy (_istats_dummy_client.vhost, "*@");
  }
  strfcat (_istats_dummy_client.vhost, c, sizeof(_istats_dummy_client.vhost));
  /* _istats_dummy_client.vhost contains now user@host/port */
  c = strchr (_istats_dummy_client.vhost, '/');
  if (c)
  {
    *c++ = '\0';
    port = (unsigned short)strtoul(c, NULL, 10);
  }
  ircd_do_unumeric (_ircd_stats_client, RPL_STATSCLINE, &_istats_dummy_client,
		    port, NULL);
}

static void _istats_c_show_S (INTERFACE *tmp, char *serv)
{
  lid_t lid = FindLID (serv);

  strfcpy (_istats_dummy_client.nick, serv, sizeof(_istats_dummy_client.nick));
  _ircd_list_receiver_show = &_istats_c_show_host;
  if (Get_Hostlist (tmp, lid))
    Get_Request();
}

BINDING_TYPE_ircd_stats_reply(_istats_c);
static void _istats_c (INTERFACE *srv, const char *rq, modeflag umode)
{
  const char *n = ((IRCD *)srv->data)->sub->name;
  INTERFACE *tmp;

  if (!(umode & (A_OP | A_HALFOP)))
  {
    ircd_do_unumeric (_ircd_stats_client, ERR_NOPRIVILEGES, _ircd_stats_client, 0, NULL);
    return;
  }
  tmp = Add_Iface (I_TEMP, NULL, NULL, &_ircd_qlist_r, NULL);
  _ircd_list_receiver_show = &_istats_c_show_S;
  Set_Iface (tmp);
  if (Get_Clientlist (tmp, U_UNSHARED, n, "*"))
    Get_Request(); /* it will do recurse itself */
  Unset_Iface();
  tmp->ift = I_DIED;
}

static void _istats_h_show (INTERFACE *tmp, char *serv)
{
  struct clrec_t *clr = Lock_Clientrecord (serv);
  char *hub, *c1, *c2;

  if (clr)
  {
    strfcpy (_istats_dummy_client.nick, serv, sizeof(_istats_dummy_client.nick));
    hub = safe_strdup (Get_Field (clr, "hub", NULL));
    Unlock_Clientrecord (clr);
    if (hub)
    {
      for (c1 = hub; *c1; c1 = c2)
      {
	c2 = gettoken (c1, NULL);
	ircd_do_unumeric (_ircd_stats_client, RPL_STATSHLINE, &_istats_dummy_client, 0, c1);
      }
      FREE (&hub);
    }
  }
}

BINDING_TYPE_ircd_stats_reply(_istats_h);
static void _istats_h (INTERFACE *srv, const char *rq, modeflag umode)
{
  const char *n = ((IRCD *)srv->data)->sub->name;
  INTERFACE *tmp;

  if (!(umode & (A_OP | A_HALFOP)))
  {
    ircd_do_unumeric (_ircd_stats_client, ERR_NOPRIVILEGES, _ircd_stats_client, 0, NULL);
    return;
  }
  tmp = Add_Iface (I_TEMP, NULL, NULL, &_ircd_qlist_r, NULL);
  _ircd_list_receiver_show = &_istats_h_show;
  Set_Iface (tmp);
  if (Get_Clientlist (tmp, U_UNSHARED, n, "*"))
    Get_Request(); /* it will do recurse itself */
  Unset_Iface();
  tmp->ift = I_DIED;
}


/* ---------------------------------------------------------------------------
 * Common external functions.
 */

/* common end and start of channel protocol */
void ircd_queries_proto_end (void)
{
  UnregisterVariable ("ircd-motd-file");
  UnregisterVariable ("ircd-admin-info");
  UnregisterVariable ("ircd-admin-email");
  UnregisterVariable ("ircd-max-matches");
  UnregisterVariable ("ircd-max-whois");
  FREE (&IrcdMotd);
  IrcdMotdSize = 0;
  Delete_Binding ("ircd-client-cmd", &ircd_names_cb, NULL);
  Delete_Binding ("ircd-client-cmd", &ircd_list_cb, NULL);
  Delete_Binding ("ircd-client-cmd", &ircd_motd_cb, NULL);
  Delete_Binding ("ircd-client-cmd", &ircd_lusers_cb, NULL);
  Delete_Binding ("ircd-client-cmd", &ircd_version_cb, NULL);
  Delete_Binding ("ircd-client-cmd", &ircd_stats_cb, NULL);
  Delete_Binding ("ircd-client-cmd", &ircd_links_cb, NULL);
  Delete_Binding ("ircd-client-cmd", &ircd_time_cb, NULL);
  Delete_Binding ("ircd-client-cmd", &ircd_connect_cb, NULL);
  Delete_Binding ("ircd-client-cmd", &ircd_trace_cb, NULL);
  Delete_Binding ("ircd-client-cmd", &ircd_admin_cb, NULL);
  Delete_Binding ("ircd-client-cmd", &ircd_info_cb, NULL);
  Delete_Binding ("ircd-client-cmd", &ircd_whois_cb, NULL);
  Delete_Binding ("ircd-client-cmd", &ircd_whowas_cb, NULL);
  Delete_Binding ("ircd-client-cmd", &ircd_ping_cb, NULL);
  Delete_Binding ("ircd-client-cmd", &ircd_pong_cb, NULL);
  Delete_Binding ("ircd-client-cmd", &ircd_summon_cb, NULL);
  Delete_Binding ("ircd-client-cmd", &ircd_users_cb, NULL);
  Delete_Binding ("ircd-server-cmd", (Function)&ircd_names_sb, NULL);
  Delete_Binding ("ircd-server-cmd", (Function)&ircd_list_sb, NULL);
  Delete_Binding ("ircd-server-cmd", (Function)&ircd_motd_sb, NULL);
  Delete_Binding ("ircd-server-cmd", (Function)&ircd_lusers_sb, NULL);
  Delete_Binding ("ircd-server-cmd", (Function)&ircd_version_sb, NULL);
  Delete_Binding ("ircd-server-cmd", (Function)&ircd_stats_sb, NULL);
  Delete_Binding ("ircd-server-cmd", (Function)&ircd_links_sb, NULL);
  Delete_Binding ("ircd-server-cmd", (Function)&ircd_time_sb, NULL);
  Delete_Binding ("ircd-server-cmd", (Function)&ircd_connect_sb, NULL);
  Delete_Binding ("ircd-server-cmd", (Function)&ircd_trace_sb, NULL);
  Delete_Binding ("ircd-server-cmd", (Function)&ircd_admin_sb, NULL);
  Delete_Binding ("ircd-server-cmd", (Function)&ircd_info_sb, NULL);
  Delete_Binding ("ircd-server-cmd", (Function)&ircd_whois_sb, NULL);
  Delete_Binding ("ircd-server-cmd", (Function)&ircd_whowas_sb, NULL);
  Delete_Binding ("ircd-server-cmd", (Function)&ircd_ping_sb, NULL);
  Delete_Binding ("ircd-server-cmd", (Function)&ircd_pong_sb, NULL);
  Delete_Binding ("ircd-server-cmd", (Function)&ircd_summon_sb, NULL);
  Delete_Binding ("ircd-server-cmd", (Function)&ircd_users_sb, NULL);
  Delete_Binding ("ircd-local-client", (Function)&_igotc_lu_mo, NULL);
  Delete_Binding ("ircd-client", (Function)&_icchg_ww, NULL);
  Delete_Binding ("ircd-stats-reply", (Function)&_istats_o, NULL);
  Delete_Binding ("ircd-stats-reply", (Function)&_istats_u, NULL);
  Delete_Binding ("ircd-stats-reply", (Function)&_istats_c, NULL);
  Delete_Binding ("ircd-stats-reply", (Function)&_istats_h, NULL);
  Destroy_Tree (&IrcdWhowasTree, NULL);
  FREE (&IrcdWhowasArray);
  _forget_(whowas_t);
}

void ircd_queries_register (void)
{
  RegisterString ("ircd-motd-file", _ircd_motd_file, sizeof(_ircd_motd_file), 0);
  RegisterString ("ircd-admin-info", _ircd_admin_info,
		  sizeof(_ircd_admin_info), 0);
  RegisterString ("ircd-admin-email", _ircd_admin_email,
		  sizeof(_ircd_admin_email), 0);
  RegisterInteger ("ircd-max-matches", &_ircd_max_matches);
  RegisterInteger ("ircd-max-whois", &_ircd_max_whois);
}

void ircd_queries_proto_start (void)
{
  ircd_queries_register();
  //TODO: fail to start if no admin email set?
  BTIrcdStatsReply = Add_Bindtable ("ircd-stats-reply", B_KEYWORD);
  BTIrcdWhois = Add_Bindtable ("ircd-whois", B_MASK);
  Add_Binding ("ircd-client-cmd", "names", 0, 0, &ircd_names_cb, NULL);
  Add_Binding ("ircd-client-cmd", "list", 0, 0, &ircd_list_cb, NULL);
  Add_Binding ("ircd-client-cmd", "motd", 0, 0, &ircd_motd_cb, NULL);
  Add_Binding ("ircd-client-cmd", "lusers", 0, 0, &ircd_lusers_cb, NULL);
  Add_Binding ("ircd-client-cmd", "version", 0, 0, &ircd_version_cb, NULL);
  Add_Binding ("ircd-client-cmd", "stats", 0, 0, &ircd_stats_cb, NULL);
  Add_Binding ("ircd-client-cmd", "links", 0, 0, &ircd_links_cb, NULL);
  Add_Binding ("ircd-client-cmd", "time", 0, 0, &ircd_time_cb, NULL);
  Add_Binding ("ircd-client-cmd", "connect", 0, U_HALFOP, &ircd_connect_cb, NULL);
  Add_Binding ("ircd-client-cmd", "trace", 0, 0, &ircd_trace_cb, NULL);
  Add_Binding ("ircd-client-cmd", "admin", 0, 0, &ircd_admin_cb, NULL);
  Add_Binding ("ircd-client-cmd", "info", 0, 0, &ircd_info_cb, NULL);
  Add_Binding ("ircd-client-cmd", "whois", 0, 0, &ircd_whois_cb, NULL);
  Add_Binding ("ircd-client-cmd", "whowas", 0, 0, &ircd_whowas_cb, NULL);
  Add_Binding ("ircd-client-cmd", "ping", 0, 0, &ircd_ping_cb, NULL);
  Add_Binding ("ircd-client-cmd", "pong", 0, 0, &ircd_pong_cb, NULL);
  Add_Binding ("ircd-client-cmd", "summon", 0, 0, &ircd_summon_cb, NULL);
  Add_Binding ("ircd-client-cmd", "users", 0, 0, &ircd_users_cb, NULL);
  Add_Binding ("ircd-server-cmd", "names", 0, 0, (Function)&ircd_names_sb, NULL);
  Add_Binding ("ircd-server-cmd", "list", 0, 0, (Function)&ircd_list_sb, NULL);
  Add_Binding ("ircd-server-cmd", "motd", 0, 0, (Function)&ircd_motd_sb, NULL);
  Add_Binding ("ircd-server-cmd", "lusers", 0, 0, (Function)&ircd_lusers_sb, NULL);
  Add_Binding ("ircd-server-cmd", "version", 0, 0, (Function)&ircd_version_sb, NULL);
  Add_Binding ("ircd-server-cmd", "stats", 0, 0, (Function)&ircd_stats_sb, NULL);
  Add_Binding ("ircd-server-cmd", "links", 0, 0, (Function)&ircd_links_sb, NULL);
  Add_Binding ("ircd-server-cmd", "time", 0, 0, (Function)&ircd_time_sb, NULL);
  Add_Binding ("ircd-server-cmd", "connect", 0, 0, (Function)&ircd_connect_sb, NULL);
  Add_Binding ("ircd-server-cmd", "trace", 0, 0, (Function)&ircd_trace_sb, NULL);
  Add_Binding ("ircd-server-cmd", "admin", 0, 0, (Function)&ircd_admin_sb, NULL);
  Add_Binding ("ircd-server-cmd", "info", 0, 0, (Function)&ircd_info_sb, NULL);
  Add_Binding ("ircd-server-cmd", "whois", 0, 0, (Function)&ircd_whois_sb, NULL);
  Add_Binding ("ircd-server-cmd", "whowas", 0, 0, (Function)&ircd_whowas_sb, NULL);
  Add_Binding ("ircd-server-cmd", "ping", 0, 0, (Function)&ircd_ping_sb, NULL);
  Add_Binding ("ircd-server-cmd", "pong", 0, 0, (Function)&ircd_pong_sb, NULL);
  Add_Binding ("ircd-server-cmd", "summon", U_HALFOP, 0, (Function)&ircd_summon_sb, NULL);
  Add_Binding ("ircd-server-cmd", "users", U_HALFOP, 0, (Function)&ircd_users_sb, NULL);
  Add_Binding ("ircd-local-client", "*", 0, 0, (Function)&_igotc_lu_mo, NULL);
  Add_Binding ("ircd-client", "*", 0, 0, (Function)&_icchg_ww, NULL);
  Add_Binding ("ircd-stats-reply", "o", 0, 0, (Function)&_istats_o, NULL);
  Add_Binding ("ircd-stats-reply", "u", 0, 0, (Function)&_istats_u, NULL);
  Add_Binding ("ircd-stats-reply", "c", 0, 0, (Function)&_istats_c, NULL);
  Add_Binding ("ircd-stats-reply", "h", 0, 0, (Function)&_istats_h, NULL);
  _ircd_time_started = Time;
//TODO: add bindtable to add chars into ircd_version_flags?
}
#endif
