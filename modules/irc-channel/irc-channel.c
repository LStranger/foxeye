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
 *
 * The FoxEye "irc-channel" module: base IRC-client channel management. Does:
 *   - autojoins
 *   - control of channel
 *   - statistics for users
 *   - detection of netjoins
 *   - run bindtables
 *
 * Note: flood protection placed in the other module.
 */

#include "foxeye.h"
#include "modules.h"

#include <pthread.h>

#include "tree.h"
#include "wtmp.h"
#include "init.h"
#include "sheduler.h"
#include "irc-channel.h"

static NODE *IRCNetworks = NULL;

#define SAVESIZE 1024
static lid_t ChLids[SAVESIZE];
static short ChCounts[SAVESIZE];

static bindtable_t *BT_IrcJoin;
static bindtable_t *BT_IrcKick;
static bindtable_t *BT_IrcMChg;
static bindtable_t *BT_IrcNJoin;
static bindtable_t *BT_IrcNSplit;
static bindtable_t *BT_IrcNChg;
static bindtable_t *BT_IrcPart;
static bindtable_t *BT_IrcSignoff;
static bindtable_t *BT_IrcTopic;
static bindtable_t *BT_Keychange;

static long int ircch_netsplit_log = 3;		/* collect for 3s */
static long int ircch_netsplit_ping = 30;	/* answer from server in 30s */
static long int ircch_netsplit_keep = 21600;	/* keep array for 6h */
static bool ircch_join_on_invite = (CAN_ASK | ASK | FALSE); /* ask-no */
long int ircch_enforcer_time = 4;		/* bans enforcer timeout */

static char *format_irc_join;
static char *format_irc_part;
static char *format_irc_nickchange;
static char *format_irc_lostinnetsplit;
static char *format_irc_kick;
static char *format_irc_modechange;
static char *format_irc_quit;
static char *format_irc_netsplit;
static char *format_irc_netjoin;
static char *format_irc_topic;


/* --- Internal functions --------------------------------------------------- */

int ircch_add_mask (list_t **list, char *by, size_t sby, char *what)
{
  list_t *topic;

  while (*list)
    if (!strcasecmp ((*list)->what, what))
      return 0;					/* the same already exist */
    else
      list = &(*list)->next;
  topic = safe_malloc (sizeof(list_t) + strlen (what) + sby + 1);
  topic->next = NULL;
  topic->since = Time;
  memcpy (topic->by, by, sby);
  topic->by[sby] = 0;
  topic->what = &topic->by[sby+1];
  strcpy (topic->what, what);
  *list = topic;
  return 1;
}

list_t *ircch_find_mask (list_t *list, char *mask)
{
  while (list)
    if (!strcasecmp (list->what, mask))
      break;
    else
      list = list->next;
  return list;
}

void ircch_remove_mask (list_t **list, list_t *mask)
{
  while (*list)
    if (*list == mask)
      break;
  if (*list)
    *list = mask->next;
  FREE (&mask);
}

static void _ircch_add_lname (nick_t *nick, char *lname)
{
  LEAF *leaf = Find_Leaf (nick->net->lnames, lname);

  if (leaf)
  {
    nick->prev_TSL = leaf->s.data;
    leaf->s.data = nick;
    nick->lname = nick->prev_TSL->lname;
  }
  else
  {
    nick->lname = safe_strdup (lname);
    Insert_Key (&nick->net->lnames, nick->lname, nick, 0);
  }
}

static void _ircch_del_lname (nick_t *nick)
{
  LEAF *leaf = Find_Leaf (nick->net->lnames, nick->lname);

  if (leaf->s.data == nick)			/* it's last of nicks */
  {
    if (!(leaf->s.data = nick->prev_TSL))	/* last one so delete it */
    {
      Delete_Key (nick->net->lnames, nick->lname, nick);
      FREE (&nick->lname);
      return;
    }
  }
  else
  {
    nick_t *next_TSL;

    for (next_TSL = leaf->s.data; next_TSL->prev_TSL != nick; )
      next_TSL = next_TSL->prev_TSL;
    next_TSL->prev_TSL = nick->prev_TSL;
  }
  nick->lname = NULL;
}

static net_t *_ircch_get_network (const char *network, int create)
{
  char netname[NAMEMAX+2];
  net_t *net;
  clrec_t *clr;
  char *c;

  if (!network)
    return NULL;	/* bad request */
  if (network[0] == '@')
    strfcpy (netname, network, sizeof(netname));
  else
  {
    netname[0] = '@';
    strfcpy (&netname[1], network, sizeof(netname) - 1);
  }
  net = Find_Key (IRCNetworks, netname);
  if (net || !create)
    return net;
  net = safe_calloc (1, sizeof (net_t));
  net->name = safe_strdup (netname);
  net->features = L_NOEXEMPTS;		/* set defaults */
  net->maxmodes = 3;
  net->maxbans = 30;
  net->maxtargets = 4;
  clr = Lock_Clientrecord (netname);
  if (clr)
  {
    c = Get_Field (clr, IRCPAR_FIELD, NULL);
    if (c) while (*c)
    {
      if (!memcmp (c, IRCPAR_MODES, strlen(IRCPAR_MODES)) &&
	  c[strlen(IRCPAR_MODES)] == '=')
	net->maxmodes = atoi (&c[strlen(IRCPAR_MODES)+1]);
      else if (!memcmp (c, IRCPAR_MAXBANS, strlen(IRCPAR_MAXBANS)) &&
	       c[strlen(IRCPAR_MAXBANS)] == '=')
	net->maxbans = atoi (&c[strlen(IRCPAR_MAXBANS)+1]);
      else if (!memcmp (c, IRCPAR_TARGETS, strlen(IRCPAR_TARGETS)) &&
	       c[strlen(IRCPAR_TARGETS)] == '=')
	net->maxtargets = atoi (&c[strlen(IRCPAR_TARGETS)+1]);
      else if (!memcmp (c, IRCPAR_PREFIX, strlen(IRCPAR_PREFIX)) &&
	       c[strlen(IRCPAR_PREFIX)] == '=')
      {
	c += strlen(IRCPAR_PREFIX) + 1;
	if (*c == '(')
	  while (*c && *c != ' ' && *c++ != ')');
	while (*c && *c != ' ')
	{
	  if (*c == '!')
	    net->features |= L_HASADMIN;
	  else if (*c == '%')
	    net->features |= L_HASHALFOP;
	  c++;
	}
      }
      else if (!memcmp (c, IRCPAR_CHANMODES, strlen(IRCPAR_CHANMODES)) &&
	       c[strlen(IRCPAR_CHANMODES)] == '=')
      {
	c += strlen(IRCPAR_CHANMODES) + 1;
	while (*c && *c != ' ')
	  if (*c++ == 'e')
	  {
	    net->features &= ~L_NOEXEMPTS;
	    break;
	  }
      }
      /* TODO: set network-specific modechars */
      c = NextWord(c);
    }
    Unlock_Clientrecord (clr);
  }
  Insert_Key (&IRCNetworks, net->name, net, 0);
  return net;
}

static iftype_t _ircch_sig (INTERFACE *, ifsig_t);

static ch_t *_ircch_get_channel (net_t *net, const char *chname, int create)
{
  char ch[CHANNAMELEN+NAMEMAX+3];
  ch_t *chan;
  clrec_t *u;

  if (chname[0] == '!')	/* skip "!XXXXX" part, short name has to be unique */
    safe_strlower (ch, &chname[6], sizeof(ch));
  else
    safe_strlower (ch, chname, sizeof(ch));
  if (safe_strcmp (strrchr (ch, '@'), net->name))
    strfcat (ch, net->name, sizeof(ch));
  chan = Find_Key (net->channels, ch);
  if (chan || !create)
    return chan;
  chan = safe_calloc (1, sizeof(ch_t));
  chan->chi = Add_Iface (ch, I_SERVICE, &_ircch_sig, NULL, chan);
  if ((u = Lock_Clientrecord (ch)))
  {
    char *modeline = Get_Field (u, "info", NULL);

    if (modeline)
      ircch_parse_configmodeline (net, chan, modeline);
    /* TODO: check if we might be invited/joined to unknown channel! */
    Unlock_Clientrecord (u);
  }
  chan->id = GetLID (ch);
  chan->tid = -1;
  Insert_Key (&net->channels, chan->chi->name, chan, 0);
  return chan;
}

static void _ircch_shutdown_channel (ch_t *chan)
{
  register size_t i = 0;
  register link_t *link;

  if (chan->id != ID_REM) for (link = chan->nicks; link; link = link->prevnick)
    if (link->nick->lname != NULL)	/* ignore unregistered */
    {
      ChLids[i] = link->nick->id;
      ChCounts[i] = link->count;
      i++;
      if (i == SAVESIZE)
      {
	NewEvents (W_DOWN, chan->id, i, ChLids, ChCounts);
	i = 0;
      }
    }
  if (i)
    NewEvents (W_DOWN, chan->id, i, ChLids, ChCounts);
}

static nick_t *_ircch_destroy_link (link_t *);		/* declarations */
static void _ircch_destroy_nick (void *);

static void _ircch_destroy_channel (void *cht)
{
  nick_t *nt;

  _ircch_shutdown_channel (cht); /* wtmp for all nicks */
  while (((ch_t *)cht)->nicks)
    if ((nt = _ircch_destroy_link (((ch_t *)cht)->nicks)))
      {
	Delete_Key (nt->net->nicks, nt->name, nt);
	_ircch_destroy_nick (nt);
      }
  ircch_remove_mask (&((ch_t *)cht)->topic, ((ch_t *)cht)->topic);
  while (((ch_t *)cht)->bans)
    ircch_remove_mask (&((ch_t *)cht)->bans, ((ch_t *)cht)->bans);
  while (((ch_t *)cht)->exempts)
    ircch_remove_mask (&((ch_t *)cht)->exempts, ((ch_t *)cht)->exempts);
  while (((ch_t *)cht)->invites)
    ircch_remove_mask (&((ch_t *)cht)->invites, ((ch_t *)cht)->invites);
  KillTimer (((ch_t *)cht)->tid);
  FREE (&((ch_t *)cht)->key);
  ((ch_t *)cht)->chi->ift = I_DIED;
  //safe_free (&((ch_t *)cht)->chi->data); /* it's cht, will be freed itself */
}

static nick_t *_ircch_get_nick (net_t *net, char *lcn, int create)
{
//  register char *c;
  nick_t *nt;

//  if ((c = strchr (lcn, '!'))) /* it may be nick!user@host */
//    *c = 0;
//  strfcat (n, net->name, sizeof(n));
  nt = Find_Key (net->nicks, lcn);
  if (!nt && create)
  {
    nt = safe_calloc (1, sizeof(nick_t));
    nt->name = safe_strdup (lcn);
    nt->net = net;
    Insert_Key (&net->nicks, nt->name, nt, 0);
  }
//  if (c)
//    *c = '!';
  return nt;
}

static char *_ircch_get_lname (char *nuh, userflag *sf, userflag *cf,
			       char *net, char *chan)
{
  char *c;
  clrec_t *u;

  u = Find_Clientrecord (nuh, &c, sf, net);
  if (u)
  {
    c = safe_strdup (c);
    if (cf)
      *cf = Get_Flags (u, chan);
    Unlock_Clientrecord (u);
    return c;
  }
  return NULL;
}

static void _ircch_destroy_nick (void *nt)		/* definition */
{
  while (((nick_t *)nt)->channels)
    _ircch_destroy_link (((nick_t *)nt)->channels);
  if (((nick_t *)nt)->lname)
    _ircch_del_lname (nt);
  FREE (&((nick_t *)nt)->name);
  FREE (&((nick_t *)nt)->host);
  safe_free (&nt);
}

static void _ircch_destroy_network (net_t *net)
{
  netsplit_t *split;

  FREE (&net->name);
  if (net->invited)
  {
    pthread_cancel (net->invited->th);
    Unset_Iface();
    pthread_join (net->invited->th, NULL);
    Set_Iface (NULL);
    FREE (&net->invited->chname);
    FREE (&net->invited->who);
    FREE (&net->invited);
  }
  Destroy_Tree (&net->channels, &_ircch_destroy_channel);
  Destroy_Tree (&net->nicks, &_ircch_destroy_nick); /* it must be already empty */
  Destroy_Tree (&net->lnames, NULL);
  while ((split = net->splits))
  {
    net->splits = split->next;
    FREE (&split->servers);
    Destroy_Tree (&split->nicks, NULL);
    FREE (&split);
  }
  FREE (&net);
}

link_t *ircch_find_link (net_t *net, char *lcn, ch_t *ch)
{
  link_t *link;
  nick_t *nt;

  nt = _ircch_get_nick (net, lcn, 0);
  if (nt) for (link = nt->channels; link; link = link->prevchan)
    if (link->chan == ch)
      return link;
  return NULL;
}

static link_t *_ircch_get_link (net_t *net, char *lcn, ch_t *ch)
{
  link_t *link;
  nick_t *nt;

  nt = _ircch_get_nick (net, lcn, 1);
  for (link = nt->channels; link; link = link->prevchan)
    if (link->chan == ch)			/* may return from netsplit */
      return link;
  link = safe_calloc (1, sizeof(link_t));
  link->chan = ch;
  link->prevnick = ch->nicks;
  link->nick = nt;
  link->prevchan = nt->channels;
  ch->nicks = nt->channels = link;
  return link;
}

/* returns nick if it was last channel */
static nick_t *_ircch_destroy_link (link_t *link)	/* definition */
{
  ch_t *chan;
  nick_t *nick;
  link_t *l;

  chan = link->chan;
  nick = link->nick;
  if (chan->nicks == link)
    chan->nicks = link->prevnick;
  else
  {
    for (l = chan->nicks; l && l->prevnick != link; l = l->prevnick);
    if (l)
      l->prevnick = link->prevnick;
  }
  if (nick->channels == link)
    nick->channels = link->prevchan;
  else
  {
    for (l = nick->channels; l && l->prevchan != link; l = l->prevchan);
    if (l)
      l->prevchan = link->prevchan;
  }
  FREE (&link);
  if (nick->channels == NULL)
    return nick; /* remove it from tree if called not from _ircch_destroy_nick() */
  return NULL;
}

static void _ircch_recheck_link (net_t *net, link_t *link, char *lname,
				 userflag uf, userflag cf)
{
  link_t *nl;

  link->chan->id = GetLID (link->chan->chi->name); /* hmm, id may be changed */
  if (safe_strcmp (lname, link->nick->lname))	/* hmm, listfile was changed */
  {
    if (link->nick->lname)
    {
      for (nl = link->nick->channels; nl; nl = nl->prevchan)
	if (nl->chan->id != ID_REM)
	  NewEvent (W_END, nl->chan->id, link->nick->id, nl->count);
      _ircch_del_lname (link->nick);
    }
    if (lname)
    {
      _ircch_add_lname (link->nick, lname);
      link->nick->id = GetLID (lname);
      for (nl = link->nick->channels; nl; nl = nl->prevchan)
	if (nl->chan->id != ID_REM)
	NewEvent (W_START, nl->chan->id, link->nick->id, 0);
    }
    for (nl = link->nick->channels; nl; nl = nl->prevchan)
    {
      strfcpy (nl->joined, DateString, sizeof(nl->joined));
      nl->count = 0;
    }
    ircch_recheck_modes (net, link, uf, cf, NULL); /* NULL reason if kickban */
  }
  link->activity = Time;
}


/* --- Logging -------------------------------------------------------------- */

static void _ircch_joined (link_t *link, char *nuh, char *atuh, userflag uf,
			   userflag cf, char *chan)
{ // run bindings and log all
  char *c, *uh;
  binding_t *bind;
  int i;
  char str[MESSAGEMAX];

  if (chan)
    c = NULL;
  else
  {
    chan = link->chan->chi->name;
    c = strrchr (chan, '@');
  }
  snprintf (str, sizeof(str), "%s %s", link->chan->chi->name, nuh);
  for (bind = NULL; (bind = Check_Bindtable (BT_IrcJoin, str, uf, cf, bind)); )
  {
    if (bind->name)
      i = RunBinding (bind, nuh, link->nick->lname ? link->nick->lname : "*",
		      link->chan->chi->name, -1, NULL);
    else
      i = bind->func (nuh, link->nick->lname, link->chan->chi);
  }
  /* %N - nick, %@ - user@host, %L - lname, %# - channel */
  uh = strchr (nuh, '!');
  if (uh) *uh = 0;
  if (c) *c = 0;
  printl (str, sizeof(str), format_irc_join, 0,
	  nuh, uh ? &uh[1] : uh, link->nick->lname, chan, 0, 0, 0, NULL);
  if (c) *c = '@';
  if (uh) *uh = '!';
  Add_Request (I_LOG, link->chan->chi->name, F_JOIN, "%s", str);
}

static void _ircch_quited (nick_t *nick, char *lname, userflag uf,
			   unsigned char *who, char *msg)
{
  char *c, *cc;
  userflag cf;
  binding_t *bind;
  link_t *link;
  char str[MESSAGEMAX];

  c = strchr (who, '!');
  cc = strchr (nick->host, '!');
  for (link = nick->channels; link; link = link->prevchan)
  {
    if (nick->lname && link->chan->id != ID_REM)
      NewEvent (W_END, link->chan->id, nick->id, link->count);
    /* run script bindings */
    cf = Get_Clientflags (lname, link->chan->chi->name);
    snprintf (str, sizeof(str), "%s%s", nick->name, NONULL(cc));
    for (bind = NULL; (bind = Check_Bindtable (BT_IrcSignoff, str, uf, cf,
					       bind)); )
      if (bind->name)
	RunBinding (bind, who, lname ? lname : "*", link->chan->chi->name, -1,
		    msg);
    if (c) *c = 0;
    /* %N - nick, %@ - user@host, %L - Lname, %# - network, %* - message */
    printl (str, sizeof(str), format_irc_quit, 0,
	    who, c ? &c[1] : c, lname, nick->net->neti->name, 0, 0, 0, msg);
    if (c) *c = '!';
    Add_Request (I_LOG, link->chan->chi->name, F_JOIN, "%s", str);
  }
  Delete_Key (nick->net->nicks, nick->name, nick);
  _ircch_destroy_nick (nick);
}

static void _ircch_netsplit_channellog (netsplit_t *split, ch_t *chan,
					char *str, size_t len)
{//log netsplit to channel
  char buf[MESSAGEMAX];
  char *c;

  str[len] = 0; /* terminate it */
  c = strrchr (chan->chi->name, '@');
  if (c) *c = 0;
  /* %N - nicklist, %# - channel, %* - netjoin servers */
  printl (buf, sizeof(buf), format_irc_netsplit, 0, str, NULL, NULL,
	  chan->chi->name, 0L, 0, 0, split->servers);
  if (c) *c = '@';
  Add_Request (I_LOG, chan->chi->name, F_JOIN, "%s", buf);
}

static void _ircch_netsplit_log (net_t *net, netsplit_t *split)
{//log netsplit to all channels and set split->ping to 0
  LEAF *l = NULL;
  size_t s, nl;
  link_t *link;
  char *c;
  char buf[STRING];

  while ((l = Next_Leaf (net->channels, l, NULL)))
  {
    s = 0;
    for (link = ((ch_t *)l->s.data)->nicks; link; link = link->prevnick)
    {
      if (link->nick->split != split)
	continue;
      c = strchr (link->nick->host, '!');
      if (c)
	nl = c - link->nick->host;
      else
	nl = strlen (link->nick->host);
      if (s + nl >= sizeof(buf))
      {
	_ircch_netsplit_channellog (split, link->chan, buf, s);
	s = 0;
	if (nl >= sizeof(buf))
	  nl = sizeof(buf) - 1;
      }
      if (s)
	buf[s++] = ',';
      memcpy (&buf[s], link->nick->host, nl);
      s += nl;			/* s < sizeof(buf) */
    }
    if (s)
      _ircch_netsplit_channellog (split, link->chan, buf, s);
  }
  split->ping = 0;
}

static void _ircch_netjoin_log (netsplit_t *split, ch_t *chan,
				char *str, size_t len, char *buf, size_t buflen)
{//log netjoin to channel
  char *c;

  str[len] = 0; /* terminate it */
  c = strrchr (chan->chi->name, '@');
  if (c) *c = 0;
  /* %N - nicklist, %# - channel, %* - netjoin server, %- - time of split */
  printl (buf, buflen, format_irc_netjoin, 0, str, NULL, NULL, chan->chi->name,
	  0L, 0, Time - split->at, NextWord (split->servers));
  if (c) *c = '@';
  Add_Request (I_LOG, chan->chi->name, F_JOIN, "%s", buf);
}


/* --- Netjoin detection ---------------------------------------------------- */

/* sequence:
 *		-> "JOIN"
 * "PING" ->
 *		-> "JOIN" ... "PONG"		: ok (netsplit is over)
 *		-> "402" (no such server)	: fake (nick is reconnected)
 *		-> server modechange		: ok
 *		-> something... "402"		: fake
 *		-> timeout...			: unknown but assume it's fake
 *		-> something... "PONG"		: ok but we already decided fake
 *		-> ... "PONG"			: destroy netsplit
 *		-> ... "402"			: assume all fake
 */

static void _ircch_netsplit_add (net_t *net, char *servers, nick_t *nick)
{ // add to list
  netsplit_t *split;
  netsplit_t **tmp = &net->splits;
  link_t *link;

  if (nick->split)				/* it's already in split! */
    return;
  while ((split = *tmp))
  {
    if (split->ping == 1 && !strcmp (servers, split->servers)) /* opened */
      break;
    tmp = &split->next;
  }
  if (!split)
  {
    *tmp = split = safe_malloc (sizeof(netsplit_t));
    split->servers = safe_strdup (servers);
    split->at = Time;
    split->ping = 1;
    split->next = NULL;
    split->nicks = NULL;
  }
  for (link = nick->channels; link; link = link->prevchan)
    link->mode = 0;
  Insert_Key (&split->nicks, nick->name, nick, 0);
  nick->split = split;
}

static void _ircch_netsplit_remove (nick_t *nick)
{ // remove from list
  if (!nick->split)
    return;
  Delete_Key (nick->split->nicks, nick->name, nick);
  nick->split = NULL;
}

static void _ircch_netsplit_islost (link_t *link, char *nuh, char *atuh,
				    userflag uf, userflag cf)
{
  binding_t *bind;
  char buf[MESSAGEMAX];

  if (atuh) *atuh = 0;
  /* run script bindings */
  for (bind = NULL; (bind = Check_Bindtable (BT_IrcSignoff, nuh, uf, cf,
					     bind)); )
    if (bind->name)
      RunBinding (bind, nuh, link->nick->lname ? link->nick->lname : "*",
		   link->chan->chi->name, -1, link->nick->split->servers);
  /* %N - nick, %@ - user@host, %L - Lname, %# - channel@net, %* - servers */
  printl (buf, sizeof(buf), format_irc_lostinnetsplit, 0,
	  nuh, atuh ? &atuh[1] : NULL, link->nick->lname, link->chan->chi->name,
	  0, 0, 0, link->nick->split->servers);
  Add_Request (I_LOG, link->chan->chi->name, F_WARN, "%s", buf);
  if (atuh) *atuh = '!';
}

static void _ircch_netsplit_gotuser (net_t *net, nick_t *nick, userflag uf)
{ // change user from njoin to join
  link_t *link;
  char *c;

  if (nick && nick->split)
  {
    c = safe_strchr (nick->host, '!');
    for (link = nick->channels; link; link = link->prevchan)
    {
      userflag cf = Get_Clientflags (nick->lname, link->chan->chi->name);

      if (IS_INSPLIT(link))			/* lost in netsplit! */
	_ircch_netsplit_islost (link, nick->host, c, uf, cf);
      else					/* just joined a channel */
	_ircch_joined (link, nick->host, c, uf, cf, NULL);
    }
    _ircch_netsplit_remove (nick);
  }
}

static void _ircch_netsplit_noserver (net_t *net, netsplit_t *split)
{ // keep split, all already joined users change from njoin to join
  LEAF *l, *pl;
  char *c;
  nick_t *nick;
  link_t *link;

  for (pl = NULL; (l = Next_Leaf (split->nicks, pl, &c)); )
  {
    nick = l->s.data;
    for (link = nick->channels; link; link = link->prevchan)
      if (!IS_INSPLIT(link))
      {
	_ircch_netsplit_gotuser (net, nick,
				 Get_Clientflags (nick->lname, net->name));
	break;
      }
    if (!link)
      pl = l;
  }
  split->ping = 0;
}

static void _ircch_netsplit_over (net_t *net, netsplit_t **ptr)
{ // all users got njoin or lost in netsplit
  netsplit_t *split;
  LEAF *l;
  link_t *link;
  binding_t *bind;
  char *c;

  if (!ptr || !*ptr)
    return;						/* hmm.... */
  split = *ptr;
  *ptr = split->next;
  /* drop all channels if got netsplit right now */
  if (split->ping == 1)
    _ircch_netsplit_log (net, split);
  /* scan all for rejoined and log */
  l = NULL;
  while ((l = Next_Leaf (net->channels, l, NULL)))
  {
    char str[MESSAGEMAX];
    char buf[STRING];
    size_t s = 0, nl;
    clrec_t *u;
    userflag uf, cf;

    for (link = ((ch_t *)l->s.data)->nicks; link; link = link->prevnick)
    {
      if (link->nick->split != split || link->mode == 0)
	continue;
      /* add to list for logging */
      c = strchr (link->nick->host, '!');
      if (c)
	nl = c - link->nick->host;
      else
	nl = strlen (link->nick->host);
      if (s + nl >= sizeof(buf))
      {
	_ircch_netjoin_log (split, link->chan, buf, s, str, sizeof(str));
	s = 0;
	if (nl >= sizeof(buf))
	  nl = sizeof(buf) - 1;
      }
      if (s)
	buf[s++] = ',';
      memcpy (&buf[s], link->nick->host, nl);
      s += nl;			/* s < sizeof(buf) */
      /* run all bindings */
      snprintf (str, sizeof(str), "%s %s", link->chan->chi->name,
		link->nick->name);
      if ((u = Lock_Clientrecord (link->nick->name)))
      {
	uf = Get_Flags (u, net->name);
	cf = Get_Flags (u, link->chan->chi->name);
	Unlock_Clientrecord (u);
      }
      else
	uf = cf = 0;
      for (bind = NULL; (bind = Check_Bindtable (BT_IrcNJoin, str, uf, cf,
						 bind)); )
      {
	if (bind->name)
	  RunBinding (bind, link->nick->host,
		      link->nick->lname ? link->nick->lname : "*",
		      link->chan->chi->name, -1, NULL);
	else
	  bind->func (link->nick->host, link->nick->lname, link->chan->chi);
      }
    }
    if (s)
      _ircch_netjoin_log (split, link->chan, buf, s, str, sizeof(str));
  }
  /* scan all for lost and log quits */
  l = NULL;
  while ((l = Next_Leaf (split->nicks, l, &c)))
  {
    nick_t *nick = l->s.data;
    userflag uf;

    if (!nick || (nick->channels && !IS_INSPLIT(nick->channels)))
      continue;
    uf = Get_Clientflags (nick->lname, net->name);
    /* run internal bindings */
    for (bind = NULL; (bind = Check_Bindtable (BT_IrcSignoff, nick->host,
					       uf, -1, bind)); )
      if (!bind->name)
	bind->func (net->neti, nick->lname, nick->host, split->servers);
    c = strchr (nick->host, '!');
    /* run script bindings and log */
    for (link = nick->channels; link; link = link->prevchan)
      _ircch_netsplit_islost (link, nick->host, c, uf,
			Get_Clientflags (nick->lname, link->chan->chi->name));
    Delete_Key (net->nicks, nick->name, nick);
    _ircch_destroy_nick (nick);
  }
  /* free all allocations */
  FREE (&split->servers);
  Destroy_Tree (&split->nicks, NULL);
  FREE (&split);
}

static void _ircch_netsplit_setping (net_t *net, netsplit_t *split)
{ // send ping to server
  if (split->ping > 1)
    return;
  else if (split->ping)
    _ircch_netsplit_log (net, split);
  New_Request (net->neti, F_QUICK, "PING %s", split->servers);
  split->ping = Time;
}

static void _ircch_netsplit_timeout (net_t *net)
{ // check for timeouts
  netsplit_t *split;
  netsplit_t **tmp = &net->splits;

  while ((split = *tmp))
  {
    if (split->ping == 1 && Time >= split->at + ircch_netsplit_log)
      _ircch_netsplit_log (net, split);
    else if (split->ping && Time >= split->ping + ircch_netsplit_ping)
      _ircch_netsplit_noserver (net, split);
    else if (Time >= split->at + ircch_netsplit_keep)
      _ircch_netsplit_over (net, tmp);
    if (!Next_Leaf (split->nicks, NULL, NULL))
    {
      *tmp = split->next;
      FREE (&split->servers);
      Destroy_Tree (&split->nicks, NULL);
      FREE (&split);
    }
    else
      tmp = &split->next;
  }
}


/* --- Channel manipulation functions --------------------------------------- */

/* sequence:
 * "JOIN" ->
 * 		-> "JOIN"
 *		-> "331" | "332" [ "333" ] (no | topic [topicwhotime])
 *		-> "353" ... "366" (names ... end)
 * "MODE" ->
 *		-> "324" (channel mode)
 * "MODE b" ->
 *		-> "367" ... "368" (ban ... end)
 * "MODE e" ->
 *		-> "348" ... "349" (exempt ... end)
 * "MODE I" ->
 *		-> "346" ... "347" (invite ... end)
 *
 * ...or...
 *		-> "403"|"405"|"407"|"437"|"471"|"473"|"474"|"475" (cannot join)
 */
static void _ircch_join_channel (net_t *net, char *chname)
{
  char *key, *c;
  clrec_t *clr;

  clr = Lock_Clientrecord (chname);
  if (clr)
  {
    key = safe_strdup (Get_Field (clr, "passwd", NULL));
    Unlock_Clientrecord (clr);
  }
  else
    key = NULL;
  c = strrchr (chname, '@');
  if (c) *c = 0;
  if (key)
    New_Request (net->neti, 0, "JOIN %s %s", chname, key);
  else
    New_Request (net->neti, 0, "JOIN %s", chname);
  if (c) *c = '@';
  FREE (&key);
}

static int connect_ircchannel (const char *chname, char *keys)
{
  char *c;
  net_t *net;

  if (!chname || !*chname)
    return 0;				/* invalid request */
  c = strrchr (chname, '@');
  if (!(net = _ircch_get_network (c, 0)))
    return 0;				/* not connected to such network */
  *c = 0; /* network found so it's not NULL */
  if (keys && *keys)
    New_Request (net->neti, 0, "JOIN %s %s", chname, keys);
  else
    New_Request (net->neti, 0, "JOIN %s", chname);
  *c = '@';
  return 1;
}


/* --- Channel interface ---------------------------------------------------- */

/* supported signals: S_TERMINATE, S_SHUTDOWN, S_REPORT */
static iftype_t _ircch_sig (INTERFACE *iface, ifsig_t sig)
{
  char *c;
  net_t *net;
  link_t *link;
  INTERFACE *tmp;

  switch (sig)
  {
    case S_TERMINATE:
      c = strrchr (iface->name, '@');
      net = _ircch_get_network (c, 0);
      if (!net)				/* it's impossible, I think */
	break;
      *c = 0;				/* send PART and wait for server */
      if (ShutdownR)
	New_Request (net->neti, 0, "PART %s :%s", iface->name, ShutdownR);
      else
	New_Request (net->neti, 0, "PART %s", iface->name);
      *c = '@';
      break;
    case S_REPORT:
      c = strrchr (iface->name, '@');
      net = _ircch_get_network (c, 0);
      tmp = Set_Iface (iface);
      for (link = ((ch_t *)iface->data)->nicks; link; link = link->prevnick)
      {
	size_t s;
	char str[MESSAGEMAX];
	char nick[NICKLEN+2];

	if (!(link->mode & ReportMask))
	  continue;
	c = safe_strchr (link->nick->host, '!');
	if (c)
	  s = c++ - link->nick->host;
	else
	  s = safe_strlen (link->nick->host);
	if (s >= sizeof(nick) - 1)
	  s = sizeof(nick) - 2;
	if ((net->features & L_HASADMIN) && (link->mode & A_ADMIN))
	  nick[0] = '!';
	else if (link->mode & (A_OP | A_ADMIN))
	  nick[0] = '@';
	else if (link->mode & A_HALFOP)
	  nick[0] = '%';
	else if (link->mode & A_VOICE)
	  nick[0] = '+';
	else
	  nick[0] = ' ';
	memcpy (&nick[1], link->nick->host, s);
	nick[s+1] = 0;
	printl (str, sizeof(str), ReportFormat, 0, nick, c ? c : NULL,
		link->nick->lname, link->joined, 0, 0, Time - link->activity,
		IS_INSPLIT(link) ? _("is in netsplit") : NULL);
	New_Request (tmp, F_REPORT, "%s", str);
      }
      Unset_Iface();
      break;
    case S_LOCAL:
      c = strrchr (iface->name, '@');
      net = _ircch_get_network (c, 0);
      if (!net)				/* it's impossible, I think */
	break;
      ircch_enforcer (net, (ch_t *)iface->data);
      ((ch_t *)iface->data)->tid = -1;
      break;
    case S_SHUTDOWN:
      /* nothing to do: module will do all itself */
    default:
      break;
  }
  return 0;
}


/* --- Bindings ------------------------------------------------------------- */

/* internal temp interface list receiver */
static int _ircch_servlist (INTERFACE *iface, REQUEST *req)
{
  size_t l = safe_strlen ((char *)iface->data);

  if (l)
    ((char *)iface->data)[l++] = ' ';
  safe_realloc (&iface->data, l + strlen (req->string) + 1);
  strcpy (&((char *)iface->data)[l], req->string);
  return REQ_OK;
}

/*
 * "irc-connected" binding:
 *   - check for autojoins
 */
static void ic_ircch (INTERFACE *network, char *servname, char *nick,
		      char *(*lc) (char *, const char *, size_t))
{
  char mask[NAMEMAX+3];
  net_t *net;
  char *c, *ch;
  INTERFACE *tmp;
  int i;

  net = _ircch_get_network (network->name, 1);
  if (net->me)					/* already registered??? */
    return;
  net->neti = network;
  if (lc)
  {
    lc (mask, nick, sizeof(mask));
    net->me = _ircch_get_nick (net, mask, 1);
  }
  else
    net->me = _ircch_get_nick (net, nick, 1);
  New_Request (network, F_QUICK, "USERHOST %s", nick); /* check it ASAP! */
  mask[0] = '*';
  strfcpy (&mask[1], net->name, sizeof(mask)-1);
  tmp = Add_Iface (NULL, I_TEMP, NULL, &_ircch_servlist, NULL);
  i = Get_Clientlist (tmp, U_SPECIAL, NULL, mask);
  if (i)
  {
    Set_Iface (tmp);
    for (; i; i--)
      Get_Request();
    Unset_Iface();
  }
  c = tmp->data;
  for (c = tmp->data; c && *c; c = ch)
  {
    if ((ch = strchr (c, ' ')))			/* get a token */
      *ch++ = 0;
    if (Get_Clientflags (c, NULL) & U_ACCESS)	/* autojoin found */
      _ircch_join_channel (net, c);
  }
  tmp->ift = I_DIED;
}


/*
 * "irc-disconnected" binding:
 *   - destroy all channels, then all users
 */
static void id_ircch (INTERFACE *network, char *servname, char *nick,
		      char *(*lc) (char *, const char *, size_t))
{
  net_t *net = _ircch_get_network (network->name, 0);

  if (net)
  {
    Delete_Key (IRCNetworks, net->name, net);
    _ircch_destroy_network (net);
  }
  //.......
}


/* internal functions for invite confirmation */
static void ircch_invite_confirm_cleanup (void *inv)
{
  ((invited_t *)inv)->defl = FALSE;
}

static void *ircch_invite_confirm (void *inv)
{
  bool defl = ((invited_t *)inv)->defl;
  char msg[STRING];

  pthread_cleanup_push (&ircch_invite_confirm_cleanup, inv);
  if (defl & ASK)
  {
    snprintf (msg, sizeof(msg), _("%s invited you to %s. Would you like to join"),
	      ((invited_t *)inv)->who, ((invited_t *)inv)->chname);
    defl = Confirm (msg, defl);
  }
  if (defl & TRUE)
  {
    char *c = strrchr (((invited_t *)inv)->chname, '@');

    *c++ = 0;
    Add_Request (I_SERVICE, c, 0, "JOIN %s", ((invited_t *)inv)->chname);
  }
  pthread_cleanup_pop (1);
  return NULL;
}

/*
 * "irc-raw" bindings:
 *  int func (INTERFACE *iface, char *servname, char *mynick, char *prefix,
 *            int parc, char **parv);
 */
static int irc_invite (INTERFACE *iface, char *svname, char *me, char *prefix,
		       int parc, char **parv, char *(*lc) (char *, const char *, size_t))
{/*   Parameters: <nickname> <channel> */
  net_t *net;
  char chname[CHANNAMELEN+NAMEMAX+3];
  userflag cf;

  /* hmm, someone invited me... do I waiting for invitation or ignore it? */
  if (parc < 2 || !(net = _ircch_get_network (iface->name, 0)))
    return -1;		/* it's impossible, I think */
  strfcpy (chname, parv[1], sizeof(chname));
  strfcat (chname, net->name, sizeof(chname));
  if (_ircch_get_channel (net, chname, 0))	/* already joined! */
    return 0;
  cf = Get_Clientflags (chname, NULL);
  if (cf & U_AUTO)				/* it seems it's pending */
  {
    _ircch_join_channel (net, chname);
    return 0;
  }
  if (net->invited)				/* oops, another invite came */
  {
    Add_Request (I_LOG, "*", F_WARN,
		 "another invite (%s) while confirmation, ignored", chname);
    return 0;
  }
  net->invited = safe_malloc (sizeof(invited_t));
  net->invited->chname = safe_strdup (chname);
  net->invited->who = safe_strdup (prefix);
  net->invited->defl = ircch_join_on_invite;
  if (pthread_create (&net->invited->th, NULL, &ircch_invite_confirm,
		      net->invited))
  {
    FREE (&net->invited->chname);
    FREE (&net->invited->who);
    FREE (&net->invited);
  }
  return 0;
}

static int irc_join (INTERFACE *iface, char *svname, char *me, char *prefix,
		     int parc, char **parv, char *(*lc) (char *, const char *, size_t))
{/*   Parameters: <channel> */
  net_t *net;
  ch_t *chan;
  nick_t *nick;
  link_t *link;
  char *ch, *lname;
  userflag uf, cf;
  char lcn[HOSTMASKLEN+1];

  if (!prefix || parc == 0 || !(net = _ircch_get_network (iface->name, 0)))
    return -1;
  if ((ch = safe_strchr (prefix, '!')))
    *ch = 0;
  if (lc)
    lc (lcn, prefix, MBNAMEMAX+1);
  else
    strfcpy (lcn, prefix, MBNAMEMAX+1);
  nick = _ircch_get_nick (net, lcn, 1);
  if (ch)
    *ch = '!';
  /* if it's me then check our invites and continue our join sequence */
  if (nick == net->me)
  {
    if (net->invited && net->invited->defl == 0)
    {
      Unset_Iface();
      pthread_join (net->invited->th, NULL);
      Set_Iface (NULL);
      FREE (&net->invited->chname);
      FREE (&net->invited->who);
      FREE (&net->invited);
    }
    chan = _ircch_get_channel (net, parv[0], 1);
    if (net->features & L_NOUSERHOST)		/* it's slow but what we can? */
      New_Request (iface, 0, "WHO %s", parv[0]);
    New_Request (iface, 0, "MODE %s\r\nMODE %s b\r\nMODE %s e\r\nMODE %s I",
		 parv[0], parv[0], parv[0], parv[0]);
    if (chan->id != ID_REM)
      NewEvent (W_START, chan->id, ID_ME, 0);
    lname = NULL;
    uf = cf = 0;
  }
  else
  {
    size_t s;

    if (!(chan = _ircch_get_channel (net, parv[0], 0)))
      return -1;			/* got JOIN for channel where I'm not! */
    s = strlen (lcn);
    safe_strlower (&lcn[s], ch, sizeof(lcn) - s);
    lname = _ircch_get_lname (lcn, &uf, &cf, net->name, chan->chi->name);
    lcn[s] = 0;				/* prepare it for _ircch_get_link() */
  }
  /* create link, update wtmp */
  link = _ircch_get_link (net, lcn, chan);
  if (nick->split && nick->split->ping == 1)	/* got netsplit just now */
  {
    register char *c = nick->split->servers;

    _ircch_netsplit_remove (nick);
    _ircch_quited (nick, nick->lname, Get_Clientflags (nick->lname, net->name),
		   nick->host, c);		/* assume it was quit */
    link = _ircch_get_link (net, lcn, chan);	/* create new one */
  }
  if (nick->lname && link->chan->id != ID_REM)	/* first try for it */
    NewEvent (W_START, link->chan->id, nick->id, 0);
  _ircch_recheck_link (net, link, lname, uf, cf); /* do rest with lname and wtmp */
  /* check for netjoin and else run bindings */
  link->mode = (nick == net->me) ? A_ME : A_ISON;	/* ~A_INSPLIT */
  if (nick->split)
  {
    if (safe_strcmp (prefix, nick->host))	/* someone with the same nick */
    {
      _ircch_netsplit_remove (nick);
      FREE (&nick->host);
    }
    else					/* it seems netjoin detected */
      _ircch_netsplit_setping (net, nick->split);
  }
  if (!nick->host)
  {
    register char *c = safe_strchr (prefix, '!');

    if (c)
    {
      nick->host = safe_strdup (prefix); /* if server doesn't support USERHOST */
      *c = 0;
    }
    if (!(net->features & L_NOUSERHOST))
      New_Request (net->neti, 0, "USERHOST %s", prefix);
    if (c) *c = '!';
  }
  if (!nick->split)
  {
    _ircch_joined (link, prefix, strchr (prefix, '!'), uf, cf, parv[0]);
    strfcpy (link->joined, DateString, sizeof(link->joined));
  }
  /* check permissions is delayed */
  FREE (&lname);
  return 0;
}

static int irc_kick (INTERFACE *iface, char *svname, char *me, char *prefix,
		     int parc, char **parv, char *(*lc) (char *, const char *, size_t))
{/*   Parameters: <channel> <user> <comment> */
  link_t *link, *tlink;
  net_t *net;
  ch_t *ch;
  nick_t *nt;
  char *lname, *c;
  size_t s;
  binding_t *bind;
  userflag uf, cf;
  char str[MESSAGEMAX];

  if (!prefix || parc < 2 || !(net = _ircch_get_network (iface->name, 0)) ||
      !(ch = _ircch_get_channel (net, parv[0], 0)))	/* alien kick? */
    return -1;
  if (lc)
  {
    lc (str, parv[1], sizeof(str));
    tlink = _ircch_get_link (net, str, ch);
  }
  else
    tlink = _ircch_get_link (net, parv[1], ch);
  if ((c = safe_strchr (prefix, '!')))
    *c = 0;
  if (lc)
    lc (str, prefix, sizeof(str));
  else
    strfcpy (str, prefix, sizeof(str));
  link = _ircch_get_link (net, str, ch);
  if (c)
  {
    *c = '!';
    s = strlen (str);
    safe_strlower (&str[s], c, sizeof(str) - s);
  }
  lname = _ircch_get_lname (str, &uf, &cf, net->name, ch->chi->name);
  /* get op info */
  _ircch_recheck_link (net, link, lname, uf, cf);
  _ircch_netsplit_gotuser (net, link->nick, uf);
  /* update wtmp */
  if (tlink->nick->lname && ch->id != ID_REM)
    NewEvent (W_END, ch->id, tlink->nick->id, tlink->count);
  else if (tlink->nick == net->me && ch->id != ID_REM)
    NewEvent (W_DOWN, ch->id, ID_ME, tlink->count);
  /* run bindings, log it, destroy link... */
  snprintf (str, sizeof(str), "%s %s", ch->chi->name, parv[1]);
  for (bind = NULL; (bind = Check_Bindtable (BT_IrcKick, str, -1, -1, bind)); )
  {
    if (bind->name)
      RunBinding (bind, prefix, lname ? lname : "*", str, -1,
		  parc > 2 ? parv[2] : "");
    else
      bind->func (prefix, lname, ch->chi, parv[1], parv[2]);
  }
  if (c)
    *c = 0;
  /* %N - nick, %@ - user@host, %L - target (!), %# - channel, %* - reason */
  printl (str, sizeof(str), format_irc_kick, 0, prefix, c ? c + 1 : NULL,
	  parv[1], parv[0], 0, 0, 0, parv[2]);
  if (c)
    *c = '!';
  Add_Request (I_LOG, ch->chi->name, F_MODES, "%s", str);
  if (tlink->nick == net->me)
  {
    Delete_Key (net->channels, ch->chi->name, ch);
    _ircch_destroy_channel (ch);
    nt = NULL;
  }
  else
    nt = _ircch_destroy_link (tlink);
  /* destroy nick if no channels left */
  if (nt)
  {
    Delete_Key (net->nicks, nt->name, nt);
    _ircch_destroy_nick (nt);
  }
  FREE (&lname);
  return 0;
}

static int irc_mode (INTERFACE *iface, char *svname, char *me, char *prefix,
		     int parc, char **parv, char *(*lc) (char *, const char *, size_t))
{/*   Parameters: <channel> *( ( "-" / "+" ) *<modes> *<modeparams> ) */
  net_t *net;
  link_t *origin;
  char *c;
  userflag uf, cf;

  if (parc < 2 || !(net = _ircch_get_network (iface->name, 0)))
    return -1;
  /* TODO: do something with own modes? */
  if (!prefix)
    return 0;
  else
  {
    char *lname;
    size_t s;
    char lcn[HOSTMASKLEN+1];
    ch_t *ch;

    if ((c = strchr (prefix, '!')))
      *c = 0;
    if (lc)
      lc (lcn, prefix, MBNAMEMAX+1);
    else
      strfcpy (lcn, prefix, MBNAMEMAX+1);
    if (!(ch = _ircch_get_channel (net, parv[0], 0)) ||
	!(origin = ircch_find_link (net, lcn, ch)))
      return -1;
    if (c)
    {
      *c = '!';
      s = strlen (lcn);
      safe_strlower (&lcn[s], c, sizeof(lcn) - s);
    }
    lname = _ircch_get_lname (lcn, &uf, &cf, net->name, ch->chi->name);
    _ircch_recheck_link (net, origin, lname, uf, cf);
    FREE (&lname);
  }
  /* parse parameters, run bindings */
  if (ircch_parse_modeline (net, origin->chan, origin, prefix, uf, BT_IrcMChg,
			    BT_Keychange, parc - 1, &parv[1], lc))
  /* do logging */
  {
    register int i;
    char mbuf[STRING];
    char buf[MESSAGEMAX];

    strfcpy (mbuf, parv[1], sizeof(mbuf));
    for (i = 2; parv[i]; i++)
    {
      strfcat (mbuf, " ", sizeof(mbuf));
      strfcat (mbuf, parv[i], sizeof(mbuf));
    }
    if (c)
      *c = 0;
    /* %N - nick, %@ - user@host, %L - lname, %# - channel, %* - modeline */
    printl (buf, sizeof(buf), format_irc_modechange, 0, prefix,
	    c ? c + 1 : NULL, origin->nick->lname, parv[0], 0, 0, 0, mbuf);
    Add_Request (I_LOG, origin->chan->chi->name, F_MODES, "%s", buf);
    if (c)
      *c = '!';
  }
  return 0;
}

static int irc_part (INTERFACE *iface, char *svname, char *me, char *prefix,
		     int parc, char **parv, char *(*lc) (char *, const char *, size_t))
{/*   Parameters: <channel> <Part Message> */
  link_t *link;
  net_t *net;
  ch_t *ch;
  nick_t *nt;
  char *lname, *c;
  size_t s;
  userflag uf, cf;
  binding_t *bind;
  char str[MESSAGEMAX];

  if (!prefix || parc == 0 || !(net = _ircch_get_network (iface->name, 0)) ||
      !(ch = _ircch_get_channel (net, parv[0], 0)))
    return -1;
  if ((c = safe_strchr (prefix, '!')))
    *c = 0;
  if (lc)
    lc (str, prefix, sizeof(str));
  else
    strfcpy (str, prefix, sizeof(str));
  link = _ircch_get_link (net, str, ch);
  if (c)
  {
    *c = '!';
    s = strlen (str);
    safe_strlower (&str[s], c, sizeof(str) - s);
  }
  lname = _ircch_get_lname (str, &uf, &cf, net->name, ch->chi->name);
  _ircch_recheck_link (net, link, lname, uf, cf);
  _ircch_netsplit_gotuser (net, link->nick, uf);
  if (!lname)
    cf = uf = 0;
  /* update wtmp */
  if (link->nick->lname && ch->id != ID_REM)
    NewEvent (W_END, ch->id, link->nick->id, link->count);
  else if (link->nick == net->me && ch->id != ID_REM)
    NewEvent (W_DOWN, ch->id, ID_ME, link->count);
  /* run bindings, log it, destroy link... */
  snprintf (str, sizeof(str), "%s %s", ch->chi->name, prefix);
  for (bind = NULL; (bind = Check_Bindtable (BT_IrcPart, str, uf, cf, bind)); )
  {
    if (bind->name)
      RunBinding (bind, prefix, lname ? lname : "*", ch->chi->name, -1, parv[1]);
    else
      bind->func (prefix, lname, ch->chi, parv[1]);
  }
  if ((c = strchr (prefix, '!')))
    *c = 0;
  /* %N - nick, %@ - user@host, %L - lname, %# - channel, %* - message */
  printl (str, sizeof(str), format_irc_part, 0, prefix, c ? c + 1 : NULL,
	  lname, parv[0], 0, 0, 0, parv[1]);
  if (c) *c = '!';
  Add_Request (I_LOG, ch->chi->name, F_JOIN, "%s", str);
  if (link->nick == net->me)
  {
    Delete_Key (net->channels, ch->chi->name, ch);
    _ircch_destroy_channel (ch);
    nt = NULL;
  }
  else
    nt = _ircch_destroy_link (link);
  /* destroy nick if no channels left */
  if (nt)
  {
    Delete_Key (net->nicks, nt->name, nt);
    _ircch_destroy_nick (nt);
  }
  FREE (&lname);
  return 0;
}

static int irc_pong (INTERFACE *iface, char *svname, char *me, char *prefix,
		     int parc, char **parv, char *(*lc) (char *, const char *, size_t))
{/*   Parameters: <me> <server> */
  net_t *net = _ircch_get_network (iface->name, 0);
  netsplit_t **ptr;

  if (!net || !prefix)
    return 0;		/* it's impossible! */
  for (ptr = &net->splits; *ptr; ptr = &(*ptr)->next)
    if (!strcasecmp (prefix, NextWord ((*ptr)->servers)))
      _ircch_netsplit_over (net, ptr);
  return 0;
}

static int irc_topic (INTERFACE *iface, char *svname, char *me, char *prefix,
		      int parc, char **parv, char *(*lc) (char *, const char *, size_t))
{/*   Parameters: <channel> <topic> */
  net_t *net;
  ch_t *ch;
  char *lname, *c;
  size_t s;
  userflag uf, cf;
  link_t *link;
  binding_t *bind;
  char str[MESSAGEMAX];

  if (!prefix || parc == 0 || !(net = _ircch_get_network (iface->name, 0)) ||
      !(ch = _ircch_get_channel (net, parv[0], 0)))
    return -1;		/* it's impossible! */
  if ((c = safe_strchr (prefix, '!')))
    *c = 0;
  if (lc)
    lc (str, prefix, sizeof(str));
  else
    strfcpy (str, prefix, sizeof(str));
  link = _ircch_get_link (net, str, ch);
  if (c)
  {
    *c = '!';
    s = strlen (str);
    safe_strlower (&str[s], c, sizeof(str) - s);
  }
  lname = _ircch_get_lname (str, &uf, &cf, net->name, ch->chi->name);
  _ircch_recheck_link (net, link, lname, uf, cf);
  _ircch_netsplit_gotuser (net, link->nick, uf);
  if (!lname)
    uf = cf = 0;
  /* set structure */
  ircch_remove_mask (&ch->topic, ch->topic);
  if (parv[1] && *parv[1])
    ircch_add_mask (&ch->topic, prefix, safe_strlen (link->nick->name), parv[1]);
  /* run bindings, log it... */
  snprintf (str, sizeof(str), "%s %s", ch->chi->name, parv[1]);
  for (bind = NULL; (bind = Check_Bindtable (BT_IrcTopic, str, uf, cf, bind)); )
  {
    if (bind->name)
      RunBinding (bind, prefix, lname ? lname : "*", ch->chi->name, -1, parv[1]);
    else
      bind->func (prefix, lname, ch->chi, parv[1]);
  }
  if (c)
    *c = 0;
  /* %N - nick, %@ - user@host, %L - lname, %# - channel, %* - topic */
  printl (str, sizeof(str), format_irc_topic, 0, prefix, c ? c + 1 : NULL,
	  lname, parv[0], 0, 0, 0, parv[1]);
  if (c)
    *c = '!';
  Add_Request (I_LOG, ch->chi->name, F_MODES, "%s", str);
  FREE (&lname);
  return 0;
}

static int irc_rpl_userhost (INTERFACE *iface, char *svname, char *me,
			     char *prefix, int parc, char **parv,
			     char *(*lc) (char *, const char *, size_t))
{/* Parameters: :<nick>[*]?=[+-]<hostname>( <nick>[*]?=[+-]<hostname>)* */
  net_t *net;
  nick_t *nick;
  char *c, *cc, *host;
  size_t s;
  char userhost[HOSTMASKLEN+1];

  if (parc == 0 || !(net = _ircch_get_network (iface->name, 0)))
    return -1;		/* it's impossible, tough */
  c = parv[0];
  while (*c)
  {
    for (host = c; *host && *host != '*' && *host != '='; host++);
    s = host - c;
    if (s > NICKLEN)
      s = NICKLEN;
    if(lc)
      lc (userhost, c, s+1);
    else
    {
      memcpy (userhost, c, s);
      userhost[s] = 0;
    }
    nick = _ircch_get_nick (net, userhost, 0);
    c = NextWord (host);
    if (!nick)
      continue;				/* alien request? */
    if (*host == '*')
    {
      nick->umode |= A_OP;		/* IRCOp */
      host++;
    }
    else
      nick->umode &= ~A_OP;
    host++;
    if (*host++ == '+')
      nick->umode |= A_AWAY;
    cc = strchr (host, ' ');
    if (cc) *cc = 0;
    userhost[s++] = '!';
    strfcpy (&userhost[s], host, sizeof(userhost) - s);
    if (cc) *cc = ' ';
    FREE (&nick->host);
    nick->host = safe_strdup (userhost);
  }
  return 0;
}

static int irc_rpl_endofwho (INTERFACE *iface, char *svname, char *me,
			     char *prefix, int parc, char **parv,
			     char *(*lc) (char *, const char *, size_t))
{
  // TODO: show "Join to #XXX was synced in XXX" ?
  return 0;
}

static int irc_rpl_channelmodeis (INTERFACE *iface, char *svname, char *me,
				  char *prefix, int parc, char **parv,
				  char *(*lc) (char *, const char *, size_t))
{/* Parameters: <channel> <mode> <mode params> */
  net_t *net;
  ch_t *ch;

  if (parc < 2 || !(net = _ircch_get_network (iface->name, 0)))
    return 0;		/* it's impossible, I think */
  ch = _ircch_get_channel (net, parv[0], 0);
  if (ch)
    ircch_parse_modeline (net, ch, NULL, prefix, -1, BT_IrcMChg, BT_Keychange,
			  parc - 1, &parv[1], lc);
  return 0;
}

static int irc_rpl_uniqopis (INTERFACE *iface, char *svname, char *me,
			     char *prefix, int parc, char **parv,
			     char *(*lc) (char *, const char *, size_t))
{/* Parameters: <channel> <nickname> */
  net_t *net;
  ch_t *chan;
  link_t *op;
  char lcn[MBNAMEMAX+1];

  if (parc != 2 || !(net = _ircch_get_network (iface->name, 0)))
    return -1;		/* it's impossible, I think */
  chan = _ircch_get_channel (net, parv[0], 0);
  if (chan && lc)
  {
    lc (lcn, parv[1], sizeof(lcn));
    if ((op = _ircch_get_link (net, lcn, chan)))
      op->mode |= A_ADMIN;
  }
  else if (chan && (op = _ircch_get_link (net, parv[1], chan)))
    op->mode |= A_ADMIN;
  return 0;
}

static int irc_rpl_notopic (INTERFACE *iface, char *svname, char *me,
			    char *prefix, int parc, char **parv,
			    char *(*lc) (char *, const char *, size_t))
{/* Parameters: <channel> "No topic is set" */
  net_t *net = _ircch_get_network (iface->name, 0);
  ch_t *ch;

  if (!net || parc == 0)
    return -1;		/* impossible... */
  ch = _ircch_get_channel (net, parv[0], 0);
  if (ch)
    ircch_remove_mask (&ch->topic, ch->topic);
  return 0;
}

static int irc_rpl_topic (INTERFACE *iface, char *svname, char *me,
			  char *prefix, int parc, char **parv,
			  char *(*lc) (char *, const char *, size_t))
{/* Parameters: <channel> <topic> */
  net_t *net = _ircch_get_network (iface->name, 0);
  ch_t *ch;

  if (!net || parc != 2)
    return -1;		/* impossible... */
  ch = _ircch_get_channel (net, parv[0], 0);
  if (ch)
  {
    ircch_remove_mask (&ch->topic, ch->topic);
    if (parv[1] && *parv[1])
      ircch_add_mask (&ch->topic, "", 0, parv[1]);
  }
  return 0;
}

static int irc_rpl_topicwhotime (INTERFACE *iface, char *svname, char *me,
				 char *prefix, int parc, char **parv,
				 char *(*lc) (char *, const char *, size_t))
{/* Parameters: <channel> <by> <unixtime> */
  net_t *net;
  ch_t *ch;
  list_t *topic;

  if (parc != 3 || !(net = _ircch_get_network (iface->name, 0)))
    return -1;		/* it's impossible, I think */
  ch = _ircch_get_channel (net, parv[0], 0);
  if (!ch || !ch->topic)
    return 0;		/* it's impossible, I think */
  topic = ch->topic;
  ch->topic = NULL;
  ircch_add_mask (&ch->topic, parv[1], strlen (parv[1]), topic->what);
  ch->topic->since = strtoul (parv[2], NULL, 10);
  ircch_remove_mask (&topic, topic);
  return 0;
}

static int irc_rpl_invitelist (INTERFACE *iface, char *svname, char *me,
			       char *prefix, int parc, char **parv,
			       char *(*lc) (char *, const char *, size_t))
{/* Parameters: <channel> <invitemask> */
  net_t *net = _ircch_get_network (iface->name, 0);
  ch_t *ch;

  if (!net || parc != 2)
    return -1;		/* impossible... */
  ch = _ircch_get_channel (net, parv[0], 0);
  if (ch)
    ircch_add_mask (&ch->invites, "", 0, parv[1]);
  return 0;
}

static int irc_rpl_exceptlist (INTERFACE *iface, char *svname, char *me,
			       char *prefix, int parc, char **parv,
			       char *(*lc) (char *, const char *, size_t))
{/* Parameters: <channel> <exceptionmask> */
  net_t *net = _ircch_get_network (iface->name, 0);
  ch_t *ch;

  if (!net || parc != 2)
    return -1;		/* impossible... */
  ch = _ircch_get_channel (net, parv[0], 0);
  if (ch)
    ircch_add_mask (&ch->exempts, "", 0, parv[1]);
  return 0;
}

static int irc_rpl_whoreply (INTERFACE *iface, char *svname, char *me,
			     char *prefix, int parc, char **parv,
			     char *(*lc) (char *, const char *, size_t))
{/* Parameters: <channel> <user> <host> <server> <nick> [HG][x]?[*]?[!@%+]?
              :<hopcount> <real name> */	/* G=away x=host *=ircop */
  net_t *net;
  nick_t *nick;
  char *c;
  char userhost[HOSTMASKLEN+1];

  if (parc < 6 || !(net = _ircch_get_network (iface->name, 0)))
    return -1;		/* it's impossible, I think */
  if (lc)
  {
    lc (userhost, parv[4], sizeof(userhost));
    nick = _ircch_get_nick (net, userhost, 0);
  }
  else
    nick = _ircch_get_nick (net, parv[4], 0);
  if (nick && !nick->host)
  {
    snprintf (userhost, sizeof(userhost), "%s!%s@%s", parv[4], parv[1], parv[2]);
    c = parv[5];
    if (*c++ == 'G')
      nick->umode |= A_AWAY;
    if (*c == 'x')
    {
      nick->umode |= A_MASKED;
      c++;
    }
    else
      nick->umode &= ~A_MASKED;
    if (*c == '*')
    {
      nick->umode |= A_OP;	/* IRCOp */
      c++;
    }
    else
      nick->umode &= ~A_OP;
    nick->host = safe_strdup (userhost);
  }
  return 0;
}

static int irc_rpl_namreply (INTERFACE *iface, char *svname, char *me,
			     char *prefix, int parc, char **parv,
			     char *(*lc) (char *, const char *, size_t))
{/* Parameters: "="|"*"|"@" <channel> :[@%+]?<nick>( [@%+]?<nick>)* */
  net_t *net;
  ch_t *chan;
  link_t *link;
  char *c, *cc;
  char nn;
  int i;
  size_t sz, sl;
  char lcn[MBNAMEMAX+1];
  char nicklist[STRING];

  if (parc != 3 || !(net = _ircch_get_network (iface->name, 0)))
    return -1;		/* it's impossible, I think */
  chan = _ircch_get_channel (net, parv[1], 0);
  if (chan)
  {
    i = 0;
    sz = 0;
    for (c = parv[2]; c; c = cc)
    {
      cc = strchr (c, ' ');			/* select a token */
      if (cc) *cc = 0;
      if (*c == '@' || *c == '%' || *c == '+' || *c == '!')
	nn = *c++;				/* check for modechar */
      else
	nn = 0;
      if (lc)
      {
	lc (lcn, c, sizeof(lcn));
	link = _ircch_get_link (net, lcn, chan);	/* create a link */
      }
      else
	link = _ircch_get_link (net, c, chan);
      if (nn == 0);
      else if (nn == '!')			/* update user mode */
	link->mode |= A_ADMIN;
      else if (nn == '@')
	link->mode |= A_OP;
      else if (nn == '%')
	link->mode |= A_HALFOP;
      else
	link->mode |= A_VOICE;
      if (!link->nick->host && !(net->features & L_NOUSERHOST))
      {
	sl = strlen (c);			/* query userhosts */
	if (i == 5 || sz + sl + 1 >= sizeof(nicklist))
	{
	  nicklist[sz] = 0;
	  New_Request (net->neti, 0, "USERHOST %s", nicklist);
	  sz = 0;
	  i = 0;
	  if (sl >= sizeof(nicklist))
	    sl = sizeof(nicklist) - 1;		/* impossible but anyway */
	}
	if (sz)
	  nicklist[sz++] = ' ';
	memcpy (&nicklist[sz], c, sl);
	sz += sl;
      }
      if (cc) *cc++ = ' ';
    }
    if (i)					/* query userhosts */
    {
      nicklist[sz] = 0;
      New_Request (net->neti, 0, "USERHOST %s", nicklist);
    }
  }
  return 0;
}

static int irc_rpl_endofnames (INTERFACE *iface, char *svname, char *me,
			       char *prefix, int parc, char **parv,
			       char *(*lc) (char *, const char *, size_t))
{/* Parameters: <channel> "End of NAMES list" */
  int n, v, h, o;
  net_t *net;
  ch_t *ch;
  link_t *link;

  // show nick stats
  if (!(net = _ircch_get_network (iface->name, 0)) ||
      !(ch = _ircch_get_channel (net, parv[0], 0)))
    return -1;
  n = v = h = o = 0;
  for (link = ch->nicks; link; link = link->prevnick)
    if (link->mode & A_OP)
      o++;
    else if (link->mode & A_HALFOP)
      h++;
    else if (link->mode & A_VOICE)
      v++;
    else
      o++;
  Add_Request (I_LOG, ch->chi->name, F_JOIN,
	       _("-|- %s: %d nicks [%d ops, %d halfops, %d voices, %d normal]"),
	       parv[0], n + v + h + o, o, h, v, n);
  return 0;
}

static int irc_rpl_banlist (INTERFACE *iface, char *svname, char *me,
			    char *prefix, int parc, char **parv,
			    char *(*lc) (char *, const char *, size_t))
{/* Parameters: <channel> <banmask> */
  net_t *net = _ircch_get_network (iface->name, 0);
  ch_t *ch;

  if (!net || parc != 2)
    return -1;		/* impossible... */
  ch = _ircch_get_channel (net, parv[0], 0);
  if (ch)
    ircch_add_mask (&ch->bans, "", 0, parv[1]);
  return 0;
}

static int irc_err_nosuchserver (INTERFACE *iface, char *svname, char *me,
				 char *prefix, int parc, char **parv,
				 char *(*lc) (char *, const char *, size_t))
{/*   Parameters: <server> <text> */
  net_t *net;
  netsplit_t *split;

  if (parc && (net = _ircch_get_network (iface->name, 0)))
    for (split = net->splits; split; split = split->next)
      if (!strcasecmp (parv[0], NextWord (split->servers)))
      {
	_ircch_netsplit_noserver (net, split);
	break;
      }
  return 0;
}

static int irc_err_nosuchchannel (INTERFACE *iface, char *svname, char *me,
				  char *prefix, int parc, char **parv,
				  char *(*lc) (char *, const char *, size_t))
{/* Parameters: <channel> <text> */
  net_t *net = _ircch_get_network (iface->name, 0);
  ch_t *ch;

  if (!net || parc == 0)
    return -1;		/* impossible... */
  if (parv[0][0] == '!')
    /* ERR_NOSUCHCHANNEL for '!channel' - try to create it: "JOIN !!channel" */
    New_Request (iface, 0, "JOIN !%s", parv[0]);
  else if ((ch = _ircch_get_channel (net, parv[0], 0)))
  {
    link_t *link;

    Add_Request (I_LOG, "*", F_WARN,
		 "I think I'm on channel %s but it isn't so!", ch->chi->name);
    if (ch->id != ID_REM)
      for (link = ch->nicks; link; link = link->prevnick)
	if (link->nick == net->me)
	{
	  NewEvent (W_DOWN, ch->id, ID_ME, link->count);
	  break;
	}
    Delete_Key (net->channels, ch->chi->name, ch);
    _ircch_destroy_channel (ch);
  }
  return 0;
}

static int irc_err_unknowncommand (INTERFACE *iface, char *svname, char *me,
				   char *prefix, int parc, char **parv,
				   char *(*lc) (char *, const char *, size_t))
{/* Parameters: <command> <text> */
  net_t *net;

  if (parc == 0 || !(net = _ircch_get_network (iface->name, 0)))
    return -1;
  if (!strcasecmp (parv[0], "USERHOST"))
    net->features |= L_NOUSERHOST;
  return 0;
}

static int irc_err_cannotsendtochan (INTERFACE *iface, char *svname, char *me,
				     char *prefix, int parc, char **parv,
				     char *(*lc) (char *, const char *, size_t))
{/* Parameters: <channel name> "Cannot send to channel" */
  net_t *net;
  ch_t *ch;

  if (parc == 0 || !(net = _ircch_get_network (iface->name, 0)))
    return -1;
  if ((ch = _ircch_get_channel (net, parv[0], 0)))
    Add_Request (I_LOG, ch->chi->name, F_PUBLIC,
		 _("*** cannot send to channel %s"), parv[0]);
  return 0;
}


/*
 * "irc-raw" bindings from "irc" module - script support part
 */
static void ircch_nick (INTERFACE *iface, char *lname, unsigned char *who,
			char *lcon, char *newnick, char *lcnn)
{
  net_t *net;
  nick_t *nick;
  link_t *link;
  userflag uf, cf = 0;
  binding_t *bind;
  char *c;
  char str[MESSAGEMAX];

  if (!(net = _ircch_get_network (iface->name, 0)) ||
      !(nick = _ircch_get_nick (net, lcon, 0)))
    return;		/* it's impossible anyway */
  if (lname)
    uf = Get_Clientflags (lname, net->name);
  else
    uf = 0;
  _ircch_netsplit_gotuser (net, nick, uf);	/* hmm, netsplit isn't over? */
  if ((c = strchr (who, '!')))
    *c = 0;
  /* %N - oldnick, %@ - user@host, %L - lname, %* - newnick */
  printl (str, sizeof(str), format_irc_nickchange, 0, who, c ? c + 1 : NULL,
	  lname, NULL, 0, 0, 0, newnick);
  if (c) *c = '!';
  for (link = nick->channels; link; link = link->prevchan)
  {
    if (lname)
      cf = Get_Clientflags (lname, link->chan->chi->name);
    _ircch_recheck_link (net, link, lname, uf, cf);
    Add_Request (I_LOG, link->chan->chi->name, F_JOIN, "%s", str);
    for (bind = NULL;
		(bind = Check_Bindtable (BT_IrcNChg, newnick, uf, cf, bind)); )
      if (bind->name)
	RunBinding (bind, who, lname ? lname : "*", link->chan->chi->name, -1,
		    newnick);
  }
  FREE (&nick->name);
  nick->name = safe_strdup (lcnn);
}

static void ircch_quit (INTERFACE *iface, char *lname, unsigned char *who,
			char *lcnick, char *msg)
{
  net_t *net;
  nick_t *nick;
  userflag uf;

  if (!(net = _ircch_get_network (iface->name, 0)) ||
      !(nick = _ircch_get_nick (net, lcnick, 0)))
    return;					/* what???!!! who???!!! */
  uf = Get_Clientflags (lname, net->name);
  _ircch_netsplit_gotuser (net, nick, uf);
  _ircch_quited (nick, lname, uf, who, msg);
}

static void ircch_netsplit (INTERFACE *iface, char *lname, unsigned char *who,
			    char *lcnick, char *servers)
{
  net_t *net;
  nick_t *nick;
  link_t *link;
  binding_t *bind;
  userflag uf, cf;

  if (!(net = _ircch_get_network (iface->name, 0)) ||
      !(nick = _ircch_get_nick (net, lcnick, 0)))
    return;					/* what???!!! who???!!! */
  uf = Get_Clientflags (lname, net->name);
  _ircch_netsplit_gotuser (net, nick, uf);	/* re-netsplit! */
  _ircch_netsplit_add (net, servers, nick);
  if (nick->lname)
    nick->id = GetLID (nick->lname);		/* it might be changed */
  for (link = nick->channels; link; link = link->prevchan)
  {
    link->chan->id = GetLID (link->chan->chi->name); /* it might be changed */
    if (nick->lname && link->chan->id != ID_REM) /* ignore new lname! */
      NewEvent (W_END, link->chan->id, nick->id, link->count);
    link->count = 0;
    /* run script bindings */
    cf = Get_Clientflags (lname, link->chan->chi->name);
    for (bind = NULL; (bind = Check_Bindtable (BT_IrcNSplit, who, uf, cf,
					       bind)); )
      if (bind->name)
	RunBinding (bind, who, lname ? lname : "*", link->chan->chi->name, -1, NULL);
  }
  if (safe_strcmp (nick->lname, lname))
  {
    FREE (&nick->lname);
    nick->lname = safe_strdup (lname);
    if (lname)
      nick->id = GetLID (lname);
  }
}


/*
 * "irc-pub-msg-mask" binding
 *   void func (INTERFACE *, char *prefix, char *lname, char *chan@net, char *msg);
 *
 * - do statistics (msg ignored)
 * - check for lname changes and netsplits
 */
static void icmm_ircch (INTERFACE *client, unsigned char *from, char *lname,
			char *unick, char *chan, char *msg)
{
  net_t *net;
  ch_t *ch;
  link_t *link;
  userflag uf, cf;

  if (*chan == '!')	/* it already has no XXXXX part */
    chan++;
  if (!(net = _ircch_get_network (strrchr (chan, '@'), 0)) ||
      !(ch = _ircch_get_channel (net, chan, 0)))
    return;				/* hmm, it's impossible!? */
  link = _ircch_get_link (net, unick, ch);
  if (lname)
  {
    uf = Get_Clientflags (lname, net->name);
    cf = Get_Clientflags (lname, ch->chi->name);
  }
  else
    uf = cf = 0;
  _ircch_recheck_link (net, link, lname, uf, cf);
  link->count++;
  _ircch_netsplit_gotuser (net, link->nick, uf);
}


/*
 * "new-lname" binding
 *   void func (char *newlname, char *oldlname);
 */
static void nl_ircch (char *nl, char *ol)
{
  LEAF *l = NULL;
  nick_t *nick;

  while ((l = Next_Leaf (IRCNetworks, l, NULL)))
  {
    nick = Find_Key (((net_t *)l->s.data)->lnames, ol);
    if (nick)
    {
      Delete_Key (((net_t *)l->s.data)->lnames, nick->lname, nick);
      FREE (&nick->lname);
      nl = safe_strdup (nl);
      Insert_Key (&((net_t *)l->s.data)->lnames, nl, nick, 0);
      for (; nick; nick = nick->prev_TSL)
	nick->lname = nl;
    }
  }
}


/*
 * "ison" binding
 *   int func (const char *net, const char *public, const char *lname,
 *		const char **name);
 */
static int ison_irc (const char *netn, const char *channel, const char *lname,
		     const char **name)
{
  net_t *net;
  nick_t *nick;
  ch_t *ch;
  link_t *link;
  
  if (netn && (net = _ircch_get_network (netn, 0)))
  {
    if (!lname)			/* inspect own nick */
      nick = net->me;
    else			/* inspect other nick visibility */
      nick = Find_Key (net->lnames, lname);
    if (nick && channel)	/* inspect channel presence */
    {
      if ((ch = _ircch_get_channel (net, channel, 0)))
	for (link = nick->channels; link && link->chan != ch; )
	  link = link->prevchan;
      if (!ch || !link)
	nick = NULL;		/* isn't on that channel */
    }
  }
  else
    nick = NULL;
  if (name)
    *name = nick ? nick->name : NULL;
  return nick ? 1 : 0;
}


/*
 * "inspect-client" binding
 *   (modeflag) int func (const char *net, const char *public, const char *name,
 *		const char **lname, const char **host, time_t *idle);
 */
static int incl_irc (const char *netn, const char *channel, const char *name,
		     const char **lname, const char **host, time_t *idle)
{
}


/* --- Script functions ----------------------------------------------------- */


/* --- Common module functions ---------------------------------------------- */

static void module_ircch_regall (void)
{
  /* register module itself */
  Add_Request (I_INIT, "*", F_REPORT, "module irc-channel");
  /* register all variables */
  RegisterInteger ("irc-netsplit-log-timeout", &ircch_netsplit_log);
  RegisterInteger ("irc-netjoin-detect-timeout", &ircch_netsplit_ping);
  RegisterInteger ("irc-netsplit-keep", &ircch_netsplit_keep);
  RegisterInteger ("irc-enforcer-time", &ircch_enforcer_time);
  RegisterBoolean ("irc-join-on-invite", &ircch_join_on_invite);
  //.......
}

static void _ircch_leave_allchannels (void *net)
{
  New_Request (((net_t *)net)->neti, 0, "JOIN 0");
  _ircch_destroy_network (net);
}

static tid_t ircch_tid;

/*
 * this function must receive signals:
 *  S_TERMINATE - unload module,
 *  S_SHUTDOWN - just save statistics ("quit" will do rest),
 *  S_REPORT - out state info to log,
 *  S_REG - [re]register all.
 */
static int module_ircch_signal (INTERFACE *iface, ifsig_t sig)
{
  register LEAF *l1, *l2;

  switch (sig)
  {
    case S_TERMINATE:
      /* unregister all variables and bindings */
      Delete_Binding ("irc-raw", &irc_invite);
      Delete_Binding ("irc-raw", &irc_join);
      Delete_Binding ("irc-raw", &irc_kick);
      Delete_Binding ("irc-raw", &irc_mode);
      Delete_Binding ("irc-raw", &irc_part);
      Delete_Binding ("irc-raw", &irc_pong);
      Delete_Binding ("irc-raw", &irc_topic);
      Delete_Binding ("irc-raw", &irc_rpl_userhost);
      Delete_Binding ("irc-raw", &irc_rpl_endofwho);
      Delete_Binding ("irc-raw", &irc_rpl_channelmodeis);
      Delete_Binding ("irc-raw", &irc_rpl_uniqopis);
      Delete_Binding ("irc-raw", &irc_rpl_notopic);
      Delete_Binding ("irc-raw", &irc_rpl_topic);
      Delete_Binding ("irc-raw", &irc_rpl_topicwhotime);
      Delete_Binding ("irc-raw", &irc_rpl_invitelist);
      Delete_Binding ("irc-raw", &irc_rpl_exceptlist);
      Delete_Binding ("irc-raw", &irc_rpl_whoreply);
      Delete_Binding ("irc-raw", &irc_rpl_namreply);
      Delete_Binding ("irc-raw", &irc_rpl_endofnames);
      Delete_Binding ("irc-raw", &irc_rpl_banlist);
      Delete_Binding ("irc-raw", &irc_err_nosuchserver);
      Delete_Binding ("irc-raw", &irc_err_nosuchchannel);
      Delete_Binding ("irc-raw", &irc_err_unknowncommand);
      Delete_Binding ("irc-raw", &irc_err_cannotsendtochan);
      Delete_Binding ("irc-nickchg", (Function)&ircch_nick);
      Delete_Binding ("irc-signoff", (Function)&ircch_quit);
      Delete_Binding ("irc-netsplit", (Function)&ircch_netsplit);
      Delete_Binding ("irc-pub-msg-mask", (Function)&icmm_ircch);
      Delete_Binding ("irc-connected", (Function)&ic_ircch);
      Delete_Binding ("irc-disconnected", (Function)&id_ircch);
      Delete_Binding ("new-lname", (Function)&nl_ircch);
      Delete_Binding ("connect", &connect_ircchannel);
      /* TODO: remove handlers for "ison" and "inspect-client" */
      //.......
      UnregisterVariable ("irc-netsplit-log-timeout");
      UnregisterVariable ("irc-netjoin-detect-timeout");
      UnregisterVariable ("irc-netsplit-keep");
      UnregisterVariable ("irc-join-on-invite");
      UnregisterVariable ("irc-enforcer-time");
      Delete_Help ("irc-channel");
      KillTimer (ircch_tid);
      /* part all channels in all networks */
      Destroy_Tree (&IRCNetworks, &_ircch_leave_allchannels);
      //.......
      iface->ift |= I_DIED;
      break;
    case S_SHUTDOWN:
      for (l1 = NULL; (l1 = Next_Leaf (IRCNetworks, l1, NULL)); )
	for (l2 = NULL;
	     (l2 = Next_Leaf (((net_t *)l1->s.data)->channels, l2, NULL)); )
	  _ircch_shutdown_channel ((ch_t *)l2->s.data);
      break;
    case S_REG:
      module_ircch_regall();
      break;
    case S_TIMEOUT:
      for (l1 = NULL; (l1 = Next_Leaf (IRCNetworks, l1, NULL)); )
	_ircch_netsplit_timeout ((net_t *)l1->s.data);
      ircch_tid = NewTimer (I_MODULE, "irc-channel", S_TIMEOUT, 1, 0, 0, 0);
      break;
    case S_REPORT:
      //TODO
      //.......
    default:
      break;
  }
  return 0;
}

/*
 * this function called when you load a module.
 * Input: parameters string args - nothing.
 * Returns: address of signals receiver function, NULL if not loaded.
 */
Function ModuleInit (char *args)
{
  /* init all stuff */
  BT_IrcJoin = Add_Bindtable ("irc-join", B_MASK);
  BT_IrcKick = Add_Bindtable ("irc-kick", B_MASK);
  BT_IrcMChg = Add_Bindtable ("irc-modechg", B_MASK);
  BT_IrcNJoin = Add_Bindtable ("irc-netjoin", B_MASK);
  BT_IrcNSplit = Add_Bindtable ("irc-netsplit", B_MATCHCASE); /* always lowercase */
  BT_IrcNChg = Add_Bindtable ("irc-nickchg", B_MATCHCASE); /* always lowercase */
  BT_IrcPart = Add_Bindtable ("irc-part", B_MASK);
  BT_IrcSignoff = Add_Bindtable ("irc-signoff", B_MATCHCASE); /* always lowercase */
  BT_IrcTopic = Add_Bindtable ("irc-topic", B_MASK);
  BT_Keychange = Add_Bindtable ("keychange", B_MASK);
  Add_Binding ("irc-raw", "INVITE", 0, 0, &irc_invite);
  Add_Binding ("irc-raw", "JOIN", 0, 0, &irc_join);
  Add_Binding ("irc-raw", "KICK", 0, 0, &irc_kick);
  Add_Binding ("irc-raw", "MODE", 0, 0, &irc_mode);
  Add_Binding ("irc-raw", "PART", 0, 0, &irc_part);
  Add_Binding ("irc-raw", "PONG", 0, 0, &irc_pong);
  Add_Binding ("irc-raw", "TOPIC", 0, 0, &irc_topic);
  Add_Binding ("irc-raw", "302", 0, 0, &irc_rpl_userhost);
  Add_Binding ("irc-raw", "315", 0, 0, &irc_rpl_endofwho);
  Add_Binding ("irc-raw", "324", 0, 0, &irc_rpl_channelmodeis);
  Add_Binding ("irc-raw", "325", 0, 0, &irc_rpl_uniqopis);
  Add_Binding ("irc-raw", "331", 0, 0, &irc_rpl_notopic);
  Add_Binding ("irc-raw", "332", 0, 0, &irc_rpl_topic);
  Add_Binding ("irc-raw", "333", 0, 0, &irc_rpl_topicwhotime);
  Add_Binding ("irc-raw", "346", 0, 0, &irc_rpl_invitelist);
  Add_Binding ("irc-raw", "348", 0, 0, &irc_rpl_exceptlist);
  Add_Binding ("irc-raw", "352", 0, 0, &irc_rpl_whoreply);
  Add_Binding ("irc-raw", "353", 0, 0, &irc_rpl_namreply);
  Add_Binding ("irc-raw", "366", 0, 0, &irc_rpl_endofnames);
  Add_Binding ("irc-raw", "367", 0, 0, &irc_rpl_banlist);
  Add_Binding ("irc-raw", "402", 0, 0, &irc_err_nosuchserver);
  Add_Binding ("irc-raw", "403", 0, 0, &irc_err_nosuchchannel);
  Add_Binding ("irc-raw", "404", 0, 0, &irc_err_cannotsendtochan);
  Add_Binding ("irc-raw", "421", 0, 0, &irc_err_unknowncommand);
  Add_Binding ("irc-raw", "442", 0, 0, &irc_err_nosuchchannel); /* NOTONCHANNEL */
  Add_Binding ("irc-nickchg", "*", 0, 0, (Function)&ircch_nick);
  Add_Binding ("irc-signoff", "*", 0, 0, (Function)&ircch_quit);
  Add_Binding ("irc-netsplit", "*", 0, 0, (Function)&ircch_netsplit);
  Add_Binding ("irc-pub-msg-mask", "*", 0, 0, (Function)&icmm_ircch);
  Add_Binding ("irc-connected", "*", 0, 0, (Function)&ic_ircch);
  Add_Binding ("irc-disconnected", "*", 0, 0, (Function)&id_ircch);
  Add_Binding ("new-lname", "*", 0, 0, (Function)&nl_ircch);
  Add_Binding ("connect", "irc", -1, U_SPECIAL, &connect_ircchannel); /* no network */
  //.......
  Add_Help ("irc-channel");
  ircch_tid = NewTimer (I_MODULE, "irc-channel", S_TIMEOUT, 1, 0, 0, 0);
  /* set up variables */
  module_ircch_regall();
  format_irc_join = SetFormat ("irc_join",
			       _("-|- %y%N%n(%@) has joined %#"));
  format_irc_part = SetFormat ("irc_part",
			       _("-|- %b%N%b(%@) has left %# (%*)"));
  format_irc_nickchange = SetFormat ("irc_nickchange",
				     _("-|- %b%N%b is now known as %y%*%n"));
  format_irc_quit = SetFormat ("irc_quit",
			       _("-|- %b%N%b(%@) has quit %# (%*)"));
  format_irc_lostinnetsplit = SetFormat ("irc_lost_in_netsplit",
				_("-|- %b%N%b has lost in netsplit (%*)"));
  format_irc_kick = SetFormat ("irc_kick",
			       _("-|- %b%N%b has kicked %L from %# (%*)"));
  format_irc_modechange = SetFormat ("irc_modechange",
				     _("-|- mode/%# (%*) by %b%N%b"));
  format_irc_netsplit = SetFormat ("irc_netsplit",
				   _("-|- netsplit (%*), quits: %N"));
  format_irc_netjoin = SetFormat ("irc_netjoin",
				  _("-|- netsplit of %* over, joins: %N"));
  format_irc_topic = SetFormat ("irc_topic",
				_("-|- %N %?*changed?unset? the topic of %#%?* to: %*??"));
  //.......
  /* TODO: add handlers for "ison" and "inspect-client" */
  //.......
  return (&module_ircch_signal);
}

#if 0
           ERR_BADCHANMASK
           ERR_BADCHANNELKEY
           ERR_BANNEDFROMCHAN
           ERR_CHANNELISFULL               
           ERR_CHANOPRIVSNEEDED
           ERR_INVITEONLYCHAN              
	   ERR_KEYSET
           ERR_NEEDMOREPARAMS              
           ERR_NOCHANMODES                 
           ERR_NORECIPIENT                 
           ERR_NOSUCHNICK
	   ERR_NOTOPLEVEL
	   ERR_RESTRICTED
	   ERR_TOOMANYCHANNELS
           ERR_TOOMANYMATCHES              
           ERR_TOOMANYTARGETS              
           ERR_UNAVAILRESOURCE             
	   ERR_UNKNOWNMODE
           ERR_USERNOTINCHANNEL            
	   ERR_USERONCHANNEL
           ERR_WILDTOPLEVEL                
	   RPL_AWAY
	   RPL_ENDOFBANLIST
	   RPL_ENDOFEXCEPTLIST
	   RPL_ENDOFINVITELIST
           RPL_INVITING                    
           RPL_LIST                        
	   RPL_LISTEND
#endif
