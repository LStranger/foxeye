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
 *   - keeping data of known users
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
static long int ircch_netjoin_log = 6;		/* collect for 6s */
static long int ircch_netsplit_keep = 21600;	/* keep array for 6h */
static bool ircch_join_on_invite = (CAN_ASK | ASK | FALSE); /* ask-no */

long int ircch_enforcer_time = 4;		/* bans enforcer timeout */
long int ircch_ban_keep = 120;			/* keep dynamic bans for 2h */
long int ircch_exempt_keep = 60;
long int ircch_invite_keep = 60;
long int ircch_greet_time = 120;		/* greet if absent for 2min */
long int ircch_mode_timeout = 30;		/* push modes to the same nick */
bool ircch_ignore_ident_prefix = TRUE;

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
    if (!strcmp ((*list)->what, what))
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
  dprint (4, "ircch_add_mask: {%s %s} %s", topic->since, topic->by, topic->what);
  return 1;
}

list_t *ircch_find_mask (list_t *list, char *mask)
{
  while (list)
    if (!strcmp (list->what, mask))
      break;
    else
      list = list->next;
  if (list)
    dprint (4, "ircch_find_mask: {%s %s} %s", list->since, list->by, list->what);
  return list;
}

void ircch_remove_mask (list_t **list, list_t *mask)
{
  while (*list)
    if (*list == mask)
      break;
  if (*list)
    *list = mask->next;
  if (mask)
    dprint (4, "ircch_remove_mask: {%s %s} %s", mask->since, mask->by, mask->what);
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

static net_t *_ircch_get_network (const char *network, int create,
				  char *(*lc) (char *, const char *, size_t))
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
  if ((net = Find_Key (IRCNetworks, netname)))
    net->lc = lc;
  if (net || !create)
    return net;
  net = safe_calloc (1, sizeof (net_t));
  net->name = safe_strdup (netname);
  net->features = L_NOEXEMPTS;		/* set defaults */
  net->maxmodes = 3;
  net->maxbans = 30;
  net->maxtargets = 4;
  net->lc = lc;
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
	c += strlen(IRCPAR_CHANMODES);
	while (*(++c) && *c != ' ')
	  if (*c == 'e')
	    net->features &= ~L_NOEXEMPTS;
	  else if (*c == 'R')
	    net->features |= L_HASREGMODE;
      }
      c = NextWord(c);
    }
    Unlock_Clientrecord (clr);
  }
  if (net->features & L_HASREGMODE)
    net->modechars[0] = 'R';
  Insert_Key (&IRCNetworks, net->name, net, 0);
  dprint (4, "_ircch_get_network: added %s", net->name);
  return net;
}

static net_t *_ircch_get_network2 (const char *network)
{
  char netname[NAMEMAX+2];

  if (!network)
    return NULL;	/* bad request */
  if (network[0] == '@')
    return Find_Key (IRCNetworks, network);
  netname[0] = '@';
  strfcpy (&netname[1], network, sizeof(netname) - 1);
  dprint (4, "_ircch_get_network2: trying %s", netname);
  return Find_Key (IRCNetworks, netname);
}

static iftype_t _ircch_sig (INTERFACE *, ifsig_t);
static int _ircch_req (INTERFACE *, REQUEST *);

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
  dprint (4, "_ircch_get_channel: trying%s %s", create ? "/creating" : "", ch);
  chan = Find_Key (net->channels, ch);
  if (chan || !create)
    return chan;
  chan = safe_calloc (1, sizeof(ch_t));
  chan->chi = Add_Iface (I_SERVICE, ch, &_ircch_sig, &_ircch_req, chan);
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
  NewShedule (I_SERVICE, ch, S_TIMEOUT, "*", "*", "*", "*", "*");
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
  dprint (4, "ircch: destroying channel %s", ((ch_t *)cht)->chi->name);
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
  KillShedule (I_SERVICE, ((ch_t *)cht)->chi->name, S_TIMEOUT,
	       "*", "*", "*", "*", "*");
  FREE (&((ch_t *)cht)->key);
  ((ch_t *)cht)->chi->ift = I_DIED;
  //safe_free (&((ch_t *)cht)->chi->data); /* it's cht, will be freed itself */
}

static nick_t *_ircch_get_nick (net_t *net, const char *lcn, int create)
{
  nick_t *nt;

  nt = Find_Key (net->nicks, lcn);
  if (!nt && create)
  {
    nt = safe_calloc (1, sizeof(nick_t));
    nt->name = safe_strdup (lcn);
    nt->net = net;
    Insert_Key (&net->nicks, nt->name, nt, 0);
  }
  return nt;
}

static char *_ircch_get_lname (char *nuh, userflag *sf, userflag *cf,
			       char *net, char *chan, char **info)
{
  char *c;
  clrec_t *u;

  u = Find_Clientrecord (nuh, &c, sf, net);
  if (u)
  {
    c = safe_strdup (c);
    if (cf)
      *cf = Get_Flags (u, chan);
    if (info)
      *info = safe_strdup (Get_Field (u, "info", NULL));
    Unlock_Clientrecord (u);
    return c;
  }
  if (sf) *sf = 0;
  if (cf) *cf = 0;
  if (info) *info = NULL;
  return NULL;
}

static void _ircch_destroy_nick (void *nt)		/* definition */
{
  dprint (4, "ircch: destroying nick %s", ((nick_t *)nt)->name);
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

  dprint (4, "ircch: destroying network %s", net->name);
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
    Destroy_Tree (&split->channels, NULL);
    FREE (&split);
  }
  FREE (&net);
}

ch_t *ircch_find_service (INTERFACE *service, net_t **netptr)
{
  net_t *net;
  char *c = NULL;	/* to avoid warning */
  
  if (!service || !service->name)
    net = NULL;
  else if ((c = strrchr (service->name, '@')))
    net = _ircch_get_network2 (c);
  else
    net = _ircch_get_network2 (service->name);
  if (netptr)
    *netptr = net;
  if (net && c)
    return Find_Key (net->channels, service->name);
  else
    return NULL;
}

link_t *ircch_find_link (net_t *net, char *lcn, ch_t *ch)
{
  link_t *link;
  nick_t *nt;

  nt = _ircch_get_nick (net, lcn, 0);
  if (nt) for (link = nt->channels; link; link = link->prevchan)
    if (link->chan == ch || !ch)
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
  dprint (4, "ircch: adding %s to %s", lcn, ch->chi->name);
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
  dprint (4, "ircch: removing %s from %s", nick->name, chan->chi->name);
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
				 userflag uf, userflag cf, char *info)
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
    if (!link->nick->lname || link->mode & A_ISON)
      nl = link;
    else for (nl = link->chan->nicks; nl; nl = nl->prevnick)
      if (nl->nick->lname == link->nick->lname)
	break;
    ircch_recheck_modes (net, link, uf, cf, info, nl ? 0 : 1);
  }
  else if (!(link->mode & A_ISON))			/* just joined */
  {
    if (!link->nick->lname)
      nl = link;
    else for (nl = link->chan->nicks; nl; nl = nl->prevnick)
      if (nl->nick->lname == link->nick->lname)
	break;
    ircch_recheck_modes (net, link, uf, cf, info, nl ? 0 : 1);
  }
  dprint (4, "_ircch_recheck_link: success on %s[%ld]", lname, link->nick->id);
  link->activity = Time;
}

static void _ircch_quit_bindings (char *lname, userflag uf, userflag cf,
				  char *who, char *chname, char *msg)
{
  binding_t *bind;

  /* run script bindings */
  for (bind = NULL; (bind = Check_Bindtable (BT_IrcSignoff, who, uf, cf, bind)); )
    if (bind->name)
      RunBinding (bind, who, lname ? lname : "*", chname, -1, msg);
}


/* --- Logging -------------------------------------------------------------- */

/* Logging: join=>part|kick|quit join=>netsplit[=>netjoin|lost] */

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
  dprint (4, "_ircch_joined: %s to %s", link->nick->name, chan);
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
  link_t *link;
  char str[MESSAGEMAX];

  c = strchr (who, '!');
  cc = strchr (nick->host, '!');
  dprint (4, "_ircch_quited: %s (%s)", nick->name, lname);
  for (link = nick->channels; link; link = link->prevchan)
  {
    if (nick->lname && link->chan->id != ID_REM)
      NewEvent (W_END, link->chan->id, nick->id, link->count);
    _ircch_quit_bindings (lname, uf,
			  Get_Clientflags (lname, link->chan->chi->name), who,
			  link->chan->chi->name, msg);
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
 *		-> "JOIN" nick1
 *		-> something from nick1...
 * "LINKS goneserver" ->
 *		-> something from nick2...	: over
 *		-> something from nick...	: unknown, assume it's reconnect
 *		-> "364"			: over
 *		-> "365"			: eighter over or reconnect
 *		-> timeout...			: report it's over
 *		-> something not JOIN on chan	: report it's over
 *
 * stage -1: got netsplit	: : create netsplit
 * stage 0: collect QUITs	: .ping = 1 : wait for timeout (t1) >>1
 * stage 1: yet in netsplit	: .ping = 0 : wait for JOIN >>2
 * stage 2: someone JOINed	: .ping = 2 : wait for RPL_LINKS >>1/3
 * stage 3: RPL_LINKS got	: .ping = t1*1/2 : >>4
 * stage 4: over, collect JOINs	: .ping < t1 : wait then report joined/lost >>5
 * stage 5: wait for timeout	: .ping >= t1 && .ping < t2 : wait then >>6
 * stage 6: all rest are lost	: .ping >= t2 : report lost, destroy netsplit
 *
 * nick->mode is ~A_ISON in stage 1 and A_ISON+ in other stages
 */

static void _ircch_netsplit_add (net_t *net, char *servers, nick_t *nick)
{ // add to list
  netsplit_t *split;
  netsplit_t **tmp = &net->splits;
  link_t *link;

  if (nick->split)				/* it's already in split! */
    return;
  dprint (4, "_ircch_netsplit_add for %s: %s", nick->name, servers);
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
    split->ping = 1;
    split->next = NULL;
    split->nicks = NULL;
    split->channels = NULL;
    split->lastch = NULL;
  }
  split->at = Time;
  for (link = nick->channels; link; link = link->prevchan)
  {
    link->mode = 0;
    Insert_Key (&split->channels, link->chan->chi->name, link->chan, 1);
  }
  nick->umode &= ~A_ISON;
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

static netsplit_t *_ircch_netsplit_find (net_t *net, const char *server)
{
  netsplit_t *split;

  for (split = net->splits; split; split = split->next)
    if (!strcasecmp (server, NextWord(split->servers)))
      return split;
  return NULL;
}

static void _ircch_netsplit_islost (link_t *link, char *nuh, char *atuh,
				    userflag uf, userflag cf)
{
  char buf[MESSAGEMAX];

  _ircch_quit_bindings (link->nick->lname, uf, cf, nuh,	link->chan->chi->name,
			link->nick->split->servers);
  if (atuh) *atuh = 0;
  /* %N - nick, %@ - user@host, %L - Lname, %# - channel@net, %* - servers */
  printl (buf, sizeof(buf), format_irc_lostinnetsplit, 0,
	  nuh, atuh ? &atuh[1] : NULL, link->nick->lname, link->chan->chi->name,
	  0, 0, 0, link->nick->split->servers);
  Add_Request (I_LOG, link->chan->chi->name, F_WARN, "%s", buf);
  if (atuh) *atuh = '!';
  _ircch_destroy_link (link);
}


static void _ircch_netjoin_gotchan (net_t *net, netsplit_t *split, ch_t *ch)
{ // report eighter lost in netsplit or returned for all nicks in channel
  link_t *link, *link2;
  char *c;
  size_t s = 0, nl;
  clrec_t *u;
  binding_t *bind;
  userflag uf, cf;
  char str[MESSAGEMAX];
  char buf[STRING];

  Delete_Key (split->channels, ch->chi->name, ch);
  dprint (4, "_ircch_netjoin_gotchan: %s", ch->chi->name);
  for (link = ch->nicks; link; link = link->prevnick)
  {
    if (link->nick->split == split && (link->mode & A_ISON)) /* is returned */
    {
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
  }
  if (s)
    _ircch_netjoin_log (split, link->chan, buf, s, str, sizeof(str));
  for (link = ch->nicks; link; link = link2) /* log all who lost in netsplit */
  {
    link2 = link->prevnick;
    if (link->nick->split == split && !(link->mode & A_ISON)) /* is lost */
    {
      c = strchr (link->nick->host, '!');
      if ((u = Lock_Clientrecord (link->nick->name)))
      {
	uf = Get_Flags (u, net->name);
	cf = Get_Flags (u, link->chan->chi->name);
	Unlock_Clientrecord (u);
      }
      else
	uf = cf = 0;
      _ircch_netsplit_islost (link, link->nick->host, c, uf, cf);
    }
  }
}

static void _ircch_netsplit_gotuser (net_t *net, nick_t *nick, link_t *link,
				     userflag uf)
{ // initialise stage 2+
  if (!nick || !nick->split)
    return;
  if (link && !(link->mode & A_ISON))
    WARNING ("_ircch_netsplit_gotuser: %s on %s without JOIN!", nick->name,
	     link->chan->chi->name);
  else
    dprint (4, "_ircch_netsplit_gotuser: %s on %s", nick->name,
	    link ? link->chan->chi->name : (uchar *)net->name);
  if (!(nick->umode & A_ISON))
  {
    if (nick->split->ping == 1)		/* netsplit wasn't even reported yet */
      _ircch_netsplit_log (net, nick->split);
    if (nick->split->ping == 0)		/* OK, we are in stage 1 */
    {
      New_Request (net->neti, F_QUICK, "LINKS %s",
		   NextWord(nick->split->servers));
      nick->split->ping = 2;
    }
    else				/* stage 2...4 - continue at stage 4 */
    {
      nick->split->ping = Time;
      if (!link && nick->split->lastch)	/* ah, it's not join! goto stage 5 */
	_ircch_netjoin_gotchan (net, nick->split, nick->split->lastch);
    }
    nick->umode |= A_ISON;
  }
  if (link)
  {
    if ((link->chan != nick->split->lastch))
    {
      if (nick->split->lastch)		/* end of server's NJOIN */
	_ircch_netjoin_gotchan (net, nick->split, nick->split->lastch);
      nick->split->lastch = link->chan;
    }
    else if (link->mode & A_ISON)	/* ah, it's not join! goto stage 5 */
      _ircch_netjoin_gotchan (net, nick->split, link->chan);
  }
}

static void _ircch_netsplit_isnt_over (net_t *net, netsplit_t *split)
{ // keep split, already joined user change from njoin to join
  LEAF *l;
  userflag uf, cf;
  nick_t *nick;
  link_t *link, *link2;

  for (l = NULL; (l = Next_Leaf (split->nicks, l, NULL)); )
  {
    nick = l->s.data;
    if (nick->umode & A_ISON)
      break;
  }
  if (l)
  {
    dprint (4, "_ircch_netsplit_isnt_over: have %s", nick->name);
    uf = Get_Clientflags (nick->lname, net->name);
    _ircch_netsplit_remove (nick);
    for (link = nick->channels; link; link = link2)
    {
      link2 = link->prevchan;
      cf = Get_Clientflags (nick->lname, link->chan->chi->name);
      _ircch_quit_bindings (nick->lname, uf, cf, nick->host,
			    link->chan->chi->name, split->servers);
      if (link->mode & A_ISON)
	_ircch_joined (link, nick->host, safe_strchr (nick->host, '!'), uf, cf,
		       link->chan->chi->name);
      else
	_ircch_destroy_link (link);
    }
  }
  split->ping = 0;
}

static void _ircch_netsplit_is_over (net_t *net, netsplit_t **ptr)
{ // all users got njoin or lost in netsplit
  netsplit_t *split;
  LEAF *l;
  nick_t *nick;

  if (!ptr || !*ptr)
    return;						/* hmm, I'm dumb.... */
  split = *ptr;
  *ptr = split->next;
  dprint (4, "_ircch_netsplit_is_over: %s", split->channels);
  /* drop all channels if got netsplit right now */
  if (split->ping == 1)
    _ircch_netsplit_log (net, split);
  /* scan all for rejoined and log */
  while ((l = Next_Leaf (split->channels, NULL, NULL)))
    _ircch_netjoin_gotchan (net, split, l->s.data);
  /* scan for gone nicks */
  while ((l = Next_Leaf (split->nicks, NULL, NULL)))
  {
    nick = l->s.data;
    _ircch_netsplit_remove (nick);
    if (nick->channels == NULL)
      _ircch_destroy_nick (nick);
  }
  /* free all allocations */
  FREE (&split->servers);
  Destroy_Tree (&split->nicks, NULL);
  Destroy_Tree (&split->channels, NULL);
  FREE (&split);
}

static void _ircch_netsplit_timeout (net_t *net)
{ // check for timeouts
  netsplit_t *split;
  netsplit_t **tmp = &net->splits;

  while ((split = *tmp))
  {
    if (split->ping == 1 && Time >= split->at + ircch_netsplit_log)
      _ircch_netsplit_log (net, split);
    else if (split->ping > 2 && Time >= split->ping + ircch_netjoin_log)
      _ircch_netsplit_is_over (net, tmp);
    else if (Time >= split->at + ircch_netsplit_keep)
      _ircch_netsplit_is_over (net, tmp);
    if (!Next_Leaf (split->nicks, NULL, NULL))
    {
      *tmp = split->next;
      FREE (&split->servers);
      Destroy_Tree (&split->nicks, NULL);
      Destroy_Tree (&split->channels, NULL);
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
  if (!(net = _ircch_get_network2 (c)))
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
      net = _ircch_get_network2 (c);
      if (!net)				/* it's impossible, I think */
      {
	iface->ift = I_DIED;
	break;
      }
      *c = 0;				/* send PART and wait for server */
      if (ShutdownR)
	New_Request (net->neti, 0, "PART %s :%s", iface->name, ShutdownR);
      else
	New_Request (net->neti, 0, "PART %s", iface->name);
      *c = '@';
      /* don't set I_DIED flag because it must be done on request call */
      break;
    case S_REPORT:
      c = strrchr (iface->name, '@');
      net = _ircch_get_network2 (c);
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
		(link->mode & A_ISON) ? NULL : _("is in netsplit"));
	New_Request (tmp, F_REPORT, "%s", str);
      }
      Unset_Iface();
      break;
    case S_LOCAL:
      net = _ircch_get_network2 (strrchr (iface->name, '@'));
      if (!net)				/* it's impossible, I think */
	break;
      ircch_enforcer (net, (ch_t *)iface->data);
      ((ch_t *)iface->data)->tid = -1;
      break;
    case S_TIMEOUT:
      net = _ircch_get_network2 (strrchr (iface->name, '@'));
      ircch_expire (net, (ch_t *)iface->data);
      break;
    case S_SHUTDOWN:
      /* nothing to do: module will do all itself */
    default: ;
  }
  return 0;
}

static int _ircch_req (INTERFACE *iface, REQUEST *req)
{
  net_t *net;

  net = _ircch_get_network2 (strrchr (iface->name, '@'));
  if (net)
    _ircch_netsplit_timeout (net);
  if (!req)
    return REQ_OK;
  req->mask_if = I_CLIENT;
  return REQ_RELAYED;
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

  net = _ircch_get_network (network->name, 1, lc);
  if (net->me)					/* already registered??? */
  {
    WARNING ("ircch: got duplicate connection to %s", network->name);
    return;
  }
  net->neti = network;
  if (lc)
  {
    lc (mask, nick, sizeof(mask));
    net->me = _ircch_get_nick (net, mask, 1);
  }
  else
    net->me = _ircch_get_nick (net, nick, 1);
  net->me->umode = A_ME;
  New_Request (network, F_QUICK, "USERHOST %s", nick); /* check it ASAP! */
  mask[0] = '*';
  strfcpy (&mask[1], net->name, sizeof(mask)-1);
  tmp = Add_Iface (I_TEMP, NULL, NULL, &_ircch_servlist, NULL);
  i = Get_Clientlist (tmp, U_SPECIAL, NULL, mask);
  if (i)
  {
    Set_Iface (tmp);
    for (; i; i--)
      Get_Request();
    Unset_Iface();
  }
  c = tmp->data;
  DBG ("ircch: connected to %s, known channels: %s", network->name, NONULL(c));
  for ( ; c && *c; c = ch)
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
  net_t *net = _ircch_get_network2 (network->name);

  if (net)
  {
    Delete_Key (IRCNetworks, net->name, net);
    _ircch_destroy_network (net);
  }
  else
    WARNING ("ircch: disconnected from unknown network %s", network->name);
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
  if (parc < 2 || !(net = _ircch_get_network (iface->name, 0, lc)))
    return -1;		/* it's impossible, I think */
  strfcpy (chname, parv[1], sizeof(chname));
  strfcat (chname, net->name, sizeof(chname));
  if (_ircch_get_channel (net, chname, 0))	/* already joined! */
  {
    Add_Request (I_LOG, net->name, F_SERV,
		 "Got invite request from %s for already joined channel %s",
		 prefix ? prefix : svname, chname);
    return 0;
  }
  cf = Get_Clientflags (chname, NULL);
  if (cf & U_ACCESS)				/* it seems it's pending */
  {
    _ircch_join_channel (net, chname);
    return 0;
  }
  if (net->invited)				/* oops, another invite came */
  {
    WARNING ("another invite (%s) while confirmation, ignored", chname);
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

#define CHECKHOSTEMPTY(n)	if (!n->channels) FREE(&n->host)
#define CHECKHOSTSET(n,h)	if (!n->channels) n->host = safe_strdup(h)

static int irc_join (INTERFACE *iface, char *svname, char *me, char *prefix,
		     int parc, char **parv, char *(*lc) (char *, const char *, size_t))
{/*   Parameters: <channel> */
  net_t *net;
  ch_t *chan;
  nick_t *nick;
  link_t *link;
  char *ch, *lname, *r;
  userflag uf, cf;
  char lcn[HOSTMASKLEN+1];

  if (!prefix || parc == 0 || !(net = _ircch_get_network (iface->name, 0, lc)))
    return -1;
  dprint (4, "got JOIN %s for %s", parv[0], prefix);
  if ((ch = safe_strchr (prefix, '!')))
    *ch = 0;
  if (lc)
    lc (lcn, prefix, MBNAMEMAX+1);
  else
    strfcpy (lcn, prefix, MBNAMEMAX+1);
  nick = _ircch_get_nick (net, lcn, 1);
  CHECKHOSTEMPTY (nick);
  if (ch)
  {
    *ch = '!';
    CHECKHOSTSET (nick, prefix);
  }
  if (!nick->host && !(net->features & L_NOUSERHOST))
  {
    if (ch)
      *ch = 0;
    New_Request (net->neti, 0, "USERHOST %s", prefix);
    if (ch)
      *ch = '!';
  }
  /* if it's me then check our invites and continue our join sequence */
  if (nick == net->me)
  {
    if (net->invited && net->invited->defl == FALSE)
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
    lname = r = NULL;
    uf = cf = 0;
  }
  else
  {
    size_t s;

    if (!(chan = _ircch_get_channel (net, parv[0], 0)))
      return -1;			/* got JOIN for channel where I'm not! */
    s = strlen (lcn);
    safe_strlower (&lcn[s], ch, sizeof(lcn) - s);
    lname = _ircch_get_lname (lcn, &uf, &cf, net->name, chan->chi->name, &r);
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
  _ircch_recheck_link (net, link, lname, uf, cf, r); /* do rest with lname and wtmp */
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
      _ircch_netsplit_gotuser (net, nick, link, uf);
  }
  if (!nick->split)
  {
    _ircch_joined (link, prefix, strchr (prefix, '!'), uf, cf, parv[0]);
    strfcpy (link->joined, DateString, sizeof(link->joined));
  }
  /* check permissions is delayed */
  FREE (&lname);
  FREE (&r);
  return 0;
}

static int irc_kick (INTERFACE *iface, char *svname, char *me, char *prefix,
		     int parc, char **parv, char *(*lc) (char *, const char *, size_t))
{/*   Parameters: <channel> <user> <comment> */
  link_t *link, *tlink;
  net_t *net;
  ch_t *ch;
  nick_t *nt;
  char *lname, *c, *r;
  size_t s;
  binding_t *bind;
  userflag uf, cf;
  netsplit_t *split;
  char str[MESSAGEMAX];

  if (!prefix || parc < 2 || !(net = _ircch_get_network (iface->name, 0, lc)) ||
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
  dprint (4, "ircch: got KICK %s from %s on %s", parv[1], str, parv[0]);
  link = _ircch_get_link (net, str, ch);
  if (c)
  {
    *c = '!';
    s = strlen (str);
    safe_strlower (&str[s], c, sizeof(str) - s);
  }
  lname = _ircch_get_lname (str, &uf, &cf, net->name, ch->chi->name, &r);
  /* get op info */
  _ircch_recheck_link (net, link, lname, uf, cf, r);
  _ircch_netsplit_gotuser (net, link->nick, link, uf);
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
    for (split = net->splits; split; split = split->next)
      Delete_Key (split->channels, ch->chi->name, ch);
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
  /* TODO: do revenge? */
  FREE (&lname);
  FREE (&r);
  return 0;
}

static modeflag umode_flags[] = {
    A_OP, A_HALFOP, A_INVISIBLE, A_WALLOP, A_AWAY, A_MASKED, A_RESTRICTED
};
static char umode_chars[] = "oOiwaxR";

static void _ircch_parse_umode (net_t *net, nick_t *me, char *c)
{
  char *sc;
  char mc = 0;
  modeflag mf = 0;

  FOREVER
  {
    if (*c == '+' || *c == '-' || !*c)
    {
      if (mf && mc)
      {
	if (mc == '+')
	  me->umode |= mf;
	else
	  me->umode &= ~mf;
      }
      if (!*c)
	break;
      mc = *c;
      mf = 0;
    }
    else if (*c == 'r')
    {
      if (net->features & L_HASREGMODE)
	mf |= A_REGISTERED;
      else
	mf |= A_RESTRICTED;
    }
    else if ((sc = strchr (umode_chars, *c)))
      mf |= umode_flags[sc-umode_chars];
    c++;
  }
}

static int irc_mode (INTERFACE *iface, char *svname, char *me, char *prefix,
		     int parc, char **parv, char *(*lc) (char *, const char *, size_t))
{/*   Parameters: <channel|me> *( ( "-" / "+" ) *<modes> *<modeparams> ) */
  net_t *net;
  link_t *origin;
  char *c;
  userflag uf, cf;

  if (parc < 2 || !(net = _ircch_get_network (iface->name, 0, lc)))
    return -1;
  dprint (4, "ircch: got MODE for %s", parv[0]);
  if (!prefix)	/* it seems it's my own mode */
  {
    char lcn[MBNAMEMAX+1];
    nick_t *nick;
    int i = 0;

    if (lc)
    {
      lc (lcn, parv[0], sizeof(lcn));
      nick = _ircch_get_nick (net, lcn, 0);
    }
    else
      nick = _ircch_get_nick (net, parv[0], 0);
    if (nick)
      while (++i < parc)
	_ircch_parse_umode (net, nick, parv[i]);
    return 0;
  }
  else
  {
    char *lname, *r;
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
    lname = _ircch_get_lname (lcn, &uf, &cf, net->name, ch->chi->name, &r);
    _ircch_recheck_link (net, origin, lname, uf, cf, r);
    FREE (&lname);
    FREE (&r);
  }
  /* parse parameters, run bindings */
  if (ircch_parse_modeline (net, origin->chan, origin, prefix, uf, BT_IrcMChg,
			    BT_Keychange, parc - 1, &parv[1]))
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
  char *lname, *c, *r;
  size_t s;
  userflag uf, cf;
  binding_t *bind;
  netsplit_t *split;
  char str[MESSAGEMAX];

  if (!prefix || parc == 0 ||
      !(net = _ircch_get_network (iface->name, 0, lc)) ||
      !(ch = _ircch_get_channel (net, parv[0], 0)))
    return -1;
  dprint (4, "ircch: %s PART from %s", prefix, parv[0]);
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
  lname = _ircch_get_lname (str, &uf, &cf, net->name, ch->chi->name, &r);
  _ircch_recheck_link (net, link, lname, uf, cf, r);
  _ircch_netsplit_gotuser (net, link->nick, link, uf);
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
    for (split = net->splits; split; split = split->next)
      Delete_Key (split->channels, ch->chi->name, ch);
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
  /* TODO: implement "+cycle" feature? */
  FREE (&lname);
  FREE (&r);
  return 0;
}

static int irc_topic (INTERFACE *iface, char *svname, char *me, char *prefix,
		      int parc, char **parv, char *(*lc) (char *, const char *, size_t))
{/*   Parameters: <channel> <topic> */
  net_t *net;
  ch_t *ch;
  char *lname, *c, *r;
  size_t s;
  userflag uf, cf;
  link_t *link;
  binding_t *bind;
  char str[MESSAGEMAX];

  if (!prefix || parc == 0 ||
      !(net = _ircch_get_network (iface->name, 0, lc)) ||
      !(ch = _ircch_get_channel (net, parv[0], 0)))
    return -1;		/* it's impossible! */
  dprint (4, "ircch: got TOPIC for %s", parv[0]);
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
  lname = _ircch_get_lname (str, &uf, &cf, net->name, ch->chi->name, &r);
  _ircch_recheck_link (net, link, lname, uf, cf, r);
  _ircch_netsplit_gotuser (net, link->nick, link, uf);
  /* set structure */
  ircch_remove_mask (&ch->topic, ch->topic);
  if (parv[1]) /* save it even if it's empty */
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
  FREE (&r);
  return 0;
}

static int irc_rpl_userhost (INTERFACE *iface, char *svname, char *me,
			     char *prefix, int parc, char **parv,
			     char *(*lc) (char *, const char *, size_t))
{/* Parameters: :<nick>[*]?=[+-]<hostname>( <nick>[*]?=[+-]<hostname>)* */
  net_t *net;
  nick_t *nick;
  char *c, *cc, *host;
  char ch;
  size_t s;
  char userhost[HOSTMASKLEN+1];

  if (parc == 0 || !(net = _ircch_get_network (iface->name, 0, lc)))
    return -1;		/* it's impossible, tough */
  c = parv[0];
  while (*c)
  {
    for (host = c; *host && *host != '*' && *host != '='; host++);
    if ((ch = *host))
      *host = 0;
    if(lc)				/* get it lowcase */
      lc (userhost, c, MBNAMEMAX+1);
    else
      strfcpy (userhost, c, MBNAMEMAX+1);
    nick = _ircch_get_nick (net, userhost, 0);
    if(lc)				/* but we need real nick anyway */
      strfcpy (userhost, c, MBNAMEMAX+1);
    if (ch)
      *host = ch;
    c = NextWord (host);
    if (!nick)
    {
      WARNING ("ircch: unrequested RPL_USERHOST from %s for nick %s",
	       net->name, userhost);
      continue;				/* alien request? */
    }
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
    s = strlen (userhost);
    snprintf (&userhost[s], sizeof(userhost) - s, "!%s", host);
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

static int irc_rpl_umodeis (INTERFACE *iface, char *svname, char *me,
			    char *prefix, int parc, char **parv,
			    char *(*lc) (char *, const char *, size_t))
{/* Parameters: <user mode string> */
  net_t *net;

  if (parc && (net = _ircch_get_network (iface->name, 0, lc)))
    _ircch_parse_umode (net, net->me, parv[0]);
  return 0;
}

static int irc_rpl_channelmodeis (INTERFACE *iface, char *svname, char *me,
				  char *prefix, int parc, char **parv,
				  char *(*lc) (char *, const char *, size_t))
{/* Parameters: <channel> <mode> <mode params> */
  net_t *net;
  ch_t *ch;

  if (parc < 2 || !(net = _ircch_get_network (iface->name, 0, lc)))
    return 0;		/* it's impossible, I think */
  ch = _ircch_get_channel (net, parv[0], 0);
  if (ch)
    ircch_parse_modeline (net, ch, NULL, prefix, -1, BT_IrcMChg, BT_Keychange,
			  parc - 1, &parv[1]);
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

  if (parc != 2 || !(net = _ircch_get_network (iface->name, 0, lc)))
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
  net_t *net = _ircch_get_network (iface->name, 0, lc);
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
  net_t *net = _ircch_get_network (iface->name, 0, lc);
  ch_t *ch;

  if (!net || parc != 2)
    return -1;		/* impossible... */
  dprint (4, "ircch: got TOPIC for %s", parv[0]);
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

  if (parc != 3 || !(net = _ircch_get_network (iface->name, 0, lc)))
    return -1;		/* it's impossible, I think */
  ch = _ircch_get_channel (net, parv[0], 0);
  if (!ch || !ch->topic)
    return -1;		/* it's impossible, I think */
  topic = ch->topic;			/* store it */
  ch->topic = NULL;			/* it will be reset */
  ircch_add_mask (&ch->topic, parv[1], strlen (parv[1]), topic->what);
  ch->topic->since = strtoul (parv[2], NULL, 10);
  ircch_remove_mask (&topic, topic);	/* unalloc stored */
  return 0;
}

static int irc_rpl_invitelist (INTERFACE *iface, char *svname, char *me,
			       char *prefix, int parc, char **parv,
			       char *(*lc) (char *, const char *, size_t))
{/* Parameters: <channel> <invitemask> */
  net_t *net = _ircch_get_network (iface->name, 0, lc);
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
  net_t *net = _ircch_get_network (iface->name, 0, lc);
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
{/* Parameters: <channel> <user> <host> <server> <nick> [HG][x]?[R]?[*]?[!@%+]?
              :<hopcount> <real name> */	/* G=away x=host *=ircop */
  net_t *net;
  nick_t *nick;
  char *c;
  char userhost[HOSTMASKLEN+1];

  if (parc < 6 || !(net = _ircch_get_network (iface->name, 0, lc)))
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
    nick->umode &= ~(A_MASKED | A_RESTRICTED | A_OP);
    for (c = parv[5]; *c; c++)
      switch (*c)
      {
	case 'H':
	  nick->umode &= ~A_AWAY;
	  break;
	case 'G':
	  nick->umode |= A_AWAY;
	  break;
	case 'x':
	  nick->umode |= A_MASKED;
	  break;
	case 'R':
	  nick->umode |= A_RESTRICTED;	/* rusnet-ircd 1.4.x */
	  break;
	case '*':
	  nick->umode |= A_OP;		/* IRCOp */
	default: ;
      }
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

  if (parc != 3 || !(net = _ircch_get_network (iface->name, 0, lc)))
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
{/* Parameters: <channel> "End of /NAMES list" */
  int n, v, h, o;
  net_t *net;
  ch_t *ch;
  link_t *link;

  // show nick stats
  if (!(net = _ircch_get_network (iface->name, 0, lc)) ||
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
      n++;
  Add_Request (I_LOG, ch->chi->name, F_JOIN,
	       _("%s: %d nicks [%d ops, %d halfops, %d voices, %d normal]"),
	       parv[0], n + v + h + o, o, h, v, n);
  return 0;
}

static int irc_rpl_banlist (INTERFACE *iface, char *svname, char *me,
			    char *prefix, int parc, char **parv,
			    char *(*lc) (char *, const char *, size_t))
{/* Parameters: <channel> <banmask> */
  net_t *net = _ircch_get_network (iface->name, 0, lc);
  ch_t *ch;

  if (!net || parc != 2)
    return -1;		/* impossible... */
  ch = _ircch_get_channel (net, parv[0], 0);
  if (ch)
    ircch_add_mask (&ch->bans, "", 0, parv[1]);
  return 0;
}

static int irc_rpl_links (INTERFACE *iface, char *svname, char *me,
			  char *prefix, int parc, char **parv,
			  char *(*lc) (char *, const char *, size_t))
{/* Parameters: <mask> <server> "<hopcount> <server info>" */
  net_t *net = _ircch_get_network (iface->name, 0, lc);
  netsplit_t *split;

  if (!net || parc < 2)
    return -1;		/* impossible... */
  else if (!(split = _ircch_netsplit_find (net, parv[1])))
    return 0;		/* server isn't in split */
  dprint (4, "ircch: got reply for splitted server %s", parv[1]);
  if (split->ping == 2)
    split->ping = Time - ircch_netjoin_log / 2;	/* goto stage 3 */
  if (strcmp (NextWord(split->servers), parv[0]));
    return 0;		/* alien request */
  return 1;
}

static int irc_rpl_endoflinks (INTERFACE *iface, char *svname, char *me,
			       char *prefix, int parc, char **parv,
			       char *(*lc) (char *, const char *, size_t))
{/* Parameters: <mask> "End of /LINKS list" */
  net_t *net = _ircch_get_network (iface->name, 0, lc);
  netsplit_t *split;

  if (!net || parc < 2)
    return -1;		/* impossible... */
  else if (!(split = _ircch_netsplit_find (net, parv[0])))
    return 0;		/* alien request */
  if (split->ping == 2)	/* it's still in stage 2 but netsplit isn't over */
    _ircch_netsplit_isnt_over (net, split);
  return 1;
}

static int irc_err_nosuchchannel (INTERFACE *iface, char *svname, char *me,
				  char *prefix, int parc, char **parv,
				  char *(*lc) (char *, const char *, size_t))
{/* Parameters: <channel> <text> */
  net_t *net = _ircch_get_network (iface->name, 0, lc);
  ch_t *ch;

  if (!net || parc == 0)
    return -1;		/* impossible... */
  if (parv[0][0] == '!')
    /* ERR_NOSUCHCHANNEL for '!channel' - try to create it: "JOIN !!channel" */
    New_Request (iface, 0, "JOIN !%s", parv[0]);
  else if ((ch = _ircch_get_channel (net, parv[0], 0)))
  {
    link_t *link;
    netsplit_t *split;

    WARNING ("I thought I'm on channel %s but I'm not!", ch->chi->name);
    if (ch->id != ID_REM)
      for (link = ch->nicks; link; link = link->prevnick)
	if (link->nick == net->me)
	{
	  NewEvent (W_DOWN, ch->id, ID_ME, link->count);
	  break;
	}
    Delete_Key (net->channels, ch->chi->name, ch);
    for (split = net->splits; split; split = split->next)
      Delete_Key (split->channels, ch->chi->name, ch);
    _ircch_destroy_channel (ch);
  }
  return 0;
}

static int irc_err_unknowncommand (INTERFACE *iface, char *svname, char *me,
				   char *prefix, int parc, char **parv,
				   char *(*lc) (char *, const char *, size_t))
{/* Parameters: <command> <text> */
  net_t *net;

  if (parc == 0 || !(net = _ircch_get_network (iface->name, 0, lc)))
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

  if (parc == 0 || !(net = _ircch_get_network (iface->name, 0, lc)))
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

  if (!(net = _ircch_get_network2 (iface->name)) ||
      !(nick = _ircch_get_nick (net, lcon, 0)))
    return;		/* it's impossible anyway */
  dprint (4, "ircch: nickchange for %s", who);
  if (lname)
    uf = Get_Clientflags (lname, net->name);
  else
    uf = 0;
  _ircch_netsplit_gotuser (net, nick, NULL, uf); /* hmm, netsplit isn't over? */
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
    /* note: we cannot trace if new nick is matched to ban pattern */
    _ircch_recheck_link (net, link, lname, uf, cf, NULL);
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

  if (!(net = _ircch_get_network2 (iface->name)) ||
      !(nick = _ircch_get_nick (net, lcnick, 0)))
    return;					/* what???!!! who???!!! */
  dprint (4, "ircch: quit for %s", who);
  uf = Get_Clientflags (lname, net->name);
  _ircch_netsplit_gotuser (net, nick, NULL, uf);
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

  if (!(net = _ircch_get_network2 (iface->name)) ||
      !(nick = _ircch_get_nick (net, lcnick, 0)))
    return;					/* what???!!! who???!!! */
  uf = Get_Clientflags (lname, net->name);
  _ircch_netsplit_gotuser (net, nick, NULL, uf);	/* re-netsplit! */
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
 * "irc-pub-msg-mask" and "irc-pub-notice-mask" bindings
 *   void func (INTERFACE *, char *prefix, char *lname, char *chan@net, char *msg);
 *
 * - do statistics (msg itself is ignored)
 * - check for lname changes and netsplits
 */
static void icam_ircch (INTERFACE *client, unsigned char *from, char *lname,
			char *unick, char *chan, char *msg)
{
  net_t *net;
  ch_t *ch;
  link_t *link;
  nick_t *nick;
  userflag uf, cf;

  if (!unick || !(net = _ircch_get_network2 (strrchr (chan, '@'))))
    return;				/* hmm, it's impossible!? */
  nick = _ircch_get_nick (net, unick, 1);
  CHECKHOSTEMPTY (nick);
  if (from && strchr (from, '!'))	/* if doesn't set yet */
    CHECKHOSTSET (nick, from);
  if (*chan == '!')	/* it already has no XXXXX part */
    chan++;
  if (!(ch = _ircch_get_channel (net, chan, 0)))
    return;				/* hmm, it's impossible!? */
  for (link = nick->channels; link && link->chan != ch; )
    link = link->prevchan;
  if (lname)
  {
    uf = Get_Clientflags (lname, net->name);
    cf = Get_Clientflags (lname, ch->chi->name);
  }
  else
    uf = cf = 0;
  if (link) 				/* hmm, it may be outside message */
  {
    /* note: we cannot trace if it is matched to ban pattern */
    _ircch_recheck_link (net, link, lname, uf, cf, NULL);
    link->count++;
  }
  _ircch_netsplit_gotuser (net, nick, link, uf);
}


/*
 * unfortunately, we have to parse all private PRIVMSG/NOTICE here too
 * to catch hosts and netjoins
 */
static void ipam_ircch (INTERFACE *client, unsigned char *from, char *lname,
			char *unick, char *msg)
{
  net_t *net;
  nick_t *nick;
  userflag uf;

  if (!unick || !(net = _ircch_get_network2 (strrchr (client->name, '@'))))
    return;				/* hmm, it's impossible!? */
  nick = _ircch_get_nick (net, unick, 1);
  CHECKHOSTEMPTY (nick);
  if (from && strchr (from, '!'))	/* if doesn't set yet */
    CHECKHOSTSET (nick, from);
  if (lname)
    uf = Get_Clientflags (lname, net->name);
  else
    uf = 0;
  _ircch_netsplit_gotuser (net, nick, NULL, uf);
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

  dprint (4, "ircch: ison request for %s on %s@%s", NONULL(lname),
	  NONULL(channel), NONULL(netn));
  if (netn && (net = _ircch_get_network2 (netn)))
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
static int _ircch_is_hostmask (const char *name)
{
  register char *c = strchr (name, '!');

  if (!c || strchr (name, '@') < c)
    return 0;
  return 1;
}

static modeflag incl_irc (const char *netn, const char *channel, const char *name,
			  const char **lname, const char **host, time_t *idle)
{
  net_t *net;
  nick_t *nick = NULL; /* don't need NULL really (see below) but gcc warns me */
  ch_t *ch;
  link_t *link = NULL;
  list_t *list = NULL, *listi, *liste;
  char *uh;
  modeflag mf = 0;
  int n;
  char lcname[HOSTMASKLEN+1];
  
  dprint (4, "ircch: ispect-client request for %s on %s@%s", NONULL(name),
	  NONULL(channel), NONULL(netn));
  /* check all at first */
  if (netn && (net = _ircch_get_network2 (netn)))
  {
    if (!channel)
      ch = NULL;
    else if (!(ch = _ircch_get_channel (net, channel, 0)))
      net = NULL;
    if (net)
    {
      if (!name || _ircch_is_hostmask (name))
	nick = NULL;
      else
      {
	if (net->lc)
	  name = net->lc (lcname, name, sizeof(lcname));
	if (!(nick = _ircch_get_nick (net, name, 0)))
	  net = NULL;
      }
    }
    if (net)
    {
      if (ch)
      {
	if (nick) /* client */
	{
	  list = NULL;
	  for (link = nick->channels; link && link->chan != ch; )
	    link = link->prevchan;
	  if (link)
	    mf = link->mode;
	}
	else if (name) /* hostmask */
	{
	  name = safe_strdup (name);
	  uh = strchr (name, '!');
	  *uh = 0;
	  if (net->lc)
	    net->lc (lcname, name, MBNAMEMAX+1);
	  else
	    strfcpy (lcname, name, MBNAMEMAX+1);
	  n = strlen (lcname);
	  *uh = '!';
	  safe_strlower (&lcname[n], uh, sizeof(lcname) - n);
	  FREE (&name);
	  /* check for exact invite/ban/exception */
	  listi = ircch_find_mask (link->chan->invites, lcname);
	  if (listi) /* ignore bans if found */
	    list = NULL;
	  else
	    list = ircch_find_mask (link->chan->bans, lcname);
	  if (!list) /* ignore excepts if no ban */
	    liste = NULL;
	  else
	    liste = ircch_find_mask (link->chan->exempts, lcname);
	  /* check for matching */
	  if (!listi && !liste && !list)
	  {
	    for (listi = link->chan->invites; listi; listi = listi->next)
	      if (match (listi->what, lcname) > 0)
		break;
	    if (!listi)
	      for (list = link->chan->bans; list; list = list->next)
		if (match (list->what, lcname) > 0)
		  break;
	    if (list)
	      for (liste = link->chan->exempts; liste; liste = liste->next)
		if (match (liste->what, lcname) > 0)
		  break;
	  }
	  if (listi)
	  {
	    list = listi;
	    mf = A_INVITED;
	  }
	  else if (liste)
	  {
	    list = liste;
	    mf = A_EXEMPT;
	  }
	  else if (list)
	    mf = A_DENIED;
	}
	else
	{
	  list = ch->topic;
	  mf = ch->mode;
	}
      }
      else if (nick) /* least idle */
      {
	register link_t *link2;

	for (link2 = link = nick->channels; link2; link2 = link2->prevchan)
	  if (link->activity < link2->activity)
	    link = link2;
	mf = nick->umode;
      }
    }
  }
  /* lname = name/hostmask ? someonelname/(ban|ex|inv)setter : topicsetter
     host = name/hostmask ? someonehost/found(ban|ex|inv) : topic
     idle = name/hostmask ? lastevent/since : topicsince
     return = name/hostmask ? umode/found(ban|ex|inv) : chanmode */
  if (lname)
    *lname = list ? list->by : nick ? nick->lname : NULL;
  if (host)
  {
    if (list)
      *host = list->what;
    else if (nick && (uh = safe_strchr (nick->host, '!')))
      *host = &uh[1];
    else
      *host = NULL;
  }
  if (idle)
    *idle = list ? list->since : link ? link->activity : 0;
  return mf;
}


/* --- Script functions ----------------------------------------------------- */


/* --- Common module functions ---------------------------------------------- */

static void module_ircch_regall (void)
{
  /* register module itself */
  Add_Request (I_INIT, "*", F_REPORT, "module irc-channel");
  /* register all variables */
  RegisterInteger ("irc-netsplit-log-timeout", &ircch_netsplit_log);
  RegisterInteger ("irc-netjoin-log-timeout", &ircch_netjoin_log);
  RegisterInteger ("irc-netsplit-keep", &ircch_netsplit_keep);
  RegisterInteger ("irc-enforcer-time", &ircch_enforcer_time);
  RegisterInteger ("irc-ban-keep", &ircch_ban_keep);
  RegisterInteger ("irc-exempt-keep", &ircch_exempt_keep);
  RegisterInteger ("irc-invite-keep", &ircch_invite_keep);
  RegisterInteger ("irc-greet-time", &ircch_greet_time);
  RegisterInteger ("irc-mode-timeout", &ircch_mode_timeout);
  RegisterBoolean ("irc-join-on-invite", &ircch_join_on_invite);
  RegisterBoolean ("irc-ignore-ident-prefix", &ircch_ignore_ident_prefix);
  //.......
}

static void _ircch_leave_allchannels (void *net)
{
  New_Request (((net_t *)net)->neti, 0, "JOIN 0");
  _ircch_destroy_network (net);
}

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
      Delete_Binding ("irc-raw", &irc_topic);
      Delete_Binding ("irc-raw", &irc_rpl_userhost);
      Delete_Binding ("irc-raw", &irc_rpl_endofwho);
      Delete_Binding ("irc-raw", &irc_rpl_umodeis);
      Delete_Binding ("irc-raw", &irc_rpl_channelmodeis);
      Delete_Binding ("irc-raw", &irc_rpl_uniqopis);
      Delete_Binding ("irc-raw", &irc_rpl_notopic);
      Delete_Binding ("irc-raw", &irc_rpl_topic);
      Delete_Binding ("irc-raw", &irc_rpl_topicwhotime);
      Delete_Binding ("irc-raw", &irc_rpl_invitelist);
      Delete_Binding ("irc-raw", &irc_rpl_exceptlist);
      Delete_Binding ("irc-raw", &irc_rpl_whoreply);
      Delete_Binding ("irc-raw", &irc_rpl_namreply);
      Delete_Binding ("irc-raw", &irc_rpl_links);
      Delete_Binding ("irc-raw", &irc_rpl_endoflinks);
      Delete_Binding ("irc-raw", &irc_rpl_endofnames);
      Delete_Binding ("irc-raw", &irc_rpl_banlist);
      Delete_Binding ("irc-raw", &irc_err_nosuchchannel);
      Delete_Binding ("irc-raw", &irc_err_unknowncommand);
      Delete_Binding ("irc-raw", &irc_err_cannotsendtochan);
      Delete_Binding ("irc-nickchg", (Function)&ircch_nick);
      Delete_Binding ("irc-signoff", (Function)&ircch_quit);
      Delete_Binding ("irc-netsplit", (Function)&ircch_netsplit);
      Delete_Binding ("irc-pub-msg-mask", (Function)&icam_ircch);
      Delete_Binding ("irc-pub-notice-mask", (Function)&icam_ircch);
      Delete_Binding ("irc-priv-msg-mask", (Function)&ipam_ircch);
      Delete_Binding ("irc-priv-notice-mask", (Function)&ipam_ircch);
      Delete_Binding ("irc-connected", (Function)&ic_ircch);
      Delete_Binding ("irc-disconnected", (Function)&id_ircch);
      Delete_Binding ("new-lname", (Function)&nl_ircch);
      Delete_Binding ("connect", &connect_ircchannel);
      Delete_Binding ("ison", &ison_irc);
      Delete_Binding ("inspect-client", (Function)&incl_irc);
      ircch_unset_ss(); /* "ss-irc" bindings */
      //.......
      UnregisterVariable ("irc-netsplit-log-timeout");
      UnregisterVariable ("irc-netjoin-log-timeout");
      UnregisterVariable ("irc-netsplit-keep");
      UnregisterVariable ("irc-join-on-invite");
      UnregisterVariable ("irc-enforcer-time");
      UnregisterVariable ("irc-ban-keep");
      UnregisterVariable ("irc-exempt-keep");
      UnregisterVariable ("irc-invite-keep");
      UnregisterVariable ("irc-greet-time");
      UnregisterVariable ("irc-mode-timeout");
      UnregisterVariable ("irc-ignore-ident-prefix");
      Delete_Help ("irc-channel");
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
    case S_REPORT:
      //TODO
      //.......
    default: ;
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
  CheckVersion;
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
  Add_Binding ("irc-raw", "TOPIC", 0, 0, &irc_topic);
  Add_Binding ("irc-raw", "221", 0, 0, &irc_rpl_umodeis);
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
  Add_Binding ("irc-raw", "364", 0, 0, &irc_rpl_links);
  Add_Binding ("irc-raw", "365", 0, 0, &irc_rpl_endoflinks);
  Add_Binding ("irc-raw", "366", 0, 0, &irc_rpl_endofnames);
  Add_Binding ("irc-raw", "367", 0, 0, &irc_rpl_banlist);
  Add_Binding ("irc-raw", "403", 0, 0, &irc_err_nosuchchannel);
  Add_Binding ("irc-raw", "404", 0, 0, &irc_err_cannotsendtochan);
  Add_Binding ("irc-raw", "421", 0, 0, &irc_err_unknowncommand);
  Add_Binding ("irc-raw", "442", 0, 0, &irc_err_nosuchchannel); /* NOTONCHANNEL */
  Add_Binding ("irc-nickchg", "*", 0, 0, (Function)&ircch_nick);
  Add_Binding ("irc-signoff", "*", 0, 0, (Function)&ircch_quit);
  Add_Binding ("irc-netsplit", "*", 0, 0, (Function)&ircch_netsplit);
  Add_Binding ("irc-pub-msg-mask", "*", 0, 0, (Function)&icam_ircch);
  Add_Binding ("irc-pub-notice-mask", "*", 0, 0, (Function)&icam_ircch);
  Add_Binding ("irc-priv-msg-mask", "*", 0, 0, (Function)&ipam_ircch);
  Add_Binding ("irc-priv-notice-mask", "*", 0, 0, (Function)&ipam_ircch);
  Add_Binding ("irc-connected", "*", 0, 0, (Function)&ic_ircch);
  Add_Binding ("irc-disconnected", "*", 0, 0, (Function)&id_ircch);
  Add_Binding ("new-lname", "*", 0, 0, (Function)&nl_ircch);
  Add_Binding ("connect", "irc", -1, U_SPECIAL, &connect_ircchannel); /* no network */
  Add_Binding ("ison", "irc", 0, 0, &ison_irc);
  Add_Binding ("inspect-client", "irc", 0, 0, (Function)&incl_irc);
  ircch_set_ss(); /* "ss-irc" bindings */
  //.......
  Add_Help ("irc-channel");
  /* set up variables */
  module_ircch_regall();
  format_irc_join = SetFormat ("irc_join",
			       _("%y%N%n(%@) has joined %#"));
  format_irc_part = SetFormat ("irc_part",
			       _("%b%N%b(%@) has left %# (%*)"));
  format_irc_nickchange = SetFormat ("irc_nickchange",
				     _("%b%N%b is now known as %y%*%n"));
  format_irc_quit = SetFormat ("irc_quit",
			       _("%b%N%b(%@) has quit %# (%*)"));
  format_irc_lostinnetsplit = SetFormat ("irc_lost_in_netsplit",
				_("%b%N%b has lost in netsplit (%*)"));
  format_irc_kick = SetFormat ("irc_kick",
			       _("%b%N%b has kicked %L from %# (%*)"));
  format_irc_modechange = SetFormat ("irc_modechange",
				     _("mode/%# (%*) by %b%N%b"));
  format_irc_netsplit = SetFormat ("irc_netsplit",
				   _("netsplit (%*), quits: %N"));
  format_irc_netjoin = SetFormat ("irc_netjoin",
				  _("netsplit of %* over, joins: %N"));
  format_irc_topic = SetFormat ("irc_topic",
				_("%N %?*changed?unset? the topic of %#%?* to: %*??"));
  //.......
  return ((Function)&module_ircch_signal);
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
           RPL_NOSUCHSERVER
#endif
