/*
 * Copyright (C) 2005-2010  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 *   - tracking identification
 *
 * Network: IRC. Where: client. Service: channels.
 *
 * Note: flood protection placed in the other module.
 */

#include "foxeye.h"
#include "modules.h"

#include "tree.h"
#include "wtmp.h"
#include "init.h"
#include "sheduler.h"
#include "direct.h"
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
static long int ircch_netjoin_log = 20;		/* collect for 20s */
static long int ircch_netsplit_keep = 21600;	/* keep array for 6h */
static bool ircch_join_on_invite = (CAN_ASK | ASK | FALSE); /* ask-no */
static bool ircch_kick_on_revenge = FALSE;

long int ircch_enforcer_time = 4;		/* bans enforcer timeout */
long int ircch_ban_keep = 120;			/* keep dynamic bans for 2h */
long int ircch_greet_time = 120;		/* greet if absent for 2min */
long int ircch_mode_timeout = 4;		/* push modes to the same nick */
bool ircch_ignore_ident_prefix = TRUE;
char ircch_default_kick_reason[120] = "requested";

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
static char *format_irc_topic_is;
static char *format_irc_topic_by;

static iftype_t _ircch_sig (INTERFACE *, ifsig_t);	/* some declarations */
static int _ircch_req (INTERFACE *, REQUEST *);
static NICK *_ircch_destroy_link (LINK *);
static void _ircch_destroy_nick (void *);


/* --- Internal functions --------------------------------------------------- */

int ircch_add_mask (LIST **list, char *by, size_t sby, char *what)
{
  LIST *topic;

  while (*list)
    if (!strcmp ((*list)->what, what))
      return 0;					/* the same already exist */
    else
      list = &(*list)->next;
  topic = safe_malloc (sizeof(LIST) + safe_strlen (what) + sby + 1);
  topic->next = NULL;
  topic->since = Time;
  memcpy (topic->by, by, sby);
  topic->by[sby] = 0;
  topic->what = &topic->by[sby+1];
  strcpy (topic->what, what);
  *list = topic;
  dprint (4, "ircch_add_mask: {%lu %s} %s", (unsigned long int)topic->since, topic->by, topic->what);
  return 1;
}

LIST *ircch_find_mask (LIST *list, char *mask)
{
  while (list)
    if (!strcmp (list->what, mask))
      break;
    else
      list = list->next;
  if (list)
    dprint (4, "ircch_find_mask: {%lu %s} %s", (unsigned long int)list->since, list->by, list->what);
  return list;
}

void ircch_remove_mask (LIST **list, LIST *mask)
{
  while (*list)
    if (*list == mask)
      break;
    else
      list = &(*list)->next;
  if (*list)
    *list = mask->next;
  if (mask)
    dprint (4, "ircch_remove_mask: {%lu %s} %s", (unsigned long int)mask->since, mask->by, mask->what);
  FREE (&mask);
}

static void _ircch_add_lname (NICK *nick, char *lname)
{
  LEAF *leaf = Find_Leaf (nick->net->lnames, lname, 1);

  if (leaf && nick == leaf->s.data)
  {
    ERROR ("_ircch_add_lname: %s: going loop on %s!", lname, nick->name);
  }
  else if (leaf)
  {
    nick->prev_TSL = leaf->s.data;
    leaf->s.data = nick;
    nick->lname = nick->prev_TSL->lname;
    dprint (4, "_ircch_add_lname: %s: %s <- %s", nick->lname,
	    nick->prev_TSL->name, nick->name);
  }
  else
  {
    nick->prev_TSL = NULL;		/* to prevent errors */
    nick->lname = safe_strdup (lname);
    dprint (4, "_ircch_add_lname: adding %s: %s", nick->lname, nick->name);
    if (Insert_Key (&nick->net->lnames, nick->lname, nick, 1))
      ERROR ("_ircch_add_lname: tree error!");
  }
  DBG ("_ircch_add_lname: set %p", nick->lname);
}

static void _ircch_del_lname (NICK *nick)
{
  LEAF *leaf = Find_Leaf (nick->net->lnames, nick->lname, 1);

  DBG ("_ircch_del_lname: free %p (prev=%p)", nick->lname,
       nick->prev_TSL);
  if (leaf == NULL)
    ERROR ("_ircch_del_lname: tree error, %s not found", nick->lname);
  else if (leaf->s.data == nick)	/* it's last added */
  {
    if (!nick->prev_TSL)		/* last one so delete it */
    {
      dprint (4, "_ircch_del_lname: removing %s", nick->lname);
      if (Delete_Key (nick->net->lnames, nick->lname, nick))
	ERROR ("_ircch_del_lname: tree error");
      FREE (&nick->lname);
      return;
    }
    else
    {
      dprint (4, "_ircch_del_lname: %s: %s", nick->lname, nick->name);
      leaf->s.data = nick->prev_TSL;	/* key is the same so just replace */
    }
  }
  else
  {
    NICK *next_TSL;

    dprint (4, "_ircch_del_lname: %s: %s", nick->lname, nick->name);
    for (next_TSL = leaf->s.data; next_TSL && next_TSL->prev_TSL != nick; )
    {
      DBG ("_ircch_del_lname: skipping %s", next_TSL->name);
      next_TSL = next_TSL->prev_TSL;
    }
    if (next_TSL)
      next_TSL->prev_TSL = nick->prev_TSL;
    else				/* it must be impossible! */
      ERROR ("_ircch_del_lname: nick %s not found in Lname %s", nick->name,
	     nick->lname);
  }
  nick->prev_TSL = NULL;		/* reset cleared fields */
  nick->lname = NULL;
}

static void _ircch_recheck_features (IRC *net)
{
  clrec_t *clr;
  char *c;

  clr = Lock_Clientrecord (&net->name[1]);
  if (clr)
  {
    c = Get_Field (clr, IRCPAR_FIELD, NULL);
    DBG ("parse network parameters: [%s]", c);
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
      else if (!memcmp (c, IRCPAR_UMODES, strlen(IRCPAR_UMODES)) &&
	       c[strlen(IRCPAR_UMODES)] == '=')
      {
	c += strlen(IRCPAR_UMODES);
	while (*(++c) && *c != ' ')
	  if (*c == 'x')
	    net->modechars[2] = 'x';	/* A_MASKED - hidden host */
      }
      c = NextWord(c);
    }
    Unlock_Clientrecord (clr);
  }
  if (net->features & L_HASREGMODE)
    net->modechars[1] = 'R';
}

static IRC *_ircch_get_network (const char *network, int create,
				  size_t (*lc) (char *, const char *, size_t))
{
  char netname[NAMEMAX+2];
  IRC *net;

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
  net = safe_calloc (1, sizeof (IRC));
  net->name = safe_strdup (netname);
  net->features = L_NOEXEMPTS;		/* set defaults */
  net->maxmodes = 3;
  net->maxbans = 30;
  net->maxtargets = 4;
  net->lc = lc;
  if (Insert_Key (&IRCNetworks, net->name, net, 1))
    ERROR ("_ircch_get_network: tree error on adding %s!", net->name);
  else
    dprint (4, "_ircch_get_network: added %s", net->name);
  return net;
}

static IRC *_ircch_get_network2 (const char *network)
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

inline static void _ircch_format_chname (IRC *net, const char *chname,
					 char *ch, size_t s)
{
  ch[0] = chname[0];	/* copy identifier char as is */
  /* TODO: use network-specific lowercase function for channel name too */
  if (chname[0] == '!')	/* skip "!XXXXX" part, short name has to be unique */
    unistrlower (&ch[1], &chname[6], s - 1);
  else
    unistrlower (&ch[1], &chname[1], s - 1);
  strfcat (ch, net->name, s);
}

/* if you provide real then chan will be created */
static CHANNEL *_ircch_get_channel0 (IRC *net, const char *ch, const char *real)
{
  CHANNEL *chan;
  clrec_t *u;

  dprint (4, "_ircch_get_channel: trying%s %s", real ? "/creating" : "", ch);
  chan = Find_Key (net->channels, ch);
  if (chan && chan->id == ID_REM)
    chan->id = FindLID (ch); /* we just got it registered so should update id */
  if (chan || !real)
    return chan;
  _ircch_recheck_features (net);	/* we might get params from server */
  chan = safe_calloc (1, sizeof(CHANNEL));
  chan->chi = Add_Iface (I_SERVICE, ch, &_ircch_sig, &_ircch_req, chan);
  chan->real = safe_strdup (real);
  if ((u = Lock_Clientrecord (ch)))
  {
    register char *modeline = Get_Field (u, "info", NULL);

    if (modeline)
      ircch_parse_configmodeline (net, chan, modeline);
    chan->id = Get_LID (u);
    Unlock_Clientrecord (u);
  }
  chan->tid = -1;
  NewShedule (I_SERVICE, ch, S_TIMEOUT, "*", "*", "*", "*", "*");
  if (Insert_Key (&net->channels, chan->chi->name, chan, 1))
    ERROR ("_ircch_get_channel: tree error!");
  return chan;
}

/* chname has to be real one always, not in form channel@net */
static CHANNEL *_ircch_get_channel (IRC *net, const char *chname, int create)
{
  char ch[CHANNAMELEN+NAMEMAX+3];

  _ircch_format_chname (net, chname, ch, sizeof(ch));
  return _ircch_get_channel0 (net, ch, create ? chname : NULL);
}

static void _ircch_shutdown_channel (CHANNEL *chan)
{
  register size_t i = 0;
  register LINK *link;

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

static void _ircch_destroy_channel (void *cht)
{
  NICK *nt;

  _ircch_shutdown_channel (cht); /* wtmp for all nicks */
  dprint (4, "ircch: destroying channel %s", ((CHANNEL *)cht)->chi->name);
  while (((CHANNEL *)cht)->nicks)
    if ((nt = _ircch_destroy_link (((CHANNEL *)cht)->nicks)))
    {
      dprint (4, "ircch: deleting %s%s", nt->name, nt->net->name);
      if (Delete_Key (nt->net->nicks, nt->name, nt))
	ERROR ("_ircch_destroy_channel: tree error");
      _ircch_destroy_nick (nt);
    }
  ircch_remove_mask (&((CHANNEL *)cht)->topic, ((CHANNEL *)cht)->topic);
  while (((CHANNEL *)cht)->bans)
    ircch_remove_mask (&((CHANNEL *)cht)->bans, ((CHANNEL *)cht)->bans);
  while (((CHANNEL *)cht)->exempts)
    ircch_remove_mask (&((CHANNEL *)cht)->exempts, ((CHANNEL *)cht)->exempts);
  while (((CHANNEL *)cht)->invites)
    ircch_remove_mask (&((CHANNEL *)cht)->invites, ((CHANNEL *)cht)->invites);
  KillTimer (((CHANNEL *)cht)->tid);
  KillShedule (I_SERVICE, ((CHANNEL *)cht)->chi->name, S_TIMEOUT,
	       "*", "*", "*", "*", "*");
  FREE (&((CHANNEL *)cht)->key);
  FREE (&((CHANNEL *)cht)->real);
  ((CHANNEL *)cht)->chi->ift = I_DIED;
  //safe_free (&((CHANNEL *)cht)->chi->data); /* it's cht, will be freed itself */
}

ALLOCATABLE_TYPE (NICK, nick_, prev_TSL) /* alloc_NICK(), free_NICK() */

static NICK *_ircch_get_nick (IRC *net, const char *lcn, int create)
{
  NICK *nt;

  nt = Find_Key (net->nicks, lcn);
  if (!nt && create)
  {
    nt = alloc_NICK();
    memset (nt, 0, sizeof(NICK));		/* empty it now */
    nt->name = safe_strdup (lcn);
    nt->net = net;
    dprint (4, "_ircch_get_nick: adding %s%s [%p]", nt->name, net->name, nt);
    if (Insert_Key (&net->nicks, nt->name, nt, 1))
      ERROR ("_ircch_get_nick: tree error!");
  }
  else
    dprint (4, "_ircch_get_nick: %s: found %s%s", lcn, nt ? nt->name : "<none>",
	    nt ? net->name : "");
  return nt;
}

/* it's nonsence to find Lname on me so don't call! */
static char *_ircch_get_lname (char *nuh, userflag *sf, userflag *cf, lid_t *id,
			       char *net, char *chan, char **info, NICK *nn)
{
  char *c;
  clrec_t *u;

  if (nn && (nn->umode & A_REGISTERED))		/* we know lname aleady! */
  {
    u = Lock_Clientrecord ((c = nn->lname));
    if (u && sf)
      *sf = Get_Flags (u, NULL) | Get_Flags (u, net);
  }
  else						/* search for lname */
    u = Find_Clientrecord (nuh, &c, sf, net);
  if (u)
  {
    c = safe_strdup (c);
    if (cf)
      *cf = Get_Flags (u, chan);
    if (info)
      *info = safe_strdup (Get_Field (u, "info", NULL));
    if (id)
      *id = Get_LID (u);
    Unlock_Clientrecord (u);
    return c;
  }
  if (sf) *sf = 0;
  if (cf) *cf = 0;
  if (info) *info = NULL;
  if (id) *id = ID_REM;
  return NULL;
}

/*
 very important notes:
 1) it DOESN'T remove key from tree, so DO it BEFORE you call _ircch_destroy_nick()!
 2) you cannot use nt structure after this call since it's freed!
 */
static void _ircch_destroy_nick (void *nt)		/* definition */
{
  dprint (4, "ircch: destroying nick %s [%p]", ((NICK *)nt)->name, nt);
  while (((NICK *)nt)->channels)
    _ircch_destroy_link (((NICK *)nt)->channels);
  if (((NICK *)nt)->lname)
    _ircch_del_lname (nt);
  FREE (&((NICK *)nt)->name);
  FREE (&((NICK *)nt)->host);
  free_NICK (nt);
}

ALLOCATABLE_TYPE(SplitMember, SML, next) /* alloc_SplitMember, free_SplitMember */

static void _ircch_destroy_network (IRC *net)
{
  netsplit *split;
  SplitMember *sm;

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
    net->splits = split->prev;
    FREE (&split->servers);
    while (split->members)
    {
      sm = split->members->next;
      free_SplitMember (split->members);
      split->members = sm;
    }
    FREE (&split);
  }
  FREE (&net);
}

CHANNEL *ircch_find_service (const char *service, IRC **netptr)
{
  IRC *net;
  char *c = NULL;	/* to avoid warning */
  
  if (!service)
    net = NULL;
  else if ((c = strrchr (service, '@')))
    net = _ircch_get_network2 (c);
  else
    net = _ircch_get_network2 (service);
  if (netptr)
    *netptr = net;
  if (net && c)
    return Find_Key (net->channels, service);
  else
    return NULL;
}

/* find the link that MIGHT be already on the channel */
LINK *ircch_find_link (IRC *net, char *lcn, CHANNEL *ch)
{
  LINK *link;
  NICK *nt;

  nt = _ircch_get_nick (net, lcn, 0);
  if (nt) for (link = nt->channels; link; link = link->prevchan)
    if (link->chan == ch || !ch)
      return link;
  return NULL;
}

ALLOCATABLE_TYPE (LINK, link_, prevnick) /* alloc_LINK(), free_LINK() */

/* create the link that joined channel (may be after netsplit of course) */
static LINK *_ircch_get_link (IRC *net, char *lcn, CHANNEL *ch)
{
  LINK *link;
  NICK *nt;

  nt = _ircch_get_nick (net, lcn, 1);
  nt->umode |= A_ISON;			/* force it now */
  for (link = nt->channels; link; link = link->prevchan)
    if (link->chan == ch)		/* they might return from netsplit */
      return link;
  link = alloc_LINK();
  dprint (4, "ircch: adding %s to %s [%p]", lcn, ch->chi->name, link);
  link->chan = ch;
  link->prevnick = ch->nicks;
  link->nick = nt;
  link->prevchan = nt->channels;
  link->mode = 0;
  link->count = 0;
  link->lmct = 0;
  ch->nicks = nt->channels = link;
  return link;
}

/* returns nick if it was last channel */
static NICK *_ircch_destroy_link (LINK *link)	/* definition */
{
  CHANNEL *chan;
  NICK *nick;
  LINK **l;

  chan = link->chan;
  nick = link->nick;
  dprint (4, "ircch: removing %s from %s [%p]", nick->name, chan->chi->name, link);
  for (l = &chan->nicks; *l && *l != link; l = &(*l)->prevnick);
  if (*l)
    *l = link->prevnick;
  else
    ERROR ("_ircch_destroy_link: nick %s not found in channel %s", nick->name,
	   chan->chi->name);
  for (l = &nick->channels; *l && *l != link; l = &(*l)->prevchan);
  if (*l)
    *l = link->prevchan;
  else
    ERROR ("_ircch_destroy_link: channel %s not found in joins of nick %s",
	   chan->chi->name, nick->name);
  free_LINK (link);
  if (nick->channels == NULL)
    return nick; /* remove it from tree if called not from _ircch_destroy_nick() */
  return NULL;
}

static void _ircch_update_link (NICK *nick, LINK *link, char *lname, lid_t lid)
{
  LINK *nl;
  short hash;

  /* check if either listfile was changed or client joined first time */
  if (safe_strcmp (lname, nick->lname))
  {
    DBG ("_ircch_update_link: lname change %s -> %s", nick->lname, lname);
    if (nick->lname)			/* only if listfile was changed */
    {
      for (nl = nick->channels; nl; nl = nl->prevchan)
	if (nl->chan->id != ID_REM)
	  NewEvent (W_END, nl->chan->id, nick->id, nl->count);
      _ircch_del_lname (nick);
    }
    if (lname)
    {
      _ircch_add_lname (nick, lname);
      nick->id = lid;
      hash = Get_Hosthash (lname, nick->host);
      for (nl = nick->channels; nl; nl = nl->prevchan)
	if (nl != link && nl->chan->id != ID_REM)	/* all but this link */
	  NewEvent (W_START, nl->chan->id, lid, hash);
    }
    for (nl = nick->channels; nl; nl = nl->prevchan)
    {
      nl->count = 0;
    }
  }
  dprint (4, "_ircch_update_link: success on nick %s", nick->name);
}

static void _ircch_recheck_link (IRC *net, LINK *link, char *lname,
				 userflag uf, userflag cf, char *info, lid_t id)
{
  LINK *nl;
  wtmp_t wtmp;

  _ircch_update_link (link->nick, link, lname, id);
  if (!(link->mode & (A_ISON | A_ME)))			/* just joined */
  {
    DBG ("_ircch_recheck_link:just joined %s, check last %lu", lname, Time - ircch_greet_time);
    if (!lname || ircch_greet_time <= 0 ||
	(!FindEvent (&wtmp, lname, W_ANY, link->chan->id,
		     Time - ircch_greet_time)/* &&
	 (Time - wtmp.time < ircch_greet_time)*/))
      nl = link;
    else for (nl = link->chan->nicks; nl; nl = nl->prevnick)
      if (nl->nick->lname == link->nick->lname && nl != link)
      {
	DBG ("_ircch_recheck_link:found duplicate for %s(%s): %s",
	     nl->nick->lname, link->nick->host, nl->nick->host);
	break;						/* any but current */
      }
    ircch_recheck_modes (net, link, uf, cf, info, nl ? 0 : 1);
    if (lname && link->chan->id != ID_REM)		/* and now this too */
      NewEvent (W_START, link->chan->id, id,
		Get_Hosthash (lname, link->nick->host));
  }
  dprint (4, "_ircch_recheck_link: success on %s[%hd]", lname, link->nick->id);
  link->activity = Time;
}

/* alternate to above: find nick and update lname */
NICK *ircch_retry_nick (IRC *net, const char *lcn)
{
  NICK *nt = _ircch_get_nick (net, lcn, 0);
  char *lname;
  lid_t id;

  if (nt)
  {
    lname = _ircch_get_lname (nt->host, NULL, NULL, &id, NULL, NULL, NULL, nt);
    _ircch_update_link (nt, nt->channels, lname, id);
    FREE (&lname);
  }
  return nt;
}

static void _ircch_quit_bindings (char *lname, userflag uf, userflag cf,
				  char *who, char *chname, char *msg)
{
  binding_t *bind;

  /* run script bindings */
  for (bind = NULL; (bind = Check_Bindtable (BT_IrcSignoff, who, uf, cf, bind)); )
    if (bind->name)
      RunBinding (bind, who, lname ? lname : "*", chname, NULL, -1, msg);
}


/* --- Logging -------------------------------------------------------------- */

/* Logging: join=>part|kick|quit join=>netsplit[=>netjoin|lost] */

/* run bindings, log for plain JOIN */
static void _ircch_joined (LINK *link, char *nuh, char *atuh, userflag uf,
			   userflag cf, char *chan)
{
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
		      link->chan->chi->name, NULL, -1, NULL);
    else
      i = bind->func (nuh, link->nick->lname, link->chan->chi);
  }
  /* %N - nick, %@ - user@host, %L - lname, %# - channel */
  uh = safe_strchr (nuh, '!');
  if (uh) *uh = 0;
  if (c) *c = 0;
  printl (str, sizeof(str), format_irc_join, 0,
	  nuh, uh ? &uh[1] : uh, link->nick->lname, chan, 0, 0, 0, NULL);
  if (c) *c = '@';
  if (uh) *uh = '!';
  Add_Request (I_LOG, link->chan->chi->name, F_JOIN, "%s", str);
}

/* !!! be pretty sure there isn't any split structure before calling this !!! */
/* log event, run bindings, log one channel for plain QUIT */
static void _ircch_quited_log (NICK *nick, char *lname, userflag uf,
			       LINK *link, unsigned char *who, char *msg)
{
  char *c;
  char str[MESSAGEMAX];

  c = safe_strchr (who, '!');
  if (link->mode && nick->lname && link->chan->id != ID_REM)
    NewEvent (W_END, link->chan->id, nick->id, link->count);
  _ircch_quit_bindings (lname, uf, lname ?
			Get_Clientflags (lname, link->chan->chi->name) : 0,
			who, link->chan->chi->name, msg);
  if (c) *c = 0;
  /* %N - nick, %@ - user@host, %L - Lname, %# - network, %* - message */
  printl (str, sizeof(str),
	  link->mode ? format_irc_quit : format_irc_lostinnetsplit, 0, who,
	  c ? &c[1] : c, lname, &nick->net->name[1], 0, 0, 0, msg);
  if (c) *c = '!';
  Add_Request (I_LOG, link->chan->chi->name, link->mode ? F_JOIN : F_WARN,
	       "%s", str);
  Set_Iface (link->chan->chi);
  Add_Request (I_MODULE, "ui", F_JOIN, "%s", nick->name); /* inform UI */
  Unset_Iface();
}

/* !!! be pretty sure there isn't any split structure before calling this !!! */
/* log event, run bindings, log all channels, delete user after plain QUIT */
static void _ircch_quited (NICK *nick, char *lname, userflag uf,
			   unsigned char *who, char *msg)
{
  LINK *link;

  dprint (4, "_ircch_quited: %s (%s)%s", nick->name, lname,
	  (nick->umode & A_ISON) ? "" : " at netsplit");
  for (link = nick->channels; link; link = link->prevchan)
    _ircch_quited_log (nick, lname, uf, link, who, msg);
  if (Delete_Key (nick->net->nicks, nick->name, nick))
    ERROR ("_ircch_quited: tree error");
  _ircch_destroy_nick (nick);
}


/* log netsplit text str[len] for one channel */
static void _ircch_netsplit_channellog (netsplit *split, CHANNEL *chan,
					char *str, size_t len)
{
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

static char _ircch_get_userchar (IRC *net, modeflag f)
{
  if (f & A_ADMIN)
    return (net->features & L_HASADMIN) ? '!' : '@';
  if (f & A_OP)
    return '@';
  if (f & A_HALFOP)
    return '%';
  if (f & A_VOICE)
    return '+';
  return 0;
}

/* log netsplit on all channels that are involved and set stage to 1 */
static void _ircch_netsplit_report (IRC *net, netsplit *split)
{
  SplitMember *m, *cchm;
  size_t s, nl;
  char *c, *h;
  char x;
  char buf[STRING];

  for (cchm = split->members; cchm; cchm = m)
  {
    s = 0;
    /* here we scan entire split array and report all sorted by channel */
    for (m = cchm; m; m = m->next)
    {
      if (m->member->chan != cchm->member->chan) /* another channel */
	continue;
      else if (m->member->mode == 0)		/* is it reported already? */
      {
	WARNING ("_ircch_netsplit_log: link->mode==0 for %s on %s",
		 m->member->nick->name, m->member->chan->chi->name);
	continue;
      }
      x = _ircch_get_userchar (net, m->member->mode);
      m->member->mode = 0;
      if (!(h = m->member->nick->host))
	h = m->member->nick->name;		/* channel not sync yet! */
      c = strchr (h, '!');
      if (c)
	nl = c - h;
      else
	nl = strlen (h);
      if (s + nl + (x ? 1 : 0) >= sizeof(buf))
      {
	_ircch_netsplit_channellog (split, m->member->chan, buf, s);
	s = 0;
	if (nl + (x ? 1 : 0) >= sizeof(buf))
	  nl = sizeof(buf) - (x ? 2 : 1);
      }
      if (s)
	buf[s++] = ',';
      if (x)
	buf[s++] = x;
      memcpy (&buf[s], h, nl);
      s += nl;			/* s < sizeof(buf) */
    }
    if (s)
      _ircch_netsplit_channellog (split, cchm->member->chan, buf, s);
    for (m = cchm; m && m->member->mode == 0; m = m->next);
  }
  split->stage = 1;
}

/* log netjoin text str[len] for one channel */
static void _ircch_netjoin_log (netsplit *split, char *channame,
				char *str, size_t len, char *buf, size_t buflen)
{
  char *c;

  str[len] = 0; /* terminate it */
  c = strrchr (channame, '@');
  if (c) *c = 0;
  /* %N - nicklist, %# - channel, %* - netjoin server, %- - time of split */
  printl (buf, buflen, format_irc_netjoin, 0, str, NULL, NULL, channame,
	  0L, 0, Time - split->at, NextWord (split->servers));
  if (c) *c = '@';
  Add_Request (I_LOG, channame, F_JOIN, "%s", buf);
}

/* "halfclose" channel NJOIN, i.e. report list of users returned and run
 * bindings
 * NOTE: this function deletes entries from split list after reporting! */
static void _ircch_netjoin_report (IRC *net, netsplit *split, CHANNEL *chan)
{
  NICK *nick;
  SplitMember **mm = &split->members;
  SplitMember *sm;
  LINK *link;
  char *c;
  size_t s = 0, nl;
  clrec_t *u;
  binding_t *bind;
  userflag uf, cf;
  char m;
  char str[MESSAGEMAX];
  char buf[STRING];

  while ((sm = *mm))
  {
    if (sm->member->chan != chan ||  /* that one is on another channel, skip */
	!(sm->member->mode & A_ISON))	/* it isn't returned even */
    {
      mm = &(*mm)->next;
      continue;
    }
    nick = sm->member->nick;
    /* add to list for logging */
    m = _ircch_get_userchar (net, sm->member->mode);
    c = strchr (nick->host, '!');
    if (c)
      nl = c - nick->host;
    else
      nl = strlen (nick->host);
    if (s + nl + (m ? 1 : 0) >= sizeof(buf))
    {
      _ircch_netjoin_log (split, chan->chi->name, buf, s, str, sizeof(str));
      s = 0;
      if (nl + (m ? 1 : 0) >= sizeof(buf))
	nl = sizeof(buf) - (m ? 2 : 1);
    }
    if (s)
      buf[s++] = ',';
    if (m)
      buf[s++] = m;
    memcpy (&buf[s], nick->host, nl);
    s += nl;			/* s < sizeof(buf) */
    /* run all bindings */
    snprintf (str, sizeof(str), "%s %s", chan->chi->name, nick->name);
    if (nick->lname && (u = Lock_Clientrecord (nick->lname)))
    {
      uf = Get_Flags (u, NULL) | Get_Flags (u, &net->name[1]);
      cf = Get_Flags (u, chan->chi->name);
      Unlock_Clientrecord (u);
    }
    else
      uf = cf = 0;
    for (bind = NULL; (bind = Check_Bindtable (BT_IrcNJoin, str, uf, cf, bind)); )
    {
      if (bind->name)
	RunBinding (bind, nick->host, nick->lname ? nick->lname : "*",
		    chan->chi->name, NULL, -1, NULL);
      else
	bind->func (nick->host, nick->lname, chan->chi);
    }
    /* remove it from the split members list */
    *mm = sm->next;
    /* remove user from split if there was no LINK left */
    for (link = nick->channels; link; link = link->prevchan)
      if (!(link->mode & A_ISON))
	break;
    if (!link)
      nick->split = NULL;
    free_SplitMember (sm);
  }
  /* report all still unreported netjoin */
  if (s)
    _ircch_netjoin_log (split, chan->chi->name, buf, s, str, sizeof(str));
}

/* "finishclose" NJOIN, i.e. report one user that still is in split list as if
 * them are lost in netsplit */
static void _ircch_netsplit_lost_report (IRC *net, SplitMember **sm, char *msg)
{
  SplitMember *s;
  NICK *nick, *n = NULL;

  nick = (*sm)->member->nick;
  dprint (4, "_ircch_netsplit_lost_report: %s (%s)", nick->name, nick->lname);
  nick->split = NULL;				/* remove it ASAP */
  while ((s = *sm))
  {
    if (s->member->nick != nick)		/* do recursion only for nick */
    {
      sm = &s->next;
      continue;
    }
    _ircch_quited_log (nick, nick->lname,
		       nick->lname ? (Get_Clientflags (nick->lname, NULL) |
				Get_Clientflags (nick->lname, &net->name[1])) : 0,
		       s->member, nick->host, msg);
    n = _ircch_destroy_link (s->member);	/* remove link */
    *sm = s->next;				/* remove from list */
    free_SplitMember (s);
    if (n)
    {
      if (Delete_Key (net->nicks, n->name, n))
	ERROR ("_ircch_netsplit_lost_report: tree error");
      _ircch_destroy_nick (n);		/* destroy struct and remove lname */
      return;
    }
  }
  /* we should never get here! */
  ERROR ("_ircch_netsplit_lost_report: inconsistency for nick %s", nick->name);
}

/* "close" netsplit, i.e. report everyone who are returned, then report
 * everyone who are lost in netsplit, then destroy netsplit structure */
static void _ircch_netsplit_terminate (IRC *net, netsplit **ptr)
{
  netsplit *split;
  LEAF *l = NULL;
  SplitMember **s;

  split = *ptr;
  *ptr = split->prev;
  dprint (4, "_ircch_netsplit_terminate: %s", split->servers);
  /* report all channels if got netsplit right now */
  if (split->stage == 0)
    _ircch_netsplit_report (net, split);
  /* let report NJOINs if we got any unreported */
  while ((l = Next_Leaf (net->channels, l, NULL)))
    _ircch_netjoin_report (net, split, l->s.data);
  /* now only those who lost in split left! */
  for (s = &split->members; *s; )
  {
    /* sanity check! */
    if ((*s)->member->nick->split != split)
      ERROR ("_ircch_netsplit_terminate: member %s is from another split!",
	     (*s)->member->nick->name);
    _ircch_netsplit_lost_report (net, s, split->servers);
  }
  /* free all allocations */
  FREE (&split->servers);
  FREE (&split);
}


/* --- Netjoin detection ---------------------------------------------------- */

/* sequence:
 *		-> "JOIN" nick1
 *		<- "LINKS goneserver"
 *		-> "JOIN" the same channel	: continuing
 *		-> "MODE" the same channel	: continuing
 *		-> "365" before "364"		: user just reconnected
 *		-> "364" then "365"		: netsplit is over
 *		-> anything else		: use our intellect...
 *		-> timeout...			: the same as above
 *
 * stage -1: got netsplit	: create netsplit
 * stage 0: collect QUITs	: wait for timeout (t1) >>1
 * stage 1: yet in netsplit	: wait for JOIN >>2
 * stage 2: someone JOINed	: wait for RPL_LINKS >>1/3
 * stage 3: RPL_LINKS got	: report rejoined/lost for current channel
 *
 * Note that we can get some lags before getting NJOIN for next channel so
 * we can get RPL_LINKS right after JOINs for some channel but we can get it
 * after all channels too, so detection gets tricky a bit:
 *  - we got JOIN/MODE onto next channel for the same split: think it's over
 *  - we got something else in stage 3: "close" netsplit for channel
 *  - we got timeout in stage 3: "close" netsplit for all channels
 *  - we got something else in stage 2: if only one JOIN but there are other
 *	users in split then think it's just reconnect or else it's over
 *  - we got timeout in stage 2: the same as above
 *
 * nick->umode is ~A_ISON in stages 0,1 and A_ISON+ in other stages
 * link->mode is 0 in stage 1
 */

/* find netsplit in network's list */
static netsplit **_ircch_netsplit_find (IRC *net, const char *server)
{
  netsplit **split;

  for (split = &net->splits; *split; split = &(*split)->prev)
    if (!strcasecmp (server, NextWord((*split)->servers)))
      return split;
  return NULL;
}

/* add every channel for the user into netsplit list */
static void _ircch_netsplit_add (IRC *net, char *servers, NICK *nick)
{
  netsplit *split;
  netsplit **tmp;
  SplitMember **sm;
  LINK *link;

  dprint (4, "_ircch_netsplit_add for %s: %s", nick->name, servers);
  if ((tmp = _ircch_netsplit_find (net, NextWord(servers))) &&
      strcmp (servers, (*tmp)->servers))
  {
    ERROR ("_ircch_netsplit_add: duplicate split, previous was for servers %s!",
	   (*tmp)->servers);
    _ircch_netsplit_terminate (net, tmp);
    tmp = NULL;
  }
  if (tmp)
    split = *tmp;
  else
  {
    DBG ("_ircch_netsplit_add: %s", servers);
    split = safe_malloc (sizeof(netsplit));
    split->servers = safe_strdup (servers);
    split->stage = 0;
    split->prev = net->splits;
    split->members = NULL;
    split->njlast = NULL;
    split->at = Time;
    net->splits = split;
  }
  /* find the end and consistency check at the same time */
  sm = &split->members;
  for (sm = &split->members; *sm; sm = &(*sm)->next)
    if ((*sm)->member->nick == nick)
      break;
  if (*sm)
  {
    ERROR ("_ircch_netsplit_add: %s is already in split list!", nick->name);
    return;
  }
  for (link = nick->channels; link; link = link->prevchan)
  {
    *sm = alloc_SplitMember();
    (*sm)->member = link;
    split->njlast = *sm;
    sm = &(*sm)->next;
    DBG ("_ircch_netsplit_add: %s", link->chan->chi->name);
  }
  *sm = NULL;	/* there is no implicit value there! */
  split->njlastact = Time;
  nick->split = split;
}

/* update NJOIN info in the netsplit structure and report previous channel
 * if current JOIN is for another channel */
static void _ircch_netjoin_add (IRC *net, LINK *link)
{
  SplitMember *sm;
  netsplit *split = link->nick->split;

  dprint (4, "_ircch_netjoin_add: %s@%s", link->nick->name, link->chan->chi->name);
  if (split->stage == 1)
  {
    New_Request (net->neti, F_QUICK, "LINKS %s", NextWord(split->servers));
    split->stage = 2;			/* going to stage 2 now */
  }
  for (sm = split->members; sm && sm->member != link; sm = sm->next);
  if (!sm)
  {
    ERROR ("_ircch_netjoin_add: link %s@%s absent in split list!",
	   link->nick->name, link->chan->chi->name);
    return;
  }
  if (split->njlast && link->chan != split->njlast->member->chan)
    _ircch_netjoin_report (net, split, split->njlast->member->chan);
  split->njlast = sm;
  split->njlastact = Time;
}

/* !!! _irrch_net_got_activity() have to be called before calling this function
   and be sure nick->split isn't NULL !!! */
/* removes the user from netsplit list and clears nick->split */
static void _ircch_netsplit_remove_nick (NICK *nick)
{
  SplitMember **s = &nick->split->members;
  register SplitMember *sm;

  DBG ("_ircch_netsplit_remove_nick: %s", nick->name);
  nick->split = NULL;
  /* since _ircch_net_got_activity called we have nick->split->njlast == NULL */
  while ((sm = *s))
  {
    if (sm->member->nick == nick)
    {
      *s = sm->next;
      free_SplitMember (sm);
    }
    else
      s = &sm->next;
  }
}

/* silently "close" netsplit for a channel, i.e. just purge every entry
 * matching this channel from netsplit list */
static void _ircch_netsplit_purge_channel (netsplit *split, CHANNEL *ch)
{
  SplitMember **s = &split->members;
  register SplitMember *sm;
  NICK *nick;

  while (*s)
  {
    if ((*s)->member->chan == ch)
    {
      nick = (*s)->member->nick;
      sm = *s;
      *s = sm->next;
      free_SplitMember (sm);
      for (sm = split->members; sm && sm->member->nick != nick; sm = sm->next);
      if (!sm)		/* this nick is nowhere now, no more split for them */
	nick->split = NULL; /* nick will be deleted by purging channel later */
    }
    else
      s = &(*s)->next;
  }
}

/* it's not NJOIN so purge the user(s) from netsplit list, run quit (i.e. lost
 * in netsplit) bindings for each channel, and report them have been joined */
static void _ircch_its_rejoin (IRC *net, netsplit *split)
{
  SplitMember *s = split->members;
  userflag uf, cf;
  NICK *nick;
  LINK *link, *link2;

  split->stage = 1;			/* we decided it's rejoin so reset it */
  while (s)
  {
    if (s->member->mode & A_ISON)	/* it's what we hunt for */
    {
      nick = s->member->nick;
      _ircch_netsplit_remove_nick (nick); /* remove from list now */
      if (nick->lname)
	uf = Get_Clientflags (nick->lname, NULL) |
	     Get_Clientflags (nick->lname, &net->name[1]);
      else
	uf = 0;
      dprint (4, "_ircch_its_rejoin: have %s", nick->name);
      for (link = nick->channels; link; link = link2)
      {
	link2 = link->prevchan;
	cf = nick->lname ? Get_Clientflags (nick->lname, link->chan->chi->name) : 0;
	_ircch_quit_bindings (nick->lname, uf, cf, nick->host,
			      link->chan->chi->name, split->servers);
	if (link->mode & A_ISON)	/* is rejoined instead of netsplit */
	{
	  _ircch_joined (link, nick->host, strchr (nick->host, '!'), uf, cf,
			 link->chan->chi->name);
	  if (link->mode != A_ISON)
	  {
	    register char modechar;
	    register char *c;
	    size_t sb;

	    /* we might skip some modes on JOIN's so let's show the change */
	    if ((c = safe_strchr (nick->host, '!'))) sb = c - nick->host;
	    else sb = safe_strlen (nick->host);
	    if (link->mode & A_ADMIN) modechar = 'a';
	    else if (link->mode & A_OP) modechar = 'h';
	    else if (link->mode & A_HALFOP) modechar = 'o';
	    else modechar = 'v';
	    Add_Request (I_LOG, link->chan->chi->name, F_MODES,
			 "servermode %s: +%c %.*s", link->chan->real,
			 modechar, sb, NONULL(nick->host));
	  }
	}
	else
	  _ircch_destroy_link (link);
	s = split->members;		/* rescan it again, list may be empty */
      }
    }
    else
      s = s->next;
  }
}

/* check if JOINed users are 1 and left >0 and return 0
 * return 1 otherwise */
static int _ircch_netjoin_AI (netsplit *split)
{
  register SplitMember *sm;
  register int x = 1;

  for (sm = split->members; sm; sm = sm->next)
  {
    if (sm->member->mode & A_ISON)	/* joined already */
    {
      if (split->njlast && (sm != split->njlast))
	/* we got >1 joined */
	return 1;
    }
    else				/* yet in split */
      x = 0;
  }
  return x;
}

static void _ircch_netsplit_timeout (IRC *net)
{ /* check for timeouts */
  netsplit *split;
  netsplit **tmp = &net->splits;

  while ((split = *tmp))
  {
    if (!split->members || (Time >= split->at + ircch_netsplit_keep) ||
	(split->stage == 3 && Time >= split->njlastact + ircch_netjoin_log))
    {
      _ircch_netsplit_terminate (net, tmp);	/* netsplit is over de-facto */
      continue;
    }
    if (split->stage == 0 && Time >= split->at + ircch_netsplit_log)
      _ircch_netsplit_report (net, split);	/* continue to stage 1 */
    else if (split->stage == 2 && split->njlast &&
	     Time >= split->njlastact + ircch_netjoin_log)
    {
      if (_ircch_netjoin_AI (split))
	_ircch_netsplit_terminate (net, tmp);	/* timeout for RPL_LINKS */
      else
	_ircch_its_rejoin (net, split);		/* it's not NJOIN */
      split->njlast = NULL;
    }
    tmp = &split->prev;
  }
}

/* called if this is neither QUIT, JOIN nor MODE for user on the same channel
   so we have to report something */
static void _ircch_net_got_activity (IRC *net, LINK *link)
{
  netsplit *split;

  DBG ("_ircch_net_got_activity %s", net->name);
  for (split = net->splits; split; split = split->prev)
  {
    if (!split->njlast)		/* nothing to do */
      continue;
    if (split->stage == 0)	/* report netsplit now */
      _ircch_netsplit_report (net, split);
    else if (split->stage == 3)	/* report netjoin for chan */
      _ircch_netjoin_report (net, split, split->njlast->member->chan);
    else /* stage 2 */		/* report joins, it not seems to be netjoin */
      if (!(_ircch_netjoin_AI (split)))	/* but let check it somehow */
	_ircch_its_rejoin (net, split);
    split->njlast = NULL;
  }
  if (link && !(link->mode & A_ISON))	/* sanity check */
    WARNING ("_ircch_net_got_activity: %s on %s without JOIN!",
	     link->nick->name, link->chan->chi->name);	/* netjoin wasn't reported yet? */
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
static void _ircch_join_channel (IRC *net, char *chname)
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

BINDING_TYPE_connect (connect_ircchannel);
static int connect_ircchannel (const char *chname, char *keys)
{
  char *c;
  IRC *net;

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
  IRC *net;
  LINK *link;
  INTERFACE *tmp;
  register clrec_t *u;

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
      for (link = ((CHANNEL *)iface->data)->nicks; link; link = link->prevnick)
      {
	size_t s;
	char *lname;
	char str[MESSAGEMAX];
	char nick[NICKLEN+2];

	DBG ("ircch:report: nick %s prefix %s mode %#x", link->nick->name,
	     link->nick->host, link->mode);
	if (!(link->mode & ReportMask))
	  continue;
	if (!link->nick->host)		/* channel not fully sync. yet */
	  continue;
	c = strchr (link->nick->host, '!');
	if (c)
	  s = c++ - link->nick->host;
	else
	  s = strlen (link->nick->host);
	if (s >= sizeof(nick) - 1)
	  s = sizeof(nick) - 2;
	nick[0] = _ircch_get_userchar (net, link->mode);
	if (!nick[0])
	  nick[0] = ' ';
	memcpy (&nick[1], link->nick->host, s);
	nick[s+1] = 0;
	/* lname might be changed since last event */
	if (link->nick == net->me)
	  lname = NULL;
	else
	  lname = _ircch_get_lname (link->nick->host, NULL, NULL, NULL, NULL,
				    NULL, NULL, link->nick);
	DBG ("ircch:report: (pt2) nick %s host %s lname %s times %.13s/%lu",
	     nick, c, lname, link->joined, (unsigned long int)link->activity);
	printl (str, sizeof(str), ReportFormat, 0, nick, c,
		(link->nick == net->me) ? "ME!" : lname, link->joined, 0, 0,
		link->activity ? Time - link->activity : 0,
		(link->mode & A_ISON) ? NULL : _("is in netsplit"));
	New_Request (tmp, F_REPORT, "%s", str);
	FREE (&lname);
      }
      Unset_Iface();
      break;
    case S_LOCAL:
      net = _ircch_get_network2 (strrchr (iface->name, '@'));
      if (!net)				/* it's impossible, I think */
	break;
      ircch_enforcer (net, (CHANNEL *)iface->data);
      ((CHANNEL *)iface->data)->tid = -1;
      break;
    case S_TIMEOUT:
      net = _ircch_get_network2 (strrchr (iface->name, '@'));
      ircch_expire (net, (CHANNEL *)iface->data);
      break;
    case S_FLUSH:
      if ((u = Lock_Clientrecord (iface->name)))
	Unlock_Clientrecord (u);
      else			/* someone deleted this channel from Listfile */
      {
	register CHANNEL *ch;

	net = _ircch_get_network2 (strrchr (iface->name, '@'));
	ch = _ircch_get_channel0 (net, iface->name, NULL);
	ch->id = ID_REM;	/* and keep other data until leaving */
      }
      break;
    case S_SHUTDOWN:
      /* nothing to do: module will do all itself */
    default: ;
  }
  return 0;
}

static int _ircch_req (INTERFACE *iface, REQUEST *req)
{
  IRC *net;
  char chname[IFNAMEMAX+1];
  register size_t s;

  net = _ircch_get_network2 (strrchr (iface->name, '@'));
  if (net)	/* we do polling timeouts this way */
    _ircch_netsplit_timeout (net);
  if (!req)
    return REQ_OK;
  /* we have to send to real one name always to prevent errors */
  s = strfcpy (chname, ((CHANNEL *)iface->data)->real, sizeof(chname));
  strfcpy (&chname[s], net->name, sizeof(chname) - s);
  return Relay_Request (I_CLIENT, chname, req);
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
BINDING_TYPE_irc_connected (ic_ircch);
static void ic_ircch (INTERFACE *network, char *servname, char *nick,
		      size_t (*lc) (char *, const char *, size_t))
{
  char mask[NAMEMAX+4];
  IRC *net;
  char *c, *ch;
  INTERFACE *tmp;
  int i;

  net = _ircch_get_network (network->name, 1, lc);
  if (net->me)					/* already registered? */
  {
    WARNING ("ircch: got duplicate connection notification: %s", network->name);
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
  net->me->host = safe_strdup (nick);
  New_Request (network, F_QUICK, "USERHOST %s", nick); /* check it ASAP! */
  mask[0] = '?';
  mask[1] = '*';
  strfcpy (&mask[2], net->name, sizeof(mask)-2);
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
    if (Get_Clientflags (c, "") & U_ACCESS)	/* autojoin found */
      _ircch_join_channel (net, c);
  }
  tmp->ift = I_DIED;
}


/*
 * "irc-disconnected" binding:
 *   - destroy all channels, then all users
 */
BINDING_TYPE_irc_disconnected (id_ircch);
static void id_ircch (INTERFACE *network, char *servname, char *nick,
		      size_t (*lc) (char *, const char *, size_t))
{
  IRC *net = _ircch_get_network2 (network->name);

  if (net)
  {
    if (Delete_Key (IRCNetworks, net->name, net))
      ERROR ("id_ircch: tree error");
    _ircch_destroy_network (net);
  }
  else
    WARNING ("ircch: disconnected from unknown network %s", network->name);
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
    register char *c = strrchr (((invited_t *)inv)->chname, '@');

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
BINDING_TYPE_irc_raw (irc_invite);
static int irc_invite (INTERFACE *iface, char *svname, char *me, unsigned char *prefix,
		       int parc, char **parv, size_t (*lc) (char *, const char *, size_t))
{/*   Parameters: <nickname> <channel> */
  IRC *net;
  char chname[CHANNAMELEN+NAMEMAX+3];
  userflag cf;

  /* hmm, someone invited me... do I waiting for invitation or ignore it? */
  if (parc < 2 || !(net = _ircch_get_network (iface->name, 0, lc)))
    return -1;		/* it's impossible, I think */
  _ircch_format_chname (net, parv[1], chname, sizeof(chname));
  if (_ircch_get_channel0 (net, chname, NULL))	/* already joined! */
  {
    Add_Request (I_LOG, net->name, F_SERV,
		 "Got invite request from %s for already joined channel %s",
		 prefix ? (char *)prefix : svname, chname);
    return 0;
  }
  cf = Get_Clientflags (chname, "");
  if (cf & U_ACCESS)				/* it seems it's pending */
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
    ERROR ("irc-channel:irc_invite: thread creating error");
  }
  return 0;
}

#define CHECKHOSTSET(n,h)	if (!n->host) n->host = safe_strdup(h)

BINDING_TYPE_irc_raw (irc_join);
static int irc_join (INTERFACE *iface, char *svname, char *me, unsigned char *prefix,
		     int parc, char **parv, size_t (*lc) (char *, const char *, size_t))
{/*   Parameters: <channel> */
  IRC *net;
  CHANNEL *chan;
  NICK *nick;
  LINK *link;
  char *ch, *lname, *r;
  userflag uf, cf;
  lid_t id;
  size_t s;
  char lcn[HOSTMASKLEN+1];

  if (!prefix || parc == 0 || !(net = _ircch_get_network (iface->name, 0, lc)))
    return -1;
  dprint (4, "got JOIN %s for %s", parv[0], prefix);
  if ((ch = safe_strchr (prefix, '!')))
    *ch = 0;
  if (lc)
    s = lc (lcn, prefix, NAMEMAX+1);
  else
    s = strfcpy (lcn, prefix, NAMEMAX+1);
  if ((nick = _ircch_get_nick (net, lcn, 0)) && nick->split)
  {
    if (ch) *ch = '!';
    if (nick->split->stage == 0)		/* got netsplit right now */
      _ircch_net_got_activity (net, NULL);
    if (safe_strcmp (prefix, nick->host)) /* is it someone with the same nick */
    {
      r = nick->split->servers;			/* it's available now! */
      _ircch_netsplit_remove_nick (nick); /* remove from split structure ASAP */
      _ircch_quited (nick, nick->lname,
		     nick->lname ? (Get_Clientflags (nick->lname, NULL) |
				Get_Clientflags (nick->lname, iface->name)) : 0,
		     nick->host, r);
    }
    if (ch) *ch = 0;
  }
  else if (nick && !(nick->umode & A_ISON))
    FREE (&nick->host);				/* it might be hidden before */
  nick = _ircch_get_nick (net, lcn, 1);
  nick->umode |= A_ISON;
  if (!nick->host && !(net->features & L_NOUSERHOST))	/* to check umode */
    New_Request (net->neti, 0, "USERHOST %s", prefix);
  else if (!nick->host)
    New_Request (net->neti, 0, "WHO %s", prefix);
  if (ch)
    *ch = '!';
  CHECKHOSTSET (nick, prefix);
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
    if (!(chan = _ircch_get_channel (net, parv[0], 0)))
      return -1;			/* got JOIN for channel where I'm not! */
    lname = _ircch_get_lname (prefix, &uf, &cf, &id, iface->name,
			      chan->chi->name, &r, NULL);
  }
  /* create link, update wtmp */
  link = _ircch_get_link (net, lcn, chan);
  if (nick == net->me)			/* skip recheck noncense for me */
    link->mode = A_ME;
  else					/* it should be zero, isn't it? */
    link->mode = 0;
  /* do rest with lname and wtmp */
  _ircch_recheck_link (net, link, lname, uf, cf, r, id);
  /* check for netjoin and else run bindings */
  link->mode |= A_ISON;					/* ~A_INSPLIT */
  if (!nick->split)
  {
    _ircch_joined (link, prefix, safe_strchr (prefix, '!'), uf, cf, parv[0]);
    snprintf (link->joined, sizeof(link->joined), "%s %s", DateString, TimeString);
  }
  else						/* it seems netjoin detected */
    _ircch_netjoin_add (net, link);		/* it does report if need */
  /* check permissions is delayed */
  FREE (&lname);
  FREE (&r);
  Set_Iface (chan->chi);
  Add_Request (I_MODULE, "ui", F_JOIN, "%s", nick->name); /* inform UI */
  Unset_Iface();
  return 0;
}

BINDING_TYPE_irc_raw (irc_kick);
static int irc_kick (INTERFACE *iface, char *svname, char *me, unsigned char *prefix,
		     int parc, char **parv, size_t (*lc) (char *, const char *, size_t))
{/*   Parameters: <channel> <user> <comment> */
  LINK *link, *tlink;
  IRC *net;
  CHANNEL *ch;
  NICK *nt;
  char *lname, *c, *r;
  binding_t *bind;
  userflag uf, cf;
  netsplit *split;
  lid_t id;
#if HOSTMASKLEN >= MESSAGEMAX
  char str[HOSTMASKLEN+1];
#else
  char str[MESSAGEMAX];
#endif

  if (!prefix || parc < 2 || !(net = _ircch_get_network (iface->name, 0, lc)) ||
      !(ch = _ircch_get_channel (net, parv[0], 0)))	/* alien kick? */
    return -1;
  if (lc)
  {
    lc (str, parv[1], sizeof(str));
    tlink = ircch_find_link (net, str, ch);
  }
  else
    tlink = ircch_find_link (net, parv[1], ch);
  if (!tlink)
  {
    ERROR ("we've got KICK for alien %s from %s on %s!", parv[1], prefix,
	   ch->chi->name);
    return -1;
  }
  CHECKHOSTSET (tlink->nick, parv[1]);
  if ((c = safe_strchr (prefix, '!')))
    *c = 0;
  if (lc)
    lc (str, prefix, sizeof(str));
  else
    strfcpy (str, prefix, sizeof(str));
  dprint (4, "ircch: got KICK %s from %s on %s", parv[1], str, parv[0]);
  link = ircch_find_link (net, str, ch);
  if (link)
    CHECKHOSTSET (link->nick, prefix);	/* we might got KICK from alien? */
  if (c)
    *c = '!';
  if (!link || link->nick == net->me)
    lname = r = NULL;
  else
    lname = _ircch_get_lname (prefix, &uf, &cf, &id, iface->name, ch->chi->name,
			      &r, link->nick);
  /* get op info */
  if (link)
    _ircch_recheck_link (net, link, lname, uf, cf, r, id);
  _ircch_net_got_activity (net, tlink);
  /* update wtmp */
  if (tlink->nick->lname && ch->id != ID_REM)
    NewEvent (W_END, ch->id, tlink->nick->id, tlink->count);
  else if (tlink->nick == net->me && ch->id != ID_REM)
    NewEvent (W_DOWN, ch->id, ID_ME, tlink->count);
  /* run bindings, log it, destroy link... */
  snprintf (str, sizeof(str), "%s %s", ch->chi->name, parv[1]);
  bind = NULL;
  while ((bind = Check_Bindtable (BT_IrcKick, str, U_ALL, U_ANYCH, bind)))
  {
    if (bind->name)
      RunBinding (bind, prefix, lname ? lname : "*", ch->chi->name, parv[1], -1,
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
  Add_Request (I_LOG, ch->chi->name, F_MODES | F_JOIN, "%s", str);
  /* do revenge */
#define U_TOREVENGE (U_FRIEND | U_HALFOP | U_OP)
  if (tlink->nick->lname && !((uf | cf) & U_FRIEND) && /* except from revenge */
      Get_Clientflags (ch->chi->name, NULL) & U_QUIET && /* +revenge */
      (Get_Clientflags (tlink->nick->lname, &net->neti->name[1]) & U_TOREVENGE ||
       Get_Clientflags (tlink->nick->lname, ch->chi->name) & U_TOREVENGE))
  {
    clrec_t *u;
    LINK *lme;

    /* set U_DEOP on channel record of link->nick */
    if (lname && (u = Lock_Clientrecord (lname)))
    {
      cf |= U_DEOP;
      Set_Flags (u, ch->chi->name, cf);
      Unlock_Clientrecord (u);
    }
    /* find me op */
    for (lme = net->me->channels; lme; lme = lme->prevchan)
      if (lme->chan == ch)
	break;
    if (lme && lme->mode & (A_ADMIN | A_OP | A_HALFOP))
    {
      /* deop or kick link */
      if (c)
	*c = 0;
      if (ircch_kick_on_revenge == TRUE)
	New_Request (net->neti, 0, "KICK %s %s :revenge!", ch->real, prefix);
      else
	New_Request (net->neti, 0, "MODE %s -o %s", ch->real, prefix);
      if (c)
	*c = '!';
    }
  }
  if (link && link->mode == 0)	/* TODO: is it possible to have link here? */
  {
    nt = _ircch_destroy_link (link);
    if (nt)			/* it's even on no channels */
    {
      WARNING ("ircch: KICK by alien on %s, deleting %s", ch->chi->name,
		nt->name);
      if (Delete_Key (net->nicks, nt->name, nt))
	ERROR ("irc_kick: tree error");
      _ircch_destroy_nick (nt);
    }
    else
      WARNING ("ircch: KICK by alien on %s", ch->chi->name);
  }
  if (tlink->nick == net->me)	/* they kicked me, unfortunately */
  {
    dprint (4, "irc_kick: deleting %s%s", net->me->name, net->name);
    if (Delete_Key (net->channels, ch->chi->name, ch))
      ERROR ("irc_kick: tree error");
    Set_Iface (ch->chi);
    Send_Signal (I_MODULE, "ui", S_FLUSH); /* inform UI about this part */
    Unset_Iface();
    for (split = net->splits; split; split = split->prev)
      _ircch_netsplit_purge_channel (split, ch);	/* ignore errors */
    if (Get_Clientflags (ch->chi->name, NULL) & U_HALFOP)
      _ircch_join_channel (net, ch->real);		/* do 'cycle' feature */
    _ircch_destroy_channel (ch);
    nt = NULL;
  }
  else
  {
    Set_Iface (ch->chi);
    Add_Request (I_MODULE, "ui", F_JOIN, "%s", parv[1]); /* inform UI */
    Unset_Iface();
    nt = _ircch_destroy_link (tlink);
  }
  /* destroy nick if no channels left */
  if (nt)
  {
    dprint (4, "irc_kick: deleting %s%s", nt->name, net->name);
    if (Delete_Key (net->nicks, nt->name, nt))
      ERROR ("irc_kick: tree error");
    _ircch_destroy_nick (nt);
  }
  FREE (&lname);
  FREE (&r);
  return 0;
}

static modeflag umode_flags[] = {
    A_OP, A_HALFOP, A_INVISIBLE, A_WALLOP, A_AWAY, A_MASKED, A_RESTRICTED
};
static char umode_chars[] = "oOiwaxR";

static void _ircch_parse_umode (IRC *net, NICK *me, char *c)
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

BINDING_TYPE_irc_raw (irc_mode);
static int irc_mode (INTERFACE *iface, char *svname, char *me, unsigned char *prefix,
		     int parc, char **parv, size_t (*lc) (char *, const char *, size_t))
{/*   Parameters: <channel|me> *( ( "-" / "+" ) *<modes> *<modeparams> ) */
  IRC *net;
  LINK *origin;
  char *c;
  CHANNEL *ch;
  userflag uf, cf;
  lid_t id;

  if (parc < 2 || !(net = _ircch_get_network (iface->name, 0, lc)))
    return -1;
  dprint (4, "ircch: got MODE for %s", parv[0]);
  if (!prefix || !strcmp (prefix, me))	/* it seems it's my own mode */
  {
    int i = 0;

    while (++i < parc)
      _ircch_parse_umode (net, net->me, parv[i]);
    return 0;
  }
  else
  {
    char *lname, *r;
    char lcn[HOSTMASKLEN+1];

    if ((c = safe_strchr (prefix, '!')))
      *c = 0;
    if (lc)
      lc (lcn, prefix, NAMEMAX+1);
    else
      strfcpy (lcn, prefix, NAMEMAX+1);
    if (!(ch = _ircch_get_channel (net, parv[0], 0)))
    {
      WARNING ("ircch: got mode for unknown channel %s%s", parv[0], net->name);
      return -1;
    }
    origin = ircch_find_link (net, lcn, ch); /* no origin if it's servermode */
    if (c)
      *c = '!';
    if (origin)
    {
      if (origin->nick == net->me)
	lname = r = NULL;
      else
	lname = _ircch_get_lname (prefix, &uf, &cf, &id, iface->name,
				  ch->chi->name, &r, origin->nick);
      _ircch_recheck_link (net, origin, lname, uf, cf, r, id);
      FREE (&lname);
      FREE (&r);
    }
  }
  /* parse parameters, run bindings */
  if (origin)			/* if server mode - it may be part of NJOIN */
    _ircch_net_got_activity (net, origin);
  if (ircch_parse_modeline (net, ch, origin, prefix, uf, BT_IrcMChg,
			    BT_Keychange, parc - 1, &parv[1]))
  /* do logging */
  {
    register int i;
    register size_t s;
    char mbuf[STRING];
    char buf[MESSAGEMAX];

    s = strfcpy (mbuf, parv[1], sizeof(mbuf));
    for (i = 2; parv[i] && s < sizeof(mbuf) - 2; i++)
    {
      mbuf[s++] = ' ';
      s += strfcpy (&mbuf[s], parv[i], sizeof(mbuf) - s);
    }
    if (c)
      *c = 0;
    /* %N - nick, %@ - user@host, %L - lname, %# - channel, %* - modeline */
    printl (buf, sizeof(buf), format_irc_modechange, 0, prefix,
	    c ? c + 1 : NULL, origin ? origin->nick->lname : "*", parv[0], 0,
	    0, 0, mbuf);
    Add_Request (I_LOG, ch->chi->name, F_MODES, "%s", buf);
    if (c)
      *c = '!';
  }
  return 0;
}

BINDING_TYPE_irc_raw (irc_part);
static int irc_part (INTERFACE *iface, char *svname, char *me, unsigned char *prefix,
		     int parc, char **parv, size_t (*lc) (char *, const char *, size_t))
{/*   Parameters: <channel> <Part Message> */
  LINK *link;
  IRC *net;
  CHANNEL *ch;
  NICK *nt;
  char *lname, *c, *r;
  userflag uf, cf;
  binding_t *bind;
  netsplit *split;
  lid_t id;
#if HOSTMASKLEN >= MESSAGEMAX
  char str[HOSTMASKLEN+1];
#else
  char str[MESSAGEMAX];
#endif

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
  if (!(link = ircch_find_link (net, str, ch)))
  {
    ERROR ("irc-channel:irc_part: impossible PART from %s on %s", str,
	   ch->chi->name);
    return -1;
  }
  CHECKHOSTSET (link->nick, prefix);
  if (c)
    *c = '!';
  if (link->nick == net->me)
    lname = r = NULL;
  else
    lname = _ircch_get_lname (prefix, &uf, &cf, &id, iface->name, ch->chi->name,
			      &r, link->nick);
  _ircch_recheck_link (net, link, lname, uf, cf, r, id);
  _ircch_net_got_activity (net, link);
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
      RunBinding (bind, prefix, lname ? lname : "*", ch->chi->name, NULL, -1,
		  parv[1]);
    else
      bind->func (prefix, lname, ch->chi, parv[1]);
  }
  if ((c = safe_strchr (prefix, '!')))
    *c = 0;
  /* %N - nick, %@ - user@host, %L - lname, %# - channel, %* - message */
  printl (str, sizeof(str), format_irc_part, 0, prefix, c ? c + 1 : NULL,
	  lname, parv[0], 0, 0, 0, parv[1]);
  if (c) *c = '!';
  Add_Request (I_LOG, ch->chi->name, F_JOIN, "%s", str);
  if (link->nick == net->me)	/* I left channel, clean up */
  {
    dprint (4, "irc_part: deleting %s%s", net->me->name, net->name);
    if (Delete_Key (net->channels, ch->chi->name, ch))
      ERROR ("irc_part: tree error");
    Set_Iface (ch->chi);
    Send_Signal (I_MODULE, "ui", S_FLUSH); /* inform UI about this part */
    Unset_Iface();
    for (split = net->splits; split; split = split->prev)
      _ircch_netsplit_purge_channel (split, ch);	/* ignore errors */
    if (Get_Clientflags (ch->chi->name, NULL) & U_HALFOP)
      _ircch_join_channel (net, ch->real);		/* do 'cycle' feature */
    _ircch_destroy_channel (ch);
    nt = NULL;
  }
  else
  {
    Set_Iface (ch->chi);
    Add_Request (I_MODULE, "ui", F_JOIN, "%s", link->nick->name); /* inform UI */
    Unset_Iface();
    nt = _ircch_destroy_link (link);
  }
  /* destroy nick if no channels left */
  if (nt)
  {
    dprint (4, "irc_part: deleting %s%s", nt->name, net->name);
    if (Delete_Key (net->nicks, nt->name, nt))
      ERROR ("irc_part: tree error");
    _ircch_destroy_nick (nt);
  }
  FREE (&lname);
  FREE (&r);
  return 0;
}

BINDING_TYPE_irc_raw (irc_topic);
static int irc_topic (INTERFACE *iface, char *svname, char *me, unsigned char *prefix,
		      int parc, char **parv, size_t (*lc) (char *, const char *, size_t))
{/*   Parameters: <channel> <topic> */
  IRC *net;
  CHANNEL *ch;
  char *lname, *c, *r;
  size_t s;
  userflag uf, cf;
  LINK *link;
  binding_t *bind;
  lid_t id;
#if HOSTMASKLEN >= MESSAGEMAX
  char str[HOSTMASKLEN+1];
#else
  char str[MESSAGEMAX];
#endif

  if (!prefix || parc == 0 ||
      !(net = _ircch_get_network (iface->name, 0, lc)) ||
      !(ch = _ircch_get_channel (net, parv[0], 0)))
    return -1;		/* it's impossible! */
  dprint (4, "ircch: got TOPIC for %s", parv[0]);
  if ((c = safe_strchr (prefix, '!')))
    *c = 0;
  if (lc)
    s = lc (str, prefix, sizeof(str));
  else
    s = strfcpy (str, prefix, sizeof(str));
  link = _ircch_get_link (net, str, ch);
  CHECKHOSTSET (link->nick, prefix);	/* we might got TOPIC from alien? */
  if (c)
    *c = '!';
  if (link->nick == net->me)
    lname = r = NULL;
  else
    lname = _ircch_get_lname (prefix, &uf, &cf, &id, iface->name, ch->chi->name,
			      &r, link->nick);
  _ircch_recheck_link (net, link, lname, uf, cf, r, id);
  _ircch_net_got_activity (net, link);
  /* set structure */
  ircch_remove_mask (&ch->topic, ch->topic);
  if (parv[1]) /* save it even if it's empty */
    ircch_add_mask (&ch->topic, prefix, s, parv[1]);
  /* run bindings, log it... */
  snprintf (str, sizeof(str), "%s %s", ch->chi->name, parv[1]);
  for (bind = NULL; (bind = Check_Bindtable (BT_IrcTopic, str, uf, cf, bind)); )
  {
    if (bind->name)
      RunBinding (bind, prefix, lname ? lname : "*", ch->chi->name, NULL, -1,
		  parv[1]);
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
  if (link->mode == 0)		/* topic set by some alien (service?) */
  {
    NICK *nt = _ircch_destroy_link (link);

    if (nt)			/* it's even on no channels */
    {
      dprint (4, "ircch: TOPIC by alien on %s, deleting %s", ch->chi->name,
	      nt->name);
      if (Delete_Key (net->nicks, nt->name, nt))
	ERROR ("irc_topic: tree error");
      _ircch_destroy_nick (nt);
    }
    else
      dprint (4, "ircch: TOPIC by alien on %s", ch->chi->name);
  }
  FREE (&lname);
  FREE (&r);
  Set_Iface (ch->chi);
  Send_Signal (I_MODULE, "ui", S_FLUSH); /* inform UI about topic change */
  Unset_Iface();
  return 0;
}

BINDING_TYPE_irc_raw (irc_rpl_userhost);
static int irc_rpl_userhost (INTERFACE *iface, char *svname, char *me,
			     unsigned char *prefix, int parc, char **parv,
			     size_t (*lc) (char *, const char *, size_t))
{/* Parameters: me :<nick>[*]?=[+-]<hostname>( <nick>[*]?=[+-]<hostname>)* */
  IRC *net;
  NICK *nick;
  char *c, *cc, *host, *name;
  char ch;
  size_t s;
  lid_t id;
  char userhost[HOSTMASKLEN+1];

  if (parc < 2 || !(net = _ircch_get_network (iface->name, 0, lc)))
    return -1;		/* it's impossible, tough */
  c = parv[1];
  while (*c)
  {
    for (name = host = c; *host && *host != '*' && *host != '='; host++);
    c = gettoken (host, &cc); /* set it at next nick before anything else */
    if ((ch = *host))			/* it's now next to nick */
      *host = 0;
    else
      ERROR ("irc_rpl_userhost: host part not found for %s!", c);
    if(lc)				/* get it lowcase */
    {
      lc (userhost, name, NAMEMAX+1);
      nick = _ircch_get_nick (net, userhost, 0);
    }
    else
      nick = _ircch_get_nick (net, name, 0);
    s = host - name;
    if (ch)				/* and restore the input */
      *host = ch;
    if (!nick)
    {
      WARNING ("ircch: unrequested RPL_USERHOST from %s for nick %.*s",
	       net->name, s, name);
      continue;				/* alien request? */
    }
    if (ch == '*')
    {
      nick->umode |= A_OP;		/* IRCOp */
      host++;
    }
    else
      nick->umode &= ~A_OP;
    host++;				/* skip '=' */
    if (*host++ == '-')
      nick->umode |= A_AWAY;
    else
      nick->umode &= ~A_AWAY;
    FREE (&nick->host);
    nick->host = safe_malloc (strlen (host) + s + 2);
    memmove (nick->host, name, s);	/* composite %s!%s there */
    name = &nick->host[s];		/* we dont need it anymore */
    *name = '!';
    strcpy (&name[1], host);
    DBG ("irc_rpl_userhost: set host %s", nick->host);
    if (*c) *cc = ' ';			/* see gettoken above */
    if (!nick->lname && ch && nick != net->me)	/* update lname now! */
    {
      name = _ircch_get_lname (nick->host, NULL, NULL, &id, NULL, NULL, NULL, nick);
      if (name)
	_ircch_update_link (nick, NULL, name, id);
      FREE (&name);
      DBG ("irc_rpl_userhost: got %s = %s", userhost, NONULL(nick->lname));
    }
    else
      DBG ("irc_rpl_userhost: got %s (%s)", userhost, NONULL(nick->lname));
  }
  return 0;
}

BINDING_TYPE_irc_raw (irc_rpl_endofwho);
static int irc_rpl_endofwho (INTERFACE *iface, char *svname, char *me,
			     unsigned char *prefix, int parc, char **parv,
			     size_t (*lc) (char *, const char *, size_t))
{/* Parameters: me <channel> "End of WHO list." */
  IRC *net;
  CHANNEL *ch;
  LINK *l;

  if (parc >= 2 && (net = _ircch_get_network (iface->name, 0, lc)) &&
      (ch = _ircch_get_channel (net, parv[1], 0)))
  {
    for (l = ch->nicks; l->prevnick; l = l->prevnick);
    DBG ("irc_rpl_endofwho:%s:%s act %lu", ch->chi->name, l->nick->name, (unsigned long)l->activity);
    Add_Request (I_LOG, ch->chi->name, F_JOIN,
		 "Join to %s was synced in %d seconds.", parv[1],
		 (int)(Time - l->activity)); /* first link should be me */
    Set_Iface (ch->chi);
    Send_Signal (I_MODULE, "ui", S_FLUSH); /* notify the UI */
    Unset_Iface();
  }
  return 0;
}

BINDING_TYPE_irc_raw (irc_rpl_umodeis);
static int irc_rpl_umodeis (INTERFACE *iface, char *svname, char *me,
			    unsigned char *prefix, int parc, char **parv,
			    size_t (*lc) (char *, const char *, size_t))
{/* Parameters: me <user mode string> */
  IRC *net;

  if (parc > 1 && (net = _ircch_get_network (iface->name, 0, lc)))
    _ircch_parse_umode (net, net->me, parv[1]);
  return 0;
}

BINDING_TYPE_irc_raw (irc_rpl_channelmodeis);
static int irc_rpl_channelmodeis (INTERFACE *iface, char *svname, char *me,
				  unsigned char *prefix, int parc, char **parv,
				  size_t (*lc) (char *, const char *, size_t))
{/* Parameters: me <channel> <mode> <mode params> */
  IRC *net;
  CHANNEL *ch;

  if (parc < 3 || !(net = _ircch_get_network (iface->name, 0, lc)))
    return 0;		/* it's impossible, I think */
  ch = _ircch_get_channel (net, parv[1], 0);
  if (ch)
    ircch_parse_modeline (net, ch, NULL, prefix, -1, BT_IrcMChg, BT_Keychange,
			  parc - 2, &parv[2]);
  /* don't logging it, UI will ask mode itself */
  return 0;
}

BINDING_TYPE_irc_raw (irc_rpl_uniqopis);
static int irc_rpl_uniqopis (INTERFACE *iface, char *svname, char *me,
			     unsigned char *prefix, int parc, char **parv,
			     size_t (*lc) (char *, const char *, size_t))
{/* Parameters: me <channel> <nickname> */
  IRC *net;
  CHANNEL *chan;
  LINK *op = NULL;
  char lcn[NAMEMAX+1];

  if (parc != 3 || !(net = _ircch_get_network (iface->name, 0, lc)))
    return -1;		/* it's impossible, I think */
  chan = _ircch_get_channel (net, parv[1], 0);
  if (chan && lc)
  {
    lc (lcn, parv[2], sizeof(lcn));
    if ((op = ircch_find_link (net, lcn, chan)))
      op->mode |= A_ADMIN;
  }
  else if (chan && (op = ircch_find_link (net, parv[2], chan)))
    op->mode |= A_ADMIN;
  if (!op)
    WARNING ("irc_rpl_uniqopis: OP %s not found", parv[2]);
  else
    CHECKHOSTSET (op->nick, parv[2]);
  return 0;
}

BINDING_TYPE_irc_raw (irc_rpl_notopic);
static int irc_rpl_notopic (INTERFACE *iface, char *svname, char *me,
			    unsigned char *prefix, int parc, char **parv,
			    size_t (*lc) (char *, const char *, size_t))
{/* Parameters: me <channel> "No topic is set" */
  IRC *net = _ircch_get_network (iface->name, 0, lc);
  CHANNEL *ch;

  if (!net || parc < 2)
    return -1;		/* impossible... */
  ch = _ircch_get_channel (net, parv[1], 0);
  if (ch)
    ircch_remove_mask (&ch->topic, ch->topic);
  /* don't logging it, UI will ask topic itself */
  return 0;
}

BINDING_TYPE_irc_raw (irc_rpl_topic);
static int irc_rpl_topic (INTERFACE *iface, char *svname, char *me,
			  unsigned char *prefix, int parc, char **parv,
			  size_t (*lc) (char *, const char *, size_t))
{/* Parameters: me <channel> <topic> */
  IRC *net = _ircch_get_network (iface->name, 0, lc);
  CHANNEL *ch;
  char str[MESSAGEMAX];

  if (!net || parc != 3)
    return -1;		/* impossible... */
  dprint (4, "ircch: got TOPIC for %s", parv[1]);
  ch = _ircch_get_channel (net, parv[1], 0);
  if (ch)
  {
    ircch_remove_mask (&ch->topic, ch->topic);
    if (parv[2] && *parv[2])
      ircch_add_mask (&ch->topic, "", 0, parv[2]);
  }
  /* %# - channel, %* - topic */
  printl (str, sizeof(str), format_irc_topic_is, 0, NULL, NULL, NULL,
	  parv[1], 0, 0, 0, parv[2]);
  Add_Request (I_LOG, ch->chi->name, F_MODES, "%s", str);
  return 0;
}

BINDING_TYPE_irc_raw (irc_rpl_topicwhotime);
static int irc_rpl_topicwhotime (INTERFACE *iface, char *svname, char *me,
				 unsigned char *prefix, int parc, char **parv,
				 size_t (*lc) (char *, const char *, size_t))
{/* Parameters: me <channel> <by> <unixtime> */
  IRC *net;
  CHANNEL *ch;
  LIST *topic;
  struct tm tm;
  char tdate[64];
  char str[MESSAGEMAX];

  if (parc != 4 || !(net = _ircch_get_network (iface->name, 0, lc)))
    return -1;		/* it's impossible, I think */
  ch = _ircch_get_channel (net, parv[1], 0);
  if (!ch || !ch->topic)
  {
    WARNING ("irc_rpl_topicwhotime for %s nowhere to put", parv[1]);
    return -1;		/* it's impossible, I think */
  }
  topic = ch->topic;			/* store it */
  ch->topic = NULL;			/* it will be reset */
  ircch_add_mask (&ch->topic, parv[2], strlen (parv[2]), topic->what);
  ch->topic->since = strtoul (parv[3], NULL, 10);
  ircch_remove_mask (&topic, topic);	/* unalloc stored */
  localtime_r (&ch->topic->since, &tm);
  strftime (tdate, sizeof(tdate), "%c", &tm);
  /* %N - nick, %@ - when, %# - channel */
  printl (str, sizeof(str), format_irc_topic_by, 0, parv[2], tdate, NULL,
	  parv[1], 0, 0, 0, NULL);
  Add_Request (I_LOG, ch->chi->name, F_MODES, "%s", str);
  return 0;
}

BINDING_TYPE_irc_raw (irc_rpl_invitelist);
static int irc_rpl_invitelist (INTERFACE *iface, char *svname, char *me,
			       unsigned char *prefix, int parc, char **parv,
			       size_t (*lc) (char *, const char *, size_t))
{/* Parameters: me <channel> <invitemask> */
  IRC *net = _ircch_get_network (iface->name, 0, lc);
  CHANNEL *ch;

  if (!net || parc != 3)
    return -1;		/* impossible... */
  ch = _ircch_get_channel (net, parv[1], 0);
  if (ch)
    ircch_add_mask (&ch->invites, "", 0, parv[2]);
  return 0;
}

BINDING_TYPE_irc_raw (irc_rpl_exceptlist);
static int irc_rpl_exceptlist (INTERFACE *iface, char *svname, char *me,
			       unsigned char *prefix, int parc, char **parv,
			       size_t (*lc) (char *, const char *, size_t))
{/* Parameters: me <channel> <exceptionmask> */
  IRC *net = _ircch_get_network (iface->name, 0, lc);
  CHANNEL *ch;

  if (!net || parc != 3)
    return -1;		/* impossible... */
  ch = _ircch_get_channel (net, parv[1], 0);
  if (ch)
    ircch_add_mask (&ch->exempts, "", 0, parv[2]);
  return 0;
}

BINDING_TYPE_irc_raw (irc_rpl_whoreply);
static int irc_rpl_whoreply (INTERFACE *iface, char *svname, char *me,
			     unsigned char *prefix, int parc, char **parv,
			     size_t (*lc) (char *, const char *, size_t))
{/* Parameters: me <channel> <user> <host> <server> <nick> [HG][x]?[R]?[*]?[!@%+]?
              :<hopcount> <real name> */	/* G=away x=host *=ircop */
  IRC *net;
  NICK *nick;
  char *c;
  lid_t id;
  char userhost[HOSTMASKLEN+1];

  if (parc < 7 || !(net = _ircch_get_network (iface->name, 0, lc)))
    return -1;		/* it's impossible, I think */
  if (lc)
    lc (userhost, parv[5], sizeof(userhost)-1);
  else
    strfcpy (userhost, parv[5], sizeof(userhost)-1);
  nick = _ircch_get_nick (net, userhost, 0);
  if (nick && nick != net->me)
  {
    /* do with host */
    snprintf (userhost, sizeof(userhost), "%s!%s@%s", parv[5], parv[2], parv[3]);
    if (nick->host)
    {
      dprint (4, "irc_rpl_whoreply: replacing host %s with %s", nick->host,
	      userhost);
      FREE (&nick->host);
    }
    nick->host = safe_strdup (userhost);
    /* do with lname */
    DBG ("irc_rpl_whoreply: checking lname for %s", userhost);
    c = _ircch_get_lname (userhost, NULL, NULL, &id, NULL, NULL, NULL, nick);
    _ircch_update_link (nick, NULL, c, id);
    FREE (&c);
    /* do with usermodes */
    nick->umode &= ~(A_MASKED | A_RESTRICTED | A_OP);
    for (c = parv[6]; *c; c++)
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
    /* I don't have operator permission when I just joined to not empty channel
       so I cannot do anything with link here even if we are in bitchmode */
  }
  return 0;
}

BINDING_TYPE_irc_raw (irc_rpl_namreply);
static int irc_rpl_namreply (INTERFACE *iface, char *svname, char *me,
			     unsigned char *prefix, int parc, char **parv,
			     size_t (*lc) (char *, const char *, size_t))
{/* Parameters: me "="|"*"|"@" <channel> :[@%+]?<nick>( [@%+]?<nick>)* */
  IRC *net;
  CHANNEL *chan;
  LINK *link;
  char *c, *cc, *cx;
  char nn;
  size_t sz;
  char lcn[NAMEMAX+1];

  if (parc != 4 || !(net = _ircch_get_network (iface->name, 0, lc)))
    return -1;		/* it's impossible, I think */
  chan = _ircch_get_channel (net, parv[2], 0);
  if (chan)
  {
    sz = 0;
    for (c = parv[3]; c && *c; c = cc)
    {
      cc = strchr (c, ' ');			/* select a token */
      if (cc) *cc = 0;
      if (*c == '@' || *c == '%' || *c == '+' || *c == '!')
	nn = *c++;				/* check for modechar */
      else
	nn = 0;
      if (lc)
	lc ((cx = lcn), c, sizeof(lcn));
      else
        cx = c;
      if (chan->mode & A_ISON)
      {
	if (!(link = ircch_find_link (net, cx, chan)))
	{
	  ERROR ("irc_rpl_namreply: %s on %s without a JOIN", cx, chan->chi->name);
	  link = _ircch_get_link (net, cx, chan);
	}
      }
      else
	link = _ircch_get_link (net, cx, chan);	/* create a link */
      if (link->nick->split)			/* is it at time of netjoin? */
	_ircch_net_got_activity (net, link);
      else if (link->mode == 0)			/* was it just created? */
      {
	link->joined[0] = 0;			/* join time is unknown now */
	link->activity = 0;
      }
      link->mode = A_ISON;			/* it's simple :) */
      if (nn == 0);
      else if (nn == '!')			/* update user mode */
	link->mode |= A_ADMIN;
      else if (nn == '@')
	link->mode |= A_OP;
      else if (nn == '%')
	link->mode |= A_HALFOP;
      else
	link->mode |= A_VOICE;
      if (cc) *cc++ = ' ';
    }
  }
  return 0;
}

BINDING_TYPE_irc_raw (irc_rpl_endofnames);
static int irc_rpl_endofnames (INTERFACE *iface, char *svname, char *me,
			       unsigned char *prefix, int parc, char **parv,
			       size_t (*lc) (char *, const char *, size_t))
{/* Parameters: me <channel> "End of /NAMES list" */
  int n, v, h, o;
  IRC *net;
  CHANNEL *ch;
  LINK *link;

  /* show nick stats */
  if (!(net = _ircch_get_network (iface->name, 0, lc)) ||
      !(ch = _ircch_get_channel (net, parv[1], 0)))
    return -1;
  n = v = h = o = 0;
  ch->mode |= A_ISON;		/* we done with join so let mark it */
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
	       parv[1], n + v + h + o, o, h, v, n);
  return 0;
}

BINDING_TYPE_irc_raw (irc_rpl_banlist);
static int irc_rpl_banlist (INTERFACE *iface, char *svname, char *me,
			    unsigned char *prefix, int parc, char **parv,
			    size_t (*lc) (char *, const char *, size_t))
{/* Parameters: me <channel> <banmask> */
  IRC *net = _ircch_get_network (iface->name, 0, lc);
  CHANNEL *ch;

  if (!net || parc != 3)
    return -1;		/* impossible... */
  ch = _ircch_get_channel (net, parv[1], 0);
  if (ch)
    ircch_add_mask (&ch->bans, "", 0, parv[2]);
  return 0;
}

BINDING_TYPE_irc_raw (irc_rpl_links);
static int irc_rpl_links (INTERFACE *iface, char *svname, char *me,
			  unsigned char *prefix, int parc, char **parv,
			  size_t (*lc) (char *, const char *, size_t))
{/* Parameters: me <mask> <via> :<hopcount> <server info> */
  IRC *net = _ircch_get_network (iface->name, 0, lc);
  netsplit **split;

  if (!net || parc < 3)
    return -1;		/* impossible... */
  else if (!(split = _ircch_netsplit_find (net, parv[1])))
    return 0;		/* server isn't in split */
  dprint (4, "ircch: got reply for splitted server %s", parv[1]);
  (*split)->stage = 3;
  _ircch_net_got_activity (net, NULL);
  return 1;
}

BINDING_TYPE_irc_raw (irc_rpl_endoflinks);
static int irc_rpl_endoflinks (INTERFACE *iface, char *svname, char *me,
			       unsigned char *prefix, int parc, char **parv,
			       size_t (*lc) (char *, const char *, size_t))
{/* Parameters: me <mask> "End of /LINKS list" */
  IRC *net = _ircch_get_network (iface->name, 0, lc);
  netsplit **split;

  if (!net || parc < 3)
    return -1;		/* impossible... */
  else if (!(split = _ircch_netsplit_find (net, parv[1])))
    return 0;		/* alien request or netsplit is over */
  if ((*split)->stage == 3)	/* ok, netsplit seems to be over */
    return 1;
  _ircch_its_rejoin (net, *split);
  return 1;
}

BINDING_TYPE_irc_raw (irc_err_nosuchchannel);
static int irc_err_nosuchchannel (INTERFACE *iface, char *svname, char *me,
				  unsigned char *prefix, int parc, char **parv,
				  size_t (*lc) (char *, const char *, size_t))
{/* Parameters: me <channel> <text> */
  IRC *net = _ircch_get_network (iface->name, 0, lc);
  CHANNEL *ch;

  if (!net || parc < 2)
    return -1;		/* impossible... */
  if (parv[1][0] == '!')
    /* ERR_NOSUCHCHANNEL for '!channel' - try to create it: "JOIN !!channel" */
    New_Request (iface, 0, "JOIN !%s", parv[1]);
  else if ((ch = _ircch_get_channel (net, parv[1], 0)))
  {
    LINK *link;
    netsplit *split;

    Add_Request (I_LOG, "*", F_WARN, "I thought I'm on channel %s but I'm not!",
		 ch->chi->name);
    if (ch->id != ID_REM)
      for (link = ch->nicks; link; link = link->prevnick)
	if (link->nick == net->me)
	{
	  NewEvent (W_DOWN, ch->id, ID_ME, link->count);
	  break;
	}
    if (Delete_Key (net->channels, ch->chi->name, ch))
      ERROR ("irc_err_nosuchchannel: tree error");
    for (split = net->splits; split; split = split->prev)
      _ircch_netsplit_purge_channel (split, ch);	/* ignore errors */
    _ircch_destroy_channel (ch);
  }
  return 0;
}

BINDING_TYPE_irc_raw (irc_err_unknowncommand);
static int irc_err_unknowncommand (INTERFACE *iface, char *svname, char *me,
				   unsigned char *prefix, int parc, char **parv,
				   size_t (*lc) (char *, const char *, size_t))
{/* Parameters: me <command> <text> */
  IRC *net;

  if (parc < 2 || !(net = _ircch_get_network (iface->name, 0, lc)))
    return -1;
  if (!strcasecmp (parv[1], "USERHOST"))
    net->features |= L_NOUSERHOST;
  return 0;
}

BINDING_TYPE_irc_raw (irc_err_cannotsendtochan);
static int irc_err_cannotsendtochan (INTERFACE *iface, char *svname, char *me,
				     unsigned char *prefix, int parc, char **parv,
				     size_t (*lc) (char *, const char *, size_t))
{/* Parameters: me <channel name> "Cannot send to channel" */
  IRC *net;
  CHANNEL *ch;

  if (parc < 2 || !(net = _ircch_get_network (iface->name, 0, lc)))
    return -1;
  if ((ch = _ircch_get_channel (net, parv[1], 0)))
    Add_Request (I_LOG, ch->chi->name, F_PUBLIC | F_WARN,
		 _("*** cannot send to channel %s"), parv[1]);
  return 0;
}

BINDING_TYPE_irc_raw (irc_join_errors);
static int irc_join_errors (INTERFACE *iface, char *svname, char *me,
			    unsigned char *prefix, int parc, char **parv,
			    size_t (*lc) (char *, const char *, size_t))
{/* Parameters: me <channel name> <different error messages> */
  IRC *net;
  char ch[IFNAMEMAX+1];
  register size_t s;

  if (parc < 3 || !(net = _ircch_get_network (iface->name, 0, lc)))
    return -1;		/* impossible I think */
  /* TODO: use lc() for channel name */
  s = unistrlower (ch, parv[1], sizeof(ch));
  strfcpy (&ch[s], net->name, sizeof(ch) - s);
  Add_Request (I_LOG, ch, F_WARN, _("cannot join to channel %s: %s"), parv[1],
	       parv[2]);
  return 0;
}

BINDING_TYPE_irc_raw (irc_unexpected_error);
static int irc_unexpected_error (INTERFACE *iface, char *svname, char *me,
				 unsigned char *prefix, int parc, char **parv,
				 size_t (*lc) (char *, const char *, size_t))
{/* Parameters: me [<target>] <error text> */
  if (parc > 2)
    ERROR ("irc-channel: unexpected error from network %s: %s :%s", iface->name,
	   parv[1], parv[2]);
  else
    ERROR ("irc-channel: unexpected error from network %s: %s", iface->name,
	   parc > 1 ? parv[1] : "");
  return 0;
}

BINDING_TYPE_irc_raw (irc_err_chanoprivsneeded);
static int irc_err_chanoprivsneeded (INTERFACE *iface, char *svname, char *me,
				     unsigned char *prefix, int parc, char **parv,
				     size_t (*lc) (char *, const char *, size_t))
{/* Parameters: me <channel> :You're not channel operator */
  IRC *net;
  CHANNEL *ch;
  register LINK *l;

  if (parc < 2 || !(net = _ircch_get_network (iface->name, 0, lc)))
    return -1;		/* impossible I think */
  if ((ch = _ircch_get_channel (net, parv[1], 0)))
  {
    for (l = ch->nicks; l; l = l->prevnick)
      if (l->nick == net->me)
	break;
  }
  else
    l = NULL;
  if (l && (l->mode & (A_ADMIN | A_OP | A_HALFOP)))
  {
    l->mode &= ~(A_ADMIN | A_OP | A_HALFOP); /* reset my operator flags */
    ERROR ("irc-channel: got ERR_CHANOPRIVSNEEDED for %s on %s", parv[1],
	   iface->name);
  }
  else
    WARNING ("irc-channel: got ERR_CHANOPRIVSNEEDED for %s on %s", parv[1],
	     iface->name);
  return 0;
}

BINDING_TYPE_irc_raw (irc_err_nosuchnick);
static int irc_err_nosuchnick (INTERFACE *iface, char *svname, char *me,
			       unsigned char *prefix, int parc, char **parv,
			       size_t (*lc) (char *, const char *, size_t))
{/* Parameters: me <nickname> :No such nick/channel */
  IRC *net;
  NICK *n;
  char lcn[NAMEMAX+1];

  if (parc < 2 || !(net = _ircch_get_network (iface->name, 0, lc)))
    return -1;		/* impossible I think */
  if (lc)
    lc (lcn, parv[1], sizeof(lcn)-1);
  n = _ircch_get_nick (net, lc ? lcn : parv[1], 0);
  ERROR ("irc-channel: got ERR_NOSUCHNICK for %s (%p) on %s", parv[1], n,
	 iface->name);
  if (n) /* drop this nick */
  {
    if (Delete_Key (net->nicks, n->name, n))
      ERROR ("irc_err_nosuchnick: tree error");
    _ircch_destroy_nick (n);
  }
  return 0;
}

BINDING_TYPE_irc_raw (irc_err_usernotinchannel);
static int irc_err_usernotinchannel (INTERFACE *iface, char *svname, char *me,
				     unsigned char *prefix, int parc, char **parv,
				     size_t (*lc) (char *, const char *, size_t))
{/* Parameters: me <nick> <channel> :They aren't on that channel */
  IRC *net;
  CHANNEL *ch;
  LINK *l;
  char lcn[NAMEMAX+1];

  if (parc < 3 || !(net = _ircch_get_network (iface->name, 0, lc)))
    return -1;		/* impossible I think */
  l = NULL;
  if ((ch = _ircch_get_channel (net, parv[2], 0)))
  {
    if (lc)
    {
      lc (lcn, parv[1], sizeof(lcn)-1);
      l = ircch_find_link (net, lcn, ch);
    }
    else
      l = ircch_find_link (net, parv[1], ch);
  }
  ERROR ("irc-channel: got ERR_USERNOTINCHANNEL for %s (%p) on %s @%s", parv[1],
	 l, parv[2], iface->name);
  if (l) /* drop this link */
  {
    NICK *n = _ircch_destroy_link (l);
    if (n) /* it was last one even */
    {
      if (Delete_Key (net->nicks, n->name, n))
	ERROR ("irc_err_usernotinchannel: tree error");
      _ircch_destroy_nick (n);
    }
  }
  return 0;
}

BINDING_TYPE_irc_raw (irc_err_useronchannel);
static int irc_err_useronchannel (INTERFACE *iface, char *svname, char *me,
				  unsigned char *prefix, int parc, char **parv,
				  size_t (*lc) (char *, const char *, size_t))
{/* Parameters: me <user> <channel> :is already on channel */
  IRC *net;

  if (parc < 3 || !(net = _ircch_get_network (iface->name, 0, lc)))
    return -1;		/* impossible I think */
  Add_Request (I_LOG, net->neti->name, F_WARN, /* our invite wes unneeded */
	       "irc: nick %s is already on channel %s in network %s!", parv[1],
	       parv[2], iface->name);
  return 0;
}


/*
 * "irc-raw" bindings from "irc" module - script support part
 */
BINDING_TYPE_irc_nickchg (ircch_nick);
static void ircch_nick (INTERFACE *iface, char *lname, unsigned char *who,
			char *lcon, char *newnick, char *lcnn)
{
  IRC *net;
  NICK *nick, *nnick;
  LINK *link;
  userflag uf, cf = 0;
  binding_t *bind;
  char *c, *cc;
  lid_t id;
#if HOSTMASKLEN >= MESSAGEMAX
  char str[HOSTMASKLEN+1];
#else
  char str[MESSAGEMAX];
#endif

  if (!(net = _ircch_get_network2 (iface->name)) ||
      !(nick = _ircch_get_nick (net, lcon, 0)))
    return;		/* it's impossible anyway */
  dprint (4, "ircch: nickchange for %s", who);
  nick->umode &= ~A_REGISTERED;	/* identification isn't valid anymore */
  _ircch_net_got_activity (net, NULL);
  if ((nnick = _ircch_get_nick (net, lcnn, 0)) /* it might be lost in netsplit */
      && nick != nnick)		/* but it might be alike nIcK -> NiCk too */
  {
    dprint (4, "ircch: nick change to %s that might be in netsplit", newnick);
    nnick->umode &= ~A_ISON;	/* for _ircch_quited() */
    if (nnick->split)		/* remove from split structure ASAP */
    {
      c = nnick->split->servers;
      _ircch_netsplit_remove_nick (nnick);
    }
    else
      c = NULL;
    _ircch_quited (nnick, nnick->lname,
		   nnick->lname ? (Get_Clientflags (nnick->lname, NULL) |
				Get_Clientflags (nnick->lname, iface->name)) : 0,
		   nnick->host, c ? c : "*");
  }
  if (nick == net->me)		/* renaming of me? */
    lname = NULL;
  if (lname)
    uf = Get_Clientflags (lname, iface->name) | Get_Clientflags (lname, NULL);
  else
    uf = 0;
  if (nick->split)		/* can it be that nick is marked as in split? */
    ERROR ("%s did nickchange but still in split for me!", who);
  c = safe_strchr (who, '!');
  if (c)
    cc = c;
  else
    cc = safe_strchr (nick->host, '!');
  if (cc)	/* make new hoststring */
  {
    snprintf (str, sizeof(str), "%s%s", newnick, cc);
    cc = str;
  }
  else		/* no userhost got, don't try to get it again */
    cc = newnick;
  FREE (&nick->host);
  nick->host = safe_strdup (cc);
  if (c) *c = 0;
  /* %N - oldnick, %@ - user@host, %L - lname, %* - newnick */
  printl (str, sizeof(str), format_irc_nickchange, 0, who, c ? c + 1 : NULL,
	  lname, NULL, 0, 0, 0, newnick);
  if (c) *c = '!';
  if (!safe_strcmp (nick->lname, lname))
  {
    cc = NULL;	/* use it as mark of lname change */
    id = FindLID (lname);
  }
  else
    id = nick->id;
  for (link = nick->channels; link; link = link->prevchan)
  {
    if (lname)
      cf = Get_Clientflags (lname, link->chan->chi->name);
    /* note: we cannot trace if new nick is matched to ban pattern */
    _ircch_recheck_link (net, link, lname, uf, cf, NULL, id);
    if (cc)	/* if lname was changed */
    {
      dprint (4, "ircch_nick: lname switched to %s, updating join time: %s => %s %s",
	      nick->lname, link->joined, DateString, TimeString);
      snprintf (link->joined, sizeof(link->joined), "%s %s", DateString,
		TimeString);
    }
    Add_Request (I_LOG, link->chan->chi->name, F_JOIN, "%s", str);
    for (bind = NULL;
		(bind = Check_Bindtable (BT_IrcNChg, newnick, uf, cf, bind)); )
      if (bind->name)
	RunBinding (bind, who, lname ? lname : "*", link->chan->chi->name,
		    NULL, -1, newnick);
    Set_Iface (link->chan->chi);
    Add_Request (I_MODULE, "ui", F_JOIN, "%s", nick->name); /* inform UI */
    Add_Request (I_MODULE, "ui", F_JOIN, "%s", newnick);
    Unset_Iface();
  }
  dprint (4, "ircch_nick: deleting %s%s", nick->name, net->name);
  if (Delete_Key (net->nicks, nick->name, nick))
    ERROR ("ircch_nick: tree error!");
  FREE (&nick->name);
  nick->name = safe_strdup (lcnn);
  dprint (4, "ircch_nick: adding %s%s", nick->name, net->name);
  if (Insert_Key (&net->nicks, nick->name, nick, 1))
    ERROR ("ircch_nick: tree error!");
}

BINDING_TYPE_irc_signoff (ircch_quit);
static void ircch_quit (INTERFACE *iface, char *lname, unsigned char *who,
			char *lcnick, char *msg)
{
  IRC *net;
  NICK *nick;
  userflag uf;

  if (!(net = _ircch_get_network2 (iface->name)) ||
      !(nick = _ircch_get_nick (net, lcnick, 0)))
  {
    ERROR ("ircch_quit: %s not found in network %s!", lcnick, iface->name);
    return;					/* what???!!! who???!!! */
  }
  dprint (4, "ircch: quit for %s", who);
  if (lname)
    uf = Get_Clientflags (lname, NULL) | Get_Clientflags (lname, iface->name);
  else
    uf = 0;
  _ircch_net_got_activity (net, NULL);
  if (nick->split)
  {
    ERROR ("ircch_quit: %s found in split but ought be not!", lcnick);
    _ircch_netsplit_remove_nick (nick); /* remove from split structure ASAP */
  }
  _ircch_quited (nick, lname, uf, who, msg);
}

BINDING_TYPE_irc_netsplit (ircch_netsplit);
static void ircch_netsplit (INTERFACE *iface, char *lname, unsigned char *who,
			    char *lcnick, char *servers)
{
  IRC *net;
  NICK *nick;
  LINK *link;
  binding_t *bind;
  userflag uf, cf;

  if (!(net = _ircch_get_network2 (iface->name)) ||
      !(nick = _ircch_get_nick (net, lcnick, 0)))
  {
    ERROR ("ircch_netsplit: %s not found in network %s!", lcnick, iface->name);
    return;					/* what???!!! who???!!! */
  }
  if (lname)
    uf = Get_Clientflags (lname, NULL) | Get_Clientflags (lname, iface->name);
  else
    uf = 0;
  _ircch_netsplit_add (net, servers, nick);	/* it will check for re-split */
  for (link = nick->channels; link; link = link->prevchan)
  {
    if (nick->lname && link->chan->id != ID_REM) /* ignore new lname! */
      NewEvent (W_END, link->chan->id, nick->id, link->count);
    link->count = 0;
    /* run script bindings */
    cf = lname ? Get_Clientflags (lname, link->chan->chi->name) : 0;
    for (bind = NULL; (bind = Check_Bindtable (BT_IrcNSplit, who, uf, cf,
					       bind)); )
      if (bind->name)
	RunBinding (bind, who, lname ? lname : "*", link->chan->chi->name,
		    NULL, -1, NULL);
  }
}


/*
 * "irc-pub-msg-mask" and "irc-pub-notice-mask" bindings
 *   void func (INTERFACE *, unsigned char *prefix, char *lname, char *chan@net, char *msg);
 *
 * - do statistics (msg itself is ignored)
 * - check for lname changes and netsplits
 */
BINDING_TYPE_irc_pub_msg_mask (icam_ircch);
static void icam_ircch (INTERFACE *client, unsigned char *from, char *lname,
			char *unick, char *chan, char *msg)
{
  IRC *net;
  CHANNEL *ch;
  LINK *link;
  NICK *nick;
  userflag uf, cf;

  if (!unick || !from || !(net = _ircch_get_network2 (strrchr (chan, '@'))))
    return;				/* hmm, it's impossible!? */
  nick = _ircch_get_nick (net, unick, 1);
  if (!(nick->umode & A_ISON))
    WARNING ("irc-channel:icam_ircch: hidden nick %s on %s!", unick, chan);
  CHECKHOSTSET (nick, from);
  if (!(ch = _ircch_get_channel0 (net, chan, NULL)))
    return;				/* hmm, it's impossible!? */
  for (link = nick->channels; link && link->chan != ch; )
    link = link->prevchan;
  if (!link || !(link->mode & A_ISON))
    ERROR ("irc-channel:icam_ircch: %s on %s without a join!", unick, chan);
  if (nick == net->me)			/* if it's me then it's false */
    lname = NULL;
  if (lname)
  {
    uf = Get_Clientflags (lname, &net->name[1]) | Get_Clientflags (lname, NULL);
    cf = Get_Clientflags (lname, ch->chi->name);
  }
  else
    uf = cf = 0;
  if (link) 				/* hmm, it may be outside message */
  {
    /* note: we cannot trace if it is matched to ban pattern */
    _ircch_recheck_link (net, link, lname, uf, cf, NULL, nick->id);
    link->count++;
  }
  _ircch_net_got_activity (net, link);
}


/*
 * unfortunately, we have to parse all private PRIVMSG/NOTICE here too
 * to catch hosts and netjoins
 */
BINDING_TYPE_irc_priv_msg_mask (ipam_ircch);
static void ipam_ircch (INTERFACE *client, unsigned char *from, char *lname,
			char *unick, char *msg)
{
  IRC *net;
  NICK *nick;

  if (!unick || !from || !(net = _ircch_get_network2 (strrchr (client->name, '@'))))
    return;				/* hmm, it's impossible!? */
  nick = _ircch_get_nick (net, unick, 1);
  CHECKHOSTSET (nick, from);
  _ircch_net_got_activity (net, NULL);
  if (nick->split)			/* nick is in split, go to check */
  {
    netsplit *split = nick->split; /* the same as _ircch_netjoin_add() does */

    dprint (4, "ipam_ircch on %s: check split %s", nick->name, split->servers);
    if (split->stage == 1)
    {
      New_Request (net->neti, F_QUICK, "LINKS %s", NextWord(split->servers));
      split->stage = 2;			/* going to stage 2 now */
    }
  }
}


/*
 * "new-lname" binding
 *   void func (char *newlname, char *oldlname);
 */
BINDING_TYPE_new_lname (nl_ircch);
static void nl_ircch (char *nl, char *ol)
{
  LEAF *l = NULL;
  NICK *nick;

  while ((l = Next_Leaf (IRCNetworks, l, NULL)))
  {
    nick = Find_Key (((IRC *)l->s.data)->lnames, ol);
    if (nick)
    {
      if (Delete_Key (((IRC *)l->s.data)->lnames, nick->lname, nick))
	ERROR ("nl_ircch: tree error on deleting %s", nick->lname);
      FREE (&nick->lname);
      nl = safe_strdup (nl);
      if (Insert_Key (&((IRC *)l->s.data)->lnames, nl, nick, 1))
	ERROR ("nl_ircch: tree error on adding %s", nl);
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
BINDING_TYPE_ison (ison_irc);
static int ison_irc (const char *netn, const char *channel, const char *lname,
		     const char **name)
{
  IRC *net;
  NICK *nick;
  CHANNEL *ch;
  LINK *link = NULL;		/* make compiler happy */

  dprint (4, "ircch: ison request for %s on \"%s%s\"", NONULL(lname),
	  NONULL(channel), channel ? "" : NONULL(netn));
  if (netn && (net = _ircch_get_network2 (netn)))
  {
    if (!lname)			/* inspect own nick */
      nick = net->me;
    else			/* inspect other nick visibility */
      nick = Find_Key (net->lnames, lname);
    if (nick && channel)	/* inspect channel presence */
    {
      if ((ch = _ircch_get_channel0 (net, channel, NULL)))
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
static inline int _ircch_is_hostmask (const char *name)
{
  register char *c = safe_strchr ((char *)name, '!');

  if (!c || safe_strchr ((char *)name, '@') < c)
    return 0;
  return 1;
}

BINDING_TYPE_inspect_client (incl_irc);
static modeflag incl_irc (const char *netn, const char *channel, const char *name,
			  const char **lname, const char **host, time_t *idle,
			  short *cnt)
{
  IRC *net;
  NICK *nick = NULL; /* don't need NULL really (see below) but gcc warns me */
  CHANNEL *ch;
  LINK *link = NULL;
  LIST *list = NULL, *listi, *liste;
  char *uh;
  modeflag mf = 0;
  int n;
  char lcname[HOSTMASKLEN+1];
  
  dprint (4, "ircch: ispect-client request for %s on \"%s%s\"", NONULL(name),
	  NONULL(channel), channel ? "" : NONULL(netn));
  /* check all at first */
  if (netn && (net = _ircch_get_network2 (netn)))
  {
    if (!channel)
      ch = NULL;		/* request for global */
    else if (!(ch = _ircch_get_channel0 (net, channel, NULL)))
      net = NULL;		/* request for unknown channel */
    if (net)
    {
      if (!name || _ircch_is_hostmask (name))
	nick = NULL;
      else
      {
	if (net->lc)
	{
	  net->lc (lcname, name, sizeof(lcname));
	  name = lcname;
	}
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
	  char *name2 = safe_strdup (name);
	  uh = safe_strchr (name2, '!');
	  *uh = 0;
	  if (net->lc)
	    n = net->lc (lcname, name2, NAMEMAX+1);
	  else
	    n = strfcpy (lcname, name2, NAMEMAX+1);
	  *uh = '!';
	  unistrlower (&lcname[n], uh, sizeof(lcname) - n);
	  FREE (&name2);
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
	register LINK *link2;

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
  /* TODO: recheck lname now, it may be without A_ISON even */
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
  if (cnt)
    *cnt = (list || !link) ? 0 : link->count;
  return mf;
}


/*
 * "irc-priv-msg-ctcp" binding
 *   int func (INTERFACE *client, unsigned char *who, char *lname,
 *             char *unick, char *msg);
 */
BINDING_TYPE_irc_priv_msg_ctcp (ctcp_identify);
static int ctcp_identify (INTERFACE *client, unsigned char *who, char *lname,
			  char *lcnick, char *msg)
{
  clrec_t *clr;
  IRC *net;
  NICK *nick;
  char *epass, *ln;
  lid_t id;

  /* check if command has password */
  if (!msg || !*msg)
    return 0;				/* silently ignore request */
  /* check if lcnick is existing lname */
  else if (!(clr = Lock_Clientrecord (lcnick)))
    New_Request (client, F_T_NOTICE, _("I don't know anyone with name %s."),
		 lcnick);
  /* check if it's on one of channels where I'm on too */
  else if (!(net = _ircch_get_network2 (strrchr (client->name, '@'))) ||
	   !(nick = _ircch_get_nick (net, lcnick, 0)) ||
	   !(nick->umode & A_ISON))
  {
    Unlock_Clientrecord (clr);
    New_Request (client, F_T_NOTICE,
		 _("Sorry, you aren't on any channel I'm on too."));
  }
  else
  {
    /* check if password matches */
    epass = safe_strdup (Get_Field (clr, "passwd", NULL));
    ln = safe_strdup (Get_Field (clr, NULL, NULL));
    id = Get_LID (clr);
    Unlock_Clientrecord (clr);
    if (Check_Passwd (msg, epass))	/* if does not match */
      New_Request (client, F_T_NOTICE, _("Password incorrect."));
    else				/* update state everywhere */
    {
      New_Request (client, F_T_NOTICE, _("You're recognized as %s."), lcnick);
      nick->umode |= A_REGISTERED;
      if (nick->channels)	/* update lname and wtmp for all channels */
	_ircch_recheck_link (net, nick->channels, ln, 0, 0, NULL, id);
    }
    FREE (&epass);
    FREE (&ln);
  }
  /* log this CTCP but hide password */
  while (*msg)
    *msg++ = '*';		/* replace each char */
  return 1;
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
  RegisterInteger ("irc-greet-time", &ircch_greet_time);
  RegisterInteger ("irc-mode-timeout", &ircch_mode_timeout);
  RegisterBoolean ("irc-join-on-invite", &ircch_join_on_invite);
  RegisterBoolean ("irc-ignore-ident-prefix", &ircch_ignore_ident_prefix);
  RegisterBoolean ("irc-kick-on-revenge", &ircch_kick_on_revenge);
  RegisterString ("irc-default-kick-reason", ircch_default_kick_reason,
		  sizeof(ircch_default_kick_reason), 0);
}

static void _ircch_leave_allchannels (void *net)
{
  New_Request (((IRC *)net)->neti, 0, "JOIN 0");
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
  INTERFACE *tmp;

  switch (sig)
  {
    case S_TERMINATE:
      /* unregister all variables and bindings */
      Delete_Binding ("irc-raw", &irc_invite, NULL);
      Delete_Binding ("irc-raw", &irc_join, NULL);
      Delete_Binding ("irc-raw", &irc_kick, NULL);
      Delete_Binding ("irc-raw", &irc_mode, NULL);
      Delete_Binding ("irc-raw", &irc_part, NULL);
      Delete_Binding ("irc-raw", &irc_topic, NULL);
      Delete_Binding ("irc-raw", &irc_rpl_userhost, NULL);
      Delete_Binding ("irc-raw", &irc_rpl_endofwho, NULL);
      Delete_Binding ("irc-raw", &irc_rpl_umodeis, NULL);
      Delete_Binding ("irc-raw", &irc_rpl_channelmodeis, NULL);
      Delete_Binding ("irc-raw", &irc_rpl_uniqopis, NULL);
      Delete_Binding ("irc-raw", &irc_rpl_notopic, NULL);
      Delete_Binding ("irc-raw", &irc_rpl_topic, NULL);
      Delete_Binding ("irc-raw", &irc_rpl_topicwhotime, NULL);
      Delete_Binding ("irc-raw", &irc_rpl_invitelist, NULL);
      Delete_Binding ("irc-raw", &irc_rpl_exceptlist, NULL);
      Delete_Binding ("irc-raw", &irc_rpl_whoreply, NULL);
      Delete_Binding ("irc-raw", &irc_rpl_namreply, NULL);
      Delete_Binding ("irc-raw", &irc_rpl_links, NULL);
      Delete_Binding ("irc-raw", &irc_rpl_endoflinks, NULL);
      Delete_Binding ("irc-raw", &irc_rpl_endofnames, NULL);
      Delete_Binding ("irc-raw", &irc_rpl_banlist, NULL);
      Delete_Binding ("irc-raw", &irc_err_nosuchchannel, NULL);
      Delete_Binding ("irc-raw", &irc_err_unknowncommand, NULL);
      Delete_Binding ("irc-raw", &irc_err_cannotsendtochan, NULL);
      Delete_Binding ("irc-raw", &irc_join_errors, NULL);
      Delete_Binding ("irc-raw", &irc_unexpected_error, NULL);
      Delete_Binding ("irc-raw", &irc_err_chanoprivsneeded, NULL);
      Delete_Binding ("irc-raw", &irc_err_nosuchnick, NULL);
      Delete_Binding ("irc-raw", &irc_err_usernotinchannel, NULL);
      Delete_Binding ("irc-raw", &irc_err_useronchannel, NULL);
      Delete_Binding ("irc-nickchg", (Function)&ircch_nick, NULL);
      Delete_Binding ("irc-signoff", (Function)&ircch_quit, NULL);
      Delete_Binding ("irc-netsplit", (Function)&ircch_netsplit, NULL);
      Delete_Binding ("irc-pub-msg-mask", (Function)&icam_ircch, NULL);
      Delete_Binding ("irc-pub-notice-mask", (Function)&icam_ircch, NULL);
      Delete_Binding ("irc-priv-msg-mask", (Function)&ipam_ircch, NULL);
      Delete_Binding ("irc-priv-notice-mask", (Function)&ipam_ircch, NULL);
      Delete_Binding ("irc-connected", (Function)&ic_ircch, NULL);
      Delete_Binding ("irc-disconnected", (Function)&id_ircch, NULL);
      Delete_Binding ("irc-priv-msg-ctcp", &ctcp_identify, NULL);
      Delete_Binding ("new-lname", (Function)&nl_ircch, NULL);
      Delete_Binding ("connect", &connect_ircchannel, NULL);
      Delete_Binding ("ison", &ison_irc, NULL);
      Delete_Binding ("inspect-client", (Function)&incl_irc, NULL);
      ircch_unset_ss(); /* "ss-irc" bindings */
      UnregisterVariable ("irc-netsplit-log-timeout");
      UnregisterVariable ("irc-netjoin-log-timeout");
      UnregisterVariable ("irc-netsplit-keep");
      UnregisterVariable ("irc-join-on-invite");
      UnregisterVariable ("irc-enforcer-time");
      UnregisterVariable ("irc-ban-keep");
      UnregisterVariable ("irc-greet-time");
      UnregisterVariable ("irc-mode-timeout");
      UnregisterVariable ("irc-ignore-ident-prefix");
      UnregisterVariable ("irc-kick-on-revenge");
      UnregisterVariable ("irc-default-kick-reason");
      Delete_Help ("irc-channel");
      /* part all channels in all networks */
      Destroy_Tree (&IRCNetworks, &_ircch_leave_allchannels);
      _forget_(NICK);
      _forget_(SplitMember);
      _forget_(LINK);
      iface->ift |= I_DIED;
      break;
    case S_SHUTDOWN:
      for (l1 = NULL; (l1 = Next_Leaf (IRCNetworks, l1, NULL)); )
	for (l2 = NULL;
	     (l2 = Next_Leaf (((IRC *)l1->s.data)->channels, l2, NULL)); )
	  _ircch_shutdown_channel ((CHANNEL *)l2->s.data);
      break;
    case S_REG:
      module_ircch_regall();
      break;
    case S_REPORT:
      tmp = Set_Iface (iface);
      New_Request (tmp, F_REPORT, "Module irc-channel: working.");
      for (l1 = NULL; (l1 = Next_Leaf (IRCNetworks, l1, NULL)); )
	for (l2 = NULL;
	     (l2 = Next_Leaf (((IRC *)l1->s.data)->channels, l2, NULL)); )
	{
	  register int i = 0, j = 0;
	  register LINK *link;

	  for (link = ((CHANNEL *)l2->s.data)->nicks; link; link = link->prevnick)
	  {
	    i++;
	    if (link->mode & (A_ADMIN | A_HALFOP | A_OP))
	      j++;
	  }
	  New_Request (tmp, F_REPORT, "   channel %s%s: %d nicks (%d privileged);",
		       ((CHANNEL *)l2->s.data)->real, ((IRC *)l1->s.data)->name,
		       i, j);
	  if (((CHANNEL *)l2->s.data)->topic)
	    New_Request (tmp, F_REPORT, "     topic is: %s",
			 ((CHANNEL *)l2->s.data)->topic->what);
	}
      Unset_Iface();
      break;
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
  Add_Binding ("irc-raw", "INVITE", 0, 0, &irc_invite, NULL);
  Add_Binding ("irc-raw", "JOIN", 0, 0, &irc_join, NULL);
  Add_Binding ("irc-raw", "KICK", 0, 0, &irc_kick, NULL);
  Add_Binding ("irc-raw", "MODE", 0, 0, &irc_mode, NULL);
  Add_Binding ("irc-raw", "PART", 0, 0, &irc_part, NULL);
  Add_Binding ("irc-raw", "TOPIC", 0, 0, &irc_topic, NULL);
  Add_Binding ("irc-raw", "221", 0, 0, &irc_rpl_umodeis, NULL);
  Add_Binding ("irc-raw", "302", 0, 0, &irc_rpl_userhost, NULL);
  Add_Binding ("irc-raw", "315", 0, 0, &irc_rpl_endofwho, NULL);
  Add_Binding ("irc-raw", "324", 0, 0, &irc_rpl_channelmodeis, NULL);
  Add_Binding ("irc-raw", "325", 0, 0, &irc_rpl_uniqopis, NULL);
  Add_Binding ("irc-raw", "331", 0, 0, &irc_rpl_notopic, NULL);
  Add_Binding ("irc-raw", "332", 0, 0, &irc_rpl_topic, NULL);
  Add_Binding ("irc-raw", "333", 0, 0, &irc_rpl_topicwhotime, NULL);
  Add_Binding ("irc-raw", "346", 0, 0, &irc_rpl_invitelist, NULL);
  Add_Binding ("irc-raw", "348", 0, 0, &irc_rpl_exceptlist, NULL);
  Add_Binding ("irc-raw", "352", 0, 0, &irc_rpl_whoreply, NULL);
  Add_Binding ("irc-raw", "353", 0, 0, &irc_rpl_namreply, NULL);
  Add_Binding ("irc-raw", "364", 0, 0, &irc_rpl_links, NULL);
  Add_Binding ("irc-raw", "365", 0, 0, &irc_rpl_endoflinks, NULL);
  Add_Binding ("irc-raw", "366", 0, 0, &irc_rpl_endofnames, NULL);
  Add_Binding ("irc-raw", "367", 0, 0, &irc_rpl_banlist, NULL);
  Add_Binding ("irc-raw", "401", 0, 0, &irc_err_nosuchnick, NULL);
  Add_Binding ("irc-raw", "403", 0, 0, &irc_err_nosuchchannel, NULL);
  Add_Binding ("irc-raw", "404", 0, 0, &irc_err_cannotsendtochan, NULL);
  Add_Binding ("irc-raw", "405", 0, 0, &irc_join_errors, NULL); /* TOOMANYCHANNELS */
  Add_Binding ("irc-raw", "407", 0, 0, &irc_join_errors, NULL); /* TOOMANYTARGETS */
  Add_Binding ("irc-raw", "411", 0, 0, &irc_unexpected_error, NULL); /* NORECIPIENT */
  Add_Binding ("irc-raw", "413", 0, 0, &irc_unexpected_error, NULL); /* NOTOPLEVEL */
  Add_Binding ("irc-raw", "414", 0, 0, &irc_unexpected_error, NULL); /* WILDTOPLEVEL */
  Add_Binding ("irc-raw", "421", 0, 0, &irc_err_unknowncommand, NULL);
  Add_Binding ("irc-raw", "437", 0, 0, &irc_join_errors, NULL); /* UNAVAILRESOURCE */
  Add_Binding ("irc-raw", "441", 0, 0, &irc_err_usernotinchannel, NULL);
  Add_Binding ("irc-raw", "442", 0, 0, &irc_err_nosuchchannel, NULL); /* NOTONCHANNEL */
  Add_Binding ("irc-raw", "443", 0, 0, &irc_err_useronchannel, NULL);
  Add_Binding ("irc-raw", "461", 0, 0, &irc_unexpected_error, NULL); /* NEEDMOREPARAMS */
  Add_Binding ("irc-raw", "462", 0, 0, &irc_unexpected_error, NULL); /* ALREADYREGISTRED */
  Add_Binding ("irc-raw", "467", 0, 0, &irc_unexpected_error, NULL); /* KEYSET */
  Add_Binding ("irc-raw", "471", 0, 0, &irc_join_errors, NULL); /* CHANNELISFULL */
  Add_Binding ("irc-raw", "472", 0, 0, &irc_unexpected_error, NULL); /* UNKNOWNMODE */
  Add_Binding ("irc-raw", "473", 0, 0, &irc_join_errors, NULL); /* INVITEONLYCHAN */
  Add_Binding ("irc-raw", "474", 0, 0, &irc_join_errors, NULL); /* BANNEDFROMCHAN */
  Add_Binding ("irc-raw", "475", 0, 0, &irc_join_errors, NULL); /* BADCHANNELKEY */
  Add_Binding ("irc-raw", "476", 0, 0, &irc_unexpected_error, NULL); /* BADCHANMASK */
  Add_Binding ("irc-raw", "477", 0, 0, &irc_unexpected_error, NULL); /* NOCHANMODES */
  Add_Binding ("irc-raw", "482", 0, 0, &irc_err_chanoprivsneeded, NULL);
  Add_Binding ("irc-raw", "484", 0, 0, &irc_unexpected_error, NULL); /* RESTRICTED */
  Add_Binding ("irc-raw", "485", 0, 0, &irc_unexpected_error, NULL); /* UNIQOPPRIVSNEEDED */
  Add_Binding ("irc-raw", "501", 0, 0, &irc_unexpected_error, NULL); /* UMODEUNKNOWNFLAG */
  Add_Binding ("irc-nickchg", "*", 0, 0, (Function)&ircch_nick, NULL);
  Add_Binding ("irc-signoff", "*", 0, 0, (Function)&ircch_quit, NULL);
  Add_Binding ("irc-netsplit", "*", 0, 0, (Function)&ircch_netsplit, NULL);
  Add_Binding ("irc-pub-msg-mask", "*", 0, 0, (Function)&icam_ircch, NULL);
  Add_Binding ("irc-pub-notice-mask", "*", 0, 0, (Function)&icam_ircch, NULL);
  Add_Binding ("irc-priv-msg-mask", "*", 0, 0, (Function)&ipam_ircch, NULL);
  Add_Binding ("irc-priv-notice-mask", "*", 0, 0, (Function)&ipam_ircch, NULL);
  Add_Binding ("irc-connected", "*", 0, 0, (Function)&ic_ircch, NULL);
  Add_Binding ("irc-disconnected", "*", 0, 0, (Function)&id_ircch, NULL);
  Add_Binding ("irc-priv-msg-ctcp", "IDENTIFY", U_ANY, U_NONE, &ctcp_identify, NULL);
  Add_Binding ("new-lname", "*", 0, 0, (Function)&nl_ircch, NULL);
  Add_Binding ("connect", "irc", U_NONE, U_SPECIAL, &connect_ircchannel, NULL); /* no network */
  Add_Binding ("ison", "irc", 0, 0, &ison_irc, NULL);
  Add_Binding ("inspect-client", "irc", 0, 0, (Function)&incl_irc, NULL);
  ircch_set_ss(); /* "ss-irc" bindings */
  /* TODO: add binding for "time-shift" */
  Add_Help ("irc-channel");
  /* set up variables */
  module_ircch_regall();
  format_irc_join = SetFormat ("irc_join",
			       _("%y%N%n(%@) has joined %#"));
  format_irc_part = SetFormat ("irc_part",
			       _("%^%N%^(%@) has left %# (%*)"));
  format_irc_nickchange = SetFormat ("irc_nickchange",
				     _("%^%N%^ is now known as %y%*%n"));
  format_irc_quit = SetFormat ("irc_quit",
			       _("%^%N%^(%@) has quit %# (%*)"));
  format_irc_lostinnetsplit = SetFormat ("irc_lost_in_netsplit",
				_("%^%N%^ has lost in netsplit (%*)"));
  format_irc_kick = SetFormat ("irc_kick",
			       _("%^%N%^ has kicked %L from %# (%*)"));
  format_irc_modechange = SetFormat ("irc_modechange",
				     _("mode/%# (%*) by %^%N%^"));
  format_irc_netsplit = SetFormat ("irc_netsplit",
				   _("netsplit (%*), quits: %N"));
  format_irc_netjoin = SetFormat ("irc_netjoin",
				  _("netsplit of %* is over, joins: %N"));
  format_irc_topic = SetFormat ("irc_topic",
				_("%N %?*changed?unset? the topic of %#%?* to: %*??"));
  format_irc_topic_is = SetFormat ("irc_topic_is",
				   _("Topic on %# is: %*"));
  format_irc_topic_by = SetFormat ("irc_topic_by",
				   _("Topic for %# is set %@ by %N"));
  /* request for all already connected networks to get our autojoins */
  NewTimer (I_MODULE, "irc", S_FLUSH, 1, 0, 0, 0);
  return ((Function)&module_ircch_signal);
}
