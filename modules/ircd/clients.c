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
 *     You should have received a copy of the GNU General Public License
 *     along with this program; if not, write to the Free Software
 *     Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * This file is a part of FoxEye IRCd module: user commands (RFC2812).
 */

#include <foxeye.h>
#if IRCD_USES_ICONV == 0 || (defined(HAVE_ICONV) && (IRCD_NEEDS_TRANSLIT == 0 || defined(HAVE_CYRILLIC_TRANSLIT)))
#include <modules.h>
#include <list.h>
#include <init.h>
#include <conversion.h>

#include "ircd.h"
#include "numerics.h"


/* ---------------------------------------------------------------------------
 * Common internal functions.
 */
#define _ircd_find_client_lc(I,X) Find_Key ((I)->clients, X)

#define _ircd_find_channel_lc(I,X) Find_Key ((I)->channels, X)

static inline MEMBER *_ircd_is_on_channel (CLIENT *cl, CHANNEL *ch)
{
  register MEMBER *m;

  for (m = ch->users; m; m = m->prevnick)
    if (m->who == cl)
      break;
  return m;
}

/* Checks if testing host matched to any hostmask of received host list */
static int _ircd_client_receiver (INTERFACE *iface, REQUEST *req)
{
  if (req && *(char *)iface->data)	/* we still need to check */
  {
    char *c, *next;

    for (c = req->string; *c; c = next)
    {
      next = gettoken (c, NULL);	/* split with next host */
      if (simple_match (c, iface->data) > 0)	/* host matches! */
      {
	*(char *)iface->data = '\0';	/* mark it done */
	break;
      }
    }
  }
  return REQ_OK;
}


/* ---------------------------------------------------------------------------
 * Check message binding.
 */
static int ichmsg_ircd (modeflag umode, modeflag mmode, char *msg)
{
  if (mmode & A_QUIET)
    return 0;
  if (!(umode & A_ISON) && (mmode & A_NOOUTSIDE))
    return 0;
  if (umode & (A_OP | A_ADMIN))		/* ops can send always */
    return 1;
  if ((mmode & A_MODERATED) && !(umode & A_VOICE))
    return 0;
  if (umode & A_DENIED)			/* banned are silent */
    return 0;
  return -1;				/* default to allow */
}


/* ---------------------------------------------------------------------------
 * Client protocol bindings.
 */

/* note: if channel mode is A_INVISIBLE then it should not be broadcasted
   and any type of messages for it from servers should generate an error!!! */

/* usage: if (CHECK_NOMEMBER(member,client,channame)) print error; */
#define CHECK_NOMEMBER(a,b,c) \
  a == NOSUCHCHANNEL) /* channel does not exist */ \
    return ircd_do_unumeric (b, ERR_NOSUCHCHANNEL, b, 0, c); \
  else if (!a

/* usage: CHECK_PRESENCE(member,client,channame); */
#define CHECK_PRESENCE(a,b,c) \
  if (CHECK_NOMEMBER (a,b,c)) \
    return ircd_do_unumeric (b, ERR_NOTONCHANNEL, b, 0, c)

BINDING_TYPE_ircd_client_cmd(ircd_oper_cb);
static int ircd_oper_cb(INTERFACE *srv, struct peer_t *peer, char *lcnick, char *user,
			char *host, int argc, const char **argv)
{ /* args: <name> <password> */
  CLIENT *cl = ((struct peer_priv *)peer->iface->data)->link->cl;
  struct clrec_t *u;
  userflag fl;
  char *pass, *uh;
  INTERFACE *chk;
  lid_t id;
  size_t sz;
  int i;

  if (argc < 2)
    return ircd_do_unumeric (cl, ERR_NEEDMOREPARAMS, cl, 0, NULL);
  u = Lock_Clientrecord (argv[0]);
  if (!u)
    return ircd_do_unumeric (cl, ERR_NOOPERHOST, cl, 0, NULL);
  fl = Get_Flags (u, srv->name);
  if (!(fl & (U_OP | U_HALFOP)))
    return ircd_do_unumeric (cl, ERR_NOOPERHOST, cl, 0, NULL);
  /* we hope we never get OPER flood so doing memory allocation here */
  pass = safe_strdup (Get_Field (u, "passwd", NULL));
  id = Get_LID (u);
  Unlock_Clientrecord (u);
  sz = strlen (peer->dname) + strlen (user) + strlen (host) + 3;
  uh = safe_malloc (sz);
  snprintf (uh, sz, "%s!%s@%s", peer->dname, user, host);
  chk = Add_Iface (I_TEMP, NULL, NULL, &_ircd_client_receiver, uh);
  i = Get_Hostlist (chk, id);
  if (i != 0)
  {
    Set_Iface (chk);
    while (Get_Request());
    Unset_Iface();
    if (uh[0] != '\0')			/* was reset by check */
      i = 0;
  }
  chk->ift = I_DIED;
  if (i == 0)
  {
    FREE (&pass);
    return ircd_do_unumeric (cl, ERR_NOOPERHOST, cl, 0, NULL);
  }
  if (!pass || Check_Passwd (argv[1], pass))
  {
    FREE (&pass);
    return ircd_do_unumeric (cl, ERR_PASSWDMISMATCH, cl, 0, NULL);
  }
  FREE (&pass);
  if (fl & U_OP)
  {
    cl->umode |= A_OP;			/* global oper */
    New_Request (peer->iface, 0, "MODE %s +o", peer->dname);
    ircd_sendto_servers_new ((IRCD *)srv->data, NULL, ":%s IMODE %d %s +o",
			     peer->dname, ircd_new_id(), peer->dname);
    ircd_sendto_servers_old ((IRCD *)srv->data, NULL, ":%s MODE %s +o",
			     peer->dname, peer->dname);
  }
  else
  {
    cl->umode |= A_HALFOP;		/* local oper */
    New_Request (peer->iface, 0, "MODE %s +O", peer->dname);
  }
  return ircd_do_unumeric (cl, RPL_YOUREOPER, cl, 0, NULL);
}

BINDING_TYPE_ircd_client_cmd(ircd_quit_cb);
static int ircd_quit_cb(INTERFACE *srv, struct peer_t *peer, char *lcnick, char *user,
			char *host, int argc, const char **argv)
{ /* args: [<Quit Message>] */
  CLIENT *cl = ((struct peer_priv *)peer->iface->data)->link->cl;
  char msg[STRING];

  if (argc == 0)
    strfcpy (msg, "I Quit", sizeof(msg));
  else
  {
    size_t sz = unistrcut (argv[0], sizeof(msg)-3, 256); /* cut it */
    snprintf (msg, sizeof(msg), "\"%.*s\"", (int)sz, argv[0]); /* quote it */
  }
#ifdef USE_SERVICES
  //TODO: do with services
#endif
  ircd_sendto_servers_all_ack ((IRCD *)srv->data, cl, NULL, NULL,
			       ":%s QUIT :%s", peer->dname, msg);
  ircd_prepare_quit (cl, cl->via, msg);
  Add_Request (I_PENDING, "*", 0, ":%s QUIT :%s", peer->dname, msg);
  cl->hold_upto = Time;
  cl->host[0] = '\0';			/* for collision check */
  return 1;
}

BINDING_TYPE_ircd_client_cmd(ircd_squit_cb);
static int ircd_squit_cb(INTERFACE *srv, struct peer_t *peer, char *lcnick, char *user,
			 char *host, int argc, const char **argv)
{ /* args: <server> <comment> */
  CLIENT *cl = ((struct peer_priv *)peer->iface->data)->link->cl;
  CLIENT *tgt;

  if (argc < 2)
  {
    if (!(cl->umode & (A_OP | A_HALFOP)))
      ircd_do_unumeric (cl, ERR_NOPRIVILEGES, cl, 0, NULL);
    return ircd_do_unumeric (cl, ERR_NEEDMOREPARAMS, cl, 0, NULL);
  }
  tgt = ircd_find_client (argv[0], NULL);
  if (!(cl->umode & (A_OP | A_HALFOP)))
  {
    if (!tgt)
      ircd_do_unumeric (cl, ERR_NOSUCHSERVER, cl, 0, argv[0]);
    return ircd_do_unumeric (cl, ERR_NOPRIVILEGES, cl, 0, NULL);
  }
  if (!tgt || CLIENT_IS_ME(tgt) || !CLIENT_IS_SERVER(tgt))
    return ircd_do_unumeric (cl, ERR_NOSUCHSERVER, cl, 0, argv[0]);
  /* we doing squit only for shortest way despite of possible multiconnect! */
  if (CLIENT_IS_LOCAL(tgt)) {		/* squit if it's local link */
    ircd_sendto_wallops((IRCD *)srv->data, "SQUIT %s from %s: %s", argv[0],
			cl->nick, argv[1]);
    ircd_do_squit (tgt->via->link, NULL, argv[1]); /* do job */
  } else				/* or else forward it to it's links */
    ircd_sendto_remote (tgt, ":%s SQUIT %s :%s", peer->dname, argv[0], argv[1]);
  return 1;
}

BINDING_TYPE_ircd_client_cmd(ircd_part_cb);
static int ircd_part_cb(INTERFACE *srv, struct peer_t *peer, char *lcnick, char *user,
			char *host, int argc, const char **argv)
{ /* args: <channel>[,<channel> ...] [<Part Message>] */
  CLIENT *cl = ((struct peer_priv *)peer->iface->data)->link->cl;
  char *c;
  const char *msg;

  if (argc == 0)
    return ircd_do_unumeric (cl, ERR_NEEDMOREPARAMS, cl, 0, NULL);
  if (argc == 1)
    msg = peer->dname;
  else
    msg = argv[1];
  for (c = (char *)argv[0]; c; )
  {
    char *cc, *cmask;
    MEMBER *memb;

    cc = strchr (c, ',');
    if (cc)
      *cc++ = 0;
    memb = ircd_find_member ((IRCD *)srv->data, argv[0], cl);
    if (memb == NOSUCHCHANNEL)
      ircd_do_unumeric (cl, ERR_NOSUCHCHANNEL, cl, 0, c);
    else if (!memb)
      ircd_do_unumeric (cl, ERR_NOTONCHANNEL, cl, 0, c);
    else
    {
      if ((memb->chan->mode & A_QUIET)) /* notify only sender */
	New_Request (peer->iface, 0, ":%s!%s@%s PART %s :%s", cl->nick, user,
		     host, memb->chan->name, msg);
      else				/* notify local users */
      {
	if (memb->chan->mode & A_ANONYMOUS)
	{
	  New_Request (peer->iface, 0, ":%s!%s@%s PART %s :%s", cl->nick, user,
		       host, memb->chan->name, msg);
	  ircd_sendto_chan_butone (memb->chan, cl,
				   ":anonymous!anonymous@anonymous. PART %s :anonymous",
				   memb->chan->name);
	}
	else
	  ircd_sendto_chan_local (memb->chan, ":%s!%s@%s PART %s :%s", cl->nick,
				  user, host, memb->chan->name, msg);
      }
#ifdef USE_SERVICES
      //TODO: notify services
#endif
      if (memb->chan->mode & A_INVISIBLE) ; /* local channel */
      else if ((cmask = strchr (c, ':'))) /* notify servers */
      {
	cmask++;
	ircd_sendto_servers_mask_all_ack ((IRCD *)srv->data, cl, memb->chan,
					  NULL, cmask, ":%s PART %s :%s",
					  cl->nick, memb->chan->name, msg);
      }
      else
	ircd_sendto_servers_all_ack ((IRCD *)srv->data, cl, memb->chan, NULL,
				     ":%s PART %s :%s", cl->nick,
				     memb->chan->name, msg);
      ircd_del_from_channel ((IRCD *)srv->data, memb, 0);
    }
    c = cc;
  }
  return 1;
}

BINDING_TYPE_ircd_client_cmd(ircd_topic_cb);
static int ircd_topic_cb(INTERFACE *srv, struct peer_t *peer, char *lcnick, char *user,
			 char *host, int argc, const char **argv)
{ /* args: <channel> [<topic>] */
  CLIENT *cl = ((struct peer_priv *)peer->iface->data)->link->cl;
  MEMBER *memb;
  CHANNEL *ch;
  register size_t sz;
  char *cmask;

  if (argc == 0)
    return ircd_do_unumeric (cl, ERR_NEEDMOREPARAMS, cl, 0, NULL);
  memb = ircd_find_member ((IRCD *)srv->data, argv[0], NULL);
#ifdef IRCD_PUBLIC_TOPIC
  if (memb == NOSUCHCHANNEL)
#else
  if (memb == NOSUCHCHANNEL || memb == NULL)
#endif
    return ircd_do_unumeric (cl, ERR_NOTONCHANNEL, cl, 0, argv[0]);
  ch = memb->chan;
  memb = _ircd_is_on_channel(cl, ch);
#ifdef IRCD_PUBLIC_TOPIC
  /* private and secret channels should be not visible such way - RFC2811 */
  if ((ch->mode & (A_PRIVATE | A_SECRET | A_TOPICLOCK | A_NOOUTSIDE)) &&
      memb == NULL)
#else
  if (memb == NULL)
#endif
    return ircd_do_unumeric (cl, ERR_NOTONCHANNEL, cl, 0, argv[0]);
  if (argc == 1)			/* it's query */
  {
    if (ch->topic[0])
      return ircd_do_cnumeric (cl, RPL_TOPIC, ch, 0, ch->topic);
    return ircd_do_cnumeric (cl, RPL_NOTOPIC, ch, 0, NULL);
  }
  if ((ch->mode & A_TOPICLOCK) && !(memb->mode & (A_ADMIN | A_OP)))
  {
    if (ch->name[0] == '+')
      return ircd_do_cnumeric (cl, ERR_NOCHANMODES, ch, 0, NULL);
    return ircd_do_cnumeric (cl, ERR_CHANOPRIVSNEEDED, ch, 0, NULL);
  }
  sz = unistrcut (argv[1], sizeof(ch->topic), TOPICLEN); /* validate */
  strfcpy (ch->topic, argv[1], sz+1);
  ircd_sendto_chan_local(ch, ":%s!%s@%s TOPIC %s :%s", peer->dname, user, host,
			 ch->name, ch->topic);
  if (ch->mode & A_INVISIBLE)		/* it's local channel */
    return 1;
  cmask = strchr (ch->name, ':');
  if (cmask)
  {
    cmask++; /* don't place this in macro below */
    ircd_sendto_servers_mask_new ((IRCD *)srv->data, NULL, cmask,
				  ":%s ITOPIC %d %s :%s", peer->dname,
				  ircd_new_id(), ch->name, ch->topic);
    ircd_sendto_servers_mask_old ((IRCD *)srv->data, NULL, cmask,
				  ":%s TOPIC %s :%s", peer->dname, ch->name,
				  ch->topic);
    return 1;
  }
  ircd_sendto_servers_new ((IRCD *)srv->data, NULL, ":%s ITOPIC %d %s :%s",
			   peer->dname, ircd_new_id(), ch->name, ch->topic);
  ircd_sendto_servers_old ((IRCD *)srv->data, NULL, ":%s TOPIC %s :%s",
			   peer->dname, ch->name, ch->topic);
  return 1;
}

BINDING_TYPE_ircd_client_cmd(ircd_invite_cb);
static int ircd_invite_cb(INTERFACE *srv, struct peer_t *peer, char *lcnick, char *user,
			  char *host, int argc, const char **argv)
{ /* args: <nickname> <channel> */
  CLIENT *cl = ((struct peer_priv *)peer->iface->data)->link->cl, *tgt;
  MEMBER *memb;

  if (argc < 2)
    return ircd_do_unumeric (cl, ERR_NEEDMOREPARAMS, cl, 0, NULL);
  tgt = ircd_find_client (argv[0], NULL);
  if (!tgt || (tgt->umode & (A_SERVER|A_SERVICE)))
    ircd_do_unumeric (cl, ERR_NOSUCHNICK, cl, 0, argv[0]);
  memb = ircd_find_member ((IRCD *)srv->data, argv[1], cl);
  if (memb != NOSUCHCHANNEL)
  {
    if (!memb)
      return ircd_do_unumeric (cl, ERR_NOTONCHANNEL, cl, 0, argv[1]);
    if ((memb->chan->mode & A_INVITEONLY) && !(memb->mode & A_OP))
      return ircd_do_cnumeric (cl, ERR_CHANOPRIVSNEEDED, memb->chan, 0, NULL);
    if (tgt && _ircd_is_on_channel (tgt, memb->chan))
      return ircd_do_unumeric (cl, ERR_USERONCHANNEL, tgt, 0, argv[1]);
  }
  if (!tgt)
    return 1;
  ircd_sendto_one (tgt, "INVITE %s %s", argv[0], argv[1]);
  if (!CLIENT_IS_REMOTE(tgt) && memb != NOSUCHCHANNEL)
    ircd_add_invited (tgt, memb->chan);
  if (tgt->away[0])
    ircd_do_unumeric (cl, RPL_AWAY, tgt, 0, tgt->away);
  return ircd_do_unumeric (cl, RPL_INVITING, tgt, 0, argv[1]);
}

BINDING_TYPE_ircd_client_cmd(ircd_kick_cb);
static int ircd_kick_cb(INTERFACE *srv, struct peer_t *peer, char *lcnick, char *user,
			char *host, int argc, const char **argv)
{ /* args: <channel>[,<channel> ...] <user>[,<user> ...] [<comment>] */
  CLIENT *cl = ((struct peer_priv *)peer->iface->data)->link->cl, *tgt;
  MEMBER *memb, *tm;
  const char *reason;
  char *lcl, *lch, *chn, *nlcl, *nchn;
  register char *cmask;

  if (argc < 2)
    return ircd_do_unumeric (cl, ERR_NEEDMOREPARAMS, cl, 0, NULL);
  if (argc == 3)
    reason = argv[2];
  else
    reason = peer->dname;
  lch = strchr (argv[0], ',');
  for (chn = nchn = (char *)argv[0], lcl = (char *)argv[1]; lcl;
	lcl = nlcl, chn = nchn)
  {
    nlcl = strchr (lcl, ',');
    if (nlcl)
      *nlcl++ = 0;
    if (lch && chn && (nchn = strchr (chn, ',')))
      *nchn++ = 0;
    if (!chn)
      ircd_do_unumeric (cl, ERR_BADCHANMASK, cl, 0, "");
    else if ((memb = ircd_find_member ((IRCD *)srv->data, chn, cl))
	     == NOSUCHCHANNEL)
      ircd_do_unumeric (cl, ERR_NOSUCHCHANNEL, cl, 0, chn);
    else if (memb == NULL)
      ircd_do_unumeric (cl, ERR_NOTONCHANNEL, cl, 0, chn);
    else if (!(memb->mode & A_OP))
      ircd_do_cnumeric (cl, ERR_CHANOPRIVSNEEDED, memb->chan, 0, NULL);
    else if (!(tgt = ircd_find_client (lcl, NULL)) ||
	     !(tm = _ircd_is_on_channel (tgt, memb->chan)))
      ircd_do_unumeric (cl, ERR_USERNOTINCHANNEL, cl, 0, chn);
    else
    {
      ircd_sendto_chan_local (memb->chan, ":%s!%s@%s KICK %s %s :%s",
			      peer->dname, user, host, chn, lcl, reason);
#ifdef USE_SERVICES
      //TODO: inform services
#endif
      if (memb->chan->mode & A_INVISIBLE) ;
      else if ((cmask = strchr (memb->chan->name, ':'))) {
	cmask++; /* not put '++' into macro below */
	ircd_sendto_servers_mask_all_ack ((IRCD *)srv->data, tgt, memb->chan,
					  NULL, cmask, ":%s KICK %s %s :%s",
					  peer->dname, memb->chan->name,
					  tgt->nick, reason);
      } else
	ircd_sendto_servers_all_ack ((IRCD *)srv->data, tgt, memb->chan, NULL,
				     ":%s KICK %s %s :%s", peer->dname,
				     memb->chan->name, tgt->nick, reason);
      ircd_del_from_channel ((IRCD *)srv->data, tm, 0);
    }
  }
  return 1;
}

BINDING_TYPE_ircd_client_cmd(ircd_servlist_cb);
static int ircd_servlist_cb(INTERFACE *srv, struct peer_t *peer, char *lcnick, char *user,
			    char *host, int argc, const char **argv)
{ /* args: [<mask>[ <type>]] */
  CLIENT *cl = ((struct peer_priv *)peer->iface->data)->link->cl;
  CLIENT *tgt;
#ifdef USE_SERVICES
  CLIENT *me = ircd_find_client(NULL, NULL);
#endif
  LEAF *l = NULL;
  NODE *t = ((IRCD *)srv->data)->clients;
  const char *mask;
  char buf[MESSAGEMAX];

  if (argc > 0)
    mask = argv[0];
  else
    mask = "*";
  /* 'type' parameter is currently not in use as RFC2812 says */
  while ((l = Next_Leaf (t, l, NULL)))
  {
    tgt = l->s.data;
    if (!tgt->hold_upto && CLIENT_IS_SERVICE (tgt) &&
	simple_match (mask, tgt->lcnick) >= 0)
    {
      snprintf (buf, sizeof(buf), "%s %s %s %hu :%s",
#ifdef USE_SERVICES
      !CLIENT_IS_REMOTE (tgt) ? me :
#endif
		tgt->cs->nick, mask, tgt->away, tgt->hops, tgt->fname);
      ircd_do_unumeric (cl, RPL_SERVLIST, tgt, 0, buf);
    }
  }
  snprintf (buf, sizeof(buf), "%s %s", mask, "*"); /* 'type' isn't in use now */
  return ircd_do_unumeric (cl, RPL_SERVLISTEND, cl, 0, buf);
}

static inline void _ircd_who_reply (CLIENT *rq, CLIENT *srv, CLIENT *tgt,
				    MEMBER *m)
{
  char buf[MESSAGEMAX];

  if (m)
  {
    char ch[2];

    ch[1] = 0;
    if (m->mode & A_ADMIN)
      ch[0] = '@';
    else
      ch[0] = ircd_mode2whochar (m->mode);
    snprintf (buf, sizeof(buf), "%s %s %s %s %s %c%s%s :%hu %s", m->chan->name,
	      tgt->user, tgt->host, srv->lcnick, tgt->nick,
	      (tgt->umode & A_AWAY) ? 'G' : 'H',
	      (tgt->umode & (A_OP | A_HALFOP)) ? "*" : "", ch, tgt->hops,
	      tgt->fname);
  }
  else
    snprintf (buf, sizeof(buf), "* %s %s %s %s %c%s :%hu %s", tgt->user,
	      tgt->host, srv->lcnick, tgt->nick, (tgt->umode & A_AWAY) ? 'G' : 'H',
	      (tgt->umode & (A_OP | A_HALFOP)) ? "*" : "", tgt->hops, tgt->fname);
  ircd_do_unumeric (rq, RPL_WHOREPLY, rq, 0, buf);
}

BINDING_TYPE_ircd_client_cmd(ircd_who_cb);
static int ircd_who_cb(INTERFACE *srv, struct peer_t *peer, char *lcnick,
		       char *user, char *host, int argc, const char **argv)
{ /* args: [<mask>[ "o"]] */
  CLIENT *cl = ((struct peer_priv *)peer->iface->data)->link->cl;
  const char *mask = NULL;
  CLIENT *tgt, *me = ircd_find_client(NULL, NULL);
  MEMBER *m, *mc;
  modeflag mmf = 0;

  if (argc > 0)
  {
    if (argc > 1 && !strcmp (argv[1], "o"))
      mmf = (A_OP | A_HALFOP);
    if ((argv[0])[1] != '\0' || (*argv[0] != '0' && *argv[0] != '*'))
      mask = argv[0];
  }
  if (!mask || strpbrk (mask, "*?.")) { /* so we have wildcards, ok */
    LINK *link;
    int i, smatched = 0;

    /* do every server starting from me */
    for (i = 0; i < ((IRCD *)srv->data)->s; i++)
      if ((tgt = ((IRCD *)srv->data)->token[i]) && !tgt->hold_upto)
      {
	if (mask)
	  smatched = simple_match (mask, tgt->lcnick);
	for (link = tgt->c.lients; link; link = link->prev)
	{
	  tgt = link->cl;
	  if (CLIENT_IS_SERVER (tgt) || (tgt->umode & mmf) != mmf)
	    continue;
	  if ((cl->umode & (A_OP | A_HALFOP)) || !(tgt->umode & A_INVISIBLE) ||
	      tgt == cl)
	    mc = (MEMBER *)1;
	  else
	    for (m = tgt->c.hannels; (mc = m); m = m->prevchan)
	      if (!(m->chan->mode & (A_PRIVATE | A_SECRET)) ||
		  ((!(m->chan->mode & (A_ANONYMOUS | A_QUIET))) &&
		   (mc = _ircd_is_on_channel (cl, mc->chan))))
		  break;
	  if (mc)
	    if (!mask || smatched >= 0 || simple_match (mask, tgt->host) >= 0 ||
		simple_match (mask, tgt->lcnick) >= 0 ||
		simple_match (mask, tgt->fname) >= 0) //TODO: LC search?
	      _ircd_who_reply (cl, (i == 0) ? me : tgt->cs, tgt, NULL);
	}
      }
  } else if ((m = ircd_find_member ((IRCD *)srv->data, mask, NULL)) &&
	     m != NOSUCHCHANNEL) {
    if (!(m->chan->mode & (A_ANONYMOUS | A_QUIET))) { /* users are hidden */
      mc = m;				/* allow seeing for opers */
      if ((cl->umode & (A_OP | A_HALFOP)) ||
	  (mc = _ircd_is_on_channel (cl, m->chan)) ||
	  !(m->chan->mode & (A_PRIVATE | A_SECRET)))
	for ( ; m; m = m->prevnick)
	  if ((m->mode & mmf) == mmf) /* use "o" parameter against chanmode */
	    if (mc || !(m->who->umode & A_INVISIBLE))
	      _ircd_who_reply (cl, CLIENT_IS_REMOTE (m->who) ? m->who->cs : me,
			       m->who, m); /* ME can be only in QUIET chan */
      }
  } else if ((tgt = ircd_find_client(mask, NULL)) != NULL &&
	     !CLIENT_IS_SERVER(tgt) && (tgt->umode & mmf) == mmf) {
    _ircd_who_reply (cl, CLIENT_IS_REMOTE (tgt) ? tgt->cs : me, tgt, NULL);
  } else if (tgt != NULL && CLIENT_IS_SERVER (tgt)) {
    LINK *link;

    for (link = tgt->c.lients; link; link = link->prev) {
      tgt = link->cl;
      if ((tgt->umode & mmf) == mmf)
	_ircd_who_reply (cl, CLIENT_IS_REMOTE (tgt) ? tgt->cs : me, tgt, NULL);
    }
  } else
    ircd_do_unumeric (cl, ERR_NOSUCHSERVER, cl, 0, mask);
  return ircd_do_unumeric (cl, RPL_ENDOFWHO, cl, 0, mask ? mask : "*");
}

#ifdef IRCD_ENABLE_KILL
BINDING_TYPE_ircd_client_cmd(ircd_kill_cb);
static int ircd_kill_cb(INTERFACE *srv, struct peer_t *peer, char *lcnick,
			char *user, char *host, int argc, const char **argv)
{ /* args: <nickname> <comment> */
  CLIENT *cl = ((struct peer_priv *)peer->iface->data)->link->cl, *tcl;
  char reason[MB_LEN_MAX*TOPICLEN+HOSTMASKLEN];
  int len;
  register char *c;

  if (argc < 2)
    return ircd_do_unumeric(cl, ERR_NEEDMOREPARAMS, cl, 0, NULL);
  tcl = ircd_find_client(argv[0], NULL);
  if (tcl == NULL)
    return ircd_do_unumeric(cl, ERR_NOSUCHNICK, cl, 0, argv[0]);
  if (CLIENT_IS_SERVER(tcl))
    return ircd_do_unumeric(cl, ERR_CANTKILLSERVER, cl, 0, argv[0]);
  if (!(cl->umode & A_OP) &&		/* global op can kill anyone */
      !(CLIENT_IS_LOCAL(tcl) && (cl->umode & A_HALFOP))) /* local - only local */
    return ircd_do_unumeric(cl, ERR_NOPRIVILEGES, cl, 0, NULL);
  len = unistrcut(argv[1], sizeof(reason), TOPICLEN);
  snprintf(reason, sizeof(reason), "%s!%s (%.*s)", cl->host, cl->nick, len,
	   argv[1]);			/* make the message with reason */
  //TODO: implement LOCAL_KILL_ONLY option
  if (!CLIENT_IS_REMOTE(tcl))
    New_Request(tcl->via->p.iface, 0, ":%s KILL %s :%s", cl->nick, tcl->nick,
		reason);		/* notify the victim */
  ircd_sendto_servers_all_ack((IRCD *)srv->data, tcl, NULL, NULL,
			      ":%s KILL %s :%s", cl->nick, tcl->nick, reason);
				/* broadcast KILL */
  ircd_prepare_quit(tcl, cl->via, "you are killed");
  tcl->hold_upto = Time + CHASETIMELIMIT; /* make 'nick delay' */
  for (c = NextWord(reason); c > reason && c[-1] != '!'; c--); /* find nick */
  Add_Request(I_PENDING, "*", 0, ":%s QUIT :Killed by %s", tcl->nick, c);
  tcl->host[0] = 0;		/* for collision check */
  Add_Request(I_LOG, "*", F_MODES, "KILL %s :%s", tcl->nick, reason);
  return (1);
}
#endif

BINDING_TYPE_ircd_client_cmd(ircd_away_cb);
static int ircd_away_cb(INTERFACE *srv, struct peer_t *peer, char *lcnick,
			char *user, char *host, int argc, const char **argv)
{ /* args: [<text>] */
  CLIENT *cl = ((struct peer_priv *)peer->iface->data)->link->cl;
  register size_t len;

  if (argc == 0 || *argv[0] == '\0') { /* unaway */
    cl->away[0] = '\0';
    cl->umode &= ~A_AWAY;
    ircd_sendto_servers_new((IRCD *)srv->data, NULL, ":%s IMODE %d %s :-a",
			    peer->dname, ircd_new_id(), peer->dname);
    ircd_sendto_servers_old((IRCD *)srv->data, NULL, ":%s MODE %s :-a",
			    peer->dname, peer->dname);
    return ircd_do_unumeric(cl, RPL_UNAWAY, cl, 0, NULL);
  }
  len = unistrcut(argv[0], sizeof(cl->away), AWAYLEN);
  strfcpy(cl->away, argv[0], len + 1); /* unistrcut includes '\0' */
  cl->umode |= A_AWAY;
  ircd_sendto_servers_new((IRCD *)srv->data, NULL, ":%s IMODE %d %s :+a",
			  peer->dname, ircd_new_id(), peer->dname);
  ircd_sendto_servers_old((IRCD *)srv->data, NULL, ":%s MODE %s :+a",
			  peer->dname, peer->dname);
  return ircd_do_unumeric(cl, RPL_NOWAWAY, cl, 0, NULL);
}

#ifdef IRCD_ENABLE_REHASH
BINDING_TYPE_ircd_client_cmd(ircd_rehash_cb);
static int ircd_rehash_cb(INTERFACE *srv, struct peer_t *peer, char *lcnick,
			  char *user, char *host, int argc, const char **argv)
{ /* args: none */
  CLIENT *cl = ((struct peer_priv *)peer->iface->data)->link->cl;
  static char cmd[] = ".rehash";

  if (!(cl->umode & (A_OP | A_HALFOP)))
    return ircd_do_unumeric(cl, ERR_NOPRIVILEGES, cl, 0, NULL);
  Dcc_Parse(peer, peer->dname, cmd, U_OWNER, 0, (int)peer->socket + 1, -1,
	    NULL, NULL);
  return ircd_do_unumeric(cl, RPL_REHASHING, cl, 0, NULL);
}
#endif

#ifdef IRCD_ENABLE_DIE
BINDING_TYPE_ircd_client_cmd(ircd_die_cb);
static int ircd_die_cb(INTERFACE *srv, struct peer_t *peer, char *lcnick,
		       char *user, char *host, int argc, const char **argv)
{ /* args: none */
  CLIENT *cl = ((struct peer_priv *)peer->iface->data)->link->cl;
  static char cmd[] = ".die";

  if (!(cl->umode & (A_OP | A_HALFOP)))
    return ircd_do_unumeric(cl, ERR_NOPRIVILEGES, cl, 0, NULL);
  Dcc_Parse(peer, peer->dname, cmd, U_OWNER, 0, (int)peer->socket + 1, -1,
	    NULL, NULL);
  return 1; /* never reached though */
}
#endif

#ifdef IRCD_ENABLE_RESTART
BINDING_TYPE_ircd_client_cmd(ircd_restart_cb);
static int ircd_restart_cb(INTERFACE *srv, struct peer_t *peer, char *lcnick,
			   char *user, char *host, int argc, const char **argv)
{ /* args: none */
  CLIENT *cl = ((struct peer_priv *)peer->iface->data)->link->cl;
  static char cmd[] = ".restart";

  if (!(cl->umode & (A_OP | A_HALFOP)))
    return ircd_do_unumeric(cl, ERR_NOPRIVILEGES, cl, 0, NULL);
  Dcc_Parse(peer, peer->dname, cmd, U_OWNER, 0, (int)peer->socket + 1, -1,
	    NULL, NULL);
  return 1;
}
#endif

BINDING_TYPE_ircd_client_cmd(ircd_userhost_cb);
static int ircd_userhost_cb(INTERFACE *srv, struct peer_t *peer, char *lcnick,
			    char *user, char *host, int argc, const char **argv)
{ /* args: <nickname>[ ...] */
  CLIENT *cl = ((struct peer_priv *)peer->iface->data)->link->cl, *tgt;
  int i;
  size_t s;
  const char *c;
  char nick[MB_LEN_MAX*NICKLEN+1];
  char buf[IRCMSGLEN-HOSTLEN-NICKLEN-9]; /* :server 302 user :reply\r\n */

  if (argc == 0)
    return ircd_do_unumeric(cl, ERR_NEEDMOREPARAMS, cl, 0, NULL);
  s = 0;
  for (i = 0; i < argc; i++) {
    for (c = argv[i]; *c; c = NextWord((char *)c)) /* it's still const */ {
      register size_t lt = 0;
      while (*c && *c != ' ' && lt < sizeof(nick) - 1)
	nick[lt++] = *c++;
      nick[lt] = '\0';
      tgt = ircd_find_client(nick, NULL);
      if (tgt == NULL || CLIENT_IS_SERVER(tgt))
	continue;
      if ((s + strlen(tgt->nick) + strlen(tgt->user) +
	  strlen(tgt->host)) >= (sizeof(buf) - 5)) {
	ircd_do_unumeric(cl, RPL_USERHOST, cl, 0, buf);
	s = 0;
      }
      if (s > 0)
	buf[s++] = ' ';
      s += strfcpy(&buf[s], tgt->nick, sizeof(buf) - s);
      if (tgt->umode & (A_OP | A_HALFOP))
	buf[s++] = '*';
      buf[s++] = '=';
      if (tgt->umode & A_AWAY)
	buf[s++] = '-';
      else
	buf[s++] = '+';
      s += strfcpy(&buf[s], tgt->user, sizeof(buf) - s);
      buf[s++] = '@';
      s += strfcpy(&buf[s], tgt->host, sizeof(buf) - s);
    }
  }
  if (s)
    ircd_do_unumeric(cl, RPL_USERHOST, cl, 0, buf);
  return 1;
}

BINDING_TYPE_ircd_client_cmd(ircd_ison_cb);
static int ircd_ison_cb(INTERFACE *srv, struct peer_t *peer, char *lcnick,
			char *user, char *host, int argc, const char **argv)
{ /* args: <nickname>[ ...] */
  CLIENT *cl = ((struct peer_priv *)peer->iface->data)->link->cl, *tgt;
  int i;
  size_t s;
  const char *c;
  char nick[MB_LEN_MAX*NICKLEN+1];
  char buf[IRCMSGLEN-HOSTLEN-NICKLEN-9]; /* :server 303 user :reply\r\n */

  if (argc == 0)
    return ircd_do_unumeric(cl, ERR_NEEDMOREPARAMS, cl, 0, NULL);
  s = 0;
  buf[0] = '\0';
  for (i = 0; i < argc; i++) {
    for (c = argv[i]; *c; c = NextWord((char *)c)) /* it's still const */ {
      register size_t lt = 0;
      while (*c && *c != ' ' && lt < sizeof(nick) - 1)
	nick[lt++] = *c++;
      nick[lt] = '\0';
      tgt = ircd_find_client(nick, NULL);
      if (tgt == NULL || CLIENT_IS_SERVER(tgt))
	continue;
      if (s + strlen(tgt->nick) >= sizeof(buf) - 1) /* space */
        break;				/* list too long */
      if (s > 0)
	buf[s++] = ' ';
      s += strfcpy(&buf[s], tgt->nick, sizeof(buf) - s);
    }
  }
  ircd_do_unumeric(cl, RPL_ISON, cl, 0, buf);
  return (-1);				/* don't reset idle time */
}

#if IRCD_USES_ICONV
BINDING_TYPE_ircd_client_cmd(ircd_charset_cb);
static int ircd_charset_cb(INTERFACE *srv, struct peer_t *peer, char *lcnick,
			   char *user, char *host, int argc, const char **argv)
{ /* args: [<charset>] */
  CLIENT *cl = ((struct peer_priv *)peer->iface->data)->link->cl;
  struct conversion_t *conv;

  if (argc > 0) {
    conv = Get_Conversion(argv[0]);
    if (conv == NULL && strcasecmp(Conversion_Charset(conv), argv[0]))
      return ircd_do_unumeric(cl, ERR_NOCODEPAGE, cl, 0, argv[0]);
    Free_Conversion(peer->iface->conv);
    peer->iface->conv = conv;
  }
  return ircd_do_unumeric(cl, RPL_CODEPAGE, cl, 0,
			  Conversion_Charset(peer->iface->conv));
}
#endif


/* ---------------------------------------------------------------------------
 * Common external functions.
 */


/* common end and start of channel protocol */
void ircd_client_proto_end (void)
{
  Delete_Binding ("ircd-check-message", &ichmsg_ircd, NULL);
  Delete_Binding ("ircd-client-cmd", &ircd_oper_cb, NULL);
  Delete_Binding ("ircd-client-cmd", &ircd_quit_cb, NULL);
  Delete_Binding ("ircd-client-cmd", &ircd_squit_cb, NULL);
  Delete_Binding ("ircd-client-cmd", &ircd_part_cb, NULL);
  Delete_Binding ("ircd-client-cmd", &ircd_topic_cb, NULL);
  Delete_Binding ("ircd-client-cmd", &ircd_invite_cb, NULL);
  Delete_Binding ("ircd-client-cmd", &ircd_kick_cb, NULL);
  Delete_Binding ("ircd-client-cmd", &ircd_servlist_cb, NULL);
  Delete_Binding ("ircd-client-cmd", &ircd_who_cb, NULL);
#ifdef IRCD_ENABLE_KILL
  Delete_Binding ("ircd-client-cmd", &ircd_kill_cb, NULL);
#endif
  Delete_Binding ("ircd-client-cmd", &ircd_away_cb, NULL);
#ifdef IRCD_ENABLE_REHASH
  Delete_Binding ("ircd-client-cmd", &ircd_rehash_cb, NULL);
#endif
#ifdef IRCD_ENABLE_DIE
  Delete_Binding ("ircd-client-cmd", &ircd_die_cb, NULL);
#endif
#ifdef IRCD_ENABLE_RESTART
  Delete_Binding ("ircd-client-cmd", &ircd_restart_cb, NULL);
#endif
  Delete_Binding ("ircd-client-cmd", &ircd_userhost_cb, NULL);
  Delete_Binding ("ircd-client-cmd", &ircd_ison_cb, NULL);
#if IRCD_USES_ICONV
  Delete_Binding ("ircd-client-cmd", &ircd_charset_cb, NULL);
#endif
}

void ircd_client_proto_start (void)
{
  Add_Binding ("ircd-check-message", "*", 0, 0, &ichmsg_ircd, NULL);
  Add_Binding ("ircd-client-cmd", "oper", 0, 0, &ircd_oper_cb, NULL);
  Add_Binding ("ircd-client-cmd", "quit", 0, 0, &ircd_quit_cb, NULL);
  Add_Binding ("ircd-client-cmd", "squit", 0, 0, &ircd_squit_cb, NULL);
  Add_Binding ("ircd-client-cmd", "part", 0, 0, &ircd_part_cb, NULL);
  Add_Binding ("ircd-client-cmd", "topic", 0, 0, &ircd_topic_cb, NULL);
  Add_Binding ("ircd-client-cmd", "invite", 0, 0, &ircd_invite_cb, NULL);
  Add_Binding ("ircd-client-cmd", "kick", 0, 0, &ircd_kick_cb, NULL);
  Add_Binding ("ircd-client-cmd", "servlist", 0, 0, &ircd_servlist_cb, NULL);
  Add_Binding ("ircd-client-cmd", "who", 0, 0, &ircd_who_cb, NULL);
#ifdef IRCD_ENABLE_KILL
  Add_Binding ("ircd-client-cmd", "kill", 0, 0, &ircd_kill_cb, NULL);
#endif
  Add_Binding ("ircd-client-cmd", "away", 0, 0, &ircd_away_cb, NULL);
#ifdef IRCD_ENABLE_REHASH
  Add_Binding ("ircd-client-cmd", "rehash", 0, 0, &ircd_rehash_cb, NULL);
#endif
#ifdef IRCD_ENABLE_DIE
  Add_Binding ("ircd-client-cmd", "die", U_HALFOP, 0, &ircd_die_cb, NULL);
#endif
#ifdef IRCD_ENABLE_RESTART
  Add_Binding ("ircd-client-cmd", "restart", U_HALFOP, 0, &ircd_restart_cb, NULL);
#endif
  Add_Binding ("ircd-client-cmd", "userhost", 0, 0, &ircd_userhost_cb, NULL);
  Add_Binding ("ircd-client-cmd", "ison", 0, 0, &ircd_ison_cb, NULL);
#if IRCD_USES_ICONV
  Add_Binding ("ircd-client-cmd", "charset", 0, 0, &ircd_charset_cb, NULL);
#endif
}
#endif
