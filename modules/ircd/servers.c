/*
 * Copyright (C) 2011  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 * This file is a part of FoxEye IRCd module: servers communication (RFC2813).
 */

#include <foxeye.h>
#if IRCD_USES_ICONV == 0 || (defined(HAVE_ICONV) && (IRCD_NEEDS_TRANSLIT == 0 || defined(HAVE_CYRILLIC_TRANSLIT)))
#include <modules.h>
#include <init.h>

#include "ircd.h"
#include "numerics.h"

#if IRCD_MULTICONNECT
ALLOCATABLE_TYPE (ACK, IrcdAck_, next)
#endif

/* -- common internal functions ------------------------------------------- */
#define _ircd_find_client_lc(S,X) Find_Key ((S)->clients, X)

static inline MEMBER *_ircd_is_on_channel (CLIENT *cl, CHANNEL *ch)
{
  register MEMBER *m;

  for (m = ch->users; m; m = m->prevnick)
    if (m->who == cl)
      break;
  return m;
}


#if IRCD_MULTICONNECT
/* -- acks management ----------------------------------------------------- */
/* adds one more ack to link */
void ircd_add_ack (struct peer_priv *link, CLIENT *who, CHANNEL *where)
{
  ACK **a;
  register ACK *ack;

  for (a = &link->acks; *a; a = &(*a)->next); /* go to end */
  *a = ack = alloc_ACK();
  ack->next = NULL;
  ack->who = who;
  ack->where = where;
  if (who)
    who->on_ack++;
  ack->contrary = 0;
  if (where != NULL && where != CHANNEL0)
    where->on_ack++;
}

/* removes first ack from link */
void ircd_drop_ack (IRCD *ircd, struct peer_priv *link)
{
  register ACK *ack = link->acks;

  link->acks = ack->next;
  if (ack->who) {
    ack->who->on_ack--;			/* unlock one more */
    if (Time > ack->who->hold_upto && !ack->who->on_ack)
      ircd_drop_nick (ack->who);	/* it was on hold by acks */
  }
  if (ack->where != NULL && ack->where != CHANNEL0) {
    ack->where->on_ack--;
    if (Time > ack->where->hold_upto && !ack->where->on_ack)
      ircd_drop_channel (ircd, ack->where); /* it was on hold by acks */
  }
  free_ACK (ack);
}

/* finds ack for client, on channel or global */
ACK *ircd_check_ack (struct peer_priv *link, CLIENT *who, CHANNEL *where)
{
  register ACK *ack;

  for (ack = link->acks; ack; ack = ack->next)
    if (!ack->contrary && ack->who == who && ack->where == where)
      return ack;
  return NULL;
}


/* -- ids management ------------------------------------------------------ */
static int localid = 0;

#define IRCD_ID_MAXVAL 0x7fffffff /* INT32_MAX - for 32bit arch compatibility */

/* generate new id for own messages */
int ircd_new_id(void)
{
  if (localid == IRCD_ID_MAXVAL)
    localid = 0;
  else
    localid++;
  return (localid);
}

/* set misseds to current and set current to id */
static inline void _ircd_extend_id(CLIENT *cl, int id)
{
  dprint(4, "ircd:_ircd_extend_id for %s: %d...%d/%d -> %d...%d/%d",
	 cl->lcnick, cl->last_id[2], cl->last_id[1], cl->last_id[0],
	 cl->last_id[0], id - 1, id);
  if (cl->last_id[2] >= 0)
    Add_Request(I_LOG, "*", F_WARN, "ircd:server %s has missed interval %d-%d "
		"and we got %d so we probably lost those", cl->lcnick,
		cl->last_id[2], cl->last_id[1], id);
  cl->last_id[2] = cl->last_id[0];
  cl->last_id[1] = id - 1;
  cl->last_id[0] = id;
}

/* if id isn't received yet then register it and return 1, else return 0 */
int ircd_test_id(CLIENT *cl, int id)
{
  if (cl == NULL || !CLIENT_IS_SERVER(cl)) {
    ERROR("ircd:ircd_test_id: called not for server");
    return (-1);
  }
  dprint(4, "ircd:ircd_test_id:server %s id %d", cl->lcnick, id);
  id &= IRCD_ID_MAXVAL;		/* get it to template */
  if (cl->last_id[0] < 0) {
    cl->last_id[0] = id;
    return (1);
  }
  if (id < cl->last_id[0]) {	/* it might get over margin or just duplicate */
    if (cl->last_id[0] - id > IRCD_ID_MAXVAL/2) { /* it's over margin */
      if (cl->last_id[0] == IRCD_ID_MAXVAL && id == 0)
	cl->last_id[0] = 0;
      else
	_ircd_extend_id(cl, id);
      return (1);
    }
    if (cl->last_id[2] < 0 || id <= cl->last_id[2])
      return (0);
    if (id == cl->last_id[2] + 1) { /* first in missed interval */
      if (id == cl->last_id[1])
	cl->last_id[2] = -1;	/* interval was filled */
      else
	cl->last_id[2] = id;
      return (1);
    }
    if (id == cl->last_id[1]) {
      cl->last_id[1] = id - 1;
      return (1);
    }
    ERROR("ircd:got message id=%d from %s inside of missed interval %d-%d "
	  "so may get duplicate later", id, cl->lcnick, cl->last_id[2],
	  cl->last_id[1]);
    return (1);			/* accept it anyway, may be bugged */
  }
  if (id == cl->last_id[0] + 1) {
    if (id == cl->last_id[2])	/* it reaches misseds */
      cl->last_id[2] = -1;
    cl->last_id[0] = id;
  } else
    _ircd_extend_id(cl, id);
  return (1);
}
#endif


/* -- server-to-server protocol commands ---------------------------------- */
#undef __TRANSIT__
#define __TRANSIT__ __CHECK_TRANSIT__(token)

BINDING_TYPE_ircd_server_cmd(ircd_quit_sb);
static int ircd_quit_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			const char *sender, const char *lcsender, char *cmd,
			int argc, const char **argv)
{ /* args: [<Quit Message>] */
  CLIENT *cl;
  const char *msg;

  if (argc)
    msg = sender;
  else
    msg = argv[0];
  cl = _ircd_find_client_lc((IRCD *)srv->data, lcsender);
#ifdef USE_SERVICES
  //TODO: notify services
#endif
#if IRCD_MULTICONNECT
  if (((struct peer_priv *)peer->iface->data)->link->cl->umode & A_MULTI)
    New_Request(peer->iface, 0, "ACK QUIT %s", sender);
#endif
  ircd_sendto_servers_all_ack((IRCD *)srv->data, cl, NULL, peer->iface->data,
			      ":%s QUIT :%s", cl->nick, msg);
  ircd_prepare_quit(cl, cl->via, msg);
  Add_Request(I_PENDING, "*", 0, ":%s!%s@%s QUIT :%s", cl->nick, cl->user,
	      cl->host, msg);
  cl->host[0] = 0;			/* for collision check */
  return 1;
}

BINDING_TYPE_ircd_server_cmd(ircd_squit_sb);
static int ircd_squit_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			 const char *sender, const char *lcsender, char *cmd,
			 int argc, const char **argv)
{ /* args: <server> <comment> */
  CLIENT *cl, *tgt;
  register LINK *l;
  struct peer_priv *pp = peer->iface->data; /* it's really peer */
#if IRCD_MULTICONNECT
  register ACK *ack;
#endif

  if (argc != 2) {
    ERROR("ircd:got SQUIT from %s with %d != 2 parameters", peer->dname, argc);
    return ircd_recover_done(pp, "SQUIT need more parameters");
  }
#if IRCD_MULTICONNECT
  if (pp->link->cl->umode & A_MULTI)
    New_Request(peer->iface, 0, "ACK SQUIT %s", argv[0]);
#endif
  tgt = ircd_find_client(argv[0], pp);	/* in case of backfired it's NULL */
  if (tgt == NULL || !CLIENT_IS_SERVER(tgt))
#if IRCD_MULTICONNECT
  {
    if (tgt == NULL && (pp->link->cl->umode & A_MULTI))
      return (1);
      //TODO: log duplicate?
    else
#endif
      return ircd_recover_done(pp, "No such server");
#if IRCD_MULTICONNECT
  }
  ack = ircd_check_ack(pp, tgt, NULL);
  if (ack != NULL) {
    ack->contrary = 1;
    return (1); /* ignore the message */
  }
#endif
  cl = _ircd_find_client_lc((IRCD *)srv->data, lcsender);
  if (CLIENT_IS_SERVER(cl)) {
    for (l = cl->c.lients; l; l = l->prev)
      if (l->cl == tgt)
	break;
    if (l == NULL) {			/* ambiguous sender */
      ircd_do_squit(((struct peer_priv *)peer->iface->data)->link, pp,
		    "Invalid SQUIT message");
      return 0;				/* kill our peer instead */
    }
    ircd_do_squit(l, pp, argv[1]);
  } else if (cl->hold_upto) {
    ERROR("ircd:got SQUIT from dead man %s", sender);
  } else {
    /* we doing squit only for shortest way despite of possible multiconnect! */
    if (CLIENT_IS_LOCAL(tgt)) {		/* squit if it's local link */
      ircd_sendto_wallops((IRCD *)srv->data, "SQUIT %s from %s: %s", argv[0],
			  cl->nick, argv[1]);
      ircd_do_squit(tgt->via->link, pp, argv[1]); /* do job */
    } else				/* or else forward it to it's links */
      ircd_sendto_remote(tgt, ":%s SQUIT %s :%s", cl->nick, argv[0], argv[1]);
  }
  return 1;
}

static inline int _ircd_join_0_remote(IRCD *ircd, struct peer_priv *bysrv,
				      unsigned short token, CLIENT *cl,
				      const char *key)
{
  register CHANNEL *ch;
#if IRCD_MULTICONNECT
  register ACK *ack;
#endif

  if (key == NULL)
    key = cl->nick;
#if IRCD_MULTICONNECT
  if (bysrv->link->cl->umode & A_MULTI)
    New_Request(bysrv->p.iface, 0, "ACK JOIN %s :0", cl->nick);
  ack = ircd_check_ack(bysrv, cl, CHANNEL0);
  if (ack != NULL) {
    ack->contrary = 1;
    return (1);
  }
#endif
  while (cl->c.hannels)
  {
    if ((ch = cl->c.hannels->chan)->mode & A_QUIET) ;
    else if (ch->mode & A_ANONYMOUS)
      ircd_sendto_chan_local(ch, ":anonymous!anonymous@anonymous. PART %s :anonymous",
			     ch->name);
    else
      ircd_sendto_chan_local(ch, ":%s!%s@%s PART %s :%s", cl->nick,
			     cl->user, cl->host, ch->name, key);
#ifdef USE_SERVICES
    //TODO: inform services
#endif
    ircd_del_from_channel(ircd, cl->c.hannels, 0);
  }
  ircd_sendto_servers_all_ack(ircd, cl, CHANNEL0, bysrv, ":%s JOIN 0 :%s",
			      cl->nick, key);
  return (1);
}

BINDING_TYPE_ircd_server_cmd(ircd_join_sb);
static int ircd_join_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			const char *sender, const char *lcsender, char *cmd,
			int argc, const char **argv)
{ /* args: <channel>[^G<modes>][,<channel>[^G<modes>]]
           0 [reason] */
  CLIENT *cl;
  MEMBER *memb;
  const char *c;
  char *t, *m, *cmask;
  modeflag mf;
  register modeflag am;
  int ptr, err = 0;
  char chname[MB_LEN_MAX*CHANNAMELEN+1];
  char msg[MB_LEN_MAX*IRCMSGLEN];

  if (argc < 1) {
    ERROR("ircd:got JOIN from %s for %s without parameters", peer->dname, sender);
    return ircd_recover_done(peer->iface->data, "Invalid JOIN message");
  }
  cl = _ircd_find_client_lc((IRCD *)srv->data, lcsender);
  if (cl == NULL || (cl->umode & (A_SERVER|A_SERVICE))) {
    ERROR("ircd:got JOIN from %s for not known user %s", peer->dname, sender);
    return ircd_recover_done(peer->iface->data, "Invalid JOIN message");
  }
  c = argv[0];
  if (!strcmp(argv[0], "0"))
    return _ircd_join_0_remote(srv->data, peer->iface->data, token, cl, argv[1]);
  m = msg;
  while (*c) {
    t = chname;
    ptr = 0;
    if (m != msg)
      m[ptr++] = ',';
    while (*c != '\0' && *c != '\007' && *c != ',' &&
	   t < &chname[sizeof(chname)-1]) {
      m[ptr++] = *c;
      *t++ = *c++;
    }
    *t = '\0';
    mf = 0;
    if (*c == '\007') {
      m[ptr++] = *c;
      while (*++c != '\0' && *c != ',') {
	am = ircd_char2mode(srv, peer->dname, sender, chname, *c);
	if (am) {
	  mf |= am;
	  m[ptr++] = *c;
	}
      }
    } else
      mf = 0;
    if (ircd_char2mode(srv, peer->dname, sender, chname, '\0') & A_INVISIBLE) {
      memb = NULL;			/* no join to local channels! */
      ERROR("ircd:invalid JOIN channel %s via %s", chname, peer->dname);
      err = 1;
    } else if ((cmask = strchr(chname, ':')) != NULL) {
      register CLIENT *me = ircd_find_client(NULL, NULL);
      cmask++;
      if (simple_match(cmask, me->lcnick) < 0) {
	memb = NULL;
	ERROR("ircd:invalid JOIN channel mask %s via %s", cmask, peer->dname);
	err = 1;
      } else
	memb = ircd_new_to_channel(srv->data, peer->iface->data, chname, cl, mf);
    } else
      memb = ircd_new_to_channel(srv->data, peer->iface->data, chname, cl, mf);
    /* acks will be checked by ircd_new_to_channel() */
    if (memb != NULL) {			/* acceptable join */
      if (cmask != NULL)
	ircd_sendto_servers_mask((IRCD *)srv->data,
				 (struct peer_priv *)peer->iface->data, cmask,
				 ":%s JOIN %.*s", cl->nick, ptr,
				 (m == msg) ? m : &m[1]);
      else
	m += ptr;
    }
    if (*c == ',')
      c++;
  }
  if (m != msg) {
    //broadcast the list
    *m = '\0';
    ircd_sendto_servers_all((IRCD *)srv->data,
			    (struct peer_priv *)peer->iface->data,
			    ":%s JOIN %s", cl->nick, msg);
  }
  if (err)
    ircd_recover_done(peer->iface->data, "Invalid JOIN channel");
  return 1;
}

BINDING_TYPE_ircd_server_cmd(ircd_njoin);
static int ircd_njoin(INTERFACE *srv, struct peer_t *peer, unsigned short token,
		      const char *sender, const char *lcsender, char *cmd,
		      int argc, const char **argv)
{ /* args: <channel> [@@|@|+]<nickname>[,[@@|@|+]<nickname>...] */
  MEMBER *tgt;
  register MEMBER *t;
  CLIENT *cl;
  const char *c;
  struct peer_priv *pp = peer->iface->data; /* it's really peer */
  size_t mptr;
  modeflag mf;
  char clname[MB_LEN_MAX*NICKLEN+1];
  char msg[MB_LEN_MAX*IRCMSGLEN];
  register size_t i;

  /* check number of parameters and if channel isn't local one */
  if (argc != 2) {
    ERROR("ircd:got NJOIN from %s with %d(<2) parameters", peer->dname, argc);
    return ircd_recover_done(pp, "Invalid number of parameters");
  }
  if (ircd_char2mode(srv, peer->dname, sender, argv[0], '\0') & A_INVISIBLE ||
      ((c = strchr(argv[0], ':')) != NULL &&
       (cl = ircd_find_client(NULL, NULL)) &&
       simple_match(&c[1], cl->lcnick)) < 0) {
    ERROR("ircd:invalid NJOIN channel %s via %s", argv[0], peer->dname);
    return ircd_recover_done(pp, "Invalid NJOIN channel");
  }
  tgt = NULL;
  mptr = 0;
  c = argv[1];
  while (*c) {
    if (mptr < sizeof(msg)-1) {
      if (mptr == 0)
	msg[0] = *c;
      else
	msg[mptr+1] = *c;
    }
    if (c[0] == '@' && c[1] == '@') {
      mf = A_ADMIN | A_OP;
      c += 2;
    } else {
      mf = ircd_whochar2mode(*c);
      if (mf != 0)
	c++;
    }
    for (i = 0; i < sizeof(clname)-1 && *c != '\0' && *c != ','; c++)
      clname[i++] = *c;
    while (*c != '\0' && *c++ != ',');	/* skip ',' if any */
    clname[i] = '\0';
    cl = ircd_find_client(clname, pp);
    if (cl == NULL) {
      ERROR("ircd:invalid NJOIN member from %s: %s", peer->dname, clname);
      if (!ircd_recover_done(pp, "invalid NJOIN member"))
	return (0);
      continue;
    }
    if (tgt == NULL)		/* adding will check acks too */
      tgt = t = ircd_new_to_channel(srv->data, pp, argv[0], cl, mf);
    else
      t = ircd_add_to_channel(srv->data, pp, tgt->chan, cl, mf);
    if (t == NULL)		/* not approved to add */
      continue; //TODO: make debug message?
    if (mptr + strlen(clname) >= sizeof(msg) - 4) /* it's impossible! ERROR? */
      continue;
    if (mptr != 0)
      msg[mptr++] = ',';
    mptr++;			/* it already took the char, see above */
    if (mf & A_ADMIN)
      msg[mptr++] = '@';
    mptr += strfcpy(&msg[mptr], clname, sizeof(msg) - mptr);
  }
  if (tgt) {			/* do broadcast to neighbours */
    register char *cmask;

    if ((cmask = strchr(tgt->chan->name, ':')) != NULL) {
      cmask++;
      ircd_sendto_servers_mask((IRCD *)srv->data, pp, cmask, "NJOIN %s :%s",
			       tgt->chan->name, msg);
    } else
      ircd_sendto_servers_all((IRCD *)srv->data, pp, "NJOIN %s :%s",
			      tgt->chan->name, msg);
  }
  return (1);
}

BINDING_TYPE_ircd_server_cmd(ircd_part_sb);
static int ircd_part_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			const char *sender, const char *lcsender, char *cmd,
			int argc, const char **argv)
{ /* args: <channel>[,<channel> ...] [<Part Message>] */
  CLIENT *cl;
  const char *c, *msg;
  char *t;
  register char *cmask;
  MEMBER *memb;
  struct peer_priv *pp = peer->iface->data; /* it's really peer */
  char chname[MB_LEN_MAX*CHANNAMELEN+1];
#if IRCD_MULTICONNECT
  register ACK *ack;
#endif

  if (argc < 1) {
    ERROR("ircd:got PART from %s without parameters", peer->dname);
    return ircd_recover_done(pp, "Invalid PART message");
  }
#if IRCD_MULTICONNECT
  if (pp->link->cl->umode & A_MULTI)
    New_Request(peer->iface, 0, "ACK PART %s :%s", sender, argv[0]);
#endif
  cl = _ircd_find_client_lc((IRCD *)srv->data, lcsender);
  if (argc == 1)
    msg = sender;
  else
    msg = argv[1];
  for (c = argv[0]; *c; )
  {
    if (*c == ',')
      c++;
    if (*c == '\0')
      break;
    t = chname;
    while (*c != '\0' && *c != ',' && t < &chname[sizeof(chname)-1])
      *t++ = *c++;
    *t = '\0';
    memb = ircd_find_member ((IRCD *)srv->data, chname, NULL);
    if (memb == NOSUCHCHANNEL) {
      ERROR("ircd:got PART from %s for %s on nonexistent channel %s",
	    peer->dname, sender, chname);
      ircd_recover_done(pp, "PART for nonexistent channel");
      continue;
    }
#if IRCD_MULTICONNECT
    if ((ack = ircd_check_ack(pp, cl, memb->chan)) != NULL) {
      ack->contrary = 1;
      continue;
    /* if we sent JOIN 0 there but got PART then we got JOIN from the link before
       and if we sent JOIN + JOIN 0 and got delayed PART then it's catched above */
    }
#endif
    if ((memb->chan->mode & A_INVISIBLE) || /* local channel */
	       (memb = _ircd_is_on_channel(cl, memb->chan)) == NULL) {
      ERROR("ircd:got PART from %s for %s not member of %s", peer->dname,
	    sender, chname);
      ircd_recover_done(pp, "Invalid PART message");
      continue;
    }
    if ((memb->chan->mode & A_QUIET)) ;
    else if (memb->chan->mode & A_ANONYMOUS)
      ircd_sendto_chan_local(memb->chan,
			     ":anonymous!anonymous@anonymous. PART %s :anonymous",
			     memb->chan->name);
    else
      ircd_sendto_chan_local(memb->chan, ":%s PART %s :%s", cl->nick,
			     memb->chan->name, msg);
#ifdef USE_SERVICES
    //TODO: notify services
#endif
    if ((cmask = strchr (chname, ':'))) /* notify servers */ {
      cmask++; /* not put '++' into macro below */
      ircd_sendto_servers_mask_all_ack((IRCD *)srv->data, cl, memb->chan, pp,
				       cmask, ":%s PART %s :%s", cl->nick,
				       memb->chan->name, msg);
    } else /* we don't send list because we need acks */
      ircd_sendto_servers_all_ack((IRCD *)srv->data, cl, memb->chan, pp,
				  ":%s PART %s :%s", cl->nick,
				  memb->chan->name, msg);
    ircd_del_from_channel ((IRCD *)srv->data, memb, 0);
  }
  return 1;
}

/* declaration */
static int
_ircd_do_stopic(IRCD *ircd, const char *via, const char *sender,
		struct peer_priv *pp, unsigned short token, int id,
		CLIENT *cl, CHANNEL *ch, const char *topic);

BINDING_TYPE_ircd_server_cmd(ircd_topic_sb);
static int ircd_topic_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			 const char *sender, const char *lcsender, char *cmd,
			 int argc, const char **argv)
{ /* args: <channel> <topic> */
  CLIENT *cl;
  MEMBER *memb;
  struct peer_priv *pp = peer->iface->data; /* it's really peer */

  /* check number of parameters and if channel isn't local one */
  if (argc != 2) {
    ERROR("ircd:got TOPIC from %s with %d(<2) parameters", peer->dname, argc);
    return ircd_recover_done(pp, "Invalid number of parameters");
  }
  cl = _ircd_find_client_lc((IRCD *)srv->data, lcsender);
  memb = ircd_find_member ((IRCD *)srv->data, argv[0], NULL);
  /* we should never get TOPIC from A_MULTI link so no reason to check acks */
  if (memb == NOSUCHCHANNEL || memb->chan->mode & A_INVISIBLE) {
    ERROR("ircd:got TOPIC via %s by %s on nonexistent channel %s",
	  peer->dname, sender, argv[0]);
    return ircd_recover_done(pp, "TOPIC for nonexistent channel");
  }
  return _ircd_do_stopic((IRCD *)srv->data, peer->dname, sender, pp, 0, -1, cl,
			 memb->chan, argv[1]);
}

BINDING_TYPE_ircd_server_cmd(ircd_invite_sb);
static int ircd_invite_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			  const char *sender, const char *lcsender, char *cmd,
			  int argc, const char **argv)
{ /* args: <nickname> <channel> */
  CLIENT *cl, *tgt;
  MEMBER *memb;
  struct peer_priv *pp = peer->iface->data; /* it's really peer */

  if (argc != 2) {
    ERROR("ircd:got INVITE from %s with %d(<2) parameters", peer->dname, argc);
    return ircd_recover_done(pp, "Invalid number of parameters");
  }
  cl = _ircd_find_client_lc((IRCD *)srv->data, lcsender);
  tgt = ircd_find_client (argv[0], pp);
  if (!tgt || (tgt->umode & (A_SERVER|A_SERVICE)))
    return ircd_do_unumeric (cl, ERR_NOSUCHNICK, cl, 0, argv[0]);
    //TODO: what if cl is a server?
  memb = ircd_find_member ((IRCD *)srv->data, argv[1], cl);
  if (memb != NOSUCHCHANNEL)
  {
    if (!memb)
      Add_Request(I_LOG, "*", F_WARN, "ircd:got INVITE via %s from %s to %s "
		  "which is not on that channel", peer->dname, sender, argv[1]);
    else if (memb->chan->mode & A_INVISIBLE)
      return ircd_recover_done(pp, "Invalid channel name for INVITE");
    else if ((memb->chan->mode & A_INVITEONLY) && !(memb->mode & A_OP))
      Add_Request(I_LOG, "*", F_WARN, "ircd:got INVITE via %s from %s to %s "
		  "overriding channel modes", peer->dname, sender, argv[1]);
    else if (_ircd_is_on_channel (tgt, memb->chan))
      return ircd_do_unumeric (cl, ERR_USERONCHANNEL, tgt, 0, argv[1]);
  }
  ircd_sendto_one (tgt, "INVITE %s %s", argv[0], argv[1]);
  if (!CLIENT_IS_REMOTE(tgt) && memb != NOSUCHCHANNEL)
    ircd_add_invited (tgt, memb->chan);
  if (!(cl->umode & (A_SERVER|A_SERVICE)) && tgt->away[0])
    ircd_do_unumeric (cl, RPL_AWAY, tgt, 0, tgt->away);
  return (1);
}

BINDING_TYPE_ircd_server_cmd(ircd_kick_sb);
static int ircd_kick_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			const char *sender, const char *lcsender, char *cmd,
			int argc, const char **argv)
{ /* args: <channel>[,<channel> ...] <user>[,<user> ...] [<comment>] */
  CLIENT *cl, *tgt;
  MEMBER *memb, *tm;
  const char *reason;
  char *lcl, *lch, *chn, *nlcl, *nchn;
  struct peer_priv *pp = peer->iface->data; /* it's really peer */
  register char *cmask;

  if (argc < 2) {
    ERROR("ircd:got KICK from %s with %d(<2) parameters", peer->dname, argc);
    return ircd_recover_done(pp, "Invalid number of parameters");
  }
#if IRCD_MULTICONNECT
  if (pp->link->cl->umode & A_MULTI)
    New_Request(peer->iface, 0, "ACK KICK %s :%s", argv[0], argv[1]);
#endif
  if (argc == 3)
    reason = argv[2];
  else
    reason = sender;
  cl = _ircd_find_client_lc((IRCD *)srv->data, lcsender);
  lch = strchr (argv[0], ',');
  for (chn = nchn = (char *)argv[0], lcl = (char *)argv[1]; lcl;
	lcl = nlcl, chn = nchn)
  {
    nlcl = strchr (lcl, ',');
    if (nlcl)
      *nlcl++ = 0;
    if (lch && chn && (nchn = strchr (chn, ',')))
      *nchn++ = 0;
    if (!chn) {
      ERROR("ircd:got invalid KICK via %s", peer->dname);
      ircd_recover_done(pp, "Invalid KICK channel list");
    } else if (!(tgt = ircd_find_client (lcl, pp))) { /* follows nickchanges */
      ERROR("ircd:KICK via %s for unknown user %s", peer->dname, lcl);
      ircd_recover_done(pp, "Invalid KICK target");
    } else if ((tm = ircd_find_member ((IRCD *)srv->data, chn, NULL))
		== NOSUCHCHANNEL || (tm->chan->mode & A_INVISIBLE)) {
      ERROR("ircd:KICK via %s for unknown channel %s", peer->dname, chn);
      ircd_recover_done(pp, "Invalid KICK channel list");
    } else {
      register MEMBER *tst;
#if IRCD_MULTICONNECT
      register ACK *ack = ircd_check_ack(pp, tgt, tm->chan);

      if (ack != NULL) {		/* we got backfired it */
	ack->contrary = 1;
	continue;
      }
#endif
      tst = _ircd_is_on_channel (tgt, tm->chan); /* recover from NULL */
      if (tst == NULL) {
#if IRCD_MULTICONNECT
	if (pp->link->cl->umode & A_MULTI)
	  //TODO: log duplicate?
	  continue;
#endif
	ERROR("ircd:KICK via %s for unknown user %s", peer->dname, lcl);
	ircd_recover_done(pp, "Invalid KICK target");
	continue;
      } else
	tm = tst;
      memb = _ircd_is_on_channel (cl, tm->chan);
      if (memb == NULL)
	Add_Request(I_LOG, "*", F_WARN, "ircd:KICK via %s by %s not member of %s",
		    peer->dname, sender, chn);
      if (CLIENT_IS_SERVER(cl)) //TODO: can servers kick users?
	ircd_sendto_chan_local (memb->chan, ":%s KICK %s %s :%s",
				sender, chn, lcl, reason);
      else if (CLIENT_IS_SERVICE(cl))
	ircd_sendto_chan_local (memb->chan, ":%s!service@%s KICK %s %s :%s",
				sender, cl->cs->lcnick, chn, lcl, reason);
      else
	ircd_sendto_chan_local (memb->chan, ":%s!%s@%s KICK %s %s :%s",
				sender, cl->user, cl->host, chn, lcl, reason);
#ifdef USE_SERVICES
      //TODO: inform services
#endif
      if ((cmask = strchr (memb->chan->name, ':'))) {
	cmask++; /* not put '++' into macro below */
	ircd_sendto_servers_mask_all_ack ((IRCD *)srv->data, tgt, tm->chan,
					  pp, cmask, ":%s KICK %s %s :%s",
					  sender, tm->chan->name, tgt->nick,
					  reason);
      } else /* don't merge targets since we need acks */
	ircd_sendto_servers_all_ack ((IRCD *)srv->data, tgt, tm->chan, pp,
				     ":%s KICK %s %s :%s", sender,
				     tm->chan->name, tgt->nick, reason);
      ircd_del_from_channel ((IRCD *)srv->data, tm, 0);
    }
  }
  return (1);
}

BINDING_TYPE_ircd_server_cmd(ircd_kill_sb);
static int ircd_kill_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			const char *sender, const char *lcsender, char *cmd,
			int argc, const char **argv)
{ /* args: <nickname> <comment> */
  CLIENT *cl, *tcl;
  struct peer_priv *pp = peer->iface->data; /* it's really peer */
  char reason[MB_LEN_MAX*IRCMSGLEN];
  register char *c;
#if IRCD_MULTICONNECT
  register ACK *ack;
#endif

  if (argc < 2) {
    ERROR("ircd:got KILL from %s with %d(<2) parameters", peer->dname, argc);
    return ircd_recover_done(pp, "Invalid number of parameters");
  }
#if IRCD_MULTICONNECT
  if (pp->link->cl->umode & A_MULTI)
    New_Request(peer->iface, 0, "ACK KILL %s", argv[0]);
#endif
  cl = _ircd_find_client_lc((IRCD *)srv->data, lcsender);
  tcl = ircd_find_client_nt(argv[0], pp); /* we need no traced one for ack */
  if (tcl == NULL || CLIENT_IS_SERVER(tcl)) {
    ERROR("ircd:KILL via %s for unknown user %s", peer->dname, argv[0]);
    return ircd_recover_done(pp, "Invalid KILL target");
    //TODO: squit a broken server?
  }
#if IRCD_MULTICONNECT
  ack = ircd_check_ack(pp, tcl, NULL);
  if (ack != NULL) {			/* we got it backfired */
    ack->contrary = 1;
    return (1);
  }
#endif
  while (tcl != NULL && tcl->hold_upto != 0) /* trace nickchanges now */
    tcl = tcl->x.rto;
  if (tcl == NULL) {			/* user has quited for us already */
    //TODO: log it!
    return (1);
  }
  //TODO: check if reason is badly formatted - should be path!killer (reason)
  /* prepare the message with path and reason */
  snprintf(reason, sizeof(reason), "%s!%s", peer->dname, argv[1]);
  if (!CLIENT_IS_REMOTE(tcl))
    New_Request(tcl->via->p.iface, 0, ":%s KILL %s :%s", cl->nick, tcl->nick,
		reason);		/* notify the victim */
  ircd_sendto_servers_all_ack((IRCD *)srv->data, tcl, NULL, NULL,
			      ":%s KILL %s :%s", cl->nick, tcl->nick, reason);
			      /* broadcast KILL */
  ircd_prepare_quit(tcl, cl->via, "you are killed");
  tcl->hold_upto = Time + CHASETIMELIMIT; /* make 'nick delay' */
  for (c = NextWord(reason); c > reason && c[-1] != '!'; c--); /* find nick */
  Add_Request(I_PENDING, "*", 0, ":%s!%s@%s QUIT :Killed by %s", tcl->nick,
	      tcl->user, tcl->host, c); /* notify local users */
  tcl->host[0] = 0;			/* for collision check */
  return (1);
}

BINDING_TYPE_ircd_server_cmd(ircd_error_sb);
static int ircd_error_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			 const char *sender, const char *lcsender, char *cmd,
			 int argc, const char **argv)
{ /* args: <error message> */
  /* just broadcasting it to channel and log */
  ERROR("ircd: ERROR from %s: %s", peer->dname, argc ? argv[0] : "(nil)");
  return (1);
}

/* this one is used by ircd_topic_sb too but should use token so is put here */
static int _ircd_do_stopic(IRCD *ircd, const char *via, const char *sender,
			   struct peer_priv *pp, unsigned short token, int id,
			   CLIENT *cl, CHANNEL *ch, const char *topic)
{
  register size_t sz;
  char *cmask;

  if (_ircd_is_on_channel(cl, ch) == NULL) /* log alien topic */
    Add_Request(I_LOG, "*", F_WARN, "ircd:TOPIC via %s by %s not member of %s",
		via, sender, ch->name);
  //TODO: check permissions may be?
  sz = unistrcut(topic, sizeof(ch->topic), TOPICLEN); /* validate */
  strfcpy(ch->topic, topic, sz+1);
  if (CLIENT_IS_SERVER(cl)) //TODO: can servers set topics?
    ircd_sendto_chan_local(ch, ":%s TOPIC %s :%s", sender, ch->name, ch->topic);
  else if (CLIENT_IS_SERVICE(cl))
    ircd_sendto_chan_local(ch, ":%s!service@%s TOPIC %s :%s", sender,
			   cl->cs->lcnick, ch->name, ch->topic);
  else
    ircd_sendto_chan_local(ch, ":%s!%s@%s TOPIC %s :%s", sender, cl->user,
			   cl->host, ch->name, ch->topic);
  cmask = strchr(ch->name, ':');
  if (cmask)
  {
    cmask++; /* not put '++' into macro below */
#if IRCD_MULTICONNECT
    if (id >= 0) {
      ircd_sendto_servers_mask_new(ircd, pp, cmask, ":%s ITOPIC %d %s :%s",
				   sender, id, ch->name, ch->topic);
      ircd_sendto_servers_mask_old(ircd, pp, cmask, ":%s TOPIC %s :%s", sender,
				   ch->name, ch->topic);
    } else
#endif
      ircd_sendto_servers_mask(ircd, pp, cmask, ":%s TOPIC %s :%s", sender,
			       ch->name, ch->topic);
    return 1;
  }
#if IRCD_MULTICONNECT
  if (id >= 0) {
    ircd_sendto_servers_new(ircd, pp, ":%s ITOPIC %d %s :%s",
			    sender, id, ch->name, ch->topic);
    ircd_sendto_servers_old(ircd, pp, ":%s TOPIC %s :%s",
			    sender, ch->name, ch->topic);
  } else
#endif
    ircd_sendto_servers_all(ircd, pp, ":%s TOPIC %s :%s",
			    sender, ch->name, ch->topic);
  return 1;
}

#if IRCD_MULTICONNECT
BINDING_TYPE_ircd_server_cmd(ircd_itopic);
static int ircd_itopic(INTERFACE *srv, struct peer_t *peer, unsigned short token,
		       const char *sender, const char *lcsender, char *cmd,
		       int argc, const char **argv)
{ /* args: <num> <channel> <topic> */
  CLIENT *cl;
  MEMBER *memb;
  struct peer_priv *pp = peer->iface->data; /* it's really peer */
  int id;
  register ACK *ack;

  if (!(pp->link->cl->umode & A_MULTI)) /* it's ambiguous from RFC2813 server */
    return (0);
  /* check number of parameters and if channel isn't local one */
  if (argc != 3) {
    ERROR("ircd:got ITOPIC from %s with %d(<3) parameters", peer->dname, argc);
    return ircd_recover_done(pp, "Invalid number of parameters");
  }
  id = atoi(argv[0]);
  if (!ircd_test_id(((IRCD *)srv->data)->token[token], id))
    //TODO: log duplicate?
    return (1);
  cl = _ircd_find_client_lc((IRCD *)srv->data, lcsender);
  memb = ircd_find_member ((IRCD *)srv->data, argv[1], NULL);
  if (memb == NOSUCHCHANNEL || memb->chan->mode & A_INVISIBLE) {
    ERROR("ircd:got ITOPIC via %s by %s on nonexistent channel %s",
	  peer->dname, sender, argv[0]);
    return ircd_recover_done(pp, "ITOPIC for nonexistent channel");
  }
  ack = ircd_check_ack(pp, cl, memb->chan);
  if (ack != NULL) {
    /* is it really possible to get new ID and have ack on it? */
    Add_Request(I_LOG, "*", F_WARN,
		"ircd:ignoring ITOPIC via %s for %s which already left %s",
		peer->dname, sender, argv[1]);
    return (1);
  }
  return _ircd_do_stopic((IRCD *)srv->data, peer->dname, sender, pp, token, id,
			 cl, memb->chan, argv[2]);
}

BINDING_TYPE_ircd_server_cmd(ircd_ack);
static int ircd_ack(INTERFACE *srv, struct peer_t *peer, unsigned short token,
		    const char *sender, const char *lcsender, char *cmd,
		    int argc, const char **argv)
{ /* args: <command> <target> [<channel>] */
  register struct peer_priv *pp = peer->iface->data; /* it's really peer */

  if (!(pp->link->cl->umode & A_MULTI)) /* it's ambiguous from RFC2813 server */
    return (0);
  /* check number of parameters */
  if (argc < 2) {
    ERROR("ircd:got ACK from %s with %d(<2) parameters", peer->dname, argc);
    return ircd_recover_done(pp, "Invalid number of parameters");
  }
  //TODO: check if parameters do match link->acks
  ircd_drop_ack((IRCD *)srv->data, pp);
  return (0);
}
#endif /* IRCD_MULTICONNECT */
#undef __TRANSIT__
#define __TRANSIT__


/* -- common functions ---------------------------------------------------- */

/* -- common interface ---------------------------------------------------- */
void ircd_server_proto_end (void)
{
  Delete_Binding ("ircd-server-cmd", (Function)&ircd_quit_sb, NULL);
  Delete_Binding ("ircd-server-cmd", (Function)&ircd_squit_sb, NULL);
  Delete_Binding ("ircd-server-cmd", (Function)&ircd_join_sb, NULL);
  Delete_Binding ("ircd-server-cmd", (Function)&ircd_njoin, NULL);
  Delete_Binding ("ircd-server-cmd", (Function)&ircd_part_sb, NULL);
  Delete_Binding ("ircd-server-cmd", (Function)&ircd_topic_sb, NULL);
  Delete_Binding ("ircd-server-cmd", (Function)&ircd_invite_sb, NULL);
  Delete_Binding ("ircd-server-cmd", (Function)&ircd_kick_sb, NULL);
  Delete_Binding ("ircd-server-cmd", (Function)&ircd_kill_sb, NULL);
  Delete_Binding ("ircd-server-cmd", (Function)&ircd_error_sb, NULL);
//  Delete_Binding ("ircd-server-cmd", (Function)&ircd_wallops_sb, NULL);
#if IRCD_MULTICONNECT
  Delete_Binding ("ircd-server-cmd", (Function)&ircd_itopic, NULL);
//  Delete_Binding ("ircd-server-cmd", (Function)&ircd_iwallops, NULL);
  Delete_Binding ("ircd-server-cmd", (Function)&ircd_ack, NULL);
  _forget_(ACK);
#endif
  //TODO: kill messaging iface
}

void ircd_server_proto_start (void)
{
  Add_Binding ("ircd-server-cmd", "quit", 0, 0, (Function)&ircd_quit_sb, NULL);
  Add_Binding ("ircd-server-cmd", "squit", 0, 0, (Function)&ircd_squit_sb, NULL);
  Add_Binding ("ircd-server-cmd", "join", 0, 0, (Function)&ircd_join_sb, NULL);
  Add_Binding ("ircd-server-cmd", "njoin", 0, 0, (Function)&ircd_njoin, NULL);
  Add_Binding ("ircd-server-cmd", "part", 0, 0, (Function)&ircd_part_sb, NULL);
  Add_Binding ("ircd-server-cmd", "topic", 0, 0, (Function)&ircd_topic_sb, NULL);
  Add_Binding ("ircd-server-cmd", "invite", 0, 0, (Function)&ircd_invite_sb, NULL);
  Add_Binding ("ircd-server-cmd", "kick", 0, 0, (Function)&ircd_kick_sb, NULL);
  Add_Binding ("ircd-server-cmd", "kill", 0, 0, (Function)&ircd_kill_sb, NULL);
  Add_Binding ("ircd-server-cmd", "error", 0, 0, (Function)&ircd_error_sb, NULL);
//  Add_Binding ("ircd-server-cmd", "wallops", 0, 0, (Function)&ircd_wallops_sb, NULL);
#if IRCD_MULTICONNECT
  Add_Binding ("ircd-server-cmd", "itopic", 0, 0, (Function)&ircd_itopic, NULL);
//  Add_Binding ("ircd-server-cmd", "iwallops", 0, 0, (Function)&ircd_iwallops, NULL);
  Add_Binding ("ircd-server-cmd", "ack", 0, 0, (Function)&ircd_ack, NULL);
#endif
  //TODO: add messaging iface
}
#endif
