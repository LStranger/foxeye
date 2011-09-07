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
 * This file is a part of FoxEye IRCd module: connections and few bindings that
 *   require IrcdLock lock or (de)allocation of peer_priv, CLIENT, or LINK.
 *
 * TODO: make support for script bindings!
 */

#include "foxeye.h"
#if IRCD_USES_ICONV == 0 || (defined(HAVE_ICONV) && (IRCD_NEEDS_TRANSLIT == 0 || defined(HAVE_CYRILLIC_TRANSLIT)))
#include "modules.h"
#include "init.h"
#include "list.h"
#include "sheduler.h"
#include "conversion.h"
#include "socket.h"

#include <wchar.h>

#include "ircd.h"
#include "numerics.h"

struct CLASS
{
  CLASS *next;		/* classes list */
  char *name;		/* Lname, allocated */
  int pingf;		/* ping frequency */
  int sendq;		/* queue size */
  int lpul, lpug;	/* login per user: local, global */
  int lpc, lin;		/* login per class, currently in class */
  LINK *local;		/* logged in in this class */
  CLIENT *glob;		/* the same */
};

static char _ircd_default_class[64] = "2 2 100 90 1000"; /* lpul lpug lpc pingf sendq */
static char _ircd_flags_first[32] = "Z";	/* on start of connchain */
static char _ircd_flags_post[32] = "IPU";	/* allowed after 'x' filter */
static char _ircd_version_string[16] = "021000"; /* read only */
char _ircd_description_string[SHORT_STRING] = "";
long int _ircd_hold_period = 900;		/* 15 minutes, see RFC 2811 */
static long int _ircd_server_class_pingf = 30;	/* in seconds */

static short *_ircd_corrections;		/* for CheckFlood() */

typedef struct peer_priv peer_priv;

/* peer_priv, LINK, and CLIENT alloc_ and free_ should be locked by IrcdLock */
ALLOCATABLE_TYPE (peer_priv, IrcdPeer_, p.priv)
ALLOCATABLE_TYPE (LINK, IrcdLink_, prev)
ALLOCATABLE_TYPE (CLIENT, IrcdCli_, pcl)
ALLOCATABLE_TYPE (CLASS, IrcdClass_, next)

static size_t IrcdClass_namesize = 0;

static peer_priv *IrcdPeers = NULL;	/* list of actives, via peer->p.priv */

static char *IrcdLlist[IRCDLMAX];	/* Listening ports list */
static size_t IrcdLnum = 0;

static struct bindtable_t *BTIrcdAuth;
static struct bindtable_t *BTIrcdServerCmd;
static struct bindtable_t *BTIrcdClientCmd;
static struct bindtable_t *BTIrcdRegisterCmd;
static struct bindtable_t *BTIrcdClientFilter;
static struct bindtable_t *BTIrcdGotClient;
static struct bindtable_t *BTIrcdLostClient;
static struct bindtable_t *BTIrcdDoNumeric;
static struct bindtable_t *BTIrcdCollision;

/* access to IrcdPeers and allocators should be locked with this */
static pthread_mutex_t IrcdLock = PTHREAD_MUTEX_INITIALIZER;

static IRCD *Ircd = NULL;		/* our network we working on */

static peer_priv *_ircd_uplink = NULL;	/* RFC2813 autoconnected server */
#if IRCD_MULTICONNECT
static int _ircd_uplinks = 0;		/* number of autoconnects active */
#endif

static CLIENT ME = { .umode = A_SERVER, .via = NULL, .x.token = 0,
		     .c.lients = NULL };

#define MY_NAME ME.lcnick

#define TOKEN_ALLOC_SIZE	32

#define DEFCLASSNAME "<default>"


/* -- class management ----------------------------------------------------
   "ircd-auth" binding; thread-safe and dispatcher wants unlock!
   returns 1 if passed or 0 and error message if not allowed */

static inline CLASS *_ircd_get_new_class (const char *name, const char *parms)
{
  register CLASS *cl = alloc_CLASS();

  cl->next = NULL;
  cl->name = safe_strdup (name);
  IrcdClass_namesize += (strlen (name) + 1);
  cl->pingf = 90;		/* some defaults assuming it's individual */
  cl->lpul = cl->lpug = cl->lpc = 2;
  cl->sendq = IRCD_DEFAULT_SENDQ;
  cl->lin = 0;			/* reset values */
  cl->local = NULL;
  cl->glob = NULL;
  sscanf (parms, "%d %d %d %d %d", &cl->lpul, &cl->lpug, &cl->lpc,
	  &cl->pingf, &cl->sendq);
  dprint(3, "ircd:ircd.c: allocated new class: %s", NONULLP(name));
  return cl;
}

/* macro for _ircd_class_in() */
#define _ircd_check_limits(What,Where,Prev,Client) \
  i = 0; \
  if (user) \
  { \
    register What *td; \
    for (td = Where; td; td = Prev) \
      if (!strcmp (Client->host, link->cl->host)) \
	i++; \
  } \
  else do \
  { \
    register What *td; \
    for (td = Where; td; td = Prev) \
      if (!strcmp (Client->user, link->cl->user) && \
	  !strcmp (Client->host, link->cl->host)) \
	i++; \
  } while(0)

BINDING_TYPE_ircd_auth(_ircd_class_in);
static int _ircd_class_in (struct peer_t *peer, char *user, char *host, const char **msg)
{
  LINK *link = ((peer_priv *)peer->iface->data)->link; /* really peer->link */
  struct clrec_t *cl;
  char *clname;
  char *clparms = NULL;
  CLASS **clp;
  userflag uf = 0;
  char uh[HOSTMASKLEN+1];
  register CLASS *clcl;
  register int i;

  snprintf (uh, sizeof(uh), "%s@%s", NONULL(user), host);
  dprint(4, "ircd:ircd.c: adding %s into class", uh);
  if (!Ircd->iface)			/* OOPS! */
  {
    Unset_Iface();
    *msg = "internal error";
    return 0;
  }
  cl = Find_Clientrecord (uh, &clname, NULL, NULL);
  if (!cl) {				/* do matching by IP too */
    snprintf (uh, sizeof(uh), "%s@%s", NONULL(user), SocketIP(peer->socket));
    cl = Find_Clientrecord (uh, &clname, NULL, NULL);
  }
  if (cl)
  {
    clparms = Get_Field (cl, Ircd->iface->name, NULL);
    uf = Get_Flags (cl, Ircd->iface->name);
  }
  if (clparms);
  else if (cl && clname && (clparms == NULL || clparms[0] == 0) &&
	   (uf & U_ACCESS)) /* ok, it's service */
  {
    Unlock_Clientrecord (cl);
    DBG("ircd:ircd.c: user %s is server", uh);
    Unset_Iface();
    return 1;				/* it's passed with server class */
  }
  else					/* we cannot detect server from host */
  {
    clname = DEFCLASSNAME;
    clparms = _ircd_default_class;
  }
  for (clp = &Ircd->users; (clcl = *clp); clp = &clcl->next)
    if (!strcmp (clcl->name, clname))
      break;
  if (!clcl)
    *clp = clcl = _ircd_get_new_class (clname, clparms);
#if IRCD_USES_ICONV
  uh[0] = 0;
#endif
  if (cl)
  {
#if IRCD_USES_ICONV
    clname = Get_Field (cl, "charset", NULL); /* it gets over port's one */
    if (clname)
      strfcpy (uh, clname, sizeof(uh));
#endif
    Unlock_Clientrecord (cl);
  }
  peer->uf = uf;
  link->cl->x.class = clcl;		/* insert it into class */
  link->prev = clcl->local;
  link->cl->pcl = clcl->glob;
  clcl->local = link;
  clcl->glob = link->cl;
  if (clcl->lin++ >= clcl->lpc)		/* class overloaded */
  {
    Unset_Iface();
    *msg = "too many users";
    return 0;
  }
  /* check local limits */
  _ircd_check_limits (LINK, clcl->local, td->prev, td->cl);
  if (i > clcl->lpul)			/* local limit overloaded */
  {
    Unset_Iface();
    *msg = "too many users from this host on this server";
    return 0;
  }
  /* check for global limits */
  _ircd_check_limits (CLIENT, clcl->glob, td->pcl, td);
  Unset_Iface();
  if (i > clcl->lpug)			/* global limit overloaded */
  {
    *msg = "too many users from this host";
    return 0;
  }
#if IRCD_USES_ICONV
  if (*uh)				/* override charset with class' one */
  {
    Free_Conversion (peer->iface->conv);
    peer->iface->conv = Get_Conversion (uh);
  }
#endif
  DBG("ircd:ircd.c: %s@%s added to class %s", NONULL(user), host, clcl->name);
  return 1;
}

/* insert remote user into class */
static void _ircd_class_rin (LINK *l)
{
  struct clrec_t *cl;
  char *clname;
  char *clparms = NULL;
  CLASS **clp;
  char uh[HOSTMASKLEN+1];
  register CLASS *clcl;

  if (!Ircd->iface)
    return;
  snprintf (uh, sizeof(uh), "%s@%s", l->cl->user, l->cl->host);
  dprint(4, "ircd:ircd.c: adding %s (remote) into class", uh);
  cl = Find_Clientrecord (uh, &clname, NULL, NULL);
  /* host is reported by remote server so no other matching is possible */
  if (cl)
    clparms = Get_Field (cl, Ircd->iface->name, NULL);
  if (!clparms || !*clparms)
  {
    clname = DEFCLASSNAME;
    clparms = _ircd_default_class;
  }
  for (clp = &Ircd->users; (clcl = *clp); clp = &clcl->next)
    if (!strcmp (clcl->name, clname))
      break;
  if (!clcl)
    *clp = clcl = _ircd_get_new_class (clname, clparms);
  if (cl)
    Unlock_Clientrecord (cl);
  l->cl->x.class = clcl;
  l->cl->pcl = clcl->glob;
  clcl->glob = l->cl;
}

/* removes client from class, not from remote server list! */
/* thread-unsafe! */
static void _ircd_class_out (LINK *link)
{
  register CLIENT **clp;
  CLASS *cc = link->cl->x.class;

  dprint(4, "ircd:ircd.c: removing %s from class %s", link->cl->nick, cc->name);
  /* removing from ->prev */
  if (CLIENT_IS_LOCAL (link->cl))
  {
    register LINK **lp = &cc->local;

    while (*lp)
      if (*lp == link)
	break;
      else
	lp = &(*lp)->prev;
    if (*lp)
    {
      *lp = link->prev;
      cc->lin--;
    }
    else
      ERROR ("ircd:_ircd_class_out: client %s not found in local class %s!",
	     link->cl->nick, cc->name);
    link->prev = NULL;
  }
  /* removing from ->pcl */
  clp = &cc->glob;
  while (*clp)
    if (*clp == link->cl)
      break;
    else
      clp = &(*clp)->pcl;
  if (*clp)
    *clp = link->cl->pcl;
  else
    ERROR ("ircd:_ircd_class_out: client %s not found in global list!",
	   link->cl->nick);
  link->cl->x.rto = NULL;
  link->cl->pcl = NULL;
}

/* updates every class data from Listfile */
static void _ircd_class_update (void)
{
  CLASS *cls, *cld = NULL, **clp;
  char *clparms;

  for (cls = Ircd->users; cls; cls = cls->next)
    if (!strcmp (cls->name, DEFCLASSNAME))
    {
      cld = cls;
      break;
    }
  for (clp = &Ircd->users; (cls = *clp); )
  {
    struct clrec_t *clu;

    if (cls == cld)			/* default class */
      clparms = _ircd_default_class;
    else if ((clu = Lock_Clientrecord (cls->name))) /* it's still there */
      clparms = Get_Field (clu, Ircd->iface->name, NULL);
    else				/* class was removed, join to default */
    {
      register LINK **x;
      register CLIENT **y;

      *clp = cls->next;
      for (x = &cls->local; *x; x = &(*x)->prev)
	cld->lin++;
      *x = cld->local;			/* tail it to local default */
      cld->local = cls->local;
      for (y = &cls->glob; *y; y = &(*y)->pcl);
      *y = cld->glob;			/* tail it to global default */
      cld->glob = cls->glob;
      IrcdClass_namesize -= (strlen (cls->name) + 1);
      FREE (&cls->name);
      free_CLASS (cls);
      continue;
    }
    sscanf (clparms, "%d %d %d %d %d", &cls->lpul, &cls->lpug, &cls->lpc,
	    &cls->pingf, &cls->sendq);
    if (clu)
      Unlock_Clientrecord (clu);
    clp = &(*clp)->next;
  }
}


/* -- common internal functions ------------------------------------------- */

/* deletes already deleted from Ircd->clients phantom structure */
static inline void _ircd_real_drop_nick(CLIENT **ptr)
{
  register CLIENT *cl = *ptr;

  dprint(4, "ircd:ircd.c:_ircd_real_drop_nick: client %s", cl->nick);
  *ptr = cl->pcl;
  if (cl->rfr != NULL)
    cl->rfr->x.rto = cl->x.rto;
  if (cl->x.rto != NULL)
    cl->x.rto->rfr = cl->rfr;
  free_CLIENT(cl);
}

#define _ircd_find_client_lc(x) Find_Key (Ircd->clients, x)

static inline CLIENT *_ircd_find_client (const char *name)
{
  char lcname[MB_LEN_MAX*NICKLEN+1];

  dprint(4, "ircd:ircd.c:_ircd_find_client: %s", name);
  unistrlower (lcname, name, sizeof(lcname));
  return _ircd_find_client_lc (lcname);
}

static inline unsigned short int _ircd_alloc_token (void)
{
  unsigned short int i = 0;

  while (i < Ircd->s)
    if (Ircd->token[i] == NULL)
      return i;
    else
      i++;
  Ircd->s = i + TOKEN_ALLOC_SIZE;
  safe_realloc ((void **)&Ircd->token, Ircd->s * sizeof(CLIENT *));
  memset (&Ircd->token[i], 0, TOKEN_ALLOC_SIZE * sizeof(CLIENT *));
  return i;
}

static inline void _ircd_free_token (unsigned short int i)
{
  Ircd->token[i] = NULL;
}

static inline void _ircd_bt_lost_client(CLIENT *cl, const char *server)
{
  struct binding_t *b = NULL;

  while ((b = Check_Bindtable(BTIrcdLostClient, cl->nick, U_ALL, U_ANYCH, b)))
    if (b->name == NULL)
      b->func(Ircd->iface, server, cl->lcnick, cl->nick, cl->user, cl->host,
	      cl->fname, cl->umode, IrcdCli_num);
}

/*
 * puts message to peer and marks it to die after message is sent
 * any active user should be phantomized after call (i.e. have ->pcl
   and ->rfr pointers reset to collision list and 'renamed from')
 * does not remove it from server's list
 * this function should be thread-safe!
 */
static inline void _ircd_peer_kill (peer_priv *peer, const char *msg)
{
  dprint(4, "ircd:ircd.c:_ircd_peer_kill: %p state=%#x", peer, (int)peer->p.state);
  if (peer->p.state != P_DISCONNECTED)	/* link might be not initialized yet */
    Add_Request (I_LOG, "*", F_CONN, "ircd: killing peer %s@%s: %s",
		 peer->link->cl->user, peer->link->cl->host, msg);
  New_Request (peer->p.iface, F_AHEAD, "ERROR :%s", msg);
  Set_Iface (peer->p.iface);		/* lock it for next call */
  if (peer->p.state != P_DISCONNECTED && !CLIENT_IS_SERVER(peer->link->cl))
    _ircd_class_out (peer->link);
  if (peer->p.state == P_TALK) {
    if (CLIENT_IS_SERVER(peer->link->cl))
      ;//TODO: BTIrcdUnlinked
    else
      _ircd_bt_lost_client(peer->link->cl, MY_NAME); /* "ircd-lost-client" */
  }
  peer->p.state = P_QUIT;		/* it will die eventually */
  Unset_Iface();
}

#if IRCD_MULTICONNECT
static inline void _ircd_recalculate_hops (void)
{
  unsigned short int i, hops;
  register CLIENT *t;
  CLIENT *lastset;

  dprint(4, "ircd:ircd.c:_ircd_recalculate_hops");
  for (i = 1; i < Ircd->s; i++) /* reset whole servers list */
    if ((t = Ircd->token[i]) != NULL)
    {
      if (!CLIENT_IS_LOCAL(t))
      {
	t->via = NULL; /* don't reset local connects! */
	t->hops = Ircd->s;
      }
      t->alt = NULL; /* reset data */
    }
  hops = 1;
  do /* set paths from servers tree */
  {
    lastset = NULL; /* reset mark */
    for (i = 1; i < Ircd->s; i++) /* iteration: scan whole servers list */
      if ((t = Ircd->token[i]) != NULL && t->hops == hops) /* do iteration */
      {
	register LINK *l;

	for (l = t->c.lients; l; l = l->prev) /* scan it's links */
	  if (CLIENT_IS_SERVER(l->cl)) /* check linked servers */
	  {
	    lastset = l->cl; /* mark for next iteration */
	    if (l->cl->via == NULL) /* it's shortest, yes */
	    {
	      l->cl->hops = hops + 1;
	      l->cl->via = t->via;
	    }
	    else if (l->cl->alt == NULL && t->via != l->cl->via)
	      l->cl->alt = t->via; /* don't set alt the same as via */
	  }
	  else
	    l->cl->hops = hops + 1; /* reset hops for users */
      }
    hops++; /* do next iteration */
  } while (lastset != NULL);
  /* TODO: in case of errors check ->via ??? */
  /* some servers don't get alternate paths but servers that we see them via
     can have alternates so let set alternates with those alternates */
  for (i = 1; i < Ircd->s; i++) /* iteration: scan whole servers list */
    if ((t = Ircd->token[i]) != NULL && t->alt == NULL)
      t->alt = t->via->link->cl->alt;
}
#endif

/*
 * returns:
 *  a) phantom with ->away matching via->p.dname
 *  b) or host client if non-phantom and (a) not found
 *  c) or phantom matching "" if got neither (a) nor (b)
 *  d) or host client if got neither (a), (b) nor (c)
 * !!! both args should be not NULL and host client should be not server !!!
 */
static inline CLIENT *_ircd_find_phantom(CLIENT *nick, peer_priv *via)
{
  CLIENT *resort, *phantom;

  dprint(4, "ircd:ircd.c:_ircd_find_phantom: %s", nick->nick);
  if (nick->hold_upto == 0) {		/* it's non-phantom */
    resort = nick;
    if (nick->rfr != NULL && nick->rfr->cs == nick) /* it's nick holder */
      phantom = nick->rfr;
    else				/* it's renamed one */
      phantom = NULL;
  } else {				/* it's phantom */
    resort = NULL;
    phantom = nick;
  }
  while (phantom) {
    if (!strcmp(phantom->away, via->p.dname))
      return (phantom);
    else if (resort == NULL && phantom->away[0] == '\0')
      resort = phantom;
    phantom = phantom->pcl;
  }
  if (resort != NULL)
    return (resort);
  return (nick);
}

/* executes message from server */
static inline int _ircd_do_command (peer_priv *peer, int argc, const char **argv)
{
  struct binding_t *b = NULL;
  int i = 0;
  CLIENT *c;
  int t;
#if IRCD_MULTICONNECT
  ACK *ack;
#endif

  if (Ircd->iface)
  {
    /* check if message source is known for me */
    c = _ircd_find_client (argv[0]);
    if (c == NULL) {
      ERROR("ircd:invalid source [%s] from [%s]", argv[0],
	    peer ? peer->link->cl->lcnick : "internal call");
      //TODO: drop link if argv[0] is server name (RFC2813)
      return (0);
    }
    /* check if message may come from the link */
#if IRCD_MULTICONNECT
    if (peer != NULL && !(peer->link->cl->umode & A_MULTI))
#else
    if (peer != NULL)
#endif
      if (c->cs->via != peer) {		/* it should not came from this link! */
	ERROR("ircd:invalid source %s from %s: invalid path", argv[0],
	      peer->link->cl->lcnick);
	if (CLIENT_IS_SERVER(c)) {
	  ircd_do_squit(peer->link, peer, "invalid message source path");
	  return (0);
	}
	return (ircd_recover_done(peer, "invalid message source path"));
	//TODO: RFC2813:3.3 - KILL for (c) if it's a client instead?
      }
    /* check if this link have phantom instead of real client on nick */
    if (peer != NULL && !CLIENT_IS_SERVER(c))
      /* link haven't got our NICK or KILL so track it */
      c = _ircd_find_phantom(c, peer);
#if IRCD_MULTICONNECT
    //TODO: rewrite acks check for QUIT and NICK here!
    if (peer && c->hold_upto && !(CLIENT_IS_SERVER(c)) &&
	(ack = ircd_check_ack(peer, c, NULL)) && /* sender has quited/renamed */
	strcasecmp(argv[1], "NICK"))	/* ircd_nick_sb handles this case */
    {
      /* some backfired messages need special care right now */
      if (!strcasecmp (argv[1], "QUIT"))
	ack->contrary = 1;
      dprint(2, "ircd: message %s from %s seems to be delayed by %s", argv[1],
	     argv[0], peer->p.dname);
      return (1);
    }
#endif
    while (c != NULL && c->hold_upto)
      c = c->x.rto;		/* if it's phantom then go to current nick */
    if (c == NULL) {			/* sender has quited at last */
      dprint(2, "ircd: sender [%s] of message %s is offline for us", argv[0],
	     argv[1]);
      return (0);
    }
    if ((CLIENT_IS_ME(c) || (CLIENT_IS_LOCAL(c) && !(CLIENT_IS_SERVER(c)))) &&
	peer != c->via) /* we should not get our or our users messages back */
    {
      ERROR ("ircd: message %s from %s seems looped back by %s", argv[1],
	     argv[0], peer ? peer->p.dname : "internal call");
      return (1);			/* ouch, it was looped back! */
    }
    t = client2token (c);
    while ((b = Check_Bindtable (BTIrcdServerCmd, argv[1], U_ALL, U_ANYCH, b)))
      if (!b->name)
	i |= b->func (Ircd->iface, peer ? &peer->p : NULL, t, argv[0],
		      c->lcnick, argv[1], argc - 2, &argv[2]);
    return i;
  }
  return 0;
}

/* args: (ignore) numeric target text... */
static inline int _ircd_do_server_numeric(peer_priv *peer, const char *sender,
					  int id, int argc, const char **argv)
{
  CLIENT *tgt;
  register struct binding_t *b;
  size_t ptr;
  int i;
  char buf[MESSAGEMAX];

  if ((tgt = ircd_find_client(sender, peer)) == NULL)
  {
    ERROR("ircd: target %s for numeric from %s not found!", argv[2], sender);
    return 0;
  }
  for (i = 3, ptr = 0; i < argc - 1; i++)
  {
    if (ptr && ptr < sizeof(buf) - 1)
      buf[ptr++] = ' ';
    ptr += strfcpy(&buf[ptr], argv[i], sizeof(buf) - ptr);
  }
  snprintf(&buf[ptr], sizeof(buf) - ptr, "%s:%s", ptr ? " " : "", argv[i]);
  b = Check_Bindtable(BTIrcdDoNumeric, argv[1], U_ALL, U_ANYCH, NULL);
  if (b && !b->name &&
      b->func(Ircd->iface, atoi(argv[1]), argv[2], tgt->umode, buf))
    return 1;				/* aborted by binding */
#if IRCD_MULTICONNECT
  if (!CLIENT_IS_LOCAL(tgt) && id != -1)
  {
    ircd_sendto_new(tgt, ":%s INUM %d %s %s %s", sender, id, argv[1], argv[2],
		    buf);
    ircd_sendto_old(tgt, ":%s %s %s %s", sender, argv[1], argv[2], buf);
  }
  else
#endif
    ircd_sendto_one(tgt, ":%s %s %s %s", sender, argv[1], argv[2], buf);
  return 1;
}

/* passes numerics to target or executes message from server */
static inline int _ircd_do_server_message (peer_priv *peer, int argc,
					   const char **argv)
{
  /* some special support for numerics in transit */
  if (argc >= 4 && match ("[0-9][0-9][0-9]", argv[1]) >= 0)
    /* params: sender numeric target text... */
    return _ircd_do_server_numeric(peer, argv[0], -1, argc, argv);
  else
    return _ircd_do_command (peer, argc, argv);
}

/* sublist receiver interface (for internal usage, I_TEMP) */
static char *_ircd_sublist_buffer;	/* MESSAGEMAX sized! */

static int _ircd_sublist_receiver (INTERFACE *iface, REQUEST *req)
{
  if (req)
    strfcpy (_ircd_sublist_buffer, req->string, MESSAGEMAX);
  return REQ_OK;
}

/* create phantom client for old nick and set collision relations for it
   if [to] is active nick holder then caller should remember it or else
   that relation will be lost after the return from this function
   sets only relation with [to] and previous nick and reference to nick holder
   collision relations should be set by caller */
__attribute__((warn_unused_result)) static inline CLIENT *
	_ircd_get_phantom(const char *on, const char *lon, CLIENT *to)
{
  CLIENT *cl, *cl2;

  dprint(4, "ircd:ircd.c:_ircd_get_phantom: %s -> %s", on, to->nick);
  pthread_mutex_lock (&IrcdLock);
  cl2 = alloc_CLIENT();			/* it should be nowhere now */
  pthread_mutex_unlock (&IrcdLock);
  if (lon)
    cl = _ircd_find_client_lc(lon);
  else {
    unistrlower(cl2->lcnick, on, sizeof(cl2->lcnick));
    cl = _ircd_find_client_lc(cl2->lcnick);
  }
  cl2->hold_upto = Time;
  if (cl) {
    cl2->cs = cl;
    cl2->lcnick[0] = 0;
  } else {
    cl2->cs = cl2;
    if (lon)
      strfcpy(cl2->lcnick, lon, sizeof(cl2->lcnick));
    if (Insert_Key (&Ircd->clients, cl2->lcnick, cl2, 1) < 0)
      ERROR("ircd:_ircd_get_phantom: tree error on adding %s", cl2->lcnick);
      /* FIXME: isn't it something fatal? */
  }
  cl2->via = NULL;			/* to CLIENT_IS_ME work */
  cl2->host[0] = 0;			/* mark it to drop later */
  cl2->away[0] = 0;			/* it's used by nick tracking */
  cl2->x.rto = to;			/* set 'renamed to' */
  cl2->rfr = to->rfr;			/* copy 'renamed from' */
  cl2->pcl = NULL;			/* this has to be set by caller! */
  cl2->umode = 0;
  if (to->rfr != NULL && to->rfr->cs != to) /* it has reference to previous nick */
    to->rfr->x.rto = cl2;		/* so insert this between */
  to->rfr = cl2;
#if IRCD_MULTICONNECT
  cl2->on_ack = 0;
#endif
  return (cl2);
}

#if IRCD_MULTICONNECT
/* should be called after nick is deleted from Ircd->clients */
static inline void _ircd_move_acks (CLIENT *tgt, CLIENT *clone)
{
  dprint(4, "ircd:ircd.c:_ircd_move_acks: %s", tgt->nick);
  if (tgt->on_ack)
  {
    register LINK *l;
    register ACK *ack;

    clone->on_ack += tgt->on_ack;
    tgt->on_ack = 0;
    for (l = Ircd->servers; l; l = l->prev) /* scan every server */
      for (ack = l->cl->via->acks; ack; ack = ack->next)
	if (ack->who == tgt)		/* and move each ack here */
	  ack->who = clone;
  }
}
#endif

/* declaration. caution, two functions calls each other recursively! */
static void _ircd_try_drop_collision(CLIENT **);

/* bounce collision seek pointer to some phantom
   if phantom lcnick is cleared then fill it and insert into Ircd->clients */
static void _ircd_bounce_collision(CLIENT *cl)
{
  register CLIENT *host;

  if (cl->lcnick[0] == '\0') /* it should take name */ {
    _ircd_try_drop_collision(&cl);
    if (cl == NULL)		/* it might be gone */
      return;
    strfcpy(cl->lcnick, cl->cs->lcnick, sizeof(cl->lcnick));
    if (Insert_Key(&Ircd->clients, cl->lcnick, cl, 1) < 0)
      ERROR("ircd:_ircd_bounce_collision: tree error on %s", cl->lcnick);
      /* FIXME: isn't it something fatal? */
  } //TODO: else check for expired holders somehow too?
  for (host = cl; cl; cl = cl->pcl)
    cl->cs = host;
}

/* tries to drop expired phantoms starting from given */
static void _ircd_try_drop_collision(CLIENT **ptr)
{
  register CLIENT *cl = *ptr;

  if (cl->pcl != NULL)		/* update pcl by recursion */
    _ircd_try_drop_collision(&cl->pcl);
  cl = *ptr;
#if IRCD_MULTICONNECT
  if (cl->on_ack > 0 || cl->hold_upto >= Time)
#else
  if (cl->hold_upto >= Time)
#endif
    return;			/* not expired yet */
  dprint (2, "ircd: dropping nick %s from hold (was on %s)", cl->nick, cl->host);
  if (cl->lcnick[0] != '\0') {	/* it's nick holder */
    if (Delete_Key(Ircd->clients, cl->lcnick, cl) < 0)
      ERROR("ircd:_ircd_try_drop_collision: tree error on %s", cl->lcnick);
    if ((*ptr)->pcl != NULL)
      _ircd_bounce_collision((*ptr)->pcl);
  }
  _ircd_real_drop_nick(ptr);	/* if rfr ot x.rto then shift */
}

/* declaration, args: client, server-sender, sender token, new nick
   returns phantom client structure on hold by CHASETIMELIMIT */
static CLIENT *_ircd_do_nickchange(CLIENT *, peer_priv *, unsigned short, const char *);

/* checks nick for collision and if collision not found then returns NULL
   else may try to make a new nick for this one and rename collided
   if there is no solution then removes collided one and sets nick to ""
   in either case returns collided nick structure */
static CLIENT *_ircd_check_nick_collision(char *nick, size_t nsz, peer_priv *pp)
{
  char *collnick;
  struct binding_t *b;
  CLIENT *collided;
  int res;
#define static register
  BINDING_TYPE_ircd_collision ((*f));
#undef static
  register CLIENT *test;

  dprint(4, "ircd:ircd.c:_ircd_check_nick_collision: %s", nick);
  collided = _ircd_find_client(nick);
  if (collided == NULL)
    return (collided);
  if (collided->hold_upto != 0) { /* check if a collision was from the peer */
    CLIENT *tst;
    for (tst = collided; tst; tst = tst->pcl)
      if (tst->host[0] != 0 && !strcmp(tst->host, pp->link->cl->lcnick)) {
	tst->hold_upto = 1;		/* drop hold as netsplit is over */
	break;
      }
    _ircd_try_drop_collision(&collided);
    if (collided == NULL)
      return (collided);
  }
  b = Check_Bindtable(BTIrcdCollision, "*", U_ALL, U_ANYCH, NULL);
  if (b == NULL || b->name) {		/* no binding or script binding? */
    res = 0;
    nick[0] = '\0';			/* both should be removed (RFC2812) */
  } else {
    /* set res to 0 if collided is active and is renamed one so we are forced
       to change collided nick too or else we unable to resolve that */
    if (collided->hold_upto != 0 ||	/* either it's phantom */
	collided->rfr == NULL ||	/* or no collision */
	collided->rfr->cs == collided)	/* or keyholder */
      res = 1;
    else
      res = 0;
    f = (void *)b->func;
    collnick = f(nick, nsz, res);
    if (collnick == NULL)
      res = 0; /* going to remove it */
    else if ((test = _ircd_find_client(collnick)) == collided)
      collnick = collided->nick; /* ignore case change from binding */
    else if (test)
      collnick = collided->nick; /* abort change which makes collision */
    else if (res == 0)
      res = 2;			/* binding was forced to change and done job */
    /* check if binding made it right */
    if ((test = _ircd_find_client(nick)) == NULL) ; /* no collision anymore */
    else if ((res == 0 || collnick != collided->nick) && test == collided)
      ; /* collided will be changed/removed instead */
    else {
      ERROR("ircd:collision resolving conflict for nick %s", nick);
      nick[0] = '\0';
    }
  }
  if (res == 0) {			/* no solution from binding */
    if (CLIENT_IS_LOCAL(collided))
      New_Request(collided->via->p.iface, 0, ":%s KILL %s :Nick collision from %s",
		  MY_NAME, collided->nick, pp->p.dname); /* notify the victim */
    ircd_sendto_servers_all_ack(Ircd, collided, NULL, NULL,
				":%s KILL %s :Nick collision from %s", MY_NAME,
				collided->nick, pp->p.dname); /* broadcast KILL */
    ircd_prepare_quit(collided, pp, "nick collision");
    collided->hold_upto = Time + CHASETIMELIMIT;
    Add_Request(I_PENDING, "*", 0, ":%s!%s@%s QUIT :Nick collision from %s",
		collided->nick, collided->user, collided->host, pp->p.dname);
    collided->host[0] = 0;		/* for collision check */
  } else if (collnick != collided->nick) { /* binding asked to change collided */
    _ircd_do_nickchange(collided, NULL, 0, collnick);
    if (_ircd_find_client(nick)) { /* ouch! we got the same for both collided! */
      ERROR("ircd:collision resolving conflict for nick %s", nick);
      nick[0] = '\0';
    }
  }
  return (collided);
}

/* do the same as _ircd_peer_kill but for remote user and thread-unsafe */
static void _ircd_remote_user_gone(CLIENT *cl)
{
  register LINK **s;
  LINK *l;

  dprint(3, "ircd:ircd.c:_ircd_remote_user_gone: %s", cl->nick);
  /* remove it from lists but from Ircd->clients */
  for (s = &cl->cs->c.lients; *s; s = &(*s)->prev)
    if ((*s)->cl == cl)
      break;
  if ((l = *s) != NULL)
    *s = l->prev;
  if (l != NULL && cl->x.class != NULL)
    _ircd_class_out(l);
  else
    cl->pcl = NULL; //TODO: error message?
  _ircd_bt_lost_client(cl, cl->cs->lcnick); /* do bindtable ircd-lost-client */
  cl->cs = cl;		/* abandon server */
  cl->x.rto = NULL;
  /* converts active user into phantom on hold for this second */
  cl->hold_upto = Time;
  cl->away[0] = '\0';	/* it's used by nick change tracking */
  if (cl->rfr != NULL && cl->rfr->cs == cl) { /* it was nick holder */
    cl->pcl = cl->rfr;
    cl->rfr = NULL;
  }
  cl->via = NULL;	/* to CLIENT_IS_ME work */
  pthread_mutex_lock (&IrcdLock);
  if (l != NULL)	/* free structure */
    free_LINK(l);
  pthread_mutex_unlock (&IrcdLock);
}


/* state	client		server		outgoing
 *
 * P_INITIAL	waiting		waiting		sent PASS
 * P_LOGIN	got USER / NICK	got PASS
 * P_IDLE					sent SERVER
 * P_TALK	got both	got+sent SERVER	got SERVER
 */

/* -- client interface ----------------------------------------------------
   on terminating it does not kill interface but shedules death instead */
static iftype_t _ircd_client_signal (INTERFACE *cli, ifsig_t sig)
{
  peer_priv *peer = cli->data;
  size_t sw;
  char buff[STRING];

  dprint(4, "ircd:ircd.c:_ircd_client_signal: name=%s sig=%d",
	 NONULL((char *)cli->name), (int)sig);
  switch (sig)
  {
    case S_REPORT:
      //TODO...
      //host isn't valid if not P_LOGIN nor P_TALK
      break;
    case S_TERMINATE:
      switch (peer->p.state)
      {
	case P_DISCONNECTED:		/* there is a thread still */
	  pthread_cancel (peer->th);
	  Unset_Iface();		/* let it to finish bindings */
	  pthread_join (peer->th, NULL);
	  Set_Iface(cli);
	case P_INITIAL:			/* isn't registered yet */
	case P_IDLE:
	case P_LOGIN:
	  _ircd_peer_kill (peer, NONULL(ShutdownR));
	case P_QUIT:			/* shutdown is in progress */
	case P_LASTWAIT:
	  cli->ift &= ~I_FINWAIT;	/* don't kill me anymore */
	  break;
	case P_TALK:			/* shedule death to it */
	  if (CLIENT_IS_SERVER (peer->link->cl))
	    ircd_do_squit (peer->link, peer, NONULL(ShutdownR));
	  else
	  {
	    ircd_sendto_servers_all_ack (Ircd, peer->link->cl, NULL, NULL,
					 ":%s QUIT :%s", peer->p.dname,
					 NONULL(ShutdownR));
	    ircd_prepare_quit (peer->link->cl, peer, NONULL(ShutdownR));
	    Add_Request (I_PENDING, "*", 0, "QUIT :%s", NONULL(ShutdownR));
	  }
      }
      break;
    case S_SHUTDOWN:
      sw = snprintf (buff, sizeof(buff), "ERROR : Emergency : %s",
		     NONULL(ShutdownR));
      if (Peer_Put ((&peer->p), buff, &sw) > 0)
	while (!Peer_Put ((&peer->p), NULL, &sw));
      //CloseSocket (peer->p.socket);
      cli->ift = I_DIED;
      break;
    default: ;
  }
  return 0;
}

static void _ircd_init_uplinks (void); /* declaration; definitoon is below */

#define IRCDMAXARGS 16		/* maximum number of arguments in protocol */

/* adds prefix to message if there is none */
static int _ircd_client_request (INTERFACE *cli, REQUEST *req)
{
  peer_priv *peer = cli->data;
  register peer_priv **pp;
  char *c;
  CLIENT *cl;
  struct binding_t *b;
  const char *argv[IRCDMAXARGS+3];	/* sender, command, args, NULL */
  size_t sw;
  ssize_t sr;
  int argc, i;
  char buff[MB_LEN_MAX*IRCMSGLEN+1];
#if IRCD_USES_ICONV
  char sbuff[MB_LEN_MAX*IRCMSGLEN+1];
#endif
  register LINK **ll;

//  dprint(4, "ircd:ircd.c:_ircd_client_request: name=%s state=%d req=%p",
//	 NONULL(cli->name), (int)peer->p.state, req);
  if (peer->p.state == P_DISCONNECTED)
    return REQ_REJECTED;
  cl = peer->link->cl;
  switch (peer->p.state)
  {
    case P_QUIT:	/* at this point it should be isolated already */
      if (req)
      {
	if (strncmp (req->string, "ERROR ", 6) &&
	    strncmp (NextWord(req->string), "KILL ", 5))
	  return REQ_OK;	/* skip anything but ERROR or KILL message */
	DBG("sending last message to client \"%s\"", cl->nick);
	sw = strlen (req->string);
	if (sw && Peer_Put ((&peer->p), req->string, &sw) == 0)
	  return REQ_REJECTED;	/* try again later */
      }
      Rename_Iface(cli, NULL);
      Delete_Key (Ircd->clients, cl->lcnick, cl); /* delete it before checks */
      if (peer == _ircd_uplink)
	_ircd_uplink = NULL;
      if (CLIENT_IS_SERVER (cl)) { /* was it autoconnect who left? */
	if (Get_Clientflags (cl->lcnick, Ircd->iface->name) & U_AUTO)
	{
#if IRCD_MULTICONNECT
	  _ircd_uplinks--;
#endif
	  _ircd_init_uplinks();	/* recheck uplinks list */
	}
      } else {			/* clear any collision relations */
	if (cl->rfr != NULL) {
	  if (cl->rfr->cs == cl) /* it was active keyholder */
	    cl->pcl = cl->rfr;
	  else if (cl->rfr->x.rto == cl) { /* it was renamed */
	    cl->rfr->x.rto = NULL; /* omit this one */
	    _ircd_try_drop_collision(&cl->rfr);
	  }
	  cl->rfr = NULL;	/* we reset our relation already */
	}
	/* we have ->cs to itself for local client always, ->pcl is set by kill
	   and ->x.rto is NULL for non-phantoms after leaving class */
	if (cl->hold_upto <= Time) {
	  if (cl->pcl != NULL)
	    _ircd_bounce_collision(cl->pcl);
	} else {
	  register CLIENT *phantom;

	  phantom = _ircd_get_phantom(cl->nick, cl->lcnick, cl);
	  phantom->x.rto = NULL;
	  phantom->hold_upto = cl->hold_upto;
	  cl->rfr = NULL;
	  if (cl->pcl != NULL) {
	    phantom->pcl = cl->pcl;
	    _ircd_bounce_collision(phantom);
	  }
	  cl->lcnick[0] = 0;	/* we deleted the key */
	}
	cl->pcl = NULL;		/* for safe module termination */
	cl->hold_upto = 0;	/* it's 0 since no collisions on it */
      } /* and it is not in any list except peers now */
      peer->p.state = P_LASTWAIT;
    case P_LASTWAIT:
      sw = 0;			/* trying to send what is still left */
      sr = Peer_Put ((&peer->p), NULL, &sw);
      if (sr == 0)
	return REQ_OK;		/* still something left, OK, will try later */
      if (Connchain_Kill ((&peer->p)))
	KillSocket(&peer->p.socket);
      cli->data = NULL;		/* disown it */
      cli->ift |= I_DIED;
      //TODO: run "ircd-lost-client" bindtable on non-servers
      pthread_mutex_lock (&IrcdLock);
      for (pp = &IrcdPeers; *pp; pp = &(*pp)->p.priv)
	if ((*pp) == peer)
	{
	  *pp = peer->p.priv;
	  break;
	}
      for (ll = &ME.c.lients; *ll != NULL; ll = &(*ll)->prev)
	if (*ll == peer->link)
	  break;
      if (*ll != NULL)
	*ll = peer->link->prev;
      else
	ERROR("ircd:could not find %s in local client list", cl->nick);
      free_LINK (peer->link);
      if (CLIENT_IS_SERVER (cl))
	NoCheckFlood (&peer->corrections);
      free_peer_priv (peer);
#if IRCD_MULTICONNECT
      if (cl->on_ack)		/* hold it until acks gone */
      {
	cl->via = NULL;		/* to CLIENT_IS_ME work */
	cl->hold_upto = Time;
      }
      else
#endif
	free_CLIENT (cl);	/* free structures */
      pthread_mutex_unlock (&IrcdLock);
      return REQ_OK;		/* interface will now die */
    case P_DISCONNECTED:	/* unused here, handled above */
    case P_INITIAL:
    case P_LOGIN:
    case P_TALK:
    case P_IDLE:
      sw = 0;
      if (Peer_Put ((&peer->p), "", &sw) == CONNCHAIN_READY && req) {
	  /* flush buffer in any case*/
	if (req->string[0] == ':' ||		/* if already prefixed or */
	    req->from->IFRequest != &_ircd_client_request || /* alien message */
	    !strncmp (req->string, "ERROR ", 6)) /* or ERROR message */
	  strfcpy(buff, req->string, sizeof(buff)); /* will not add sender prefix */
	else					/* it must be local request */
	  /* add sender prefix to the message */
	  if (CLIENT_IS_SERVER (cl))
#if IRCD_USES_ICONV
	    sw = snprintf(sbuff, sizeof(sbuff), ":%s ",
			  ((peer_priv *)req->from->data)->p.dname);
#else
	    snprintf (buff, sizeof(buff), ":%s %s",
		      ((peer_priv *)req->from->data)->p.dname, req->string);
#endif /* IRCD_USES_ICONV */
	  else
	  {
#ifdef USE_SERVICES
	    if (CLIENT_IS_SERVICE (((peer_priv *)req->from->data)->link->cl))
#if IRCD_USES_ICONV
	      sw = snprintf(sbuff, sizeof(sbuff), ":%s@%s ",
			    ((peer_priv *)req->from->data)->p.dname, MY_NAME);
#else
	      snprintf (buff, sizeof(buff), ":%s@%s %s",
			((peer_priv *)req->from->data)->p.dname, MY_NAME,
			req->string);
#endif /* IRCD_USES_ICONV */
	    else
#endif /* USE_SERVICES */
#if IRCD_USES_ICONV
	    sw = snprintf(sbuff, sizeof(sbuff), ":%s!%s@%s ",
			  ((peer_priv *)req->from->data)->p.dname,
			  ((peer_priv *)req->from->data)->link->cl->user,
			  ((peer_priv *)req->from->data)->link->cl->host);
#else
	    snprintf (buff, sizeof(buff), ":%s!%s@%s %s",
		      ((peer_priv *)req->from->data)->p.dname,
		      ((peer_priv *)req->from->data)->link->cl->user,
		      ((peer_priv *)req->from->data)->link->cl->host,
		      req->string);
#endif /* IRCD_USES_ICONV */
	  }
#if IRCD_USES_ICONV
	if (sw > 0) {			/* was prefixed above */
	  c = buff;
	  if (sw >= sizeof(sbuff))
	    sw = sizeof(sbuff) - 1;
	  sr = Undo_Conversion(cli->conv, &c, sizeof(buff) - 1, sbuff, sw);
	  if (c == sbuff) {		/* null conversion */
	    sw = snprintf(buff, sizeof(buff), "%s%s", sbuff, req->string);
	    if (sw >= sizeof(buff))
	      sw = sizeof(buff) - 1;
	  } else			/* c == buff */
	    sw = sr + strfcpy(&buff[sr], req->string, sizeof(buff) - sr);
	} else
#endif
	/* would be nice to cut the message to standard size but we don't know
	   how to handle message in target's charset unfortunately */
	sw = strlen(buff);
	sr = sw + 1;			/* for statistics */
	//TODO: BTIrcdCheckSend(cmd): func (Ircd, &peer->p, peer->link->cl->umode);
	if (Peer_Put ((&peer->p), buff, &sw) > 0)
	{
	  peer->ms++;
	  peer->bs += sr;
	  req = NULL;			/* it's done */
	}
	//TODO: else check if sendq isn't exceeded limit
      } else if (Peer_Put ((&peer->p), buff, &sw) < 0)
	
      break;
  }
  sr = Peer_Get ((&peer->p), buff, sizeof(buff));
  if (sr > 0)				/* we got a message from peer */
  {
    peer->p.last_input = Time;
    peer->mr++;				/* do statistics */
    peer->br += sr;
#if IRCD_USES_ICONV
    c = sbuff;
    sr = Do_Conversion (cli->conv, &c, sizeof(sbuff), buff, sr);
#else
    c = buff;
    sr--;				/* skip ending '\0' */
#endif
    if (*c == ':')			/* we got sender prefix */
    {
      register char *cc;

      argv[0] = &c[1];
      c = gettoken (c, NULL);
      cc = strchr (argv[0], '!');
      if (cc) *cc = 0;			/* leave only sender name here */
      if (!CLIENT_IS_SERVER (cl) &&	/* verify if sender is ok */
	  _ircd_find_client (argv[0]) != cl)
	*(char *)argv[0] = 0;
    }
    else
      argv[0] = peer->p.dname;
    argc = 1;
    do {
      if (*c == ':')
      {
	argv[argc++] = ++c;
	break;
      }
      else
	argv[argc++] = c;
      if (argc == IRCDMAXARGS + 2)
	break;
      c = gettoken (c, NULL);
    } while (*c);
    i = 0;
    argv[argc] = NULL;
    if (!*argv[1]);			/* got malformed line */
    else if (!Ircd->iface);		/* internal error! */
    else if (peer->p.state == P_INITIAL) /* not registered yet */
    {
      b = Check_Bindtable (BTIrcdRegisterCmd, argv[1], U_ALL, U_ANYCH, NULL);
      if (b)
	if (!b->name)
	  i = b->func (Ircd->iface, &peer->p, argc - 2, &argv[2]);
    } else if (!*argv[0])
      WARNING("ircd: invalid prefix from peer \"%s\"", peer->p.dname);
    else if (CLIENT_IS_SERVER (cl))	/* got server protocol input */
      i = _ircd_do_server_message (peer, argc, argv);
    else				/* got client protocol input */
    {
      b = NULL;
      while ((b = Check_Bindtable (BTIrcdClientFilter, argv[1], peer->p.uf,
				   U_ANYCH, b)))
	if (!b->name)
	  if ((i = b->func (Ircd->iface, &peer->p, cl->umode, argc - 2,
			    &argv[2])))
	    break;			/* it's consumed so it's done */
      if (i == 0)
	if ((b = Check_Bindtable (BTIrcdClientCmd, argv[1], peer->p.uf, U_ANYCH,
				  NULL)))
	  if (!b->name)			/* passed thru filter and found cmd */
	    i = b->func (Ircd->iface, &peer->p, cl->lcnick, cl->user, cl->host,
			 argc - 2, &argv[2]);
    }
    if (i == 0)				/* protocol failed */
    {
      if (CLIENT_IS_SERVER (cl))
	ircd_recover_done (peer, "Invalid command"); /* it might get squit */
      else
	ircd_do_unumeric (cl, ERR_UNKNOWNCOMMAND, cl, 0, argv[1]);
    }
#ifndef IDLE_FROM_MSG
    else if (i > 0)
      peer->noidle = Time;		/* for idle calculation */
#endif
  }
  if (peer->p.state == P_QUIT);		/* died in execution! */
  else if (CLIENT_IS_SERVER (cl))
    i = _ircd_server_class_pingf;
  else
    i = cl->x.class->pingf;
  if (sr < 0 || Time > (peer->p.last_input + (i<<1)))
    cli->ift |= I_FINWAIT;		/* suicide */
  if (Time >= (peer->p.last_input + i) && !(cl->umode & A_PINGED))
  {
    cl->umode |= A_PINGED;		/* ping our peer */
    New_Request (cli, F_QUICK, ":%s PING %s", MY_NAME, MY_NAME);
  }
  if (req)
    return REQ_REJECTED;
  return REQ_OK;
}

/*
 * listfile records:
 * hosts for servers are in form [ident[:pass]@]host[/port[%flags]]
 *   they cannot (and should not) be checked after connect but will be checked
 *   after we got SERVER message
 *   host record can be used for connect or for autoconnect
 *   pass and port[%flags] in it are used for autoconnect only
 * hosts for classes should be in form x@y - there is no nick on check for it
 * passwd is encrypted password for incoming connect
 * info is description
 *
 * subrecord for network:
 * flags for servers are U_ACCESS (ircd_server_rb)
 * flags for autoconnect are U_AUTO (_ircd_init_uplinks, ircd_server_rb)
 * flags for restricted class are U_DEOP (_ircd_got_local_user)
 * flags for kill are U_DENY (_ircd_got_local_user)
 * content is:
 *   empty for autoconnect (only one server at the time, of course)
 *   empty for server (not usable for class anyway)
 *   not empty for any classes: ul/loc uh/glob u/class pingfreq sendq
 *
 * '.connect' is there: .connect server@network [port]
 *   should use server record and check network subrecord;
 *   using password, port, and flags from hostrecord; port may replace one
 */

/* -- ircd listener interface ---------------------------------------------
   called right after socket was answered or listener died */
static void _ircd_prehandler (pthread_t th, void **data, idx_t *as)
{
  peer_priv *peer;
  char *pn;		/* [host/]port[%flags] */
#if IRCD_USES_ICONV
  char charset[64];	/* I hope it's enough */
#endif

  if (*as < 0)
    return; /* listener died but it can be SIGSEGV so no diagnostics */
  /* listener data is its confline :) */
#if IRCD_USES_ICONV
  pn = NextWord((char *)*data);
  if (*pn == '-')
    pn = NextWord_Unquoted (charset, ++pn, sizeof(charset));
  else
    charset[0] = 0;
#endif
  pthread_mutex_lock (&IrcdLock);
  *data = peer = alloc_peer_priv();
  peer->p.state = P_DISCONNECTED;
  peer->p.priv = IrcdPeers;
  IrcdPeers = peer;
  pthread_mutex_unlock (&IrcdLock);
  peer->p.socket = *as;
  peer->p.connchain = NULL;
  peer->p.start[0] = 0;
  peer->bs = peer->br = peer->ms = peer->mr = 0;
  peer->th = th;
  /* lock dispatcher and create connchain */
  Set_Iface (NULL);
  if ((pn = strchr (pn, '%')))		/* do custom connchains for SSL etc. */
    while (*++pn)
      if (*pn != 'x' && !Connchain_Grow (&peer->p, *pn))
	KillSocket (&peer->p.socket);	/* filter failed and we own the socket */
  Connchain_Grow (&peer->p, 'x');	/* text parser is mandatory */
  peer->p.last_input = peer->started = Time;
  /* create interface */
  peer->p.iface = Add_Iface (I_CLIENT | I_CONNECT, NULL, &_ircd_client_signal,
			     &_ircd_client_request, peer);
#if IRCD_USES_ICONV
  if (*charset)
    peer->p.iface->conv = Get_Conversion (charset);
  else
    peer->p.iface->conv = NULL;
#endif
  Unset_Iface();
}

#define peer ((peer_priv *)data)
/* we got ident and host so can continue, cln is NULL here */
static void _ircd_handler (char *cln, char *ident, const char *host, void *data)
{
  register CLIENT *cl;
  const char *msg;
  struct binding_t *b;

  dprint(4, "ircd:ircd.c:_ircd_handler: %s@%s", NONULL(ident), host);
  /* set parameters for peer */
  pthread_mutex_lock (&IrcdLock);
  peer->link = alloc_LINK();
  peer->link->cl = cl = alloc_CLIENT();
  peer->link->where = &ME;
  peer->link->prev = ME.c.lients;
  peer->link->flags = 0;
  ME.c.lients = peer->link;
  cl->via = peer;
  cl->x.class = NULL;
  pthread_mutex_unlock (&IrcdLock);
  strfcpy (cl->user, NONULL(ident), sizeof(cl->user));
  unistrlower (cl->host, host, sizeof(cl->host));
  cl->pcl = cl->cs = NULL;
  cl->umode = 0;
  cl->nick[0] = 0;
  cl->lcnick[0] = 0;
  cl->fname[0] = 0;
  cl->away[0] = 0;
  cl->hold_upto = 0;
  cl->rfr = NULL;			/* no collisions for it yet */
  cl->hops = 1;
#if IRCD_MULTICONNECT
  cl->on_ack = 0;
  cl->alt = NULL;
#endif
  peer->p.dname = &cl->nick[0];
  peer->noidle = 0;
  /* find class, validate user... "ircd-auth" bindtable */
  Set_Iface (peer->p.iface);		/* lock bindtable access */
  b = NULL;
  msg = NULL;
  while ((b = Check_Bindtable (BTIrcdAuth, host, U_ALL, U_ANYCH, b)))
    if (b->name == NULL)		/* only internal allowed */
    {
      int res = b->func (&peer->p, ident, host, &msg);
      Set_Iface (peer->p.iface);	/* regain lock */
      if (res == 0)
	break;				/* auth error */
    }
  peer->p.state = P_INITIAL;
  Unset_Iface();			/* done so unlock bindtable */
  if (msg)				/* not allowed! */
    _ircd_peer_kill (peer, msg);
  else
    ircd_do_unumeric (cl, RPL_HELLO, &ME, 0, Ircd->iface->name);
}
#undef peer

		/* ircd [-charset] [host/]port[%flags] */
ScriptFunction (func_ircd)
{
  char buff[STRING];
  char host[HOSTLEN+1];
#if IRCD_USES_ICONV
  struct conversion_t *conv;
#endif
  char *c, *data;
  unsigned short port;
  size_t s, t;

  if (IrcdLnum >= IRCDLMAX)
  {
    BindResult = "too many ircd ports opened";
    return 0;
  }
  s = strfcpy (buff, "ircd ", sizeof(buff));
  if (*args == '-')
  {
    /* note: ignore parameter charset if no iconv available */
#if IRCD_USES_ICONV
    args++;
    args = NextWord_Unquoted (&buff[s], (char *)args, sizeof(buff) - s - 1);
    conv = Get_Conversion (&buff[s]);
    if (!conv)
    {
      BindResult = "unknown charset";
      return 0;
    }
    s += strlen (&buff[s]);
    buff[s++] = ' ';
#else
    args = NextWord ((char *)args);
    Add_Request (I_LOG, "*", F_WARN,
		 "ircd: ignoring charset parameter, no iconv in use!");
#endif
  }
  t = s;
  while (*args && *args != ' ' && s < (sizeof(buff) - 1))
    buff[s++] = *args++;
  buff[s] = 0;
  if ((c = strchr (&buff[t], '/')))
  {
    port = atoi (++c);
    if (c > &buff[t+sizeof(host)])
      c = &buff[t+sizeof(host)];
    strfcpy (host, &buff[t], c - &buff[t]);
  }
  else
  {
    port = atoi (&buff[t]);
    host[0] = 0;
  }
  if (Find_Iface (I_LISTEN, buff))	/* it's reconfigure */
  {
    Unset_Iface();
    Add_Request(I_LOG, "*", F_BOOT,
		"Attempt to regain \"%s\" which is already listening", buff);
    return (1);
  }
  //TODO: check if there is listener for the same port but another charset etc.
  for (s = 0; s < IrcdLnum; s++)
    if (!IrcdLlist[s] || !strcmp (IrcdLlist[s], buff))
      break;
  if (s == IrcdLnum || !IrcdLlist[s])
    IrcdLlist[s] = safe_strdup (buff);
  else
    Add_Request (I_LOG, "*", F_WARN, "Found dead listener for: %s", buff);
  data = safe_strdup (buff);
  if (port == 0 ||
      Listen_Port(NULL, *host ? host : NULL, port, buff, data,
		  NULL, &_ircd_prehandler, &_ircd_handler))
  {
    FREE (&IrcdLlist[s]);
    FREE (&data);
    BindResult = "could not open listening port";
    return 0;
  }
  if (s == IrcdLnum)
    IrcdLnum++;
  return (IrcdLnum);
}


/* -- uplink init interface -----------------------------------------------
   states: P_DISCONNECTED, P_INITIAL, P_LASTWAIT
   in-thread handler : (CLIENT *)id is uplink */
static void _ircd_uplink_handler (int res, void *id)
{
  if (res < 0)
    ((CLIENT *)id)->via->p.state = P_LASTWAIT;
  else
    ((CLIENT *)id)->via->p.state = P_INITIAL;
}

/* out-of-thread parts */
static iftype_t _ircd_uplink_sig (INTERFACE *uli, ifsig_t sig)
{
  peer_priv *uplink = uli->data;
  register peer_priv **ull;
  register LINK **ll;

  dprint(2, "ircd:ircd.c:_ircd_uplink_sig: name=%s sig=%d", uli->name, (int)sig);
  if (!uplink)				/* already terminated */
    return I_DIED;
  switch (sig)
  {
    case S_REPORT:
      //TODO.......
      break;
    case S_TERMINATE:
      /* free everything including socket */
      if (uplink->p.state == P_DISCONNECTED) /* there is a thread still */
      {
	pthread_cancel (uplink->th);
	pthread_join (uplink->th, NULL); /* it never locks dispatcher */
      }
      if (Connchain_Kill ((&uplink->p))) /* always true */
	KillSocket (&uplink->p.socket);
#if IRCD_MULTICONNECT
      _ircd_uplinks--;
#endif
      pthread_mutex_lock (&IrcdLock);
      for (ull = &IrcdPeers; *ull; ull = &(*ull)->p.priv)
	if (*ull == uplink) {
	  *ull = uplink->p.priv;	/* remove it from list */
	  break;
	}
      for (ll = &ME.c.lients; *ll != NULL; ll = &(*ll)->prev)
	if (*ll == uplink->link)
	  break;
      if (*ll != NULL)
	*ll = uplink->link->prev;
      else
	ERROR("ircd:autoconnect %s not found in local clients list",
	      uplink->link->cl->lcnick);
      free_CLIENT (uplink->link->cl);
      free_LINK (uplink->link);
      free_peer_priv (uplink);
      pthread_mutex_unlock (&IrcdLock);
      uli->data = NULL;			/* there is no data there */
      uli->ift = I_DIED;
      break;
    case S_SHUTDOWN:
      //CloseSocket (uplink->p.socket);
      uli->ift = I_DIED;
    default: ;
  }
  return 0;
}

static inline int _ircd_stop_uplink (INTERFACE *uli)
{
  _ircd_uplink_sig (uli, S_TERMINATE);
  _ircd_init_uplinks();
  return REQ_OK;
}

static int _ircd_uplink_req (INTERFACE *uli, REQUEST *req)
{
  char *c, *opt;
  size_t sz;
  char buff[MESSAGEMAX];
  register CLIENT *ul;
  peer_priv *_uplink = uli->data;

//  dprint(3, "ircd:ircd.c:_ircd_uplink_req: name=%s state=%d req=%p",
//	 NONULL(uli->name), (int)_uplink->p.state, req);
  ul = _ircd_find_client_lc (_uplink->link->cl->lcnick);
  if (ul && !ul->hold_upto && CLIENT_IS_LOCAL(ul)) /* it's connected already! */
    _uplink->p.state = P_LASTWAIT;	/* so abort this one */
  if (_ircd_uplink)		/* we got RFC2813 autoconnect connected */
    _uplink->p.state = P_LASTWAIT; /* so we should stop every autoconnect */
  switch (_uplink->p.state)
  {
    case P_INITIAL:	/* got connected, switch to normal */
#if IRCD_USES_ICONV
      /* set conversion to CHARSET_8BIT which is default */
      _uplink->p.iface->conv = Get_Conversion (CHARSET_8BIT);
#endif
      opt = _uplink->link->cl->away;
      c = strchr (opt, '%');		/* check for flags */
      if (c)
	while (*++c)			/* create connection chain */
	  if (!Connchain_Grow (&_uplink->p, *c))
	    return _ircd_stop_uplink (uli);
      Connchain_Grow (&_uplink->p, 'x'); /* mandatory one */
      uli->IFRequest = &_ircd_client_request; /* set ASAP for Connchain_Check */
      /* try all connchain flags (for PASS) */
      for (c = _ircd_flags_first; *c; c++)
	if (Connchain_Check (&_uplink->p, *c) > 0)
	  *opt++ = *c;
      for (c = _ircd_flags_post; *c; c++)
	if (Connchain_Check (&_uplink->p, *c) > 0)
	  *opt++ = *c;
      *opt = '\0';			/* terminate options */
      ul = _uplink->link->cl;
      sz = snprintf (buff, sizeof(buff), /* send PASS+SERVER to peer */
		     "PASS %s %s IRC|" PACKAGE " %s\r\n"
		     "SERVER %s 1 %hu :%s",
		     *ul->fname ? ul->fname : "*",
		     _ircd_version_string, ul->away, MY_NAME,
		     (unsigned short int)_uplink->p.socket,
		     _ircd_description_string);
      _uplink->bs = sz - 2;
      _uplink->ms = 2;
      if (Peer_Put ((&_uplink->p), buff, &sz) <= 0) /* something went bad */
	return _ircd_stop_uplink (uli);
      *ul->away = '\0';			/* clear what we filled before */
      *ul->fname = '\0';
      _uplink->br = _uplink->mr = 0;
      _uplink->started = Time;
      _uplink->p.last_input = Time;
      _uplink->p.start[0] = 0;
      _uplink->p.state = P_IDLE;	/* we will wait for responce now */
      uli->IFSignal = &_ircd_client_signal;   /* common client handlers */
      break;
    case P_LASTWAIT:	/* connection error or killed */
      return _ircd_stop_uplink (uli);
    default: ;		/* waiting for connection yet */
  }
  return REQ_OK;	/* ignoring requests ATM */
}

static inline void _ircd_start_uplink2 (const char *name, char *host,
					const char *port, const char *pass)
{
  CLIENT *uplink;

  pthread_mutex_lock (&IrcdLock);
  uplink = alloc_CLIENT();
  uplink->via = alloc_peer_priv();
  uplink->via->link = alloc_LINK();
  uplink->via->link->cl = uplink;
  uplink->via->link->where = &ME;
  uplink->via->link->prev = ME.c.lients;
  uplink->via->link->flags = 0;
  ME.c.lients = uplink->via->link;
  uplink->via->p.priv = IrcdPeers;
  IrcdPeers = uplink->via;
  pthread_mutex_unlock (&IrcdLock);
#if IRCD_MULTICONNECT
  _ircd_uplinks++;
#endif
  uplink->via->p.dname = uplink->lcnick;
  uplink->via->p.state = P_DISCONNECTED;
  uplink->via->p.connchain = NULL;
  uplink->pcl = uplink->cs = NULL;
  uplink->x.class = NULL;
  uplink->hold_upto = 0;
  uplink->umode = A_UPLINK;
  uplink->away[0] = 0;
  uplink->nick[0] = 0;
  uplink->fname[0] = 0;
  uplink->user[0] = 0;
  uplink->hops = 1;
  unistrlower (uplink->lcnick, name, sizeof(uplink->lcnick));
  if (pass)
    strfcpy (uplink->fname, pass, sizeof(uplink->fname)); /* remember it */
  strfcpy (uplink->away, port, sizeof(uplink->away)); /* remember port string */
  strfcpy (uplink->host, host, sizeof(uplink->host)); /* remember host name */
  Connchain_Grow (&uplink->via->p, 0); /* init empty connchain */
  uplink->via->p.iface = Add_Iface (I_CONNECT, uplink->lcnick,
				    &_ircd_uplink_sig, &_ircd_uplink_req,
				    uplink->via);
  if (Connect_Host (host, atoi(port), &uplink->via->th,
		    &uplink->via->p.socket, &_ircd_uplink_handler, uplink))
    Add_Request (I_LOG, "*", F_CONN, "ircd: starting autoconnect: %s/%s",
		 host, port);
  else
  {
    register peer_priv **pp;
    register LINK **ll;

    uplink->via->p.iface->ift = I_DIED; /* error on thread creating */
    ERROR ("ircd:error on starting autoconnect to %s/%s", host, port);
#if IRCD_MULTICONNECT
    _ircd_uplinks--;
#endif
    pthread_mutex_lock (&IrcdLock);
    for (pp = &IrcdPeers; *pp; pp = &(*pp)->p.priv)
      if (*pp == uplink->via)
      {
	*pp = uplink->via->p.priv;
	break;
      }
    for (ll = &ME.c.lients; *ll != NULL; ll = &(*ll)->prev)
      if (*ll == uplink->via->link)
	break;
    if (*ll != NULL)
      *ll = uplink->via->link->prev;
    else
      ERROR("ircd:_ircd_start_uplink2: internal error on %s", uplink->lcnick);
    free_LINK (uplink->via->link);
    free_peer_priv (uplink->via);
    free_CLIENT (uplink);
    pthread_mutex_unlock (&IrcdLock);
  }
}

/* parse hostrecord (full form) and do _ircd_start_uplink2 */
static void _ircd_start_uplink (char *name, char *host)
{
  char *c = host, *port;		/* user/passwd part, port */

  if ((host = strchr (c, '@')))		/* get host name from record */
    *host++ = 0;
  else
  {
    host = c;
    c = NULL;
  }
  port = strchr (host, '/');		/* check for port */
  if (!port)
  {
    ERROR ("ircd:host %s of uplink %s has no port, ignoring it.", host, name);
    return;
  }
  *port++ = 0;
  c = safe_strchr (c, ':');		/* check for password */
  if (c)
    c++;
  _ircd_start_uplink2 (name, host, port, c);
}

/* called when uplink is invalid (absent or died) */
static void _ircd_init_uplinks (void)
{
  INTERFACE *tmp;
  int i;
  char *c;

  if (_ircd_uplink)			/* got RFC2813 server autoconnected*/
    return;				/* so nothing to do */
  tmp = Add_Iface (I_TEMP, NULL, NULL, &_ircd_sublist_receiver, NULL);
  i = Get_Clientlist (tmp, U_AUTO, Ircd->iface->name, "*");
  if (i)
  {
    lid_t lid;
    char buff[MESSAGEMAX];
    char hosts[MESSAGEMAX];

    c = _ircd_sublist_buffer = buff;
    Set_Iface (tmp);
    Get_Request();
    Add_Request (I_LOG, "*", F_CONN, "ircd: got autoconnect list: %s",
		 _ircd_sublist_buffer);
    /* side effect: autoconnect list should be not longer that one message */
    while (*c)				/* for each autoconnect */
    {
      char *cc = c, *hl;

      c = gettoken (cc, NULL);
      lid = FindLID (c);
      while (Get_Request());		/* we need queue to be empty */
      _ircd_sublist_buffer = hosts;
      i = Get_Hostlist (tmp, lid);
      if (i)
	Get_Request();
      else
      {
	struct clrec_t *u = Lock_byLID (lid);
	register userflag uf = Get_Flags (u, Ircd->iface->name);

	uf &= ~U_AUTO;
	Set_Flags (u, Ircd->iface->name, uf);
	Unlock_Clientrecord (u);
	Unset_Iface();
	ERROR ("ircd:uplink %s has no host record, reset autoconnect flag!", c);
	continue;
      }
      hl = hosts;
      while (*hl)			/* for each host */
      {
	char *ch = hl;

	hl = gettoken (ch, NULL);
	_ircd_start_uplink (c, ch);	/* create a connection thread */
      }
      /* we do ignoring too long hosts list too! */
    }
    Unset_Iface();
  }
  else					/* no autoconnects found */
    //TODO: set some timer for recheck autoconnects if none found?
#if IRCD_MULTICONNECT
    _ircd_uplinks = -1;			/* just disable checking */
#else
    _ircd_uplink = (peer_priv *)1;
#endif
  tmp->ift = I_DIED;
}


/* -- ircd register stage bindings ----------------------------------------
   sets ->lcnick if neither ->nick nor ->fname is set yet */
BINDING_TYPE_ircd_register_cmd (ircd_pass);
static int ircd_pass (INTERFACE *srv, struct peer_t *peer, int argc, const char **argv)
{ /* args: <password> [<version> <flags> [<options>]] */
  CLIENT *cl = ((peer_priv *)peer->iface->data)->link->cl; /* it's really peer->link->cl */

  if (argc == 0)
    return ircd_do_unumeric (cl, ERR_NEEDMOREPARAMS, cl, 0, NULL);
  if (cl->nick[0] || cl->fname[0])	/* got either NICK or USER already */
    return ircd_do_unumeric (cl, ERR_ALREADYREGISTRED, cl, 0, NULL);
  if (cl->lcnick[0])			/* second PASS command */
    Add_Request (I_LOG, "*", F_WARN, "duplicate PASS attempt from %s@%s",
		 cl->user, cl->host);
  strfcpy (cl->lcnick, argv[0], sizeof(cl->lcnick));
  switch (argc)				/* store additional serverlink params */
  {
    case 1:
      cl->away[0] = '\0';
      break;
    case 2:
      strfcpy (cl->away, argv[1], sizeof(cl->away));
      break;
    case 3:
      snprintf (cl->away, sizeof(cl->away), "%s %s", argv[1], argv[2]);
      break;
    default: /* 4 */
      snprintf (cl->away, sizeof(cl->away), "%s %s %s", argv[1], argv[2], argv[3]);
  }
  return 1;
}

BINDING_TYPE_ircd_register_cmd(ircd_quit_rb);
static int ircd_quit_rb(INTERFACE *srv, struct peer_t *peer, int argc, const char **argv)
{ /* args: [<Quit Message>] */
  CLIENT *cl = ((struct peer_priv *)peer->iface->data)->link->cl;
  const char *msg;

  if (argc > 0)
    msg = argv[0];
  else
    msg = "I Quit";
  _ircd_peer_kill (cl->via, msg);
  return 1;
}

static char _ircd_modesstring[128]; /* should be enough for two A-Za-z */

/* adds it into lists, sets fields, sends notify to all servers */
static int _ircd_got_local_user (CLIENT *cl)
{
  struct binding_t *b;
  userflag uf;
  char mb[MB_LEN_MAX*NICKLEN+NAMEMAX+2]; /* it should be enough for umode */

  if (cl->via->p.uf & U_DENY)
  {
    ircd_do_unumeric (cl, ERR_YOUREBANNEDCREEP, cl, 0, NULL);
    _ircd_peer_kill (cl->via, "Bye!");
    return 1;
  }
  unistrlower (cl->lcnick, cl->nick, sizeof(cl->lcnick));
  if (Insert_Key (&Ircd->clients, cl->lcnick, cl, 1) < 0)
    ERROR("ircd:_ircd_got_local_user: tree error on %s", cl->lcnick);
    /* FIXME: isn't it fatal? */
  snprintf (mb, sizeof(mb), "%s@%s", cl->lcnick, Ircd->iface->name);
  Rename_Iface (cl->via->p.iface, mb);	/* rename iface to nick@net */
  cl->away[0] = 0;
  cl->via->i.nvited = cl->c.hannels = NULL;
  /*
  ** prefixes used:
  **      none    I line with ident
  **      ^       I line with OTHER type ident
  **      ~       I line, no ident
  **      +       i line with ident
  **      =       i line with OTHER type ident
  **      -       i line, no ident
  **
  ** if no ident then cl->user[0] is ' '
  ** if ident type is OTHER it may be '=' (see core/direct.c if implemented)
  */
  if (cl->via->p.uf & U_DEOP) {
    cl->umode |= A_RESTRICTED;
    if (cl->user[0] == ' ')
      cl->user[0] = '-';
    else if (cl->user[0] != '=') {
      memmove(cl->user, &cl->user[1], sizeof(cl->user)-2);
      cl->user[0] = '+';
    }
  } else {
    if (cl->user[0] == ' ')
      cl->user[0] = '~';
    else if (cl->user[0] == '=')
      cl->user[0] = '^';
  }
  ircd_make_umode (mb, cl->umode, sizeof(mb));
  ircd_sendto_servers_all (Ircd, NULL, ":%s NICK %s 1 %s %s 0 +%s :%s", MY_NAME,
			   cl->nick, cl->user, cl->host, mb, cl->fname);
#ifdef USE_SERVICES
  //TODO: notify services about new user
#endif
  ircd_do_unumeric (cl, RPL_WELCOME, cl, 0, NULL);
  ircd_do_unumeric (cl, RPL_YOURHOST, &ME, 0, NULL);
  ircd_do_unumeric (cl, RPL_CREATED, &ME, 0, COMPILETIME);
  ircd_do_unumeric (cl, RPL_MYINFO, &ME, 0, _ircd_modesstring);
  b = NULL;
  uf = Get_Clientflags (cl->x.class->name, Ircd->iface->name);
  while ((b = Check_Bindtable (BTIrcdGotClient, cl->nick, uf, U_ANYCH, b)))
    if (!b->name)			/* do lusers and custom messages */
      b->func (Ircd->iface, &cl->via->p);
#if IRCD_USES_ICONV
  ircd_do_unumeric (cl, RPL_CODEPAGE, cl, 0,
		    Conversion_Charset (cl->via->p.iface->conv));
#endif
  if (cl->umode & A_RESTRICTED)
    ircd_do_unumeric (cl, ERR_RESTRICTED, cl, 0, NULL);
  cl->via->p.state = P_TALK;
  return 1;
}

/* sets params; if ->nick already set then register new user */
BINDING_TYPE_ircd_register_cmd (ircd_user);
static int ircd_user (INTERFACE *srv, struct peer_t *peer, int argc, const char **argv)
{ /* args: <user> <mode> <unused> <realname> */
  CLIENT *cl = ((peer_priv *)peer->iface->data)->link->cl; /* it's really peer->link->cl */
  int umode;

  if (argc < 4)
    return ircd_do_unumeric (cl, ERR_NEEDMOREPARAMS, cl, 0, NULL);
  if (cl->fname[0])			/* got USER already */
    return ircd_do_unumeric (cl, ERR_ALREADYREGISTRED, cl, 0, NULL);
  if (!cl->user[0])			/* got no ident */
  {
    cl->user[0] = ' ';			/* marker */
    strfcpy (&cl->user[1], argv[0], sizeof(cl->user) - 1);
  }
  umode = atoi (argv[1]);
  if (umode & 4)
    cl->umode = A_WALLOP;
#ifndef DEFAULT_INVISIBLE
  if (umode & 8)
#endif
    cl->umode |= A_INVISIBLE;
  if (*argv[3])
  {
    strfcpy (cl->fname, argv[3], sizeof(cl->fname));
    umode = unistrcut (cl->fname, sizeof(cl->fname), REALNAMELEN);
    cl->fname[umode] = '\0';
  }
  else
    strcpy (cl->fname, " ");
  if (!cl->nick[0])
    return 1;
  return _ircd_got_local_user (cl);
}

/* validate chars and length and if ok then copy into d[s] string */
static int _ircd_validate_nickname (char *d, const char *name, size_t s)
{
  size_t sz, sp;
  ssize_t sc;
  wchar_t wc;
  mbstate_t ps;
  const char *c;
#if IRCD_STRICT_NAMES
  char *os, *ds;
  struct conversion_t *conv;
  char namebuf[NICKLEN+1];
#endif

  dprint(4, "ircd:ircd.c:_ircd_validate_nickname: %s", name);
  if (!strcasecmp (name, "anonymous"))	/* RFC2811 */
    return 0;
  sz = safe_strlen (name);
  if (sz == 0)
    return 0;
#if IRCD_STRICT_NAMES
  /* check if name is compatible with CHARSET_8BIT */
  conv = Get_Conversion (CHARSET_8BIT);
  os = namebuf;
  sp = Undo_Conversion (conv, &os, sizeof(namebuf), name, sz);
  if (sp > NICKLEN)			/* too long nickname */
  {
    Free_Conversion (conv);
    return 0;
  }
  ds = d;
  sp = Do_Conversion (conv, &ds, s, os, sp);
  if (sp == s)				/* output buffer exhausted */
  {
    if (d) *d = '\0';
    Free_Conversion (conv);
    return 0;
  }
  if (ds != name)
  {
    ds[sp] = 0;
    if (sp != sz || strcmp (ds, name))	/* we lost something in conversion */
    {
      *ds = '\0';
      Free_Conversion (conv);
      return 0;
    }
    *d = '\0'; /* reset it for validation below */
  }
  Free_Conversion (conv);
#endif
  memset(&ps, 0, sizeof(mbstate_t));	/* reset state for mbrtowc */
  /* validate if name consists of alphanumeric chars (RFC2813) */
  if (strchr ("[]\\`_^{|}~", *name))	/* allowed non-alphanum chars */
  {
    sz--;
    c = name + 1;
  }
  else
  {
    sc = mbrtowc (&wc, name, sz, &ps);
    if (sc <= 0 || !iswalpha (wc))	/* first char must be letter */
      return 0;
    sz -= sc;
    c = name + sc;
  }
  for (sp = 1; *c; sp++)
  {
    if (sp > NICKLEN)			/* nick is too long */
      return 0;
    if (strchr ("[]\\`_^{|}~-", *c))	/* allowed non-alphanum chars */
    {
      c++;
      sz--;
      continue;
    }
    sc = mbrtowc (&wc, c, sz, &ps);
    if (sc <= 0)			/* invalid sequence */
      return 0;
    if (!iswalnum (wc))			/* invalid character */
      return 0;
    c += sc;				/* go to next char */
    sz -= sc;
  }
  strfcpy (d, name, s);
  return 1;
}

static int _ircd_check_nick_cmd (CLIENT *cl, char *b, const char *nick,
				 size_t bs)
{
  CLIENT *cl2;

  if (!_ircd_validate_nickname (b, nick, bs))
  {
    ircd_do_unumeric (cl, ERR_ERRONEUSNICKNAME, cl, 0, NULL);
    return 0;
  }
  cl2 = _ircd_find_client (b);
  if (cl2)	/* check if that name is in use/on hold */
  {
    if (!cl2->hold_upto)
    {
      ircd_do_unumeric (cl, ERR_NICKNAMEINUSE, cl, 0, NULL);
      b[0] = 0;
      return 0;
    }
    _ircd_try_drop_collision(&cl2);
    if (cl2 != NULL)
    {
      ircd_do_unumeric (cl, ERR_UNAVAILRESOURCE, cl, 0, NULL);
      b[0] = 0;
      return 0;
    }
  }
  return 1;
}

/* sets nick; if ->fname already set then register new user */
BINDING_TYPE_ircd_register_cmd (ircd_nick_rb);
static int ircd_nick_rb (INTERFACE *srv, struct peer_t *peer, int argc, const char **argv)
{ /* args: <nick> */
  CLIENT *cl = ((peer_priv *)peer->iface->data)->link->cl; /* it's really peer->link->cl */

  if (argc == 0)
    return ircd_do_unumeric (cl, ERR_NONICKNAMEGIVEN, cl, 0, NULL);
  if (!_ircd_check_nick_cmd (cl, cl->nick, argv[0], sizeof(cl->nick)))
    return 1;
  if (!cl->fname[0])
    return 1;
  return _ircd_got_local_user (cl);
}

BINDING_TYPE_ircd_client_cmd(ircd_nick_cb);
static int ircd_nick_cb(INTERFACE *srv, struct peer_t *peer, char *lcnick, char *user,
			char *host, int argc, const char **argv)
{ /* args: <new nick> */
  CLIENT *cl = ((peer_priv *)peer->iface->data)->link->cl; /* it's really peer->link->cl */
  char checknick[MB_LEN_MAX*NICKLEN+NAMEMAX+2];

  if (argc == 0)
    return ircd_do_unumeric (cl, ERR_NONICKNAMEGIVEN, cl, 0, NULL);
  if (!_ircd_check_nick_cmd (cl, checknick, argv[0], sizeof(checknick)))
    return 1;
#ifdef USE_SERVICES
  //TODO: forbidden for services!
#endif
  if (cl->umode & A_RESTRICTED)
    return ircd_do_unumeric (cl, ERR_RESTRICTED, cl, 0, NULL);
  _ircd_do_nickchange(cl, NULL, 0, checknick);
  snprintf (checknick, sizeof(checknick), "%s@%s", cl->lcnick, Ircd->iface->name);
  Rename_Iface (peer->iface, checknick); /* rename iface to newnick@net */
  return 1;
}

#if IRCD_MULTICONNECT
/* recursive traverse into tree sending every server we found */
static inline void _ircd_burst_servers_new (CLIENT *cl, const char *sn, LINK *l)
{
  dprint(4, "ircd:ircd.c:_ircd_burst_servers_new: %s to %s", sn, cl->nick);
  while (l)
  {
    if (CLIENT_IS_SERVER (l->cl) && l->cl != cl) /* don't send it back sure */
    {
      register char *cmd = "SERVER";

      if (l->cl->umode & A_MULTI)	/* new server type */
	cmd = "ISERVER";		/* protocol extension */
      New_Request (cl->via->p.iface, 0, ":%s %s %s %hu %hu :%s", sn, cmd,
		   l->cl->nick, l->cl->hops + 1, l->cl->x.token, l->cl->fname);
      _ircd_burst_servers_new (cl, l->cl->nick, l->cl->c.lients); /* recursion */
    }
    l = l->prev;
  }
}
#endif

/* traverse tree and find link it's connected via */
static LINK *_ircd_burst_find (CLIENT *cl, LINK *via, unsigned short hops)
{
  register LINK *l = via->cl->c.lients, *l2;

  hops--; /* one hop is the list itself */
  while (l)
    if (l->cl == cl)
      return l;
    else if (hops > 0 && CLIENT_IS_SERVER (l->cl) &&
	     (l2 = _ircd_burst_find (cl, l, hops)) != NULL)
      return l2;
    else
      l = l->prev;
  return NULL;
}

/* send every server we know finding where it is */
static inline void _ircd_burst_servers_old (INTERFACE *cl)
{
  register LINK *l;
  unsigned short int i;

  dprint(4, "ircd:ircd.c:_ircd_burst_servers_old: to %s", cl->name);
  for (i = 1; i < Ircd->s; i++)
  {
    if (Ircd->token[i] == NULL)		/* token was freed */
      continue;
    l = Ircd->token[i]->via->link;	/* the shortest path to server */
    if (!CLIENT_IS_LOCAL(Ircd->token[i]))
      l = _ircd_burst_find (Ircd->token[i], l, Ircd->token[i]->hops - 1);
    if (l == NULL)			/* OOPS! our tree is broken! */
      ERROR ("ircd:_ircd_burst_servers_old: could not find server %s",
	     Ircd->token[i]->lcnick);
    else
      New_Request (cl, 0, ":%s SERVER %s %hu %hu :%s", l->where->nick,
		   l->cl->nick, l->cl->hops + 1, l->cl->x.token, l->cl->fname);
  }
}

static inline void _ircd_burst_clients (INTERFACE *cl, unsigned short t,
					LINK *s, char *umode/* 16 bytes */)
{
  dprint(4, "ircd:ircd.c:_ircd_burst_clients: %s to %s", s->cl->nick, cl->name);
  while (s)
  {
    if (CLIENT_IS_SERVER (s->cl))	/* recursion */
      _ircd_burst_clients (cl, s->cl->x.token, s->cl->c.lients, umode);
    else if (CLIENT_IS_SERVICE (s->cl))
      /* <servicename> <servertoken> <distribution> <type> <hopcount> <info> */
      New_Request (cl, 0, "SERVICE %s %hu %s 0 %hu :%s", s->cl->nick, t,
		   s->cl->away, s->cl->hops, s->cl->fname);
    else
      /* <nickname> <hopcount> <username> <host> <servertoken> <umode> <realname> */
      New_Request (cl, 0, "NICK %s %hu %s %s %hu +%s :%s", s->cl->nick,
		   s->cl->hops, s->cl->user, s->cl->host, t,
		   ircd_make_umode (umode, s->cl->umode, 16), s->cl->fname);
    s = s->prev;
  }
}

/* sends everything to fresh connected server */
static void _ircd_connection_burst (CLIENT *cl)
{
  char umode[16];			/* it should be enough in any case */

#if IRCD_MULTICONNECT
  if (cl->umode & A_MULTI)
    _ircd_burst_servers_new (cl, MY_NAME, Ircd->servers);
  else
    /* never send duplicate servers to old-style connections! */
#endif
    _ircd_burst_servers_old (cl->via->p.iface);
  _ircd_burst_clients (cl->via->p.iface, 0, Ircd->servers, umode);
  ircd_burst_channels (cl->via->p.iface, Ircd->channels);
}

/* trying to register new local server link... */
BINDING_TYPE_ircd_register_cmd (ircd_server_rb);
static int ircd_server_rb (INTERFACE *srv, struct peer_t *peer, int argc, const char **argv)
{ /* args: <servername> <hopcount> <token/info(RFC1459)> <info(RFC2813)> */
  CLIENT *cl = ((peer_priv *)peer->iface->data)->link->cl; /* it's really peer->link->cl */
  CLIENT *clt;
  struct clrec_t *u;
  char *cc, *ourpass, *approved;
  char *ftbf;				/* those to be first */
  long token = 0;
  char buff[MB_LEN_MAX*MESSAGEMAX-1];
  register char *c;

  if (cl->nick[0] || cl->fname[0])	/* got either NICK or USER already */
    return ircd_do_unumeric (cl, ERR_ALREADYREGISTRED, cl, 0, NULL);
  if (argc < 3 || atoi (argv[1]) != 1)	/* strict to RFC 1459 / RFC 2813 */
  {
    _ircd_peer_kill (cl->via, "no servername");
    return 1;				/* no default reason here :) */
  }
  if (argc < 4 || (token = strtol (argv[2], &cc, 10)) < 0 || *cc != ' ')
  {
    strfcpy (cl->fname, argv[2], sizeof(cl->fname));
    token = -1L;
  }
  else
    strfcpy (cl->fname, argv[3], sizeof(cl->fname));
  u = Lock_Clientrecord (argv[0]);	/* check if I know that server */
  if (!u)
  {
    _ircd_peer_kill (cl->via, "no c/N lines for you");
    return 1;
  }
  if (!((peer->uf = Get_Flags (u, srv->name)) & U_ACCESS))
  {
    Unlock_Clientrecord (u);		/* it's person not server */
    _ircd_peer_kill (cl->via, "no c/N lines for you");
    return 1;
  }
  /* check if password matches */
  c = Get_Field (u, "passwd", NULL);
  if (c && Check_Passwd (cl->lcnick, c))
  {
    Unlock_Clientrecord (u);
    _ircd_peer_kill (cl->via, "bad password");
    return 1;
  }
  if (peer->state == P_INITIAL) /* if it's incoming then check it to match */
  {
    INTERFACE *tmp;
    const char *ipname;
    lid_t lid;

    /* check if host matches */
    lid = Get_LID (u);
    Unlock_Clientrecord (u);
    _ircd_sublist_buffer = buff;
    tmp = Add_Iface (I_TEMP, NULL, NULL, &_ircd_sublist_receiver, NULL);
    if (Get_Hostlist (tmp, lid) == 0) /* that's weird, no hosts even found */
    {
      tmp->ift = I_DIED;
      _ircd_peer_kill (cl->via, "no c/N lines for you");
      return 1;
    }
    ipname = SocketIP(peer->socket);
    Set_Iface (tmp);
    while (Get_Request())		/* at least once */
    {
      c = _ircd_sublist_buffer;
      do			/* parse each [ident[:pass]@]host[/port[%fl]] */
      {
	register char *ccc;
	char *chost, *ident;

	chost = c;			/* preset chost if no ident[:pass] */
	cc = gettoken (c, &ident);	/* preset ident if no ident[:pass] */
	if ((ccc = strchr (chost, '@'))) /* ok, we have ident[:pass] */
	{
	  ident = chost;		/* set it to ident */
	  chost = ccc;			/* set it to found '@' */
	  *chost++ = 0;			/* split ident and host */
	  if ((ccc = strchr (chost, '/'))) /* cut off port part */
	    *ccc = 0;
	}
	if ((ourpass = strrchr (ident, ':'))) /* split off password part */
	  *ourpass++ = 0;
	if ((!*ident || match (ident, cl->user) >= 0) && /* user part matches */
	    (!strcasecmp (chost, cl->host) || /* host part matches host */
	     !strcasecmp (chost, ipname))) /* or host part matches IP */
	  break;			/* it's matched, done */
	c = cc;				/* else try next host */
      } while (*c);
      if (*c)
	break;				/* see break above */
    }
    Unset_Iface();
    tmp->ift = I_DIED;			/* done with it */
    if (!*c)				/* found no matches! */
    {
      _ircd_peer_kill (cl->via, "no c/N lines for you");
      return 1;
    }
  }
  else
  {
    Unlock_Clientrecord (u);
    if (_ircd_uplink) /* there is autoconnected RFC2813 server already */
    {
      _ircd_peer_kill (cl->via, "extra autoconnect, bye, sorry");
      return 1;
    }
  }
  /* we used password we got so can use lcnick as it should be */
  unistrlower (cl->lcnick, argv[0], sizeof(cl->lcnick));
  clt = _ircd_find_client_lc (cl->lcnick);
#if IRCD_MULTICONNECT
  if (clt && !clt->hold_upto && (!CLIENT_IS_SERVER(clt) || CLIENT_IS_LOCAL(clt)))
#else
  if (clt)				/* it's already in our network */
#endif
  {
    // TODO: try to resolv that somehow?
    _ircd_peer_kill (cl->via, "duplicate connection not allowed");
    return 1;
  }
  cc = gettoken (cl->away, NULL);	/* split off server version string */
  if (strncmp (cl->away, "021", 3))	/* want 2.10+ version, RFC2813 */
  {
    _ircd_peer_kill (cl->via, "old version");
    return 1;
  }
  if (*cc)				/* got flags string */
  {
    char *cflags = gettoken (cc, NULL);

    if (*cc != '|' && strncmp (cc, "IRC|", 4)) /* RFC2813 */
    {
      _ircd_peer_kill (cl->via, "unknown implementation");
      return 1;
    }
    cc = cflags;			/* skip flags string */
  }
  ftbf = approved = cc;
  if (*cc)				/* re-sort options string */
  {
    char *ccur = cc;
    register char ch;

    while ((ch = *ccur))
    {
      if (strchr (_ircd_flags_first, ch)) /* should be first */
      {
	*ccur = *cc;			/* swap them */
	*cc++ = ch;
      }
      ccur++;				/* go to next char */
    }
  }
  //TODO: check if token is too big!
  cl->via->t = token + 1;		/* no tokens there yet */
  cl->via->i.token = safe_calloc (cl->via->t, sizeof(CLIENT *));
  if (token >= 0)
    cl->via->i.token[token] = cl;
  /* if it's incoming connect then check every option flag we got
     for appliance to connection chain and answer accepted flags back
     don't using interface but connchain only to avoid message queue
     connchain should be ready at this point to get one message up to
     MB_LEN_MAX*MESSAGEMAX-2 so we will send both PASS and SERVER at once */
  if (peer->state == P_INITIAL)
  {
    size_t sz;

#if IRCD_USES_ICONV
    Free_Conversion (peer->iface->conv); /* reset charset to default */
    peer->iface->conv = Get_Conversion (CHARSET_8BIT);
#endif
    if (*ftbf)				/* have we got them at all? */
    {
      char *ccur = ftbf;

      while (ccur != cc)		/* testing pre-'x' filters */
	if (Connchain_Check (peer, *ccur) > 0) /* option is available */
	  *approved++ = *ccur++;	/* add char */
	else
	  ccur++;			/* skip char */
      cc = approved;			/* we might disapprove filter */
      while (*ccur)			/* testing post-'x' filters */
	if (strchr (_ircd_flags_post, *ccur) && /* it's in list of allowed */
	    Connchain_Check (peer, *ccur) > 0) /* and it's available */
	  *approved++ = *ccur++;	/* add char */
	else
	  ccur++;			/* skip char */
      *approved = 0;			/* terminate it in any case */
    }
    sz = snprintf (buff, sizeof(buff),
		   "PASS %s %s IRC|" PACKAGE " %s\r\n"
		   "SERVER %s 1 0 :%s",	/* own token is always 0 */
		   (ourpass && *ourpass) ? ourpass : "*", _ircd_version_string,
		   ftbf, MY_NAME, _ircd_description_string);
    if (sz >= sizeof(buff))
      sz = sizeof(buff) - 1;		/* recover from snprintf */
    if (Peer_Put (peer, buff, &sz) <= 0) /* put it into connchain buffers */
    {
      _ircd_peer_kill (cl->via, "handshake error");
      return 1;
    }
  }
  if ((peer->uf & U_AUTO) &&		/* we connected to uplink */
      !_ircd_uplink)			/* and there is no uplink yet */
    _ircd_uplink = cl->via;		/* so this may be our uplink now */
  if (cc != ftbf)			/* ok, we can redo connchain now */
  {
    char *ccur = ftbf;

    while (ccur != cc)
      if (Connchain_Grow (peer, *ccur) <= 0)
      {
	snprintf (buff, sizeof(buff), "server option unavailable: %c", *ccur);
	_ircd_peer_kill (cl->via, buff);
	return 1;
      }
      else
	ccur++;
    Connchain_Grow (peer, 'x');		/* some filter might kill it */
  }
  while (*cc)
  {
    if (Connchain_Grow (peer, *cc) <= 0)
    {
      snprintf (buff, sizeof(buff), "server option unavailable: %c", *cc);
      _ircd_peer_kill (cl->via, buff);
      return 1;
    }
    else
      cc++;
  }
#ifdef IRCD_P_FLAG
  if (!(cl->umode & A_ISON))		/* should be received 'P' flag */
  {
    _ircd_peer_kill (cl->via, "option flag P is required");
    return 1;
  }
#endif
  _ircd_class_out (cl->via->link); /* it's still !A_SERVER */
#if IRCD_MULTICONNECT
  /* check if it's another connect of already known server */
  if (clt) /* see above! */
  {
    cl->via->link->cl = clt;
    clt->alt = clt->via;
    clt->via = cl->via;
    clt->hops = 1;
    strfcpy (clt->fname, cl->fname, sizeof(clt->fname)); /* rewrite! */
    pthread_mutex_lock (&IrcdLock);
    free_CLIENT (cl);
    pthread_mutex_unlock (&IrcdLock);
    cl = clt; /* replace CLIENT struct and skip token! */
  }
  else
  {
    cl->last_id[0] = cl->last_id[2] = -1; /* no ids received yet */
#endif
    strfcpy (cl->nick, argv[0], sizeof(cl->nick)); /* all done, fill data */
    cl->x.token = _ircd_alloc_token();	/* right after class out! */ //!
#if IRCD_MULTICONNECT
  }
#endif
  cl->via->link->prev = Ircd->servers;	/* add it to local lists */
  Ircd->servers = cl->via->link;
#if IRCD_MULTICONNECT
  cl->via->acks = NULL;			/* no acks from fresh connect */
  if (cl->alt == NULL)			/* it's first instance */
#endif
    Insert_Key (&Ircd->clients, cl->lcnick, cl, 1); //!
  cl->umode |= A_SERVER; //!
  cl->via->corrections = 0;		/* reset correctable errors */
  peer->state = P_TALK;			/* we registered it */
  snprintf (buff, sizeof(buff), "%s@%s", cl->lcnick, Ircd->iface->name);
  Rename_Iface (peer->iface, buff);	/* rename iface to server.name@net */
  peer->iface->ift |= I_CLIENT;		/* it might be not set yet */
#if IRCD_MULTICONNECT
  /* propagate new server over network now */
  if (cl->umode & A_MULTI)		/* it's updated already */
    ircd_sendto_servers_new (Ircd, cl->via, "ISERVER %s 2 %hu :%s", argv[0],
			     cl->x.token, cl->fname); //!
  else
    ircd_sendto_servers_new (Ircd, cl->via, "SERVER %s 2 %hu :%s", argv[0],
			     cl->x.token, cl->fname); //!
#endif
  ircd_sendto_servers_old (Ircd, cl->via, "SERVER %s 2 %hu :%s", argv[0],
			   cl->x.token, cl->fname); //!
  Add_Request(I_LOG, "*", F_SERV, "Received SERVER %s from %s (0 %s)", argv[0],
	      cl->lcnick, cl->fname);
#if IRCD_MULTICONNECT
  if (cl->alt != NULL) /* it's not first instance */
    _ircd_recalculate_hops(); /* we got better path so recalculate hops map */
#endif
  _ircd_connection_burst (cl);		/* tell it everything I know */
  //TODO: BTIrcdGotServer
  return 1;
}


/* "ircd-server-cmd" bindings */
static inline int _ircd_server_duplicate_link (peer_priv *old, peer_priv *this,
					const char *sender, const char *name)
{
  /* server announces another instance of RFC2813 server */
  ERROR ("Server %s introduced already known server %s, dropping link", sender,
	 name);
#ifdef IRCD_SQUIT_YOUNGEST
  /* kill youngest link */
  if (old->started > this->started)
    ircd_do_squit (old->link, NULL, "Introduced server already exists");
  else
#endif
  ircd_do_squit (this->link, NULL, "Introduced server already exists");
  return 1;
}

static inline int _ircd_remote_server_is_allowed (const char *net,
						const char *name, peer_priv *pp)
{
  register userflag uf = Get_Clientflags (name, net);

  if (!uf)				/* not registered */
    return 1;
  if (!(uf & U_ACCESS))			/* is known as something else */
  {
    ERROR ("ircd: %s introduced by %s is not a server", name, pp->p.dname);
    ircd_recover_done (pp, "Bogus server name");
    return 0;
  }
  if (uf & U_DENY)
  {
    ERROR ("ircd: got quarantined server %s from %s", name, pp->p.dname);
    ircd_do_squit (pp->link, NULL, "Q-Lined Server");
    return 0;
  }
  return 1;
}

static inline int _ircd_is_server_name (const char *lcc)
{
  if (!strchr (lcc, '.'))		/* it should have at least one dot */
    return 0;
  while (*lcc)
    switch (*lcc)
    {
      case 'a': case 'b': case 'c': case 'd': case 'e': case 'f': case 'g':
      case 'h': case 'i': case 'j': case 'k': case 'l': case 'm': case 'n':
      case 'o': case 'p': case 'q': case 'r': case 's': case 't': case 'u':
      case 'v': case 'w': case 'x': case 'y': case 'z': case '0': case '1':
      case '2': case '3': case '4': case '5': case '6': case '7': case '8':
      case '9': case '.': case '-':
	break;
      default:
	return 0;
    }
  return 1;
}

static char *_ircd_validate_hub (peer_priv *pp, const char *nhn)
{
  struct clrec_t *u = Lock_Clientrecord (pp->p.dname);
  char *hub;
  size_t ptr;
  char hm[HOSTLEN+2];

  dprint(4, "ircd:ircd.c:_ircd_validate_hub: %s on %s", pp->p.dname, nhn);
  if (!u)
  {
    ERROR ("ircd: clientrecord on %s seems gone, drop link", pp->p.dname);
    return ("Client record error");
  }
  hub = Get_Field (u, "hub", NULL);
  hm[0] = 0;
  if (hub)
  {
    while (*hub)
    {
      for (ptr = 0; *hub && *hub != ' ' && ptr < sizeof(hm)-1; hub++)
	hm[ptr++] = *hub;
      hm[ptr] = 0;
      if (hm[0] == '!')
      {
	if (simple_match (&hm[1], nhn) >= 0)
	{
	  Unlock_Clientrecord (u);
	  return ("Leaf Only");		/* that server cannot be behind peer */
	}
      }
      else if (simple_match (hm, nhn) >= 0)
	break;				/* it matched */
      hm[0] = 0;
      while (*hub == ' ') hub++;
    }
  }
  Unlock_Clientrecord (u);
  if (!hm[0])				/* peer cannot be hub for introduced */
    return ("Too many servers");
  return NULL;
}

static CLIENT *_ircd_got_new_remote_server (peer_priv *pp, CLIENT *src,
					    long ntok, const char *nick,
					    const char *lcn, const char *info)
{
  CLIENT *cl;

  dprint(3, "ircd:ircd.c:_ircd_got_new_remote_server: %s via %s", nick,
	 pp->p.dname);
  cl = alloc_CLIENT();
  if (ntok >= 0)
  {
    if (ntok >= pp->t)
    {
      size_t add = ntok - pp->t + 1;

      if (add < TOKEN_ALLOC_SIZE)
	add = TOKEN_ALLOC_SIZE;
      safe_realloc ((void **)pp->i.token, (pp->t + add) * sizeof(CLIENT *));
      while (add--)
	pp->i.token[pp->t++] = NULL;
    }
    if (pp->i.token[ntok])
    {
      ERROR ("ircd: got token %ld from %s which is already in use", ntok,
	     pp->p.dname);
      if (!ircd_recover_done (pp, "Invalid token"))
      {
	free_CLIENT (cl);
	return NULL;
      }
    }
    else
      pp->i.token[ntok] = cl;
  }
  /* else notokenized server may have no clients, ouch */
  cl->pcl = NULL;
  cl->x.token = _ircd_alloc_token();
  Ircd->token[cl->x.token] = cl;
#if IRCD_MULTICONNECT
  cl->last_id[0] = cl->last_id[2] = -1; /* no ids received yet */
  cl->on_ack = 0;
#endif
  cl->c.lients = NULL;
  cl->umode = A_SERVER;
  cl->cs = cl;
  cl->hold_upto = 0;
  cl->hops = src->hops + 1;		/* ignore introduced number */
  cl->away[0] = 0;
  strfcpy (cl->nick, nick, sizeof(cl->nick));
  strfcpy (cl->lcnick, lcn, sizeof(cl->lcnick));
  strfcpy (cl->fname, info, sizeof(cl->fname));
  cl->user[0] = 0;
  cl->host[0] = 0;
  if (Insert_Key (&Ircd->clients, cl->lcnick, cl, 1) < 0)
    ERROR("ircd:_ircd_got_new_remote_server: tree error on adding %s",
	  cl->lcnick); /* TODO: isn't it fatal? */
  return cl;
}

#undef __TRANSIT__
#define __TRANSIT__ __CHECK_TRANSIT__(token)
BINDING_TYPE_ircd_server_cmd(ircd_server_sb);
static int ircd_server_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			  const char *sender, const char *lcsender, char *cmd,
			  int argc, const char **argv)
{ /* args: <servername> <hopcount> <token/info(RFC1459)> <info(RFC2813)> */
  peer_priv *pp = peer->iface->data; /* it's peer really */
  CLIENT *src, *cl;
  long ntok;
  const char *info;
  register char *c;
  LINK *link;
  char nhn[HOSTLEN+1];

  if (argc < 3)
    return 0;
  src = Ircd->token[token];
  if (_ircd_find_client_lc (lcsender) != src)
  {
    ERROR ("ircd: not permitted SERVER from %s via %s", sender, peer->dname);
    ircd_do_squit (pp->link, pp, "bogus SERVER sender");
    return 1;
  }
  cl = _ircd_find_client (argv[0]);
#if IRCD_MULTICONNECT
  if (cl && CLIENT_IS_SERVER(cl) && src->alt) /* it may be backup introduce */
  {
    register LINK *tst = src->c.lients;

    while (tst && tst->cl != cl)
      break;
    if (tst)
    {
      dprint (3, "%s: backup command SERVER %s", peer->dname, argv[0]);
      return 1;
    }
  }
#endif
  if (cl)
    return _ircd_server_duplicate_link (cl->via, pp, lcsender, argv[0]);
  /* check parameters */
  if (!_ircd_remote_server_is_allowed (srv->name, argv[0], pp))
    return 1;
  unistrlower (nhn, argv[0], sizeof(nhn));
  if (!_ircd_is_server_name (nhn))
  {
    ERROR ("ircd: %s introduced by %s is not hostname", nhn, peer->dname);
    return ircd_recover_done (pp, "Bogus server name");
  }
  if (argc > 3)
  {
    if ((ntok = atoi (argv[2])) < 0) //TODO: check if token is too big!
    {
      ERROR ("Server %s sent us invalid token %ld", peer->dname, ntok);
      if (!ircd_recover_done (pp, "Invalid token"))
	return 1;
      //TODO: drop link?
    }
    info = argv[3];
  }
  else
  {
    ntok = -1L;
    info = argv[2];
  }
  if ((c = _ircd_validate_hub (pp, nhn)))
  {
    ircd_do_squit (pp->link, NULL, c);
    return 1;
  }
  /* ok, we got and checked everything, create data and announce */
  cl = _ircd_got_new_remote_server (pp, src, ntok, argv[0], nhn, info);
  if (!cl)
    return 1; /* peer was squited */
  cl->via = src->via;
#if IRCD_MULTICONNECT
  cl->alt = src->alt;
#endif
  link = alloc_LINK();
  link->where = src;
  link->cl = cl;
  link->prev = src->c.lients;
  link->flags = 0;
  src->c.lients = link;
  ircd_sendto_servers_all (Ircd, pp, ":%s SERVER %s %hd %hd :%s", sender,
			   argv[0], cl->hops, cl->x.token, info);
  return 1;
}

#if IRCD_MULTICONNECT
BINDING_TYPE_ircd_server_cmd(ircd_iserver);
static int ircd_iserver(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			const char *sender, const char *lcsender, char *cmd,
			int argc, const char **argv)
{ /* args: <servername> <hopcount> <token> <info> */
  peer_priv *pp = peer->iface->data; /* it's peer really */
  CLIENT *src, *cl;
  long ntok;
  LINK *link;
  register char *c;
  char nhn[HOSTLEN+1];

  if (argc < 3)
    return 0;
  src = Ircd->token[token];
  if (_ircd_find_client_lc (lcsender) != src)
  {
    ERROR ("ircd: not permitted SERVER from %s via %s", sender, peer->dname);
    ircd_do_squit (pp->link, pp, "bogus SERVER sender");
    return 1;
  }
  cl = _ircd_find_client (argv[0]);
  if (cl)				/* it may be backup introduce */
  {
    register LINK *tst;

    if (!CLIENT_IS_SERVER(cl))
    {
      ERROR ("ircd: server/nick collision %s from %s", argv[0], peer->dname);
      return ircd_recover_done (pp, "Bogus server name");
    }
    tst = src->c.lients;
    while (tst && tst->cl != cl)
      break;
    if (tst)
    {
      dprint (3, "%s: backup command ISERVER %s", peer->dname, argv[0]);
      return 1;
    }
  }
  if (cl && !(cl->umode & A_MULTI)) /* ouch, it multiconnected via old server */
    return _ircd_server_duplicate_link (cl->via, pp, lcsender, argv[0]);
  /* check parameters */
  if (!cl && !_ircd_remote_server_is_allowed (srv->name, argv[0], pp))
    return 1;
  unistrlower (nhn, argv[0], sizeof(nhn));
  if (!cl && !_ircd_is_server_name (nhn))
  {
    ERROR ("ircd: %s introduced by %s is not hostname", nhn, peer->dname);
    return ircd_recover_done (pp, "Bogus server name");
  }
  if ((ntok = atoi (argv[2])) < 0) //TODO: check if token is too big!
  {
    ERROR ("Server %s sent us invalid token %ld", peer->dname, ntok);
    if (!ircd_recover_done (pp, "Invalid token"))
      return 1;
    //TODO: drop link?
  }
  if ((c = _ircd_validate_hub (pp, nhn)))
  {
    ircd_do_squit (pp->link, NULL, c);
    return 1;
  }
  /* ok, we got and checked everything, create data and announce */
  if (!cl)
    cl = _ircd_got_new_remote_server (pp, src, ntok, argv[0], nhn, argv[3]);
  if (!cl) /* peer was squited */
    return 1;
  link = alloc_LINK();
  link->where = src;
  link->cl = cl;
  link->prev = src->c.lients;
  link->flags = 0;
  src->c.lients = link;
  cl->umode |= A_MULTI;			/* it's not set on new */
  if (cl->via) /* it's not first connection */
    _ircd_recalculate_hops();
  else
  {
    cl->via = src->via;
    cl->alt = src->alt;
  }
  ircd_sendto_servers_all (Ircd, pp, ":%s ISERVER %s %hd %hd :%s", sender,
			   argv[0], cl->hops, cl->x.token, argv[3]);
  return 1;
}
#endif /* IRCD_MULTICONNECT */

static inline void _ircd_transform_invalid_nick(char *buf, const char *nick,
						size_t bs)
{
  while (bs > 0 && *nick)
    if (*nick == '-' ||
	(*nick >= 'A' && *nick <= '~') ||
	(*nick >= '0' && *nick <= '9')) {
      *buf++ = *nick;
      bs--;
    } else
      nick++; /* skip non-ASCII and invalid chars so we never get rename back */
  *buf = '\0';
}

/* args: client, server-sender, sender token, new nick
   returns: phantom (on hold) old nick
   new nick should be checked to not collide! */
static CLIENT *_ircd_do_nickchange(CLIENT *tgt, peer_priv *pp,
				   unsigned short token, const char *nn)
{
  CLIENT *phantom, *holded;

  dprint(4, "ircd:ircd.c:_ircd_do_nickchange: %s to %s", tgt->nick, nn);
  /* notify new and old servers about nick change */
  ircd_sendto_servers_all_ack(Ircd, tgt, NULL, pp, ":%s NICK %s", tgt->nick, nn);
  /* notify local users including this one about nick change */
  ircd_quit_all_channels(Ircd, tgt, 0, 0); /* mark for notify */
  if (CLIENT_IS_LOCAL(tgt))
    tgt->via->p.iface->ift |= I_PENDING;
  Add_Request(I_PENDING, "*", 0, ":%s!%s@%s NICK %s", tgt->nick, tgt->user,
	      tgt->host, nn);
  /* change our data now */
  if (Delete_Key(Ircd->clients, tgt->lcnick, tgt) < 0)
    ERROR("ircd:_ircd_do_nickchange: tree error on removing %s", tgt->lcnick);
    //TODO: isn't it fatal?
  holded = tgt->rfr;			/* phantom should inherit it */
  if (holded != NULL && holded->cs != tgt)
    holded = NULL;			/* it's not nick holder */
  phantom = _ircd_get_phantom(tgt->nick, tgt->lcnick, tgt);
  phantom->hold_upto = Time + CHASETIMELIMIT; /* nick delay for collided */
  if (holded != NULL) {			/* do inheritance */
    phantom->pcl = holded;
    _ircd_bounce_collision(phantom);
  }
#if IRCD_MULTICONNECT
  _ircd_move_acks(tgt, phantom); /* move acks into the clone with old lcnick */
#endif
  strfcpy(tgt->nick, nn, sizeof(tgt->nick));
  unistrlower(tgt->lcnick, tgt->nick, sizeof(tgt->lcnick));
  if (Insert_Key(&Ircd->clients, tgt->lcnick, tgt, 1) < 0)
    ERROR("ircd:_ircd_do_nickchange: tree error on adding %s", tgt->lcnick);
    //TODO: isn't it fatal?
#ifdef USE_SERVICES
  //TODO: notify services about nick change?
#endif
  return phantom;
}

static int _ircd_remote_nickchange(CLIENT *tgt, peer_priv *pp,
				   unsigned short token, const char *sender,
				   const char *nn)
{
  CLIENT *collision, *phantom;
  int changed;
  char checknick[MB_LEN_MAX*NICKLEN+NAMEMAX+2];

  dprint(4, "ircd:ircd.c:_ircd_remote_nickchange: %s to %s", tgt->nick, nn);
  //TODO: check nickchange collision (we got nickchange while sent ours)
#if IRCD_MULTICONNECT
  if (pp->link->cl->umode & A_MULTI)
    New_Request(pp->p.iface, 0, "ACK NICK %s", sender);
#endif
  if (!tgt || (tgt->umode & (A_SERVER | A_SERVICE))) {
    ERROR("ircd:got NICK from nonexistent user %s via %s", sender, pp->p.dname);
    return ircd_recover_done(pp, "Bogus NICK sender");
  }
  changed = 1;
  if (!_ircd_validate_nickname(checknick, nn, sizeof(checknick))) {
    _ircd_transform_invalid_nick(checknick, nn, sizeof(checknick));
    ERROR("ircd:invalid NICK %s via %s => %s", nn, pp->p.dname, checknick);
    changed = -1;
    ircd_recover_done(pp, "Invalid nick");
  }
  collision = _ircd_check_nick_collision(checknick, sizeof(checknick), pp);
  if (collision != NULL && strcmp(nn, checknick)) {
    ERROR("ircd:nick collision on nick change %s => %s: => %s", sender, nn,
	  checknick);
    changed = -1;
  }
  if (!strcmp(tgt->nick, checknick)) {
    Add_Request(I_LOG, "*", F_WARN, "ircd:dummy NICK change via %s for %s",
		pp->p.dname, checknick);
    return ircd_recover_done(pp, "Bogus nickchange");
  }
  phantom = NULL;
  if (changed < 0) {			/* redo change on collision */
    //create collided phantom client and get it linked.......
    collision = NULL;
    if (tgt->rfr != NULL && tgt->rfr->cs == tgt)
      collision = tgt->rfr;		/* it is nick holder */
    phantom = _ircd_get_phantom(nn, NULL, tgt); /* order: ? -> phantom -> tgt */
    if (collision != NULL)		/* restore it */
      tgt->rfr = collision;		/* phantom->x.rto is asymmetric now! */
    if (phantom->cs != phantom) {	/* have to set new collision */
      if (phantom->cs->rfr->cs == phantom->cs) { /* active keyholder */
	phantom->pcl = phantom->cs->rfr; /* insert it */
	phantom->cs->rfr = phantom;
      } else {
	phantom->pcl = phantom->cs->pcl; /* insert it */
	phantom->cs->pcl = phantom;
      }
    }
#if IRCD_MULTICONNECT
    if (pp->link->cl->umode & A_MULTI)
      ircd_add_ack(pp, phantom, NULL); /* either KILL or NICK */
    else
#endif
    phantom->hold_upto = Time + CHASETIMELIMIT; /* nick delay for collided */
    strfcpy(phantom->away, pp->p.dname, sizeof(phantom->away));
    if (checknick[0] == '\0') {		/* unresolvable nick collision */
      if (CLIENT_IS_LOCAL(tgt))
	New_Request(tgt->via->p.iface, 0, ":%s KILL %s :Nick collision from %s",
		    MY_NAME, tgt->nick, pp->p.dname); /* notify the victim */
      New_Request(pp->p.iface, 0, ":%s KILL %s :Unresolvable nick collision",
		  MY_NAME, nn);		/* send KILL back */
      ircd_sendto_servers_all_ack(Ircd, tgt, NULL, pp,
				  ":%s KILL %s :Nick collision from %s", MY_NAME,
				  tgt->nick, pp->p.dname); /* broadcast KILL */
      if (collision != NULL)
	tgt->rfr = phantom;		/* recover; see above */
      ircd_prepare_quit(tgt, pp, "nick collision");
      tgt->hold_upto = Time + CHASETIMELIMIT;
      Add_Request(I_PENDING, "*", 0, ":%s!%s@%s QUIT :Nick collision from %s",
		  tgt->nick, tgt->user, tgt->host, pp->p.dname);
      tgt->host[0] = 0;			/* for collision check */
      return 1;
    }
    New_Request(pp->p.iface, 0, ":%s NICK :%s", nn, checknick);
  }
  collision = _ircd_do_nickchange(tgt, pp, token, checknick);
  /* order is now: ? -> (?phantom?) -> collision -> tgt */
  if (phantom != NULL)			/* it may be asymmetric; see above */
    collision->rfr = phantom;		/* change back relation to right one */
  return 1;
}

BINDING_TYPE_ircd_server_cmd(ircd_nick_sb);
static int ircd_nick_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			const char *sender, const char *lcsender, char *cmd,
			int argc, const char **argv)
{ /* args: <nickname> <hopcount> <username> <host> <servertoken> <umode> <realname> */
  /* args: <newnickname> */
  CLIENT *tgt, *on, *collision, *phantom;
  LINK *link;
  peer_priv *pp = peer->iface->data; /* it's peer really */
  const char *c;
  int ct;

  if (argc < 7) {
    if (argc != 1) {
      ERROR("ircd:incorrect number of arguments for NICK from %s: %d",
	    peer->dname, argc);
      return ircd_recover_done(pp, "Invalid NICK arguments");
    }
    return _ircd_remote_nickchange(_ircd_find_client_lc(lcsender), pp, token,
				   sender, argv[0]);
  }
  ct = atoi(argv[4]);
  if (ct < 0 || ct > (int)pp->t || (on = pp->i.token[ct]) == NULL)
  {
    New_Request(peer->iface, 0, ":%s KILL %s :Invalid server", MY_NAME, argv[0]);
#if IRCD_MULTICONNECT
    if (pp->link->cl->umode & A_MULTI)
      ircd_add_ack(pp, NULL, NULL);
#endif
    return ircd_recover_done(pp, "Bogus source server");
  }
  tgt = alloc_CLIENT();
  tgt->cs = on;
  tgt->hold_upto = 0;
  tgt->rfr = NULL;
  tgt->umode = 0;
  ct = 0;
  if (!_ircd_validate_nickname(tgt->nick, argv[0], sizeof(tgt->nick))) {
    _ircd_transform_invalid_nick(tgt->nick, argv[0], sizeof(tgt->nick));
    ERROR("ircd:invalid NICK %s via %s => %s", argv[0], peer->dname, tgt->nick);
    ct = 1;
    ircd_recover_done(pp, "Invalid nick");
  }
  collision = _ircd_check_nick_collision(tgt->nick, sizeof(tgt->nick), pp);
  if (collision != NULL) {
    ERROR("ircd:nick collision via %s: %s => %s", peer->dname, argv[0],
	  tgt->nick);
    ct = 1;
  }
  if (ct != 0) {			/* change on collision */
    //create collided nick on hold and add link to it.......
    phantom = _ircd_get_phantom(argv[0], NULL, tgt);
    if (phantom->cs != phantom) {	/* have to set new collision */
      if (phantom->cs->rfr->cs == phantom->cs) { /* active keyholder */
	phantom->pcl = phantom->cs->rfr; /* insert it */
	phantom->cs->rfr = phantom;
      } else {
	phantom->pcl = phantom->cs->pcl; /* insert it */
	phantom->cs->pcl = phantom;
      }
    }
#if IRCD_MULTICONNECT
    if (pp->link->cl->umode & A_MULTI)
      ircd_add_ack(pp, phantom, NULL); /* either KILL or NICK */
    else
#endif
    phantom->hold_upto = Time + CHASETIMELIMIT; /* nick delay for collided */
    strfcpy(phantom->away, peer->dname, sizeof(phantom->away));
    if (tgt->nick[0] == '\0')
    {
      New_Request(peer->iface, 0, ":%s KILL %s :Nick collision", MY_NAME, argv[0]);
      phantom->pcl = NULL;
      free_CLIENT(tgt);
      return 1;
    }
    New_Request(peer->iface, 0, ":%s NICK :%s", argv[0], tgt->nick);
  }
  tgt->hops = on->hops + 1;
  strfcpy(tgt->user, argv[2], sizeof(tgt->user));
  strfcpy(tgt->host, argv[3], sizeof(tgt->host));
  strfcpy(tgt->fname, argv[6], sizeof(tgt->fname));
  for (c = argv[5]; *c; c++) { /* make umode from argv[5] */
    register modeflag mf;

    if (*c == '+' && c == argv[5])
      continue;
    mf = ircd_char2umode(srv, peer->dname, *c);
    if (mf == 0)
      ERROR("ircd:unknown umode char %c for NICK from %s", *c, peer->dname);
    else
      tgt->umode |= mf;
  }
#if IRCD_MULTICONNECT
  tgt->on_ack = 0;
#endif
  link = alloc_LINK();
  link->cl = tgt;
  link->where = on;
  link->prev = on->c.lients;
  link->flags = 0;
  on->c.lients = link;
  _ircd_class_rin(link); /* add it into class global list */
  unistrlower(tgt->lcnick, tgt->nick, sizeof(tgt->lcnick));
  if (Insert_Key(&Ircd->clients, tgt->lcnick, tgt, 1))
    ERROR("ircd:ircd_nick_sb: tree error on adding %s", tgt->lcnick);
    //TODO: isn't it fatal?
  ircd_sendto_servers_all(Ircd, pp, ":%s NICK %s %hu %s %s %hu %s :%s",
			  sender, tgt->nick, tgt->hops, argv[2], argv[3],
			  on->x.token, argv[5], argv[6]);
#ifdef USE_SERVICES
  //TODO: notify services about new client?
#endif
  //TODO: BTIrcdGotRemote
  return 1;
}

#if IRCD_MULTICONNECT
BINDING_TYPE_ircd_server_cmd(ircd_inum);
static int ircd_inum(INTERFACE *srv, struct peer_t *peer, unsigned short token,
		     const char *sender, const char *lcsender, char *cmd,
		     int argc, const char **argv)
{ /* args: <id> <numeric> <target> text... */
  struct peer_priv *pp = peer->iface->data; /* it's peer really */
  int id;

  if (argc < 5) {
    ERROR("ircd:incorrect number of arguments for INUM from %s: %d",
	  peer->dname, argc);
    return ircd_recover_done(pp, "Invalid INUM arguments");
  }
  if (!(pp->link->cl->umode & A_MULTI))
    return (0);		/* this is ambiguous to come from RFC2813 servers */
  id = atoi(argv[2]);
  if (!ircd_test_id(Ircd->token[token], id))
    //TODO: log duplicate?
    return (1);
  return _ircd_do_server_numeric(pp, sender, id, argc, argv);
}
#endif

BINDING_TYPE_ircd_server_cmd(ircd_service_sb);
static int ircd_service_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			   const char *sender, const char *lcsender, char *cmd,
			   int argc, const char **argv)
{ /* args: <servicename> <servertoken> <distribution> <type> <hopcount> <info> */
  CLIENT *tgt, *on;
  LINK *link;
  peer_priv *pp = peer->iface->data; /* it's peer really */
  int ct;

  if (argc < 6) {
    ERROR("ircd:incorrect number of arguments for SERVICE from %s: %d",
	  peer->dname, argc);
    return ircd_recover_done(pp, "Invalid SERVICE arguments");
  }
  ct = atoi(argv[1]);
  if (ct < 0 || ct > (int)pp->t || (on = pp->i.token[ct]) == NULL)
  {
    ERROR("ircd:invalid SERVICE token %s via %s", argv[1], peer->dname);
    New_Request(peer->iface, 0, ":%s KILL %s :Invalid server", MY_NAME, argv[0]);
#if IRCD_MULTICONNECT
    if (pp->link->cl->umode & A_MULTI)
      ircd_add_ack(pp, NULL, NULL);
#endif
    return ircd_recover_done(pp, "Bogus source server");
  }
  /* check if that's duplicate */
  tgt = ircd_find_client(argv[0], pp);
#if IRCD_MULTICONNECT
  if (tgt != NULL && tgt->cs == on)
    //TODO: log duplicate
    return (1);
  else
#endif
  if (tgt != NULL) {
    ERROR("ircd:invalid SERVICE token %s via %s", argv[1], peer->dname);
    New_Request(peer->iface, 0, ":%s KILL %s :Service name collision",
		MY_NAME, argv[0]);
#if IRCD_MULTICONNECT
    if (pp->link->cl->umode & A_MULTI)
      ircd_add_ack(pp, NULL, NULL);
#endif
    return ircd_recover_done(pp, "Duplicate service");
  }
  if (simple_match(argv[2], MY_NAME) < 0) { /* our name doesn't match */
    ERROR("ircd:invalid SERVICE distribution %s via %s", argv[2], peer->dname);
    return ircd_recover_done(pp, "Invalid distribution");
  }
  /* service type parameter isn't currently in use, see RFC2813 */
  tgt = alloc_CLIENT();
  if (!_ircd_validate_nickname(tgt->nick, argv[0], sizeof(tgt->nick))) {
    ERROR("ircd:invalid SERVICE %s via %s", argv[0], peer->dname);
    free_CLIENT(tgt);
    New_Request(peer->iface, 0, ":%s KILL %s :Invalid SERVICE name", MY_NAME,
		argv[0]);
#if IRCD_MULTICONNECT
    if (pp->link->cl->umode & A_MULTI)
      ircd_add_ack(pp, NULL, NULL);
#endif
    return ircd_recover_done(pp, "Bogus SERVICE name");
  }
  tgt->pcl = NULL;			/* service is out of classes */
  tgt->x.class = NULL;
#if IRCD_MULTICONNECT
  tgt->on_ack = 0;
#endif
  tgt->c.hannels = NULL;
  tgt->cs = on;
  tgt->hold_upto = 0;
  tgt->rfr = NULL;
  tgt->umode = A_SERVICE;
  strfcpy(tgt->away, argv[3], sizeof(tgt->away));
  tgt->hops = on->hops + 1;
  tgt->user[0] = '\0';
  strfcpy(tgt->host, argv[2], sizeof(tgt->host));
  strfcpy(tgt->fname, argv[5], sizeof(tgt->fname));
  link = alloc_LINK();
  link->cl = tgt;
  link->where = on;
  link->prev = on->c.lients;
  link->flags = 0;
  on->c.lients = link;
  unistrlower(tgt->lcnick, tgt->nick, sizeof(tgt->lcnick));
  if (Insert_Key(&Ircd->clients, tgt->lcnick, tgt, 1))
    ERROR("ircd:ircd_service_sb: tree error on adding %s", tgt->lcnick);
    //TODO: isn't it fatal?
  ircd_sendto_servers_mask(Ircd, pp, argv[2], ":%s SERVICE %s %hu %s %s %hu :%s",
			   sender, tgt->nick, on->x.token, argv[2], argv[3],
			   tgt->hops, argv[5]);
#ifdef USE_SERVICES
  //TODO: notify services about new service?
#endif
  //TODO: BTIrcdGotRemote
  return 1;
}
#undef __TRANSIT__
#define __TRANSIT__


/* for composite names only! should be obsoleted in 0.10 ! */
static inline CHANNEL *_ircd_find_channel_c (const char *name)
{
  char lcname[MB_LEN_MAX*CHANNAMELEN+1];
  register char *c;

  unistrlower (lcname, name, sizeof(lcname));
  if ((c = strrchr (lcname, '@')))
    *c = '\0';
  return Find_Key (Ircd->channels, lcname);
}

/* "inspect-client" - this is the most huge used so needs to be fast! */
BINDING_TYPE_inspect_client(incl_ircd);
static modeflag incl_ircd(const char *net, const char *public,
			  const char *name, const char **lname,
			  const char **host, time_t *idle, short *cnt)
{
  CLIENT *cl;
  CHANNEL *ch = NULL;
  MEMBER *memb;

  /* ignoring parameter net, we are only-one-network */
  if (name == NULL)			/* it's request for channel data */
  {
    ch = _ircd_find_channel_c (public);
    if (ch == NULL || ch->hold_upto)
      return 0;
    if (host)
      *host = ch->topic;
    if (cnt && (ch->mode & A_LIMIT))
      *cnt = ch->limit;
    else if (cnt)
      *cnt = -1;
    return ch->mode;
  }
  if (strchr (name, '@'))		/* request for mask check */
  {
    MASK *m, *e;

    ch = _ircd_find_channel_c (public);
    if (ch == NULL || ch->hold_upto)
      return 0;
    for (m = ch->invites; m; m = m->next) /* invite overrides ban */
      if (simple_match (m->what, name) > 0) /* check invites */
      {
	if (host)
	  *host = m->what;
//	if (lname)
//	  *lname = m->by;
//	if (idle)
//	  *idle = m->since;
	return A_INVITED;
      }
    for (m = ch->bans; m; m = m->next)
      if (simple_match (m->what, name) > 0) /* check for ban */
      {
	for (e = ch->exempts; e; e = e->next)
	  if (simple_match (e->what, name) > 0) /* check for exempt */
	  {
	    if (host)
	      *host = e->what;
//	    if (lname)
//	      *lname = e->by;
//	    if (idle)
//	      *idle = e->since;
	    return A_EXEMPT;
	  }
	if (host)
	  *host = m->what;
//	if (lname)
//	  *lname = m->by;
//	if (idle)
//	  *idle = m->since;
	return A_DENIED;
      }
    return 0;				/* no invite/ban/exempt */
  }
  cl = _ircd_find_client_lc (name);	/* it's request for client data */
  if (cl == NULL || cl->hold_upto)	/* no such client found */
    return 0;
  if (CLIENT_IS_SERVER(cl))
    return cl->umode;
  if (host)
    *host = cl->host;
  if (lname)
    *lname = cl->user;
  if (idle && CLIENT_IS_LOCAL(cl))
    *idle = cl->via->noidle;
  if (public == NULL)			/* request for client's umode */
    return cl->umode;
  ch = _ircd_find_channel_c (public); /* it's request for client on channel */
  if (ch == NULL || ch->hold_upto)	/* inactive channel! */
    return 0;
  for (memb = cl->c.hannels; memb; memb = memb->prevchan)
    if (memb->chan == ch)
      return memb->mode;
  return 0;
}


/* -- connchain filters --------------------------------------------------- */
struct connchain_buffer { char c; };

static ssize_t _ircd_ccfilter_stub_send (struct connchain_i **c, idx_t i, const char *b,
					 size_t *s, struct connchain_buffer **x)
{
  return Connchain_Put (c, i, b, s);
}

static ssize_t _ircd_ccfilter_stub_recv (struct connchain_i **c, idx_t i, char *b,
					 size_t s, struct connchain_buffer **x)
{
  return Connchain_Get (c, i, b, s);
}

BINDING_TYPE_connchain_grow(_ccfilter_P_init);
static int _ccfilter_P_init(struct peer_t *peer, ssize_t (**recv)(struct connchain_i **, idx_t,
					char *, size_t, struct connchain_buffer **),
			    ssize_t (**send)(struct connchain_i **, idx_t, const char *,
					size_t *, struct connchain_buffer **),
			    struct connchain_buffer **buf)
{
  if (peer->iface->IFRequest != &_ircd_client_request) /* the simplest check */
    return 0;
  if (buf == NULL)			/* that's a check */
    return 1;
  ((peer_priv *)peer->iface->data)->link->cl->umode |= A_ISON;
  *recv = &_ircd_ccfilter_stub_recv;
  *send = &_ircd_ccfilter_stub_send;
  return 1;
}

#if IRCD_USES_ICONV
BINDING_TYPE_connchain_grow(_ccfilter_U_init);
static int _ccfilter_U_init(struct peer_t *peer, ssize_t (**recv)(struct connchain_i **, idx_t,
					char *, size_t, struct connchain_buffer **),
			    ssize_t (**send)(struct connchain_i **, idx_t, const char *,
					size_t *, struct connchain_buffer **),
			    struct connchain_buffer **buf)
{
  if (peer->iface->IFRequest != &_ircd_client_request) /* the simplest check */
    return 0;
  if (buf == NULL)			/* that's a check */
    return 1;
  Free_Conversion (peer->iface->conv);
  peer->iface->conv = Get_Conversion (CHARSET_UNICODE);
  *recv = &_ircd_ccfilter_stub_recv;
  *send = &_ircd_ccfilter_stub_send;
  return 1;
}
#endif

#if IRCD_MULTICONNECT
BINDING_TYPE_connchain_grow(_ccfilter_I_init);
static int _ccfilter_I_init(struct peer_t *peer, ssize_t (**recv)(struct connchain_i **, idx_t,
					char *, size_t, struct connchain_buffer **),
			    ssize_t (**send)(struct connchain_i **, idx_t, const char *,
					size_t *, struct connchain_buffer **),
			    struct connchain_buffer **buf)
{
  if (peer->iface->IFRequest != &_ircd_client_request) /* the simplest check */
    return 0;
  if (buf == NULL)			/* that's a check */
    return 1;
  ((peer_priv *)peer->iface->data)->link->cl->umode |= A_MULTI;
  *recv = &_ircd_ccfilter_stub_recv;
  *send = &_ircd_ccfilter_stub_send;
  return 1;
}
#endif


BINDING_TYPE_ircd_stats_reply(_istats_l);
static void _istats_l (INTERFACE *srv, const char *rq, modeflag umode)
{
  peer_priv *peer;
  const char *argv[5]; /* sender, num, target, message, NULL */
  char buf[MESSAGEMAX];

  argv[0] = MY_NAME;
  argv[1] = "211"; /* RPL_STATSLINKINFO macro is never used! */
  argv[2] = rq;
  argv[3] = buf;
  argv[4] = NULL;
  pthread_mutex_lock (&IrcdLock);
  for (peer = IrcdPeers; peer; peer = peer->p.priv)
  {
    snprintf (buf, sizeof(buf), "%s[%s@%s] %d %zu %zu %zu %zu %ld",
	      peer->link->cl->nick, peer->link->cl->user, peer->link->cl->host,
	      peer->p.iface->qsize, peer->ms, peer->bs/1000, peer->mr,
	      peer->br/1000, (long int)(Time - peer->started));
    _ircd_do_server_message (NULL, 4, argv);
  }
  pthread_mutex_unlock (&IrcdLock);
}

#if 0 /* needs 'hits' field - 0.10+ */
BINDING_TYPE_ircd_stats_reply(_istats_m);
static void _istats_m (INTERFACE *srv, const char *rq, modeflag umode)
{
  struct binding_t *bc = NULL, *bs;
  unsigned int hc, hs;
  const char *argv[5]; /* sender, num, target, message, NULL */
  char buf[SHORT_STRING];

  argv[0] = MY_NAME;
  argv[1] = "212"; /* RPL_STATSCOMMANDS macro is never used! */
  argv[2] = rq;
  argv[3] = buf;
  argv[4] = NULL;
  /* show commands in clients bindtable */
  while ((bc = Check_Bindtable (BTIrcdClientCmd, NULL, U_ALL, U_ANYCH, bc)))
  {
    hc = b->hits;
    bs = Check_Bindtable (BTIrcdServerCmd, bc->key, U_ALL, U_ANYCH, NULL);
    if (bs)
      hs = bs->hits;
    else
      hs = 0;
#ifndef IRCD_STATM_EMPTYTOO
    if (hc > 0 || hs > 0)
#endif
    {
      snprintf (buf, sizeof(buf), "%u %u", hc, hs);
      _ircd_do_server_message (NULL, 4, argv);
    }
  }
  /* show server-only commands */
  while ((bc = Check_Bindtable (BTIrcdServerCmd, NULL, U_ALL, U_ANYCH, bc)))
  {
    if (Check_Bindtable (BTIrcdClientCmd, bc->key, U_ALL, U_ANYCH, NULL))
      continue;				/* it was shown on previous cycle */
    hs = b->hits;
#ifndef IRCD_STATM_EMPTYTOO
    if (hs)
#endif
    {
      snprintf (buf, sizeof(buf), "0 %u", hs);
      _ircd_do_server_message (NULL, 4, argv);
    }
  }
}
#endif


/* -- common network interface -------------------------------------------- */
static int _ircd_request (INTERFACE *cli, REQUEST *req)
{
  const char *argv[IRCDMAXARGS+3];	/* sender, command, args, NULL */
  char *c;
  static unsigned char chreop;
  int argc, i;

#if IRCD_MULTICONNECT
  if (_ircd_uplinks == 0)		/* no autoconnects started */
#else
  if (_ircd_uplink == NULL)
#endif
    _ircd_init_uplinks();		/* try our uplink proc */
  if (chreop++ == 0)
    ircd_channels_chreop(Ircd, &ME);
  if (!req)				/* it's idle call */
    return REQ_OK;
  c = req->string;
  if (*c == ':')			/* we got sender prefix */
  {
    register char *cc;

    argv[0] = &c[1];
    c = gettoken (c, NULL);
    cc = strchr (argv[0], '!');
    if (cc) *cc = 0;			/* leave only sender name here */
  }
  else
    argv[0] = MY_NAME;
  argc = 1;
  do {
    if (*c == ':')
    {
      argv[argc++] = ++c;
      break;
    }
    else
      argv[argc++] = c;
    if (argc == IRCDMAXARGS + 2)
      break;
    c = gettoken (c, NULL);
  } while (*c);
  argv[argc] = NULL;
  i = 0;
  if (*argv[0] && *argv[1])		/* got malformed line? */
    i = _ircd_do_server_message (NULL, argc, argv);
  if (i == 0)
    ERROR ("ircd: bad service request: %s", argv[1]);
  return REQ_OK;
}

static void _ircd_catch_undeleted_ch (void *ch)
{
  ERROR ("ircd:_ircd_catch_undeleted_ch: channel %s with %d users",
	 ((CHANNEL *)ch)->name, ((CHANNEL *)ch)->count);
  ircd_drop_channel (Ircd, ch);
}

static void _ircd_catch_undeleted_cl (void *cl)
{
  if (CLIENT_IS_ME((CLIENT *)cl))
    return;
  ERROR ("ircd:_ircd_catch_undeleted_cl: client %s (%s)", ((CLIENT *)cl)->nick,
	 (CLIENT_IS_SERVER((CLIENT *)cl)) ? "server" : "user");
  if (CLIENT_IS_SERVER((CLIENT *)cl))
  {
#if IRCD_MULTICONNECT
    ircd_clear_acks (Ircd, ((CLIENT *)cl)->via);
#endif
    _ircd_free_token (((CLIENT *)cl)->x.token);
    free_CLIENT(cl);
    return;
  }
  /* simplified phantomization if it was active nick holder */
  if (((CLIENT *)cl)->rfr != NULL && ((CLIENT *)cl)->rfr->cs == cl)
    ((CLIENT *)cl)->pcl = ((CLIENT *)cl)->rfr;
  /* free list of collided phantoms of the same nick */
  while (cl != NULL) {
    register CLIENT *tmp = cl;
    cl = tmp->pcl;
    free_CLIENT(tmp);
  }
  /* nothing else to do for user */
}

static iftype_t _ircd_signal (INTERFACE *iface, ifsig_t sig)
{
  CLASS *cl;
  LINK *s;
  size_t i;

  switch (sig)
  {
    case S_TERMINATE:
      /* kill everything and wait until they die */
      for (i = 0; i < IrcdLnum; i++)	/* kill all listeners */
      {
	Send_Signal (I_LISTEN, IrcdLlist[i], S_TERMINATE);
	FREE (&IrcdLlist[i]);
      }
      IrcdLnum = 0; /* if module is static then mark it empty */
      for (s = Ircd->servers; s; s = s->prev) /* squit all links */
	ircd_do_squit (s, s->cl->via, NONULL(ShutdownR));
      while (IrcdPeers) 		/* kill every peer */
      { /* no lock because no new peer can be added after all listeners died */
	INTERFACE *ifcl = IrcdPeers->p.iface;
	register iftype_t rc;

	dprint (4, "ircd: killing peer %s.", IrcdPeers->link->cl->lcnick);
	rc = _ircd_client_signal (ifcl, S_TERMINATE);
	ifcl->ift |= rc;
	Set_Iface (ifcl);
	while (!(ifcl->ift & I_DIED))
	  Get_Request();		/* wait it to die */
	Unset_Iface();
      }
      if (Ircd->servers)
	ERROR ("ircd:_ircd_signal:termination failed: local list isn't empty: %s!",
	       Ircd->servers->cl->lcnick);
      while ((cl = Ircd->users))
      {
	if (cl->glob)
	  ERROR ("ircd:_ircd_signal:termination failed: class %s isn't empty: %s!",
		 cl->name, cl->glob->nick);
	FREE (&cl->name);
	Ircd->users = cl->next;
	free_CLASS (cl);
      }
      Destroy_Tree (&Ircd->channels, &_ircd_catch_undeleted_ch);
      Destroy_Tree (&Ircd->clients, &_ircd_catch_undeleted_cl);
      Ircd->iface = NULL;
      if (iface)
      {
	iface->ift |= I_DIED; /* it will free Ircd */
	iface->data = NULL; /* module owns it */
      }
      break;
    default: ;
  }
  return 0;
}


/* -- common functions ---------------------------------------------------- */
void ircd_drop_nick (CLIENT *cl)
{
  dprint(4, "ircd:ircd.c:ircd_drop_nick: %s", cl->nick);
  if (cl->umode & A_SERVER)
    return;
  if (cl->cs == NULL)
    ERROR("ircd:ircd_drop_nick() not for nick on hold: %s", cl->nick);
  else if (cl->cs->hold_upto != 0)
    _ircd_try_drop_collision(&cl->cs);	/* phantom nick holder */
  else if (cl->cs->rfr != NULL && cl->cs->rfr->cs == cl->cs)
    _ircd_try_drop_collision(&cl->cs->rfr); /* active nick holder */
  else
    ERROR("ircd:ircd_drop_nick() reference error: %s -> %s", cl->nick, cl->cs->nick);
}

CLIENT *ircd_find_client (const char *name, peer_priv *via)
{
  register CLIENT *c;

  dprint(4, "ircd:ircd.c:ircd_find_client: %s", name);
  if (!name)
    return &ME;
  c = _ircd_find_client (name);
  if (c != NULL && via != NULL && !CLIENT_IS_SERVER(c))
    c = _ircd_find_phantom(c, via);
  if (c == NULL || c->umode & (A_SERVER|A_SERVICE))
    return (c);
  /* if it's phantom then go to current nick */
  while (c != NULL && c->hold_upto != 0)
    c = c->x.rto;
  return (c);
}

CLIENT *ircd_find_client_nt(const char *name, peer_priv *via)
{
  register CLIENT *c;

  if (!name)
    return &ME;
  c = _ircd_find_client(name);
  if (c == NULL || via == NULL || CLIENT_IS_SERVER(c))
    return (c);
  return (_ircd_find_phantom(c, via));
}

/* manages lists, prepares to notify network about that quit (I_PENDING),
   and kills peer if it's local */
void ircd_prepare_quit (CLIENT *client, peer_priv *via, const char *msg)
{
//  register LINK *s;

  dprint(4, "ircd:ircd.c:ircd_prepare_quit: %s", client->nick);
  ircd_quit_all_channels (Ircd, client, 0, 1); /* remove and mark */
//  for (s = Ircd->servers; s; s = s->prev)
//    if (s->cl->via != via)		/* don't send it back */
//      s->cl->via->p.iface->ift |= I_PENDING; /* all linked servers need notify */
  if (CLIENT_IS_LOCAL (client))
    _ircd_peer_kill (client->via, msg);
  else
    _ircd_remote_user_gone(client);
  client->away[0] = '\0';		/* caller may not fill it */
}

/* clears link->cl and notifies local users about lost server */
static inline void _ircd_squit_one (LINK *link)
{
  CLIENT *server = link->cl;
  LINK *l;

  /* notify local users about complete squit and clear server->c.lients */
  while ((l = server->c.lients))
  {
    server->c.lients = l->prev;
    if (CLIENT_IS_SERVER (l->cl)) /* server is gone so free all */
    {
      pthread_mutex_lock (&IrcdLock);
      if (l->cl != link->where)		/* never free backlink! */
	free_CLIENT (l->cl);
	// TODO: shouldn't we log it? transit had to squit it before!
      /* link is about to be destroyed so don't remove token of l */
      free_LINK (l);
      pthread_mutex_unlock (&IrcdLock);
      continue;
    }
    ircd_quit_all_channels (Ircd, l->cl, 1, 1); /* it's user, remove it */
    Add_Request (I_PENDING, "*", 0, "QUIT :%s %s", /* send split message */
		 link->where->lcnick, server->lcnick);
    _ircd_class_out (l);		/* remove from global class list */
    _ircd_bt_lost_client(l->cl, server->lcnick); /* "ircd-lost-client" */
    l->cl->hold_upto = Time + _ircd_hold_period; /* put it in temp. unavailable list */
    l->cl->x.rto = NULL;		/* convert active user into phantom */
    l->cl->cs = l->cl;			/* it holds key for itself */
    l->cl->away[0] = '\0';		/* it's used by nick change tracking */
    if (l->cl->rfr != NULL && l->cl->rfr->cs == l->cl) { /* it was nick holder */
      l->cl->pcl = l->cl->rfr;
      l->cl->rfr = NULL;
    }
    //TODO: run "ircd-lost-client" bindtable
    l->cl->via = NULL;			/* to CLIENT_IS_ME work */
    strfcpy (l->cl->host, server->lcnick, sizeof(l->cl->host));
  }
  _ircd_free_token (server->x.token);	/* no token for gone server */
  //TODO: BTIrcdLostServer
}

/* notify local servers about squit */
static inline void _ircd_send_squit (LINK *link, peer_priv *via, const char *msg)
{
  /* notify local servers about squit */
  ircd_sendto_servers_all_ack (Ircd, link->cl, NULL, via, ":%s SQUIT %s :%s",
			       link->where->lcnick, link->cl->lcnick, msg);
}

/* server is gone; notifies network recursively and clears link->cl
   does not not remove link->cl from link->where */
static void _ircd_do_squit (LINK *link, peer_priv *via, const char *msg)
{
  register LINK *s;

  for (s = link->cl->c.lients ; s; s = s->prev) /* squit all behind it first */
    if (CLIENT_IS_SERVER (s->cl) && s->cl != link->where) /* could point back */
      _ircd_do_squit (s, via, link->cl->lcnick); /* reason is the server gone */
  _ircd_squit_one (link); /* no left behind; clear and notify users */
  _ircd_send_squit (link, via, msg); /* notify local servers now */
  if (link->where != &ME) /* it's remote, for local see ircd_do_squit() */
  {
    if (Delete_Key (Ircd->clients, link->cl->lcnick, link->cl)) /* remove it */
      ERROR("ircd:_ircd_do_squit: tree error on removing %s", link->cl->lcnick);
      // TODO: isn't it fatal?
#if IRCD_MULTICONNECT
    if (link->cl->on_ack) /* make a clone with acks so we can delete this one */
    {
      CLIENT *phantom;

      phantom = alloc_CLIENT();
      phantom->umode = A_SERVER;
      phantom->on_ack = 0;
      _ircd_move_acks(link->cl, phantom);
    }
#endif
    link->cl->lcnick[0] = '\0';
  }
}

/* local link squitted */
static inline void _ircd_lserver_out (LINK *l)
{
  register LINK **s;

  for (s = &Ircd->servers; *s; s = &(*s)->prev)
    if ((*s) == l)
      break;
  if (*s)
    *s = l->prev;
  else
    ERROR ("ircd:_ircd_lserver_out: local server %s not found in list!",
	   l->cl->lcnick);
  FREE (&l->cl->via->i.token);
  l->cl->via->t = 0;
}

/* remote link squitted */
static inline void _ircd_rserver_out (LINK *l)
{
  register LINK **s;

  for (s = &l->where->c.lients; *s; s = &(*s)->prev)
    if ((*s) == l)
      break;
  if (*s)
    *s = l->prev;
  else
    ERROR ("ircd:_ircd_rserver_out: server %s not found on %s!", l->cl->nick,
	   l->where->lcnick);
  if (CLIENT_IS_LOCAL(l->where))
  {
    register peer_priv *ppp = l->where->via;
    register int i;

    for (i = 0; i < ppp->t; i++)
      if (ppp->i.token[i] == l->cl)
	ppp->i.token[i] = NULL;
  }
  if (l->cl->lcnick[0] == '\0')		/* see _ircd_do_squit() */
  {
    pthread_mutex_lock (&IrcdLock);
    free_CLIENT (l->cl);
    free_LINK (l);
    pthread_mutex_unlock (&IrcdLock);
  }
}

/* if this server is multiconnected then we should only remove one instance
   and notify local servers but if it's only instance then do it recursively
   via is where SQUIT came from */
void ircd_do_squit (LINK *link, peer_priv *via, const char *msg)
{
#if IRCD_MULTICONNECT
  size_t i;
  register CLIENT *t;
  register LINK *s;

  dprint(4, "ircd:ircd.c:ircd_do_squit: %s", link->cl->nick);
  /* check if this server is connected anywhere else */
  s = NULL; /* if not-A_MULTI or single connected */
  if (link->cl->umode & A_MULTI)
    for (i = 1; s == NULL && i < Ircd->s; i++)
      if ((t = Ircd->token[i]) == NULL || t == link->cl || t == link->where)
	continue;
      else /* scan its links for this server */
	for (s = t->c.lients; s; s = s->prev)
	  if (s->cl == link->cl)
	    break; /* that will break outer loop too */
  if (s != NULL) /* it's multiconnected, just notify */
    _ircd_send_squit (link, via, msg);
  else /* it's completely gone from network */
#endif /* always last one for RFC2813 server */
    _ircd_do_squit (link, via, msg); /* notify everyone */
  if (link->where == &ME) /* it's local */
  {
    _ircd_lserver_out (link); /* remove it from Ircd->servers list */
#if IRCD_MULTICONNECT
    ircd_clear_acks (Ircd, link->cl->via); /* clear acks */
#endif
    _ircd_peer_kill (link->cl->via, msg); /* it will free structures */
  }
  else
    _ircd_rserver_out (link); /* remove it from link->where list and free it */
#if IRCD_MULTICONNECT
  if (s != NULL) /* it was multiconnected */
    _ircd_recalculate_hops(); /* recalculate all hops map */
#endif
}

int ircd_do_unumeric (CLIENT *requestor, int n, const char *template,
		      CLIENT *target, unsigned short i, const char *m)
{
  struct binding_t *b = NULL;
  char buff[MESSAGEMAX];

  snprintf (buff, sizeof(buff), "%03d", n); /* use buffer to get binding first */
  b = Check_Bindtable (BTIrcdDoNumeric, buff, U_ALL, U_ANYCH, NULL);
  /* macros: %N - nick(requestor), %@ - user host/server description,
	     %L - ident, %# - nick, %P - $i, %- - idle, %* - $m */
  printl (buff, sizeof(buff), template, 0, requestor->nick,
	  CLIENT_IS_SERVER(target) ? target->fname : target->host,
	  target->user,
	  CLIENT_IS_SERVER(target) ? target->lcnick : target->nick, i, 0,
	  target->via ? (Time - target->via->p.last_input) : (time_t)0, m);
  if (!b || b->name ||
      !b->func (Ircd->iface, n, requestor->nick, requestor->umode, buff))
  {
    char *rnick = (requestor->nick[0]) ? requestor->nick : MY_NAME;

    if (CLIENT_IS_LOCAL(requestor))	/* send it directly */
      New_Request (requestor->via->p.iface, 0, ":%s %03d %s %s", MY_NAME, n,
		   rnick, buff);
    else				/* send numeric or INUM */
    {
      ircd_sendto_new (requestor, ":%s INUM %d %03d %s %s", MY_NAME,
		       ircd_new_id(), n, rnick, buff);
      ircd_sendto_old (requestor, ":%s %03d %s %s", MY_NAME, n, rnick, buff);
    }
  }
  return 1;
}

int ircd_do_cnumeric (CLIENT *requestor, int n, const char *template,
		      CHANNEL *target, unsigned short i, const char *m)
{
  struct binding_t *b = NULL;
  char buff[MESSAGEMAX];

  snprintf (buff, sizeof(buff), "%03d", n); /* use buffer to get binding first */
  b = Check_Bindtable (BTIrcdDoNumeric, buff, U_ALL, U_ANYCH, NULL);
  /* macros: %N - nick(requestor), %# - channel, %* - $m */
  printl (buff, sizeof(buff), template, 0, requestor->nick, NULL,
	  NULL, target->name, i, 0, 0, m);
  if (!b || b->name ||
      !b->func (Ircd->iface, n, requestor->nick, requestor->umode, buff))
  {
    if (CLIENT_IS_LOCAL(requestor))	/* send it directly */
      New_Request (requestor->via->p.iface, 0, ":%s %03d %s %s", MY_NAME, n,
		   requestor->nick, buff);
    else				/* send numeric or INUM */
    {
      ircd_sendto_new (requestor, ":%s INUM %d %03d %s %s", MY_NAME,
		       ircd_new_id(), n, requestor->nick, buff);
      ircd_sendto_old (requestor, ":%s %03d %s %s", MY_NAME, n,
		       requestor->nick, buff);
    }
  }
  return 1;
}

int ircd_recover_done (peer_priv *peer, const char *msg)
{
  if (CheckFlood (&peer->corrections, _ircd_corrections) > 0)
  {
    ircd_do_squit (peer->link, peer, "Too many protocol errors");
    return 0;
  }
  New_Request (peer->p.iface, 0, "ERROR :%s", msg);
  return 1;
}

int ircd_try_connect (CLIENT *rq, const char *name, const char *port)
{
  struct clrec_t *u;
  INTERFACE *tmp;
  userflag uf;
  lid_t lid = FindLID (name);
  char host[MESSAGEMAX];

  dprint(4, "ircd:ircd.c:ircd_try_connect: %s", name);
  u = Lock_byLID (lid);
  if (!u)
    return ircd_do_unumeric (rq, ERR_NOSUCHSERVER, rq, atoi (port), name);
  uf = Get_Flags (u, Ircd->iface->name);
  Unlock_Clientrecord (u);
  if (!(uf & U_ACCESS))
    return ircd_do_unumeric (rq, ERR_NOSUCHSERVER, rq, atoi (port), name);
  tmp = Add_Iface (I_TEMP, NULL, NULL, &_ircd_sublist_receiver, NULL);
  Set_Iface (tmp);
  _ircd_sublist_buffer = host;
  if (Get_Hostlist (tmp, lid))
  {
    char *h, *p;			/* host, pass */

    Get_Request();
    p = gettoken (host, NULL);		/* isolate first host of it */
    if ((h = strchr (host, '@')))	/* get host name from record */
      *h++ = 0;
    else
      h = host;
    p = strchr (host, '/');		/* check for port */
    if (p)
      *p = 0;
    if (h == host)
      p = NULL;
    else if ((p = safe_strchr (host, ':'))) /* check for password */
      p++;
    _ircd_start_uplink2 (name, h, port, p); /* create a connection thread */
  }
  else
    ERROR ("ircd:server %s has no host record, ignoring CONNECT", name);
  Unset_Iface();
  tmp->ift = I_DIED;
  ircd_mark_wallops();
  //TODO: implement IWALLOPS
  ircd_sendto_servers_all(Ircd, NULL, ":%s WALLOPS :Connect '%s %s' from %s",
			  MY_NAME, name, port, rq->nick);
  return 1;
}

/* if tgt is NULL then show all, tgt should be local! */
int ircd_show_trace (CLIENT *rq, CLIENT *tgt)
{
  peer_priv *t;
#ifdef IRCD_TRACE_USERS
  CLASS *c;
#endif
  char buf[MESSAGEMAX];

  if (tgt != NULL)
    switch (tgt->via->p.state)
    {
      case P_DISCONNECTED:
	return ircd_do_unumeric (rq, RPL_TRACECONNECTING, &ME, 0, "-");
      case P_IDLE:
      case P_LOGIN:
	return ircd_do_unumeric (rq, RPL_TRACEHANDSHAKE, &ME, 0, "-");
      case P_INITIAL:
      case P_QUIT:
      case P_LASTWAIT:
	return ircd_do_unumeric (rq, RPL_TRACEUNKNOWN, &ME, 0, "-");
      case P_TALK:
	if (CLIENT_IS_SERVER (tgt))
	  //TODO: "Serv <class> <int>S <int>C <server> <nick!user|*!*>@<host|server> V<protocol version>"
	  // "Serv %*"
	//  snprintf (buf, sizeof(buf), "- %dS %dC %s *!*@%s V0210", ....);
	  return ircd_do_unumeric (rq, RPL_TRACESERVER, tgt, 0, "-");
#ifdef USE_SERVICES
	else if (CLIENT_IS_SERVICE (tgt))
	{
	  snprintf (buf, sizeof(buf), "%s %s %s :%s",
		    tgt->x.class ? tgt->x.class->name : "-", tgt->nick,
		    tgt->away, tgt->fname);
	  return ircd_do_unumeric (rq, RPL_TRACESERVICE, tgt, 0, buf);
	}
#endif
	else if (tgt->umode & (A_OP | A_HALFOP))
	  return ircd_do_unumeric (rq, RPL_TRACEOPERATOR, tgt, 0,
				   tgt->x.class ? tgt->x.class->name : "-");
	else if (!tgt->x.class)
	  return ircd_do_unumeric (rq, RPL_TRACENEWTYPE, tgt, 0, "Unclassed");
	return ircd_do_unumeric (rq, RPL_TRACEUSER, tgt, 0, tgt->x.class->name);
    }
#ifdef IRCD_TRACE_USERS
  if (CLIENT_IS_LOCAL(rq) && (rq->umode & (A_OP | A_HALFOP)))
    tgt = rq;				/* mark it for full listing */
#endif
  pthread_mutex_lock (&IrcdLock);
  for (t = IrcdPeers; t; t = t->p.priv)
    if (tgt || (t->link->cl->umode & (A_SERVER | A_SERVICE | A_OP | A_HALFOP)))
      ircd_show_trace (rq, t->link->cl);
#ifdef IRCD_TRACE_USERS
  if (!CLIENT_IS_LOCAL(rq) && (rq->umode & A_OP)) /* for remote opers only */
    for (c = Ircd->users; c; c = c->next)
      ircd_do_unumeric (rq, RPL_TRACECLASS, rq, c->lin, c->name);
#endif
  pthread_mutex_unlock (&IrcdLock);
  return 1;
// RPL_TRACELOG
}

const char *ircd_mark_wallops(void)
{
  register CLASS *ccl;
  register LINK *cln;

  for (ccl = Ircd->users; ccl; ccl = ccl->next)
    for (cln = ccl->local; cln; cln = cln->prev)
#ifdef WALLOP_ONLY_OPERS
      if ((cln->cl->umode & A_WALLOP) && (cln->cl->umode & (A_OP | A_HALFOP)))
#else
      if (cln->cl->umode & A_WALLOP)
#endif
	cln->cl->via->p.iface->ift |= I_PENDING;
  return (MY_NAME);
}


/* -- common module interface --------------------------------------------- */
static void _ircd_register_all (void)
{
  Add_Request (I_INIT, "*", F_REPORT, "module ircd");
  /* register variables */
  RegisterString ("ircd-flags-first", _ircd_flags_first,
		  sizeof(_ircd_flags_first), 0);
  RegisterString ("ircd-flags-post", _ircd_flags_post,
		  sizeof(_ircd_flags_post), 0);
  RegisterString ("ircd-default-class", _ircd_default_class,
		  sizeof(_ircd_default_class), 0);
  RegisterString ("ircd-version-string", _ircd_version_string,
		  sizeof(_ircd_version_string), 1);
  RegisterString ("ircd-description-string", _ircd_description_string,
		  sizeof(_ircd_description_string), 1);
  RegisterInteger ("ircd-hold-period", &_ircd_hold_period);
  RegisterInteger ("ircd-serverclass-pingf", &_ircd_server_class_pingf);
  RegisterFunction ("ircd", &func_ircd, "charset [host/]port");
}

/*
 * this function must receive signals:
 *  S_TERMINATE - unload module,
 *  S_REPORT - out state info to log,
 *  S_REG - report/register anything we should have in config file,
 *  S_TIMEOUT - setup Ircd->iface.
 */
static iftype_t _ircd_module_signal (INTERFACE *iface, ifsig_t sig)
{
  INTERFACE *tmp;
  int i;
  peer_priv *pp;
  char buff[MESSAGEMAX];

  if (Ircd == NULL) {
    ERROR("ircd: got signal but module already dead");
    return I_DIED;
  }
  switch (sig)
  {
    case S_TERMINATE:
      /* unregister everything */
      UnregisterVariable ("ircd-flags-first");
      UnregisterVariable ("ircd-flags-post");
      UnregisterVariable ("ircd-default-class");
      UnregisterVariable ("ircd-version-string");
      UnregisterVariable ("ircd-description-string");
      UnregisterVariable ("ircd-hold-period");
      UnregisterVariable ("ircd-serverclass-pingf");
      UnregisterFunction ("ircd");
      Delete_Binding ("ircd-auth", &_ircd_class_in, NULL);
      Delete_Binding ("ircd-register-cmd", &ircd_pass, NULL);
      Delete_Binding ("ircd-register-cmd", &ircd_quit_rb, NULL);
      Delete_Binding ("ircd-register-cmd", &ircd_server_rb, NULL);
      Delete_Binding ("ircd-server-cmd", (Function)&ircd_server_sb, NULL);
#if IRCD_MULTICONNECT
      Delete_Binding ("ircd-server-cmd", (Function)&ircd_iserver, NULL);
      Delete_Binding ("ircd-server-cmd", (Function)&ircd_inum, NULL);
#endif
#ifdef USE_SERVICES
//      Delete_Binding ("ircd-register-cmd", &ircd_service, NULL);
#endif
      Delete_Binding ("ircd-server-cmd", (Function)&ircd_service_sb, NULL);
      Delete_Binding ("ircd-register-cmd", &ircd_user, NULL);
      Delete_Binding ("ircd-register-cmd", &ircd_nick_rb, NULL);
      Delete_Binding ("ircd-client-cmd", &ircd_nick_cb, NULL);
      Delete_Binding ("ircd-server-cmd", (Function)&ircd_nick_sb, NULL);
//      Delete_Binding ("connect", &connect_ircd, NULL);
      Delete_Binding ("inspect-client", (Function)&incl_ircd, NULL);
      Delete_Binding ("connchain-grow", &_ccfilter_P_init, NULL);
#if IRCD_USES_ICONV
      Delete_Binding ("connchain-grow", &_ccfilter_U_init, NULL);
#endif
#if IRCD_MULTICONNECT
      Delete_Binding ("connchain-grow", &_ccfilter_I_init, NULL);
#endif
      Delete_Binding ("ircd-stats-reply", (Function)&_istats_l, NULL);
//      Delete_Binding ("ircd-stats-reply", (Function)&_istats_m, NULL);
      ircd_channel_proto_end();
      ircd_client_proto_end();
      ircd_server_proto_end();
      ircd_queries_proto_end();
      _ircd_signal (Ircd->iface, S_TERMINATE);
      FREE (&Ircd->token);
      FREE (&Ircd);
      _forget_(peer_priv);
      _forget_(CLASS);
      _forget_(CLIENT);
      _forget_(LINK);
      iface->ift |= I_DIED;
      dprint(2, "module ircd terminated succesfully");
      return I_DIED;
    case S_SHUTDOWN:
      for (pp = IrcdPeers; pp; pp = pp->p.priv) /* just notify everyone */
	_ircd_client_signal (pp->p.iface, S_SHUTDOWN);
      break;
    case S_REPORT:
      // TODO......
      break;
    case S_REG:
      _ircd_register_all();
      break;
    case S_TIMEOUT:
      //TODO: do validation of Nick before anything else?
      if (Ircd->iface)
      {
	Add_Request (I_LOG, "*", F_WARN, "ircd: stray S_TIMEOUT signal to module!");
	break;				/* ignore it */
      }
      /* find first valid IRCD record and use it, ignoring any others */
      _ircd_sublist_buffer = buff;
      tmp = Add_Iface (I_TEMP, NULL, NULL, &_ircd_sublist_receiver, NULL);
      i = Get_Clientlist (tmp, U_SPECIAL, ".logout", "ircd");
      if (i == 0)			/* ouch! no network record! */
      {
	tmp->ift = I_DIED;
	ERROR ("ircd: no network found! aborting now...");
	iface->ift |= I_FINWAIT;	/* schedule suicide */
	break;				/* it will be died anyway */
      }
      Set_Iface (tmp);
      Get_Request();
      Unset_Iface();
      tmp->ift = I_DIED;		/* done with it */
      if (gettoken (_ircd_sublist_buffer, NULL)) /* take one name from list */
      Ircd->iface = Add_Iface (I_SERVICE, _ircd_sublist_buffer, &_ircd_signal,
			       &_ircd_request, Ircd);
      strfcpy (MY_NAME, Nick, sizeof(MY_NAME)); /* unchangeable in runtime */
      strfcpy(ME.fname, _ircd_description_string, sizeof(ME.fname));
      Ircd->token = safe_calloc (TOKEN_ALLOC_SIZE, sizeof(CLIENT *));
      Ircd->s = TOKEN_ALLOC_SIZE;
      Ircd->token[0] = &ME;		/* set token 0 to ME */
      Insert_Key (&Ircd->clients, MY_NAME, &ME, 1); /* nothing to check? */
      /* continue with S_FLUSH too */
    case S_FLUSH:
      ircd_channels_flush (Ircd, _ircd_modesstring, sizeof(_ircd_modesstring));
      break;
    default: ;
  }
  return 0;
}

/*
 * this function called when you load a module.
 * Input: parameters string args.
 * Returns: address of signals receiver function, NULL if not loaded.
 */
SigFunction ModuleInit (char *args)
{
  CheckVersion;
  //return NULL;
  /* create main bindtables */
//  BTIrcdLinked = Add_Bindtable ("ircd-got-server", B_MASK);
//  BTIrcdUnlinked = Add_Bindtable ("ircd-lost-server", B_MASK);
  BTIrcdGotClient = Add_Bindtable ("ircd-got-client", B_MASK);
  BTIrcdLostClient = Add_Bindtable ("ircd-lost-client", B_MASK);
//  BTIrcdGotRemote = Add_Bindtable ("ircd-got-remote", B_MASK);
//  BTIrcdLostRemote = Add_Bindtable ("ircd-lost-remote", B_MASK);
  BTIrcdCollision = Add_Bindtable ("ircd-collision", B_UNIQMASK);
  BTIrcdAuth = Add_Bindtable ("ircd-auth", B_MASK);
  BTIrcdServerCmd = Add_Bindtable ("ircd-server-cmd", B_KEYWORD);
  BTIrcdClientCmd = Add_Bindtable ("ircd-client-cmd", B_UNIQ);
  BTIrcdRegisterCmd = Add_Bindtable ("ircd-register-cmd", B_UNIQ);
  BTIrcdClientFilter = Add_Bindtable ("ircd-client-filter", B_KEYWORD);
  BTIrcdDoNumeric = Add_Bindtable ("ircd-do-numeric", B_UNIQ);
  /* add every binding into them */
  Add_Binding ("ircd-auth", "*", 0, 0, &_ircd_class_in, NULL);
  Add_Binding ("ircd-register-cmd", "pass", 0, 0, &ircd_pass, NULL);
  Add_Binding ("ircd-register-cmd", "quit", 0, 0, &ircd_quit_rb, NULL);
  Add_Binding ("ircd-register-cmd", "server", 0, 0, &ircd_server_rb, NULL);
  Add_Binding ("ircd-server-cmd", "server", 0, 0, (Function)&ircd_server_sb, NULL);
#if IRCD_MULTICONNECT
  Add_Binding ("ircd-server-cmd", "iserver", 0, 0, (Function)&ircd_iserver, NULL);
  Add_Binding ("ircd-server-cmd", "inum", 0, 0, (Function)&ircd_inum, NULL);
#endif
#ifdef USE_SERVICES
//  Add_Binding ("ircd-register-cmd", "service", 0, 0, &ircd_service, NULL);
#endif
  Add_Binding ("ircd-server-cmd", "service", 0, 0, (Function)&ircd_service_sb, NULL);
  Add_Binding ("ircd-register-cmd", "user", 0, 0, &ircd_user, NULL);
  Add_Binding ("ircd-register-cmd", "nick", 0, 0, &ircd_nick_rb, NULL);
  Add_Binding ("ircd-client-cmd", "nick", 0, 0, &ircd_nick_cb, NULL);
  Add_Binding ("ircd-server-cmd", "nick", 0, 0, (Function)&ircd_nick_sb, NULL);
//  Add_Binding ("connect", "ircd", 0, 0, &connect_ircd, NULL);
  Add_Binding ("inspect-client", "ircd", 0, 0, (Function)&incl_ircd, NULL);
  Add_Binding ("connchain-grow", "P", 0, 0, &_ccfilter_P_init, NULL);
#if IRCD_USES_ICONV
  Add_Binding ("connchain-grow", "U", 0, 0, &_ccfilter_U_init, NULL);
#endif
#if IRCD_MULTICONNECT
  Add_Binding ("connchain-grow", "I", 0, 0, &_ccfilter_I_init, NULL);
#endif
  Add_Binding ("ircd-stats-reply", "l", 0, 0, (Function)&_istats_l, NULL);
//  Add_Binding ("ircd-stats-reply", "m", 0, 0, (Function)&_istats_m, NULL);
  Ircd = safe_calloc (1, sizeof(IRCD));
  ircd_channel_proto_start (Ircd);
  ircd_client_proto_start();
  ircd_server_proto_start();
  ircd_queries_proto_start();
  /* need to add interface into Ircd->iface ASAP! */
  _ircd_corrections = FloodType ("ircd-errors"); /* sets corrections */
  NewTimer (I_MODULE, "ircd", S_TIMEOUT, 1, 0, 0, 0);
  /* register everything */
  _ircd_register_all();
  return (&_ircd_module_signal);
}
#else /* if cannot use iconv */
SigFunction ModuleInit (char *args)
{
  ERROR ("Module ircd: need iconv but cannot use it, sorry.");
  return NULL;
}
#endif
