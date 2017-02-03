/*
 * Copyright (C) 2010-2017  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 * This file is a part of FoxEye IRCd module: connections and few bindings that
 *   require IrcdLock lock or (de)allocation of peer_priv, CLIENT, or LINK.
 *
 * TODO: make support for script bindings!
 */

#include "foxeye.h"
#include "modules.h"
#if IRCD_USES_ICONV == 0 || (defined(HAVE_ICONV) && (IRCD_NEEDS_TRANSLIT == 0 || defined(HAVE_CYRILLIC_TRANSLIT)))
#include "init.h"
#include "list.h"
#include "sheduler.h"
#include "conversion.h"
#include "socket.h"

#include <wchar.h>
#include <signal.h>

#define __IN_IRCD_C 1
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
  CLIENT *glob;		/* logged in in this class */
};

static char _ircd_default_class[64] = "2 2 100 90 1000"; /* lpul lpug lpc pingf sendq */
static char _ircd_flags_first[32] = "Z";	/* on start of connchain */
static char _ircd_flags_post[32] = "IPU";	/* allowed after 'x' filter */
static char _ircd_version_string[16] = "021000001100"; /* read only */
char _ircd_description_string[SHORT_STRING] = "";
long int _ircd_hold_period = 900;		/* 15 minutes, see RFC 2811 */
static long int _ircd_server_class_pingf = 30;	/* in seconds */
static bool _ircd_squit_youngest = TRUE;
static bool _ircd_statm_empty_too = FALSE;
static bool _ircd_trace_users = TRUE;
bool _ircd_public_topic = TRUE;
bool _ircd_idle_from_msg = FALSE;
static bool _ircd_default_invisible = TRUE;
static bool _ircd_wallop_only_opers = FALSE;
bool _ircd_no_spare_invites = FALSE;
bool _ircd_strict_modecmd = TRUE;
bool _ircd_ignore_mkey_arg = FALSE;
long int _ircd_max_bans = 30;
long int _ircd_max_channels = 20;

unsigned int _ircd_nicklen = NICKLEN;
static char _ircd_nicklen_str[16] = "";		/* read-only for everyone */

static short *_ircd_corrections;		/* for CheckFlood() */
short *_ircd_client_recvq;

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
static struct bindtable_t *BTIrcdLocalClient;
//static struct bindtable_t *BTIrcdSetClient;
static struct bindtable_t *BTIrcdClient;
static struct bindtable_t *BTIrcdDoNumeric;
static struct bindtable_t *BTIrcdCollision;
static struct bindtable_t *BTIrcdCheckSend;
static struct bindtable_t *BTIrcdGotServer;
static struct bindtable_t *BTIrcdLostServer;

/* access to IrcdPeers and allocators should be locked with this */
static pthread_mutex_t IrcdLock = PTHREAD_MUTEX_INITIALIZER;

static IRCD *Ircd = NULL;		/* our network we working on */

static peer_priv *_ircd_uplink = NULL;	/* RFC2813 autoconnected server */
#if IRCD_MULTICONNECT
static int _ircd_uplinks = 0;		/* number of autoconnects active */
#endif

static sig_atomic_t __ircd_have_started = 0;

static tid_t _uplinks_timer = -1;

static CLIENT ME = { .umode = A_SERVER, .via = NULL, .x.class = 0, .cs = NULL,
		     .c.lients = NULL, .hops = 0 };

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
  cl->glob = NULL;
  sscanf (parms, "%d %d %d %d %d", &cl->lpul, &cl->lpug, &cl->lpc,
	  &cl->pingf, &cl->sendq);
  dprint(2, "ircd:ircd.c: allocated new class: %s", NONULLP(name));
  return cl;
}

BINDING_TYPE_ircd_auth(_ircd_class_in);
static int _ircd_class_in (struct peer_t *peer, char *user, char *host,
			   const char **msg, modeflag *umode)
{
  LINK *link = ((peer_priv *)peer->iface->data)->link; /* really peer->link */
  struct clrec_t *cl;
  const char *clname;
  char *clparms = NULL;
  CLASS **clp;
  userflag uf = 0;
  char uh[HOSTMASKLEN+1];
  register CLASS *clcl;
  int locnt, glcnt;
  register CLIENT *td;

  snprintf (uh, sizeof(uh), "%s@%s", NONULL(user), host);
  dprint(2, "ircd:ircd.c: adding %s into class", uh);
  if (!Ircd->iface)			/* OOPS! */
  {
    Unset_Iface();
    *msg = "internal error";
    return 0;
  }
  DBG("ircd:ircd.c: trying find %s", uh);
  cl = Find_Clientrecord (uh, &clname, NULL, NULL);
  if (!cl) {				/* do matching by IP too */
    snprintf (uh, sizeof(uh), "%s@%s", NONULL(user), SocketIP(peer->socket));
    DBG("ircd:ircd.c: trying find %s", uh);
    cl = Find_Clientrecord (uh, &clname, NULL, NULL);
  }
  if (cl)
  {
    DBG("ircd:ircd.c: found matched");
    clparms = Get_Field (cl, Ircd->sub->name, NULL);
    uf = Get_Flags (cl, Ircd->iface->name);
  }
  if (clparms);
  else if (cl && clname && (clparms == NULL || clparms[0] == 0) &&
	   (uf & U_UNSHARED)) /* ok, it's a server */
  {
    DBG("ircd:ircd.c: user %s is server", clname);
    Unlock_Clientrecord (cl);
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
  DBG("ircd:ircd.c: got class: %s", clname);
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
  if (clcl->lin >= clcl->lpc)		/* class overloaded */
  {
    Unset_Iface();
    *msg = "too many users";
    return 0;
  }
  /* check for local and global limits */
  DBG("ircd:ircd.c: counting users in class");
  locnt = glcnt = 0;
  for (td = clcl->glob; td; td = td->pcl)
    if ((!user || !strcmp (td->user, link->cl->user)) &&
	!strcmp (td->host, link->cl->host)) {
      if (CLIENT_IS_LOCAL(td))
	locnt++;
      glcnt++;
    }
  Unset_Iface();
  if (locnt >= clcl->lpul)		/* local limit overloaded */
  {
    *msg = "too many users from this host on this server";
    return 0;
  }
  if (glcnt >= clcl->lpug)		/* global limit overloaded */
  {
    *msg = "too many users from this host";
    return 0;
  }
  DBG("ircd:CLASS: adding %p into class %p: prev %p", link->cl, clcl, clcl->glob);
  link->cl->x.class = clcl;		/* insert it into class */
  link->cl->pcl = clcl->glob;
  clcl->glob = link->cl;
#if IRCD_USES_ICONV
  DBG("ircd:ircd.c: setting charset %s", uh);
  if (*uh)				/* override charset with class' one */
  {
    Free_Conversion (peer->iface->conv);
    peer->iface->conv = Get_Conversion (uh);
  }
#endif
  clcl->lin++;
  DBG("ircd:ircd.c: %s@%s added to class %s", NONULL(user), host, clcl->name);
  return 1;
}

/* insert remote user into class */
static void _ircd_class_rin (LINK *l)
{
  struct clrec_t *cl;
  const char *clname;
  char *clparms = NULL;
  CLASS **clp;
  char uh[HOSTMASKLEN+1];
  register CLASS *clcl;

  if (!Ircd->iface)
    return;
  snprintf (uh, sizeof(uh), "%s@%s", l->cl->user, l->cl->host);
  dprint(2, "ircd:ircd.c: adding %s!%s (remote) into class", l->cl->nick, uh);
  cl = Find_Clientrecord (uh, &clname, NULL, NULL);
  /* host is reported by remote server so no other matching is possible */
  if (cl) {
    clparms = Get_Field (cl, Ircd->sub->name, NULL);
  }
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
  DBG("ircd:CLASS: adding %p into class %p: prev %p", l->cl, clcl, clcl->glob);
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

  if (cc == NULL) {
    ERROR("ircd:ircd.c: undefined class for %s!", link->cl->nick);
    return;
  }
  dprint(2, "ircd:ircd.c: removing %s from class %s", link->cl->nick, cc->name);
  /* removing from ->pcl */
  clp = &cc->glob;
  DBG("ircd:CLASS: removing %p from class %p", link->cl, cc);
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
  if (link->cl->via != NULL)	/* it's local client */
    cc->lin--;
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
      clparms = Get_Field (clu, Ircd->sub->name, NULL);
    else				/* class was removed, join to default */
    {
      register CLIENT **y;

      *clp = cls->next;
      for (y = &cls->glob; *y; y = &(*y)->pcl);
      *y = cld->glob;			/* tail it to global default */
      cld->glob = cls->glob;
      cld->lin += cls->lin;
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

  dprint(2, "ircd:CLIENT: deleting phantom %s: %p <= %p", cl->nick, cl, cl->pcl);
  *ptr = cl->pcl;
  if (cl->rfr != NULL)
    cl->rfr->x.rto = cl->x.rto;
  if (cl->x.rto != NULL)
    cl->x.rto->rfr = cl->rfr;
  DBG("ircd:CLIENT: removed phantom from relation: %p => (%p) => %p", cl->rfr, cl, cl->x.rto);
  free_CLIENT(cl);
}

#define _ircd_find_client_lc(x) Find_Key (Ircd->clients, x)

static inline CLIENT *_ircd_find_client (const char *name)
{
  char lcname[MB_LEN_MAX*NICKLEN+1];

  dprint(5, "ircd:ircd.c:_ircd_find_client: %s", name);
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
  DBG("ircd:token %hu freed", i);
}

static inline void _ircd_bt_client(CLIENT *cl, const char *on, const char *nn,
				   const char *server)
{
  struct binding_t *b = NULL;

  while ((b = Check_Bindtable(BTIrcdClient, cl->nick, U_ALL, U_ANYCH, b)))
    if (b->name == NULL)
      b->func(Ircd->iface, server, cl->lcnick, on, nn, cl->user, cl->host,
	      cl->fname, cl->umode, IrcdCli_num);
}

/* it's defined below */
static inline void _ircd_lserver_out (LINK *);

/*
 * puts message to peer and marks it to die after message is sent
 * any active user should be phantomized after call (i.e. have ->pcl
   and ->rfr pointers reset to collision list and 'renamed from')
 * does not remove it from server's list
 * this function should be thread-safe!
 */
static void _ircd_peer_kill (peer_priv *peer, const char *msg)
{
  CLIENT *cl;

  dprint(5, "ircd:ircd.c:_ircd_peer_kill: %p state=%#x", peer, (int)peer->p.state);
  if (peer->link == NULL) {		/* link might be not initialized yet */
    LOG_CONN ("ircd: killing unknown connection: %s", msg);
    peer->p.state = P_QUIT;
    return;
  }
  if (peer->p.state == P_QUIT || peer->p.state == P_LASTWAIT)
  {
    ERROR ("ircd:ircd.c:_ircd_peer_kill: diplicate call!");
    return;
  }
  cl = peer->link->cl;
  LOG_CONN ("ircd: killing peer %s@%s: %s", cl->user, cl->host, msg);
  New_Request (peer->p.iface, 0, "ERROR :closing link to %s@%s: %s",
	       cl->user, cl->host, msg);
  cl->umode &= ~A_UPLINK;		/* don't mix it with A_AWAY */
  Set_Iface (peer->p.iface);		/* lock it for next call */
  if (peer->p.state != P_DISCONNECTED) {
    if (CLIENT_IS_SERVER(cl))		/* remove from Ircd->servers */
      _ircd_lserver_out (peer->link);
    else if (peer->p.state != P_IDLE)	/* no class on broken uplink attempt */
      _ircd_class_out (peer->link);
  }
  if (peer->p.state == P_TALK) {
    if (CLIENT_IS_SERVER(cl)) {
      //TODO: BTIrcdUnlinked
    } else {
      ME.x.a.uc--;
      DBG("ircd:updated local users count to %u", ME.x.a.uc);
      _ircd_bt_client(cl, cl->nick, NULL, MY_NAME);
    }
  } else if (peer->p.state == P_IDLE)
    cl->umode |= A_UPLINK;		/* only for registering uplink */
  if (peer->t > 0) {
    FREE(&peer->i.token);
    peer->t = 0;
  }
  peer->p.state = P_QUIT;		/* it will die eventually */
  cl->pcl = NULL;			/* ensure cleanup */
#if IRCD_MULTICONNECT
  cl->on_ack++;				/* borrow a reference for now */
  /* note: server can be multiconnected and if it is then don't remove name */
  if (cl->via != peer || cl->alt != NULL)
  {
    DBG("ircd:_ircd_peer_kill: %s appear to be available by other way, will not"
	" touch name", cl->lcnick);
    if (cl->via == peer)
    {
      /* ensure CLIENT is not freed by _ircd_client_request() */
      cl->via = cl->alt;
      cl->alt = NULL;
    }
  }
  else
#endif
  /* phantomize user right away so it will be not foundable anymore */
  if (cl->lcnick[0])
  {
    /* converts active user into phantom on hold for this second */
    cl->hold_upto = Time;
    cl->away[0] = '\0';			/* it's used by nick change tracking */
    if (cl->rfr != NULL && cl->rfr->cs == cl) /* it's a nick holder */
    {
      cl->pcl = cl->rfr;
      cl->rfr = NULL;
    }
    DBG("ircd:_ircd_peer_kill: %s (%p) converted to phantom", cl->lcnick, cl);
  }
  Unset_Iface();
}

#if IRCD_MULTICONNECT
static inline void _ircd_recalculate_hops (void)
{
  unsigned short int i, hops;
  register CLIENT *t;
  int hassubs;

  dprint(5, "ircd:ircd.c:_ircd_recalculate_hops");
  for (i = 1; i < Ircd->s; i++) /* reset whole servers list */
    if ((t = Ircd->token[i]) != NULL)
    {
      if (t->via != NULL && t->via->link == NULL) {
	ERROR ("ircd: server %s has no valid link!", t->lcnick);
	t->hops = Ircd->s;
      } else if (!CLIENT_IS_LOCAL(t)) {
	t->via = NULL; /* don't reset local connects! */
	t->hops = Ircd->s;
      } else if (t->via != NULL && t->via->p.state == P_QUIT)
	DBG("ircd:ircd.c:_ircd_recalculate_hops: server %s is dying", t->lcnick);
      else
	DBG("ircd:ircd.c:_ircd_recalculate_hops: server %s is local (%hu)",
	    t->lcnick, t->hops);
      t->alt = NULL; /* reset data */
    }
  hops = 1;
  do /* set paths from servers tree */
  {
    hassubs = 0; /* reset mark */
    for (i = 1; i < Ircd->s; i++) /* iteration: scan whole servers list */
      if ((t = Ircd->token[i]) != NULL && t->hops == hops) /* do iteration */
      {
	register LINK *l;

	for (l = t->c.lients; l; l = l->prev) /* scan it's links */
	  if (CLIENT_IS_SERVER(l->cl)) /* check linked servers */
	  {
	    hassubs = 1; /* mark for next iteration */
	    if (l->cl->via == NULL || /* it's shortest, yes */
		l->cl->via->p.state == P_QUIT) /* or ->via is dead */
	    {
	      l->cl->hops = hops + 1;
	      l->cl->via = t->via;
	      DBG("ircd:ircd.c:_ircd_recalculate_hops: server %s seen via %s",
		  l->cl->lcnick, t->lcnick);
	    }
	    else if (l->cl->alt == NULL && t->via != l->cl->via)
	    {
	      DBG("ircd:ircd.c:_ircd_recalculate_hops: server %s alt path via %s",
		  l->cl->lcnick, t->lcnick);
	      if (!(l->cl->via->link->cl->umode & A_MULTI))
		ERROR("server %s has diplicate link while connected via RFC server %s",
		      l->cl->lcnick, l->cl->via->link->cl->lcnick);
	      else if (t->via->link->cl->umode & A_MULTI)
		l->cl->alt = t->via; /* don't set alt the same as via */
	      else
		ERROR("server %s has duplicate link to RFC server %s",
		      l->cl->lcnick, t->lcnick);
	    }
	  }
	  else if (l->cl->hops == Ircd->s)
	    l->cl->hops = hops + 1; /* reset hops for users */
      }
    hops++; /* do next iteration */
  } while (hassubs);
  /* TODO: in case of errors check ->via ??? */
  /* some servers don't get alternate paths but servers that we see them via
     can have alternates so let set alternates with those alternates */
  for (i = 1; i < Ircd->s; i++) /* iteration: scan whole servers list */
    if ((t = Ircd->token[i]) != NULL && t->alt == NULL && t->via != NULL)
    {
      t->alt = t->via->link->cl->alt;
      DBG("ircd:ircd.c:_ircd_recalculate_hops: server %s backup path via %s",
	  t->lcnick, t->alt ? t->alt->link->cl->lcnick : NULL);
    }
}
#endif

/*
 * note: 'nick holder' here and below is an active client which has the nick
 * and collided structures are linked to it
 *
 * returns:
 *  a) phantom with ->away matching via->p.dname
 *  b) or phantom matching "" if (a) not found
 * !!! both args should be not NULL and host client should be phantom !!!
 */
static inline CLIENT *_ircd_find_phantom(CLIENT *nick, peer_priv *via)
{
  CLIENT *resort = NULL;

  dprint(5, "ircd:ircd.c:_ircd_find_phantom %s via %s", nick->nick, via->p.dname);
  if (via->link->cl->umode & A_SERVER)
    while (nick) {
#if IRCD_MULTICONNECT
      if ((nick->hold_upto <= Time) && (nick->on_ack == 0));
#else
      if (nick->hold_upto <= Time);
#endif
      else if (!strcmp(nick->away, via->p.dname))
	return (nick);
      else if (resort == NULL && nick->away[0] == '\0')
	resort = nick;
      nick = nick->pcl;
    }
  return (resort);
}

/* sublist receiver interface (for internal usage, I_TEMP) */
static char *_ircd_sublist_buffer;	/* MESSAGEMAX sized! */

static int _ircd_sublist_receiver (INTERFACE *iface, REQUEST *req)
{
  if (req)
    strfcpy (_ircd_sublist_buffer, req->string, MESSAGEMAX);
  return REQ_OK;
}

/* declaration. caution, two functions calls each other recursively! */
static void _ircd_try_drop_collision(CLIENT **);

/* bounce collision seek pointer to some phantom
   if phantom lcnick is cleared then fill it and insert into Ircd->clients */
static void _ircd_bounce_collision(CLIENT *cl)
{
  register CLIENT *host;

  dprint(5, "ircd:ircd.c:_ircd_bounce_collision: bouncing collisions %s to %p",
	 cl->nick, cl);
  if (cl->lcnick[0] == '\0') /* it should take name */ {
    _ircd_try_drop_collision(&cl);
    if (cl == NULL)		/* it might be gone */
      return;
    strfcpy(cl->lcnick, cl->cs->lcnick, sizeof(cl->lcnick));
    if (Insert_Key(&Ircd->clients, cl->lcnick, cl, 1) < 0)
      ERROR("ircd:_ircd_bounce_collision: tree error on %s", cl->lcnick);
      /* FIXME: isn't it something fatal? */
    else
      dprint(2, "ircd:CLIENT: added phantom name %s", cl->lcnick);
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
  if (cl->on_ack > 0 || cl->hold_upto > Time)
#else
  if (cl->hold_upto > Time)
#endif
    return;			/* not expired yet */
  dprint (2, "ircd: dropping nick %s from hold (was on %s)", cl->nick, cl->host);
  if (cl->lcnick[0] != '\0') {	/* it had the nick key */
    if (Delete_Key(Ircd->clients, cl->lcnick, cl) < 0)
      ERROR("ircd:_ircd_try_drop_collision: tree error on %s (%p)", cl->lcnick, cl);
    else
      dprint(2, "ircd:CLIENT: del phantom name %s: %p", cl->lcnick, cl);
    cl = (*ptr)->pcl;
    if (cl != NULL)
      _ircd_bounce_collision(cl);
  }
  _ircd_real_drop_nick(ptr);	/* if rfr ot x.rto then shift */
}

/* drops every phantom starting from given but leave CLIENT structure
   if hold by acks so ircd_drop_ack can find it and free as soon no acks left */
static void _ircd_force_drop_collision(CLIENT **ptr)
{
  register CLIENT *cl = *ptr;

  if (cl->pcl != NULL)		/* reset pcl by recursion */
    _ircd_force_drop_collision(&cl->pcl);
#if IRCD_MULTICONNECT
  if (cl->on_ack > 0 || cl->hold_upto > Time)
#else
  if (cl->hold_upto > Time)
#endif
    dprint (2, "ircd: forcing drop nick %s from hold (was on %s)", cl->nick,
	    cl->host);
  else
    dprint (2, "ircd: dropping nick %s from hold (was on %s)", cl->nick, cl->host);
  if (cl->lcnick[0] != '\0') {	/* it had the nick key */
    if (Delete_Key(Ircd->clients, cl->lcnick, cl) < 0)
      ERROR("ircd:_ircd_force_drop_collision: tree error on %s (%p)", cl->lcnick, cl);
      //FIXME: it's fatal, isn't it?
    else
      dprint(2, "ircd:CLIENT: del phantom name %s: %p", cl->lcnick, cl);
    cl->lcnick[0] = '\0';
  }
#if IRCD_MULTICONNECT
  if (cl->on_ack > 0) {
    DBG("ircd: holding %s(%p) still until acks are gone", cl->nick, cl);
    cl->hold_upto = 1;		/* ircd_drop_ack will need it */
    cl->cs = cl;		/* ircd_drop_nick will need it */
    *ptr = NULL;		/* for caller satisfying */
    return;		/* ircd_drop_ack will call _ircd_try_drop_collision */
  }
#endif
  _ircd_real_drop_nick(ptr);	/* if rfr ot x.rto then shift */
}

/* create phantom client for old nick and set collision relations for it
   sets only relations with nick host (i.e. ->cs and ->pcl)
   relations with next/previous nick should be set by caller
   if returned client has ->cs pointed to itself then it's lonely one */
__attribute__((warn_unused_result)) static inline CLIENT *
	_ircd_get_phantom(const char *on, const char *lon)
{
  CLIENT *cl, *cl2;

  dprint(5, "ircd:ircd.c:_ircd_get_phantom: %s", on);
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
  dprint(2, "ircd:CLIENT: adding phantom %p", cl2);
  if (cl) {
    cl2->cs = cl;
    cl2->lcnick[0] = 0;
    if (cl->hold_upto == 0) {		/* active client */
      if (cl->rfr == NULL)		/* it has no relations */
	cl2->pcl = NULL;
      else if (cl->rfr->cs != cl) {	/* convert to nick holder */
	DBG("ircd:CLIENT: clearing phantom relation: %p => (%p)", cl->rfr, cl->rfr->x.rto);
	_ircd_try_drop_collision(&cl->rfr);
	if (cl->rfr != NULL && cl->rfr->x.rto == cl) {
	  /* client's previous nick is still kept on hold */
	  WARNING("ircd: previous nick %s of %s is lost due to collision",
		  cl->rfr->cs->lcnick, cl->lcnick);
	  cl->rfr->x.rto = NULL;
	} else /* else it's not our previous nick */
	  ERROR("ircd: illegal relation %p <= %p but %p => %p", cl, cl->rfr,
		cl->rfr, cl->rfr->x.rto);
	cl2->pcl = NULL;
      } else				/* it's a nick holder already */
	cl2->pcl = cl->rfr;
      cl->rfr = cl2;			/* set relation from keyholder */
    } else {				/* ok, phantom, just insert it */
      cl2->pcl = cl->pcl;
      cl->pcl = cl2;
    }
    dprint(2, "ircd:CLIENT: added phantom to name %s: %p shift %p", cl->lcnick,
	   cl2, cl2->pcl);
  } else {
    cl2->cs = cl2;
    cl2->pcl = NULL;			/* it's alone now */
    if (lon)
      strfcpy(cl2->lcnick, lon, sizeof(cl2->lcnick));
    if (Insert_Key (&Ircd->clients, cl2->lcnick, cl2, 1) < 0)
      ERROR("ircd:_ircd_get_phantom: tree error on adding %s", cl2->lcnick);
      /* FIXME: isn't it something fatal? */
    else
      dprint(2, "ircd:CLIENT: new phantom name %s: %p", cl2->lcnick, cl2);
  }
  strfcpy(cl2->nick, on, sizeof(cl2->nick));
  cl2->via = NULL;			/* no structures for this */
  cl2->local = NULL;
  cl2->host[0] = 0;			/* mark it to drop later */
  cl2->vhost[0] = 0;
  cl2->away[0] = 0;			/* it's used by nick tracking */
  cl2->umode = 0;
#if IRCD_MULTICONNECT
  cl2->on_ack = 0;
#endif
  /* fields c.hannels, hops, user, fname are irrelevant for phantoms */
  return (cl2);
}

static inline int _ircd_is_server_name (const char *lcc)
{
  if (!strchr (lcc, '.'))		/* it should have at least one dot */
    return 0;
  for ( ; *lcc; lcc++)
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

/* executes message from server */
static inline int _ircd_do_command (peer_priv *peer, int argc, const char **argv)
{
  struct binding_t *b = NULL;
  int i = 0;
  CLIENT *c;
  register CLIENT *c2;
  int t;
#if IRCD_MULTICONNECT
  ACK *ack;
#endif

  if (Ircd->iface)
  {
    /* check if message source is known for me */
    c = _ircd_find_client (argv[0]);
    /* check if this link have phantom instead of real client on nick */
    if (c == NULL || peer == NULL) ; /* skip check for internal call */
    else if (c->hold_upto != 0)
      /* link haven't got our NICK or KILL so track it */
      c = _ircd_find_phantom(c, peer);
    else if (c->rfr != NULL && c->rfr->cs == c && /* it's nick holder */
	     (c2 = _ircd_find_phantom(c->rfr, peer)) != NULL &&
	     c2->away[0] != '\0')
      c = c2;			/* found collision originated from this link */
    /* it's real client, check if message may come from the link */
    else if (c->cs->via != peer)
#if IRCD_MULTICONNECT
    if (!(peer->link->cl->umode & A_MULTI)) /* else if (X && Y) */
#endif
    {
      ERROR("ircd:invalid source %s from %s: invalid path", argv[0],
	    peer->link->cl->lcnick);
      if (CLIENT_IS_SERVER(c)) {
	ircd_do_squit(peer->link, peer, "invalid message source path");
	return (0);
      }
      return (ircd_recover_done(peer, "invalid message source path"));
      //TODO: RFC2813:3.3 - KILL for (c) if it's a client instead?
    }
    if (c == NULL) {
#if IRCD_MULTICONNECT
      if ((peer->link->cl->umode & A_MULTI) &&
	  strcasecmp (argv[1], "QUIT") == 0) {
	/* delayed QUIT message may need special care, client isn't
	   online for us anymore but we still should return ACK */
	New_Request(peer->p.iface, 0, "ACK QUIT %s", argv[0]);
	dprint(3, "ircd: message %s from %s seems to be delayed by %s", argv[1],
	       argv[0], peer->p.dname);
	return (1);
      }
#endif
      ERROR("ircd:invalid source [%s] from [%s]", argv[0],
	    peer ? peer->link->cl->lcnick : "internal call");
      /* drop link if argv[0] is server name (RFC2813) */
      if (peer && _ircd_is_server_name(argv[0]))
	ircd_do_squit(peer->link, peer, "invalid source");
      return (0);
    }
#if IRCD_MULTICONNECT
    //TODO: rewrite acks check for QUIT and NICK here!
    if (peer && c->hold_upto && !(CLIENT_IS_SERVER(c)) &&
	(ack = ircd_check_ack(peer, c, NULL)) && /* sender has quited/renamed */
	strcasecmp(argv[1], "NICK"))	/* ircd_nick_sb handles this case */
    {
      /* some backfired messages need special care right now */
      if (!strcasecmp (argv[1], "QUIT"))
	ack->contrary = 1;
      dprint(3, "ircd: message %s from %s seems to be delayed by %s", argv[1],
	     argv[0], peer->p.dname);
      return (1);
    }
#endif
    c2 = c;
    while (c2 != NULL && c2->hold_upto)
      c2 = c2->x.rto;		/* if it's phantom then go to current nick */
    if (c2 == NULL) {			/* sender has quited at last */
      dprint(3, "ircd: sender [%s] of message %s is offline for us", argv[0],
	     argv[1]);
#if IRCD_MULTICONNECT
      /* handle remote ":killed NICK :someone" message as well */
      if (peer != NULL && (peer->link->cl->umode & A_MULTI) &&
	  argc == 3 && !strcmp(argv[1], "NICK")) {
	New_Request(peer->p.iface, 0, "ACK NICK %s", argv[0]);
	/* ack sent, add phantom for new nick after old nick phantom */
	c2 = _ircd_get_phantom(argv[2], NULL);
	c2->hold_upto = Time + CHASETIMELIMIT;
	c2->x.rto = c->x.rto;
	if (c2->x.rto != NULL)
	  c2->x.rto->rfr = c2;
	c2->rfr = c;
	c->x.rto = c2;
      }
#endif
      return (1);		/* just ignore it then */
    } else
      c = c2;			/* it's not phantom at this moment */
    if (peer == NULL && peer->p.state != P_LOGIN && peer->p.state != P_IDLE &&
	CLIENT_IS_LOCAL(c) && !CLIENT_IS_SERVER(c))
    {
      /* internal call - client message simulation */
      if ((b = Check_Bindtable (BTIrcdClientCmd, argv[1], U_ALL, U_ANYCH, NULL)))
	if (!b->name)
	  return b->func (Ircd->iface, c->via, c->lcnick, c->user, c->host,
			  c->vhost, A_SERVER, argc - 2, &argv[2]);
      return 0;
    }
    if ((CLIENT_IS_ME(c) ||
	 (CLIENT_IS_LOCAL(c) && !CLIENT_IS_SERVER(c))) && peer != c->via)
    {
      /* we should never get our or our users messages back */
      ERROR ("ircd: message %s from %s seems looped back by %s", argv[1],
	     argv[0], peer ? peer->p.dname : "internal call");
      return (1);			/* ouch, it was looped back! */
    }
    t = client2token (c);
    while ((b = Check_Bindtable (BTIrcdServerCmd, argv[1], U_ALL, U_ANYCH, b)))
      if (!b->name)
	i |= b->func (Ircd->iface, peer ? &peer->p : NULL, t, argv[0],
		      c->lcnick, argc - 2, &argv[2]);
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
  int i, num;
  char buf[MESSAGEMAX];

  if ((tgt = ircd_find_client(argv[2], peer)) == NULL || CLIENT_IS_SERVER(tgt))
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
  num = atoi(argv[1]);
  if (peer != NULL && num < 100) /* special care for transit - see orig. ircd */
    num += 100;
  snprintf(&buf[ptr], sizeof(buf) - ptr, "%s:%s", ptr ? " " : "", argv[i]);
  b = Check_Bindtable(BTIrcdDoNumeric, argv[1], U_ALL, U_ANYCH, NULL);
  if (b && !b->name &&
      b->func(Ircd->iface, num, argv[2], tgt->umode, buf))
    return 1;				/* aborted by binding */
#if IRCD_MULTICONNECT
  if (CLIENT_IS_REMOTE(tgt) && id != -1)
  {
    ircd_sendto_new(tgt, ircd_find_client(argv[0], peer), peer,
		    ":%s INUM %d %03d %s %s", sender, id, num, argv[2], buf);
    ircd_sendto_old(tgt, ":%s %03d %s %s", sender, num, argv[2], buf);
  }
  else if (CLIENT_IS_REMOTE(tgt))
  {
    ircd_sendto_remote(tgt, ircd_find_client(argv[0], peer), peer,
		       ":%s %03d %s %s", sender, num, argv[2], buf);
  }
  else
#endif
    ircd_sendto_one(tgt, ":%s %03d %s %s", sender, num, argv[2], buf);
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

#if IRCD_MULTICONNECT
/* should be called after nick is deleted from Ircd->clients */
static inline void _ircd_move_acks (CLIENT *tgt, CLIENT *clone)
{
  dprint(5, "ircd:ircd.c:_ircd_move_acks: %s: %d", tgt->nick, tgt->on_ack);
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

static void _ircd_kill_collided(CLIENT *collided, peer_priv *pp, const char *by)
{
  if (!CLIENT_IS_REMOTE(collided))
    New_Request(collided->via->p.iface, 0, ":%s KILL %s :Nick collision from %s",
		MY_NAME, collided->nick, by); /* notify the victim */
#ifdef USE_SERVICES
  ircd_sendto_services_mark_all(Ircd, SERVICE_WANT_KILL);
#endif
  ircd_sendto_servers_all_ack(Ircd, collided, NULL, NULL,
			      ":%s KILL %s :Nick collision from %s", MY_NAME,
			      collided->nick, by); /* broadcast KILL */
  ircd_prepare_quit(collided, pp, "nick collision");
  collided->hold_upto = Time + CHASETIMELIMIT;
  Add_Request(I_PENDING, "*", 0, ":%s!%s@%s QUIT :Nick collision from %s",
	      collided->nick, collided->user, collided->vhost, by);
  collided->host[0] = '\0';		/* for collision check */
  Add_Request(I_LOG, "*", F_MODES, "KILL %s :Nick collision from %s",
	      collided->nick, by);
}

/* declaration, args: client, server-sender, sender token, new nick, is-casechange
   returns phantom client structure on hold by CHASETIMELIMIT */
static CLIENT *_ircd_do_nickchange(CLIENT *, peer_priv *, unsigned short, const char *, int);

/* checks nick for collision and if collision not found then returns NULL
   else may try to make a new nick for this one and rename collided
   if there is no solution then removes collided one and sets nick to ""
   in either case returns collided nick structure which caller should handle:
   either tail phantom to it or destroy it if new collided nick isn't phantom */
static CLIENT *_ircd_check_nick_collision(char *nick, size_t nsz, peer_priv *pp,
					  char *onserv)
{
  char *collnick;
  struct binding_t *b;
  CLIENT *collided;
  int res;
#define static register
  BINDING_TYPE_ircd_collision ((*f));
#undef static
  register CLIENT *test;

  dprint(5, "ircd:ircd.c:_ircd_check_nick_collision: %s from %s", nick, onserv);
  /* phase 1: check if collision exists and isn't expired */
  collided = _ircd_find_client(nick);
  if (collided && collided->hold_upto != 0) /* collision with phantom */
    _ircd_try_drop_collision(&collided);
  if (collided == NULL)
    return (collided);
  if (collided->hold_upto != 0) { /* check if it's a phantom after squit */
    CLIENT *tst;
    for (tst = collided; tst; tst = tst->pcl)
      if (tst->host[0] != 0 && !strcmp(tst->host, onserv)) {
	tst->hold_upto = 1;		/* drop hold as netsplit is over */
	break;
      }
    if (tst) DBG("_ircd_check_nick_collision: nick was after squit");
    _ircd_try_drop_collision(&collided);
    if (collided == NULL)
      return (collided);
  }
  /* phase 2: try to resolve collision making a solution */
  b = Check_Bindtable(BTIrcdCollision, "*", U_ALL, U_ANYCH, NULL);
  if (b == NULL || b->name) {		/* no binding or script binding? */
    res = 0;
    if (collided->hold_upto == 0)
      nick[0] = '\0';			/* both should be removed (RFC2812) */
    collnick = NULL;			/* initialize to avoid warning */
  } else {
    /* set res to 0 if collided is active and is renamed one so we are forced
       to change collided nick too or else we unable to resolve that */
    if (collided->hold_upto != 0 ||	/* either it's phantom */
	collided->rfr == NULL ||	/* or no collision before */
	collided->rfr->cs == collided)	/* or keyholder */
      res = 1;
    else
      res = 0;
    f = (char * (*)())b->func;
    collnick = f(Ircd->iface, nick, nsz, res, collided->cs->lcnick, onserv);
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
    } /* here res: 0 = kill collided, 1 = may leave it, 2 = rename it */
  }
  /* phase 3: apply solution to existing nick */
  if (collided->hold_upto != 0) {	/* collision with phantom */
    DBG("ircd:collision with nick %s on hold", collided->nick);
    /* caller should resolve this itself */
  } else if (res == 0) {		/* no solution from binding */
    _ircd_kill_collided(collided, pp, onserv);
  } else if (collnick != collided->nick) { /* binding asked to change collided */
    if (!CLIENT_IS_SERVICE(collided))	/* service cannot be renamed! */
      collided = _ircd_do_nickchange(collided, NULL, 0, collnick, 0);
    if (_ircd_find_client(nick)) { /* ouch! we got the same for both collided! */
      ERROR("ircd:collision resolving conflict for nick %s", nick);
      nick[0] = '\0';
    }
  } /* else binding decided to keep collided intact */
  return (collided);
}

/* do the same as _ircd_peer_kill but for remote user and thread-unsafe */
static void _ircd_remote_user_gone(CLIENT *cl)
{
  register LINK **s;
  LINK *l;

  dprint(2, "ircd:ircd.c:_ircd_remote_user_gone: %s", cl->nick);
  /* remove it from lists but from Ircd->clients */
  for (s = &cl->cs->c.lients; *s; s = &(*s)->prev)
    if ((*s)->cl == cl)
      break;
  if ((l = *s) != NULL)
    *s = l->prev;
  if (l != NULL)
    dprint(2, "ircd:CLIENT: removing client %s from %s: unshifted link %p prev %p",
	   cl->nick, cl->cs->lcnick, l, l->prev);
  if (l == NULL) {
    cl->pcl = NULL;
    cl->x.rto = NULL;
    ERROR("ircd: client %s not found in client list on server %s", cl->nick,
	  cl->cs->lcnick);
  } else if (cl->x.class == NULL) {
    cl->pcl = NULL;
    ERROR("ircd: client %s from %s is not in class", cl->nick, cl->cs->lcnick);
  } else {
    _ircd_class_out(l);
    if (cl->cs->x.a.uc > 0)
    {
      cl->cs->x.a.uc--;
      DBG("ircd:updated users count on %s to %u", cl->cs->lcnick, cl->cs->x.a.uc);
    }
    else
      ERROR("ircd:internal error with users count on %s", cl->cs->lcnick);
  }
  _ircd_bt_client(cl, cl->nick, NULL, cl->cs->lcnick); /* do bindtable */
  cl->cs = cl;		/* abandon server */
  /* converts active user into phantom on hold for this second */
  cl->hold_upto = Time;
  cl->away[0] = '\0';	/* it's used by nick change tracking */
  if (cl->rfr != NULL && cl->rfr->cs == cl) { /* it was a nick holder */
    cl->pcl = cl->rfr;
    cl->rfr = NULL;
    dprint(2, "ircd:CLIENT: converted holder %s (%p) into phantom, prev %p",
	   cl->nick, cl, cl->pcl);
  }
  /* cl->via is already NULL for remotes */
  pthread_mutex_lock (&IrcdLock);
  if (l != NULL)	/* free structure */
    free_LINK(l);
  pthread_mutex_unlock (&IrcdLock);
}


/* state	client		server		outgoing
 *
 * P_INITIAL	auth		auth		connected
 * P_LOGIN	registering	registering
 * P_IDLE					sent PASS+SERVER
 * P_TALK	got NICK+USER	got+sent SERVER	got SERVER
 */

/* -- client interface ----------------------------------------------------
   on terminating it does not kill interface but shedules death instead */
static iftype_t _ircd_client_signal (INTERFACE *cli, ifsig_t sig)
{
  peer_priv *peer = cli->data;
  const char *reason, *host;
  INTERFACE *tmp;
  size_t sw;
  char nstr[MB_LEN_MAX*NICKLEN+2];
  char buff[STRING];

  dprint(5, "ircd:ircd.c:_ircd_client_signal: name=%s sig=%d",
	 NONULL((char *)cli->name), (int)sig);
  switch (sig)
  {
    case S_REPORT:
      tmp = Set_Iface(cli);
      if (peer->link == NULL) {
	printl(buff, sizeof(buff), ReportFormat, 0, NULL, NULL, NULL,
	       NULL, 0, peer->p.socket + 1, (int)(Time - peer->started),
	       "unknown connection (startup)");
	New_Request(tmp, F_REPORT, "%s", buff);
	Unset_Iface();
	break;
      }
      if (peer->link->cl->umode & (A_OP | A_HALFOP))
	nstr[0] = '*';
      else if (peer->link->cl->umode & A_RESTRICTED)
	nstr[0] = '=';
      else
	nstr[0] = ' ';
      strfcpy(&nstr[1], peer->link->cl->nick, sizeof(nstr) - 1);
      if (peer->p.state == P_LOGIN || peer->p.state == P_TALK)
	host = peer->link->cl->host;
      else
	host = NULL;		/*host isn't valid if not P_LOGIN nor P_TALK */
      switch (peer->p.state) {
      case P_TALK:
	if (CLIENT_IS_SERVER(peer->link->cl))
	  reason = "active IRCD server connection";
#ifdef USE_SERVICES
	else if (CLIENT_IS_SERVICE(peer->link->cl))
	  reason = "active IRCD service connection";
#endif
	else
	  reason = "active IRCD client connection";
	break;
      case P_LASTWAIT:
      case P_QUIT:
	reason = "(IRCD) link is terminating";
	break;
      default:
	reason = "(IRCD) registering";
      }
      printl(buff, sizeof(buff), ReportFormat, 0, nstr, host,
	     CLIENT_IS_SERVER(peer->link->cl) ? peer->link->cl->lcnick :
						peer->link->cl->x.class->name,
	     NULL, 0, peer->p.socket + 1, (int)(Time - peer->noidle), reason);
      New_Request(tmp, F_REPORT, "%s", buff);
      Unset_Iface();
      break;
    case S_TERMINATE:
      switch (peer->p.state)
      {
	case P_DISCONNECTED:		/* there is a thread still */
	case P_INITIAL:
	  pthread_cancel (peer->th);
	  Unset_Iface();		/* let it to finish bindings */
	  pthread_join (peer->th, NULL);
	  Set_Iface(cli);
	case P_LOGIN:			/* isn't registered yet */
	case P_IDLE:
	  sw = (peer->link != NULL && peer->link->cl->umode & A_UPLINK) ? 1 : 0;
					/* no peer->link yet if P_DISCONNECTED */
	  if (ShutdownR)
	    _ircd_peer_kill (peer, ShutdownR);
	  else
	    _ircd_peer_kill (peer, "Connection timeout");
	  if (sw)			/* couldn't connect uplink, retry */
	    peer->link->cl->umode |= A_UPLINK;
	case P_QUIT:			/* shutdown is in progress */
	case P_LASTWAIT:
	  cli->ift &= ~I_FINWAIT;	/* don't kill me again */
	  break;
	case P_TALK:			/* shedule death to it */
	  if (peer->p.last_input == 0)
	    reason = "Ping timeout";
	  else if (peer->p.last_input < 0)
	    reason = SocketError(peer->p.last_input, buff, sizeof(buff));
	  else if (ShutdownR)
	    reason = ShutdownR;
	  else
	    reason = "Link broken";
	  if (CLIENT_IS_SERVER (peer->link->cl))
	    ircd_do_squit (peer->link, peer, reason);
	  else
	  {
#ifdef USE_SERVICES
	    ircd_sendto_services_mark_nick (Ircd, SERVICE_WANT_QUIT | SERVICE_WANT_RQUIT);
#endif
	    ircd_sendto_servers_all_ack (Ircd, peer->link->cl, NULL, NULL,
					 ":%s QUIT :%s", peer->p.dname, reason);
	    ircd_prepare_quit (peer->link->cl, peer, reason);
#ifdef USE_SERVICES
	    ircd_sendto_services_mark_prefix (Ircd, SERVICE_WANT_QUIT | SERVICE_WANT_RQUIT);
#endif
	    peer->link->cl->hold_upto = Time;
	    Add_Request (I_PENDING, "*", 0, ":%s!%s@%s QUIT :%s", peer->p.dname,
			 peer->link->cl->user, peer->link->cl->vhost, reason);
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

#define _ircd_start_timeout 90
				//FIXME: it should be config variable!

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
  int argc, i, p, p0;
  char buff[MB_LEN_MAX*IRCMSGLEN+1];
#if IRCD_USES_ICONV
  char sbuff[MB_LEN_MAX*IRCMSGLEN+1];
#endif
  register LINK **ll;

//  dprint(5, "ircd:ircd.c:_ircd_client_request: name=%s state=%d req=%p",
//	 cli->name, peer ? (int)peer->p.state : -1, req);
  if (peer->p.state < P_LOGIN) {
    if (req != NULL)
      WARNING("ircd:_ircd_client_request: got request to client which isn't ready");
    if (Time >= peer->started + _ircd_start_timeout) {
      c = (char *)SocketIP(peer->p.socket);
      LOG_CONN("ircd: timeout on connection start from %s", NONULLP(c));
      _ircd_client_signal(cli, S_TERMINATE);
    }
    return REQ_OK;
  }
  if (peer->link == NULL) {	/* it's P_QUIT after timeout or emergency */
    Peer_Cleanup (&peer->p);
    pthread_mutex_lock (&IrcdLock);
    for (pp = &IrcdPeers; *pp; pp = &(*pp)->p.priv)
      if ((*pp) == peer) {
	*pp = peer->p.priv;
	break;
      }
    free_peer_priv (peer);
    pthread_mutex_unlock (&IrcdLock);
    cli->data = NULL;		/* disown data */
    cli->ift |= I_DIED;
    return REQ_OK;
  }
  cl = peer->link->cl;
  switch (peer->p.state)
  {
    case P_QUIT: /* at this point it should be not in local class/servers list */
      if (req)
      {
	if (strncmp (req->string, "ERROR ", 6) &&
	    strncmp (NextWord(req->string), "465 ", 4) && /* ERR_YOUREBANNEDCREEP */
	    strncmp (NextWord(req->string), "KILL ", 5))
	  return REQ_OK;	/* skip anything but ERROR or KILL message */
	DBG("sending last message to client \"%s\"", cl->nick);
	sw = strlen (req->string);
	if (sw && Peer_Put ((&peer->p), req->string, &sw) == 0)
	  return REQ_REJECTED;	/* try again later */
	return REQ_OK;		/* let every ERROR/KILL be delivered */
      }
      Rename_Iface(cli, NULL);	/* delete it from everywhere before checks */
      if (cl->pcl != NULL)
	_ircd_try_drop_collision(&cl->pcl);
#if IRCD_MULTICONNECT
      if (cl->on_ack < 1)
      {
	ERROR("ircd:invalid reference count on quit: %d < 1", cl->on_ack);
	cl->on_ack++;		/* it is required */
      }
      /* note: server can be multiconnected and if so then cl->via != peer */
      if (cl->via == peer)
#endif
      /* check if it's not a nick holder */
      if (cl->pcl == NULL && cl->lcnick[0])
      {
	/* name is not needed anymore, drop it from tree */
	if (Delete_Key (Ircd->clients, cl->lcnick, cl) < 0)
	  ERROR("ircd:CLIENT: on quit: tree error on %s (%p)", cl->lcnick, cl);
	else
	  dprint(2, "ircd:CLIENT: del quitting name %s: %p", cl->lcnick, cl);
      }
      /* cleanup on local indication, it's not even a valid connect anymore */
      cl->local = NULL;
      if (peer == _ircd_uplink)
	_ircd_uplink = NULL;
      NoCheckFlood (&peer->penalty); /* no more messages will be accepted */
      if (cl->umode & (A_SERVER | A_UPLINK)) { /* was it autoconnect who left? */
	if ((cl->umode & A_UPLINK) || /* we may don't have lcnick set yet */
	    (Get_Clientflags (cl->lcnick, Ircd->iface->name) & U_AUTO))
	{
#if IRCD_MULTICONNECT
	  _ircd_uplinks--;
#endif
	  _ircd_init_uplinks();	/* recheck uplinks list */
	}
      } else {			/* clear any collision relations */
	/* it's either not logged or phantom at this point */
	if (cl->rfr != NULL)
	  _ircd_try_drop_collision(&cl->rfr);
	/* cl->rfr is 'from' and cl->pcl is 'next holded' now */
	if (cl->x.rto != NULL)
	  ERROR("ircd:CLIENT: impossible relation (%p) => %p", cl, cl->x.rto);
	cl->x.rto = NULL;	/* cleanup */
	/* we have ->cs to itself for local client always, ->pcl is set above
	   and ->x.rto is NULL for non-phantoms after leaving class */
	if (cl->pcl != NULL) {
	  /* it's a nick holder still, keep it */
#if IRCD_MULTICONNECT
	} else if (cl->hold_upto <= Time && cl->on_ack == 1) {
#else
	} else if (cl->hold_upto <= Time) {
#endif
	  if (cl->rfr != NULL) {
	    DBG("ircd:CLIENT: clearing relation %p => (%p)", cl->rfr, cl);
	    WARNING("ircd: next nick %s of %s is lost", cl->nick,
		    cl->rfr->cs->nick);
	    cl->rfr->x.rto = NULL; /* drop this reference */
	    cl->rfr = NULL;
	  }
	  cl->lcnick[0] = 0;	/* we deleted the key above */
	} else {
	  register CLIENT *phantom;

	  phantom = _ircd_get_phantom(cl->nick, cl->lcnick);
	  phantom->x.rto = NULL;
	  phantom->rfr = cl->rfr;
	  cl->rfr = NULL;
	  if (phantom->rfr != NULL)
	    phantom->rfr->x.rto = phantom;
	  DBG("ircd:CLIENT: phantom relation changed: %p => (%p)%p", cl->rfr, cl, phantom);
	  phantom->hold_upto = cl->hold_upto;
#if IRCD_MULTICONNECT
	  cl->on_ack--;		/* it was a borrowed reference */
	  _ircd_move_acks(cl, phantom);
	  cl->on_ack++;		/* restore the status quo */
#endif
	  cl->lcnick[0] = 0;	/* we deleted the key */
	}
      }
      if (!CLIENT_IS_SERVER(cl)) { /* should be done for incomplete uplink too */
	DBG("ircd:CLIENT: unshifting %p prev %p", peer->link, peer->link->prev);
	pthread_mutex_lock (&IrcdLock);
	for (ll = &ME.c.lients; *ll != NULL; ll = &(*ll)->prev)
	  if (*ll == peer->link)
	    break;
	if (*ll != NULL)
	  *ll = peer->link->prev;
	else
	  ERROR("ircd:could not find %s in local client list", cl->nick);
	pthread_mutex_unlock (&IrcdLock);
	peer->link->where = NULL;
      } /* and it is not in any list except peers now */
      else if (cl->c.lients != NULL)
#if IRCD_MULTICONNECT
	/* it's not an error if server is still multiconnected elsewhere */
	if (cl->via == peer)
#endif
	ERROR("ircd:clients list on dead server %s isn't empty!", cl->lcnick);
      peer->p.state = P_LASTWAIT;
    case P_LASTWAIT:
      sw = 0;			/* trying to send what is still left */
      sr = Peer_Put ((&peer->p), NULL, &sw);
      if (sr == 0)
	return REQ_OK;		/* still something left, OK, will try later */
      //TODO: read 'message of death' from connchain and log it
      Peer_Cleanup (&peer->p);
      cli->data = NULL;		/* disown it */
      cli->ift |= I_DIED;
      pthread_mutex_lock (&IrcdLock);
      for (pp = &IrcdPeers; *pp; pp = &(*pp)->p.priv)
	if ((*pp) == peer)
	{
	  *pp = peer->p.priv;
	  break;
	}
      free_LINK (peer->link);	/* free all structures */
      dprint(2, "ircd: link %p freed", peer->link);
#if IRCD_MULTICONNECT
      cl->on_ack--;		/* a borrowed reference, see _ircd_peer_kill() */
      if (cl->via == peer && cl->pcl == NULL && cl->on_ack == 0)
#else
      if (cl->via == peer && cl->pcl == NULL)
#endif
      {
	/* neither server still connected, nor acks/nick holder */
	dprint(2, "ircd:CLIENT: deleting client %p", cl);
	free_CLIENT (cl);
      } else
	dprint(5, "ircd:ircd.c:_ircd_client_request: leaving dying client %s intact",
	       cl->lcnick);
      free_peer_priv (peer);
      pthread_mutex_unlock (&IrcdLock);
      return REQ_OK;		/* interface will now die */
    case P_DISCONNECTED:	/* unused here, handled above */
    case P_INITIAL:		/* and this one too */
    case P_LOGIN:
    case P_TALK:
    case P_IDLE:
      sw = 0;
      if (Peer_Put ((&peer->p), "", &sw) == CONNCHAIN_READY && req) {
	b = NULL;
	if (req->string[0] == ':')
	  c = NextWord (req->string);
	else
	  c = req->string;
	sw = 0;
	while (*c && *c != ' ' && sw < sizeof(buff) - 1)
	  buff[sw++] = *c++; /* get command itself */
	buff[sw] = 0;
	while ((b = Check_Bindtable (BTIrcdCheckSend, buff, U_ALL, U_ANYCH, b)))
	  if (!b->name && !b->func (Ircd, &peer->p, peer->link->cl->umode,
				    req->string, sizeof(req->string)))
	    break; /* binding has cancelled sending of message */
	sw = strlen(req->string);
	sr = sw + 1;			/* for statistics */
	if (b != NULL)
	  req = NULL;			/* cancelled */
	else if (Peer_Put ((&peer->p), req->string, &sw) > 0)
	{
	  peer->ms++;
	  peer->bs += sr;
	  req = NULL;			/* it's done */
	}
	/* else check if sendq hasn't exceeded limit */
	else if (!(cl->umode & (A_SERVER | A_SERVICE)))
	{
	  if (cl->x.class == NULL) {
	    ERROR("ircd:classless client %s from %s", cl->nick, cl->cs->lcnick);
	    if (cli->qsize > IRCD_DEFAULT_SENDQ)
	      goto _sendq_exceeded;
	  } else if (cli->qsize > cl->x.class->sendq) {
_sendq_exceeded:
	    ShutdownR = "Max SendQ exceeded";
	    _ircd_client_signal(cli, S_TERMINATE);
	    ShutdownR = NULL;
	  }
	}
	//FIXME: do any sendq check for server/service too?
      }
      break;
  }
  if (!(cl->umode & (A_SERVER | A_SERVICE)) &&
      peer->penalty > _ircd_client_recvq[1])
    sr = 0;				/* apply penalty on flood from clients */
  else while ((sr = Peer_Get ((&peer->p), buff, sizeof(buff))) > 0)
  {					/* we got a message from peer */
    peer->p.last_input = Time;
    peer->mr++;				/* do statistics */
    peer->br += sr;
    sr = unistrcut (buff, sr, IRCMSGLEN - 2); /* cut input message */
#if IRCD_USES_ICONV
    c = sbuff;
    sr = Do_Conversion (cli->conv, &c, sizeof(sbuff) - 1, buff, &sr);
#else
    c = buff;
#endif
    c[sr] = '\0';
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
    p0 = p = 1;
    argv[argc] = NULL;
    if (!*argv[1]);			/* got malformed line */
    else if (!Ircd->iface);		/* internal error! */
    else if (peer->p.state == P_QUIT)	/* killed by processing */
      dprint(4, "ircd: got message \"%s\" from killed \"%s\"", argv[1], cl->nick);
    else if (peer->p.state == P_LOGIN ||
	     peer->p.state == P_IDLE)	/* not registered yet */
    {
      b = NULL;
      while ((b = Check_Bindtable (BTIrcdClientFilter, argv[1], peer->p.uf,
				   U_ANYCH, b)))
	if (!b->name)
	{
	  if ((p0 = b->func (Ircd->iface, &peer->p, cl->umode, argc - 2,
			     &argv[2])) == 0)
	    break;			/* it's consumed so it's done */
	  else if (p0 > p)
	    p = p0;
	}
      b = NULL;
      if (p0 == 0)
	i = 1;				/* binding sent reply itself */
      else
	b = Check_Bindtable (BTIrcdRegisterCmd, argv[1], U_ALL, U_ANYCH, NULL);
      if (b)
	if (!b->name)
	  i = b->func (Ircd->iface, &peer->p, argc - 2, &argv[2]);
    } else if (!*argv[0])
      WARNING("ircd: invalid prefix from peer \"%s\"", peer->p.dname);
    else if (CLIENT_IS_SERVER (cl))	/* got server protocol input */
    {
      if (strcmp (argv[0], MY_NAME) == 0) /* got my own message from the peer */
      {
	ERROR("ircd:server %s sent my \"%s\" back to me", cl->lcnick, argv[1]);
	ircd_recover_done (peer, "Invalid sender"); /* it might get squit */
	i = -1;				/* don't do ircd_recover_done() again */
      }
      else
	i = _ircd_do_server_message (peer, argc, argv);
    }
    else				/* got client protocol input */
    {
      b = NULL;
      while ((b = Check_Bindtable (BTIrcdClientFilter, argv[1], peer->p.uf,
				   U_ANYCH, b)))
	if (!b->name)
	{
	  if ((p0 = b->func (Ircd->iface, &peer->p, cl->umode, argc - 2,
			     &argv[2])) == 0)
	    break;			/* it's consumed so it's done */
	  else if (p0 > p)
	    p = p0;
	}
      if (p0 == 0)
	i = 1;				/* binding sent reply itself */
      else
	if ((b = Check_Bindtable (BTIrcdClientCmd, argv[1], peer->p.uf, U_ANYCH,
				  NULL)))
	  if (!b->name)			/* passed thru filter and found cmd */
	    i = b->func (Ircd->iface, &peer->p, cl->lcnick, cl->user, cl->host,
			 cl->vhost, cl->umode, argc - 2, &argv[2]);
    }
    cl = peer->link->cl;		/* binding might change it! */
    if (i == 0)				/* protocol failed */
    {
      if (peer->p.state == P_QUIT) ;	/* no reply to a killed client */
      else if (CLIENT_IS_SERVER (cl))
	ircd_recover_done (peer, "Invalid command"); /* it might get squit */
      else
	ircd_do_unumeric (cl, ERR_UNKNOWNCOMMAND, cl, 0, argv[1]);
    }
    else if (!_ircd_idle_from_msg && i > 0)
      peer->noidle = Time;		/* for idle calculation */
    /* we accepted a message, apply antiflood penalty on client */
    if (!(cl->umode & (A_SERVER | A_SERVICE)) && p >= 0) {
      while (p-- > 1)			/* apply extra penalties */
	CheckFlood (&peer->penalty, _ircd_client_recvq);
      if (CheckFlood (&peer->penalty, _ircd_client_recvq) > 0) {
	dprint(4, "ircd: flood from %s, applying penalty on next message",
	       cl->nick);
	break;				/* don't accept more messages */
      }
    }
  }
  if (peer->p.state == P_QUIT)		/* died in execution! */
    return REQ_OK;
  else if (peer->p.state != P_TALK)
    i = _ircd_start_timeout;		/* don't send PING at registering */
  else if (CLIENT_IS_SERVER(cl))
    i = _ircd_server_class_pingf;
  else
    i = cl->x.class->pingf;
  if (sr < 0) {
    peer->p.last_input = sr;
    cli->ift |= I_FINWAIT;
  } else if (Time > (peer->p.last_input + (i<<1))) {
    peer->p.last_input = 0;
    cli->ift |= I_FINWAIT;		/* suicide */
  } else if (Time >= (peer->p.last_input + i) && !(cl->umode & A_PINGED)) {
    cl->umode |= A_PINGED;		/* ping our peer */
    if (peer->p.state == P_TALK)	/* but don't send while registering */
      New_Request (cli, F_QUICK, "PING %s", MY_NAME);
  }
  if (req)
    return REQ_REJECTED;		/* retry it later */
  return REQ_OK;
}

/*
 * listfile records:
 * hosts for servers are in form [ident[:pass]@]host[/port[%flags]]
 *   they cannot (and should not) be checked after connect but will be checked
 *   after we got SERVER message
 *   host record can be used for connect or for autoconnect
 *   pass and port[%flags] in it are used for uplink connect only
 * hosts for classes should be in form x@y - there is no nick on check for it
 * passwd is encrypted password for incoming connect
 * info is description
 *
 * subrecord for network:
 * flags for servers are U_UNSHARED (ircd_server_rb)
 * flags for autoconnect are U_AUTO (_ircd_init_uplinks, ircd_server_rb)
 * flags for restricted class are U_DEOP (_ircd_got_local_user)
 * flags for kill are U_DENY (_ircd_got_local_user)
 * flags for exempt are U_ACCESS
 * content is:
 *   empty for server (not usable as there is no class anyway)
 *   not empty for any classes: ul/loc uh/glob u/class pingfreq sendq
 *
 * as exception there might be kill records with mask including nick, such
 * records will be checked after completed registration and client still
 * will be killed, no other records could be applied.
 *
 * '.connect' is there: .connect server@network [port]
 *   should use server record and check network subrecord;
 *   using password, port, and flags from hostrecord; port may replace one
 */

static inline size_t _ircd_make_hello_msg(char *buff, size_t bs, int num,
					  const char *template)
{
  size_t sw;

  sw = snprintf(buff, bs, ":%s %03d %s ", MY_NAME, num, MY_NAME);
  /* macros: %# - network name */
  printl(&buff[sw], bs - sw, template, 0, NULL, NULL, NULL, Ircd->iface->name,
	 0, 0, (time_t)0, NULL);
  return (strlen(buff));
}

/* -- ircd listener interface ---------------------------------------------
   called right after socket was answered or listener died */
static void _ircd_prehandler (pthread_t th, void **data, idx_t *as)
{
  peer_priv *peer;
  char *pn;		/* [host/]port[%flags] */
  size_t sw;
#if IRCD_USES_ICONV
  char charset[128];	/* I hope it's enough */
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
  peer->p.dname = NULL;
  peer->p.network_type = "ircd";
  peer->p.state = P_DISCONNECTED;
  peer->p.priv = IrcdPeers;
  peer->p.modules_data = NULL;
  IrcdPeers = peer;
  peer->t = 0;
  peer->link = NULL;
  pthread_mutex_unlock (&IrcdLock);
  peer->p.socket = *as;
  peer->p.connchain = NULL;
  peer->p.start[0] = 0;
  peer->bs = peer->br = peer->ms = peer->mr = 0;
  peer->th = th;
  peer->penalty = 0;
  while (__ircd_have_started == 0) sleep(1); /* wait for main thread */
  /* lock dispatcher and create connchain */
  Set_Iface (NULL);
  if ((pn = strchr (pn, '%')))		/* do custom connchains for SSL etc. */
    while (*++pn)
      if (*pn != 'x' && !Connchain_Grow (&peer->p, *pn))
	KillSocket (&peer->p.socket);	/* filter failed and we own the socket */
  Connchain_Grow (&peer->p, 'x');	/* text parser is mandatory */
  peer->p.last_input = peer->started = Time;
  peer->i.nvited = NULL;
  /* create interface */
  peer->p.iface = Add_Iface (I_CLIENT | I_CONNECT, NULL, &_ircd_client_signal,
			     &_ircd_client_request, peer);
#if IRCD_USES_ICONV
  if (*charset)
    peer->p.iface->conv = Get_Conversion (charset);
  else
    peer->p.iface->conv = NULL;
#endif
  /* cannot do ircd_do_unumeric so have to handle and send it myself
     while in listening thread yet
     note: listener will wait it, can we handle DDoS here? */
  sw = _ircd_make_hello_msg(charset, sizeof(charset), RPL_HELLO);
  Unset_Iface();
  if (Peer_Put((&peer->p), charset, &sw) > 0) /* connchain should eat it */
    while (Peer_Put((&peer->p), NULL, &sw) == 0); /* wait until data sent */
}

#define peer ((peer_priv *)data)
/* we got ident and host so can continue, cln is NULL here */
static void _ircd_handler (char *cln, char *ident, const char *host, void *data)
{
  register CLIENT *cl;
  const char *msg;
  struct binding_t *b;

  dprint(5, "ircd:ircd.c:_ircd_handler: %s@%s", NONULL(ident), host);
  /* set parameters for peer */
  pthread_mutex_lock (&IrcdLock);
  peer->link = alloc_LINK();
  peer->link->cl = cl = alloc_CLIENT();
  peer->link->where = &ME;
  dprint(2, "ircd:CLIENT: adding %p: local link %p prev %p", peer->link->cl,
	 peer->link, ME.c.lients);
  peer->link->prev = ME.c.lients;
  peer->link->flags = 0;
  ME.c.lients = peer->link;
  cl->via = peer;
  cl->local = peer;
  cl->x.class = NULL;
  peer->p.state = P_INITIAL;
  pthread_mutex_unlock (&IrcdLock);
  unistrlower (cl->user, NONULL(ident), sizeof(cl->user));
  unistrlower (cl->host, host, sizeof(cl->host));
  cl->vhost[0] = 0;
  cl->pcl = NULL;
  cl->cs = cl;
  cl->umode = 0;
  cl->nick[0] = 0;
  cl->lcnick[0] = 0;
  cl->fname[0] = 0;
  cl->away[0] = 0;
  cl->hold_upto = 0;
  cl->c.hannels = NULL;
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
      int res = b->func (&peer->p, ident, host, &msg, &cl->umode);
      Set_Iface (peer->p.iface);	/* regain lock */
      if (res == 0)
	break;				/* auth error */
    }
  peer->p.state = P_LOGIN;
  pthread_detach(pthread_self());	/* don't let thread turn into zombie */
  Unset_Iface();			/* done so unlock bindtable */
  if (msg)				/* not allowed! */
    _ircd_peer_kill (peer, msg);
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
    args = NextWord_Unquoted (&buff[s+1], (char *)args, sizeof(buff) - s - 2);
    conv = Get_Conversion (&buff[s+1]);
    if (conv) {
      buff[s++] = '-';
      s += strlen (&buff[s]);
      buff[s++] = ' ';
    } else
      Add_Request(I_LOG, "*", F_WARN, "ircd: using default charset for ircd %s",
		  args);
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
  const char *reason;
  INTERFACE *tmp;
  char nstr[MB_LEN_MAX*NICKLEN+2];
  char buff[STRING];

  dprint(5, "ircd:ircd.c:_ircd_uplink_sig: name=%s sig=%d", uli->name, (int)sig);
  if (!uplink)				/* already terminated */
    return I_DIED;
  switch (sig)
  {
    case S_REPORT:
      tmp = Set_Iface (uli);
      nstr[0] = ' ';
      strfcpy (&nstr[1], uplink->link->cl->nick, sizeof(nstr) - 1);
      switch (uplink->p.state) {
      case P_DISCONNECTED:
	reason = "connecting to IRCD server";
	break;
      case P_LASTWAIT:
      case P_QUIT:
	reason = "(IRCD) aborting connection";
	break;
      default:
	reason = "(IRCD) registering";
      }
      printl (buff, sizeof(buff), ReportFormat, 0, nstr, uplink->link->cl->host,
	      uplink->link->cl->lcnick, NULL, 0, uplink->p.socket + 1, 0, reason);
      New_Request(tmp, F_REPORT, "%s", buff);
      Unset_Iface();
      break;
    case S_TERMINATE:
      /* free everything including socket */
      pthread_cancel (uplink->th);
      pthread_join (uplink->th, NULL); /* it never locks dispatcher */
      Peer_Cleanup (&uplink->p);
#if IRCD_MULTICONNECT
      _ircd_uplinks--;
#endif
      pthread_mutex_lock (&IrcdLock);
      for (ull = &IrcdPeers; *ull; ull = &(*ull)->p.priv)
	if (*ull == uplink) {
	  *ull = uplink->p.priv;	/* remove it from list */
	  break;
	}
      dprint(2, "ircd:CLIENT: deleting uplink %s (%p): unshifting link %p prev %p",
	     uplink->link->cl->lcnick, uplink, uplink->link, uplink->link->prev);
      for (ll = &ME.c.lients; *ll != NULL; ll = &(*ll)->prev)
	if (*ll == uplink->link)
	  break;
      if (*ll != NULL)
	*ll = uplink->link->prev;
      else
	ERROR("ircd:uplink %s not found in local clients list",
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

//  dprint(5, "ircd:ircd.c:_ircd_uplink_req: name=%s state=%d req=%p",
//	 NONULL(uli->name), (int)_uplink->p.state, req);
  ul = _ircd_find_client_lc (uli->name);
  if (ul && !ul->hold_upto && CLIENT_IS_LOCAL(ul)) /* it's connected already! */
    _uplink->p.state = P_LASTWAIT;	/* so abort this one */
  if (_ircd_uplink)		/* we got RFC2813 autoconnect connected */
    _uplink->p.state = P_LASTWAIT; /* so we should stop every autoconnect */
  switch (_uplink->p.state)
  {
    case P_INITIAL:	/* got connected, switch to normal */
      ul = _uplink->link->cl;
      LOG_CONN ("ircd: connected to uplink %s at %s", uli->name, ul->host);
#if IRCD_USES_ICONV
      /* set conversion to CHARSET_8BIT which is default */
      _uplink->p.iface->conv = Get_Conversion (CHARSET_8BIT);
#endif
      opt = ul->away;
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
      sz = snprintf (buff, sizeof(buff), /* send PASS+SERVER to peer */
		     "PASS %s %s IRC|" PACKAGE " %s\r\n"
		     "SERVER %s 1 1 :%s", /* own token is always 1 */
		     *ul->fname ? ul->fname : "*",
		     _ircd_version_string, ul->away, MY_NAME,
		     _ircd_description_string);
      _uplink->bs = sz - 2;
      _uplink->ms = 2;
      if (Peer_Put ((&_uplink->p), buff, &sz) <= 0) /* something went bad */
	return _ircd_stop_uplink (uli);
      pthread_join (_uplink->th, NULL);
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
  uplink->local = uplink->via;
  uplink->via->p.network_type = "ircd";
  uplink->via->link = alloc_LINK();
  uplink->via->link->cl = uplink;
  uplink->via->link->where = &ME;
  dprint(2, "ircd:CLIENT: adding uplink %p: link %p prev %p", uplink,
	 uplink->via->link, ME.c.lients);
  uplink->via->link->prev = ME.c.lients;
  uplink->via->link->flags = 0;
  ME.c.lients = uplink->via->link;
  uplink->via->p.priv = IrcdPeers;
  uplink->via->p.modules_data = NULL;
  IrcdPeers = uplink->via;
  pthread_mutex_unlock (&IrcdLock);
#if IRCD_MULTICONNECT
  _ircd_uplinks++;
  uplink->on_ack = 0;
  uplink->alt = NULL;
#endif
  uplink->via->p.dname = uplink->lcnick;
  uplink->via->p.state = P_DISCONNECTED;
  uplink->via->p.socket = -1;
  uplink->via->p.connchain = NULL;
  uplink->via->started = Time;
  uplink->via->i.token = NULL;
  uplink->via->penalty = 0;
  uplink->via->t = 0;
  uplink->pcl = NULL;
  uplink->cs = uplink;
  uplink->x.class = NULL;
  uplink->c.lients = NULL;
  uplink->hold_upto = 0;
  uplink->umode = A_UPLINK;
  uplink->nick[0] = 0;
  uplink->fname[0] = 0;
  uplink->user[0] = 0;
  uplink->hops = 1;
  unistrlower (uplink->lcnick, name, sizeof(uplink->lcnick)); /* temp buff */
  if (pass)
    strfcpy (uplink->fname, pass, sizeof(uplink->fname)); /* remember it */
  strfcpy (uplink->away, port, sizeof(uplink->away)); /* remember port string */
  strfcpy (uplink->host, host, sizeof(uplink->host)); /* remember host name */
  uplink->vhost[0] = 0;
  Connchain_Grow (&uplink->via->p, 0); /* init empty connchain */
  uplink->via->p.iface = Add_Iface (I_CONNECT, uplink->lcnick,
				    &_ircd_uplink_sig, &_ircd_uplink_req,
				    uplink->via);
  uplink->lcnick[0] = '\0';		/* don't need it anymore */
  if (Connect_Host (host, atoi(port), &uplink->via->th,
		    &uplink->via->p.socket, &_ircd_uplink_handler, uplink))
    LOG_CONN ("ircd: starting connect: %s/%s", host, port);
  else
  {
    register peer_priv **pp;
    register LINK **ll;

    uplink->via->p.iface->data = NULL; /* disown it */
    uplink->via->p.iface->ift = I_DIED; /* error on thread creating */
    ERROR ("ircd:error on starting connect to %s/%s", host, port);
#if IRCD_MULTICONNECT
    _ircd_uplinks--;
#endif
    if (Connchain_Kill ((&uplink->via->p))) ll=NULL; /* socket is still dead */
    pthread_mutex_lock (&IrcdLock);
    for (pp = &IrcdPeers; *pp; pp = &(*pp)->p.priv)
      if (*pp == uplink->via)
      {
	*pp = uplink->via->p.priv;
	break;
      }
    dprint(2, "ircd:CLIENT: deleting uplink %s (%p): unshifting %p prev %p",
	   uplink->lcnick, uplink, uplink->via->link, uplink->via->link->prev);
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
  if (_uplinks_timer == -1)
    /* start autoconnect each 30 seconds until got some uplink */
    _uplinks_timer = NewTimer(I_SERVICE, Ircd->iface->name, S_TIMEOUT, 30, 0, 0, 0);
}

/* called when timer is expired */
static void _ircd_do_init_uplinks (void)
{
  INTERFACE *tmp;
  char *c;
  int i;
  char buff[MESSAGEMAX];

  if (_ircd_uplink)			/* got RFC2813 server autoconnected*/
    return;				/* so nothing to do */
  tmp = Add_Iface (I_TEMP, NULL, NULL, &_ircd_sublist_receiver, NULL);
  i = Get_Clientlist (tmp, U_AUTO, Ircd->sub->name, "*");
  if (i)
  {
    lid_t lid;
    char hosts[MESSAGEMAX];

    c = _ircd_sublist_buffer = buff;
    Set_Iface (tmp);
    Get_Request();
    LOG_CONN ("ircd: got autoconnect list: %s", _ircd_sublist_buffer);
    /* side effect: autoconnect list should be not longer that one message */
    while (*c)				/* for each autoconnect */
    {
      char *cc, *hl;
      peer_priv *peer;

      cc = gettoken (c, NULL);
      unistrlower(hosts, c, sizeof(hosts));
      pthread_mutex_lock(&IrcdLock);
      for (peer = IrcdPeers; peer != NULL; peer = peer->p.priv)
	if (safe_strcmp(peer->p.dname, hosts) == 0)
	  break;
      pthread_mutex_unlock(&IrcdLock);
      if (peer != NULL) {		/* already connected, go to next */
	c = cc;
	continue;
      }
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
	ERROR ("ircd:uplink %s has no host record, reset autoconnect flag!", c);
	c = cc;
	continue;
      }
      hl = hosts;
      while (*hl)			/* for each host */
      {
	char *ch = hl;
	register char *ch2;

	hl = gettoken (ch, NULL);
	ch2 = strchr(ch, '@');		/* don't show password in log */
	if (ch2)
	  ch2++;
	else
	  ch2 = ch;
	LOG_CONN("ircd: found autoconnect %s, starting it", ch2);
	_ircd_start_uplink (c, ch);	/* create a connection thread */
      }
      /* we do ignoring too long hosts list too! */
      c = cc;
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
    return ircd_do_unumeric (cl, ERR_NEEDMOREPARAMS, cl, 0, "PASS");
  if (cl->nick[0] || cl->fname[0])	/* got either NICK or USER already */
    return ircd_do_unumeric (cl, ERR_ALREADYREGISTRED, cl, 0, NULL);
  if (cl->vhost[0])			/* second PASS command */
    Add_Request (I_LOG, "*", F_WARN, "duplicate PASS attempt from %s@%s",
		 cl->user, cl->host);
  strfcpy (cl->vhost, argv[0], sizeof(cl->vhost));
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

static void _ircd_update_users_counters(void)
{
  size_t i;
  unsigned int gu;

  if (Ircd->token[0]->x.a.uc > Ircd->lu)
    Ircd->lu = Ircd->token[0]->x.a.uc;
  for (i = 0, gu = 0; i < Ircd->s; i++)
    if (Ircd->token[i])
      gu += Ircd->token[i]->x.a.uc;
  if (gu > Ircd->gu)
    Ircd->gu = gu;
}

static char _ircd_modesstring[128]; /* should be enough for two A-Za-z */

/* adds it into lists, sets fields, sends notify to all servers */
static int _ircd_got_local_user (CLIENT *cl)
{
  struct binding_t *b;
  struct clrec_t *clr;
  char *c;
  userflag uf;
#if IFNAMEMAX > HOSTMASKLEN
  char mb[IFNAMEMAX+1]; /* it should be enough for umode */
#else
  char mb[HOSTMASKLEN+1];
#endif

  /* last chance to check for kill records */
  snprintf (mb, sizeof(mb), "%s!%s@%s", cl->nick, cl->user, cl->host);
  clr = Find_Clientrecord (mb, NULL, &uf, Ircd->iface->name);
  if (!clr && (cl->via->p.uf & U_DENY))
  {
    /* let recheck regular kill records again to get kill message */
    snprintf (mb, sizeof(mb), "%s@%s", cl->user, cl->host);
    clr = Find_Clientrecord (mb, NULL, &uf, Ircd->iface->name);
  }
  if (clr)
  {
    if (uf & U_DENY)		/* keep kill message for ERR_YOUREBANNEDCREEP */
      strfcpy (cl->lcnick, Get_Field (clr, Ircd->sub->name, NULL),
	       sizeof(cl->lcnick));
    Unlock_Clientrecord (clr);
  }
  else
    uf = 0;
  if ((uf & U_DENY) || (cl->via->p.uf & U_DENY))
  {
    /* there might be some non-comment data in the field */
    c = cl->lcnick ? strchr (cl->lcnick, ':') : NULL;
    ircd_do_unumeric (cl, ERR_YOUREBANNEDCREEP, cl, 0, c ? c : cl->lcnick);
    _ircd_peer_kill (cl->via, "Bye!");
    return 1;
  }
  if (cl->x.class != NULL && (clr = Lock_Clientrecord(cl->x.class->name)))
  {
    /* check if class record has a password so it should be verified */
    c = Get_Field(clr, "passwd", NULL);
    if (c && Check_Passwd(cl->vhost, c))
    {
      Unlock_Clientrecord(clr);
      ircd_do_unumeric(cl, ERR_PASSWDMISMATCH, cl, 0, NULL);
      _ircd_peer_kill(cl->via, "Bad Password");
      return 1;
    }
    uf = Get_Flags(clr, Ircd->iface->name);
    Unlock_Clientrecord(clr);
  }
  else
    uf = 0;
  unistrlower (cl->lcnick, cl->nick, sizeof(cl->lcnick));
  if (Insert_Key (&Ircd->clients, cl->lcnick, cl, 1) < 0)
    ERROR("ircd:_ircd_got_local_user: tree error on %s", cl->lcnick);
    /* FIXME: isn't it fatal? */
  else
    dprint(2, "ircd:CLIENT: new local user name %s", cl->lcnick);
  snprintf (mb, sizeof(mb), "%s@%s", cl->lcnick, Ircd->iface->name);
  Rename_Iface (cl->via->p.iface, mb);	/* rename iface to nick@net */
  strfcpy (cl->vhost, cl->host, sizeof(cl->vhost));
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
      memmove(&cl->user[1], cl->user, sizeof(cl->user)-2);
      cl->user[0] = '+';
    }
  } else {
    if (cl->user[0] == ' ')
      cl->user[0] = '~';
    else if (cl->user[0] == '=')
      cl->user[0] = '^';
  }
  /* special support for SSL connection: set an userflag */
  if (Connchain_Check(&cl->via->p, 'S') < 0)
    cl->umode |= A_SSL;
  ircd_make_umode (mb, cl->umode, sizeof(mb));
  /* run all bindings on the client now, something may need update */
  for (c = mb; *c; c++)
    ircd_char2umode(Ircd->iface, MY_NAME, *c, cl);
#ifdef USE_SERVICES
  /* notify services about new user: no token first, then with token */
{
  register LINK *L;
  for (L = ME.c.lients; L; L = L->prev)
    if (CLIENT_IS_SERVICE(L->cl) &&
	(SERVICE_FLAGS(L->cl) & SERVICE_WANT_NICK) &&
	!(SERVICE_FLAGS(L->cl) & SERVICE_WANT_TOKEN))
      L->cl->via->p.iface->ift |= I_PENDING;
  Add_Request (I_PENDING, "*", 0, "NICK %s 1 %s %s %s +%s :%s",
	       cl->nick, cl->user, cl->host, MY_NAME, mb, cl->fname);
  for (L = ME.c.lients; L; L = L->prev)
    if (CLIENT_IS_SERVICE(L->cl) &&
	(SERVICE_FLAGS(L->cl) & SERVICE_WANT_NICK) &&
	(SERVICE_FLAGS(L->cl) & SERVICE_WANT_TOKEN))
      L->cl->via->p.iface->ift |= I_PENDING;
}
#endif
  ircd_sendto_servers_all (Ircd, NULL, "NICK %s 1 %s %s 1 +%s :%s",
			   cl->nick, cl->user, cl->host, mb, cl->fname);
  cl->via->p.state = P_TALK;
  ME.x.a.uc++;
  DBG("ircd:updated local users count to %u", ME.x.a.uc);
  _ircd_update_users_counters();
  ircd_do_unumeric (cl, RPL_WELCOME, cl, 0, NULL);
  ircd_do_unumeric (cl, RPL_YOURHOST, &ME, 0, NULL);
  ircd_do_unumeric (cl, RPL_CREATED, &ME, 0, COMPILETIME);
  ircd_do_unumeric (cl, RPL_MYINFO, &ME, 0, _ircd_modesstring);
  send_isupport (Ircd, cl);
  b = NULL;
  while ((b = Check_Bindtable (BTIrcdLocalClient, cl->nick, uf, U_ANYCH, b)))
    if (!b->name)			/* do lusers and custom messages */
      b->func (Ircd->iface, &cl->via->p, cl->umode);
  _ircd_bt_client(cl, NULL, cl->nick, MY_NAME);
#if IRCD_USES_ICONV
  ircd_do_unumeric (cl, RPL_CODEPAGE, cl, 0,
		    Conversion_Charset (cl->via->p.iface->conv));
#endif
  if (mb[0])
    New_Request(cl->via->p.iface, 0, ":%s MODE %s +%s", cl->nick, cl->nick, mb);
  if (cl->umode & A_RESTRICTED)
    ircd_do_unumeric (cl, ERR_RESTRICTED, cl, 0, NULL);
  return 1;
}

/* returns 1 if nick available now
   else sends numerics to client, resets nick and returns 0 */
static int _ircd_nickname_available(CLIENT *cl, char *b)
{
  CLIENT *cl2;

  cl2 = _ircd_find_client (b);
  if (cl2)	/* check if that name is in use/on hold */
  {
    if (!cl2->hold_upto)
    {
      ircd_do_unumeric (cl, ERR_NICKNAMEINUSE, cl2, 0, NULL);
      b[0] = 0;
      return 0;
    }
    _ircd_try_drop_collision(&cl2);
    if (cl == cl2)			/* client took own old nick back */
      _ircd_force_drop_collision(&cl2); /* new nick cannot have tail in ->rfr */
    //FIXME: add some #define for behavior below?
    if (cl2 && cl2->x.rto != NULL)	/* it's phantom from nick change */
      _ircd_force_drop_collision(&cl2); /* let's allow client to regain it */
    if (cl2 != NULL)
    {
      ircd_do_unumeric (cl, ERR_UNAVAILRESOURCE, cl, 0, b);
      b[0] = 0;
      return 0;
    }
  }
  return 1;
}

/* sets params; if ->nick already set then register new user */
BINDING_TYPE_ircd_register_cmd (ircd_user);
static int ircd_user (INTERFACE *srv, struct peer_t *peer, int argc, const char **argv)
{ /* args: <user> <mode> <unused> <realname> */
  CLIENT *cl = ((peer_priv *)peer->iface->data)->link->cl; /* it's really peer->link->cl */
//  register char *c;
  int umode;

  if (cl->umode & A_UPLINK)		/* illegal here! */
    return (0);
  if (argc < 4)
    return ircd_do_unumeric (cl, ERR_NEEDMOREPARAMS, cl, 0, "USER");
  if (cl->fname[0])			/* got USER already */
    return ircd_do_unumeric (cl, ERR_ALREADYREGISTRED, cl, 0, NULL);
//  c = NextWord(argv[3]);
//  if (*c == '\0')
  if (*argv[3] == '\0')
    return ircd_do_unumeric (cl, ERR_NEEDMOREPARAMS, cl, 0, "USER");
  if (!cl->user[0])			/* got no ident */
  {
    register unsigned char *cc;

    cl->user[0] = ' ';			/* marker */
    strfcpy (&cl->user[1], argv[0], sizeof(cl->user) - 1);
    for (cc = &cl->user[1]; *cc; cc++)	/* restrict ident to ASCII printable */
      if (*cc <= ' ' || *cc >= 0x80 || *cc == '*')
	*cc = 'x';
  }
  umode = atoi (argv[1]);
  if (umode & 4)
    cl->umode = A_WALLOP;
  if (_ircd_default_invisible || (umode & 8))
    cl->umode |= A_INVISIBLE;
//  StrTrim(cl->fname);
  umode = unistrcut (argv[3], sizeof(cl->fname), REALNAMELEN);
  strfcpy (cl->fname, argv[3], umode + 1);
  if (!cl->nick[0] || !_ircd_nickname_available(cl, cl->nick))
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

  dprint(5, "ircd:ircd.c:_ircd_validate_nickname: %s", name);
  if (!strcasecmp (name, "anonymous"))	/* RFC2811 */
    return 0;
  sz = safe_strlen (name);
  if (sz == 0)
    return 0;
#if IRCD_STRICT_NAMES
  /* check if name is compatible with CHARSET_8BIT */
  conv = Get_Conversion (CHARSET_8BIT);
  os = namebuf;
  sp = sz;
  sp = Undo_Conversion (conv, &os, sizeof(namebuf), name, &sp);
  if (sp > _ircd_nicklen)		/* too long nickname */
  {
    Free_Conversion (conv);
    return 0;
  }
  ds = d;
  sp = Do_Conversion (conv, &ds, s, os, &sp);
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
    if (sp > _ircd_nicklen)		/* nick is too long */
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
  if (!_ircd_validate_nickname (b, nick, bs))
  {
    ircd_do_unumeric (cl, ERR_ERRONEUSNICKNAME, cl, 0, nick);
    return 0;
  }
  return (_ircd_nickname_available(cl, b));
}

/* sets nick; if ->fname already set then register new user */
BINDING_TYPE_ircd_register_cmd (ircd_nick_rb);
static int ircd_nick_rb (INTERFACE *srv, struct peer_t *peer, int argc, const char **argv)
{ /* args: <nick> */
  CLIENT *cl = ((peer_priv *)peer->iface->data)->link->cl; /* it's really peer->link->cl */

  if (cl->umode & A_UPLINK)		/* illegal here! */
    return (0);
  if (argc == 0)
    return ircd_do_unumeric (cl, ERR_NONICKNAMEGIVEN, cl, 0, NULL);
  if (!_ircd_check_nick_cmd (cl, cl->nick, argv[0], sizeof(cl->nick)))
    return 1;
  if (!cl->fname[0])
    return 1;
  return _ircd_got_local_user (cl);
}

BINDING_TYPE_ircd_client_cmd(ircd_nick_cb);
static int ircd_nick_cb(INTERFACE *srv, struct peer_t *peer, const char *lcnick,
			const char *user, const char *host, const char *vhost,
			modeflag eum, int argc, const char **argv)
{ /* args: <new nick> */
  CLIENT *cl = ((peer_priv *)peer->iface->data)->link->cl; /* it's really peer->link->cl */
  int is_casechange;
  char checknick[MB_LEN_MAX*NICKLEN+NAMEMAX+2];
  MEMBER *ch;

#ifdef USE_SERVICES
  /* forbidden for services! */
  if (CLIENT_IS_SERVICE(cl))
    return ircd_do_unumeric (cl, ERR_ALREADYREGISTRED, cl, 0, NULL);
#endif
  if (argc == 0)
    return ircd_do_unumeric (cl, ERR_NONICKNAMEGIVEN, cl, 0, NULL);
  if (strcmp(cl->nick, argv[0]) == 0) /* ignore dummy change */
    return 1;
  unistrlower(checknick, argv[0], sizeof(checknick));
  if (strcmp(checknick, cl->lcnick) == 0)
    is_casechange = 1;
  else if (!_ircd_check_nick_cmd (cl, checknick, argv[0], sizeof(checknick)))
    return 1;
  else
    is_casechange = 0;
  if (cl->umode & A_RESTRICTED)
    return ircd_do_unumeric (cl, ERR_RESTRICTED, cl, 0, NULL);
  /* also test joined channels rules for the nick */
  for (ch = cl->c.hannels; ch; ch = ch->prevchan)
    if (!ircd_check_modechange(peer->iface, cl->umode, ch->chan->name,
			       ch->chan->mode, 1, 0, argv[0], cl->umode, 0))
      return (1);		/* quiet, binding sent a message */
  _ircd_do_nickchange(cl, NULL, 0, argv[0], is_casechange);
  if (is_casechange)		/* no iface rename required */
    return (1);
  snprintf (checknick, sizeof(checknick), "%s@%s", cl->lcnick, Ircd->iface->name);
  Rename_Iface (peer->iface, checknick); /* rename iface to newnick@net */
  return 1;
}

#if IRCD_MULTICONNECT
/* recursive traverse into tree sending every server we found */
static inline void _ircd_burst_servers(INTERFACE *cl, const char *sn, LINK *l,
				       int tst, peer_priv *via)
{
  dprint(5, "ircd:ircd.c:_ircd_burst_servers: %s to %s", sn, cl->name);
  while (l) {
    if (CLIENT_IS_SERVER (l->cl) && (l->cl->hops >= l->where->hops) &&
	l->cl->via != via &&		/* never send server back */
	/* send any: our link, server behind this one,
	   or if we send to A_MULTI then send other equal path too */
	(tst || l->where == &ME ||
	 (l->cl->via == l->where->via && l->cl->hops > l->where->hops))) {
      register char *cmd = "SERVER";

      if (tst && (l->cl->umode & A_MULTI)) /* new server type */
	cmd = "ISERVER";		/* protocol extension */
      New_Request (cl, 0, ":%s %s %s %hu %hu :%s", sn, cmd, l->cl->nick,
		   l->cl->hops + 1, l->cl->x.a.token + 1, l->cl->fname);
      if (l->where == &ME || l->cl->hops > l->where->hops) /* recursion */
	/* for alternative path only send multipath but don't go further */
	_ircd_burst_servers(cl, l->cl->nick, l->cl->c.lients, tst, via);
    }
    l = l->prev;
  }
}
#else
static inline void _ircd_burst_servers(INTERFACE *cl, const char *sn, LINK *l)
{
  dprint(5, "ircd:ircd.c:_ircd_burst_servers: %s to %s", sn, cl->name);
  while (l) {
    if (CLIENT_IS_SERVER (l->cl)) {
      New_Request (cl, 0, ":%s SERVER %s %hu %hu :%s", sn, l->cl->nick,
		   l->cl->hops + 1, l->cl->x.a.token + 1, l->cl->fname);
      _ircd_burst_servers(cl, l->cl->nick, l->cl->c.lients); /* recursion */
    }
    l = l->prev;
  }
}
#endif

static inline void _ircd_burst_clients (INTERFACE *cl, unsigned short t,
					LINK *s, unsigned short hops,
					char *umode/* 16 bytes */)
{
  if (s == NULL)
    return;
  dprint(5, "ircd:ircd.c:_ircd_burst_clients: %s to %s", s->cl->nick, cl->name);
  for ( ; s; s = s->prev)
  {
    if ((t == 1) && (s->cl->via->p.state != P_TALK)) { /* not ready */
      dprint(5, "ircd: ignoring incomplete connection %s@%s", s->cl->user,
	     s->cl->host);
      continue;
    } else if (CLIENT_IS_SERVER (s->cl))
      continue;
    else if (CLIENT_IS_SERVICE (s->cl))
      /* <servicename> <servertoken> <distribution> <type> <hopcount> <info> */
      New_Request (cl, 0, "SERVICE %s %hu %s 0 %hu :%s", s->cl->nick, t,
		   s->cl->away, hops, s->cl->fname);
    else
      /* <nickname> <hopcount> <username> <host> <servertoken> <umode> <realname> */
      New_Request (cl, 0, "NICK %s %hu %s %s %hu +%s :%s", s->cl->nick,
		   hops, s->cl->user, s->cl->host, t,
		   ircd_make_umode (umode, s->cl->umode, 16), s->cl->fname);
  }
}

/* sends everything to fresh connected server */
static void _ircd_connection_burst (CLIENT *cl)
{
  char umode[16];			/* it should be enough in any case */
  unsigned short i;
#if IRCD_MULTICONNECT
  register int tst = (cl->umode & A_MULTI);

  /* Ircd->servers is our recipient */
  _ircd_burst_servers(cl->via->p.iface, MY_NAME, Ircd->servers->prev, tst, cl->via);
#else
  _ircd_burst_servers(cl->via->p.iface, MY_NAME, Ircd->servers->prev);
#endif
  for (i = 0; i < Ircd->s; i++)
    if (Ircd->token[i] != NULL && Ircd->token[i]->via != cl->via)
      _ircd_burst_clients (cl->via->p.iface, i + 1, Ircd->token[i]->c.lients,
			   Ircd->token[i]->hops + 1, umode);
  ircd_burst_channels (cl->via->p.iface, Ircd->channels);
  dprint(5, "ircd: burst done for %s", cl->lcnick);
}

static inline void _kill_bad_server(CLIENT *cl, const char *msg)
{
  cl->lcnick[0] = '\0';			/* do not try to remove it */
  _ircd_peer_kill(cl->via, msg);
}

/* trying to register new local server link... */
BINDING_TYPE_ircd_register_cmd (ircd_server_rb);
static int ircd_server_rb (INTERFACE *srv, struct peer_t *peer, int argc, const char **argv)
{ /* args: <servername> <hopcount> <token/info(RFC1459)> <info(RFC2813)> */
  CLIENT *cl = ((peer_priv *)peer->iface->data)->link->cl; /* it's really peer->link->cl */
  CLIENT *clt;
  struct clrec_t *u;
  char *cc, *ourpass = NULL, *approved; /* initialize to avoid warning */
  char *ftbf;				/* those to be first */
  LINK **lnk;
  struct binding_t *b = NULL;
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
  cc = "";
  if (argc < 4 || (token = strtol (argv[2], &cc, 10)) <= 0 || *cc)
  {
    Add_Request(I_LOG, "*", F_WARN, "ircd: invalid token %ld%s in SERVER %s",
		token, cc, argv[0]);
    strfcpy (cl->fname, argv[2], sizeof(cl->fname));
    token = 1;
  }
  else
    strfcpy (cl->fname, argv[3], sizeof(cl->fname));
  token--;				/* tokens are sent from 1 */
  u = Lock_Clientrecord (argv[0]);	/* check if I know that server */
  if (!u)
  {
    _ircd_peer_kill (cl->via, "no c/N lines for you");
    return 1;
  }
  if (!((peer->uf = Get_Flags (u, srv->name)) & U_UNSHARED))
  {
    Unlock_Clientrecord (u);		/* it's person not server */
    _ircd_peer_kill (cl->via, "no c/N lines for you");
    return 1;
  }
  /* check if password matches */
  c = Get_Field (u, "passwd", NULL);
  if (c && Check_Passwd (cl->vhost, c))
  {
    Unlock_Clientrecord (u);
    _ircd_peer_kill (cl->via, "bad password");
    return 1;
  }
  strfcpy (cl->vhost, cl->host, sizeof(cl->vhost));
  if (peer->state == P_LOGIN) /* if it's incoming then check it to match */
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
	}
	if ((ccc = strchr (chost, '/'))) /* cut off port part */
	  *ccc = 0;
	if ((ourpass = strchr (ident, ':'))) /* split off password part */
	  *ourpass++ = 0;
	if ((!*ident || match (ident, cl->user) >= 0) && /* user part matches */
	    (!strcasecmp (chost, cl->host) || /* host part matches host */
	     !strcasecmp (chost, ipname))) { /* or host part matches IP */
	  *c = ':';			/* in case if no ident mask given */
	  break;			/* it's matched, done */
	}
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
  else /* P_IDLE */
    Unlock_Clientrecord (u);
  /* we used password we got so can use lcnick as it should be */
  unistrlower (cl->lcnick, argv[0], sizeof(cl->lcnick));
  clt = _ircd_find_client_lc (cl->lcnick);
#if IRCD_MULTICONNECT
  if (clt && clt->hold_upto) {
    ERROR("ircd: internal error on %s", cl->lcnick);
    _ircd_force_drop_collision (&clt);
  } else if (clt && (!CLIENT_IS_SERVER(clt) || CLIENT_IS_LOCAL(clt) ||
	     !(clt->umode & A_MULTI)))
#else
  if (clt)				/* it's already in our network */
#endif
  {
    // TODO: try to resolv that somehow?
    _kill_bad_server (cl, "duplicate connection not allowed");
    return 1;
  }
  cc = gettoken (cl->away, NULL);	/* split off server version string */
  if (strncmp (cl->away, "021", 3))	/* want 2.10+ version, RFC2813 */
  {
    _kill_bad_server (cl, "old version");
    return 1;
  }
  if (*cc)				/* got flags string */
  {
    char *cflags = gettoken (cc, NULL);

    if (*cc != '|' && strncmp (cc, "IRC|", 4)) /* RFC2813 */
    {
      _kill_bad_server (cl, "unknown implementation");
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
  if (token > SHRT_MAX) {
    _kill_bad_server (cl, "invalid token value");
    return 1;
  }
  /* if it's incoming connect then check every option flag we got
     for appliance to connection chain and answer accepted flags back
     don't using interface but connchain only to avoid message queue
     connchain should be ready at this point to get one message up to
     MB_LEN_MAX*MESSAGEMAX-2 so we will send both PASS and SERVER at once */
  if (peer->state == P_LOGIN)
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
    /* password is in buff yet */
    if (!ourpass || !*ourpass)
      ourpass = "*";
    sz = strlen(ourpass);
    memmove (&buff[5], ourpass, sz);
    memcpy (buff, "PASS ", 5);
    sz += 5;
    sz += snprintf (&buff[sz], sizeof(buff) - sz,
		   " %s IRC|%s|" PACKAGE " %s\r\n"
		   "SERVER %s 1 1 :%s",	/* own token is always 0 */
		   _ircd_version_string, ircd_version_flags, ftbf, MY_NAME,
		   _ircd_description_string);
    if (sz >= sizeof(buff))
      sz = sizeof(buff) - 1;		/* recover from snprintf */
    if (Peer_Put (peer, buff, &sz) <= 0) /* put it into connchain buffers */
    {
      _kill_bad_server (cl, "handshake error");
      return 1;
    }
  }
  if (cc != ftbf)			/* ok, we can redo connchain now */
  {
    char *ccur = ftbf;

    while (ccur != cc)
    {
      if (Connchain_Grow (peer, *ccur) <= 0)
      {
#if 0
	snprintf (buff, sizeof(buff), "server option unavailable: %c", *ccur);
	_kill_bad_server (cl, buff);
	return 1;
#else
	ERROR("server %s sent unsupported option: %c", cl->lcnick, *ccur);
#endif
      }
      ccur++;
    }
    Connchain_Grow (peer, 'x');		/* some filter might kill it */
  }
  while (*cc)
  {
    if (Connchain_Grow (peer, *cc) <= 0)
    {
#if 0
      snprintf (buff, sizeof(buff), "server option unavailable: %c", *cc);
      _kill_bad_server (cl, buff);
      return 1;
#else
      ERROR("server %s sent unsupported option: %c", cl->lcnick, *cc);
#endif
    }
    cc++;
  }
#if IRCD_MULTICONNECT
  if (!(cl->umode & A_MULTI))
#endif
  if (peer->uf & U_AUTO) {		/* we connected to uplink */
    if (!_ircd_uplink)			/* and there is no uplink yet */
      _ircd_uplink = cl->via;		/* so this may be our uplink now */
    else		/* there is autoconnected RFC2813 server already */
    {
      _kill_bad_server (cl, "extra uplink connect, bye, sorry");
      return 1;
    }
  }
#ifdef IRCD_P_FLAG
  if (!(cl->umode & A_ISON))		/* should be received 'P' flag */
  {
    _kill_bad_server (cl, "option flag P is required");
    return 1;
  }
#endif
#if IRCD_MULTICONNECT
  /* check if it's another connect of already known server */
  if (clt && !(cl->umode & A_MULTI)) { /* another connect with different mode */
    _kill_bad_server (cl, "duplicate connection not allowed");
    //FIXME: SQUIT another one too?
    return 1;
  }
#endif
  if (!(cl->umode & A_UPLINK))
    _ircd_class_out (cl->via->link); /* it's still !A_SERVER if not uplink */
#if IRCD_MULTICONNECT
  /* check if it's another connect of already known server */
  if (clt) /* see above! */
  {
    cl->via->link->cl = clt;
    clt->alt = clt->via;	/* shift shortest to alt */
    clt->via = cl->via;		/* and set shortest to this */
    clt->local = cl->via;	/* and it is local connect as well */
    clt->hops = 1;
    clt->umode &= ~A_PINGED;	/* drop pinged state from previous connect */
    clt->umode |= cl->umode;	/* copy A_UPLINK there */
    strfcpy (clt->fname, cl->fname, sizeof(clt->fname)); /* rewrite! */
    strfcpy (clt->user, cl->user, sizeof(clt->user));
    strfcpy (clt->host, cl->host, sizeof(clt->host));
    strfcpy (clt->vhost, cl->vhost, sizeof(clt->vhost));
    pthread_mutex_lock (&IrcdLock);
    free_CLIENT (cl);
    pthread_mutex_unlock (&IrcdLock);
    dprint(2, "ircd:CLIENT: %s: released %p using %p", clt->nick, cl, clt);
    cl = clt; /* replace CLIENT struct and skip token! */
  }
  else
  {
    cl->last_id = -1;			/* no ids received yet */
    memset(cl->id_cache, 0, sizeof(cl->id_cache));
#endif
    strfcpy (cl->nick, argv[0], sizeof(cl->nick)); /* all done, fill data */
    cl->x.a.token = _ircd_alloc_token();	/* right after class out! */ //!
    Ircd->token[cl->x.a.token] = cl;
    DBG("ircd:token %hu set to %s", cl->x.a.token, cl->lcnick);
    cl->x.a.uc = 0;
#if IRCD_MULTICONNECT
  }
#endif
  DBG("ircd:server: assigned token %hd", cl->x.a.token);
  cl->via->t = token + 1;		/* no tokens there yet */
  cl->via->i.token = safe_calloc (cl->via->t, sizeof(CLIENT *));
  cl->via->i.token[token] = cl;
  dprint(2, "ircd:CLIENT: unshifting %p prev %p", cl->via->link, cl->via->link->prev);
  for (lnk = &ME.c.lients; *lnk; lnk = &(*lnk)->prev) /* remove from the list */
    if (*lnk == cl->via->link)
      break;
  if (*lnk)
    *lnk = cl->via->link->prev;
  else
    ERROR("ircd:ircd_server_rb: cannot find %s in local clients list", cl->nick);
  dprint(2, "ircd:server: adding %p prev %p", cl->via->link, Ircd->servers);
  cl->via->link->prev = Ircd->servers;	/* add it to local lists */
  Ircd->servers = cl->via->link;
  cl->via->p.dname = cl->lcnick;	/* it should be lower case for server */
#if IRCD_MULTICONNECT
  cl->via->acks = NULL;			/* no acks from fresh connect */
  if (cl->alt == NULL)			/* it's first instance */
  {
#endif
    if (Insert_Key (&Ircd->clients, cl->lcnick, cl, 1) < 0) //!
      ERROR("ircd:ircd_server_rb: tree error on adding %s", cl->lcnick);
      /* FIXME: isn't it something fatal? */
    else
      dprint(2, "ircd:CLIENT: new local server name %s", cl->lcnick);
#if IRCD_MULTICONNECT
  }
#endif
  dprint(2, "ircd:CLIENT: local server link %s: %p", cl->lcnick, cl);
  cl->umode |= A_SERVER; //!
  peer->state = P_TALK;			/* we registered it */
  snprintf (buff, sizeof(buff), "%s@%s", cl->lcnick, Ircd->iface->name);
  Rename_Iface (peer->iface, buff);	/* rename iface to server.name@net */
  peer->iface->ift |= I_CLIENT;		/* it might be not set yet */
#ifdef USE_SERVICES
# if IRCD_MULTICONNECT
  /* notify services */
  ircd_sendto_services_all (Ircd, SERVICE_WANT_SERVER, "SERVER %s 2 %hu :%s",
			    argv[0], cl->x.a.token + 1, cl->fname);
# else
  /* mark services and send along with servers, see below */
  ircd_sendto_services_mark_all (Ircd, SERVICE_WANT_SERVER);
# endif
#endif
#if IRCD_MULTICONNECT
  /* propagate new server over network now */
  if (cl->umode & A_MULTI)		/* it's updated already */
    ircd_sendto_servers_new (Ircd, cl->via, "ISERVER %s 2 %hu :%s", argv[0],
			     cl->x.a.token + 1, cl->fname); //!
  else
    ircd_sendto_servers_new (Ircd, cl->via, "SERVER %s 2 %hu :%s", argv[0],
			     cl->x.a.token + 1, cl->fname); //!
  if (clt != NULL)			/* cyclic, our map is changed! */
    _ircd_recalculate_hops(); /* we got better path so recalculate hops map */
  else					/* don't send duplicates to RFC2813 */
#endif
  ircd_sendto_servers_old (Ircd, cl->via, "SERVER %s 2 %hu :%s", argv[0],
			   cl->x.a.token + 1, cl->fname); //!
  Add_Request(I_LOG, "*", F_SERV, "Received SERVER %s from %s (1 %s)", argv[0],
	      cl->lcnick, cl->fname);
  /* tell other modules about connected server */
  while ((b = Check_Bindtable(BTIrcdGotServer, cl->lcnick, U_ALL, U_ANYCH, b)))
    if (b->name == NULL) /* internal only */
      b->func(Ircd->iface, peer, cl->umode, cl->x.a.token, ftbf);
  _ircd_connection_burst (cl);		/* tell it everything I know */
  return 1;
}

BINDING_TYPE_ircd_register_cmd (__ignored__rb);
static int __ignored__rb (INTERFACE *srv, struct peer_t *peer, int argc, const char **argv)
{
  return 1;
}


/* "ircd-server-cmd" bindings */
static inline int _ircd_server_duplicate_link (peer_priv *old, peer_priv *this,
					const char *sender, const char *name)
{
  /* server announces another instance of RFC2813 server */
  ERROR ("Server %s introduced already known server %s, dropping link", sender,
	 name);
  /* kill youngest link */
  if (_ircd_squit_youngest && old->started > this->started)
    this = old;
  ircd_do_squit (this->link, NULL, "Introduced server already exists");
  return 1;
}

static inline int _ircd_remote_server_is_allowed (const char *net,
						const char *name, peer_priv *pp)
{
  register userflag uf = Get_Clientflags (name, net);

  if (!uf)				/* not registered */
    return 1;
  if (!(uf & U_UNSHARED))		/* is known as something else */
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

static char *_ircd_validate_hub (peer_priv *pp, const char *nhn)
{
  struct clrec_t *u = Lock_Clientrecord (pp->p.dname);
  char *hub;
  size_t ptr;
  char hm[HOSTLEN+2];

  dprint(5, "ircd:ircd.c:_ircd_validate_hub: %s on %s", pp->p.dname, nhn);
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

/* adds src into tokens list on pp using ntok */
static bool _ircd_add_token_to_server(peer_priv *pp, CLIENT *cl, long ntok)
{
  if (ntok >= pp->t)
  {
    size_t add = ntok - pp->t + 1;

    if (add < TOKEN_ALLOC_SIZE)
      add = TOKEN_ALLOC_SIZE;
    safe_realloc ((void **)&pp->i.token, (pp->t + add) * sizeof(CLIENT *));
    while (add--)
      pp->i.token[pp->t++] = NULL;
  }
  if (pp->i.token[ntok])
#if IRCD_MULTICONNECT
    WARNING("ircd: got token %ld from %s which is already in use", ntok,
	    pp->p.dname);
#else
  {
    ERROR ("ircd: got token %ld from %s which is already in use", ntok,
	   pp->p.dname);
    if (!ircd_recover_done (pp, "Invalid token"))
      return FALSE;
  }
  else
#endif
    pp->i.token[ntok] = cl;
  return TRUE;
}

/* creates a CLIENT, adds it to nicks list and adds tokens for it */
static CLIENT *_ircd_got_new_remote_server (peer_priv *pp, CLIENT *src,
					    long ntok, const char *nick,
					    const char *lcn, const char *info)
{
  CLIENT *cl;

  cl = alloc_CLIENT();
  dprint(2, "ircd:CLIENT: adding new remote server %s via %s: %p", nick,
	 pp->p.dname, cl);
  if (ntok >= 0)
  {
    if (!_ircd_add_token_to_server(pp, cl, ntok))
    {
      dprint(2, "ircd:CLIENT: deleting %p due to token conflict", cl);
      free_CLIENT (cl);
      return NULL;
    }
  }
  /* else notokenized server may have no clients, ouch */
  cl->pcl = NULL;
  cl->x.a.token = _ircd_alloc_token();
  cl->x.a.uc = 0;
  Ircd->token[cl->x.a.token] = cl;
  DBG("ircd:token %hu set to %s", cl->x.a.token, nick);
#if IRCD_MULTICONNECT
  cl->last_id = -1;			/* no ids received yet */
  memset(cl->id_cache, 0, sizeof(cl->id_cache));
  cl->on_ack = 0;
#endif
  cl->c.lients = NULL;
  cl->umode = A_SERVER;
  cl->cs = cl;
  cl->via = NULL;			/* it will be recalculated */
  cl->local = NULL;
  cl->hold_upto = 0;
  cl->hops = src->hops + 1;		/* ignore introduced number */
  cl->away[0] = 0;
  strfcpy (cl->nick, nick, sizeof(cl->nick));
  strfcpy (cl->lcnick, lcn, sizeof(cl->lcnick));
  strfcpy (cl->fname, info, sizeof(cl->fname));
  cl->user[0] = 0;
  cl->host[0] = 0;
  cl->vhost[0] = 0;
  if (Insert_Key (&Ircd->clients, cl->lcnick, cl, 1) < 0)
    ERROR("ircd:_ircd_got_new_remote_server: tree error on adding %s",
	  cl->lcnick); /* TODO: isn't it fatal? */
  else
    dprint(2, "ircd:CLIENT: new remote server name %s", cl->lcnick);
  return cl;
}

#undef __TRANSIT__
#define __TRANSIT__ __CHECK_TRANSIT__(token)
BINDING_TYPE_ircd_server_cmd(ircd_server_sb);
static int ircd_server_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			  const char *sender, const char *lcsender,
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
  if (cl == &ME)
  {
    ERROR ("ircd: %s sent SERVER %s back to me", sender, MY_NAME);
    ircd_do_squit (pp->link, pp, "you cannot introduce me to me");
    return 1;
  }
#if IRCD_MULTICONNECT
  if (cl && CLIENT_IS_SERVER(cl) && src->alt) /* it may be backup introduce */
  {
    register LINK *tst = src->c.lients;

    while (tst && tst->cl != cl)
      tst = tst->prev;
    if (tst)
    {
      dprint (3, "%s: backup command SERVER %s", peer->dname, argv[0]);
      return 1;
    }
  }
  /* only non-known yet servers may be introduced with SERVER */
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
    if ((ntok = atoi (argv[2])) <= 0 || ntok > SHRT_MAX)
    {
      ERROR ("Server %s sent us invalid token %ld", peer->dname, ntok);
      if (ircd_recover_done (pp, "Invalid token"))
	ircd_do_squit (pp->link, pp, "Invalid token"); /* cannot continue */
      return 1;
    }
    ntok--;				/* tokens are sent from 1 */
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
#if IRCD_MULTICONNECT
  if (cl)
  {
    /* we got and verified duplicate connection */
    _ircd_add_token_to_server (pp, cl, ntok);
    /* map might change completely */
    _ircd_recalculate_hops();
  }
  else
  {
#endif
  cl = _ircd_got_new_remote_server (pp, src, ntok, argv[0], nhn, info);
  if (!cl)
    return 1; /* peer was squited */
  cl->via = src->via;
#if IRCD_MULTICONNECT
  cl->alt = src->alt;
  }
#endif
  link = alloc_LINK();
  link->where = src;
  link->cl = cl;
  link->prev = src->c.lients;
  link->flags = 0;
  src->c.lients = link;
  dprint(2, "ircd:server: added link %p on serv %s prev %p", link, sender,
	 link->prev);
  if (atoi(argv[1]) != (int)cl->hops)
    Add_Request(I_LOG, "*", F_WARN, "ircd: hops count for %s from %s %s!=%hd",
		argv[0], cl->lcnick, argv[1], cl->hops);
#ifdef USE_SERVICES
  ircd_sendto_services_mark_all (Ircd, SERVICE_WANT_SERVER);
#endif
  ircd_sendto_servers_all (Ircd, pp, ":%s SERVER %s %hd %hd :%s", sender,
			   argv[0], cl->hops + 1, cl->x.a.token + 1, info);
  Add_Request(I_LOG, "*", F_SERV, "Received SERVER %s from %s (%hd %s)",
	      argv[0], sender, cl->hops, cl->fname);
  return 1;
}

#if IRCD_MULTICONNECT
BINDING_TYPE_ircd_server_cmd(ircd_iserver);
static int ircd_iserver(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			const char *sender, const char *lcsender,
			int argc, const char **argv)
{ /* args: <servername> <hopcount> <token> <info> */
  peer_priv *pp = peer->iface->data; /* it's peer really */
  CLIENT *src, *cl, *clo;
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
  if (cl == &ME)
  {
    ERROR ("ircd: %s sent ISERVER %s back to me", peer->dname, MY_NAME);
    ircd_do_squit (pp->link, pp, "you cannot introduce me to me");
    return 1;
  }
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
      tst = tst->prev;
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
  if ((ntok = atoi (argv[2])) <= 0 || ntok > SHRT_MAX)
  {
    ERROR ("Server %s sent us invalid token %ld", peer->dname, ntok);
    if (ircd_recover_done (pp, "Invalid token"))
      ircd_do_squit (pp->link, pp, "Invalid token"); /* cannot continue */
    return 1;
  }
  ntok--;				/* tokens are sent from 1 */
  if ((c = _ircd_validate_hub (pp, nhn)))
  {
    ircd_do_squit (pp->link, NULL, c);
    return 1;
  }
  /* ok, we got and checked everything, create data and announce */
  clo = cl;
  if (!cl)
    cl = _ircd_got_new_remote_server (pp, src, ntok, argv[0], nhn, argv[3]);
  else
    _ircd_add_token_to_server (pp, cl, ntok);
  if (!cl) /* peer was squited */
    return 1;
  /* create the link now */
  link = alloc_LINK();
  link->where = src;
  link->cl = cl;
  link->prev = src->c.lients;
  link->flags = 0;
  src->c.lients = link;
  dprint(2, "ircd:server: added link %p on serv %s prev %p", link, sender,
	 link->prev);
  cl->umode |= A_MULTI;			/* it's not set on new */
  /* don't create backlink, it will be created by request */
  if (cl->via) /* it's not first connection */
    _ircd_recalculate_hops();
  else
  {
    cl->via = src->via;
    cl->alt = src->alt;
  }
  if (atoi(argv[1]) != (int)cl->hops)
    dprint(5, "ircd: hops count for %s from %s: got %s, have %hd", argv[0],
	   cl->lcnick, argv[1], cl->hops);
  if (clo == NULL)		/* don't send duplicate to RFC2813 servers */
    ircd_sendto_servers_old (Ircd, pp, ":%s SERVER %s %hd %hd :%s", sender,
			     argv[0], cl->hops + 1, cl->x.a.token + 1, argv[3]);
  else if (cl->hops > 1)	/* don't send it again if it's local connect */
    ircd_sendto_servers_new (Ircd, pp, ":%s ISERVER %s %hd %hd :%s", sender,
			     argv[0], cl->hops + 1, cl->x.a.token + 1, argv[3]);
  Add_Request(I_LOG, "*", F_SERV, "Received ISERVER %s from %s (%hd %s)",
	      argv[0], sender, cl->hops, cl->fname);
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

/* args: live client, server-sender, sender token, new nick, casechange flag
   returns: phantom (on hold) old nick
            (may return NULL if that was just case change)
   new nick should be checked to not collide! */
static CLIENT *_ircd_do_nickchange(CLIENT *tgt, peer_priv *pp,
				   unsigned short token, const char *nn,
				   int casechange)
{
  CLIENT *phantom;

  dprint(5, "ircd:ircd.c:_ircd_do_nickchange: %s to %s", tgt->nick, nn);
  /* notify new and old servers about nick change */
#ifdef USE_SERVICES
  ircd_sendto_services_mark_nick(Ircd, SERVICE_WANT_NICK);
#endif
  ircd_sendto_servers_all_ack(Ircd, tgt, NULL, pp, ":%s NICK %s", tgt->nick, nn);
  /* notify local users including this one about nick change */
  ircd_quit_all_channels(Ircd, tgt, 0, 0); /* mark for notify */
  if (!CLIENT_IS_REMOTE(tgt))
    tgt->via->p.iface->ift |= I_PENDING;
#ifdef USE_SERVICES
  ircd_sendto_services_mark_prefix(Ircd, SERVICE_WANT_NICK);
#endif
  Add_Request(I_PENDING, "*", 0, ":%s!%s@%s NICK %s", tgt->nick, tgt->user,
	      tgt->vhost, nn);
  _ircd_bt_client(tgt, tgt->nick, nn, pp ? pp->link->cl->lcnick : MY_NAME);
  /* change our data now */
  if (casechange) {
    strfcpy(tgt->nick, nn, sizeof(tgt->nick));
    return (NULL);
  }
  if (Delete_Key(Ircd->clients, tgt->lcnick, tgt) < 0)
    ERROR("ircd:_ircd_do_nickchange: tree error on removing %s", tgt->lcnick);
    //TODO: isn't it fatal?
  else
    dprint(2, "ircd:CLIENT: nick change: del old name %s", tgt->lcnick);
  if (tgt->rfr != NULL && tgt->rfr->cs == tgt) { /* it was a nick holder */
    _ircd_bounce_collision(tgt->rfr);
    tgt->rfr = NULL;
  }
  phantom = _ircd_get_phantom(tgt->nick, tgt->lcnick);
  phantom->rfr = tgt->rfr;
  if (phantom->rfr != NULL)
    phantom->rfr->x.rto = phantom;
  phantom->x.rto = tgt;
  tgt->rfr = phantom;
  DBG("ircd:CLIENT: nick change: new phantom relations: %p => %p => %p",
      phantom->rfr, phantom, tgt);
  phantom->hold_upto = Time + CHASETIMELIMIT; /* nick delay for changed nick */
#if IRCD_MULTICONNECT
  _ircd_move_acks(tgt, phantom); /* move acks into the clone with old lcnick */
#endif
  strfcpy(tgt->nick, nn, sizeof(tgt->nick));
  unistrlower(tgt->lcnick, tgt->nick, sizeof(tgt->lcnick));
  if (Insert_Key(&Ircd->clients, tgt->lcnick, tgt, 1) < 0)
    ERROR("ircd:_ircd_do_nickchange: tree error on adding %s", tgt->lcnick);
    //TODO: isn't it fatal?
  else
    dprint(2, "ircd:CLIENT: nick change: new name %s", tgt->lcnick);
  return phantom;
}

static int _ircd_remote_nickchange(CLIENT *tgt, peer_priv *pp,
				   unsigned short token, const char *sender,
				   const char *nn)
{
  CLIENT *collision, *phantom;
  int changed;
  char checknick[MB_LEN_MAX*NICKLEN+NAMEMAX+2];

  dprint(5, "ircd:ircd.c:_ircd_remote_nickchange: %s to %s", tgt->nick, nn);
#if IRCD_MULTICONNECT
  if (pp->link->cl->umode & A_MULTI)
    New_Request(pp->p.iface, 0, "ACK NICK %s", sender);
#endif
  if (tgt && tgt->hold_upto != 0) {
    dprint(5, "ircd:ircd.c: nickchange collision via %s", pp->p.dname);
    tgt = _ircd_find_phantom(tgt, pp);
#if IRCD_MULTICONNECT
    collision = tgt;
    if ((pp->link->cl->umode & A_MULTI) && ircd_check_ack(pp, tgt, NULL))
      /* it's nickchange collision (we got nickchange while sent ours) */
      changed = 1;
    else
      changed = 0;
#endif
    while (tgt != NULL && tgt->hold_upto != 0)
      tgt = tgt->x.rto;			/* find current nick */
    if (pp->link->cl->umode & A_UPLINK) { /* ok, it's uplink */
#if IRCD_MULTICONNECT
      if (changed) {
	phantom = _ircd_find_client(nn);
	if (phantom != NULL && collision->x.rto != NULL &&
	    phantom == collision->x.rto->cs) {
	  dprint(4, "ircd:ircd.c: nickchange to %s already known to me", nn);
	  return 1;			/* we got the change back */
	}
      }
#endif
      if (tgt)
	dprint(5, "ircd:ircd.c:_ircd_remote_nickchange: accepting change from uplink %s => %s",
	       tgt->nick, nn);
    } else if (tgt) {			/* ok, it's downlink */
#if IRCD_MULTICONNECT
      if (changed)			/* we waiting ack on this one */
	return (1);
      if (pp->link->cl->umode & A_MULTI) {
	WARNING("ircd: got phantom NICK on %s from %s after ACK", sender,
		pp->p.dname);
	ircd_add_ack(pp, tgt, NULL);
      }
#endif
      dprint(5, "ircd:ircd.c:_ircd_remote_nickchange: reverting change from downlink %s => %s",
	     nn, tgt->nick);
      New_Request(pp->p.iface, 0, ":%s NICK :%s", nn, tgt->nick);
      return 1;
    } else
      dprint(5, "ircd:ircd.c:_ircd_remote_nickchange: nick %s already gone",
	     sender);
  }
  if (tgt == NULL || (tgt->umode & (A_SERVER | A_SERVICE))) {
    /* tgt->hold_upto can be only 0 after check above */
    ERROR("ircd:got NICK from nonexistent user %s via %s", sender, pp->p.dname);
    return ircd_recover_done(pp, "Bogus NICK sender");
  }
  if (strcmp(tgt->nick, nn) == 0) {
    Add_Request(I_LOG, "*", F_WARN, "ircd:dummy NICK change via %s for %s",
		pp->p.dname, nn);
    return ircd_recover_done(pp, "Bogus nickchange");
  }
  unistrlower(checknick, nn, sizeof(checknick));
  if (strcmp(tgt->lcnick, checknick) == 0) { /* this is just case change */
    _ircd_do_nickchange(tgt, pp, token, nn, 1);
    return (1);
  }
  changed = 1;
  if (!_ircd_validate_nickname(checknick, nn, sizeof(checknick))) {
    _ircd_transform_invalid_nick(checknick, nn, sizeof(checknick));
    ERROR("ircd:invalid NICK %s via %s => %s", nn, pp->p.dname, checknick);
    changed = -1;			/* should be corrected */
    ircd_recover_done(pp, "Invalid nick");
  }
  collision = _ircd_check_nick_collision(checknick, sizeof(checknick), pp,
					 tgt->cs ? tgt->cs->lcnick : pp->p.dname);
  if (collision != NULL && strcmp(nn, checknick)) {
    /* we have the same nick either live or on hold and we should
       to do something with the client which changed nick now */
    ERROR("ircd:nick collision on nick change %s => %s: => %s", sender, nn,
	  checknick);
    changed = -1;			/* should be changed due to collision */
  } else if (collision != NULL && collision->hold_upto == 0) {
    ERROR("ircd:internal error: _ircd_check_nick_collision() did not make decision on change %s => %s",
	  sender, nn);
    checknick[0] = '\0';		/* kill client then */
    changed = -1;
  }
  phantom = NULL;
  if (changed < 0) {			/* redo change on collision */
    phantom = _ircd_get_phantom(nn, NULL); /* order: ? -> tgt-> phantom */
#if IRCD_MULTICONNECT
    if (pp->link->cl->umode & A_MULTI)
      ircd_add_ack(pp, phantom, NULL);	/* either KILL or NICK */
    else
#endif
    phantom->hold_upto = Time + CHASETIMELIMIT; /* nick delay for collided */
    strfcpy(phantom->away, pp->p.dname, sizeof(phantom->away));
    if (checknick[0] == '\0') {		/* unresolvable nick collision */
      New_Request(pp->p.iface, 0, ":%s KILL %s :Unresolvable nick collision",
		  MY_NAME, nn);		/* send KILL back */
      _ircd_kill_collided(tgt, pp, pp->p.dname);
      tgt->x.rto = phantom;		/* set relations */
      phantom->rfr = tgt;
      phantom->x.rto = NULL;
      DBG("ircd:CLIENT: nick change collision KILL: %p => %p", tgt, phantom);
      return 1;
    }
    /* relations will be fixed after rename below */
    New_Request(pp->p.iface, 0, ":%s NICK :%s", nn, checknick);
  } else if (collision != NULL) {
    /* we have collision on new nick with phantom but decided to accept change
       and we cannot keep collided one since we'll get ->rfr filled with
       phantom which client is changed from so cannot to tail collided there */
    _ircd_force_drop_collision(&collision);
  } /* else nick change is non-colliding and just accepted */
  collision = _ircd_do_nickchange(tgt, pp, token, checknick, 0);
  /* order is now: ? -> collision=old -> (?phantom?) -> tgt=new */
  if (phantom != NULL) {		/* fix relations now */
    collision->x.rto = phantom;
    phantom->rfr = collision;
    phantom->x.rto = tgt;
    tgt->rfr = phantom;
    DBG("ircd:CLIENT: nick change new relations: %p => %p => %p", collision,
	phantom, tgt);
  }
  return 1;
}

BINDING_TYPE_ircd_server_cmd(ircd_nick_sb);
static int ircd_nick_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			const char *sender, const char *lcsender,
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
  if (ct <= 0 || ct > (int)pp->t || (on = pp->i.token[ct-1]) == NULL)
  {
    New_Request(peer->iface, 0, ":%s KILL %s :Invalid server", MY_NAME, argv[0]);
    Add_Request(I_LOG, "*", F_MODES, "KILL %s :Invalid server %hu", argv[0], ct);
#if IRCD_MULTICONNECT
    if (pp->link->cl->umode & A_MULTI)
      ircd_add_ack(pp, NULL, NULL);
#endif
    return ircd_recover_done(pp, "Bogus source server");
  }
  tgt = alloc_CLIENT();
  ct = 0;				/* use ct as a mark */
  if (!_ircd_validate_nickname(tgt->nick, argv[0], sizeof(tgt->nick))) {
    _ircd_transform_invalid_nick(tgt->nick, argv[0], sizeof(tgt->nick));
    ERROR("ircd:invalid NICK %s via %s => %s", argv[0], peer->dname, tgt->nick);
    ct = 1;				/* should be corrected */
    ircd_recover_done(pp, "Invalid nick");
#if IRCD_MULTICONNECT
    collision = NULL;
  } else
    collision = ircd_find_client(tgt->nick, pp);
  if (collision != NULL)
    DBG("found collided name %s on server %s(%p), got %s(%p)", tgt->nick,
	collision->cs->lcnick, collision->cs, on->lcnick, on);
  if (collision != NULL && collision->cs == on) {
    dprint(4, "ircd: backup introduction of %s from %s by %s", tgt->nick,
	   on->lcnick, peer->dname);
    free_CLIENT(tgt);
    return (1);
#endif
  }
  tgt->cs = on;
  tgt->hold_upto = 0;
  tgt->rfr = NULL;
  tgt->umode = 0;
  tgt->via = NULL;
  tgt->local = NULL;
  tgt->c.hannels = NULL;
  tgt->away[0] = '\0';
  collision = _ircd_check_nick_collision(tgt->nick, sizeof(tgt->nick), pp,
					 on->lcnick);
  if ((collision != NULL && collision->hold_upto == 0) || tgt->nick[0] == '\0') {
    /* another client of that nick found and still kept alive
       or asked to remove remote client too */
    ERROR("ircd:nick collision via %s: %s => %s", peer->dname, argv[0],
	  tgt->nick);
    ct = 1;				/* should be changed by collision */
  }
  if (ct != 0) {			/* change invalid/collided nick */
    /* create phantom which is tailed to collision and link it to client */
    phantom = _ircd_get_phantom(argv[0], NULL);
    phantom->rfr = NULL;
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
      Add_Request(I_LOG, "*", F_MODES, "KILL %s :Nick collission", argv[0]);
      phantom->x.rto = NULL;
      free_CLIENT(tgt);
      return 1;
    }
    phantom->x.rto = tgt;		/* set relations */
    tgt->rfr = phantom;
    New_Request(peer->iface, 0, ":%s NICK :%s", argv[0], tgt->nick);
    dprint(2, "ircd:CLIENT: adding remote client %s: %p", tgt->nick, tgt);
    DBG("ircd:CLIENT: collided NICK relations: %p => %p", phantom, tgt);
  } else if (collision != NULL) { /* we got new client collided with phantom */
    if (Delete_Key(Ircd->clients, collision->lcnick, collision) < 0)
      ERROR("ircd:ircd_nick_sb: tree error on removing %s", collision->lcnick);
      //TODO: isn't it fatal?
    else
      dprint(2, "ircd:CLIENT: del phantom name %s", collision->lcnick);
    collision->lcnick[0] = '\0';
    tgt->rfr = collision;
    while (collision) {			/* make it a nick holder now */
      collision->cs = tgt;		/* as we are about to insert it */
      collision = collision->pcl;
    }
    dprint(2, "ircd:CLIENT: adding phantom %p tailed to holder %p", tgt->rfr, tgt);
  } else
    dprint(2, "ircd:CLIENT: adding remote client %s: %p", tgt->nick, tgt);
  tgt->hops = on->hops + 1;
  unistrlower(tgt->user, argv[2], sizeof(tgt->user));
  unistrlower(tgt->host, argv[3], sizeof(tgt->host));
  strfcpy(tgt->vhost, tgt->host, sizeof(tgt->vhost));
  strfcpy(tgt->fname, argv[6], sizeof(tgt->fname));
  for (c = argv[5]; *c; c++) { /* make umode from argv[5] */
    register modeflag mf;

    if (*c == '+' && c == argv[5])
      continue;
    mf = ircd_char2umode(srv, peer->dname, *c, tgt);
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
  dprint(2, "ircd:CLIENT: added link %p on serv %s prev %p", link, on->lcnick,
	 link->prev);
  _ircd_class_rin(link); /* add it into class global list */
  on->x.a.uc++;
  DBG("ircd:updated users count on %s to %u", on->lcnick, on->x.a.uc);
  _ircd_update_users_counters();
  unistrlower(tgt->lcnick, tgt->nick, sizeof(tgt->lcnick));
  if (Insert_Key(&Ircd->clients, tgt->lcnick, tgt, 1))
    ERROR("ircd:ircd_nick_sb: tree error on adding %s (%p)", tgt->lcnick, tgt);
    //TODO: isn't it fatal?
  else
    dprint(2, "ircd:CLIENT: new remote name %s: %p", tgt->lcnick, tgt);
#ifdef USE_SERVICES
  /* notify services about new client: no token first, then with token */
  for (link = ME.c.lients; link; link = link->prev)
    if (CLIENT_IS_SERVICE(link->cl) &&
	(SERVICE_FLAGS(link->cl) & SERVICE_WANT_NICK) &&
	!(SERVICE_FLAGS(link->cl) & SERVICE_WANT_TOKEN))
      link->cl->via->p.iface->ift |= I_PENDING;
  Add_Request (I_PENDING, "*", 0, "NICK %s %hu %s %s %s +%s :%s",
	       tgt->nick, tgt->hops, argv[2], argv[3], on->lcnick, argv[5],
	       argv[6]);
  for (link = ME.c.lients; link; link = link->prev)
    if (CLIENT_IS_SERVICE(link->cl) &&
	(SERVICE_FLAGS(link->cl) & SERVICE_WANT_NICK) &&
	(SERVICE_FLAGS(link->cl) & SERVICE_WANT_TOKEN))
      link->cl->via->p.iface->ift |= I_PENDING;
#endif
  ircd_sendto_servers_all_but(Ircd, pp, on, "NICK %s %hu %s %s %hu %s :%s",
			      tgt->nick, tgt->hops, argv[2], argv[3],
			      on->x.a.token + 1, argv[5], argv[6]);
  _ircd_bt_client(tgt, NULL, tgt->nick, on->lcnick);
  return 1;
}

#if IRCD_MULTICONNECT
BINDING_TYPE_ircd_server_cmd(ircd_inum);
static int ircd_inum(INTERFACE *srv, struct peer_t *peer, unsigned short token,
		     const char *sender, const char *lcsender,
		     int argc, const char **argv)
{ /* args: <id> <numeric> <target> text... */
  struct peer_priv *pp = peer->iface->data; /* it's peer really */
  int id;

  if (argc < 4) {
    ERROR("ircd:incorrect number of arguments for INUM from %s: %d",
	  peer->dname, argc);
    return ircd_recover_done(pp, "Invalid INUM arguments");
  }
  if (!(pp->link->cl->umode & A_MULTI))
    return (0);		/* this is ambiguous to come from RFC2813 servers */
  id = atoi(argv[0]);
  if (!ircd_test_id(Ircd->token[token], id))
    //TODO: log duplicate?
    return (1);
  return _ircd_do_server_numeric(pp, sender, id, argc, argv);
}
#endif

BINDING_TYPE_ircd_server_cmd(ircd_service_sb);
static int ircd_service_sb(INTERFACE *srv, struct peer_t *peer, unsigned short token,
			   const char *sender, const char *lcsender,
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
  if (ct <= 0 || ct > (int)pp->t || (on = pp->i.token[ct-1]) == NULL)
  {
    ERROR("ircd:invalid SERVICE token %s via %s", argv[1], peer->dname);
    New_Request(peer->iface, 0, ":%s KILL %s :Invalid server", MY_NAME, argv[0]);
    Add_Request(I_LOG, "*", F_MODES, "KILL %s :Invalid server %hu", argv[0], ct);
#if IRCD_MULTICONNECT
    if (pp->link->cl->umode & A_MULTI)
      ircd_add_ack(pp, NULL, NULL);
#endif
    return ircd_recover_done(pp, "Bogus source server");
  }
  ct--;					/* tokens are sent from 1 */
  /* check if that's duplicate */
  tgt = ircd_find_client(argv[0], pp);
#if IRCD_MULTICONNECT
  if (tgt != NULL && tgt->cs == on)
  {
    dprint(4, "ircd: backup introduction of %s from %s by %s", tgt->nick,
	   on->lcnick, peer->dname);
    return (1);
  }
#endif
  if (tgt != NULL && tgt->hold_upto != 0) { /* collision with phantom */
    /* force drop phantom now */
    _ircd_force_drop_collision(&tgt);
  } else if (tgt != NULL && !CLIENT_IS_SERVICE(tgt)) {
    /* collision with nick, let remove nick then and forget it */
    _ircd_kill_collided(tgt, pp, pp->p.dname);
    tgt->hold_upto = Time;
    if (Delete_Key(Ircd->clients, tgt->lcnick, tgt) < 0)
      ERROR("ircd:ircd_nick_sb: tree error on removing %s", tgt->lcnick);
      //TODO: isn't it fatal?
    else
      dprint(2, "ircd:CLIENT: del name %s collided with SERVICE", tgt->lcnick);
    tgt->lcnick[0] = '\0';
  } else if (tgt != NULL) {
    ERROR("ircd:invalid SERVICE token %s via %s", argv[1], peer->dname);
    New_Request(peer->iface, 0, ":%s KILL %s :Service name collision",
		MY_NAME, argv[0]);
    Add_Request(I_LOG, "*", F_MODES, "KILL %s :Service name collision", argv[0]);
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
    Add_Request(I_LOG, "*", F_MODES, "KILL %s :Invalid SERVICE name", argv[0]);
#if IRCD_MULTICONNECT
    if (pp->link->cl->umode & A_MULTI)
      ircd_add_ack(pp, NULL, NULL);
#endif
    return ircd_recover_done(pp, "Bogus SERVICE name");
  }
  dprint(2, "ircd:CLIENT: adding remote service %s (%p)", tgt->nick, tgt);
  tgt->pcl = NULL;			/* service is out of classes */
  tgt->x.class = NULL;
  tgt->via = NULL;
  tgt->local = NULL;
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
  strfcpy(tgt->vhost, argv[2], sizeof(tgt->vhost));
  strfcpy(tgt->fname, argv[5], sizeof(tgt->fname));
  link = alloc_LINK();
  link->cl = tgt;
  link->where = on;
  link->prev = on->c.lients;
  link->flags = 0;
  on->c.lients = link;
  dprint(2, "ircd:service: added link %p on serv %s prev %p", link, on->lcnick,
	 link->prev);
  unistrlower(tgt->lcnick, tgt->nick, sizeof(tgt->lcnick));
  if (Insert_Key(&Ircd->clients, tgt->lcnick, tgt, 1))
    ERROR("ircd:ircd_service_sb: tree error on adding %s (%p)", tgt->lcnick, tgt);
    //TODO: isn't it fatal?
  else
    dprint(2, "ircd:CLIENT: new remote service name %s: %p", tgt->lcnick, tgt);
  ircd_sendto_servers_mask(Ircd, pp, argv[2], ":%s SERVICE %s %hu %s %s %hu :%s",
			   sender, tgt->nick, on->x.a.token + 1, argv[2], argv[3],
			   tgt->hops, argv[5]);
#ifdef USE_SERVICES
  /* notify services about new service, using server name instead of token */
  ircd_sendto_services_all(Ircd, SERVICE_WANT_SERVICE,
			   "SERVICE %s %s %s %s %hu :%s", tgt->nick, on->lcnick,
			   argv[2], argv[3], tgt->hops, argv[5]);
#endif
  //TODO: BTIrcdGotRemote
  return 1;
}
#undef __TRANSIT__
#define __TRANSIT__


/* light version of case-insencitive search engine */
static inline CHANNEL *_ircd_find_channel_c (const char *name)
{
  char lcname[MB_LEN_MAX*CHANNAMELEN+1];
//  register char *c;

  unistrlower (lcname, name, sizeof(lcname));
//  if ((c = strrchr (lcname, '@')))
//    *c = '\0';
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
#ifdef TOPICWHOTIME
    if (lname)
      *lname = ch->topic_by;
    if (idle)
      *idle = ch->topic_since;
#endif
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
    *host = cl->vhost;
  if (lname)
    *lname = cl->user;
  if (idle && !CLIENT_IS_REMOTE(cl))
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

/* this one should be the fastest way to get MY_NAME */
BINDING_TYPE_ison(ison_ircd);
static int ison_ircd(const char *net, const char *public, const char *lname,
		     const char **name)
{
  CLASS *cl;
  MEMBER *ch;
  CLIENT *cli;
  CHANNEL *chi;

  /* ignoring parameter net, we are only-one-network */
  if (lname == NULL)			/* own name requested */
  {
    if (name)
      *name = MY_NAME;
    return (1);
  }
  /* search for lname may be slow but what else? */
  for (cl = Ircd->users; cl; cl = cl->next)
    if (strcmp(lname, cl->name) == 0)	/* found match */
      break;
  if (public == NULL)			/* global state requested */
  {
    if (cl == NULL)			/* last chance, check for server */
    {
      unsigned short int i;
      for (i = 0; i < Ircd->s; i++)
	if (strcmp(lname, Ircd->token[i]->nick) == 0) /* found match */
	{
	  if (name)
	    *name = lname;
	  return (1);
	}
      return (0);
    }
    if (cl->glob == NULL)		/* empty class? is that possible? */
      return (0);
    if (name)
      *name = cl->glob->nick;
    return (1);
  }
  if (cl == NULL || cl->glob == NULL)
    return (0);
  /* find class in public may be slow as well */
  chi = _ircd_find_channel_c (public);
  if (chi == NULL)
    return (0);
  for (cli = cl->glob; cli; cli = cli->pcl)
    for (ch = cli->c.hannels; ch; ch = ch->prevchan)
      if (ch->chan == chi)		/* found match */
      {
	if (name)
	  *name = cli->nick;
	return (1);
      }
  return (0);
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
    if (peer->p.state < P_LOGIN) /* no link data yet */
      continue;
    snprintf (buf, sizeof(buf), "%s[%s@%s] %d %zu %zu %zu %zu %ld",
	      peer->link->cl->nick, peer->link->cl->user, peer->link->cl->host,
	      peer->p.iface->qsize, peer->ms, peer->bs/1000, peer->mr,
	      peer->br/1000, (long int)(Time - peer->started));
    _ircd_do_server_message (NULL, 4, argv);
  }
  pthread_mutex_unlock (&IrcdLock);
}

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
    hc = bc->hits;
    bs = Check_Bindtable (BTIrcdServerCmd, bc->key, U_ALL, U_ANYCH, NULL);
    if (bs)
      hs = --bs->hits;
    else
      hs = 0;
    if (_ircd_statm_empty_too || hc > 0 || hs > 0)
    {
      snprintf (buf, sizeof(buf), "%s %u %u", bc->key, hc, hs);
      _ircd_do_server_message (NULL, 4, argv);
    }
  }
  /* show server-only commands */
  while ((bc = Check_Bindtable (BTIrcdServerCmd, NULL, U_ALL, U_ANYCH, bc)))
  {
    bs = Check_Bindtable (BTIrcdClientCmd, bc->key, U_ALL, U_ANYCH, NULL);
    if (bs) {
      bs->hits--;
      continue;				/* it was shown on previous cycle */
    }
    hs = bc->hits;
    if (_ircd_statm_empty_too || hs)
    {
      snprintf (buf, sizeof(buf), "%s 0 %u", bc->key, hs);
      _ircd_do_server_message (NULL, 4, argv);
    }
  }
}


/* -- "time-shift" binding to work out TZ corrections --------------------- */
BINDING_TYPE_time_shift (ts_ircd);
static void ts_ircd (int drift)
{
  register peer_priv *peer;

  pthread_mutex_lock (&IrcdLock);
  for (peer = IrcdPeers; peer != NULL; peer = peer->p.priv) {
    peer->p.last_input += drift; /* correct time for keep-alive */
    if (peer->noidle > peer->p.last_input) /* so it was TZ change */
      peer->noidle = peer->p.last_input; /* correct idle time too */
  }
  pthread_mutex_unlock (&IrcdLock);
}


/* -- I_CLIENT @network interface ----------------------------------------- */
static int _ircd_sub_request (INTERFACE *cli, REQUEST *req)
{
  char lcname[MB_LEN_MAX*NICKLEN+1];
  char *c;
  CLIENT *tgt;

  if (!req)				/* it's idle call */
    return REQ_OK;
  if (req->to[0] == '@')
  {
    /* do broadcast to every local client */
    register LINK *cll;

    for (cll = ME.c.lients; cll; cll = cll->prev)
      cll->cl->via->p.iface->ift |= I_PENDING;
    Add_Request (I_PENDING, "*", 0, "%s", req->string);
    return REQ_OK;
  }
  unistrlower (lcname, req->to, sizeof(lcname));
  c = strchr (lcname, '@');
  if (c)
    *c = '\0';
  tgt = _ircd_find_client_lc (lcname);
  if (tgt && tgt->via)
    /* just bounce it to actual server interface */
    return _ircd_client_request (tgt->via->p.iface, req);
  /* invalid recipient */
  Add_Request (I_LOG, "*", F_WARN, "ircd: request for unknown target \"%s\"", lcname);
  return REQ_OK;
}


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
    _ircd_free_token (((CLIENT *)cl)->x.a.token);
    dprint(2, "ircd:CLIENT: deleting client %p", cl);
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
    dprint(2, "ircd:CLIENT: deleting phantomized %p", cl);
    free_CLIENT(tmp);
  }
  /* nothing else to do for user */
}

static iftype_t _ircd_signal (INTERFACE *iface, ifsig_t sig)
{
  CLASS *cl;
  LINK *s;
  size_t i;

  DBG("_ircd_signal: got sig=%d", (int)sig);
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

	dprint (5, "ircd: killing peer %s.", IrcdPeers->p.dname);
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
      Destroy_Tree (&Ircd->clients, &_ircd_catch_undeleted_cl);
      if (Ircd->sub)
      {
	Ircd->sub->ift |= I_DIED;
	Ircd->sub = NULL;
      }
      Ircd->iface = NULL;
      if (iface) {
	iface->ift |= I_DIED; /* it will free Ircd */
	iface->data = NULL; /* module owns it */
      } else
	WARNING("ircd:cannot find main interface for termination!");
      break;
    case S_TIMEOUT:
      _ircd_do_init_uplinks();
      _uplinks_timer = -1;
      break;
    default: ;
  }
  return 0;
}


/* -- common functions ---------------------------------------------------- */
void ircd_drop_nick (CLIENT *cl)
{
  dprint(5, "ircd:CLIENT:ircd_drop_nick: %s: %p", cl->nick, cl);
  if (cl->umode & A_SERVER) {
    dprint(2, "ircd:CLIENT: deleting server %p", cl);
    free_CLIENT(cl);
  } else if (cl->via != NULL && cl->via->p.state == P_QUIT)
    return;				/* it's at last message sending */
  else if (cl->via != NULL)
    ERROR("ircd:ircd_drop_nick() not for nick on hold: %s", cl->nick);
  else if (cl->cs->hold_upto != 0)
    _ircd_try_drop_collision(&cl->cs);	/* phantom nick holder */
  else if (cl->cs->rfr != NULL && cl->cs->rfr->cs == cl->cs)
    _ircd_try_drop_collision(&cl->cs->rfr); /* active nick holder */
  else
    ERROR("ircd:ircd_drop_nick() reference error: %s -> %s", cl->nick, cl->cs->nick);
}

/* finds alive client which probably known for server pp */
CLIENT *ircd_find_client (const char *name, peer_priv *via)
{
  register CLIENT *c;

  if (!name)
    return &ME;
  c = _ircd_find_client (name);
  if (c == NULL || (c->hold_upto == 0)) {
    dprint(5, "ircd:ircd.c:ircd_find_client: %s: %p", name, c);
    return (c);
  } else
    dprint(5, "ircd:ircd.c:ircd_find_client: %s: %p (phantom)", name, c);
  if (via == NULL)
    return (NULL);
  c = _ircd_find_phantom(c, via);
  while (c != NULL && c->hold_upto != 0)
    c = c->x.rto;
  return (c);
}

/* finds alive or phantom client which probably known for server via */
CLIENT *ircd_find_client_nt(const char *name, peer_priv *via)
{
  register CLIENT *c;

  if (!name)
    return &ME;
  dprint(5, "ircd:ircd.c:ircd_find_client_nt: %s", name);
  c = _ircd_find_client(name);
  if (c == NULL || via == NULL || (c->hold_upto == 0))
    return (c);
  return (_ircd_find_phantom(c, via));
}

/* manages lists, prepares to notify network about that quit (I_PENDING),
   and kills peer if it's local */
void ircd_prepare_quit (CLIENT *client, peer_priv *via, const char *msg)
{
  dprint(5, "ircd:ircd.c:ircd_prepare_quit: %s", client->nick);
  if (client->hold_upto != 0 || CLIENT_IS_SERVER(client)) {
    ERROR("ircd:ircd_prepare_quit: %s isn't online user", client->nick);
    return;
  }
  if (CLIENT_IS_REMOTE (client))
    _ircd_remote_user_gone(client);
  else
    _ircd_peer_kill (client->via, msg);
  ircd_quit_all_channels (Ircd, client, 0, 1); /* remove and mark */
}

/* see also _ircd_peer_kill(), client might be on acks yet */
static inline void _ircd_release_rserver(CLIENT *cl)
{
#if IRCD_MULTICONNECT
  if (cl->on_ack) /* convert the server into phantom instead of freeing */
  {
    cl->hold_upto = Time;
    cl->away[0] = '\0';
    cl->pcl = NULL;
    DBG("ircd:_ircd_release_rserver: holding %s(%p) until acks gone", cl->nick, cl);
    return;
  }
#endif
  dprint(2, "ircd:CLIENT: deleting gone server %s: %p", cl->nick, cl);
  free_CLIENT(cl);
}

/* clears link->cl and notifies local users about lost server */
static inline void _ircd_squit_one (LINK *link)
{
  CLIENT *server = link->cl, *tgt;
  LINK *l;
  LEAF *leaf = NULL;

  /* drop phantoms if there were referenced on this server */
  while ((leaf = Next_Leaf(Ircd->clients, leaf, NULL))) {
    tgt = leaf->s.data;
    if (CLIENT_IS_SERVER(tgt))
      continue;
    if (tgt->hold_upto == 0) {
      if (tgt->rfr == NULL || tgt->rfr->cs != tgt) /* it's not nick holder */
	continue;
      tgt = tgt->rfr;		/* go to phantoms list */
    }
    do {
      if (tgt->hold_upto > Time && !strcmp(tgt->away, server->lcnick)) {
	dprint(2, "ircd:ircd.c:_ircd_squit_one: dropping phantom %s",
	       tgt->cs->lcnick);
	tgt->away[0] = '\0';
	tgt->hold_upto = 1;	/* it will be wiped eventually */
      }
      tgt = tgt->pcl;
    } while (tgt != NULL);
  }
  /* notify local users about complete squit and clear server->c.lients */
  while ((l = server->c.lients))
  {
    tgt = l->cl;
    server->c.lients = l->prev;
    if (CLIENT_IS_SERVER (tgt)) /* server is gone so free all */
    {
      pthread_mutex_lock (&IrcdLock);
      if (tgt->lcnick[0] == '\0')	/* see _ircd_do_squit() */
	_ircd_release_rserver(tgt);
      /* link is about to be destroyed so don't remove token of l */
      free_LINK (l);			/* see _ircd_do_squit */
      dprint(2, "ircd: link %p freed", l);
      pthread_mutex_unlock (&IrcdLock);
      continue;
    }
    ircd_quit_all_channels (Ircd, tgt, 1, 1); /* it's user, remove it */
#ifdef USE_SERVICES
    ircd_sendto_services_mark_prefix (Ircd, SERVICE_WANT_QUIT);
#endif
    Add_Request (I_PENDING, "*", 0, ":%s!%s@%s QUIT :%s %s", tgt->nick,
		 tgt->user, tgt->vhost, link->where->lcnick, server->lcnick);
		 /* send split message */
    _ircd_class_out (l);		/* remove from global class list */
    _ircd_bt_client(tgt, tgt->nick, NULL, server->lcnick); /* "ircd-client" */
    tgt->hold_upto = Time + _ircd_hold_period; /* put it in temp. unavailable list */
    tgt->x.rto = NULL;			/* convert active user into phantom */
    tgt->cs = tgt;			/* it holds key for itself */
    tgt->away[0] = '\0';		/* it's used by nick change tracking */
    if (tgt->rfr != NULL && tgt->rfr->cs == tgt) { /* it was nick holder */
      tgt->pcl = tgt->rfr;
      tgt->rfr = NULL;
      dprint(2, "ircd:CLIENT: converting holder %s (%p) into phantom, prev %p",
	     tgt->nick, tgt, tgt->pcl);
    }
    strfcpy (tgt->host, server->lcnick, sizeof(tgt->host));
    pthread_mutex_lock (&IrcdLock);
    free_LINK (l);
    dprint(2, "ircd: link %p freed", l);
    pthread_mutex_unlock (&IrcdLock);
  }
  _ircd_free_token (server->x.a.token);	/* no token for gone server */
  for (l = Ircd->servers; l; l = l->prev) { /* for each local server */
    register peer_priv *pp = l->cl->via;
    register unsigned short i;

    for (i = 0; i < pp->t; i++)		/* check each its token */
      if (pp->i.token[i] == server)
	pp->i.token[i] = NULL;		/* and clear if found */
  }
}

/* remote link squitted */
static inline void _ircd_rserver_out (LINK *l)
{
  register LINK **s;

  dprint(2, "ircd:server: unshifting link %p prev %p", l, l->prev);
  for (s = &l->where->c.lients; *s; s = &(*s)->prev)
    if ((*s) == l)
      break;
  if (*s)
    *s = l->prev;
  else
    ERROR ("ircd:_ircd_rserver_out: server %s not found on %s!", l->cl->nick,
	   l->where->lcnick);
  pthread_mutex_lock (&IrcdLock);
  if (l->cl->lcnick[0] == '\0')		/* see _ircd_do_squit() */
    _ircd_release_rserver(l->cl);
  free_LINK (l);
  pthread_mutex_unlock (&IrcdLock);
}

/* notify local servers about squit */
static inline void _ircd_send_squit (LINK *link, peer_priv *via, const char *msg, bool all)
{
  /* notify local servers about squit */
#if IRCD_MULTICONNECT
  if (all) {
#endif
#ifdef USE_SERVICES
    ircd_sendto_services_mark_all (Ircd, SERVICE_WANT_SQUIT);
#endif
    ircd_sendto_servers_all_ack(Ircd, link->cl, NULL, via, ":%s SQUIT %s :%s",
				link->where->lcnick, link->cl->lcnick, msg);
#if IRCD_MULTICONNECT
  } else
    ircd_sendto_servers_new_ack(Ircd, link->cl, NULL, via, ":%s SQUIT %s :%s",
				link->where->lcnick, link->cl->lcnick, msg);
#endif
  Add_Request(I_LOG, "*", F_SERV, "Received SQUIT %s from %s (%s)",
	      link->cl->lcnick, link->where->lcnick, msg);
}

#if IRCD_MULTICONNECT
/* check if server behind link */
static LINK *_ircd_check_multiconnect (LINK *link, peer_priv *via)
{
  LINK *s1 = NULL, *s2 = NULL;
  register CLIENT *t;
  size_t i;

  if (link->cl->umode & A_MULTI)
  {
    /* scan local server links first */
    if (link->where != &ME) for (s1 = Ircd->servers; s1; s1 = s1->prev)
      if (s1->cl == link->cl)
	break; /* the squit'ed server is also our link */
    /* also scan all servers to check for multiconnect after link removal */
    for (i = 1; s2 == NULL && i < Ircd->s; i++)
      if ((t = Ircd->token[i]) == NULL || t == link->cl || t == link->where)
	continue; /* got another server which is neither one of this pair */
      else /* scan its links for squit'ed server */
	for (s2 = t->c.lients; s2; s2 = s2->prev)
	  if (s2->cl == link->cl) {
	    if (s1 == NULL)
	      s1 = s2; /* found one connect */
	    else
	      break; /* that will break outer loop too */
	  }
  }
  if (s2 != NULL) { /* it's multiconnected still, just notify */
    DBG ("ircd:ircd_do_squit: server %s is also connected via %s and %s",
	 link->cl->lcnick, s1->where->lcnick, s2->where->lcnick);
  } else if (s1 != NULL) { /* it's single connected now so clear links further */
    DBG ("ircd:ircd_do_squit: server %s is also connected via %s",
	 link->cl->lcnick, s1->where->lcnick);
    if (s1->where == &ME)		/* we never record backlinks to me */
      return s1;
    for (s2 = link->cl->c.lients; s2; s2 = s2->prev) /* find direct link */
      if (s2->cl == s1->where)
	break;
    if (s2 == NULL) {
      DBG ("ircd:ircd_do_squit: link from server %s to %s already gone, skip checks",
	   link->cl->lcnick, s1->where->lcnick);
      return s1;
    }
    if (!_ircd_check_multiconnect (s2, via)) {
      ERROR ("ircd:ircd_do_squit: server %s multi-connected via dead-end %s, clearing up",
	     link->cl->lcnick, s2->cl->lcnick);
      return NULL;
    }
    /* well, link will be gone now, send notification and remove link */
    _ircd_send_squit (s2, via, link->cl->lcnick, FALSE);
    _ircd_rserver_out (s2);
  }
  return s1; /* it's just a marker now */
}
#endif

/* server is gone; notifies network recursively and clears link->cl
   does not not remove link->cl from link->where */
static void _ircd_do_squit (LINK *link, peer_priv *via, const char *msg)
{
  register LINK *s;

#if IRCD_MULTICONNECT
  /* the link might have incomplete burst, don't remove it if multiconnected */
  s = _ircd_check_multiconnect (link, via);
  if (s != NULL) { /* it's multiconnected, just notify now */
    _ircd_send_squit (link, via, msg, FALSE);
    return;
  } /* else it's completely gone from network */
#endif
  for (s = link->cl->c.lients ; s; s = s->prev) /* squit all behind it first */
    if (CLIENT_IS_SERVER (s->cl) && s->cl != link->where) /* could point back */
      _ircd_do_squit (s, via, link->cl->lcnick); /* reason is the server gone */
  _ircd_squit_one (link); /* no one left behind; clear and notify users */
  _ircd_send_squit (link, via, msg, TRUE); /* notify local servers now */
  if (link->where != &ME) /* it's remote, for local see ircd_do_squit() */
  {
#if IRCD_MULTICONNECT
    if (link->cl->local != NULL) /* there is a local link in P_QUIT state */
    {
      /* let _ircd_client_request() process it as needed instead */
      link->cl->via = link->cl->local;
      return;
    }
#endif
    if (Delete_Key (Ircd->clients, link->cl->lcnick, link->cl)) /* remove it */
      ERROR("ircd:_ircd_do_squit: tree error on removing %s", link->cl->lcnick);
      // TODO: isn't it fatal?
    else
      dprint (2, "ircd:CLIENT: del remote server name %s", link->cl->lcnick);
    link->cl->lcnick[0] = '\0'; /* mark it to delete */
  }
}

/* local link squitted */
static inline void _ircd_lserver_out (LINK *l)
{
  register LINK **s;
  struct binding_t *b = NULL;

  for (s = &Ircd->servers; *s; s = &(*s)->prev)
    if ((*s) == l)
      break;
  dprint(2, "ircd:server: trying unshift %p prev %p", l, l->prev);
  if (*s)
    *s = l->prev;
  else
    ERROR ("ircd:_ircd_lserver_out: local server %s not found in list!",
	   l->cl->lcnick);
  l->cl->umode &= ~A_UPLINK;	/* it's valid only for local connects */
  if (l->cl->local == NULL)
    ERROR("ircd:_ircd_lserver_out: server %s isn't a local one!", l->cl->lcnick);
  else
    /* tell other modules about disconnected server */
    while ((b = Check_Bindtable(BTIrcdLostServer, l->cl->lcnick, U_ALL, U_ANYCH, b)))
      if (b->name == NULL) /* internal only */
	b->func(Ircd->iface, &l->cl->local->p);
}

/* if this server is multiconnected then we should only remove one instance
   and notify local servers but if it's only instance then do it recursively
   via is where SQUIT came from */
void ircd_do_squit (LINK *link, peer_priv *via, const char *msg)
{
  dprint(5, "ircd:ircd.c:ircd_do_squit: %s", link->cl->nick);
  _ircd_do_squit (link, via, msg); /* notify everyone */
  if (link->where == &ME) /* it's local */
  {
#if IRCD_MULTICONNECT
    ircd_clear_acks (Ircd, link->cl->via); /* clear acks */
#endif
    _ircd_peer_kill (link->cl->via, msg); /* it will free structures */
  }
  else
    _ircd_rserver_out (link); /* remove it from link->where list and free it */
#if IRCD_MULTICONNECT
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
	  CLIENT_IS_SERVER(target) ? target->fname : target->vhost,
	  target->user,
	  CLIENT_IS_SERVER(target) ? target->lcnick : target->nick, 0, i,
	  target->via ? (Time - target->via->p.last_input) : (time_t)0, m);
  if (!b || b->name ||
      !b->func (Ircd->iface, n, requestor->nick, requestor->umode, buff))
  {
    char *rnick = (requestor->nick[0]) ? requestor->nick : MY_NAME;

    if (CLIENT_IS_REMOTE(requestor)) {	/* send numeric or INUM */
      ircd_sendto_new (requestor, NULL, NULL, ":%s INUM %d %03d %s %s", MY_NAME,
		       ircd_new_id(), n, rnick, buff);
      ircd_sendto_old (requestor, ":%s %03d %s %s", MY_NAME, n, rnick, buff);
    } else				/* send it directly */
      New_Request (requestor->via->p.iface, 0, ":%s %03d %s %s", MY_NAME, n,
		   rnick, buff);
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
  /* macros: %N - nick(requestor), %# - channel, %P - $i, %* - $m */
  printl (buff, sizeof(buff), template, 0, requestor->nick, NULL,
	  NULL, target->name, 0, i, 0, m);
  if (!b || b->name ||
      !b->func (Ircd->iface, n, requestor->nick, requestor->umode, buff))
  {
    if (CLIENT_IS_REMOTE(requestor)) {	/* send numeric or INUM */
      ircd_sendto_new (requestor, NULL, NULL, ":%s INUM %d %03d %s %s", MY_NAME,
		       ircd_new_id(), n, requestor->nick, buff);
      ircd_sendto_old (requestor, ":%s %03d %s %s", MY_NAME, n,
		       requestor->nick, buff);
    } else				/* send it directly */
      New_Request (requestor->via->p.iface, 0, ":%s %03d %s %s", MY_NAME, n,
		   requestor->nick, buff);
  }
  return 1;
}

int ircd_recover_done (peer_priv *peer, const char *msg)
{
  if (CheckFlood (&peer->penalty, _ircd_corrections) > 0)
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

  dprint(5, "ircd:ircd.c:ircd_try_connect: %s", name);
  u = Lock_byLID (lid);
  if (!u)
    return ircd_do_unumeric (rq, ERR_NOSUCHSERVER, rq, atoi (port), name);
  uf = Get_Flags (u, Ircd->iface->name);
  Unlock_Clientrecord (u);
  if (!(uf & U_UNSHARED))
    return ircd_do_unumeric (rq, ERR_NOSUCHSERVER, rq, atoi (port), name);
  tmp = Add_Iface (I_TEMP, NULL, NULL, &_ircd_sublist_receiver, NULL);
  Set_Iface (tmp);
  _ircd_sublist_buffer = host;
  if (Get_Hostlist (tmp, lid))
  {
    char *h, *p;			/* host, pass */

    Get_Request();
    p = gettoken (host, NULL);		/* isolate first host of it */
    DBG("ircd_try_connect: got token %s", host);
    if ((h = strchr (host, '@')))	/* get host name from record */
      *h++ = 0;
    else
      h = host;
    p = strchr (h, '/');		/* check for port */
    if (p)
      *p = 0;
    if (h == host)
      p = NULL;
    else if ((p = safe_strchr (host, ':'))) /* check for password */
      p++;
    DBG("ircd_try_connect: host=%s port=%s pass=%s", h, port, p);
    _ircd_start_uplink2 (name, h, port, p); /* create a connection thread */
  }
  else
    ERROR ("ircd:server %s has no host record, ignoring CONNECT", name);
  Unset_Iface();
  tmp->ift = I_DIED;
  ircd_sendto_wallops(Ircd, NULL, MY_NAME, "Connect '%s %s' from %s", name,
		      port, rq->nick);
  return 1;
}

/* if tgt is NULL then show all, tgt should be local! */
int ircd_show_trace (CLIENT *rq, CLIENT *tgt)
{
  peer_priv *t;
  LINK *l;
  int sc, ss;
  unsigned short i;
  CLASS *c;
  char flags[8];
  char buf[MESSAGEMAX];

  if (tgt != NULL)
    switch (tgt->via->p.state)
    {
      case P_DISCONNECTED:
      case P_INITIAL:
	return ircd_do_unumeric (rq, RPL_TRACECONNECTING, &ME, 0, "-");
      case P_IDLE:
      case P_LOGIN:
	return ircd_do_unumeric (rq, RPL_TRACEHANDSHAKE, &ME, 0, "-");
      case P_QUIT:
      case P_LASTWAIT:
	return ircd_do_unumeric (rq, RPL_TRACEUNKNOWN, &ME, 0, "-");
      case P_TALK:
	if (CLIENT_IS_SERVER (tgt)) {
	  sc = 0;
	  if (tgt->umode & A_UPLINK)
	    flags[sc++] = 'c';
#if IRCD_MULTICONNECT
	  if (tgt->umode & A_MULTI)
	    flags[sc++] = 'm';
#endif
#if IRCD_USES_ICONV
	  if (!strcasecmp(Conversion_Charset(tgt->via->p.iface->conv),
			  CHARSET_UNICODE))
	    flags[sc++] = 'u';
#endif
	  /* special support for Zlib connection */
	  if (Connchain_Check(&tgt->via->p, 'Z') < 0)
	    flags[sc++] = 'z';
	  flags[sc] = '\0';
	  for (ss = 0, sc = 0, i = 1; i < Ircd->s; i++)
	    if (Ircd->token[i] != NULL && Ircd->token[i]->via == tgt->via)
	      for (l = Ircd->token[i]->c.lients, ss++; l; l = l->prev)
		if (!CLIENT_IS_SERVER(l->cl))
		  sc++;
	  snprintf (buf, sizeof(buf), "- %dS %dC %s *!*@%s V%c%s", ss, sc,
		    tgt->nick, tgt->host, tgt->away[3], flags);
	  return ircd_do_unumeric (rq, RPL_TRACESERVER, tgt, 0, buf);
#ifdef USE_SERVICES
	} else if (CLIENT_IS_SERVICE (tgt)) {
	  snprintf (buf, sizeof(buf), "%s %s %s :%s",
		    tgt->x.class ? tgt->x.class->name : "-", tgt->nick,
		    tgt->away, tgt->fname);
	  return ircd_do_unumeric (rq, RPL_TRACESERVICE, tgt, 0, buf);
#endif
	} else if (tgt->umode & (A_OP | A_HALFOP))
	  return ircd_do_unumeric (rq, RPL_TRACEOPERATOR, tgt, 0,
				   tgt->x.class ? tgt->x.class->name : "-");
	else if (!tgt->x.class)
	  return ircd_do_unumeric (rq, RPL_TRACENEWTYPE, tgt, 0, "Unclassed");
	return ircd_do_unumeric (rq, RPL_TRACEUSER, tgt, 0, tgt->x.class->name);
    }
  if (_ircd_trace_users && !CLIENT_IS_REMOTE(rq) && (rq->umode & (A_OP | A_HALFOP)))
    tgt = rq;				/* mark it for full listing */
  pthread_mutex_lock (&IrcdLock);
  for (t = IrcdPeers; t; t = t->p.priv)
    if (tgt || (t->link->cl->umode & (A_SERVER | A_SERVICE | A_OP | A_HALFOP)))
      ircd_show_trace (rq, t->link->cl);
  if (_ircd_trace_users && CLIENT_IS_REMOTE(rq) && (rq->umode & A_OP))
    /* for remote opers only */
    for (c = Ircd->users; c; c = c->next)
      ircd_do_unumeric (rq, RPL_TRACECLASS, rq, c->lin, c->name);
  pthread_mutex_unlock (&IrcdLock);
  return 1;
// RPL_TRACELOG
}

int ircd_lusers_unknown(void)
{
  register peer_priv *t;
  int i = 0;

  pthread_mutex_lock (&IrcdLock);
  for (t = IrcdPeers; t; t = t->p.priv)
    if (t->p.state < P_QUIT && t->p.state != P_TALK) /* ignore terminating ones */
      i++;
  pthread_mutex_unlock (&IrcdLock);
  return (i);
}

const char *ircd_mark_wallops(void)
{
  register LINK *cll;

  for (cll = ME.c.lients; cll; cll = cll->prev)
    if ((cll->cl->umode & A_WALLOP) &&
	(!_ircd_wallop_only_opers || (cll->cl->umode & (A_OP | A_HALFOP))))
      cll->cl->via->p.iface->ift |= I_PENDING;
#ifdef USE_SERVICES
    else if (CLIENT_IS_SERVICE(cll->cl) &&
	     (SERVICE_FLAGS(cll->cl) & SERVICE_WANT_WALLOP))
      cll->cl->via->p.iface->ift |= I_PENDING;
#endif
  return (MY_NAME);
}

CLIENT *ircd_find_by_userhost(const char *nick, int ns, const char *user, int us,
			      const char *host, int hs)
{
  CLIENT *cl;
  LEAF *leaf = NULL;
  char lcnick[MB_LEN_MAX*NICKLEN+1];
  char lchost[HOSTLEN+1];
  int len;

  DBG("ircd:ircd_find_by_userhost: nick=%.*s user=%.*s host=%.*s", ns, nick, us, user, hs, host);
  /* it is easy with nick... */
  if (nick && ns > 0)
  {
    len = unistrcut (nick, ns+1, NICKLEN);
    if (len < ns)
      return NULL;
    unistrlower (lcnick, nick, len + 1);
    cl = _ircd_find_client_lc (lcnick);
    if (!cl)
      return cl;
    if (user && us > 0)
      if (strcmp (user, cl->user))
	return NULL;
    if (!host || hs <= 0)
      return cl;
    unistrlower (lchost, host, hs < HOSTLEN ? hs + 1 : HOSTLEN + 1);
    if (strcmp (lchost, cl->host))
      return NULL;
    return cl;
  }
  /* ouch, now comes a heavy scan... */
  if (hs <= 0)
    host = NULL;
  if (us <= 0)
    user = NULL;
  if (host)
    unistrlower (lchost, host, hs < HOSTLEN ? hs + 1 : HOSTLEN + 1);
  else if (!user) /* nothing to find? */
    return NULL;
  while ((leaf = Next_Leaf (Ircd->clients, leaf, NULL)))
  {
    cl = leaf->s.data;
    if (user)
      if (strcmp (user, cl->user) != 0)
	continue;
    if (host && strcmp (lchost, cl->host) == 0)
      return cl;
  }
  return NULL;
}

/* -- command line interface ---------------------------------------------- */
                /* .+hub server mask */
BINDING_TYPE_dcc (dc__phub);
static int dc__phub (struct peer_t *dcc, char *args)
{
  char *c, *r;
  struct clrec_t *u;
  int ret;

  if (!args)
    return 0;				/* need exactly 2 args */
  r = gettoken (args, &c);
  if (!*r)
    return 0;				/* need exactly 2 args */
  u = Lock_Clientrecord (args);
  if (!u)
  {
    New_Request (dcc->iface, 0, "Server %s not found", args);
    if (*r)
      *c = ' ';
    return 0;
  }
  args = safe_strdup(Get_Field(u, NULL, NULL)); /* unalias the name */
  ret = Grow_Field (u, "hub", r);
  Unlock_Clientrecord (u);
  if (ret)
    New_Request (dcc->iface, 0, "Added hub mask \"%s\" for %s.", r, args);
  else
    New_Request (dcc->iface, 0, "Failed to add hub mask \"%s\" for %s.", r, args);
  FREE(&args);
  *c = ' ';
  return 1;
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
		  sizeof(_ircd_description_string), 0);
  RegisterInteger ("ircd-hold-period", &_ircd_hold_period);
  RegisterInteger ("ircd-serverclass-pingf", &_ircd_server_class_pingf);
  RegisterBoolean ("ircd-squit-youngest", &_ircd_squit_youngest);
  RegisterBoolean ("ircd-statm-empty-too", &_ircd_statm_empty_too);
  RegisterBoolean ("ircd-trace-users", &_ircd_trace_users);
  RegisterBoolean ("ircd-public-topic", &_ircd_public_topic);
  RegisterBoolean ("ircd-idle-from-msg", &_ircd_idle_from_msg);
  RegisterBoolean ("ircd-default-invisible", &_ircd_default_invisible);
  RegisterBoolean ("ircd-wallop-only-opers", &_ircd_wallop_only_opers);
  RegisterBoolean ("ircd-no-spare-invites", &_ircd_no_spare_invites);
  RegisterBoolean ("ircd-strict-modecmd", &_ircd_strict_modecmd);
  RegisterBoolean ("ircd-ignore-mkey-arg", &_ircd_ignore_mkey_arg);
  RegisterInteger ("ircd-max-bans", &_ircd_max_bans);
  RegisterInteger ("ircd-max-channels", &_ircd_max_channels);
  RegisterString ("ircd-nicklen", _ircd_nicklen_str, sizeof(_ircd_nicklen_str), 1);
  ircd_queries_register();
  RegisterFunction ("ircd", &func_ircd, "[-charset ][host/]port[%flags]");
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
      UnregisterVariable ("ircd-squit-youngest");
      UnregisterVariable ("ircd-statm-empty-too");
      UnregisterVariable ("ircd-trace-users");
      UnregisterVariable ("ircd-public-topic");
      UnregisterVariable ("ircd-idle-from-msg");
      UnregisterVariable ("ircd-default-invisible");
      UnregisterVariable ("ircd-wallop-only-opers");
      UnregisterVariable ("ircd-no-spare-invites");
      UnregisterVariable ("ircd-strict-modecmd");
      UnregisterVariable ("ircd-ignore-mkey-arg");
      UnregisterVariable ("ircd-max-bans");
      UnregisterVariable ("ircd-max-channels");
      UnregisterVariable ("ircd-nicklen");
      UnregisterFunction ("ircd");
      Delete_Binding ("ircd-auth", &_ircd_class_in, NULL);
      Delete_Binding ("ircd-register-cmd", &ircd_pass, NULL);
      Delete_Binding ("ircd-register-cmd", &ircd_quit_rb, NULL);
      Delete_Binding ("ircd-register-cmd", &ircd_server_rb, NULL);
      Delete_Binding ("ircd-register-cmd", &__ignored__rb, NULL);
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
      Delete_Binding ("time-shift", (Function)&ts_ircd, NULL);
      Delete_Binding ("connchain-grow", &_ccfilter_P_init, NULL);
#if IRCD_USES_ICONV
      Delete_Binding ("connchain-grow", &_ccfilter_U_init, NULL);
#endif
#if IRCD_MULTICONNECT
      Delete_Binding ("connchain-grow", &_ccfilter_I_init, NULL);
#endif
      Delete_Binding ("ircd-stats-reply", (Function)&_istats_l, NULL);
      Delete_Binding ("ircd-stats-reply", (Function)&_istats_m, NULL);
      Delete_Binding ("dcc", &dc__phub, NULL);
      _ircd_signal (Ircd->iface, S_TERMINATE);
      ircd_channel_proto_end(&Ircd->channels);
      ircd_client_proto_end();
      ircd_server_proto_end();
      ircd_queries_proto_end();
      ircd_message_proto_end();
      Delete_Help("ircd");
      FREE (&Ircd->token);
      FREE (&Ircd);
      _forget_(peer_priv);
      _forget_(CLASS);
      _forget_(CLIENT);
      _forget_(LINK);
      iface->ift |= I_DIED;
      KillTimer(_uplinks_timer);
      _uplinks_timer = -1;
      Add_Request(I_LOG, "*", F_BOOT, "module ircd terminated successfully");
      return I_DIED;
    case S_SHUTDOWN:
      for (pp = IrcdPeers; pp; pp = pp->p.priv) /* just notify everyone */
	if (!(pp->p.iface->ift & I_DIED))
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
      /* also make name@network messages collector */
      snprintf (buff, sizeof(buff), "@%s", Ircd->iface->name);
      Ircd->sub = Add_Iface (I_CLIENT, buff, NULL, &_ircd_sub_request, NULL);
      strfcpy (MY_NAME, Nick, sizeof(MY_NAME)); /* unchangeable in runtime */
      strfcpy(ME.fname, _ircd_description_string, sizeof(ME.fname));
      strfcpy(ME.away, _ircd_version_string, sizeof(ME.away));
      Ircd->token = safe_calloc (TOKEN_ALLOC_SIZE, sizeof(CLIENT *));
      Ircd->s = TOKEN_ALLOC_SIZE;
      Ircd->token[0] = &ME;		/* set token 0 to ME */
      Insert_Key (&Ircd->clients, MY_NAME, &ME, 1); /* nothing to check? */
      dprint(2, "ircd:CLIENT: added own name %s", MY_NAME);
      __ircd_have_started = 1;
      /* continue with S_FLUSH too */
    case S_FLUSH:
      ircd_channels_flush (Ircd, _ircd_modesstring, sizeof(_ircd_modesstring));
      if (_ircd_client_recvq[0] <= 0 || _ircd_client_recvq[1] <= 0 /* sanity */ ||
	  _ircd_client_recvq[1] > 300 /* too big interval to check */ ||
	  _ircd_client_recvq[1] < _ircd_client_recvq[0] / 4 /* 4 msg in 1 sec */ ||
	  _ircd_client_recvq[1] > _ircd_client_recvq[0] * 10 /* 1 msg in 10 sec */) {
	_ircd_client_recvq[0] = 5; /* 5 messages in 10 seconds is default */
	_ircd_client_recvq[1] = 10;
	Add_Request(I_LOG, "*", F_BOOT,
		    "ircd: reset ircd-penalty flood to default 5:10");
      }
      /* reload and verify _ircd_nicklen from R/O string */
      sscanf(_ircd_nicklen_str, "%u", &_ircd_nicklen);
      if (_ircd_nicklen < 9 || _ircd_nicklen > NICKLEN)
	_ircd_nicklen = NICKLEN;
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
  BTIrcdGotServer = Add_Bindtable ("ircd-got-server", B_MASK);
  BTIrcdLostServer = Add_Bindtable ("ircd-lost-server", B_MASK);
  BTIrcdLocalClient = Add_Bindtable ("ircd-local-client", B_MASK);
//  BTIrcdGotRemote = Add_Bindtable ("ircd-got-client", B_MASK);
  BTIrcdClient = Add_Bindtable ("ircd-client", B_MASK);
  BTIrcdCollision = Add_Bindtable ("ircd-collision", B_UNIQMASK);
  BTIrcdAuth = Add_Bindtable ("ircd-auth", B_MASK);
  BTIrcdServerCmd = Add_Bindtable ("ircd-server-cmd", B_KEYWORD);
  BTIrcdClientCmd = Add_Bindtable ("ircd-client-cmd", B_UNIQ);
  BTIrcdRegisterCmd = Add_Bindtable ("ircd-register-cmd", B_UNIQ);
  BTIrcdClientFilter = Add_Bindtable ("ircd-client-filter", B_KEYWORD);
  BTIrcdDoNumeric = Add_Bindtable ("ircd-do-numeric", B_UNIQ);
  BTIrcdCheckSend = Add_Bindtable ("ircd-check-send", B_MATCHCASE);
  /* add every binding into them */
  Add_Binding ("ircd-auth", "*", 0, 0, &_ircd_class_in, NULL);
  Add_Binding ("ircd-register-cmd", "pass", 0, 0, &ircd_pass, NULL);
  Add_Binding ("ircd-register-cmd", "quit", 0, 0, &ircd_quit_rb, NULL);
  Add_Binding ("ircd-register-cmd", "server", 0, 0, &ircd_server_rb, NULL);
  Add_Binding ("ircd-register-cmd", "020", 0, 0, &__ignored__rb, NULL);
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
  Add_Binding ("ison", "ircd", 0, 0, (Function)&ison_ircd, NULL);
  Add_Binding ("time-shift", "*", 0, 0, (Function)&ts_ircd, NULL);
  Add_Binding ("connchain-grow", "P", 0, 0, &_ccfilter_P_init, NULL);
#if IRCD_USES_ICONV
  Add_Binding ("connchain-grow", "U", 0, 0, &_ccfilter_U_init, NULL);
#endif
#if IRCD_MULTICONNECT
  Add_Binding ("connchain-grow", "I", 0, 0, &_ccfilter_I_init, NULL);
#endif
  Add_Binding ("ircd-stats-reply", "l", 0, 0, (Function)&_istats_l, NULL);
  Add_Binding ("ircd-stats-reply", "m", 0, 0, (Function)&_istats_m, NULL);
  Add_Help("ircd");
  Add_Binding ("dcc", "+hub", U_MASTER, U_MASTER, &dc__phub, NULL);
  Ircd = safe_calloc (1, sizeof(IRCD));
  ircd_channel_proto_start (Ircd);
  ircd_client_proto_start();
  ircd_server_proto_start();
  ircd_queries_proto_start();
  ircd_message_proto_start();
  /* need to add interface into Ircd->iface ASAP! */
  _ircd_corrections = FloodType ("ircd-errors"); /* sets corrections */
  _ircd_client_recvq = FloodType ("ircd-penalty");
  NewTimer (I_MODULE, "ircd", S_TIMEOUT, 1, 0, 0, 0);
  /* register everything */
  snprintf(_ircd_nicklen_str, sizeof(_ircd_nicklen_str), "%d", NICKLEN);
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
