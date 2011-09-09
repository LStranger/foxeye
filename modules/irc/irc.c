/*
 * Copyright (C) 2004-2011  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 * The FoxEye "irc" module: common IRC-client connection service. Does:
 *   - open outgoing server connection
 *   - parse input stream to parameters
 *   - answer to PING command
 *   - support of common client RFC2812 commands (no channel/oper/UI commands)
 *   - limit output stream with $maxpenalty value
 *   - close outgoing server connection
 *   - detection of netsplits
 *   - some console commands
 *
 * Network: IRC. Where: network. Service: client.
 */

#include "foxeye.h"

#include <pwd.h>
#include <ctype.h>

#include "modules.h"
#include "irc.h"
#include "list.h"
#include "init.h"
#include "socket.h"
#include "direct.h"
#include "sheduler.h"
#include "conversion.h"

typedef struct irc_server {
  struct irc_server *next;
  struct irc_server *prev;
  struct irc_await *await;
  time_t last_output;
  int penalty;				/* in messages*2, applied to sendq */
  char **servlist;
  char *mynick;
  INTERFACE *pmsgout;			/* with lname */
  size_t (*lc)(char *, const char *, size_t); /* lowercase nick conversion */
  struct peer_t p;
//not used in struct peer_t:
//  userflag uf;
//  void (*parse) (struct peer_t *, char *, char *, userflag, userflag, int, int,
//	 struct bindtable_t *, char *);/* function to parse/broadcast line */
//  const char *network_type;
//  struct peer_priv *priv;
} irc_server;

typedef struct irc_await {
  pthread_t th;
  irc_server *serv;
  struct irc_await *next;
  int ready:1;
} irc_await;

/* must be locked by dispatcher lock so don't access it from threads! */
static irc_await *IrcAwaits = NULL;
static irc_server *IrcServers = NULL;

static long int irc_timeout = 180;	/* 3 minutes by default */
static long int irc_connect_timeout = 300;
static long int irc_retry_timeout = 120;
static long int irc_retry_server = 60;	/* in minutes */
static long int defaultport = 6667;
static long int maxpenalty = 10;	/* in seconds, see ircd sources */
static long int irc_pmsg_keep = 30;
static char irc_default_nick[NICKLEN+1] = "";
static char irc_default_ident[10] = "";
static char irc_default_realname[REALNAMELEN+1] = "";
static char irc_umode[33] = "";
static bool irc_privmsg_commands = FALSE;	/* disallowed by default */

static struct bindtable_t *BT_Irc = NULL;	/* incoming IRC message */
static struct bindtable_t *BT_IrcConn = NULL;	/* connected to server */
static struct bindtable_t *BT_IrcDisc = NULL;	/* connection to server lost */
static struct bindtable_t *BT_IrcNChg = NULL;	/* some nick changed, internal only */
static struct bindtable_t *BT_IrcSignoff = NULL; /* someone quits, internal only */
static struct bindtable_t *BT_IrcNSplit = NULL; /* netsplit detected, internal only */
static struct bindtable_t *BT_IrcMyQuit = NULL; /* we terminating connection */


/* --- Thread handler ------------------------------------------------------- */
/*
 * handler for connection - only give us a sign that connection is established
 * or failed
 * note that it's thread and it may be cancelled at any time
 */
static void _irc_connection_ready (int result, void *id)
{
  /* go get ready */
  if (result < 0)
    ((irc_await *)id)->serv->p.socket = result;
  ((irc_await *)id)->ready = 1;
  /* return to the core/direct.c:_connect_host() */
}


/* --- Lowercase conversions variants --------------------------------------- */

static char irc_ascii_lowertable[256]; /* filled by ModuleInit() */
static char irc_rfc1459_lowertable[256];

/* irc_none_strlower is NULL */

static size_t irc_ascii_strlower (char *dst, const char *o, size_t s)
{
  register char *d = dst;

  while (*o && d < &dst[s-1])
    *d++ = irc_ascii_lowertable[*(uchar *)o++];
  *d = 0;
  return (d - dst);
}

static size_t irc_rfc1459_strlower (char *dst, const char *o, size_t s)
{
  register char *d = dst;

  while (*o && d < &dst[s-1])
    *d++ = irc_rfc1459_lowertable[*(uchar *)o++];
  *d = 0;
  return (d - dst);
}


/* --- Internal functions --------------------------------------------------- */

/*
 * form of hostrecord:
 * [[*]:passwd@]domain.net[/port][%flags]
 *
 * returns server real name if connected, else host/port and password
 *
 * internal chars: '=' current '-' banned ' ' ok
 */
static char *_irc_current_server (irc_server *serv, char **pass)
{
  char *c;
  char **cc;

  if (serv->p.dname)
  {
    if (pass)
      *pass = NULL;
    return serv->p.dname;
  }
  /* nothing to check - try to have good code :) */
  for (cc = serv->servlist; *cc && (*cc)[0] != '='; cc++); /* find current */
  if (!*cc)
    return NULL;
  c = &(*cc)[1];
  if (*c == ':') /* has passwd */
  {
    if (pass)
      *pass = &c[1];
    return (c + strlen (c) + 1);
  }
  if (pass)
    *pass = NULL;
  return c;
}

/* here we will get hostlist */
static int _irc_servlist (INTERFACE *iface, REQUEST *req)
{
  size_t l = safe_strlen ((char *)iface->data);

  if (l)
    ((char *)iface->data)[l++] = ' ';
  safe_realloc (&iface->data, l + strlen (req->string) + 1);
  strcpy (&((char *)iface->data)[l], req->string);
  return REQ_OK;
}

/* internal for _irc_getnext_server()
   removes garbage from hostname form [:passwd@]host[/port] */
static const char *_irc_parse_hostline (const char *hostline, char **parsed)
{
  register const char *c;
  register char *ch;
  char nn[STRING];

  c = hostline;
  ch = (char *)c;
  nn[0] = ' ';
  while (*c && *c != ' ' && *c != '@') c++;	/* find '@' */
  if (*c == '@')				/* found a '@' */
  {
    c = ch;
    while (*c != ':' && *c != '@') c++;		/* skip all before ':' */
    if (*c == '@')
      c++;					/* incorrect: no passwd found */
  }
  else
    c = ch;
  ch = &nn[1];
  while (*c && *c != ' ' && ch < &nn[sizeof(nn)-1]) *ch++ = *c++;
  *ch = 0;
  *parsed = safe_strdup (nn);
  if ((ch = strchr(*parsed, '@')))
    *ch = 0;
  while (*c == ' ') c++;
  dprint (4, "_irc_parse_hostline: \"%s\" -> \"%s\"", hostline, nn);
  return c;
}

static int _irc_find_hostline (char **list, const char *line)
{
  register const char *c;
  register int i;

  if (!line)
    return 0;
  if ((c = strchr (line, '@')))
    line = &c[1];
  i = 2;
  while ((c = *list++))
  {
    if (c[1] == ':')
      c += (strlen (c) + 1);
    if (!strcmp (c, line))
      return 0;
    i++;
  }
  return i;
}

/* returns: host[:port] or "" (retry later) or NULL
 * current_is_bad is -1 to shedule connection, 1 for removing from list */
static char *_irc_getnext_server (irc_server *serv, const char *add,
				  int current_is_bad)
{
  char **cc, **ccn;
  int i;

  if (add && !*add)
    add = NULL;
  if (!serv->servlist)
  {
    INTERFACE *tmp = Add_Iface (I_TEMP, NULL, NULL, &_irc_servlist, NULL);
    register const char *c;

    /* load servers list from userrecord */
    i = Get_Hostlist (tmp, FindLID (&serv->pmsgout->name[1]));
    dprint (4, "_irc_getnext_server: got %d", i);
    if (i)
    {
      Set_Iface (tmp);
      for (; i; i--)
	Get_Request();
      Unset_Iface();
    }
    /* form serv->servlist */
    if (add) i++;
    for (c = tmp->data; c && *c; c = NextWord ((char *)c)) i++;
    serv->servlist = cc = ccn = safe_malloc ((i+1) * sizeof(char *));
    for (c = tmp->data; c && *c; cc++)
      c = _irc_parse_hostline (c, cc);
    if (_irc_find_hostline (ccn, add))
      _irc_parse_hostline (add, (ccn = cc++));
    *cc = NULL;
    tmp->ift = I_DIED;
  }
  else
  {
    if ((i = _irc_find_hostline (serv->servlist, add))) /* add it first */
    {
      safe_realloc ((void **)&serv->servlist, i * sizeof(char *));
      ccn = &serv->servlist[i-2];
      _irc_parse_hostline (add, ccn);
      ccn[1] = NULL;
    }
    else
      ccn = NULL;	/* we don't need it really but compiler warns... */
    for (cc = serv->servlist; *cc && (*cc)[0] != '='; cc++); /* find current */
    if (*cc && current_is_bad > 0) /* disable it right now */
      (*cc)[0] = '-';
    if (i); /* select added */
    else if (*cc)
      ccn = cc + 1; /* goto next */
    else
    {
      DBG ("_irc_getnext_server: no current, reset server list");
      ccn = serv->servlist; /* goto first */
    }
    while (*ccn && (*ccn)[0] == '-') ccn++; /* skip all bad */
  }	/* here *cc is current (last) server and *ccn is next enabled in list */
  if (current_is_bad < 0)
    return "";
  if (!*ccn && Time - serv->last_output < irc_retry_timeout)
    return "";
  dprint (4, "_irc_getnext_server: next server:%s, timer=%d",
	  *ccn ? *ccn : " [none]", (int)(Time - serv->last_output));
  serv->last_output = Time;
  if (*cc && (*cc)[0] == '=') /* don't reenable disabled server */
    (*cc)[0] = ' ';
  if (!*ccn)
  {
    for (ccn = serv->servlist; *ccn && (*ccn)[0] == '-'; ccn++); /* skip bad */
    dprint (4, "_irc_getnext_server: first server:%s", *ccn ? *ccn : " [none]");
  }
  if (*ccn)
  {
    (*ccn)[0] = '=';
    if ((*ccn)[1] == ':')
      return (*ccn + strlen(*ccn) + 1);
    else
      return (*ccn + 1);
  }
  dprint (4, "_irc_getnext_server: no server");
  return NULL;
}

/* run bindings */
static void _irc_run_conn_bind (irc_server *serv, struct bindtable_t *bt)
{
  struct binding_t *bind = NULL;
  char *name = _irc_current_server (serv, NULL);

  Set_Iface (serv->p.iface);
  Send_Signal (I_MODULE, "ui", S_FLUSH); /* inform UIs about [dis]connect */
  Unset_Iface();
  while ((bind = Check_Bindtable (bt, serv->p.iface->name, U_ALL, U_ANYCH, bind)))
  {
    if (bind->name)
      RunBinding (bind, NULL, serv->p.iface->name, name, NULL, -1, serv->mynick);
    else
      bind->func (serv->p.iface, name, serv->mynick, serv->lc);
  }
}

static iftype_t _irc_privmsgout_sig (INTERFACE *iface, ifsig_t sig)
{
  irc_server *serv;

  if (sig != S_TERMINATE || iface->data == NULL)
    return 0;
  for (serv = IrcServers; serv; serv = serv->next)
    if (serv->pmsgout == iface)
      break;
  if (serv == NULL)
    ERROR("irc: privmsgout interface %s dying but not found in servers list",
	  iface->name);
  else
    serv->pmsgout = NULL;
  irc_privmsgout_cancel (iface, NULL);
  iface->ift = I_DIED;
  return I_DIED;
}

#define _irc_connected(serv) _irc_run_conn_bind (serv, BT_IrcConn)
#define _irc_disconnected(serv) _irc_run_conn_bind (serv, BT_IrcDisc)

#define LOG_CONN(...) Add_Request (I_LOG, "*", F_CONN, __VA_ARGS__)
/*
 * do first try (serv->servlist is NULL) or retry if autoreconnect is on
 * creates new connection thread and irc_await for it
 * banned is -1 to shedule connection, 1 for removing from list.
 * returns 1 if successful or 0 if error
 */
static int _irc_try_server (irc_server *serv, const char *tohost, int banned,
			    char *reason)
{
  userflag uf;
  char *name, *c, *c2;
  irc_await *await;

  /* if already connected then break connection first */
  if (Connchain_Kill ((&serv->p)) &&	/* condition to avoid warn */
      serv->p.socket >= 0)
    KillSocket(&serv->p.socket);
  FREE (&serv->p.dname);
  serv->p.socket = -1;		/* it may still contain an error code */
  if (serv->p.state == P_TALK || serv->p.state == P_IDLE ||
      serv->p.state == P_QUIT)
    _irc_disconnected (serv); /* registered and disconnected so run bindings */
  if (!serv->pmsgout)
  {
    char lname[NAMEMAX+2];

    lname[0] = '@';
    strfcpy (&lname[1], serv->p.iface->name, sizeof(lname) - 1);
    serv->pmsgout = Add_Iface (I_CLIENT, lname, &_irc_privmsgout_sig,
			       &irc_privmsgout_default, NULL);
  }
  /* some cleanup... */
  serv->penalty = 0;
  serv->p.last_input = Time;
  /* check if we will try connection/reconnect */
  uf = Get_Clientflags (serv->p.iface->name, "");	/* all flags */
  if (serv->p.state != P_DISCONNECTED)
    LOG_CONN (_("Connection with network %s lost%s%s%s."), serv->p.iface->name,
	      reason ? ": " : "", reason ? reason : banned ? _(": denied") : "",
	      (uf & U_ACCESS) ? _(", retrying..") : "");
  if ((!serv->servlist || serv->p.state == P_DISCONNECTED || (uf & U_ACCESS)) &&
      serv->p.state != P_QUIT &&			/* dont quitting */
      (name = _irc_getnext_server (serv, tohost, banned))) /* have a server */
  {
    serv->p.state = P_DISCONNECTED;
    if (*name == 0)
      return 1; /* try later again */
    /* OK, let's give it a try... */
    if (IrcAwaits == NULL)
      IrcAwaits = await = safe_calloc (1, sizeof(irc_await));
    else
    {
      for (await = IrcAwaits; await->next; await = await->next);
      await->next = safe_calloc (1, sizeof(irc_await));
      await = await->next;
    }
    await->serv = serv;
    serv->await = await;
    c2 = NULL;		/* make gcc -O2 happy */
    do {		/* fake cycle to get continue working */
      c = strchr (name, '/');	/* ':' may be used in IPv6 notation later */
      if (c) *c = 0;
      else if ((c2 = strchr (name, '%'))) *c2 = 0; /* split flags */
      if (Connect_Host (name, c ? atoi (&c[1]) : defaultport, &await->th,
			&serv->p.socket, &_irc_connection_ready, await))
	LOG_CONN (_("Connecting to %s, port %ld..."), name,
		  c ? atol (&c[1]) : defaultport);
      else
	await->th = 0;
      if (c) *c = '/';
      else if (c2) *c2 = '%';
      if (await->th == 0 && (uf & U_ACCESS) &&
	  (name = _irc_getnext_server (serv, NULL, 0)))
	continue;
    } while (0);
    if (await->th != 0)
    {
      serv->p.state = P_INITIAL;
      return 1;
    }
    await->ready = 1;	/* to destroy await struct */
  }
  /* cannot find working server, give up... voila */
  serv->p.state = P_LASTWAIT;
  Add_Request (I_LOG, "*", F_CONN | F_ERROR,
	       _("Could not find a server for network %s"), serv->p.iface->name);
  return 0;
}

static char *_irc_try_nick (irc_server *serv, struct clrec_t *clr)
{
  register char *c;
  char nn[NAMEMAX+1];
  char *nlist;

  nlist = Get_Field (clr, "nick", NULL);
  if (!serv->mynick)				/* the first try */
  {
    if (!nlist || !*nlist)			/* no nicklist */
      serv->mynick = safe_strdup (irc_default_nick);
    else
    {
      for (c = nn; *nlist && *nlist != ' ' && c < &nn[sizeof(nn)-1]; nlist++)
	*c++ = *nlist;
      *c = 0;
      serv->mynick = safe_strdup (nn);
    }
  }
  else if (!nlist || !strcmp (nlist, serv->mynick) ||	/* no alternates */
	   !strncmp (nlist, serv->mynick, strlen (nlist)))
  {
    safe_realloc ((void **)&serv->mynick, strlen (serv->mynick) + 2);
    c = serv->mynick + strlen (serv->mynick);
    *c++ = '_';
    *c = 0;
  }
  else						/* choose from list */
  {
    size_t s = strlen (serv->mynick);

    for (c = nlist; *c; c = NextWord (c))
      if (!strncmp (c, serv->mynick, s) && (c[s] == 0 || c[s] == ' '))
	break;
    c = NextWord (c);	/* choose next one */
    if (*c)		/* if no next - get first */
      nlist = c;	/* or else get next */
    FREE (&serv->mynick);
    for (c = nn; *nlist && *nlist != ' ' && c < &nn[sizeof(nn)-1]; nlist++)
      *c++ = *nlist;
    *c = 0;
    serv->mynick = safe_strdup (nn);
  }
  dprint (4, "_irc_try_nick: trying %s", serv->mynick);
  return serv->mynick;
}

static int _irc_send (irc_server *serv, char *line)
{
  char *c;
  ssize_t sw, sd;
  int i;
  char buf[MB_LEN_MAX*IRCMSGLEN];
  register char *cc;

  if (serv->p.socket < 0)		/* nothing to do */
    return -1;
  /* check connchain */
  sw = 0;
  sd = Peer_Put ((&serv->p), "", &sw);
  if (sd < 0)				/* error */
    return -1;
  if (sd != CONNCHAIN_READY)		/* not ready */
    return 0;
  if (line == NULL)			/* nothing to do but it's check */
    return 1;
  for (i = 1, c = line; c; i++)		/* count number of CR-LF in buffer */
  {
    c = safe_strchr (c, '\n');
    if (c) c++;				/* LF found */
    else break;				/* EOL reached */
  }
  /* check SendQ */
  if (Time + maxpenalty < serv->last_output + serv->penalty + 2 * i)
    return 0;
  /* format the line now */
  for (c = line, cc = buf; *c && cc < &buf[sizeof(buf)-2]; c++)
  {
    if (*c == '\r' && c[1] == '\n')	/* already CR+LF pair so pass it */
      *cc++ = *c++;
    else if (*c == '\n')		/* only LF so convert to CR+LF */
      *cc++ = '\r';
    *cc++ = *c;				/* copy char */
    /* it would be nice to split too long lines with unsistrcut but:
       - we don't know hot to work with server encoding
       - line isn't just text and we don't know how to recover protocol after
       but it can be handled by msgs.c */
  }
  if (cc != buf && *(cc-1) == '\n')	/* was ended with CR+LF? */
    cc -= 2;				/* skip CR+LF at end */
  sw = cc - buf;
  if (sw == 0)
    return 1;				/* nothing to do */
  dprint (4, "_irc_send: buffer filled for %s: %zd bytes",
	  serv->p.iface->name, sw);
  /* try to send buffer */
  sd = Peer_Put ((&serv->p), buf, &sw);
  DBG("_irc_send: Peer_Put() returned %zd", sd);
  if (sd < 0)				/* error here */
    return -1;
  if (sd == 0)
    return 0;
  if (sw != 0)	/* it should be impossible - if it's ready it can get twice */
    ERROR ("irc:_irc_send: could not send: only %d out of %d done.", (int)sd,
	   (int)(sw + sd));
  /* recalculate penalty */
  serv->penalty += 2 * i;
  if (Time - serv->last_output >= serv->penalty)
    serv->penalty = 0;
  else
    serv->penalty -= (Time - serv->last_output);
  serv->last_output = Time;
  return 1;
}

/* since Find_Clientrecord is case-insensitive now, we don't need lower case */
static char *_irc_get_lname (char *nuh, userflag *uf, char *net)
{
  char *c;
  struct clrec_t *u;

  DBG ("irc:_irc_get_lname:looking for %s", nuh);
  u = Find_Clientrecord (nuh, &c, uf, net);
  if (u)
  {
    c = safe_strdup (c);
    Unlock_Clientrecord (u);
    return c;
  }
  return NULL;
}


/* --- Server interface ----------------------------------------------------- */

/* supported: S_REPORT, S_SHUTDOWN, S_TERMINATE, S_FLUSH */
static iftype_t _irc_signal (INTERFACE *iface, ifsig_t sig)
{
  irc_server *serv = (irc_server *)iface->data;
  const char *reason, *domain;
  unsigned short port;
  size_t bufpos, inbuf;
  INTERFACE *tmp;
  struct binding_t *bind;
  struct clrec_t *nclr;
  char report[STRING];
  char servhost[HOSTLEN+6];

  switch (sig)
  {
    case S_SHUTDOWN: /* QUIT :leaving */
      if (ShutdownR)
	reason = ShutdownR;
      else
	reason = "leaving";
      snprintf (report, sizeof(report), "\r\nQUIT :%s\r\n", reason);
      inbuf = strlen (report);
      bufpos = 0;
      WriteSocket (serv->p.socket, report, &bufpos, &inbuf, M_RAW);
      iface->ift |= I_DIED;
      serv->p.iface = NULL;
      break;
    case S_FLUSH:
      nclr = Lock_Clientrecord (iface->name);
      if (nclr)
      {
	Unlock_Clientrecord (nclr);
	break;
      }
      else
	Add_Request (I_LOG, "*", F_CONN | F_WARN,
		     "Network %s deleted, so shutting down now.", iface->name);
      /* they deleted us from Listfile so stop */
    case S_TERMINATE: /* QUIT :leaving */
      if (serv->p.state != P_LOGIN && serv->p.state != P_TALK &&
	  serv->p.state != P_IDLE)
      {
	if (serv->p.state != P_QUIT)
	  serv->p.state = P_LASTWAIT;
	break;
      }
      if (ShutdownR)
	reason = ShutdownR;
      else
      {
	reason = "leaving";
	report[0] = 0;
	bind = NULL;
	while ((bind = Check_Bindtable (BT_IrcMyQuit, iface->name, U_ALL,
					U_ANYCH, bind)))
	  if (!bind->name)
	  {
	    if (bind->func (iface, report, sizeof(report)))
	      reason = report;
	  }
	  else if (RunBinding (bind, NULL, iface->name, report, NULL, -1, NULL))
	  {
	    strfcpy (report, BindResult, sizeof(report));
	    reason = report;
	  }
      }
      New_Request (iface, F_QUICK, "QUIT :%s", reason); /* ignore queue */
      serv->p.state = P_QUIT;
      /* don't set I_DIED flag because it must be done on request call */
      break;
    case S_REPORT: /* for .cstat */
      if (serv->await && !serv->await->ready)
      {
	domain = _irc_current_server (serv, NULL);
	port = 0;
      }
      else
	domain = SocketDomain (serv->p.socket, &port);
      switch (serv->p.state)
      {
	case P_DISCONNECTED:
	  reason = _("reconnecting IRC server");
	  break;
	case P_INITIAL:
	  reason = _("connecting IRC server");
	  break;
	case P_LOGIN:
	  reason = _("registering at IRC server");
	  break;
	case P_TALK:
	case P_IDLE:
	  reason = _("IRC server connected");
	  break;
	default:
	  reason = _("disconnecting IRC server");
	  break;
      }
      if (port)
      {
	snprintf (servhost, sizeof(servhost), "%s/%hu", domain, port);
	domain = servhost;
      }
      /* %N - my nick, %@ - server name, %L - network name, %# - connected at,
	 %P - socket id, %* - state */
      printl (report, sizeof(report), ReportFormat, 0, serv->mynick, domain,
	      iface->name, serv->p.start, (uint32_t)0, serv->p.socket + 1,
	      0, reason);
      tmp = Set_Iface (iface);
      New_Request (tmp, F_REPORT, "%s", report);
      Unset_Iface();
    default: ; /* ignore others */
  }
  return 0;
}

/* returns: 0 - disconnected, 1 - again later, 2 - accepted */
static int _irc_request_main (INTERFACE *iface, REQUEST *req)
{
  irc_server *serv = (irc_server *)iface->data;
  register char *c;
  char thebuf[STRING];
  int i, isregistered = 0, reject = 1;
  int sw = 0;		/* we don't need that 0 but to exclude warning... */

  /* there may be still an await structure, we cannot touch socket then! */
  if (serv->await)
  {
    if (serv->await->ready)
    {
      irc_await *await = IrcAwaits;
      char *msg;

      if (await == serv->await)
	IrcAwaits = await->next;
      else
	while (await && await->next != serv->await)
	  await = await->next;
      await->next = serv->await->next;
      if (serv->await->th != 0)	/* it may be invalid, see _irc_try_server() */
      {
	Unset_Iface();
	pthread_join (serv->await->th, (void **)&msg);
	Set_Iface (NULL);
      }
      else
	msg = NULL;
      FREE (&serv->await);
      dprint (4, "_irc_request: await terminated");
      if (serv->p.socket == E_UNDEFDOMAIN || serv->p.socket == E_NOSUCHDOMAIN)
	return _irc_try_server (serv, NULL, 1, msg);	/* remove if invalid */
      else if (serv->p.socket < 0)
	return _irc_try_server (serv, NULL, 0, msg);	/* try next server */
    }
    else
      return 1;
  }
  if (serv->p.state != P_DISCONNECTED && serv->pmsgout == NULL)
  {
    ERROR ("_irc_request: unknown condition for IRC server %s", iface->name);
    return 0;			/* already died! */
  }
  /* check for connection state */
  switch (serv->p.state)
  {
    case P_DISCONNECTED:
      return _irc_try_server (serv, NULL, 0, NULL);
    case P_INITIAL:
      /* is connection established? - let's register myself! */
      /* if there was an error then serv->p.socket < 0 (see function
	 _irc_connection_ready()), else if waiting for connection
	 then ReadSocket will return E_AGAIN */
      if (serv->p.socket >= 0 && 
	  (sw = ReadSocket (thebuf, serv->p.socket, sizeof(thebuf),
			    M_RAW)) >= 0)
      {
	struct clrec_t *clr;
	char *ident, *realname, *sl;

	LOG_CONN (_("Connected to %s, registering..."), iface->name);
	sl = _irc_current_server (serv, &ident); /* have to send PASS? */
	c = ident;
	clr = Lock_Clientrecord (iface->name);
	if (!clr)		/* it was already deleted??? */
	{
	  serv->p.state = P_LASTWAIT;
	  Add_Request (I_LOG, "*", F_CONN | F_ERROR,
		       _("Disconnected from %s: unknown error."), iface->name);
	  return _irc_request_main (iface, req);
	}
	if (serv->mynick)
	{
	  if (!(ident = Get_Field (clr, "nick", NULL)))	/* nicklist */
	    FREE (&serv->mynick);			/* try to regain it */
	  else if (!strncmp (ident, serv->mynick, (sw = strlen (ident))) &&
	      (!strcmp (&serv->mynick[sw], "_") ||
	      !strcmp (&serv->mynick[sw], "__")))
	    FREE (&serv->mynick);			/* try to regain it */
	}
	if (!serv->mynick)
	  _irc_try_nick (serv, clr);
	ident = Get_Field (clr, "passwd", NULL);	/* ident */
	if (!ident)
	  ident = irc_default_ident;
	realname = Get_Field (clr, "info", NULL);	/* realname */
	if (!realname)
	  realname = irc_default_realname;
	/* send NICK/USER pair */
	if (c)
	  snprintf (thebuf, sizeof(thebuf),
		    "PASS %s\r\nNICK %s\r\nUSER %s 8 * :%s\r\n", c,
		    serv->mynick, ident, realname);
	else
	  snprintf (thebuf, sizeof(thebuf),
		    "NICK %s\r\nUSER %s 8 * :%s\r\n", serv->mynick, ident,
		    realname);
#ifdef HAVE_ICONV
	ident = safe_strdup (Get_Field (clr, "charset", NULL));
#endif
	Unlock_Clientrecord (clr);
#ifdef HAVE_ICONV
	iface->conv = Get_Conversion (ident);
	FREE (&ident);
#endif
	/* setup the state */
	serv->p.state = P_LOGIN;
	/* add some nice filter from % in host - SSL, etc. */
	if ((c = strchr (sl, '%')))		/* flags found */
	  while (*++c)
	    if (*c != 'x' && *c != 'y' &&	/* forbidden flags */
	      !Connchain_Grow ((&serv->p), *c))	/* try filter */
	      {
		ERROR ("irc:_irc_request_main: cannot create filter %c", *c);
		return _irc_try_server (serv, NULL, 0, NULL); /* abort it */
	      }
	Connchain_Grow ((&serv->p), 'x');	/* RAW -> TXT filter */
	_irc_send (serv, thebuf); /* no errors should be here yet */
      }
      else if (serv->p.socket < 0 || sw != E_AGAIN)
      {
	dprint (4, "_irc_request: no connection: %s",
		SocketError ((serv->p.socket >= 0) ? sw : serv->p.socket,
			     thebuf, sizeof(thebuf)));
	return _irc_try_server (serv, NULL, 0, NULL);
      }
    case P_LOGIN:
      if (serv->p.state == P_LOGIN &&
	  _irc_send (serv, NULL) < 0)	/* it might reset connection? */
	return _irc_try_server (serv, NULL, 0, NULL);
      /* we are waiting for RPL_WELCOME now */
      /* connection timeout? - disconnect and check if we may retry */
      if (Time - serv->p.last_input > irc_connect_timeout)
      {
	dprint (4, "_irc_request: connection timeout");
	return _irc_try_server (serv, NULL, 0, _("connection timeout"));
      }
      /* delay request for now since we aren't ready */
      break;
    case P_IDLE:
      /* check for timeout */
      if (Time - serv->p.last_input > 2 * irc_timeout)
	return _irc_try_server (serv, NULL, 0, NULL);
    case P_QUIT:
    case P_TALK:
      if (_irc_send (serv, NULL) < 0)	/* flush output to server */
	return _irc_try_server (serv, NULL, 0, NULL);
      if (serv->p.state == P_IDLE || serv->p.state == P_TALK)
	isregistered = 1;		/* _irc_send() might reset connection */
      if (serv->p.state != P_QUIT)
	break;
      if (req)				/* we still have message to send */
        _irc_send (serv, req->string);	/* ignoring result... */
      serv->p.state = P_LASTWAIT;
    case P_LASTWAIT:
      if (_irc_send (serv, NULL) == 0)	/* still not ready */
	return 1;
      /* it was just sent quit message so run bindings and go off */
      _irc_disconnected (serv);
      LOG_CONN (_("Disconnected from %s."), iface->name);
      /* we are disconnected and will be no reconnect so empty all queues */
      irc_privmsgout_cancel (serv->pmsgout, NULL);
      serv->pmsgout->ift |= I_DIED;
      serv->pmsgout = NULL;
		/* "Connection reset by peer" */
		/* note: I wonder if terminator might not send QUIT here yet */
      KillSocket (&serv->p.socket);
      if (serv->next)
	serv->next->prev = serv->prev;
      if (serv->prev)
	serv->prev->next = serv->next;
      else
	IrcServers = serv->next;
      if (serv->servlist)
	for (i = 0; serv->servlist[i] != NULL; i++)
	  FREE (&serv->servlist[i]);
      FREE (&serv->servlist);
      FREE (&serv->mynick);
      iface->ift |= I_DIED;
      /* shedule retry of autoconnects (in 1 hour by default) */
      NewTimer (I_MODULE, "irc", S_FLUSH, 0, irc_retry_server, 0, 0);
      return 0;
  }
  /* get input if it's possible */
  if (serv->p.state == P_LOGIN || serv->p.state == P_TALK ||
      serv->p.state == P_IDLE)
  {
#ifdef HAVE_ICONV
    char sbuf[MB_LEN_MAX*IRCMSGLEN];
#endif
    char inbuf[MB_LEN_MAX*IRCMSGLEN];
    char uhb[HOSTMASKLEN+1]; /* nick!user@host */
    char *params[19]; /* network sender command args ... NULL */
    char *prefix, *p, *uh;
    struct binding_t *bind;

    /* connection established, we may send data */
    if ((sw = _irc_send (serv, req ? req->string : NULL)) == 1)
      reject = 0; /* nice, we sent it */
    /* check for input (sw includes '\0') */
    sw = Peer_Get ((&serv->p), inbuf, sizeof(inbuf));
    if (sw < 0)	/* error, close it */
      return _irc_try_server (serv, NULL, 0, NULL);
    else if (sw == 0) /* check last input if ping timeout then try to ping it */
    {
      if (Time - serv->p.last_input > irc_timeout)
      {
	if (serv->p.state == P_TALK)
	{
	  New_Request (iface, F_QUICK, "PING :%s", serv->mynick);
	  serv->p.state = P_IDLE;
	}
	else if (serv->p.state != P_IDLE ||
		 Time - serv->p.last_input > 2 * irc_timeout)
	{
	  LOG_CONN (_("Timeout for IRC server %s (%d seconds)..."),
		    serv->p.dname, (int)(Time - serv->p.last_input));
	  serv->p.state = P_DISCONNECTED;
	  reject = 1;
	}
      }
    }
    else	/* congratulations, we got the input! */
    {
      sw--;		/* skip ending '\0' */
#ifdef HAVE_ICONV
      p = sbuf;
      sw = Do_Conversion (iface->conv, &p, sizeof(sbuf) - 1, inbuf, sw);
      p[sw] = 0;	/* end this line with '\0' anyway */
#else
      p = inbuf;
#endif
      dprint (5, "_irc_request: got from %s: [%-*.*s]", iface->name, sw, sw, p);
      if (serv->p.state == P_IDLE)
	serv->p.state = P_TALK;
      serv->p.last_input = Time;
      params[0] = iface->name; /* network name (server id) */
      if (p[0] == ':')	/* there is a prefix */
      {
	prefix = params[1] = ++p; /* prefix, i.e. sender */
	p = gettoken (p, NULL);
      }
      else
	prefix = NULL;
      params[2] = p; /* command */
      p = gettoken (p, NULL);
      for (i = 0; *p; i++)
      {
	if (*p == ':')
	{
	  params[(i++) + 3] = &p[1];
	  break;
	}
	if (i == 14)
	{
	  params[(i++) + 3] = p;
	  break;
	}
	params[i + 3] = p;
	p = gettoken (p, NULL);
      }
      params[i + 3] = NULL;
      p = _irc_current_server (serv, NULL);
      uh = NULL;
      if (!prefix) /* it's from server */
	params[1] = p;
      else if (!strcmp (p, prefix)) /* the same as above */
	prefix = NULL;
      else
      {
	/* parse prefix */
	if ((uh = safe_strchr (prefix, '!')))		/* nick!user[@host] */
	  uh = prefix;
	else if ((uh = safe_strchr (prefix, '@')))	/* @host */
	{
	  *uh++ = 0;				/* correcting to nick!*@host */
	  snprintf (uhb, sizeof(uhb), "%s!*@%s", prefix, uh);
	  uh = uhb;
	}
	else						/* only nick was got */
	  uh = prefix;
      }
      /* run bindings */
      bind = NULL;
      //FIXME: how we can have no mynick still here?
      while ((bind = Check_Bindtable (BT_Irc, params[2], U_ALL, U_ANYCH, bind)))
      {
	if (bind->name) /* cannot use RunBinding here! */
	  i = bind->func (bind->name, i+3, params);
	else
	  i = bind->func (iface, p, serv->mynick, uh, i, &params[3], serv->lc);
	if (i)
	  break;
      }
      if (i == -1)
	ERROR ("strange IRC command from %s: %s %s%s%s%s%s%s",
		prefix ? prefix : (NONULLP(serv->p.dname)), params[2],
		i ? params[3] : "", i > 1 ? " " : "", i > 1 ? params[4] : "",
		i > 2 ? " " : "", i > 2 ? params[5] : "", i > 3 ? " ..." : "");
      if (serv->p.state != P_LOGIN && serv->p.state != P_TALK &&
	  serv->p.state != P_IDLE)
	reject = 1;	/* bindings might reset connection */
    }
  }
  /* accept (any?) request if ready for it (SendQ checked by _irc_send) */
  if (!reject && req)
  {
    return 2;
  }
  else if (isregistered && !reject && !req)	/* all sent already */
    irc_privmsgout(serv->pmsgout, irc_pmsg_keep);
  return 1;				/* default to reject */
}

static int _irc_request (INTERFACE *iface, REQUEST *req)
{
  if (_irc_request_main (iface, req) != 2 && req != NULL)
    return REQ_REJECTED;
  return REQ_OK;
}


/* --- Helpers for msgs.c --------------------------------------------------- */

char *irc_mynick (char *servname)
{
  INTERFACE *iface = Find_Iface (I_SERVICE, servname);

  if (!iface)
    return NULL;
  Unset_Iface();
  return ((irc_server *)iface->data)->mynick;
}


/* --- Bindings ------------------------------------------------------------- */

/*
 * "irc-raw" bindings:
 *   int func(INTERFACE *net, char *sv, char *me, unsigned char *src,
 *		int parc, char **parv, size_t (*lc)(char *, const char *, size_t))
 *
 * note that src is NULL if message has no prefix or originatin from server
 * src is in form "server" or "nick"
 * host is in form "ident@host"
 * lc is used for server-specific lowercase conversion
 */
BINDING_TYPE_irc_raw (irc_ping);
static int irc_ping (INTERFACE *net, char *sv, char *me, unsigned char *src,
		int parc, char **parv, size_t (*lc)(char *, const char *, size_t))
{ /* Parameters: server [server-to] */
  if (parc > 1 && src)
    New_Request (net, F_QUICK, "PONG %s :%s", sv, src);
  else
    New_Request (net, F_QUICK, "PONG :%s",
		 src ? (char *)src : ((irc_server *)net->data)->p.dname);
  return 1;
}

/*
 * currently being ignored:
 * PONG ERR_USERSDONTMATCH ERR_NOTEXTTOSEND ERR_TOOMANYTARGETS ERR_NOORIGIN
 * ERR_NOSUCHSERVER queries opers channels motd
 *
 * ERR_ALREADYREGISTRED ERR_UMODEUNKNOWNFLAG RPL_UMODEIS ERR_NEEDMOREPARAMS
 * RPL_AWAY ERR_NORECIPIENT RPL_YOURHOST RPL_CREATED RPL_TRYAGAIN
 * ERR_UNKNOWNCOMMAND ERROR
 */

/*
 * aborted registration, wants to change nick first:
 * ERR_ERRONEUSNICKNAME ERR_NICKNAMEINUSE ERR_UNAVAILRESOURCE ERR_NICKCOLLISION
 * ERR_NOTREGISTERED
 */
BINDING_TYPE_irc_raw (irc__nextnick);
static int irc__nextnick (INTERFACE *net, char *sv, char *me, unsigned char *src,
		int parc, char **parv, size_t (*lc)(char *, const char *, size_t))
{ /* Parameters: current new text */
  irc_server *serv = net->data;
  struct clrec_t *clr;

  dprint (4, "irc__nextnick: %s: nickname %s juped", net->name, serv->mynick);
  clr = Lock_Clientrecord (net->name);
  if (clr)
  {
    _irc_try_nick (serv, clr);
    Unlock_Clientrecord (clr);
  }
  New_Request (net, 0, "NICK %s", serv->mynick);
  return 0;
}

BINDING_TYPE_irc_raw (irc_rpl_bounce);
static int irc_rpl_bounce (INTERFACE *net, char *sv, char *me, unsigned char *src,
		int parc, char **parv, size_t (*lc)(char *, const char *, size_t))
{ /* Parameters: me host port text */
  char newhost[HOSTLEN+7];

  if (parc != 4 || atoi(parv[2]) == 0)	/* some other format? */
    return 0;
  snprintf (newhost, sizeof(newhost), "%s:%s", parv[1], parv[2]);
  _irc_try_server ((irc_server *)net->data, newhost, 1, _("bounced"));
  return 1;
}

/*
 * cannot register at all, drop any further attempts for this server
 * ERR_NOPERMFORHOST ERR_PASSWDMISMATCH ERR_YOUREBANNEDCREEP
 */
BINDING_TYPE_irc_raw (irc__fatal);
static int irc__fatal (INTERFACE *net, char *sv, char *me, unsigned char *src,
		int parc, char **parv, size_t (*lc)(char *, const char *, size_t))
{ /* Parameters: me text */
  _irc_try_server ((irc_server *)net->data, NULL, 1, NULL);
  return 1;
}

/*
 * we got 001 (RPL_WELCOME) so connection is completed now
 */
BINDING_TYPE_irc_raw (irc_rpl_welcome);
static int irc_rpl_welcome (INTERFACE *net, char *sv, char *me, unsigned char *src,
		int parc, char **parv, size_t (*lc)(char *, const char *, size_t))
{ /* Parameters: me text */
  irc_server *serv = net->data;

  /* do all bindings */
  _irc_connected (serv);
  /* change state */
  snprintf (serv->p.start, sizeof(serv->p.start), "%s %s", DateString,
	    TimeString);
  serv->p.state = P_TALK;
  LOG_CONN (_("Registered on %s."), net->name);
  return 0;
}

/* declaration */
static void _irc_update_isupport (INTERFACE *, int, char **);

BINDING_TYPE_irc_raw (irc_rpl_myinfo);
static int irc_rpl_myinfo (INTERFACE *net, char *sv, char *me, unsigned char *src,
		int parc, char **parv, size_t (*lc)(char *, const char *, size_t))
{ /* Parameters: me srvname version umodes chanmodes */
  char umodes[SHORT_STRING];

  if (parc != 5)
    return -1;
  ((irc_server *)net->data)->p.dname = safe_strdup (parv[1]);
  LOG_CONN (_("Got version from %s: %s"), parv[1], parv[2]);
  snprintf (umodes, sizeof(umodes), IRCPAR_UMODES "=%s", parv[3]);
  me = umodes;	/* use it as pointer */
  _irc_update_isupport (net, 1, &me);
  return 0;
}

static size_t _irc_check_domain_part (char *domain)
{
  register char *l = domain, *c;

  while (*l && *l != '.') l++;
  for (c = domain; c != l; c++)
  {
    /* last domain part must be [a-zA-Z]+ all previous may have [-0-9] also */
    if ((*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') ||
	(*l && (*c == '-' || (*c >= '0' && *c <= '9'))))
      continue;
    DBG ("_irc_check_domain_part: invalid %-*.*s", (int)(c - domain + 1),
	 (int)(c - domain + 1), domain);
    return 0;
  }
  if (*c) c++;
  DBG ("_irc_check_domain_part: %-*.*s", (int)(c - domain),
       (int)(c - domain + 1), domain);
  return (c - domain);
}

static int _irc_check_domain (char *domain)
{
  register size_t i;
  char *c = domain;	/* begin of last part */

  while (*c)
  {
    i = _irc_check_domain_part (c);
    if (i < 2)
      return 0;
    if (c[i])
      c += i;
    else
      break;
  }
  if (c == domain)	/* less than 2 parts? */
    return 0;
  return 1;
}

BINDING_TYPE_irc_raw (irc_quit);
static int irc_quit (INTERFACE *net, char *sv, char *me, unsigned char *src,
		int parc, char **parv, size_t (*lc)(char *, const char *, size_t))
{ /* Parameters: text */
  char *cc;

  if (parc != 1 || !src)
    return 0;
  if ((cc = safe_strchr (src, '!')))
    *cc = 0;
  if (strcasecmp (src, me)) /* it's not me */
  {
    /* Quit reason in netsplit: leftserver goneserver */
    char *gone;
    char *lname;
#if IFNAMEMAX > HOSMASKLEN
    char target[IFNAMEMAX+1];
#else
    char target[HOSTMASKLEN+1];
#endif
    userflag uf;
    int s;
    struct binding_t *bind;

    strfcpy (target, src, NAMEMAX+1); /* use old nick for interfaces */
    irc_privmsgout_cancel (((irc_server *)net->data)->pmsgout, src);
    strfcat (target, ((irc_server *)net->data)->pmsgout->name, sizeof(target));
    if (Find_Iface (I_LOG, target))
    {					/* log it only if there is opened log */
      Unset_Iface();
      Add_Request (I_LOG, target, F_PRIV | F_END, _("%s quits: %s"), src, parv[0]);
    }
    if (lc)
      lc (target, src, NAMEMAX+1);
    else
      target[safe_strlen(src)] = 0;	/* leave only nick there for bindings */
    if (cc)
      *cc = '!';
    lname = _irc_get_lname (src, &uf, net->name);
    gone = strchr (parv[0], ' ');
    if (gone)	/*  to check if it's netsplit message */
      *gone = 0;
    if (gone && strcmp (&gone[1], parv[0]) &&
	_irc_check_domain (parv[0]) && _irc_check_domain (&gone[1]))
      s = 1;	/* netsplit message detected */
    else
      s = 0;	/* it was just a quit message... */
    if (gone)	/* restore status quo */
      *gone = ' ';
    for (bind = NULL; (bind = Check_Bindtable (s ? BT_IrcNSplit : BT_IrcSignoff,
						target, uf, U_ANYCH, bind)); )
      if (!bind->name)
	bind->func (net, lname, src, target, parv[0]);
    FREE (&lname);
  }
  else		/* someone killed me? */
  {
    if (cc)
      *cc = '!';
    _irc_try_server ((irc_server *)net->data, NULL, 0, NULL);
  }
  return 0;
}

BINDING_TYPE_irc_raw (irc_error);
static int irc_error (INTERFACE *net, char *sv, char *me, unsigned char *src,
		int parc, char **parv, size_t (*lc)(char *, const char *, size_t))
{ /* Parameters: text */
  _irc_try_server ((irc_server *)net->data, NULL, 0, parv[0]);
  return 0;
}

BINDING_TYPE_irc_raw (irc_kill);
static int irc_kill (INTERFACE *net, char *sv, char *me, unsigned char *src,
		int parc, char **parv, size_t (*lc)(char *, const char *, size_t))
{ /* Parameters: nick text */
  if (parc != 2)
    return 0;
  if (!strcasecmp (parv[0], me))
    _irc_try_server ((irc_server *)net->data, NULL, 0, _("killed"));
  else		/* it must be some bug! */
  {
    ERROR ("irc:irc_kill: got KILL for someone else than me: %s", parv[0]);
    irc_privmsgout_cancel (((irc_server *)net->data)->pmsgout, parv[0]);
  }
  return 0;
}

BINDING_TYPE_irc_raw (irc_privmsg);
static int irc_privmsg (INTERFACE *net, char *sv, char *me, unsigned char *src,
		int parc, char **parv, size_t (*lc)(char *, const char *, size_t))
{ /* Parameters: nick text */
  char f[NAMEMAX+1], m[NAMEMAX+1];
  char *cc;

  if (parc != 2 || !src)
    return 0;	/* bad number of parameters so ignore it */
  if (lc)
  {
    lc (f, parv[0], sizeof(f));
    lc (m, me, sizeof(m));
    cc = (strcmp (m, f)) ? parv[0] : NULL;
  }
  else
    cc = (strcmp (me, parv[0])) ? parv[0] : NULL;
  return irc_privmsgin (((irc_server *)net->data)->pmsgout, src, cc,
			parv[1], 0, irc_privmsg_commands, irc_pmsg_keep, lc);
}

BINDING_TYPE_irc_raw (irc_err_nosuchnick);
static int irc_err_nosuchnick (INTERFACE *net, char *sv, char *me, unsigned char *src,
		int parc, char **parv, size_t (*lc)(char *, const char *, size_t))
{ /* Parameters: me nick text */
  char f[IFNAMEMAX+1];

  if (parc != 3)
    return -1;
  strfcpy (f, parv[1], sizeof(f));
  if (strcmp (me, f))
  {
    irc_privmsgout_cancel (((irc_server *)net->data)->pmsgout, parv[1]);
    strfcat (f, ((irc_server *)net->data)->pmsgout->name, sizeof(f));
    Add_Request (I_LOG, f, F_PRIV | F_END, _("*** no such nick %s"), parv[1]);
  }
  /* else bug */
  return 0;
}

BINDING_TYPE_irc_raw (irc_err_unavailable);
static int irc_err_unavailable (INTERFACE *net, char *sv, char *me, unsigned char *src,
		int parc, char **parv, size_t (*lc)(char *, const char *, size_t))
{ /* Parameters: me nick/chan text */
  struct clrec_t *clr;
  irc_server *serv = net->data;

  if (parc != 3)
    return -1;
  if (!strcmp (serv->mynick, parv[1]))
  {
    dprint (4, "irc_err_unavailable: %s: nickname %s juped", net->name, serv->mynick);
    clr = Lock_Clientrecord (net->name);
    if (clr)
    {
      _irc_try_nick (serv, clr);
      Unlock_Clientrecord (clr);
    }
    New_Request (net, 0, "NICK %s", serv->mynick);
  }
  /* else ignore */
  return 0;
}

BINDING_TYPE_irc_raw (irc_notice);
static int irc_notice (INTERFACE *net, char *sv, char *me, unsigned char *src,
		int parc, char **parv, size_t (*lc)(char *, const char *, size_t))
{ /* Parameters: nick text */
  char f[NAMEMAX+1], m[NAMEMAX+1];
  char *cc;

  if (parc != 2 || !src)
    return 0;	/* bad number of parameters so ignore it */
  if (lc)
  {
    lc (f, parv[0], sizeof(f));
    lc (m, me, sizeof(m));
    cc = (strcmp (m, f)) ? parv[0] : NULL;
  }
  else
    cc = (strcmp (me, parv[0])) ? parv[0] : NULL;
  return irc_privmsgin (((irc_server *)net->data)->pmsgout, src, cc,
			parv[1], 1, irc_privmsg_commands, irc_pmsg_keep, lc);
}

/*
 * may be it's my nick was changed?
 */
BINDING_TYPE_irc_raw (irc_nick);
static int irc_nick (INTERFACE *net, char *sv, char *me, unsigned char *src,
		int parc, char **parv, size_t (*lc)(char *, const char *, size_t))
{ /* Parameters: newnick */
  irc_server *serv;
  char oldnick[IFNAMEMAX+1];
  char newnick[HOSTMASKLEN+1];
  size_t s;
  char *lname;
  userflag uf;
  struct binding_t *bind;
  INTERFACE *i;

  /* test if it's me */
  if (!src || parc != 1)
    return 0;
  if ((lname = strchr (src, '!')))
    *lname = 0;
  serv = net->data;
  if (strcmp (src, serv->mynick))
  {
    /* it isn't me so rename I_CLIENT interface */
    snprintf (oldnick, sizeof(oldnick), "%s%s", src, serv->pmsgout->name);
    snprintf (newnick, sizeof(newnick), "%s%s", parv[0], serv->pmsgout->name);
    while ((i = Find_Iface (I_CLIENT, oldnick)))
    {
	Rename_Iface (i, newnick);
	Unset_Iface();
    }
    if (lc)
    {
      lc (oldnick, src, sizeof(oldnick));
      s = lc (newnick, parv[0], NAMEMAX+1);
    }
    else
    {
      oldnick[safe_strlen(src)] = 0;
      s = safe_strlen (parv[0]);
    }
    if (lname)				/* compose new mask */
    {
      *lname = '!';
      strfcpy (&newnick[s], lname, sizeof(newnick) - s);
    }
    lname = _irc_get_lname (newnick, &uf, net->name);
    newnick[s] = 0;
  }
  else
  {
    /* it's me so change local data */
    Add_Request (I_LOG, "*", F_WARN, "irc_nick: %s: my nickname changed %s -> %s",
		 net->name, me, parv[0]);
    FREE (&serv->mynick);
    serv->mynick = safe_strdup (parv[0]);
    if (lc)
    {
      lc (oldnick, src, sizeof(oldnick));
      lc (newnick, parv[0], NAMEMAX+1);
    }
    else
      strfcpy (oldnick, src, sizeof(oldnick));
    if (lname)
      *lname = '!';
    lname = NULL;
    uf = -1;
  }
  /* call all internal bindings */
  bind = NULL;
  while ((bind = Check_Bindtable (BT_IrcNChg, newnick, uf, U_ANYCH, bind)))
    if (!bind->name)
      bind->func (net, lname, src, oldnick, parv[0], lc ? newnick : parv[0]);
  FREE (&lname);
  return 1;
}

static void _set_isupport_num (char *value, size_t s, unsigned int *i,
			       char *name, size_t nl, int x)
{
  if (*i)
    nl++;
  s -= *i;
  value += *i;
  if (x == 0 || s <= nl + 8)		/* _name=xxxxxx */
    return;				/* OOPS! */
  snprintf (value, s, "%s%s=%d", *i ? " " : "", name, x);
  *i += strlen (value);
}

static void _set_isupport_string (char *value, size_t s, unsigned int *i,
				  char *name, size_t nl, char *x)
{
  register size_t l = strlen (x);

  if (*i)
    nl++;
  s -= *i;
  value += *i;
  if (l == 0 || s <= nl + l + 2)	/* _name=string */
    return;				/* OOPS! */
  snprintf (value, s, "%s%s=%s", *i ? " " : "", name, x);
  *i += strlen (value);
}

static void _irc_update_isupport (INTERFACE *net, int parc, char **parv)
{
  char *c, *cs, *cf, *cv;
  unsigned int i;
  int nicklen, topiclen, maxbans, maxchannels, modes, maxtargets;
  size_t (*lc) (char *, const char *, size_t);
  struct clrec_t *clr;
  char chanmodes[SHORT_STRING];
  char prefix[32];
  char umodes[32];
  char value[LONG_STRING];

  dprint (4, "irc_update_isupport: %d params, first one is %s.", parc, parv[0]);
  nicklen = topiclen = maxbans = maxchannels = modes = maxtargets = 0;
  lc = &unistrlower; /* assume it's default for me */
  clr = Lock_Clientrecord (net->name);
  if (!clr)
    return;		/* it's impossible */
  cs = c = Get_Field (clr, IRCPAR_FIELD, NULL);
  while (c)
  {
    cf = c;
    cv = strchr (c, '=');
    if (cv && (c = strchr (cv, ' ')))
      i = c++ - cv;
    else if (cv)
      i = strlen (cv);
    if (cv)
    {
      register unsigned int xx = (cv++ - cf);
      DBG ("irc_update_isupport: found saved %.*s=\"%.*s\"", xx, cf, i-1, cv);
      strfcpy (value, cf, xx >= sizeof(value) ? sizeof(value) : xx + 1);
      if (!strcmp (value, IRCPAR_NICKLEN))
	nicklen = atoi (cv);
      else if (!strcmp (value, IRCPAR_TOPICLEN))
	topiclen = atoi (cv);
      else if (!strcmp (value, IRCPAR_MAXBANS))
	maxbans = atoi (cv);
      else if (!strcmp (value, IRCPAR_CHANNELS))
	maxchannels = atoi (cv);
      else if (!strcmp (value, IRCPAR_MODES))
	modes = atoi (cv);
      else if (!strcmp (value, IRCPAR_TARGETS))
	maxtargets = atoi (cv);
      else if (!strcmp (value, IRCPAR_PREFIX))
	strfcpy (prefix, cv, i > sizeof(prefix) ? sizeof(prefix) : i);
      else if (!strcmp (value, IRCPAR_CHANMODES))
	strfcpy (chanmodes, cv, i > sizeof(chanmodes) ? sizeof(chanmodes) : i);
      else if (!strcmp (value, IRCPAR_UMODES))
	strfcpy (umodes, cv, i > sizeof(umodes) ? sizeof(umodes) : i);
      else if (!strcmp (value, IRCPAR_CASEMAPPING))
      {
	if (!strncasecmp (cv, "none", 4))
	  lc = NULL;
	else if (!strncasecmp (cv, "ascii", 5))
	  lc = &irc_ascii_strlower;
	else if (!strncasecmp (cv, "rfc1459", 7))
	  lc = &irc_rfc1459_strlower;
	else
	  lc = &unistrlower;
      }
    }
  }
  for (i = 0; (int)i < parc; i++)
  {
    cv = strchr (parv[i], '=');
    if (cv)
      *cv++ = 0;
    else
      continue;
    if (!strcmp (parv[i], IRCPAR_NICKLEN))
      nicklen = atoi (cv);
    else if (!strcmp (parv[i], IRCPAR_TOPICLEN))
      topiclen = atoi (cv);
    else if (!strcmp (parv[i], IRCPAR_MAXBANS))
      maxbans = atoi (cv);
    else if (!strcmp (parv[i], IRCPAR_CHANNELS))
      maxchannels = atoi (cv);
    else if (!strcmp (parv[i], IRCPAR_MODES))
      modes = atoi (cv);
    else if (!strcmp (parv[i], IRCPAR_TARGETS))
      maxtargets = atoi (cv);
    else if (!strcmp (parv[i], IRCPAR_PREFIX))
      strfcpy (prefix, cv, sizeof(prefix));
    else if (!strcmp (parv[i], IRCPAR_CHANMODES))
      strfcpy (chanmodes, cv, sizeof(chanmodes));
    else if (!strcmp (parv[i], IRCPAR_UMODES))
      strfcpy (umodes, cv, sizeof(umodes));
    else if (!strcmp (parv[i], IRCPAR_CASEMAPPING))
    {
      if (!strcasecmp (cv, "none"))
	lc = NULL;
      else if (!strcasecmp (cv, "ascii"))
	lc = &irc_ascii_strlower;
      else if (!strcasecmp (cv, "rfc1459"))
	lc = &irc_rfc1459_strlower;
      else /* assume any other are locale dependent */
	lc = &unistrlower;
    }
    else
      DBG ("irc_update_isupport: ignoring %s=%s.", parv[i], cv);
  }
  i = 0;
#define _set_isupport(a,b) _set_isupport_num (value, sizeof(value), &i, \
						a, sizeof(a), b)
  _set_isupport (IRCPAR_NICKLEN, nicklen);
  _set_isupport (IRCPAR_TOPICLEN, topiclen);
  _set_isupport (IRCPAR_MAXBANS, maxbans);
  _set_isupport (IRCPAR_CHANNELS, maxchannels);
  _set_isupport (IRCPAR_MODES, modes);
  _set_isupport (IRCPAR_TARGETS, maxtargets);
#undef _set_isupport
#define _set_isupport(a,b) _set_isupport_string (value, sizeof(value), &i, \
						a, sizeof(a), b)
  _set_isupport (IRCPAR_PREFIX, prefix);
  _set_isupport (IRCPAR_CHANMODES, chanmodes);
  _set_isupport (IRCPAR_UMODES, umodes);
  if (lc == NULL)
    _set_isupport (IRCPAR_CASEMAPPING, "none");
  else if (lc == &irc_ascii_strlower)
    _set_isupport (IRCPAR_CASEMAPPING, "ascii");
  else if (lc == &irc_rfc1459_strlower)
    _set_isupport (IRCPAR_CASEMAPPING, "rfc1459");
#undef _set_isupport
  value[i] = 0;
  DBG ("irc_update_isupport: [%s]->[%s]", NONULL(cs), value);
  if (safe_strcmp (cs, value) &&
    !Set_Field (clr, IRCPAR_FIELD, value, 0))
      Add_Request (I_LOG, "*", F_WARN, "irc:irc_update_isupport: could not save.");
  Unlock_Clientrecord (clr);
  ((irc_server *)net->data)->lc = lc;
}

BINDING_TYPE_irc_raw (irc_rpl_isupport);
static int irc_rpl_isupport (INTERFACE *net, char *sv, char *me, unsigned char *src,
		int parc, char **parv, size_t (*ilc)(char *, const char *, size_t))
{ /* Parameters: me param=value ... "are supported by this server" */
  char *c;

  dprint (4, "irc_rpl_isupport: %d params, first one is %s.", parc-2, parv[1]);
  if (parc < 3)
    return 0;		/* something other than ISUPPORT */
  for (c = parv[1]; *c; c++)
  {
    if (*c == '=')
      break;
    else if (*c < 'A' || *c > 'Z')
      return 0;		/* invalid */
  }
  if (!*c)
    return 0;
  _irc_update_isupport (net, parc-2, &parv[1]);
  return 1;
}


/*
 * "connect" binding:
 *   int func (const char *link, char *args);
 *
 * Creates an outgoing connection to given server. Server must be described
 * in listfile already. Note: it vas revised to run via ".connect ircnet"
 * may have a parameter server (additional hostline)
 *
 * each listfile host line has special meaning:
 * [login:pass@]host[:port]
 * where login will be ignored
 */
BINDING_TYPE_connect (connect_irc);
static int connect_irc (const char *link, char *args)
{
  irc_server *serv;

  /* check parameters */
  if (args && !*args)
    args = NULL;
  /* check if such service already exists */
  if ((Find_Iface (I_SERVICE, link)))
    return Unset_Iface();
  /* create new server interface and add it to list */
  if (IrcServers == NULL)
    IrcServers = serv = safe_calloc (1, sizeof(irc_server));
  else
  {
    for (serv = IrcServers; serv->next; serv = serv->next);
    serv->next = safe_calloc (1, sizeof(irc_server));
    serv->next->prev = serv;
    serv = serv->next;
  }
  serv->p.socket = -1;
  serv->p.priv = (void *)1; /* it's unused but we should not wait on socket */
  serv->lc = &unistrlower;
  serv->p.iface = Add_Iface (I_SERVICE | I_CONNECT, link, &_irc_signal,
			     &_irc_request, serv);
  return _irc_try_server (serv, args, -1, NULL); /* shedule a connection */
}


/*
 * "irc-connected" bindings
 *   (int)void func (INTERFACE *iface, char *server, char *nick, size_t (*lc) (char *, const char *, size_t))
 */
/* internal one is to set umode and send on-login commands */
BINDING_TYPE_irc_connected (ic_default);
static void ic_default (INTERFACE *iface, char *server, char *nick,
			size_t (*lc) (char *, const char *, size_t))
{
  struct clrec_t *clr;
  char *msg;

  if (*irc_umode != 0)
    New_Request (iface, 0, "MODE %s :%s", nick, irc_umode);
  clr = Lock_Clientrecord (iface->name);
  if (clr)
  {
    msg = Get_Field (clr, "umode", NULL);
    dprint (4, "ic_default: sending default commands for %s...", iface->name);
    if (msg)
      New_Request (iface, 0, "MODE %s :%s", nick, msg);
    msg = Get_Field (clr, ".login", NULL);
    if (msg)
      New_Request (iface, 0, "%s", msg);
    Unlock_Clientrecord (clr);
  }
}

BINDING_TYPE_time_shift (ts_irc);
static void ts_irc (int drift)
{
  register irc_server *serv;

  for (serv = IrcServers; serv; serv = serv->next)
    serv->last_output += drift;		/* correct it for keep-alive */
}


/* --- Common module functions ---------------------------------------------- */

static void module_irc_regall (void)
{
  /* register module itself */
  Add_Request (I_INIT, "*", F_REPORT, "module irc");
  /* register all variables */
  RegisterInteger ("irc-timeout", &irc_timeout);
  RegisterInteger ("irc-connect-timeout", &irc_connect_timeout);
  RegisterInteger ("irc-retry-timeout", &irc_retry_timeout);
  RegisterInteger ("irc-next-try", &irc_retry_server);
  RegisterInteger ("irc-default-port", &defaultport);
  RegisterInteger ("irc-max-penalty", &maxpenalty);
  RegisterInteger ("irc-privmsg-keep", &irc_pmsg_keep);
  RegisterString ("irc-default-nick", irc_default_nick, sizeof(irc_default_nick), 0);
  RegisterString ("irc-default-ident", irc_default_ident, sizeof(irc_default_ident), 0);
  RegisterString ("irc-default-realname", irc_default_realname, sizeof(irc_default_realname), 0);
  RegisterString ("irc-umode", irc_umode, sizeof(irc_umode), 0);
  RegisterBoolean ("irc-privmsg-commands", &irc_privmsg_commands);
}

/*
 * this function must receive signals:
 *  S_TERMINATE - unload module,
 *  S_REPORT - out state info to log,
 *  S_REG - [re]register all.
 */
static iftype_t module_irc_signal (INTERFACE *iface, ifsig_t sig)
{
  irc_server *serv;
  INTERFACE *tmp;
  irc_await *awh;
  int i;
  char *c, *ch;

  switch (sig)
  {
    case S_TERMINATE:
      /* unregister all variables and bindings */
      UnregisterVariable ("irc-timeout");
      UnregisterVariable ("irc-connect-timeout");
      UnregisterVariable ("irc-retry-timeout");
      UnregisterVariable ("irc-next-try");
      UnregisterVariable ("irc-default-port");
      UnregisterVariable ("irc-max-penalty");
      UnregisterVariable ("irc-privmsg-keep");
      UnregisterVariable ("irc-default-nick");
      UnregisterVariable ("irc-default-ident");
      UnregisterVariable ("irc-default-realname");
      UnregisterVariable ("irc-umode");
      UnregisterVariable ("irc-privmsg-commands");
      Delete_Binding ("irc-raw", &irc_ping, NULL);
      Delete_Binding ("irc-raw", &irc_quit, NULL);
      Delete_Binding ("irc-raw", &irc_error, NULL);
      Delete_Binding ("irc-raw", &irc_kill, NULL);
      Delete_Binding ("irc-raw", &irc_privmsg, NULL);
      Delete_Binding ("irc-raw", &irc_notice, NULL);
      Delete_Binding ("irc-raw", &irc_nick, NULL);
      Delete_Binding ("irc-raw", &irc_rpl_welcome, NULL);
      Delete_Binding ("irc-raw", &irc_rpl_myinfo, NULL);
      Delete_Binding ("irc-raw", &irc_rpl_isupport, NULL);
      Delete_Binding ("irc-raw", &irc_rpl_bounce, NULL);
      Delete_Binding ("irc-raw", &irc_err_nosuchnick, NULL);
      Delete_Binding ("irc-raw", &irc__nextnick, NULL);
      Delete_Binding ("irc-raw", &irc__fatal, NULL);
      Delete_Binding ("irc-connected", (Function)&ic_default, NULL);
      Delete_Binding ("connect", &connect_irc, NULL);
      Delete_Binding ("time-shift", (Function)&ts_irc, NULL);
      Delete_Help ("irc");
      /* kill all awaiting connections if there were any */
      while ((awh = IrcAwaits))
      {
	IrcAwaits = awh->next;
	awh->serv->await = NULL;
	pthread_cancel (awh->th);
	Unset_Iface();
	pthread_join (awh->th, NULL);
	Set_Iface (NULL);
	FREE (&awh);
      }
      /* send QUITs for all connected servers */
      if (IrcServers)
      {
	tmp = Set_Iface (iface);	/* who called me? */
	New_Request (tmp, F_QUICK, _("Waiting for IRC servers for terminating connection..."));
	Unset_Iface();
	Get_Request();		/* send it now */
	for (serv = IrcServers; serv; serv = serv->next)
	  _irc_signal (serv->p.iface, S_TERMINATE);
	/* kill all server connections */
	/* TODO: check for timeout here or interface will do that itself? */
	while (IrcServers != NULL)
	  for (serv = IrcServers; serv; )
	  {
	    Set_Iface (serv->p.iface);
	    serv = serv->next;	/* choose it now since it may die later */
	    Get_Request();	/* in this state it may only send data */
	    Unset_Iface();
	  }
      }
      irc_privmsgunreg();	/* do it after all privmsg ifaces gone */
      iface->ift |= I_DIED;
      break;
    case S_REG:
      module_irc_regall();
      break;
    case S_FLUSH:
      /* recall "irc-connected" bindings for all connected networks */
      for (serv = IrcServers; serv; serv = serv->next)
	if (serv->p.state == P_TALK || serv->p.state == P_IDLE)
	  _irc_connected (serv);
      /* check for autoconnects in listfile */
      tmp = Add_Iface (I_TEMP, NULL, NULL, &_irc_servlist, NULL);
      i = Get_Clientlist (tmp, U_SPECIAL, ".logout", "irc");
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
	if ((Get_Clientflags (c, "") & U_AUTO) &&	/* autoconnect found */
	    (!Find_Iface (I_SERVICE, c) || Unset_Iface()))
	  connect_irc (c, NULL);			/* shedule a connection */
      }
      tmp->ift = I_DIED;
      break;
    case S_REPORT:
      tmp = Set_Iface (iface);
      New_Request (tmp, F_REPORT, "Module irc: %s",
		   IrcServers ? "connected to servers:" : "no servers connected.");
      for (serv = IrcServers; serv; serv = serv->next)
	New_Request (tmp, F_REPORT, "   network %s: server %s, my nick %s, pmsgout interfaces %d",
		     serv->p.iface->name, SocketDomain (serv->p.socket, NULL),
		     serv->mynick, irc_privmsgout_count (serv->pmsgout));
      Unset_Iface();
    default: ;
  }
  return 0;
}

static void _irc_init_bindings (void)
{
#define NB(a,b) Add_Binding ("irc-raw", a, 0, 0, &b, NULL)
  NB ("PING", irc_ping);
  NB ("ERROR", irc_error);
  NB ("QUIT", irc_quit);
  NB ("KILL", irc_kill);
  NB ("PRIVMSG", irc_privmsg);
  NB ("NOTICE", irc_notice);
  NB ("NICK", irc_nick);
  NB ("001", irc_rpl_welcome);
  NB ("004", irc_rpl_myinfo);
  NB ("005", irc_rpl_isupport);
  NB ("010", irc_rpl_bounce);
  NB ("401", irc_err_nosuchnick);
  NB ("432", irc__nextnick);
  NB ("433", irc__nextnick);
//  NB ("436", irc__nextnick); // server kills us in that case
  NB ("437", irc_err_unavailable);
  NB ("451", irc__nextnick);
  NB ("463", irc__fatal);
  NB ("464", irc__fatal);
  NB ("465", irc__fatal);
#undef NB
}

/*
 * this function called when you load a module.
 * Input: parameters string args - nothing.
 * Returns: address of signals receiver function, NULL if not loaded.
 */
SigFunction ModuleInit (char *args)
{
  struct passwd *pwd;
  register char *c;
  register int i;
  struct passwd pwdbuf;
  char buf[LONG_STRING];

  CheckVersion;
  /* set up variables and get login and full name */
  if (getpwuid_r(getuid(), &pwdbuf, buf, sizeof(buf), &pwd) || pwd == NULL) {
    ERROR("Cannot retrieve user info, not loading module \"irc\".");
    return (NULL);
  }
  strfcpy (irc_default_nick, Nick, sizeof(irc_default_nick));
  strfcpy (irc_default_ident, pwd->pw_name, sizeof(irc_default_ident));
  strfcpy (irc_default_realname, pwd->pw_gecos, sizeof(irc_default_realname));
  if ((c = strchr (irc_default_realname, ',')))		/* strip other info */
    *c = 0;
  /* init all stuff */
  BT_Irc = Add_Bindtable ("irc-raw", B_MATCHCASE);
  _irc_init_bindings();
  BT_IrcConn = Add_Bindtable ("irc-connected", B_MASK);
  Add_Binding ("irc-connected", "*", 0, 0, (Function)&ic_default, NULL);
  BT_IrcDisc = Add_Bindtable ("irc-disconnected", B_MASK);
  Add_Binding ("connect", "irc", U_SPECIAL, U_NONE, &connect_irc, NULL); /* no channels */
  BT_IrcNChg = Add_Bindtable ("irc-nickchg", B_MATCHCASE); /* always lowercase */
  BT_IrcSignoff = Add_Bindtable ("irc-signoff", B_MATCHCASE); /* the same */
  BT_IrcNSplit = Add_Bindtable ("irc-netsplit", B_MATCHCASE); /* the same */
  BT_IrcMyQuit = Add_Bindtable ("irc-quit", B_MASK);
  Add_Binding ("time-shift", "*", 0, 0, (Function)&ts_irc, NULL);
  Add_Help ("irc");
  irc_privmsgreg();
  for (i = 0; i < 256; i++)
  {
    if (i >= 'A' && i <= 'Z')
      irc_ascii_lowertable[i] = irc_rfc1459_lowertable[i] = i + 0x20;
    else if (i == '~')
      irc_rfc1459_lowertable[i] = ((irc_ascii_lowertable[i] = i)) - 0x20;
    else if (i == '[' || i == ']' || i == '\\')
      irc_rfc1459_lowertable[i] = ((irc_ascii_lowertable[i] = i)) + 0x20;
    else
      irc_ascii_lowertable[i] = irc_rfc1459_lowertable[i] = i;
  }
  module_irc_regall();
  /* shedule check for autoconnects since listfile may be not loaded yet */
  NewTimer (I_MODULE, "irc", S_FLUSH, 1, 0, 0, 0);
  return (&module_irc_signal);
}
