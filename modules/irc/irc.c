/*
 * Copyright (C) 2004-2006  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 */

#include "foxeye.h"

#include <pwd.h>

#include "modules.h"
#include "irc.h"
#include "list.h"
#include "init.h"
#include "socket.h"
#include "direct.h"
#include "sheduler.h"
#include "conversion.h"

typedef enum {
  L_DISCONNECTED = 0,		/* goto next server */
  L_INITIAL,			/* waiting for connection */
  L_REGISTERING,		/* not registered yet */
  L_CONNECTED,			/* main state */
  L_PINGSENT,			/* wait for pong */
  L_QUIT,			/* want to send "QUIT" */
  L_LASTWAIT			/* "QUIT" sent */
} irc_state;

typedef struct ircserver_t {
  struct ircserver_t *next;
  struct ircserver_t *prev;
  INTERFACE *iface;
  struct irc_await *await;
  idx_t socket;				/* -1 on start and socket after */
  time_t last_input, last_output;
  int penalty;				/* in messages*2, applied to sendq */
  irc_state state;
  char **servlist;
  char *mynick;
  char *lcnick;
  char *srvname;			/* server name from server itself */
  INTERFACE *pmsgout;			/* with lname */
  char start[13];			/* registered at */
  size_t inbuf;
  size_t bufptr;
  char *(*lc)(char *, const char *, size_t); /* lowercase nick conversion */
  char buf[MB_LEN_MAX*MESSAGEMAX];	/* output buffer */
} ircserver_t;

typedef struct irc_await {
  pthread_t th;
  ircserver_t *serv;
  struct irc_await *next;
  int ready:1;
} irc_await;

/* must be locked by dispatcher lock so don't access it from threads! */
static irc_await *IrcAwaits = NULL;
static ircserver_t *IrcServers = NULL;

static long int irc_timeout = 180;	/* 3 minutes by default */
static long int irc_connect_timeout = 300;
static long int irc_retry_timeout = 120;
static long int defaultport = 6667;
static long int maxpenalty = 10;	/* in seconds, see ircd sources */
static long int irc_pmsg_keep = 30;
static char irc_default_nick[NICKLEN+1] = "";
static char irc_default_ident[10] = "";
static char irc_default_realname[REALNAMELEN+1] = "";
static char irc_umode[33] = "";
static bool irc_privmsg_commands = FALSE;	/* disallowed by default */
static bool irc_ignore_ident_prefix = TRUE;

static bindtable_t *BT_Irc = NULL;	/* incoming IRC message */
static bindtable_t *BT_IrcConn = NULL;	/* connected to server */
static bindtable_t *BT_IrcDisc = NULL;	/* connection to server lost */
static bindtable_t *BT_IrcNChg = NULL;	/* some nick changed, internal only */
static bindtable_t *BT_IrcSignoff = NULL; /* someone quits, internal only */
static bindtable_t *BT_IrcNSplit = NULL; /* netsplit detected, internal only */


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
    ((irc_await *)id)->serv->socket = result;
  ((irc_await *)id)->ready = 1;
  /* return to the core/direct.c:_connect_host() */
}


/* --- Lowercase conversions variants --------------------------------------- */

static char irc_ascii_lowertable[256]; /* filled by ModuleInit() */
static char irc_rfc1459_lowertable[256];

/* irc_none_strlower is NULL */
/* irc_uni_strlower is rfc2812_strlower */

static char *irc_ascii_strlower (char *dst, const char *o, size_t s)
{
  register char *d = dst;

  while (*o && d < &dst[s-1])
    *d++ = irc_ascii_lowertable[*(uchar *)o++];
  *d = 0;
  return dst;
}

static char *irc_rfc1459_strlower (char *dst, const char *o, size_t s)
{
  register char *d = dst;

  while (*o && d < &dst[s-1])
    *d++ = irc_rfc1459_lowertable[*(uchar *)o++];
  *d = 0;
  return dst;
}


/* --- Internal functions --------------------------------------------------- */

/* see RFC1459 or RFC2812 */
static int parse_ircparams (char **array, char *param)
{
  register char *c;
  register int n;

  c = param;
  for (n = 0; *c && n < 15; n++)
  {
    if (*c == ':')
    {
      array[n++] = c+1;
      break;
    }
    array[n] = c;
    while (*c && *c != ' ') c++;
    if (*c) *c++ = 0;
    while (*c == ' ') c++;
  }
  array[n] = NULL;
  return n;
}

/*
 * form of hostrecord:
 * [[*]:passwd@]domain.net[:port]
 *
 * returns server real name if connected, else host:port and password
 *
 * internal chars: '=' current '-' banned ' ' ok
 */
static char *_irc_current_server (ircserver_t *serv, char **pass)
{
  char *c;
  char **cc;

  if (serv->srvname)
    return serv->srvname;
  /* nothing to check - try to have good code :) */
  for (cc = serv->servlist; *cc && (*cc)[0] != '='; cc++); /* find current */
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
   removes garbage from hostname form [:passwd@]host[:port] */
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
  dprint (3, "_irc_parse_hostline: \"%s\" -> \"%s\"", hostline, nn);
  return c;
}

/* returns: host[:port] or "" (retry later) or NULL */
static char *_irc_getnext_server (ircserver_t *serv, const char *add,
				  int current_is_bad)
{
  char **cc;
  int i;

  if (add && !*add)
    add = NULL;
  if (!serv->servlist)
  {
    INTERFACE *tmp = Add_Iface (NULL, I_TEMP, NULL, &_irc_servlist, NULL);
    register const char *c, *ch;

    /* load servers list from userrecord */
    i = Get_Hostlist (tmp, serv->pmsgout->name);
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
    for (c = tmp->data; c && *c; c = NextWord (c)) i++;
    serv->servlist = cc = safe_malloc ((i+1) * sizeof(char *));
    for (c = tmp->data; c && *c; cc++)
      c = _irc_parse_hostline (c, cc);
    *cc = NULL;
    cc = serv->servlist;
    if (add)
    {
      if (!(ch = strchr (add, '@')))
	ch = add;
      else
	ch++;
      while ((c = *cc))
      {
	if (c[1] == ':')
	  c += (strlen (c) + 1);
	if (!strcmp (c, ch))
	  break;
	cc++;
      }
      if (!c)
      {
	_irc_parse_hostline (add, cc);
	cc[1] = NULL;
      }
    }
    tmp->ift = I_DIED;
  }
  else
  {
    for (cc = serv->servlist; *cc && (*cc)[0] != '='; cc++); /* find current */
    if (*cc)
    {
      if (current_is_bad > 0)
	(*cc)[0] = '-';
      else
	(*cc)[0] = ' ';
      cc++;
    }
    else
      cc = serv->servlist;
    while (*cc && (*cc)[0] == '-') cc++; /* skip all bad */
    if (add)
    {
      register const char *c, *ch;

      cc = serv->servlist;
      if (!(ch = strchr (add, '@')))
	ch = add;
      i = 0;
      while ((c = *cc))
      {
	if (c[1] == ':')
	  c += (strlen (c) + 1);
	if (!strcmp (c, ch))
	  break;
	i++;
	cc++;
      }
      if (!c)
      {
	safe_realloc ((void **)&serv->servlist, (i + 2) * sizeof(char *));
	cc = &serv->servlist[i];
	_irc_parse_hostline (add, cc);
	cc[1] = 0;
      }
    }
  }
  dprint (3, "_irc_getnext_server: next server:%s", *cc ? *cc : " [none]");
  if (current_is_bad < 0)
    return "";
  if (*cc)
  {
    (*cc)[0] = '=';
    if ((*cc)[1] == ':')
      return (*cc + strlen(*cc) + 1);
    else
      return (*cc + 1);
  }
  else if (Time - serv->last_output < irc_retry_timeout)
    return "";
  serv->last_output = Time;
  for (cc = serv->servlist; *cc && (*cc)[0] == '-'; cc++); /* skip bad */
  if (*cc)
  {
    (*cc)[0] = '=';
    return (*cc + strlen(*cc) + 1);
  }
  return NULL;
}

/* run bindings */
static void _irc_run_conn_bind (ircserver_t *serv, bindtable_t *bt)
{
  binding_t *bind = NULL;
  char *name = _irc_current_server (serv, NULL);

  while ((bind = Check_Bindtable (bt, serv->iface->name, -1, -1, bind)))
  {
    if (bind->name)
      RunBinding (bind, NULL, serv->iface->name, name, -1, serv->mynick);
    else
      bind->func (serv->iface, name, serv->mynick, serv->lc);
  }
}

#define _irc_connected(serv) _irc_run_conn_bind (serv, BT_IrcConn)
#define _irc_disconnected(serv) _irc_run_conn_bind (serv, BT_IrcDisc)

/*
 * do first try (serv->servlist is NULL) or retry if autoreconnect is on
 * creates new connection thread and irc_await for it
 * banned is -1 to shedule connection, 1 for removing from list.
 * returns 1 if successful or 0 if error
 */
static int _irc_try_server (ircserver_t *serv, const char *tohost, int banned,
			    char *reason)
{
  userflag uf;
  char *name, *c;
  irc_await *await;

  /* if already connected then break connection first */
  KillSocket(&serv->socket);
  FREE (&serv->srvname);
  serv->socket = -1;		/* it may still contain an error code */
  if (serv->state >= L_CONNECTED && serv->state <= L_QUIT)
    _irc_disconnected (serv); /* registered and disconnected so run bindings */
  if (!serv->pmsgout)
  {
    char lname[IFNAMEMAX+1];

    lname[0] = '@';
    strfcpy (&lname[1], serv->iface->name, sizeof(lname) - 1);
    serv->pmsgout = Add_Iface (lname, I_CLIENT, NULL,
			       &irc_privmsgout_default, NULL);
  }
  /* some cleanup... */
  serv->inbuf = 0;
  serv->penalty = 0;
  serv->last_input = Time;
  /* check if we will try connection/reconnect */
  uf = Get_Clientflags (serv->pmsgout->name, NULL);
  if (serv->state != L_DISCONNECTED)
    Add_Request (I_LOG, "*", F_CONN, _("Connection with network %s lost%s%s%s."),
		 serv->iface->name, reason ? ": " : "",
		 reason ? reason : banned ? _(": denied") : "",
		 (uf & U_ACCESS) ? _(", retrying..") : "");
  if ((!serv->servlist || serv->state == L_DISCONNECTED || (uf & U_ACCESS)) &&
      serv->state != L_QUIT &&				/* dont quitting */
      (name = _irc_getnext_server (serv, tohost, banned))) /* have a server */
  {
    serv->state = L_DISCONNECTED;
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
    do {		/* fake cycle to get continue working */
      c = strchr (name, ':');
      if (c) *c = 0;
      await->th = Connect_Host (name, c ? atoi (&c[1]) : defaultport,
				&serv->socket, &_irc_connection_ready, await);
      if (c) *c = ':';
      if (await->th != 0)
	Add_Request (I_LOG, "*", F_CONN, _("Connecting to %s, port %hu..."),
		     name, c ? atoi (&c[1]) : defaultport);
      if (await->th == 0 && (uf & U_ACCESS) &&
	  (name = _irc_getnext_server (serv, NULL, 0)))
	continue;
    } while (0);
    if (await->th != 0)
    {
      serv->state = L_INITIAL;
      return 1;
    }
    await->ready = 1;	/* to destroy await struct */
  }
  /* cannot find working server, give up... voila */
  serv->state = L_LASTWAIT;
  Add_Request (I_LOG, "*", F_CONN | F_ERROR,
	       _("Could not find a server for network %s"), serv->iface->name);
  return 0;
}

static char *_irc_try_nick (ircserver_t *serv, clrec_t *clr)
{
  register char *c;
  char nn[LNAMELEN+1];
  char *nlist;

  nlist = Get_Field (clr, "nick", NULL);
  if (!serv->mynick)				/* the first try */
  {
    if (!nlist || !*nlist)			/* no nicklist */
      serv->mynick = safe_strdup (irc_default_nick);
    else
    {
      for (c = nn; *nlist && c < &nn[sizeof(nn)-1]; nlist++) *c++ = *nlist++;
      *c = 0;
      serv->mynick = safe_strdup (nn);
    }
  }
  else if (!strcmp (nlist, serv->mynick) ||	/* no alternates */
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
    if (*c)
      nlist = NextWord (c);
    FREE (&serv->mynick);
    serv->mynick = safe_strdup (nn);
  }
  FREE (&serv->lcnick);
  if (serv->lc)
  {
    serv->lc (nn, serv->mynick, sizeof(nn));
    serv->lcnick = safe_strdup (nn);
  }
  else
    serv->lcnick = safe_strdup (serv->mynick);
  dprint (3, "_irc_try_nick: trying %s", serv->mynick);
  return serv->mynick;
}

static void _irc_send (ircserver_t *serv)
{
  char *c, *last;
  size_t sw;
  int i;

  if (serv->socket < 0)		/* nothing to do */
    return;
  /* count number of CR-LF in buffer */
  for (i = 0, c = &serv->buf[serv->bufptr], last = &c[serv->inbuf]; c < last; i++)
  {
    c = memchr (c, '\n', last - c) + 1;
    if (c) c++;
    else break;
  }
  /* check SendQ */
  if (Time + maxpenalty < serv->last_output + serv->penalty + i)
    return;
  /* try to send buffer */
  c = &serv->buf[serv->bufptr];
  sw = WriteSocket (serv->socket, serv->buf, &serv->bufptr, &serv->inbuf, M_RAW);
  if (sw == 0)
    return;
  else if (sw > 0)
  {
    dprint (4, "_irc_send: sent to %s: \"%.*s\"", serv->iface->name, sw, c);
    for (i = 0, last = &c[sw]; c < last; i++)
    {
      c = memchr (c, '\n', last - c);
      if (c) c++;
      else break;
    }
    serv->penalty += 2 * i;
    if (Time - serv->last_output >= serv->penalty)
      serv->penalty = 0;
    else
      serv->penalty -= (Time - serv->last_output);
    serv->last_output = Time;
    return;
  }
  /* if socket died then kill it */
  _irc_try_server (serv, NULL, 0, NULL);
}

static char *_irc_get_lname (char *nuh, userflag *uf, char *net)
{
  char *c;
  clrec_t *u;

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

/* supported: S_REPORT, S_SHUTDOWN, S_TERMINATE */
static iftype_t _irc_signal (INTERFACE *iface, ifsig_t sig)
{
  ircserver_t *serv = (ircserver_t *)iface->data;
  char *reason, *domain;
  unsigned short port;
  INTERFACE *tmp;
  char report[STRING];

  switch (sig)
  {
    case S_SHUTDOWN: /* QUIT :leaving */
      if (ShutdownR)
	reason = ShutdownR;
      else
	reason = "leaving";
      snprintf (serv->buf, sizeof(serv->buf), "\r\nQUIT :%s\r\n", reason);
      serv->inbuf = strlen (serv->buf);
      serv->bufptr = 0;
      WriteSocket (serv->socket, serv->buf, &serv->bufptr, &serv->inbuf, M_RAW);
      CloseSocket (serv->socket);
      iface->ift |= I_DIED;
      serv->iface = NULL;
      break;
    case S_TERMINATE: /* QUIT :leaving */
      if (serv->state <= L_INITIAL || serv->state >= L_QUIT)
	if (serv->state != L_QUIT)
	  serv->state = L_LASTWAIT;
	break;
      /* TODO: make some nice stuff for QUIT message here */
      if (ShutdownR)
	reason = ShutdownR;
      else
	reason = "leaving";
      New_Request (iface, F_QUICK, "QUIT :%s", reason); /* ignore queue */
      serv->state = L_QUIT;
      break;
    case S_REPORT: /* for .cstat */
      if (serv->await || !serv->await->ready)
      {
	domain = _irc_current_server (serv, NULL);
	port = 0;
      }
      else
	domain = SocketDomain (serv->socket, &port);
      switch (serv->state)
      {
	case L_DISCONNECTED:
	  reason = _("reconnecting IRC server");
	  break;
	case L_INITIAL:
	  reason = _("connecting IRC server");
	  break;
	case L_REGISTERING:
	  reason = _("registering at IRC server");
	  break;
	case L_CONNECTED:
	case L_PINGSENT:
	  reason = _("IRC server connected");
	  break;
	default:
	  reason = _("disconnecting IRC server");
	  break;
      }
      /* %N - my nick, %@ - server name, %L - network name, %# - connected at,
	 %I - socket id, %P - port, %* - state */
      printl (report, sizeof(report), ReportFormat, 0, serv->mynick, domain,
	      iface->name, serv->start, (uint32_t)serv->socket, port, 0, reason);
      tmp = Set_Iface (iface);
      New_Request (tmp, F_REPORT, "%s", report);
      Unset_Iface();
    default: /* ignore others */
      break;
  }
  return 0;
}

/* returns: 0 - disconnected, 1 - again later, 2 - accepted */
static int _irc_request_main (INTERFACE *iface, REQUEST *req)
{
  ircserver_t *serv = (ircserver_t *)iface->data;
  register char *c;
  int i, isregistered = 0, reject = 1;
  ssize_t sw;

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
      dprint (3, "_irc_request: await terminated");
      if (serv->socket < 0)	/* could not resolve the server? remove it! */
	return _irc_try_server (serv, NULL, 1, msg);
    }
    else
      return 1;
  }
  if (serv->state != L_DISCONNECTED && serv->pmsgout == NULL)
  {
    dprint (1, "_irc_request: unknown condition!");
    return 0;			/* already died! */
  }
  /* check for connection state */
  switch (serv->state)
  {
    case L_DISCONNECTED:
      return _irc_try_server (serv, NULL, 0, NULL);
    case L_INITIAL:
      /* is connection established? - let's register myself! */
      /* if there was an error then serv->socket < 0 (see function
	 _irc_connection_ready()), else if waiting for connection
	 then ReadSocket will return E_AGAIN */
      if (serv->socket >= 0 && 
	  (sw = ReadSocket (serv->buf, serv->socket, sizeof(serv->buf),
			     M_RAW)) >= 0)
      {
	clrec_t *clr;
	char *ident, *realname;

	Add_Request (I_LOG, "*", F_CONN, _("Connected to %s, registering..."),
		     iface->name);
	_irc_current_server (serv, &ident);	/* have to send PASS? */
	c = ident;
	clr = Lock_Clientrecord (serv->pmsgout->name);
	if (!clr)		/* it was already deleted??? */
	{
	  serv->state = L_LASTWAIT;
	  Add_Request (I_LOG, "*", F_CONN | F_ERROR,
		       _("Disconnected from %s: unknown error."), iface->name);
	  return _irc_request_main (iface, req);
	}
	if (serv->mynick)
	{
	  ident = Get_Field (clr, "nick", NULL);	/* nicklist */
	  sw = strlen (ident);
	  if (!strncmp (ident, serv->mynick, sw) &&
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
	  snprintf (serv->buf, sizeof(serv->buf),
		    "PASS %s\r\nNICK %s\r\nUSER %s 8 * :%s\r\n", c,
		    serv->mynick, ident, realname);
	else
	  snprintf (serv->buf, sizeof(serv->buf), "NICK %s\r\nUSER %s 8 * :%s\r\n",
		    serv->mynick, ident, realname);
#ifdef HAVE_ICONV
	ident = safe_strdup (Get_Field (clr, "charset", NULL));
#endif
	Unlock_Clientrecord (clr);
#ifdef HAVE_ICONV
	iface->conv = Get_Conversion (ident);
	FREE (&ident);
#endif
	/* setup the state */
	serv->state = L_REGISTERING;
	serv->inbuf = strlen (serv->buf);
	serv->bufptr = 0;
      }
      else if (serv->socket < 0 || sw != E_AGAIN)
      {
	/* TODO: print errors */
	dprint (3, "_irc_request: no connection, error %d",
		(serv->socket >= 0) ? sw : serv->socket);
	return _irc_try_server (serv, NULL, 0, NULL);
      }
    case L_REGISTERING:
      if (serv->state == L_REGISTERING && serv->inbuf != 0)
	_irc_send (serv);
      /* we are waiting for RPL_WELCOME now */
      /* connection timeout? - disconnect and check if we may retry */
      if (Time - serv->last_input > irc_connect_timeout)
      {
	dprint (3, "_irc_request: connection timeout");
	return _irc_try_server (serv, NULL, 0, _("connection timeout"));
      }
      /* delay request for now since we aren't ready */
      break;
    case L_PINGSENT:
      /* check for timeout */
      if (Time - serv->last_input > 2 * irc_timeout)
	return _irc_try_server (serv, NULL, 0, NULL);
    case L_CONNECTED:
    case L_QUIT:
      if (serv->inbuf)
	_irc_send (serv);
      if (serv->state == L_PINGSENT || serv->state == L_CONNECTED)
	isregistered = 1;		/* _irc_send() might reset connection */
      else if (serv->inbuf)		/* serv->state == L_QUIT */
	return 1;
      if (serv->state != L_QUIT)
	break;
      /* it was just sent quit message so run bindings and go off */
      _irc_disconnected (serv);
      //serv->state = L_LASTWAIT;
      Add_Request (I_LOG, "*", F_CONN, _("Disconnected from %s."), iface->name);
    case L_LASTWAIT:
      /* we are disconnected and will be no reconnect so empty all queues */
      irc_privmsgout_cancel (serv->pmsgout, NULL);
      serv->pmsgout->ift |= I_DIED;
      serv->pmsgout = NULL;
		/* "Connection reset by peer" */
		/* note: I wonder if terminator might not send QUIT here yet */
      KillSocket (&serv->socket);
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
      FREE (&serv->lcnick);
      iface->ift |= I_DIED;
      return 0;
  }
  /* get input if it's possible */
  if (serv->state > L_INITIAL && serv->state < L_QUIT)
  {
#ifdef HAVE_ICONV
    char sbuf[MB_LEN_MAX*MESSAGEMAX];
#endif
    char inbuf[MB_LEN_MAX*MESSAGEMAX];
    char uhb[HOSTMASKLEN+1]; /* nick!user@host */
    char *params[19]; /* network sender command args ... NULL */
    char *prefix, *p, *uh;
    binding_t *bind;

    if (serv->inbuf == 0)	/* connection established, we may send data */
      reject = 0;
    /* check for input (sw includes '\0') */
    sw = ReadSocket (inbuf, serv->socket, sizeof(inbuf), M_TEXT);
    if (sw < 0)	/* error, close it */
      return _irc_try_server (serv, NULL, 0, NULL);
    else if (sw == 0) /* check last input if ping timeout then try to ping it */
    {
      if (serv->state == L_CONNECTED && Time - serv->last_input > irc_timeout)
      {
	New_Request (iface, F_QUICK, "PING :%s", serv->mynick);
	serv->state = L_PINGSENT;
	reject = 1;
      }
    }
    else	/* congratulations, we get the input! */
    {
      dprint (4, "_irc_request: got from %s: \"%s\"", iface->name, inbuf);
#ifdef HAVE_ICONV
      p = sbuf;
      sbuf[sizeof(sbuf)-1] = 0; /* we may exceed sbuf? */
      sw = Do_Conversion (iface->conv, &p, sizeof(sbuf) - 1, inbuf, sw);
#else
      p = inbuf;
#endif
      if (serv->state == L_PINGSENT)
	serv->state = L_CONNECTED;
      serv->last_input = Time;
      params[0] = iface->name; /* network name (server id) */
      if (p[0] == ':')	/* there is a prefix */
      {
	prefix = params[1] = ++p; /* prefix, i.e. sender */
	while (*p && *p != ' ') p++;
	*p++ = 0;
      }
      else
	prefix = NULL;
      while (*p == ' ') p++;
      params[2] = p; /* command */
      while (*p && *p != ' ') p++;
      i = parse_ircparams (&params[3], NextWord (p));
      *p = 0;
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
	{
	  uh++;
	  if (irc_ignore_ident_prefix && (*uh == '~' || *uh == '^'))
	    *uh = '*';
	  uh = prefix;
	}
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
      while ((bind = Check_Bindtable (BT_Irc, params[2], -1, -1, bind)))
      {
	if (bind->name) /* cannot use RunBinding here! */
	  i = bind->func (bind->name, i+3, params);
	else
	  i = bind->func (iface, p, serv->mynick, uh, i, &params[3], serv->lc);
	if (i)
	  break;
      }
      if (serv->state <= L_INITIAL || serv->state >= L_QUIT)
	reject = 1;	/* bindings might reset connection */
    }
  }
  /* accept (any?) request if ready for it (SendQ checked by _irc_send) */
  if (!reject && req)
  {
    register char *cc;

    for (c = req->string, cc = serv->buf; *c &&
	 cc < &serv->buf[sizeof(serv->buf)-2]; c++)
    {
      if (*c == '\r' && c[1] == '\n')	/* already CR+LF pair so skip it */
	*cc++ = *c++;
      else if (*c == '\n')		/* only LF so convert to CR+LF */
	*cc++ = '\r';
      *cc++ = *c;			/* copy char */
    }
    if (cc != serv->buf && *(cc-1) != '\n')	/* didn't ended with CR+LF? */
    {
      *cc++ = '\r';			/* add CR+LF at end */
      *cc++ = '\n';
    }
    serv->inbuf = cc - serv->buf;
    serv->bufptr = 0;
    return 2;
  }
  else if (isregistered && !serv->inbuf && !req)	/* all sent already */
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
  return ((ircserver_t *)iface->data)->mynick;
}

void irc_lcs (char *buf, INTERFACE *pmsgout, const char *nick, size_t s)
{
  ircserver_t *serv = IrcServers;

  while (serv && serv->pmsgout != pmsgout)
    serv = serv->next;
  if (!serv || !serv->lc)
    strfcpy (buf, nick, s);
  else
    lc (buf, nick, s);
}


/* --- Bindings ------------------------------------------------------------- */

/*
 * "irc-raw" bindings:
 *   int func(INTERFACE *net, char *sv, char *me, char *src,
 *		int parc, char **parv, char *(*lc)(char *, const char *, size_t))
 *
 * note that src is NULL if message has no prefix or originatin from server
 * src is in form "server" or "nick"
 * host is in form "ident@host"
 * lc is used for server-specific lowercase conversion
 */
static int irc_ping (INTERFACE *net, char *sv, char *me, char *src,
		int parc, char **parv, char *(*lc)(char *, const char *, size_t))
{
// Parameters: server [server-to]
  if (parc > 1 && src)
    New_Request (net, F_QUICK, "PONG %s :%s", sv, src);
  else
    New_Request (net, F_QUICK, "PONG :%s", src ? src : sv);
  return -1;
}

/*
 * currently being ignored:
 * PONG ERR_USERSDONTMATCH ERR_NOTEXTTOSEND ERR_TOOMANYTARGETS ERR_NOORIGIN
 * ERR_NOSUCHSERVER queries opers channels motd
 *
 * ERR_ALREADYREGISTRED ERR_UMODEUNKNOWNFLAG RPL_UMODEIS ERR_NEEDMOREPARAMS
 * RPL_AWAY ERR_NORECIPIENT RPL_YOURHOST RPL_CREATED RPL_MYINFO RPL_TRYAGAIN
 * ERR_UNKNOWNCOMMAND ERROR
 */

/*
 * aborted registration, wants to change nick first:
 * ERR_ERRONEUSNICKNAME ERR_NICKNAMEINUSE ERR_UNAVAILRESOURCE ERR_NICKCOLLISION
 * ERR_NOTREGISTERED
 */
static int irc__nextnick (INTERFACE *net, char *sv, char *me, char *src,
		int parc, char **parv, char *(*lc)(char *, const char *, size_t))
{
// Parameters: current new text
  ircserver_t *serv = net->data;
  clrec_t *clr;

  dprint (3, "irc__nextnick: %s: nickname %s juped", net->name, serv->mynick);
  clr = Lock_Clientrecord (serv->pmsgout->name);
  if (clr)
  {
    _irc_try_nick (serv, clr);
    Unlock_Clientrecord (clr);
  }
  New_Request (net, 0, "NICK %s", serv->mynick);
  return 0;
}

static int irc_rpl_bounce (INTERFACE *net, char *sv, char *me, char *src,
		int parc, char **parv, char *(*lc)(char *, const char *, size_t))
{
// Parameters: host port text
  char newhost[HOSTLEN+7];

  if (parc != 3 || atoi(parv[1]) == 0)	/* some other format? */
    return 0;
  snprintf (newhost, sizeof(newhost), "%s:%s", parv[0], parv[1]);
  _irc_try_server ((ircserver_t *)net->data, newhost, 1, _("bounced"));
  return 1;
}

/*
 * cannot register at all, drop any further attempts for this server
 * ERR_NOPERMFORHOST ERR_PASSWDMISMATCH ERR_YOUREBANNEDCREEP
 */
static int irc__fatal (INTERFACE *net, char *sv, char *me, char *src,
		int parc, char **parv, char *(*lc)(char *, const char *, size_t))
{
// Parameters: text
  _irc_try_server ((ircserver_t *)net->data, NULL, 1, NULL);
  return 1;
}

/*
 * we got 001 (RPL_WELCOME) so connection is completed now
 */
static int irc_rpl_welcome (INTERFACE *net, char *sv, char *me, char *src,
		int parc, char **parv, char *(*lc)(char *, const char *, size_t))
{
// Parameters: nick text
  ircserver_t *serv = net->data;

  /* do all bindings */
  _irc_connected (serv);
  /* change state */
  strfcpy (serv->start, DateString, sizeof(serv->start));
  serv->state = L_CONNECTED;
  Add_Request (I_LOG, "*", F_CONN, _("Registered on %s."), net->name);
  return 0;
}

static int irc_rpl_myinfo (INTERFACE *net, char *sv, char *me, char *src,
		int parc, char **parv, char *(*lc)(char *, const char *, size_t))
{
// Parameters: srvname version umodes chanmodes
  if (parc != 4)
    return 0;
  ((ircserver_t *)net->data)->srvname = safe_strdup (parv[0]);
  return 1;
}

static size_t _irc_check_domain_part (char *domain)
{
  register char *l = domain, *c = domain;

  while (*l && *l != '.') c++;
  for (c = domain; c != l; c++)
  {
    if ((*c < 'a' || *c > 'z') && (*c < 'A' && *c > 'Z') && *l == 0)
      return 0;			/* last domain part must be [a-zA-Z]+ */
    if (*c != '-' && (*c < '0' || *c > '9'))
      return 0;			/* all previous may have [-0-9] also */
  }
  if (*c) c++;
  return (c - domain);
}

static int _irc_check_domain (char *domain)
{
  register size_t i;
  char *c = domain;	/* begin of last part */

  while (*domain)
  {
    i = _irc_check_domain_part (domain);
    if (i < 2)
      return 0;
    c = domain;
    domain += i;
  }
  if (c == domain)	/* less than 2 parts? */
    return 0;
  return 1;
}

static int irc_quit (INTERFACE *net, char *sv, char *me, char *src,
		int parc, char **parv, char *(*lc)(char *, const char *, size_t))
{
// Parameters: text
  if (parc != 1 || !src)
    return 0;
  if (strcasecmp (src, me)) /* it's not me */
  {
// Quit reason in netsplit: leftserver goneserver
    char *gone;
    char *lname;
    char target[HOSTMASKLEN+1];	/* assume it's not less than IFNAMEMAX+1 */
    userflag uf;
    int s;
    binding_t *bind;

    if ((gone = safe_strchr (src, '!'))) /* using *gone as temp char* var */
      *gone = 0;
    if (lc)
      lc (target, src, MBNAMEMAX+1);
    else
      strfcpy (target, src, MBNAMEMAX+1);
    irc_privmsgout_cancel (((ircserver_t *)net->data)->pmsgout, target);
    s = safe_strlen (target);
    strfcat (target, ((ircserver_t *)net->data)->pmsgout->name, sizeof(target));
    Add_Request (I_LOG, target, F_NOTICE | F_END, _("%s quits: %s"), src, parv[0]);
    if (gone)
    {
      *gone = '!';
      safe_strlower (&target[s], gone, sizeof(target) - s);
    }
    else
      target[s] = 0;
    lname = _irc_get_lname (target, &uf,
			    ((ircserver_t *)net->data)->pmsgout->name);
    gone = strchr (parv[0], ' ');
    if (gone)
      *gone = 0;
    if (gone && strcmp (&gone[1], parv[0]) &&
	_irc_check_domain (parv[0]) && _irc_check_domain (&gone[1]))
      s = 1;	/* netsplit message detected */
    else
      s = 0;	/* it was just a quit message... */
    if (gone)
      *gone = ' ';
    for (bind = NULL; (bind = Check_Bindtable (s ? BT_IrcNSplit : BT_IrcSignoff,
						target, uf, -1, bind)); )
      if (!bind->name)
	bind->func (net, lname, src, target, parv[0]);
    FREE (&lname);
  }
  else		/* someone killed me? */
    _irc_try_server ((ircserver_t *)net->data, NULL, 0, NULL);
  return 0;
}

static int irc_error (INTERFACE *net, char *sv, char *me, char *src,
		int parc, char **parv, char *(*lc)(char *, const char *, size_t))
{
// Parameters: text
  _irc_try_server ((ircserver_t *)net->data, NULL, 0, parv[0]);
  return 0;
}

static int irc_kill (INTERFACE *net, char *sv, char *me, char *src,
		int parc, char **parv, char *(*lc)(char *, const char *, size_t))
{
// Parameters: nick text
  if (parc != 2)
    return 0;
  if (!strcasecmp (parv[0], me))
    _irc_try_server ((ircserver_t *)net->data, NULL, 0, _("killed"));
  else		/* it must be some bug! */
    irc_privmsgout_cancel (((ircserver_t *)net->data)->pmsgout, parv[0]);
  return 0;
}

static int irc_privmsg (INTERFACE *net, char *sv, char *me, char *src,
		int parc, char **parv, char *(*lc)(char *, const char *, size_t))
{
// Parameters: nick text
  if (parc != 2 || !src)
    return 0;	/* bad number of parameters so ignore it */
  return irc_privmsgin (((ircserver_t *)net->data)->pmsgout, src, parv[0],
			parv[1], 0, irc_privmsg_commands, irc_pmsg_keep, lc);
}

static int irc_err_nosuchnick (INTERFACE *net, char *sv, char *me, char *src,
		int parc, char **parv, char *(*lc)(char *, const char *, size_t))
{
// Parameters: nick text
  char f[IFNAMEMAX+1];

  if (parc != 2)
    return 0;
  if (lc)
    lc (f, parv[0], sizeof(f));
  else
    strfcpy (f, parv[0], sizeof(f));
  if (strcmp (me, f))
  {
    irc_privmsgout_cancel (((ircserver_t *)net->data)->pmsgout, f);
    strfcat (f, ((ircserver_t *)net->data)->pmsgout->name, sizeof(f));
    Add_Request (I_LOG, f, F_PRIV | F_END, _("*** no such nick %s"), parv[0]);
  }
  /* else bug */
  return 0;
}

static int irc_notice (INTERFACE *net, char *sv, char *me, char *src,
		int parc, char **parv, char *(*lc)(char *, const char *, size_t))
{
// Parameters: nick text
  if (parc != 2 || !src)
    return 0;	/* bad number of parameters so ignore it */
  return irc_privmsgin (((ircserver_t *)net->data)->pmsgout, src, parv[0],
			parv[1], 1, irc_privmsg_commands, irc_pmsg_keep, lc);
}

/*
 * may be it's my nick was changed?
 */
static int irc_nick (INTERFACE *net, char *sv, char *me, char *src,
		int parc, char **parv, char *(*lc)(char *, const char *, size_t))
{
// Parameters: newnick
  ircserver_t *serv;
  char oldnick[IFNAMEMAX+1];
  char newnick[HOSTMASKLEN+1];
  size_t s, s2;
  char *lname;
  userflag uf;
  binding_t *bind;

  /* test if it's me */
  if (!src || parc != 1)
    return 0;
  if ((lname = strchr (src, '!')))
    *lname = 0;
  if (lc)
  {
    lc (oldnick, src, sizeof(oldnick));
    lc (newnick, parv[0], MBNAMEMAX+1);
  }
  else
  {
    strfcpy (oldnick, src, sizeof(oldnick));
    strfcpy (newnick, parv[0], MBNAMEMAX+1);
  }
  if (lname)
    *lname = '!';
  serv = net->data;
  if (strcmp (oldnick, serv->lcnick))
  {
    s = strlen (newnick);
    safe_strlower (&newnick[s], lname, sizeof(newnick) - s);
    lname = _irc_get_lname (newnick, &uf, serv->pmsgout->name);
    newnick[s] = 0;
    /* it isn't me so rename I_CLIENT interface */
    s2 = strlen (oldnick);
    strfcat (oldnick, serv->pmsgout->name, sizeof(oldnick));
    strfcat (newnick, serv->pmsgout->name, sizeof(newnick));
    Rename_Iface (I_CLIENT, oldnick, newnick);
    newnick[s] = 0;
    oldnick[s2] = 0;
  }
  else
  {
    /* it's me so change local data */
    dprint (3, "irc_nick: %s: my nickname changed %s -> %s", net->name,
	    me, parv[0]);
    FREE (&serv->mynick);
    serv->mynick = safe_strdup (parv[0]);
    FREE (&serv->lcnick);
    serv->lcnick = safe_strdup (newnick);
    lname = NULL;
    uf = -1;
  }
  /* call all internal bindings */
  for (bind = NULL; (bind = Check_Bindtable (BT_IrcNChg, newnick, uf, -1, bind)); )
    if (!bind->name)
      bind->func (net, lname, src, oldnick, parv[0], newnick);
  FREE (&lname);
  return 1;
}

static void _set_isupport_num (char *value, size_t s, size_t *i,
			       char *name, size_t nl, int x)
{
  if (*i)
    nl++;
  s -= *i;
  value += *i;
  if (x == 0 || s >= nl + 7)		/* name=xxxxxx */
    return;				/* OOPS! */
  snprintf (value, s, "%s%s=%d", *i ? " " : "", name, x);
  *i += strlen (value);
}

static void _set_isupport_string (char *value, size_t s, size_t *i,
				  char *name, size_t nl, char *x)
{
  register size_t l = strlen (x);

  if (*i)
    nl++;
  s -= *i;
  value += *i;
  if (l == 0 || s >= nl + l + 1)	/* name=string */
    return;				/* OOPS! */
  snprintf (value, s, "%s%s=%s", *i ? " " : "", name, x);
  *i += strlen (value);
}

static int irc_rpl_isupport (INTERFACE *net, char *sv, char *me, char *src,
		int parc, char **parv, char (*ilc)(char *, const char *, size_t))
{
// Parameters: mynick param=value ... "are supported by this server"
  char *c, *cs, *cf, *cv;
  size_t i;
  int nicklen, topiclen, maxbans, maxchannels, modes, maxtargets;
  char *(*lc) (char *, const char *, size_t);
  clrec_t *clr;
  char chanmodes[SHORT_STRING];
  char prefix[32];
  char value[LONG_STRING];

  dprint (3, "irc_rpl_isupport: %d params, first one is %s.", parc-2, parv[1]);
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
  nicklen = topiclen = maxbans = maxchannels = modes = maxtargets = 0;
  lc = &rfc2812_strlower; /* assume it's default for me */
  value[0] = '@';
  strfcpy (&value[1], net->name, sizeof(value) - 1);
  clr = Lock_Clientrecord (value);
  if (!clr)
    return 0;		/* it's impossible */
  cs = c = Get_Field (clr, IRCPAR_FIELD, NULL);
  while (c)
  {
    cv = strchr (c, '=');
    cf = c;
    if (cv)
      c = strchr (cv++, ' ');
    else
      c = NULL;
    if (c) *c = 0;
    if (cv)
    {
      if (!strcmp (cf, IRCPAR_NICKLEN))
	nicklen = atoi (cv);
      else if (!strcmp (cf, IRCPAR_TOPICLEN))
	topiclen = atoi (cv);
      else if (!strcmp (cf, IRCPAR_MAXBANS))
	maxbans = atoi (cv);
      else if (!strcmp (cf, IRCPAR_CHANNELS))
	maxchannels = atoi (cv);
      else if (!strcmp (cf, IRCPAR_MODES))
	modes = atoi (cv);
      else if (!strcmp (cf, IRCPAR_TARGETS))
	maxtargets = atoi (cv);
      else if (!strcmp (cf, IRCPAR_PREFIX))
	strfcpy (prefix, cv, sizeof(prefix));
      else if (!strcmp (cf, IRCPAR_CHANMODES))
	strfcpy (chanmodes, cv, sizeof(chanmodes));
      else if (!strcmp (cf, IRCPAR_CASEMAPPING))
      {
	if (!strcasecmp (cv, "none"))
	  lc = NULL;
	else if (!strcasecmp (cv, "ascii"))
	  lc = &irc_ascii_strlower;
	else if (!strcasecmp (cv, "rfc1459"))
	  lc = &irc_rfc1459_strlower;
	else
	  lc = &rfc2812_strlower;
      }
    }
    if (c) *c++ = ' ';
  }
  for (i = 0; i < parc - 1; i++)
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
    else if (!strcmp (parv[i], IRCPAR_CASEMAPPING))
    {
      if (!strcasecmp (cv, "none"))
	lc = NULL;
      else if (!strcasecmp (cv, "ascii"))
	lc = &irc_ascii_strlower;
      else if (!strcasecmp (cv, "rfc1459"))
	lc = &irc_rfc1459_strlower;
      else /* assume any other are locale dependent */
	lc = &rfc2812_strlower;
    }
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
  if (lc == NULL)
    _set_isupport (IRCPAR_CASEMAPPING, "none");
  else if (lc == &irc_ascii_strlower)
    _set_isupport (IRCPAR_CASEMAPPING, "ascii");
  else if (lc == &irc_rfc1459_strlower)
    _set_isupport (IRCPAR_CASEMAPPING, "rfc1459");
#undef _set_isupport
  value[i] = 0;
  if (strcmp (cs, value))
    Set_Field (clr, IRCPAR_FIELD, value);
  Unlock_Clientrecord (clr);
  ((ircserver_t *)net->data)->lc = lc;
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
static int connect_irc (const char *link, char *args)
{
  ircserver_t *serv;

  /* check parameters */
  if (args && !*args)
    args = NULL;
  /* check if such service already exists */
  if ((Find_Iface (I_SERVICE, link)))
    return Unset_Iface();
  /* create new server interface and add it to list */
  if (IrcServers == NULL)
    IrcServers = serv = safe_calloc (1, sizeof(ircserver_t));
  else
  {
    for (serv = IrcServers; serv->next; serv = serv->next);
    serv->next = safe_calloc (1, sizeof(ircserver_t));
    serv->next->prev = serv;
    serv = serv->next;
  }
  serv->socket = -1;
  serv->iface = Add_Iface (link, I_SERVICE | I_CONNECT, &_irc_signal,
			   &_irc_request, serv);
  return _irc_try_server (serv, args, -1, NULL); /* shedule a connection */
}


/*
 * "irc-connected" bindings
 *   (int)void func (INTERFACE *iface, char *server, char *nick, char *(*lc) (char *, const char *, size_t))
 */
/* internal one is to set umode and send on-login commands */
static void ic_default (INTERFACE *iface, char *server, char *nick,
			char *(*lc) (char *, const char *, size_t))
{
  clrec_t *clr;
  char *msg;

  if (*irc_umode != 0)
    New_Request (iface, 0, "MODE %s :%s", nick, irc_umode);
  clr = Lock_Clientrecord (((ircserver_t *)iface->data)->pmsgout->name);
  if (clr)
  {
    msg = Get_Field (clr, "umode", NULL);
    dprint (3, "ic_default: sending default commands for %s...", iface->name);
    if (msg)
      New_Request (iface, 0, "MODE %s :%s", nick, msg);
    msg = Get_Field (clr, ".login", NULL);
    if (msg)
      New_Request (iface, 0, "%s", msg);
    Unlock_Clientrecord (clr);
  }
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
  RegisterInteger ("irc-default-port", &defaultport);
  RegisterInteger ("irc-max-penalty", &maxpenalty);
  RegisterInteger ("irc-privmsg-keep", &irc_pmsg_keep);
  RegisterString ("irc-default-nick", irc_default_nick, sizeof(irc_default_nick), 0);
  RegisterString ("irc-default-ident", irc_default_ident, sizeof(irc_default_ident), 0);
  RegisterString ("irc-default-realname", irc_default_realname, sizeof(irc_default_realname), 0);
  RegisterString ("irc-umode", irc_umode, sizeof(irc_umode), 0);
  RegisterBoolean ("irc-privmsg-commands", &irc_privmsg_commands);
  RegisterBoolean ("irc-ignore-ident-prefix", &irc_ignore_ident_prefix);
}

/*
 * this function must receive signals:
 *  S_TERMINATE - unload module,
 *  S_REPORT - out state info to log,
 *  S_REG - [re]register all.
 */
static int module_irc_signal (INTERFACE *iface, ifsig_t sig)
{
  ircserver_t *serv;
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
      UnregisterVariable ("irc-default-port");
      UnregisterVariable ("irc-max-penalty");
      UnregisterVariable ("irc-privmsg-keep");
      UnregisterVariable ("irc-default-nick");
      UnregisterVariable ("irc-default-ident");
      UnregisterVariable ("irc-default-realname");
      UnregisterVariable ("irc-umode");
      UnregisterVariable ("irc-privmsg-commands");
      UnregisterVariable ("irc-ignore-ident-prefix");
      Delete_Binding ("irc-raw", &irc_ping);
//      Delete_Binding ("ERROR", irc__2log);
      Delete_Binding ("irc-raw", &irc_quit);
      Delete_Binding ("irc-raw", &irc_error);
      Delete_Binding ("irc-raw", &irc_kill);
      Delete_Binding ("irc-raw", &irc_privmsg);
      Delete_Binding ("irc-raw", &irc_notice);
      Delete_Binding ("irc-raw", &irc_nick);
      Delete_Binding ("irc-raw", &irc_rpl_welcome);
      Delete_Binding ("irc-raw", &irc_rpl_myinfo);
      Delete_Binding ("irc-raw", &irc_rpl_isupport);
      Delete_Binding ("irc-raw", &irc_rpl_bounce);
      Delete_Binding ("irc-raw", &irc_err_nosuchnick);
      Delete_Binding ("irc-raw", &irc__nextnick);
      Delete_Binding ("irc-raw", &irc__fatal);
      Delete_Binding ("irc-connected", (Function)&ic_default);
      Delete_Binding ("connect", &connect_irc);
      irc_privmsgunreg();
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
	  _irc_signal (serv->iface, S_TERMINATE);
	/* kill all server connections */
	/* TODO: check for timeout here or interface will do that itself? */
	while (IrcServers != NULL)
	  for (serv = IrcServers; serv; )
	  {
	    Set_Iface (serv->iface);
	    serv = serv->next;	/* choose it now since it may die later */
	    Get_Request();	/* in this state it may only send data */
	    Unset_Iface();
	  }
      }
      iface->ift |= I_DIED;
      break;
    case S_REG:
      module_irc_regall();
      break;
    case S_FLUSH:
      /* check for autoconnects in listfile */
      tmp = Add_Iface (NULL, I_TEMP, NULL, &_irc_servlist, NULL);
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
	if ((Get_Clientflags (c, NULL) & U_AUTO) &&	/* autoconnect found */
	    (!Find_Iface (I_SERVICE, &c[1]) || Unset_Iface()))
	  connect_irc (&c[1], NULL);			/* shedule a connection */
      }
      tmp->ift = I_DIED;
      break;
    case S_REPORT:
      tmp = Set_Iface (iface);
      New_Request (tmp, F_REPORT, "Module irc: %s",
		   IrcServers ? "connected to servers:" : "no servers connected.");
      for (serv = IrcServers; serv; serv = serv->next)
	New_Request (tmp, F_REPORT, "   network %s: server %s, my nick %s, pmsgout interfaces %d",
		     serv->iface->name, SocketDomain (serv->socket, NULL),
		     serv->mynick, irc_privmsgout_count (serv->pmsgout));
      Unset_Iface();
    default:
      break;
  }
  return 0;
}

static void _irc_init_bindings (void)
{
#define NB(a,b) Add_Binding ("irc-raw", a, 0, 0, &b)
  NB ("PING", irc_ping);
  NB ("ERROR", irc_error);
  NB ("QUIT", irc_quit);
  NB ("KILL", irc_kill);
  NB ("PRIVMSG", irc_privmsg);
  NB ("NOTICE", irc_notice);
  NB ("NICK", irc_nick);
  NB ("001", irc_rpl_welcome);
//  NB ("002", irc__2log);
//  NB ("003", irc__2log);
  NB ("004", irc_rpl_myinfo);
  NB ("005", irc_rpl_isupport);
  NB ("010", irc_rpl_bounce);
//  NB ("221", irc__2log);
//  NB ("263", irc__2log);
//  NB ("301", irc__2log);
  NB ("401", irc_err_nosuchnick);
//  NB ("411", irc__2log);
//  NB ("421", irc__2log);
  NB ("432", irc__nextnick);
  NB ("433", irc__nextnick);
  NB ("436", irc__nextnick);
  NB ("437", irc__nextnick);
  NB ("451", irc__nextnick);
//  NB ("461", irc__2log);
//  NB ("462", irc__2log);
  NB ("463", irc__fatal);
  NB ("464", irc__fatal);
  NB ("465", irc__fatal);
//  NB ("501", irc__2log);
#undef NB
}

/*
 * this function called when you load a module.
 * Input: parameters string args - nothing.
 * Returns: address of signals receiver function, NULL if not loaded.
 */
Function ModuleInit (char *args)
{
  struct passwd *pwd;
  register char *c;
  register int i;

  /* init all stuff */
  BT_Irc = Add_Bindtable ("irc-raw", B_MATCHCASE);
  _irc_init_bindings();
  BT_IrcConn = Add_Bindtable ("irc-connected", B_MASK);
  Add_Binding ("irc-connected", "*", 0, 0, (Function)&ic_default);
  BT_IrcDisc = Add_Bindtable ("irc-disconnected", B_MASK);
  Add_Binding ("connect", "irc", U_SPECIAL, -1, &connect_irc); /* no channels */
  BT_IrcNChg = Add_Bindtable ("irc-nickchg", B_MATCHCASE); /* always lowercase */
  BT_IrcSignoff = Add_Bindtable ("irc-signoff", B_MATCHCASE); /* the same */
  BT_IrcNSplit = Add_Bindtable ("irc-netsplit", B_MATCHCASE); /* the same */
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
  /* set up variables and get login and full name */
  pwd = getpwuid (getuid());
  strfcpy (irc_default_nick, Nick, sizeof(irc_default_nick));
  strfcpy (irc_default_ident, pwd->pw_name, sizeof(irc_default_ident));
  strfcpy (irc_default_realname, pwd->pw_gecos, sizeof(irc_default_realname));
  if ((c = strchr (irc_default_realname, ',')))		/* strip other info */
    *c = 0;
  module_irc_regall();
  /* shedule check for autoconnects since listfile may be not loaded yet */
  NewTimer (I_MODULE, "irc", S_FLUSH, 1, 0, 0, 0);
  return (&module_irc_signal);
}
