/*
 * Copyright (C) 1999-2002  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 * This file contains main DCC interface.  Bindtables: passwd dcc upload
 *              login chat out-filter in-filter chat-on chat-off chat-join
 *              chat-part
 * CTCP CHAT and CTCP DCC handled here for reasons don't duplicate listen
 *		port code and include Dcc_Send() in main API
 */

#include "foxeye.h"
#include <fcntl.h>
#include <errno.h>
#include <netinet/in.h>
#include <netdb.h>

#ifdef HAVE_CRYPT_H
# include <crypt.h>
#endif

#include "dcc.h"
#include "init.h"
#include "socket.h"
#include "sheduler.h"
#include "wtmp.h"

static BINDTABLE *BT_Crypt;
static BINDTABLE *BT_Dcc;
static BINDTABLE *BT_Chat;
static BINDTABLE *BT_Chatact;
static BINDTABLE *BT_Outfilter;
static BINDTABLE *BT_Infilter;
static BINDTABLE *BT_Login;
static BINDTABLE *BT_Chaton;
static BINDTABLE *BT_Chatoff;
static BINDTABLE *BT_Chatjoin;
static BINDTABLE *BT_Chatpart;
static BINDTABLE *BT_Upload;

static uint32_t ip_local;		/* my IP in host byte order */

static char _userdccflag (userflag uf)
{
  register char ch = ' ';

  if (uf & U_OWNER)
    ch = '*';
  else if (uf & U_MASTER)
    ch = '+';
  else if (uf & U_HALFOP)
    ch = '%';
  else if (uf & U_OP)
    ch = '@';
  return ch;
}

int Get_DccIdx (DCC_SESSION *dcc)
{
  return (dcc->socket + 1);
}

void Chat_Join (DCC_SESSION *dcc)
{
  register BINDING *bind = NULL;
  char *on_bot;
  char l[STRING];
  char ch[16];
  char *name = NULL;

  /* what??? */
  if (!dcc || !dcc->iface)
    return;
  name = dcc->iface->name;
  on_bot = safe_strchr (NONULL(name), '@');
  if (!on_bot)
    on_bot = Nick;
  else
    on_bot++;
  snprintf (ch, sizeof(ch), ":*:%d", dcc->botnet);
  dprint (4, "dcc:Chat_Join: %s@%s joining %d", name, on_bot, dcc->botnet);
  Set_Iface (dcc->iface);
  /* run bindtable */
  snprintf (l, sizeof(l), "%c %d %s", _userdccflag (dcc->uf), Get_DccIdx (dcc),
	    SocketDomain (dcc->socket, NULL));
  do
  {
    if ((bind = Check_Bindtable (BT_Chatjoin, &ch[3], -1, -1, bind)))
    {
      if (bind->name)
        RunBinding (bind, NULL, on_bot, name, dcc->botnet, l);
      else
        bind->func (name, on_bot, dcc);
    }
  } while (bind);
  /* notify the botnet! */
  Add_Request (I_DCCALIAS, ch, F_NOTICE, _("joined this botnet channel."));
  Unset_Iface();
  /* start getting the messages */
  if (dcc->alias)
  {
    if (dcc->socket >= 0)
      snprintf (ch, sizeof(ch), ":%d:%d", Get_DccIdx (dcc), dcc->botnet);
    else				/* for console interfcae */
      snprintf (ch, sizeof(ch), "::%d", dcc->botnet);
    FREE (&dcc->alias->name);
    dcc->alias->name = safe_strdup (ch);
  }
}

void Chat_Part (DCC_SESSION *dcc)
{
  register BINDING *bind = NULL;
  char *on_bot;
  char ch[16];
  char *name = NULL;

  /* what??? */
  if (!dcc || !dcc->iface)
    return;
  name = dcc->iface->name;
  on_bot = safe_strchr (NONULL(name), '@');
  if (!on_bot)
    on_bot = Nick;
  else
    on_bot++;
  dprint (4, "dcc:Chat_Part: %s@%s parting %d", name, on_bot, dcc->botnet);
  /* stop getting the messages */
  if (dcc->alias && dcc->socket >= 0)	/* don't rename console interface */
  {
    snprintf (ch, sizeof(ch), ":%d", Get_DccIdx (dcc));
    FREE (&dcc->alias->name);
    dcc->alias->name = safe_strdup (ch);
  }
  snprintf (ch, sizeof(ch), ":*:%d", dcc->botnet);
  /* notify the botnet! */
  Set_Iface (dcc->iface);
  /* if quit - send the formed notice */
  if (dcc->state == D_OK)
    Add_Request (I_DCCALIAS, ch, F_NOTICE, _("quit botnet: %s"), name,
		 dcc->buf[0] ? dcc->buf : _("no reason."));
  else
    Add_Request (I_DCCALIAS, ch, F_NOTICE, _("left this botnet channel."));
  /* run bindtable */
  do
  {
    if ((bind = Check_Bindtable (BT_Chatpart, &ch[3], -1, -1, bind)))
    {
      if (bind->name)
        RunBinding (bind, NULL, on_bot, name, Get_DccIdx (dcc), &ch[3]);
      else
        bind->func (name, on_bot, dcc);
    }
  } while (bind);
  Unset_Iface();
}

static char _Flags[] = FLAG_T;

/*
 * Set console state from saved value: "loglevel IRCchannel BotChannel"
 */
void setdccconsole (DCC_SESSION *dcc, char *line)
{
  register flag_t logl = F_COLOR;	/* color mirc by default */
#if 1
  flag_t maskfl = (F_JOIN | F_MODES | F_ECHO | F_COLOR | F_COLORCONV);
#else
  flag_t maskfl = -1;
#endif
  register char *fl;
  unsigned int botch;
  char chan[IFNAMEMAX+1];
  userflag cf;

  /* return if arguments are invalid */
  if (!line || sscanf (line, "%*s %s %u", chan, &botch) != 2)
    return;
  cf = Get_ChanFlags (dcc->iface->name, chan);
#if 1
  if (dcc->uf & U_OWNER)
    maskfl |= (F_BOOT | F_DEBUG);
  if ((dcc->uf & U_MASTER) || (cf & U_MASTER))
    maskfl |= (F_CMDS | F_USERS | F_CRAP);
  if ((dcc->uf & U_OP) || (cf & U_OP))
    maskfl |= (F_CONN | F_PUBLIC | F_WALL | F_MSGS | F_SERV);
#else
  if (!(dcc->uf & U_OWNER))
    maskfl &= ~(F_BOOT | F_DEBUG);
  if (!(dcc->uf & U_MASTER) && !(cf & U_MASTER))
    maskfl &= ~(F_CMDS | F_USERS | F_CRAP);
  if (!(dcc->uf & U_OP) && !(cf & U_OP))
    maskfl &= ~(F_CONN | F_PUBLIC | F_WALL | F_MSGS | F_SERV);
#endif
  /* get flags from line */
  while (*line && *line != ' ')
  {
    switch (*line)
    {
      case '+':
	logl |= F_ECHO;
	break;
      case '%':
	logl |= (F_COLORCONV | F_COLOR);
	break;
      case '#':
	logl |= F_COLORCONV;
	logl &= ~F_COLOR;
	break;
      case '$':
        logl &= ~(F_COLOR | F_COLORCONV);
	break;
      default:
        if ((fl = safe_strchr (_Flags, *line)))
	  logl |= 1<<(fl-_Flags);
    }
    line++;
  }
  logl &= maskfl;
  if ((logl & F_DEBUG) && O_DLEVEL > 3)
  {
    New_Request (dcc->iface, F_NOTICE,
	    "Debug level is too high for DCC CHAT, switching debug log off");
    logl &= ~F_DEBUG;
  }
  /* set DCC session console parameters */
  dcc->botnet = botch;
  if (dcc->log)
  {
    FREE (&dcc->log->name);
    dcc->log->name = safe_strdup (chan);
  }
  dcc->loglev = logl;
}

static char *getdccconsole (DCC_SESSION *dcc, char *str, size_t sz)
{
  register int i;
  register char *s = str;
  register flag_t f = 1;

  sz -= 3;
  if (dcc->loglev & F_ECHO)
    *s++ = '+';
  else
    sz++;
  if (!(dcc->loglev & F_COLOR))
  {
    if (dcc->loglev & F_COLORCONV)
      *s++ = '#';
    else
      *s++ = '$';
  }
  else if (dcc->loglev & F_COLORCONV)
    *s++  = '%';
  else
    sz++;
  for (i = 0; _Flags[i] && sz > 1; i++, f += f)
    if (dcc->loglev & f)
    {
      *s++ = _Flags[i];
      sz--;
    }
  *s = 0;
  return str;
}

static short *flood_dcc;

static pthread_mutex_t SessionsLock = PTHREAD_MUTEX_INITIALIZER;
static int Sessions = 0;

static REQUEST ReqTemplate;
#define ReqString ReqTemplate.string

static void _died_iface (INTERFACE *iface, int quiet)
{
  BINDING *bind = NULL;
  DCC_SESSION *dcc = (DCC_SESSION *)iface->data;
  userflag cf = 0;

  /* it already killed! */
  if (!dcc || dcc->socket == -1)
    return;
  iface = dcc->iface;
  /* .quit may set message to dcc->buf */
  if (!(iface->iface & I_DIED))
    dcc->buf[0] = 0;
  iface->iface |= I_DIED;
  iface->iface &= ~I_CHAT;
  pthread_mutex_lock (&SessionsLock);
  Sessions--;
  pthread_mutex_unlock (&SessionsLock);
  /* hmmm, this is nested? */
  if (!quiet && iface->prev)
  {
    iface->data = NULL;			/* to avoid erase dcc session */
    Chat_Part (dcc);
    dcc->iface = iface->prev;
    if (iface->IFSignal)
      iface->prev->IFSignal (iface->prev, S_CONTINUE);
    ReqString[0] = 0;
    return;
  }
  dprint (4, "dcc:_died_iface: %s", iface->name);
  /* %L - login nick, %@ - hostname */
  printl (ReqString, MESSAGEMAX, format_dcc_lost, 0, NULL,
	  SocketDomain (dcc->socket, NULL), iface->name, NULL, 0, 0, NULL);
  /* kill the socket */
  KillSocket (&dcc->socket);
  /* is this shutdown call? */
  if (quiet)
    return;
  /* disable timers */
  NoCheckFlood (&dcc->floodcnt);
  /* down log interface */
  if (dcc->log)
  {
    cf = Get_ChanFlags (iface->name, dcc->log->name);
    dcc->log->data = NULL;
    dcc->log->iface |= I_DIED;
  }
  /* kill the script alias for iface */
  if (dcc->alias)
  {
    dcc->alias->data = NULL;
    dcc->alias->iface |= I_DIED;
  }
  ReqTemplate.mask_if = I_DIED | I_LOG;
  ReqTemplate.mask[0] = '*';
  ReqTemplate.mask[1] = 0;
  ReqTemplate.flag = F_CONN;
  /* if it was not DCC CHAT */
  if (dcc->state == D_LOGIN || (iface->iface & I_DCC))
    return;
  /* log to Wtmp */
  NewEvent (W_END, iface->name, NULL, 0);
  /* now run "chat-part" and "chat-off" bindings... */
  dcc->state = D_OK;
  Chat_Part (dcc);
  do
  {
    if ((bind = Check_Bindtable (BT_Chatoff, iface->name, dcc->uf, cf, bind)))
    {
      if (bind->name)
        RunBinding (bind, NULL, iface->name, NULL, Get_DccIdx (dcc), NULL);
      else
        bind->func (dcc);
    }
  } while (bind);
}

/*static void _log_conn (char *msg)
{
  Add_Request (I_LOG, "*", F_CONN, msg);
}*/

#define _log_conn(a) Add_Request (I_LOG, "*", F_CONN, a)

/* predefined templates */
static REQUEST *dcc_request (INTERFACE *, REQUEST *);
static iface_t dcc_signal (INTERFACE *, ifsig_t);
static iface_t dcclog_signal (INTERFACE *, ifsig_t);

int Check_Passwd (const char *pass, char *encrypted)
{
  char *upass = NULL;
  BINDING *bind = Check_Bindtable (BT_Crypt, encrypted, -1, -1, NULL);

  if (bind && !bind->name)
  {
    upass = encrypted;
    bind->func (pass, &upass);
  }
  return safe_strcmp (encrypted, upass);
}

static char *_dcc_login (DCC_SESSION *dcc, char *name)
{
  ssize_t get;
  void *user;
  char *upass;
  BINDING *bind;
  userflag cf = 0;

  if (Time - dcc->timestamp > dcc_timeout)
    return _("login timeout");
  /* no echo now! */
  get = ReadSocket (dcc->buf, dcc->socket, sizeof(dcc->buf), M_NORM);
  if (get == 0 || get == E_AGAIN)
    return NULL;
  else if (get < 0)
    return _("connection lost");
  if ((dcc->iface->iface & I_TELNET) && !safe_strncmp (dcc->buf, "\377\375\001", 3))
    get = 3;
  else
    get = 0;
  user = Lock_User (name);
  if (!user)
    return _("OOPS! No such user");	/* user was deleted? */
  if (!(upass = Get_Userfield (user, "passwd")))
  {
    Unlock_User (user);
    return _("user has no password yet");
  }
  get = Check_Passwd (&dcc->buf[get], upass);
  Unlock_User (user);
  *dcc->buf = 0;
  if (get)
    return _("authentication failed");	/* password does not match */
  dprint (4, "dcc login auth OK: user %s, flags 0x%x", dcc->iface->name, dcc->uf);
  dcc->state = D_CHAT;
  /* create nonamed log interface - it will set later, they are
     different because Lname and #channel console name are different */
  if (!dcc->log)
    dcc->log = Add_Iface (NULL, I_LOG, &dcclog_signal, &dcc_request,
			  (void *)dcc);
  user = Lock_User (name);
  upass = Get_Userfield (user, "");
  Unlock_User (user);
  setdccconsole (dcc, upass);
  dcc->log->iface &= ~I_LOCKED;
  /* update timestamp */
  dcc->timestamp = Time;
  strfcpy (dcc->start, DateString, sizeof(dcc->start));
  if (dcc->log)
    cf = Get_ChanFlags (name, dcc->log->name);
  /* run "chat-on" and "chat-join" bindings... */
  bind = NULL;
  if (!dcc->iface->prev) do
  {
    if ((bind = Check_Bindtable (BT_Chaton, name, dcc->uf, cf, bind)))
    {
      if (bind->name)
	RunBinding (bind, NULL, name, NULL, Get_DccIdx (dcc), NULL);
      else
	bind->func (dcc);
    }
  } while (bind);
  Chat_Join (dcc);
  dcc->cmdbind = BT_Dcc;
  Add_Request (I_LOG, "*", F_CONN, _("Logged in: %s."), name);
  return NULL;
}

static int _is_report (char *str, size_t sz)
{
  while (str && *str)
  {
    if (*str < '\027' || *str > '\036')	/* range for reports */
      return 0;
    if (!(str = safe_strchr (str, '\001'))) /* malformed report! */
      return 0;
    str++;
  }
  return 1;
}

static char *_report_line (char *line, size_t sz, char ch)
{
  char *c, *cc;

  if ((c = (char *)memchr (line, ch, sz)))
  {
    if ((cc = safe_strchr (c, '\001')))
      *cc = 0;
    return &c[1];
  }
  return "";
}

#define __string_of_num(a) __string_arg(a)
#define __string_arg(a) #a
#define LNAMELS __string_of_num (LNAMELEN)

static REQUEST *_do_report (REQUEST *req, DCC_SESSION *dcc)
{
  register char *s = req->string;
  register size_t sz = safe_strlen (req->string);
  char fmt[SHORT_STRING];
  char times[16];		/* at_time idle_time */
  char *away;
  register int in_chat = 0;
  unsigned int ubotnet = 0;
  char *ch;

  if (!(req->from->iface & (I_CHAT | I_LISTEN | I_BOT | I_DCCALIAS)) ||
      !(req->flag & F_REPORT) || !_is_report (s, sz))
    return req;
  dprint (5, "dcc:_do_report: %s", s);
  /* attempt to get botnet and away message from report */
  away = _report_line (s, sz, '\036');
  if (!safe_strncmp (away, "chat:", 5))
  {
    away = NextWord (away);
    if (*away >= '0' && *away <= '9')
    {
      ubotnet = atoi (away);
      in_chat++;
    }
  }
  away = _report_line (s, sz, '\034');
  switch (dcc->state)
  {
    case D_R_WHO:
    case D_R_WHO1:
    case D_R_WHO2:
      if ((ch = safe_strchr (_report_line (s, sz, '\030'), ':')))
	*ch = 0;
      /* first section: local people on this channel: */
      if ((req->from->iface & I_DCCALIAS) && in_chat && ubotnet == dcc->botnet)
      {
	snprintf (fmt, sizeof(fmt), "%%c%%-" LNAMELS "s %%s%s (idle %%s)%s%%s",
		  (dcc->uf & U_MASTER) ? " (con:%s)" : "%s",
		  away[1] ? "\n  is away: " : "");
	snprintf (ReqString, sizeof(ReqString), fmt, away[0],
		  ((DCC_SESSION *)req->from->data)->iface->name,
		  _report_line (s, sz, '\030'),
		  (dcc->uf & U_MASTER) ? _report_line (s, sz, '\031') : "",
		  _report_line (s, sz, '\032'), &away[1]);
      }
      /* second section: connected bots */
      else if (req->from->iface & I_BOT)
      {
	snprintf (ReqString, sizeof(ReqString),
		  "%s %" LNAMELS "s %s (connected %s) %s",
		  dcc->state == D_R_WHO1 ? "" : _("Connected bots:\n"),
		  req->from->name, _report_line (s, sz, '\036'),
		  _report_line (s, sz, '\032'), _report_line (s, sz, '\035'));
	dcc->state = D_R_WHO1;
      }
      /* third section: other local people */
      else if ((req->from->iface & I_CHAT) &&
	       !safe_strchr (req->from->name, '@') &&
	       (!in_chat || ubotnet != dcc->botnet))
      {
	snprintf (fmt, sizeof(fmt), "%s%%c%%-" LNAMELS "s %%s%s (idle %%s)%s%%s",
		  dcc->state == D_R_WHO2 ? "" : _("Other people on the bot or on the botnet:\n"),
		  (dcc->uf & U_MASTER) ? " (con:%s) %s" : "%s%s",
		  away[1] ? "\n  is away: " : "");
	snprintf (ReqString, sizeof(ReqString), fmt, away[0], req->from->name,
		  _report_line (s, sz, '\030'),
		  (dcc->uf & U_MASTER) ? _report_line (s, sz, '\031') : "",
		  (dcc->uf & U_MASTER) ? _report_line (s, sz, '\036') : "",
		  _report_line (s, sz, '\032'), &away[1]);
	dcc->state = D_R_WHO2;
      }
      else
      {
	req->string[0] = 0;
	return req;
      }
      break;
    case D_R_WHOM:
//      if (ubotnet != dcc->botnet)
//      {
//	req->string[0] = 0;
//	return req;
//      }
      if ((ch = strchr (_report_line (s, sz, '\030'), ':')))
	*ch = 0;
      fmt[0] = away[0];
      strfcpy (&fmt[1], ((DCC_SESSION *)req->from->data)->iface->name,
	       sizeof(fmt)-1);
      ch = _report_line (s, sz, '\033');	/* connect time */
      if (!safe_strncmp (ch, DateString, 6))
        ch += 6;				/* today */
      snprintf (times, sizeof(times), "%6.6s %s",
		ch, _report_line (s, sz, '\032'));
      if ((ch = strchr (&fmt[1], '@')))
	*ch++ = 0;
      else
        ch = "-";
      /* %@ - bot, %L - lname, %N - times, %# - prefix of %* */
      printl (ReqString, sizeof(ReqString), format_w, 0,
	      times, ch, fmt, away[1] ? "away : " : NULL, 0, 0, &away[1]);
      dprint (5, "dcc:_do_report:formed %s", ReqString);
//      snprintf (ReqString, sizeof(ReqString),
//		"%c%-" LNAMELS "s %-" LNAMELS "s %s [idle %s]%s%s%s",
//		away[0], fmt, ch, _report_line (req->string, sz, '\030'),
//		_report_line (req->string, sz, '\032'),
//		(req->from->iface & I_LOCKED) ? " (off)" : "",
//		away[1] ? "\n  is away: " : "", &away[1]);
      break;
    default: /* D_R_DCCSTAT */
      snprintf (ReqString, sizeof(ReqString), "%-" LNAMELS "s %s (%s)",
		NONULL(req->from->name), _report_line (req->string, sz, '\030'),
		_report_line (req->string, sz, '\036'));
  }
  ReqTemplate.from = dcc->iface;	/* me is I_CHAT */
  /* other no need... */
  return &ReqTemplate;
}

/*
 * get message for user, if it is
 * to me or from another user on same botnet channel to "*"
 * used also when such command as "su" or "files" is in progress
 */
static REQUEST *dcc_request (INTERFACE *iface, REQUEST *req)
{
  DCC_SESSION *dcc = (DCC_SESSION *)iface->data;
  ssize_t sw;
  BINDING *bind = NULL;
  userflag cf = 0;
  char *cmd;
  volatile int to_all;

  if (dcc->state == D_OK)
  {
    _died_iface (iface, 0);
    return NULL;
  }
  if (dcc->state == D_LOGIN)
  {
    char *msg = _("connection lost");

    if (req)
      req->flag |= F_REJECTED;
    if (!(iface->iface & I_CHAT))
      return req;
    sw = safe_strlen (dcc->buf);
    if ((dcc->buf[0] &&
	WriteSocket (dcc->socket, dcc->buf, (size_t *)&sw, M_NORM) == -1) ||
	((msg = _dcc_login (dcc, iface->name))))
    {
      unsigned short port;

      cmd = SocketDomain (dcc->socket, &port);
      /* %L - Lname, %P - port, %@ - hostname, %* - reason */
      printl (ReqString, sizeof(ReqString), format_dcc_closed, 0,
	      NULL, cmd, iface->name, NULL, 0, port, msg);
      _log_conn (ReqString);
      _died_iface (iface, 0);
      return NULL;
    }
    if (dcc->state == D_LOGIN)
      return req;
    /* log to Wtmp */
    NewEvent (W_START, iface->name, NULL, 0);
    if (iface->iface & I_TELNET)
      strfcpy (dcc->buf, "\377\374\001\n", sizeof(dcc->buf));
    else
      *dcc->buf = 0;
  }
  /* check if this is mine but echo disabled */
  if (req)
  {
    to_all = Have_Wildcard (req->mask) + 1;
    /* check if this is: not for me exactly, but from me and no echo */
    if (to_all && req->from == dcc->iface && (req->mask_if & I_DCCALIAS) &&
	!(dcc->loglev & F_ECHO))
      req = NULL;
  }
  if (dcc->log && dcc->log->name)
    cf = Get_ChanFlags (dcc->iface->name, dcc->log->name);
  /* check if we have empty output buf */
  if (dcc->buf[0] || req)
  {
    if (req && dcc->buf[0])
      req->flag |= F_REJECTED;
    else if (req)
    {
      /* for logs... formatted, just add timestamp */
      if (req->mask_if & I_LOG)
      {
	if (req->flag & dcc->loglev)
	  printl (dcc->buf, sizeof(dcc->buf) - 1, "[%t] %*", 0,
		  NULL, NULL, NULL, NULL, 0, 0, req->string);
	req = NULL;
      }
      /* for reports... */
      else if (dcc->state != D_CHAT && dcc->state != D_PRELOGIN &&
	       *req->string > '\026' && *req->string < '\037')
      {
	if (req->string[1] == '\002')
	{
	  dcc->state = D_CHAT;
	  req = NULL;
	}
	else
	  req = _do_report (req, dcc);
      }
      /* flush command - see the users.c */
      else if (req->string[0] == '\010' && !req->string[1])
      {
	dcc_signal (iface, S_FLUSH);
	req = NULL;
      }
      /* for chat channel messages */
      else if (to_all && req->from && (req->from->iface & I_CHAT) &&
	       (req->mask_if & I_DCCALIAS))
      {
	char *prefix;
	char *suffix = "";
	char *str = req->string;

	if (req->flag & F_NOTICE)
	  prefix = "*** ";
	else if (*str == '.')
	{
	  prefix = "* ";
	  str++;
	}
	else
	{
	  prefix = "<";
	  suffix = ">";
	}
	snprintf (dcc->buf, sizeof(dcc->buf) - 1, "%s%s%s %s", prefix,
		  req->from->name, suffix, str);
	req = NULL;
      }
      /* direct messages */
      if (req)
      {
	strfcpy (dcc->buf, req->string, sizeof(dcc->buf) - 1);
	req = NULL;				/* request done! */
      }
      /* run "out-filter" bindings... */
      if (dcc->buf[0])
	do
	{
	  bind = Check_Bindtable (BT_Outfilter, dcc->buf, dcc->uf, cf, bind);
	  if (bind && !bind->name)
	    bind->func (dcc, &dcc->buf, sizeof(dcc->buf) - 1);
	} while (bind);
      if ((sw = safe_strlen (dcc->buf)))	/* ending with newline */
	strfcpy (&dcc->buf[sw], "\n", 2);
    }
    sw = safe_strlen (dcc->buf);
    if (sw)
      sw = WriteSocket (dcc->socket, dcc->buf, (size_t *)&sw, M_NORM);
    if (sw < 0)			/* error, kill dcc... */
    {
      _died_iface (iface, 0);
      return (&ReqTemplate);
    }
    /* don't input until empty buffer */
    else if (req && (req->flag & F_REJECTED))
      return req;
  }
  /* don't check input if this is interface shadow */
  if (!(iface->iface & ~(I_DCCALIAS | I_LOG)))
    return NULL;
  /* we sent the message, can D_PRELOGIN -> D_LOGIN */
  if (dcc->state == D_PRELOGIN)
  {
    dcc->state = D_LOGIN;
    return NULL;
  }
  sw = ReadSocket (ReqString, dcc->socket, sizeof(ReqString), M_NORM);
  if (sw < 0)
  {
    _died_iface (iface, 0);
    return &ReqTemplate;
  }
  if (!sw)
    return NULL;
  cmd = ReqString;
  dprint (5, "got from dcc chat of %s: %s", iface->name, ReqString);
  if ((iface->iface & I_TELNET) && !safe_strncmp (ReqString, "\377\376\001", 3))
  {
    while (cmd[3]) *cmd++ = cmd[3];	/* ignore TELNET response */
    *cmd = 0;
    cmd = ReqString;
  }
  dcc->timestamp = Time;		/* timestamp for idle */
  /* check the "dcc" flood... need just ignore or break connection? */
  if (CheckFlood (&dcc->floodcnt, flood_dcc) >= 0)
    return NULL;
  /* run "in-filter" bindings... */
  do
  {
    bind = Check_Bindtable (BT_Infilter, ReqString, dcc->uf, cf, bind);
    if (bind)
    {
      if (bind->name)
      {
	if (RunBinding (bind, NULL, NULL, NULL, Get_DccIdx (dcc), ReqString))
	  strfcpy (ReqString, BindResult, sizeof(ReqString));
      }
      else
	bind->func (dcc, ReqString, sizeof(ReqString));
    }
  } while (bind);
  /* run dcc->cmdbind ("dcc"|"files") and "chat" bindings... */
  if (dcc->state != D_CHAT || ReqString[0] == '.')
    Dcc_Exec (dcc, iface->name, ReqString, dcc->cmdbind, dcc->uf, cf,
	      Get_DccIdx (dcc));
  else
  {
    do
    {
      if ((bind = Check_Bindtable (BT_Chat, ReqString, dcc->uf, cf, bind)))
      {
	if (bind->name)
	  RunBinding (bind, NULL, iface->name, NULL, Get_DccIdx (dcc), ReqString);
	else
	  bind->func (dcc, ReqString);
      }
    } while (bind);
    ReqTemplate.mask_if = I_DCCALIAS;
    snprintf (ReqTemplate.mask, sizeof(ReqTemplate.mask), ":*:%d", dcc->botnet);
    ReqTemplate.flag = F_BOTNET;
    return &ReqTemplate;
  }
  return NULL;
}

void Dcc_Exec (DCC_SESSION *dcc, char *name, char *cmd, BINDTABLE *bt,
		   userflag gf, userflag cf, int dccidx)
{
  char *arg;
  BINDING *bind;
  int res;

  if (*cmd == '.')
    cmd++;
  if (!bt)
    bt = BT_Dcc;
  arg = NextWord (cmd);
  dprint (4, "dcc:Dcc_Exec: %s", cmd);
  if (!*arg)
    arg = NULL;
  bind = Check_Bindtable (bt, cmd, gf, cf, NULL);
  if (!bind)
  {
    if (arg) *arg = 0;
    New_Request (dcc->iface, 0, _("Nothing appropriated to: %s"), cmd);
    return;
  }
  else if (bind->name)
    res = RunBinding (bind, NULL, name, NULL, dccidx, arg);
  else
    res = bind->func (dcc, arg);
  if (res == 0)
    Get_Help (bind->key, NULL, dcc->iface, dcc->uf, cf, dcc->cmdbind,
	      _("Usage: "), 0);
  else if (res > 0)
    Add_Request (I_LOG, "*", F_CMDS, "#%s# %s %s", name, bind->key,
		 NONULL(arg));
}

/*
 * if signal == S_TERMINATE then also down iface->data->log interface
 * if signal == S_FLUSH then just update user info from userfile
 * S_SHUTDOWN, S_REPORT - as default...
 */
static iface_t dcc_signal (INTERFACE *iface, ifsig_t signal)
{
  DCC_SESSION *dcc = (DCC_SESSION *)iface->data;
  userflag gf;
  void *user;
  char idlestr[8];
  char bs[8];
  char c[64];
  int idle;
  INTERFACE *tmp;
  unsigned short p;
  char *dom;

  if (!dcc || dcc->socket == -1)	/* already killed? */
    return I_DIED;
  if (dcc) switch (signal)
  {
    case S_FLUSH:
      if (iface->name && *iface->name)
      {
	gf = Get_ChanFlags (iface->name, NULL);
	if (gf != dcc->uf)
	  dcc->uf = gf;
	/* check the IRC and botnet channels */
	user = Lock_User (iface->name);
	dom = Get_Userfield (user, "");
	Unlock_User (user);
	setdccconsole (dcc, dom);
      }
      break;
    case S_REPORT:
      switch (dcc->state)
      {
	case D_PRELOGIN:
        case D_LOGIN:
	  snprintf (ReqString, sizeof(ReqString), "\030%s\001\036logging in\001",
		    SocketDomain (dcc->socket, NULL));
	  break;
	default:
	  idle = Time - dcc->timestamp;
	  /* %Mm:%Ss */
	  if (idle < 3600)
	    snprintf (idlestr, sizeof(idlestr), "%2dm:%02ds", idle/60, idle%60);
	  /* %kh:%Mm */
	  else if (idle < 86400)
	    snprintf (idlestr, sizeof(idlestr), "%2dh:%02dm", idle/3600,
		      (idle%3600)/60);
	  /* %ed:%Hh */
	  else
	    snprintf (idlestr, sizeof(idlestr), "%2dd:%02dh", idle/86400,
		      (idle%86400)/3600);
	  snprintf (bs, sizeof(bs), "%u", dcc->botnet);
	  dom = SocketDomain (dcc->socket, &p);
	  snprintf (ReqString, sizeof(ReqString),
		    "\030%s:%hu\001\031%s\001\032%s\001\033%s\001\034%c%s\001\036chat: %s\001",
		    dom, p, getdccconsole (dcc, c, sizeof(c)), idlestr,
		    dcc->start, _userdccflag (dcc->uf), NONULL(dcc->away),
		    (dcc->iface->iface & I_LOCKED) ? "off" : bs);
      }
      tmp = Set_Iface (iface);
      New_Request (tmp, F_REPORT, ReqString);
      Unset_Iface();
      break;
    case S_STOP:
      /* stop the interface */
      iface->iface |= I_LOCKED;
      dcc->log->iface |= I_LOCKED;
      /* message - left */
      Chat_Part (dcc);
      break;
    case S_CONTINUE:
      /* restart the interface - only if user has partyline access */
      dcc_signal (iface, S_FLUSH);
      if (dcc->uf & U_CHAT)
      {
	iface->iface &= ~I_LOCKED;
	dcc->log->iface &= ~I_LOCKED;
	dcc->state = D_CHAT;
	/* message - returned */
	Chat_Join (dcc);
	break;
      }
      /* stop DCC CHAT or continue... */
    case S_TERMINATE:
      /* destroy all data */
      ReqString[0] = 0;
      _died_iface (iface, 0);
      if (ReqString[0])
	_log_conn (ReqString);
      FREE (&dcc->away);
      return I_DIED;
    case S_SHUTDOWN:
      /* attempt to sent shutdown message and quiet shutdown */
      if (signal == S_SHUTDOWN && BindResult)
      {
        size_t sw;

	strfcpy (dcc->buf, BindResult, sizeof(dcc->buf));
	sw = safe_strlen (dcc->buf);
	WriteSocket (dcc->socket, dcc->buf, &sw, M_NORM);
      }
      _died_iface (iface, 1);
    default:
      break;
  }
  return 0;
}

static iface_t dcclog_signal (INTERFACE *iface, ifsig_t signal)
{
  if (signal == S_TERMINATE)
  {
    iface->data = NULL;
    iface->iface |= I_DIED;
    return I_DIED;
  }
  return 0;
}

static iface_t dccalias_signal (INTERFACE *iface, ifsig_t signal)
{
  DCC_SESSION *dcc = (DCC_SESSION *)iface->data;

  if (dcc == NULL || signal == S_TERMINATE)
  {
    iface->data = NULL;
    iface->iface |= I_DIED;
    return I_DIED;
  }
  else if (signal == S_REPORT)
  {
    if (dcc->iface && dcc->iface->IFSignal)
      dcc->iface->IFSignal (iface, signal);
  }
  return 0;
}

/* locking fields: ->state ->socket ->botnet ->iface */
static iface_t thrdcc_signal (INTERFACE *iface, ifsig_t signal)
{
  DCC_SESSION *dcc = (DCC_SESSION *)iface->data;
  INTERFACE *tmp;
  char *msg;

  if (!dcc)			/* already killed? */
    return I_DIED;
  switch (signal)
  {
    case S_REPORT:
      msg = ReqString;
      pthread_mutex_lock (&dcc->lock);
      if (iface->iface & I_LISTEN)
	snprintf (ReqString, sizeof(ReqString),
		  "\036listening on port %s\001", iface->name);
      else if (dcc->state != D_LOGIN)
	snprintf (ReqString, sizeof(ReqString),
		  "\030%s\001\036waiting for connection\001",
		  SocketDomain (dcc->socket, NULL));
      else
	snprintf (ReqString, sizeof(ReqString),
		  "\030%s\001\033%s\001\036download: %02u.%d%% completed\001",
		  SocketDomain (dcc->socket, NULL), dcc->start,
		  dcc->botnet / 10, dcc->botnet % 10);
      pthread_mutex_unlock (&dcc->lock);
      tmp = Set_Iface (iface);
      New_Request (tmp, F_REPORT, msg);
      Unset_Iface();
      break;
    case S_REG:
      if (iface->iface & I_LISTEN)
	Add_Request (I_INIT, "*", F_REPORT, "port %s%s",
		     (dcc->uf & U_BOT) ? "-b " : "",iface->name);
      break;
    case S_LOCAL:
      if ((iface->iface & I_DCC) && BindResult[0] == 'A')
      {
	unsigned short port;

	pthread_mutex_lock (&dcc->lock);
	if (dcc->state == D_PRELOGIN)	/* are we waiting for ACCEPT? */
	{
	  SocketDomain (dcc->socket, &port);
	  if (atoi (NextWord_Unquoted (NULL, 0, NextWord(BindResult))) == port)
	    dcc->state = D_OFFER;	/* don't check filename, mIRC says
					    it is "file.ext" anyway */
	}
	pthread_mutex_unlock (&dcc->lock);
      }
      break;
    case S_TERMINATE:
      if (iface->iface & I_LISTEN)
	Add_Request (I_LOG, "*", F_CONN,
		    _("Listening socket on port %s terminated."), iface->name);
      else
	Add_Request (I_LOG, "*", F_CONN, _("DCC GET %s from %s terminated."),
		     dcc->away, iface->name);	/* see dcc_dnload() */
      pthread_mutex_lock (&dcc->lock);
    case S_SHUTDOWN:
      /* just kill it... */
      KillSocket (&dcc->socket);
      dcc->iface = NULL;
      /* ...it die itself */
      iface->data = NULL;
      iface->iface |= I_DIED;
      if (signal != S_SHUTDOWN)
	pthread_mutex_unlock (&dcc->lock);
//      else
//	pthread_join (dcc->th, NULL);
      return I_DIED;
    default:
      break;
  }
  return 0;
}

/*
 * Internal login bindings:
 * void func(DCC_SESSION *dcc, uchar *who, char **msg)
 */

/* called from threads! */
/* away is Lname if this is CTCP CHAT answer or NULL */
static void GetChat (DCC_SESSION *dcc, char *name, char **msg)
{
  size_t sz;
  iface_t i = I_CHAT;
  time_t t;

  /* turn off echo if telnet and check password */
  Set_Iface (NULL);
  t = time(NULL) + dcc_timeout;
  Unset_Iface();
  snprintf (dcc->buf, sizeof(dcc->buf), "Password: %s", dcc->away ? "" : "\377\373\001");
  sz = safe_strlen (dcc->buf);
  while (sz && WriteSocket (dcc->socket, dcc->buf, &sz, M_NORM) >= 0 &&
	 time(NULL) < t);
  if (sz)
  {
    *msg = "socket died";
    return;
  }
  /* dcc->buf is empty and no echo now! */
  dcc->state = D_LOGIN;
  dcc->uf = Get_ChanFlags (name, NULL);
  time (&dcc->timestamp);
  if (dcc->away)
    FREE (&dcc->away);
  else
    i = (I_TELNET | I_CHAT);
  pthread_mutex_lock (&SessionsLock);
  Sessions++;
  pthread_mutex_unlock (&SessionsLock);
  /* create interface - lock interfaces before */
  Set_Iface (NULL);
  dcc->iface = Add_Iface (name, i, &dcc_signal, &dcc_request,
			  (void *)dcc);
  /* try to create the alias for scripts :) */
  dcc->alias = Add_Iface (NULL, I_DCCALIAS, &dccalias_signal, &dcc_request,
			  (void *)dcc);
  Unset_Iface();
  /* now we cannot touch any dcc fields since interface can be ran */
  *msg = NULL;
}

/* internal: dcc->away has "chat", dcc->buf is "lname nick:addr" */
#define dcc ((DCC_SESSION *) input_data)
static void *create_chat (void *input_data)
{
  char *name, *buf = NULL;
  char *addr;

  addr = safe_strchr (dcc->buf, ':');
  *addr++ = 0;
  name = safe_strchr (dcc->buf, ' ');
  *name = 0;
  /* save it now due to Lname may be erased by login */
  name = safe_strdup (dcc->buf);
  /* init connection */
  if ((dcc->socket = AddSocket (M_FILE, addr, dcc->botnet)) < 0)
    buf = _("cannot create socket");
  else
  {
    BINDING *bind = Check_Bindtable (BT_Login, name, dcc->uf, 0, NULL);

    if (bind)
      bind->func (dcc, name, &buf);
    else
      buf = _("access denied");
  }
  if (buf)
  {
    /* %L - Lname, %P - port, %@ - hostname, %* - reason */
    printl (dcc->buf, sizeof(dcc->buf), format_dcc_closed, 0, NULL,
	    SocketDomain (dcc->socket, NULL), name, NULL, 0L, dcc->botnet, buf);
    /* cannot create connection */
    KillSocket (&dcc->socket);
    _log_conn (dcc->buf);
    FREE (&dcc->away);
    safe_free (&input_data);
  }
  else
  {
    Add_Request (I_LOG, "*", F_CONN, _("Logged in: %s."), name);
  }
  FREE (&name);
  return NULL;
}

/* away is Lname if this is CTCP CHAT answer or NULL */
static void *listen_port (void *input_data)
{
  idx_t new_idx, ident_idx;
  DCC_SESSION *child;
  char *user = NULL, *domain;
  char ident[24];
  userflag uf;
  ssize_t sz, get;
  unsigned short op, p;
  BINDING *bind;
  time_t t, tt;
  struct timespec tp;

  tp.tv_sec = 0;
  tp.tv_nsec = 100000000L;			/* 0.1s per cycle */
  pthread_mutex_init (&dcc->lock, NULL);
  pthread_mutex_lock (&dcc->lock);
  while (dcc->socket >= 0)
  {
    nanosleep (&tp, NULL);
    pthread_mutex_unlock (&dcc->lock);
    user = domain = NULL;
    pthread_mutex_lock (&dcc->lock);
    /* TODO: check timeout for M_LINP */
    if ((new_idx = AnswerSocket (dcc->socket)) == E_AGAIN)
      continue;
    else if (new_idx < 0)
    {
      /* print error message */
      _log_conn (_("Listening socket died."));
      /* kill the socket */
      KillSocket (&dcc->socket);
      break;
    }
    /* get own port */
    SocketDomain (dcc->socket, &op);
    /* get domain and port */
    pthread_mutex_unlock (&dcc->lock);
    domain = SocketDomain (new_idx, &p);
    /* SocketDomain() does not return NULL, let's don't wait! */
    if (!*domain)
      domain = NULL;
    /* get ident of user */
    *ident = 0;
    if (dcc->away)
    {
      /* it is DCC CHAT answer - close listening socket, don't ask ident */
      pthread_mutex_lock (&dcc->lock);
      KillSocket (&dcc->socket);
      pthread_mutex_unlock (&dcc->lock);
      user = dcc->away;
    }
    else if ((ident_idx = AddSocket (M_FILE, domain, 113)) > 0)
    {
      snprintf (dcc->buf, sizeof(dcc->buf), "%hu, %hu\n", p, op);
      dprint (5, "ask host %s for ident: %s", domain, dcc->buf);
      sz = safe_strlen (dcc->buf);
      Set_Iface (NULL);
      tt = ident_timeout;
      Unset_Iface();
      time (&t);
      while (!(WriteSocket (ident_idx, dcc->buf, (size_t *)&sz, M_FILE)))
	if (time(NULL) - t > tt) break;
      while (!(sz = ReadSocket (dcc->buf, ident_idx, sizeof(dcc->buf), M_NORM)) ||
	     sz == E_AGAIN)
      {
	if (time(NULL) - t > tt) break;
	nanosleep (&tp, NULL);
      }
      if (sz > 0)
      {
	dprint (5, "%s ident answer: %s", domain, dcc->buf);
	sscanf (dcc->buf, "%*[^:]: %[^: ] :%*[^:]: %23[^ \n]", dcc->buf, ident);
	if (safe_strcmp (dcc->buf, "USERID"))
	  *ident = 0;
      }
      KillSocket (&ident_idx);
    }
    /* check username@domain... */
    uf = Match_User (domain, ident, user);
    /* %* - ident, %U - user nick, %@ - hostname, %L - Lname, %P - port */
    Set_Iface (NULL);
    printl (dcc->buf, sizeof(dcc->buf), format_dcc_input_connection, 0, user,
	    domain, dcc->away, NULL, 0, p, ident[0] ? ident : _("((unknown))"));
    tt = dcc_timeout;
    Unset_Iface();
    _log_conn (dcc->buf);
    pthread_mutex_lock (&dcc->lock);
    if (drop_unknown && !(Check_Bindtable (BT_Login, "*", uf, 0, NULL) &&
	(((dcc->uf & U_ANY) && !(uf & U_BOT)) ||
	((dcc->uf & U_BOT) && (uf & U_BOT)))))
    {
      Add_Request (I_LOG, "*", F_CONN,
		_("Connection from %s dropped: not allowed."), domain);
      KillSocket (&new_idx);
      continue;
    }
    if (!dcc->away)
    {
      /* it is input connection, we must get Lname */
      strfcpy (dcc->buf, "\nFoxEye network node\n\nlogin: ", sizeof(dcc->buf));
      sz = safe_strlen (dcc->buf);
      time (&t);
      while (!(get = WriteSocket (new_idx, dcc->buf, (size_t *)&sz, M_NORM)))
	if (time(NULL) - t > tt) break;
      if (get > 0)
	while (!(get = ReadSocket (dcc->buf, new_idx, sizeof(dcc->buf), M_NORM)) ||
	       get == E_AGAIN)
	{
	  if (time(NULL) - t > tt) break;
	  nanosleep (&tp, NULL);
	}
      if (get <= 0)
      {
	Add_Request (I_LOG, "*", F_CONN,
		  _("Connection from %s lost while logging in."), domain);
	KillSocket (&new_idx);
	continue;
      }
      user = dcc->buf;
    }
    pthread_mutex_unlock (&dcc->lock);
    uf = Match_User (domain, ident, user);
    bind = Check_Bindtable (BT_Login, user, uf, 0, NULL);
    user = safe_strdup (user);
    if (!bind || !(((dcc->uf & U_ANY) && !(uf & U_BOT)) ||
	((dcc->uf & U_BOT) && (uf & U_BOT))))
    {
      char msg[] = "Access denied.";
      sz = safe_strlen (msg);

      while (!(WriteSocket (new_idx, msg, (size_t *)&sz, M_NORM)));
      Add_Request (I_LOG, "*", F_CONN,
		_("Connection from %s dropped: not allowed."), user);
      KillSocket (&new_idx);
    }
    else
    {
      child = safe_calloc (1, sizeof(DCC_SESSION));
      child->socket = new_idx;
      child->away = dcc->away;		/* is not NULL for CTCP CHAT only */
      dcc->away = NULL;
      bind->func (child, user, &domain);
      if (domain)
      {
	/* %L - Lname, %P - port, %@ - hostname, %* - reason */
	Set_Iface (NULL);
	printl (dcc->buf, sizeof(dcc->buf), format_dcc_closed, 0,
		NULL, domain, user, NULL, 0, p, domain);
	Unset_Iface();
	/* cannot create connection */
	_log_conn (dcc->buf);
	KillSocket (&new_idx);
	FREE (&child->away);
	FREE (&child);
      }
    }
    FREE (&user);
    pthread_mutex_lock (&dcc->lock);
  }
  pthread_mutex_unlock (&dcc->lock);
  /* if no interface (incoming DCC CHAT) we need free ->away */
  FREE (&dcc->away);
  Set_Iface (NULL);
  if (dcc->iface)
    thrdcc_signal (dcc->iface, S_TERMINATE);
  Unset_Iface();
  pthread_mutex_destroy (&dcc->lock);
  safe_free (&input_data);
  return NULL;
}

/* internal: dcc->away is filename, dcc->buf is "lname nick:addr" */
static void *dcc_dnload (void *input_data)
{
  char *msg = NULL;
  char path[HUGE_STRING];
  char *addr;
  FILE *tmp = NULL;
  uint32_t fsize, tptr, ptrn, ptrh, sptr, bs = 0;
  long name_max, path_max;
  unsigned short p;
  ssize_t sw;
  int N;
  void *buff;
  struct stat st;
  time_t t;
  struct tm tm;

  addr = safe_strchr ((char *)dcc->buf, ':');
  *addr++ = 0;
  /* test if we can download */
  snprintf (path, sizeof(path), _("Get file \"%s\" from %s"),
	    dcc->away, NextWord (dcc->buf));
  Set_Iface (NULL);
  tptr = dcc_getmax;
  Unset_Iface();
  if (dcc->rate > tptr || !Confirm (path, dcc_get))	/* lock problem? */
  {
    FREE (&dcc->away);
    safe_free (&input_data);
    return NULL;
  }
  /* set filenames */
  name_max = pathconf (dnload_dir, _PC_NAME_MAX);
  if (name_max >= HUGE_STRING)
    name_max = HUGE_STRING-1;
  path_max = pathconf (dnload_dir, _PC_PATH_MAX);
  if (path_max >= HUGE_STRING)
    path_max = HUGE_STRING-1;
  if (safe_strlen (dcc->away) > name_max)
  {
    char *bg;

    bg = strrchr (dcc->away, '.');
    if (bg)
    {
      char *bg2;

      *bg = 0;
      bg2 = strrchr (dcc->away, '.');
      *bg = '.';
      if (bg2 && (safe_strlen (dcc->away) - (bg2 - dcc->away)) < name_max)
	bg = bg2;
    }
    if (bg)
    {
      size_t st = safe_strlen (dcc->away) - (bg - dcc->away);

      if (st < name_max)
	memmove (dcc->away + name_max - st, bg, st);
    }
    else
      bg = &dcc->away[name_max];
    if (bg > dcc->away)
      bg--;
    *bg = '~';
    dcc->away[name_max] = 0;
  }
  Set_Iface (NULL);
  snprintf (path, path_max, "%s/%s",
	    expand_path (path, dnload_dir, sizeof(path)), dcc->away);
  Unset_Iface();
  if (!stat (path, &st))
  {
    char cc[SHORT_STRING];

    Set_Iface (NULL);
    tptr = resume_min;
    Unset_Iface();
    if (st.st_size > tptr)
    {
      snprintf (cc, sizeof(cc), _("Resume file \"%s\""), dcc->away);
      if (Confirm (cc, dcc_resume))		/* lock problem? */
	msg = "ab";				/* append if confirmed */
    }
    if (!msg)
    {
      snprintf (cc, sizeof(cc), _("Overwrite existing file \"%s\""), dcc->away);
      if (!Confirm (cc, dcc_overwrite))		/* lock problem? */
      {
	FREE (&dcc->away);
	safe_free (&input_data);
	return NULL;
      }
    }
  }
  if (!msg)
    msg = "wb";					/* rewrite it by default */
  /* create and get tmpfile */
  tmp = safe_fopen (path, msg);
  if (tmp)
    ptrh = sptr = ftell (tmp);
  else
    ptrh = 0;					/* if error... */
  p = dcc->botnet;
  dcc->botnet = 0;
  fsize = dcc->rate;
  dcc->rate = 0;
  pthread_mutex_init (&dcc->lock, NULL);
  pthread_mutex_lock (&dcc->lock);
  msg = NextWord (dcc->buf);
  dcc->iface = Add_Iface (msg, I_DCC, &thrdcc_signal, NULL, input_data);
  if (tmp && ptrh)
  {
    Set_Iface (NULL);
    N = resume_timeout;
    Unset_Iface();
    /* send the DCC RESUME */
    msg2nick (msg, "\001DCC RESUME \"%s\" %hu %lu\001", dcc->away, p, ptrh);
    /* wait for accept */
    time (&t);
    while (t && dcc->state != D_OFFER)
    {
      pthread_mutex_unlock (&dcc->lock);
      if (time (NULL) - t > N)
	t = 0;
      pthread_mutex_lock (&dcc->lock);
    }
  }
  Set_Iface (NULL);
  N = dcc_turbo;
  Unset_Iface();
  if (N < 1)					/* correct it ;) */
    N = 1;
  else if (N > 32)
    N = 32;
  /* get socket */
  if (!tmp || (dcc->socket = AddSocket (M_FILE, addr, p)) < 0)
  {
    if (!tmp)
      Add_Request (I_LOG, "*", F_CONN,
		   _("DCC GET aborted: couldn't open \"%s\"."), dcc->away);
    else			/* E_NOSOCKET or E_NOCONNECT */
      Add_Request (I_LOG, "*", F_CONN,
		   _("DCC GET aborted: couldn't create connection to %s:%hu."),
		   addr, p);
    Set_Iface (NULL);
    if (dcc->iface)
      thrdcc_signal (dcc->iface, S_TERMINATE);
    Unset_Iface();
    pthread_mutex_unlock (&dcc->lock);
    pthread_mutex_destroy (&dcc->lock);
    FREE (&dcc->away);
    safe_free (&input_data);
    if (tmp)
      fclose (tmp);
    return NULL;
  }
  tptr = sptr = ptrh;
  dcc->state = D_LOGIN;
  time (&dcc->timestamp);
  localtime_r (&dcc->timestamp, &tm);
  strftime (dcc->start, sizeof(dcc->start), "%e %b %H:%M", &tm);
  /* send 32-bit network ordered pointer */
  sw = sizeof(ptrn);
  ptrn = htonl (sptr);
  do
  {
    sw = WriteSocket (dcc->socket, (void *)&ptrn, (size_t *)&sw, M_FILE);
  } while (!sw);
  pthread_mutex_unlock (&dcc->lock);
#define sizeofbuff 16384	/* i think, it is enough */
  buff = safe_malloc (sizeofbuff);
  msg = safe_strchr (dcc->buf, ' ');
  if (msg)
    *msg++ = 0;
  else
    msg = "?";
  /* %L - lname, %U - nick, %@ - ip, %P - port, %* - filename(unquoted) */
  Set_Iface (NULL);
  printl (buff, sizeofbuff, format_dcc_startget, 0,
	  msg, addr, dcc->buf, NULL, 0L, p, dcc->away);
  Unset_Iface();
  _log_conn (buff);
  do
  {
    if (sptr < ptrh + N * bs)
    {
      /* send 32-bit network ordered pointer */
      sw = sizeof(ptrn);
      ptrn = htonl (sptr);
      pthread_mutex_lock (&dcc->lock);
      do
      {
	sw = WriteSocket (dcc->socket, (void *)&ptrn, (size_t *)&sw, M_FILE);
      } while (!sw);
      pthread_mutex_unlock (&dcc->lock);
      sptr += bs;
    }
    pthread_mutex_unlock (&dcc->lock);
    do
    {
      pthread_mutex_lock (&dcc->lock);
      /* receive the block and write it to file */
      sw = ReadSocket (buff, dcc->socket, sizeofbuff, M_FILE);
      pthread_mutex_unlock (&dcc->lock);
    } while (!bs && sw == E_AGAIN);
    if (sw > 0)
    {
      if (!bs)
      {
	bs = sw;
	sptr += bs;
      }
      ptrh += sw;
      sw = fwrite (buff, sw, 1, tmp);
      pthread_mutex_lock (&dcc->lock);
      dcc->botnet = ptrh / (fsize/1000);	/* promilles */
      time (&t);
      if (t - dcc->timestamp >= 50)		/* interval is 50s */
      {
	dcc->rate = (ptrh - tptr) / (t - dcc->timestamp);
	dcc->timestamp = t;
	tptr = ptrh;
      }
      pthread_mutex_unlock (&dcc->lock);
    }
  } while ((sw == E_AGAIN || sw > 0) && ptrh < fsize);
  /* check if error has happened */
  if (ptrh > fsize)		/* file is more long than declared */
    snprintf (buff, sizeofbuff, _("Got file \"%s\" from %s: %lu bytes instead of %lu."),
	      dcc->away, msg, (unsigned long)ptrh, (unsigned long)fsize);
  else if (ptrh != fsize)	/* incomplete file! */
    snprintf (buff, sizeofbuff, _("Got incomplete file \"%s\" from %s: %lu/%lu bytes."),
	      dcc->away, msg, (unsigned long)ptrh, (unsigned long)fsize);
  else
  {
    /* %L - lname, %U - nick, %@ - ip, %P - port, %* - filename(unquoted) */
    Set_Iface (NULL);
    printl (buff, sizeofbuff, format_dcc_gotfile, 0,
	    msg, addr, dcc->buf, NULL, 0L, p, dcc->away);
    Unset_Iface();
    p = 0;
  }
  _log_conn (buff);
  fclose (tmp);
#undef sizeofbuff
  safe_free (&buff);
  if (!p)
  {
    BINDING *bind = NULL;

    do
    {
      if ((bind = Check_Bindtable (BT_Upload, (char *)dcc->buf, dcc->uf, -1, bind)))
      {
	if (bind->name)
	{
	  if (msg) *msg = ' ';
	  RunBinding (bind, NULL, (char *)dcc->buf, NULL, -1, path);
	  if (msg) *msg = 0;
	}
	else
	  bind->func ((char *)dcc->buf, path);
      }
    } while (bind);
  }
  /* end all */
  Set_Iface (NULL);
  if (dcc->iface)
    thrdcc_signal (dcc->iface, S_TERMINATE);
  Unset_Iface();
  pthread_mutex_destroy (&dcc->lock);
  FREE (&dcc->away);
  safe_free (&input_data);
  return NULL;
}

/*
 * Caller must place domain of user who get file at DCC_SESSION::away before
 * it says IP/port to user and then we compare that domain with connected now
 *
 * DCC_SESSION structure (and ->away) must be released by function that has
 * called Dcc_Send().  Finish can be checked if ->state is D_OK or D_NOSOCKET.
 * ->state is D_OFFER when we are waiting for connection and D_LOGIN when we
 * are sending the file.  ->botnet contains promille of completed transfer.
 * ->rate contains current transfer speed in bytes per second.  If you want to
 * read/write eighter ->socket, or ->state, or ->botnet, or ->rate you must
 * lock mutex at ->lock.  You can terminate the session by KillSocket() then
 * wait D_OK or D_NOSOCKET, destroy mutex and release DCC_SESSION.
 *
 * Caller interface has to be I_DCC and may receive the signal S_LOCAL with
 * BindResult filled by RESUME request.  If port is the same (to verify file
 * name is silly i think) then we can ACCEPT that resume.
 *
 * Note: function logs only connection state.
 */
static void *dcc_upload (void *input_data)
{
  char *buffer;
  unsigned short port = 0;
  idx_t new_idx;
  ssize_t ss;
  size_t blksize, sz = 0;
  int N;
  uint32_t tptr, ptrn, ptrh, sptr;
  _dcc_state res = D_OK;
  /* file is at EOF! */
  uint32_t fsize = ftell ((FILE *)dcc->log);
  time_t t;
  struct tm tm;

  /* hmmm, socket is in non-blocking mode? */
  /* answer and close listening socket and check who asked connection */
  time (&t);
  Set_Iface (NULL);
  N = dcc_timeout;
  Unset_Iface();
  pthread_mutex_lock (&dcc->lock);
  while ((new_idx = AnswerSocket (dcc->socket)) == E_AGAIN && t)
  {
    pthread_mutex_unlock (&dcc->lock);
    if (time (NULL) - t > N)
      t = 0;
    pthread_mutex_lock (&dcc->lock);
  }
  KillSocket (&dcc->socket);
  dcc->socket = new_idx;
  if (t)
  {
    localtime_r (&t, &tm);
    strftime (dcc->start, sizeof(dcc->start), "%e %b %H:%M", &tm);
  }
  pthread_mutex_unlock (&dcc->lock);
  buffer = SocketDomain (new_idx, &port);	/* get domain of client */
  if (new_idx < 0 || safe_strcasecmp (buffer, dcc->away))
    res = D_NOSOCKET;
  else
  {
    Add_Request (I_LOG, "*", F_CONN,
		 _("DCC send connection granted to %s on port %hu."),
		 buffer, port);
    /* set the blocksize */
    Set_Iface (NULL);
    blksize = dcc_blksize;
    N = dcc_turbo;
    Unset_Iface();
    buffer = safe_malloc (blksize);
    if (N < 1)					/* correct it ;) */
      N = 1;
    else if (N > 32)
      N = 32;
    /* send the file */
    tptr = sptr = ptrh = 0;
    time (&dcc->timestamp);
    do
    { 
      /* try to send N frames if protocol was started yet */
      if (ptrh && sptr < fsize && sptr < ptrh + N * blksize &&
	  (sz || (sz = fread (buffer, 1, blksize, (FILE *)dcc->log))))
      {
	pthread_mutex_lock (&dcc->lock);
	ss = WriteSocket (dcc->socket, buffer, (size_t *)&sz, M_FILE);
	pthread_mutex_unlock (&dcc->lock);
	if (ss < 0)
	  res = D_NOSOCKET;
	else
	  sptr += ss;
      }
      pthread_mutex_lock (&dcc->lock);
      dcc->botnet = sptr / (fsize/1000);	/* promilles */
      if (t - dcc->timestamp >= 50)		/* interval is 50s */
      {
	dcc->rate = (ptrh - tptr) / (t - dcc->timestamp);
	dcc->timestamp = t;
	tptr = ptrh;
      }
      pthread_mutex_unlock (&dcc->lock);
      if (sptr == fsize)		/* transfer completed */
	break;
      /* if me got request then advance ptr */
      pthread_mutex_lock (&dcc->lock);
      ss = ReadSocket ((void *)&ptrn, dcc->socket, sizeof(uint32_t), M_FILE);
      pthread_mutex_unlock (&dcc->lock);
      if (ss == sizeof(uint32_t))
      {
	if (!ptrh)				
	{
	  sptr = ptrh = ntohl (ptrn);
	  if (fseek ((FILE *)dcc->log, sptr, SEEK_SET))
	  {
	    dprint (5, "dcc send block request out of file: %lu",
		    (unsigned long)ptrh);
	    res = D_NOSOCKET;
	  }
	}
	else if (ptrh > ntohl (ptrn))		/* illegal ptr! */
	{
	  dprint (5, "dcc send block request out of sequence: %lu after %lu",
		  (unsigned long)ntohl (ptrn), (unsigned long)ptrh);
	  res = D_NOSOCKET;
	}
	else
	  ptrh = ntohl (ptrn);
	ptrh++;					/* min ptr for next */
      }
      else if (ss != E_AGAIN)
	res = D_NOSOCKET;
    } while (res != D_NOSOCKET);
    FREE (&buffer);
  }
  Add_Request (I_LOG, "*", F_CONN,
	       _("DCC send connection to %s on port %hu closed."),
	       NONULL(dcc->away), port);
  pthread_mutex_lock (&dcc->lock);
  KillSocket (&dcc->socket);
  fclose ((FILE *)dcc->log);
  dcc->state = res;
  pthread_mutex_unlock (&dcc->lock);
  return NULL;
}
#undef dcc

DCC_SESSION *Dcc_Send (char *filename, long offset)
{
  DCC_SESSION *dcc;
  FILE *file;

  file = safe_fopen (filename, "rb");
  if (!file || fseek (file, 0L, SEEK_END))
    return NULL;
  dcc = safe_calloc (1, sizeof(DCC_SESSION));
  /* create DCC session and open listening socket */
  dcc->state = D_OFFER;
  dcc->log = (INTERFACE *) file;
  /* if no port_files defined, port will be assigned by system */
  dcc->socket = AddSocket (M_LINP, hostname, port_files);
  pthread_mutex_init (&dcc->lock, NULL);
  /* init a thread */
  if (dcc->socket < 0 || pthread_create (&dcc->th, NULL, &dcc_upload, dcc))
  {
    KillSocket (&dcc->socket);
    pthread_mutex_destroy (&dcc->lock);
    FREE (&dcc);
    fclose (file);
  }
  if (dcc)
    dprint (1, "listening socket for dcc send %s opened", filename);
  return dcc;
}

/*
 * Internal ctcp bindings:
 * int func(void *to, uchar *from, char *lname, char *msg)
 */
		/* DCC */
static int IncomingDCC (char *to, uchar *from, char *lname, char *msg)
{
  DCC_SESSION *dcc;
  char *c;
  char nick[IFNAMEMAX+1];
  char addr[16];
  unsigned long ip, ptr = 0;
  void * (*create_dcc) (void *);

  /* parse and check */
  if (safe_strchr (SPECIALCHARS, *to) || safe_strlen (msg) < 12)
    return 0;
  strfcpy (nick, (char *)from, sizeof(nick));
  if ((c = safe_strchr (nick, '!')))
    *c = 0;
  c = msg+4;			/* skip "DCC " */
  while (*c == ' ') c++;
  if (!strncmp (c, "CHAT ", 5))
    create_dcc = &create_chat;
  else if (!strncmp (c, "SEND ", 5))
    create_dcc = &dcc_dnload;
  else if (!strncmp (c, "RESUME ", 7) || !strncmp (c, "ACCEPT ", 7))
  {
    ifsig_t sig = S_LOCAL;

    BindResult = c;
    Add_Request (I_DCC, nick, F_SIGNAL, (char *)&sig);
    return 1;
  }
  else
    return 0;
  c = NextWord (c);
  if (!*c)
    return 0;
  /* create DCC session and init DCC connection */
  dcc = safe_calloc (1, sizeof(DCC_SESSION));
  sscanf (NextWord_Unquoted (dcc->buf, sizeof(dcc->buf), c), "%lu %u %lu",
	  &ip, &dcc->botnet, &ptr);
  if (!ptr || ptr > LONG_MAX)
  {
    FREE (&dcc);
    dprint (2, "invalid DCC: size %lu out of range", ptr);
    return 0;
  }
  dcc->rate = ptr;
  if ((c = strrchr (dcc->buf, '/')))		/* skip subdirs if there are */
    dcc->away = safe_strdup (c);
  else
    dcc->away = safe_strdup (dcc->buf);
  snprintf (addr, sizeof(addr), "%u.%u.%u.%u", (int) ip>>24,
	    (int) (ip>>16)%256, (int) (ip>>8)%256, (int) ip%256);
  printl (dcc->buf, sizeof(dcc->buf), format_dcc_request, 0, nick,
	  (char *)from, lname, NULL, ip, (unsigned short)dcc->botnet, dcc->away);
  _log_conn (dcc->buf);
  snprintf (dcc->buf, sizeof(dcc->buf), "%s %s:%s", lname, nick, addr);
  if (Sessions == max_dcc)
  {
    /* send notice to current server */
    notice2nick (nick, _("Sorry, my limit of DCC is exhausted. Try later, please."));
    FREE (&dcc->away);
    FREE (&dcc);
    return 1;
  }
  dcc->uf = Get_ChanFlags (lname, NULL);
  c = NULL;
  if (create_dcc == &create_chat)		/* DCC CHAT attempt */
  {
    if (Find_Iface (I_CHAT, lname))		/* duplicate chat attempt */
    {
      Unset_Iface();
      notice2nick (nick, _("I'm sorry, no duplicate connections allowed."));
      c = _("DCC CHAT: Duplicate connection attempt.");
    }
    /* TODO: have to do anything if chat request and UI exist? */
  }
  dcc->state = D_PRELOGIN;
  if (!c && pthread_create (&dcc->th, NULL, create_dcc, dcc))
    c = _("DCC: Cannot create thread!");
  if (c)
  {
    _log_conn (c);
    FREE (&dcc);
    return 0;
  }
  return 1;					/* although logging :) */
}

		/* CHAT */
static int OutgoingDCC (char *to, uchar *from, char *lname, char *msg)
{
  unsigned short port = 0;
  char nick[IFNAMEMAX+1];			/* nick@net */
  char *c;
  DCC_SESSION *dcc;

  /* no public CTCP's */
  if (safe_strchr (SPECIALCHARS, *to))
    return 0;
  strfcpy (nick, (char *)from, sizeof(nick));
  if ((c = safe_strchr (nick, '!')))
    *c = 0;
  dcc = safe_calloc (1, sizeof(DCC_SESSION));
  dcc->away = safe_strdup (lname);
  /* if no firewall, assign and listen port (?) */
  dcc->socket = AddSocket (M_LINP, hostname, 0);
  SocketDomain (dcc->socket, &port);
  if (!port || pthread_create (&dcc->th, NULL, &listen_port, dcc))
  {
    _log_conn ("DCC CHAT: Cannot open port for connection!");
    FREE (&dcc);
  }
  else
    msg2nick (nick, "\001DCC CHAT chat %lu %hu\001", ip_local, port);
  return 1;
}

/*
 * Internal dcc bindings:
 * int func(DCC_SESSION *from, char *args)
 */

static void _say_current (DCC_SESSION *dcc, char *msg)
{
  New_Request (dcc->iface, 0, _("Now: %s"), NONULL(msg));
}

		/* .away [<message>] */
static int dc_away (DCC_SESSION *dcc, char *args)
{
  char ch[16];

  if (args)
  {
    /* set away message */
    FREE (&dcc->away);
    dcc->away = safe_strdup (args);
    /* send notify to botnet */
    snprintf (ch, sizeof(ch), ":*:%u", dcc->botnet);
    Add_Request (I_DCCALIAS, ch, F_NOTICE, _("now away: %s"), args);
  }
  else
    _say_current (dcc, dcc->away);
  return -1;	/* no log it */
}

		/* .me <message> */
static int dc_me (DCC_SESSION *dcc, char *args)
{
  BINDING *bind = NULL;
  char ch[16];

  do
  {
    if ((bind = Check_Bindtable (BT_Chatact, args, dcc->uf, -1, bind)))
    {
      if (bind->name)
	RunBinding (bind, NULL, dcc->iface->name, NULL, Get_DccIdx (dcc), args);
      else
	bind->func (dcc, args);
    }
  } while (bind);
  snprintf (ch, sizeof(ch), ":*:%u", dcc->botnet);
  Add_Request (I_DCCALIAS, ch, 0, ".%s", NONULL(args));
  return -1;	/* no log it */
}

		/* .back */
static int dc_back (DCC_SESSION *dcc, char *args)
{
  char ch[16];

  /* free away message */
  FREE (&dcc->away);
  /* send notify to botnet */
  snprintf (ch, sizeof(ch), ":*:%u", dcc->botnet);
  Add_Request (I_DCCALIAS, ch, F_NOTICE, _("returned to life."));
  return -1;	/* no log it */
}

		/* .boot <nick on botnet> */
static int dc_boot (DCC_SESSION *dcc, char *args)
{
  INTERFACE *uif;
  userflag uf = 0;
  DCC_SESSION *udcc = NULL;
  char *msg = NULL;

  if ((uif = Find_Iface (I_CHAT, args)))
  {
    if ((udcc = (DCC_SESSION *)uif->data))
      uf = udcc->uf;
    Unset_Iface();
  }
  /* some checks */
  if (!udcc)
    msg = _("No such person at the botnet!");
  else if (uf & U_OWNER)
    msg = _("Cannot boot the bot owner!");
  else if ((uf & U_MASTER) && !(dcc->uf & U_OWNER))
    msg = _("You not permitted to boot a bot master!");
  else if (!uif->IFSignal)
    msg = _("I don't know how to boot it!");
  if (msg)
  {
    New_Request (dcc->iface, 0, msg);
    return -1;	/* no log it */
  }
  Add_Request (I_LOG, "*", F_NOTICE | F_CONN, _("%s booted by %s@%s."),
	       args, dcc->iface->name, Nick);
  uif->IFSignal (uif, S_TERMINATE);
  return 1;
}

static void
_set_console_parms (DCC_SESSION *dcc, void *user, char *fl, char *chan, unsigned int botch)
{
  char cons[SHORT_STRING];

  snprintf (cons, sizeof(cons), "%s %s %u", fl[0] ? fl : "-", chan, botch);
  if (user)			/* if console user, can not have a record */
    Set_Userfield (user, "", cons);
  Unlock_User (user);
  setdccconsole (dcc, cons);
}

		/* .chat [<botnet channel #>] */
static int dc_chat (DCC_SESSION *dcc, char *args)
{
  char consfl[64];
  char chan[IFNAMEMAX+1] = "*";
  unsigned int botch = atoi (NONULL(args));
  void *user;

  if (botch == dcc->botnet)
    return 1;
  Chat_Part (dcc);
  user = Lock_User (dcc->iface->name);
  consfl[0] = 0;
  if (user)
    sscanf (NONULL(Get_Userfield (user, "")), "%63s %s", consfl, chan);
  else
    getdccconsole (dcc, consfl, sizeof(consfl));
  _set_console_parms (dcc, user, consfl, chan, botch);
  Chat_Join (dcc);
  return 1;
}

static void _console_fl (DCC_SESSION *dcc, char *plus, char *minus, char *ch)
{
  char flags[64];
  char *cons = flags;
  register char *fl = flags;
  char chan[IFNAMEMAX+1];
  void *user;
  register int it = 0;

  minus = NONULL(minus);
  dprint (4, "dcc:_console_fl: %s %s %s %s", dcc->iface->name, plus, minus, NONULL(ch));
  user = Lock_User (dcc->iface->name);
  if (user)
    cons = Get_Userfield (user, "");
  else
  {
    getdccconsole (dcc, flags, sizeof(flags));
    ch = "*";
  }
  if (!ch)
  {
    sscanf (cons, "%*s %s", chan);
    ch = chan;
  }
  while (cons && *cons && *cons != ' ')
  {
    if (!safe_strchr (minus, *cons) && (safe_strchr (_Flags, *cons) || *cons == '+'))
      *fl++ = *cons;
    else
      it++;
    cons++;
  }
  *fl = 0;
  while (plus && *plus)
  {
    if (!safe_strchr (flags, *plus) && (safe_strchr (_Flags, *plus) ||
	*plus == '%' || *plus == '$' || *plus == '#' || *plus == '+'))
    {
      *fl++ = *plus;
      *fl = 0;
      it++;
    }
    plus++;
  }
  if (it)
    _set_console_parms (dcc, user, flags, ch, dcc->botnet);
  else
    Unlock_User (user);
}

		/* .color [off|mono|ansi|mirc] */
static int dc_color (DCC_SESSION *dcc, char *args)
{
  flag_t fl = dcc->loglev & (F_COLORCONV | F_COLOR);

  if (!args)
  {
    char *msg = "off";

    if (fl & F_COLOR)
    {
      if (fl & F_COLORCONV)
	msg = "ansi";
      else
        msg = "mirc";
    }
    else if (fl & F_COLORCONV)
      msg = "mono";
    _say_current (dcc, msg);
  }
  else
  {
    if (!safe_strcmp (args, "mirc"))
      _console_fl (dcc, NULL, "#$%", NULL);
    else if (!safe_strcmp (args, "mono"))
      _console_fl (dcc, "#", "$%", NULL);
    else if (!safe_strcmp (args, "ansi"))
      _console_fl (dcc, "%", "#$", NULL);
    else if (!safe_strcmp (args, "off"))
      _console_fl (dcc, "$", "#%", NULL);
    else return 0;
  }
  return 1;
}

		/* .console [<channel>] [+-<mode>] */
static int dc_console (DCC_SESSION *dcc, char *args)
{
  char msg[MESSAGEMAX];
  char cl[128];
  char pm[2];
  char *cc = "*";
  char *ch;
  flag_t f, fl;
  int i = 0;

  if (args)
  {
    if (*args == '#' || *args == '&')
    {
      cc = args;
      while (*cc && *cc != ' ') cc++;
      if (*cc)
      {
	*cc = 0;
	/* no such channel? */
	strfcpy (msg, args, sizeof(msg));
	*cc = ' ';
	cc = msg;
      }
      if (!Find_Iface (I_CHANNEL, cc) || Unset_Iface())
	return -1;
      args = NextWord (args);
    }
    else if (dcc->log && dcc->log->name)
      cc = dcc->log->name;
    pm[1] = cl[0] = cl[64] = 0;
    for (; *args; args++)
    {
      if (*args == '+')
	i = 1;
      else if (*args == '-')
	i = -1;
      else if (i != 0 && *args != ' ' && safe_strchr (_Flags, *args))
      {
	pm[0] = *args;
	if (i == 1)
	  strfcat (cl, pm, 64);
	else
	  strfcat (&cl[64], pm, 64);
      }
    }
    _console_fl (dcc, cl, &cl[64], cc);
  }
  fl = dcc->loglev & (F_MSGS | F_CMDS | F_CONN | F_SERV | F_WALL | F_USERS | F_DEBUG | F_CRAP | F_PUBLIC | F_JOIN | F_MODES);
  if (dcc->log && dcc->log->name && (fl & (F_PUBLIC | F_JOIN | F_MODES)))
    cc = dcc->log->name;
  else
    cc = "";
  /* reset result */
  msg[0] = cl[0] = 0;
  /* check for channel */
  if (!cc)
    cc = "";
  for (f = 1, ch = _Flags; *ch; ch++, f += f)
  {
    if (fl & f)
    {
      char *m1, *m2;

      m1 = m2 = "";
      switch (f)
      {
	case F_MSGS:
	  m1 = _("messages");
	  break;
	case F_CMDS:
	  m1 = _("commands");
	  break;
	case F_CONN:
	  m1 = _("connections/shares");
	  break;
	case F_SERV:
	  m1 = _("server messages");
	  break;
	case F_WALL:
	  m1 = _("wallops");
	  break;
	case F_USERS:
	  m1 = _("userfile changes");
	  break;
	case F_DEBUG:
	  m1 = _("debug");
	  break;
	case F_CRAP:
	  m1 = _("other crap");
	  break;
	case F_PUBLIC:
	  m2 = _("public");
	  break;
	case F_JOIN:
	  m2 = _("joins/parts");
	  break;
	default:
          m2 = _("mode changes");
      }
      if (*m1)
      {
	if (*msg)
	  strfcat (msg, ", ", sizeof(msg));
	strfcat (msg, m1, sizeof(msg));
      }
      else
      {
	if (*cl)
	  strfcat (cl, ", ", sizeof(cl));
	strfcat (cl, m2, sizeof(cl));
      }
    }
  }
  if (*cc && *cl)
    New_Request (dcc->iface, 0, "%s: %s%s%s %s %s", _("Your console logs"),
		 *msg ? msg : "", *msg ? _(", and ") : "", cl,
		 _("on the channel"), cc);
  else
    New_Request (dcc->iface, 0, "%s: %s", _("Your console logs"),
		 *msg ? msg : "none");
  return 1;
}

static void _report_req (iface_t iface)
{
  ifsig_t t = S_REPORT;

  Add_Request (iface, "*", F_SIGNAL, (char *)&t);
}

		/* .dccstat */
static int dc_dccstat (DCC_SESSION *dcc, char *args)
{
  dcc->state = D_R_DCCSTAT;
  _report_req (I_CHAT | I_DCC | I_BOT | I_LISTEN);
  New_Request (dcc->iface, 0, "\030\002");
  return 1;
}

		/* .echo [on|off] */
static int dc_echo (DCC_SESSION *dcc, char *args)
{
  flag_t fl = dcc->loglev & F_ECHO;

  if (args)
  {
    if (!safe_strcmp (args, "on"))
    {
      if (!fl)
	_console_fl (dcc, "+", NULL, NULL);
    }
    else if (!safe_strcmp (args, "off"))
    {
      if (fl)
	_console_fl (dcc, NULL, "+", NULL);
    }
    else
      return -1;
    fl = dcc->loglev & F_ECHO;
  }
  if (fl)
    _say_current (dcc, "on");
  else
    _say_current (dcc, "off");
  return 1;
}

		/* .help [<what need>] */
static int dc_help (DCC_SESSION *dcc, char *args)
{
  char *sec = NextWord (args);
  char *fst = args;

  if (args)
  {
    while (*args && *args != ' ') args++;
    *args = 0;
  }
  /* usage - not required if no arguments */
  if (args && !Get_Help (fst, sec, dcc->iface, dcc->uf,
	      Get_ChanFlags (dcc->iface->name, NULL), BT_Dcc, _("Usage: "), 0))
    return -1;
  /* full help */
  Get_Help (fst, sec, dcc->iface, dcc->uf,
	    Get_ChanFlags (dcc->iface->name, NULL), BT_Dcc, NULL, 2);
  if (sec && *sec)
    *args = ' ';
  return 1;			/* return 1 because usage at least displayed */
}

		/* .motd */
static int dc_motd (DCC_SESSION *dcc, char *args)
{
  char msg[HUGE_STRING];
  char buff[HUGE_STRING];
  register FILE *file;
  char *c, *end;

  /* get motd file to buffer msg */
  msg[0] = 0;
  if ((file = fopen (expand_path (buff, motd, sizeof(buff)), "r")))
    fread (msg, 1, sizeof(msg), file);
  if (file)
    fclose (file);
  if (!*msg)
    return -1;	/* no log it */
  msg[sizeof(msg)-1] = 0;
  /* convert all macros and out MOTD */
  printl (buff, sizeof(buff), msg, 0, NULL, SocketDomain (dcc->socket, NULL),
	  dcc->iface->name, NULL, 0L, 0, args);
  /* print out - line by line */
  for (c = buff; c; c = end)
  {
    end = strchr (c, '\n');
    if (end)
      *end++ = 0;
    New_Request (dcc->iface, 0, c);
  }
  return 1;
}

		/* .simul <Lname> <message|command> */
static int dc_simul (DCC_SESSION *dcc, char *args)
{
  DCC_SESSION *ud;
  INTERFACE *iface;
  char name[IFNAMEMAX+1];
  char *c;

  strfcpy (name, args, sizeof(name));
  for (c = name; *c && *c != ' '; c++);
  *c = 0;
  iface = Find_Iface (I_CHAT, name);
  if (!iface)
  {
    New_Request (dcc->iface, 0, _("No such user on DCC now"));
    return 0;
  }
  ud = (DCC_SESSION *)iface->data;
  Set_Iface (iface);
  args = NextWord (args);
  if (ud->state != D_CHAT || args[0] == '.')
    Dcc_Exec (ud, c, args, ud->cmdbind, ud->uf, 0, Get_DccIdx (ud));
  else
  {
    snprintf (name, sizeof(name), ":*:%d", ud->botnet);
    Add_Request (I_DCCALIAS, name, F_BOTNET, args);
  }
  Unset_Iface();		/* from Set_Iface() */
  Unset_Iface();		/* from Find_Iface() */
  return 1;
}

		/* .su <Lname> */
static int dc_su (DCC_SESSION *dcc, char *args)
{
  userflag owner = (dcc->uf & U_OWNER);
  INTERFACE *iface;
  void *user;

  user = Lock_User (args);
  if (!user || (!owner && !Get_Userfield (user, "passwd")))
  {
    Unlock_User (user);
    if (user)
      New_Request (dcc->iface, 0, _("%s has no password yet"), args);
    else
      return 0;
    return -1;
  }
  Unlock_User (user);
  /* go to su */
  iface = Add_Iface (args, dcc->iface->iface, &dcc_signal, &dcc_request, dcc);
  if (!iface)
    return 0;
  dcc_signal (dcc->iface, S_STOP);	/* stop my interface */
  iface->prev = dcc->iface;
  FREE (&dcc->away);
  dcc->iface = iface;
  dcc_signal (dcc->iface, S_FLUSH);	/* set up new interface */
  if (owner)
    Chat_Join (dcc);			/* state is not changed */
  else
  {
    dcc->state = D_PRELOGIN;
    New_Request (iface, F_QUICK, "Enter the %s's password: %s", args,
		 (iface->iface & I_TELNET) ? "" : "\377\373\001");
  }
  /* it's all? */
  pthread_mutex_lock (&SessionsLock);
  Sessions++;
  pthread_mutex_unlock (&SessionsLock);
  return 1;
}

		/* .who [<botnick>|<service>] */
static int dc_who (DCC_SESSION *dcc, char *args)
{
  char b[SHORT_STRING];

  dcc->state = D_R_WHO;
  if (args)
  {
    Add_Request (I_BOT, args, 0, "\010who");
    strfcpy (b, args, sizeof(b));
  }
  else
  {
    New_Request (dcc->iface, 0, _("Users on this channel:"));
    _report_req (I_DCCALIAS);			/* that channel users */
    _report_req (I_BOT);			/* bots connected */
    _report_req (I_CHAT);			/* other dcc chats */
    New_Request (dcc->iface, 0, "\030\002");
  }
  if (args)
    strcpy (args, b);
  return 1;
}

		/* .w [channel] */
static int dc_w (DCC_SESSION *dcc, char *args)
{
  ifsig_t t = S_REPORT;
  char b[SHORT_STRING];

  dcc->state = D_R_WHOM;
  printl (b, sizeof(b), format_w_head, 0, NULL, NULL, NULL, NULL, 0, 0, NULL);
  New_Request (dcc->iface, 0, b);
  if (args)
    snprintf (b, sizeof(b), ":*:%s", args);
  else
    snprintf (b, sizeof(b), ":*:%u", dcc->botnet);
  Add_Request (I_DCCALIAS, b, F_SIGNAL, (char *)&t);
  New_Request (dcc->iface, 0, "\030\002");
  if (args)
    strcpy (args, &b[3]);
  return 1;
}

		/* .quit [<message>] */
static int dc_quit (DCC_SESSION *dcc, char *args)
{
  dcc->iface->iface |= I_DIED;
  dcc->state = D_OK;
  strfcpy (dcc->buf, NONULL(args), sizeof(dcc->buf));
  return 1;
}

static void init_bindings (void)
{
#define NB(a,b,c) Add_Binding ("dcc", a, b, -1, &c)
  NB ("away", U_CHAT, dc_away);
  NB ("back", U_CHAT, dc_back);
  NB ("boot", U_OP, dc_boot);
  NB ("chat", U_CHAT, dc_chat);
  NB ("color", 0, dc_color);
  NB ("console", U_CHAT, dc_console);
  NB ("dccstat", U_OP, dc_dccstat);
  NB ("echo", 0, dc_echo);
  NB ("help", 0, dc_help);
  NB ("me", U_CHAT, dc_me);
  NB ("motd", 0, dc_motd);
  NB ("simul", U_OWNER, dc_simul);
  NB ("su", U_CHAT, dc_su);
  NB ("who", 0, dc_who);
  NB ("w", U_CHAT, dc_w);
  NB ("quit", 0, dc_quit);
#undef NB
}

static char __spass[20];
/* alphabet for crypt() - 64 chars */
static char __crlph[] = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM1234567890/.";

/*
 * Internal passwd bindings:
 * void func(char *pass, char **crypted)
 */
static void IntCrypt (char *pass, char **cr)
{
  register char *c = *cr;
  register unsigned int i;
  char salt[3];
  
  if (c)
    strfcpy (salt, &c[2], sizeof(salt));
  else					/* generate a new password */
  {
    i = rand();
    salt[0] = __crlph[i%64];
    salt[1] = __crlph[(i/64)%64];
    salt[2] = 0;
  }
  snprintf (__spass, sizeof(__spass), "$1%s", crypt (pass, salt));
  *cr = __spass;
}

/*
 * Internal chat-on bindings:
 * void func(DCC_SESSION *who)
 */

/*
 * Internal out-filter bindings:
 * void func(DCC_SESSION *to, char *msg, size_t msglen)
 */

#define __FGSET	1<<6
#define __BGSET	1<<7
#define __BOLD	1<<8
#define __BLINK	1<<9
#define __REV	1<<10
#define __UL	1<<11

#define ADD_COLORSTRING(a) *s++ = '\033', *s++ = '[', *s++ = a, *s++ = 'm'

static size_t _reset_colormode (register char *s, register int colormode)
{
  register size_t i = 4;

  *s++ = '\033';
  *s++ = '[';
  *s++ = '0';
  if (colormode & (__FGSET | __BGSET))	/* foregrond or background color */
  {
    if (colormode & __FGSET)
    {
      *s++ = ';';
      *s++ = '3';
      *s++ = '0' + (colormode & 7);		/* foregrond color */
      i += 3;
    }
    if (colormode & __BGSET)
    {
      *s++ = ';';
      *s++ = '4';
      *s++ = '0' + ((colormode >> 3) & 7);	/* backgrond color */
      i += 3;
    }
  }
  else if (colormode & __REV)
  {
    *s++ = ';';
    *s++ = '7';
    i += 2;
  }
  if (colormode & __BOLD)
  {
    *s++ = ';';
    *s++ = '1';
    i += 2;
  }
  if (colormode & __BLINK)
  {
    *s++ = ';';
    *s++ = '5';
    i += 2;
  }
  if (colormode & __UL)
  {
    *s++ = ';';
    *s++ = '4';
    i += 2;
  }
  *s = 'm';
  return i;
}

int mirccolors[] = {__BOLD|7, 0, 4, 2, 1, 3, 5, __BOLD|1, __BOLD|3, __BOLD|2};
int mirccolors2[] = {6, __BOLD|6, __BOLD|4, __BOLD|5, __BOLD|0, 7};

static void ConvertColors (DCC_SESSION *dcc, char *msg, size_t msglen)
{
  char buff[HUGE_STRING];
  register char *c, *s;
  register flag_t fl = (dcc->loglev & (F_COLOR | F_COLORCONV));
  int colormode;

  colormode = 0;
  msg[msglen-1] = 0;
  if (fl == F_COLOR)			/* mirc color - don't convert */
    return;
  for (c = msg, s = buff; *c && s < &buff[sizeof(buff)-17]; c++)
    switch (*c)
    {
      case '\002':		/* start/stop bold */
	if (fl)				/* ansi or mono */
	{
	  colormode ^= __BOLD;
	  if (colormode & __BOLD)
	    ADD_COLORSTRING ('1');
	  else
	    s += _reset_colormode (s, colormode);
	}
	break;
      case '\003':		/* mirc colors */
	if ((c[1] >= '0' && c[1] <= '9') ||
	    (c[1] == ',' && c[2] >= '0' && c[2] <= '9'))
	{
	  colormode &= (__BLINK | __UL);
	  if (c[1] != ',')			/* foreground */
	  {
	    c++;
	    if (fl)
	    {
	      if (fl & F_COLOR)			/* ansi */
		colormode |= __FGSET;
	      if (*c == '1' && c[1] >= '0' && c[1] < '6')
	      {
		c++;
		colormode |= mirccolors2[c[0] - '0'];
	      }
	      else
		colormode |= mirccolors[c[0] - '0'];
	    }
	    else if (*c == '1' && c[1] >= '0' && c[1] < '6')
	      c++;				/* just skip */
	  }
	  if (c[1] == ',' && c[2] >= '0' && c[2] <= '9')
	  {
	    c += 2;
	    if (fl & F_COLOR)
	    {
	      colormode |= __BGSET;		/* ansi */
	      if (*c == '1' && c[1] >= '0' && c[1] < '6')
	      {
		c++;
		colormode |= (mirccolors2[c[0] - '0'] & ~__BOLD) << 3;
	      }
	      else
		colormode |= (mirccolors[c[0] - '0'] & ~__BOLD) << 3;
	    }
	    else
	    {
	      if (*c == '1' && c[1] >= '0' && c[1] < '6')
	      {
		c++;
		if (fl && (mirccolors2[c[0] - '0'] & __BOLD))
		  colormode |= __REV;		/* mono */
	      }
	      else if (fl && (mirccolors[c[0] - '0'] & __BOLD))
		colormode |= __REV;		/* mono */
	    }
	  }
	  if (fl) s += _reset_colormode (s, colormode);
	}
	else
	{
	  if (colormode & (__FGSET | __BGSET))
	  {
	    colormode &= (__BLINK | __UL);
	    s += _reset_colormode (s, colormode);
	  }
	}
	break;
      case '\006':		/* start/stop blink */
	if (fl)				/* ansi or mono */
	{
	  colormode ^= __BLINK;
	  if (colormode & __BLINK)
	    ADD_COLORSTRING ('5');
	  else
	    s += _reset_colormode (s, colormode);
	}
	break;
      case '\017':		/* stop all colors */
	if (fl)				/* ansi or mono */
	{
	  colormode = 0;
	  ADD_COLORSTRING ('0');
	}
	break;
//      case '\005':		/* start/stop alternate chars */
//      case '\022':		/* ROM char */
//	break;
//      case '\011':		/* HT */
//      case '\007':		/* bell */
//	*s++ = *c;
//	break;
      case '\023':		/* just space */
	*s++ = ' ';
	break;
      case '\026':		/* start/stop reverse */
	if (fl)				/* ansi or mono */
	{
	  colormode ^= __REV;
	  if (colormode & __REV)
	    ADD_COLORSTRING ('7');
	  else
	    s += _reset_colormode (s, colormode);
	}
	break;
      case '\037':		/* start/stop underline */
	if (fl)				/* ansi or mono */
	{
	  colormode ^= __UL;
	  if (colormode & __UL)
	    ADD_COLORSTRING ('4');
	  else
	    s += _reset_colormode (s, colormode);
	}
	break;
      default:
	if (*c == '\011' || *c == '\007' || *c > '\037')
	  *s++ = *c;		/* supress control codes but HT and bell */
    }
  if (colormode)		/* has ansi or mono color codes */
  {
    if (s > &buff[msglen-8])
      s = &buff[msglen-8];
    snprintf (s, 8, "\033[0;10m");
  }
  else
    *s = 0;
  strfcpy (msg, buff, msglen);
}

/* Config/scripts functions... */
static int _dellistenport (char *pn)
{
  ifsig_t sig = S_TERMINATE;
  INTERFACE *pi;

  if (!(pi = Find_Iface (I_LISTEN, pn)))
    return 0;
  New_Request (pi, F_SIGNAL, (char *)sig);
  Unset_Iface();
  return 1;
}

ScriptFunction (FE_port)	/* to config - see thrdcc_signal() */
{
  unsigned short port;
  char pn[8];
  static char msg[SHORT_STRING];
  DCC_SESSION *dcc;
  userflag u = U_ANY | U_BOT;

  if (!args || !*args)
    return 0;
  while (*args == '-')
  {
    if (args[1] == 'd')
      u = 0;
    else if (args[1] == 'b')
      u &= ~U_ANY;
    args = NextWord (args);
  }
  port = atoi (args);
  if (port < 1024)
    return 0;
  snprintf (pn, sizeof(pn), "%hu", port);
  args = NextWord (args);
  if (u == 0)
    return _dellistenport (pn);
  /* check if already exist */
  if (Find_Iface (I_LISTEN, pn))
  {
    Unset_Iface();
    Add_Request (I_LOG, "*", F_CONN, _("Already listening on port %s!"), pn);
    return port;
  }
  dcc = safe_calloc (1, sizeof(DCC_SESSION));
  dcc->socket = AddSocket (M_LIST, hostname, port);
  dcc->uf = u;
  dcc->away = NULL;
  dcc->iface = Add_Iface (pn, I_LISTEN, &thrdcc_signal, NULL, dcc);
  if (dcc->socket < 0 || !dcc->iface ||
      pthread_create (&dcc->th, NULL, &listen_port, dcc))
  {
    snprintf (msg, sizeof(msg), _("Cannot open listening port on %hu%s!"),
	      port, (dcc->uf & U_ANY) ? "" : _(" for bots"));
    BindResult = msg;
    KillSocket (&dcc->socket);
    dcc->iface->iface |= I_DIED;
    return 0;
  }
  Add_Request (I_LOG, "*", F_CONN, _("Listening on port %s%s."),
	       pn, (dcc->uf & U_ANY) ? "" : _(" for bots"));
  return port;
}

char *IFInit_DCC (void)
{
  struct hostent *hptr;

  if (!ip_local)			/* sockets are initialized? */
  {
    if ((!*hostname && gethostname (hostname, sizeof(hostname))) ||
	(fe_init_sockets ()))
      return _("Cannot get hostname!");
    /* fix the Linux/Alpha gethostname() bug */
    hostname[sizeof(hostname)-1] = 0;
    if (!(hptr = gethostbyname (hostname)))
      return _("Cannot resolve own IP!");
    ip_local = ntohl (*hptr->h_addr_list[0]);
  }
  /* add own bindtables */
  BT_Dcc = Add_Bindtable ("dcc", B_UNIQ);		/* this tables have bindings */
  init_bindings();
  BT_Crypt = Add_Bindtable ("passwd", B_UNIQMASK);
  Add_Binding ("passwd", "$1*", 0, 0, (Function)&IntCrypt);
  BT_Login = Add_Bindtable ("login", B_MASK);
  Add_Binding ("login", "*", U_CHAT, -1, (Function)&GetChat);
  BT_Chaton = Add_Bindtable ("chat-on", B_MASK);
  BT_Outfilter = Add_Bindtable ("out-filter", B_MASK);
  Add_Binding ("out-filter", "*", 0, 0, (Function)&ConvertColors);
  BT_Chat = Add_Bindtable ("chat", B_MASK);		/* rest are empty */
  BT_Infilter = Add_Bindtable ("in-filter", B_MASK);
  BT_Chatoff = Add_Bindtable ("chat-off", B_MASK);
  BT_Chatact = Add_Bindtable ("chat-act", B_MASK);
  BT_Chatjoin = Add_Bindtable ("chat-join", B_MASK);
  BT_Chatpart = Add_Bindtable ("chat-part", B_MASK);
  BT_Upload = Add_Bindtable ("dcc-got", B_MASK);
  flood_dcc = FloodType ("dcc");
  Add_Bindtable ("ctcp", B_UNIQ);
  Add_Binding ("ctcp", "dcc", U_ANY, -1, &IncomingDCC);
  Add_Binding ("ctcp", "chat", U_CHAT, -1, &OutgoingDCC);
  return NULL;
}
