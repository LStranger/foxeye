/*
 * Copyright (C) 1999-2006  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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

#include "socket.h"
#include "direct.h"
#include "init.h"
#include "sheduler.h"
#include "list.h"
#include "wtmp.h"
#include "conversion.h"

typedef struct
{
  peer_t s;
  flag_t loglev;
  int botnet;				/* botnet channel, chat off if < 0 */
  short floodcnt;			/* flood counter */
  INTERFACE *log;			/* interface for logs */
  INTERFACE *alias;			/* interface for botnet channel */
  char *netname;			/* service name (for "ss-*") */
  bindtable_t *ssbt;			/* network-specitic bindtable */
} session_t;

static bindtable_t *BT_Crypt;
static bindtable_t *BT_Dcc;
static bindtable_t *BT_Chat;
static bindtable_t *BT_Chatact;
static bindtable_t *BT_Outfilter;
static bindtable_t *BT_Infilter;
static bindtable_t *BT_Login;
static bindtable_t *BT_Chaton;
static bindtable_t *BT_Chatoff;
static bindtable_t *BT_Chatjoin;
static bindtable_t *BT_Chatpart;
static bindtable_t *BT_Connect;

/* returns char appropriated to userflag */
static char _userdccflag (userflag uf)
{
  if (uf & U_OWNER)
    return '*';
  else if (uf & U_MASTER)
    return '+';
  else if (uf & U_HALFOP)
    return '%';
  else if (uf & U_OP)
    return '@';
  return '-';
}

#define DccIdx(a) (int)(((peer_t *)a)->socket + 1)

void Chat_Join (INTERFACE *iface, userflag uf, int botnet, int idx, char *host)
{
  register binding_t *bind = NULL;
  char *on_bot;
  char l[SHORT_STRING];
  char ch[16];
  char *name = NULL;

  /* what??? */
  if (!iface)
    return;
  name = iface->name;
  if ((on_bot = safe_strchr (name, '@')))
    on_bot++;
  else
    on_bot = Nick;
  snprintf (ch, sizeof(ch), ":*:%d", botnet);
  dprint (4, "dcc:Chat_Join: %s joining %d", name, botnet);
  Set_Iface (iface);
  /* run bindtable */
  snprintf (l, sizeof(l), "%c %d %s", _userdccflag (uf), idx, host);
  do
  {
    if ((bind = Check_Bindtable (BT_Chatjoin, &ch[3], -1, -1, bind)))
    {
      if (bind->name)
        RunBinding (bind, NULL, on_bot, name, botnet, l);
      else
        bind->func (iface, botnet, host);
    }
  } while (bind);
  /* notify local botnet users! */
  if (botnet >= 0)
    Add_Request (I_DCCALIAS, ch, F_T_NOTICE, _("joined this botnet channel."));
  Unset_Iface();
}

static void _chat_join (session_t *dcc)
{
  char ch[16];

  Chat_Join (dcc->s.iface, dcc->s.uf, dcc->botnet, DccIdx(dcc),
	     SocketDomain (dcc->s.socket, NULL));
  /* start getting the messages from botnet channel */
  if (dcc->alias)
  {
    snprintf (ch, sizeof(ch), ":%d:%d", DccIdx(dcc), dcc->botnet);
    FREE (&dcc->alias->name);
    dcc->alias->name = safe_strdup (ch);
  }
}

void Chat_Part (INTERFACE *iface, int botnet, int idx, char *quit)
{
  register binding_t *bind = NULL;
  char *on_bot;
  char ch[16];
  char *name = NULL;

  /* what??? */
  if (!iface)
    return;
  name = iface->name;
  if ((on_bot = safe_strchr (name, '@')))
    on_bot++;
  else
    on_bot = Nick;
  dprint (4, "dcc:Chat_Part: %s parting %d", name, botnet);
  snprintf (ch, sizeof(ch), ":*:%d", botnet);
  /* notify the botnet! */
  Set_Iface (iface);
  /* if quit - send the formed notice */
  if (botnet < 0);
  else if (quit)
    Add_Request (I_DCCALIAS, ch, F_T_NOTICE, _("quit botnet: %s"), quit);
  else
    Add_Request (I_DCCALIAS, ch, F_T_NOTICE, _("left this botnet channel."));
  /* run bindtable */
  do
  {
    if ((bind = Check_Bindtable (BT_Chatpart, &ch[3], -1, -1, bind)))
    {
      if (bind->name)
        RunBinding (bind, NULL, on_bot, name, idx, &ch[3]);
      else
        bind->func (iface, botnet);
    }
  } while (bind);
  Unset_Iface();
}

static void _chat_part (session_t *dcc)
{
  char ch[16];

  /* stop getting the messages */
  if (dcc->alias)
  {
    snprintf (ch, sizeof(ch), ":%d", DccIdx(dcc));
    FREE (&dcc->alias->name);
    dcc->alias->name = safe_strdup (ch);
  }
  Chat_Part (dcc->s.iface, dcc->botnet, DccIdx(dcc),
	     dcc->s.state != P_LASTWAIT ? NULL : dcc->s.inbuf ? dcc->s.buf : _("no reason."));
}

static char _Flags[] = FLAG_T;

/*
 * Set console state from saved value: "loglevel IRCchannel BotChannel"
 */
static void setconsole (session_t *dcc)
{
  register flag_t logl = F_COLOR;	/* color mirc by default */
#if 1
  flag_t maskfl = (F_JOIN | F_MODES | F_ECHO | F_COLOR | F_COLORCONV);
#else
  flag_t maskfl = -1;
#endif
  register char *fl;
  int botch;
  char chan[128];
  userflag cf;
  clrec_t *user;
  char *line;

  /* return if arguments are invalid */
  if ((user = Lock_Clientrecord (dcc->s.iface->name)))
    line = Get_Field (user, "", NULL);
  else
    line = NULL;
  if (line && sscanf (line, "%*s %127s %d", chan, &botch) == 2)
  {
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
	  if ((fl = strchr (_Flags, *line)))
	    logl |= F_MIN<<(fl-_Flags);
      }
      line++;
    }
    if (user) {
      cf = Get_Flags (user, chan);
      Unlock_Clientrecord (user);
    }
    else
      cf = 0;
#if 1
    if (dcc->s.uf & U_OWNER)
      maskfl |= (F_BOOT | F_DEBUG);
    if ((dcc->s.uf & U_MASTER) || (cf & U_MASTER))
      maskfl |= (F_CMDS | F_USERS | F_ERROR | F_WARN);
    if ((dcc->s.uf & U_OP) || (cf & U_OP))
      maskfl |= (F_CONN | F_PUBLIC | F_WALL | F_PRIV | F_SERV);
#else
    if (!(dcc->s.uf & U_OWNER))
      maskfl &= ~(F_BOOT | F_DEBUG);
    if (!(dcc->s.uf & U_MASTER) && !(cf & U_MASTER))
      maskfl &= ~(F_CMDS | F_USERS | F_ERROR | F_WARN);
    if (!(dcc->s.uf & U_OP) && !(cf & U_OP))
      maskfl &= ~(F_CONN | F_PUBLIC | F_WALL | F_PRIV | F_SERV);
#endif
    logl &= maskfl;
    if ((logl & F_DEBUG) && O_DLEVEL > 2)
    {
      New_Request (dcc->s.iface, F_T_NOTICE,
	      "Debug level is too high for DCC CHAT, switching debug log off");
      logl &= ~F_DEBUG;
    }
    /* set DCC session console parameters */
    dcc->botnet = botch;
    if (dcc->log)
    {
      FREE (&dcc->log->name);
      dcc->log->name = safe_strdup (chan);
      /* now get network name and "ss-*" bindtable */
      if (dcc->log->name && (line = strrchr (dcc->log->name, '@')))
	line++;
      else
	line = dcc->log->name;
      snprintf (chan, sizeof(chan), "@%s", NONULL(line));
      if ((user = Lock_Clientrecord (chan)))
      {
	dcc->netname = dcc->log->name;
	if ((line = Get_Field (user, ".logout", NULL)))
	{
	  snprintf (chan, sizeof(chan), "irc-%s", line);
	  dcc->ssbt = Add_Bindtable (chan, B_UNIQ);
	}
	Unlock_Clientrecord (user);
      }
      else
	dcc->netname = NULL;
    }
  }
  else if (user)
    Unlock_Clientrecord (user);
  dcc->loglev = logl;
}

static char *getconsole (session_t *dcc, char *str, size_t sz)
{
  register int i;
  register char *s = str;
  register flag_t f = F_MIN;

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

#define LOG_CONN(a...) Add_Request (I_LOG, "*", F_CONN, ##a)

/* if s==0 then quiet termination (shutdown sequence) */
static void _died_iface (INTERFACE *iface, char *buf, size_t s)
{
  binding_t *bind = NULL;
  session_t *dcc = (session_t *)iface->data;
  userflag cf = 0;

  if (!dcc || dcc->s.socket == -1)		/* is it already killed? */
    return;
  iface = dcc->s.iface;				/* to the right one! */
  iface->ift |= I_DIED;
  iface->ift &= ~I_DIRECT;
  dcc->s.state = P_LASTWAIT;
  if (dcc->log)					/* down log interface */
  {
    dcc->log->data = NULL;
    dcc->log->ift |= I_DIED;
    dcc->netname = NULL;
    dcc->ssbt = NULL;
  }
  if (dcc->alias)				/* down script alias for iface */
  {
    dcc->alias->data = NULL;
    dcc->alias->ift |= I_DIED;
  }
  CloseSocket (dcc->s.socket);			/* kill the socket */
  if (s == 0)					/* is this shutdown call? */
    return;
  dprint (4, "dcc:_died_iface: %s", iface->name);
  KillSocket (&dcc->s.socket);
  /* %L - login nick, %@ - hostname */
  printl (buf, s, format_dcc_lost, 0, NULL,
	  SocketDomain (dcc->s.socket, NULL), iface->name, NULL, 0, 0, 0, NULL);
  LOG_CONN (buf);
  NoCheckFlood (&dcc->floodcnt);		/* remove all flood timers */
  if (dcc->s.state == P_LOGIN)			/* if it was fresh connection */
    return;
  NewEvent (W_END, GetLID (iface->name), ID_ME, 0); /* log to Wtmp */
  /* now run "chat-part" and "chat-off" bindings... */
  if (dcc->log)
    cf = Get_Clientflags (iface->name, dcc->log->name);
  _chat_part (dcc);
  do
  {
    if ((bind = Check_Bindtable (BT_Chatoff, iface->name, dcc->s.uf, cf, bind)))
    {
      if (bind->name)
        RunBinding (bind, NULL, iface->name, NULL, DccIdx(dcc), NULL);
      else
        bind->func (dcc);
    }
  } while (bind);
}

ssize_t Session_Put (peer_t *dcc, char *line, size_t sz)
{
  ssize_t i = 0;
  binding_t *bind;

  if (dcc->inbuf &&
      (i = WriteSocket (dcc->socket, dcc->buf, &dcc->bufpos, &dcc->inbuf, M_RAW)) < 0)
    return i;
  if (i)
    dprint (5, "put to peer %s: \"%.*s\"", dcc->iface->name, i, dcc->buf);
  if (dcc->inbuf > 0 || sz == 0)		/* cannot put message to buf */
    return 0;
  if (sz > sizeof(dcc->buf) - 1)		/* we cannot overwrite buffer */
    sz = sizeof(dcc->buf) - 1;
  if (line != dcc->buf)
    memmove (dcc->buf, line, sz);
  i = sz;
  dcc->buf[i] = 0;				/* for bindings */
  /* run "out-filter" bindings... */
  bind = NULL;
  do
  {
    bind = Check_Bindtable (BT_Outfilter, dcc->buf, dcc->uf, 0, bind);
    if (bind && !bind->name)
    {
      bind->func (dcc, dcc->buf, sizeof(dcc->buf) - 1);
      i = strlen (dcc->buf);
    }
  } while (i && bind);
  if (!i)
    return sz;					/* assume it's done */
  if (i > sizeof(dcc->buf) - 2)			/* for CR+LF */
    i = sizeof(dcc->buf) - 2;
  dcc->buf[i] = '\r';
  dcc->buf[i+1] = '\n';
  dcc->inbuf = i + 2;
  dcc->bufpos = 0;
  i = WriteSocket (dcc->socket, dcc->buf, &dcc->bufpos, &dcc->inbuf, M_RAW);
  if (i > 0)
    dprint (5, "put to peer %s: \"%.*s\"", dcc->iface->name, i, dcc->buf);
  return (i < 0) ? i : sz;
}

ssize_t Session_Get (peer_t *dcc, char *line, size_t sz)
{
  ssize_t sw;
  binding_t *bind;

  sw = ReadSocket (line, dcc->socket, sz, M_TEXT);
  if (sw > 0)
  {
    dprint (5, "got from peer %s: \"%.*s\"", dcc->iface->name, sw, line);
    /* TODO: see RFC854 ;) */
    if ((dcc->iface->ift & I_TELNET) && !safe_strncmp (line, "\377\376\001", 3))
    {
      sw -= 3;
      memmove (line, &line[3], sw);	/* ignore TELNET response */
      line[sw] = 0;
    }
    dcc->last_input = Time;		/* timestamp for idle */
    /* run "in-filter" bindings... */
    bind = NULL;
    do
    {
      bind = Check_Bindtable (BT_Infilter, line, dcc->uf, 0, bind);
      if (bind)
      {
	if (bind->name)
	{
	  if (RunBinding (bind, NULL, NULL, NULL, DccIdx(dcc), line))
	    strfcpy (line, BindResult, sz);
	}
	else
	  bind->func (dcc, line, sz);
      }
    } while (bind);
    sw = strlen (line);
  }
  return sw;
}

/* it's really static but it's used by console too :( */
/* note that first argument is really session_t * type unless it's console */
void Dcc_Parse (peer_t *dcc, char *name, char *cmd, userflag gf, userflag cf,
		int dccidx, int botch, bindtable_t *ssbt, char *service)
{
  char *arg;
  binding_t *bind;
  INTERFACE *sif;
  int res;

  dprint (4, "dcc:Dcc_Parse: %s", cmd);
  if (cmd[0] == '.')
  {
    arg = NextWord (++cmd);
    if (!*arg)
      arg = NULL;
    if (ssbt && service && (bind = Check_Bindtable (ssbt, cmd, gf, cf, NULL)) &&
	(sif = Find_Iface (I_SERVICE, service)))
    {
      if (!bind->name)
	res = bind->func (dcc, sif, arg);
      else
	res = 0;
      Unset_Iface();
      if (res == 0)
	Get_Help (Bindtable_Name (ssbt), bind->key, dcc->iface, gf, cf, ssbt,
		  _("Usage: "), 0);
    }
    else
    {
      ssbt = NULL;
      bind = Check_Bindtable (BT_Dcc, cmd, gf, cf, NULL);
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
	Get_Help (bind->key, NULL, dcc->iface, gf, cf, BT_Dcc, _("Usage: "), 0);
    }
    if (res > 0)
      Add_Request (I_LOG, "*", F_CMDS, "#%s# %s %s", name, bind->key,
		   NONULL(arg));
  }
  else if (botch >= 0)
  {
    char to[12];

    for (bind = NULL; ((bind = Check_Bindtable (BT_Chat, cmd, gf, cf, bind))); )
      if (bind->name)
	RunBinding (bind, NULL, name, NULL, dccidx, cmd);
      else
	bind->func (dcc, cmd);
    snprintf (to, sizeof(to), ":*:%d", botch);
    Add_Request (I_DCCALIAS, to, F_BOTNET, cmd);
  }
}

/*
 * get message for user, if it is
 * to me or from another user on same botnet channel to "*"
 * used also when such command as "su" or "files" is in progress
 */
static int dcc_request (INTERFACE *iface, REQUEST *req)
{
  session_t *dcc = (session_t *)iface->data;
  ssize_t sw;
  binding_t *bind = NULL;
  userflag cf = 0;
  char *cmd;
  volatile int to_all;
  char buf[MESSAGEMAX];
#ifdef HAVE_ICONV
  char sbuf[MESSAGEMAX];
#endif

  if (dcc->s.state == P_LASTWAIT)	/* already killed */
    return REQ_OK;
  if (dcc->s.state == P_LOGIN)		/* init the client session */
  {
    register char *name = dcc->s.iface->name;

    dcc->s.state = P_TALK;
    setconsole (dcc);
    if (dcc->log)
      cf = Get_Clientflags (name, dcc->log->name);
    else
      cf = 0;
    /* run "chat-on" and "chat-join" bindings... */
    bind = NULL;
    if (!dcc->s.iface->prev) do		/* it might be tricked so check it */
    {
      if ((bind = Check_Bindtable (BT_Chaton, name, dcc->s.uf, cf, bind)))
      {
	if (bind->name)
	  RunBinding (bind, NULL, name, NULL, DccIdx(dcc), NULL);
	else
	  bind->func (dcc);
      }
    } while (bind);
    _chat_join (dcc);
    LOG_CONN (_("Logged in: %s."), name);
    /* log to Wtmp */
    NewEvent (W_START, GetLID (name), ID_ME, 0);
  }
  /* check if this is mine but echo disabled */
  if (req)
  {
    to_all = Have_Wildcard (req->to) + 1;
    /* check if this is: not for me exactly, but from me and no echo */
    if (to_all && req->from == dcc->s.iface && (req->mask_if & I_DCCALIAS) &&
	!(dcc->loglev & F_ECHO))
      req = NULL;
  }
  if (dcc->log && dcc->log->name)
    cf = Get_Clientflags (dcc->s.iface->name, dcc->log->name);
  if (dcc->s.inbuf || req)		/* do we have something to out? */
  {
    sw = Session_Put (&dcc->s, NULL, 0);
    if (sw >= 0 &&			/* socket not died */
	!dcc->s.inbuf &&		/* nothing to send yet */
	req)				/* there is a request */
    {
      /* for logs... formatted, just add timestamp */
      if (req->mask_if & I_LOG)
      {
	if (req->flag & dcc->loglev)
	  printl (dcc->s.buf, sizeof(dcc->s.buf) - 1, "[%t] %*", 0,
		  NULL, NULL, NULL, NULL, 0, 0, 0, req->string);
	req = NULL;
      }
      /* flush command - see the users.c, ignore commands for non-bots */
      else if (req->string[0] == '\010')
      {
	dcc->s.iface->IFSignal (dcc->s.iface, S_FLUSH);
	dcc->s.buf[0] = 0;
	req = NULL;
      }
      /* for chat channel messages */
      else if (to_all && req->from && (req->from->ift & I_DIRECT) &&
	       (req->mask_if & I_DCCALIAS))
      {
	char *prefix;
	char *suffix = "";
	char *str = req->string;

	switch (req->flag & F_T_MASK)
	{
	  case F_T_NOTICE:
	    prefix = "*** ";
	    break;
	  case F_T_ACTION:
	    prefix = "* ";
	    break;
	  default:
	    prefix = "<";
	    suffix = ">";
	}
	snprintf (dcc->s.buf, sizeof(dcc->s.buf) - 1, "%s%s%s %s", prefix,
		  req->from->name, suffix, str);
	req = NULL;
      }
      /* direct messages or reports */
      if (req)
	sw = Session_Put (&dcc->s, req->string, strlen (req->string));
      else
	sw = Session_Put (&dcc->s, dcc->s.buf, strlen (dcc->s.buf));
      req = NULL;				/* request done! */
    }
    if (sw < 0)			/* error, kill dcc... */
    {
      _died_iface (iface, buf, sizeof(buf));
      return REQ_OK;
    }
    /* don't input until empty buffer */
    else if (req)
      return REQ_REJECTED;
  }
  /* don't check input if this is interface shadow */
  if (!(iface->ift & ~(I_DCCALIAS | I_LOG)))
    return REQ_OK;
  /* we sent the message, can P_INITIAL -> P_LOGIN */
  if (dcc->s.state == P_INITIAL)
  {
    dcc->s.state = P_LOGIN;
    return REQ_OK;
  }
  sw = Session_Get (&dcc->s, buf, sizeof(buf));
  if (sw < 0)
  {
    _died_iface (iface, buf, sizeof(buf));
    return REQ_OK;
  }
  if (!sw)
    return REQ_OK;
  /* check the "dcc" flood... need just ignore or break connection? TODO? */
  if (CheckFlood (&dcc->floodcnt, flood_dcc) > 0)
    return REQ_OK;
#ifdef HAVE_ICONV
  /* do conversion now */
  cmd = sbuf;
  sw = Do_Conversion (iface->conv, &cmd, sizeof(sbuf) - 1, buf, sw);
  cmd[sw] = 0;
#else
  cmd = buf;
#endif
  /* run "dcc" and "chat" bindings... */
  dcc->s.parse (&dcc->s, iface->name, cmd, dcc->s.uf, cf, DccIdx(dcc),
		dcc->botnet, dcc->ssbt, dcc->netname);
  return REQ_OK;
}

/*
 * if signal == S_TERMINATE then also down iface->data->log interface
 * if signal == S_FLUSH then just update user info from userfile
 * S_SHUTDOWN, S_REPORT - as default...
 */
static iftype_t dcc_signal (INTERFACE *iface, ifsig_t signal)
{
  session_t *dcc = (session_t *)iface->data;
  userflag gf;
  char c[LNAMELEN+2];
  char buf[STRING];
  int idle;
  INTERFACE *tmp;
  unsigned short p;
  char *dom, *desc;

  if (!dcc || dcc->s.socket == -1)	/* already killed? */
    return I_DIED;
  if (dcc) switch (signal)
  {
    case S_FLUSH:
      if (iface->name && *iface->name)
      {
	gf = Get_Clientflags (iface->name, NULL);
	if (gf != dcc->s.uf)
	  dcc->s.uf = gf;
	/* check the IRC and botnet channels */
	setconsole (dcc);
      }
      break;
    case S_REPORT:
      switch (dcc->s.state)
      {
        case P_LOGIN:
	  /* %@ - hostname, %L - Lname, %* - state */
	  printl (buf, sizeof(buf), ReportFormat, 0,
		  NULL, SocketDomain (dcc->s.socket, NULL), dcc->s.iface->name,
		  NULL, 0, 0, 0, "logging in");
	  break;
	default:
	  idle = Time - dcc->s.last_input;
	  dom = SocketDomain (dcc->s.socket, &p);
	  if (dcc->s.dname && !(dcc->s.iface->ift & I_LOCKED))
	  {
	    desc = safe_malloc (strlen (dcc->s.dname) + 7);
	    strcpy (desc, "away: ");
	    strcpy (&desc[7], dcc->s.dname);
	  }
	  else
	    desc = NULL;
	  c[0] = _userdccflag (dcc->s.uf);
	  strfcpy (&c[1], dcc->s.iface->name, sizeof(c)-1);
	  /* %@ - hostname, %L - Lname, %# - start time, %I - socket number,
	     %P - port, %- - idle time, %* - state */
	  printl (buf, sizeof(buf), ReportFormat, 0,
		  NULL, dom, c, dcc->s.start, (uint32_t)dcc->s.socket, p,
		  idle, (dcc->s.iface->ift & I_LOCKED) ? "chat off" : desc);
	  FREE (&desc);
      }
      tmp = Set_Iface (iface);
      New_Request (tmp, F_REPORT, "%s", buf);
      Unset_Iface();
      break;
    case S_STOP:
      /* stop the interface */
      iface->ift |= I_LOCKED;
      dcc->log->ift |= I_LOCKED;
      _chat_part (dcc);				/* has left botnet channel */
      break;
    case S_CONTINUE:
      /* restart the interface - only if user has partyline access */
      dcc_signal (iface, S_FLUSH);		/* recursive call */
      dcc->s.parse = &Dcc_Parse;
      iface->ift &= ~I_LOCKED;
      dcc->log->ift &= ~I_LOCKED;
      if (dcc->s.state != P_LASTWAIT)		/* has socket died? */
      {
	dcc->s.state = P_TALK;
	_chat_join (dcc);			/* has returned to channel */
	break;
      }						/* else terminate it */
    case S_TERMINATE:
      /* .quit might left message in dcc->s.buf */
      if (!(iface->ift & I_DIED))
	dcc->s.inbuf = 0;
      _died_iface (iface, buf, sizeof(buf));
      FREE (&dcc->s.dname);
      return I_DIED;
    case S_SHUTDOWN:
      /* try to sent shutdown message and quiet shutdown anyway */
      if (signal == S_SHUTDOWN && ShutdownR)
      {
	strfcpy (dcc->s.buf, ShutdownR, sizeof(dcc->s.buf));
	strfcat (dcc->s.buf, "\r\n", sizeof(dcc->s.buf));
	dcc->s.inbuf = strlen (dcc->s.buf);
	dcc->s.bufpos = 0;
	WriteSocket (dcc->s.socket, dcc->s.buf, &dcc->s.bufpos, &dcc->s.inbuf, M_RAW);
      }
      _died_iface (iface, NULL, 0);
    default: ;
  }
  return 0;
}

#define IS_SESSION(a) (((peer_t *)a)->iface->IFSignal == dcc_signal)

static iftype_t dcclog_signal (INTERFACE *iface, ifsig_t signal)
{
  if (signal == S_TERMINATE)
  {
    iface->data = NULL;
    iface->ift |= I_DIED;
    return I_DIED;
  }
  return 0;
}

static iftype_t dccalias_signal (INTERFACE *iface, ifsig_t signal)
{
  peer_t *dcc = (peer_t *)iface->data;

  if (dcc == NULL || signal == S_TERMINATE)
  {
    iface->data = NULL;
    iface->ift |= I_DIED;
    return I_DIED;
  }
  else if (signal == S_REPORT)
  {
    if (dcc->iface && dcc->iface->IFSignal)
      dcc->iface->IFSignal (iface, signal);
  }
  return 0;
}

int Check_Passwd (const char *pass, char *encrypted)
{
  char *upass = NULL;
  binding_t *bind = Check_Bindtable (BT_Crypt, encrypted, -1, -1, NULL);

  if (bind && !bind->name)
  {
    upass = encrypted;
    bind->func (pass, &upass);
  }
  return safe_strcmp (encrypted, upass);
}

/*
 * Internal login bindings:
 * void func(char *who, char *ident, char *host, idx_t socket, char *buf, char **msg)
 */

/* called from threads and dispatcher is locked! */
/* buf is Lname if this is CTCP CHAT answer or empty string */
static void get_chat (char *name, char *ident, char *host, idx_t socket,
		      char buf[SHORT_STRING], char **msg)
{
  ssize_t sz;
  size_t sp;
  iftype_t i = I_DIRECT | I_CONNECT;
  time_t t;
  int telnet;
  userflag uf;
  session_t *dcc;
  clrec_t *user;

  /* turn off echo if telnet and check password */
  t = time(NULL) + dcc_timeout;
  Unset_Iface();
  /* check if user has password set */
  user = Lock_Clientrecord (name);
  if (!user)
  {
    *msg = "no such user";		/* user was deleted? */
    return;
  }
  ident = Get_Field (user, "passwd", NULL); /* we don't need ident anymore */
  Unlock_Clientrecord (user);
  if (!ident)
  {
    *msg = "user has no password yet";
    return;
  }
  if (*buf)
    telnet = 0;
  else
    telnet = 1;
  snprintf (buf, SHORT_STRING, "Password: %s", telnet ? "\377\373\001" : "\r\n");
  sz = strlen (buf);					/* IAC WILL ECHO */
  sp = 0;
  while (sz &&
	 WriteSocket (socket, buf, &sp, (size_t *)&sz, M_POLL) >= 0 &&
	 time(NULL) < t);
  /* wait password and check it */
  while (sz == 0 && time(NULL) < t)
  {
    sz = ReadSocket (buf, socket, SHORT_STRING-1, M_POLL);
    if (sz == 3)
      sz = 0;
  }
  if (sz > 0)
  {
    register size_t s;
    for (s = 0; s < sz; s++)
      if (buf[s] == '\r')
	buf[s] = 0;
  }
  if (sz < 0)
  {
    *msg = "connection lost";
    return;
  }
  else if (sz == 0 || sz == E_AGAIN)
  {
    *msg = "login timeout";
    return;
  }
  if (telnet && !strncmp (buf, "\377\375\001", 3))
    sz = 3;
  else
    sz = 0;
  user = Lock_Clientrecord (name);
  if (!user)
  {
    *msg = "no such user";		/* user was deleted? */
    return;
  }
  ident = safe_strdup (Get_Field (user, "passwd", NULL));
#ifdef HAVE_ICONV
  host = safe_strdup (Get_Field (user, "charset", NULL));
#endif
  name = safe_strdup (Get_Field (user, NULL, NULL)); /* unaliasing */
  uf = Get_Flags (user, NULL);
  Unlock_Clientrecord (user);
  Set_Iface (NULL);			/* lock dispatcher to get bindtable */
  sz = Check_Passwd (&buf[sz], ident);
  Unset_Iface();
  FREE (&ident);
  if (sz)
  {
    FREE (&name);
#ifdef HAVE_ICONV
    FREE (&host);
#endif
    *msg = "authentication failed";	/* password does not match */
    return;
  }
  /* now it logged in so enable echo, create session and interface */
  dcc = safe_malloc (sizeof(session_t));
  dcc->s.state = P_LOGIN;
  dcc->s.uf = uf;
  dcc->s.dname = NULL;
  dcc->s.socket = socket;
  dcc->s.parse = &Dcc_Parse;
  time (&dcc->s.last_input);
  dcc->floodcnt = 0;
  dcc->netname = NULL;
  dcc->ssbt = NULL;
  if (telnet)
  {
    dprint (5, "enabling echo for user");
    memcpy (dcc->s.buf, "\377\374\001\r\n", 5);		/* IAC WON'T ECHO */
    dcc->s.inbuf = 5;
    i |= I_TELNET;
  }
  else
    dcc->s.inbuf = 0;
  /* create interfaces - lock dispatcher to syncronize */
  Set_Iface (NULL);
  strfcpy (dcc->s.start, DateString, sizeof(dcc->s.start));
  dcc->s.iface = Add_Iface (i, name, &dcc_signal, &dcc_request, (void *)dcc);
#ifdef HAVE_ICONV
  dcc->s.iface->conv = Get_Conversion (host);
#endif
  /* try to create the alias for scripts :) */
  dcc->alias = Add_Iface (I_DCCALIAS, NULL, &dccalias_signal, &dcc_request,
			  (void *)dcc);
  /* the same for logs */
  dcc->log = Add_Iface (I_LOG, NULL, &dcclog_signal, &dcc_request, (void *)dcc);
  Unset_Iface();
  FREE (&name);
#ifdef HAVE_ICONV
  FREE (&host);
#endif
  /* now we cannot touch any dcc fields since interface can be ran */
  *msg = NULL;
}

/*
 * internal handler for peer_t (in a thread!)
 *   client is NULL since it's listening port
 *   ident, host, and socket are from connection
 */
static void session_handler (char *ident, char *host, idx_t socket, int botsonly)
{
  char buf[SHORT_STRING];
  char client[NAMEMAX+1];
  userflag uf;
  binding_t *bind;
  size_t sz, sp;
  ssize_t get = 0;
  time_t t;
  char *msg;
  clrec_t *clr;

  /* we have no client name at this point */  
  uf = Match_Client (host, ident, NULL);	/* check ident@domain */
  if (drop_unknown)
  {
    Set_Iface (NULL);
    bind = Check_Bindtable (BT_Login, "*", uf, 0, NULL);
    Unset_Iface();
    if (!(bind && (!botsonly || (uf & U_BOT))))
    {
      Add_Request (I_LOG, "*", F_CONN,
		   _("Connection from %s dropped: not allowed."), host);
      KillSocket (&socket);
      return;
    }
  }
  /* get Lname of user */
  strfcpy (buf, "\r\nFoxEye network node\r\n\r\nlogin: ", sizeof(buf));
  sz = strlen (buf);
  sp = 0;
  time (&t);
  Set_Iface (NULL);
  t += dcc_timeout;
  Unset_Iface();
  while (sz && (get = WriteSocket (socket, buf, &sp, &sz, M_POLL)) >= 0)
    if (time(NULL) > t) break;
  if (get > 0)
    while (!(get = ReadSocket (client, socket, sizeof(client), M_POLL)))
      if (time(NULL) > t) break;
  if (get <= 0)
  {
    Add_Request (I_LOG, "*", F_CONN,
		 _("Connection from %s lost while logging in."), host);
    KillSocket (&socket);
    return;
  }
  /* check of allowance */
  uf = Match_Client (host, ident, client);
  /* for services we have to check network type */
  if ((uf & (U_BOT|U_SPECIAL)) && (clr = Lock_Clientrecord (client)))
  {
    msg = safe_strdup (Get_Field (clr, ".logout", NULL));
    Unlock_Clientrecord (clr);
  }
  else
    msg = NULL;
  Set_Iface (NULL);
  bind = Check_Bindtable (BT_Login, msg ? msg : "*", uf, 0, NULL);
  FREE (&msg);
  if (bind && !bind->name && (!botsonly || (uf & U_BOT))) /* allowed to logon */
  {
    buf[0] = 0;
    bind->func (client, ident, host, socket, buf, &msg); /* it will unlock dispatcher */
  }
  else
  {
    Unset_Iface();
    msg = "no access";
  }
  if (msg)					/* was error on connection */
  {
    unsigned short p;

    snprintf (buf, sizeof(buf), "Access denied: %s\r\n", msg);
    sz = strlen (buf);
    sp = 0;
    while (!(WriteSocket (socket, buf, &sp, &sz, M_POLL)));
    SocketDomain (socket, &p);
    /* %L - Lname, %P - port, %@ - hostname, %* - reason */
    Set_Iface (NULL);
    printl (buf, sizeof(buf), format_dcc_closed, 0,
	    NULL, host, client, NULL, 0, p, 0, msg);
    Unset_Iface();
    /* cannot create connection */
    LOG_CONN (buf);
    KillSocket (&socket);
  }
}

static void session_handler_any (char *client, char *ident, char *host, idx_t socket)
{
  session_handler (ident, host, socket, 0);
}

static void session_handler_bots (char *client, char *ident, char *host, idx_t socket)
{
  session_handler (ident, host, socket, 1);
}

typedef struct
{
  char *client;			/* it must be allocated by caller */
  char *confline;		/* the same */
  unsigned short lport;		/* listener port */
  idx_t socket;
  idx_t id;
  pthread_t th;
  void (*prehandler) (pthread_t, idx_t);
  void (*handler) (char *, char *, char *, idx_t);
} accept_t;

static iftype_t port_signal (INTERFACE *iface, ifsig_t signal)
{
  accept_t *acptr = (accept_t *)iface->data;
  INTERFACE *tmp;
  char msg[48];
  char buf[STRING];

  switch (signal)
  {
    case S_REPORT:
      /* %@ - hostname, %I - socket num, %P - port, %* - state */
      snprintf (msg, sizeof(msg), _("listening on port %hu"), acptr->lport);
      printl (buf, sizeof(buf), ReportFormat, 0,
	      NULL, SocketDomain (acptr->socket, NULL), NULL, NULL,
	      (uint32_t)acptr->socket, acptr->lport, 0, msg);
      tmp = Set_Iface (iface);
      New_Request (tmp, F_REPORT, "%s", buf);
      Unset_Iface();
      break;
    case S_REG:
      if (acptr->confline)
	Add_Request (I_INIT, "*", F_REPORT, "%s", acptr->confline);
      break;
    case S_TERMINATE:
      Add_Request (I_LOG, "*", F_CONN,
		   _("Listening socket on port %hu terminated."), acptr->lport);
      Unset_Iface();			/* unlock dispatcher */
      CloseSocket (acptr->socket);	/* just kill it... */
      pthread_join (acptr->th, NULL);	/* ...and wait until it die */
      Set_Iface (NULL);			/* restore status quo */
      iface->ift |= I_DIED;
      break;
    case S_SHUTDOWN:
      /* just kill it... */
      CloseSocket (acptr->socket);
      /* ...it die itself */
    default: ;
  }
  return 0;
}

/* internal thread functions for Listen_Port */
#define acptr ((accept_t *)input_data)
static void _accept_port_cleanup (void *input_data)
{
  KillSocket (&acptr->id);
  FREE (&acptr->client);
  safe_free (&input_data); /* FREE (&acptr) */
}

static void *_accept_port (void *input_data)
{
  char *domain;
  char ident[24];
  char buf[SHORT_STRING];
  ssize_t sz;
  size_t sp;
  unsigned short p;
  time_t t;

  /* set cleanup for the thread before any cancellation point */
  acptr->id = -1;
  pthread_cleanup_push (&_accept_port_cleanup, input_data);
  domain = SocketDomain (acptr->socket, &p);
  /* SocketDomain() does not return NULL, let's don't wait! */
  if (!*domain)
    domain = NULL;
  /* get ident of user */
  *ident = 0;
  acptr->id = GetSocket();
  if (acptr->id > 0 && SetupSocket (acptr->id, M_RAW, domain, 113) == 0)
  {
    snprintf (buf, sizeof(buf), "%hu, %hu\n", p, acptr->lport);
    dprint (5, "ask host %s for ident: %s", domain, buf);
    sz = strlen (buf);
    sp = 0;
    time (&t);
    Set_Iface (NULL);
    t += ident_timeout;
    Unset_Iface();
    while (!(WriteSocket (acptr->id, buf, &sp, (size_t *)&sz, M_POLL)))
      if (time(NULL) > t) break;
    while (!(sz = ReadSocket (buf, acptr->id, sizeof(buf), M_POLL)))
      if (time(NULL) > t) break;
    if (sz > 0)
    {
      dprint (5, "%s ident answer: %s", domain, buf);
      /* overflow is impossible: part of buf isn't greater than buf */
      sscanf (buf, "%*[^:]: %[^: ] :%*[^:]: %23[^ \n]", buf, ident);
      if (strcmp (buf, "USERID"))		/* bad answer */
	*ident = 0;
    }
  } /* ident is checked */
  KillSocket (&acptr->id);
  /* %* - ident, %@ - hostname, %L - Lname, %P - port */
  Set_Iface (NULL);
  printl (buf, sizeof(buf), format_dcc_input_connection, 0, NULL, domain,
	  acptr->client, NULL, 0, p, 0, ident[0] ? ident : _("((unknown))"));
  Unset_Iface();
  LOG_CONN (buf);
  /* we have ident now so call handler and exit */
  acptr->handler (acptr->client, ident, domain, acptr->socket);
  pthread_cleanup_pop (1);
  return NULL;
}

static void *_listen_port (void *input_data)
{
  idx_t new_idx;
  accept_t *child;
  char buf[8];
  INTERFACE *iface;
  pthread_t th;

  if (!acptr->confline)
    snprintf (buf, sizeof(buf), "%hu", acptr->lport);
  /* create interface and deny cancellation of the thread */
  pthread_setcancelstate (PTHREAD_CANCEL_DISABLE, NULL);
  iface = Add_Iface (I_LISTEN | I_CONNECT, acptr->confline ? acptr->confline : buf,
		     &port_signal, NULL, acptr);
  while (acptr->socket >= 0)
  {
    /* TODO: check timeout for M_LINP */
    if ((new_idx = AnswerSocket (acptr->socket)) == E_AGAIN)
      continue;
    else if (new_idx < 0)
    {
      /* print error message */
      LOG_CONN (_("Listening socket died."));
      KillSocket (&acptr->socket);	/* die now */
      break;
    }
    child = safe_malloc (sizeof(accept_t));
    child->client = acptr->client;
    child->lport = acptr->lport;
    child->socket = new_idx;
    child->handler = acptr->handler;
    dprint (4, "direct:_listen_port: socket %d answered, %s: new socket %d",
	    acptr->socket, acptr->client ? "terminated" : "continue", new_idx);
    if (pthread_create (&th, NULL, &_accept_port, child))
    {
      KillSocket (&new_idx);
      FREE (&child);
    }
    else
    {
      if (acptr->client)		/* it's client connection so die now */
	KillSocket (&acptr->socket);
      if (acptr->prehandler)
	acptr->prehandler (th, acptr->socket);
    }
  }
  /* terminated - destroy all */
  FREE (&acptr->confline);
  Set_Iface (iface);
  iface->ift |= I_DIED;
  Unset_Iface();
  /* we don't need to free acptr since dispatcher will do it for us */
  return NULL;
}
#undef acptr

/*
 * Global function for listening port.
 * Returns: 0 if no listening or port number of process.
 */
unsigned short Listen_Port (char *client, unsigned short port, char *confline,
			    void (*prehandler) (pthread_t, idx_t),
			    void (*handler) (char *, char *, char *, idx_t))
{
  accept_t *acptr;
  idx_t p;
  
  if (!handler ||			/* stupidity check ;) */
      (port && port < 1024))		/* don't try system ports! */
    return 0;
  p = GetSocket();
  /* check for two more sockets - accepted and ident check */
  if (p < 0 || p >= SOCKETMAX - 2 ||
      SetupSocket (p, M_LIST, *hostname ? hostname : NULL, port) < 0)
  {
    KillSocket (&p);
    return 0;
  }
  acptr = safe_malloc (sizeof(accept_t));
  acptr->client = safe_strdup (client);
  acptr->confline = safe_strdup (confline);
  acptr->prehandler = prehandler;
  acptr->handler = handler;
  acptr->socket = p;
  SocketDomain (p, &port);
  acptr->lport = port;
  if (pthread_create (&acptr->th, NULL, &_listen_port, acptr))
  {
    KillSocket (&p);
    FREE (&acptr->client);
    FREE (&acptr->confline);
    FREE (&acptr);
    return 0;
  }
  return port;
}

typedef struct
{
  char *host;
  unsigned short port;
  idx_t *idx;
  void (*handler) (int, void *);
  void *id;
} connect_t;

#define cptr ((connect_t *)input_data)
static void _connect_host_cleanup (void *input_data)
{
  FREE (&cptr->host);
  safe_free (&input_data);	/* FREE (&cptr) */
}

static void *_connect_host (void *input_data)
{
  int i = E_NOSOCKET;

  /* set cleanup for the thread before any cancellation point */
  pthread_cleanup_push (&_connect_host_cleanup, input_data);
  if ((*cptr->idx = GetSocket()) >= 0)
    i = SetupSocket (*cptr->idx, M_RAW, cptr->host, cptr->port);
  if (i == 0)
    dprint (4, "direct:_connect_host: connected to %s at port %hu: new socket %d",
	    cptr->host, cptr->port, *cptr->idx);
  else
  {
    Add_Request (I_LOG, "*", F_CONN,
		 "Could not make connection to %s at port %hu: error %d",
		 cptr->host, cptr->port, -i);
    KillSocket (cptr->idx);
  }
  cptr->handler (i, cptr->id);
  pthread_cleanup_pop (1);
  return NULL;
}
#undef cptr

pthread_t Connect_Host (char *host, unsigned short port, idx_t *idx,
			void (*handler) (int, void *), void *id)
{
  connect_t *cptr;
  pthread_t th;

  if (!handler || !host || !port)	/* stupidity check ;) */
    return 0;
  cptr = safe_malloc (sizeof(connect_t));
  cptr->host = safe_strdup (host);
  cptr->port = port;
  cptr->idx = idx;
  cptr->handler = handler;
  cptr->id = id;
  if (pthread_create (&th, NULL, &_connect_host, cptr))
  {
    FREE (&cptr->host);
    FREE (&cptr);
    return (pthread_t)0;
  }
  return th;
}

/*
 * Internal dcc bindings:
 * int func(peer_t *from, char *args)
 * int func(session_t *from, char *args)
 */

static void _say_current (peer_t *dcc, char *msg)
{
  New_Request (dcc->iface, 0, _("Now: %s"), NONULL(msg));
}

		/* .away [<message>] */
static int dc_away (peer_t *dcc, char *args)
{
  char ch[16];

  if (args)
  {
    /* set away message */
    FREE (&dcc->dname);
    dcc->dname = safe_strdup (args);
    if (IS_SESSION(dcc) && ((session_t *)dcc)->botnet < 0)
      return -1;
    /* send notify to botnet */
    snprintf (ch, sizeof(ch), ":*:%d",
	      IS_SESSION(dcc) ? ((session_t *)dcc)->botnet : 0);
    Add_Request (I_DCCALIAS, ch, F_T_NOTICE, _("now away: %s"), args);
  }
  else
    _say_current (dcc, dcc->dname);
  return -1;	/* no log it */
}

		/* .me <message> */
static int dc_me (peer_t *dcc, char *args)
{
  binding_t *bind = NULL;
  char ch[16];

  if (!args)
    return 0;
  do
  {
    if ((bind = Check_Bindtable (BT_Chatact, args, dcc->uf, -1, bind)))
    {
      if (bind->name)
	RunBinding (bind, NULL, dcc->iface->name, NULL, DccIdx(dcc), args);
      else
	bind->func (dcc, args);
    }
  } while (bind);
  if (IS_SESSION(dcc) && ((session_t *)dcc)->botnet < 0)
    return -1;
  snprintf (ch, sizeof(ch), ":*:%d",
	    IS_SESSION(dcc) ? ((session_t *)dcc)->botnet : 0);
  Add_Request (I_DCCALIAS, ch, F_T_ACTION | F_BOTNET, "%s", args);
  return -1;	/* no log it */
}

		/* .back */
static int dc_back (peer_t *dcc, char *args)
{
  char ch[16];

  /* free away message */
  FREE (&dcc->dname);
  if (IS_SESSION(dcc) && ((session_t *)dcc)->botnet < 0)
    return -1;
  /* send notify to botnet */
  snprintf (ch, sizeof(ch), ":*:%u",
	    IS_SESSION(dcc) ? ((session_t *)dcc)->botnet : 0);
  Add_Request (I_DCCALIAS, ch, F_T_NOTICE, _("returned to life."));
  return -1;	/* no log it */
}

		/* .boot <nick on botnet> */
static int dc_boot (peer_t *dcc, char *args)
{
  INTERFACE *uif = NULL;
  userflag uf = 0;
  peer_t *udcc;
  char *msg;

  if (args && (uif = Find_Iface (I_DIRECT, args)))
  {
    if ((udcc = (peer_t *)uif->data))
      uf = udcc->uf;
    Unset_Iface();
  }
  else
    udcc = NULL;
  /* some checks */
  if (!udcc)
    msg = _("No such person at the botnet!");
  else if (uf & U_OWNER)
    msg = _("Cannot boot the bot owner!");
  else if ((uf & U_MASTER) && !(dcc->uf & U_OWNER))
    msg = _("You not permitted to boot a bot master!");
  else if (!uif->IFSignal)
    msg = _("I don't know how to boot it!");
  else
    msg = NULL;
  if (msg)
  {
    New_Request (dcc->iface, 0, msg);
    return -1;	/* no log it */
  }
  Add_Request (I_LOG, "*", F_T_NOTICE | F_CONN, _("%s booted by %s."),
	       args, dcc->iface->name);
  uif->IFSignal (uif, S_TERMINATE);
  return 1;
}

static void
_set_console_parms (session_t *dcc, clrec_t *user, char *fl, char *chan, int botch)
{
  char cons[SHORT_STRING];

  snprintf (cons, sizeof(cons), "%s %s %d",
	    fl[0] ? fl : "-", chan ? chan : "-", botch);
  Set_Field (user, "", cons);
  Unlock_Clientrecord (user);
  setconsole (dcc);
  dprint (4, "dcc:_set_console_parms: %s", cons);
}

		/* .chat [<botnet channel #>] */
static int dc_chat (session_t *dcc, char *args)
{
  char consfl[64];
  char chan[128] = "*";
  int botch = atoi (NONULL(args));
  clrec_t *user;

  if (!IS_SESSION(dcc))			/* aliens can have only channel 0 */
    return 0;
  else if (botch == dcc->botnet)
    return 1;
  _chat_part (dcc);
  user = Lock_Clientrecord (dcc->s.iface->name);
  consfl[0] = 0;
  if (user)
  {
    register char *c = Get_Field (user, "", NULL);
    sscanf (NONULL(c), "%63s %127s", consfl, chan);
    _set_console_parms (dcc, user, consfl, chan, botch);
  }
  _chat_join (dcc);
  return 1;
}

static void _console_fl (session_t *dcc, char *plus, char *minus, char *ch)
{
  char flags[64];
  char *cons = flags;
  register char *fl = flags;
  char chan[128];
  clrec_t *user;
  register int it = 0;

  minus = NONULL(minus);
  dprint (4, "dcc:_console_fl: %s %s %s %s", dcc->s.iface->name, plus, minus, NONULL(ch));
  user = Lock_Clientrecord (dcc->s.iface->name);
  if (!user)
    return;				/* hmm, could it be? */
  cons = Get_Field (user, "", NULL);	/* default color to mirc */
  if (!ch && cons)
  {
    sscanf (cons, "%*s %127s", chan);	/* channel wasn't defined so get it */
    ch = chan;
  }
  else
  {
    getconsole (dcc, flags, sizeof(flags));
    ch = "*";
  }
  while (cons && *cons && *cons != ' ')
  {
    if (!strchr (minus, *cons) && (strchr (_Flags, *cons) || *cons == '+'))
      *fl++ = *cons;
    else
      it++;
    cons++;
  }
  *fl = 0;
  while (plus && *plus)
  {
    if (!strchr (flags, *plus) && (strchr (_Flags, *plus) ||
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
    Unlock_Clientrecord (user);
}

		/* .color [off|mono|ansi|mirc] */
static int dc_color (session_t *dcc, char *args)
{
  flag_t fl = dcc->loglev & (F_COLORCONV | F_COLOR);

  if (!IS_SESSION(dcc))			/* aliens cannot change this */
    return 0;
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
    _say_current (&dcc->s, msg);
  }
  else
  {
    if (!strcmp (args, "mirc"))
      _console_fl (dcc, "", "#$%", NULL);
    else if (!strcmp (args, "mono"))
      _console_fl (dcc, "#", "$%", NULL);
    else if (!strcmp (args, "ansi"))
      _console_fl (dcc, "%", "#$", NULL);
    else if (!strcmp (args, "off"))
      _console_fl (dcc, "$", "#%", NULL);
    else return 0;
  }
  return 1;
}

		/* .console [<channel>] [+-<mode>] */
static int dc_console (session_t *dcc, char *args)
{
  char msg[MESSAGEMAX];
  char cl[128];
  char pm[2];
  char *cc = "*";
  char *ch;
  flag_t f, fl;
  int i = 0;

  if (!IS_SESSION(dcc))			/* you cannot change console logging */
    return 0;
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
      if (!Find_Iface (I_SERVICE, cc) || Unset_Iface())
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
      else if (i != 0 && *args != ' ' && strchr (_Flags, *args))
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
  fl = dcc->loglev & (F_PRIV | F_CMDS | F_CONN | F_SERV | F_WALL | F_USERS | F_DEBUG | F_ERROR | F_WARN | F_PUBLIC | F_JOIN | F_MODES);
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
	case F_PRIV:
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
	case F_BOOT:
	  m1 = _("boot diagnostics");
	  break;
	case F_ERROR:
	  m1 = _("errors");
	  break;
	case F_WARN:
	  m1 = _("warnings");
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
    New_Request (dcc->s.iface, 0, "%s: %s%s%s %s %s", _("Your console logs"),
		 *msg ? msg : "", *msg ? _(", and ") : "", cl,
		 _("on the channel"), cc);
  else
    New_Request (dcc->s.iface, 0, "%s: %s", _("Your console logs"),
		 *msg ? msg : "none");
  return 1;
}

static void _report_req (iftype_t iface, char *who)
{
  char t[sizeof(ifsig_t)] = {S_REPORT};

  Add_Request (iface, who, F_SIGNAL, t);
}

		/* .cstat */
static int dc_cstat (peer_t *dcc, char *args)
{
  char b[SHORT_STRING];

  printl (b, sizeof(b), format_cstat_head, 0, NULL, NULL, NULL, NULL, 0, 0, 0, NULL);
  New_Request (dcc->iface, 0, b);
  ReportFormat = format_cstat;
  _report_req (I_CONNECT, "*");
  return 1;
}

		/* .echo [on|off] */
static int dc_echo (session_t *dcc, char *args)
{
  flag_t fl = dcc->loglev & F_ECHO;

  if (!IS_SESSION(dcc))			/* aliens cannot on/off echo ;) */
    return 0;
  if (args)
  {
    if (!strcmp (args, "on"))
    {
      if (!fl)
	_console_fl (dcc, "+", NULL, NULL);
    }
    else if (!strcmp (args, "off"))
    {
      if (fl)
	_console_fl (dcc, NULL, "+", NULL);
    }
    else
      return -1;
    fl = dcc->loglev & F_ECHO;
  }
  if (fl)
    _say_current (&dcc->s, "on");
  else
    _say_current (&dcc->s, "off");
  return 1;
}

		/* .help [<what need>] */
static int dc_help (peer_t *dcc, char *args)
{
  char *sec = NextWord (args);
  char *fst = args;
  userflag df = Get_Clientflags (dcc->iface->name, NULL);

  if (args)
  {
    while (*args && *args != ' ') args++;
    *args = 0;
  }
  /* usage - not required if no arguments */
  if (args && !Get_Help (fst, sec, dcc->iface, dcc->uf, df,
			 BT_Dcc, _("Usage: "), 0))
    return -1;
  /* full help */
  Get_Help (fst, sec, dcc->iface, dcc->uf, df, BT_Dcc, NULL, 2);
  if (sec && *sec)
    *args = ' ';
  return 1;			/* return 1 because usage at least displayed */
}

		/* .motd */
static int dc_motd (peer_t *dcc, char *args)
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
	  dcc->iface->name, NULL, 0L, 0, 0, args);
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
static int dc_simul (peer_t *dcc, char *args)
{
  session_t *ud;
  INTERFACE *iface;
  char name[IFNAMEMAX+1];
  char *c;

  if (!args)
    return 0;
  strfcpy (name, args, sizeof(name));
  for (c = name; *c && *c != ' '; c++);
  *c = 0;
  iface = Find_Iface (I_DIRECT, name);
  if (!iface)
  {
    New_Request (dcc->iface, 0, _("No such client on DCC now"));
    return 0;
  }
  else if (iface->IFSignal == &dcc_signal)	/* it should not be alien */
  {
    ud = (session_t *)iface->data;
    Set_Iface (iface);
    args = NextWord (args);
    ud->s.parse (&ud->s, c, args, ud->s.uf, 0, DccIdx(ud), ud->botnet, ud->ssbt,
		 ud->netname);
    Unset_Iface();		/* from Set_Iface() */
  }
  else
    New_Request (dcc->iface, 0,
		 _("You can simulate only local DCC clients, sorry"));
  Unset_Iface();		/* from Find_Iface() */
  return 1;
}

		/* .who [<service>] */
static int dc_who (peer_t *dcc, char *args)
{
  char b[SHORT_STRING];

  if (dcc->uf & U_MASTER)
  {
    printl (b, sizeof(b), format_who_head_master, 0, NULL, NULL, NULL, NULL, 0, 0, 0, NULL);
    ReportFormat = format_who_master;
  }
  else
  {
    printl (b, sizeof(b), format_who_head, 0, NULL, NULL, NULL, NULL, 0, 0, 0, NULL);
    ReportFormat = format_who;
  }
  New_Request (dcc->iface, 0, b);
  ReportMask = -1;
  if (args)
    _report_req (I_SERVICE, args);
  else
    _report_req (I_DIRECT, "*");
  return 1;
}

		/* .w [channel] */
static int dc_w (session_t *dcc, char *args)
{
  char b[SHORT_STRING];

  printl (b, sizeof(b), format_w_head, 0, NULL, NULL, NULL, NULL, 0, 0, 0, NULL);
  New_Request (dcc->s.iface, 0, b);
  if (args)
    snprintf (b, sizeof(b), ":*:%s", args);
  else if (!IS_SESSION(dcc))
    strcpy (b, ":*:0");
  else
    snprintf (b, sizeof(b), ":*:%d", dcc->botnet);
  ReportFormat = format_w;
  _report_req (I_DCCALIAS, b);
  if (args)
    strcpy (args, &b[3]);
  return 1;
}

		/* .quit [<message>] */
static int dc_quit (peer_t *dcc, char *args)
{
  strfcpy (dcc->buf, NONULL(args), sizeof(dcc->buf));
  dcc->inbuf = strlen (dcc->buf);
  dcc->iface->ift |= I_DIED;		/* let _died_iface know it was .quit */
  if (dcc->iface->IFSignal)
    dcc->iface->IFSignal (dcc->iface, S_TERMINATE);
  return 1;
}

		/* .connect <network|channel|bot> [<args>] */
static int dc_connect (peer_t *dcc, char *args)
{
  char netname[IFNAMEMAX+2];
  char *snet;
  clrec_t *netw;
  char *nt;
  binding_t *bind;
  userflag uf = 0;

  /* find the network and it type as @net->info */
  netname[0] = '@';
  args = NextWord_Unquoted (&netname[1], args, sizeof(netname)-1);
  snet = strrchr (&netname[1], '@'); /* network if it's channel */
  /* try as network at first then as channel and as bot at last */
  if ((snet || !((uf = Get_Clientflags (netname, NULL)) & U_SPECIAL) ||
      (netw = Lock_Clientrecord (netname)) == NULL) &&
      (!snet || (netw = Lock_Clientrecord (snet)) == NULL) &&
      (!((uf = Get_Clientflags (&netname[1], NULL)) & U_BOT) ||
      (netw = Lock_Clientrecord (&netname[1])) == NULL))
    return 0;
  /* find the connect type in BT_Connect */
  nt = Get_Field (netw, ".logout", NULL);
  if (!nt)
    bind = NULL;
  else if (snet) /* a channel */
    bind = Check_Bindtable (BT_Connect, nt, 0, U_SPECIAL, NULL);
  else /* a network */
    bind = Check_Bindtable (BT_Connect, nt, uf, 0, NULL);
  Unlock_Clientrecord (netw);
  /* try to call connect function */
  if (!bind || bind->name)
  {
    New_Request (dcc->iface, 0, _("I don't know how to connect to %s."),
		 &netname[1]);
    return -1; /* no log it */
  }
  return bind->func (&netname[1], args);
}

		/* .disconnect <network|channel|bot> [<reason>] */
static int dc_disconnect (peer_t *dcc, char *args)
{
  INTERFACE *cif;
  char netname[IFNAMEMAX+1];

  /* find the link by name */
  if (!args)
    return 0;
  args = NextWord_Unquoted (netname, args, sizeof(netname));
  if ((cif = Find_Iface (I_SERVICE, netname)) == NULL)
    return 0;
  Unset_Iface();
  /* terminate it */
  if (!cif->IFSignal)
  {
    New_Request (dcc->iface, 0, _("I don't know how disconnect %s."), netname);
    return -1;
  }
  if (*args)
    ShutdownR = args;
  cif->IFSignal (cif, S_TERMINATE);
  ShutdownR = NULL;
  return 1;
}

static void _dc_init_bindings (void)
{
#define NB(a,b) Add_Binding ("dcc", #a, b, -1, &dc_##a)
  NB (away, U_ACCESS);
  NB (back, U_ACCESS);
  NB (boot, U_OP);
  NB (chat, U_ACCESS);
  NB (color, 0);
  NB (console, U_ACCESS);
  NB (cstat, U_OP);
  NB (echo, 0);
  NB (help, 0);
  NB (me, U_ACCESS);
  NB (motd, 0);
  NB (simul, U_OWNER);
  NB (who, 0);
  NB (w, U_ACCESS);
  NB (quit, 0);
  NB (connect, U_OWNER);
  NB (disconnect, U_OWNER);
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
 * void func(peer_t *who)
 */

/*
 * Internal out-filter bindings:
 * void func(peer_t *to, char *msg, size_t msglen)
 */

/* Config/scripts functions... */
static int _dellistenport (char *pn)
{
  char sig[sizeof(ifsig_t)] = {S_TERMINATE};
  INTERFACE *pi;

  if (!(pi = Find_Iface (I_LISTEN, pn)))
    return 0;
  New_Request (pi, F_SIGNAL, sig);
  Unset_Iface();
  return 1;
}

ScriptFunction (FE_port)	/* to config - see thrdcc_signal() */
{
  unsigned short port;
  static char msg[SHORT_STRING];
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
  snprintf (msg, sizeof(msg), "port %s%hu", (u & U_ANY) ? "" : "-b ", port);
  args = NextWord (args);
  if (u == 0)
    return _dellistenport (msg);
  /* check if already exist */
  if (Find_Iface (I_LISTEN, msg))
  {
    Unset_Iface();
    LOG_CONN (_("Already listening on port %hu!"), port);
    return port;
  }
  if (u & U_ANY)
    port = Listen_Port (NULL, port, msg, NULL, &session_handler_any);
  else
    port = Listen_Port (NULL, port, msg, NULL, &session_handler_bots);
  if (port == 0)
  {
    snprintf (msg, sizeof(msg), _("Cannot open listening port on %hu%s!"),
	      port, (u & U_ANY) ? "" : _(" for bots"));
    BindResult = msg;
    return 0;
  }
  LOG_CONN (_("Listening on port %hu%s."), port,
	    (u & U_ANY) ? "" : _(" for bots"));
  return port;
}

char *IFInit_DCC (void)
{
  if (fe_init_sockets())
    return _("Sockets init error!");
  /* add own bindtables */
  BT_Dcc = Add_Bindtable ("dcc", B_UCOMPL);		/* these tables have bindings */
  _dc_init_bindings();
  BT_Crypt = Add_Bindtable ("passwd", B_UNIQMASK);
  Add_Binding ("passwd", "$1*", 0, 0, (Function)&IntCrypt);
  BT_Login = Add_Bindtable ("login", B_MASK);
  Add_Binding ("login", "*", U_ACCESS, -1, (Function)&get_chat);
  BT_Chaton = Add_Bindtable ("chat-on", B_MASK);	/* rest are empty */
  BT_Outfilter = Add_Bindtable ("out-filter", B_MASK);
  BT_Chat = Add_Bindtable ("chat", B_MASK);
  BT_Infilter = Add_Bindtable ("in-filter", B_MASK);
  BT_Chatoff = Add_Bindtable ("chat-off", B_MASK);
  BT_Chatact = Add_Bindtable ("chat-act", B_MASK);
  BT_Chatjoin = Add_Bindtable ("chat-join", B_MASK);
  BT_Chatpart = Add_Bindtable ("chat-part", B_MASK);
  BT_Connect = Add_Bindtable ("connect", B_MASK);
  flood_dcc = FloodType ("dcc");
  return NULL;
}
