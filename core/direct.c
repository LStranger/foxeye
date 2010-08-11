/*
 * Copyright (C) 1999-2010  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 * This file is part of FoxEye's source: direct connections interface.
 *      Bindtables: passwd dcc upload login chat out-filter in-filter
 *      chat-on chat-off chat-join chat-part
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

#define DccIdx(a) (int)(((peer_t *)a)->socket + 1)

/*
 * Direct session management.
 */
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

static void _chat_join (session_t *dcc)
{
  register binding_t *bind = NULL;
  char *on_bot;
  char *name;
  char *h;
  char *cc;
  char ch[16];

  /* start getting the messages from botnet channel */
  snprintf (ch, sizeof(ch), ":%d:%d", DccIdx(dcc), dcc->botnet);
  Rename_Iface (dcc->alias, ch);
  name = dcc->s.iface->name;
  if ((on_bot = safe_strchr (name, '@')))
    on_bot++;
  else
    on_bot = Nick;
  snprintf (ch, sizeof(ch), ":*:%d %c", dcc->botnet, _userdccflag (dcc->s.uf));
  cc = strchr (ch, ' ');		/* between botch and flag */
  dprint (4, "dcc:_chat_join: %s joining %d", name, dcc->botnet);
  /* run bindtable */
  h = SocketDomain (dcc->s.socket, NULL);
  Set_Iface (dcc->s.iface);
  do
  {
    *cc = '\0';
    if ((bind = Check_Bindtable (BT_Chatjoin, &ch[3], U_ALL, U_ANYCH, bind)))
    {
      *cc = ' ';
      if (bind->name)
        RunBinding (bind, NULL, on_bot, name, &ch[3], DccIdx(dcc), h);
      else
        bind->func (dcc->s.iface, dcc->botnet, h);
    }
  } while (bind);
  Unset_Iface();
  *cc = '\0';
  /* notify local botnet users! */
  Set_Iface (dcc->alias);
  if (dcc->botnet >= 0)
    Add_Request (I_DCCALIAS, ch, F_T_NOTICE, _("joined this botnet channel."));
  Unset_Iface();
}

static void _chat_part (session_t *dcc, char *quit)
{
  register binding_t *bind = NULL;
  char *on_bot;
  char ch[16];
  char *name = NULL;

  name = dcc->s.iface->name;
  if ((on_bot = safe_strchr (name, '@')))
    on_bot++;
  else
    on_bot = Nick;
  dprint (4, "dcc:_chat_part: %s parting %d", name, dcc->botnet);
  snprintf (ch, sizeof(ch), ":*:%d", dcc->botnet);
  /* notify the botnet! */
  Set_Iface (dcc->alias);
  /* if quit - send the formed notice */
  if (dcc->botnet < 0);
  else if (quit)
    Add_Request (I_DCCALIAS, ch, F_T_NOTICE, _("quit botnet: %s"), quit);
  else
    Add_Request (I_DCCALIAS, ch, F_T_NOTICE, _("left this botnet channel."));
  Unset_Iface();
  /* run bindtable */
  Set_Iface (dcc->s.iface);
  do
  {
    if ((bind = Check_Bindtable (BT_Chatpart, &ch[3], U_ALL, U_ANYCH, bind)))
    {
      if (bind->name)
        RunBinding (bind, NULL, on_bot, name, NULL, DccIdx(dcc), &ch[3]);
      else
        bind->func (dcc->s.iface, dcc->botnet);
    }
  } while (bind);
  Unset_Iface();
  /* stop getting the messages */
  snprintf (ch, sizeof(ch), ":%d:", DccIdx(dcc));
  Rename_Iface (dcc->alias, ch);
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
  if (user)
    dcc->s.uf = Get_Flags (user, "");	/* global+direct service flags */
  else
    dcc->s.uf = 0;			/* did someone deleted you? */
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
    if (user)
    {
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
      Rename_Iface (dcc->log, chan);
      /* now get network name and "ss-*" bindtable */
      if (dcc->log->name && (line = strrchr (dcc->log->name, '@')))
	line++;
      else
	line = dcc->log->name;
      if ((user = Lock_Clientrecord (line)))
      {
	if (Get_Flags (user, "") & U_SPECIAL)
	{
	  dcc->netname = dcc->log->name;
	  if ((line = Get_Field (user, ".logout", NULL)))
	  {
	    snprintf (chan, sizeof(chan), "ss-%s", line);
	    dcc->ssbt = Add_Bindtable (chan, B_UCOMPL);
	  }
	}
	else
	  dcc->netname = NULL;
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
  Connchain_Kill ((&dcc->s));
  KillSocket (&dcc->s.socket);
  /* %L - login nick, %@ - hostname */
  printl (buf, s, format_dcc_lost, 0, NULL,
	  SocketDomain (dcc->s.socket, NULL), iface->name, NULL, 0, 0, 0, NULL);
  LOG_CONN ("%s", buf);
  NoCheckFlood (&dcc->floodcnt);		/* remove all flood timers */
  if (dcc->s.state == P_LOGIN)			/* if it was fresh connection */
    return;
  NewEvent (W_END, ID_ME, FindLID (iface->name), 0); /* log to Wtmp */
  /* now run "chat-part" and "chat-off" bindings... */
  if (dcc->log)
    cf = Get_Clientflags (iface->name, dcc->log->name);
  _chat_part (dcc, ShutdownR ? ShutdownR : _("no reason.")); /* NONULL */
  do
  {
    if ((bind = Check_Bindtable (BT_Chatoff, iface->name, dcc->s.uf, cf, bind)))
    {
      if (bind->name)
        RunBinding (bind, NULL, iface->name, NULL, NULL, DccIdx(dcc), NULL);
      else
        bind->func (dcc);
    }
  } while (bind);
}

/* it's really static but it's used by console too :( */
/* note that first argument is really session_t * type unless it's console */
void Dcc_Parse (peer_t *dcc, char *name, char *cmd, userflag gf, userflag cf,
		int dccidx, int botch, bindtable_t *ssbt, char *service,
		INTERFACE *source)
{
  char *arg;
  binding_t *bind;
  INTERFACE *sif;
  int res;

  dprint (4, "dcc:Dcc_Parse: \"%s\"", cmd);
  if (cmd[0] == '.')
  {
    StrTrim (++cmd);
    arg = NextWord (cmd);
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
	res = RunBinding (bind, NULL, name, NULL, NULL, dccidx, arg);
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
	RunBinding (bind, NULL, name, NULL, NULL, botch, cmd);
      else
	bind->func (dcc, cmd);
    if (source)
      Set_Iface (source);
    snprintf (to, sizeof(to), ":*:%d", botch);
    Add_Request (I_DCCALIAS, to, F_T_MESSAGE, "%s", cmd);
    if (source)
      Unset_Iface();
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
	  RunBinding (bind, NULL, name, NULL, NULL, DccIdx(dcc), NULL);
	else
	  bind->func (dcc);
      }
    } while (bind);
    _chat_join (dcc);
    LOG_CONN (_("Logged in: %s."), name);
    /* log to Wtmp */
    NewEvent (W_START, ID_ME, FindLID (name), 0);
  }
  /* check if this is mine but echo disabled */
  if (req)
  {
    /* check if this is botnet mesage from me but echo disabled */
    if (req->from == dcc->alias && (req->mask_if & I_DCCALIAS) &&
	!(dcc->loglev & F_ECHO))
      req = NULL;
  }
  if (dcc->log && dcc->log->name)
    cf = Get_Clientflags (dcc->s.iface->name, dcc->log->name);
  sw = 0;
  if ((sw = Peer_Put ((&dcc->s), "", &sw)) > 0 && /* connchain is ready */
      req)				/* do we have something to out? */
  {
    DBG ("process request: type 0x%x, flag 0x%x, to %s, starts %.10s",
	 req->mask_if, req->flag, req->to, req->string);
    /* for logs... formatted, just add timestamp */
    if (req->mask_if & I_LOG)
    {
      if (req->flag & dcc->loglev)
	printl (buf, sizeof(buf), "[%t] %*", 0, NULL, NULL, NULL, NULL,
		0, 0, 0, req->string);
      else
	buf[0] = 0;
      req = NULL;
    }
    /* flush command - see the users.c, ignore commands for non-bots */
    else if (req->string[0] == '\010')
    {
      dcc->s.iface->IFSignal (dcc->s.iface, S_FLUSH);
      buf[0] = 0;
      req = NULL;
    }
    /* for chat channel messages */
    else if (req->from && (req->from->ift & I_DCCALIAS) &&
	     (req->mask_if & I_DCCALIAS))
    {
      char *prefix;
      char *suffix = "";

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
      snprintf (buf, sizeof(buf), "%s%s%s %s", prefix,
		req->from->name, suffix, req->string);
      req = NULL;
    }
    /* prefixing any other notice */
    else if (req->flag & F_T_NOTICE)
    {
      snprintf (buf, sizeof(buf), "*** %s", req->string);
      req = NULL;
    }
    /* direct messages or reports */
    if (req)
      cmd = req->string;
    else
      cmd = buf;
    sw = strlen (cmd);
    sw = Peer_Put ((&dcc->s), cmd, &sw);
    /* and it had to accept all string not part of it! */
    req = NULL;				/* request done! */
  }
  if (sw < 0)			/* error, kill dcc... */
  {
    ShutdownR = _("session lost");
    _died_iface (iface, buf, sizeof(buf));
    ShutdownR = NULL;
    return REQ_OK;
  }
  /* don't input until empty buffer */
  else if (req)
    return REQ_REJECTED;
  /* don't check input if this is interface shadow */
  if (!(iface->ift & I_CONNECT))
    return REQ_OK;
  /* we sent the message, can P_INITIAL -> P_LOGIN */
  if (dcc->s.state == P_INITIAL)
  {
    dcc->s.state = P_LOGIN;
    return REQ_OK;
  }
  sw = Peer_Get ((&dcc->s), buf, sizeof(buf));
  if (sw < 0)
  {
    ShutdownR = _("session lost");
    _died_iface (iface, buf, sizeof(buf));
    ShutdownR = NULL;
    return REQ_OK;
  }
  if (sw < 2)				/* ignore empty input too */
    return REQ_OK;
  dcc->s.last_input = Time;		/* timestamp for idle */
  /* check the "dcc" flood... need just ignore or break connection? TODO? */
  if (CheckFlood (&dcc->floodcnt, flood_dcc) > 0)
    return REQ_OK;
  sw--;					/* skip ending '\0' */
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
		dcc->botnet, dcc->ssbt, dcc->netname, dcc->alias);
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
	/* check the IRC and botnet channels, set dcc->s.uf */
	setconsole (dcc);
      break;
    case S_REPORT:
      switch (dcc->s.state)
      {
        case P_LOGIN:
	  /* %@ - hostname, %L and %N - Lname, %* - state */
	  printl (buf, sizeof(buf), ReportFormat, 0,
		  dcc->s.iface->name, SocketDomain (dcc->s.socket, NULL),
		  dcc->s.iface->name, NULL, (uint32_t)dcc->s.socket + 1, 0,
		  0, "logging in");
	  break;
	default:
	  idle = Time - dcc->s.last_input;
	  dom = SocketDomain (dcc->s.socket, &p);
	  if (dcc->s.dname && !(dcc->s.iface->ift & I_LOCKED))
	  {
	    desc = safe_malloc (strlen (dcc->s.dname) + 7);
	    strcpy (desc, "away: ");
	    strcpy (&desc[6], dcc->s.dname);
	  }
	  else
	    desc = NULL;
	  c[0] = _userdccflag (dcc->s.uf);
	  strfcpy (&c[1], dcc->s.iface->name, sizeof(c)-1);
	  /* %@ - hostname, %L - Lname, %# - start time, %I - socket number,
	     %P - port, %- - idle time, %* - state */
	  printl (buf, sizeof(buf), ReportFormat, 0,
		  c, dom, c, dcc->s.start, (uint32_t)dcc->s.socket + 1, p,
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
      _chat_part (dcc, NULL);			/* has left botnet channel */
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
      /* using already filled ShutdownR - can it be weird? */
      _died_iface (iface, buf, sizeof(buf));
      FREE (&dcc->s.dname);
      return I_DIED;
    case S_SHUTDOWN:
      /* try to sent shutdown message and quiet shutdown anyway */
      if (signal == S_SHUTDOWN && ShutdownR)
      {
        size_t inbuf, bufpos;

	strfcpy (buf, ShutdownR, sizeof(buf));
	strfcat (buf, "\r\n", sizeof(buf));
	inbuf = strlen (buf);
	bufpos = 0;
	WriteSocket (dcc->s.socket, buf, &bufpos, &inbuf, M_RAW);
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
  binding_t *bind = Check_Bindtable (BT_Crypt, encrypted, U_ALL, U_ANYCH, NULL);

  if (bind && !bind->name)
  {
    upass = encrypted;
    bind->func (pass, &upass);
  }
  return safe_strcmp (encrypted, upass);
}

/*
 * Filter 'y' - RFC854 (i.e. telnet) handler.
 */
static ssize_t _ccfilter_y_send (connchain_i **ch, idx_t id, const char *str,
				 size_t *sz, connchain_buffer **b)
{
  ssize_t i = 0, ii, left;
  char *c;

  if (*b == NULL)			/* already terminated */
    return E_NOSOCKET;
  if (str == NULL ||			/* got termination */
      (i = Connchain_Put (ch, id, "", &i)) < 0)	/* dead end */
  {
    *b = NULL;
    return E_NOSOCKET;
  }
  if (i != CONNCHAIN_READY)		/* next chain isn't ready */
    return 0;				/* we don't ready too, of course */
  if ((left = *sz) == 0)		/* it's a test! */
    return CONNCHAIN_READY;
  while ((i = left) != 0)		/* cycle line+IAC */
  {
    c = memchr (str, '\377', i);	/* IAC */
    if (c)
      ii = c - str;			/* how many to put */
    else
      ii = left;			/* put everything we have */
    if (left - ii > 2 && (uchar)str[ii+1] >= 251 && str[ii+2] == '\001')
    {
      c = NULL;
      ii += 3;				/* process IAC * ECHO as is */
    }
    i = Connchain_Put (ch, id, str, &ii);
    if (i < 0)
      return i;
    left -= i;
    if (ii != 0)			/* not fully put there */
      break;
    str += i;
    if (c)				/* IAC was found */
    {
      ii = 2;
      i = Connchain_Put (ch, id, "\377\377", &ii);
      if (i < 0)		/* don't check for 1, is it impossible? */
	return i;
      if (ii != 0)			/* could not send it */
	break;
      str++;
      left--;
    }
  }
  i = *sz - left;
  *sz = left;
  return i;
}

static inline void _session_try_add (char **t, size_t *s, char ch1, char ch2, char ch3)
{
  if (*s >= 3)
  {
    register char *c = *t;

    c[0] = ch1;
    c[1] = ch2;
    c[2] = ch3;
    *s -= 3;
    *t = &c[3];
  }
}

static size_t _do_rfc854_input (char *str, size_t sz, char *tosend, size_t *s)
{
  char *c;
  size_t x = 0, eol, done = 0;

  while (x < sz)		/* until EOL */
  {
    c = memchr (&str[x], '\377', sz - x); /* IAC */
    if (c)
      eol = c - &str[x];		/* parse this part */
    else
      eol = sz - x;			/* parse upto end */
    if (x != done)
      memcpy (&str[done], &str[x], eol);
    x += eol;
    done += eol;
    eol = sz - x;			/* left in source */
    if (c)			/* got IAC! */
    {
      register unsigned char ch;

      if (eol == 1)		/* bogus! */
        break;
      x++;
      ch = str[x++];
      if (ch == 255)
      {
	str[done++] = ch;	/* IAC IAC - it's data */
	continue;
      }
      if (ch >= 251)		/* WILL WON'T DO DON'T */
      {
	if (x == sz)		/* bogus! */
	  break;
	if (str[x] == 1);	/* ECHO will be always ignored */
	else if (ch == 251)	/* on WILL send DON'T */
	  _session_try_add (&tosend, s, 255, 254, str[x]);
	else if (ch == 253)	/* on DO send WON'T */
	  _session_try_add (&tosend, s, 255, 252, str[x]);
	x++;
      }
      else if (ch == 246)	/* Are You There? -> "Y\r\n" */
	_session_try_add (&tosend, s, 'Y', '\r', '\n');
    }
  }
  return done;
}

static ssize_t _ccfilter_y_recv (connchain_i **ch, idx_t id, char *str,
				 size_t sz, connchain_buffer **b)
{
  char buftosend[24];
  char *bts;
  ssize_t sr, sw, st;

  if (str == NULL)			/* they killed me */
    return E_NOSOCKET;
  sr = Connchain_Get (ch, id, str, sz);
  if (sr <= 0)				/* error or no data */
    return sr;
  sw = sizeof(buftosend);
  sr = _do_rfc854_input (str, sr, buftosend, &sw);
  sw = sizeof(buftosend) - sw;		/* reverse meaning */
  bts = buftosend;
  while (sw > 0)			/* can it be forever? TODO? */
  {
    if ((st = Connchain_Put (ch, id, bts, &sw)) < 0)
      return st;			/* error ? */
    bts += st;
  }
  return sr;
}

BINDING_TYPE_connchain_grow(_ccfilter_y_init);
static int _ccfilter_y_init (peer_t *peer,
	ssize_t (**recv)(connchain_i **, idx_t, char *, size_t, connchain_buffer **),
	ssize_t (**send)(connchain_i **, idx_t, const char *, size_t *, connchain_buffer **),
	connchain_buffer **b)
{
  *recv = &_ccfilter_y_recv;
  *send = &_ccfilter_y_send;
  /* we will use buffer as marker, yes */
  *b = (void *)1;
  return 1;
}


/*
 * Filter 'b' - eggdrop style filter bindtables handler. Local only.
 */
static ssize_t _ccfilter_b_send (connchain_i **ch, idx_t id, const char *str,
				 size_t *sz, connchain_buffer **b)
{
  ssize_t i = 0, left;
  binding_t *bind;
  char buf[MB_LEN_MAX*MESSAGEMAX];

  if (*b == NULL)			/* already terminated */
    return E_NOSOCKET;
  if (str == NULL ||			/* got termination */
      (i = Connchain_Put (ch, id, "", &i)) < 0)	/* dead end */
  {
    *b = NULL;
    return E_NOSOCKET;
  }
  if (i != CONNCHAIN_READY)		/* next chain isn't ready */
    return 0;				/* we don't ready too, of course */
  if ((left = *sz) == 0)		/* it's a test! */
    return CONNCHAIN_READY;
  /* run "out-filter" bindings... */
  bind = NULL;
  /* unfortunately we don't know charset at this point so cannot do better */
  if ((size_t)left >= sizeof(buf))
    left = sizeof(buf)-1;		/* hmm... truncating? */
  strfcpy (buf, str, left + 1);
  do
  {
    bind = Check_Bindtable (BT_Outfilter, buf, ((peer_t *)*b)->uf, 0, bind);
    if (bind)
    {
      if (bind->name)
      {
	RunBinding (bind, NULL, NULL, NULL, NULL, DccIdx(*b), buf);
	strfcpy (buf, BindResult, sizeof(buf));
      }
      else
	bind->func ((peer_t *)*b, buf, sizeof(buf));
      i = strlen (buf);
    }
  } while (i && bind);
  *sz -= left;
  if (!i)
    return left;				/* assume it's done */
  i = Connchain_Put (ch, id, buf, &i);		/* assume it fits in */
  return (i < 0) ? i : left;
}

static ssize_t _ccfilter_b_recv (connchain_i **ch, idx_t id, char *str,
				 size_t sz, connchain_buffer **b)
{
  ssize_t sr;
  binding_t *bind;

  if (str == NULL)			/* they killed me */
    return E_NOSOCKET;
  sr = Connchain_Get (ch, id, str, sz);
  if (sr <= 0)				/* error or no data */
    return sr;
  if (str[0] != 0)
  {
    /* run "in-filter" bindings... */
    bind = NULL;
    do
    {
      bind = Check_Bindtable (BT_Infilter, str, ((peer_t *)*b)->uf, 0, bind);
      if (bind)
      {
	if (bind->name)
	{
	  RunBinding (bind, NULL, NULL, NULL, NULL, DccIdx(*b), str);
	  strfcpy (str, BindResult, sz);
	}
	else
	  bind->func ((peer_t *)*b, str, sz);
      }
    } while (bind && str[0]);
  }
  return (safe_strlen (str) + 1);
}

BINDING_TYPE_connchain_grow(_ccfilter_b_init);
static int _ccfilter_b_init (peer_t *peer,
	ssize_t (**recv) (connchain_i **, idx_t, char *, size_t, connchain_buffer **),
	ssize_t (**send) (connchain_i **, idx_t, const char *, size_t *, connchain_buffer **),
	connchain_buffer **b)
{
  if (!(IS_SESSION(peer)))		/* local only! */
    return 0;
  *recv = &_ccfilter_b_recv;
  *send = &_ccfilter_b_send;
  /* we do using *b as peer pointer, make sure connchain is used non-thread */
  *b = (void *)peer;
  return 1;
}


/*
 * Internal login bindings:
 * void func(char *who, char *ident, char *host, idx_t socket, char *buf, char **msg)
 */

/* called from threads and dispatcher is locked! */
/* buf is Lname if this is CTCP CHAT answer or empty string */
BINDING_TYPE_login (get_chat);
static void get_chat (char *name, char *ident, char *host, idx_t socket,
		      char buf[SHORT_STRING], char **msg)
{
  ssize_t sz;
  size_t sp;
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
  sp = 0;
  while (time(NULL) < t)
  {
    sz = ReadSocket (&buf[sp], socket, SHORT_STRING - sp, M_POLL);
    if (sz < 0)
      break;
    while (sz)
      if (buf[sp] == '\r' || buf[sp] == '\n')
      {
	buf[sp] = 0;
	break;
      }
      else
      {
	sz--;
	sp++;
      }
    if (sz)
      break;
  }
  if (sz == 0 || sz == E_AGAIN)
  {
    *msg = "login timeout";
    return;
  }
  else if (sz < 0)
  {
    *msg = "connection lost";
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
  uf = Get_Flags (user, "");
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
  dcc->s.connchain = NULL;
  time (&dcc->s.last_input);
  dcc->floodcnt = 0;
  dcc->netname = NULL;
  dcc->ssbt = NULL;
  /* create interfaces - lock dispatcher to syncronize */
  Set_Iface (NULL);
  strfcpy (dcc->s.start, DateString, sizeof(dcc->s.start));
  dcc->s.iface = Add_Iface (I_DIRECT | I_CONNECT, name, &dcc_signal,
			    &dcc_request, dcc);
  /* try to create the alias for scripts :) */
  dcc->alias = Add_Iface (I_DCCALIAS, NULL, &dccalias_signal, &dcc_request, dcc);
  /* the same for logs */
  dcc->log = Add_Iface (I_LOG, NULL, &dcclog_signal, &dcc_request, dcc);
#ifdef HAVE_ICONV
  dcc->s.iface->conv = Get_Conversion (host);
  dcc->alias->conv = Clone_Conversion (dcc->s.iface->conv);
  dcc->log->conv = Clone_Conversion (dcc->s.iface->conv);
#endif
  if (telnet)
    /* Adding telnet filter 'y' now! */
    Connchain_Grow ((&dcc->s), 'y');	/* TODO: diagnostics on that? */
  Connchain_Grow ((&dcc->s), 'x');	/* text parser! TODO: see above */
  if (telnet)			/* dispatcher is locked, can do connchain */
  {
    dprint (5, "enabling echo for user");
    sp = 3;						/* set it manually */
    Peer_Put ((&dcc->s), "\377\374\001", &sp);		/* IAC WON'T ECHO */
  }
  /* TODO: add some connchains too? */
  Connchain_Grow ((&dcc->s), 'b');	/* bindtables filter */
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
static char *session_handler_main (char *ident, char *host, idx_t socket,
				   int botsonly, char buf[SHORT_STRING],
				   char client[NAMEMAX+1])
{
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
    if (!(bind && (!botsonly || (uf & U_SPECIAL))))
      return ("not allowed");
  }
  /* get Lname of user */
  strfcpy (buf, "\r\nFoxEye network node\r\n\r\nlogin: ", SHORT_STRING);
  sz = strlen (buf);
  sp = 0;
  time (&t);
  Set_Iface (NULL);
  t += dcc_timeout;
  Unset_Iface();
  while (sz && (get = WriteSocket (socket, buf, &sp, &sz, M_POLL)) >= 0)
    if (time(NULL) > t) break;
  if (get > 0)		/* everything sent and sz == 0 */
    while (time(NULL) < t)
    {
      get = ReadSocket (&client[sz], socket, NAMEMAX - sz, M_POLL);
      if (get < 0)
	break;
      while (get)
	if (client[sz] == '\r' || client[sz] == '\n')
	  break;
	else
	{
	  sz++;
	  get--;
	}
      if (get)
	break;
    }
  if (get > 0)
  {
    get = sz;
    sz = SHORT_STRING;
    get = _do_rfc854_input (client, get, buf, &sz); /* RFC854 */
    client[get] = 0;
    DBG ("direct.c:session_handler: lname=%s", client);
    sz = SHORT_STRING - sz;
    sp = 0;
    while (sz && (get = WriteSocket (socket, buf, &sp, &sz, M_POLL)) >= 0)
      if (time(NULL) > t) break;
  }
  if (get <= 0)
    return ("connection lost");
  /* check of allowance */
  uf = Match_Client (host, ident, client);
  /* for services we have to check network type */
  if ((uf & U_SPECIAL) && (clr = Lock_Clientrecord (client)))
  {
    msg = safe_strdup (Get_Field (clr, ".logout", NULL));
    Unlock_Clientrecord (clr);
  }
  else
    msg = NULL;
  Set_Iface (NULL);
  bind = Check_Bindtable (BT_Login, msg ? msg : "*", uf, 0, NULL);
  FREE (&msg);
  if (bind && !bind->name && (!botsonly || (uf & U_SPECIAL))) /* allowed to logon */
  {
    buf[0] = 0;
    bind->func (client, ident, host, socket, buf, &msg); /* it will unlock dispatcher */
  }
  else
  {
    Unset_Iface();
    msg = "not allowed";
  }
  return msg;
}

static void session_handler (char *ident, char *host, idx_t socket, int botsonly)
{
  char buf[SHORT_STRING];
  char client[NAMEMAX+1];
  size_t sz, sp;
  register char *msg;

  msg = session_handler_main (ident, host, socket, botsonly, buf, client);
  if (msg)					/* was error on connection */
  {
    unsigned short p;

    LOG_CONN (_("Connection from %s terminated: %s"), host, msg);
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
    LOG_CONN ("%s", buf);
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
  void (*prehandler) (pthread_t, idx_t, idx_t);
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
	      (uint32_t)acptr->socket + 1, acptr->lport, 0, msg);
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
    sp = 0;
    sz = 0;
    while (time(NULL) < t)
    {
      sz = ReadSocket (&buf[sp], acptr->id, sizeof(buf) - sp, M_POLL);
      if (sz < 0)
	break;
      while (sz)
	if (buf[sp] == '\r' || buf[sp] == '\n')
	{
	  buf[sp] = 0;
	  break;
	}
	else
	{
	  sp++;
	  sz--;
	}
      if (sz)
	break;
    }
    if (sz > 0)
    {
      dprint (5, "%s ident answer: %s", domain, buf);
      /* overflow is impossible: part of buf isn't greater than buf */
      sscanf (buf, "%*[^:]: %[^: ] :%*[^:]: %23[^ \n]", buf, ident);
      if (strcmp (buf, "USERID"))		/* bad answer */
	*ident = 0;
    }
  } /* ident is checked */
  DBG ("_accept_port: killing ident socket");
  KillSocket (&acptr->id);
  /* %* - ident, %@ - hostname, %L - Lname, %P - port */
  Set_Iface (NULL);
  printl (buf, sizeof(buf), format_dcc_input_connection, 0, NULL, domain,
	  acptr->client, NULL, 0, p, 0, ident[0] ? ident : _("((unknown))"));
  Unset_Iface();
  LOG_CONN ("%s", buf);
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
  while (acptr->socket >= 0)			/* ends by KillSocket() */
  {
    if ((new_idx = AnswerSocket (acptr->socket)) == E_AGAIN)
      continue;
    else if (new_idx < 0)
    {
      LOG_CONN (_("Listening socket died."));	/* print error message */
      if (acptr->prehandler)			/* notify caller */
	acptr->prehandler ((pthread_t)0, acptr->socket, -1);
      KillSocket (&acptr->socket);		/* die now */
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
      KillSocket (&child->socket);
      FREE (&child);
    }
    else
    {
      if (acptr->prehandler)
	acptr->prehandler (th, acptr->socket, child->socket);
      else
	pthread_detach (th);		/* since it's not joinable */
      if (acptr->client)		/* it's client connection so die now */
	KillSocket (&acptr->socket);
    }
  }
  /* terminated - destroy all */
  FREE (&acptr->confline);
  Set_Iface (iface);
  iface->ift |= I_FINWAIT; /* let know dispatcher that we must be finished */
  Unset_Iface();
  /* we don't need to free acptr since dispatcher will do it for us */
  return NULL;
}
#undef acptr

/*
 * Global function for listening port.
 * Returns: -1 if no listening or listen socket ID on success.
 */
static idx_t
Listen_Port_main (char *client, char *host, unsigned short port, char *confline,
		  void (*prehandler) (pthread_t, idx_t, idx_t),
		  void (*handler) (char *, char *, char *, idx_t))
{
  accept_t *acptr;
  idx_t p;
  int n = -1;
  
  if (!handler ||			/* stupidity check ;) */
      (port && port < 1024))		/* don't try system ports! */
    return -1;
  p = GetSocket();
  /* check for two more sockets - accepted and ident check */
  if (p < 0 || p >= SOCKETMAX - 2 ||
      (n = SetupSocket (p, M_LIST, (host && *host) ? host : NULL, port)) < 0)
  {
    KillSocket (&p);
    return (idx_t)n;
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
    return -1;
  }
  return p;
}

static void _assign_port_range (unsigned short *ps, unsigned short *pe)
{
  *ps = *pe = 0;
  sscanf (dcc_port_range, "%hu - %hu", ps, pe);
  if (*ps < 1024)
    *ps = 1024;
  if (*pe < *ps)
    *pe = *ps;
}

idx_t Listen_Port (char *client, char *host, unsigned short *sport, char *confline,
		   void (*prehandler) (pthread_t, idx_t, idx_t),
		   void (*handler) (char *, char *, char *, idx_t))
{
  unsigned short port, pe;
  idx_t idx;

  if (*sport)
    port = pe = *sport;
  else
    _assign_port_range (&port, &pe);
  while (port <= pe)
  {
    idx = Listen_Port_main (client, host, port, confline, prehandler, handler);
    dprint (4, "Listen_Port: %s:%hu: returned %d", host, port, (int)idx);
    if (idx >= 0)
    {
      *sport = port;
      return idx;
    }
    port++;
  }
  return -1;
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
	    cptr->host, cptr->port, (int)*cptr->idx);
  else
  {
    char buf[SHORT_STRING];

    LOG_CONN ("Could not make connection to %s at port %hu (socket %d): %s",
	      cptr->host, cptr->port, (int)*cptr->idx,
	      SocketError (i, buf, sizeof(buf)));
    KillSocket (cptr->idx);
  }
  cptr->handler (i, cptr->id);
  pthread_cleanup_pop (1);
  return NULL;
}
#undef cptr

int Connect_Host (char *host, unsigned short port, pthread_t *th, idx_t *idx,
		  void (*handler) (int, void *), void *id)
{
  connect_t *cptr;

  if (!handler || !host || !port)	/* stupidity check ;) */
    return 0;
  cptr = safe_malloc (sizeof(connect_t));
  cptr->host = safe_strdup (host);
  cptr->port = port;
  cptr->idx = idx;
  cptr->handler = handler;
  cptr->id = id;
  if (pthread_create (th, NULL, &_connect_host, cptr))
  {
    FREE (&cptr->host);
    FREE (&cptr);
    return 0;
  }
  return 1;
}

/*
 * Internal dcc bindings:
 * int func(peer_t *from, char *args)
 * int func(session_t *from, char *args)
 */

static void _say_current (peer_t *dcc, const char *msg)
{
  New_Request (dcc->iface, 0, _("Now: %s"), NONULL(msg));
}

		/* .away [<message>] */
BINDING_TYPE_dcc (dc_away);
static int dc_away (peer_t *dcc, char *args)
{
  char ch[16];

  if (!args && !dcc->dname)
    return -1; /* cannot unaway if isn't away */
  /* reset away message */
  FREE (&dcc->dname);
  if (args)
    dcc->dname = safe_strdup (args);
  if (!IS_SESSION(dcc) || ((session_t *)dcc)->botnet < 0)
    return -1; /* nobody to notify */
  /* send notify to botnet */
  Set_Iface (((session_t *)dcc)->alias);
  snprintf (ch, sizeof(ch), ":*:%d", ((session_t *)dcc)->botnet);
  if (args)
    Add_Request (I_DCCALIAS, ch, F_T_NOTICE, _("now away: %s"), args);
  else
    Add_Request (I_DCCALIAS, ch, F_T_NOTICE, _("returned to life."));
  Unset_Iface();
  return -1;	/* don't log it */
}

		/* .me <message> */
BINDING_TYPE_dcc (dc_me);
static int dc_me (peer_t *dcc, char *args)
{
  binding_t *bind = NULL;
  char ch[16];

  if (!args)
    return 0;
  if (!IS_SESSION(dcc) || ((session_t *)dcc)->botnet < 0)
    return -1;				/* ignore it from not-sessions */
  do
  {
    if ((bind = Check_Bindtable (BT_Chatact, args, dcc->uf, U_ANYCH, bind)))
    {
      if (bind->name)
	RunBinding (bind, NULL, dcc->iface->name, NULL, NULL, DccIdx(dcc), args);
      else
	bind->func (dcc, args);
    }
  } while (bind);
  Set_Iface (((session_t *)dcc)->alias);
  snprintf (ch, sizeof(ch), ":*:%d", ((session_t *)dcc)->botnet);
  Add_Request (I_DCCALIAS, ch, F_T_ACTION, "%s", args);
  Unset_Iface();
  return -1;	/* no log it */
}

		/* .boot <nick on botnet> */
BINDING_TYPE_dcc (dc_boot);
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
    New_Request (dcc->iface, 0, "%s", msg);
    return -1;	/* no log it */
  }
  Add_Request (I_LOG, "*", F_T_NOTICE | F_CONN, _("%s booted by %s."),
	       args, dcc->iface->name);
  uif->ift |= uif->IFSignal (uif, S_TERMINATE);
  return 1;
}

static void
_set_console_parms (session_t *dcc, clrec_t *user, char *fl, char *chan, int botch)
{
  char cons[SHORT_STRING];

  snprintf (cons, sizeof(cons), "%s %s %d",
	    fl[0] ? fl : "-", chan ? chan : "-", botch);
  Set_Field (user, "", cons, 0);
  Unlock_Clientrecord (user);
  setconsole (dcc);
  dprint (4, "dcc:_set_console_parms: %s", cons);
}

#ifdef HAVE_ICONV
		/* .charset [<charset name>] */
BINDING_TYPE_dcc (dc_charset);
static int dc_charset (peer_t *dcc, char *args)
{
  conversion_t *conv;
  const char *charset;
  clrec_t *u;

  if (args)
  {
    conv = Get_Conversion (args);
    charset = Conversion_Charset (conv);
    if (conv != dcc->iface->conv)	/* changed */
    {
      Free_Conversion (dcc->iface->conv);
      dcc->iface->conv = conv;
      if (IS_SESSION(dcc) && ((session_t *)dcc)->alias)
      {
	Free_Conversion (((session_t *)dcc)->alias->conv);
	((session_t *)dcc)->alias->conv = Clone_Conversion (conv);
      }
      if (IS_SESSION(dcc) && ((session_t *)dcc)->log)
      {
	Free_Conversion (((session_t *)dcc)->log->conv);
	((session_t *)dcc)->log->conv = Clone_Conversion (conv);
      }
      if ((u = Lock_Clientrecord (dcc->iface->name)))
      {
	Set_Field (u, "charset", charset, 0);
	Unlock_Clientrecord (u);
      }
    }
    else
      Free_Conversion (conv);		/* not changed */
  }
  else
    charset = Conversion_Charset (dcc->iface->conv);
  _say_current (dcc, charset ? charset : "NONE");
  return 1;
}

		/* .chcharset <lname> [<charset name>] */
BINDING_TYPE_dcc (dc_chcharset);
static int dc_chcharset (peer_t *dcc, char *args)
{
  const char *charset;
  char *c;
  clrec_t *u;

  if (!args)				/* has to have at least 1 arg */
    return 0;
  charset = gettoken (args, &c);
  if (!(u = Lock_Clientrecord (args)))
  {
    New_Request (dcc->iface, 0, "No such client known: %s", args);
    if (*charset) *c = ' '; /* restore after gettoken() */
    return 0;
  }
  if (*charset)
    Set_Field (u, "charset", charset, 0); /* set field for client */
  else
    charset = Get_Field (u, "charset", NULL);
  Unlock_Clientrecord (u);
  New_Request (dcc->iface, 0, "Charset for %s is now %s.", args,
	       charset ? charset : "NONE");
  // TODO: can we update charset for user right now?
  if (*charset)
    *c = ' '; /* restore after gettoken() */
  return 1;
}
#endif

#define session ((session_t *)dcc)
		/* .chat [<botnet channel #>] */
BINDING_TYPE_dcc (dc_chat);
static int dc_chat (peer_t *dcc, char *args)
{
  char consfl[64];
  char chan[128] = "";
  int botch = atoi (NONULL(args));
  clrec_t *user;

  if (!IS_SESSION(session))			/* aliens can have only channel 0 */
    return 0;
  else if (botch == session->botnet)
    return 1;
  _chat_part (session, NULL);
  user = Lock_Clientrecord (session->s.iface->name);
  consfl[0] = 0;
  if (user)
  {
    register char *c = Get_Field (user, "", NULL);
    sscanf (NONULL(c), "%63s %127s", consfl, chan);
    _set_console_parms (session, user, consfl, chan, botch);
  }
  _chat_join (session);
  return 1;
}

static void _console_fl (session_t *dcc, char *plus, char *minus, char *ch)
{
  char flags[64];
  char *cons = flags;
  register char *fl = flags;
  char chan[128];			/* channel from config */
  clrec_t *user;
  register int it = 0;

  minus = NONULL(minus);
  dprint (4, "dcc:_console_fl: %s %s %s %s", dcc->s.iface->name, plus, minus, NONULL(ch));
  user = Lock_Clientrecord (dcc->s.iface->name);
  if (!user)
    return;				/* hmm, could it be? */
  cons = Get_Field (user, "", NULL);	/* default color to mirc */
  if (cons)
    sscanf (cons, "%63s %127s", flags, chan);
  else
    chan[0] = 0;
  if (!ch)
    ch = chan;
  if (!cons)				/* it's strange fairly but use it */
    cons = getconsole (dcc, flags, sizeof(flags));
  while (*cons && *cons != ' ')
  {
    if (!strchr (minus, *cons) && (strchr (_Flags, *cons) ||
	*cons == '%' || *cons == '$' || *cons == '#' || *cons == '+'))
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
  if (it || safe_strcmp (ch, chan))
    _set_console_parms (dcc, user, flags, ch, dcc->botnet);
  else
    Unlock_Clientrecord (user);
}

		/* .color [off|mono|ansi|mirc] */
BINDING_TYPE_dcc (dc_color);
static int dc_color (peer_t *dcc, char *args)
{
  flag_t fl = session->loglev & (F_COLORCONV | F_COLOR);

  if (!IS_SESSION(session))			/* aliens cannot change this */
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
    _say_current (&session->s, msg);
  }
  else
  {
    if (!strcmp (args, "mirc"))
      _console_fl (session, "", "#$%", NULL);
    else if (!strcmp (args, "mono"))
      _console_fl (session, "#", "$%", NULL);
    else if (!strcmp (args, "ansi"))
      _console_fl (session, "%", "#$", NULL);
    else if (!strcmp (args, "off"))
      _console_fl (session, "$", "#%", NULL);
    else return 0;
  }
  return 1;
}

		/* .console [<channel>] [+-<mode>] */
BINDING_TYPE_dcc (dc_console);
static int dc_console (peer_t *dcc, char *args)
{
  char msg[MESSAGEMAX];
  char cl[128];
  char pm[2];
  char *cc = "*";
  char *ch;
  flag_t f, fl;
  int i = 0;

  if (!IS_SESSION(session))		/* you cannot change console logging */
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
	strfcpy (msg, args, sizeof(msg));
	*cc = ' ';
	cc = msg;
      }
      else
	cc = args;
      if (!Find_Iface (I_SERVICE, cc) || Unset_Iface())
      {
	New_Request (session->s.iface, 0, _("No such active service found: %s"),
		     cc);
	return -1;
      }
      args = NextWord (args);
    }
    else if (*args == '*')		/* reset channel */
      args = NextWord (args);
    else if (session->log && session->log->name)
      cc = session->log->name;
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
    _console_fl (session, cl, &cl[64], cc);
  }
  fl = session->loglev & (F_PRIV | F_CMDS | F_CONN | F_SERV | F_WALL | F_USERS | F_DEBUG | F_BOOT | F_ERROR | F_WARN | F_PUBLIC | F_JOIN | F_MODES | F_BOTNET);
  if (session->log && session->log->name && (fl & (F_PUBLIC | F_JOIN | F_MODES)))
    cc = session->log->name;
  else
    cc = "";
  /* reset result */
  msg[0] = cl[0] = 0;
  /* check for channel */
  if (!cc)
    cc = "";
  for (f = F_MIN, ch = _Flags; *ch; ch++, f += f)
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
	case F_BOTNET:
	  m2 = _("botnet notices");
	  break;
	default: /* F_MODES */
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
    New_Request (session->s.iface, 0, "%s: %s%s%s %s %s", _("Your console logs"),
		 *msg ? msg : "", *msg ? _(", and ") : "", cl,
		 _("on the channel"), cc);
  else
    New_Request (session->s.iface, 0, "%s: %s", _("Your console logs"),
		 *msg ? msg : "none");
  return 1;
}

static void _report_req (iftype_t iface, char *who)
{
  char t[sizeof(ifsig_t)] = {S_REPORT};

  Add_Request (iface, who, F_SIGNAL, t);
}

		/* .cstat */
BINDING_TYPE_dcc (dc_cstat);
static int dc_cstat (peer_t *dcc, char *args)
{
  char b[SHORT_STRING];

  printl (b, sizeof(b), format_cstat_head, 0, NULL, NULL, NULL, NULL, 0, 0, 0, NULL);
  New_Request (dcc->iface, 0, "%s", b);
  ReportFormat = format_cstat;
  _report_req (I_CONNECT, "*");
  return 1;
}

		/* .echo [on|off] */
BINDING_TYPE_dcc (dc_echo);
static int dc_echo (peer_t *dcc, char *args)
{
  flag_t fl = session->loglev & F_ECHO;

  if (!IS_SESSION(session))		/* aliens cannot on/off echo ;) */
    return 0;
  if (args)
  {
    if (!strcmp (args, "on"))
    {
      if (!fl)
	_console_fl (session, "+", NULL, NULL);
    }
    else if (!strcmp (args, "off"))
    {
      if (fl)
	_console_fl (session, NULL, "+", NULL);
    }
    else
      return -1;
    fl = session->loglev & F_ECHO;
  }
  if (fl)
    _say_current (&session->s, "on");
  else
    _say_current (&session->s, "off");
  return 1;
}

		/* .help [<what need>] */
BINDING_TYPE_dcc (dc_help);
static int dc_help (peer_t *dcc, char *args)
{
  char *sec;
  char *fst;
  bindtable_t *ssbt;
  userflag df;

  if (!IS_SESSION(session))
    return 1;
  if (session->log && session->log->name)
    df = Get_Clientflags (session->s.iface->name, session->log->name);
  else
    df = 0;
  if ((fst = args))
    sec = gettoken (args, &args);
  else
    sec = NULL;
  DBG ("dc_help for %s on %c%s", fst, session->ssbt ? '*' : '!', session->netname);
  if ((!sec || !*sec) && session->netname && session->ssbt &&
      (!fst || Check_Bindtable (session->ssbt, fst, session->s.uf, df, NULL)))
    ssbt = session->ssbt;
  else
    ssbt = NULL;
  /* usage - not required if no arguments */
  if (args && !(ssbt && Get_Help (NULL, fst, session->s.iface,
				  session->s.uf, df, ssbt, _("Usage: "), -1)) &&
      !Get_Help (fst, sec, session->s.iface, session->s.uf, df, BT_Dcc,
		 _("Usage: "), 0))
    return -1;
  /* full help */
  if (ssbt)
    Get_Help (NULL, fst ? fst : "*", session->s.iface, session->s.uf, df, ssbt, NULL, 2);
  if (!ssbt || !fst)
    Get_Help (fst, sec, session->s.iface, session->s.uf, df, BT_Dcc, NULL, 2);
  if (sec && *sec)
    *args = ' ';
  return 1;			/* return 1 because usage at least displayed */
}

		/* .motd */
BINDING_TYPE_dcc (dc_motd);
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
    New_Request (dcc->iface, 0, "%s", c);
  }
  return 1;
}

		/* .simul <Lname> <message|command> */
BINDING_TYPE_dcc (dc_simul);
static int dc_simul (peer_t *dcc, char *args)
{
  session_t *ud;
  INTERFACE *iface;
  char name[IFNAMEMAX+1];

  if (!args)
    return 0;
  args = NextWord_Unquoted (name, args, sizeof(name));
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
    ud->s.parse (&ud->s, name, args, ud->s.uf, 0, DccIdx(ud), ud->botnet, ud->ssbt,
		 ud->netname, ud->alias);
    Unset_Iface();		/* from Set_Iface() */
  }
  else
    New_Request (dcc->iface, 0,
		 _("You can simulate only local DCC clients, sorry"));
  Unset_Iface();		/* from Find_Iface() */
  return 1;
}

		/* .who [<service>] */
BINDING_TYPE_dcc (dc_who);
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
  New_Request (dcc->iface, 0, "%s", b);
  ReportMask = -1;
  if (args)
    _report_req (I_SERVICE, args);
  else
    _report_req (I_DIRECT, "*");
  return 1;
}

		/* .w [channel] */
BINDING_TYPE_dcc (dc_w);
static int dc_w (peer_t *dcc, char *args)
{
  char b[SHORT_STRING];

  printl (b, sizeof(b), format_w_head, 0, NULL, NULL, NULL, NULL, 0, 0, 0, NULL);
  New_Request (session->s.iface, 0, "%s", b);
  if (args)
    snprintf (b, sizeof(b), ":*:%s", args);
  else if (!IS_SESSION(session))
    strcpy (b, ":*:0");
  else
    snprintf (b, sizeof(b), ":*:%d", session->botnet);
  ReportFormat = format_w;
  _report_req (I_DCCALIAS, b);
  if (args)
    strcpy (args, &b[3]);
  return 1;
}

		/* .quit [<message>] */
BINDING_TYPE_dcc (dc_quit);
static int dc_quit (peer_t *dcc, char *args)
{
  ShutdownR = args;
  if (dcc->iface->IFSignal)
    dcc->iface->IFSignal (dcc->iface, S_TERMINATE);
  ShutdownR = NULL;
  return 1;
}

		/* .connect <network|channel|bot> [<args>] */
BINDING_TYPE_dcc (dc_connect);
static int dc_connect (peer_t *dcc, char *args)
{
  char netname[IFNAMEMAX+1];
  char *snet;
  clrec_t *netw;
  char *nt;
  binding_t *bind;
  userflag uf = 0;

  /* find the network and it type as @net->info */
  args = NextWord_Unquoted (netname, args, sizeof(netname));
  if ((snet = strrchr (netname, '@'))) /* network if it's channel */
    snet++;
  else
    snet = netname;
  /* try as network/bot at first then as channel */
  if (!((uf = Get_Clientflags (snet, NULL)) & U_SPECIAL) ||
      !(netw = Lock_Clientrecord (snet)))
    return 0;
  /* find the connect type in BT_Connect */
  nt = Get_Field (netw, ".logout", NULL);
  if (!nt)
    bind = NULL;
  else if (snet != netname) /* a channel (network service) */
    bind = Check_Bindtable (BT_Connect, nt, 0, U_SPECIAL, NULL);
  else /* a network/bot (local service) */
    bind = Check_Bindtable (BT_Connect, nt, uf, 0, NULL);
  Unlock_Clientrecord (netw);
  /* try to call connect function */
  if (!bind || bind->name)
  {
    New_Request (dcc->iface, 0, _("I don't know how to connect to %s."),
		 netname);
    return -1; /* no log it */
  }
  return bind->func (netname, args);
}

		/* .disconnect <network|channel|bot> [<reason>] */
BINDING_TYPE_dcc (dc_disconnect);
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
  cif->ift |= cif->IFSignal (cif, S_TERMINATE);
  ShutdownR = NULL;
  return 1;
}

static void _dc_init_bindings (void)
{
#define NB(a,b) Add_Binding ("dcc", #a, b, U_NONE, &dc_##a, NULL)
  NB (away, U_ACCESS);
  NB (boot, U_OP);
#ifdef HAVE_ICONV
  NB (charset, 0);
  NB (chcharset, U_MASTER);
#endif
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
BINDING_TYPE_passwd (IntCrypt);
static void IntCrypt (const char *pass, char **cr)
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

#define __FGSET	(1<<6)
#define __BGSET	(1<<7)
#define __BOLD	(1<<8)
#define __BLINK	(1<<9)
#define __REV	(1<<10)
#define __UL	(1<<11)

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

int mirccolors[] = {__BOLD|7, 0, 4, 2, 1, 3, 5, __BOLD|1, __BOLD|3, __BOLD|2,
		    6, __BOLD|6, __BOLD|4, __BOLD|5, __BOLD|0, 7};

BINDING_TYPE_out_filter (ConvertColors);
static void ConvertColors (peer_t *dcc, char *msg, size_t msglen)
{
  unsigned char buff[HUGE_STRING];
  register unsigned char *c, *s;
  register flag_t fl;
  int colormode;

  if (!IS_SESSION(session))
    return;
  colormode = 0;
  fl = (session->loglev & (F_COLOR | F_COLORCONV));
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
	  register int colorcode;

	  colormode &= (__BLINK | __UL);
	  if (c[1] != ',')			/* foreground */
	  {
	    c++;
	    if (*c == '0' && c[1] >= '0' && c[1] <= '9')
	      colorcode = *(++c) - '0';
	    else if (*c == '1' && c[1] >= '0' && c[1] < '6')
	      colorcode = *(++c) - '0' + 10;
	    else
	      colorcode = *c - '0';
	    if (fl)				/* ansi or mono */
	    {
	      if (fl & F_COLOR)			/* ansi */
		colormode |= __FGSET;
	      colormode |= mirccolors[colorcode];
	    }
	  }
	  if (c[1] == ',' && c[2] >= '0' && c[2] <= '9')
	  {
	    c += 2;
	    if (*c == '0' && c[1] >= '0' && c[1] <= '9')
	      colorcode = *(++c) - '0';
	    else if (*c == '1' && c[1] >= '0' && c[1] < '6')
	      colorcode = *(++c) - '0' + 10;
	    else
	      colorcode = *c - '0';
	    if (fl & F_COLOR)			/* ansi */
	      colormode |= __BGSET + ((mirccolors[colorcode] & ~__BOLD) << 3);
	    else if (fl)			/* mono */
	    {
	      if (mirccolors[colorcode] & __BOLD)
		  colormode |= __REV;
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
      case '\011':		/* HT */
      case '\007' :		/* bell */
      case '\r' :		/* CR */
      case '\n' :		/* LF */
	*s++ = *c;
	break;
      default:			/* supress rest of control codes */
	if (*c > '\037')
	  *s++ = *c;
    }
  if (colormode)		/* has ansi or mono color codes */
  {
    if (s > &buff[msglen-8])
      s = &buff[msglen-8];
    memcpy (s, "\033[0;10m", 8);
  }
  else
    *s = 0;
  strfcpy (msg, buff, msglen);
}

/* Config/scripts functions... */
static int _dellistenport (char *pn)
{
  INTERFACE *pi;

  if (!(pi = Find_Iface (I_LISTEN, pn)))
    return 0;
  Unset_Iface();
  if (pi->IFSignal)
    pi->ift |= pi->IFSignal (pi, S_TERMINATE);
  else
  {
    ERROR ("_dellistenport: no signal function for \"%s\"", pn);
    pi->ift |= I_DIED;
  }
  return 1;
}

typedef struct
{
  unsigned short port;
  userflag u;
  int cnt;
  tid_t tid;
} _port_retrier;

static iftype_t _port_retrier_s (INTERFACE *iface, ifsig_t signal)
{
  _port_retrier *r;
  idx_t socket;

  switch (signal)
  {
    case S_SHUTDOWN:
    case S_TERMINATE:
      KillTimer (((_port_retrier *)iface->data)->tid);
      return I_DIED;
    case S_TIMEOUT:
      r = (_port_retrier *)iface->data;
      if (r->u & U_ANY)
	socket = Listen_Port (NULL, hostname, &r->port, iface->name, NULL, &session_handler_any);
      else
	socket = Listen_Port (NULL, hostname, &r->port, iface->name, NULL, &session_handler_bots);
      if (socket >= 0)
      {
	LOG_CONN (_("Listening on port %hu%s."), r->port,
		  (r->u & U_ANY) ? "" : _(" for bots"));
	return I_DIED;			/* it done... */
      }
      else if (--r->cnt == 0)
      {
	LOG_CONN (_("Too many retries to listen port %hu%s, aborted."),
		  r->port, (r->u & U_ANY) ? "" : _(" for bots"));
	return I_DIED;			/* it done... */
      }
      r->tid = NewTimer (iface->ift, iface->name, S_TIMEOUT, 10, 0, 0, 0);
      LOG_CONN (_("Could not open listening port %hu%s, retrying in 10 seconds."),
		r->port, (r->u & U_ANY) ? "" : _(" for bots"));
      break;
    default: ;
  }
  return 0;
}

ScriptFunction (FE_port)	/* to config - see thrdcc_signal() */
{
  unsigned short port;
  idx_t socket;
  INTERFACE *tmp;
  static char msg[SHORT_STRING];
  userflag u = U_ANY | U_SPECIAL;

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
  if ((tmp = Find_Iface (I_LISTEN, msg)))
  {
    tmp->ift &= ~I_FINWAIT;		/* abort terminating on restart */
    Unset_Iface();
    LOG_CONN (_("Already listening on port %hu!"), port);
    return port;
  }
  if (u & U_ANY)
    socket = Listen_Port (NULL, hostname, &port, msg, NULL, &session_handler_any);
  else
    socket = Listen_Port (NULL, hostname, &port, msg, NULL, &session_handler_bots);
  if (socket < 0)
  {
    /* check if we are called from init() */
    if (Set_Iface (NULL) == NULL)
    {
      INTERFACE *i;
      register _port_retrier *x = safe_malloc (sizeof(_port_retrier));

      x->port = port;
      x->u = u;
      x->cnt = 0;
      i = Add_Iface (I_TEMP, msg, _port_retrier_s, NULL, x);
      x->tid = NewTimer (i->ift, i->name, S_TIMEOUT, 10, 0, 0, 0);
      snprintf (msg, sizeof(msg),
		_("Could not open listening port %hu%s, retrying in 10 seconds."),
		port, (u & U_ANY) ? "" : _(" for bots"));
    }
    else snprintf (msg, sizeof(msg), _("Cannot open listening port on %hu%s!"),
	      port, (u & U_ANY) ? "" : _(" for bots"));
    Unset_Iface();
    BindResult = msg;
    return 0;
  }
  LOG_CONN (_("Listening on port %hu%s."), port,
	    (u & U_ANY) ? "" : _(" for bots"));
  return port;
}

char *IFInit_DCC (void)
{
  _fe_init_sockets();
  _fe_init_connchains();
  /* add own bindtables */
  BT_Dcc = Add_Bindtable ("dcc", B_UCOMPL);		/* these tables have bindings */
  _dc_init_bindings();
  BT_Crypt = Add_Bindtable ("passwd", B_UNIQMASK);
  Add_Binding ("passwd", "$1*", 0, 0, (Function)&IntCrypt, NULL);
  BT_Login = Add_Bindtable ("login", B_MASK);
  Add_Binding ("login", "*", U_ACCESS, U_NONE, (Function)&get_chat, NULL);
  BT_Chaton = Add_Bindtable ("chat-on", B_MASK);	/* rest are empty */
  BT_Outfilter = Add_Bindtable ("out-filter", B_MASK);
  Add_Binding ("out-filter", "*", 0, 0, (Function)&ConvertColors, NULL);
  BT_Chat = Add_Bindtable ("chat", B_MASK);
  BT_Infilter = Add_Bindtable ("in-filter", B_MASK);
  BT_Chatoff = Add_Bindtable ("chat-off", B_MASK);
  BT_Chatact = Add_Bindtable ("chat-act", B_MASK);
  BT_Chatjoin = Add_Bindtable ("chat-join", B_MASK);
  BT_Chatpart = Add_Bindtable ("chat-part", B_MASK);
  BT_Connect = Add_Bindtable ("connect", B_MASK);
  Add_Binding ("connchain-grow", "y", 0, 0, &_ccfilter_y_init, NULL);
  Add_Binding ("connchain-grow", "b", 0, 0, &_ccfilter_b_init, NULL);
  flood_dcc = FloodType ("dcc");
  return NULL;
}
