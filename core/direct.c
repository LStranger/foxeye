/*
 * Copyright (C) 1999-2011  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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

#ifdef HAVE_CRYPT_H
# include <crypt.h>
#endif
#include <fcntl.h>

#include "socket.h"
#include "direct.h"
#include "init.h"
#include "sheduler.h"
#include "list.h"
#include "wtmp.h"
#include "conversion.h"

struct peer_priv
{
  INTERFACE *log;			/* interface for logs */
  INTERFACE *alias;			/* interface for botnet channel */
  char *netname;			/* service name (for "ss-*") */
  struct bindtable_t *ssbt;		/* network-specitic bindtable */
  flag_t loglev;
  int botnet;				/* botnet channel, chat off if < 0 */
  short floodcnt;			/* flood counter */
};

static struct bindtable_t *BT_Crypt;
static struct bindtable_t *BT_Dcc;
static struct bindtable_t *BT_Chat;
static struct bindtable_t *BT_Chatact;
static struct bindtable_t *BT_Outfilter;
static struct bindtable_t *BT_Infilter;
static struct bindtable_t *BT_Login;
static struct bindtable_t *BT_Chaton;
static struct bindtable_t *BT_Chatoff;
static struct bindtable_t *BT_Chatjoin;
static struct bindtable_t *BT_Chatpart;
static struct bindtable_t *BT_Connect;

#define DccIdx(a) ((int)(a)->socket + 1)

typedef struct peer_t peer_t; /* for better usability */

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

static void _chat_join (peer_t *dcc)
{
  register struct binding_t *bind = NULL;
  char *on_bot;
  char *name;
  const char *h;
  char *cc;
  char ch[16];

  /* start getting the messages from botnet channel */
  snprintf (ch, sizeof(ch), ":%d:%d", DccIdx(dcc), dcc->priv->botnet);
  Rename_Iface (dcc->priv->alias, ch);
  name = dcc->iface->name;
  if ((on_bot = safe_strchr (name, '@')))
    on_bot++;
  else
    on_bot = Nick;
  snprintf (ch, sizeof(ch), ":*:%d %c", dcc->priv->botnet, _userdccflag (dcc->uf));
  cc = strchr (ch, ' ');		/* between botch and flag */
  dprint (4, "dcc:_chat_join: %s joining %d", name, dcc->priv->botnet);
  /* run bindtable */
  h = SocketDomain (dcc->socket, NULL);
  Set_Iface (dcc->iface);
  do
  {
    *cc = '\0';
    if ((bind = Check_Bindtable (BT_Chatjoin, &ch[3], U_ALL, U_ANYCH, bind)))
    {
      *cc = ' ';
      if (bind->name)
        RunBinding (bind, NULL, on_bot, name, &ch[3], DccIdx(dcc), h);
      else
        bind->func (dcc->iface, dcc->priv->botnet, h);
    }
  } while (bind);
  Unset_Iface();
  *cc = '\0';
  /* notify local botnet users! */
  if (dcc->priv->botnet >= 0)
    Add_Request (I_DCCALIAS, ch, F_T_NOTICE, _("joined this botnet channel."));
}

static void _chat_part (peer_t *dcc, char *quit)
{
  register struct binding_t *bind = NULL;
  char *on_bot;
  char ch[16];
  char *name = NULL;

  name = dcc->iface->name;
  if ((on_bot = safe_strchr (name, '@')))
    on_bot++;
  else
    on_bot = Nick;
  dprint (4, "dcc:_chat_part: %s parting %d", name, dcc->priv->botnet);
  snprintf (ch, sizeof(ch), ":*:%d", dcc->priv->botnet);
  /* notify the botnet! */
  /* if quit - send the formed notice */
  if (dcc->priv->botnet < 0);
  else if (quit)
    Add_Request (I_DCCALIAS, ch, F_T_NOTICE, _("quit botnet: %s"), quit);
  else
    Add_Request (I_DCCALIAS, ch, F_T_NOTICE, _("left this botnet channel."));
  /* run bindtable */
  Set_Iface (dcc->iface);
  do
  {
    if ((bind = Check_Bindtable (BT_Chatpart, &ch[3], U_ALL, U_ANYCH, bind)))
    {
      if (bind->name)
        RunBinding (bind, NULL, on_bot, name, NULL, DccIdx(dcc), &ch[3]);
      else
        bind->func (dcc->iface, dcc->priv->botnet);
    }
  } while (bind);
  Unset_Iface();
  /* stop getting the messages */
  snprintf (ch, sizeof(ch), ":%d:", DccIdx(dcc));
  Rename_Iface (dcc->priv->alias, ch);
}

static char _Flags[] = FLAG_T;

/*
 * Set console state from saved value: "loglevel IRCchannel BotChannel"
 */
static void setconsole (peer_t *dcc)
{
  register flag_t logl = F_COLOR;	/* color mirc by default */
  flag_t maskfl = (F_JOIN | F_MODES | F_ECHO | F_COLOR | F_COLORCONV);
  register char *fl;
  int botch;
  char chan[128];
  userflag cf;
  struct clrec_t *user;
  char *line;

  /* return if arguments are invalid */
  if ((user = Lock_Clientrecord (dcc->iface->name)))
    line = Get_Field (user, "", NULL);
  else
    line = NULL;
  if (user)
    dcc->uf = Get_Flags (user, "");	/* global+direct service flags */
  else
    dcc->uf = 0;			/* did someone deleted you? */
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
	    logl |= (flag_t)F_MIN<<(fl-_Flags);
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
    if (dcc->uf & U_OWNER)
      maskfl |= (F_BOOT | F_DEBUG);
    if ((dcc->uf & U_MASTER) || (cf & U_MASTER))
      maskfl |= (F_CMDS | F_USERS | F_ERROR | F_WARN);
    if ((dcc->uf & U_OP) || (cf & U_OP))
      maskfl |= (F_CONN | F_PUBLIC | F_WALL | F_PRIV | F_SERV);
    logl &= maskfl;
    if ((logl & F_DEBUG) && O_DLEVEL > 2)
    {
      New_Request (dcc->iface, F_T_NOTICE,
	      "Debug level is too high for DCC CHAT, switching debug log off");
      logl &= ~F_DEBUG;
    }
    /* set DCC session console parameters */
    dcc->priv->botnet = botch;
    if (dcc->priv->log)
    {
      Rename_Iface (dcc->priv->log, chan);
      /* now get network name and "ss-*" bindtable */
      if (dcc->priv->log->name && (line = strrchr (dcc->priv->log->name, '@')))
	line++;
      else
	line = dcc->priv->log->name;
      if ((user = Lock_Clientrecord (line)))
      {
	if (Get_Flags (user, "") & U_SPECIAL)
	{
	  dcc->priv->netname = dcc->priv->log->name;
	  if ((line = Get_Field (user, ".logout", NULL)))
	  {
	    snprintf (chan, sizeof(chan), "ss-%s", line);
	    dcc->priv->ssbt = Add_Bindtable (chan, B_UCOMPL);
	  }
	}
	else
	  dcc->priv->netname = NULL;
	Unlock_Clientrecord (user);
      }
      else
	dcc->priv->netname = NULL;
    }
  }
  else if (user)
    Unlock_Clientrecord (user);
  dcc->priv->loglev = logl;
}

static char *getconsole (peer_t *dcc, char *str, size_t sz)
{
  register int i;
  register char *s = str;
  register flag_t f = F_MIN;

  sz -= 3;
  if (dcc->priv->loglev & F_ECHO)
    *s++ = '+';
  else
    sz++;
  if (!(dcc->priv->loglev & F_COLOR))
  {
    if (dcc->priv->loglev & F_COLORCONV)
      *s++ = '#';
    else
      *s++ = '$';
  }
  else if (dcc->priv->loglev & F_COLORCONV)
    *s++  = '%';
  else
    sz++;
  for (i = 0; _Flags[i] && sz > 1; i++, f += f)
    if (dcc->priv->loglev & f)
    {
      *s++ = _Flags[i];
      sz--;
    }
  *s = 0;
  return str;
}

static short *flood_dcc;

/* if s==0 then quiet termination (shutdown sequence) */
static void _died_iface (INTERFACE *iface, char *buf, size_t s)
{
  struct binding_t *bind = NULL;
  peer_t *dcc = iface->data;
  userflag cf = 0;

  if (!dcc || dcc->socket < 0)			/* is it already killed? */
    return;
  iface = dcc->iface;				/* to the right one! */
  iface->ift |= I_DIED;
  dcc->state = P_LASTWAIT;
  if (s == 0)					/* is this shutdown call? */
    return;
  dprint (4, "dcc:_died_iface: %s", iface->name);
  if (Connchain_Kill (dcc))			/* always true */
    KillSocket (&dcc->socket);
  /* %L - login nick, %@ - hostname */
  printl (buf, s, format_dcc_lost, 0, NULL,
	  SocketDomain (dcc->socket, NULL), iface->name, NULL, 0, 0, 0, NULL);
  LOG_CONN ("%s", buf);
  NoCheckFlood (&dcc->priv->floodcnt);		/* remove all flood timers */
  if (dcc->state <= P_LOGIN)			/* if it was fresh connection */
  {
    FREE (&dcc->priv);
    return;
  }
  NewEvent (W_END, ID_ME, FindLID (iface->name), 0); /* log to Wtmp */
  /* now run "chat-part" and "chat-off" bindings... */
  if (dcc->priv->log)
    cf = Get_Clientflags (iface->name, dcc->priv->log->name);
  _chat_part (dcc, ShutdownR ? ShutdownR : _("no reason.")); /* NONULL */
  do
  {
    if ((bind = Check_Bindtable (BT_Chatoff, iface->name, dcc->uf, cf, bind)))
    {
      if (bind->name)
        RunBinding (bind, NULL, iface->name, NULL, NULL, DccIdx(dcc), NULL);
      else
        bind->func (dcc);
    }
  } while (bind);
  FREE (&dcc->priv);		/* dispatcher will get rid of subinterfaces */
}

/* it's really static but it's used by console too :( */
void Dcc_Parse (peer_t *dcc, char *name, char *cmd, userflag gf, userflag cf,
		int dccidx, int botch, struct bindtable_t *ssbt, char *service)
{
  char *arg;
  struct binding_t *bind;
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
    snprintf (to, sizeof(to), ":*:%d", botch);
    Add_Request (I_DCCALIAS, to, F_T_MESSAGE | F_BOTNET, "%s", cmd);
  }
}

/*
 * get message for user, if it is
 * to me or from another user on same botnet channel to "*"
 * used also when such command as "su" or "files" is in progress
 */
static int dcc_request (INTERFACE *iface, REQUEST *req)
{
  peer_t *dcc = iface->data;
  ssize_t sw;
  struct binding_t *bind = NULL;
  userflag cf = 0;
  char *cmd;
  char buf[MESSAGEMAX+LNAMELEN+4];	/* increased for possible prifix */
#ifdef HAVE_ICONV
  char sbuf[MESSAGEMAX+LNAMELEN+4];
#endif

  if (dcc->state == P_LASTWAIT)	/* already killed */
    return REQ_OK;
  if (dcc->state == P_LOGIN)		/* init the client session */
  {
    register char *name = dcc->iface->name;

    dcc->state = P_TALK;
    setconsole (dcc);
    if (dcc->priv->log)
      cf = Get_Clientflags (name, dcc->priv->log->name);
    else
      cf = 0;
    /* run "chat-on" and "chat-join" bindings... */
    bind = NULL;
    if (!dcc->iface->prev) do		/* it might be tricked so check it */
    {
      if ((bind = Check_Bindtable (BT_Chaton, name, dcc->uf, cf, bind)))
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
  /* check if this is my botnet message but echo disabled */
  if (req && req->from == iface && (req->mask_if & I_DCCALIAS) &&
      !strncmp (req->to, ":*:", 3) && !(dcc->priv->loglev & F_ECHO))
    req = NULL;
  if (dcc->priv->log && dcc->priv->log->name)
    cf = Get_Clientflags (dcc->iface->name, dcc->priv->log->name);
  sw = 0;
  if ((sw = Peer_Put (dcc, "", &sw)) > 0 && /* connchain is ready */
      req)				/* do we have something to out? */
  {
    DBG ("process request: type %#x, flag %#x, to %s, starts %.10s",
	 req->mask_if, req->flag, req->to, req->string);
    /* for logs... formatted, just add timestamp */
    if (req->mask_if & I_LOG)
    {
      if (req->flag & dcc->priv->loglev)
	printl (buf, sizeof(buf), "[%t] %*", 0, NULL, NULL, NULL, NULL,
		0, 0, 0, req->string);
      else
	buf[0] = 0;
      req = NULL;
    }
    /* flush command - see the users.c, ignore commands for non-bots */
    else if (req->string[0] == '\010')
    {
      dcc->iface->IFSignal (dcc->iface, S_FLUSH);
      buf[0] = 0;
      req = NULL;
    }
    /* for chat channel messages */
    else if (req->mask_if & I_DCCALIAS)
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
    sw = Peer_Put (dcc, cmd, &sw);
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
  if (dcc->state == P_INITIAL)
  {
    WARNING("direct.c:dcc_request: unexpectedly P_INITIAL state for %s",
	    iface->name);
    dcc->state = P_LOGIN;
    return REQ_OK;
  }
  sw = Peer_Get (dcc, buf, sizeof(buf));
  if (sw < 0)
  {
    ShutdownR = _("session lost");
    _died_iface (iface, buf, sizeof(buf));
    ShutdownR = NULL;
    return REQ_OK;
  }
  if (sw < 2)				/* ignore empty input too */
    return REQ_OK;
  dcc->last_input = Time;		/* timestamp for idle */
  /* check the "dcc" flood... need just ignore or break connection? TODO? */
  if (CheckFlood (&dcc->priv->floodcnt, flood_dcc) > 0)
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
  dcc->parse (dcc, iface->name, cmd, dcc->uf, cf, DccIdx(dcc),
	      dcc->priv->botnet, dcc->priv->ssbt, dcc->priv->netname);
  return REQ_OK;
}

/*
 * if signal == S_TERMINATE then also down iface->data->log interface
 * if signal == S_FLUSH then just update user info from userfile
 * S_SHUTDOWN, S_REPORT - as default...
 */
static iftype_t dcc_signal (INTERFACE *iface, ifsig_t signal)
{
  peer_t *dcc = iface->data;
  char c[LNAMELEN+2];
  char buf[STRING];
  int idle;
  INTERFACE *tmp;
  unsigned short p;
  const char *dom;
  char *desc;

  if (!dcc || dcc->socket < 0)		/* already killed? */
    return I_DIED;
  if (dcc) switch (signal)
  {
    case S_FLUSH:
      if (iface->name && *iface->name)
	/* check the IRC and botnet channels, set dcc->uf */
	setconsole (dcc);
      break;
    case S_REPORT:
      switch (dcc->state)
      {
	case P_LOGIN:
	  /* %@ - hostname, %L and %N - Lname, %P - socket, %* - state */
	  printl (buf, sizeof(buf), ReportFormat, 0,
		  dcc->iface->name, SocketDomain (dcc->socket, NULL),
		  dcc->iface->name, NULL, (uint32_t)0, dcc->socket + 1,
		  0, "logging in");
	  break;
	default:
	  idle = Time - dcc->last_input;
	  dom = SocketDomain (dcc->socket, &p);
	  if (dcc->dname && !(dcc->iface->ift & I_LOCKED))
	  {
	    desc = safe_malloc (strlen (dcc->dname) + 7);
	    strcpy (desc, "away: ");
	    strcpy (&desc[6], dcc->dname);
	  }
	  else
	    desc = NULL;
	  c[0] = _userdccflag (dcc->uf);
	  strfcpy (&c[1], dcc->iface->name, sizeof(c)-1);
	  /* %@ - hostname, %L and %N - Lname, %# - start time,
	     %P - socket number, %- - idle time, %* - state */
	  printl (buf, sizeof(buf), ReportFormat, 0,
		  c, dom, &c[1], dcc->start, (uint32_t)0, dcc->socket + 1,
		  idle, (dcc->iface->ift & I_LOCKED) ? "chat off" : desc);
	  FREE (&desc);
      }
      tmp = Set_Iface (iface);
      New_Request (tmp, F_REPORT, "%s", buf);
      Unset_Iface();
      break;
    case S_STOP:
      /* stop the interface */
      iface->ift |= I_LOCKED;
      _chat_part (dcc, NULL);			/* has left botnet channel */
      break;
    case S_CONTINUE:
      /* restart the interface - only if user has partyline access */
      dcc_signal (iface, S_FLUSH);		/* recursive call */
      dcc->parse = &Dcc_Parse;
      iface->ift &= ~I_LOCKED;
      if (dcc->state != P_LASTWAIT)		/* has socket died? */
      {
	dcc->state = P_TALK;
	_chat_join (dcc);			/* has returned to channel */
	break;
      }						/* else terminate it */
    case S_TERMINATE:
      /* using already filled ShutdownR - can it be weird? */
      _died_iface (iface, buf, sizeof(buf));
      FREE (&dcc->dname);
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
	WriteSocket (dcc->socket, buf, &bufpos, &inbuf, M_RAW);
      }
      _died_iface (iface, NULL, 0);
    default: ;
  }
  return 0;
}

#define IS_SESSION(a) (a->iface->IFSignal == dcc_signal)

int Check_Passwd (const char *pass, char *encrypted)
{
  char *upass = NULL;
  struct binding_t *bind;

  bind = Check_Bindtable (BT_Crypt, encrypted, U_ALL, U_ANYCH, NULL);
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
struct connchain_buffer
{
  char data[24];
  size_t tosend;
};

static ssize_t _ccfilter_y_send(struct connchain_i **ch, idx_t id,
				const char *str, size_t *sz,
				struct connchain_buffer **b)
{
  ssize_t i = E_NOSOCKET, ii = 0, left;
  char *c;

  if (*b == NULL)			/* already terminated */
    return i;
  if ((i = Connchain_Put (ch, id, "", &ii)) < 0) /* check next link */
    return i;
  if (i != CONNCHAIN_READY)		/* next link in chain isn't ready */
    return 0;				/* we don't ready too, of course */
  if ((left = *sz) == 0 && str != NULL)	/* it's a test! */
    return CONNCHAIN_READY;
  if ((*b)->tosend)			/* there was something to send */
  {
    i = Connchain_Put (ch, id, (*b)->data, &(*b)->tosend);
    if (i < 0)				/* has it died? */
      return i;
    if ((*b)->tosend)			/* still something left */
    {
      if (i > 0)			/* but we send something */
	memmove ((*b)->data, &(*b)->data[i], (*b)->tosend);
      return 0;				/* we don't ready to do anything */
    }
  }
  if (str == NULL)			/* no buffer and got flush */
    return (Connchain_Put (ch, id, str, sz));
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
      if (str[ii-2] == '\373')		/* we have disabled far echo? */
	left = ii;			/* skip rest of it now */
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

static ssize_t _ccfilter_y_recv (struct connchain_i **ch, idx_t id, char *str,
				 size_t sz, struct connchain_buffer **b)
{
  ssize_t sr, sw;

  if (str == NULL)			/* they killed me */
  {
    FREE (b);
    return E_NOSOCKET;
  }
  sr = Connchain_Get (ch, id, str, sz);
  if (sr < 0)				/* got an error */
    FREE (b);
  if (sr <= 0)				/* error or no data */
    return sr;
  sw = sizeof((*b)->data) - (*b)->tosend; /* free space in buffer */
  sr = _do_rfc854_input (str, sr, &(*b)->data[(*b)->tosend], &sw);
  (*b)->tosend = sizeof((*b)->data) - sw; /* reverse calculation */
  return sr;
}

BINDING_TYPE_connchain_grow(_ccfilter_y_init);
static int _ccfilter_y_init (peer_t *peer,
	ssize_t (**recv)(struct connchain_i **, idx_t, char *, size_t, struct connchain_buffer **),
	ssize_t (**send)(struct connchain_i **, idx_t, const char *, size_t *, struct connchain_buffer **),
	struct connchain_buffer **b)
{
  *recv = &_ccfilter_y_recv;
  *send = &_ccfilter_y_send;
  if (b == NULL)
    return 1;
  /* we will use buffer as marker, yes */
  *b = safe_malloc (sizeof(struct connchain_buffer));
  (*b)->tosend = 0;
  return 1;
}


/*
 * Filter 'b' - eggdrop style filter bindtables handler. Local only.
 *   Note: it's not async-safe on send!
 */
static ssize_t _ccfilter_b_send(struct connchain_i **ch, idx_t id,
				const char *str, size_t *sz,
				struct connchain_buffer **b)
{
  ssize_t i = 0, left;
  struct binding_t *bind;
  char buf[MB_LEN_MAX*MESSAGEMAX];

  if (*b == NULL)			/* already terminated */
    return E_NOSOCKET;
  if (str == NULL)			/* ah, it was a flush! */
    return (Connchain_Put (ch, id, str, sz));
  if ((i = Connchain_Put (ch, id, "", &i)) < 0)	/* dead end */
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
	RunBinding (bind, NULL, NULL, NULL, NULL, DccIdx((peer_t *)*b), buf);
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

static ssize_t _ccfilter_b_recv (struct connchain_i **ch, idx_t id, char *str,
				 size_t sz, struct connchain_buffer **b)
{
  ssize_t sr;
  struct binding_t *bind;

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
	  RunBinding (bind, NULL, NULL, NULL, NULL, DccIdx((peer_t *)*b), str);
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
	ssize_t (**recv) (struct connchain_i **, idx_t, char *, size_t, struct connchain_buffer **),
	ssize_t (**send) (struct connchain_i **, idx_t, const char *, size_t *, struct connchain_buffer **),
	struct connchain_buffer **b)
{
  if (!(IS_SESSION(peer)))		/* local only! */
    return 0;
  *recv = &_ccfilter_b_recv;
  *send = &_ccfilter_b_send;
  /* we do using *b as peer pointer, make sure connchain is used non-thread */
  if (b)
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
static void get_chat (char *name, char *ident, char *host, peer_t *dcc,
		      char buf[SHORT_STRING], char **msg)
{
  ssize_t sz, sp, pp;
  time_t t;
  int telnet = 0;
  struct clrec_t *user;

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
  if (buf[0] == 0)
    telnet = 1;
  snprintf (buf, SHORT_STRING, "Password: %s",
	    telnet ? "\377\373\001" : "");	/* IAC WILL ECHO */
  sz = strlen (buf);
  sp = 0;
  while (sz && time(NULL) < t && (pp = Peer_Put (dcc, &buf[sp], &sz)) >= 0)
    sp += pp;
  /* wait password and check it */
  while (time(NULL) < t)
    if ((sp = Peer_Put (dcc, "", &sz)) < 0 ||	/* push connchain buffers */
	(sp = Peer_Get (dcc, buf, SHORT_STRING)))
      break;				/* in both cases on error or success */
  if (sz != 0 || sp == 0)
  {
    *msg = "login timeout";
    return;
  }
  else if (sp < 0)
  {
    *msg = "connection lost";
    return;
  }
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
  dcc->uf = Get_Flags (user, "");
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
  dcc->priv = safe_malloc (sizeof(struct peer_priv));
  dcc->priv->floodcnt = 0;
  dcc->priv->netname = NULL;
  dcc->priv->ssbt = NULL;
  /* create interfaces - lock dispatcher to syncronize */
  Set_Iface (NULL);
  dcc->state = P_LOGIN;
  dcc->iface = Add_Iface (I_DIRECT | I_CONNECT, name, &dcc_signal,
			  &dcc_request, dcc);
  /* try to create a clone for scripts :) */
  dcc->priv->alias = Add_Iface (I_DCCALIAS, NULL, NULL, NULL, NULL);
  dcc->priv->alias->prev = dcc->iface;
  /* the same for logs */
  dcc->priv->log = Add_Iface (I_LOG, NULL, NULL, NULL, NULL);
  dcc->priv->log->prev = dcc->iface;
#ifdef HAVE_ICONV
  dcc->iface->conv = Get_Conversion (host);
#endif
  if (telnet)
  {
    dprint (5, "enabling echo for user");
    sp = 3;						/* set it manually */
    if(Peer_Put (dcc, "\377\374\001", &sp))sp=sp;	/* IAC WON'T ECHO */
	/* ignoring result, it should work at this point */
  }
  if (Connchain_Grow (dcc, 'b') <= 0)	/* bindtables filter */
    Add_Request (I_LOG, "*", F_WARN, "direct.c:get_chat: error with filter 'b'.");
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
 *   adds 'x' connection chain link in any case
 */
static char *session_handler_main (char *ident, const char *host, peer_t *dcc,
				   int botsonly, char buf[SHORT_STRING],
				   char client[LNAMELEN+1])
{
  struct binding_t *bind;
  size_t sz, sp;
  ssize_t get = 0;
  time_t t;
  char *msg;
  struct clrec_t *clr;

  /* we have no client name at this point */  
  dcc->uf = Match_Client (host, ident, NULL);	/* check ident@domain */
  Set_Iface (NULL);
  if (drop_unknown && !(Check_Bindtable (BT_Login, "*", dcc->uf, 0, NULL) &&
			(!botsonly || (dcc->uf & U_SPECIAL))))
  {
    Connchain_Grow (dcc, 'x');	/* adding text parser */
    Unset_Iface();
    return ("not allowed");
  }
  Unset_Iface();
  /* get Lname of user */
  sz = strfcpy (buf, "\r\nFoxEye network node\r\n\r\nlogin: ", SHORT_STRING);
  sp = 0;
  time (&t);
  Set_Iface (NULL);
  t += dcc_timeout;
  Unset_Iface();
  /* connchain may be bufferized but may be not */
  while (sz && (get = Peer_Put (dcc, &buf[sp], &sz)) >= 0)
    if (time(NULL) > t)
      break;
    else
      sp += get;
  Set_Iface (NULL);
  Connchain_Grow (dcc, 'x');	/* adding text parser now! */
  Unset_Iface();
  get = 0;
  if (sz == 0)		/* everything sent and sz == 0 */
    while (time(NULL) < t) /* push chain buffer if there is some */
      if ((get = Peer_Put (dcc, "", &sz)) < 0 ||
	  (get = Peer_Get (dcc, client, LNAMELEN+1)))
	break;		/* both cases of error and success */
  if (get > 0)
    DBG ("direct.c:session_handler: lname=%s", client);
  else
    return ("connection lost");
  /* check of allowance */
  dcc->uf = Match_Client (host, ident, client);
  /* for services we have to check network type */
  if ((dcc->uf & U_SPECIAL) && (clr = Lock_Clientrecord (client)))
  {
    msg = safe_strdup (Get_Field (clr, ".logout", NULL));
    Unlock_Clientrecord (clr);
  }
  else
    msg = NULL;
  Set_Iface (NULL);
  bind = Check_Bindtable (BT_Login, msg ? msg : "*", dcc->uf, 0, NULL);
  FREE (&msg);
  /* log in if they allowed to */
  if (bind && !bind->name && (!botsonly || (dcc->uf & U_SPECIAL))) 
  {
    buf[0] = 0;
    bind->func (client, ident, host, dcc, buf, &msg); /* it will unlock dispatcher */
  }
  else
  {
    Unset_Iface();
    msg = "not allowed";
  }
  return msg;
}


typedef struct
{
  char *client;			/* it must be allocated by caller */
  char *confline;		/* the same */
  void *data;			/* from caller */
  int (*cb) (const struct sockaddr *, void *);
  void (*prehandler) (pthread_t, void **, idx_t *);
  void (*handler) (char *, char *, const char *, void *);
  char *host;			/* host to listen */
  INTERFACE *iface;		/* interface of listener */
  unsigned short lport, eport;	/* listener port range */
  idx_t socket, id;
  int tst:1;
  pthread_t th;
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
      /* %@ - hostname, %L - name, %P - idx, %* - state */
      snprintf (msg, sizeof(msg), _("listening on port %hu"), acptr->lport);
      printl (buf, sizeof(buf), ReportFormat, 0,
	      NULL, SocketDomain (acptr->socket, NULL), iface->name, NULL,
	      (uint32_t)0, acptr->socket + 1, 0, msg);
      tmp = Set_Iface (iface);
      New_Request (tmp, F_REPORT, "%s", buf);
      Unset_Iface();
      break;
    case S_REG:
      if (acptr->confline && acptr->confline[0] && acptr->confline[0] != '#')
	Add_Request (I_INIT, "*", F_REPORT, "%s", acptr->confline);
      break;
    case S_TERMINATE:
      DBG("Terminating listener %s...", iface->name);
      Unset_Iface();			/* unlock dispatcher */
      pthread_cancel (acptr->th);	/* just kill it... */
      pthread_join (acptr->th, NULL);	/* ...and wait until it die */
      Set_Iface (NULL);			/* restore status quo */
      KillSocket (&acptr->socket);	/* free everything now */
      FREE (&acptr->client);
      FREE (&acptr->confline);
      FREE (&acptr->data);
      FREE (&acptr->host);
      LOG_CONN (_("Listening socket on port %hu terminated."), acptr->lport);
      /* we don't need to free acptr since dispatcher will do it for us */
      iface->ift |= I_DIED;
      break;
    case S_SHUTDOWN:
      /* cannot do anything with it */
    default: ;
  }
  return 0;
}

/* internal thread functions for Listen_Port */
#define acptr ((accept_t *)input_data)
static void _ident_cleanup (void *input_data)
{
  acptr->tst = 0;
}

static void *_ask_ident (void *input_data)
{
  const char *domain;
  size_t sz, sp;
  unsigned short p;
  char buf[SHORT_STRING];

  pthread_cleanup_push (&_ident_cleanup, input_data);
  domain = SocketDomain (acptr->socket, &p);
  if (SetupSocket (acptr->id, domain, 113, NULL, NULL) == 0)
  {
    snprintf (buf, sizeof(buf), "%hu, %hu\n", p, acptr->lport);
    dprint (5, "ask host %s for ident: %s", domain, buf);
    sz = strlen (buf);
    sp = 0;
    while (!(WriteSocket (acptr->id, buf, &sp, (size_t *)&sz, M_POLL)));
  }
  pthread_cleanup_pop(1);
  return (NULL);
}

static void _accept_port_cleanup (void *input_data)
{
  KillSocket (&acptr->id);
  FREE (&acptr->client);
  safe_free (&input_data); /* FREE (&acptr) */
}

/* fields but client, lport, socket, prehadler, handler, data are undefined */
static void *_accept_port (void *input_data)
{
  const char *domain;
  char ident[24];
  char buf[SHORT_STRING];
  ssize_t sz;
  size_t sp;
  unsigned short p;
  time_t t;
  struct timespec ts1, ts2;
  pthread_t ith;

  /* set cleanup for the thread before any cancellation point */
  acptr->id = -1;
  pthread_cleanup_push (&_accept_port_cleanup, input_data);
  ts1.tv_sec = 0;
  ts1.tv_nsec = 50000000; /* sleep 50 ms */
  while (acptr->tst == 0)
    nanosleep (&ts1, &ts2);		/* wait for prehandler */
  domain = SocketDomain (acptr->socket, &p);
  /* SocketDomain() does not return NULL, let's don't wait! */
  if (!*domain)
    domain = NULL;
  /* get ident of user */
  *ident = 0;
  acptr->id = GetSocket (M_RAW);
  if (acptr->id >= 0 && pthread_create(&ith, NULL, &_ask_ident, input_data) == 0)
  {
    time (&t);
    Set_Iface (NULL);
    t += ident_timeout;
    Unset_Iface();
    while (acptr->tst != 0) {
      nanosleep (&ts1, &ts2);		/* wait for prehandler */
      if (time(NULL) > t)
	pthread_cancel(ith);
    }
    pthread_join(ith, NULL);
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
      /* TODO: make support for OTHER ident prepending it with '=' */
    } /* ident is checked */
    DBG ("_accept_port: killing ident socket");
    KillSocket (&acptr->id);
  }
  /* %* - ident, %@ - hostname, %L - Lname, %P - port */
  Set_Iface (NULL);
  printl (buf, sizeof(buf), format_dcc_input_connection, 0, NULL, domain,
	  acptr->client, NULL, 0, p, 0, ident[0] ? ident : _("((unknown))"));
  Unset_Iface();
  LOG_CONN ("%s", buf);
  /* we have ident now so call handler and exit */
  if (acptr->data == NULL)
    acptr->data = &acptr->socket;
  acptr->handler (acptr->client, ident, domain, acptr->data);
  pthread_cleanup_pop (1);
  return NULL;
}

static int _direct_listener_callback(const struct sockaddr *sa, void *input_data)
{
  register int ec;

  if (acptr->cb == NULL)
    return (0);
  ec = acptr->cb(sa, acptr->data);
  if (ec != E_AGAIN)
    acptr->cb = NULL;
  return (ec);
}

static void _listen_port_cleanup (void *input_data)
{
  void *data = acptr->data;

  if (acptr->prehandler && acptr->id < 0)	/* notify caller */
    acptr->prehandler ((pthread_t)0, &data, &acptr->id);
  /* job's ended so let dispatcher know that we must be finished
     don't do locking and I hope it's still atomic so should be OK */
  acptr->iface->ift = I_LISTEN | I_FINWAIT;
  /* everything will be done by dispatcher */
}

static inline unsigned short _random_port(unsigned short start,
					  unsigned short end)
{
  register unsigned short ps;

  if (end == start)
    return start;
  ps = end - start + 1;
  ps = random() % ps;
  return (start + ps);
}

static void *_listen_port (void *input_data)
{
  idx_t new_idx;
  accept_t *child;
  char buf[8];
  char *host = acptr->host;
  int n, i, cancelstate;
  unsigned short port;

  /* set cleanup for the thread before any cancellation point */
  pthread_cleanup_push (&_listen_port_cleanup, input_data);
  acptr->id = 0;
  i = acptr->eport - acptr->lport;
  FOREVER {
    port = _random_port(acptr->lport, acptr->eport);
    n = SetupSocket(acptr->socket, (host && *host) ? host : NULL, port,
		    &_direct_listener_callback, input_data);
    DBG("_listen_port:SetupSocket for port %hu returned %d", port, n);
    if (n == 0)
      break;
    if (--i < 0 &&			/* final try */
	(!acptr->cb || acptr->cb(NULL, acptr->data) != E_AGAIN))
					/* give it a chance */
      break;
    ResetSocket(acptr->socket, M_LIST);
    port++;
  }
  if (n) {
    char errstr[SHORT_STRING];

    SocketError(n, errstr, sizeof(errstr));
    dprint(2, "_listen_port: could not start listener [%s]: %s",
	   NONULL(acptr->confline), errstr);
    return NULL;
  }
  SocketDomain(acptr->socket, &port);	/* update with real one */
  acptr->lport = port;
  /* rename interface if need */
  if (!acptr->confline) {
    SocketDomain(acptr->socket, &port);
    snprintf (buf, sizeof(buf), "%hu", port);
    if (strcmp(acptr->iface->name, buf))
      Rename_Iface(acptr->iface, buf);
  }
  /* let it be async-safe as much as possible: it may be killed by shutdown */
  acptr->id = -1;
  while (acptr->socket >= 0)		/* ends by cancellation */
  {
    if ((new_idx = AnswerSocket (acptr->socket)) == E_AGAIN)
      continue;
    else if (new_idx < 0) /* listening socket died */
      break;
    /* deny cancellation of the thread while we have extra data */
    pthread_setcancelstate (PTHREAD_CANCEL_DISABLE, &cancelstate);
    child = safe_malloc (sizeof(accept_t));
    child->client = acptr->client;
    child->lport = acptr->lport;
    child->socket = new_idx;
    child->prehandler = acptr->prehandler;
    child->handler = acptr->handler;
    child->data = acptr->data;
    child->tst = 0;			/* use it to wait for prehandler */
    dprint (4, "direct:_listen_port: socket %d answered, %s: new socket %d",
	    (int)acptr->socket, acptr->client ? "terminated" : "continue",
	    (int)new_idx);
    if (pthread_create (&child->th, NULL, &_accept_port, child))
    {
      KillSocket (&child->socket);
      FREE (&child);
    }
    else
    {
      if (acptr->prehandler)
	acptr->prehandler (child->th, &child->data, &child->socket);
      else
	pthread_detach (child->th);	/* since it's not joinable */
      child->tst = 1;			/* let new thread continue */
      if (acptr->client)		/* it's client connection so die now */
      {
	acptr->id = 0;			/* do not call prehandler again */
	acptr->client = NULL;		/* it's inherited by child */
	break;
      }
    }
    pthread_setcancelstate (cancelstate, NULL);
  }
  pthread_cleanup_pop(1);
  return NULL;
}
#undef acptr

static void _assign_port_range (unsigned short *ps, unsigned short *pe)
{
  *ps = *pe = 0;
  sscanf (dcc_port_range, "%hu - %hu", ps, pe);
  /* use system algorhytm if dcc_port_range is empty and 0 requested */
  if (*ps == 0 && *pe == 0)
    return;
  if (*ps < 1024)
    *ps = 1024;
  if (*pe < *ps)
    *pe = *ps;
}

int Listen_Port (char *client, const char *host, unsigned short sport,
		 char *confline, void *data,
		 int (*cb) (const struct sockaddr *, void *),
		 void (*prehandler) (pthread_t, void **, idx_t *),
		 void (*handler) (char *, char *, const char *, void *))
{
  accept_t *acptr;
  idx_t idx;
  char buf[8];

  idx = GetSocket (M_LIST);
  if (idx < 0)
    return (int)idx;
  /* check for two more sockets - accepted and ident check */
  if (idx >= SOCKETMAX - 2) {
    KillSocket(&idx);
    return E_NOSOCKET;
  }
  acptr = safe_malloc (sizeof(accept_t));
  acptr->client = safe_strdup (client);
  acptr->confline = safe_strdup (confline);
  acptr->data = data;
  acptr->cb = cb;
  acptr->prehandler = prehandler;
  acptr->handler = handler;
  acptr->host = safe_strdup (host);
  if (sport)
    acptr->lport = acptr->eport = sport;
  else
    _assign_port_range (&acptr->lport, &acptr->eport);
  acptr->socket = idx;
  /* create interface now */
  if (!acptr->confline)
    snprintf (buf, sizeof(buf), "%hu", sport);
  acptr->iface = Add_Iface (I_LISTEN | I_CONNECT,
			    acptr->confline ? acptr->confline : buf,
			    &port_signal, NULL, acptr);
  if (pthread_create (&acptr->th, NULL, &_listen_port, acptr))
  {
    acptr->iface->ift = (I_LISTEN | I_FINWAIT);
    /* everything will be done by dispatcher */
    return E_NOTHREAD;
  }
  return 0;
}

typedef struct
{
  char *host;
  unsigned short port;
  idx_t *idx;
  void (*handler) (int, void *);
  void *id;
  int rc;
} connect_t;

#define cptr ((connect_t *)input_data)
static void _connect_host_cleanup (void *input_data)
{
  if (cptr->rc != 0)
    KillSocket(cptr->idx);
  cptr->handler (cptr->rc, cptr->id);
  FREE (&cptr->host);
  safe_free (&input_data);	/* FREE (&cptr) */
}

static void *_connect_host (void *input_data)
{
  /* set cleanup for the thread before any cancellation point */
  pthread_cleanup_push (&_connect_host_cleanup, input_data);
  cptr->rc = E_NOSOCKET;
  if ((*cptr->idx = GetSocket (M_RAW)) >= 0)
    cptr->rc = SetupSocket (*cptr->idx, cptr->host, cptr->port, NULL, NULL);
  if (cptr->rc == 0)
    dprint (4, "direct:_connect_host: connected to %s at port %hu: new socket %d",
	    cptr->host, cptr->port, (int)*cptr->idx);
  else
  {
    char buf[SHORT_STRING];

    LOG_CONN ("Could not make connection to %s at port %hu (socket %d): %s",
	      cptr->host, cptr->port, (int)*cptr->idx,
	      SocketError (cptr->rc, buf, sizeof(buf)));
    KillSocket (cptr->idx);
  }
  pthread_cleanup_pop (1);
  return NULL;
}
#undef cptr

int Connect_Host (const char *host, unsigned short port, pthread_t *th, idx_t *idx,
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
  if (!IS_SESSION(dcc) || dcc->priv->botnet < 0)
    return -1; /* nobody to notify */
  /* send notify to botnet */
  snprintf (ch, sizeof(ch), ":*:%d", dcc->priv->botnet);
  if (args)
    Add_Request (I_DCCALIAS, ch, F_T_NOTICE, _("now away: %s"), args);
  else
    Add_Request (I_DCCALIAS, ch, F_T_NOTICE, _("returned to life."));
  return -1;	/* don't log it */
}

		/* .me <message> */
BINDING_TYPE_dcc (dc_me);
static int dc_me (peer_t *dcc, char *args)
{
  struct binding_t *bind = NULL;
  char ch[16];

  if (!args)
    return 0;
  if (!IS_SESSION(dcc) || dcc->priv->botnet < 0)
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
  snprintf (ch, sizeof(ch), ":*:%d", dcc->priv->botnet);
  Add_Request (I_DCCALIAS, ch, F_T_ACTION | F_BOTNET, "%s", args);
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
  register iftype_t rc;

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
  rc = uif->IFSignal (uif, S_TERMINATE);
  uif->ift |= rc;
  return 1;
}

static void
_set_console_parms (peer_t *dcc, struct clrec_t *user, char *fl, char *chan, int botch)
{
  char cons[SHORT_STRING];

  snprintf (cons, sizeof(cons), "%s %s %d",
	    fl[0] ? fl : "-", chan ? chan : "-", botch);
  if (!Set_Field (user, "", cons, 0))
  {
    Unlock_Clientrecord (user);
    ERROR ("direct.c:_set_console_parms: error on saving parameters!");
    return;
  }
  Unlock_Clientrecord (user);
  setconsole (dcc);
  dprint (4, "dcc:_set_console_parms: %s", cons);
}

#ifdef HAVE_ICONV
		/* .charset [<charset name>] */
BINDING_TYPE_dcc (dc_charset);
static int dc_charset (peer_t *dcc, char *args)
{
  struct conversion_t *conv;
  const char *charset;
  struct clrec_t *u;

  if (args)
  {
    conv = Get_Conversion (args);
    charset = Conversion_Charset (conv);
    if (conv != dcc->iface->conv)	/* changed */
    {
      Free_Conversion (dcc->iface->conv);
      dcc->iface->conv = conv;
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
  struct clrec_t *u;

  if (!args)				/* has to have at least 1 arg */
    return 0;
  charset = gettoken (args, &c);
  if (!(u = Lock_Clientrecord (args)))
  {
    New_Request (dcc->iface, 0, "No such client known: %s", args);
    if (*charset) *c = ' '; /* restore after gettoken() */
    return 0;
  }
  if (!*charset ||
      !Set_Field (u, "charset", charset, 0)) /* failed to set field? */
    charset = Get_Field (u, "charset", NULL);
  Unlock_Clientrecord (u);
  New_Request (dcc->iface, 0, "Charset for %s is now %s.", args,
	       charset ? charset : "NONE");
  if (*charset)
    *c = ' '; /* restore after gettoken() */
  return 1;
}
#endif

		/* .chat [<botnet channel #>] */
BINDING_TYPE_dcc (dc_chat);
static int dc_chat (peer_t *dcc, char *args)
{
  char consfl[64];
  char chan[128] = "";
  int botch = atoi (NONULL(args));
  struct clrec_t *user;

  if (!IS_SESSION(dcc))			/* aliens can have only channel 0 */
    return 0;
  else if (botch == dcc->priv->botnet)
    return 1;
  _chat_part (dcc, NULL);
  user = Lock_Clientrecord (dcc->iface->name);
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

static void _console_fl (peer_t *dcc, char *plus, char *minus, char *ch)
{
  char flags[64];
  char *cons = flags;
  register char *fl = flags;
  char chan[128];			/* channel from config */
  struct clrec_t *user;
  register int it = 0;

  minus = NONULL(minus);
  dprint (4, "dcc:_console_fl: %s %s %s %s", dcc->iface->name, plus, minus, NONULL(ch));
  user = Lock_Clientrecord (dcc->iface->name);
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
    _set_console_parms (dcc, user, flags, ch, dcc->priv->botnet);
  else
    Unlock_Clientrecord (user);
}

		/* .color [off|mono|ansi|mirc] */
BINDING_TYPE_dcc (dc_color);
static int dc_color (peer_t *dcc, char *args)
{
  flag_t fl = dcc->priv->loglev & (F_COLORCONV | F_COLOR);

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
    _say_current (dcc, msg);
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

  if (!IS_SESSION(dcc))			/* you cannot change console logging */
    return 0;
  if (args)
  {
    if (*args == '#' || *args == '&')
    {
      cc = gettoken(args, &ch);
      unistrlower (msg, args, sizeof(msg)); /* make it lowercase */
      if (*cc)
	*ch = ' ';
      if (!Find_Iface (I_SERVICE, msg) || Unset_Iface())
      {
	New_Request (dcc->iface, 0, _("No such active service found: %s"),
		     msg);
	return -1;
      }
      args = cc;
      cc = msg;
    }
    else if (*args == '*')		/* reset channel */
      args = NextWord (args);
    else if (dcc->priv->log && dcc->priv->log->name)
      cc = dcc->priv->log->name;
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
  fl = dcc->priv->loglev & (F_PRIV | F_CMDS | F_CONN | F_SERV | F_WALL | F_USERS | F_DEBUG | F_BOOT | F_ERROR | F_WARN | F_PUBLIC | F_JOIN | F_MODES);
  if (dcc->priv->log && dcc->priv->log->name && (fl & (F_PUBLIC | F_JOIN | F_MODES)))
    cc = dcc->priv->log->name;
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
    New_Request (dcc->iface, 0, "%s: %s%s%s %s %s", _("Your console logs"),
		 *msg ? msg : "", *msg ? _(", and ") : "", cl,
		 _("on the channel"), cc);
  else
    New_Request (dcc->iface, 0, "%s: %s", _("Your console logs"),
		 *msg ? msg : "none");
  return 1;
}

#define _report_req(iface,who) Send_Signal (iface, who, S_REPORT)

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
  flag_t fl = dcc->priv->loglev & F_ECHO;

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
    fl = dcc->priv->loglev & F_ECHO;
  }
  if (fl)
    _say_current (dcc, "on");
  else
    _say_current (dcc, "off");
  return 1;
}

		/* .help [<what need>] */
BINDING_TYPE_dcc (dc_help);
static int dc_help (peer_t *dcc, char *args)
{
  char *sec;
  char *fst;
  struct bindtable_t *ssbt;
  userflag df;

  if (!IS_SESSION(dcc))
    return 1;
  if (dcc->priv->log && dcc->priv->log->name)
    df = Get_Clientflags (dcc->iface->name, dcc->priv->log->name);
  else
    df = 0;
  if ((fst = args))
    sec = gettoken (args, &args);
  else
    sec = NULL;
  DBG ("dc_help for %s on %c%s", fst, dcc->priv->ssbt ? '*' : '!',
       dcc->priv->netname);
  if ((!sec || !*sec) && dcc->priv->netname && dcc->priv->ssbt &&
      (!fst || Check_Bindtable (dcc->priv->ssbt, fst, dcc->uf, df, NULL)))
    ssbt = dcc->priv->ssbt;
  else
    ssbt = NULL;
  /* usage - not required if no arguments */
  if (args && !(ssbt && Get_Help (NULL, fst, dcc->iface,
				  dcc->uf, df, ssbt, _("Usage: "), -1)) &&
      !Get_Help (fst, sec, dcc->iface, dcc->uf, df, BT_Dcc,
		 _("Usage: "), 0))
    return -1;
  /* full help */
  if (ssbt)
    Get_Help (NULL, fst ? fst : "*", dcc->iface, dcc->uf, df, ssbt, NULL, 2);
  if (!ssbt || !fst)
    Get_Help (fst, sec, dcc->iface, dcc->uf, df, BT_Dcc, NULL, 2);
  if (sec && *sec)
    *args = ' ';
  return 1;			/* return 1 because usage at least displayed */
}

		/* .motd */
BINDING_TYPE_dcc (dc_motd);
static int dc_motd (peer_t *dcc, char *args)
{
  char *c, *end;
  ssize_t s = 0;
  int fd;
  char msg[HUGE_STRING];
  char buff[HUGE_STRING];

  /* get motd file to buffer msg */
  msg[0] = 0;
  if ((fd = open (expand_path (buff, motd, sizeof(buff)), O_RDONLY)) >= 0) {
    s = read (fd, msg, sizeof(msg) - 1);
    close (fd);
  }
  if (s <= 0)
    return -1;	/* no log it */
  msg[s] = 0;
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
  peer_t *ud;
  INTERFACE *iface;
  char name[LNAMELEN+1];

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
    ud = iface->data;
    Set_Iface (iface);
    ud->parse (ud, name, args, ud->uf, 0, DccIdx(ud), ud->priv->botnet,
	       ud->priv->ssbt, ud->priv->netname);
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
  New_Request (dcc->iface, 0, "%s", b);
  if (args)
    snprintf (b, sizeof(b), ":*:%s", args);
  else if (!IS_SESSION(dcc))
    strcpy (b, ":*:0");
  else
    snprintf (b, sizeof(b), ":*:%d", dcc->priv->botnet);
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
  if (dcc->iface->IFSignal) {
    register iftype_t rc = dcc->iface->IFSignal (dcc->iface, S_TERMINATE);
    dcc->iface->ift |= rc;
  }
  ShutdownR = NULL;
  return 1;
}

		/* .connect <network|channel|bot> [<args>] */
BINDING_TYPE_dcc (dc_connect);
static int dc_connect (peer_t *dcc, char *args)
{
  char netname[IFNAMEMAX+1];
  char *snet;
  struct clrec_t *netw;
  char *nt;
  struct binding_t *bind;
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
  register iftype_t rc;

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
  rc = cif->IFSignal (cif, S_TERMINATE);
  cif->ift |= rc;
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
    i = random();
    salt[0] = __crlph[i%64];
    salt[1] = __crlph[(i/64)%64];
    salt[2] = 0;
  }
  snprintf (__spass, sizeof(__spass), "$$%s", crypt (pass, salt));
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

int mirccolors[] = {__BOLD|7, 0, 4, 2, __BOLD|1, 1, 5, 3, __BOLD|3, __BOLD|2,
		    6, __BOLD|6, __BOLD|4, __BOLD|5, __BOLD|0, 7};

BINDING_TYPE_out_filter (ConvertColors);
static void ConvertColors (peer_t *dcc, char *msg, size_t msglen)
{
  unsigned char buff[HUGE_STRING];
  register unsigned char *c, *s;
  register flag_t fl;
  int colormode;

  if (!IS_SESSION(dcc))
    return;
  colormode = 0;
  fl = (dcc->priv->loglev & (F_COLOR | F_COLORCONV));
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
  iftype_t rc = I_DIED;

  if (!(pi = Find_Iface (I_LISTEN, pn)))
    return 0;
  Unset_Iface();
  if (pi->IFSignal)
    rc = pi->IFSignal (pi, S_TERMINATE);
  else
    ERROR ("_dellistenport: no signal function for \"%s\"", pn);
  pi->ift |= rc;
  return 1;
}

/*
 * sequence to keep ->retrier valid:
 * signal : +kill => (wait)+done
 * fail   : +I_FINWAIT => +done
 * success: +I_FINWAIT => +done
 * retrier would not free data until ->done is set
 */
typedef struct
{
  INTERFACE *retrier;		/* listening thread data */
  int ch;
  int cnt;
  unsigned short port;
  bool kill, done;
} _port_retrier;

typedef struct
{
  int ch;			/* accepting thread data */
  idx_t as;
} _port_acceptor;

static void _dport_prehandler (pthread_t th, void **id, idx_t *as)
{
  register _port_retrier *r;
  register _port_acceptor *a;

  if (*as == -1) /* fatal error */
    return;
  a = safe_malloc(sizeof(_port_acceptor));
  r = *((_port_retrier **)id);
  a->ch = r->ch;
  a->as = *as;
  *id = a;
  /* as we don't have any interface to control th ATM we cannot cancel it */
}

static void _dport_handler_cleanup(void *data)
{
  if (Connchain_Kill(((peer_t *)data))) /* condition to awoid warn */
  KillSocket(&((peer_t *)data)->socket);
  FREE(&data);
}

static void _dport_handler (char *cname, char *ident, const char *host, void *d)
{
  char buf[SHORT_STRING];
  char client[LNAMELEN+1];
  size_t sz;
  peer_t *dcc;
  register char *msg;
  int flag = ((_port_acceptor *)d)->ch;
  unsigned short p;

  dcc = safe_malloc (sizeof(peer_t));
  dcc->socket = ((_port_acceptor *)d)->as;
  dcc->state = P_INITIAL;
  dcc->dname = NULL;
  dcc->parse = &Dcc_Parse;
  dcc->connchain = NULL;
  dcc->iface = NULL;
  dcc->priv = NULL;
  time (&dcc->last_input);
  safe_free(&d);
  Set_Iface (NULL);
  client[0] = 0; /* terminate it for case of error */
  pthread_cleanup_push(&_dport_handler_cleanup, dcc);
  snprintf (dcc->start, sizeof(dcc->start), "%s %s", DateString, TimeString);
  /* dispatcher is locked, can do connchain */
  if (!Connchain_Grow (dcc, (flag & 0xff))) /* adding mandatory filters now */
    msg = "connection chain error";	/* ouch... it should die */
  else
    msg = NULL;
  Connchain_Grow (dcc, 'y');		/* adding telnet filter */
  Unset_Iface();
  if (msg == NULL)
    msg = session_handler_main (ident, host, dcc, (flag & 256), buf, client);
  if (msg != NULL) {			/* some errors on connection */
    LOG_CONN (_("Connection from %s terminated: %s"), host, msg);
    snprintf (buf, sizeof(buf), "Access denied: %s", msg);
    sz = strlen (buf);
    if (Peer_Put (dcc, buf, &sz) > 0)	/* it should be OK */
      while (!(Peer_Put (dcc, NULL, &sz))); /* wait it to be sent */
    SocketDomain (dcc->socket, &p);
    /* %L - Lname, %P - port, %@ - hostname, %* - reason */
    Set_Iface (NULL);
    printl (buf, sizeof(buf), format_dcc_closed, 0,
	    NULL, host, client, NULL, 0, p, 0, msg);
    Unset_Iface();
    LOG_CONN ("%s", buf);
    return;			/* implisit pthread_cleanup_pop(1) applied */
  }
  pthread_cleanup_pop(0);
}

static iftype_t _port_retrier_s (INTERFACE *iface, ifsig_t signal)
{
  _port_retrier *r = (_port_retrier *)iface->data;
  INTERFACE *tmp;
  char buf[STRING];

  switch (signal)
  {
    case S_REPORT:
      /* %L - name, %* - state */
      printl (buf, sizeof(buf), ReportFormat, 0,
	      NULL, NULL, iface->name, NULL, (uint32_t)0, 0, 0,
	      "trying to open listening port");
      tmp = Set_Iface (iface);
      New_Request (tmp, F_REPORT, "%s", buf);
      Unset_Iface();
      break;
    case S_SHUTDOWN:
      r->kill = TRUE;
      /* ...it will die itself */
      return I_DIED;
    case S_TERMINATE:
      DBG("_port_retrier_s:%s: got termination signal, waiting for thread...",
	  iface->name);
      r->kill = TRUE;
      while(!r->done);		/* waiting for thread */
      iface->data = NULL;	/* keep it for thread */
      DBG("_port_retrier_s: terminated.");
      return I_DIED;
    default: ;
  }
  return 0;
}

static int _direct_port_callback(const struct sockaddr *sa, void *data)
{
  _port_retrier *rtr = data;

  if (rtr->kill)		/* aborted */
    goto aborted;
  if (sa == NULL) {		/* failed */
    if (rtr->cnt-- > 0)		/* still retry left */
    {
      struct timespec ts = { .tv_sec = 0, .tv_nsec = 10000000 };
      int cnt = 1000;

      LOG_CONN(_("Could not open listening port %hu%s, retrying in 10 seconds."),
	       rtr->port, (rtr->ch & 256) ? _(" for bots") : "");
      do {
	nanosleep(&ts, NULL);	/* check each 10 ms if killed */
	if (rtr->kill)
	  goto aborted;
      } while (--cnt);
      return E_AGAIN;
    }
    LOG_CONN(_("Cannot open listening port on %hu%s!"), rtr->port,
	     (rtr->ch & 256) ? _(" for bots") : "");

aborted:
    rtr->retrier->ift = (I_LISTEN | I_FINWAIT);
    rtr->done = TRUE;
    return E_NOSOCKET;		/* data is unusable anymore */
  }
  /* ipv4 and ipv6 both have port in the same place */
  /* rtr->port = ntohc(((struct sockaddr_in *)sa)->sin_port); */
  LOG_CONN(_("Listening on port %hu%s."), rtr->port,
	   (rtr->ch & 256) ? _(" for bots") : "");
  rtr->retrier->ift = (I_LISTEN | I_FINWAIT);
  rtr->done = TRUE;
  return 0;
}

ScriptFunction (FE_port)	/* to config - see thrdcc_signal() */
{
  unsigned short port;
  INTERFACE *tmp;
  _port_retrier *rtr;
  static char msg[SHORT_STRING];
  userflag u = U_ANY | U_SPECIAL;
  int ii = E_NOSOCKET, ch = 0;

  if (!args || !*args)
    return 0;
  while (*args == '-')
  {
    if (args[1] == 'd')
      u = 0;
    else if (args[1] == 'b')
      u &= ~U_ANY;
    args = NextWord ((char *)args);	/* it's still const */
  }
  if (*args == '+')
  {
    args++;
    if (*args != 'x' && *args != 'y' && *args != 'b')	/* forbidden flags */
      ch = *args;
    args = NextWord ((char *)args);	/* it's const really */
  }
  port = atoi (args);
  if (port < 1024)
    return 0;
  if (ch)
    snprintf (msg, sizeof(msg), "port %s+%c %hu", (u & U_ANY) ? "" : "-b ",
	      (char)ch, port);
  else
    snprintf (msg, sizeof(msg), "port %s%hu", (u & U_ANY) ? "" : "-b ", port);
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
  if (!(u & U_ANY))
    ch |= 256;
  rtr = safe_malloc(sizeof(_port_retrier));
  rtr->port = port;
  rtr->ch = ch;
  /* check if we are called from init() */
  if (Set_Iface (NULL) != NULL) {
    rtr->cnt = 0;
    Unset_Iface();
  } else
    rtr->cnt = 6;
  rtr->kill = rtr->done = FALSE;
  /* create retrier interface to be able to cancel it */
  rtr->retrier = Add_Iface(I_TEMP, msg, &_port_retrier_s, NULL, rtr);
  if (rtr->retrier)
    ii = Listen_Port(NULL, hostname, port, msg, rtr, &_direct_port_callback,
		     &_dport_prehandler, &_dport_handler);
  else
    ERROR("Cannot create retrier interface for [%s]", msg);
  if (ii == 0)
    return port;
  if (rtr->retrier)
    rtr->retrier->ift = I_DIED;
  FREE(&rtr);
  snprintf (msg, sizeof(msg), _("Could not create listening thread for port on %hu%s!"),
	    port, (u & U_ANY) ? _(" for bots") : "");
  BindResult = msg;
  return 0;
}

char *IFInit_DCC (void)
{
  _fe_init_sockets();
  _fe_init_connchains();
  /* add own bindtables */
  BT_Dcc = Add_Bindtable ("dcc", B_UCOMPL);		/* these tables have bindings */
  _dc_init_bindings();
  BT_Crypt = Add_Bindtable ("passwd", B_UNIQMASK);
  Add_Binding ("passwd", "$$*", 0, 0, (Function)&IntCrypt, NULL);
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
