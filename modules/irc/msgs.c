/*
 * Copyright (C) 2005-2017  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 * The FoxEye "irc" module: do queue private msgs for my IRC client connection
 */

#include "foxeye.h"
#include "modules.h"
#include "irc.h"
#include "init.h"
#include "list.h"
#include "sheduler.h"

typedef struct pmsgout_stack {
  INTERFACE *client;
  struct pmsgout_stack *prev;
  struct pmsgout_stack *next;
  time_t last;
  short msg_flood;
  short ctcp_flood;
  unsigned run:1;
} pmsgout_stack;


static struct bindtable_t *BT_PubMsgMask;
static struct bindtable_t *BT_PubNoticeMask;
static struct bindtable_t *BT_PubMsgCmd;
static struct bindtable_t *BT_PubNoticeCmd;
static struct bindtable_t *BT_PubCtcp;
static struct bindtable_t *BT_PubCtcr;
static struct bindtable_t *BT_PrivMsgMask;
static struct bindtable_t *BT_PrivNoticeMask;
static struct bindtable_t *BT_PrivMsgCmd;
static struct bindtable_t *BT_PrivNoticeCmd;
static struct bindtable_t *BT_PrivCtcp;
static struct bindtable_t *BT_PrivCtcr;
static struct bindtable_t *BT_Flood;

static char *format_irc_message;
static char *format_irc_notice;
static char *format_irc_ctcp;
static char *format_irc_ctcr;
static char *format_irc_action;
static char *format_irc_cmdmessage;
static char *format_irc_cmdctcp;

static short *FloodMsg;
static short *FloodCtcp;


struct pmsgin_actions
{
  struct bindtable_t **priv_bt;
  struct bindtable_t **pub_bt;
  size_t shift;
  char **format;
  char **cmdformat;
};

static struct bindtable_t *BT_NULL = NULL;

static struct pmsgin_actions PmsginTable[] = {
  { &BT_PrivMsgCmd,	&BT_PubMsgCmd,		0, &format_irc_message,	&format_irc_cmdmessage },
  { &BT_PrivNoticeCmd,	&BT_PubNoticeCmd,	0, &format_irc_notice,	NULL },
  { &BT_PrivCtcp,	&BT_PubCtcp,		1, &format_irc_ctcp,	&format_irc_cmdctcp },
  { &BT_PrivCtcr,	&BT_PubCtcr,		1, &format_irc_ctcr,	NULL },
  { &BT_NULL,		&BT_NULL,		8, &format_irc_action,	NULL }
};


/* --- me => server part ---------------------------------------------------- */

static const char *_pmsgout_send_format[] = {
  "PRIVMSG %s :%s",
  "NOTICE %s :%s",
  "PRIVMSG %s :\001%s\001",
  "NOTICE %s :\001%s\001",
  "PRIVMSG %s :\001ACTION %s\001"
};

/* send one message from stack */
/* be careful with formats since warnings are disabled by #pragma!!! */
#if __GNUC__ >= 4
#pragma GCC diagnostic ignored "-Wformat-nonliteral" /* for Add_Request below */
#endif
static void _pmsgout_send (char *to, char *msg, flag_t flag, char *dog)
{
  register unsigned int i;
  unsigned char *c;
  char buff[2*MESSAGEMAX];		/* should be enough for any message */

  StrTrim (msg);			/* remove ending spaces, CR, LF */
  if (dog && msg[0])			/* don't send empty messages */
  {
    *dog = 0;
    i = (flag & F_T_MASK);
    if (i > 4)
      i = 0;				/* default */
    /* check out line with unistrcut */
    c = msg;
    do {
      register size_t sm, sw;

      snprintf (buff, sizeof(buff), _pmsgout_send_format[i], to, c);
      /* FIXME: count own prefix (IRCMSGLEN-5-prefixlen) in the message size! */
      sw = unistrcut (buff, sizeof(buff), IRCMSGLEN - 45); /* calculate */
      sm = strlen (buff);
      c = &c[strlen(c)];		/* set it at EOL */
      if (sw < sm)			/* ouch, it exceed the size! */
      {
	if (i >= 2) {			/* has to be ended with '\001' */
	  buff[sw] = '\001';
	  buff[sw+1] = '\0';
	} else
	  buff[sw] = '\0';		/* terminate partial message */
	c -= (sm - sw);			/* go back chars that don't fit */
      }
      Add_Request (I_SERVICE, &dog[1], 0, "%s", buff);
    } while (*c);			/* do it again if msg was splitted */
    /* parse all recipients */
    for (c = to; to; to = c)
    {
      int pub;
      char tocl[IFNAMEMAX+1];
      register size_t ss;

      if ((*c >= 'A' && *c < '~') || *c >= 160 ||
	  ((*c == '$' || *c == '#') && strpbrk (c, "*?")))
	pub = 0;
      else
	pub = 1;
      c = strchr (to, ',');
      if (c)
	*c = 0;
      /* convert recipient to lowercase, it might be #ChaNNel or niCK */
      if (*to == '!')		/* special support for "!XXXXXchannel" */
      {
	tocl[0] = '!';
	ss = unistrlower (&tocl[1], &to[6], sizeof(tocl)-2) + 1;
      }
      else
	ss = unistrlower (tocl, to, sizeof(tocl)-1);
      *dog = '@';
      strfcpy (&tocl[ss], dog, sizeof(tocl) - ss);
      *dog = 0;
      /* %N - mynick, %# - target, %* - message */
      printl (buff, sizeof(buff), *PmsginTable[i].format, 0,
	      irc_mynick (&dog[1]), NULL, NULL, to, 0, 0, 0, msg);
      if (*buff)
	Add_Request (I_LOG, tocl, (pub ? F_PUBLIC : F_PRIV) | F_MINE | i,
		     "%s", buff);
      if (c)
	*c++ = ',';
    }
    *dog = '@';
  }
}
#if __GNUC__ >= 4
#pragma GCC diagnostic error "-Wformat-nonliteral"
#endif

static iftype_t _pmsgout_sig (INTERFACE *iface, ifsig_t sig)
{
  if (sig != S_TERMINATE || iface->data == NULL)
    return 0;
  ((pmsgout_stack *)iface->data)->client = NULL;
  iface->data = NULL;
  return I_DIED;
}

static int _pmsgout_run (INTERFACE *client, REQUEST *req)
{
  if (!req)
    return REQ_OK;
  if (!((pmsgout_stack *)client->data)->run)
  {
    return REQ_REJECTED;
  }
  _pmsgout_send (client->name, req->string, req->flag,
		 strrchr (client->name, '@'));	/* get server name from a@b */
  ((pmsgout_stack *)client->data)->run = 0;
  return REQ_OK;
}

ALLOCATABLE_TYPE (pmsgout_stack, _PMS, next) /* (alloc|free)_pmsgout_stack() */

static INTERFACE *_pmsgout_stack_insert (pmsgout_stack **stack, char *to)
{
  INTERFACE *client;
  pmsgout_stack *cur = alloc_pmsgout_stack();

  dprint (5, "_pmsgout_stack_insert: adding %s", to);
  client = Add_Iface (I_CLIENT, to, &_pmsgout_sig, &_pmsgout_run, NULL);
  if (*stack)
  {
    cur->next = *stack;
    cur->prev = (*stack)->prev;
    (*stack)->prev = cur;
    cur->prev->next = cur;
  }
  else
    *stack = cur->prev = cur->next = cur;
  cur->client = client;
  client->data = cur;
  cur->msg_flood = cur->ctcp_flood = 0;
  cur->run = 0;
  return client;
}

static void _pmsgout_stack_remove (pmsgout_stack **stack, pmsgout_stack *cur)
{
  if (cur->client != NULL)
    dprint (5, "_pmsgout_stack_remove: removing %s", cur->client->name);
  else
    dprint (5, "_pmsgout_stack_remove: cleaning died one");
  if (cur->prev == cur)
    *stack = NULL;
  else if (*stack == cur)
    *stack = cur->next;
  cur->next->prev = cur->prev;
  cur->prev->next = cur->next;
  NoCheckFlood (&cur->msg_flood);
  NoCheckFlood (&cur->ctcp_flood);
  free_pmsgout_stack (cur);
  if (!cur->client)
    return;
  cur->client->ift |= I_DIED;		/* it will free cur too so preserve it */
  cur->client->data = NULL;
}

/* ATTENTION: on returned INTERFACE must be called Unset_Iface() after use! */
static INTERFACE *_pmsgout_get_client (char *net, char *to)
{
  char lcto[IFNAMEMAX+1];
  register size_t s;

  s = strfcpy (lcto, to, sizeof(lcto));
  strfcpy (&lcto[s], net, sizeof(lcto) - s);
  dprint (5, "_pmsgout_get_client: search %s", lcto);
  return Find_Iface (I_CLIENT, lcto); 
}

/* send message from head of stack and revolve stack */
void irc_privmsgout (INTERFACE *pmsgout, int pmsg_keep)
{
  register pmsgout_stack *stack = pmsgout->data, *cur;

  if (!stack)
    return;
  cur = stack->next;
  while (cur != stack)
  {
    if (cur->client == NULL)		/* killed already */
      continue;
    if (cur->client->qsize != 0)	/* has something to out */
      break;
    if (Time > cur->last)
    {
      if (Find_Iface (I_QUERY, cur->client->name)) /* keep it while query exists */
	Unset_Iface();
      else
      {
	cur = cur->prev;
	_pmsgout_stack_remove ((pmsgout_stack **)&pmsgout->data, cur->next);
	/* if it was last then stack is NULL; if it IS last then stack = it */
	stack = pmsgout->data;
	if (stack == NULL)		/* emptied */
	  return;
      }
    }
    cur = cur->next;
  }
  if (cur->client == NULL || cur->client->qsize == 0)
    return;
  pmsgout->data = cur;
  cur->last = Time + pmsg_keep;
  cur->run = 1;
}

int irc_privmsgout_default (INTERFACE *pmsgout, REQUEST *req)
{
  INTERFACE *client;
  char *dog;
  register pmsgout_stack *stack;
  int i;

  if (!req)
    return REQ_OK;
  /* may we send it to list or some mask? just forward it to server then */
  dog = strrchr (req->to, '@');			/* get server name from a@b */
  if (strchr (req->to, ',') || strchr (req->to, '%') ||
      strchr (req->to, '@') != dog ||
      (req->to[0] < 0x41 && strchr (CHANNFIRSTCHAR, req->to[0])) ||
      (req->to[0] > 0x7d && (uchar)req->to[0] < 0xa0))
  {
    _pmsgout_send (req->to, req->string, req->flag, dog);
    return REQ_OK;
  }
  /* it's to one so let's create client queue interface */
  client = _pmsgout_stack_insert ((pmsgout_stack **)&pmsgout->data, req->to);
  /* check if it should be ran immediately and unblock */
  i = 0;
  stack = pmsgout->data;
  do {
    if (stack->client != NULL)		/* check if it's cleared already */
      i += stack->client->qsize;
    stack = stack->next;
  } while (stack != pmsgout->data);
  if (i == 0)				/* stack was ran out */
    ((pmsgout_stack *)client->data)->run = 1;
  return Relay_Request (I_CLIENT, client->name, req);
}

/* remove client from stack or destroy all stack if NULL */
void irc_privmsgout_cancel (INTERFACE *pmsgout, char *to)
{
  INTERFACE *iface;

  if (!pmsgout)
    return;
  dprint (5, "_privmsgout_cancel: cancel %s%s", to ? to : "*", pmsgout->name);
  if (pmsgout->data && !to)
  {
    while (pmsgout->data)
      _pmsgout_stack_remove ((pmsgout_stack **)&pmsgout->data,
			     ((pmsgout_stack *)pmsgout->data)->prev);
    return;
  }
  if (!pmsgout->data || !(iface = _pmsgout_get_client (pmsgout->name, to)))
    return;
  _pmsgout_stack_remove ((pmsgout_stack **)&pmsgout->data, iface->data);
  Unset_Iface();
}

int irc_privmsgout_count (INTERFACE *pmsgout)
{
  register int i;
  register pmsgout_stack *stack;
  if (!pmsgout)
    return 0;
  stack = pmsgout->data;
  if (!stack)
    return 0;
  for (i = 1; stack->next != pmsgout->data; stack = stack->next)
    i++;
  return i;
}


/* --- server => me part ---------------------------------------------------- */

/*
 * do PRIVMSG and NOTICE parsing
 * to is target of the message and is NULL if message is for me
 * message may be modified free (see irc.c)
 * msg_type has bits:
 *   xx1  notice
 *   00x  message
 *   01x  ctcp
 *   100  action
 */
int irc_privmsgin (INTERFACE *pmsgout, char *from, char *to,
		   char *msg, int notice, int allow_cmdpmsg, int pmsg_keep,
		   size_t (*lc) (char *, const char *, size_t))
{
  char lcnick[HOSTMASKLEN+1];
  char tocl[IFNAMEMAX+1];
  int msg_type;
  const char *lname;
  char *ft, *ae; /* ae - at exclamation */
  size_t msglen = 0;			/* avoiding compiler warning */
  INTERFACE *client;
  struct clrec_t *clr;
  userflag uf, df = 0;
  struct binding_t *bind;
  struct bindtable_t *btmask;
  int i;

  /* convert sender nick to lower case before searching for client */
  if ((ae = strchr (from, '!')))
    *ae = 0;
  if (lc)
    lc (lcnick, from, NAMEMAX+1);
  else
    strfcpy (lcnick, from, NAMEMAX+1);
  /* let's check if it's identified user at first */
  if (Inspect_Client (&pmsgout->name[1], NULL, from, (const char **)&lname,
		      NULL, NULL, NULL) & A_REGISTERED)
  {
    if ((clr = Lock_Clientrecord (lname)))	/* might it be deleted yet? */
      uf = Get_Flags (clr, &pmsgout->name[1]);	/* network flags */
    else
      uf = 0;
  }
  else					/* Find_Clientrecord ignores case */
  {
    if (ae)
      *ae = '!';
    clr = Find_Clientrecord (from, &lname, &uf, &pmsgout->name[1]);
    if (ae)
      *ae = 0;				/* (from) still have to be just nick */
  }
  if (clr)
  {
    uf |= Get_Flags (clr, NULL);	/* add global flags */
    if (!to)				/* it's for me */
      df = Get_Flags (clr, "");		/* direct service flags for bindings */
    lname = safe_strdup (lname);
    Unlock_Clientrecord (clr);
  }
  else
    lname = NULL;
  msg_type = notice ? 1 : 0;		/* check type of the message */
  msglen = safe_strlen (msg);
  if (*msg == '\001' && msg[msglen-1] == '\001')
  {
    msg_type += 2;
    if (!notice && !strncmp (&msg[1], "ACTION ", 7))	/* ignore CTCR ACTION */
      msg_type = 4;
    msglen--;
  }
  dprint (5, "irc_privmsgin: got message from %s to %s of type %d", from,
	  NONULL(to), msg_type);
  /* find/create pmsgout for sender, pmsgout has to be nick@net */
  if ((client = _pmsgout_get_client (pmsgout->name, from)))
    Unset_Iface();
  else
  {
    strfcpy (tocl, from, sizeof(tocl));		/* use as temporary buffer */
    strfcat (tocl, pmsgout->name, sizeof(tocl));
    client = _pmsgout_stack_insert ((pmsgout_stack **)&pmsgout->data, tocl);
  }
  if (ae)
    *ae = '!';				/* restore full mask in (from) */
  ((pmsgout_stack *)client->data)->last = Time + pmsg_keep;
  /* check for flood */
  bind = NULL;
  ft = (msg_type & 2) ? "ctcp" : "msg";			/* action as msg too */
  i = 0;
  while ((bind = Check_Bindtable (BT_Flood, ft, uf, U_ANYCH, bind)))
  {
    if (bind->name)
      i = RunBinding (bind, from, lname ? lname : "*", ft, NULL, -1,
		      to ? to : "*");
    else
      i = bind->func (from, lname, ft, to);
    if (i)
      break;
  }
  if (i == 0)
  {
    if (msg_type & 2)
    {
      if (CheckFlood (&((pmsgout_stack *)pmsgout->data)->ctcp_flood, FloodCtcp) > 0)
      {
	FREE (&lname);
        return 1;
      }
    }
    else
    {
      if (CheckFlood (&((pmsgout_stack *)pmsgout->data)->msg_flood, FloodMsg) > 0)
      {
	FREE (&lname);
        return 1;
      }
    }
  }
  /* prepare mask bindtable */
  if (notice)
  {
    if (to)
      btmask = BT_PubNoticeMask;
    else
      btmask = BT_PrivNoticeMask;
  }
  else
  {
    if (to)
      btmask = BT_PubMsgMask;
    else
      btmask = BT_PrivMsgMask;
  }
  /* parse destination (*to) - i hope it is just one but really may be not */
  do
  {
    char tomask[NAMEMAX+MESSAGEMAX+1];
    char *chmask;
    INTERFACE *tmp;

    /*
     * now get where to put it! (for each of targets, of course)
     * a) private message/action: if there is a I_QUERY for target then go to (d)
     * b) check for mask bindings - run all
     * c) check for command - run (and log if 1) and go out
     * d) log unmatched to any
     */
    /* select the target */
    if (to)
    {
      register size_t ss;

      ft = strchr (to, ',');
      if (ft)
	*ft++ = 0;
      if (*to == '!')		/* special support for "!XXXXXchannel" */
      {
	snprintf (tomask, sizeof(tomask), "!%s %s", &to[6], msg);
	tocl[0] = '!';
	/* TODO: use lc() for channel name too */
	ss = unistrlower (&tocl[1], &to[6], sizeof(tocl) - 1) + 1;
      }
      else
      {
	snprintf (tomask, sizeof(tomask), "%s %s", to, msg);
	/* TODO: use lc() for channel name too */
	ss = unistrlower (tocl, to, sizeof(tocl));
      }
      chmask = tomask;
      strfcpy (&tocl[ss], pmsgout->name, sizeof(tocl) - ss);
    }
    else
      chmask = msg;
    /* check for query for target and pass casual privates */
    if (!allow_cmdpmsg && !to && (msg_type == 0 || msg_type == 4))
      tmp = Find_Iface (I_QUERY, client->name);
    else
      tmp = NULL;
    i = 0;
    if (tmp)
      Unset_Iface();
    else
    {
      userflag cf;

      if (lname && to)			/* known one to channel */
	cf = Get_Clientflags (lname, tocl);
      else if (to)			/* unknown to channel */
	cf = 0;
      else				/* private msg */
	cf = df;
      /* do mask bindtable */
      for (bind = NULL; (bind = Check_Bindtable (btmask, chmask, uf, cf, bind)); )
      {
	if (bind->name)	/* TODO: make scripts multinet-capable? */
	  RunBinding (bind, from, lname ? lname : "*",
		      to ? tocl : NULL, NULL, -1, msg);
	else if (to)
	  bind->func (client, from, lname, lcnick, tocl, msg);
	else
	  bind->func (client, from, lname, lcnick, msg);
      }
      if (msg_type >= 2)
	msg[msglen] = 0;
      /* check for command */
      bind = NULL;
      while ((bind = Check_Bindtable (to ? *PmsginTable[msg_type].pub_bt :
					*PmsginTable[msg_type].priv_bt,
				      &msg[PmsginTable[msg_type].shift],
				      uf, cf, bind)))
      {
	if (bind->name && (msg_type & 2)) /* another args for ctcp/ctcr */
	{
	  i = RunBinding (bind, from, lname ? lname : "*",
			  to ? tocl : irc_mynick(&pmsgout->name[1]),
			  &msg[PmsginTable[msg_type].shift], -1, NULL);
	}
	else if (bind->name)
	  i = RunBinding (bind, from, lname ? lname : "*",
			  to ? tocl : NULL, NULL, -1,
			  NextWord(&msg[PmsginTable[msg_type].shift]));
	else if (to)
	  i = bind->func (client, from, lname, lcnick, tocl,
			  NextWord(&msg[PmsginTable[msg_type].shift]));
	else
	  i = bind->func (client, from, lname, lcnick,
			  NextWord(&msg[PmsginTable[msg_type].shift]));
	if (i)
	  break;
      }
      if (msg_type >= 2)
	msg[msglen] = '\001';
    }
    /* log if no command or if command was succesful */
    if ((i == 0 && PmsginTable[msg_type].format != NULL) ||
	(i > 0 && PmsginTable[msg_type].cmdformat != NULL))
    {
      if (ae)
	*ae = 0;
      /* %N - nick, %@ - ident@host, %L - lname, %# - target, %* - message */
      if (msg_type >= 2)
	msg[msglen] = 0;
      if (i)
	printl (tomask, sizeof(tomask), *PmsginTable[msg_type].cmdformat, 0,
		from, ae ? &ae[1] : NULL, lname, to, 0, 0, 0,
		&msg[PmsginTable[msg_type].shift]);
      else
	printl (tomask, sizeof(tomask), *PmsginTable[msg_type].format, 0,
		from, ae ? &ae[1] : NULL, lname, to, 0, 0, 0,
		&msg[PmsginTable[msg_type].shift]);
      if (msg_type >= 2)
	msg[msglen] = '\001';
      if (*tomask)
	Add_Request (I_LOG, to ? tocl : lcnick,
		     (i ? F_CMDS : to ? F_PUBLIC : F_PRIV) | msg_type,
		     "%s", tomask);
      if (ae)
	*ae = '!';
    }
    if (to)
      to = ft;	/* next target */
  } while (to && *to);
  FREE (&lname);
  return 1;
}

/* nocheckflood for friends */
BINDING_TYPE_irc_flood (irc_ignflood);
static int irc_ignflood (unsigned char *from, char *lname, char *type, char *chan)
{
  return 1;
}


/* --- common part ---------------------------------------------------------- */

void irc_privmsgreg (void)
{
  BT_PubMsgMask = Add_Bindtable ("irc-pub-msg-mask", B_MASK);
  BT_PubNoticeMask = Add_Bindtable ("irc-pub-notice-mask", B_MASK);
  BT_PubMsgCmd = Add_Bindtable ("irc-pub-msg-cmd", B_UNIQ);
  BT_PubNoticeCmd = Add_Bindtable ("irc-pub-notice-cmd", B_UNIQ);
  BT_PubCtcp = Add_Bindtable ("irc-pub-msg-ctcp", B_MATCHCASE);
  BT_PubCtcr = Add_Bindtable ("irc-pub-notice-ctcp", B_MATCHCASE);
  BT_PrivMsgMask = Add_Bindtable ("irc-priv-msg-mask", B_MASK);
  BT_PrivNoticeMask =  Add_Bindtable ("irc-priv-notice-mask", B_MASK);
  BT_PrivMsgCmd = Add_Bindtable ("irc-priv-msg-cmd", B_UNIQ);
  BT_PrivNoticeCmd = Add_Bindtable ("irc-priv-notice-cmd", B_UNIQ);
  BT_PrivCtcp = Add_Bindtable ("irc-priv-msg-ctcp", B_MATCHCASE);
  BT_PrivCtcr = Add_Bindtable ("irc-priv-notice-ctcp", B_MATCHCASE);
  BT_Flood = Add_Bindtable ("irc-flood", B_MASK);
  Add_Binding ("irc-flood", "*", U_FRIEND, U_FRIEND, &irc_ignflood, NULL);
  FloodMsg = FloodType ("irc-msgs");	/* register flood, no defaults */
  FloodCtcp = FloodType ("irc-ctcps");
  format_irc_message = SetFormat ("irc_message", "<%N> %*");
  format_irc_notice = SetFormat ("irc_notice", "-%N- %*");
  format_irc_ctcp = SetFormat ("irc_ctcp", "%N requested CTCP %* from %?#%#?me?");
  format_irc_ctcr = SetFormat ("irc_ctcp_reply", "CTCP reply from %N: %*");
  format_irc_action = SetFormat ("irc_action", "* %N %*");
  format_irc_cmdmessage = SetFormat ("irc_message_command", "%?#<<?(?%N%?#>>?!%@)? !%L! %*");
  format_irc_cmdctcp = SetFormat ("irc_ctcp_command", "((%N)) %?L!%L! ??%?#(CTCP to %#) ??%*");
}

void irc_privmsgunreg (void)
{
  Delete_Binding ("irc-flood", &irc_ignflood, NULL);
  _forget_(pmsgout_stack);
}
