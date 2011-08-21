/*
 * Copyright (C) 2006-2011  Andriy N. Gritsenko <andrej@rep.kiev.ua>
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
 * The FoxEye "irc-ctcp" module: CTCP DCC related stuff.
 */

#include "foxeye.h"

#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>

#include "modules.h"
#include "direct.h"
#include "init.h"
#include "socket.h"
#include "sheduler.h"
#include "list.h"

#define MINBLOCKSIZE	256
#define MAXBLOCKSIZE	16384

typedef struct dcc_priv_t
{
  struct dcc_priv_t *next;		/* R/O in thread */
  INTERFACE *iface;			/* undefined in P_DISCONNECTED state */
  char *filename;			/* R/O in thread */
  uint32_t size;			/* R/O while in thread, file size */
  uint32_t ptr, startptr;		/* size got, start pointers */
  uint32_t rate;			/* average (16s) filetransfer speed */
  long int ahead;			/* R/O local value of ahead parameter */
  unsigned int token;			/* R/O in thread */
  idx_t socket;				/* owned by thread, inherited later */
  pthread_t th;				/* undefined in P_DISCONNECTED state */
  pthread_mutex_t mutex;		/* for ->ptr ... ->rate */
  _peer_state state;			/* locked by dispatcher */
  tid_t tid;				/* dispatcher-only, for S_TIMEOUT */
  bool wait_accept;			/* we still waiting for DCC ACCEPT */
  char lname[LNAMELEN+1];		/* R/O in thread */
#if HOSTMASKLEN >= LONG_STRING
  char uh[HOSTMASKLEN+1];		/* R/O in thread, nick!user@host */
#else
  char uh[LONG_STRING];			/* used temp. for filename too */
#endif
} dcc_priv_t;

static dcc_priv_t *ActDCC = NULL;	/* chain of active sessions */

static struct bindtable_t *BT_IDcc;	/* "ctcp-dcc" : CTCP DCC bindings */
static struct bindtable_t *BT_Login;	/* "login" bindtable from Core */
static struct bindtable_t *BT_Dnload;	/* "dcc-got" : received a file */
static struct bindtable_t *BT_Cctcp;	/* a bindtable from module "irc" */
static struct bindtable_t *BT_Upload;	/* "dcc-sent" : received a file */


static long int ircdcc_ahead_size = 0;	/* "turbo" mode to speed up transfer */
static long int ircdcc_conn_timeout = 60;
static long int ircdcc_resume_timeout = 30;
static long int ircdcc_resume_min = 10000;
static long int ircdcc_get_maxsize = 1000000000;
static long int ircdcc_blocksize = 2048;
static bool ircdcc_allow_dcc_chat = TRUE;
static bool ircdcc_allow_resume = TRUE;
static bool ircdcc_do_resume_send = (CAN_ASK | TRUE);	/* yes */
static bool ircdcc_accept_send = (CAN_ASK | TRUE);	/* yes */
static bool ircdcc_accept_chat = (CAN_ASK | ASK | TRUE);/* ask-yes */
static bool ircdcc_do_overwrite = (CAN_ASK | FALSE);	/* no */
static char ircdcc_dnload_dir[LONG_STRING] = "~/.foxeye/files";

static char *format_dcc_gotfile;
static char *format_dcc_sentfile;
static char *format_dcc_startget;
static char *format_dcc_request;

#undef ALLOCSIZE
#define ALLOCSIZE 2
ALLOCATABLE_TYPE (dcc_priv_t, DCC, next) /* alloc_dcc_priv_t(), free_dcc_priv_t() */

/* has no locks so non-thread calls only! */
static dcc_priv_t *new_dcc (void)
{
  register dcc_priv_t *dcc;
  register dcc_priv_t **p = &ActDCC;

  while ((dcc = *p) && dcc->state != P_LASTWAIT)
    p = &dcc->next;
  if (!dcc)
  {
    *p = dcc = alloc_dcc_priv_t();
    dcc->next = NULL;
    pthread_mutex_init (&dcc->mutex, NULL);
  }
  dcc->state = P_DISCONNECTED;
  dcc->socket = -1;
  dcc->tid = (tid_t)-1;
  dprint (4, "dcc:new_dcc: %p", dcc);
  return dcc;
}

static void free_dcc (dcc_priv_t *dcc)
{
  register dcc_priv_t *last;
  register dcc_priv_t **p = &ActDCC;

  dprint (4, "dcc:free_dcc: %p", dcc);
  while ((last = *p) && last != dcc)
    p = &last->next;
  if (last)
    *p = dcc->next;
  else
    ERROR ("irc-ctcp:dcc.c:free_dcc: could not find %p to free it!", dcc);
  pthread_mutex_destroy (&dcc->mutex);
  free_dcc_priv_t (dcc);
}

#define LOG_CONN(...) Add_Request (I_LOG, "*", F_CONN, __VA_ARGS__)

/* sequence (m - dispathcer's thread, 1...3 - new threads):
    m	got DCC CHAT or DCC SEND or CTCP CHAT (last one skips thread 1 part)
    1	check for UI confirmation
    1	got confirmation
    1		need to be resumed? ask to resume confirmation
    1		got confirmation? send DCC RESUME and finish with state=P_OFFER
    m	got DCC ACCEPT? remap pointer and continue with I_FINWAIT
    m	got timeout? don't wait for DCC ACCEPT anymore
    m	kill thread 1 and if state!=P_QUIT then start connection
    2	got connected, start main interface (_dcc_X_handler())
    2	terminate thread and socket when done
    m	join thread 2 and finish all */

/* ----------------------------------------------------------------------------
   thread 2 non-thread part (signal handler)
   states here are:
	- P_INITIAL: waiting for outgoing connection or got incoming
	- P_TALK: in file transfer */

/* when: before connection, in connection, on finishing stage 2 */
static iftype_t _dcc_sig_2 (INTERFACE *iface, ifsig_t signal)
{
  dcc_priv_t *dcc = iface->data;
  INTERFACE *tmp;
  char msg[MESSAGEMAX];
  char buf[SHORT_STRING];
  char *txt;

  if (!dcc)				/* already killed? */
    return I_DIED;
  switch (signal)
  {
    case S_REPORT:
      if (dcc->state == P_INITIAL)	/* waiting for connection */
	txt = "waiting for DCC connection";
      else				/* file transfer in progress */
      {
	if ((txt = strrchr (dcc->filename, '/')))
	  txt++;
	else
	  txt = dcc->filename;
	pthread_mutex_lock (&dcc->mutex);
	snprintf (buf, sizeof(buf), "transfer %s: %lu of %lu bytes, %lu B/s",
		  txt, (unsigned long int)(dcc->startptr + dcc->ptr),
		  (unsigned long int)dcc->size, (unsigned long int)dcc->rate);
	pthread_mutex_unlock (&dcc->mutex);
	txt = buf;
      }
      /* %@ - uh, %L - Lname, %P - socket, %* text */
      printl (msg, sizeof(msg), ReportFormat, 0, NULL, dcc->uh, dcc->lname,
	      NULL, (uint32_t)0, dcc->socket + 1, 0, txt);
      tmp = Set_Iface (iface);
      New_Request (tmp, F_REPORT, "%s", msg);
      Unset_Iface();
      break;
    case S_LOCAL:			/* we might get ACCEPT after timeout */
      if (dcc->filename && dcc->wait_accept &&
	  !safe_strncmp (BindResult, "ACCEPT ", 7))
      {
	unsigned long port, position;
	unsigned short port2;

	txt = NextWord_Unquoted (NULL, NextWord(BindResult), 0);
	port = strtoul(txt, (char **)NULL, 10);
	if (dcc->state == P_INITIAL)
	{
	  if (dcc->ptr != port)	/* before we got .idx we have port in .ptr */
	  {
	    DBG ("irc-ctcp:_dcc_sig_2: ACCEPT port %lu != %u", port, dcc->ptr);
	    break;
	  }
	}
	else
	{
	  SocketDomain (dcc->socket, &port2);
	  if (port != port2)	/* check for ports in ACCEPT message */
	  {
	    DBG ("irc-ctcp:_dcc_sig_2: ACCEPT port %lu != %hu", port, port2);
	    break;
	  }
	}
	position = strtoul (NextWord (txt), NULL, 10);
	port = strtoul(NextWord(txt), NULL, 10);
	if (dcc->token != port) { /* for active SEND token is 0 obviously */
	  DBG ("irc-ctcp:_dcc_sig_2: ACCEPT token %lu != %u", port, dcc->token);
	  break;
	}
	BindResult = NULL;		/* we used it so drop it */
	pthread_mutex_lock (&dcc->mutex);
	if (dcc->startptr)
	{
	  pthread_mutex_unlock (&dcc->mutex);
	  Add_Request (I_LOG, "*", F_WARN,
		       _("DCC GET: got late ACCEPT for %s, ignoring it."),
		       dcc->filename);
	  break;
	}
	dcc->startptr = position;
	dcc->wait_accept = FALSE;
	pthread_mutex_unlock (&dcc->mutex);
	LOG_CONN (_("DCC: got ACCEPT on %s, transfer resumed at %u."),
		  dcc->filename, dcc->startptr);
      }
      break;
    case S_TIMEOUT:			/* connection timeout? */
    case S_TERMINATE:
      if (dcc->socket >= 0)		/* check if it's forced to die */
	LOG_CONN (_("DCC connection to %s terminated."), iface->name);
      CloseSocket (dcc->socket);	/* just kill its socket... */
      if (dcc->th)
      {
	Unset_Iface();			/* unlock dispatcher */
	pthread_join (dcc->th, NULL);	/* ...it die itself, waiting for it */
	Set_Iface (NULL);		/* restore status quo */
      }
      FREE (&dcc->filename);
      KillTimer (dcc->tid);		/* if it's still on timeout */
      free_dcc (dcc);
      iface->data = NULL;		/* dispatcher should not unalloc it */
      Set_Iface (iface);		/* for UI notifying */
      iface->ift = I_DIED;
      Send_Signal (I_MODULE, "ui", S_FLUSH); /* notify the UI */
      Unset_Iface();			/* restore status quo */
      break;
    case S_SHUTDOWN:
      /* just kill it... */
      CloseSocket (dcc->socket);
      /* ...it die itself */
      return I_DIED;
    default:;
  }
  return 0;
}


/* ----------------------------------------------------------------------------
   thread 2 (both CTCP CHAT and CTCP DCC CHAT connection handler) */

static void chat_handler (char *lname, char *ident, const char *host, void *data)
{
  char buf[SHORT_STRING];
  userflag uf;
  struct binding_t *bind;
  size_t sz, sp;
  char *msg;
  dcc_priv_t *dcc = data;
  struct peer_t *peer;

  dprint (4, "dcc:chat_handler for %s", lname);
  /* check for allowance */
  if (dcc == NULL)
  {
    ERROR ("DCC CHAT: connection with %s(%s@%s) not found, forgetting thread.",
	   lname, ident, host);
    return;
  }
  uf = Match_Client (host, ident, lname);
  Set_Iface (NULL);
  /* if UI exists then it have binding for everyone so will create UI window */
  bind = Check_Bindtable (BT_Login, "*", uf, 0, NULL);
  msg = NULL;
  peer = safe_malloc (sizeof(struct peer_t));
  peer->socket = dcc->socket;
  peer->state = dcc->state;
  peer->dname = NULL;
  peer->parse = &Dcc_Parse;
  peer->connchain = NULL;
  peer->iface = NULL;
  peer->priv = NULL;
  time (&peer->last_input);
  snprintf (peer->start, sizeof(peer->start), "%s %s", DateString, TimeString);
  /* dispatcher is locked, can initialize connchain: only RAW->TXT for now */
  Connchain_Grow (peer, 'x');
  if (bind && !bind->name) /* allowed to logon */
  {
    buf[0] = 'x';
    buf[1] = 0;
    bind->func (lname, ident, host, peer, buf, &msg); /* it will unlock dispatcher */
  }
  else
  {
    Unset_Iface();
    msg = "no access";
  }
  if (msg)					/* was error on connection */
  {
    unsigned short p;
    register ssize_t got;

    snprintf (buf, sizeof(buf), "Access denied: %s", msg);
    sz = strlen (buf);
    sp = 0;
    while (sz && (got = Peer_Put (peer, &buf[sp], &sz)) >= 0)
      sp += got;
    SocketDomain (dcc->socket, &p);
    /* %L - Lname, %P - port, %@ - hostname, %* - reason */
    Set_Iface (NULL);
    printl (buf, sizeof(buf), format_dcc_closed, 0,
	    NULL, host, lname, NULL, 0, p, 0, msg);
    Unset_Iface();
    LOG_CONN ("%s", buf);
    if(Connchain_Kill (peer))got=got;
    KillSocket (&peer->socket);	/* it's really dead now */
    FREE (&peer);
  }
  dcc->socket = -1;		/* socket might be inherited by login */
  Set_Iface (NULL);		/* ask dispatcher to kill thread 2 */
  dcc->iface->ift |= I_FINWAIT; /* all rest will be done by _dcc_sig_2() */
  Unset_Iface();
}

/* thread 2 (incoming connection) */

struct dcc_listener_data {
  dcc_priv_t *dcc;
};

/* connected for CTCP CHAT / .send, fields (if dcc is found) are now:
    .filename	NULL / path
    .state	P_DISCONNECTED
    .socket	listening socket id
    .uh		nick!user@host / nick@net */
static void _dcc_inc_pre (pthread_t th, void **data, idx_t as)
{
  register struct dcc_listener_data *dld = *data;
  register dcc_priv_t *dcc = dld->dcc;

  *data = dcc;				/* pass it to handler */
  if (as == -1)				/* listener terminated */
  {
    if (dcc)
      dcc->state = P_LASTWAIT;		/* mark it to be freed */
    /* it would be nice to write some debug but aren't we in SIGSEGV? */
    return;
  }
  if (dcc)
  {
    dcc->th = th;
    dcc->socket = as;
    dcc->state = P_INITIAL;		/* and now listener can die free */
    dcc->iface = Add_Iface (I_CONNECT, dcc->uh, &_dcc_sig_2, NULL, dcc);
  }
  else					/* is answered to unknown socket? */
  {
    ERROR ("DCC CHAT: socket not found, shutdown thread.");
    CloseSocket (as);			/* module may be already terminated */
    pthread_detach (th);
  }
}

/* connected for sending file, fields are now:
    .size	file size on start
    .ahead	ircdcc_ahead_size
    .state	P_INITIAL
    .uh		nick@net, or nick@user!host if it's from (p)SEND
    .ptr	port
    .startptr	0/1 or resume ptr
    .filename	filename (allocated)
    .lname	"", or Lname if we got valid ACCEPT or (p)SEND request before
    .iface	thread interface (I_CONNECT nick@net)
    .socket	socket ID
    .th		thread ID
    .mutex	initialised and unlocked */
static void isend_handler (char *lname, char *ident, const char *host, void *data)
{
  char *buff;
  dcc_priv_t *dcc = data;
  FILE *f;
  uint32_t ptr, aptr, nptr;		/* ptr, ack ptr, net-ordered */
  uint32_t sr;
  time_t t, t2;
  size_t bs, bptr, ahead;
  ssize_t sw;
  size_t statistics[16];		/* to calculate average speed */

  dprint (4, "dcc:isend_handler for %s to \"%s\".", lname, dcc->lname);
  buff = safe_malloc (MAXBLOCKSIZE);
  Set_Iface (dcc->iface);
  if (host)				/* if it's from passive then it's NULL */
  {
    sr = strchr (dcc->uh, '@') - dcc->uh; /* size of nick */
    snprintf (&dcc->uh[sr], sizeof(dcc->uh) - sr, "!%s@%s", ident ? ident : "*",
	      host ? host : "*");
  }					/* dcc->uh is nick!user@host now */
  dcc->ptr = 0;
  dcc->rate = 0;
  if (dcc->startptr == 1)		/* it was '-flush' flag */
    dcc->startptr = 0;
  dcc->state = P_TALK;			/* now we can use mutex, ok */
  f = fopen (dcc->filename, "rb");	/* try to open file */
  if (f == NULL)
  {
    strerror_r (errno, buff, sizeof(buff));
    ERROR ("DCC SEND: cannot open file %s: %s.", dcc->filename, buff);
    KillSocket (&dcc->socket);
    FREE (&buff);
    dcc->iface->ift |= I_FINWAIT; /* all rest will be done by _dcc_sig_2() */
    Unset_Iface();
    return;
  }
  bs = ircdcc_blocksize;
  if (bs > MAXBLOCKSIZE)
    bs = MAXBLOCKSIZE;
  if (bs < MINBLOCKSIZE)
    bs = MINBLOCKSIZE;
  Send_Signal (I_MODULE, "ui", S_FLUSH); /* notify the UI on transfer */
  Unset_Iface();
  fseek (f, dcc->startptr, SEEK_SET);
  aptr = ptr = 0;
  ahead = dcc->ahead * bs;
  time (&t);
  memset (statistics, 0, sizeof(statistics));
  FOREVER					/* cycle to get file */
  {
    pthread_mutex_lock (&dcc->mutex);
    dcc->ptr = ptr;
    time (&t2);
    if (t != t2)
    {
      for (sw = 0, sr = 0; sr < 16; sr++)	/* use sr as temp */
	sw += statistics[sr];
      dcc->rate = sw/16;
      while (t++ < t2)
	statistics[t%16] = 0;
    }
    pthread_mutex_unlock (&dcc->mutex);
    sw = ReadSocket ((char *)&nptr, dcc->socket, 4, M_RAW); /* next block ack */
    if (sw < 0)
      break;					/* connection error */
    else if (sw)
    {
      DBG ("DCC SEND %s:got ack %#x.", dcc->filename, (int)sw);
      sr = ntohl (nptr);
    }
    else
      sr = aptr;
    if (sr < aptr || sr > ptr)			/* wrong ack */
      break;
    if (sr >= dcc->size)			/* all done! */
      break;
    aptr = sr;					/* updating aptr */
    if (aptr + ahead < ptr)
      continue;					/* not ready to send anything */
    sw = sr = fread (buff, 1, bs, f);		/* 0 if EOF or error */
    bptr = 0;
    while (sw)
      if (WriteSocket (dcc->socket, buff, &bptr, &sw, M_POLL) < 0)
	break;					/* if socket died */
    if (sw)
      break;
    ptr += sr;					/* updating ptr */
    statistics[t%16] += sr;
    DBG ("DCC SEND %s:sent %u bytes.", dcc->filename, (unsigned int)sr);
  }
  if (ptr == dcc->size)
  {
    char *c;
    userflag uf;
    struct clrec_t *u;
    struct binding_t *b;

    c = strchr (dcc->iface->name, '@') + 1; /* network name */
    if (dcc->lname[0])			/* we know Lname already */
    {
      lname = NULL;
      uf = Get_Clientflags (dcc->lname, c);
      c = dcc->lname;
    }
    else if ((u = Find_Clientrecord (buff, &c, &uf, c))) /* ok, find it */
    {
      lname = safe_strdup (c);
      Unlock_Clientrecord (u);
      c = NONULL(lname);
    }
    else				/* cannot recognize target Lname */
    {
      lname = NULL;
      c = "";
      uf = 0;
    }
    Set_Iface (NULL);
    b = NULL;
    while ((b = Check_Bindtable (BT_Upload, c, uf, U_ANYCH, b)))
      if (b->name)
	RunBinding (b, NULL, lname, dcc->iface->name, NULL, -1, dcc->filename);
      else
	b->func (dcc->uh, dcc->filename);
    /* %L - Lname, %N - nick@net, %@ - user@host, %I - socket, %* - filename */
    sr = strchr (dcc->uh, '!') - dcc->uh;
    printl (buff, MAXBLOCKSIZE, format_dcc_sentfile, 0, dcc->iface->name,
	    &dcc->uh[sr+1], lname, NULL, dcc->socket + 1, 0, 0, dcc->filename);
    Unset_Iface();
    FREE (&lname);
    LOG_CONN ("%s", &buff[MAXBLOCKSIZE/2]);
  }
  else
    ERROR ("DCC SEND %s failed: sent %lu out from %lu bytes.", dcc->filename,
	   (unsigned long int)ptr, (unsigned long int)dcc->size);
  fclose (f);
  KillSocket (&dcc->socket);
  FREE (&buff);
  Set_Iface (NULL);
  dcc->iface->ift |= I_FINWAIT; /* all rest will be done by _dcc_sig_2() */
  Unset_Iface();
}

#define dcc ((dcc_priv_t *) input_data)
/* connected for passive file sending, fields are now:
    .size	file size on start
    .ahead	ircdcc_ahead_size
    .state	P_INITIAL
    .uh		nick!user@host
    .startptr	0 or resume ptr
    .filename	filename (allocated)
    .lname	Lname
    .iface	thread interface (I_CONNECT nick@net)
    .socket	socket ID
    .th		thread ID
    .mutex	initialized, unlocked */
static void _isend_phandler (int res, void *input_data)
{
  dprint (4, "dcc:_isend_phandler: %d", res);
  if (res == 0)
    isend_handler (NULL, NULL, NULL, input_data);
  else
  {
    char buf[HOSTMASKLEN];

    LOG_CONN (_("DCC SEND connection to %s failed: %s."), dcc->iface->name,
	      SocketError (res, buf, sizeof(buf)));
    KillSocket (&dcc->socket);
    Set_Iface (NULL);
    dcc->iface->ift |= I_FINWAIT; /* all rest will be done by _dcc_sig_2() */
    Unset_Iface();
  }
}

/* thread 2 (outgoing connection, i.e. answer to DCC CHAT and DCC SEND) */

/* connected for DCC CHAT, fields are now:
    .filename	NULL
    .ahead	ircdcc_ahead_size
    .state	P_INITIAL
    .uh		nick!user@host
    .rate	IP #
    .lname	Lname
    .iface	thread interface (I_CONNECT nick!user@host)
    .socket	socket ID
    .th		thread ID */
static void _dcc_chat_handler (int res, void *input_data)
{
  register char *host = safe_strchr (dcc->uh, '@');
  register char *ident = safe_strchr (dcc->uh, '!');

  dprint (4, "dcc:_dcc_chat_handler: %d", res);
  if (host)
    *host++ = 0;
  if (ident)
    ident++;
  if (res == 0)
    chat_handler (dcc->lname, ident, host, dcc);
  else
  {
    char buf[SHORT_STRING];

    LOG_CONN (_("DCC CHAT connection to %s failed: %s."), dcc->iface->name,
	      SocketError (res, buf, sizeof(buf)));
    KillSocket (&dcc->socket);
    Set_Iface (NULL);
    dcc->iface->ift |= I_FINWAIT; /* all rest will be done by _dcc_sig_2() */
    Unset_Iface();
  }
}

/* connected for DCC SEND (receiving file), fields are now:
    .size	offered size
    .ptr	port #
    .filename	full path (allocated)
    .ahead	ircdcc_ahead_size
    .state	P_INITIAL
    .uh		nick!user@host
    .rate	IP #
    .lname	Lname
    .startptr	0 or resume ptr (may be changed even later)
    .iface	thread interface (I_CONNECT nick@net)
    .socket	socket ID
    .th		thread ID
    .mutex	inited, unlocked */

/* sequence:
    -> DCC SEND ...
    <- wait for connection
    <-  DCC RESUME ...
    ->  DCC ACCEPT ...
    <- connect
    -> packet
    <- bytes got
    -> packet... */
	/* we will get file anyway but if we got ACCEPT then reset startptr */
	/* on send we will ignore RESUME after first packet already sent */
static void _dcc_send_handler (int res, void *input_data)
{
  uint32_t ptr, nptr, ip;	/* current ptr in chunk, network-ordered, IP */
  uint32_t aptr, toget;		/* ahead ptr, toget */
  ssize_t bs, sbs, sw, sw2;	/* gotten block size, temp var */
  int ahead;			/* current ahead size */
  time_t t, t2;
  size_t statistics[16];	/* to calculate average speed */
  FILE *f, *rf;			/* opened file */
  void *buff;
  char *uh, *sfn;
  bool wait_accept;

  dprint (4, "dcc:_dcc_send_handler: %d", res);
  if (res != 0)					/* some error catched */
  {
    Set_Iface (NULL);
    dcc->iface->ift |= I_FINWAIT; /* all rest will be done by _dcc_sig_2() */
    Unset_Iface();
  }
  pthread_mutex_lock (&dcc->mutex);		/* prepare to work */
  wait_accept = dcc->wait_accept;
  dcc->ptr = 0;
  ip = dcc->rate;
  dcc->rate = 0;
  pthread_mutex_unlock (&dcc->mutex);
  Set_Iface (dcc->iface);
  dcc->state = P_TALK;
  Send_Signal (I_MODULE, "ui", S_FLUSH); /* notify the UI on transfer */
  Unset_Iface();
  ptr = 0;
  bs = sbs = sw2 = 0;
  ahead = 0;
  time (&t);
  memset (statistics, 0, sizeof(statistics));
  if (wait_accept)		/* if waiting for ACCEPT then open temp file */
    f = tmpfile();
  else if ((f = fopen (dcc->filename, "wb")))	/* else open real file */
  {
    pthread_mutex_lock (&dcc->mutex);
    fseek (f, dcc->startptr, SEEK_SET);
    pthread_mutex_unlock (&dcc->mutex);
  }
  if (f == NULL)
  {
    ERROR ("DCC GET: cannot open local file to download there.");
    KillSocket (&dcc->socket);
    Set_Iface (NULL);
    dcc->iface->ift |= I_FINWAIT; /* all rest will be done by _dcc_sig_2() */
    Unset_Iface();
    return;
  }
  buff = safe_malloc (MAXBLOCKSIZE);
  uh = safe_strchr (dcc->uh, '!');	/* split nick and user@host in buf */
  if (uh)
    uh++;
  sfn = strrchr (dcc->filename, '/');		/* get short filename */
  if (sfn)
    sfn++;
  else
    sfn = dcc->filename;
  Set_Iface (NULL);
  /* %L - lname, %@ - uh, %N - nick@net, %I - IP, %* - filename(unquoted) */
  printl (buff, MAXBLOCKSIZE, format_dcc_startget, 0, dcc->iface->name, uh,
	  dcc->lname, NULL, ip, 0, 0, sfn);
  Unset_Iface();
  LOG_CONN ("%s", (char *)buff);		/* do logging */
  aptr = ptr;
  FOREVER					/* cycle to get file */
  {
    toget = 0;
    time (&t2);
    pthread_mutex_lock (&dcc->mutex);
    dcc->ptr = ptr;
    if (t != t2)
    {
      for (sw = 0, nptr = 0; nptr < 16; nptr++)	/* use nptr as temp */
	sw += statistics[nptr];
      dcc->rate = sw/16;
      while (t++ < t2)
	statistics[t%16] = 0;
    }
    if (dcc->size > dcc->startptr)
      toget = dcc->size - dcc->startptr;	/* to get: for use below */
    pthread_mutex_unlock (&dcc->mutex);
    sw = ReadSocket (buff, dcc->socket, MAXBLOCKSIZE, M_RAW); /* next block */
    if (!sbs && sw == sw2)		/* two cons. blocks of the same size */
      sbs = sw;					/* assume it's block size */
    if (sw > 0)
      bs = fwrite (buff, 1, sw, f);
    else if (!sw || sw == E_AGAIN)		/* try again */
    {
      if (sbs && ahead < dcc->ahead)		/* sending request */
      {
	nptr = aptr + sbs;
	if (nptr >= toget)			/* nowhere to ahead */
	  continue;
	ahead++;
	aptr = nptr;
	DBG ("DCC GET %s:ack ptr %#x ahead bs %d.", dcc->filename, (int)aptr, (int)sbs);
	nptr = htonl (aptr);			/* next block for ahead */
	bs = 0;
	sw = sizeof(nptr);
	while (sw)				/* send network-ordered ptr */
	  if (WriteSocket (dcc->socket, (char *)&nptr, &bs, &sw, M_POLL) < 0)
	    break;
	if (sw)
	  break;				/* if socket died */
      }
      continue;
    }
    else if (sw < 0)				/* error happened */
      break;
    if (sw != bs)				/* file writing error */
      break;
    ptr += bs;
    statistics[t%16] += bs;
    sw2 = sw;					/* keep it for next cycle */
    DBG ("DCC GET %s:got %zd bytes.", dcc->filename, sw);
    if (ahead && bs == sbs)			/* we got full next block */
      ahead--;
    if (ptr < aptr)				/* we sent ptr ahead */
      continue;
    ahead = 0;					/* we are at ptr! */
    DBG ("DCC GET %s:ack ptr %#x.", dcc->filename, (int)ptr);
    nptr = htonl ((aptr = ptr));
    bs = 0;
    sw = sizeof(nptr);
    while (sw)					/* send network-ordered ptr */
      if (WriteSocket (dcc->socket, (char *)&nptr, &bs, &sw, M_POLL) < 0)
	break;					/* if socket died */
    if (sw)					/* we got all we can */
      break;
  }
  pthread_mutex_lock (&dcc->mutex);
  if (wait_accept && dcc->startptr)
  {
    /* if want_resume and got startptr then move file chunk to real file */
    aptr = dcc->startptr;
    dcc->startptr = 1;			/* it's too late to get ACCEPT now */
    pthread_mutex_unlock (&dcc->mutex);
    if (!(rf = fopen (dcc->filename, "wb")))
      ERROR ("DCC GET: cannot append to local file after resume.");
    else
    {
      fseek (rf, aptr, SEEK_SET);
      fseek (f, 0L, SEEK_SET);
      while ((sw = fread (buff, 1, MAXBLOCKSIZE, f)) > 0 &&
	(sw2 = fwrite (buff, 1, sw, rf)) == sw);
      fclose (rf);
      if (sw < 0 || sw2 != sw)			/* got an error on save */
	ERROR ("DCC GET: error on saving file %s.", dcc->filename);
    }
    pthread_mutex_lock (&dcc->mutex);
  }
  if (dcc->size == 0 || ptr == dcc->size)	/* getting is complete */
  {
    /* %L - lname, %@ - uh, %N - nick@net, %I - IP, %* - filename(unquoted) */
    Set_Iface (NULL);
    printl (buff, MAXBLOCKSIZE, format_dcc_gotfile, 0, dcc->iface->name, uh,
	    dcc->lname, NULL, ip, 0, 0, sfn);
    Unset_Iface();
  }
  else if (ptr > dcc->size)			/* file is bigger than offered */
    snprintf (buff, MAXBLOCKSIZE,
	      _("Got file \"%s\" from %s: %lu bytes instead of %lu."), sfn,
	      dcc->iface->name, (unsigned long)ptr, (unsigned long)dcc->size);
  else						/* incomplete file! */
    snprintf (buff, MAXBLOCKSIZE,
	      _("Got incomplete file \"%s\" from %s: %lu/%lu bytes."), sfn,
	      dcc->iface->name, (unsigned long)ptr, (unsigned long)dcc->size);
  LOG_CONN ("%s", (char *)buff);		/* do logging */
  KillSocket (&dcc->socket);			/* close/unallocate all */
  fclose (f);
  if (ptr == dcc->size)				/* successfully downloaded */
  {
    struct binding_t *bind = NULL;
    userflag uf = Get_Clientflags (dcc->lname, NULL);
    const char *path;

    if (sfn == dcc->filename)			/* no path was given at all */
      path = ".";
    else					/* calculate relative path */
    {
      Set_Iface (NULL);				/* to get access to path */
      path = expand_path (buff, ircdcc_dnload_dir, MAXBLOCKSIZE);
      if (!strncmp (dcc->filename, path, strlen(path)))
	path = &dcc->filename[strlen(path)+1];	/* it contains defpath */
      else
	path = dcc->filename;			/* sorry but only fullpath */
      Unset_Iface();
      if (path == sfn)				/* file is on defpath */
	path = ".";
      sfn--;					/* put it back to '/' */
    }
    do
    {
      if ((bind = Check_Bindtable (BT_Dnload, dcc->lname, uf, U_ANYCH, bind)))
      {
	if (bind->name)
	{
	  if (sfn) *sfn = 0;
	  RunBinding (bind, NULL, dcc->iface->name, dcc->uh, NULL, -1, path);
	  if (sfn) *sfn = '/';
	}
	else
	  bind->func (dcc->uh, dcc->filename);
      }
    } while (bind);
  }
  safe_free (&buff);
  Set_Iface (NULL);
  dcc->iface->ift |= I_FINWAIT; /* all rest will be done by _dcc_sig_2() */
  Unset_Iface();
}

/* the same but for passive mode - incoming connect to our socket.
   lname contains nick@net and dcc->iface is invalid */
static void _dcc_send_phandler (char *lname, char *ident, const char *host,
				void *input_data)
{
  /* don't check ident and host - we can be wrong on that */
  /* unlocked now but dispatcher will wait this thread to join before freeing */
  dprint (4, "dcc:_dcc_send_phandler: %s", lname);
  if (!input_data)
    /* error! is it possible? */
    return;
  dcc->iface = Add_Iface (I_CONNECT, lname, &_dcc_sig_2, NULL, input_data);
  _dcc_send_handler (0, dcc);
}
#undef dcc

/* prehandler for passive DCC SEND */
static void _dcc_pasv_pre (pthread_t th, void **data, idx_t as)
{
  register struct dcc_listener_data *dld = *data;
  register dcc_priv_t *dcc = dld->dcc;

  *data = dcc;				/* pass it to handler */
  if (as == -1)				/* listener terminated */
  {
    if (dcc)
      dcc->state = P_LASTWAIT;		/* mark it to be freed */
    /* it would be nice to write some debug but aren't we in SIGSEGV? */
    return;
  }
  if (dcc)
  {
    dcc->th = th;
    dcc->socket = as;
    dcc->state = P_INITIAL;		/* and now listener can die free */
    /* we cannot create interface at this point unfortunately so cannot cancel
       this thread until we get ident and come to _dcc_send_phandler() */
  }
  else					/* is answered to unknown socket? */
  {
    ERROR ("DCC CHAT: socket not found, shutdown thread.");
    CloseSocket (as);			/* module may be already terminated */
    pthread_detach (th);
  }
}


/* ----------------------------------------------------------------------------
   pre-connection part
   *** only incoming connections: DCC SEND(p) / CTCP CHAT / .send
   called only from listening thread as result of listener creating attempt */

  /* fields are now:
    .size	offered size (only if DCC SEND / .send)
    .filename	full path (allocated) or NULL if CHAT
    .uh		nick@net
    .token	token (only if DCC SEND / .send) */
static int _dcc_callback(const struct sockaddr *sa, void *data)
{
  register struct dcc_listener_data *dld = data;
  dcc_priv_t *dcc = NULL;
  uint32_t ip_local;			/* my IP in host byte order */
  unsigned short port;
  char t[8];

  if (dld)
    dcc = dld->dcc;
  if (sa == NULL) {
failed:
    if (dcc)
      dcc->state = P_LASTWAIT;		/* for garbage gathering */
    return E_NOSOCKET;
  }
  if (sa->sa_family != AF_INET)		/* only IPv4 is supported! */
    goto failed;
  dcc->ptr = port = ntohs(((struct sockaddr_in *)sa)->sin_port);
  ip_local = ntohl(((struct sockaddr_in *)sa)->sin_addr.s_addr);
  if (dcc->filename == NULL)
    Add_Request(I_CLIENT, dcc->uh, F_T_CTCP, "DCC CHAT chat %u %hu", ip_local,
		port);
  else if (dcc->token)
    Add_Request(I_CLIENT, dcc->uh, F_T_CTCP, "DCC SEND \"%s\" %u %hu %u %u",
		dcc->filename, (unsigned int)ip_local, port,
		(unsigned int)dcc->size, dcc->token);
  else
    Add_Request(I_CLIENT, dcc->uh, F_T_CTCP, "DCC SEND \"%s\" %u %hu %u",
		dcc->filename, (unsigned int)ip_local, port, dcc->size);
  snprintf (t, sizeof(t), "%hu", port); /* setup timeout timer */
  Set_Iface (NULL);
  if (ircdcc_conn_timeout > 0)
    dcc->tid = NewTimer (I_LISTEN, t, S_TIMEOUT, ircdcc_conn_timeout, 0, 0, 0);
  Unset_Iface();
  return (0);
}


/* ----------------------------------------------------------------------------
   between-thread part (called on terminating interface of thread 1)
   *** only DCC SEND and DCC CHAT requests
   attempts to create thread 2 */

  /* support for passive DCC (if port==0 then listen instead)
    >> DCC SEND <filename> <any-ip> 0 <filesize> <token>
    << DCC RESUME <filename> 0 <position> <token>
    >> DCC ACCEPT <filename> 0 <position> <token>
    << DCC SEND <filename> <peer-ip> <port> <filesize> <token>  */
static int _dcc_connect (dcc_priv_t *dcc)
{
  char addr[16];
  unsigned short port;
  uint32_t ip;

  port = dcc->ptr;
  dprint (4, "dcc:_dcc_connect to port %hu.", port);
  dcc->socket = -1;
  dcc->state = P_INITIAL;		/* reset it after _dcc_stage_1() */
  dcc->ahead = ircdcc_ahead_size;	/* we have full access now */
  if (dcc->ahead < 0)			/* correct it if need */
    dcc->ahead = 0;
  else if (dcc->ahead > 16)
    dcc->ahead = 16;
  if (port == 0)			/* it's passive mode! */
  {
    struct dcc_listener_data *dld = safe_malloc(sizeof(struct dcc_listener_data));
    dld->dcc = dcc;
    if (Listen_Port(dcc->iface->name, hostname, port, NULL, dld,
		    &_dcc_callback, &_dcc_pasv_pre, &_dcc_send_phandler))
    {
      ERROR ("request for CTCP SEND from %s (passive): could not open listen port!",
	     dcc->iface->name);
      FREE(&dld);
      return 0;
    }
    return 1;
  }
  dcc->iface = Add_Iface (I_CONNECT, dcc->iface->name, &_dcc_sig_2, NULL, dcc);
  ip = htonl (dcc->rate);
  inet_ntop (AF_INET, &ip, addr, sizeof(addr));
  if (!Connect_Host (addr, port, &dcc->th, &dcc->socket,
		     dcc->filename ? &_dcc_send_handler : &_dcc_chat_handler,
		     dcc))		/* trying to create thread 2 */
  {
    LOG_CONN (_("DCC: Cannot create connection thread to %s."), addr);
    dcc->iface->ift = I_DIED;		/* OOPS, it died instantly */
    dcc->iface->data = NULL;		/* and it cannot own me! */
    return 0;
  }
  return 1;
}


/* ----------------------------------------------------------------------------
   thread 1 - get confirmations for DCC SEND and DCC CHAT
	- .state=P_INITIAL, .ptr=Port, .rate=IP, .uh=nick!user@host
	  .startptr=Startptr, .token=Token
    states here are:
	- P_INITIAL: waiting confirmation
	- P_QUIT: declined to connect
	- P_TALK: accepted to connect
	- P_IDLE: waiting for DCC ACCEPT */

#define dcc ((dcc_priv_t *)input_data)
static void *_dcc_stage_1 (void *input_data)
{
  bool vb;
  char *fname;
  char msg[LONG_STRING];

  if (dcc->filename && (fname = strrchr (dcc->filename, '/')))
    fname++;
  else
    fname = dcc->filename;
  if (fname && dcc->startptr > 1)
    snprintf (msg, sizeof(msg), _("Resume file \"%s\" from %s"), fname,
	      dcc->uh);
  else if (fname)
    snprintf (msg, sizeof(msg), _("Get file \"%s\" from %s"), fname, dcc->uh);
  else
    snprintf (msg, sizeof(msg), _("Accept chat request from %s"), dcc->uh);
  //Set_Iface (NULL);
  if (fname && dcc->startptr > 1)
    vb = ircdcc_do_resume_send;
  else if (fname)
    vb = ircdcc_accept_send;
  else
    vb = ircdcc_accept_chat;
  //Unset_Iface();
  vb = Confirm (msg, vb);
  if (fname && dcc->startptr != 1 &&
      ((dcc->startptr && vb == FALSE) ||	/* declined to resume */
       (!dcc->startptr && vb == TRUE)))		/* asked to get and overwrite */
  {
    snprintf (msg, sizeof(msg), _("Overvrite existing file \"%s\""), fname);
    //Set_Iface (NULL);
    vb = ircdcc_do_overwrite;
    //Unset_Iface();
    vb = Confirm (msg, vb);
    dcc->startptr = 0;
  }
  if (vb == FALSE)			/* declined */
  {
    Set_Iface (NULL);
    dcc->state = P_QUIT;
    dcc->iface->ift |= I_FINWAIT;	/* finished */
    Unset_Iface();
    return ("not confirmed");
  }
  if (fname && dcc->startptr > 1)
  {
    Set_Iface (NULL);
    if (dcc->ptr)			/* active mode */
      Add_Request (I_CLIENT, dcc->iface->name, F_T_CTCP,
		   "DCC RESUME file.ext %hu %lu", (unsigned short)dcc->ptr,
		   (unsigned long)dcc->startptr);
    else
      Add_Request (I_CLIENT, dcc->iface->name, F_T_CTCP,
		   "DCC RESUME file.ext 0 %lu %u",
		   (unsigned long)dcc->startptr, dcc->token);
    dcc->wait_accept = TRUE;		/* let thread know about resume */
    dcc->startptr = 0;
    dcc->state = P_IDLE;		/* interface is still alive! */
    dcc->tid = NewTimer (I_CONNECT, dcc->iface->name, S_TIMEOUT,
			 ircdcc_resume_timeout, 0, 0, 0); /* timeout for ACCEPT */
    Unset_Iface();
    return NULL;
  }
  Set_Iface (NULL);
  dcc->startptr = 0;
  dcc->state = P_TALK;
  dcc->iface->ift |= I_FINWAIT;		/* ask dispatcher to kill thread 1 */
  Unset_Iface();
  return NULL;
}
#undef dcc


/* ----------------------------------------------------------------------------
   thread 1 && between-thread not-thread part (signal handler)
   for DCC CHAT and DCC SEND */

static iftype_t _dcc_sig_1 (INTERFACE *iface, ifsig_t signal)
{
  dcc_priv_t *dcc = iface->data;
  INTERFACE *tmp;
  char msg[MESSAGEMAX];
  char buf[SHORT_STRING];
  char *txt;

  if (!dcc)				/* already killed? */
    return I_DIED;
  switch (signal)
  {
    case S_REPORT:
      if (dcc->state == P_QUIT ||
	  dcc->state == P_LASTWAIT)	/* it's terminating, what to report? */
	break;
      if (dcc->state == P_IDLE)		/* waiting for ACCEPT */
      {
	if ((txt = strrchr (dcc->filename, '/')))
	  txt++;
	else
	  txt = dcc->filename;
	snprintf (buf, sizeof(buf), "getting %s: waiting for DCC ACCEPT", txt);
	txt = buf;
      }
      else				/* waiting for connection */
	txt = "waiting for DCC connection";
      /* %@ - uh, %L - Lname, %P - socket, %* text */
      printl (msg, sizeof(msg), ReportFormat, 0, NULL, dcc->uh, dcc->lname,
	      NULL, (uint32_t)0, dcc->socket + 1, 0, txt);
      tmp = Set_Iface (iface);
      New_Request (tmp, F_REPORT, "%s", msg);
      Unset_Iface();
      break;
    case S_TIMEOUT:
      if (dcc->filename && dcc->state == P_IDLE)
      {
	dcc->state = P_TALK;		/* we got ACCEPT timeout so go next */
	
	return _dcc_sig_1 (iface, S_TERMINATE);		/* to be continued */
      }
      break;
    case S_LOCAL:
      if (dcc->filename && dcc->wait_accept && /* are we waiting for ACCEPT? */
	  dcc->state == P_IDLE && !strncmp (BindResult, "ACCEPT ", 7) &&
	  ((txt = NextWord_Unquoted (NULL, NextWord(BindResult), 0)))[0])
      {
	unsigned long int port, position;

	port = strtoul(txt, (char **)NULL, 10);
	if (dcc->ptr && port != dcc->ptr) {
	  DBG ("irc-ctcp:_dcc_sig_1: ACCEPT port %lu != %u", port, dcc->ptr);
	  break;			/* active mode and another port */
	}
	position = strtoul(txt, NULL, 10);
	port = strtoul(NextWord(txt), NULL, 10);
	if (dcc->ptr == 0 && port != dcc->token)
	{
	  DBG ("irc-ctcp:_dcc_sig_1: ACCEPT token %lu != %u", port, dcc->token);
	  break;			/* passive mode and another token */
	}
	/* don't check filename, mIRC says it is "file.ext" anyway */
	pthread_mutex_lock (&dcc->mutex);
	dcc->startptr = position;
	dcc->wait_accept = FALSE;
	pthread_mutex_unlock (&dcc->mutex);
	LOG_CONN (_("DCC: got ACCEPT, transfer resumed at %u."), dcc->startptr);
	BindResult = NULL;		/* we used it so drop it */
	dcc->state = P_TALK;		/* and we finished stage 1 so go next */
      }
      else
	break;
    case S_TERMINATE:
      KillTimer (dcc->tid);		/* in any case we done with timer */
      if (dcc->th)
      {
	Unset_Iface();			/* unlock dispatcher */
	pthread_cancel (dcc->th);	/* cancel the thread */
	pthread_join (dcc->th, NULL);
	Set_Iface (NULL);		/* restore status quo */
      }
      if (dcc->state != P_TALK ||	/* if we aren't ready to connect */
	  !_dcc_connect (dcc))		/* or failed to create thread 2 */
      {
	FREE (&dcc->filename);
	free_dcc (dcc);
      }
      iface->data = NULL;		/* it's inherited by thread 2 now */
      iface->ift = I_DIED;
      break;
    case S_SHUTDOWN:
      return I_DIED;			/* nothing to do on emergency */
    default:;
  }
  return 0;
}


/* ----------------------------------------------------------------------------
   pre-thread part for DCC CHAT and DCC SEND, creates thread 1 */

static int _dcc_start (dcc_priv_t *dcc, unsigned long ip, unsigned short port,
		       char *tgt, uchar *who, char *lname, unsigned int token)
{
  /* fields are now:
    .size	offered size (only if SEND)
    .startptr	1 if file doesn't exist, or to resume from this size
    .filename	full path (allocated) or NULL if CHAT
    .uh		offered name ("chat" for CHAT)
	we will set:
    .state	P_INITIAL
    .ptr	port #
    .rate	IP #
    .token	token if passive mode
    .uh		nick!user@host (active mode) or nick@net (passive mode)
    .lname	Lname
    .iface	thread interface (I_CONNECT nick@net)
    .th		thread ID
    .mutex	only if SEND */
//  if (Sessions == max_dcc) /* Do we need limit on this? TODO */
//  {
//    /* send notice to current server */
//    Add_Request (I_CLIENT, dcc->iface->name, F_T_CTCR,
//		 _("DCC ERROR Sorry, my limit of DCC is exhausted. Try later, please."));
//    free_dcc (dcc);
//    return 0;
//  }
  dcc->state = P_INITIAL;
  dcc->ptr = port;	/* little trick to know port number while .idx == -1 */
  dcc->rate = ip;
  dcc->token = token;
  if (token)		/* passive mode */
    strfcpy(dcc->uh, tgt, sizeof(dcc->uh));
  else
    strfcpy (dcc->uh, who, sizeof(dcc->uh));
  strfcpy (dcc->lname, NONULL(lname), sizeof(dcc->lname));
  dcc->iface = Add_Iface (I_CONNECT, tgt, &_dcc_sig_1, NULL, dcc);
  dprint (4, "dcc:_dcc_start at port %hu for %s.", port, tgt);
  if (pthread_create (&dcc->th, NULL, &_dcc_stage_1, dcc))
  {
    LOG_CONN (_("DCC: Cannot create thread!"));
    dcc->iface->ift = I_DIED;		/* OOPS, it died instantly */
    dcc->iface->data = NULL;		/* and it cannot own me! */
    free_dcc (dcc);
    return 0;
  }
  return 1;
}

/*
 * ctcp-dcc bindings:
 * int func(INTERFACE *client, uchar *who, char *lname, char *command)
 */
		/* DCC CHAT chat <ip> <port> */
BINDING_TYPE_ctcp_dcc (dcc_chat);
static int dcc_chat (INTERFACE *w, uchar *who, char *lname, char *cw)
{
  dcc_priv_t *dcc = new_dcc();
  unsigned long ip;
  unsigned short port = 0;
  register char *c;

  sscanf (NextWord_Unquoted (dcc->uh, NextWord (cw), sizeof(dcc->uh)),
	  "%lu %hu", &ip, &port);
  if (Find_Iface (I_DIRECT, lname))		/* duplicate chat attempt */
  {
    Unset_Iface();
    New_Request (w, F_T_CTCR, _("DCC ERRMSG No duplicate connections allowed."));
    LOG_CONN ((_("DCC CHAT: Duplicate connection attempt, refused.")));
    free_dcc (dcc);
    return 0;
  }
  dcc->filename = NULL;
  dcc->token = 0;
  c = safe_strchr (who, '!');
  if (c)
    c++;
  {
    char buff[STRING];

    /* %L - lname, %@ - uh, %N - nick@net, %I - IP, %P - port, %* - "chat" */
    printl (buff, sizeof(buff), format_dcc_request, 0, w->name, c, lname, NULL,
	    ip, port, 0, "chat");
    LOG_CONN ("%s", buff);		/* do logging */
  }
  return _dcc_start (dcc, ip, port, w->name, who, lname, 0);
}

// TODO:	/* DCC SCHAT chat <ip> <port> */

		/* DCC SEND <filename> <ip> <port> [<length>] -- actv recv
		   DCC SEND <filename> XXX 0 <length> <token> -- pasv recv
		   DCC SEND <filename> <ip> <port> <length> <token> -- pasv send */
BINDING_TYPE_ctcp_dcc (dcc_send);
static int dcc_send (INTERFACE *w, uchar *who, char *lname, char *cw)
{
  dcc_priv_t *dcc;
  unsigned long ip;
  unsigned long long size = 0;
  unsigned long name_max, path_max;
  unsigned short port = 0;
  unsigned int token = 0;
  int i;
  char *c;
  struct stat st;
  char path[HUGE_STRING];
  register char *cc;

  c = (char *)NextWord (cw);		/* skip "SEND" and it's const really */
  i = sscanf (NextWord_Unquoted (NULL, c, 0), "%lu %hu %llu %u", &ip, &port,
	      &size, &token);		/* parsing everything but file name */
  if (i == 4 && port != 0)		/* passive send not receive */
  {
    INTERFACE *target;
    char *cc;
    uint32_t ad;

    snprintf (path, sizeof(path), "irc-ctcp#%u", token);
    if ((target = Find_Iface (I_TEMP, path)))
    {
      Unset_Iface();			/* free our lock */
      /* check for consistency, they might lie us */
      dcc = target->data;
      if (dcc == NULL)
	return 0;			/* TODO: log it? */
      if (dcc->state != P_DISCONNECTED || dcc->lname[0] || !dcc->filename)
	return 0;			/* it's wrong! */
      if ((cc = strchr (who, '!')))
	*cc = 0;			/* get only nick there */
      snprintf (path, sizeof(path), "%s%s", who, strchr (w->name, '@'));
      if (cc)
	*cc = '!';			/* restore status quo */
      if (strcmp (path, dcc->uh))	/* it was a lie or case wrong */
	return 0;
      ad = htonl (ip);
      inet_ntop (AF_INET, &ad, path, sizeof(path));
      dcc->iface = Add_Iface (I_CONNECT, dcc->uh, &_dcc_sig_2, NULL, dcc);
      dcc->state = P_INITIAL;		/* prepare for _isent_phandler */
      strfcpy (dcc->uh, who, sizeof(dcc->uh));
      if (lname)
	strfcpy (dcc->lname, lname, sizeof(dcc->lname));
      dcc->ptr = port;
      if (!Connect_Host (path, port, &dcc->th, &dcc->socket,
			 &_isend_phandler, dcc)) /* trying to create thread */
      {
	LOG_CONN (_("DCC: Cannot create connection thread to %s."), path);
	dcc->iface->ift = I_DIED;	/* OOPS, it died instantly */
	dcc->iface->data = NULL;	/* and it cannot own me! */
      }
      else
	target->data = NULL;		/* it will be inherited */
      target->ift |= I_FINWAIT;		/* let this interface die */
      return 1;
    }
    return 0;				/* not found! */
  }
  else if (i < 2 || size > ULONG_MAX	/* check parameters */
	   || (i < 4 && port == 0)
	   || (ircdcc_get_maxsize >= 0 &&
	       (unsigned long)size > (uint32_t)ircdcc_get_maxsize))
  {
    Add_Request (I_LOG, "*", F_WARN, "invalid DCC: size %llu is out of range",
		 size);
    return 0;
  }
  if (expand_path (path, ircdcc_dnload_dir, sizeof(path)) != path)
    strfcpy (path, ircdcc_dnload_dir, sizeof(path));
  if (stat (path, &st) < 0)
  {
    ERROR ("DCC: cannot stat download directory %s", path);
    return 1;
  }
  dcc = new_dcc();
  dcc->size = size;
  dcc->wait_accept = FALSE;
  NextWord_Unquoted (dcc->uh, c, sizeof(dcc->uh)); /* use it to extract filename */
  if ((c = strrchr (dcc->uh, '/')))		/* skip subdirs if there are */
    c++;
  else
    c = dcc->uh;
  name_max = pathconf (ircdcc_dnload_dir, _PC_NAME_MAX);
  if (name_max >= HUGE_STRING)
    name_max = HUGE_STRING-1;
  path_max = pathconf (ircdcc_dnload_dir, _PC_PATH_MAX);
  if (path_max >= HUGE_STRING)
    path_max = HUGE_STRING-1;
  if (safe_strlen (c) > name_max)
  {
    char *bg;

    bg = strrchr (c, '.');
    if (bg)
    {
      char *bg2;

      *bg = 0;
      bg2 = strrchr (c, '.');
      *bg = '.';
      if (bg2 && (safe_strlen (c) - (bg2 - c)) < name_max)
	bg = bg2;
    }
    if (bg)
    {
      size_t st = safe_strlen (c) - (bg - c);

      if (st < name_max)
	memmove (c + name_max - st, bg, st);
    }
    else
      bg = &c[name_max];
    if (bg > c)
      bg--;
    *bg = '~';
    c[name_max] = 0;
  }
  strfcat (path, "/", sizeof(path));
  strfcat (path, c, path_max + 1);
  if (ircdcc_resume_min < 256)
    ircdcc_resume_min = 256;
  if (stat (path, &st) < 0)		/* no such file */
    dcc->startptr = 1;
  else if (st.st_size == (off_t)size)	/* full size already */
  {
    free_dcc (dcc);
    Add_Request (I_LOG, "*", F_WARN,
		 "DCC: offered file \"%s\" seems equal to existing, request ignored.",
		 path);
    return 0;
  }
  else if (st.st_size > (off_t)size)	/* it's smaller than our! */
  {
    Add_Request (I_LOG, "*", F_WARN,
		 "DCC: offered size %llu of \"%s\" is less than current, restarting file.",
		 size, path);
    dcc->startptr = 0;
  }
  else if (st.st_size < ircdcc_resume_min) /* small file, redownload */
    dcc->startptr = 0;
  else
    dcc->startptr = size;
  dcc->filename = safe_strdup (path);
  c = safe_strchr (who, '!');
  if (c)
    c++;
  cc = safe_strchr (dcc->filename, '/');
  if (cc)
    cc++;
  else
    cc = dcc->filename;
  /* %L - lname, %@ - uh, %N - nick@net, %I - IP, %P - port, %* - filename */
  printl (path, sizeof(path), format_dcc_request, 0, w->name, c, lname, NULL,
	  ip, port, 0, cc);
  LOG_CONN ("%s", path);		/* do logging */
  return _dcc_start (dcc, ip, port, w->name, who, lname, token);
}

		/* DCC ACCEPT file.ext <port> <ptr> [<token>] */
BINDING_TYPE_ctcp_dcc (dcc_accept);
static int dcc_accept (INTERFACE *w, uchar *who, char *lname, char *cw)
{
  BindResult = cw;
  Send_Signal (I_CONNECT, w->name, S_LOCAL);
  return 1;
}

		/* DCC RESUME <file> <port> <ptr> [<token>] */
BINDING_TYPE_ctcp_dcc (dcc_resume);
static int dcc_resume (INTERFACE *w, uchar *who, char *lname, char *cw)
{
  char target[IFNAMEMAX+1];
  unsigned short port;
  unsigned int token;
  unsigned long long ptr;
  char *c, *cc;
  dcc_priv_t *dcc;

  if (!who || !cw)
    return 0;				/* is that possible? */
  if (sscanf (NextWord_Unquoted (NULL, NextWord (cw), 0), "%hu %llu %u",
      &port, &ptr, &token) < 2)		/* skipping RESUME <file> */
    return 0;				/* bad parameters! */
  if (port == 0) /* it's passive */
  {
    snprintf (target, sizeof (target), "irc-ctcp#%u", token);
    Send_Signal (I_TEMP, target, S_LOCAL); /* send S_LOCAL to irc-ctcp#<token> */
    return 0;
  }
  /* find dcc by <port> and who and check if <ptr> is valid and no dublicate */
  if ((c = strchr (who, '!')))
    *c = 0;				/* get only nick there */
  if ((cc = strchr (w->name, '@')))	/* isn't w->name already target? */
    snprintf (target, sizeof(target), "%s%s", who, cc);
  else					/* is that possible? */
    snprintf (target, sizeof(target), "%s@%s", who, w->name);
  if (c)
    *c = '!';				/* restore status quo */
  for (dcc = ActDCC; dcc; dcc = dcc->next)
    if (dcc->state == P_DISCONNECTED && !strcmp (target, dcc->uh) &&
	dcc->ptr == port)
      break;				/* found! */
  if (!dcc)
    return 0;				/* not found! */
  if (ircdcc_resume_min < 256)
    ircdcc_resume_min = 0;
  if (dcc->startptr != 0 || ptr >= dcc->size || ptr < (unsigned)ircdcc_resume_min)
    return 0;				/* invalid or duplicate request */
  /* reset dcc->startptr with <ptr> and send DCC ACCEPT back */
  dcc->startptr = ptr;
  if (lname)
    strfcpy (dcc->lname, lname, sizeof(dcc->lname));
  New_Request (w, F_T_CTCP, "DCC ACCEPT \"file.ext\" %hu %llu", port, ptr);
  return 1;
}


/*
 * irc-priv-msg-ctcp bindings:
 * int func(INTERFACE *client, uchar *who, char *lname, char *unick, char *msg)
 */
		/* DCC */
BINDING_TYPE_irc_priv_msg_ctcp (ctcp_dcc);
static int ctcp_dcc (INTERFACE *client, unsigned char *who, char *lname,
		     char *unick, char *msg)
{
  userflag uf;
  struct binding_t *bind = NULL;

  dprint (4, "irc-ctcp:ctcp_dcc:got request from \"%s\"", NONULL(lname));
  uf = Get_Clientflags (lname, "");
  while ((bind = Check_Bindtable (BT_IDcc, msg, uf, 0, bind))) /* run bindtable */
  {
    register int i;

    if (!bind->name && (i = bind->func (client, who, lname, msg)) != 0)
      return i;
  }
  New_Request (client, F_T_CTCR, _("DCC ERRMSG Unknown command."));
  return 1;					/* although logging :) */
}

		/* CHAT */
BINDING_TYPE_irc_priv_msg_ctcp (ctcp_chat);
static int ctcp_chat (INTERFACE *client, unsigned char *who, char *lname,
		      char *unick, char *msg)
{
  dcc_priv_t *dcc = new_dcc();
  struct dcc_listener_data *dld;

  if (ircdcc_allow_dcc_chat != TRUE)
  {
//    New_Request (client, F_T_CTCR, _("CHAT Unknown command."));
    return 1;					/* although logging :) */
  }
  /* dcc->state == P_DISCONNECTED */
  dcc->filename = NULL;
  strfcpy (dcc->uh, client->name, sizeof(dcc->uh));
  strfcpy (dcc->lname, lname, sizeof(dcc->lname)); /* report may want it */
  dld = safe_malloc(sizeof(struct dcc_listener_data));
  dld->dcc = dcc;
  /* FIXME: create interface to watch listener */
  if (Listen_Port(lname, hostname, 0, NULL, dld, &_dcc_callback,
		  &_dcc_inc_pre, &chat_handler))
  {
    ERROR ("CTCP CHAT from %s: could not open listen port!", client->name);
    FREE(&dld);
    free_dcc (dcc);
  }
  return 1;
}

BINDING_TYPE_irc_priv_msg_ctcp (ctcp_time);
static int ctcp_time (INTERFACE *client, unsigned char *who, char *lname,
		      char *unick, char *msg)
{
  New_Request (client, F_T_CTCR, "TIME %s", ctime (&Time));
  return 1;
}

BINDING_TYPE_irc_priv_msg_ctcp (ctcp_ping);
static int ctcp_ping (INTERFACE *client, unsigned char *who, char *lname,
		      char *unick, char *msg)
{
  New_Request (client, F_T_CTCR, "PING %s", msg);
  return 1;
}

BINDING_TYPE_irc_priv_msg_ctcp (ctcp_version);
static int ctcp_version (INTERFACE *client, unsigned char *who, char *lname,
			 char *unick, char *msg)
{
  New_Request (client, F_T_CTCR, "VERSION " PACKAGE " " VERSION ".");
  return 1;
}

BINDING_TYPE_irc_priv_msg_ctcp (ctcp_help);
static int ctcp_help (INTERFACE *client, unsigned char *who, char *lname,
		      char *unick, char *msg)
{
  char *c;
  struct clrec_t *u;
  userflag uf, cf;

  StrTrim (msg);			/* is it really wise? :) */
  if (msg && !*msg)
    msg = NULL;				/* no args */
  dprint (4, "got CTCP HELP %s", NONULL(msg));
  c = strrchr (client->name, '@');	/* trying to get network name */
  if (c)				/* will use global + network flags */
    c++;
  if ((u = Lock_Clientrecord (lname)))
  {
    uf = Get_Flags (u, NULL) | Get_Flags (u, c);
    cf = Get_Flags (u, "");		/* see "irc-priv-msg-ctcp" table */
    Unlock_Clientrecord (u);
  }
  else
    uf = cf = 0;
  Get_Help (msg, NULL, client, uf, cf, BT_Cctcp, NULL, 1);
  return 1;
}

/* we are waiting for dcc send in passive mode, no thread yet ("irc-ctcp#%u") */
static iftype_t _isend_sig_w (INTERFACE *iface, ifsig_t signal)
{
  dcc_priv_t *dcc = iface->data;
  unsigned long long size;
  unsigned int token;

  if (!dcc)
    return I_DIED;
  switch (signal)
  {
    case S_LOCAL:			/* got DCC RESUME here? */
      if (dcc->startptr == 0 && !safe_strncmp (BindResult, "RESUME ", 7))
      {
	size = 0;
	token = 0;
	sscanf (NextWord_Unquoted (NULL, &BindResult[7], 0), "%*s %llu %u",
		&size, &token);
	if (size >= dcc->size) {	/* request is invalid */
	  DBG ("irc-ctcp:_isend_sig_w: RESUME invalid position %llu > %u",
	       size, dcc->size);
	  break;			/* so ignore it */
	} else if (token != dcc->token) { /* wrong token */
	  DBG ("irc-ctcp:_isend_sig_w: RESUME token %u != %u", token,
	       dcc->token);
	  break;
	}
	dcc->startptr = size;		/* else setting pointer */
	Add_Request (I_CLIENT, dcc->uh, F_T_CTCP, "DCC ACCEPT file.ext 0 %llu %u",
		     size, token);
      }
      break;
    case S_TIMEOUT:			/* time is out so terminate */
      LOG_CONN (_("Connection timeout on sending %s."), NONULL(dcc->filename));
    case S_TERMINATE:			/* terminating */
      FREE (&dcc->filename);
      KillTimer (dcc->tid);
      free_dcc (dcc);
    case S_SHUTDOWN:
      iface->ift = I_DIED;
    default: ;
  }
  return 0;
}

static unsigned int _ircdcc_dccid = 0;	/* unique token for passive sends */

		/* .send [-passive] [-flush] target [path/]file */
/* note: target is case sensitive parameter or else resume will be not available */
BINDING_TYPE_ss_(ssirc_send);
static int ssirc_send (struct peer_t *peer, INTERFACE *w, char *args)
{
  char *c, *cc;
  int passive = 0, noresume = 0;
  char *net;
  dcc_priv_t *dcc;
  unsigned short port = 0;
  struct stat sb;
  char target[IFNAMEMAX+1];

  /* check params */
  if (!args || !strchr (args, ' '))
    return 0;				/* should be at least 2 parameters */
  if (!(ircdcc_allow_resume & TRUE))
    noresume = 1;
  while (args[0] == '-')		/* parse modifiers */
  {
    c = gettoken (++args, &cc);
    if (!strcmp (args, "passive"))
      passive = 1;
    else if (!strcmp (args, "flush"))
      noresume = 1;
    else
      New_Request (peer->iface, 0, _("Unknown modifier -%s ignored!"), args);
    *cc = ' ';
    args = c;
  }
  c = gettoken (args, &cc);		/* c=file, args=target, cc=space */
  if (stat (c, &sb) < 0)		/* it's inaccessible */
  {
    if (errno == ENOENT)
      New_Request (peer->iface, 0, _("File %s does not exist."), c);
    else
      New_Request (peer->iface, 0, _("File access error."));
    *cc = ' ';
    return 1;
  }
  else if (sb.st_size > (off_t)ULONG_MAX)
  {
    New_Request (peer->iface, 0, _("File %s is too big."), c);
    *cc = ' ';
    return 1;
  }
  if ((net = strrchr (w->name, '@')))
    net++;
  else
    net = w->name;
  /* all parameters are OK, it's time to make request and start thread */
  dcc = new_dcc();
  dcc->size = sb.st_size;
  dcc->ahead = ircdcc_ahead_size;	/* set some defaults */
  dcc->startptr = noresume;
  if (dcc->ahead < 0)			/* correct it if need */
    dcc->ahead = 0;
  else if (dcc->ahead > 16)
    dcc->ahead = 16;
  dcc->lname[0] = 0;			/* thread signal handler need those */
  dcc->filename = safe_strdup (c);
  dcc->iface = NULL;
  snprintf (dcc->uh, sizeof(dcc->uh), "%s@%s", args, net); /* target@net */
  if ((net = strrchr (c, '/')))
    net++;				/* filename to tell */
  else
    net = c;
  if (passive)
  {
    register uint32_t ip_local = 0x7f000001; /* 127.0.0.1 - it's irrelevant */
    if (_ircdcc_dccid == 0)		/* token 0 used as indicator */
      _ircdcc_dccid = 1;
    dcc->token = _ircdcc_dccid;
    Add_Request (I_CLIENT, dcc->uh, F_T_CTCP, "DCC SEND \"%s\" %u 0 %u %u",
		 net, ip_local, dcc->size, _ircdcc_dccid);
    snprintf (target, sizeof(target), "irc-ctcp#%u", _ircdcc_dccid++);
    dcc->iface = Add_Iface (I_TEMP, target, &_isend_sig_w, NULL, dcc);
    dcc->tid = NewTimer (I_TEMP, target, S_TIMEOUT, ircdcc_conn_timeout, 0, 0, 0);
    /* done... we should wait for responce now so we can connect there */
  } else {
    struct dcc_listener_data *dld = safe_malloc(sizeof(struct dcc_listener_data));
    dld->dcc = dcc;
    dcc->token = 0;
    if (Listen_Port(c, hostname, port, NULL, dld, &_dcc_callback,
		    &_dcc_inc_pre, &isend_handler))
    {
      ERROR ("sending to %s: could not open listening port!", args);
      FREE(&dld);
      FREE(&dcc->filename);
      free_dcc (dcc);
    }
  }
  *cc = ' ';
  return 1;
}


static void _irc_ctcp_register (void)
{
  Add_Request (I_INIT, "*", F_REPORT, "module irc-ctcp");
  RegisterInteger ("dcc-ahead", &ircdcc_ahead_size);
  RegisterInteger ("dcc-connection-timeout", &ircdcc_conn_timeout);
  RegisterInteger ("dcc-resume-timeout", &ircdcc_resume_timeout);
  RegisterInteger ("dcc-resume-min", &ircdcc_resume_min);
  RegisterInteger ("dcc-get-maxsize", &ircdcc_get_maxsize);
  RegisterInteger ("dcc-blocksize", &ircdcc_blocksize);
  RegisterBoolean ("dcc-allow-ctcp-chat", &ircdcc_allow_dcc_chat);
  RegisterBoolean ("dcc-resume", &ircdcc_do_resume_send);
  RegisterBoolean ("dcc-get", &ircdcc_accept_send);
  RegisterBoolean ("dcc-accept-chat", &ircdcc_accept_chat);
  RegisterBoolean ("dcc-get-overwrite", &ircdcc_do_overwrite);
  RegisterBoolean ("dcc-allow-resume", &ircdcc_allow_resume);
  RegisterString ("incoming-path", ircdcc_dnload_dir, sizeof(ircdcc_dnload_dir), 0);
}

/*
 * this function must receive signals:
 *  S_TERMINATE - unload module,
 *  S_REG - reregister all for config,
 *  S_REPORT - out state info to log.
 */
static iftype_t irc_ctcp_mod_sig (INTERFACE *iface, ifsig_t sig)
{
  INTERFACE *tmp;
  dcc_priv_t *dcc;
  char *state;
  char *filename;

  switch (sig)
  {
    case S_REPORT:
      tmp = Set_Iface (iface);
      New_Request (tmp, F_REPORT, "Module irc-ctcp:%s",
		   ActDCC ? "" : " no active connections.");
      for (dcc = ActDCC; dcc; dcc = dcc->next) {
	if (dcc->state == P_LASTWAIT)
	  continue;
	switch (dcc->state) {
	case P_TALK:
	  state = "active";
	  break;
	case P_INITIAL:
	case P_IDLE:
	  state = "waiting";
	  break;
	default:
	  state = "disconnected";
	}
	if (!dcc->filename)
	  filename = "";
	else if ((filename = strrchr(dcc->filename, '/')))
	  filename++;
	else
	  filename = dcc->filename;
	New_Request(tmp, F_REPORT, "    (%s) %s%s: %s", dcc->iface->name,
		    dcc->filename ? "file " : "chat", filename, state);
      }
      Unset_Iface();
      break;
    case S_REG:
      _irc_ctcp_register();
      break;
    case S_TERMINATE:
      Delete_Binding ("ctcp-dcc", &dcc_chat, NULL);
      Delete_Binding ("ctcp-dcc", &dcc_send, NULL);
      Delete_Binding ("ctcp-dcc", &dcc_accept, NULL);
      Delete_Binding ("ctcp-dcc", &dcc_resume, NULL);
      Delete_Binding ("irc-priv-msg-ctcp", &ctcp_dcc, NULL);
      Delete_Binding ("irc-priv-msg-ctcp", &ctcp_chat, NULL);
      Delete_Binding ("irc-priv-msg-ctcp", &ctcp_time, NULL);
      Delete_Binding ("irc-priv-msg-ctcp", &ctcp_ping, NULL);
      Delete_Binding ("irc-priv-msg-ctcp", &ctcp_version, NULL);
      Delete_Binding ("irc-priv-msg-ctcp", &ctcp_help, NULL);
      Delete_Binding ("ss-irc", &ssirc_send, NULL);
      UnregisterVariable ("dcc-ahead");
      UnregisterVariable ("dcc-connection-timeout");
      UnregisterVariable ("dcc-resume-timeout");
      UnregisterVariable ("dcc-resume-min");
      UnregisterVariable ("dcc-get-maxsize");
      UnregisterVariable ("dcc-blocksize");
      UnregisterVariable ("dcc-allow-ctcp-chat");
      UnregisterVariable ("dcc-resume");
      UnregisterVariable ("dcc-get");
      UnregisterVariable ("dcc-accept-chat");
      UnregisterVariable ("dcc-get-overwrite");
      UnregisterVariable ("dcc-allow-resume");
      UnregisterVariable ("incoming-path");
      while (ActDCC)
	if (ActDCC->state == P_DISCONNECTED)	/* it's just listener */
	{
	  CloseSocket (ActDCC->socket);
	  KillTimer (ActDCC->tid);
	  free_dcc (ActDCC);
	}
	else if (ActDCC->iface && ActDCC->iface->IFSignal)
	{
	  INTERFACE *ifa = ActDCC->iface;
	  ifa->ift |= ifa->IFSignal (ifa, sig);
	}
      Delete_Help ("irc-ctcp");
      _forget_(dcc_priv_t);
      iface->ift |= I_DIED;
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
  /* add own bindtables */
  BT_IDcc = Add_Bindtable ("ctcp-dcc", B_MATCHCASE);
  Add_Binding ("ctcp-dcc", "CHAT", U_ACCESS, 0, &dcc_chat, NULL);
  Add_Binding ("ctcp-dcc", "SEND", 0, 0, &dcc_send, NULL);
  Add_Binding ("ctcp-dcc", "ACCEPT", 0, 0, &dcc_accept, NULL);
  Add_Binding ("ctcp-dcc", "RESUME", 0, 0, &dcc_resume, NULL);
  BT_Login = Add_Bindtable ("login", B_UNDEF); /* foreign! */
  BT_Dnload = Add_Bindtable ("dcc-got", B_MASK);
  BT_Upload = Add_Bindtable ("dcc-sent", B_MASK);
  BT_Cctcp = Add_Bindtable ("irc-priv-msg-ctcp", B_UNDEF); /* foreign! */
  Add_Binding ("irc-priv-msg-ctcp", "DCC", 0, 0, &ctcp_dcc, NULL);
  Add_Binding ("irc-priv-msg-ctcp", "CHAT", U_NONE, U_ACCESS, &ctcp_chat, NULL);
  Add_Binding ("irc-priv-msg-ctcp", "TIME", 0, 0, &ctcp_time, NULL);
  Add_Binding ("irc-priv-msg-ctcp", "PING", 0, 0, &ctcp_ping, NULL);
  Add_Binding ("irc-priv-msg-ctcp", "VERSION", 0, 0, &ctcp_version, NULL);
  Add_Binding ("irc-priv-msg-ctcp", "HELP", 0, 0, &ctcp_help, NULL);
  Add_Binding ("irc-priv-msg-ctcp", "CLIENTINFO", 0, 0, &ctcp_help, NULL);
  Add_Binding ("ss-irc", "send", 0, 0, &ssirc_send, NULL);
  /* register our variables */
  Add_Help ("irc-ctcp");
  _irc_ctcp_register();
  format_dcc_gotfile = SetFormat ("dcc_got_file",
				  _("DCC GET of %* from %N completed."));
  format_dcc_sentfile = SetFormat ("dcc_sent_file",
				   _("DCC SEND of %* to %N completed."));
  format_dcc_startget = SetFormat ("dcc_get_started",
				  _("DCC GET of %* from %N established."));
  format_dcc_request = SetFormat ("dcc_request",
				  _("DCC connection request for \"%*\" from %N(%@) to %I:%P"));
  return (&irc_ctcp_mod_sig);
}
