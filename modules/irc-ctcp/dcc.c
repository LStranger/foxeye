/*
 * Copyright (C) 2006-2010  Andriy N. Gritsenko <andrej@rep.kiev.ua>
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
#include <netdb.h>

#include "modules.h"
#include "direct.h"
#include "init.h"
#include "socket.h"
#include "sheduler.h"
#include "list.h"

#define MAXBLOCKSIZE	16384

typedef struct dcc_priv_t
{
  struct dcc_priv_t *next;		/* R/O in thread */
  INTERFACE *iface;			/* undefined in P_DISCONNECTED state */
  char *filename;			/* R/O in thread */
  uint32_t size;			/* R/O on thread, file size */
  uint32_t ptr, startptr;		/* size got, start pointers */
  uint32_t rate;			/* average (16s) filetransfer speed */
  long int ahead;			/* R/O local value of ahead parameter */
  idx_t socket;				/* owned by thread, inherited later */
  pthread_t th;				/* undefined in P_DISCONNECTED state */
  pthread_mutex_t mutex;		/* for ->ptr ... ->rate */
  _peer_state state;			/* locked by dispatcher */
  char lname[LNAMELEN+1];		/* R/O in thread */
  char buf[LONG_STRING];
} dcc_priv_t;

static dcc_priv_t *ActDCC = NULL;	/* chain of active sessions */

static bindtable_t *BT_IDcc;		/* "ctcp-dcc" : CTCP DCC bindings */
static bindtable_t *BT_Login;		/* "login" bindtable from Core */
static bindtable_t *BT_Dnload;		/* "dcc-got" : received a file */
static bindtable_t *BT_Cctcp;		/* a bindtable from module "irc" */


static long int ircdcc_ahead_size = 0;	/* "turbo" mode to speed up transfer */
static long int ircdcc_resume_timeout = 30;
static long int ircdcc_resume_min = 10000;
static long int ircdcc_get_maxsize = 1000000000;
static bool ircdcc_allow_dcc_chat = TRUE;
static bool ircdcc_do_resume_send = (CAN_ASK | TRUE);	/* yes */
static bool ircdcc_accept_send = (CAN_ASK | TRUE);	/* yes */
static bool ircdcc_accept_chat = (CAN_ASK | ASK | TRUE);/* ask-yes */
static bool ircdcc_do_overwrite = (CAN_ASK | FALSE);	/* no */
static char ircdcc_dnload_dir[LONG_STRING] = "~/.foxeye/files";

static char *format_dcc_gotfile;

#undef ALLOCSIZE
#define ALLOCSIZE 2
ALLOCATABLE_TYPE (dcc_priv_t, DCC, next) /* alloc_dcc_priv_t(), free_dcc_priv_t() */

/* has no locks so non-thread calls only! */
static dcc_priv_t *new_dcc (void)
{
  dcc_priv_t *dcc, *last;

  dcc = alloc_dcc_priv_t();
  dcc->next = NULL;
  dcc->state = P_DISCONNECTED;
  dcc->socket = -1;
  if (ActDCC)
  {
    for (last = ActDCC; last->next; last = last->next);
    last->next = dcc;
  }
  else
    ActDCC = dcc;
  return dcc;
}

static void free_dcc (dcc_priv_t *dcc)
{
  register dcc_priv_t *last;
  if (dcc == ActDCC)
    ActDCC = dcc->next;
  else
  {
    for (last = ActDCC; last && last->next != dcc; last = last->next);
    if (last)
      last->next = dcc->next;
  }
  free_dcc_priv_t (dcc);
}

static inline dcc_priv_t *_dcc_find_socket (idx_t socket)
{
  register dcc_priv_t *dcc;

  for (dcc = ActDCC; dcc; dcc = dcc->next)
    if (dcc->socket == socket)
      return dcc;
  return NULL;
}

#define LOG_CONN(a...) Add_Request (I_LOG, "*", F_CONN, ##a)

/* sequence (m - dispathcer's thread, 1...3 - new threads):
    m	got DCC CHAT or DCC SEND or CTCP CHAT (last one skips thread 1 part)
    1	check for UI confirmation
    1	got confirmation
    1		need to be resumed? ask to resume confirmation
    1		got confirmation? send DCC RESUME and finish with state=P_OFFER
    m	got DCC ACCEPT? remap pointer and continue with I_FINWAIT
    m	got timeout? don't wait for DCC ACCEPT anymore
    m	kill thread 1 and if state!=P_LASTWAIT then start connection
    2	got connected, start main interface (_dcc_X_handler())
    2	terminate thread and socket when done
    m	join thread 2 and finish all */

/* ----------------------------------------------------------------------------
   thread 2 non-thread part (signal handler) */

/* when: before connection, in connection, on finishing stage 2 */
static iftype_t _dcc_sig_2 (INTERFACE *iface, ifsig_t signal)
{
  dcc_priv_t *dcc = iface->data;
//  INTERFACE *tmp;
  char *msg;

  if (!dcc)				/* already killed? */
    return I_DIED;
  switch (signal)
  {
    case S_REPORT:
      if (dcc->state == P_LASTWAIT)	/* it's terminating, what to report? */
	break;
      //TODO: report.......
      //tmp = Set_Iface (iface);
      //New_Request (tmp, F_REPORT, "%s", msg);
      //Unset_Iface();
      break;
    case S_LOCAL:
      if (dcc->filename && !strncmp (BindResult, "ACCEPT ", 7))
      {
	unsigned short port, port2;

	port = atoi ((msg = NextWord_Unquoted (NULL, NextWord(BindResult), 0)));
	if (dcc->state == P_INITIAL)
	{
	  if (dcc->ptr != port)	/* before we got .idx we have port in .ptr */
	  {
	    DBG ("irc-ctcp:_dcc_sig_2: ACCEPT for %hu != %u", port, dcc->ptr);
	    break;
	  }
	}
	else
	{
	  SocketDomain (dcc->socket, &port2);
	  if (port != port2)	/* check for ports in ACCEPT message */
	  {
	    DBG ("irc-ctcp:_dcc_sig_2: ACCEPT for %hu != %hu", port, port2);
	    break;
	  }
	}
	pthread_mutex_lock (&dcc->mutex);
	if (dcc->startptr)
	{
	  pthread_mutex_unlock (&dcc->mutex);
	  Add_Request (I_LOG, "*", F_WARN,
		       _("DCC GET: got duplicate or late ACCEPT, ignoring it."));
	  break;
	}
	dcc->startptr = strtoul (NextWord (msg), NULL, 10);
	pthread_mutex_unlock (&dcc->mutex);
	LOG_CONN (_("DCC: got ACCEPT, transfer resumed at %lu."), dcc->startptr);
      }
      break;
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
      if (dcc->filename)		/* free dcc_priv_t fields */
	pthread_mutex_destroy (&dcc->mutex);
      FREE (&dcc->filename);
      free_dcc (dcc);
      iface->data = NULL;		/* dispatcher should not unalloc it */
      iface->ift = I_DIED;
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

static void dcc_handler (char *lname, char *ident, char *host, idx_t socket)
{
  char buf[SHORT_STRING];
  userflag uf;
  binding_t *bind;
  size_t sz, sp;
//  ssize_t get = 0;
  char *msg;
  dcc_priv_t *dcc;

  /* check for allowance */
  uf = Match_Client (host, ident, lname);
  Set_Iface (NULL);
  dcc = _dcc_find_socket (socket);
  bind = Check_Bindtable (BT_Login, "*", uf, 0, NULL);
  msg = NULL;
  if (bind && !bind->name) /* allowed to logon */
  {
    strcpy (buf, "+");					/* it's not telnet */
    bind->func (lname, ident, host, socket, buf, &msg); /* it will unlock dispatcher */
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
	    NULL, host, lname, NULL, 0, p, 0, msg);
    Unset_Iface();
    /* cannot create connection */
    LOG_CONN ("%s", buf);
    KillSocket (&socket);
  }
  if (dcc)
    dcc->socket = -1;			/* socket might be inherited by login */
  else
  {
    ERROR ("DCC CHAT: connection with %s(%s@%s) not found, forgetting thread.",
	   lname, ident, host);
    return;
  }
  Set_Iface (NULL);		/* ask dispatcher to kill thread 2 */
  dcc->iface->ift |= I_FINWAIT; /* all rest will be done by _dcc_sig_2() */
  Unset_Iface();
}

/* thread 2 (incoming connection) */

/* connected for CTCP CHAT, fields (if dcc is found) are now:
    .filename	NULL
    .state	P_DISCONNECTED
    .socket	listening socket id
    .buf	nick@net */
static void _dcc_chat_pre (pthread_t th, idx_t ls, idx_t as)
{
  dcc_priv_t *dcc;

  Set_Iface (NULL);
  if (as == -1)				/* listener terminated */
  {
    if ((dcc = _dcc_find_socket (ls)))
      free_dcc (dcc);
    /* TODO: it would be nice to write some debug but aren't we in SIGSEGV? */
  }
  else if ((dcc = _dcc_find_socket (ls)))
  {
    dcc->th = th;
    dcc->socket = as;
    dcc->iface = Add_Iface (I_CONNECT, dcc->buf, &_dcc_sig_2, NULL, dcc);
    dcc->state = P_INITIAL;		/* and now listener can die free */
  }
  else					/* is answered to unknown socket? */
  {
    ERROR ("DCC CHAT: socket %d not found, shutdown thread.", (int)ls);
    CloseSocket (as);			/* module may be already terminated */
    pthread_detach (th);
  }
  Unset_Iface();
}

/* thread 2 (outgoing connection, i.e. answer to DCC CHAT and DCC SEND) */

#define dcc ((dcc_priv_t *) input_data)
/* connected for DCC CHAT, fields are now:
    .filename	NULL
    .ahead	ircdcc_ahead_size
    .state	P_INITIAL
    .buf	nick!user@host
    .rate	IP #
    .lname	Lname
    .iface	thread interface (I_CONNECT nick@net)
    .socket	socket ID
    .th		thread ID */
static void _dcc_chat_handler (int res, void *input_data)
{
  register char *host = safe_strchr (dcc->buf, '@');
  register char *ident = safe_strchr (dcc->buf, '!');

  if (host)
    *host++ = 0;
  if (ident)
    ident++;
  if (res == 0)
    dcc_handler (dcc->lname, ident, host, dcc->socket);
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

/* connected for DCC SEND, fields are now:
    .size	offered size
    .ptr	0 if no resume, any other if we may want resume
    .filename	full path (allocated)
    .ahead	ircdcc_ahead_size
    .state	P_INITIAL
    .buf	nick!user@host
    .rate	IP #
    .lname	Lname
    .startptr	0 or resume ptr (may be changed later)
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
  ssize_t bs, sw;		/* gotten block size, temp var */
  int want_resume, ahead;	/* flag, current ahead size */
  time_t t, t2;
  size_t statistics[16];	/* to calculate average speed */
  FILE *f, *rf;			/* opened file */
  void *buff;
  char *c, *sfn;

  pthread_mutex_lock (&dcc->mutex);		/* prepare to work */
  if (!dcc->startptr)
    want_resume = dcc->ptr;
  else
    want_resume = 0;
  dcc->ptr = 0;
  ip = dcc->rate;
  dcc->rate = 0;
  pthread_mutex_unlock (&dcc->mutex);
  Set_Iface (NULL);
  dcc->state = P_TALK;
  Unset_Iface();
  ptr = 0;
  bs = 0;
  ahead = 0;
  time (&t);
  memset (statistics, 0, sizeof(statistics));
  if (want_resume)		/* if waiting for ACCEPT then open temp file */
    f = tmpfile();
  else if ((f = fopen (dcc->filename, "ab")))	/* else open real file */
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
#define sizeofbuff 16384			/* i think, it is enough */
  buff = safe_malloc (sizeofbuff);
  FOREVER					/* cycle to get file */
  {
    pthread_mutex_lock (&dcc->mutex);
    dcc->ptr = ptr;
    time (&t2);
    if (t != t2)
    {
      for (sw = 0, nptr = 0; nptr < 16; nptr++)	/* use nptr as temp */
	sw += statistics[nptr];
      dcc->rate = sw/16;
      statistics[t2%16] = 0;
      t = t2;
    }
    nptr = dcc->size - dcc->startptr;		/* to get: for use below */
    pthread_mutex_unlock (&dcc->mutex);
    sw = ReadSocket (buff, dcc->socket, sizeofbuff, M_RAW); /* next block */
    if (sw > 0)
      bs = fwrite (buff, 1, sw, f);
    if (!sw || sw == E_AGAIN)			/* try again */
    {
      // TODO: we have to try ahead now?
      continue;
    }
    else if (sw < 0)				/* error happened */
      break;
    ptr += bs;
    statistics[t%16] += bs;
    if (sw != bs)				/* file writing error */
      break;
    if (ptr >= nptr)				/* we got all we want */
      break;
    // TODO: we have to try ahead now?
    nptr = htonl (ptr);
    bs = 0;
    sw = sizeof(nptr);
    while (sw)					/* send network-ordered ptr */
      if (WriteSocket (dcc->socket, (char *)&nptr, &bs, &sw, M_POLL) < 0)
	break;					/* if socket died */
  }
  pthread_mutex_lock (&dcc->mutex);
  if (want_resume && dcc->startptr)
  {
    // if want_resume and got startptr then move file chunk to real file
    pthread_mutex_unlock (&dcc->mutex);
    if (!(rf = fopen (dcc->filename, "ab")))
      ERROR ("DCC GET: cannot append to local file after resume.");
    else
    {
      fseek (rf, dcc->startptr, SEEK_SET);
      fseek (f, 0L, SEEK_SET);
      while ((sw = fread (buff, 1, sizeofbuff, f)) > 0)
	fwrite (buff, 1, sw, rf);
      fclose (rf);			/* TODO: check for errors here? */
    }
    pthread_mutex_lock (&dcc->mutex);
  }
  c = safe_strchr (dcc->buf, '!');	/* split nick and user@host in buf */
  if (c)
    *c++ = 0;
  sfn = strrchr (dcc->filename, '/');		/* get short filename */
  if (sfn)
    sfn++;
  else
    sfn = dcc->filename;
  if (ptr > dcc->size)				/* file is bigger than offered */
    snprintf (buff, sizeofbuff,
	      _("Got file \"%s\" from %s: %lu bytes instead of %lu."), sfn,
	      dcc->buf, (unsigned long)ptr, (unsigned long)dcc->size);
  else if (ptr != dcc->size)			/* incomplete file! */
    snprintf (buff, sizeofbuff,
	      _("Got incomplete file \"%s\" from %s: %lu/%lu bytes."), sfn,
	      dcc->buf, (unsigned long)ptr, (unsigned long)dcc->size);
  else
  {
    /* %L - lname, %@ - host, %N - nick, %I - IP, %* - filename(unquoted) */
    Set_Iface (NULL);
    printl (buff, sizeofbuff, format_dcc_gotfile, 0, dcc->buf, c, dcc->lname,
	    NULL, ip, 0, 0, sfn);
    Unset_Iface();
  }
  LOG_CONN (buff);				/* do logging */
  KillSocket (&dcc->socket);			/* close/unallocate all */
  fclose (f);
  safe_free (&buff);
#undef sizeofbuff
  if (ptr == dcc->size)				/* successfully downloaded */
  {
    binding_t *bind = NULL;
    userflag uf = Get_Clientflags (dcc->lname, NULL);

    if (sfn == dcc->filename)
      sfn = NULL;
    /* TODO: check if filepath is default */
    do
    {
      if ((bind = Check_Bindtable (BT_Dnload, dcc->lname, uf, -1, bind)))
      {
	if (bind->name)
	{
	  if (sfn) *sfn = 0;
	  RunBinding (bind, NULL, dcc->lname, dcc->buf, -1,
		      sfn ? dcc->filename : ".");
	  if (sfn) *sfn = '/';
	}
	else
	  bind->func (dcc->buf, dcc->filename);
      }
    } while (bind);
  }
  Set_Iface (NULL);
  dcc->iface->ift |= I_FINWAIT; /* all rest will be done by _dcc_sig_2() */
  Unset_Iface();
}
#undef dcc


/* ----------------------------------------------------------------------------
   between-thread part (called on terminating interface of thread 1)
   attempts to create thread 2 */

static int _dcc_connect (dcc_priv_t *dcc)
{
  char addr[16];
  unsigned short port;

  snprintf (addr, sizeof(addr), "%u.%u.%u.%u", (unsigned int) (dcc->rate>>24),
	    (unsigned int) (dcc->rate>>16)%256,
	    (unsigned int) (dcc->rate>>8)%256, (unsigned int) (dcc->rate%256));
  /* %N - nick, %@ - ident@host,  */
//  printl (dcc->buf, sizeof(dcc->buf), format_dcc_request, 0, nick, uh, dcc->lname,
//	  strchr (dcc->iface->name, '@'), dcc->rate, dcc->transf, 0, dcc->filename);
//LOG_CONN ("%s", dcc->buf);
//  if (Sessions == max_dcc)
//  {
//    /* send notice to current server */
//    Add_Request (I_CLIENT, dcc->iface->name, F_T_CTCR,
//		 _("DCC ERROR Sorry, my limit of DCC is exhausted. Try later, please."));
//    return 0;
//  }
  port = dcc->ahead;
  if (dcc->ptr)
    dcc->ptr = port;	/* little trick to know port number while .idx == -1 */
  dcc->socket = -1;
  dcc->state = P_INITIAL;		/* reset it after _dcc_stage_1() */
  dcc->ahead = ircdcc_ahead_size;	/* we have full access now */
  dcc->iface = Add_Iface (I_CONNECT, dcc->iface->name, &_dcc_sig_2, NULL, dcc);
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
	- .state=P_INITIAL, .ahead=Port, .rate=IP, .buf=nick!user@host
	- note that .buf may be rewritten here on error
    states here are:
	- P_INITIAL: waiting confirmation
	- P_LASTWAIT: declined to connect
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
  if (fname && dcc->ptr && dcc->ptr < dcc->size)
    snprintf (msg, sizeof(msg), _("Resume file \"%s\" from %s"), fname,
	      dcc->buf);
  else if (fname)
    snprintf (msg, sizeof(msg), _("Get file \"%s\" from %s"), fname, dcc->buf);
  else
    snprintf (msg, sizeof(msg), _("Accept chat request from %s"), dcc->buf);
  Set_Iface (NULL);
  if (fname && dcc->ptr && dcc->ptr < dcc->size)
    vb = ircdcc_do_resume_send;
  else if (fname)
    vb = ircdcc_accept_send;
  else
    vb = ircdcc_accept_chat;
  Unset_Iface();
  vb = Confirm (msg, vb);
  if (fname && dcc->ptr &&
      ((dcc->ptr < dcc->size && vb == FALSE) || /* ask to resume or overwrite */
       (dcc->ptr >= dcc->size && vb == TRUE))) /* ask to get and overwrite */
  {
    snprintf (msg, sizeof(msg), _("Overvrite existing file \"%s\""), fname);
    Set_Iface (NULL);
    vb = ircdcc_do_overwrite;
    Unset_Iface();
    vb = Confirm (msg, vb);
    dcc->ptr = 0;
  }
  if (vb == FALSE)			/* declined */
  {
    Set_Iface (NULL);
    dcc->state = P_LASTWAIT;
    dcc->iface->ift |= I_FINWAIT;	/* finished */
    Unset_Iface();
    return ("not confirmed");
  }
  if (fname && dcc->ptr)
  {
    Add_Request (I_CLIENT, dcc->iface->name, F_T_CTCP,
		 "DCC RESUME file.ext %hu %lu", (unsigned short)dcc->ahead,
		 (unsigned long)dcc->ptr);
    Set_Iface (NULL);
    dcc->state = P_IDLE;		/* interface is still alive! */
    Unset_Iface();
    NewTimer (I_CONNECT, dcc->iface->name, S_TIMEOUT, ircdcc_resume_timeout,
	      0, 0, 0);			/* setup timeout for ACCEPT */
    return NULL;
  }
  Set_Iface (NULL);
  dcc->state = P_TALK;
  dcc->iface->ift |= I_FINWAIT;		/* ask dispatcher to kill thread 1 */
  Unset_Iface();
  return NULL;
}
#undef dcc


/* ----------------------------------------------------------------------------
   thread 1 && between-thread not-thread part (signal handler) */

static iftype_t _dcc_sig_1 (INTERFACE *iface, ifsig_t signal)
{
  dcc_priv_t *dcc = iface->data;
//  INTERFACE *tmp;
  char *msg;

  if (!dcc)				/* already killed? */
    return I_DIED;
  switch (signal)
  {
    case S_REPORT:
      if (dcc->state == P_LASTWAIT)	/* it's terminating, what to report? */
	break;
      //TODO .......
      //tmp = Set_Iface (iface);
      //New_Request (tmp, F_REPORT, "%s", msg);
      //Unset_Iface();
      break;
    case S_TIMEOUT:
      if (dcc->filename && dcc->state == P_IDLE)
      {
	dcc->state = P_TALK;		/* we got ACCEPT timeout so go next */
	return _dcc_sig_1 (iface, S_TERMINATE);		/* to be continued */
      }
      break;
    case S_LOCAL:
      if (dcc->filename && !strncmp (BindResult, "ACCEPT ", 7) &&
	  dcc->state == P_IDLE &&	/* are we waiting for ACCEPT? */
	  ((msg = NextWord_Unquoted (NULL, NextWord(BindResult), 0)))[0] &&
	  atoi (msg) == dcc->ahead)	/* don't check filename, mIRC says */
      {
	pthread_mutex_lock (&dcc->mutex); /* it is "file.ext" anyway */
	dcc->startptr = strtoul (NextWord (msg), NULL, 10);
	pthread_mutex_unlock (&dcc->mutex);
	LOG_CONN (_("DCC: got ACCEPT, transfer resumed at %lu."), dcc->startptr);
	dcc->state = P_TALK;		/* and we finished stage 1 so go next */
      }
      else
	break;
    case S_TERMINATE:
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
	if (dcc->filename)		/* free dcc_priv_t fields */
	  pthread_mutex_destroy (&dcc->mutex);
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
		       INTERFACE *w, uchar *who, char *lname)
{
  /* fields are now:
    .size	offered size (only if SEND)
    .ptr	0 or .size if no resume, any other to try resume (only if SEND)
    .filename	full path (allocated) or NULL if CHAT
	we will set:
    .state	P_INITIAL
    .ahead	port #
    .rate	IP #
    .buf	nick!user@host
    .lname	Lname
    .startptr	0 (only if SEND)
    .iface	thread interface (I_CONNECT nick@net)
    .th		thread ID
    .mutex	only if SEND */
  dcc->state = P_INITIAL;
  dcc->ahead = port;
  dcc->rate = ip;
  strfcpy (dcc->buf, who, sizeof(dcc->buf));
  strfcpy (dcc->lname, NONULL(lname), sizeof(dcc->lname));
  dcc->iface = Add_Iface (I_CONNECT, w->name, &_dcc_sig_1, NULL, dcc);
  if (dcc->filename)
  {
    dcc->startptr = 0;
    pthread_mutex_init (&dcc->mutex, NULL);
  }
  if (pthread_create (&dcc->th, NULL, &_dcc_stage_1, dcc))
  {
    LOG_CONN (_("DCC: Cannot create thread!"));
    dcc->iface->ift = I_DIED;		/* OOPS, it died instantly */
    dcc->iface->data = NULL;		/* and it cannot own me! */
    if (dcc->filename)
      pthread_mutex_destroy (&dcc->mutex);
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

  sscanf (NextWord_Unquoted (dcc->buf, NextWord (cw), sizeof(dcc->buf)),
	  "%lu %hu", &ip, &port);
  if (Find_Iface (I_DIRECT, lname))		/* duplicate chat attempt */
  {
    Unset_Iface();
    New_Request (w, F_T_CTCR, _("DCC ERROR No duplicate connections allowed."));
    LOG_CONN ((_("DCC CHAT: Duplicate connection attempt, refused.")));
    free_dcc (dcc);
    return 0;
  }
  dcc->filename = NULL;
  /* TODO: have to create UI window if chat request and UI exist? */
  return _dcc_start (dcc, ip, port, w, who, lname);
}

		/* DCC SEND <filename> <ip> <port> <length> */
BINDING_TYPE_ctcp_dcc (dcc_send);
static int dcc_send (INTERFACE *w, uchar *who, char *lname, char *cw)
{
  dcc_priv_t *dcc;
  unsigned long ip;
  unsigned long long size = 0;
  long name_max, path_max;
  unsigned short port = 0;
  char *c;
  struct stat st;
  char path[HUGE_STRING];

  expand_path (path, ircdcc_dnload_dir, sizeof(path));
  if (stat (path, &st) < 0)
  {
    ERROR ("DCC: cannot stat download directory %s", path);
    return 1;
  }
  dcc = new_dcc();
  sscanf (NextWord_Unquoted (dcc->buf, NextWord (cw), sizeof(dcc->buf)),
	  "%lu %hu %llu", &ip, &port, &size);
  if (!size || size > ULONG_MAX)		/* check parameters */
  {
    free_dcc (dcc);
    Add_Request (I_LOG, "*", F_WARN, "invalid DCC: size %llu is out of range",
		 size);
    return 0;
  }
  else if (ircdcc_get_maxsize >= 0 &&
	   (unsigned long)size > (unsigned long)ircdcc_get_maxsize)
  {
    free_dcc (dcc);
    Add_Request (I_LOG, "*", F_WARN, "invalid DCC: size %llu is out of range",
		 size);
    return 0;
  }
  dcc->size = size;
  if ((c = strrchr (dcc->buf, '/')))		/* skip subdirs if there are */
    c++;
  else
    c = dcc->buf;
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
  if (stat (path, &st) < 0)		/* no such file */
    dcc->ptr = 0;
  else if (st.st_size == size)		/* full size already */
  {
    free_dcc (dcc);
    Add_Request (I_LOG, "*", F_WARN,
		 _("DCC: offered file \"%s\" seems equal to existing, request ignored."),
		 path);
    return 0;
  }
  else if (st.st_size > size)		/* it's smaller than our! */
  {
    Add_Request (I_LOG, "*", F_WARN,
		 "DCC: offered size %llu of \"%s\" is below of current, restarting file.",
		 size, path);
    dcc->ptr = dcc->size;
  }
  else if (st.st_size < ircdcc_resume_min)	/* small file, redownload */
    dcc->ptr = 0;
  else
    dcc->ptr = st.st_size;
  dcc->filename = safe_strdup (path);
  return _dcc_start (dcc, ip, port, w, who, lname);
}

		/* DCC ACCEPT file.ext <port> <ptr> */
BINDING_TYPE_ctcp_dcc (dcc_accept);
static int dcc_accept (INTERFACE *w, uchar *who, char *lname, char *cw)
{
  char sig[sizeof(ifsig_t)] = {S_LOCAL};

  BindResult = cw;
  Add_Request (I_CONNECT, w->name, F_SIGNAL, sig);
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
  binding_t *bind;

  uf = Get_Clientflags (lname, NULL);
  bind = Check_Bindtable (BT_IDcc, msg, uf, 0, NULL);
  if (bind)					/* run bindtable */
  {
    if (!bind->name)
      return bind->func (client, who, lname, msg);
  }
  New_Request (client, F_T_CTCR, _("DCC ERROR Unknown command."));
  return 1;					/* although logging :) */
}

		/* CHAT */
BINDING_TYPE_irc_priv_msg_ctcp (ctcp_chat);
static int ctcp_chat (INTERFACE *client, unsigned char *who, char *lname,
		      char *unick, char *msg)
{
  dcc_priv_t *dcc = new_dcc();
  unsigned short port = 0;
  uint32_t ip_local;			/* my IP in host byte order */
  struct hostent *hptr;

  if (ircdcc_allow_dcc_chat != TRUE)
  {
//    New_Request (client, F_T_CTCR, _("CHAT Unknown command."));
    return 1;					/* although logging :) */
  }
  /* dcc->state == P_DISCONNECTED */
  dcc->filename = NULL;
  strfcpy (dcc->buf, client->name, sizeof(dcc->buf));
  if (!(hptr = gethostbyname (hostname)))
  {
    ERROR (_("Cannot resolve own IP for CTCP CHAT!"));
    return 1;
  }
  ip_local = ntohl (*(uint32_t *)hptr->h_addr_list[0]);
  if ((dcc->socket = Listen_Port (lname, hostname, &port, NULL,
				  &_dcc_chat_pre, &dcc_handler)) < 0)
  {
    ERROR ("CTCP CHAT from %s: could not open listen port!", client->name);
    /* TODO: warn the client? */
    free_dcc (dcc);
  }
  else
    New_Request (client, F_T_CTCP, "DCC CHAT chat %lu %hu", ip_local, port);
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
  clrec_t *u;
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

static void _irc_ctcp_register (void)
{
  Add_Request (I_INIT, "*", F_REPORT, "module irc-ctcp");
  RegisterInteger ("dcc-ahead", &ircdcc_ahead_size);
  RegisterInteger ("dcc-resume-timeout", &ircdcc_resume_timeout);
  RegisterInteger ("dcc-resume-min", &ircdcc_resume_min);
  RegisterInteger ("dcc-get-maxsize", &ircdcc_get_maxsize);
  RegisterBoolean ("dcc-allow-ctcp-chat", &ircdcc_allow_dcc_chat);
  RegisterBoolean ("dcc-resume", &ircdcc_do_resume_send);
  RegisterBoolean ("dcc-get", &ircdcc_accept_send);
  RegisterBoolean ("dcc-accept-chat", &ircdcc_accept_chat);
  RegisterBoolean ("dcc-get-overwrite", &ircdcc_do_overwrite);
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
//  dcc_priv_t *dcc, *next;

  switch (sig)
  {
    case S_REPORT:
      // TODO.......
      break;
    case S_REG:
      _irc_ctcp_register();
      break;
    case S_TERMINATE:
      Delete_Binding ("ctcp-dcc", &dcc_chat, NULL);
      Delete_Binding ("ctcp-dcc", &dcc_send, NULL);
      Delete_Binding ("ctcp-dcc", &dcc_accept, NULL);
      Delete_Binding ("irc-priv-msg-ctcp", &ctcp_dcc, NULL);
      Delete_Binding ("irc-priv-msg-ctcp", &ctcp_chat, NULL);
      Delete_Binding ("irc-priv-msg-ctcp", &ctcp_time, NULL);
      Delete_Binding ("irc-priv-msg-ctcp", &ctcp_ping, NULL);
      Delete_Binding ("irc-priv-msg-ctcp", &ctcp_version, NULL);
      Delete_Binding ("irc-priv-msg-ctcp", &ctcp_help, NULL);
      UnregisterVariable ("dcc-ahead");
      UnregisterVariable ("dcc-resume-timeout");
      UnregisterVariable ("dcc-resume-min");
      UnregisterVariable ("dcc-get-maxsize");
      UnregisterVariable ("dcc-allow-ctcp-chat");
      UnregisterVariable ("dcc-resume");
      UnregisterVariable ("dcc-get");
      UnregisterVariable ("dcc-accept-chat");
      UnregisterVariable ("dcc-get-overwrite");
      UnregisterVariable ("incoming-path");
      while (ActDCC)
      {
	if (ActDCC->state == P_DISCONNECTED)	/* it's just listener */
	{
	  CloseSocket (ActDCC->socket);
	  free_dcc (ActDCC);
	}
	else if (ActDCC->iface && ActDCC->iface->IFSignal)
	  ActDCC->iface->ift |= ActDCC->iface->IFSignal (ActDCC->iface, sig);
      }
      Delete_Help ("irc-ctcp");
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
Function ModuleInit (char *args)
{
  CheckVersion;
  /* add own bindtables */
  BT_IDcc = Add_Bindtable ("ctcp-dcc", B_MATCHCASE);
  Add_Binding ("ctcp-dcc", "CHAT *", 0, 0, &dcc_chat, NULL);
  Add_Binding ("ctcp-dcc", "SEND *", 0, 0, &dcc_send, NULL);
  Add_Binding ("ctcp-dcc", "ACCEPT *", 0, 0, &dcc_accept, NULL);
  BT_Login = Add_Bindtable ("login", B_UNDEF); /* foreign! */
  BT_Dnload = Add_Bindtable ("dcc-got", B_MASK);
  BT_Cctcp = Add_Bindtable ("irc-priv-msg-ctcp", B_UNDEF); /* foreign! */
  Add_Binding ("irc-priv-msg-ctcp", "DCC *", 0, 0, &ctcp_dcc, NULL);
  Add_Binding ("irc-priv-msg-ctcp", "CHAT", U_NONE, U_ACCESS, &ctcp_chat, NULL);
  Add_Binding ("irc-priv-msg-ctcp", "TIME", 0, 0, &ctcp_time, NULL);
  Add_Binding ("irc-priv-msg-ctcp", "PING *", 0, 0, &ctcp_ping, NULL);
  Add_Binding ("irc-priv-msg-ctcp", "VERSION", 0, 0, &ctcp_version, NULL);
  Add_Binding ("irc-priv-msg-ctcp", "HELP*", 0, 0, &ctcp_help, NULL);
  // register our variables
  Add_Help ("irc-ctcp");
  _irc_ctcp_register();
  format_dcc_gotfile = SetFormat ("dcc_got_file",
				  _("DCC GET of %* from %N completed."));
//  format_dcc_startget = SetFormat ("dcc_get_start",
//				  _("DCC GET of %* from %N established."));
//  format_dcc_request = SetFormat ("dcc_request",
//				  _("DCC connection request for \"%*\" from %N(%@) to %I:%P"));
  return ((Function)&irc_ctcp_mod_sig);
}
