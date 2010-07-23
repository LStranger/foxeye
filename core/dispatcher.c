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
 * This file is part of FoxEye's source: main loop and interfaces API.
 */

#include "foxeye.h"

#include <signal.h>

#define DISPATCHER_C 1

#include "init.h"
#include "wtmp.h"
#include "tree.h"
#include "conversion.h"

#ifndef STATIC		/* it's simpler to have dlcose() here */
# ifdef HAVE_DLFCN_H
#  include <dlfcn.h>
# endif
#endif

#ifndef HAVE_SIGACTION
# define sigaction sigvec
#ifndef HAVE_SA_HANDLER
# define sa_handler sv_handler
# define sa_mask sv_mask
# define sa_flags sv_flags
#endif
#endif /* HAVE_SIGACTION */

typedef struct request_t
{
  union
  {
    struct request_t *next;
    int used;
  } x;
  REQUEST a;
} request_t;

typedef struct queue_t
{
  request_t *request;
  struct queue_t *next;
} queue_t;

typedef struct ifi_t
{
  INTERFACE a;					/* must be first member! */
  queue_t *head;
  queue_t *tail;
  queue_t *pq;
} ifi_t;

typedef struct ifst_t
{
  INTERFACE *ci;
  struct ifst_t *prev;
  struct ifst_t *next;
} ifst_t;

/* since Nick is undeclared for "dispatcher.c"... */
extern char Nick[NAMEMAX+1];
extern char *ShutdownR;

static request_t *FreeReq = NULL;	/* request_t[] array */
static unsigned int _Ralloc = 0;
static unsigned int _Rnum = 0;

static ifi_t **Interface = NULL;	/* *ifi_t[] array */
static unsigned int _Ialloc = 0;
static unsigned int _Inum = 0;
static size_t _Inamessize = 0;

static NODE *ITree = NULL;

//static INTERFACE _FromGone = {0, "?", NULL, NULL, NULL, NULL, NULL};

static INTERFACE *Console = NULL;

static ifi_t *Current;

static iftype_t if_or = 0;

static FILE *lastdebuglog = NULL;

/* lock for shutdown since it can be called any time */
/* if LockIface is set then _Inum is implicitly locked for reading */
pthread_mutex_t LockInum = PTHREAD_MUTEX_INITIALIZER;

static char PID_path[LONG_STRING];

/* locks on input: (LockIface) */
/* e: -1 if SIGTERM, 0 on normal termination, >0 if error condition */
void bot_shutdown (char *message, int e)
{
  unsigned int i = 0;
  ifi_t *con = NULL;
  queue_t *q;
  ifsig_t sig;

  if (message && *message)
    ShutdownR = message;
  if (e > 0)
    sig = S_SHUTDOWN;
  else
    sig = S_TERMINATE;
  /* set message to all queues and send S_SHUTDOWN signal */
//  DBG ("shutdown with code %d: %s", e, ShutdownR);
  if (!e)
    pthread_mutex_lock (&LockInum);
  /* shutdown all connections */
  for (; i < _Inum; i++)
  {
    if (Interface[i]->a.ift & I_CONSOLE)
      con = Interface[i];
    else if ((Interface[i]->a.ift & I_CONNECT) &&
	     !(Interface[i]->a.ift & I_DIED) && Interface[i]->a.IFSignal)
    {
//      DBG ("shutdown %d: 0x%x, name %s", i, Interface[i]->a.ift, Interface[i]->a.name);
      Interface[i]->a.IFSignal (&Interface[i]->a, sig);
    }
  }
  /* shutdown/terminate all modules */
  for (i = 0; i < _Inum; i++)
  {
    if ((Interface[i]->a.ift & I_MODULE) && !(Interface[i]->a.ift & I_DIED) &&
	Interface[i]->a.IFSignal)
    {
//      DBG ("shutdown %d: 0x%x, name %s", i, Interface[i]->a.ift, Interface[i]->a.name);
      Interface[i]->a.IFSignal (&Interface[i]->a, sig);
    }
  }
  /* shutdown all if there are still left */
  for (i = 0; i < _Inum; i++)
  {
    if (Interface[i]->a.ift & I_CONSOLE)
      con = Interface[i];
    else if (!(Interface[i]->a.ift & I_DIED) && Interface[i]->a.IFSignal)
    {
//      DBG ("shutdown %d: 0x%x, name %s", i, Interface[i]->a.ift, Interface[i]->a.name);
      Interface[i]->a.IFSignal (&Interface[i]->a, S_SHUTDOWN);
    }
  }
  if (lastdebuglog)
  {
    if (ShutdownR)
      DBG ("%s", message);
    fclose (lastdebuglog);
    lastdebuglog = NULL;
  }
  /* shutdown the console */
  if (con && con->a.IFSignal)
  {
    if (con->a.IFRequest)
      for (q = con->head; q; q = q->next)
	con->a.IFRequest (&con->a, &q->request->a);
//    fprintf (stderr, "shutdown console: 0x%x, name %s\n", con->ift, NONULL(con->name));
    con->a.IFSignal (&con->a, S_SHUTDOWN);
  }
  if (!e)
    pthread_mutex_unlock (&LockInum);
  NewEvent (W_DOWN, ID_ME, ID_ME, e);
  if (*PID_path)
    unlink (PID_path);
  exit (e);
}

/*
 * Принципы блокировок:
 * 1) Созданные потоки могут добираться только тогда, когда основной поток
 *    ничего не модифицирует (снята LockIface) и не читает _Inum.
 * 2) Для созданных потоков доступ к _Inum на запись (при Add_Iface())
 *    блокируется отдельной блокировкой, т.е для чтения нужна одна из двух
 *    блокировок, для записи - обе.
 * 3) Из ->IFRequest() и ->IFSignal все публичные поля всех интерфейсов
 *    доступны как на чтение, так и на запись.
 * 4) После того, как запрос записан в очередь, он считается const, изменять
 *    его интерфейсы могут только на свой страх и риск.
 */

static pthread_mutex_t LockIface;

ALLOCATABLE_TYPE (queue_t, _Q, next) /* alloc_queue_t(), free_queue_t() */

/* locks on input: LockIface */
static int add2queue (ifi_t *to, request_t *req)
{
  queue_t *newq;

  if (!req->a.mask_if || (to->a.ift & (I_LOCKED | I_DIED)) || !to->a.IFRequest)
    return 0;			/* request to nobody? */
  /* get free queue element */
  newq = alloc_queue_t();	/* newq->next is undefined now */
  newq->request = req;
  req->x.used++;
  to->pq = newq;
  if (req->a.flag & F_QUICK)
  {
    newq->next = to->head;
    if (!to->tail)
      to->tail = newq;
    to->head = newq;
  }
  else if (req->a.flag & F_AHEAD)
  {
    newq->next = to->tail;
    if (!to->head)			/* were no requests */
      to->head = to->tail = newq;
    else if (to->head == newq->next)	/* was only request */
      to->head = newq;
    else				/* insert somewhere */
    {
      queue_t *tmpq = to->head;

      while (tmpq && tmpq->next != newq->next) tmpq = tmpq->next;
      if (tmpq)
	tmpq->next = newq;
      else
	ERROR ("dispatcher:add2queue: cannot find tail, queue lost!");
    }
  }
  else
  {
    newq->next = NULL;
    if (to->tail)
      to->tail->next = newq;
    else
      to->head = newq;
    to->tail = newq;
  }
  to->a.qsize++;
//  DBG ("dispatcher:add2queue: added 0x%08x to 0x%08x: new head=0x%08x tail=0x%08x qsize=%d",
//       newq, to, to->head, to->tail, to->a.qsize);
  if (lastdebuglog)
  {
    fprintf (lastdebuglog, "::dispatcher:add2queue: req 0x%08x: added 0x%08x to 0x%08x: new head=0x%08x tail=0x%08x qsize=%d\n",
	     (unsigned int)req, (unsigned int)newq, (unsigned int)to,
	     (unsigned int)to->head, (unsigned int)to->tail, to->a.qsize);
    fflush (lastdebuglog);
  }
  return 1;
}

static LEAF *_find_itree (iftype_t ift, const char *name, LEAF *prev)
{
  register LEAF *l;
  char *c = (char *)name;

  if (prev == NULL)
    l = Find_Leaf (ITree, name);
  else
    l = Next_Leaf (ITree, prev, &c);
  while (l)
  {
    if (safe_strcmp(name, c))
      return NULL;
    else if (((ifi_t *)l->s.data)->a.ift & ift)
      break;
    l = Next_Leaf (ITree, l, &c);
  }
  return l;
}

#define REQBLSIZE 32
typedef struct reqbl_t
{
  struct reqbl_t *prev;
  request_t req[REQBLSIZE];
} reqbl_t;

static reqbl_t *_Rbl = NULL;

/* locks on input: LockIface */
/* we don't use standard macro here to have all requests in one thread */
static request_t *alloc_request_t (void)
{
  request_t *req;

  if (!FreeReq)
  {
    register int i = REQBLSIZE;
    register reqbl_t *rbl;

    rbl = safe_malloc (sizeof(reqbl_t));
    rbl->prev = _Rbl;
    _Rbl = rbl;
    _Ralloc++;
    FreeReq = req = rbl->req;
    while ((--i))
    {
      req->x.next = &req[1];
      req++;
    }
    req->x.next = NULL;
  }
  req = FreeReq;
  FreeReq = req->x.next;
  req->x.used = 0;
  _Rnum++;
  if (lastdebuglog)
  {
    fprintf (lastdebuglog, "::dispatcher:alloc_request_t: 0x%08x free=0x%08x\n",
	     (int)req, (int)FreeReq);
    fflush (lastdebuglog);
  }
  return req;
}

/* locks on input: LockIface */
static void free_request_t (request_t *req)
{
  req->x.next = FreeReq;		/* shift free queue up */
//  req->a.mask_if = 0; // why to touch it ever?
  FreeReq = req;			/* this one is first to use now */
  _Rnum--;
  if (lastdebuglog)
  {
    fprintf (lastdebuglog, "::dispatcher:free_request_t: 0x%08x next=0x%08x\n",
	     (int)req, (int)req->x.next);
    fflush (lastdebuglog);
  }
}

/* locks on input: LockIface */
static void vsadd_request (ifi_t *to, iftype_t ift, const char *mask,
			   flag_t flag, const char *fmt, va_list ap)
{
  request_t *cur = NULL;
  char *ch;
  unsigned int i = 0, n, ii;
#ifdef HAVE_ICONV
  conversion_t *conv = NULL;
  request_t *req = NULL; /* will be initialized but make compiler happy */
  size_t s;
#endif

  if (!ift)			/* request to nobody? */
    return;
  if (lastdebuglog && (ift & I_LOG) && !(flag & F_DEBUG))
  {
    fprintf (lastdebuglog, ":%08x:", flag);
    vfprintf (lastdebuglog, fmt, ap);
    fprintf (lastdebuglog, "\n");
    fflush (lastdebuglog);
  }
  if (!Current)			/* special case */
    return;
  cur = alloc_request_t();
  strfcpy (cur->a.to, NONULL(mask), sizeof(cur->a.to));
  cur->a.mask_if = (ift & ~I_PENDING);	/* reset it anyway */
  cur->a.from = &Current->a;
  cur->a.flag = flag;
  vsnprintf (cur->a.string, sizeof(cur->a.string), fmt, ap);
  if (!(flag & F_DEBUG))
  {
    dprint (5, "dispatcher:vsadd_request: to=\"%s\" (0x%x) flags=0x%x message=\"%s\"",
	    cur->a.to, (unsigned int)ift, (unsigned int)flag, cur->a.string);
  }
  /* check for flags and matching */
  n = 0;
  if (to)
    n = add2queue (to, cur);
  else if (!strpbrk (mask, "*?"))	/* simple wildcards */
  {
    LEAF *l = NULL;

    while ((l = _find_itree (ift, cur->a.to, l))) /* check for exact name */
      n += add2queue (l->s.data, cur);
    if (!n && (ch = strrchr(cur->a.to, '@'))) /* handle client@service */
    {
      DBG ("dispatcher:vsadd_request: check for collector(s) %s type 0x%x",
	   ch, (int)ift);
      for (i = 0; i < _Inum; i++)	/* relay it to collector if there is one */
      {
	if ((Interface[i]->a.ift & ift) &&
	    simple_match (ch, Interface[i]->a.name) > 1)
	  n += add2queue (Interface[i], cur);
      }
    }
    while ((l = _find_itree (ift, "*", l))) /* check for special name "*" */
      n += add2queue (l->s.data, cur);
  }
  else /* mask have wildcards */
    for (i = 0; i < _Inum; i++)
    {
      if (&Interface[i]->a == Console && (Interface[i]->a.ift & ift))
	Console->IFRequest (Console, &cur->a);	/* if forced */
      else if ((Interface[i]->a.ift & ift) &&
	       simple_match (mask, Interface[i]->a.name) >= 0)
	n += add2queue (Interface[i], cur);
    }
  ift &= ~I_PENDING;
  ii = _Inum;
  if (!(flag & F_DEBUG))
    dprint (5, "dispatcher:vsadd_request: matching finished: %u targets", n);
  for (i = 0; n && i < _Inum; )		/* check for pending reqs */
  {
    if (Interface[i]->pq && Interface[i]->pq->request == cur)
    {
#ifdef HAVE_ICONV
      if (Interface[i]->a.conv)		/* if no conversion then skip it */
      {
	if (!conv)
	{
	  conv = Interface[i]->a.conv;
	  DBG ("dispatcher: %d:conversion to %s", i, Conversion_Charset(conv));
	  req = alloc_request_t();
	  strfcpy (req->a.to, NONULL(mask), sizeof(req->a.to));
	  req->a.mask_if = ift;
	  req->a.from = &Current->a;
	  req->a.flag = flag;		/* new request prepared, convert it */
	  ch = req->a.string;
	  s = Undo_Conversion (conv, &ch, sizeof(req->a.string) - 1,
			       cur->a.string, strlen (cur->a.string));
	  ch[s] = 0;
	  if (lastdebuglog)
	  {
	    fprintf (lastdebuglog, "::dispatcher:vsadd_request: iface 0x%08x: req 0x%08x -> 0x%08x\n",
		     (unsigned int)Interface[i],
		     (unsigned int)Interface[i]->pq->request,
		     (unsigned int)req);
	    fflush (lastdebuglog);
	  }
	  Interface[i]->pq->request = req;
	  req->x.used++;
	  cur->x.used--;
	}
	else if (Interface[i]->a.conv == conv)
	{
	  if (lastdebuglog)
	  {
	    fprintf (lastdebuglog, "::dispatcher:vsadd_request: iface %d[0x%08x]: conversion to %s: req 0x%08x -> 0x%08x\n",
		     i, (unsigned int)Interface[i], Conversion_Charset(conv),
		     (unsigned int)Interface[i]->pq->request,
		     (unsigned int)req);
	    fflush (lastdebuglog);
	  }
	  Interface[i]->pq->request = req;	/* it's ready */
	  req->x.used++;
	  cur->x.used--;
	}
	else
	{
	  if (ii > i)
	    ii = i;			/* different charset */
	  if (++i == _Inum)
	  {
	    i = ii;
	    ii = _Inum;
	    conv = NULL;
	  }
	  continue;
	}
      }
#endif
      if (lastdebuglog)
	fprintf (lastdebuglog, "::dispatcher:vsadd_request: reset pq 0x%08x\n",
		 (unsigned int)Interface[i]->pq);
      Interface[i]->pq = NULL;
      n--;
    }
    else if (Interface[i]->pq && lastdebuglog)
      fprintf (lastdebuglog, "::dispatcher:vsadd_request: skipping pq 0x%08x\n",
	       (unsigned int)Interface[i]->pq);
    if ((Interface[i]->a.ift & I_PENDING) && lastdebuglog)
      fprintf (lastdebuglog, "::dispatcher:vsadd_request: suddenly I_PENDING!\n");
    Interface[i++]->a.ift &= ~I_PENDING; /* shouldn't it be not */
#ifdef HAVE_ICONV
    if (i == _Inum)
    {
      i = ii;
      ii = _Inum;
      conv = NULL;
    }
#endif
  }
  if (lastdebuglog)
  {
    fprintf (lastdebuglog, "::dispatcher:vsadd_request: success on 0x%08x: %d\n",
	     (unsigned int)cur, cur->x.used);
    fflush (lastdebuglog);
  }
  if (!cur->x.used)
    free_request_t (cur);
  else if (cur->x.used < 0)
    ERROR ("dispatcher:vsadd_request: unknown error (used=%d)!", cur->x.used);
  if (n)
    ERROR ("dispatcher:vsadd_request: %u request(s) unhandled!", n);
}

/* locks on input: LockIface */
static int delete_request (ifi_t *i, queue_t *q)
{
  queue_t *last;
  request_t *req;

  if (!q)
    return 0;					/* nothing to do? */
  if (q == i->head)
  {
    i->head = q->next;
    if (i->tail == q)
      i->tail = NULL;
  }
  else
  {
    for (last = i->head; last->next && last->next != q; last = last->next);
    if (!last->next)
    {
      ERROR ("dispatcher:delete_request: 0x%08x from 0x%08x: not found", q, i);
      return 0;					/* not found??? */
    }
    last->next = q->next;
    if (i->tail == q)
      i->tail = last;
  }
  req = q->request;
  free_queue_t (q);
  /* if this request is last, free it */
  if (req->x.used == 1)
    free_request_t (req);
  else
    req->x.used--;
  i->a.qsize--;
//  DBG ("dispatcher:delete_request: deleted 0x%08x from 0x%08x: new head=0x%08x tail=0x%08x qsize=%d",
//       q, i, i->head, i->tail, i->a.qsize);
  return 1;
}

/* locks on input: LockIface */
static int relay_request (request_t *req)
{
  unsigned int i = 0;

  if (!req || !req->a.mask_if)
    return 1;			/* request to nobody? */
  /* check for flags and matching, don't relay back */
  for (i = 0; i < _Inum; i++)
  {
    if (Interface[i]->pq && lastdebuglog)
      fprintf (lastdebuglog, "::dispatcher error:relay_request: got pq 0x%08x!\n",
	       (int)Interface[i]->pq);
    if ((Interface[i]->a.ift & req->a.mask_if) &&
	(Interface[i] != Current) &&
	simple_match (req->a.to, Interface[i]->a.name) >= 0 &&
	add2queue (Interface[i], req))
      Interface[i]->pq = NULL;
  }
  return 1;
}

/* locks on input: LockIface */
static int _get_current (void)
{
  int out;
  queue_t *curq = Current->head;

  /* interface may be unused so lock semaphore */
  if (!Current->a.ift || (Current->a.ift & I_DIED))
    return 0;
  time (&Time);			/* moved from sheduler to allow cycle */
  if (!Current->a.IFRequest)
    out = REQ_OK;
  else if (curq)
  {
//    DBG ("dispatcher:_get_current: do 0x%08x on 0x%08x: next 0x%08x", curq, Current, curq->next);
    Current->head = curq->next;			/* to allow recursion */
    if (Current->tail == curq)
      Current->tail = NULL;
    Current->a.qsize--;
    out = Current->a.IFRequest (&Current->a, &curq->request->a);
    curq->next = Current->head;			/* restore status-quo */
    if (Current->tail == NULL)
      Current->tail = curq;
    Current->head = curq;
    Current->a.qsize++;
  }
  else
  {
    if (Current->a.qsize)
      ERROR ("Interface 0x%08x: qsize is %d but no head!", &Current->a,
	     Current->a.qsize);
    out = Current->a.IFRequest (&Current->a, NULL);
  }

  if (out == REQ_RELAYED && relay_request (curq->request))
    out = REQ_OK;

  if (out == REQ_OK)
    return delete_request (Current, curq);	/* else it was rejected */

  return 0;
}

/* locks on input: (LockIface) */
int Relay_Request (iftype_t ift, char *name, REQUEST *req)
{
  request_t *cur;
  char *ch;
  LEAF *l;
  unsigned int i, n;

  if (!ift || !name || !req)	/* request to nobody? */
    return REQ_OK;
  pthread_mutex_lock (&LockIface);
  /* TODO: debug it? */
  cur = alloc_request_t();
  strfcpy (cur->a.to, name, sizeof(cur->a.to));
  cur->a.mask_if = ift;
  cur->a.from = req->from;
  cur->a.flag = req->flag;
  memcpy (cur->a.string, req->string, sizeof(cur->a.string));
  /* check for flags and matching */
  n = 0;
  l = NULL;
  while ((l = _find_itree (ift, cur->a.to, l))) /* check for exact name */
    if (add2queue (l->s.data, cur) && (++n))	/* increment if success */
      ((ifi_t *)l->s.data)->pq = NULL;		/* it should be reset! */
  if (!n && (ch = strrchr(cur->a.to, '@')))	/* handle client@service */
  {
    for (i = 0; i < _Inum; i++)	/* relay it to collector if there is one */
    {
      if ((Interface[i]->a.ift & ift) &&
	  simple_match (ch, Interface[i]->a.name) > 1 &&
	  add2queue (Interface[i], cur))
	Interface[i]->pq = NULL;		/* it should be reset! */
    }
  }
  if (!cur->x.used)
    free_request_t (cur);
  pthread_mutex_unlock (&LockIface);
  return REQ_OK;
}

/* locks on input: LockIface */
static int unknown_iface (INTERFACE *cur)
{
  register unsigned int i = 0;
  if (cur)
    for (; i < _Inum; i++)
      if (Interface[i] == (ifi_t *)cur)
	return 0;
  WARNING ("unknown_iface(0x%08x)", cur);
  return -1;
}

/* only way to get requests for locked interface :) */
/* locks on input: (LockIface) */
int Get_Request (void)
{
  int i = 0;

  pthread_mutex_lock (&LockIface);
  i = _get_current();
  pthread_mutex_unlock (&LockIface);
//  if (lastdebuglog)
//    fprintf (lastdebuglog, "!%d", i);
  return i;
}

ALLOCATABLE_TYPE (ifi_t, _IFI, a.prev) /* alloc_ifi_t(), free_ifi_t() */

/* locks on input: (LockIface) */
INTERFACE *
Add_Iface (iftype_t ift, const char *name, iftype_t (*sigproc) (INTERFACE*, ifsig_t),
	   int (*reqproc) (INTERFACE *, REQUEST *), void *data)
{
  register unsigned int i;

  pthread_mutex_lock (&LockIface);
  i = _Inum;
  if (i == _Ialloc)
  {
    _Ialloc += 16;
    safe_realloc ((void **)&Interface, (_Ialloc) * sizeof(ifi_t *));
  }
  Interface[i] = alloc_ifi_t();
  memset (Interface[i], 0, sizeof(ifi_t));
  Interface[i]->a.name = safe_strdup (name);
  if (Interface[i]->a.name)
    _Inamessize += strlen (name) + 1;
  Interface[i]->a.IFSignal = sigproc;
  Interface[i]->a.ift = (ift | if_or);
  Interface[i]->a.IFRequest = reqproc;
  Interface[i]->a.data = data;
  pthread_mutex_lock (&LockInum);
  if (i == _Inum)
    _Inum++;
  pthread_mutex_unlock (&LockInum);
  if (Interface[i]->a.name)
    if (Insert_Key (&ITree, Interface[i]->a.name, Interface[i], 0))
      ERROR ("interface add: dispatcher tree error");
  dprint (2, "added iface %u(0x%08x): 0x%x name \"%s\"", i, &Interface[i]->a,
	  Interface[i]->a.ift, NONULL((char *)Interface[i]->a.name));
  pthread_mutex_unlock (&LockIface);
  return (&Interface[i]->a);
}

/* locks on input: LockIface */
static int _delete_iface (unsigned int r)
{
  register unsigned int i;
  register reqbl_t *rbl;
  ifi_t *curifi = Interface[r];
  register INTERFACE *todel = &curifi->a;

  while (delete_request (curifi, curifi->head)); /* no queue for dead! */
  for (rbl = _Rbl; rbl; rbl = rbl->prev)
    for (i = 0; i < REQBLSIZE; i++)	/* well, IFSignal could sent anything */
      if (rbl->req[i].a.from == todel && rbl->req[i].a.mask_if)
	return 1;			/* just put it on hold right now */
//	rbl->req[i].a.from = &_FromGone;
  pthread_mutex_lock (&LockInum);
  _Inum--;
  if (r < _Inum)
    Interface[r] = Interface[_Inum];
  pthread_mutex_unlock (&LockInum);
  if (todel->prev && todel->prev->IFSignal && /* resume if nested */
      todel->prev->IFSignal (todel->prev, S_CONTINUE) == I_DIED)
    todel->prev->ift |= I_DIED;
  dprint (2, "deleting iface %u of %u: name \"%s\"", r, _Inum,
	  NONULL((char *)todel->name));
  if (todel->name)
    Delete_Key (ITree, todel->name, curifi);
  FREE (&todel->name);
  if (!(todel->ift & I_MODULE))		/* modules have handle in data */
    safe_free (&todel->data);
#ifndef STATIC
  else
    dlclose (todel->data);
#endif
#ifdef HAVE_ICONV
  Free_Conversion (todel->conv);
#endif
  free_ifi_t (curifi);
  return 0;				/* deleting is done */
}

static ifst_t *StCur = NULL, *StAll = NULL;
static int StNum = 0;

/* locks on input: LockIface */
/* returns previous interface in stack, NULL if this is first */
static INTERFACE *stack_iface (INTERFACE *newif, int set_current)
{
  ifst_t *newst;

//  if (lastdebuglog)
//  {
//    fprintf (lastdebuglog, "!+");
//    fflush (lastdebuglog);
//  }
  if (!StCur)
  {
    if (!StAll)
    {
      StAll = safe_calloc (1, sizeof(ifst_t));
      StNum++;
    }
    StCur = StAll;
    if (newif)				/* set new interface */
      StCur->ci = newif;		/* or else try to "remember" last */
    if (set_current)
      Current = (ifi_t *)StCur->ci;
    return NULL;
  }
  if (!(newst = StCur->next))
  {
    newst = safe_malloc (sizeof(ifst_t));
    StNum++;
    if (StCur)
      StCur->next = newst;
    newst->prev = StCur;
    newst->next = NULL;
  }
  if (newif)
    newst->ci = newif;
  else
    newst->ci = newst->prev->ci;	/* inherit last */
  StCur = newst;
  if (set_current)
    Current = (ifi_t *)StCur->ci;
  return newst->prev->ci;
}

/* locks on input: LockIface */
/* returns previous interface in stack, NULL if this was first */
static INTERFACE *unstack_iface (void)
{
//  if (lastdebuglog)
//  {
//    fprintf (lastdebuglog, "!-");
//    fflush (lastdebuglog);
//  }
  if (!StCur)
  {
    bot_shutdown ("OOPS! interface stack exhausted! Extra Unset_Iface() called?", 7);
    return NULL;
  }
  StCur = StCur->prev;
  return StCur ? StCur->ci : NULL;
}

/* locks on input: none */
static void iface_run (unsigned int i)
{
  pthread_mutex_lock (&LockIface);
  /* we are died? OOPS... */
  while (i < _Inum && (Interface[i]->a.ift & I_DIED))
    if (_delete_iface (i))		/* if it sent something then skip it */
    {
      pthread_mutex_unlock (&LockIface);
      return;
    }
//  if (lastdebuglog)
//  {
//    fprintf (lastdebuglog, "%x", i);
//    fflush (lastdebuglog);
//  }
  /* all rest are died? return now! */
  if (Interface[i]->pq)
  {
    ERROR ("dispatcher error: found unhandled PQ 0x%08x on interface %u[0x%08x]!",
	   (int)Interface[i]->pq, i, (int)Interface[i]);
    Interface[i]->pq = NULL;		/* reset it until we crash! */
  }
  if (i < _Inum && (Interface[i]->a.ift & I_FINWAIT))
  {
    if (Interface[i]->a.IFSignal)
    {
      stack_iface (&Interface[i]->a, 1);
      Interface[i]->a.ift |= Interface[i]->a.IFSignal (&Interface[i]->a,
						       S_TERMINATE);
      if (unstack_iface())
	bot_shutdown ("OOPS! extra locks of interface, exiting...", 7);
    }
    else
      Interface[i]->a.ift |= I_DIED;
  }
  else if (i < _Inum && !(Interface[i]->a.ift & I_LOCKED))
  {
    stack_iface (&Interface[i]->a, 1);
    _get_current();			/* run with LockIface only */
    if (unstack_iface())
      bot_shutdown ("OOPS! extra locks of interface, exiting...", 7);
  }
  pthread_mutex_unlock (&LockIface);
}

/* locks on input: (LockIface) */
void Add_Request (iftype_t ift, const char *mask, flag_t fl, const char *text, ...)
{
  va_list ap;
  register unsigned int i;
  unsigned int inum;

  /* request to nobody? */
  if (!ift)
    return;
  pthread_mutex_lock (&LockIface);
  /* if F_SIGNAL then text is binary! */
  if (fl & F_SIGNAL)
  {
    int savestate = O_GENERATECONF;

    if (ift != -1)		/* we assume only init will call it with -1 */
      O_GENERATECONF = FALSE;			/* don't make config now */
    inum = _Inum;				/* don't sent to created now! */
    if (Have_Wildcard (mask) < 0)
    {
      LEAF *l = NULL;
      register INTERFACE *li;

      while ((l = _find_itree (ift, mask, l))) /* check for exact name */
      {
	li = l->s.data;
	if (li->IFSignal && !(li->ift & ~if_or & (I_DIED | I_LOCKED)) &&
	    li->IFSignal (li, (ifsig_t)text[0]) == I_DIED)
	  li->ift |= I_DIED;
	if (l->s.data != li)			/* oops, something inserted? */
	{
	  l = NULL;
	  while ((l = _find_itree (ift, mask, l)))
	    if (l->s.data == li)
	      break;
	}
      }
    }
    else for (i = 0; i < inum; i++)		/* check for if_or because */
    {						/* you need to get signals */
      if ((Interface[i]->a.ift & ift) && Interface[i]->a.IFSignal &&
	  !(Interface[i]->a.ift & ~if_or & (I_DIED | I_LOCKED)) &&
	  simple_match (mask, Interface[i]->a.name) >= 0)
      {
	/* request is a signal - it may die */
	if (Interface[i]->a.IFSignal (&Interface[i]->a, (ifsig_t)text[0]) == I_DIED)
	  Interface[i]->a.ift |= I_DIED;
      }
    }
    O_GENERATECONF = savestate;			/* restoring status quo */
  }
  else
  {
    va_start (ap, text);
    vsadd_request (NULL, ift, mask, fl, text, ap);
    va_end (ap);
  }
  pthread_mutex_unlock (&LockIface);
}

/* locks on input: (LockIface) */
void New_Request (INTERFACE *cur, flag_t fl, const char *text, ...)
{
  va_list ap;

  pthread_mutex_lock (&LockIface);
  /* request to nobody? */
  if (unknown_iface (cur) || (cur->ift & I_DIED));
  /* if F_SIGNAL then text is binary! */
  else if (fl & F_SIGNAL)
  {
    if (cur->IFSignal && !(cur->ift & (I_DIED | I_LOCKED)) &&
	cur->IFSignal (cur, (ifsig_t)text[0]) == I_DIED)
      cur->ift |= I_DIED;
  }
  else
  {
    va_start (ap, text);
    vsadd_request ((ifi_t *)cur, cur->ift, cur->name, fl, text, ap);
    va_end (ap);
  }
  pthread_mutex_unlock (&LockIface);
}

/* locks on input: (LockIface) */
void dprint (int level, const char *text, ...)
{
  va_list ap;

  va_start (ap, text);
  if (lastdebuglog)
  {
    fprintf (lastdebuglog, "::");
    vfprintf (lastdebuglog, text, ap);
    fprintf (lastdebuglog, "\n");
    fflush (lastdebuglog);
  }
  if (level <= O_DLEVEL && level < 9 && Interface) /* level > 8 is printed only to lastdebuglog */
  {
    pthread_mutex_lock (&LockIface);
    vsadd_request (NULL, I_LOG, "*",
		   F_DEBUG | (level < 1 ? F_ERROR : level == 1 ? F_WARN : 0),
		   text, ap);
    pthread_mutex_unlock (&LockIface);
  }
  va_end (ap);
}

/* locks on input: (LockIface) */
/* locks on return: LockIface */
INTERFACE *Set_Iface (INTERFACE *newif)
{
  pthread_mutex_lock (&LockIface);
  if (!newif || unknown_iface (newif))	/* if unknown - don't change */
    newif = NULL;
  return stack_iface (newif, 1);
}

/* locks on input: LockIface */
/* locks on return: (LockIface) */
int Unset_Iface (void)
{
  Current = (ifi_t *)unstack_iface();
  pthread_mutex_unlock (&LockIface);
  return 0;
}

/* find the interface with name and flags exatly matched
   NULL is special case - check if any iface that type exist */
/* locks on input: (LockIface) */
/* locks on return: LockIface - if found */
INTERFACE *Find_Iface (iftype_t ift, const char *name)
{
  LEAF *l = NULL;
  ifi_t *i = NULL;
  int n;

  pthread_mutex_lock (&LockIface);
  if (name == NULL)
  {
    for (n = 0; n < _Inum; n++)
      if ((Interface[n]->a.ift & ift) == ift &&
	  !(Interface[n]->a.ift & I_DIED))
      {
	i = Interface[n];
	break;
      }
  }
  else while ((l = _find_itree (ift, name, l)))	/* find first matched */
    if ((((ifi_t *)l->s.data)->a.ift & ift) == ift &&
	!(((ifi_t *)l->s.data)->a.ift & I_DIED))
    i = l->s.data;
  dprint (3, "search for iface 0x%x name \"%s\": %s", ift, NONULL(name),
	  i ? (char *)i->a.name : "<none>");
  if (i)
  {
    stack_iface ((INTERFACE *)Current, 0);
    return &i->a;
  }
  pthread_mutex_unlock (&LockIface);
  return NULL;
}

int Rename_Iface (INTERFACE *iface, const char *newname)
{
  queue_t *q;

  pthread_mutex_lock (&LockIface);
  if (unknown_iface (iface))
  {
    pthread_mutex_unlock (&LockIface);
    return 0;
  }
  dprint (2, "renaming iface 0x%x: \"%s\" --> \"%s\"", iface,
	  NONULL((char *)iface->name), NONULL(newname));
  /* don't rename requests to empty target or if target is "*" */
  if (iface->name && newname && strcmp (iface->name, "*"))
    for (q = ((ifi_t *)iface)->head; q; q = q->next)
      if (q->request && !safe_strcmp (q->request->a.to, iface->name))
	strfcpy (q->request->a.to, newname, sizeof(q->request->a.to));
  if (iface->name)
  {
    _Inamessize -= strlen (iface->name) + 1;
    Delete_Key (ITree, iface->name, iface);
  }
  FREE (&iface->name);
  iface->name = safe_strdup (newname);
  if (iface->name)
    _Inamessize += strlen (iface->name) + 1;
  if (iface->name && Insert_Key (&ITree, iface->name, iface, 0))
    ERROR ("interface add: dispatcher tree error");
  if (iface->IFSignal && iface->IFSignal (iface, S_FLUSH) == I_DIED)
    iface->ift |= I_DIED;
  pthread_mutex_unlock (&LockIface);
  return 1;
}

void Status_Interfaces (INTERFACE *iface)
{
  register int i;

  pthread_mutex_lock (&LockIface);
  for (i = 0; i < _Inum; i++)
  {
    New_Request (iface, 0,
		 "interface %d: flags 0x%x (%s%s), name %s, queue size %d",
		 i, Interface[i]->a.ift, Interface[i]->a.IFSignal ? "S":"",
		 Interface[i]->a.IFRequest ? "R":"",
		 NONULL((char *)Interface[i]->a.name), Interface[i]->a.qsize);
  }
  New_Request (iface, 0,
	       "Total: %u/%u interfaces (%lu bytes), %u/%u requests (%lu bytes)",
	       _Inum, _Ialloc, _Ialloc * sizeof(ifi_t *) +
			       _IFIalloc * sizeof(ifi_t) +
			       StNum * sizeof(ifst_t) + _Inamessize,
	       _Rnum, _Ralloc * REQBLSIZE, _Ralloc * sizeof(reqbl_t));
  New_Request (iface, 0, "       %u/%u queue slots (%lu bytes)", _Qnum, _Qalloc,
	       _Qalloc * sizeof(queue_t));
  pthread_mutex_unlock (&LockIface);
}

static ifi_t *_Boot;

static int _b_stub (INTERFACE *iface, REQUEST *req) { return 0; }

/* start the empty interface that will collect all boot messages */
static void start_boot (void)
{
  _Boot = (ifi_t *)Add_Iface (~I_CONSOLE & ~I_INIT & ~I_DIED & ~I_LOCKED,
			      "*", NULL, &_b_stub, NULL);
  stack_iface ((INTERFACE *)_Boot, 1);
  if_or = I_LOCKED;
}

/* bounce boot requests to interfaces with F_BOOT */
static void end_boot (void)
{
  INTERFACE *con = Find_Iface (I_CONSOLE, "");	/* locked now! */
  unsigned int i;

  if_or = 0;
  dprint (4, "end_boot: unlock %u interfaces (but console and init)", _Inum);
  for (i = 0; i < _Inum; i++)
    if (!(Interface[i]->a.ift & (I_CONSOLE | I_INIT)))
      Interface[i]->a.ift &= ~I_LOCKED;
  if (con)
    con->ift |= I_LOCKED;
  while (_Boot->head)
  {
    relay_request (_Boot->head->request);
    delete_request (_Boot, _Boot->head);
  }
  unstack_iface();		/* ignore current, it will be rewritten */
  if (con)
    con->ift &= ~I_LOCKED;
  _Boot->a.ift = I_DIED;
  pthread_mutex_unlock (&LockIface);
}

static void set_pid_path (void)
{
  char *ne;

  if (!*Nick || !Config)
    PID_path[0] = 0;
  /* what directory in? */
  else
    strfcpy (PID_path, Config, sizeof(PID_path) - (NAMEMAX+5));
  if (!(ne = strrchr (PID_path, '/')))
  {
    ne = &PID_path[1];
    PID_path[0] = '.';
  }
  snprintf (ne, NAMEMAX+6, "/%s.pid", Nick);
}

static pid_t try_get_pid (void)
{
  FILE *fp;
  char buff[SHORT_STRING];

  if (!*PID_path)
    return 0;
  if (!(fp = fopen (PID_path, "r")))
    return 0;
  fgets (buff, sizeof(buff), fp);
  fclose (fp);
  return (pid_t)atoi (buff);
}

static int write_pid (pid_t pid)
{
  FILE *fp;
  char buff[SHORT_STRING];
  int i = 0;

  snprintf (buff, sizeof(buff), "%d", pid);
  if (!(fp = fopen (PID_path, "w")))
    return -1;
  if (!fwrite (buff, strlen (buff), 1, fp))
    i = -1;
  fclose (fp);
  return i;
}

static pthread_mutex_t SigLock = PTHREAD_MUTEX_INITIALIZER;

static int _got_signal = 0;

static void normal_handler (int signo)
{
  pthread_mutex_lock (&SigLock);
  _got_signal = signo;
  pthread_mutex_unlock (&SigLock);
}

static void errors_handler (int signo)
{
  char *signame;
  char msg[100];
  struct sigaction act;
  int norm_exit = 1;

  act.sa_handler = SIG_DFL;
  sigemptyset (&act.sa_mask);
  act.sa_flags = 0;
  sigaction (signo, &act, NULL);
  switch (signo)
  {
    case SIGQUIT:
      signame = "QUIT";
      break;
    case SIGILL:
      signame = "ILL";
      break;
    case SIGFPE:
      signame = "FPE";
      break;
    case SIGSEGV:
      signame = "SEGV";
      break;
#ifdef SIGBUS
    case SIGBUS:
      signame = "BUS";
      break;
#endif
#ifdef SIGSYS
    case SIGSYS:
      signame = "SYS";
      break;
#endif
    case SIGTERM:
    default:
      signame = "TERM";
      norm_exit = -1;
  }
  snprintf (msg, sizeof(msg), "Caught signal SIG%s, shutdown...", signame);
  if (pthread_mutex_trylock (&SigLock) == 0)
  {
    bot_shutdown (msg, norm_exit);
#ifdef HAVE_PTHREAD_KILL_OTHER_THREADS_NP
    pthread_kill_other_threads_np();
#endif
  }
  pthread_kill (pthread_self(), signo);
}

int dispatcher (INTERFACE *start_if)
{
  struct sigaction act;
  unsigned int i = 0, count = 0, max = 0;
  int limit = 0;
  pid_t pid;
  pthread_mutexattr_t attr;
  char *oldpid;
  struct timespec tp;

  /* check if bot already runs */
  set_pid_path();
  pid = try_get_pid();
  if (pid)
  {
    if (kill (pid, SIGPIPE))
    {
      perror _("kill PID file");
      unlink (PID_path);
    }
    else
    {
      printf _("The bot already running!\n");
      return 6;
    }
  }
  /* now fork and return 0 to the parent */
  pid = fork();
  if (pid)
  {
    /* error */
    if (pid == -1)
    {
      perror _("init dispatcher");
      return 5;
    }
    /* OK, this is parent */
    write_pid (pid);
    return 0;
  }
  /* this is the child... */
  freopen ("/dev/null", "r", stdin);
  freopen ("/dev/null", "w", stdout);
  setsid();
//  while (getppid() != (pid_t) 1);
//  fprintf (stderr, "setsid()\n");
//  sleep (3);
  /* catch the signals */
  act.sa_handler = &normal_handler;
  sigemptyset (&act.sa_mask);
  act.sa_flags = 0;
  sigaction (SIGTERM, &act, NULL);	/* throw these signal to dispatcher */
  sigaction (SIGINT, &act, NULL);
  sigaction (SIGHUP, &act, NULL);
  act.sa_handler = &errors_handler;
  sigaction (SIGQUIT, &act, NULL);	/* catch these signals as errors */
  sigaction (SIGILL, &act, NULL);
  sigaction (SIGFPE, &act, NULL);
  sigaction (SIGSEGV, &act, NULL);
#ifdef SIGBUS
  sigaction (SIGBUS, &act, NULL);
#endif
#ifdef SIGSYS
  sigaction (SIGSYS, &act, NULL);
#endif
  act.sa_handler = SIG_IGN;
  sigaction (SIGPIPE, &act, NULL);	/* ignore these signals */
  sigaction (SIGUSR1, &act, NULL);
  sigaction (SIGUSR2, &act, NULL);
  /* wait a debugger :) */
  if (O_WAIT)
    while (!limit);
  /* init recursive LockIface - Unix98 only */
  pthread_mutexattr_init (&attr);
  pthread_mutexattr_settype (&attr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init (&LockIface, &attr);
  /* add console interface if available */
  if (start_if)
    Console = Add_Iface (start_if->ift, start_if->name, start_if->IFSignal,
			 start_if->IFRequest, start_if->data);
  /* start lastdebuglog if defined */
  if (O_DDLOG)
    lastdebuglog = fopen ("foxeye.debug", "w");
  /* create init interface - collect all messages */
  start_boot();
  time (&StartTime);
  /* now we must register all common interfaces
   * which have not own interface functions */
  init();
  NewEvent (W_START, ID_ME, ID_ME, 0);	/* started ok */
  if (Console)
  {
    if (Console->ift & I_LOCKED)
      Console->ift = I_DIED;		/* died already? */
    else
      Console->ift |= I_DCCALIAS;
    Console = NULL;			/* stop forcing */
  }
  /* no nick??? */
  if (!*Nick)
    bot_shutdown (_("Cannot run without a nick!"), 3);
  /* start random generator */
  pid = getpid();
  srand (pid);
  /* create new pid-file */
  oldpid = safe_strdup (PID_path);
  set_pid_path();
  if (safe_strcmp (oldpid, PID_path) && rename (oldpid, PID_path))
  {
    unlink (oldpid);
    bot_shutdown (_("Cannot write a PID file!"), 3);
  }
  FREE (&oldpid);
  /* booted OK, send all messages :) */
  end_boot();
  tp.tv_sec = 0;
  tp.tv_nsec = 10000000L;		/* 10ms timeout per full cycle */
  FOREVER
  {
    if (_got_signal)
    {
      char sf[sizeof(ifsig_t)] = {S_FLUSH};

      Set_Iface (NULL);			/* lock the dispatcher */
      /* Current is from last iface_run() so it should be valid even if dead */
      switch (_got_signal)
      {
	case SIGHUP:
	  if (lastdebuglog)			/* restart lastdebuglog */
	    fclose (lastdebuglog);
	  if (O_DDLOG)
	    lastdebuglog = fopen ("foxeye.debug", "a");
	  Add_Request (I_LOG, "*", F_BOOT, "Got SIGHUP: rehashing...");
	  Add_Request (-1, "*", F_SIGNAL, sf);	/* flush all interfaces */
	  break;
	case SIGINT:
	  Add_Request (I_LOG, "*", F_BOOT, "Got SIGINT: restarting...");
	  for (i = 0; i < _Inum; i++)		/* mark all listeners to die */
	    if (Interface[i]->a.ift & I_CONNECT)
	      Interface[i]->a.ift |= I_FINWAIT;	/* modules: unset flag later */
	  ShutdownR = "Restart requested.";
	  init();				/* restart */
	  ShutdownR = NULL;
	  break;
	case SIGTERM:
	default:
	  bot_shutdown ("Got SIGTERM, shutdown...", 0);
      }
      _got_signal = 0;				/* reset state now */
      Unset_Iface();				/* continue if alive yet */
    }
    pthread_mutex_lock (&LockIface);
    max = _Inum;
    pthread_mutex_unlock (&LockIface);
    if (i >= max)
    {
      /* some cleanup stuff */
      i = 0;
      count = 0;
      nanosleep (&tp, NULL);
    }
    if (!i)
    {
      /* check forced queues */
      for (; count < max; count++)
      {
	register int n;

	pthread_mutex_lock (&LockIface);
	n = Interface[count]->a.qsize;
	pthread_mutex_unlock (&LockIface);
	if (n > (max >> 2) + 1)		/* criteria for forcing */
	  break;
      }
      if (count < max)
      {
	iface_run (count++);		/* run forced and go on */
	continue;
      }
      /* all queue depth ok! */
    }
    /* check all interfaces */
    iface_run (i);
    i++;
  }
  /* not reached */
}
