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
 * Here is a main bot loop
 */

#include "foxeye.h"

#include <pthread.h>
#include <signal.h>

#define DISPATCHER_C 1

#include "init.h"
#include "wtmp.h"
#include "tree.h"
#include "conversion.h"

typedef struct queue_t
{
  REQUEST *request;
  struct queue_t *next;
} queue_t;

typedef struct ifi_t
{
  INTERFACE a;					/* must be first! */
  queue_t *queue;
  queue_t *pq;
} ifi_t;

/* since Nick is undeclared for "dispatcher.c"... */
extern char Nick[NAMEMAX+1];
extern char *ShutdownR;

static queue_t *Queue = NULL;
static unsigned int _Qalloc = 0;
static unsigned int _Qnum = 0;

static ifi_t **Interface = NULL;
static unsigned int _Ialloc = 0;
static unsigned int _Inum = 0;

static NODE *ITree = NULL;

static INTERFACE _FromGone = {0, "?", NULL, NULL, NULL, NULL, NULL};

static INTERFACE *Current;
static ifi_t *Console = NULL;

static iftype_t if_or = 0;

static FILE *lastdebuglog = NULL;

/* lock for shutdown since it can be called any time */
/* if LockIface is set then _Inum is implicitly locked for reading */
pthread_mutex_t LockInum = PTHREAD_MUTEX_INITIALIZER;

static char PID_path[LONG_STRING];

/* locks on input: (LockIface) */
void bot_shutdown (char *message, int e)
{
  unsigned int i = 0;
  ifi_t *con = NULL;
  queue_t *q;
  ifsig_t sig;

  if (message && *message)
    ShutdownR = message;
  if (e)
    sig = S_SHUTDOWN;
  else
    sig = S_TERMINATE;
  /* set message to all queues and send S_SHUTDOWN signal */
  pthread_mutex_lock (&LockInum);
  /* shutdown all connections */
  for (; i < _Inum; i++)
  {
    if (Interface[i]->a.ift & I_CONSOLE)
      con = Interface[i];
    else if ((Interface[i]->a.ift & I_CONNECT) &&
	     !(Interface[i]->a.ift & I_DIED) && Interface[i]->a.IFSignal)
    {
//      DBG ("shutdown %d: 0x%x, name %s\n", i, Interface[i]->a.ift, NONULL(Interface[i]->a.name));
      Interface[i]->a.IFSignal (&Interface[i]->a, sig);
    }
  }
  /* shutdown/terminate all modules */
  for (i = 0; i < _Inum; i++)
  {
    if ((Interface[i]->a.ift & I_MODULE) && !(Interface[i]->a.ift & I_DIED) &&
	Interface[i]->a.IFSignal)
    {
//      DBG ("shutdown %d: 0x%x, name %s\n", i, Interface[i]->a.ift, NONULL(Interface[i]->a.name));
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
//      DBG ("shutdown %d: 0x%x, name %s\n", i, Interface[i]->a.ift, NONULL(Interface[i]->a.name));
      Interface[i]->a.IFSignal (&Interface[i]->a, S_SHUTDOWN);
    }
  }
  if (lastdebuglog)
  {
    fclose (lastdebuglog);
    lastdebuglog = NULL;
  }
  /* shutdown the console */
  if (con && con->a.IFSignal)
  {
    if (con->a.IFRequest)
      for (q = con->queue; q; q = q->next)
	con->a.IFRequest (&con->a, q->request);
//    fprintf (stderr, "shutdown console: 0x%x, name %s\n", con->ift, NONULL(con->name));
    con->a.IFSignal (&con->a, S_SHUTDOWN);
  }
  pthread_mutex_unlock (&LockInum);
  NewEvent (W_DOWN, ID_ME, ID_ME, e);
  if (*PID_path)
    unlink (PID_path);
  if (e)
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

static int add2queue (ifi_t *to, REQUEST *req)
{
  queue_t *newq = NULL, *curq;
  unsigned int i = 0;

  if (!req->mask_if || (to->a.ift & (I_LOCKED | I_DIED)) || !to->a.IFRequest)
    return 0;			/* request to nobody? */
  /* find free queue element */
  for (; i < _Qnum; i++)
  {
    newq = &Queue[i];
    if (!newq->request)
      break;
    newq = NULL;
  }
  /* is queue array full? */
  if (!newq)
  {
    if (_Qnum == _Qalloc)
    {
      register ssize_t diff;

      _Qalloc += 32;
      newq = Queue;
      safe_realloc ((void **)&Queue, (_Qalloc) * sizeof(queue_t));
      diff = Queue - newq;
      for (i = 0; i < _Inum; i++)
	if (Interface[i]->queue)
	  Interface[i]->queue += diff;
      for (i = 0; i < _Qnum; i++)
	if (Queue[i].next)
	  Queue[i].next += diff;
    }
    newq = &Queue[_Qnum];
    _Qnum++;
  }
  newq->request = req;
  to->pq = newq;
  if (req->flag & F_QUICK)
  {
    newq->next = to->queue;
    to->queue = newq;
    to->a.qsize++;
    return 1;
  }
  newq->next = NULL;
  curq = to->queue;
  if (!curq)
    to->queue = newq;
  else
  {
    for (; curq->next;) curq = curq->next;
    curq->next = newq;
  }
  to->a.qsize++;
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
  struct reqbl_t *next;
  unsigned int n;
  REQUEST req[REQBLSIZE];
} reqbl_t;

static reqbl_t *Request = NULL;

static REQUEST *alloc_request (void)
{
  unsigned int i;
  reqbl_t **rbl = &Request;
  REQUEST *cur = NULL;

  for (rbl = &Request; *rbl; rbl = &(*rbl)->next)
  {
    for (i = 0; i < (*rbl)->n; i++)
    {
      cur = &(*rbl)->req[i];
      if (!cur->mask_if)
	break;
      cur = NULL;
    }
    if (i < REQBLSIZE)
      break;
  }
  if (cur == NULL)
  {
    if (!*rbl)
      *rbl = safe_calloc (1, sizeof(reqbl_t));
    cur = &(*rbl)->req[(*rbl)->n++];
  }
  return cur;
}

static void vsadd_request (ifi_t *to, iftype_t ift, const char *mask,
			   flag_t flag, const char *fmt, va_list ap)
{
  REQUEST *cur = NULL;
  char *ch;
  unsigned int i = 0, n, ii;
#ifdef HAVE_ICONV
  conversion_t *conv = NULL;
  REQUEST *req = NULL; /* will be initialized but make compiler happy */
  size_t s;
#endif

  if (!ift || !Current)		/* special case */
    return;			/* request to nobody? */
  if (lastdebuglog && (ift & I_LOG) && !(flag & F_DEBUG))
  {
    fprintf (lastdebuglog, ":%08x:", flag);
    vfprintf (lastdebuglog, fmt, ap);
    fprintf (lastdebuglog, "\n");
    fflush (lastdebuglog);
  }
  cur = alloc_request();
  strfcpy (cur->to, NONULL(mask), sizeof(cur->to));
  cur->mask_if = (ift & ~I_PENDING);	/* reset it anyway */
  cur->from = Current;
  cur->flag = flag;
  vsnprintf (cur->string, sizeof(cur->string), fmt, ap);
  if (!(flag & F_DEBUG))
  {
    dprint (5, "dispatcher:vsadd_request: to=\"%s\" flags=0x%x message=\"%s\"",
	    cur->to, flag, cur->string);
  }
  /* check for flags and matching */
  n = 0;
  if (to)
    n = add2queue (to, cur);
  else if (Have_Wildcard (cur->to) < 0)
  {
    LEAF *l = NULL;

    while ((l = _find_itree (ift, "*", l))) /* check for special name "*" */
      n += add2queue (l->s.data, cur);
    while ((l = _find_itree (ift, cur->to, l))) /* check for exact name */
      n += add2queue (l->s.data, cur);
    if (!n && (ch = strrchr(cur->to, '@'))) /* handle client@service */
    {
      for (i = 0; i < _Inum; i++)	/* relay it to collector if there is one */
      {
	if ((Interface[i]->a.ift & ift) && match (ch, Interface[i]->a.name) > 1)
	  n += add2queue (Interface[i], cur);
      }
    }
  }
  else /* mask have wildcards */
    for (i = 0; i < _Inum; i++)
    {
      if (Interface[i] == Console && (Interface[i]->a.ift & ift))
	Console->a.IFRequest (&Console->a, cur);	/* if forced */
      else if ((Interface[i]->a.ift & ift) &&
	       match (mask, Interface[i]->a.name) >= 0)
	n += add2queue (Interface[i], cur);
    }
  ift &= ~I_PENDING;
  ii = _Inum;
  for (i = 0; n && i < _Inum; )		/* check for pending reqs */
  {
    if (Interface[i]->pq)
    {
#ifdef HAVE_ICONV
      if (Interface[i]->a.conv)		/* no conversion, skip it */
      {
	if (!conv)
	{
	  conv = Interface[i]->a.conv;
	  req = alloc_request();
	  strfcpy (req->to, NONULL(mask), sizeof(req->to));
	  req->mask_if = ift;
	  req->from = Current;
	  req->flag = flag;		/* new request prepared, convert it */
	  ch = req->string;
	  s = Undo_Conversion (conv, &ch, sizeof(req->string) - 1, cur->string,
			       strlen (cur->string));
	  ch[s] = 0;
	  Interface[i]->pq->request = req;
	}
	else if (Interface[i]->a.conv == conv)
	  Interface[i]->pq->request = req;	/* it's ready */
	else if (ii > i)
	  ii = i;			/* different charset */
      }
#endif
      Interface[i]->pq = NULL;
      n--;
    }
    Interface[i++]->a.ift &= ~I_PENDING;
#ifdef HAVE_ICONV
    if (i == _Inum)
    {
      i = ii;
      ii = _Inum;
      conv = NULL;
    }
#endif
  }
}

static int delete_request (queue_t *q)
{
  queue_t **last;
  REQUEST *req;
  unsigned int i;

  last = &((ifi_t *)Current)->queue;
  for ( ; *last && *last != q; last = &(*last)->next);
  /* delete from current queue first */
  if (!*last)
    return 0;
  req = q->request;
  *last = q->next;
  q->request = NULL;
  /* ok, now check the all requests */
  for (i = 0; i < _Inum; i++)
  {
    q = Interface[i]->queue;
    while (q && (q->request != req))
      q = q->next;
    if (q)
      break;
  }
  /* if this request is last, mark it as unused */
  if (q == NULL)
    req->mask_if = 0;
  Current->qsize--;
  return 1;
}

static int relay_request (REQUEST *req)
{
  unsigned int i = 0;

  if (!req || !req->mask_if)
    return 1;			/* request to nobody? */
  /* check for flags and matching, don't relay back */
  for (i = 0; i < _Inum; i++)
  {
    if ((Interface[i]->a.ift & req->mask_if) &&
	(Interface[i] != (ifi_t *)Current) &&
	match (req->to, Interface[i]->a.name) >= 0)
      add2queue (Interface[i], req);
  }
  return 1;
}

static int _get_current (void)
{
  int out;
  queue_t *curq = ((ifi_t *)Current)->queue;

  /* interface may be unused so lock semaphore */
  if (!Current->ift || (Current->ift & I_DIED))
    return 0;
  if (!Current->IFRequest)
    out = REQ_OK;
  else if (curq)
  {
    ((ifi_t *)Current)->queue = curq->next;	/* to allow recursion */
    out = Current->IFRequest (Current, curq->request);
    curq->next = ((ifi_t *)Current)->queue;	/* restore status-quo */
    ((ifi_t *)Current)->queue = curq;
  }
  else
    out = Current->IFRequest (Current, NULL);

  if (out == REQ_RELAYED && relay_request (curq->request))
    out = REQ_OK;

  if (out == REQ_OK)
    return delete_request (curq);		/* else it was rejected */

  return 0;
}

static int unknown_iface (INTERFACE *cur)
{
  register unsigned int i = 0;
  if (cur)
    for (; i < _Inum; i++)
      if (Interface[i] == (ifi_t *)cur)
	return 0;
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

/* locks on input: (LockIface) */
static unsigned int IF_add (INTERFACE *iface)
{
  register unsigned int i;

  pthread_mutex_lock (&LockIface);
  i = _Inum;
  if (i == _Ialloc)
  {
    _Ialloc += 16;
    safe_realloc ((void **)&Interface, (_Ialloc) * sizeof(ifi_t *));
  }
  Interface[i] = safe_calloc (1, sizeof(ifi_t));
  Interface[i]->a.name = safe_strdup (NONULL((char *)iface->name));
  Interface[i]->a.IFSignal = iface->IFSignal;
  Interface[i]->a.ift = (iface->ift | if_or);
  Interface[i]->a.IFRequest = iface->IFRequest;
  Interface[i]->a.data = iface->data;
#ifdef HAVE_ICONV
  Interface[i]->a.conv = NULL;
#endif
  pthread_mutex_lock (&LockInum);
  if (i == _Inum)
    _Inum++;
  pthread_mutex_unlock (&LockInum);
  if (Interface[i]->a.name)
    if (Insert_Key (&ITree, Interface[i]->a.name, Interface[i], 0))
      ERROR ("interface add: dispatcher tree error");
  pthread_mutex_unlock (&LockIface);
  dprint (2, "added iface %u: 0x%x name \"%s\"", i, Interface[i]->a.ift,
	  NONULL((char *)Interface[i]->a.name));
  return i;
}

/* locks on input: (LockIface) */
INTERFACE *
Add_Iface (iftype_t ift, const char *name, iftype_t (*sigproc) (INTERFACE*, ifsig_t),
	   int (*reqproc) (INTERFACE *, REQUEST *), void *data)
{
  INTERFACE new;
  register unsigned int i;

  new.ift = ift;
  new.name = (char *)name;
  new.IFSignal = sigproc;
  new.IFRequest = reqproc;
  new.data = data;
  i = IF_add (&new);
  return (&Interface[i]->a);
}

static void _delete_iface (unsigned int r)
{
  register unsigned int i;
  register reqbl_t *rbl;

  for (rbl = Request; rbl; rbl = rbl->next)
    for (i = 0; i < rbl->n; i++)	/* well, IFSignal could sent anything */
      if (rbl->req[i].from == Current)
	rbl->req[i].from = &_FromGone;
  if (Current->prev && Current->prev->IFSignal && /* resume if nested */
      Current->prev->IFSignal (Current->prev, S_CONTINUE) == I_DIED)
    Current->prev->ift |= I_DIED;
  dprint (2, "deleting iface %u of %u: name \"%s\"", r, _Inum,
	  NONULL((char *)Current->name));
  if (Current->name)
    Delete_Key (ITree, Current->name, ((ifi_t *)Current));
  FREE (&Current->name);
  safe_free (&Current->data);
#ifdef HAVE_ICONV
  Free_Conversion (Current->conv);
#endif
  while (delete_request (((ifi_t *)Current)->queue));
  pthread_mutex_lock (&LockInum);
  _Inum--;
  if (r < _Inum)
    Interface[r] = Interface[_Inum];
  pthread_mutex_unlock (&LockInum);
  FREE (&Current);
  if (r < _Inum)
    Current = (INTERFACE *)Interface[r];
}

/* locks on input: none */
static void iface_run (unsigned int i)
{
  pthread_mutex_lock (&LockIface);
  /* we are died? OOPS... */
  if (i < _Inum)
    Current = (INTERFACE *)Interface[i];
  while (i < _Inum && (Current->ift & I_DIED))
    _delete_iface (i);
  if (lastdebuglog)
  {
    fprintf (lastdebuglog, "%x", i);
    fflush (lastdebuglog);
  }
  /* all rest are died? return now! */
  if (i < _Inum && !(Current->ift & I_LOCKED))
    _get_current();			/* run with LockIface only */
  pthread_mutex_unlock (&LockIface);
}

INTERFACE *OldCurrent = NULL;

/* locks on input: (LockIface) */
void Add_Request (iftype_t ift, char *mask, flag_t fl, const char *text, ...)
{
  va_list ap;
  register unsigned int i;
  unsigned int inum;
  INTERFACE *tmp;

  /* request to nobody? */
  if (!ift)
    return;
  pthread_mutex_lock (&LockIface);
  tmp = OldCurrent;				/* to nice Set_Iface() */
  OldCurrent = NULL;
  /* if F_SIGNAL text is binary! */
  if (fl & F_SIGNAL)
  {
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
	  match (mask, Interface[i]->a.name) >= 0)
      {
	/* request is a signal - it may die */
	if (Interface[i]->a.IFSignal (&Interface[i]->a, (ifsig_t)text[0]) == I_DIED)
	  Interface[i]->a.ift |= I_DIED;
      }
    }
  }
  else
  {
    va_start (ap, text);
    vsadd_request (NULL, ift, mask, fl, text, ap);
    va_end (ap);
  }
  OldCurrent = tmp;
  pthread_mutex_unlock (&LockIface);
}

/* locks on input: (LockIface) */
void New_Request (INTERFACE *cur, flag_t fl, const char *text, ...)
{
  va_list ap;
  INTERFACE *tmp;

  pthread_mutex_lock (&LockIface);
  tmp = OldCurrent;				/* to nice Set_Iface() */
  OldCurrent = NULL;
  /* request to nobody? */
  if (!cur || (cur->ift & I_DIED) || unknown_iface (cur));
  /* if F_SIGNAL text is binary! */
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
  OldCurrent = tmp;
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
  if (!OldCurrent)			/* if already set - return NULL */
  {
    OldCurrent = Current;
    if (unknown_iface (newif))		/* if unknown - don't change */
      OldCurrent = NULL;		/* but return NULL */
    else
      Current = newif;
  }
  return OldCurrent;
}

int Unset_Iface (void)
{
  if (OldCurrent)			/* if already unset - don't change */
  {
    Current = OldCurrent;
    OldCurrent = NULL;
  }
  pthread_mutex_unlock (&LockIface);
  return 0;
}

/* find the interface with name exatly matched
   NULL is special case - check if any iface that type exist */
/* locks on input: (LockIface) */
/* locks on return: LockIface - if found */
INTERFACE *Find_Iface (iftype_t ift, const char *name)
{
  LEAF *l;
  ifi_t *i = NULL;
  int n;

  pthread_mutex_lock (&LockIface);
  if (name == NULL)
  {
    for (n = 0; n < _Inum; n++)
      if ((Interface[n]->a.ift & ift) && !(Interface[n]->a.ift & I_DIED))
      {
	i = Interface[n];
	break;
      }
  }
  else if ((l = _find_itree (ift, name, NULL)))	/* find first matched */
    i = l->s.data;
  dprint (3, "search for iface 0x%x name \"%s\": %s", ift, NONULL(name),
	  i ? (char *)i->a.name : "<none>");
  if (i)
    return &i->a;
  pthread_mutex_unlock (&LockIface);
  return NULL;
}

int Rename_Iface (iftype_t ift, const char *oldname, const char *newname)
{
  unsigned int i;
  queue_t *q;

  pthread_mutex_lock (&LockIface);
  for (i = 0; i < _Inum; i++)
    if ((Interface[i]->a.ift & ift) &&
	!safe_strcmp (Interface[i]->a.name, oldname))
    {
      dprint (2, "renaming iface %u: \"%s\" --> \"%s\"", i,
	      Interface[i]->a.name, newname);
      if (Interface[i]->a.name)
	Delete_Key (ITree, Interface[i]->a.name, Interface[i]);
      FREE (&Interface[i]->a.name);
      Interface[i]->a.name = safe_strdup (newname);
      if (Interface[i]->a.name &&
	  Insert_Key (&ITree, Interface[i]->a.name, Interface[i], 0))
	ERROR ("interface add: dispatcher tree error");
      for (q = Interface[i]->queue; q; q = q->next)
	if (q->request && !safe_strcmp (q->request->to, oldname))
	  strfcpy (q->request->to, newname, sizeof(q->request->to));
      if (Interface[i]->a.IFSignal &&
	  Interface[i]->a.IFSignal (&Interface[i]->a, S_FLUSH) == I_DIED)
	Interface[i]->a.ift |= I_DIED;
      pthread_mutex_unlock (&LockIface);
      return 1;
    }
  pthread_mutex_unlock (&LockIface);
  return 0;
}

void Status_Interfaces (INTERFACE *iface)
{
  register int i;

  pthread_mutex_lock (&LockIface);
  for (i = 0; i < _Inum; i++)
  {
    New_Request (iface, 0, "interface %d: flags 0x%x (%s%s), name %s, queue size %d",
		i, Interface[i]->a.ift, Interface[i]->a.IFSignal ? "S":"",
		Interface[i]->a.IFRequest ? "R":"",
		NONULL((char *)Interface[i]->a.name), Interface[i]->a.qsize);
  }
  pthread_mutex_unlock (&LockIface);
}

static ifi_t *_Boot;

static int _b_stub (INTERFACE *iface, REQUEST *req) { return 0; }

/* start the empty interface that will collect all boot messages */
static void start_boot (void)
{
  Current = Add_Iface (~I_CONSOLE & ~I_INIT & ~I_DIED & ~I_LOCKED, "*",
		       NULL, &_b_stub, NULL);
  _Boot = (ifi_t *)Current;
  if_or = I_LOCKED;
}

/* bounce boot requests to interfaces with F_BOOT */
static void end_boot (void)
{
  INTERFACE *con = Find_Iface (I_CONSOLE, "");	/* locked now! */
  unsigned int i;

  if_or = 0;
  Current = (INTERFACE *)_Boot;
  dprint (4, "end_boot: unlock %u interfaces (but console and init)", _Inum);
  for (i = 0; i < _Inum; i++)
    if (!(Interface[i]->a.ift & (I_CONSOLE | I_INIT)))
      Interface[i]->a.ift &= ~I_LOCKED;
  if (con)
    con->ift |= I_LOCKED;
  while (_Boot->queue)
  {
    relay_request (_Boot->queue->request);
    delete_request (_Boot->queue);
  }
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
      norm_exit = 0;
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
  act.sa_handler = &errors_handler;
  sigemptyset (&act.sa_mask);
  act.sa_flags = 0;
  sigaction (SIGQUIT, &act, NULL);	/* catch these signals */
  sigaction (SIGILL, &act, NULL);
  sigaction (SIGFPE, &act, NULL);
  sigaction (SIGSEGV, &act, NULL);
#ifdef SIGBUS
  sigaction (SIGBUS, &act, NULL);
#endif
#ifdef SIGSYS
  sigaction (SIGSYS, &act, NULL);
#endif
  sigaction (SIGTERM, &act, NULL);
  act.sa_handler = SIG_IGN;
  sigaction (SIGPIPE, &act, NULL);	/* ignore these signals */
  sigaction (SIGUSR1, &act, NULL);
  sigaction (SIGUSR2, &act, NULL);
  sigaction (SIGINT, &act, NULL);	/* these will catched by init() */
  sigaction (SIGHUP, &act, NULL);
  /* wait a debugger :) */
  if (O_WAIT)
    while (!limit);
  /* init recursive LockIface - Unix98 only */
  pthread_mutexattr_init (&attr);
  pthread_mutexattr_settype (&attr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init (&LockIface, &attr);
  /* add console interface if available */
  if (start_if)
  {
    max = IF_add (start_if);
    Console = Interface[max];		/* start forcing the console */
  }
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
    if (Console->a.ift & I_LOCKED)
      Console->a.ift = I_DIED; /* died already? */
    else
      Console->a.ift |= I_DCCALIAS;
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
