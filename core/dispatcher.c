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
 * Here is a main bot loop
 */

#include "foxeye.h"

#include <pthread.h>
#include <signal.h>

#define DISPATCHER_C 1

#include "init.h"
#include "wtmp.h"

/* since Nick is undeclared for "dispatcher.c"... */
extern char Nick[NICKMAX+1];

static QUEUE *Queue = NULL;
static unsigned int _Qalloc = 0;
static unsigned int _Qnum = 0;

static REQUEST *Request = NULL;
static unsigned int _Ralloc = 0;
static unsigned int _Rnum = 0;

static INTERFACE **Interface = NULL;
static unsigned int _Ialloc = 0;
static unsigned int _Inum = 0;

static INTERFACE _FromGone = {0, "?", NULL, NULL, NULL, NULL, NULL};

static INTERFACE *Current;
static INTERFACE *Console = NULL;

static iface_t if_or = 0;

/* lock for shutdown since it can be called any time */
/* if LockIface is set then _Inum is implicitly locked for reading */
pthread_mutex_t LockInum = PTHREAD_MUTEX_INITIALIZER;

static char PID_path[LONG_STRING];

/* locks on input: (LockIface) */
void bot_shutdown (char *message, int e)
{
  unsigned int i = 0;
  INTERFACE *con = NULL;
  QUEUE *q;

  if (message && *message)
    BindResult = message;
  else
    BindResult = NULL;
  /* set message to all queues and send S_SHUTDOWN signal */
  pthread_mutex_lock (&LockInum);
  /* shutdown all but no files nor the console */
  for (; i < _Inum; i++)
  {
    if (Interface[i]->iface & I_CONSOLE)
      con = Interface[i];
    else if (!(Interface[i]->iface & I_FILE) && Interface[i]->IFSignal)
    {
      fprintf (stderr, "shutdown %d: 0x%x, name %s\n", i, Interface[i]->iface, NONULL(Interface[i]->name));
      Interface[i]->IFSignal (Interface[i], S_SHUTDOWN);
    }
  }
  /* shutdown all files */
  for (i = 0; i < _Inum; i++)
  {
    if ((Interface[i]->iface & I_FILE) && Interface[i]->IFSignal)
    {
      fprintf (stderr, "shutdown %d: 0x%x, name %s\n", i, Interface[i]->iface, NONULL(Interface[i]->name));
      Interface[i]->IFSignal (Interface[i], S_SHUTDOWN);
    }
  }
  /* shutdown the console */
  if (con && con->IFSignal)
  {
    if (con->IFRequest)
      for (q = con->queue; q; q = q->next)
	con->IFRequest (con, q->request);
    fprintf (stderr, "shutdown console: 0x%x, name %s\n", con->iface, NONULL(con->name));
    con->IFSignal (con, S_SHUTDOWN);
  }
  pthread_mutex_unlock (&LockInum);
  NewEvent (W_DOWN, NULL, NULL, e);
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
 *    блокируется отдельной блокировкой. Для основного потока - это
 *    блокировка чтения, пока снята LockIface.
 * 3) Из ->IFRequest() и ->IFSignal все публичные поля всех интерфейсов
 *    доступны как на чтение, так и на запись.
 * 4) После того, как запрос записан в очередь, он считается const, изменять
 *    его интерфейсы могут только на свой страх и риск.
 */

static pthread_mutex_t LockIface;

static int add2queue (INTERFACE *to, REQUEST *req)
{
  QUEUE *newq = NULL, *curq;
  unsigned int i = 0;

  if (!req->mask_if || (to->iface & (I_LOCKED | I_DIED)) || !to->IFRequest)
    return 0;			/* request to nobody? */
  /* find free queue element */
  for (; i < _Qnum; i++)
  {
    newq = &Queue[i];
    if (!newq->request)
      break;
    newq = NULL;
  }
  /* queue array full? */
  if (!newq)
  {
    if (_Qnum == _Qalloc)
    {
      register ssize_t diff;

      _Qalloc += 32;
      newq = Queue;
      safe_realloc ((void **)&Queue, (_Qalloc) * sizeof(QUEUE));
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
  if (req->flag & F_QUICK)
  {
    newq->next = to->queue;
    to->queue = newq;
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
  return 1;
}

static REQUEST *IFStub (INTERFACE *iface, REQUEST *req)
{
  if (req)
  {
    req->flag |= F_RELAYED;
    req->mask_if &= ~I_ENCRYPT;
  }
  return req;
}

static void vsadd_request (INTERFACE *to, iface_t iface, const char *mask,
			   flag_t flag, char *fmt, va_list ap)
{
  REQUEST *cur = NULL;
  unsigned int i = 0, n = 0;
  iface_t fl = iface;

  if (!iface || !Current)	/* special case */
    return;			/* request to nobody? */
  if ((iface & I_BOT) || (Current->iface & I_BOT))
    fl = I_ENCRYPT;		/* special support for encryption module */
  if ((iface & I_BOT) && (Current->iface & I_BOT))
  {
    vsadd_request (to, iface & ~I_BOT, mask, flag, fmt, ap);
    fl = iface = I_BOT;		/* don't encrypt bot->bot traffic */
  }
  for (; i < _Rnum; i++)
  {
    cur = &Request[i];
    if (!cur->mask_if)
      break;
    cur = NULL;
  }
  if (cur == NULL)
  {
    if (_Rnum == _Ralloc)
    {
      register ssize_t diff;

      _Ralloc += 32;
      cur = &Request[0];
      safe_realloc ((void **)&Request, _Ralloc * sizeof(REQUEST));
      diff = Request - cur;
      for (i = 0; i < _Qnum; i++)
	if (Queue[i].request)
	  Queue[i].request += diff;
    }
    cur = &Request[_Rnum];
    _Rnum++;
  }
  strfcpy (cur->mask, NONULL(mask), sizeof(cur->mask));
  cur->mask_if = iface;
  cur->from = Current;
  cur->flag = flag;
  vsnprintf (cur->string, sizeof(cur->string), fmt, ap);
  /* check for flags and matching, encrypt module matched always */
  if (to)
    n = add2queue (to, cur);
  else
    for (i = 0; i < _Inum; i++)
    {
      if (Interface[i] == Console && (Interface[i]->iface & fl))
	Console->IFRequest (Console, cur);	/* if forced */
      else if ((Interface[i]->iface & fl) &&
	       (fl == I_ENCRYPT || match (mask, Interface[i]->name) >= 0))
	n += add2queue (Interface[i], cur);
    }
  if (!n)			/* if no matching interface - sorry */
    cur->mask_if = 0;
}

static int delete_request (QUEUE *q)
{
  QUEUE **last;
  REQUEST *req;
  unsigned int i;

  for (last = &Current->queue; *last && *last != q; last = &(*last)->next);
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
  return 1;
}

static int relay_request (void)
{
  unsigned int i = 0;
  REQUEST *req;
  iface_t fl = I_ENCRYPT;

  if (!Current->queue || !Current->queue->request ||
      !Current->queue->request->mask_if)
    return 0;			/* request to nobody? */
  req = Current->queue->request;
  req->flag &= ~F_RELAYED;
  if (!(fl & req->mask_if))	/* special support for encryption module */
    fl = req->mask_if;		/* if don't relayed to encrypt */
  /* check for flags and matching, don't relay to me 
   * encrypt module matched always */
  for (i = 0; i < _Inum; i++)
  {
    if ((Interface[i]->iface & fl) && (Interface[i] != Current) &&
	(fl == I_ENCRYPT || match (req->mask, Interface[i]->name) >= 0))
      add2queue (Interface[i], req);
  }
  return 1;
}

static int _get_current (void)
{
  REQUEST *out;
  QUEUE *curq = Current->queue;
  int i = 0;

  /* interface may be unused so lock semaphore */
  if (!Current->iface || (Current->iface & I_DIED))
    return i;
  if (!Current->IFRequest)
    out = NULL;
  else if (curq)
    out = Current->IFRequest (Current, curq->request);
  else
    out = Current->IFRequest (Current, NULL);

  if (out && (out->flag & F_RELAYED) && relay_request())
    out = NULL;

  if (!out)
    i = delete_request (curq);
  else if (out->mask_if & I_DIED)
    Current->iface |= I_DIED;
  else if (!(out->flag & F_REJECTED))
  {
    i = delete_request(curq);
    Add_Request (out->mask_if, out->mask, out->flag, out->string);
  }
  else
    out->flag &= ~F_REJECTED;

  return i;
}

static int unknown_iface (INTERFACE *cur)
{
  register unsigned int i = 0;
  if (cur)
    for (; i < _Inum; i++)
      if (Interface[i] == cur)
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
  return i;
}

/* locks on input: (LockIface) */
static unsigned int IF_add (INTERFACE *iface)
{
  register unsigned int i;

  pthread_mutex_lock (&LockIface);
  /* for encryption module just replace old */
  if (iface->iface & I_ENCRYPT)
    for (i = 0; i < _Inum && !(Interface[i]->iface & I_ENCRYPT); i++);
  else
    i = _Inum;
  if (i == _Ialloc)
  {
    _Ialloc += 16;
    safe_realloc ((void **)&Interface, (_Ialloc) * sizeof(INTERFACE *));
  }
  Interface[i] = safe_calloc (1, sizeof(INTERFACE));
  Interface[i]->name = safe_strdup (NONULL(iface->name));
  Interface[i]->IFSignal = iface->IFSignal;
  Interface[i]->iface = (iface->iface | if_or);
  Interface[i]->IFRequest = iface->IFRequest;
  Interface[i]->data = iface->data;
  pthread_mutex_lock (&LockInum);
  if (i == _Inum)
    _Inum++;
  pthread_mutex_unlock (&LockInum);
  pthread_mutex_unlock (&LockIface);
  dprint (1, "added iface %u: 0x%x name \"%s\"", i, Interface[i]->iface,
	  Interface[i]->name);
  return i;
}

/* locks on input: (LockIface) */
INTERFACE *
Add_Iface (const char *name, iface_t iface, iface_t (*sigproc) (INTERFACE*, ifsig_t),
	   REQUEST * (*reqproc) (INTERFACE *, REQUEST *), void *data)
{
  INTERFACE new;
  register unsigned int i;

  new.iface = iface;
  new.name = (char *)name;
  new.IFSignal = sigproc;
  new.IFRequest = reqproc;
  new.data = data;
  i = IF_add (&new);
  return (Interface[i]);
}

static void _delete_iface (unsigned int r)
{
  register unsigned int i = 0;

  if (Current->IFSignal)		/* send the S_TERMINATE */
    Current->IFSignal (Current, S_TERMINATE);
  for (i = 0; i < _Rnum; i++)		/* well, IFSignal could sent anything */
    if (Request[i].from == Current)
      Request[i].from = &_FromGone;
  dprint (1, "deleting iface %u: 0x%x name \"%s\"", r, Current->iface,
	  Current->name);
  FREE (&Current->name);
  safe_free (&Current->data);
  if (Current->iface & I_ENCRYPT)
  {
    Current->IFSignal = NULL;
    Current->IFRequest = &IFStub;
    return;
  }
  while (delete_request (Current->queue));
  pthread_mutex_lock (&LockInum);
  FREE (&Interface[r]);
  _Inum--;
  if (r < _Inum)
    Interface[r] = Interface[_Inum];
  pthread_mutex_unlock (&LockInum);
  Current = Interface[r];
}

/* locks on input: none */
static void iface_run (unsigned int i)
{
  pthread_mutex_lock (&LockIface);
  /* we are died? OOPS... */
  Current = Interface[i];
  while (Current && (Current->iface & I_DIED))
    _delete_iface (i);
  /* all rest are died? return now! */
  if (i < _Inum && !(Current->iface & I_LOCKED))
    _get_current();			/* run with LockIface only */
  pthread_mutex_unlock (&LockIface);
}

INTERFACE *OldCurrent = NULL;

/* locks on input: (LockIface) */
void Add_Request (iface_t iface, char *mask, flag_t fl, char *text, ...)
{
  va_list ap;
  register unsigned int i;
  INTERFACE *tmp;

  /* request to nobody? */
  if (!iface)
    return;
  pthread_mutex_lock (&LockIface);
  tmp = OldCurrent;				/* to nice Set_Iface() */
  OldCurrent = NULL;
  /* if F_SIGNAL text is binary! */
  if (fl & F_SIGNAL)
  {
    for (i = 0; i < _Inum; i++)			/* check for if_or because */
    {						/* you need to get signals */
      if ((Interface[i]->iface & iface) && Interface[i]->IFSignal &&
	  !(Interface[i]->iface & ~if_or & (I_DIED | I_LOCKED)) &&
	  match (mask, Interface[i]->name) >= 0)
      {
	/* request is a signal - interface may die? */
	if (Interface[i]->IFSignal (Interface[i], (ifsig_t)text[0]) == I_DIED)
	  Interface[i]->iface |= I_DIED;
      }
    }
  }
  else
  {
    va_start (ap, text);
    vsadd_request (NULL, iface, mask, fl, text, ap);
    va_end (ap);
  }
  OldCurrent = tmp;
  pthread_mutex_unlock (&LockIface);
}

/* locks on input: (LockIface) */
void New_Request (INTERFACE *cur, flag_t fl, char *text, ...)
{
  va_list ap;
  INTERFACE *tmp;

  pthread_mutex_lock (&LockIface);
  tmp = OldCurrent;				/* to nice Set_Iface() */
  OldCurrent = NULL;
  /* request to nobody? */
  if (!cur || (cur->iface & I_DIED) || unknown_iface (cur));
  /* if F_SIGNAL text is binary! */
  else if (fl & F_SIGNAL)
  {
    if (cur->IFSignal && !(cur->iface & (I_DIED | I_LOCKED)) &&
	cur->IFSignal (cur, (ifsig_t)text[0]) == I_DIED)
	cur->iface |= I_DIED;
  }
  else
  {
    va_start (ap, text);
    vsadd_request (cur, cur->iface, cur->name, fl, text, ap);
    va_end (ap);
  }
  OldCurrent = tmp;
  pthread_mutex_unlock (&LockIface);
}

/* locks on input: (LockIface) */
void notice2nick (char *nick, char *text, ...)
{
  va_list ap;

  va_start (ap, text);
  pthread_mutex_lock (&LockIface);
  vsadd_request (NULL, I_SERVMSG, (char *)nick, F_NOTICE, text, ap);
  pthread_mutex_unlock (&LockIface);
  va_end (ap);
}

/* locks on input: (LockIface) */
void msg2nick (char *nick, char *text, ...)
{
  va_list ap;

  va_start (ap, text);
  pthread_mutex_lock (&LockIface);
  vsadd_request (NULL, I_SERVMSG, (char *)nick, F_MSGS, text, ap);
  pthread_mutex_unlock (&LockIface);
  va_end (ap);
}

/* locks on input: (LockIface) */
void dprint (int level, char *text, ...)
{
  va_list ap;

  if (level > O_DLEVEL || !Interface)
    return;
  va_start (ap, text);
  pthread_mutex_lock (&LockIface);
  vsadd_request (NULL, I_LOG, "*", F_DEBUG, text, ap);
  pthread_mutex_unlock (&LockIface);
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
INTERFACE *Find_Iface (iface_t iface, const char *name)
{
  unsigned int i;

  pthread_mutex_lock (&LockIface);
  for (i = 0; i < _Inum; i++)
    if ((Interface[i]->iface & iface) &&
	!(Interface[i]->iface & I_DIED) &&
	(!name || !safe_strcmp (Interface[i]->name, name)))
      break;
  dprint (3, "search for iface 0x%x name \"%s\": %d", iface, name,
	  i < _Inum ? i : -1);
  if (i < _Inum)
    return Interface[i];
  pthread_mutex_unlock (&LockIface);
  return NULL;
}

int Rename_Iface (iface_t ift, const char *oldname, const char *newname)
{
  unsigned int i;
  QUEUE *q;

  pthread_mutex_lock (&LockIface);
  for (i = 0; i < _Inum; i++)
    if ((Interface[i]->iface & ift) && !safe_strcmp (Interface[i]->name, oldname))
    {
      dprint (1, "renaming iface %u: \"%s\" --> \"%s\"", i, Interface[i]->name,
	      newname);
      FREE (&Interface[i]->name);
      Interface[i]->name = safe_strdup (newname);
      for (q = Interface[i]->queue; q; q = q->next)
	if (q->request && !safe_strcmp (q->request->mask, oldname))
	  strfcpy (q->request->mask, newname, sizeof(q->request->mask));
      if (Interface[i]->IFSignal)
	Interface[i]->IFSignal (Interface[i], S_FLUSH);
      pthread_mutex_unlock (&LockIface);
      return 1;
    }
  pthread_mutex_unlock (&LockIface);
  return 0;
}

void Status_Interfaces (INTERFACE *iface)
{
  register int i, n;
  QUEUE *q;

  pthread_mutex_lock (&LockIface);
  for (i = 0; i < _Inum; i++)
  {
    for (n = 0, q = Interface[i]->queue; q; n++) q = q->next;
    New_Request (iface, 0, "interface %d: flags 0x%x (%s%s), name %s, queue size %d",
		i, Interface[i]->iface, Interface[i]->IFSignal ? "S":"",
		Interface[i]->IFRequest ? "R":"", NONULL(Interface[i]->name), n);
  }
  pthread_mutex_unlock (&LockIface);
}

static INTERFACE *_Boot;

/* start the empty interface that will collect all boot messages */
static void start_boot (void)
{
  _Boot = Add_Iface ("*", ~I_CONSOLE & ~I_INIT, NULL, NULL, NULL);
  if_or = I_LOCKED;
}

/* bounce boot requests to interfaces with F_BOOT */
static void end_boot (void)
{
  INTERFACE *con = Find_Iface (I_CONSOLE, "");	/* locked now! */
  unsigned int i;

  if_or = 0;
  Current = _Boot;
  for (i = 0; i < _Inum; i++)
    if (!(Interface[i]->iface & (I_CONSOLE | I_INIT)))
      Interface[i]->iface &= ~I_LOCKED;
  if (con)
    con->iface |= I_LOCKED;
  while (relay_request())
    delete_request (_Boot->queue);
  if (con)
    con->iface &= ~I_LOCKED;
  _Boot->iface = I_DIED;
  pthread_mutex_unlock (&LockIface);
}

static void set_pid_path (void)
{
  char *ne;

  if (!*Nick || !Config)
    PID_path[0] = 0;
  /* what directory in? */
  else
    strfcpy (PID_path, Config, sizeof(PID_path) - (NICKMAX+5));
  if (!(ne = strrchr (PID_path, '/')))
  {
    ne = &PID_path[1];
    PID_path[0] = '.';
  }
  snprintf (ne, NICKMAX+6, "/%s.pid", Nick);
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
  if (!(fp = safe_fopen (PID_path, "wb")))
    return -1;
  if (!fwrite (buff, safe_strlen (buff), 1, fp))
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
  int norm_exit = 0;

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
      norm_exit = 1;
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
  unsigned int i = 0, count = 0, max;
  int limit = 0;
  INTERFACE encrypt;
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
  /* create init interface - collect all messages */
  start_boot();
  /* create empty Encrypt interface */
  memset (&encrypt, 0, sizeof(INTERFACE));
  encrypt.iface = I_ENCRYPT;
  encrypt.IFRequest = &IFStub;
  max = IF_add (&encrypt);
  Current = Interface[max];
  time (&StartTime);
  /* now we must register all common interfaces
   * which have not own interface functions */
  init();
  NewEvent (W_START, NULL, NULL, 0);	/* started ok */
  if (Console)
  {
    if (Console->iface & I_LOCKED)
      Console->iface = I_DIED;
    else
      Console->iface |= I_DCCALIAS;
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
	int n;
	QUEUE *q;

	pthread_mutex_lock (&LockIface);
	q = Interface[count]->queue;
	for (n = 0; q; n++)
	  q = q->next;			/* get depth of queue */
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
