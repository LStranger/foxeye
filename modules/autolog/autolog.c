/*
 * Copyright (C) 2006-2008  Andrej N. Gritsenko <andrej@@rep.kiev.ua>
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
 * The FoxEye autolog module - auto creating log files for client traffic.
 *   TODO: "autolog by lname" feature.
 *   TODO: "U_SECRET" feature.
 */

#include "foxeye.h"
#include "modules.h"

#include <errno.h>
#include <fcntl.h>

#include "init.h"

#define AUTOLOG_LEVELS (F_PUBLIC | F_PRIV | F_JOIN | F_MODES)
#define AUTOLOG_LEVELS2 (F_WARN | F_END)

static char autolog_ctl_prefix[32] = "-|- ";	/* prefix for notices */
static char autolog_path[128] = "~/.foxeye/logs/%@/%N";
static char autolog_serv_path[128] = "~/.foxeye/logs/%@.netlog";
static char autolog_open[64];			/* set on init */
static char autolog_close[64];
static char autolog_daychange[64];
static char autolog_timestamp[32] = "[%H:%M] ";	/* with ending space */
//static bool autolog_by_lname = TRUE;
static long int autolog_autoclose = 600;	/* in seconds */


typedef struct
{
  char *path;
  int fd;
  time_t timestamp;
  int reccount;
  int day;
  size_t inbuf;
  char buf[HUGE_STRING];
} autologdata_t;

typedef struct autolog_t
{
  autologdata_t *d;
  struct autolog_t *prev;
  INTERFACE *iface;
} autolog_t;

typedef struct autolognet_t
{
  struct autolognet_t *prev;
  INTERFACE *net;
  autolog_t *log;
} autolognet_t;


/* ----------------------------------------------------------------------------
 *	"name@network" autolog interface - handles opened logs
 */

static iftype_t _autolog_nolog_s (INTERFACE *iface, ifsig_t sig)
{
  switch (sig)
  {
    case S_FLUSH:
    case S_TERMINATE:
    case S_SHUTDOWN:
      ((autolog_t *)iface->data)->iface = NULL;
      iface->data = NULL;
      return I_DIED;
    default: ;
  }
  return 0;
}

static int flush_autolog (autologdata_t *log)
{
  size_t x;
  struct flock lck;
  int es;

  if (log->inbuf == 0)
    return 0;
  if (log->fd == -1)
    return EBADF;
  dprint (5, "autolog: trying logfile %s: %d bytes", log->path, log->inbuf);
  memset (&lck, 0, sizeof (struct flock));
  lck.l_type = F_WRLCK;
  lck.l_whence = SEEK_END;
  if (fcntl (log->fd, F_SETLK, &lck) == -1)
    return errno;		/* cannot lock the file */
  lseek (log->fd, 0, SEEK_END);
  x = write (log->fd, log->buf, log->inbuf);
  es = errno;
  lck.l_type = F_UNLCK;
  fcntl (log->fd, F_SETLK, &lck);
  if (x < 0)
    return es;			/* fatal error on write! */
  log->inbuf = 0;
  return 0;
}

#define MAXLOGQUEUE 50

static int __flush_autolog (autolog_t *log, int quiet)
{
  int x = flush_autolog (log->d);			/* try to write it */

  if (x == EACCES || x == EAGAIN)			/* file locked */
  {
    if (log->iface->qsize > MAXLOGQUEUE) /* check if it's locked too far ago */
    {
      if (!quiet)
	ERROR ("Logfile %s is locked but queue grew to %d, abort logging to it.",
	       log->d->path, log->iface->qsize);
      return -1;
    }
    return 0;
  }
  else if (x)						/* fatal error! */
  {
    if (!quiet)
    {
      strerror_r (x, log->d->buf, sizeof(log->d->buf));
      ERROR ("Couldn't write to logfile %s (%s), abort logging to it.",
	     log->d->path, log->d->buf);
    }
    return -1;
  }
  log->d->timestamp = Time;				/* all is OK */
  return 1;
}

/*
 * puts text to logfile with optional timestamp ts and prefix
 * prefix if skipped if sp==0
 * if text=="" then do nothing
 */
static int autolog_add (autolog_t *log, char *ts, char *text, size_t sp,
			struct tm *tm, int quiet)
{
  size_t ptr, sz, sts;

  if (log->d->inbuf && __flush_autolog (log, quiet) < 0)
    return -1;		/* error happened */
  if (text && text[0] == 0)
    return 1;		/* nothing to put */
  DBG ("autolog:autolog_add: to=\"%s\" text=\"%s%s%s\"", log->d->path, ts, sp ? autolog_ctl_prefix : "", NONULL(text));
  sz = safe_strlen (text);
  ptr = log->d->inbuf;
  if (ptr + sp + sz + safe_strlen (ts) + 1 >= sizeof(log->d->buf))
    return 0;		/* try assuming that timestamp is ts long */
  if (*ts)						/* do timestamp */
  {
    sts = strftime (&log->d->buf[ptr], sizeof(log->d->buf) - ptr - 1, ts, tm);
    if (sts >= sizeof(log->d->buf) - ptr)
      sts = sizeof(log->d->buf) - 1;
  }
  else
    sts = 0;
  if (ptr + sp + sz + sts + 1 >= sizeof(log->d->buf))
    return 0;		/* so we know full size so check it */
  if (sp)						/* do prefix */
    memcpy (&log->d->buf[ptr+sts], autolog_ctl_prefix, sp);
  if (sz)						/* do message itself */
    memcpy (&log->d->buf[ptr+sts+sp], text, sz);
  ptr += sts + sp + sz;
  log->d->buf[ptr++] = '\n';
  log->d->inbuf = ptr;
  if (__flush_autolog (log, quiet) < 0)
    return -1;
  DBG ("autolog:autolog_add: success");
  return 1;	/* it already in buffer */
}

/* TODO: make subdirectories for path? */
#define open_log_file(path) open (path, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP)

/* accepts: S_TERMINATE, S_SHUTDOWN, S_FLUSH */
static iftype_t _autolog_name_signal (INTERFACE *iface, ifsig_t sig)
{
  autolog_t *log = (autolog_t *)iface->data;
  struct tm tm;

  if (!(iface->ift & I_DIED)) switch (sig)	/* is it terminated already? */
  {
    case S_TIMEOUT:
      /* log is written immediately so nothing to do with cache_time */
      break;
    case S_FLUSH:
      if (iface->qsize > 0) /* so there is queue... just reopen the log file */
      {
	close (log->d->fd);
	log->d->fd = open_log_file (log->d->path);
	return 0;
      }			/* else terminate it on flush to get right timestamps */
    case S_TERMINATE:
      localtime_r (&log->d->timestamp, &tm);
      /* TODO: check if file is locked and retry? */
      autolog_add (log, autolog_close, NULL, 0, &tm, 0); /* ignored result */
      if (log->d->fd != -1)
	close (log->d->fd);
      FREE (&log->d->path);
      log->iface = NULL;
      iface->data = NULL;
      iface->ift |= I_DIED;
      return I_DIED;
    case S_SHUTDOWN:
      localtime_r (&log->d->timestamp, &tm);
      autolog_add (log, autolog_close, NULL, 0, &tm, 1); /* ignore result */
      if (log->d->fd != -1)
	close (log->d->fd);
      log->iface = NULL;
      iface->data = NULL;
      iface->ift |= I_DIED;
      return I_DIED;
    default: ;
  }
  return 0;
}

static int _autolog_name_request (INTERFACE *iface, REQUEST *req)
{
  ssize_t x;
  autolog_t *log;
  struct tm tm;

  if (req) DBG ("_autolog_name_request: message for %s", req->to);
  log = (autolog_t *)iface->data;
  if (!req || !(req->flag & (AUTOLOG_LEVELS | AUTOLOG_LEVELS2)))
  {
    if (Time - log->d->timestamp >= autolog_autoclose)	/* timeout: close log */
      iface->ift |= _autolog_name_signal (iface, S_TERMINATE);
    return REQ_OK;
  }
  localtime_r (&Time, &tm);
  if (log->d->day != tm.tm_mday)
  {
    if (*autolog_daychange &&
	autolog_add (log, autolog_daychange, NULL, 0, &tm, 0) <= 0)
    {
      iface->ift |= _autolog_name_signal (iface, S_TERMINATE);
      WARNING ("autolog:_autolog_name_request: %s terminated", iface->name);
      return REQ_REJECTED;				/* could not add it */
    }
    else
      log->d->day = tm.tm_mday;
    /* TODO: check for rotation (_autolog_makepath()...) */
  }
  x = autolog_add (log, autolog_timestamp, req->string,
		   (req->flag & F_PREFIXED) ? strlen (autolog_ctl_prefix) : 0,
		   &tm, 0);
  if (x <= 0)
  {
    if (x < 0)
      iface->ift |= _autolog_name_signal (iface, S_TERMINATE);
    WARNING ("autolog:_autolog_name_request: %s terminated", iface->name);
    return REQ_REJECTED;
  }
  if (req->flag & F_END && iface->qsize == 0)		/* session ended */
  {
    iface->ift |= _autolog_name_signal (iface, S_TERMINATE);
    dprint (3, "autolog:_autolog_name_request: %s terminated", iface->name);
    return REQ_OK;
  }
  if (log->d->reccount++ < 5)		/* add up to 5 sequent requests */
    Get_Request();
  else
    log->d->reccount = 0;
  return REQ_OK;
}


/* ----------------------------------------------------------------------------
 *	"@network" autolog interface - handles new logs
 */

static autolog_t *_get_autolog_t (autolognet_t *net)
{
  autolog_t *next;

  for (next = net->log; next; next = next->prev)
    if (next->iface == NULL)
      return next;
  next = safe_calloc (1, sizeof(autolog_t));
  next->prev = net->log;
  net->log = next;
  return next;
}

static autolog_t *_find_autolog_t (autolog_t *tail, char *name)
{
  for (; tail; tail = tail->prev)
    if (!strcmp (tail->iface->name, name))
      break;
  return tail;
}

static int _autolog_makepath (char *buf, size_t sb, char *net, char *tgt,
			      size_t st, struct tm *tm)
{
  char *c, *t, *tc;
  size_t sn, s;
  char templ[PATH_MAX+1];

  sn = safe_strlen (net);
  tc = NULL;
  c = templ;
  if (!st)					/* tgt is service */
    t = autolog_serv_path;
  else
    t = autolog_path;
  do
  {
    if (&c[1] >= &templ[sizeof(templ)])		/* no space for a char */
      return -1;
    if (t[0] == '%' && t[1] == 0)		/* correcting wrong syntax */
      t[0] = 0;
    if (t[0] == '%')
    {
      if (t[1] == '@')
      {
	s = &templ[sizeof(templ)] - c;
	if (tc)
	{
	  *t = 0;
	  s = strftime (c, s, tc, tm);
	  *t = '%';
	  c += s;
	  s = &templ[sizeof(templ)] - c;
	}
	if (sn >= s)
	  return -1;				/* no space for network name */
	memcpy (c, net, sn);
	c += sn;
      }
      else if (t[1] == 'N')
      {
	s = &templ[sizeof(templ)] - c;
	if (tc)
	{
	  *t = 0;
	  s = strftime (c, s, tc, tm);
	  *t = '%';
	  c += s;
	  s = &templ[sizeof(templ)] - c;
	}
	if (st >= s)
	  return -1;				/* no space for target name */
	if (st)
	  memcpy (c, tgt, st);
	c += st;
      }
      else if (t[1] == '%')			/* "%%" --> "%" */
      {
	if (!tc)				/* strftime will do it */
	  *c++ = '%';
      }
      else if (!tc)				/* it's strftime syntax */
	tc = t;
      t++;					/* skip char next to '%' */
    }
    else if (!*t)				/* end of line */
    {
      if (tc)					/* finishing strftime part */
	c += strftime (c, &templ[sizeof(templ)] - c, tc, tm);
    }
    else if (!tc)				/* no strftime syntax yet */
      *c++ = *t;				/* just copy next char */
  } while (*t++);
  *c = 0;
  t = (char *)expand_path (buf, templ, sb);
  if (t != buf)
    strfcpy (buf, templ, sb);
  return 0; /* all OK */
}

static iftype_t _autolog_net_signal (INTERFACE *iface, ifsig_t sig)
{
  autolog_t *log;

  switch (sig)
  {
    case S_TERMINATE:
    case S_SHUTDOWN:
      while ((log = ((autolognet_t *)iface->data)->log))
      {
	if (log->iface)
	  log->iface->IFSignal (log->iface, sig);
	((autolognet_t *)iface->data)->log = log->prev;
	if (sig != S_SHUTDOWN)
	  FREE (&log);
      }
      ((autolognet_t *)iface->data)->net = NULL;
      iface->data = NULL;
      iface->ift |= I_DIED;
      return I_DIED;
    default: ;
  }
  return 0;
}

static int _autolog_net_request (INTERFACE *iface, REQUEST *req)
{ // reacts only to I_LOG : F_PUBLIC F_PRIV F_JOIN F_MODES
  if (req) DBG ("_autolog_net_request: message for %s", req->to);
  if (req && (req->flag & AUTOLOG_LEVELS) && Have_Wildcard (req->to) < 0)
  {
    autolog_t *log;
    int fd;
    struct tm tm;
    char *tpath;
    size_t s;
    char path[PATH_MAX+1];

    if (Find_Iface (I_FILE | I_LOG, req->to))
    {
      dprint (4, "autolog: logger for %s found, not creating own.", req->to);
      Unset_Iface();
      return REQ_OK;
    }
    tpath = strrchr (req->to, '@');
    if (tpath)
      s = tpath - (char *)req->to;
    else				/* hmm, how it can be possible? */
      s = strlen (req->to);
    /* check if I_LOG for target already exists then bounce it */
    if ((log = _find_autolog_t (((autolognet_t *)iface->data)->log, req->to)))
    {
      WARNING ("autolog:_autolog_net_request: found strange logger \"%s\"",
	       log->iface->name);
      if (log->d)
	return _autolog_name_request (log->iface, req);
      return REQ_OK;
    }
    /* make path and open file */
    localtime_r (&Time, &tm);
    if (_autolog_makepath (path, sizeof(path), &iface->name[1], req->to, s,
			   &tm))
    {
      ERROR ("autolog: could not make path for %s", req->to);
      fd = -1;
    }
    else if ((fd = open_log_file (path)) == -1)
      ERROR ("autolog: could not open log file %s: %s", path, strerror (errno));
    if (fd < 0)
    {
      log = _get_autolog_t ((autolognet_t *)iface->data);
      FREE (&log->d);
      log->iface = Add_Iface (I_LOG, req->to, &_autolog_nolog_s, NULL, log);
      dprint (3, "autolog:_autolog_net_request: created new NOT logger \"%s\"",
	      log->iface->name);
      return REQ_OK;
    }
    log = _get_autolog_t ((autolognet_t *)iface->data);	/* make structure */
    if (!log->d)
      log->d = safe_malloc (sizeof(autologdata_t));
    log->d->path = safe_strdup (path);
    log->d->fd = fd;
    log->d->reccount = 0;
    log->d->inbuf = 0;
    log->d->day = tm.tm_mday;
    log->iface = Add_Iface (I_LOG | I_FILE, req->to, &_autolog_name_signal,
			    &_autolog_name_request, log);
    autolog_add (log, autolog_open, NULL, 0, &tm, 0);	/* ignore result */
    dprint (3, "autolog:_autolog_net_request: created new log \"%s\"",
	    log->iface->name);
    _autolog_name_request (log->iface, req);	/* anyway nothing more to do */
  }
  return REQ_OK;
}


/* ----------------------------------------------------------------------------
 *	"*" autolog interface - handles new networks
 */

static autolognet_t *_get_autolognet_t (autolognet_t **tail)
{
  autolognet_t *next;

  for (next = *tail; next; next = next->prev)
    if (next->net == NULL)
      return next;
  next = safe_calloc (1, sizeof(autolognet_t));
  next->prev = *tail;
  *tail = next;
  return next;
}

static autolognet_t *_find_autolognet_t (autolognet_t *tail, char *name)
{
  for (; tail; tail = tail->prev)
    if (!strcmp (tail->net->name, name))
      break;
  return tail;
}

static iftype_t _autolog_mass_signal (INTERFACE *iface, ifsig_t sig)
{
  autolognet_t *net;

  switch (sig)
  {
    case S_TERMINATE:
    case S_SHUTDOWN:
      while ((net = (autolognet_t *)iface->data))
      {
	if (net->net)
	  net->net->IFSignal (net->net, sig);
	iface->data = net->prev;
	if (sig != S_SHUTDOWN)
	  FREE (&net);
      }
      return I_DIED;
    default: ;
  }
  return 0;
}

static int _autolog_mass_request (INTERFACE *iface, REQUEST *req)
{ // reacts only to I_LOG : F_PUBLIC F_PRIV F_JOIN F_MODES
  char *c;
  autolognet_t *net;

  /* check for (and create if need) interface I_LOG "@network" */
  if (req && (req->flag & AUTOLOG_LEVELS) && Have_Wildcard (req->to) < 0 &&
      (c = strrchr (req->to, '@')) &&
      !(net = _find_autolognet_t (iface->data, c)))
  {
      net = _get_autolognet_t ((autolognet_t **)&iface->data);
      net->net = Add_Iface (I_LOG, c, &_autolog_net_signal,
			    &_autolog_net_request, net);
      dprint (3, "autolog:_autolog_mass_request: created new network \"%s\"",
	      net->net->name);
      return _autolog_net_request (net->net, req);
  }
  return REQ_OK;
}


/* ----------------------------------------------------------------------------
 *	common module interface
 */

static INTERFACE *_autolog_mass = NULL;

static void autolog_register (void)
{
  /* register module itself */
  Add_Request (I_INIT, "*", F_REPORT, "module autolog");
  /* register all variables */
  RegisterString ("autolog-ctl-prefix", autolog_ctl_prefix,
		  sizeof(autolog_ctl_prefix), 0);
  RegisterString ("autolog-path", autolog_path, sizeof(autolog_path), 0);
  RegisterString ("autolog-serv-path", autolog_serv_path,
		  sizeof(autolog_serv_path), 0);
  RegisterString ("autolog-open", autolog_open, sizeof(autolog_open), 0);
  RegisterString ("autolog-close", autolog_close, sizeof(autolog_close), 0);
  RegisterString ("autolog-daychange", autolog_daychange,
		  sizeof(autolog_daychange), 0);
  RegisterString ("autolog-timestamp", autolog_timestamp,
		  sizeof(autolog_timestamp), 0);
  //RegisterBoolean ("autolog-by-lname", &autolog_by_lname);
  RegisterInteger ("autolog-autoclose", &autolog_autoclose);
}

/*
 * this function must receive signals:
 *  S_TERMINATE - unload module,
 *  S_REG - (re)register variables,
 *  S_REPORT - out state info to log.
 */
static int module_autolog_signal (INTERFACE *iface, ifsig_t sig)
{
  switch (sig)
  {
    case S_TERMINATE:
      Delete_Help ("autolog");
      if (_autolog_mass)
	_autolog_mass->ift |= _autolog_mass_signal (_autolog_mass, sig);
      UnregisterVariable ("autolog-ctl-prefix");
      UnregisterVariable ("autolog-path");
      UnregisterVariable ("autolog-serv-path");
      UnregisterVariable ("autolog-open");
      UnregisterVariable ("autolog-close");
      UnregisterVariable ("autolog-daychange");
      UnregisterVariable ("autolog-timestamp");
      //UnregisterVariable ("autolog-by-lname");
      UnregisterVariable ("autolog-autoclose");
      return I_DIED;
    case S_REG:
      // reregister all
      autolog_register();
      break;
    case S_REPORT:
      // TODO:
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
  strfcpy (autolog_open, _("IRC log started %c"), sizeof(autolog_open));
  strfcpy (autolog_close, _("IRC log ended %c"), sizeof(autolog_close));
  strfcpy (autolog_daychange, _("Day changed: %a %x"), sizeof(autolog_daychange));
  Add_Help ("autolog");
  autolog_register();
  _autolog_mass = Add_Iface (I_LOG, "*", &_autolog_mass_signal,
			     &_autolog_mass_request, NULL);
  return (Function)&module_autolog_signal;
}
