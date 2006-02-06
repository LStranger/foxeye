/*
 * Copyright (C) 2003  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 */

#include "foxeye.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <ctype.h>

#include "modules.h"
#include "init.h"
#include "sheduler.h"

typedef struct logfile_t
{
  struct logfile_t *next;
  struct logfile_t *prev;
  char *path;
  char *rpath;
  int fd;
  flag_t level;
  time_t timestamp;
  time_t rotatetime;
  int rmode;
  int reccount;
  INTERFACE *iface;
  ssize_t (*add_buf) (struct logfile_t *, char *, size_t);
  int inbuf;
  char buf[HUGE_STRING];
} logfile_t;

static logfile_t *Logfiles = NULL;

static long int logfile_locks = 16;	/* "logfile-lock-attempts" */
static char logs_pattern[128] = "%$.1";	/* "logrotate-path" */
static char logrotate_time[5] = "0000";	/* "logrotate-time" */

static char logrotate_min[3] = "";
static char logrotate_hr[3] = "";
static time_t lastrotated = 0;

static int flush_log (logfile_t *log, int force, int needsync)
{
  size_t x;
  struct flock lck;
  int es;

  if (log->inbuf == 0)
    return 0;
  if (log->fd == -1)
    return EBADF;
  if (!force && Time - log->timestamp < cache_time)
    return 0;
  dprint (4, "logs/logs:flush_log: logfile %s: %d bytes after %d seconds",
	  log->path, log->inbuf, (int)(Time - log->timestamp));
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
  if (needsync)
    fsync (log->fd);		/* don't check for error here */
  log->inbuf = 0;
  return 0;
}

static ssize_t textlog_add_buf (logfile_t *log, char *text, size_t sz, int ts)
{
  char tss[8];
  size_t tsw, sw;
  int x;

  if (ts)
  {
    tss[0] = '[';
    memcpy (&tss[1], &DateString[7], 5);
    tss[6] = ']';
    tss[7] = ' ';
    if (log->inbuf > sizeof(log->buf) - 8)
      tsw = sizeof(log->buf) - log->inbuf;
    else
      tsw = 8;
    memcpy (&log->buf[log->inbuf], tss, tsw);
  }
  else
    tsw = 0;
  if (log->inbuf + tsw + sz + 1 >= sizeof(log->buf))	/* [timestamp]line\n */
  {
    if (log->inbuf + tsw >= sizeof(log->buf))
      sw = 0;
    else
    {
      sw = sizeof(log->buf) - log->inbuf - tsw;
      memcpy (&log->buf[log->inbuf+tsw], text, sw);
    }
    log->inbuf += (tsw + sw);
    x = flush_log (log, 1, 0);
    if (x == EACCES || x == EAGAIN)	/* file locked */
    {
      log->inbuf -= (tsw + sw);
      /* TODO: check if file is locked too far ago? */
      return 0;
    }
    else if (x)				/* fatal error! */
    {
      if (ts >= 0)			/* ts < 0 means quiet */
	Add_Request (I_LOG, "*", F_ERROR,
		     "Couldn't sync logfile %s, abort logging to it", log->path);
      return -1;
    }
    if (ts && tsw < 8)
    {
      memcpy (log->buf, &tss[tsw], 8 - tsw);
      tsw = 8 - tsw;
    }
    else
      tsw = 0;
  }
  else
    sw = 0;
  memcpy (&log->buf[log->inbuf+tsw], &text[sw], sz - sw);
  if (log->inbuf == 0)		/* timestamp for cache-time */
    log->timestamp = Time;
  log->inbuf += (tsw + sz - sw);
  log->buf[log->inbuf++] = '\n';
  return sz;
}

static ssize_t textlog_add_buf_ts (logfile_t *log, char *text, size_t sz)
{
  return textlog_add_buf (log, text, sz, 1);
}

static ssize_t textlog_add_buf_nots (logfile_t *log, char *text, size_t sz)
{
  return textlog_add_buf (log, text, sz, 0);
}

static iftype_t logfile_signal (INTERFACE *iface, ifsig_t sig)
{
  int x, lockcount;
  logfile_t *log;

  log = (logfile_t *)iface->data;
  switch (sig)
  {
    case S_TIMEOUT:
      flush_log (log, 0, 0);
      break;
    case S_TERMINATE:
      Set_Iface (iface);	/* get all queue now if possible */
      while (Get_Request());
      Unset_Iface();
      FREE (&log->path);	/* these are allocated */
      FREE (&log->rpath);
    case S_SHUTDOWN:
      if (ShutdownR && *ShutdownR && (log->level & (F_BOOT | F_ERROR | F_WARN)))
	textlog_add_buf (log, ShutdownR, strlen(ShutdownR), -1);
      if (log->prev)
	log->prev->next = log->next;
      else
	Logfiles = log->next;
      if (log->next)
	log->next->prev = log->prev;
      iface->ift |= I_DIED;
      lockcount = 0;
      while ((x = flush_log (log, 1, 1)) != 0)
	if ((x != EACCES && x != EAGAIN) || ++lockcount >= logfile_locks)
	  break;		/* try to flush log up to 16 times */
      close (log->fd);
      break;
    case S_FLUSH:
      flush_log (log, 1, 0);
    default:
      break;
  }
  return 0;
}

static int add_to_log (INTERFACE *iface, REQUEST *req)
{
  ssize_t x;
  logfile_t *log;

  log = (logfile_t *)iface->data;
  if (!req || !(req->flag & log->level))
    return REQ_OK;
  x = log->add_buf (log, req->string, strlen(req->string));
  if (x <= 0)
  {
    if (x < 0)
      logfile_signal (iface, S_TERMINATE);
    return REQ_REJECTED;
  }
  if (log->reccount++ < 5)		/* add up to 5 sequent requests */
    Get_Request();
  log->reccount = 0;
  return REQ_OK;
}

#define open_log_file(path) open (path, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP)

#define L_DAYL 0
#define L_WEEK 1
#define L_MONT 2
#define L_YEAR 3
#define L_DELE 16
#define L_NOTS 32
//#define L_HTML 64

static time_t get_rotatetime (int fd, int mode)
{
  struct stat st;
  struct tm tm;
  long int tmp;

  if (fd == -1)
    st.st_mtime = Time;
  else if (fstat (fd, &st))
    return 0;
  tmp = 3600 * atoi (logrotate_hr) + 60 * atoi (logrotate_min);
  st.st_mtime -= tmp;
  localtime_r (&st.st_mtime, &tm);
  tm.tm_sec = tm.tm_min = tm.tm_hour = 0;
  switch (mode)
  {
    case L_DAYL:	/* daily */
      tmp += 86400;
      break;
    case L_WEEK:	/* weekly */
      tmp += (7 - tm.tm_wday) * 86400;
      break;
    case L_MONT:	/* monthly */
      tm.tm_mday = 1;
      if ((++tm.tm_mon) != 12)
	break;
    case L_YEAR:	/* yearly */
      tm.tm_mon = 0;
      tm.tm_mday = 1;
      tm.tm_year++;
  }
  return (tmp + mktime (&tm));
}

static void do_rotate (logfile_t *log)
{
  char path[PATH_MAX+1];
  char *c, *c2, *rpath;
  size_t s = 0;
  register int x;
  struct tm tm;

  x = flush_log (log, 1, 0);
  dprint (3, "logs/logs:do_rotate: start for %s", log->path);
  if (x)
  {
    Add_Request (I_LOG, "*", F_ERROR, "Couldn't rotate %s: %s", log->path,
		 strerror (x));
    return;
  }
  localtime_r (&log->rotatetime, &tm);
  close (log->fd);
  log->fd = -1;			/* if we get any error let's don't fall */
  /* make rotate path */
  if ((rpath = log->rpath) == NULL)
    rpath = logs_pattern;
  for (c2 = c = rpath; *c; )
  {
    c2 = strchr (c2, '%');
    if (c2 && c2[1] != '$')
      continue;
    if (c2)
      *c2 = 0;
    if (strchr (c, '%'))		/* we need substitutions */
      s += strftime (&path[s], sizeof(path) - s, c, &tm);
    else if (strlen (c))		/* constant string here */
    {
      strfcpy (&path[s], c, sizeof(path) - s);
      s += strlen (&path[s]);
    }
    if (!c2)
      break;
    *c2 = '%';				/* restore it */
    c = c2 = &c2[2];			/* go to next part */
    strfcpy (&path[s], log->path, sizeof(path) - s);
    s += strlen (&path[s]);
  }
  path[s] = 0;
  dprint (3, "logs/logs:do_rotate: made path %s", path);
  /* TODO: check if we must make directory */
  unlink (path);
  if (rename (log->path, path))		/* cannot rename! */
  {
    if (errno == EXDEV)			/* another file system */
    {
      char buffer[1024];
      FILE *f1, *f2;
      int errsave;

      if ((f1 = fopen (log->path, "rb")))
	f2 = fopen (path, "wb");
      else
	f2 = NULL;
      if (f2)
      {
	clearerr (f2);
	while ((s = fread (buffer, 1, sizeof(buffer), f1)) > 0)
	  if ((s < sizeof(buffer) && !feof (f2)) ||
	      fwrite (buffer, 1, s, f2) < s)
	  {
	    errsave = errno;
	    fclose (f2);
	    unlink (path);
	    f2 = NULL;
	    errno = errsave;
	    break;
	  }
      }
      if (f1)
      {
	errsave = errno;
	fclose (f1);
	errno = errsave;
      }
      if (f2)				/* succesfully copied */
      {
	fclose (f2);
	unlink (log->path);
	errno = EXDEV;
      }
    }
    if (errno != EXDEV)			/* couldn't move/copy file */
    {
      Add_Request (I_LOG, "*", F_ERROR, "Couldn't rotate %s to %s: %s",
		   log->path, path, strerror (errno));
      log->fd = open_log_file (log->path);
      return;				/* reopen log, don't update time */
    }
  }
  log->rotatetime = get_rotatetime (-1, log->rmode);
  log->fd = open_log_file (log->path);
}

static char Flags[] = FLAG_T;

static flag_t logfile_level (const char *a)
{
  flag_t level = 0;
  char *c;

  while (*a && *a != ' ')
  {
    c = strchr (Flags, *a);
    a++;
    if (c)
      level |= F_MIN << (c - Flags);
  }
  return level;
}

static char *logfile_printlevel (flag_t level)
{
  static char aa[33];	/* capable for long int */
  char *c = aa;
  int i = 0;

  while (Flags[i++])
  {
    if (level & (F_MIN << i))
      *c++ = Flags[i];
  }
  *c = 0;
  return aa;
}

/*
 * logfile [-n[ots]] [-y|-m|-w] [-r[path] rpath] filename level [service]
 * logfile -c[lose] filename
 */
static ScriptFunction (cfg_logfile)
{
  int fd;
  int rmode = 0;
  size_t ss;
  flag_t level;
  logfile_t *log;
  char *rpath = NULL;
  const char *tpath;
  char path[PATH_MAX];
#if PATH_MAX > IFNAMEMAX
  char mask[PATH_MAX];
#else
  char mask[IFNAMEMAX+1];
#endif

  if (!args)
    return 0;
  /* parse arguments */
  path[0] = 0;
  while (*args == '-')
  {
    args = NextWord_Unquoted (path, &args[1], sizeof(path));
    ss = strlen (path);
    if (!strncmp (path, "nots", ss))
      rmode |= L_NOTS;
    else if (!strncmp (path, "yearly", ss))
      rmode = (rmode & (L_NOTS|L_DELE)) + L_YEAR;
    else if (!strncmp (path, "monthly", ss))
      rmode = (rmode & (L_NOTS|L_DELE)) + L_MONT;
    else if (!strncmp (path, "weekly", ss))
      rmode = (rmode & (L_NOTS|L_DELE)) + L_WEEK;
    else if (!strncmp (path, "close", ss))
      rmode |= L_DELE;
    else if (!strncmp (path, "rpath", ss))
    {
      args = NextWord_Unquoted (mask, args, sizeof(mask));
      rpath = mask;
    }
    else
      return 0;		/* unknown argument */
  }
  if (!*args)
    return 0;		/* one argument is required! */
  if (!(rmode & L_DELE))
    rpath = safe_strdup (rpath);
  args = NextWord_Unquoted (mask, args, sizeof(mask));
  tpath = expand_path (path, mask, sizeof(path));
  /* check if that logfile already exists */
  for (log = Logfiles; log; log = log->next)
    if (!safe_strcmp (tpath, log->path))
      break;
  if (rmode & L_DELE)
  {
    if (!log)
      return 0;
    logfile_signal (log->iface, S_TERMINATE);
    return 1;
  }
  if (*args)
  {
    level = logfile_level (args);
    args = NextWord (args);
  }
  else
    level = 0;
  if (log || !level)
  {
    FREE (&rpath);
    return 0;
  }
  /* create new logfile with interface */
  fd = open_log_file (tpath);
  if (fd < 0)
    return 0;
  log = safe_malloc (sizeof(logfile_t));
  log->next = Logfiles;
  log->prev = NULL;
  log->level = level;
  if (Logfiles)
    Logfiles->prev = log;
  Logfiles = log;
  log->path = safe_strdup (tpath);
  log->rpath = rpath;
  log->fd = fd;
  log->level = level;
  log->inbuf = 0;
  log->reccount = 0;
  if (rmode & L_NOTS)
    log->add_buf = &textlog_add_buf_nots;
  else
    log->add_buf = &textlog_add_buf_ts;
  log->rmode = (rmode & ~L_NOTS);
  if (*args)
    NextWord_Unquoted (mask, args, IFNAMEMAX+1);
  else
    strcpy (mask, "*");
  log->iface = Add_Iface (mask, I_LOG | I_FILE, &logfile_signal, &add_to_log,
			  log);
  log->rotatetime = get_rotatetime (log->fd, log->rmode);
  if (log->rotatetime <= lastrotated)
    do_rotate (log);
  dprint (3, "log:cgf_logfile: success on %s", log->path);
  return 1;
}

static void module_log_regall (void)
{
  logfile_t *log;

  /* register module itself */
  Add_Request (I_INIT, "*", F_REPORT, "module logs");
  /* register logfiles */
  for (log = Logfiles; log; log = log->next)
    Add_Request (I_INIT, "*", F_REPORT, "logfile %s%s%s %s %s",
		 (log->add_buf == &textlog_add_buf_nots) ? "-n " : "",
		 log->rmode ? ((log->rmode < 2) ? "-w " : (log->rmode == 2) ? "-m " : "-y ") : "",
		 log->path, logfile_printlevel (log->level), log->iface->name);
  /* register all variables */
  RegisterInteger ("logfile-lock-attempts", &logfile_locks);
  RegisterString ("logrotate-path", logs_pattern, sizeof(logs_pattern), 0);
  RegisterString ("logrotate-time", logrotate_time, sizeof(logrotate_time), 0);
  RegisterFunction ("logfile", &cfg_logfile, "[-n] [-y|-m|-w] filename level [service]");
}

static void logrotate_reset (void)
{
  int x;

  if (*logrotate_hr && *logrotate_min)
    KillShedule (I_MODULE, "logs", S_TIMEOUT, "*", "*", "*", "*", "*");
  if (logrotate_time[0] > '0' && logrotate_time[0] < '3')
  {
    logrotate_hr[0] = logrotate_time[0];
    if (isdigit (logrotate_time[1]))
      logrotate_hr[1] = logrotate_time[1];
    else
      logrotate_hr[1] = 0;
  }
  else
  {
    logrotate_hr[0] = logrotate_time[1];
    logrotate_hr[1] = 0;
  }
  x = atoi (logrotate_hr);
  if (x == 0)
    strcpy (logrotate_hr, "0");
  else if (x > 23)
    strcpy (logrotate_hr, "24");
  x = atoi (logrotate_time+2);
  if (x > 59)
    x = 59;
  snprintf(logrotate_min, 3, "%d", x);
  NewShedule (I_MODULE, "logs", S_TIMEOUT, logrotate_min, logrotate_hr,
	      "*", "*", "*");
}

/*
 * this function must receive signals:
 *  S_TERMINATE - unload module,
 *  S_REG - different jobs,
 *  S_FLUSH & S_SHUTDOWN - flush all on disk,
 *  S_TIMEOUT - sheduler signal for logs rotation,
 *  S_REPORT - out state info to requestor.
 */
static iftype_t module_log_signal (INTERFACE *iface, ifsig_t sig)
{
  logfile_t *log;
  INTERFACE *tmp;

  switch (sig)
  {
    case S_REG:
      module_log_regall();
      break;
    case S_REPORT:
      tmp = Set_Iface (iface);
      New_Request (tmp, F_REPORT, "Module logs: %s", Logfiles ? "opened logs:" :
		   "no opened logs found");
      for (log = Logfiles; log; log = log->next)
      {
	New_Request (tmp, F_REPORT, "   file %s, last flushed %d seconds ago",
		     log->path, log->inbuf ? Time - log->timestamp : -1);
      }
      Unset_Iface();
      break;
    case S_TIMEOUT:
      lastrotated = Time;
      for (log = Logfiles; log; log = log->next)
	if (log->rotatetime <= lastrotated)
	  do_rotate (log);
      break;
    case S_TERMINATE:
      /* stop rotation first, then terminate all logfiles and unregister all */
      if (*logrotate_hr && *logrotate_min)
	KillShedule (I_MODULE, "logs", S_TIMEOUT, "*", "*", "*", "*", "*");
      for (log = Logfiles; log; log = log->next)
	logfile_signal (log->iface, S_TERMINATE);
      UnregisterVariable ("logfile-lock-attempts");
      UnregisterVariable ("logrotate-path");
      UnregisterVariable ("logrotate-time");
      UnregisterFunction ("logfile");
      Delete_Help ("logs");
      iface->ift |= I_DIED;
      break;
    case S_SHUTDOWN:
      if (iface)
	iface->ift |= I_DIED;
      break;
    case S_FLUSH:
      /* update logrotation time */
      if (sig == S_FLUSH)
	logrotate_reset();
    default:
      break;
  }
  return 0;
}

/*
 * this function called when you load a module.
 * Input: parameters string args - nothing.
 * Returns: address of signals receiver function.
 */
Function ModuleInit (char *args)
{
  struct tm tm;

  Add_Help ("logs");
  module_log_regall();			/* variables and function */
  logrotate_reset();			/* shedule - logs rotation */
  lastrotated = Time - 3600 * atoi (logrotate_hr) + 60 * atoi (logrotate_min);
  localtime_r (&lastrotated, &tm);
  lastrotated = Time - tm.tm_sec - 60 * tm.tm_min - 3600 * tm.tm_hour;
  return ((Function)&module_log_signal);
}