/*
 * Copyright (C) 2003-2011  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 * The FoxEye "logs" module: all module source file.
 */

#include "foxeye.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <ctype.h>

#include "modules.h"
#include "init.h"
#include "sheduler.h"

#define	MAXLOGQUEUE	5000	/* max queue size before logging is aborted */

typedef struct logfile_t
{
  struct logfile_t *next;
  struct logfile_t *prev;
  char *path;
  char *rpath;
  int fd;
  flag_t level;
  time_t timestamp;
  time_t lastmsg;
  time_t rotatetime;
  int rmode;
  int reccount;
  int colormode;	/* <0 normal, 0 nocolor, >0 html */
  INTERFACE *iface;
  ssize_t (*add_buf) (struct logfile_t *, char *, size_t, size_t, int);
  size_t inbuf;
  bool wantprefix;
  char buf[HUGE_STRING];
} logfile_t;

static logfile_t *Logfiles = NULL;

static long int logfile_locks = 16;	/* "logfile-lock-attempts" */
static char logs_pattern[128] = "%$~";	/* "logrotate-path" */
static char logrotate_time[5] = "0000";	/* "logrotate-time" */
static char log_prefix[16] = "-|- ";	/* "logfile-notice-prefix" */
static char log_html_time[64] = "red";	/* html CSS color values */
static char log_html_info[64] = "gray";
static char log_html_action[64] = "purple";

static char logrotate_min[3] = "";
static char logrotate_hr[3] = "";
static time_t lastrotated = 0;

static int flush_log (logfile_t *log, int force, int needsync)
{
  ssize_t x;
  struct flock lck;
  int es;

  if (log->inbuf == 0)
    return 0;
  if (log->fd < 0)
    return EBADF;
  if (!force && Time - log->timestamp < cache_time)
    return 0;
  dprint (4, "logs/logs:flush_log: logfile %s: %zd bytes after %d seconds",
	  log->path, log->inbuf, (int)(Time - log->timestamp));
  memset (&lck, 0, sizeof (struct flock));
  lck.l_type = F_WRLCK;
  lck.l_whence = SEEK_END;
  if (fcntl (log->fd, F_SETLK, &lck) < 0)
    return errno;		/* cannot lock the file */
  x = 0;
  if (log->colormode > 0 && lseek (log->fd, 0, SEEK_END) == 0)
  {
    char buf[HUGE_STRING];
    /* add start of html here */
    x = snprintf (buf, sizeof(buf), "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01 Transitional//EN\" \"http://www.w3.org/TR/html4/loose.dtd\">"
		  "<HTML>\n<HEAD>\n"
		  "<meta http-equiv=\"Content-Type\" content=\"text/html;charset=%s\" />\n"
		  "<meta http-equiv=\"Content-Style-Type\" content=\"text/css\" />\n"
		  "<STYLE TYPE=\"text/css\"><!--\n"
		  ".time { color: %s }\n"
		  ".info { color: %s }\n"
		  ".action { color: %s }\n"
		  ".f0 { color: white }\n"
		  ".f1 { color: black }\n"
		  ".f2 { color: navy }\n"
		  ".f3 { color: green }\n"
		  ".f4 { color: red }\n"
		  ".f5 { color: maroon }\n"
		  ".f6 { color: purple }\n"
		  ".f7 { color: olive }\n"
		  ".f8 { color: yellow }\n"
		  ".f9 { color: lime }\n"
		  ".f10 { color: teal }\n"
		  ".f11 { color: aqua }\n"
		  ".f12 { color: blue }\n"
		  ".f13 { color: fuchsia }\n"
		  ".f14 { color: gray }\n"
		  ".f15 { color: silver }\n"
		  ".b0 { background-color: white }\n"
		  ".b1 { background-color: black }\n"
		  ".b2 { background-color: navy }\n"
		  ".b3 { background-color: green }\n"
		  ".b4 { background-color: red }\n"
		  ".b5 { background-color: maroon }\n"
		  ".b6 { background-color: purple }\n"
		  ".b7 { background-color: olive }\n"
		  ".b8 { background-color: yellow }\n"
		  ".b9 { background-color: lime }\n"
		  ".b10 { background-color: teal }\n"
		  ".b11 { background-color: aqua }\n"
		  ".b12 { background-color: blue }\n"
		  ".b13 { background-color: fuchsia }\n"
		  ".b14 { background-color: gray }\n"
		  ".b15 { background-color: silver }\n"
		  "--></STYLE>\n</HEAD>\n<BODY>\n", Charset, log_html_time,
		  log_html_info, log_html_action);
    if ((size_t)x >= sizeof(buf))
      x = sizeof(buf) - 1;
    x = write (log->fd, buf, x);
  }
  if (x >= 0)
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

static ssize_t textlog_add_buf (logfile_t *log, char *text, size_t sz,
				size_t sp, int ts, int ishtml)
{
  char tss[36];	/* we need 32 actually */
  size_t tsz, tsw, sw, psw;
  int x;

  if (ts)
  {
    if (ishtml)
      tsz = snprintf (tss, sizeof(tss), "<span class=time>[%.5s]</span> ",
		      TimeString);
    else
      tsz = snprintf (tss, sizeof(tss), "[%.5s] ", TimeString);
    if (log->inbuf > sizeof(log->buf) - tsz)
      tsw = sizeof(log->buf) - log->inbuf;
    else
      tsw = tsz;
    memcpy (&log->buf[log->inbuf], tss, tsw);
  }
  else
    tsz = tsw = 0;
  if (log->inbuf + tsz + sp + sz + 1 >= sizeof(log->buf))
						/* [timestamp][prefix]line\n */
  {
    if (log->inbuf + tsz >= sizeof(log->buf))
      sw = psw = 0;
    else if (log->inbuf + tsz + sp >= sizeof(log->buf))
    {
      psw = sizeof(log->buf) - log->inbuf - tsz;
      memcpy (&log->buf[log->inbuf+tsw], log_prefix, psw);
      sw = 0;
    }
    else
    {
      psw = sp;
      memcpy (&log->buf[log->inbuf+tsw], log_prefix, psw);
      sw = sizeof(log->buf) - log->inbuf - sp - tsw;
      memcpy (&log->buf[log->inbuf+tsw+psw], text, sw);
    }
    log->inbuf += (tsw + psw + sw);
    x = flush_log (log, 1, 0);
    if (x == EACCES || x == EAGAIN)	/* file locked */
    {
      log->inbuf -= (tsw + psw + sw);
      /* check if file is locked too far ago */
      if (log->iface->qsize > MAXLOGQUEUE)
      {
	if (ts >= 0)
	  ERROR ("Logfile %s is locked but queue grew to %d, abort logging to it",
		 log->path, log->iface->qsize);
	return -1;
      }
      return 0;
    }
    else if (x)				/* fatal error! */
    {
      if (ts >= 0)			/* ts < 0 means quiet */
      {
	strerror_r (x, log->buf, sizeof(log->buf));
	ERROR ("Couldn't sync logfile %s (%s), abort logging to it.",
	       log->path, log->buf);
      }
      return -1;
    }
    if (ts && tsw < tsz)
    {
      memcpy (log->buf, &tss[tsw], tsz - tsw);
      tsw = tsz - tsw;
    }
    else
      tsw = 0;
    sp -= psw;
    sz -= sw;
  }
  else
    sw = psw = 0;
  if (log->inbuf + tsw + sp + sz + 1 > sizeof(log->buf)) /* truncate it */
    sz = sizeof(log->buf) - (log->inbuf + tsw + sp + 1);
  if (sp)
    memcpy (&log->buf[log->inbuf+tsw], &log_prefix[psw], sp);
  if (sz)
    memcpy (&log->buf[log->inbuf+tsw+sp], &text[sw], sz);
  if (log->inbuf == 0)		/* timestamp for cache-time */
    log->timestamp = Time;
  log->lastmsg = Time;
  log->inbuf += (tsw + sp + sz);
  log->buf[log->inbuf++] = '\n';
  return sz + sw;
}

static ssize_t textlog_add_buf_ts (logfile_t *log, char *text, size_t sz, size_t sp, int x)
{
  return textlog_add_buf (log, text, sz, sp, 1, x);
}

static ssize_t textlog_add_buf_nots (logfile_t *log, char *text, size_t sz, size_t sp, int x)
{
  return textlog_add_buf (log, text, sz, sp, 0, x);
}

static inline int _getmirccolor (const char **p)
{
  register int n = **p - '0', n2;
  
  if (n < 0 || n > 9)
    return -1;
  (*p)++;
  if (n == 1)
  {
    n2 = **p - '0';
    if (n2 >= 0 && n2 < 6)
    {
      (*p)++;
      return (n2 + 10);
    }
  }
  return n;
}

static size_t textlog_rmcolor (char *buff, const char *text, size_t sz)
{
  register char ch;
  size_t i;

  i = 0;
  while (i < sz)			/* reserved for 1 char */
  {
    if ((ch = *text++) == '\0')		/* EOL */
      break;
    switch (ch)
    {
      case '\002':			/* bold ^B */
      case '\007':			/* ignoring ^G */
      case '\037':			/* understrike ^_ */
      case '\026':			/* reverse ^V */
      case '\006':			/* blink ^F */
	break;
      case '\003':			/* mirc colors */
	if (text[0] == '1' && text[1] >= '0' && text[1] <= '5')
	  text += 2;
	else if (*text >= '0' && *text <= '9')
	  text++;
	else
	  break;
	if (*text == ',')
	{
	  if (text[0] == '1' && text[1] >= '0' && text[1] <= '5')
	    text += 3;
	  else if (*text >= '0' && *text <= '9')
	    text += 2;
	  else
	    buff[i] = *text++;
	}
	break;
      default:
	buff[i++] = ch;
    }
  }
  return (i);
}

static size_t textlog2html (char *buff, const char *text, size_t sz, flag_t flag)
{
  int us = 0;		/* flags */
  int bold = 0;
  int rev = 0;
  int blink = 0;
  int color = 0;
  int url = 0;
  const char *p = NULL;	/* URL ptr, NULL to make compiler happy */
  register char ch;
  size_t i, sw, r;	/* counters */

  if ((flag & F_T_MASK) == F_T_ACTION)
  {
    i = strfcpy (buff, "<span class=action>", sz);
    color = -2;				/* colorize "* nick" */
    r = 12;		/* </span><br>\0 */
  }
  else if (flag & F_PREFIXED)
  {
    i = strfcpy (buff, "<span class=info>", sz);
    r = 12;		/* </span><br>\0 */
  }
  else
    i = 0, r = 5;	/* <br>\0 */
  while (i + r < sz)			/* reserved for 1 char */
  {
    if ((ch = *text++) == '\0')		/* EOL */
      break;
    if (url && ch <= ' ')		/* URL ends? */
    {
      sw = snprintf (&buff[i], r, "\">%.*s</A>", url, p);
      r -= sw;
      i += sw;
      url = 0;
      buff[i++] = ch;	/* this char */
    }
    else switch (ch)
    {
      case ' ':
	if (color < 0)			/* ACTION nick hilighting */
	{
	  if (++color == 0)
	  {
	    i += strfcpy (&buff[i], "</span>", r);
	    r -= 7;
	  }
	}
	buff[i++] = ch;
	break;
      case '\002':			/* bold ^B */
	if (bold)
	{
	  i += strfcpy (&buff[i], "</B>", r);
	  r -= 4;
	  bold = 0;
	}
	else if (i + r + 7 > sz) /* <b></b> */
	{
	  r = sz - i;
	  break;
	}
	else
	{
	  i += strfcpy (&buff[i], "<B>", sz - i);
	  r += 4; /* </b> */
	  bold = 1;
	}
	break;
      case '\007':			/* ignoring ^G */
	break;
      case '\037':			/* understrike ^_ */
	if (us)
	{
	  i += strfcpy (&buff[i], "</U>", r);
	  r -= 4;
	  us = 0;
	}
	else if (i + r + 7 > sz) /* <u></u> */
	  break;
	else
	{
	  i += strfcpy (&buff[i], "<U>", sz - i);
	  r += 4; /* </u> */
	  us = 1;
	}
	break;
      case '\026':			/* reverse ^V */
	if (rev)
	{
	  i += strfcpy (&buff[i], "</I>", r);
	  r -= 4;
	  rev = 0;
	}
	else if (i + r + 7 > sz) /* <i></i> */
	  break;
	else
	{
	  i += strfcpy (&buff[i], "<I>", sz - i);
	  r += 4; /* </i> */
	  rev = 1;
	}
	break;
      case '\006':			/* blink ^F */
	if (blink)
	{
//	  strfcpy (&buff[i], "</F>", r);
//	  r -= 4;
//	  i += 4;
	  blink = 0;
	}
//	else if (i + r + 7 > sz) /* <f></f> */
//	  break;
	else
	{
//	  strfcpy (&buff[i], "<F>", sz - i);
//	  r += 4;
//	  i += 3;
	  blink = 1;
	}
	break;
      case '\003':			/* mirc colors */
	if (*text >= '0' && *text <= '9')
	{
	  register int fg = _getmirccolor (&text);
	  register int bg = 0;

	  if (*text == ',')
	  {
	    text++;
	    bg = _getmirccolor (&text);
	  }
	  if (color)
	  {
	    i += strfcpy (&buff[i], "</span>", r);
	    r -= 7;
	    color = 0;
	  }
	  sw = 23;			/* <span class=AXX></span> */
	  if (bg)
	    sw += 6;			/* " bYY" */
	  if (i + sw + r > sz)		/* insufficient space? */
	    break;			/* ignore color directive */
	  color = 1;
	  if (bg)
	    sw = snprintf (&buff[i], sz - i,
			   "<span class=\"f%d b%d\">", fg, bg);
	  else
	    sw = snprintf (&buff[i], sz - i, "<span class=f%d>", fg);
	  i += sw;
	  r += 7; /* </span> */
	}
	else if (color > 0)
	{
	  i += strfcpy (&buff[i], "</span>", r);
	  r -= 7;
	  color = 0;
	}
	break;
      case '<':				/* should be escaped */
	if (i + r + 4 > sz)
	{
	  r = sz - r;
	  break;
	}
	i += strfcpy (&buff[i], "&lt;", 5);
	break;
      case '>':
	if (i + r + 4 > sz)
	{
	  r = sz - r;
	  break;
	}
	i += strfcpy (&buff[i], "&gt;", 5);
	break;
      case '&':
	if (i + r + 5 > sz)
	{
	  r = sz - r;
	  break;
	}
	i += strfcpy (&buff[i], "&amp;", 6);
	break;
      case 'h':				/* check for http:// */
	if (color >= 0 && !url && !strncmp (text, "ttp://", 6))
	{
	  if (i + r + 29 > sz) /* <a href="http://">http://</a> */
	  {
	    r = sz - r;
	    break;
	  }
	  p = &text[-1];
	  url = 7; /* http:// */
	  text = &p[url];
	  i += strfcpy (&buff[i], "<A HREF=\"http://", sz - i);
	  r += 13; /* ">http://</a> */
	  break;
	}
      default:
	if (url)
	{
	  url++;
	  r++;
        }
	buff[i++] = ch;
    }
  }
  if (url)
    sw = snprintf (&buff[i], sz - i, "\">%.*s</A>%s%s%s%s%s<BR>", url, p,
		   color ? "</span>" : "", us ? "</U>" : "", rev ? "</I>" : "",
		   bold ? "</B>" : "", (flag & F_PREFIXED) ? "</span>" : "");
  else
    sw = snprintf (&buff[i], sz - i, "%s%s%s%s%s<BR>", color ? "</span>" : "",
		   us ? "</U>" : "", rev ? "</I>" : "", bold ? "</B>" : "",
		   (flag & F_PREFIXED) ? "</span>" : "");
  if (i + sw >= sz)
    return (sz - 1);
  return (i + sw);
}

#define open_log_file(path) open (path, O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR | S_IRGRP)

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
	textlog_add_buf (log, ShutdownR, strlen(ShutdownR), strlen(log_prefix), -1, 0);
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
      close (log->fd);
      log->fd = open_log_file (log->path);
    default: ;
  }
  return 0;
}

static int add_to_log (INTERFACE *iface, REQUEST *req)
{
  ssize_t x;
  logfile_t *log;
  char *line;
  char buff[HUGE_STRING];

  log = (logfile_t *)iface->data;
  if (!req || !(req->flag & log->level))
    return REQ_OK;
  if (log->colormode > 0)		/* html mode */
    x = textlog2html ((line = buff), req->string, sizeof(buff), req->flag);
  else if (log->colormode < 0)		/* nocolor mode */
    x = textlog_rmcolor ((line = buff), req->string, sizeof(buff));
  else
    x = strlen ((line = req->string));
  if (log->wantprefix != FALSE && (req->flag & F_PREFIXED))
    x = log->add_buf (log, line, x, strlen(log_prefix), (log->colormode > 0));
  else
    x = log->add_buf (log, line, x, 0, (log->colormode > 0));
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

#define L_DAYL 0
#define L_WEEK 1
#define L_MONT 2
#define L_YEAR 3
#define L_DELE 16
#define L_NOTS 32
#define L_NOCL 64
#define L_HTML 128


static time_t get_rotatetime (int fd, int mode)
{
  struct stat st;
  struct tm tm;
  long int tmp;

  if (fd < 0)
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

/* inline substitution to disable warnings */
#if __GNUC__ >= 4
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif
static inline size_t __strftime (char *l, size_t s, char *f, struct tm *t)
{
  return strftime (l, s, f, t);
}
#if __GNUC__ >= 4
#pragma GCC diagnostic error "-Wformat-nonliteral"
#endif

static void do_rotate (logfile_t *log)
{
  char path[PATH_MAX+1];
  char *c, *c2, *rpath;
  ssize_t s = 0;
  register int x;
  struct tm tm;

  x = flush_log (log, 1, 0);
  dprint (4, "logs/logs:do_rotate: start for %s", log->path);
  if (x)
  {
    strerror_r (x, path, sizeof(path));
    ERROR ("Couldn't rotate %s: %s", log->path, path);
    return;
  }
  if (lseek (log->fd, 0, SEEK_END) == 0) /* we will not rotate empty file */
  {
    dprint (2, "logs/logs.c:do_rotate: nothing to do on %s", log->path);
    log->rotatetime = get_rotatetime (-1, log->rmode);
    return;
  }
  localtime_r (&log->lastmsg, &tm);
  /* end html here, ignoring any errors */
  if (log->colormode > 0)
  {
    textlog_add_buf (log, "</BODY>\n</HTML>", 15, 0, 0, 0);
    flush_log (log, 1, 0);
  }
  close (log->fd);
  log->fd = -1;			/* if we get any error let's don't fall */
  /* make rotate path */
  if ((rpath = log->rpath) == NULL)
    rpath = logs_pattern;
  if (!strcmp (rpath, "%$"))		/* cannot rotate into itself! */
    rpath = "%$~";
  for (c2 = c = rpath; *c; )
  {
    c2 = strchr (c2, '%');
    if (c2 && c2[1] != '$')		/* skip strftime substitutions */
    {
      c2++;
      if (*c2) c2++;
      continue;
    }
    if (c2)
      *c2 = 0;
    if (strchr (c, '%'))		/* we need substitutions */
    {
      s += __strftime (&path[s], sizeof(path) - s, c, &tm);
      DBG ("logs:do_rotate: +subpath \"%s\" = \"%s\"", c, path);
    }
    else if (strlen (c))		/* constant string here */
    {
      s += strfcpy (&path[s], c, sizeof(path) - s);
      DBG ("logs:do_rotate: +subpath \"%s\" = \"%s\"", c, path);
    }
    if (!c2)
      break;
    *c2 = '%';				/* restore it */
    c = c2 = &c2[2];			/* go to next part */
    s += strfcpy (&path[s], log->path, sizeof(path) - s);
    DBG ("logs:do_rotate: +subpath \"%%$\" = \"%s\"", path);
  }
  path[s] = 0;
  dprint (4, "logs/logs:do_rotate: made path %s", path);
  /* check if we must make directory */
  if (unlink (path) < 0 && errno == ENOTDIR)
  {
    c = path;
    do {
      if ((c = strchr (c, '/')))	/* make subdirectory */
      {
        *c = 0;
	x = mkdir (path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
	*c++ = '/';
	if (x < 0 && errno != EEXIST)	/* stop if error */
	  c = NULL;
      }
    } while (c);
  }
  if (rename (log->path, path))		/* cannot rename! */
  {
    char buffer[1024];
    int f1, f2, errsave;

    if (errno == EXDEV)			/* another file system */
    {
      if ((f1 = open (log->path, O_RDONLY)) >= 0)
	f2 = open (path, O_WRONLY | O_CREAT | O_APPEND,
		   S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
      else
	f2 = -1;
      if (f2 >= 0)
      {
	while ((s = read (f1, buffer, sizeof(buffer))) != 0)
	  if (s < 0 || write (f2, buffer, s) < s) /* error caught */
	  {
	    errsave = errno;
	    close (f2);
	    unlink (path);
	    f2 = -1;
	    errno = errsave;
	    break;
	  }
      }
      if (f1 >= 0)
      {
	errsave = errno;
	close (f1);
	errno = errsave;
      }
      if (f2 >= 0)			/* succesfully copied */
      {
	close (f2);
	unlink (log->path);
	errno = EXDEV;
      }
    }
    if (errno != EXDEV)			/* couldn't move/copy file */
    {
      strerror_r (errno, buffer, sizeof(buffer));
      ERROR ("Couldn't rotate %s to %s: %s", log->path, path, buffer);
      log->fd = open_log_file (log->path);
      return;				/* reopen log, don't update time */
    }
  }
  dprint (2, "logs/logs.c:do_rotate: finished on %s", log->path);
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
      level |= (flag_t)F_MIN << (c - Flags);
  }
  return level;
}

static char *logfile_printlevel (flag_t level)
{
  static char aa[65];	/* capable for long int */
  char *c = aa;
  int i = 0;

  while (Flags[i] && c < &aa[sizeof(aa)-1])
  {
    if (level & ((flag_t)F_MIN << i))
      *c++ = Flags[i];
    i++;
  }
  *c = 0;
  return aa;
}

/*
 * logfile [-n[ots]] [-h[tml]|-s[tripcolor]] [-y|-m|-w] [-r[path] rpath] filename level [service]
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
  struct stat st;
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
    args = NextWord_Unquoted (path, (char *)&args[1], sizeof(path)); /* const */
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
    else if (!strncmp (path, "html", ss))
      rmode |= L_HTML;
    else if (!strncmp (path, "stripcolor", ss))
      rmode |= L_NOCL;
    else if (!strncmp (path, "rpath", ss))
    {
      args = NextWord_Unquoted (mask, (char *)args, sizeof(mask)); /* still */
      rpath = mask;
    }
    else
      return 0;		/* unknown argument */
  }
  if (!*args)
    return 0;		/* one argument is required! */
  if (!(rmode & L_DELE))
    rpath = safe_strdup (rpath);
  args = NextWord_Unquoted (mask, (char *)args, sizeof(mask)); /* still const */
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
    args = NextWord ((char *)args);	/* it's still const */
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
  log->inbuf = 0;
  log->reccount = 0;
  if ((level & F_PREFIXED) == level) /* only prefixed */
    log->wantprefix = FALSE;
  else
    log->wantprefix = TRUE;
  if (rmode & L_NOTS)
    log->add_buf = &textlog_add_buf_nots;
  else
    log->add_buf = &textlog_add_buf_ts;
  log->colormode = (rmode & (L_HTML | L_NOCL)) - L_NOCL;
  log->rmode = (rmode & ~(L_NOTS | L_HTML | L_NOCL));
  if (*args)
    NextWord_Unquoted (mask, (char *)args, IFNAMEMAX+1); /* still const */
  else
    strcpy (mask, "*");
  log->iface = Add_Iface (I_LOG | I_FILE, mask, &logfile_signal, &add_to_log,
			  log);
  fstat (fd, &st);	/* if's impossible to get an error here? */
  log->lastmsg = st.st_mtime;
  log->rotatetime = get_rotatetime (log->fd, log->rmode);
  if (log->rotatetime <= lastrotated)
    do_rotate (log);
  dprint (2, "log:cgf_logfile: success on %s", log->path);
  return 1;
}

static void module_log_regall (void)
{
  logfile_t *log;

  /* register module itself */
  Add_Request (I_INIT, "*", F_REPORT, "module logs");
  /* register all variables */
  RegisterInteger ("logfile-lock-attempts", &logfile_locks);
  RegisterString ("logrotate-path", logs_pattern, sizeof(logs_pattern), 0);
  RegisterString ("logrotate-time", logrotate_time, sizeof(logrotate_time), 0);
  RegisterString ("logfile-notice-prefix", log_prefix, sizeof(log_prefix), 0);
  RegisterString ("log-html-color-time", log_html_time, sizeof(log_html_time), 0);
  RegisterString ("log-html-color-info", log_html_info, sizeof(log_html_info), 0);
  RegisterString ("log-html-color-action", log_html_action, sizeof(log_html_action), 0);
  /* register logfiles - only when all variables are set */
  for (log = Logfiles; log; log = log->next)
    Add_Request (I_INIT, "*", F_REPORT, "logfile%s%s%s%s%s %s %s %s",
		 (log->add_buf == &textlog_add_buf_nots) ? " -n" : "",
		 log->rmode ? ((log->rmode < 2) ? " -w" : (log->rmode == 2) ? " -m" : " -y") : "",
		 log->rpath ? " -rpath \"" : "", NONULL(log->rpath), log->rpath ? "\"" : "",
		 log->path, logfile_printlevel (log->level), log->iface->name);
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
	if (log->inbuf)
	  New_Request (tmp, F_REPORT, "   file %s, last flushed %d seconds ago",
		       log->path, (int)(Time - log->timestamp));
	else
	  New_Request (tmp, F_REPORT, "   file %s, no updates to save",
		       log->path);
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
      UnregisterVariable ("logfile-notice-prefix");
      UnregisterVariable ("log-html-color-time");
      UnregisterVariable ("log-html-color-info");
      UnregisterVariable ("log-html-color-action");
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
    default: ;
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

  CheckVersion;
  Add_Help ("logs");
  module_log_regall();			/* variables and function */
  logrotate_reset();			/* shedule - logs rotation */
  lastrotated = Time - 3600 * atoi (logrotate_hr) + 60 * atoi (logrotate_min);
  localtime_r (&lastrotated, &tm);
  lastrotated = Time - tm.tm_sec - 60 * tm.tm_min - 3600 * tm.tm_hour;
  return ((Function)&module_log_signal);
}
