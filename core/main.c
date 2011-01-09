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
 * This file is part of FoxEye's source: main startup and console interface.
 */

#define MAIN_C 1

#include "foxeye.h"

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#include <fcntl.h>
#include <sys/poll.h>
#include <sys/utsname.h>
#include <errno.h>
#include <signal.h>

#include "init.h"
#include "direct.h"

static int Fifo_Inp[2];		/* console keyboard */
static int Fifo_Out[2];		/* console display */

/* ------------------------------
 * child side */

static int _kill_pipe (INTERFACE *iface)
{
  close (Fifo_Inp[0]);
  close (Fifo_Out[1]);
  iface->ift |= I_DIED;
  return REQ_OK;
}

static char _inp_buf[2*MESSAGEMAX];
static int _bufpos = 0;
static int _inbuf = 0;

static void _pipe_get_line (char *buf, size_t l)
{
  register char *c = &_inp_buf[_bufpos];

  memcpy (buf, c, l);
  if (c[l] == '\r')
    l++;
  if (c[l] == '\n')
    l++;
  _bufpos += l;
  _inbuf -= l;
  if (_bufpos < MESSAGEMAX && _inbuf)
    return;
  if (_inbuf)
    memcpy (_inp_buf, &c[l], _inbuf);
  _bufpos = 0;
}

static ssize_t _pipe_find_line (void)
{
  register ssize_t p;
  register char *c = memchr (&_inp_buf[_bufpos], '\n', _inbuf);

  if (!c)			/* no newline */
    return (-1);
  p = c - &_inp_buf[_bufpos];	/* length of string */
  if (!p)
    return 0;
  c--;
  if (*c != '\r')
    return (p);
  return (p-1);
}

static ssize_t _read_pipe (char *buf, size_t sr)
{
  ssize_t sg;

  buf[0] = 0;				/* line terminator if EAGAIN */
  if ((sg = _pipe_find_line()) < 0)
  {
    sg = _bufpos + _inbuf;
    sg = read (Fifo_Inp[0], &_inp_buf[sg], sizeof(_inp_buf) - sg);
    if (sg <= 0)
    {
      if (sg && errno == EAGAIN)
	return 0;
      return (-1);			/* error or EOF */
    }
    _inbuf += sg;
    sg = _pipe_find_line();
    if (sg < 0)
      return 0;
  }
  if ((size_t)sg >= sr)
    sg = sr - 1;
  _pipe_get_line (buf, sg);
  if (sg)
    buf[sg] = 0;			/* line terminator */
  else
  {
    buf[0] = '\n';
    buf[1] = 0;
  }
  return (sg);
}

static ssize_t _write_pipe (char *buf, size_t *sw)
{
  register ssize_t sg = 0;

  do
  {
    sg = write (Fifo_Out[1], buf, *sw);
    if (sg < 0)
    {
      if (errno == EAGAIN)
	sg = 0;
      break;
    }
    else if ((size_t)sg != *sw)
    {
      *sw -= sg;
      memmove (buf, &buf[sg], *sw);
      break;
    }
    else
      *sw = 0;
  } while (*sw);
  if (sg > 0)
    buf[*sw] = 0;			/* line was moved - line terminator */
  return (sg);
}

typedef struct {
  peer_t s;
  char buf[MESSAGEMAX];
} console_peer;

static int _request (INTERFACE *iface, REQUEST *req)
{
  console_peer *dcc = (console_peer *)iface->data;
  ssize_t sw;
  char buff[MESSAGEMAX];

  /* first time? */
  if (!dcc->s.iface)
  {
    dcc->s.iface = iface;
    close (Fifo_Inp[1]);
    close (Fifo_Out[0]);
  }
  /* don't echo back own botnet messages */
  if (req && req->from == iface && (req->mask_if & I_DCCALIAS) &&
      !strncmp (req->to, ":*:", 3))
    req = NULL;
  /* check if we have empty output buf */
  while (dcc->buf[0] || req)
  {
    if (req && !dcc->buf[0])
    {
      /* for logs - if not from me */
      if (req->mask_if == I_LOG)
      {
	if (req->flag & CONSOLE_LOGLEV)
	  sw = printl (dcc->buf, sizeof(dcc->buf) - 1, "[%t] %*", 0,
		       NULL, NULL, NULL, NULL, 0, 0, 0, req->string);
	else
	  sw = 0;
      }
      /* for chat channel messages */
      else if (req->mask_if & I_DCCALIAS)
      {
	char *prefix = "";
	char *suffix = "";
	char *str = req->string;

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
	sw = snprintf (dcc->buf, sizeof(dcc->buf) - 1, "%s%s%s %s", prefix,
		       req->from->name, suffix, str);
	if ((size_t)sw >= sizeof(dcc->buf) - 1)
	  sw = sizeof(dcc->buf) - 2;
      }
      /* direct messages */
      else
	sw = strfcpy (dcc->buf, req->string, sizeof(dcc->buf) - 1);
      if (sw && !(req->from->ift & I_INIT))	/* ending with newline */
	strfcpy (&dcc->buf[sw++], "\n", 2);
      req = NULL;		/* request done */
    }
    else
      sw = strlen (dcc->buf);
    /* write the buffer to pipe, same as Write_Socket() does */
    if (sw)
      sw = _write_pipe (dcc->buf, (size_t *)&sw);
    if (sw < 0)			/* error, kill the pipe... */
      return _kill_pipe (iface);
    if (!(iface->ift & I_DCCALIAS))
      continue;			/* write pipe if in config */
    else if (req)
      return REQ_REJECTED;	/* don't input until empty buffer */
    break;			/* normal run */
  }
  /* read the string from the pipe to buffer and supress ending CR/LF */
  sw = _read_pipe (buff, sizeof(buff));
  if (sw < 0)			/* error, kill the pipe... */
    return _kill_pipe (iface);
  if (!(iface->ift & I_DCCALIAS) && buff[0])	/* return to config anyway */
    Add_Request (I_INIT, "*", 0, "%s", buff);
  else if (!sw)
    return REQ_OK;
  /* run command or send to 0 channel of botnet */
  else
    Dcc_Parse (&dcc->s, "", buff, U_ALL, U_ANYCH, -2, 0, NULL, NULL);
  return REQ_OK;
}

static iftype_t _signal (INTERFACE *iface, ifsig_t signal)
{
  char buff[SHORT_STRING];
  INTERFACE *tmp;

  switch (signal)
  {
    case S_TERMINATE:
      _kill_pipe (iface);
      FREE (&((peer_t *)iface->data)->dname);
      iface->ift = I_CONSOLE | I_DIED;
      return I_DIED;
    case S_REPORT:
      printl (buff, sizeof(buff), ReportFormat, 0,
	      NULL, NULL, "-console-", NULL, 0, 0, 0, NULL);
      tmp = Set_Iface (iface);
      New_Request (tmp, F_REPORT, "%s", buff);
      Unset_Iface();
      break;
    case S_SHUTDOWN:
      if (ShutdownR)
      {
	if(write (Fifo_Out[1], ShutdownR, safe_strlen (ShutdownR)))*buff=*buff;
	if(write (Fifo_Out[1], "\n", 1))*buff=*buff; /* make compiler happy */
      }
      _kill_pipe (iface);
    default: ;
  }
  return 0;
}

/* ------------------------------
 * parent side */

static void *_stdin2pipe (void *bbbb)
{
  char buff[LONG_STRING];
  char *cc;
#ifdef _FREEBSD
  int rc;
  fd_set fdr;
#endif

  FOREVER
  {
#ifdef _FREEBSD
    /* ugly hack since stdin and pipes work bad in multithreaded environment */
    FD_ZERO (&fdr);
    FD_SET (STDIN_FILENO, &fdr);
    rc = select (STDIN_FILENO+1, &fdr, NULL, NULL, NULL);
#endif
    if (!(cc = fgets (buff, sizeof(buff), stdin)))
      break;
    if (write (Fifo_Inp[1], buff, strlen(buff)) < 0)
      break;
  };
  close (Fifo_Inp[1]);
  return (NULL);
}

static int _get_RunPath (char *callpath)
{
  char buff[LONG_STRING];

  if (safe_strchr (callpath, '/'))		/* call by path */
  {
    if (callpath[0] == '/')			/* absolute path */
      buff[0] = 0;
    else if (!getcwd (buff, sizeof(buff) - 7))
      return -1;
    else					/* path from current */
      strfcpy (&buff[strlen(buff)], "/", 2);	/* insert '/' */
    strfcat (buff, callpath, sizeof(buff));	/* generate full path */
  }
  else
  {
    register char *path = getenv ("PATH");
    register char *c;
    struct stat st;
    uid_t uid = getuid();
    gid_t gid = getgid();

    if (!path)
      path = "/bin:/usr/bin";			/* default PATH */
    while (path && *path)
    {
      register size_t s;

      if (path[0] == ':')
	path++;
      if (path[0] == 0)
	break;
      c = strchr (path, ':');
      if (c)
	s = c - path;
      else
	s = strlen(path);
      if (s > sizeof(buff) - 4)
	s = sizeof(buff) - 4;
      memcpy (buff, path, s);
      buff[s++] = '/';
      strfcpy (&buff[s], callpath, sizeof(buff) - s);
      if (stat (buff, &st) == 0 &&		/* check permission for me */
	  ((st.st_uid == uid && (st.st_mode & S_IXUSR)) ||	/* owner */
	  (st.st_gid == gid && (st.st_mode & S_IXGRP)) ||	/* group */
	  (st.st_mode & S_IXOTH)))				/* world */
	break;
      path += s;				/* next in PATH */
    }
    if (!path || !path[0])			/* no such file */
      return -1;
  }
  if (O_DLEVEL > 2 && O_QUIET == FALSE)
    fprintf (stderr, "[--:--] main: running %s\n", buff);
  RunPath = safe_strdup (buff);
  return 0;
}

static char Usage[] = N_("\
Usage:\tfoxeye [-n nick] [-cqdmt] <file>\t\t- normal run\n\
\tfoxeye -cr [-n nick] [-dm] [-g <file>]\t- run with defaults\n\
\tfoxeye -[h|v]\t\t\t\t- print info and return\n\
\n\
options:\n\
  -c\t\tdon't detach console (chat simulation mode)\n\
  -d\t\tincrease a debug level by one\n\
  -g <file>\tgenerate a config file\n\
  -h\t\tthis help message\n\
  -m\t\tmake an empty user and channel files\n\
  -n <nick>\tset default nick\n\
  -q\t\tprint only fatal errors (aborts -c, -h, and -v options)\n\
  -r\t\treset parameters (don't use the config file statements)\n\
  -t\t\ttest the configuration and exit\n\
  -v\t\tversion information\n\
   <file>\tconfig file name\n\
");

static void print_version (void)
{
  struct utsname buf;

  uname (&buf);
  printf ("FoxEye " VERSION "\n");
  printf (_("Copyright (C) 1999-2010 Andriy Gritsenko.\n\n\
OS: %s %s on %s.\n"), buf.sysname, buf.release, buf.machine);
}

int main (int argc, char *argv[])
{
  int have_con = 0;
  INTERFACE if_console;
  FILE *fp;
  int ch;
  char *c;
  peer_t *dcc = safe_calloc (1, sizeof(peer_t));
  char buff[STRING];
  pthread_t sit;

  if ((c = getenv ("LANG")))
    strfcpy (locale, c, sizeof(locale));
  if ((c = strchr (locale, '.')))
  {
    *c++ = 0;
    strfcpy (Charset, c, sizeof(Charset));
  }
  foxeye_setlocale();
  buff[0] = 0;
  /* parse command line parameters */
  while ((ch = getopt (argc, argv, "cdDg:hmn:qrtvw")) > 0)
  {
    switch (ch)
    {
      case 'c':		/* chat simulation (console mode) */
	have_con = 1;
	break;
      case 'm':		/* make userfile & channelfile */
	O_MAKEFILES = TRUE;
	break;
      case 't':		/* test the config and exit */
	O_TESTCONF = TRUE;
	break;
      case 'h':		/* help */
	if (O_QUIET == FALSE)
	  printf ("%s", Usage);
	return 0;
      case 'd':		/* increase debug level */
	O_DLEVEL++;
	break;
      case 'D':		/* fast debuglog on */
	O_DDLOG = TRUE;
	break;
      case 'r':		/* reset with defaults */
	O_DEFAULTCONF = TRUE;
	have_con = 1;
	break;
      case 'g':		/* generate a config */
        O_GENERATECONF = TRUE;
	strfcpy (buff, optarg, sizeof(buff));
	break;
      case 'n':		/* set nickname to Nick */
	strfcpy (Nick, optarg, NAMEMAX+1);
	break;
      case 'v':		/* version information */
	if (O_QUIET == FALSE)
	  print_version();
	return 0;
      case 'w':		/* undocumented: for debug purpose. */
	O_WAIT = TRUE;
	break;
      case 'q':		/* be quiet on stderr */
	O_QUIET = TRUE;
	break;
      case '?':		/* unknown option */
      case ':':		/* parameter missing */
      default:
	if (O_QUIET == FALSE)
	  fprintf (stderr, "%s", Usage);
	return 1;
    }
  }
  if (O_QUIET == TRUE)
    have_con = 0;
  if (optind < argc && buff[0] == 0)
    strfcpy (buff, argv[optind], sizeof(buff));
  StrTrim (buff);
  /* get config path */
  if (buff[0])
  {
    char Path[2*_POSIX_PATH_MAX];
    size_t pl;

    if (buff[0] == '/')			/* it's absolute path */
      Config = safe_strdup (buff);
    else if (getcwd (Path, sizeof(Path)))
    {
      pl = safe_strlen (Path);
      snprintf (&Path[pl], sizeof(Path) - pl, "/%s", buff);
      Config = safe_strdup (Path);
    }
    if (Config)
    {
      char *ch = strrchr (Config, '/');

      *ch = 0;				/* isolate path from name */
      if (chdir (Config))		/* check if path is accessible */
      {
	perror ("cannot chdir");
	return 1;			/* fatal error */
      }
      *ch = '/';
    }
  }
  /* check the parameters */
  if (Config == NULL && O_DEFAULTCONF == FALSE)
  {
    if (O_QUIET == FALSE)
      fprintf (stderr, _("Incorrect options. Type 'foxeye -h' for more help.\n"));
    return 1;
  }
  /* try to get Nick */
  if (O_DEFAULTCONF == FALSE && !*Nick && Config && (fp = fopen (Config, "r")))
  {
    char *ne = &buff[2];		/* skip `#!' magic */

    if (fgets (buff, sizeof(buff), fp))	/* try to get RunPath from config */
    {
      while (*ne && *ne == ' ') ne++;
      StrTrim (ne);
      if (buff[0] == '#' && buff[1] == '!')
	RunPath = safe_strdup (ne);
    }
    while (fgets (buff, sizeof(buff), fp))
    {
      if (!safe_strncmp (buff, "set nick ", 9))
	break;
      else
	buff[0] = 0;
    }
    fclose (fp);
    if (buff[0] == 's')
    {
      ne = NextWord (&buff[8]);
      StrTrim (ne);
      if (*ne == '"')
      {
	strfcpy (Nick, &ne[1], sizeof(Nick));
	for (ne = Nick; *ne && *ne != '"'; ne++);
      }
      else
      {
	strfcpy (Nick, ne, sizeof(Nick));
	for (ne = Nick; *ne && *ne != ' '; ne++);
      }
      *ne = 0;
    }
  }
  if (O_GENERATECONF == TRUE && !RunPath && _get_RunPath (argv[0]))
  {
    perror ("get run path");
    return 1;
  }
  /* set console interface */
  if (pipe (Fifo_Inp) || pipe (Fifo_Out))
  {
    perror ("console create");
    return 4;
  }
  /* set non-blocking mode for child */
  fcntl (Fifo_Inp[0], F_SETFL, O_NONBLOCK);
  fcntl (Fifo_Out[1], F_SETFL, O_NONBLOCK);
  if (have_con)
    if_console.ift = I_CONSOLE | I_LOG | I_DIRECT;
  else
    if_console.ift = I_LOCKED | I_DIED;
  if_console.name = safe_strdup ("::0");
  if_console.IFSignal = &_signal;
  if_console.IFRequest = &_request;
  if_console.prev = NULL;
  if_console.data = dcc;
  dcc->state = P_TALK;
  dcc->socket = -1;
  dcc->uf = (userflag)-1;
  /* run the dispatcher and fork there */
  if ((ch = dispatcher (&if_console)))
    return (ch);
  close (Fifo_Inp[0]);
  close (Fifo_Out[1]);
  /* cycle console */
  if (pthread_create (&sit, NULL, &_stdin2pipe, NULL))	/* create input */
  {
    if (O_QUIET == FALSE)
      perror ("console input create");
  }
  else FOREVER					/* and here output part */
  {
    if (have_con && (ch = read (Fifo_Out[0], buff, sizeof(buff) - 1)) > 0)
    {
      buff[ch] = 0;
      if (buff[0])
	fprintf (stderr, "%s", buff);		/* buff can contain %'s! */
    }
    else
    {						/* broken pipe - kill all */
      pthread_cancel (sit);
      pthread_join (sit, NULL);
      break;
    }
  }
  close (Fifo_Inp[1]);
  close (Fifo_Out[0]);
  return 0;
}
