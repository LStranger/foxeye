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
 * This is main startup file and console interface.
 */

void unknown (void);

#define MAIN_C 1

#include "foxeye.h"

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#include <locale.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/poll.h>
#include <sys/utsname.h>
#include <errno.h>
#include <signal.h>

#include "init.h"
#include "dcc.h"

#ifndef HAVE_SIGACTION
# define sigaction sigvec
#ifndef HAVE_SA_HANDLER
# define sa_handler sv_handler
# define sa_mask sv_mask
# define sa_flags sv_flags
#endif
#endif /* HAVE_SIGACTION */

static int Fifo_Inp[2];		/* console keyboard */
static int Fifo_Out[2];		/* console display */

static REQUEST Req_EOF = {0, NULL, I_DIED, "", ""};

/* ------------------------------
 * child side */

static REQUEST *_kill_pipe (void)
{
  close (Fifo_Inp[0]);
  close (Fifo_Out[1]);
  return (&Req_EOF);
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

ssize_t _read_pipe (char *buf, size_t sr)
{
  ssize_t sg;

  buf[0] = 0;				/* line terminator if EAGAIN */
  if ((sg = _pipe_find_line()) < 0);
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
  if (sg >= sr)
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

ssize_t _write_pipe (char *buf, size_t *sw)
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
    else if (sg != *sw)
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

static REQUEST *_request (INTERFACE *iface, REQUEST *req)
{
  DCC_SESSION *dcc = (DCC_SESSION *)iface->data;
  ssize_t sw;
  char buff[MESSAGEMAX];
  volatile int to_all;

  /* first time? */
  if (!dcc->iface)
  {
    dcc->iface = dcc->alias = iface;
    close (Fifo_Inp[1]);
    close (Fifo_Out[0]);
  }
  if (req)
  {
    to_all = Have_Wildcard (req->mask) + 1;
    /* check if this is: not for me exactly, but from me and no echo */
    if (req->from == iface && (req->mask_if & I_DCCALIAS) && to_all &&
	!(dcc->loglev & F_ECHO))
      req = NULL;
  }
  /* check if we have empty output buf */
  while (dcc->buf[0] || req)
  {
    if (req && dcc->buf[0])
      req->flag |= F_REJECTED;
    else if (req)
    {
      /* for logs - if not from me */
      if (to_all && (req->mask_if & I_LOG))
      {
	if (req->flag & dcc->loglev)
	{
	  printl (dcc->buf, sizeof(dcc->buf) - 1, "[%t] %*", 0,
		  NULL, NULL, NULL, NULL, 0, 0, req->string);
	}
      }
      /* not do reports... */
      else if (*req->string > '\026' && *req->string < '\037' &&
	       (dcc->state == D_R_WHO || dcc->state == D_R_WHOM ||
	       dcc->state == D_R_DCCSTAT))
      {
	if (req->string[1] == '\002')
	  dcc->state = D_CHAT;
      }
      /* for chat channel messages */
      else if (req->from && (req->from->iface & I_CHAT) && to_all &&
	       (req->mask_if & I_DCCALIAS))
      {
	char *prefix = "";
	char *suffix = "";
	char *str = req->string;

	if (req->flag & F_NOTICE)
	    prefix = "*** ";
	else if (*str == '.')
	{
	  prefix = "* ";
	  str++;
	}
	else
	{
	  prefix = "<";
	  suffix = ">";
	}
	snprintf (dcc->buf, sizeof(dcc->buf) - 1, "%s%s%s %s", prefix,
		  req->from->name, suffix, str);
      }
      /* direct messages */
      else
	strfcpy (dcc->buf, req->string, sizeof(dcc->buf) - 1);
      sw = safe_strlen (dcc->buf);
      if (sw && !(req->from->iface & I_INIT))	/* ending with newline */
	strfcpy (&dcc->buf[sw], "\n", 2);
      req = NULL;		/* request done */
    }
    sw = safe_strlen (dcc->buf);
    /* write the buffer to pipe, same as Write_Socket() does */
    if (sw)
      sw = _write_pipe (dcc->buf, (size_t *)&sw);
    if (sw < 0)			/* error, kill the pipe... */
      return _kill_pipe();
    if (!(iface->iface & I_DCCALIAS))
      continue;			/* write pipe if in config */
    else if (req)
      return req;		/* don't input until empty buffer */
    break;			/* normal run */
  }
  /* read the string from the pipe to buffer and supress ending CR/LF */
  sw = _read_pipe (buff, sizeof(buff));
  if (sw < 0)			/* error, kill the pipe... */
    return _kill_pipe();
  if (!(iface->iface & I_DCCALIAS) && buff[0])	/* return to config anyway */
    Add_Request (I_INIT, "*", 0, buff);
  else if (!sw)
    return NULL;
  /* run command */
  else if (buff[0] == '.')
    Dcc_Exec (dcc, "", buff, NULL, -1, -1, -2);
  else
  {
    char ch[16];

    snprintf (ch, sizeof(ch), ":*:%u", dcc->botnet);
    Add_Request (I_DCCALIAS, ch, F_BOTNET, buff);
  }
  return NULL;
}

static iface_t _signal (INTERFACE *iface, ifsig_t signal)
{
  if (signal == S_TERMINATE)
  {
    _kill_pipe();
    FREE (&((DCC_SESSION *)iface->data)->away);
    iface->iface = I_CONSOLE | I_DIED;
    return (int)I_DIED;
  }
  else if (signal == S_SHUTDOWN)
  {
    if (BindResult)
    {
      write (Fifo_Out[1], BindResult, safe_strlen (BindResult));
      write (Fifo_Out[1], "\n", 1);
    }
    _kill_pipe();
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
    write (Fifo_Inp[1], buff, safe_strlen(buff));
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
      if (path[0] == ':')
	path++;
      if (path[0] == 0)
	break;
      strfcpy (buff, path, sizeof(buff) - 3);
      c = safe_strchr (buff, ':');
      if (!c)
	c = &buff[strlen(buff)];
      *c++ = '/';
      *c = 0;
      strfcat (buff, callpath, sizeof(buff));
      if (stat (buff, &st) == 0 &&		/* check permission for me */
	  ((st.st_uid == uid && (st.st_mode & S_IXUSR)) ||	/* owner */
	  (st.st_gid == gid && (st.st_mode & S_IXGRP)) ||	/* group */
	  (st.st_mode & S_IXOTH)))				/* world */
	break;
      path = safe_strchr (buff, ':');		/* next in PATH */
    }
    if (!path || !path[0])			/* no such file */
      return -1;
  }
  if (O_DLEVEL > 2)
    fprintf (stderr, "[--:--] main: running %s\n", buff);
  RunPath = safe_strdup (buff);
  return 0;
}

static char Usage[] = N_("\
Usage:\tfoxeye [-n nick] [-cdmt] <file>\t\t- normal run\n\
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
  -r\t\treset parameters (don't use the config file statements)\n\
  -t\t\ttest the configuration and exit\n\
  -v\t\tversion information\n\
   <file>\tconfig file name\n\
");

#define version_string "FoxEye " ## VERSION ## "\n"
static void print_version (void)
{
  struct utsname buf;

  uname (&buf);
  printf (version_string);
  printf (_("Copiright (C) 1999-2002 Andriy Gritsenko.\n\n\
System: %s %s on %s.\n"), buf.sysname, buf.release, buf.machine);
}
#undef version_string

int main (int argc, char *argv[])
{
  int have_con = 0;
  INTERFACE if_console;
  FILE *fp;
  int ch;
  DCC_SESSION *dcc = safe_calloc (1, sizeof(DCC_SESSION));
  char buff[STRING];
  pthread_t sit;

  strfcpy (locale, getenv ("LANG"), sizeof(locale));
  setlocale (LC_ALL, "");
#ifdef ENABLE_NLS
  bindtextdomain (PACKAGE, LOCALEDIR);
  textdomain (PACKAGE);
#endif
  buff[0] = 0;
  /* parse command line parameters */
  while ((ch = getopt (argc, argv, "cdg:hmn:rtvw")) > 0)
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
	printf (Usage);
	return 0;
      case 'd':		/* increase debug level */
	O_DLEVEL++;
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
	strfcpy (Nick, optarg, NICKMAX+1);
	break;
      case 'v':		/* version information */
	print_version();
	return 0;
      case 'w':
	O_WAIT = 1;
	break;
      case '?':		/* unknown option */
      case ':':		/* parameter missing */
      default:
	fprintf (stderr, Usage);
	return 1;
    }
  }
  if (optind < argc && buff[0] == 0)
    strfcpy (buff, argv[optind], sizeof(buff));
  StrTrim (buff);
  /* get config path */
  if (buff[0])
  {
    char Path[2*_POSIX_PATH_MAX];
    size_t pl;

    if (getcwd (Path, sizeof(Path)))
    {
      pl = safe_strlen (Path);
      snprintf (&Path[pl], sizeof(Path) - pl, "/%s", buff);
      Config = safe_strdup (Path);
    }
  }
  /* check the parameters */
  if (Config == NULL && O_DEFAULTCONF == FALSE)
  {
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
    if_console.iface = I_CONSOLE | I_LOG | I_TELNET | I_CHAT;
  else
    if_console.iface = I_LOCKED;
  if_console.name = safe_strdup ("::0");
  if_console.IFSignal = &_signal;
  if_console.IFRequest = &_request;
  if_console.prev = NULL;
  if_console.data = dcc;
  dcc->state = D_CHAT;
  dcc->socket = -1;
  dcc->uf = -1;
  dcc->loglev = F_MSGS | F_CMDS | F_CONN | F_USERS | F_BOOT | F_CRAP |
		F_DEBUG | F_COLOR | F_COLORCONV;
  /* run the dispatcher and fork there */
  if ((ch = dispatcher (&if_console)))
    return (ch);
  close (Fifo_Inp[0]);
  close (Fifo_Out[1]);
  /* cycle console */
  if (pthread_create (&sit, NULL, &_stdin2pipe, NULL))	/* create input */
    perror ("console input create");
  else FOREVER					/* and here output part */
  {
    ch = read (Fifo_Out[0], buff, sizeof(buff) - 1);
    if (ch > 0)
    {
      buff[ch] = 0;
      if (buff[0])
	fprintf (stderr, buff);
    }
    else
    {						/* broken pipe - kill all */
      pthread_kill (sit, SIGTERM);
      break;
    }
  }
  close (Fifo_Inp[1]);
  close (Fifo_Out[0]);
  return 0;
}
