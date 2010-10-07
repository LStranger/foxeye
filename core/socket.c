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
 * This file is part of FoxEye's source: sockets library.
 */

#include "foxeye.h"

#include <netinet/in.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <signal.h>
#include <setjmp.h>
#include <fcntl.h>
#include <errno.h>

#include "socket.h"

#ifndef HAVE_SIGACTION
# define sigaction sigvec
#ifndef HAVE_SA_HANDLER
# define sa_handler sv_handler
# define sa_mask sv_mask
# define sa_flags sv_flags
#endif
#endif /* HAVE_SIGACTION */

#ifdef HAVE_SYS_FILIO_H
# include <sys/filio.h>
#endif

typedef struct
{
  char *domain;			/* if free then this is NULL */
  unsigned short port;
  int ready;
} socket_t;

static pid_t _mypid;

static socket_t *Socket = NULL;
static idx_t _Salloc = 0;
static idx_t _Snum = 0;
static struct pollfd *Pollfd = NULL;

static pthread_mutex_t LockPoll = PTHREAD_MUTEX_INITIALIZER;

static void sigio_handler (int signo)
{
  poll (Pollfd, _Snum, 0);
}

void CloseSocket (idx_t idx)
{
  if (Pollfd[idx].fd != -1)
  {
    shutdown (Pollfd[idx].fd, SHUT_RDWR);
    close (Pollfd[idx].fd);
    Pollfd[idx].fd = -1;
  }
}

/*
 * returns -1 if too many opened sockets or idx 
 * note: there may be a problem with Socket[idx].domain and _Snum since its
 * are never locked but in reality these words must be changed at once so I
 * hope it must work anyway
*/
static idx_t allocate_socket ()
{
  idx_t idx;

  for (idx = 0; idx < _Snum; idx++)
    if (Socket[idx].domain == NULL && Pollfd[idx].fd == -1)
      break;
  if (idx == _Salloc)
    return -1; /* no free sockets! */
  Pollfd[idx].fd = -1;
  Pollfd[idx].events = POLLIN | POLLPRI | POLLOUT | POLLHUP | POLLERR;
  Pollfd[idx].revents = 0;
  Socket[idx].domain = NULL;
  Socket[idx].ready = FALSE;
  if (idx == _Snum)
    _Snum++;
  DBG ("allocate_socket: got socket %hd", idx);
  return idx;
}

/*
 * returns E_NOSOCKET on error and E_AGAIN on wait to connection
 */
ssize_t ReadSocket (char *buf, idx_t idx, size_t sr, int mode)
{
  socket_t *sock;
  ssize_t sg = -1;
  short rev;

  pthread_testcancel();				/* for non-POSIX systems */
  if (idx < 0 || idx >= _Snum)
    return (E_NOSOCKET);
  sock = &Socket[idx];
  if (Pollfd[idx].fd < 0)
    rev = POLLERR;
  else
    rev = Pollfd[idx].revents;
  /* now check for incomplete connection... */
  if (sock->ready == FALSE)
  {
    if (!(rev & (POLLIN | POLLPRI | POLLERR | POLLOUT)))
      return (E_AGAIN);		/* still waiting for connection */
    if (rev & POLLERR)
    {
      CloseSocket (idx);
      return (E_ERRNO - errno);	/* connection timeout or other error */
    }
    sock->ready = TRUE;		/* connection established! */
  }
  if (!rev && mode == M_POLL)
  {
    poll (&Pollfd[idx], 1, POLL_TIMEOUT);
    rev = Pollfd[idx].revents;
  }
  if (rev & POLLNVAL)
    CloseSocket (idx);
  if (rev & (POLLNVAL | POLLERR))
    return (E_NOSOCKET);
  else if (rev & (POLLIN | POLLPRI))
  {
    DBG ("trying read socket %d", idx);
    if ((sg = read (Pollfd[idx].fd, buf, sr)) > 0 && mode != M_RAW)
      DBG ("got from socket %d:[%-*.*s]", idx, sg, sg, buf);
    if (sg < 0)
    {
      CloseSocket (idx);		/* if socket died then close it */
      return (E_ERRNO - errno);		
    }
    Pollfd[idx].revents = 0;		/* we read socket, reset state */
  }
  else
    return 0;
  return (sg);
}

/*
 * returns: -1 if error or number of writed bytes from buf
 */
ssize_t WriteSocket (idx_t idx, const char *buf, size_t *ptr, size_t *sw, int mode)
{
  socket_t *sock;
  short rev;

  pthread_testcancel();				/* for non-POSIX systems */
  if (idx < 0 || idx >= _Snum || Pollfd[idx].fd < 0)
    return -1;
  if (!buf || !sw)
    return 0;
  rev = Pollfd[idx].revents;
  sock = &Socket[idx];
  if (!rev)	/* we need to poll it since we never get SIGIO for that */
  {
    poll (&Pollfd[idx], 1, mode == M_POLL ? POLL_TIMEOUT : 0);
    rev = Pollfd[idx].revents;
  }
  if (rev & POLLNVAL)			/* socket destroyed already */
    CloseSocket (idx);
  if (rev & (POLLNVAL | POLLERR))	/* any error */
    return -1;
  else
  {
    ssize_t sg;

    if (!(rev & POLLOUT))
      return 0;
    sg = write (Pollfd[idx].fd, &buf[*ptr], *sw);
    Pollfd[idx].revents = 0;		/* we wrote socket, reset state */
    if (sg <= 0)			/* EAGAIN */
      return 0;
    *ptr += sg;
    *sw -= sg;
    sock->ready = TRUE;			/* connected as we sent something */
    return (sg);
  }
}

int KillSocket (idx_t *idx)
{
  idx_t i = *idx;

  DBG ("socket:KillSocket %d", (int)i);
  if (i < 0)
    return -1;
  *idx = -1;			/* no more access to that socket */
  if (i >= _Snum)
    return -1;			/* no such socket */
  dprint (4, "socket:KillSocket: fd=%d", Pollfd[i].fd);
  CloseSocket (i);		/* must be first for reentrance */
  Socket[i].port = 0;
  FREE (&Socket[i].domain);	/* indicator of free socket */
  return 0;
}

idx_t GetSocket (unsigned short type)
{
  idx_t idx;
  int sockfd;

  pthread_mutex_lock (&LockPoll);
  if ((idx = allocate_socket()) < 0)
    sockfd = -1; /* too many sockets */
  else if (type == M_UNIX)
    Pollfd[idx].fd = sockfd = socket (AF_UNIX, SOCK_STREAM, 0);
  else
    Pollfd[idx].fd = sockfd = socket (AF_INET, SOCK_STREAM, 0);
  pthread_mutex_unlock (&LockPoll);
  /* note: there is a small chance we get it closed right away if there was
     two of CloseSocket() in the same time and we managed to get it between
     close() and resetting Pollfd[idx].fd */
  if (sockfd == -1)
    return (E_NOSOCKET);
  Socket[idx].port = type;
  return idx;
}

/* For a listening process - we have to get ECONNREFUSED to own port :) */
int SetupSocket (idx_t idx, char *domain, unsigned short port)
{
  struct sockaddr_in sin;
  struct sockaddr_un sun;
  struct sockaddr *sa;
  socklen_t len;
  struct hostent *hptr = NULL;
  struct linger ling;
  int i = 1, sockfd = Pollfd[idx].fd, type = (int)Socket[idx].port;

  /* check for errors! */
  if (!domain && type != M_LIST && type != M_LINP)
    return (E_UNDEFDOMAIN);
  if (type == M_UNIX)
  {
    sun.sun_family = AF_UNIX;
    strfcpy (sun.sun_path, domain, sizeof(sun.sun_path));
    if (unlink (sun.sun_path))
      return (E_ERRNO - errno);
    sa = (struct sockaddr *)&sun;
    len = SUN_LEN (&sun);
    Socket[idx].port = 0;		/* should be 0 for Unix socket */
  }
  else
  {
    memset (&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons (port);
    sa = (struct sockaddr *)&sin;
    len = sizeof(sin);
    if (!domain)
      sin.sin_addr.s_addr = htonl (INADDR_ANY);
    else
    {
      hptr = gethostbyname (domain);
      if (!hptr || !hptr->h_addr_list[0])
	return (E_NOSUCHDOMAIN);
      memcpy (&sin.sin_addr, hptr->h_addr_list[0], hptr->h_length);
    }
  }
  setsockopt (sockfd, SOL_SOCKET, SO_KEEPALIVE, (void *) &i, sizeof(i));
  setsockopt (sockfd, SOL_SOCKET, SO_REUSEADDR, (void *) &i, sizeof(i));
  ling.l_onoff = 1;
  ling.l_linger = 0;
  setsockopt (sockfd, SOL_SOCKET, SO_LINGER, (void *) &ling, sizeof(ling));
  fcntl (sockfd, F_SETOWN, _mypid);
  if (type == M_LIST || type == M_LINP || type == M_UNIX)
  {
    int backlog = 3;

    if (type == M_LINP)
      backlog = 1;
    if (bind (sockfd, (struct sockaddr *)&sin, sizeof(sin)) < 0 ||
	listen (sockfd, backlog) < 0 ||
	getsockname (sockfd, (struct sockaddr *)&sin, &len) < 0)
      return (E_ERRNO - errno);
    if (type != M_UNIX)
      Socket[idx].port = ntohs (sin.sin_port);
  }
  else
  {
    if ((i = connect (sockfd, (struct sockaddr *)&sin, sizeof(sin))) < 0)
      return (E_ERRNO - errno);
    Socket[idx].port = port;
  }
#ifdef HAVE_SYS_FILIO_H		/* non-BSDish systems have not O_ASYNC flag */
  i = 1;
  ioctl (sockfd, FIONBIO, &i);
  ioctl (sockfd, FIOASYNC, &i);
#else
  fcntl (sockfd, F_SETFL, O_NONBLOCK | O_ASYNC);
#endif
  if (type != M_UNIX)
  {
    hptr = gethostbyaddr ((char *)&sin.sin_addr, sizeof(sin.sin_addr), AF_INET);
    if (hptr && hptr->h_name)
      domain = hptr->h_name;	/* subst canonical name */
  }
  Socket[idx].domain = safe_strdup (domain);
  return 0;
}

idx_t AnswerSocket (idx_t listen)
{
  idx_t idx;
  struct sockaddr_in cliaddr;
  struct sockaddr_un cliua;
  struct hostent *hptr = NULL;
  int sockfd;
  short rev;
  socklen_t len;

  pthread_testcancel();				/* for non-POSIX systems */
  if (listen < 0 || listen >= _Snum || Pollfd[listen].fd < 0)
    return (E_NOSOCKET);
  rev = Pollfd[listen].revents;
  if (!rev)
  {
    poll (&Pollfd[listen], 1, POLL_TIMEOUT);
    rev = Pollfd[listen].revents;
  }
  if (!(rev & (POLLIN | POLLPRI | POLLNVAL | POLLERR)) || /* no events */
      (rev & (POLLHUP | POLLOUT)))	/* or we are in CloseSocket() now */
    return (E_AGAIN);
  else if (rev & POLLNVAL)
  {
    CloseSocket (listen);
    return (E_NOSOCKET);
  }
  else if (rev & POLLERR)
    return (E_ERRNO);
  DBG ("AnswerSocket: got 0x%hx for %hd", rev, listen);
  pthread_mutex_lock (&LockPoll);
  if ((idx = allocate_socket()) < 0)
    sockfd = -1;
  else if (Socket[listen].port == 0)	/* Unix socket */
  {
    len = sizeof(cliua);
    Pollfd[idx].fd = sockfd = accept (Pollfd[listen].fd, (struct sockaddr *)&cliua, &len);
    Socket[idx].port = 0;
  }
  else
  {
    len = sizeof(cliaddr);
    Pollfd[idx].fd = sockfd = accept (Pollfd[listen].fd, (struct sockaddr *)&cliaddr, &len);
  }
  pthread_mutex_unlock (&LockPoll);
  Pollfd[listen].revents = 0;		/* we accepted socket, reset state */
  if (sockfd == -1)
    return (E_AGAIN);
  fcntl (sockfd, F_SETOWN, _mypid);
#ifdef HAVE_SYS_FILIO_H		/* non-BSDish systems have not O_ASYNC flag */
  {
    int i = 1;
    ioctl (sockfd, FIONBIO, &i);
    ioctl (sockfd, FIOASYNC, &i);
  }
#else
  fcntl (sockfd, F_SETFL, O_NONBLOCK | O_ASYNC);
#endif
  if (Socket[listen].port == 0)
    return (idx);		/* no domains for Unix sockets */
  Socket[idx].port = ntohs (cliaddr.sin_port);
  hptr = gethostbyaddr ((char *)&cliaddr.sin_addr, sizeof(cliaddr.sin_addr),
			AF_INET);
  if (hptr && hptr->h_name)
    Socket[idx].domain = safe_strdup (hptr->h_name); /* subst canonical name */
  else
  {
    char nd[16];			/* XXX.XXX.XXX.XXX */
    uint32_t ad = htonl (cliaddr.sin_addr.s_addr);

    Socket[idx].domain = safe_strdup (inet_ntop (AF_INET, &ad, nd, sizeof(nd)));
  }
  return (idx);
}

char *SocketDomain (idx_t idx, unsigned short *port)
{
  char *d = NULL;
  /* check if idx is invalid */
  if (idx >= 0 && idx < _Snum)
  {
    if (port)
      *port = Socket[idx].port;
    d = Socket[idx].domain;
  }
  return NONULL(d);
}

char *SocketError (int er, char *buf, size_t s)
{
  if (!buf)
    return NULL;
  else if (er < E_ERRNO)
    strerror_r (E_ERRNO - er, buf, s);
  else switch (er)
  {
    case 0:
      buf[0] = 0;
      break;
    case E_AGAIN:
      strfcpy (buf, "socket is waiting for connection", s);
      break;
    case E_NOSOCKET:
      strfcpy (buf, "no such socket", s);
      break;
    case E_NOTHREAD:
      strfcpy (buf, "cannot create listening thread", s);
      break;
    case E_UNDEFDOMAIN:
      strfcpy (buf, "domain not defined", s);
      break;
    case E_NOSUCHDOMAIN:
      strfcpy (buf, "no such domain", s);
      break;
//    case E_NOCONNECT:
//      strfcpy (buf, "cannot connect to host", s);
//      break;
    default:
      strfcpy (buf, "unknown socket error", s);
  }
  return buf;
}

int _fe_init_sockets (void)
{
  struct sigaction act;

  /* allocate sockets structures */
  if (_Salloc == 0)
  {
    _Salloc = SOCKETMAX;
    Socket = safe_malloc (SOCKETMAX * sizeof(socket_t));
    Pollfd = safe_malloc (SOCKETMAX * sizeof(struct pollfd));
  }
  /* init SIGIO handler */
  _mypid = getpid();
  act.sa_handler = &sigio_handler;
  sigemptyset (&act.sa_mask);
  act.sa_flags = 0;
  return (sigaction (SIGIO, &act, NULL));
}
