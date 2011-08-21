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
 * This file is part of FoxEye's source: sockets library.
 */

#include "foxeye.h"

#include <netinet/in.h>
#include <sys/un.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/poll.h>
#include <signal.h>
#include <setjmp.h>
#include <fcntl.h>
#include <errno.h>

#include "socket.h"

#ifndef HAVE_SIGACTION
# define sigaction sigvec
# define sa_handler sv_handler
# define sa_mask sv_mask
# define sa_flags sv_flags
#endif /* HAVE_SIGACTION */

#ifdef HAVE_SYS_FILIO_H
# include <sys/filio.h>
#endif

/* solaris have this name as macro so drop it now */
#undef sun

/*
 * Sequence:		socket.domain:	pollfd.fd:
 * unallocated		NULL		-1
 * allocated		NULL		>= 0
 * domain resolved	domain		>= 0
 * shutdown		domain		-1
 * unallocated		NULL		-1
 */
typedef struct
{
  char *domain;			/* if free then this is NULL */
  char *ipname;
  sig_atomic_t ready;
  unsigned short port;
} socket_t;

typedef union {
  struct sockaddr	sa;
  struct sockaddr_in	s_in;
#ifdef ENABLE_IPV6
  struct sockaddr_in6	s_in6;
#endif
  struct sockaddr_un	s_un;
} inet_addr_t;

static pid_t _mypid;

static socket_t *Socket = NULL;
static idx_t _Salloc = 0;
static idx_t _Snum = 0;
static struct pollfd *Pollfd = NULL;

/* lock for socket allocation; deallocation will be done without lock */
static pthread_mutex_t LockPoll = PTHREAD_MUTEX_INITIALIZER;

//static volatile sig_atomic_t _got_sigio = 0;

/* this one is called only from main thread (due to F_SETOWN) so safe to poll */
static void sigio_handler (int signo)
{
  //_got_sigio = 1;
  poll(Pollfd, _Snum, 0);
}

/* use this as mark of unused socket, -1 is just freed one */
#define UNUSED_FD -2

void CloseSocket (idx_t idx)
{
  if (Pollfd[idx].fd >= 0)
  {
    DBG ("socket:CloseSocket: %hd (fd=%d)", idx, Pollfd[idx].fd);
    shutdown (Pollfd[idx].fd, SHUT_RDWR);
    close (Pollfd[idx].fd);
    Pollfd[idx].fd = -1;
  }
}

/*
 * returns -1 if too many opened sockets or idx
 * note: there may be a problem with Socket[idx].fd since it is never locked
 * but in reality that change is atomic operation so it must work anyway
 * while we lock _Snum with mutex
*/
static idx_t allocate_socket ()
{
  idx_t idx;

  for (idx = 0; idx < _Snum; idx++)
    if (Pollfd[idx].fd == UNUSED_FD)
      break;
  if (idx == _Salloc)
    return -1; /* no free sockets! */
  Pollfd[idx].fd = -1;
  Pollfd[idx].events = POLLIN | POLLPRI | POLLOUT;
  Pollfd[idx].revents = 0;
  Socket[idx].domain = NULL;
  Socket[idx].ipname = NULL;
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
  ssize_t sg = (ssize_t)-1;
  short rev;

  pthread_testcancel();			/* for non-POSIX systems */
  if (idx < 0 || idx >= _Snum || Pollfd[idx].fd < 0)
    return (E_NOSOCKET);
  sock = &Socket[idx];
//  {
//    if (_got_sigio)
//    {
//      _got_sigio = 0;
//      poll (Pollfd, _Snum, 0);
//    }
    rev = Pollfd[idx].revents;
//  }
  /* now check for incomplete connection... */
  if (sock->ready == FALSE)
  {
    if (!rev)
      return (E_AGAIN);		/* still waiting for connection */
    sock->ready = TRUE;		/* connection established or failed */
  }
  if (!rev && mode == M_POLL)
  {
    poll (&Pollfd[idx], 1, POLL_TIMEOUT);
    rev = Pollfd[idx].revents;
  }
  if (rev & (POLLNVAL | POLLERR | POLLHUP)) {
    CloseSocket (idx);
//    if (rev & POLLERR)
//      return (E_ERRNO - errno);		/* asynchronous error occurred */
    return (E_NOSOCKET);		/* cannot test errno variable ATM */
  }
  else if (rev & (POLLIN | POLLPRI))
  {
    DBG ("trying read socket %hd", idx);
    Pollfd[idx].revents = 0;		/* we'll read socket, reset state */
    if ((sg = read (Pollfd[idx].fd, buf, sr)) > 0 && mode != M_RAW)
      DBG ("got from socket %hd:[%-*.*s]", idx, (int)sg, (int)sg, buf);
    if (sg == 0) {
      CloseSocket (idx);		/* remote end closed connection */
      return (E_NOSOCKET);
    } else if (sg < 0) {
      if (errno == EAGAIN)
	return (0);
      sg = E_ERRNO - errno;		/* remember error for return */
    }
  }
  else
    return 0;
  return (sg);
}

/*
 * returns: < 0 if error or number of writed bytes from buf
 */
ssize_t WriteSocket (idx_t idx, const char *buf, size_t *ptr, size_t *sw, int mode)
{
  ssize_t sg;

  pthread_testcancel();			/* for non-POSIX systems */
  if (idx < 0 || idx >= _Snum || Pollfd[idx].fd < 0)
    return E_NOSOCKET;
  if (!buf || !sw)
    return 0;
  DBG ("trying write socket %hd: %p +%zu", idx, &buf[*ptr], *sw);
  sg = write (Pollfd[idx].fd, &buf[*ptr], *sw);
//  Pollfd[idx].revents = 0;		/* we wrote socket, reset state */
  if (sg < 0)
    return (errno == EAGAIN) ? 0 : (E_ERRNO - errno);
  else if (sg == 0)			/* remote end closed connection */
    return E_EOF;
  *ptr += sg;
  *sw -= sg;
  Socket[idx].ready = TRUE;		/* connected as we sent something */
  return (sg);
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
  FREE (&Socket[i].ipname);
  FREE (&Socket[i].domain);
  Pollfd[i].fd = UNUSED_FD;	/* indicator of free socket */
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
  if (sockfd < 0)
    return (E_NOSOCKET);
  Socket[idx].port = type;
  DBG ("socket:GetSocket: %d (fd=%d)", (int)idx, sockfd);
  return idx;
}

/* recover after failed SetupSocket */
void ResetSocket(idx_t idx, unsigned short type)
{
  register int sockfd;

  if (Pollfd[idx].fd >= 0)
    close(Pollfd[idx].fd);
  FREE (&Socket[idx].ipname);
  FREE (&Socket[idx].domain);
  if (type == M_UNIX)
    Pollfd[idx].fd = sockfd = socket (AF_UNIX, SOCK_STREAM, 0);
  else
    Pollfd[idx].fd = sockfd = socket (AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0)
    return;
  Socket[idx].port = type;
  DBG ("socket:ResetSocket: %d (fd=%d)", (int)idx, sockfd);
}

/* returns allocated ip textual representation for socket address */
static inline char *_make_socket_ipname(inet_addr_t *addr, char *buf,
					size_t bufsize)
{
  register const void *ptr;

#ifdef ENABLE_IPV6
  switch (addr->sa.sa_family) {	/* prepare ip textual representation */
  case AF_INET:
#endif
    ptr = &addr->s_in.sin_addr;
#ifdef ENABLE_IPV6
    break;
  case AF_INET6:
    ptr = &addr->s_in6.sin6_addr;
#if	0
			if ((ptr[0] == 0x0) && (ptr[1] == 0x0) &&
				(ptr[2] == 0x0) && (ptr[3] == 0x0) &&
				(ptr[4] == 0x0) && (ptr[5] == 0x0) &&
				(ptr[6] == 0x0) && (ptr[7] == 0x0) &&
				(ptr[8] == 0x0) && (ptr[9] == 0x0) &&
				(((ptr[10] == 0x0) && (ptr[11] == 0x0)) ||
				((ptr[10] == 0xFF) && (ptr[11] == 0xFF)))) {
				/* v4 to v6 mapped */
  }
#endif
    break;
  default:
    ptr = &in6addr_any;
  }
#endif
  return safe_strdup(inet_ntop(addr->sa.sa_family, ptr, buf, bufsize));
}

/* For a listening process - we have to get ECONNREFUSED to own port :) */
int SetupSocket(idx_t idx, const char *domain, unsigned short port,
		int (*callback)(const struct sockaddr *, void *),
		void *callback_data)
{
  int i, sockfd, type;
  socklen_t len;
  inet_addr_t addr;
  struct linger ling;
  char hname[NI_MAXHOST+1];

  /* check for errors! */
  if (idx < 0 || idx >= _Snum || Pollfd[idx].fd < 0)
    return (E_NOSOCKET);
  sockfd = Pollfd[idx].fd;
  type = (int)Socket[idx].port;
  if (!domain && type != M_LIST && type != M_LINP)
    return (E_UNDEFDOMAIN);
  if (type == M_UNIX)
  {
    addr.s_un.sun_family = AF_UNIX;
    strfcpy (addr.s_un.sun_path, domain, sizeof(addr.s_un.sun_path));
    if (unlink (addr.s_un.sun_path))
      return (E_ERRNO - errno);
    len = SUN_LEN (&addr.s_un);
    Socket[idx].port = 0;		/* should be 0 for Unix socket */
  }
  else
  {
    if (!domain) {
      /* NULL domain means we want listen every IPv4 address,
         for listening on every IPv6 we can ask for domain "::" */
      len = sizeof(addr.s_in);
      /* memset(&addr.s_in, 0, len); */
      addr.s_in.sin_family = AF_INET;
      addr.s_in.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
      struct addrinfo *ai;
#ifndef ENABLE_IPV6
      static struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = 0,
				       .ai_protocol = 0, .ai_flags = 0 };

      i = getaddrinfo (domain, NULL, &hints, &ai);
#else
      i = getaddrinfo (domain, NULL, NULL, &ai);
#endif
      if (i == 0)
      {
	inet_addr_t *ha = (inet_addr_t *)ai->ai_addr;

	len = ai->ai_addrlen;
	memcpy(&addr.sa, &ha->sa, len);
	/* addr.sa.sa_family = ai->ai_family; */
	freeaddrinfo (ai);
#ifdef ENABLE_IPV6
	if (addr.sa.sa_family != AF_INET) {
	  /* close IPv4 socket and open IPv6 one instead */
	  close(sockfd);
	  sockfd = socket(addr.sa.sa_family, SOCK_STREAM, 0);
	  DBG("closed IPv4 socket (fd=%d) and opened IPv6 one (fd=%d)",
	      Pollfd[idx].fd, sockfd);
	  Pollfd[idx].fd = sockfd;
	  if (sockfd < 0)
	    return (E_NOSOCKET);
	}
#endif
      }
      else if (i == EAI_AGAIN)
	return E_RESOLVTIMEOUT;
      else if (i == EAI_SYSTEM)
	return (E_ERRNO - errno);
      else
	return E_NOSUCHDOMAIN;
    }
    /* sockaddr_in is compatible with sockaddr_in6 up to port member */
    addr.s_in.sin_port = htons(port);
  }
  i = 1;
  setsockopt (sockfd, SOL_SOCKET, SO_KEEPALIVE, (void *) &i, sizeof(i));
  setsockopt (sockfd, SOL_SOCKET, SO_REUSEADDR, (void *) &i, sizeof(i));
  ling.l_onoff = 1;
  ling.l_linger = 0;
  setsockopt (sockfd, SOL_SOCKET, SO_LINGER, (void *) &ling, sizeof(ling));
  fcntl (sockfd, F_SETOWN, _mypid);
  if (type == M_LIST || type == M_LINP)
  {
    i = 3; /* backlog */
    if (type == M_LINP)
      i = 1;
    if (bind (sockfd, &addr.sa, len) < 0 || listen (sockfd, i) < 0 ||
	getsockname (sockfd, &addr.sa, &len) < 0)
      return (E_ERRNO - errno);
    /* update listening port with real opened one not asked */
    Socket[idx].port = ntohs (addr.s_in.sin_port);
  } else if (type == M_UNIX) {
    if (bind (sockfd, &addr.sa, len) < 0 || listen (sockfd, 3) < 0)
      return (E_ERRNO - errno);
  } else {
    if ((i = connect (sockfd, &addr.sa, len)) < 0)
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
    Socket[idx].ipname = _make_socket_ipname(&addr, hname, sizeof(hname));
    i = getnameinfo (&addr.sa, len, hname, sizeof(hname), NULL, 0, 0);
    /* TODO: work on errors? */
    if (i == 0)
      domain = hname;
    else if (domain == NULL) /* make it not NULL */
      domain = Socket[idx].ipname;
  }
  if (callback != NULL)
    return callback(&addr.sa, callback_data);
  Socket[idx].domain = safe_strdup (domain);
  return 0;
}

idx_t AnswerSocket (idx_t listen)
{
  idx_t idx;
  int sockfd, i;
  short rev;
  socklen_t len;
  inet_addr_t addr;
  char hname[NI_MAXHOST+1];

  pthread_testcancel();				/* for non-POSIX systems */
  if (listen < 0 || listen >= _Snum || Pollfd[listen].fd < 0)
    return (E_NOSOCKET);
  rev = Pollfd[listen].revents;
  if (!rev)
//  {
//    if (_got_sigio)
//    {
//      _got_sigio = 0;
//      poll (Pollfd, _Snum, 0);
//    }
//    else
      poll (&Pollfd[listen], 1, POLL_TIMEOUT);
//    rev = Pollfd[listen].revents;
//  }
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
    len = sizeof(addr.s_un);
    Pollfd[idx].fd = sockfd = accept (Pollfd[listen].fd, &addr.sa, &len);
    Socket[idx].port = 0;
  }
  else
  {
#ifdef ENABLE_IPV6
    len = sizeof(addr.s_in6);
#else
    len = sizeof(addr.s_in);
#endif
    Pollfd[idx].fd = sockfd = accept (Pollfd[listen].fd, &addr.sa, &len);
#ifdef ENABLE_IPV6
    switch (addr.sa.sa_family) {
    case AF_INET:
#endif
      Socket[idx].port = ntohs(addr.s_in.sin_port);
#ifdef ENABLE_IPV6
      break;
    case AF_INET6:
      Socket[idx].port = ntohs(addr.s_in6.sin6_port);
      break;
    }
#endif
  }
  pthread_mutex_unlock (&LockPoll);
  Pollfd[listen].revents = 0;		/* we accepted socket, reset state */
  if (sockfd < 0)
    return (E_AGAIN);
  fcntl (sockfd, F_SETOWN, _mypid);
#ifdef HAVE_SYS_FILIO_H		/* non-BSDish systems have not O_ASYNC flag */
  {
    i = 1;
    ioctl (sockfd, FIONBIO, &i);
    ioctl (sockfd, FIOASYNC, &i);
  }
#else
  fcntl (sockfd, F_SETFL, O_NONBLOCK | O_ASYNC);
#endif
  DBG ("socket:AnswerSocket: %hd (fd=%d)", idx, sockfd);
  if (Socket[listen].port == 0)
    return (idx);		/* no domains for Unix sockets */
  Socket[idx].ipname = _make_socket_ipname(&addr, hname, sizeof(hname));
  i = getnameinfo (&addr.sa, len, hname, sizeof(hname), NULL, 0, 0);
  if (i == 0)			/* subst canonical name */
    Socket[idx].domain = safe_strdup (hname);
  else				/* error of getnameinfo() */
    Socket[idx].domain = safe_strdup(Socket[idx].ipname);
  return (idx);
}

const char *SocketDomain (idx_t idx, unsigned short *port)
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

const char *SocketIP (idx_t idx)
{
  char *d = NULL;

  /* check if idx is invalid */
  if (idx >= 0 && idx < _Snum)
    d = Socket[idx].ipname;
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
    case E_RESOLVTIMEOUT:
      strfcpy (buf, "resolver temporary failure", s);
      break;
    case E_NOTHREAD:
      strfcpy (buf, "cannot create listening thread", s);
      break;
    case E_EOF:
      strfcpy (buf, "remote end closed connection", s);
      break;
    case E_UNDEFDOMAIN:
      strfcpy (buf, "domain not defined", s);
      break;
    case E_NOSUCHDOMAIN:
      strfcpy (buf, "no such domain", s);
      break;
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
