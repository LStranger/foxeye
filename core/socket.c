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

#ifndef SIGPOLL
# define SIGPOLL SIGURG
#endif

#ifndef SUN_LEN
/* FreeBSD doesn't have it in c99 mode */
#define SUN_LEN(su) \
	(sizeof(*(su)) - sizeof((su)->sun_path) + strlen((su)->sun_path))
#endif

/* solaris have this name as macro so drop it now */
#undef sun

/*
 * Sequence:		socket.domain:	pollfd.fd:
 * unallocated		NULL		-2
 * allocated		NULL		>= 0
 * domain resolved	domain		>= 0
 * shutdown		domain		-1
 * unallocated		NULL		-2
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

static pthread_t __main_thread;

static socket_t *Socket = NULL;
static idx_t _Salloc = 0;
static idx_t _Snum = 0;
static struct pollfd *Pollfd = NULL;

/* lock any access to whole Pollfd or write access to any element of it */
static pthread_mutex_t LockPoll = PTHREAD_MUTEX_INITIALIZER;

/* every thread will wait on this one */
static pthread_cond_t PollCond = PTHREAD_COND_INITIALIZER;

/* set when we updated Pollfd structure */
static sig_atomic_t SChanged = 0;

/* this one is called only from main thread (due to F_SETOWN) so safe to poll */
static void sigio_handler (int signo)
{
}

/* use this as mark of unused socket, -1 is just freed one */
#define UNUSED_FD -2

/*
 * returns -1 if too many opened sockets or idx
 * mutex should be locked so we don't have a conflict
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
  Pollfd[idx].events = POLLIN | POLLPRI;
  Pollfd[idx].revents = 0;
  Socket[idx].domain = NULL;
  Socket[idx].ipname = NULL;
  Socket[idx].ready = FALSE;
  if (idx == _Snum)
    _Snum++;
  DBG ("allocate_socket: got socket %hd", idx);
  SChanged = 1;
  return idx;
}

static void _socket_timedwait_cleanup(void *ptr)
{
  pthread_mutex_unlock(ptr);
}

/* unlocks LockPoll if cancelled */
static void _socket_timedwait(idx_t idx, int write)
{
  struct timespec abstime;

  if (write)
    Pollfd[idx].events = POLLIN | POLLPRI | POLLOUT;
  else
    Pollfd[idx].events = POLLIN | POLLPRI;
  if (pthread_equal(pthread_self(), __main_thread)) {
    poll (&Pollfd[idx], 1, 0);	/* don't wait in dispatcher */
    return;
  }
  SChanged = 1;			/* inform poll() in dispatcher */
  clock_gettime(CLOCK_REALTIME, &abstime);
  abstime.tv_nsec += POLL_TIMEOUT * 1000000;
  if (abstime.tv_nsec >= 1000000000) {
    abstime.tv_nsec -= 1000000000;
    abstime.tv_sec++;
  }
  pthread_cleanup_push(&_socket_timedwait_cleanup, &LockPoll);
  pthread_cond_timedwait(&PollCond, &LockPoll, &abstime);
  pthread_cleanup_pop(0);	/* leaves mutex locked */
}

/*
 * returns E_NOSOCKET on error and E_AGAIN on wait to connection
 */
ssize_t ReadSocket (char *buf, idx_t idx, size_t sr)
{
  socket_t *sock;
  ssize_t sg = -1;
  short rev;

  pthread_testcancel();			/* for non-POSIX systems */
  if (idx < 0 || idx >= _Snum || Pollfd[idx].fd < 0)
    return (E_NOSOCKET);
  sock = &Socket[idx];
  rev = Pollfd[idx].revents;
  pthread_mutex_lock(&LockPoll);
  if (!rev)
  {
    _socket_timedwait(idx, (sock->ready == FALSE) ? 1 : 0);
    rev = Pollfd[idx].revents;
  }
  Pollfd[idx].events |= (POLLIN|POLLPRI); /* update it for next read */
  Pollfd[idx].revents &= ~(POLLIN|POLLPRI); /* we'll read socket, reset state */
  SChanged = 1;				/* inform poll() in dispatcher */
  pthread_mutex_unlock(&LockPoll);
  if (!rev && (sock->ready == FALSE))	/* check for incomplete connection */
    return (E_AGAIN);			/* still waiting for connection */
  sock->ready = TRUE;			/* connection established or failed */
  if (rev & (POLLIN | POLLPRI)) {	/* even dead socket can contain data */
    DBG ("trying read socket %hd", idx);
    if ((sg = read (Pollfd[idx].fd, buf, sr)) > 0)
      DBG ("got from socket %hd:[%-*.*s]", idx, (int)sg, (int)sg, buf);
    if (sg == 0) {
      sg = E_EOF;
    } else if (sg < 0) {
      if (errno == EAGAIN)
	sg = 0;
      else
	sg = E_ERRNO - errno;		/* remember error for return */
    }
  } else if (rev & POLLHUP)
    sg = E_EOF;
  else if (rev & (POLLNVAL | POLLERR))
    sg = E_NOSOCKET;			/* cannot test errno variable ATM */
  else
    sg = 0;
  return (sg);
}

/*
 * returns: < 0 if error or number of writed bytes from buf
 */
ssize_t WriteSocket (idx_t idx, const char *buf, size_t *ptr, size_t *sw)
{
  ssize_t sg;
  int errnosave;
  register short rev;

  pthread_testcancel();			/* for non-POSIX systems */
  if (idx < 0 || idx >= _Snum || Pollfd[idx].fd < 0)
    return E_NOSOCKET;
  if (!buf || !sw || !ptr)
    return 0;
  rev = Pollfd[idx].revents & (POLLNVAL | POLLERR | POLLHUP | POLLOUT);
  /* if mode isn't M_POLL then it's dispatcher or else we should wait */
  pthread_mutex_lock(&LockPoll);
  if (!rev)
    _socket_timedwait(idx, 1);
  Pollfd[idx].revents &= POLLOUT;	/* we'll write socket, reset state */
  pthread_mutex_unlock(&LockPoll);
  DBG ("trying write socket %hd: %p +%zu", idx, &buf[*ptr], *sw);
  sg = write (Pollfd[idx].fd, &buf[*ptr], *sw);
  errnosave = errno;			/* save it as unlock can change it */
  if (sg < 0)
    return (errnosave == EAGAIN) ? 0 : (E_ERRNO - errnosave);
  else if (sg == 0)			/* remote end closed connection */
    return E_EOF;
  *ptr += sg;
  *sw -= sg;
  Socket[idx].ready = TRUE;		/* connected as we sent something */
  return (sg);
}

int KillSocket (idx_t *idx)
{
  int fd;
  idx_t i = *idx;

  DBG ("socket:KillSocket %d", (int)i);
  if (i < 0)
    return -1;
  *idx = -1;			/* no more access to that socket */
  if (i >= _Snum)		/* it should be atomic ATM */
    return -1;			/* no such socket */
  dprint (5, "socket:KillSocket: fd=%d", Pollfd[i].fd);
  pthread_kill(__main_thread, SIGPOLL); /* break poll() in main thread */
  pthread_mutex_lock (&LockPoll);
  Socket[i].port = 0;
  FREE (&Socket[i].ipname);
  FREE (&Socket[i].domain);
  fd = Pollfd[i].fd;
  Pollfd[i].fd = UNUSED_FD;	/* indicator of free socket */
  SChanged = 1;
  pthread_mutex_unlock (&LockPoll);
  if (fd >= 0) {		/* CloseSocket(i) */
    shutdown (fd, SHUT_RDWR);
    close (fd);
  }
  return 0;
}

idx_t GetSocket (unsigned short type)
{
  idx_t idx;
  int sockfd;

  if (type == M_UNIX)
    sockfd = socket (AF_UNIX, SOCK_STREAM, 0);
  else
    sockfd = socket (AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0)
    return (E_NOSOCKET);
  pthread_kill(__main_thread, SIGPOLL); /* break poll() in main thread */
  pthread_mutex_lock (&LockPoll);
  idx = allocate_socket();
  if (idx >= 0)
    Pollfd[idx].fd = sockfd;
  pthread_mutex_unlock (&LockPoll);
  if (idx < 0) /* too many sockets */
    close(sockfd);
  else
    Socket[idx].port = type;
  DBG ("socket:GetSocket: %d (fd=%d)", (int)idx, sockfd);
  return idx;
}

/* recover after failed SetupSocket */
void ResetSocket(idx_t idx, unsigned short type)
{
  int sockfd;

  sockfd = Pollfd[idx].fd;
  Pollfd[idx].fd = -1;
  SChanged = 1;
  FREE (&Socket[idx].ipname);
  FREE (&Socket[idx].domain);
  if (sockfd >= 0)
    close(sockfd);
  if (type == M_UNIX)
    sockfd = socket (AF_UNIX, SOCK_STREAM, 0);
  else
    sockfd = socket (AF_INET, SOCK_STREAM, 0);
  if (sockfd < 0)
    return;
  Pollfd[idx].fd = sockfd;
  SChanged = 1;
  Socket[idx].port = type;
  DBG ("socket:ResetSocket: %d (fd=%d)", (int)idx, sockfd);
}

/* returns ip textual representation for socket address */
static inline const char *_get_socket_ipname (inet_addr_t *addr, char *buf,
					      size_t bufsize)
{
  register const void *ptr;
  register sa_family_t fam = addr->sa.sa_family;

#ifdef ENABLE_IPV6
//  switch (addr->sa.sa_family) {	/* prepare ip textual representation */
  switch (fam) {	/* prepare ip textual representation */
  case AF_INET:
#endif
    ptr = &addr->s_in.sin_addr;
#ifdef ENABLE_IPV6
    break;
  case AF_INET6:
    ptr = &addr->s_in6.sin6_addr;
    if (*(uint32_t *)ptr == 0 && ((uint32_t *)ptr)[1] == 0 &&
	((uint16_t *)ptr)[4] == 0 &&
	(((uint16_t *)ptr)[4] == 0 || ((uint16_t *)ptr)[5] == 0xffff)) {
      fam = AF_INET;		/* v4 to v6 mapped */
      ptr = &((char *)ptr)[12];
    }
    break;
  default:
    fam = AF_INET6;
    ptr = &in6addr_any;
  }
#endif
//  return inet_ntop(addr->sa.sa_family, ptr, buf, bufsize);
  return inet_ntop(fam, ptr, buf, bufsize);
}

/* returns allocated ip textual representation for socket address */
#define _make_socket_ipname(__a,__b,__c) \
	safe_strdup(_get_socket_ipname(__a,__b,__c))

/* For a listening process - we have to get ECONNREFUSED to own port :) */
int SetupSocket(idx_t idx, const char *domain, const char *bind_to,
		unsigned short port,
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
  sockfd = Pollfd[idx].fd;		/* idx is owned by caller */
  type = (int)Socket[idx].port;
  if (!domain && type != M_LIST && type != M_LINP && type != M_UNIX)
    return (E_UNDEFDOMAIN);
  if (!bind_to && type == M_UNIX)
    return (E_UNDEFDOMAIN);
  i = 1;
  setsockopt (sockfd, SOL_SOCKET, SO_KEEPALIVE, (void *) &i, sizeof(i));
  setsockopt (sockfd, SOL_SOCKET, SO_REUSEADDR, (void *) &i, sizeof(i));
  ling.l_onoff = 1;
  ling.l_linger = 0;
  setsockopt (sockfd, SOL_SOCKET, SO_LINGER, (void *) &ling, sizeof(ling));
  fcntl (sockfd, F_SETOWN, _mypid);
  if (type == M_UNIX)
  {
    addr.s_un.sun_family = AF_UNIX;
    strfcpy (addr.s_un.sun_path, domain, sizeof(addr.s_un.sun_path));
    if (unlink (addr.s_un.sun_path))
      return (E_ERRNO - errno);
    len = SUN_LEN (&addr.s_un);
    Socket[idx].port = 0;		/* should be 0 for Unix socket */
  } else if (bind_to) {
    struct addrinfo *ai;
#ifndef ENABLE_IPV6
    static struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = 0,
				       .ai_protocol = 0, .ai_flags = 0 };

    i = getaddrinfo (bind_to, NULL, &hints, &ai);
#else
    i = getaddrinfo (bind_to, NULL, NULL, &ai);
#endif
    DBG("trying to resolve address %s to bind to it", bind_to);
    if (i == 0)
    {
	inet_addr_t *ha = (inet_addr_t *)ai->ai_addr;

	len = ai->ai_addrlen;
	memcpy(&addr.sa, &ha->sa, len);
	/* addr.sa.sa_family = ai->ai_family; */
	freeaddrinfo (ai);
#ifdef ENABLE_IPV6
	if (addr.sa.sa_family != AF_INET) {
	  int cancelstate;

	  /* close IPv4 socket and open IPv6 one instead */
	  pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancelstate);
	  pthread_mutex_lock (&LockPoll);
	  close(sockfd);
	  sockfd = socket(addr.sa.sa_family, SOCK_STREAM, 0);
	  DBG("closed IPv4 socket (fd=%d) and opened IPv6 one (fd=%d)",
	      Pollfd[idx].fd, sockfd);
	  Pollfd[idx].fd = sockfd;
	  SChanged = 1;
	  pthread_mutex_unlock (&LockPoll);
	  pthread_setcancelstate(cancelstate, NULL);
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
    /* sockaddr_in is compatible with sockaddr_in6 up to port member */
    if (type == M_LIST || type == M_LINP)
      addr.s_in.sin_port = htons(port);
    else
      addr.s_in.sin_port = 0;
  } else if (type == M_LIST || type == M_LINP) {
    /* NULL domain means we want listen every IPv4 address,
       for listening on every IPv6 we can ask for domain "::" */
    len = sizeof(addr.s_in);
    /* memset(&addr.s_in, 0, len); */
    addr.s_in.sin_family = AF_INET;
    addr.s_in.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.s_in.sin_port = htons(port);
    bind_to = "";
  }
  if (bind_to && bind (sockfd, &addr.sa, len) < 0)
    return (E_ERRNO - errno);
  if (type == M_LIST || type == M_LINP)
  {
    i = 3; /* backlog */
    if (type == M_LINP)
      i = 1;
    if (listen (sockfd, i) < 0 || getsockname (sockfd, &addr.sa, &len) < 0)
      return (E_ERRNO - errno);
    /* update listening port with real opened one not asked */
    Socket[idx].port = ntohs (addr.s_in.sin_port);
  } else if (type == M_UNIX) {
    if (listen (sockfd, 3) < 0)
      return (E_ERRNO - errno);
  } else {
    struct addrinfo *ai;
    static struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = 0,
				       .ai_protocol = 0, .ai_flags = 0 };

#ifdef ENABLE_IPV6
    if (bind_to == NULL)
      hints.ai_family = AF_UNSPEC;
    else
      hints.ai_family = addr.sa.sa_family;
    if (hints.ai_family == AF_INET6)
      hints.ai_flags = AI_V4MAPPED;
    else
      hints.ai_flags = 0;
#endif
    i = getaddrinfo (domain, NULL, &hints, &ai);
    if (i == 0)
    {
	inet_addr_t *ha = (inet_addr_t *)ai->ai_addr;

	len = ai->ai_addrlen;
	memcpy(&addr.sa, &ha->sa, len);
	/* addr.sa.sa_family = ai->ai_family; */
	freeaddrinfo (ai);
#ifdef ENABLE_IPV6
	if (bind_to == NULL && addr.sa.sa_family != AF_INET) {
	  int cancelstate;

	  /* close IPv4 socket and open IPv6 one instead */
	  pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancelstate);
	  pthread_mutex_lock (&LockPoll);
	  close(sockfd);
	  sockfd = socket(addr.sa.sa_family, SOCK_STREAM, 0);
	  DBG("closed IPv4 socket (fd=%d) and opened IPv6 one (fd=%d)",
	      Pollfd[idx].fd, sockfd);
	  Pollfd[idx].fd = sockfd;
	  SChanged = 1;
	  pthread_mutex_unlock (&LockPoll);
	  pthread_setcancelstate(cancelstate, NULL);
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
    /* sockaddr_in is compatible with sockaddr_in6 up to port member */
    addr.s_in.sin_port = htons(port);
    if ((i = connect (sockfd, &addr.sa, len)) < 0)
      return (E_ERRNO - errno);
    Socket[idx].port = port;
    //pthread_mutex_lock (&LockPoll);
    //Pollfd[idx].events = POLLIN | POLLPRI | POLLOUT; /* POLLOUT set when connected */
    //SChanged = 1;
    //pthread_mutex_unlock (&LockPoll);
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
    if (i == 0)			/* no errors */
      domain = hname;
    else if (domain == NULL)	/* else make it not NULL */
      domain = Socket[idx].ipname;
  }
  if (callback != NULL)
    return callback(&addr.sa, callback_data);
  Socket[idx].domain = safe_strdup (domain);
  return 0;
}

static void _answer_cleanup(void *data)
{
  idx_t idx = (idx_t)(int)data;

  KillSocket(&idx);
}

idx_t AnswerSocket (idx_t listen)
{
  idx_t idx;
  int sockfd, i, cancelstate, locked = 0;
  short rev;
  socklen_t len;
  inet_addr_t addr;
  char hname[NI_MAXHOST+1];

  pthread_testcancel();				/* for non-POSIX systems */
  if (listen < 0 || listen >= _Snum || Pollfd[listen].fd < 0)
    return (E_NOSOCKET);
  rev = Pollfd[listen].revents;
  if (!rev)
  {
    pthread_mutex_lock (&LockPoll);
    locked = 1;
    _socket_timedwait(listen, 0);
    rev = Pollfd[listen].revents;
  }
  if (!(rev & (POLLIN | POLLPRI | POLLNVAL | POLLERR)) || /* no events */
      (rev & (POLLHUP | POLLOUT))) {	/* or we are in CloseSocket() now */
    if (locked)
      pthread_mutex_unlock (&LockPoll);
    return (E_AGAIN);
  } else if (rev & POLLNVAL) {
    if (locked)
      pthread_mutex_unlock (&LockPoll);
    return (E_NOSOCKET);
  } else if (rev & POLLERR) {
    if (locked)
      pthread_mutex_unlock (&LockPoll);
    return (E_ERRNO);
  }
  DBG ("AnswerSocket: got 0x%hx for %hd", rev, listen);
  /* deny cancelling the thread while allocated socket is unset */
  pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancelstate);
  if (!locked)
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
  Pollfd[listen].revents = 0;		/* we accepted socket, reset state */
  if (sockfd < 0)
    Pollfd[idx].fd = UNUSED_FD;
  pthread_mutex_unlock (&LockPoll);
  /* we done with socket so restore previous cancellstate now */
  pthread_setcancelstate(cancelstate, NULL);
  if (sockfd < 0)
    return (E_AGAIN);
  /* add thread cleanup here in case if thread is cancelled */
  pthread_cleanup_push(&_answer_cleanup, (void *)(int)idx);
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
    goto done;			/* no domains for Unix sockets */
  Socket[idx].ipname = _make_socket_ipname(&addr, hname, sizeof(hname));
  i = getnameinfo (&addr.sa, len, hname, sizeof(hname), NULL, 0, 0);
  if (i == 0)			/* subst canonical name */
    Socket[idx].domain = safe_strdup (hname);
  else				/* error of getnameinfo() */
    Socket[idx].domain = safe_strdup(Socket[idx].ipname);
done:
  Socket[idx].ready = TRUE;
  /* done so remove thread cleanup leaving socket intact */
  pthread_cleanup_pop(0);
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

const char *SocketMyIP (idx_t idx, char *buf, size_t bsz)
{
  inet_addr_t addr;
  socklen_t len;

  /* check for errors! */
  if (idx < 0 || idx >= _Snum || Pollfd[idx].fd < 0)
    return (NULL);
  len = sizeof(addr);
  if (getsockname(Pollfd[idx].fd, &addr.sa, &len) < 0)
    return (NULL);
#ifdef ENABLE_IPV6
  if (addr.sa.sa_family != AF_INET && addr.sa.sa_family != AF_INET6)
#else
  if (addr.sa.sa_family != AF_INET)
#endif
    return (NULL);
  return (_get_socket_ipname(&addr, buf, bsz));
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
      strfcpy (buf, "connection reset by peer", s);
      break;
    case E_UNDEFDOMAIN:
      strfcpy (buf, "domain not defined", s);
      break;
    case E_NOSUCHDOMAIN:
      strfcpy (buf, "domain unknown", s);
      break;
    default:
      strfcpy (buf, "unknown socket error", s);
  }
  return buf;
}

/* this function is called from dispatcher instead of nanosleep */
void PollSockets(int check_out)
{
  register idx_t i;
  int x;
  static struct pollfd *_pollfd = NULL;
  static idx_t          _pfdnum = 0;

  /*
   * bits flow here is:
   *   A ---> B   means bits will be moved (cleared in A and set in B)
   *   A -?-> B   means will be moved (cleared in A) if set by poll() in B
   * Pollfd.events ---> _pollfd.events -?-> _pollfd.revents ---> Pollfd.revents
   */
  pthread_mutex_lock (&LockPoll);
  if (_pfdnum < _Salloc) {
    safe_realloc((void **)&_pollfd, _Salloc * sizeof(struct pollfd));
    memset(&_pollfd[_pfdnum], 0xff, (_Salloc - _pfdnum) * sizeof(struct pollfd));
    _pfdnum = _Salloc;
  }
  for (i = 0; i < _Snum; i++) {
    if (SChanged) {
      if (Pollfd[i].fd != _pollfd[i].fd) /* it changed, clear */
	_pollfd[i].events = 0;
      _pollfd[i].fd = Pollfd[i].fd;
      _pollfd[i].events |= Pollfd[i].events;
      Pollfd[i].events = 0;
    }
    if (_pollfd[i].fd < 0)
      continue;
    /* check if there is data to out so we know about the queue */
    if (check_out &&		/* we have something in queue */
	(_pollfd[i].events & POLLOUT)) /* check if thread waits to out */
      check_out = 0;		/* then allow the timeout */
  }
  SChanged = 0;			/* we consumed changes */
  x = _Snum;
  pthread_mutex_unlock (&LockPoll);
  if (x > 0)
    x = poll(_pollfd, (unsigned int)x, check_out ? 10 : POLL_TIMEOUT);
  pthread_mutex_lock (&LockPoll);
  /* reset found events but callers will set it again when needs */
  for (i = 0; i < _Snum; i++)
    if (_pollfd[i].fd >= 0 && (_pollfd[i].revents)) {
      _pollfd[i].events &= ~_pollfd[i].revents;
      if (_pollfd[i].fd == Pollfd[i].fd)
	Pollfd[i].revents |= _pollfd[i].revents;
    }
  if (x > 0)
    pthread_cond_broadcast(&PollCond);
  pthread_mutex_unlock (&LockPoll);
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
    __main_thread = pthread_self();
  }
  /* init SIGPOLL handler */
  _mypid = getpid();
  act.sa_handler = &sigio_handler;
  sigemptyset (&act.sa_mask);
  act.sa_flags = 0;
  return (sigaction (SIGPOLL, &act, NULL));
}
