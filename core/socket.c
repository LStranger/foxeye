/*
 * Copyright (C) 1999-2020  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 *     You should have received a copy of the GNU General Public License along
 *     with this program; if not, write to the Free Software Foundation, Inc.,
 *     51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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
#include <stdlib.h>

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

#ifdef HAVE_LIBIDN
# include <idna.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
# include <sys/ioctl.h>
#endif

#ifdef HAVE_ALLOCA_H
# include <alloca.h>
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

/* OS X treats NI_MAXHOST as optional */
#ifndef NI_MAXHOST
# define NI_MAXHOST 1025
#endif

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
  void (*callback)(void *);
  void *callback_data;
  volatile sig_atomic_t ready;
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

static pthread_t _pth;

static socket_t *Socket = NULL;
static idx_t _Salloc = 0;
static idx_t _Snum = 0;
static struct pollfd *Pollfd = NULL;

/* lock any access to whole Pollfd or write access to any element of it */
static pthread_mutex_t LockPoll = PTHREAD_MUTEX_INITIALIZER;

/* conditional variable to interrupt poll thread */
static pthread_cond_t PollIntr = PTHREAD_COND_INITIALIZER;
/* conditional variable to wait for poll success */
static pthread_cond_t PollCond = PTHREAD_COND_INITIALIZER;

/* set when we updated Pollfd structure */
static volatile sig_atomic_t SReady = 0;

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
  Pollfd[idx].events = POLLHUP;	/* not ready, to reset */
  Pollfd[idx].revents = 0;
  Socket[idx].domain = NULL;
  Socket[idx].ipname = NULL;
  Socket[idx].ready = FALSE;
  if (idx == _Snum)
    _Snum++;
  DBG ("allocate_socket: got socket %hd", idx);
  return idx;
}

static void _socket_timedwait_cleanup(void *ptr)
{
  pthread_mutex_unlock(ptr);
}

/* unlocks LockPoll if cancelled */
static void _socket_acquire_lock_and_poll(idx_t idx, int write)
{
  short old_events;
  struct timespec abstime;

  pthread_mutex_lock(&LockPoll);
  old_events = Pollfd[idx].events;
  if (write)
    Pollfd[idx].events = POLLIN | POLLPRI | POLLOUT;
  else
    Pollfd[idx].events = POLLIN | POLLPRI;
  pthread_cleanup_push(&_socket_timedwait_cleanup, &LockPoll);
  if (old_events != Pollfd[idx].events || Pollfd[idx].revents)
    /* polling thread needs updated info, let wake up it */
    while (SReady == 0) {
      pthread_cond_broadcast(&PollIntr);
      /* at this point we keep lock, polling thread waits unlock */
      clock_gettime(CLOCK_REALTIME, &abstime);
      abstime.tv_nsec += 1000000;
      if (abstime.tv_nsec >= 1000000000) {
        abstime.tv_nsec -= 1000000000;
        abstime.tv_sec++;
      }
      /* now unlock and wait for poll result */
      pthread_cond_timedwait(&PollCond, &LockPoll, &abstime); /* wait up to 1 ms */
      /* at this point lock is hold, polling thread waits unlock again */
    }
  else if ((Pollfd[idx].revents & Pollfd[idx].events) == 0 && SReady == 0) {
    /* otherwise don't wake up the polling thread, run poll() ourself */
    struct pollfd pfd;

    pfd.fd = Pollfd[idx].fd;
    pfd.revents = 0;
    pfd.events = Pollfd[idx].events;
    poll(&pfd, 1, 0);
    Pollfd[idx].revents |= pfd.revents;
  }
  pthread_cleanup_pop(0);	/* leaves mutex locked */
}

/* as _socket_acquire_lock_and_poll but unconditionally */
static void _socket_acquire_lock(void)
{
  struct timespec abstime;

  pthread_mutex_lock(&LockPoll);
  pthread_cleanup_push(&_socket_timedwait_cleanup, &LockPoll);
  while (SReady == 0) {
    pthread_cond_broadcast(&PollIntr);
    /* at this point we keep lock, polling thread waits unlock */
    clock_gettime(CLOCK_REALTIME, &abstime);
    abstime.tv_nsec += 1000000;
    if (abstime.tv_nsec >= 1000000000) {
      abstime.tv_nsec -= 1000000000;
      abstime.tv_sec++;
    }
    /* now unlock and wait for poll result */
    pthread_cond_timedwait(&PollCond, &LockPoll, &abstime); /* wait up to 1 ms */
    /* at this point lock is hold, polling thread waits unlock again */
  }
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
  _socket_acquire_lock_and_poll(idx, (sock->ready == FALSE) ? 1 : 0);
  rev = Pollfd[idx].revents;
  Pollfd[idx].events |= (POLLIN|POLLPRI); /* update it for next read */
  Pollfd[idx].revents &= ~(POLLIN|POLLPRI|POLLHUP); /* we'll read socket, reset state */
  pthread_mutex_unlock(&LockPoll);
  if (!rev && (sock->ready == FALSE))	/* check for incomplete connection */
    return (E_AGAIN);			/* still waiting for connection */
  sock->ready = TRUE;			/* connection established or failed */
  if (rev & POLLHUP)
    DBG("got POLLHUP from socket %hd!", idx);
  /*if (rev & (POLLIN | POLLPRI))*/ {	/* even dead socket can contain data */
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
    } else if ((size_t)sg == sr) {	/* buffer is full, there may be more data */
      pthread_mutex_lock(&LockPoll);
      Pollfd[idx].revents |= POLLIN;
      pthread_cond_broadcast(&PollIntr); /* inform threads about update */
      pthread_mutex_unlock(&LockPoll);
    }
  }// else if (rev & POLLHUP)
    //sg = E_EOF;
  //else if (rev & (POLLNVAL | POLLERR))
    //sg = E_NOSOCKET;			/* cannot test errno variable ATM */
  //else
    //sg = 0;
  return (sg);
}

/*
 * returns: < 0 if error or number of writed bytes from buf
 */
ssize_t WriteSocket (idx_t idx, const char *buf, size_t *ptr, size_t *sw)
{
  ssize_t sg;
  int errnosave;

  pthread_testcancel();			/* for non-POSIX systems */
  if (idx < 0 || idx >= _Snum || Pollfd[idx].fd < 0)
    return E_NOSOCKET;
  if (!buf || !sw || !ptr)
    return 0;
  pthread_mutex_lock(&LockPoll);
  Pollfd[idx].events |= POLLOUT;	/* get ready for next check */
  Pollfd[idx].revents &= ~POLLOUT;	/* we'll write socket, reset state */
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
  char *unixsocket;
  int fd;
  idx_t i = *idx;

  DBG ("socket:KillSocket %d", (int)i);
  if (i < 0)
    return -1;
  *idx = -1;			/* no more access to that socket */
  if (i >= _Snum)		/* it should be atomic ATM */
    return -1;			/* no such socket */
  dprint (5, "socket:KillSocket: fd=%d", Pollfd[i].fd);
  _socket_acquire_lock();
  unixsocket = Socket[i].domain;
  if (Socket[i].ipname == NULL && unixsocket != NULL && Socket[i].port == 0)
    Socket[i].domain = NULL;	/* UNIX socket */
  else
    unixsocket = NULL;		/* INET socket */
  Socket[i].port = 0;
  FREE (&Socket[i].ipname);
  FREE (&Socket[i].domain);
  fd = Pollfd[i].fd;
  Pollfd[i].fd = UNUSED_FD;	/* indicator of free socket */
  pthread_mutex_unlock (&LockPoll);
  if (fd >= 0) {		/* CloseSocket(i) */
    shutdown (fd, SHUT_RDWR);
    close (fd);
  }
  if (unixsocket != NULL) {
    int cancelstate;		/* unlink() may be cancellation point */

    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancelstate);
    unlink(unixsocket);
    FREE(&unixsocket);
    pthread_setcancelstate(cancelstate, NULL);
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
  pthread_mutex_lock (&LockPoll);
  idx = allocate_socket();
  if (idx >= 0)
    Pollfd[idx].fd = sockfd;
  pthread_mutex_unlock (&LockPoll);
  if (idx < 0) /* too many sockets */
    close(sockfd);
  else
    Socket[idx].port = type;
  Socket[idx].callback = NULL;
  DBG ("socket:GetSocket: %d (fd=%d)", (int)idx, sockfd);
  return idx;
}

/* recover after failed SetupSocket */
void ResetSocket(idx_t idx, unsigned short type)
{
  int sockfd;

  sockfd = Pollfd[idx].fd;
  Pollfd[idx].fd = -1;
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
  Pollfd[idx].revents = 0;
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
#ifdef HAVE_LIBIDN
  char *idndomain;
#endif

  /* check for errors! */
  if (idx < 0 || idx >= _Snum || Pollfd[idx].fd < 0)
    return (E_NOSOCKET);
  sockfd = Pollfd[idx].fd;		/* idx is owned by caller */
  type = (int)Socket[idx].port;
  if (!domain && type != M_LIST && type != M_LINP && type != M_UNIX)
    return (E_UNDEFDOMAIN);
  if (!bind_to && type == M_UNIX)
    return (E_UNDEFDOMAIN);
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
	  Pollfd[idx].revents = 0;
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
  if (type == M_LIST || type == M_LINP) {
    i = 1;
    setsockopt (sockfd, SOL_SOCKET, SO_REUSEADDR, (void *) &i, sizeof(i));
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
#ifdef HAVE_LIBIDN
    i = idna_to_ascii_lz(domain, &idndomain, IDNA_USE_STD3_ASCII_RULES);
    if (i == IDNA_SUCCESS) {
      i = getaddrinfo(idndomain, NULL, &hints, &ai);
      free(idndomain);
    } else //TODO: debug diagnostics?
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
	  Pollfd[idx].revents = 0;
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
    //pthread_mutex_unlock (&LockPoll);
  }
  i = 1;
  setsockopt (sockfd, SOL_SOCKET, SO_KEEPALIVE, (void *) &i, sizeof(i));
  ling.l_onoff = 1;
  ling.l_linger = 0;
  setsockopt (sockfd, SOL_SOCKET, SO_LINGER, (void *) &ling, sizeof(ling));
  fcntl (sockfd, F_SETOWN, _mypid);
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
#ifdef HAVE_LIBIDN
    idndomain = NULL;
#endif
    if (i == 0) {		/* no errors */
#ifdef HAVE_LIBIDN
      i = idna_to_unicode_lzlz(hname, &idndomain, 0);
      if (i == IDNA_SUCCESS)
	domain = idndomain;
      else //TODO: debug errors
#endif
      domain = hname;
    } else if (domain == NULL)	/* else make it not NULL */
      domain = Socket[idx].ipname;
  }
  if (callback != NULL)
    i = callback(&addr.sa, callback_data);
  else
    i = 0;
  Socket[idx].domain = safe_strdup (domain);
#ifdef HAVE_LIBIDN
  if (idndomain != NULL)
    free(idndomain);
#endif
  _socket_acquire_lock();
  Pollfd[idx].events = POLLIN | POLLPRI | POLLOUT;
  pthread_mutex_unlock (&LockPoll);
  return (i);
}

void AssociateSocket (idx_t idx, void (*callback)(void *), void *callback_data)
{
  /* check for errors! */
  DBG("AssociateSocket: %hd %p %p", idx, callback, callback_data);
  if (idx < 0 || idx >= _Snum || Pollfd[idx].fd < 0)
    return;
  Socket[idx].callback_data = callback_data;
  Socket[idx].callback = callback;
}

static void _answer_cleanup(void *data)
{
  idx_t idx = (idx_t)(ssize_t)data;

  KillSocket(&idx);
}

idx_t AnswerSocket (idx_t listen)
{
  volatile idx_t idx;
  volatile int sockfd;
  int i, cancelstate;
  short rev;
  socklen_t len;
  inet_addr_t addr;
  char hname[NI_MAXHOST+1];

  pthread_testcancel();				/* for non-POSIX systems */
  if (listen < 0 || listen >= _Snum || Pollfd[listen].fd < 0)
    return (E_NOSOCKET);
  _socket_acquire_lock_and_poll(listen, 0);
  rev = Pollfd[listen].revents;
  Pollfd[listen].events |= (POLLIN|POLLPRI); /* update it for next time */
  if (!(rev & (POLLIN | POLLPRI | POLLNVAL | POLLERR)) || /* no events */
      (rev & (POLLHUP | POLLOUT))) {	/* or we are in CloseSocket() now */
    pthread_mutex_unlock (&LockPoll);
    return (E_AGAIN);
  } else if (rev & POLLNVAL) {
    pthread_mutex_unlock (&LockPoll);
    return (E_NOSOCKET);
  } else if (rev & POLLERR) {
    pthread_mutex_unlock (&LockPoll);
    return (E_ERRNO);
  }
  DBG ("AnswerSocket: got 0x%hx for %hd", rev, listen);
  /* deny cancelling the thread while allocated socket is unset */
  pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancelstate);
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
  else
    Pollfd[listen].revents = POLLIN;	/* we could get 2 inputs at once so let
					   check that again (noticed by denk) */
  pthread_mutex_unlock (&LockPoll);
  /* we done with socket so restore previous cancellstate now */
  pthread_setcancelstate(cancelstate, NULL);
  if (sockfd < 0)
    return (E_AGAIN);
  /* add thread cleanup here in case if thread is cancelled */
  pthread_cleanup_push(&_answer_cleanup, (void *)(ssize_t)idx);
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
  if (Socket[listen].port == 0) {
#ifdef SO_PEERCRED
    struct ucred credentials;

    i = sizeof(struct ucred);
    if (!getsockopt(sockfd, SOL_SOCKET, SO_PEERCRED, &credentials, &i)) {
      snprintf(hname, sizeof(hname), "%u", credentials.pid);
      Socket[idx].domain = safe_strdup(hname);
#if ! defined(UID_MAX) || UID_MAX > USHRT_MAX
      if (credentials.uid > USHRT_MAX) {
	DBG("socket:AnswerSocket: UID %d is too big", (int)credentials.uid);
	credentials.uid = USHRT_MAX;
      }
#endif
      Socket[idx].port = credentials.uid;
    } else
      DBG("socket:AnswerSocket: could not retrieve credentials for UNIX socket %hd",
	  sockfd);
//#else -- to add support for getpeerucred (Solaris) and getpeereid (*BSD)
#endif
    goto done;
  }
  Socket[idx].ipname = _make_socket_ipname(&addr, hname, sizeof(hname));
  i = getnameinfo (&addr.sa, len, hname, sizeof(hname), NULL, 0, 0);
#ifdef STRICT_BACKRESOLV
  if (i == 0) {
    /* make direct resolving of hname and compare it with addr */
    struct addrinfo *ai, *aii;
    static struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = 0,
				       .ai_protocol = 0, .ai_flags = 0 };

#ifdef ENABLE_IPV6
    hints.ai_family = addr.sa.sa_family;
    if (hints.ai_family == AF_INET6)
      hints.ai_flags = AI_V4MAPPED;
    else
      hints.ai_flags = 0;
#endif
    i = getaddrinfo (hname, NULL, &hints, &ai);
    if (i == 0) {
      for (aii = ai; aii != NULL; aii = aii->ai_next) {
	inet_addr_t *ha = (inet_addr_t *)aii->ai_addr;

#ifdef ENABLE_IPV6
	if (ha->sa.sa_family == AF_INET6) {
	  if (memcmp(&ha->s_in6.sin6_addr, &addr.s_in6.sin6_addr,
		     sizeof(addr.s_in6.sin6_addr)) == 0)
	    break;
	} else if (ha->sa.sa_family == AF_INET)
#endif
	  if (memcmp(&ha->s_in.sin_addr.s_addr, &addr.s_in.sin_addr.s_addr,
		     sizeof(addr.s_in.sin_addr.s_addr)) == 0)
	    break;
      }
      freeaddrinfo (ai);
      if (aii == NULL) {
	DBG("socket:AnswerSocket: none of domain %s resolves match %s", hname,
	    Socket[idx].ipname);
	i = -1;
      }
    } else
      DBG("socket:AnswerSocket: domain %s does not resolve, using %s", hname,
	  Socket[idx].ipname);
  }
#endif
  if (i == 0) {			/* subst canonical name */
#ifdef HAVE_LIBIDN
    char *dechost;

    i = idna_to_unicode_lzlz(hname, &dechost, 0);
    if (i == IDNA_SUCCESS) {
      Socket[idx].domain = safe_strdup(dechost);
      free(dechost);
    } else //TODO: debug errors
#endif
    Socket[idx].domain = safe_strdup (hname);
  } else			/* error of getnameinfo() */
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
  buf[0] = '\0';
  if (er < E_ERRNO) {
#if _GNU_SOURCE
    strerror_r (E_ERRNO - er, buf, s);
#else
    if (strerror_r (E_ERRNO - er, buf, s) < 0)
      snprintf(buf, s, "unknown system error %d", er);
#endif
  }
  else switch (er)
  {
    case 0:
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

typedef struct {
  struct pollfd *pollfd;
  int x;
  idx_t pfdset;
} SocketPollData;

static void *_poll_subthread(void *pdata)
{
  SocketPollData *data = pdata;

  if (data->x > 0)
    /* this is a cancellation point */
    data->x = poll(data->pollfd, (unsigned int)data->pfdset, -1);
  if (data->x > 0)
    /* we got some event, let wake-up the poll thread */
    pthread_cond_broadcast(&PollIntr);
  /* now let caller join us */
  return NULL;
}

/* this function is called from dispatcher instead of nanosleep */
/* poll thread is here... */
static void *_poll_thread(void __attribute__((unused)) *data)
{
  idx_t i;
  idx_t _pfdnum;
  SocketPollData d;
  pthread_t subthread;
  struct timespec ts = { .tv_sec = 0, .tv_nsec = 100000 };

  /*
   * bits flow here is:
   *   A ---> B   means bits will be moved (cleared in A and set in B)
   *   A -?-> B   means will be moved (cleared in A) if set by poll() in B
   * Pollfd.events ---> d.pollfd.events -?-> d.pollfd.revents ---> Pollfd.revents
   */
  _pfdnum = _Salloc;
#ifdef HAVE_ALLOCA
  d.pollfd = alloca(_pfdnum * sizeof(struct pollfd));
#else
  d.pollfd = safe_alloc(_pfdnum * sizeof(struct pollfd));
  pthread_cleanup_push((void(*)(void *))&safe_free, (void *)&d.pollfd);
#endif
  memset(d.pollfd, 0, _pfdnum * sizeof(struct pollfd));

  FOREVER
  {
    /* grab lock on data */
    pthread_mutex_lock (&LockPoll);
    SReady = 0;
    /* send callbacks if some data are ready to get */
    for (i = 0; i < _Snum; i++) {
      if (Pollfd[i].fd >= 0 &&
	  (Pollfd[i].revents & (POLLIN | POLLERR | POLLHUP)) != 0 &&
	  Socket[i].callback != NULL) {
	DBG("socket.c:run callback due to revents %04hx on %hd", Pollfd[i].revents, i);
	Socket[i].callback(Socket[i].callback_data);
      }
    }
    /* update data if something changed by sockets */
    d.pfdset = _Snum;
    for (d.x = 0, i = 0; i < d.pfdset; i++) {
      if (Pollfd[i].events & POLLHUP) /* signaled to reset */
	d.pollfd[i].events = 0;
      else
	d.pollfd[i].events |= Pollfd[i].events;
      d.pollfd[i].fd = Pollfd[i].fd;
      Pollfd[i].events = 0;
      if (Pollfd[i].revents & POLLHUP) /* connection died */
	d.pollfd[i].fd = -1;
      else if (d.pollfd[i].events != 0) /* else - not ready yet */
	d.x++;
    }
    /* ungrab lock on data */
    pthread_mutex_unlock (&LockPoll);
    /* do the poll until some event come or interrupted */
    pthread_create(&subthread, NULL, _poll_subthread, &d);
    //FIXME: what to do in case of error?
    pthread_mutex_lock (&LockPoll);
    pthread_cond_wait(&PollIntr, &LockPoll);
    pthread_mutex_unlock (&LockPoll);
    pthread_cancel(subthread);
    pthread_join(subthread, NULL);
    pthread_mutex_lock (&LockPoll);
    /* reset found events but callers will set it again when needs */
    for (i = 0; i < d.pfdset; i++) {
      if (Pollfd[i].events & POLLHUP) ; /* was reset while we polled */
      else if (d.pollfd[i].fd >= 0 && d.pollfd[i].revents != 0) {
	d.pollfd[i].events &= ~d.pollfd[i].revents;
        if (d.pollfd[i].fd == Pollfd[i].fd)
	  Pollfd[i].revents |= d.pollfd[i].revents;
	d.pollfd[i].revents = 0;
      }
    }
    /* inform threads we've updated all data */
    SReady = 1;
    pthread_cond_broadcast(&PollCond);
    pthread_mutex_unlock (&LockPoll);
    nanosleep(&ts, NULL);
  }
#ifndef HAVE_ALLOCA
  /* never reached but still required */
  pthread_cleanup_pop(1);
#endif
  return NULL;
}

int _fe_init_sockets (void)
{
  struct sigaction act;

  /* allocate sockets structures */
  if (_Salloc != 0)
    return -1;
  /* start a thread */
  _Salloc = SOCKETMAX;
  Socket = safe_malloc (SOCKETMAX * sizeof(socket_t));
  Pollfd = safe_malloc (SOCKETMAX * sizeof(struct pollfd));
  if (pthread_create(&_pth, NULL, &_poll_thread, NULL) != 0)
  {
    FREE(&Socket);
    FREE(&Pollfd);
    _Salloc = 0;
    return -1; //FIXME: fatal!
  }
  _mypid = getpid();
  /* block SIGPOLL completely */
  act.sa_handler = SIG_IGN;
  sigemptyset (&act.sa_mask);
  act.sa_flags = 0;
  return (sigaction (SIGPOLL, &act, NULL));
}
