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
 * This file contains sockets control.
 */

#include "foxeye.h"

#include <pthread.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <signal.h>
#include <setjmp.h>
#include <fcntl.h>
#include <errno.h>

#include "socket.h"

typedef struct SOCKET
{
  char *domain;			/* if free is NULL */
  unsigned short port;
  ssize_t bufpos;
  size_t available;
  char inbuf[2*MESSAGEMAX];
} SOCKET;

static pid_t _mypid;

static SOCKET *Socket = NULL;
static idx_t _Salloc = 0;
static idx_t _Snum = 0;
static struct pollfd *Pollfd = NULL;

static pthread_mutex_t LockPoll;

static void sigio_handler (int signo)
{
  pthread_mutex_lock (&LockPoll);
  poll (Pollfd, _Snum, 0);
  pthread_mutex_unlock (&LockPoll);
}

/* warning: does not check anything! */
static void _socket_get_line (char *buf, SOCKET *s, size_t l, int mode)
{
  register char *c;

  memcpy (buf, &s->inbuf[s->bufpos], l);
  c = s->inbuf + s->bufpos + l;
  if (mode && *c == '\r')
  {
    c++;
    l++;
  }
  if (mode && *c == '\n')
    l++;
  s->bufpos += l;
  s->available -= l;
  if (s->bufpos < MESSAGEMAX && s->available)
    return;
  if (s->available)
    memcpy (s->inbuf, c, s->available);
  s->bufpos = 0;
}

static ssize_t _socket_find_line (SOCKET *s)
{
  register ssize_t p;
  register char *c = memchr (&s->inbuf[s->bufpos], '\n', s->available);

  if (!c)
    return (-1);
  p = c - &s->inbuf[s->bufpos];
  if (!p)
    return 0;
  c--;
  if (*c != '\r')
    return (p);
  return (p-1);
}

static void close_socket (idx_t idx)
{
  pthread_mutex_lock (&LockPoll);
  if (Pollfd[idx].fd != -1)
  {
    dprint (5, "socket:close_socket: fd=%d", Pollfd[idx].fd);
    shutdown (Pollfd[idx].fd, SHUT_RDWR);
    close (Pollfd[idx].fd);
    Pollfd[idx].fd = -1;
  }
  pthread_mutex_unlock (&LockPoll);
}

static idx_t allocate_socket ()
{
  idx_t idx;

  pthread_mutex_lock (&LockPoll);
  for (idx = 0; idx < _Snum; idx++)
    if (Socket[idx].domain == NULL && Pollfd[idx].fd == -1)
      break;
  if (idx == _Salloc)
  {
    _Salloc += 8;
    safe_realloc ((void **)&Socket, _Salloc * sizeof(SOCKET));
    safe_realloc ((void **)&Pollfd, _Salloc * sizeof(struct pollfd));
  }
  Pollfd[idx].fd = -1;
  Pollfd[idx].events = POLLIN | POLLPRI | POLLOUT;
  Pollfd[idx].revents = 0;
  Socket[idx].domain = NULL;
  Socket[idx].bufpos = Socket[idx].available = 0;
  if (idx == _Snum)
    _Snum++;
  pthread_mutex_unlock (&LockPoll);
  return idx;
}

/*
 * returns -1 on error and -2 on wait to connection
 */
ssize_t ReadSocket (char *buf, idx_t idx, size_t sr, int mode)
{
  SOCKET *sock;
  ssize_t sg = -1;
  short rev;

  pthread_mutex_lock (&LockPoll);
  if (idx < 0 || idx >= _Snum || Pollfd[idx].fd < 0)
  {
    pthread_mutex_unlock (&LockPoll);
    return (E_NOSOCKET);
  }
  rev = Pollfd[idx].revents;
  pthread_mutex_unlock (&LockPoll);
  mode -= M_FILE;
  sock = &Socket[idx];
  /* now check for incomplete connection... */
  if (sock->bufpos == -1)
  {
    if (!(rev & (POLLIN | POLLPRI | POLLOUT | POLLERR)))
    {
      return (E_AGAIN);		/* still waiting for connection */
    }
    if ((rev & POLLERR) ||
	(read (Pollfd[idx].fd, sock->inbuf, 0) < 0))
    {
      close_socket (idx);
      return (E_NOSOCKET);	/* connection timeout or other error */
    }
    sock->bufpos = 0;		/* connection established! */
  }
  if (mode)
    sg = _socket_find_line (sock);
  if (sg < 0)
  {
    if (!rev)
      return 0;
    if (rev & POLLNVAL)
    {
      close_socket (idx);
      return (E_NOSOCKET);
    }
    else if (rev & POLLERR)
    {
      if (!(sg = sock->available))
	return (E_NOSOCKET);
    }
    else if (rev & (POLLIN | POLLPRI))
    {
      sg = sock->bufpos + sock->available;
      pthread_mutex_lock (&LockPoll);
      if (mode)				/* non-raw socket, read into inbuf */
	sg = read (Pollfd[idx].fd, &sock->inbuf[sg], (sizeof(sock->inbuf) - sg));
      else				/* raw socket, just read it */
	sg = read (Pollfd[idx].fd, buf, sr);
      pthread_mutex_unlock (&LockPoll);
      if (sg < 0)
        return (E_NOSOCKET);
      else if (sg == 0)
	return (E_EOF);
      sigio_handler (0);		/* we read socket, recheck state */
      sock->available += sg;
      if (mode)
	sg = _socket_find_line (sock);
      if (sg < 0)
        return 0;
    }
    else
      return 0;
  }
  if (mode)
  {
    if (sg > sr)
      sg = sr;
  }
  else if (sg >= sr)
    sg = sr - 1;
  if (mode)
  {
    _socket_get_line (buf, sock, sg, mode);
    if (sg)
      buf[sg] = 0;			/* line terminator */
  }
  return (sg);
}

ssize_t _write_conv_crlf (int fd, char *buf, size_t count)
{
  char *ch, *chcr;
  char *che = &buf[count];
  ssize_t s = count, wr = 0;

  while (count)
  {
    ch = chcr = buf;
    do
    {
      ch = memchr (ch, '\n', s);
      if (!ch)
	ch = che;
      if (ch != buf)
	chcr = ch - 1;
      s = che - ch;
    } while (s && *chcr == '\r');
    s = write (fd, buf, ch - buf);
    if (s < 0)
      break;
    wr += s;
    count -= s;
    buf += s;
    if (ch != buf || !count || write (fd, "\r\n", 2) != 2)
      break;
    wr++;
    buf++;
    count--;
  }
  return wr;
}

/* we considered we can rewrite *buf limited by *sw :)
 * returns: -1 if error or number of writed bytes from buf */
ssize_t WriteSocket (idx_t idx, char *buf, size_t *sw, int mode)
{
  SOCKET *sock;
  short rev;

  pthread_mutex_lock (&LockPoll);
  if (idx < 0 || idx >= _Snum || Pollfd[idx].fd < 0)
  {
    pthread_mutex_unlock (&LockPoll);
    return -1;
  }
  rev = Pollfd[idx].revents;
  pthread_mutex_unlock (&LockPoll);
  if (!buf || !sw)
    return 0;
  sock = &Socket[idx];
  if (rev & POLLNVAL)			/* socket destroyed yet */
    close_socket (idx);
  if (rev & (POLLNVAL | POLLERR))	/* any error */
    return -1;
  else
  {
    ssize_t sg = 0;

    if (!(rev & POLLOUT))
      return 0;
    pthread_mutex_lock (&LockPoll);
    if (mode == M_FILE)
      sg = write (Pollfd[idx].fd, buf, *sw);
    else
      sg = _write_conv_crlf (Pollfd[idx].fd, buf, *sw);
    pthread_mutex_unlock (&LockPoll);
    sigio_handler (0);			/* we wrote socket, recheck state */
    if (sg < 0)				/* EAGAIN */
      return 0;
    else if (sg != *sw)
    {
      *sw -= sg;
      memmove (buf, &buf[sg], *sw);
    }
    else
      *sw = 0;
    if (sg > 0 && mode != M_FILE)
      buf[*sw] = 0;			/* line was moved - line terminator */
    return (sg);
  }
}

int KillSocket (idx_t *idx)
{
  idx_t i = *idx;

  if (i < 0)
    return -1;
  *idx = -1;			/* no more that socket */
  pthread_mutex_lock (&LockPoll);
  if (i >= _Snum || Socket[i].domain == NULL)
  {
    pthread_mutex_unlock (&LockPoll);
    return -1;			/* no such socket */
  }
  pthread_mutex_unlock (&LockPoll);
  close_socket (i);		/* must be first for reentrance */
  Socket[i].port = 0;
  pthread_mutex_lock (&LockPoll);
  FREE (&Socket[i].domain);
  pthread_mutex_unlock (&LockPoll);
  return 0;
}

/* For a listening process - we have to get ECONNREFUSED to own port :) */
idx_t AddSocket (int type, char *domain, unsigned short port)
{
  idx_t idx;
  struct sockaddr_in sin;
  struct hostent *hptr = NULL;
  struct linger ling;
  int i = 1, sockfd;

  /* check for errors! */
  if (!domain && type != M_LIST && type != M_LINP)
    return (E_UNDEFDOMAIN);
  memset (&sin, 0, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons (port);
  if (!domain)
  {
    sin.sin_addr.s_addr = htonl (INADDR_ANY);
  }
  else
  {
    hptr = gethostbyname (domain);
    if (!hptr || !hptr->h_addr_list[0])
      return (E_NOSUCHDOMAIN);
    memcpy (&sin.sin_addr, hptr->h_addr_list[0], hptr->h_length);
  }
  sockfd = socket (AF_INET, SOCK_STREAM, 0);
  pthread_mutex_lock (&LockPoll);
  idx = allocate_socket();
  /* now we have new idx */
  Pollfd[idx].fd = sockfd;
  pthread_mutex_unlock (&LockPoll);
  if (sockfd == -1)
    return (E_NOSOCKET);
  Socket[idx].port = port;
  setsockopt (sockfd, SOL_SOCKET, SO_KEEPALIVE, (void *) &i, sizeof(i));
  ling.l_onoff = 1;
  ling.l_linger = 0;
  setsockopt (sockfd, SOL_SOCKET, SO_LINGER, (void *) &ling, sizeof(ling));
  fcntl (sockfd, F_SETOWN, _mypid);
  fcntl (sockfd, F_SETFL, O_NONBLOCK | O_ASYNC);
  if (type == M_LIST || type == M_LINP)
  {
    socklen_t len = sizeof(sin);
    int backlog = 3;

    if (type == M_LINP)
      backlog = 1;
    if (bind (sockfd, (struct sockaddr *)&sin, sizeof(sin)) < 0 ||
	listen (sockfd, backlog) < 0 ||
	getsockname (sockfd, (struct sockaddr *)&sin, &len) < 0)
    {
      close_socket (idx);
      return (E_NOLISTEN);
    }
    Socket[idx].port = ntohs (sin.sin_port);
  }
  else
  {
    while ((i = connect (sockfd, (struct sockaddr *)&sin, sizeof(sin))) < 0 &&
	    errno == EAGAIN);
    if (errno != EINPROGRESS)
    {
      close_socket (idx);
      return (E_NOCONNECT);
    }
    Socket[idx].bufpos = i;
  }
  hptr = gethostbyaddr ((char *)&sin.sin_addr, sizeof(sin.sin_addr), AF_INET);
  if (hptr && hptr->h_name)
    domain = hptr->h_name;	/* subst canonical name */
  pthread_mutex_lock (&LockPoll);
  Socket[idx].domain = safe_strdup (domain);
  pthread_mutex_unlock (&LockPoll);
  return (idx);
}

idx_t AnswerSocket (idx_t listen)
{
  idx_t idx;
  struct sockaddr_in cliaddr;
  struct hostent *hptr = NULL;
  int sockfd;
  short rev;
  socklen_t len = sizeof(cliaddr);

  pthread_mutex_lock (&LockPoll);
  if (listen < 0 || listen >= _Snum || Pollfd[listen].fd < 0)
  {
    pthread_mutex_unlock (&LockPoll);
    return (E_NOSOCKET);
  }
  rev = Pollfd[listen].revents;
  pthread_mutex_unlock (&LockPoll);
  if (!(rev & (POLLIN | POLLPRI | POLLNVAL | POLLERR)))
    return (E_AGAIN);
  else if (rev & POLLNVAL)
  {
    close_socket (listen);
    return (E_NOSOCKET);
  }
  else if (rev & POLLERR)
    return (E_NOSOCKET);
  sockfd = accept (Pollfd[listen].fd, (struct sockaddr *)&cliaddr, &len);
  pthread_mutex_lock (&LockPoll);
  idx = allocate_socket();
  Pollfd[idx].fd = sockfd;
  pthread_mutex_unlock (&LockPoll);
  if (sockfd == -1)
    return (E_NOSOCKET);
  Socket[idx].port = ntohs (cliaddr.sin_port);
  fcntl (sockfd, F_SETOWN, _mypid);
  fcntl (sockfd, F_SETFL, O_NONBLOCK | O_ASYNC);
  hptr = gethostbyaddr ((char *)&cliaddr.sin_addr, sizeof(cliaddr.sin_addr),
			AF_INET);
  pthread_mutex_lock (&LockPoll);
  if (hptr && hptr->h_name)
    Socket[idx].domain = safe_strdup (hptr->h_name); /* subst canonical name */
  else
  {
    char nd[16];
    uchar *p = (uchar *)&cliaddr.sin_addr;

    snprintf (nd, sizeof(nd), "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
    Socket[idx].domain = safe_strdup (nd);	/* unresolved domain name */
  }
  pthread_mutex_unlock (&LockPoll);
  return (idx);
}

char *SocketDomain (idx_t idx, unsigned short *port)
{
  char *d = NULL;
  /* check if idx is invalid */
  pthread_mutex_lock (&LockPoll);
  if (idx >= 0 && idx < _Snum)
  {
    if (port)
      *port = Socket[idx].port;
    d = Socket[idx].domain;
  }
  pthread_mutex_unlock (&LockPoll);
  return NONULL(d);
}

int fe_init_sockets (void)
{
  struct sigaction act;
  pthread_mutexattr_t attr;

  /* init recursive LockIface - Unix98 only */
  pthread_mutexattr_init (&attr);
  pthread_mutexattr_settype (&attr, PTHREAD_MUTEX_RECURSIVE);
  pthread_mutex_init (&LockPoll, &attr);
  /* init SIGIO handler */
  _mypid = getpid();
  act.sa_handler = &sigio_handler;
  sigemptyset (&act.sa_mask);
  act.sa_flags = 0;
  return (sigaction (SIGIO, &act, NULL));
}
