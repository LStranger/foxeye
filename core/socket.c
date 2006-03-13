/*
 * Copyright (C) 1999-2006  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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

typedef struct
{
  char *domain;			/* if free then this is NULL */
  unsigned short port;
  ssize_t bufpos;
  size_t available;
  char inbuf[2*MB_LEN_MAX*MESSAGEMAX]; /* cyclic input buffer */
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

static void dmemcpy (void *d, socket_t *s, size_t l)
{
  DBG ("dmemcpy(%u+%u)[%*.*s]", s->bufpos, l, l, l, &s->inbuf[s->bufpos]);
  memcpy (d, &s->inbuf[s->bufpos], l);
}

/* warning: does not check anything! */
static void _socket_get_line (char *buf, socket_t *s, size_t l)
{
  register size_t available, bufpos;

  if (s->bufpos + l >= sizeof(s->inbuf))
  {
    /* get tail of buffer */
    bufpos = sizeof(s->inbuf) - s->bufpos;
    //memcpy (buf, &s->inbuf[s->bufpos], bufpos);
    dmemcpy (buf, s, bufpos);
    buf += bufpos;
    l -= bufpos;
    s->available -= bufpos;
    s->bufpos = 0;
    /* get head of buffer now */
  }
  if (l)
    //memcpy (buf, &s->inbuf[s->bufpos], l);
    dmemcpy (buf, s, l);
  bufpos = s->bufpos + l;
  available = s->available - l;
  if (available && s->inbuf[bufpos] == '\r')
  {
    bufpos++;
    available--;
    /* reached EOB? */
    if (bufpos == sizeof(s->inbuf))
      bufpos = 0;
  }
  if (available && s->inbuf[bufpos] == '\n')
  {
    bufpos++;
    available--;
  }
  s->available = available;
  if (available == 0 || bufpos == sizeof(s->inbuf))
    s->bufpos = 0;
  else
    s->bufpos = bufpos;
}

/* returns: -1 if not found, 0+ (strlen) if found */
static ssize_t _socket_find_line (socket_t *s)
{
  register ssize_t p;
  register char *c;

  if (!s->available)
    return (-1);
  if (s->bufpos + s->available > sizeof(s->inbuf))	/* YZ.....X */
  {
    /* check tail first */
    c = memchr (&s->inbuf[s->bufpos], '\n', sizeof(s->inbuf) - s->bufpos);
    /* if not found then check head */
    if (!c)
      c = memchr (s->inbuf, '\n', s->bufpos + s->available - sizeof(s->inbuf));
  }
  else							/* ...XYZ.. */
    c = memchr (&s->inbuf[s->bufpos], '\n', s->available);
  if (!c)
  {
    if (s->available < sizeof(s->inbuf)) /* there is still a chance of LF */
      return (-1);
    c = &s->inbuf[s->bufpos];		/* full buffer for out */
    p = sizeof(s->inbuf);
  }
  else
    p = c - &s->inbuf[s->bufpos];
  if (p < 0)
  {
    p += sizeof(s->inbuf);
    DBG ("found in buffer: %d(%u:%u)[%*.*s]...", p, s->bufpos, s->available,
	 sizeof(s->inbuf) - s->bufpos, sizeof(s->inbuf) - s->bufpos,
	 &s->inbuf[s->bufpos]);
  }
  else
    DBG ("found in buffer: %d(%u:%u)[%*.*s]", p, s->bufpos, s->available, p, p,
	 &s->inbuf[s->bufpos]);
  if (!p)
    return 0;
  if (c > s->inbuf)
    c--;
  else
    c = &s->inbuf[sizeof(s->inbuf)-1];
  if (*c != '\r')
    return (p);
  return (p-1);
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
  Pollfd[idx].events = POLLIN | POLLPRI | POLLOUT;
  Pollfd[idx].revents = 0;
  Socket[idx].domain = NULL;
  Socket[idx].bufpos = Socket[idx].available = 0;
  if (idx == _Snum)
    _Snum++;
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

  if (idx < 0 || idx >= _Snum)
    return (E_NOSOCKET);
  sock = &Socket[idx];
  if (Pollfd[idx].fd < 0)
    rev = POLLERR;
  else
    rev = Pollfd[idx].revents;
  mode -= M_RAW;
  /* now check for incomplete connection... */
  if (sock->bufpos == -1)
  {
    if (!(rev & (POLLIN | POLLPRI | POLLOUT | POLLERR)))
      return (E_AGAIN);		/* still waiting for connection */
    if ((rev & POLLERR) ||
	(read (Pollfd[idx].fd, sock->inbuf, 0) < 0))
    {
      CloseSocket (idx);
      return (E_NOSOCKET);	/* connection timeout or other error */
    }
    sock->bufpos = 0;		/* connection established! */
  }
  if (mode)
    sg = _socket_find_line (sock);
  if (sg < 0)
  {
    if (!rev)
    {
      poll (&Pollfd[idx], 1, mode == (M_POLL - M_RAW) ? POLL_TIMEOUT : 0);
      rev = Pollfd[idx].revents;
    }
    if (rev & POLLNVAL)
      CloseSocket (idx);
    if (rev & (POLLNVAL | POLLERR))
    {
      if (!(sg = sock->available))
	return (E_NOSOCKET);
    }
    else if (rev & (POLLIN | POLLPRI))
    {
      sg = sock->bufpos + sock->available;
      if (mode)				/* non-raw socket, read into inbuf */
      {
	/* fill tail first */
	DBG ("trying read socket %d:(%u:%u)", idx, sock->bufpos, sock->available);
	if (sg < sizeof(sock->inbuf))
	{
	  sg = read (Pollfd[idx].fd, &sock->inbuf[sg], (sizeof(sock->inbuf) - sg));
	  /* could we fill head too? */
	  if (sg > 0)
	    DBG ("got from socket %d:[%*.*s]", idx, sg, sg,
		 &sock->inbuf[sock->bufpos + sock->available]);
	  if (sg > 0 && sock->bufpos &&
	      sock->bufpos + sock->available + sg == sizeof(sock->inbuf))
	  {
	    sock->available += sg;
	    sg = read (Pollfd[idx].fd, sock->inbuf, sock->bufpos);
	    if (sg > 0)
	      DBG ("got from socket %d:[%*.*s]", idx, sg, sg, sock->inbuf);
	  }
	}
	/* could we still fill head? */
	else if (sock->available < sizeof(sock->inbuf))
	{
	  sg = read (Pollfd[idx].fd, &sock->inbuf[sg-sizeof(sock->inbuf)],
		     sizeof(sock->inbuf) - sock->available);
	  if (sg > 0)
	    DBG ("got from socket %d:[%*.*s]", idx, sg, sg,
		 &sock->inbuf[sock->bufpos + sock->available - sizeof(sock->inbuf)]);
	}
	else	/* no free space available */
	  sg = 0;
	if (sg > 0)
	  sock->available += sg;
      }
      else				/* raw socket, just read it */
	sg = read (Pollfd[idx].fd, buf, sr);
      if (sg <= 0)
      {
	CloseSocket (idx);
	sg = 0;				/* if socket died then close it */
      }
      Pollfd[idx].revents = 0;		/* we read socket, reset state */
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
    if (sg >= sr)
      sg = sr - 1;
  }
  else if (sg > sr)
    sg = sr;
  if (mode)
  {
    if (sg)
      _socket_get_line (buf, sock, sg);
    buf[sg] = 0;			/* line terminator */
    sg++;				/* in text modes it includes 0 */
  }
  return (sg);
}

/*
 * returns: -1 if error or number of writed bytes from buf
 */
ssize_t WriteSocket (idx_t idx, char *buf, size_t *ptr, size_t *sw, int mode)
{
  socket_t *sock;
  short rev;

  if (idx < 0 || idx >= _Snum || Pollfd[idx].fd < 0)
    return -1;
  if (!buf || !sw)
    return 0;
  rev = Pollfd[idx].revents;
  sock = &Socket[idx];
  if (!rev)
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
    return (sg);
  }
}

int KillSocket (idx_t *idx)
{
  idx_t i = *idx;

  if (i < 0)
    return -1;
  *idx = -1;			/* no more that socket */
  if (i >= _Snum || Socket[i].domain == NULL)
    return -1;			/* no such socket */
  dprint (4, "socket:KillSocket: fd=%d", Pollfd[i].fd);
  CloseSocket (i);		/* must be first for reentrance */
  Socket[i].port = 0;
  FREE (&Socket[i].domain);	/* indicator of free socket */
  return 0;
}

idx_t GetSocket (void)
{
  idx_t idx;
  int sockfd;

  pthread_mutex_lock (&LockPoll);
  if ((idx = allocate_socket()) < 0)
    sockfd = -1; /* too many sockets */
  else
    Pollfd[idx].fd = sockfd = socket (AF_INET, SOCK_STREAM, 0);
  pthread_mutex_unlock (&LockPoll);
  if (sockfd == -1)
    return (E_NOSOCKET);
  return idx;
}

/* For a listening process - we have to get ECONNREFUSED to own port :) */
int SetupSocket (idx_t idx, int type, char *domain, unsigned short port)
{
  struct sockaddr_in sin;
  struct hostent *hptr = NULL;
  struct linger ling;
  int i = 1, sockfd = Pollfd[idx].fd;

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
  Socket[idx].port = port;
  setsockopt (sockfd, SOL_SOCKET, SO_KEEPALIVE, (void *) &i, sizeof(i));
  ling.l_onoff = 1;
  ling.l_linger = 0;
  setsockopt (sockfd, SOL_SOCKET, SO_LINGER, (void *) &ling, sizeof(ling));
  fcntl (sockfd, F_SETOWN, _mypid);
  if (type == M_LIST || type == M_LINP)
  {
    socklen_t len = sizeof(sin);
    int backlog = 3;

    if (type == M_LINP)
      backlog = 1;
    if (bind (sockfd, (struct sockaddr *)&sin, sizeof(sin)) < 0 ||
	listen (sockfd, backlog) < 0 ||
	getsockname (sockfd, (struct sockaddr *)&sin, &len) < 0)
      return (E_NOLISTEN);
    Socket[idx].port = ntohs (sin.sin_port);
  }
  else
  {
//    while ((i = connect (sockfd, (struct sockaddr *)&sin, sizeof(sin))) < 0 &&
//	    errno == EAGAIN);
//    if (errno != EINPROGRESS)
    if ((i = connect (sockfd, (struct sockaddr *)&sin, sizeof(sin))) < 0)
      return (E_NOCONNECT);
    Socket[idx].bufpos = i;
  }
  fcntl (sockfd, F_SETFL, O_NONBLOCK | O_ASYNC);
  hptr = gethostbyaddr ((char *)&sin.sin_addr, sizeof(sin.sin_addr), AF_INET);
  if (hptr && hptr->h_name)
    domain = hptr->h_name;	/* subst canonical name */
  Socket[idx].domain = safe_strdup (domain);
  return 0;
}

idx_t AnswerSocket (idx_t listen)
{
  idx_t idx;
  struct sockaddr_in cliaddr;
  struct hostent *hptr = NULL;
  int sockfd;
  short rev;
  socklen_t len = sizeof(cliaddr);

  if (listen < 0 || listen >= _Snum || Pollfd[listen].fd < 0)
    return (E_NOSOCKET);
  rev = Pollfd[listen].revents;
  if (!rev)
  {
    poll (&Pollfd[listen], 1, POLL_TIMEOUT);
    rev = Pollfd[listen].revents;
  }
  if (!(rev & (POLLIN | POLLPRI | POLLNVAL | POLLERR)))
    return (E_AGAIN);
  else if (rev & POLLNVAL)
  {
    CloseSocket (listen);
    return (E_NOSOCKET);
  }
  else if (rev & POLLERR)
    return (E_NOSOCKET);
  pthread_mutex_lock (&LockPoll);
  if ((idx = allocate_socket()) < 0)
    sockfd = -1;
  else
    Pollfd[idx].fd = sockfd = accept (Pollfd[listen].fd, (struct sockaddr *)&cliaddr, &len);
  pthread_mutex_unlock (&LockPoll);
  Pollfd[listen].revents = 0;		/* we accepted socket, reset state */
  if (sockfd == -1)
    return (E_AGAIN);
  Socket[idx].port = ntohs (cliaddr.sin_port);
  fcntl (sockfd, F_SETOWN, _mypid);
  fcntl (sockfd, F_SETFL, O_NONBLOCK | O_ASYNC);
  hptr = gethostbyaddr ((char *)&cliaddr.sin_addr, sizeof(cliaddr.sin_addr),
			AF_INET);
  if (hptr && hptr->h_name)
    Socket[idx].domain = safe_strdup (hptr->h_name); /* subst canonical name */
  else
  {
    char nd[16];
    uchar *p = (uchar *)&cliaddr.sin_addr;

    snprintf (nd, sizeof(nd), "%u.%u.%u.%u", p[0], p[1], p[2], p[3]);
    Socket[idx].domain = safe_strdup (nd);	/* unresolved domain name */
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

int fe_init_sockets (void)
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
