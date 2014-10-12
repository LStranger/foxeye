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
 *     You should have received a copy of the GNU General Public License along
 *     with this program; if not, write to the Free Software Foundation, Inc.,
 *     51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * This file is part of FoxEye's source: sockets library API.
 */

#ifndef _SOCKET_H
#define _SOCKET_H 1

#define M_RAW		0
#define M_POLL		2
#define M_LIST		3
#define M_LINP		4
#define M_UNIX		5

#define E_AGAIN		-1L	/* socket is waiting for connection */
#define E_NOSOCKET	-2L	/* no such socket */
#define E_RESOLVTIMEOUT	-3L	/* DNS search error */
//#define E_UNREACHABLE	-4	/* host unreachable */
#define E_NOTHREAD	-5L	/* cannot create listening thread */
#define E_EOF		-6L	/* remote end closed connection */
#define E_UNDEFDOMAIN	-7L
#define E_NOSUCHDOMAIN	-8L
//#define E_NOCONNECT	-9
#define E_ERRNO		-10L

#define POLL_TIMEOUT	200	/* in milliseconds - M_POLL from threads */

/* this is required for struct sockaddr */
#include <sys/socket.h>

idx_t GetSocket (unsigned short);		/* allocate one socket */
int SetupSocket (idx_t, const char *, const char *, unsigned short,
		 int (*)(const struct sockaddr *, void *), void *);
		 /* socket, domain, bind_to, port, callback, callerdata */
void ResetSocket (idx_t, unsigned short);	/* reset after failed setup */
int KillSocket (idx_t *);			/* forget the socket */
ssize_t ReadSocket (char *, idx_t, size_t);
ssize_t WriteSocket (idx_t, const char *, size_t *, size_t *);
idx_t AnswerSocket (idx_t);
const char *SocketDomain (idx_t, unsigned short *); /* returns nonull value! */
const char *SocketIP (idx_t);			/* the same but text IP */
const char *SocketMyIP (idx_t, char *, size_t);
char *SocketError (int, char *, size_t);
void PollSockets (int);				/* sleep for dispatcher */

int _fe_init_sockets (void);

#endif /* _SOCKET_H */
