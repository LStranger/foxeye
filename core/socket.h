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
 * This file is part of FoxEye's source: sockets library API.
 */

#define M_RAW		0
#define M_TEXT		1
#define M_POLL		2
#define M_LIST		3
#define M_LINP		4

#define E_AGAIN		-1	/* socket is waiting for connection */
#define E_NOSOCKET	-2	/* no such socket */
//#define E_RESOLVTIMEOUT	-3	/* DNS search error */
//#define E_UNREACHABLE	-4	/* host unreachable */
#define E_NOLISTEN	-5	/* cannot listen the socket */
//#define E_EOF		-6
#define E_UNDEFDOMAIN	-7
#define E_NOSUCHDOMAIN	-8
#define E_NOCONNECT	-9
#define E_ERRNO		-10

#define POLL_TIMEOUT	200	/* in milliseconds - M_POLL from threads */

idx_t GetSocket (void);				/* allocate one socket */
int SetupSocket (idx_t, int, char *, unsigned short); /* mode, domain, port */
int KillSocket (idx_t *);			/* forget the socket */
void CloseSocket (idx_t);			/* just close it */
ssize_t ReadSocket (char *, idx_t, size_t, int); /* read full line, strip \r\n */
ssize_t WriteSocket (idx_t, char *, size_t *, size_t *, int); /* write line */
idx_t AnswerSocket (idx_t);
char *SocketDomain (idx_t, unsigned short *);	/* returns nonull value! */
char *SocketError (int, char *, size_t);

int fe_init_sockets (void);
