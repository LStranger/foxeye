/*
 * Copyright (C) 1999-2000  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 */

#define M_FILE		1
#define M_NORM		2
#define M_LIST		3
#define M_LINP		4

#define E_NOSOCKET	-1	/* cannot create the socket */
#define E_AGAIN		-2	/* socket is waiting for connection */
#define E_RESOLVTIMEOUT	-3	/* DNS search error */
#define E_UNREACHABLE	-4	/* host unreachable */
#define E_NOLISTEN	-5	/* cannot listen the socket */
#define E_EOF		-6	/* eof() at read socket */
#define E_UNDEFDOMAIN	-7
#define E_NOSUCHDOMAIN	-8
#define E_NOCONNECT	-9

idx_t AddSocket (int, char *, unsigned short);		/* mode, domain, port */
int KillSocket (idx_t *);
ssize_t ReadSocket (char *, idx_t, size_t, int); /* read full line, strip \r\n */
ssize_t WriteSocket (idx_t, char *, size_t *, int); /* write "%s\r\n" */
idx_t AnswerSocket (idx_t);
char *SocketDomain (idx_t, unsigned short *);		/* returns nonull value! */

int fe_init_sockets (void);
