/*
 * Copyright (C) 1999-2005  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 * public structure of all the dcc connections
 */

#ifndef _DIRECT_H
#define _DIRECT_H 1

#include <pthread.h>

typedef enum
{
  D_LOGIN = 0,				/* initiate state - user enters dcc */
  D_OFFER,				/* waiting for dcc get/send */
  D_OK,					/* closed session */
  D_CHAT,				/* user is on dcc chat */
  D_NOSOCKET,				/* lost socket */
  D_PRELOGIN				/* out the message and go to D_LOGIN */
} _dcc_state;

typedef struct
{
  _dcc_state state;
  userflag uf;
  char *away;				/* user away message / filename */
  idx_t socket;                         /* what socket we have messages to */
  time_t timestamp;
  INTERFACE *iface;			/* main interface of this session */
  size_t inbuf;				/* how much bytes are in buf */
  size_t bufpos;
  char start[13];			/* chat-on time */
  char buf[MB_LEN_MAX*MESSAGEMAX];	/* outgoing message buffer */
} peer_t;

void Chat_Join (INTERFACE *, userflag, int, int, char *); /* wrappers */
void Chat_Part (INTERFACE *, int, int, char *);
int Check_Passwd (const char *, char *);		/* plain, encrypted */

ssize_t Session_Put (peer_t *, char *, size_t);		/* data transfers */
ssize_t Session_Get (peer_t *, char *, size_t);

unsigned short Listen_Port (char *, unsigned short, char *,
			    void (*prehandler) (pthread_t, idx_t),
			    void (*) (char *, char *, char *, idx_t));
pthread_t Connect_Host (char *, unsigned short, idx_t *,
			void (*) (int, void *), void *);
#endif
