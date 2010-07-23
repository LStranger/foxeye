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
 * This file is part of FoxEye's source: direct connections API.
 */

#ifndef _DIRECT_H
#define _DIRECT_H 1

typedef enum
{
  P_DISCONNECTED = 0,			/* no socket yet / lost socket */
  P_INITIAL,				/* out the message and go P_LOGIN */
  P_LOGIN,				/* main login state */
  P_TALK,				/* connected, main state */
  P_IDLE,				/* waiting for response */
  P_QUIT,				/* has to send quit message */
  P_LASTWAIT				/* closed session */
} _peer_state;

typedef struct connchain_i connchain_i;
typedef struct connchain_buffer connchain_buffer;

typedef struct peer_t
{
  _peer_state state;
  userflag uf;
  char *dname;				/* user away message / dest. name */
  idx_t socket;                         /* what socket we have messages to */
  time_t last_input;
  INTERFACE *iface;			/* main interface of this session */
  void (*parse) (struct peer_t *, char *, char *, userflag, userflag, int, int,
		 bindtable_t *, char *);/* function to parse/broadcast line */
  connchain_i *connchain;		/* connchain instance */
  char start[13];			/* chat-on time */
} peer_t;

void Chat_Join (INTERFACE *, userflag, int, int, char *); /* wrappers */
void Chat_Part (INTERFACE *, int, int, char *);
int Check_Passwd (const char *, char *);		/* plain, encrypted */

void Dcc_Parse (struct peer_t *, char *, char *, userflag, userflag, int, int,
		bindtable_t *, char *);			/* default parser */

idx_t Listen_Port (char *, char *, unsigned short *, char *,
		   void (*) (pthread_t, idx_t, idx_t),
		   void (*) (char *, char *, char *, idx_t));
int Connect_Host (char *, unsigned short, pthread_t *, idx_t *,
		  void (*) (int, void *), void *);

#define CONNCHAIN_READY	1	/* may be return from Connchain_Put(c,i,"",0) */

int Connchain_Grow (peer_t *, char);
ssize_t Connchain_Put (connchain_i **, idx_t, const char *, size_t *);
ssize_t Connchain_Get (connchain_i **, idx_t, char *, size_t);

#define Connchain_Kill(peer) Connchain_Get(&peer->connchain,peer->socket,NULL,0)
#define Peer_Put(peer,buf,s) Connchain_Put(&peer->connchain,peer->socket,buf,s)
#define Peer_Get(peer,buf,s) Connchain_Get(&peer->connchain,peer->socket,buf,s)

/* interop direct.c -> connchain.c */
void _fe_init_connchains (void);

#endif
