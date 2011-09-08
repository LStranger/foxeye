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
 * This file is part of FoxEye's source: direct connections API.
 */

#ifndef _DIRECT_H
#define _DIRECT_H 1

/* this is required for struct sockaddr */
#include <sys/socket.h>

typedef enum
{
  P_DISCONNECTED = 0,			/* no socket yet / lost socket */
  P_INITIAL,				/* authentication request sent */
  P_LOGIN,				/* thread done, main login state */
  P_TALK,				/* connected, main state */
  P_IDLE,				/* waiting for response */
  P_QUIT,				/* has to send quit message */
  P_LASTWAIT				/* closed session */
} _peer_state;


struct peer_t
{
  char *dname;				/* user away message / dest. name */
  INTERFACE *iface;			/* main interface of this session */
  void (*parse) (struct peer_t *, char *, char *, userflag, userflag, int, int,
		 struct bindtable_t *, char *); /* function to parse/broadcast line */
  struct connchain_i *connchain;	/* connchain instance */
  const char *network_type;		/* for connchain identification */
  struct peer_priv *priv;		/* session-specific data, NULL in thread */
  time_t last_input;
  _peer_state state;
  userflag uf;				/* global+direct flags */
  idx_t socket;				/* what socket we have messages to */
  char start[20];			/* chat-on time */
};

int Check_Passwd (const char *, char *);		/* plain, encrypted */

void Dcc_Parse (struct peer_t *, char *, char *, userflag, userflag, int, int,
		struct bindtable_t *, char *);		/* default parser */

int Listen_Port (char *, const char *, unsigned short, char *, void *,
		 int (*) (const struct sockaddr *, void *),
		 void (*) (pthread_t, void **, idx_t *),
		 void (*) (char *, char *, const char *, void *))
			__attribute__((warn_unused_result));
int Connect_Host (const char *, unsigned short, pthread_t *, idx_t *,
		  void (*) (int, void *), void *)
			__attribute__((warn_unused_result));

#define CONNCHAIN_READY	1	/* may be return from Connchain_Put(c,i,"",0) */

int Connchain_Grow (struct peer_t *, char);
int Connchain_Check (struct peer_t *, char);
ssize_t Connchain_Put (struct connchain_i **, idx_t, const char *, size_t *)
			__attribute__((warn_unused_result));
ssize_t Connchain_Get (struct connchain_i **, idx_t, char *, size_t)
			__attribute__((warn_unused_result));

#define Connchain_Kill(peer) Connchain_Get(&peer->connchain,peer->socket,NULL,0)
#define Peer_Put(peer,buf,s) Connchain_Put(&peer->connchain,peer->socket,buf,s)
#define Peer_Get(peer,buf,s) Connchain_Get(&peer->connchain,peer->socket,buf,s)

/* interop direct.c -> connchain.c */
void _fe_init_connchains (void);

#endif
