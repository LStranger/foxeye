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
 * public structure of all the dcc connections
 */

#ifndef _DCC_H
#define _DCC_H 1

#include <pthread.h>

typedef enum
{
  D_LOGIN = 0,				/* initiate state - user enters dcc */
  D_OFFER,				/* waiting for dcc get/send */
  D_OK,					/* closed session */
  D_CHAT,				/* user is on dcc chat */
  D_NOSOCKET,				/* lost socket */
  D_PRELOGIN,				/* out the message and go to D_LOGIN */
  D_R_WHO,				/* collects report .who */
  D_R_WHO1,
  D_R_WHO2,
  D_R_WHOM,				/* collects report .whom */
  D_R_DCCSTAT				/* collects report .dccstat */
} _dcc_state;

typedef struct
{
  _dcc_state state;
  userflag uf;
  flag_t loglev;
  char *away;				/* user away message / filename */
  unsigned int botnet;			/* botnet channel / transferred (.1%) */
  short floodcnt;			/* flood counter */
  idx_t socket;                         /* what socket we have messages to */
  uint32_t rate;			/* average (50s) filetransfer speed */
  time_t timestamp;
  INTERFACE *iface;			/* full interface */
  INTERFACE *log;			/* interface for logs */
  INTERFACE *alias;			/* interface for botnet channel */
  BINDTABLE *cmdbind;			/* commands bindtable */
  pthread_mutex_t lock;			/* lock for all interface pointers */
  pthread_t th;
  char start[13];			/* chat-on time */
  char buf[LONG_STRING];
} DCC_SESSION;

int Get_DccIdx (DCC_SESSION *);
DCC_SESSION *Dcc_Send (char *, long);
void Chat_Join (DCC_SESSION *);		/* chat-join bindtable wrapper */
void Chat_Part (DCC_SESSION *);		/* chat-part bindtable wrapper */
void setdccconsole (DCC_SESSION *, char *);

void Dcc_Exec (DCC_SESSION *, char *, char *, BINDTABLE *, userflag, \
		   userflag, int);

#endif
