/*
 * Copyright (C) 1999-2001  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 * Internal userfile structures. It is the best do not use its outside users.c
 */

#ifndef _USERS_H
#define _USERS_H 1

#include <pthread.h>
#include "wtmp.h"

typedef struct user_chr
{
  lid_t cid;			/* channel index in list */
  userflag flag;
  char *greeting;		/* greeting or ban comment */
  time_t expire;
  struct user_chr *next;
} user_chr;

typedef struct user_hr
{
  struct user_hr *next;
  char hostmask[STRING];	/* Warning!!! This field may be variable size,
				 * don't use 'sizeof(user_hr)' anymore! */
} user_hr;

typedef struct user_fr
{
  struct user_fr *next;
  char *value;
  lid_t id;
} user_fr;

typedef struct USERRECORD
{
  lid_t uid;
  userflag flag;
  char *lname;
  char *rfcname;
  unsigned progress : 1;	/* is 1 if updating */
  unsigned ignored : 1;
  user_chr *channels;
  user_hr *host;
  char *passwd;			/* the "passwd" field */
  union				/* NULL by default */
  {
    char *info;			/* the "info" field or ban comment */
    char *chanmode;		/* channel mode string */
    struct USERRECORD *owner;	/* owner of this alias */
  }u;
  char *charset;		/* the "charset" field - no default */
  char *login;			/* the ".login" field - "motd" by default */
  char *logout;			/* the ".logoff" field - NULL by default */
  char *dccdir;			/* the "dccdir" field */
  time_t created;
  struct USERRECORD *next;
  struct USERRECORD *prev;
  user_fr *fields;
  pthread_mutex_t mutex;
} USERRECORD;

lid_t GetLID (const char *);	/* Lname -> LID */

/* async-safe, input userflag XOR'ed and final userflag returned */
userflag Set_ChanFlags (lid_t, const char *, userflag);
char *userflagtostr (userflag, char *);

#endif
