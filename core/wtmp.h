/*
 * Copyright (C) 2001  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 * wtmp file structure.
 */

#ifndef _WTMP_H
#define _WTMP_H 1

#define WTMPS_MAX 12		/* maximum value of $wtmps */
#define WTMP_GONE_EXT "gone"	/* file extention where we keep gone events */

typedef short lid_t;
#define LID_MIN SHRT_MIN
#define LID_MAX SHRT_MAX

/* special lids */
#define ID_REM -1	/* removed id */
#define ID_BOT 0	/* my own id */
#define ID_CHANN 150	/* any channel */
#define ID_FIRST 200	/* first user id */

/* events */
#define W_ANY -2	/* any event - for FindEvent() */
#define W_DOWN -1	/* "shutdown" event (also if bot parts channel) */
#define W_END 0		/* "session end" event */
#define W_START 1	/* "session start" event */
#define W_USER 2	/* start of user defined events */

typedef struct
{
  lid_t uid;
  lid_t fuid;		/* from uid */
  short count;		/* event specific data */
  short event;
  time_t time;
} wtmp_t;

short Event (const char *);				/* user event name -> event */
int FindEvent (wtmp_t *, const char *, short, lid_t);	/* Lname, event, from */
void NewEvent (short, const char *, const char *, short); /* event, Lname, from, count */
void NewEvents (short, const char *, size_t, const char **, short *);
void ChangeUid (lid_t, lid_t);				/* old, new - queue */
void CommitWtmp (void);					/* commit above */
void RotateWtmp (void);					/* called monthly */

#endif
