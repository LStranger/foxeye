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
 * This file is part of FoxEye's source: the Listfile API.
 */

#ifndef _LIST_H
#define _LIST_H 1

typedef short lid_t;
#define LID_MIN SHRT_MIN
#define LID_MAX SHRT_MAX

/* special lids */
#define ID_REM -1	/* removed id */
#define ID_ME 0		/* my own id */
#define ID_ANY 150	/* any user/channel/service */

typedef struct USERRECORD clrec_t;

int Get_Clientlist (INTERFACE *, userflag, const char *, const char *);
int Get_Hostlist (INTERFACE *, lid_t);
int Get_Fieldlist (INTERFACE *, lid_t);
unsigned short Get_Hosthash (const char *, const char *)
			__attribute__((warn_unused_result));
userflag Match_Client (char *, char *, const char *)
			__attribute__((warn_unused_result));
userflag Get_Clientflags (const char *, const char *)
			__attribute__((warn_unused_result));
clrec_t *Find_Clientrecord (const uchar *, char **, userflag *, char *)
			__attribute__((warn_unused_result));
clrec_t *Lock_Clientrecord (const char *)
			__attribute__((warn_unused_result));
char *Get_Field (clrec_t *, const char *, time_t *)
			__attribute__((warn_unused_result));
int Set_Field (clrec_t *, const char *, const char *, time_t);
int Grow_Field (clrec_t *, const char *, const char *);
userflag Get_Flags (clrec_t *, const char *)
			__attribute__((warn_unused_result));
userflag Set_Flags (clrec_t *, const char *, userflag);
int Add_Mask (clrec_t *, const uchar *)
			__attribute__((warn_unused_result));
int Delete_Mask (clrec_t *, const uchar *)
			__attribute__((warn_unused_result));
void Unlock_Clientrecord (clrec_t *);

lid_t FindLID (const char *) __attribute__((warn_unused_result)); /* Lname -> LID */
lid_t Get_LID (clrec_t *) __attribute__((warn_unused_result));
clrec_t *Lock_byLID (lid_t) __attribute__((warn_unused_result));

char *userflagtostr (userflag, char *);

#endif
