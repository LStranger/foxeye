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
 * Listfile specific functions declarations.
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

int Get_Clientlist (INTERFACE *, userflag, const char *, char *);
int Get_Hostlist (INTERFACE *, const char *);
userflag Match_Client (char *, char *, const char *);
userflag Get_Clientflags (const char *, const char *);
clrec_t *Find_Clientrecord (const uchar *, char **, userflag *, char *);
clrec_t *Lock_Clientrecord (const char *);
char *Get_Field (clrec_t *, const char *, time_t *);
int Set_Field (clrec_t *, const char *, const char *);
int Grow_Field (clrec_t *, const char *, const char *);
userflag Get_Flags (clrec_t *, const char *);
userflag Set_Flags (clrec_t *, const char *, userflag);
int Add_Mask (clrec_t *, const uchar *);
void Delete_Mask (clrec_t *, const uchar *);
void Unlock_Clientrecord (clrec_t *);

lid_t GetLID (const char *);	/* Lname -> LID */

char *userflagtostr (userflag, char *);

#endif
