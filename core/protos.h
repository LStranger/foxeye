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
 */

#define uchar unsigned char

/* ----------------------------------------------------------------------------
 * Most common functions used by all modules and submodules
 */
 
INTERFACE *Add_Iface (const char *, iface_t, iface_t (*) (INTERFACE *, ifsig_t), \
		REQUEST * (*) (INTERFACE *, REQUEST *), void *);
INTERFACE *Find_Iface (iface_t, const char *);
INTERFACE *Set_Iface (INTERFACE *);
int Unset_Iface (void);
int Rename_Iface (iface_t, const char *, const char *);
void Add_Request (iface_t, char *, flag_t, char *, ...);
void New_Request (INTERFACE *, flag_t, char *, ...);
int Get_Request (void);
BINDTABLE *Add_Bindtable (const char *, bindtable_t); /* init.c */
BINDING *Check_Bindtable (BINDTABLE *, const char *, userflag, userflag, \
		BINDING *);
BINDING *Add_Binding (const char *, const char *, userflag, userflag, Function);
void Delete_Binding (const char *, Function);
int Save_Formats (void);
int Add_Help (const char *);			/* help.c */
void Delete_Help (const char *);
int Get_Help (const char *, const char *, INTERFACE *, userflag, userflag, \
		BINDTABLE *, char *, int);
int Add_Userrecord (const char *, const uchar *, userflag); /* users.c */
int Add_Alias (const char *, const char *);
void Delete_Userrecord (const char *);
int Add_Usermask (const char *, const uchar *);
void Delete_Usermask (const char *, const uchar *);
char *Get_Userfield (void *, const char *);
int Set_Userfield (void *, const char *, char *);
int Get_Userlist (INTERFACE *, userflag, const char *, char *);
void *Find_User (const uchar *, char **, userflag *, void *);
userflag Match_User (char *, char *, const char *);
userflag Get_ChanFlags (const char *, const char *);
void *Lock_User (const char *);
void Unlock_User (void *);

int Check_Passwd (const char *, char *);	/* dcc.c */

void msg2nick (char *, char *, ...);
void notice2nick (char *, char *, ...);

/* ----------------------------------------------------------------------------
 * Internal functions
 */

void dprint (int, char *, ...);			/* dispatch.c */
void bot_shutdown (char *, int);
int dispatcher (INTERFACE *);

/* ----------------------------------------------------------------------------
 * Common library functions and definitions
 */

int Change_Lname (char *, char *);
int match (const char *, const char *);		/* lib.c */
char *strlower (char *);
char *rfc2812_strlower (char *);
int Have_Wildcard (const char *);
char *NextWord (const char *);
char *NextWord_Unquoted (char *, size_t, const char *);	/* dst, size, src */
void StrTrim (char *);
void printl (char *, size_t, char *, size_t, char *, const char *, \
		const char *, char *, uint32_t, unsigned short, const char *);
/* buf, size, fmt, linelen, nick, uhost, lname, chann, ip, port, params */

char *safe_read_line (char *, size_t *, FILE *, int *);
char *safe_strlower (char *);
char *safe_substrcpy (char *, const char *, const char *, size_t);
char *safe_substrdup (const char *, const char *);
char *safe_strpbrk (const char *, const char *);
char *strfcat (char *, const char *, size_t);

int safe_strcmp (const char *, const char *);
int safe_strcasecmp (const char *, const char *);
int safe_strncmp (const char *, const char *, size_t);
int safe_strncasecmp (const char *, const char *, size_t);
char *safe_strchr (const char *, int);
size_t safe_strlen (const char *);

char *safe_strdup (const char *);
void *safe_calloc (size_t, size_t);
void *safe_malloc (size_t);
void safe_realloc (void **, size_t);
void safe_free (void **);

int safe_open (const char *, int);
int safe_symlink (const char *, const char *);
FILE *safe_fopen (const char *, const char *);

const char *expand_path (char *, const char *, size_t);

#define FOREVER while (1)
#define NONULL(x) x?x:""
#define FREE(x) safe_free((void **)x)

#define ISSPACE(c) isspace((uchar)c)

#define strfcpy(A,B,C) strncpy(A,B,C), *(A+(C)-1)=0

/* ----------------------------------------------------------------------------
 * Prototypes for broken systems
 */

#ifdef HAVE_SRAND48
# define LRAND lrand48
# define SRAND srand48
# define DRAND drand48
#else
# define LRAND rand
# define SRAND srand
# define DRAND (double)rand
#endif /* HAVE_SRAND48 */

#ifndef HAVE_RENAME
# define rename movefile
#endif

/* HP-UX, ConvexOS and UNIXware don't have this macro */
#ifndef S_ISLNK
# define S_ISLNK(x) (((x) & S_IFMT) == S_IFLNK ? 1 : 0)
#endif

/* AIX doesn't define these in any headers (sigh) */
int strcasecmp (const char *, const char *);
int strncasecmp (const char *, const char *, size_t);
