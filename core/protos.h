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
 */

#define uchar unsigned char

/* ----------------------------------------------------------------------------
 * Common functions used by modules and submodules
 */
 
INTERFACE *Add_Iface (const char *, iftype_t, iftype_t (*) (INTERFACE *, ifsig_t), \
		int (*) (INTERFACE *, REQUEST *), void *);
INTERFACE *Find_Iface (iftype_t, const char *);
INTERFACE *Set_Iface (INTERFACE *);
int Unset_Iface (void);
int Rename_Iface (iftype_t, const char *, const char *);
void Add_Request (iftype_t, char *, flag_t, const char *, ...);
void New_Request (INTERFACE *, flag_t, const char *, ...);
int Get_Request (void);
bindtable_t *Add_Bindtable (const char *, bttype_t); /* init.c */
binding_t *Check_Bindtable (bindtable_t *, const char *, userflag, userflag, \
		binding_t *);
binding_t *Add_Binding (const char *, const char *, userflag, userflag, Function);
void Delete_Binding (const char *, Function);
int RunBinding (binding_t *, const uchar *, char *, char *, int, char *);
int Lname_IsOn (const char *, const char *, const char **);
modeflag Inspect_Client (const char *, const char *, const char **, \
			 const char **, time_t *);
int Add_Help (const char *);			/* help.c */
void Delete_Help (const char *);
int Get_Help (const char *, const char *, INTERFACE *, userflag, userflag, \
		bindtable_t *, char *, int);
int Add_Clientrecord (const char *, const uchar *, userflag); /* users.c */
int Add_Alias (const char *, const char *);
void Delete_Clientrecord (const char *);
int Change_Lname (char *, char *);

/* ----------------------------------------------------------------------------
 * Internal functions
 */

void dprint (int, const char *, ...);		/* dispatch.c */
void bot_shutdown (char *, int);
int dispatcher (INTERFACE *);

/* ----------------------------------------------------------------------------
 * Common library functions and definitions
 */

int match (const char *, const char *);		/* lib.c */
int Have_Wildcard (const char *);
char *NextWord (const char *);
char *NextWord_Unquoted (char *, const char *, size_t);	/* dst, src, size */
void StrTrim (char *);
void printl (char *, size_t, char *, size_t, char *, const char *, \
	     const char *, char *, uint32_t, unsigned short, int, const char *);
/* buf, size, fmt, linelen, nick, uhost, lname, chann, ip, port, idle, params */

char *safe_read_line (char *, size_t *, FILE *, int *);
char *safe_strlower (char *, const char *, size_t);
char *rfc2812_strlower (char *, const char *, size_t);
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
