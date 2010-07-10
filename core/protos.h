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
 * This file is part of FoxEye's source: common declarations.
 */

#define uchar unsigned char

/* ----------------------------------------------------------------------------
 * Common functions used by modules and submodules
 */
 
INTERFACE *Add_Iface (iftype_t, const char *, iftype_t (*) (INTERFACE *, ifsig_t), \
		int (*) (INTERFACE *, REQUEST *), void *);
INTERFACE *Find_Iface (iftype_t, const char *);
INTERFACE *Set_Iface (INTERFACE *);
int Unset_Iface (void);
int Rename_Iface (INTERFACE *, const char *);
void Add_Request (iftype_t, const char *, flag_t, const char *, ...);
void New_Request (INTERFACE *, flag_t, const char *, ...);
int Relay_Request (iftype_t, char *, REQUEST *);
int Get_Request (void);
bindtable_t *Add_Bindtable (const char *, bttype_t); /* init.c */
const char *Bindtable_Name (bindtable_t *);
binding_t *Check_Bindtable (bindtable_t *, const char *, userflag, userflag, \
		binding_t *);
binding_t *Add_Binding (const char *, const char *, userflag, userflag, \
			Function, const char *);
void Delete_Binding (const char *, Function, const char *);
int RunBinding (binding_t *, const uchar *, char *, char *, int, char *);
int Lname_IsOn (const char *, const char *, const char **);
modeflag Inspect_Client (const char *, const char *, const char **, \
			 const char **, time_t *, short *);
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

#define ERROR(a...) dprint (0, ##a)
#define WARNING(a...) dprint (1, ##a)

#define DBG(a...) dprint (100, ##a)

/* ----------------------------------------------------------------------------
 * Common library functions and definitions
 */

int match (const char *, const char *);		/* lib.c */
int simple_match (const char *, const char *);
userflag strtouserflag (const char *, char **);
int Have_Wildcard (const char *);
char *NextWord (const char *);
char *NextWord_Unquoted (char *, const char *, size_t);	/* dst, src, size */
void StrTrim (char *);
void printl (char *, size_t, char *, size_t, char *, const char *, \
	     const char *, char *, uint32_t, unsigned short, int, const char *);
/* buf, size, fmt, linelen, nick, uhost, lname, chann, ip, port, idle, params */

//char *safe_strlower (char *, const char *, size_t);
size_t unistrlower (char *, const char *, size_t);
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

const char *expand_path (char *, const char *, size_t);

#define FOREVER while (1)
#define NONULL(x) x?x:""
#define FREE(x) safe_free((void **)x)

#define ISSPACE(c) isspace((uchar)c)

#define strfcpy(A,B,C) strncpy(A,B,C), *(A+(C)-1)=0

/* helper function for modules and UIs */
#define CheckVersion if (strncmp(VERSION,_VERSION,3)) return NULL

/* macro prototype for different structures allocation functions
   it takes three arguments:
   - first is typedef of structure
   - second is template XXX for integers XXXalloc, XXXnum, and XXXmax that
     will contain number of allocated, used and max used respectively
   - third is member of structure that may be used as link in chain
   macro creates integers mentioned above and two functions (NNN here is first
	argument of macro):
     NNN *alloc_NNN(void);
   and
     void free_NNN(NNN *); */

#define ALLOCSIZE 32

#define ALLOCATABLE_TYPE(type,tvar,next) \
static int tvar##alloc = 0, tvar##num = 0, tvar##max = 0; \
static type *Free##tvar = NULL; \
static type *alloc_##type (void) \
{ \
  type *cur; \
  if (!Free##tvar) \
  { \
    register int i = ALLOCSIZE; \
    Free##tvar = cur = malloc (ALLOCSIZE * sizeof(type)); \
    tvar##alloc += i; \
    while ((--i)) \
    { \
      cur->next = (void *)&cur[1]; \
      cur++; \
    } \
    cur->next = NULL; \
  } \
  cur = Free##tvar; \
  Free##tvar = (type *)cur->next; \
  tvar##num++; \
  if (tvar##num > tvar##max) \
    tvar##max = tvar##num; \
  return cur; \
} \
static void free_##type (type *cur) \
{ \
  cur->next = (void *)Free##tvar; \
  Free##tvar = cur; \
  tvar##num--; \
}

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
#ifndef HAVE_STRCASECMP
int strcasecmp (const char *, const char *);
int strncasecmp (const char *, const char *, size_t);
#endif

/* Sun's rwlocks may be implemented different ways... */
#ifndef HAVE_RWLOCK_INIT
# define USYNC_THREAD 0
# ifdef HAVE_PTHREAD_RWLOCK_INIT
#  define rwlock_t pthread_rwlock_t
#  define rwlock_init(a,b,c) pthread_rwlock_init(a,c)
#  define rw_rdlock pthread_rwlock_rdlock
#  define rw_tryrdlock pthread_rwlock_tryrdlock
#  define rw_wrlock pthread_rwlock_wrlock
#  define rw_trywrlock pthread_rwlock_trywrlock
#  define rw_unlock pthread_rwlock_unlock
#  define rwlock_destroy pthread_rwlock_destroy
# else /* substitude rwlock_init.c */
typedef struct rwlock_t rwlock_t;
int rwlock_init (rwlock_t *, int, void *);
int rw_rdlock (rwlock_t *);
int rw_tryrdlock (rwlock_t *);
int rw_wrlock (rwlock_t *);
int rw_trywrlock (rwlock_t *);
int rw_unlock (rwlock_t *);
int rwlock_destroy (rwlock_t *);
# endif
#endif
