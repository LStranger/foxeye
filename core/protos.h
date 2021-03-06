/*
 * Copyright (C) 1999-2020  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 *     You should have received a copy of the GNU General Public License along
 *     with this program; if not, write to the Free Software Foundation, Inc.,
 *     51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * This file is part of FoxEye's source: common declarations.
 */

#ifndef _PROTOS_H
#define _PROTOS_H 1

#define uchar unsigned char

/* ----------------------------------------------------------------------------
 * Common functions used by modules and submodules
 */

INTERFACE *Add_Iface (iftype_t, const char *, SigFunction,
		      int (*) (INTERFACE *, REQUEST *), void *);
INTERFACE *Find_Iface (iftype_t, const char *) __attribute__((warn_unused_result));
INTERFACE *Set_Iface (INTERFACE *);
int Unset_Iface (void);
int Rename_Iface (INTERFACE *, const char *);
void Mark_Iface (INTERFACE *);
void Add_Request (iftype_t, const char *, flag_t, const char *, ...)
	__attribute__((format(printf, 4, 5)));
void New_Request (INTERFACE *, flag_t, const char *, ...)
	__attribute__((format(printf, 3, 4)));
int Relay_Request (iftype_t, char *, REQUEST *);
int Get_Request (void);
struct bindtable_t *Add_Bindtable (const char *, bttype_t) /* init.c */
	__attribute__((warn_unused_result,nonnull(1)));
const char *Bindtable_Name (struct bindtable_t *)
	__attribute__((warn_unused_result,nonnull(1)));
struct binding_t *Check_Bindtable (struct bindtable_t *, const char *,
				   userflag, userflag, struct binding_t *)
	__attribute__((warn_unused_result));
struct binding_t *Add_Binding (const char *, const char *, userflag, userflag,
			       Function, const char *)
	__attribute__((nonnull(1)));
void Delete_Binding (const char *, Function, const char *);
int RunBinding (struct binding_t *, const uchar *, const char *, const char *,
		char *, int, const char *);
int Lname_IsOn (const char *, const char *, const char *, const char **)
	__attribute__((warn_unused_result));
modeflag Inspect_Client (const char *, const char *, const char *,
			 const char **, const char **, time_t *, short *)
	__attribute__((warn_unused_result));
int Update_Public (const char *, const char *, modeflag, const char *,
		   const char *, const char *, time_t);
int Add_Help (const char *) __attribute__((nonnull(1))); /* help.c */
void Delete_Help (const char *);
int Get_Help (const char *, const char *, INTERFACE *, userflag, userflag,
		struct bindtable_t *, const char *, int);
#ifdef ENABLE_NLS
int Get_Help_L (const char *, const char *, INTERFACE *, userflag, userflag,
		struct bindtable_t *, const char *, int, int, const char *);
#else
#define Get_Help_L(a,b,c,d,e,f,g,h,i,j) Get_Help(a,b,c,d,e,f,g,i)
#endif
int Add_Clientrecord (const char *, const uchar *, userflag) /* users.c */
	__attribute__((warn_unused_result));
int Add_Alias (const char *, const char *)
	__attribute__((warn_unused_result,nonnull(1)));
void Delete_Clientrecord (const char *);
int Change_Lname (const char *, const char *);

/* ----------------------------------------------------------------------------
 * Internal functions
 */

void dprint (int, const char *, ...)		/* dispatch.c */
	__attribute__ ((format(printf, 2, 3)));
void bot_shutdown (char *, int) __attribute__((noreturn));
int dispatcher (INTERFACE *);

#define ERROR(...) dprint (0, __VA_ARGS__)
#define WARNING(...) dprint (1, __VA_ARGS__)

#define DBG(...) dprint (100, __VA_ARGS__)

#define LOG_CONN(...) Add_Request (I_LOG, "*", F_CONN, __VA_ARGS__)

/* ----------------------------------------------------------------------------
 * Common library functions and definitions
 */

int match (const char *, const char *)		/* lib.c */
	__attribute__((warn_unused_result));
int simple_match (const char *, const char *)
	__attribute__((warn_unused_result));
int simple_match_ic (const char *, const char *)
	__attribute__((warn_unused_result));
userflag strtouserflag (const char *, char **)
	__attribute__((warn_unused_result));
int Have_Wildcard (const char *) __attribute__((warn_unused_result,nonnull(1)));
size_t printl (char *, size_t, const char *, size_t, char *, const char *, \
	       const char *, char *, uint32_t, unsigned short, int, const char *);
/* buf, size, fmt, linelen, nick, uhost, lname, chann, ip, port, idle, params */
unsigned short make_hash (const char *) __attribute__((warn_unused_result));

void foxeye_setlocale (void);
size_t unistrcut (const char *, size_t, int) __attribute__((nonnull(1)));
size_t unistrlower (char *, const char *, size_t);
size_t strfcpy (char *, const char *, size_t) __attribute__((nonnull(1, 2)));

void *safe_calloc (size_t, size_t) __attribute__((warn_unused_result));
void *safe_malloc (size_t) __attribute__((warn_unused_result));
void safe_realloc (void **, size_t);
void safe_pfree (void *);
void safe_free (void **);
#ifdef HAVE_INLINE
#if __GNUC__ >= 4
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-security" /* for F_SIGNAL "string" */
#endif
	__attribute__((nonnull(2)))
static inline void Send_Signal (iftype_t i, const char *m, ifsig_t s)
{
  Add_Request (i, m, F_SIGNAL, (char *)s);
}
#if __GNUC__ >= 4
#pragma GCC diagnostic pop
#endif
#else
char *safe_strdup (const char *) __attribute__((warn_unused_result));

int safe_strcmp (const char *, const char *) __attribute__((warn_unused_result));
int safe_strcasecmp (const char *, const char *) __attribute__((warn_unused_result));
int safe_strncmp (const char *, const char *, size_t) __attribute__((warn_unused_result));
int safe_strncasecmp (const char *, const char *, size_t) __attribute__((warn_unused_result));
char *safe_strchr (char *, int) __attribute__((warn_unused_result));
size_t safe_strlen (const char *) __attribute__((warn_unused_result));

const char *expand_path (char *, const char *, size_t)
	__attribute__((warn_unused_result));
char *strfcat (char *, const char *, size_t);
char *NextWord (char *) __attribute__((warn_unused_result));
char *NextWord_Unquoted (char *, char *, size_t)	/* dst, src, size */
	__attribute__((warn_unused_result));
char *gettoken (char *, char **)			/* ptr, nptr */
	__attribute__((warn_unused_result,nonnull(1)));
void StrTrim (char *);

#define Send_Signal(i,m,s) Add_Request (i, m, F_SIGNAL, (char *)s)
#endif /* not HAVE_INLINE */

#define FOREVER while (1)
#define NONULL(x) x?x:""
#define NONULLP(x) x?x:"(nil)"
#define FREE(x) safe_free((void **)x)

#define ISSPACE(c) isspace((uchar)c)

/* helper function for modules and UIs */
#define CheckVersion if (strncmp(VERSION,_VERSION,4)) return NULL

/* macro prototype for different structures allocation functions
   it takes three arguments:
   - first is typedef of structure
   - second is template XXX for integers XXXalloc, XXXnum, and XXXmax that
     will contain number of allocated, used and max used respectively
   - third is member of structure that may be used as link in chain
   macro creates integers mentioned above and three functions (NNN here is first
   argument of macro):
     NNN *alloc_NNN(void);
   and
     void free_NNN(NNN *);
   and
     void forget_NNN(void);
   to prevent memory leak always use the call shown below on module termination
   for each defined ALLOCATABLE_TYPE(NNN,...):
     _forget_(NNN); */

#define ALLOCSIZE 32

#define ALLOCATABLE_TYPE(type,tvar,next) \
static size_t tvar##asize = 0; \
static unsigned int tvar##num = 0, tvar##max = 0; \
struct ____##type { \
  struct ____##type *prv; \
  type a[ALLOCSIZE]; \
}; \
static struct ____##type *____L##type = NULL; \
static type *Free##tvar = NULL; \
	__attribute__((warn_unused_result)) \
static type *alloc_##type (void) \
{ \
  type *cur; \
  if (!Free##tvar) \
  { \
    register int i = ALLOCSIZE; \
    struct ____##type *_l = safe_malloc (sizeof(struct ____##type)); \
    _l->prv = ____L##type; \
    ____L##type = _l; \
    Free##tvar = cur = _l->a; \
    tvar##asize += sizeof(struct ____##type); \
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
  if (tvar##num >= tvar##max) \
    tvar##max = tvar##num + 1; \
  return cur; \
} \
static inline void free_##type (type *cur) \
{ \
  cur->next = (void *)Free##tvar; \
  Free##tvar = cur; \
  tvar##num--; \
} \
static inline void forget_##type (void) \
{ \
  struct ____##type *_l; \
  while ((_l = ____L##type)) \
  { \
    ____L##type = _l->prv; \
    FREE (&_l); \
  } \
}

#ifdef STATIC
# define _forget_(a)
#else
# define _forget_(a) forget_##a()
#endif

/* simple functions have to be either in lib.c
   or here if compiler supports inline directive */
#ifdef HAVE_INLINE
# include "inlines.h"
#endif

/* ----------------------------------------------------------------------------
 * Prototypes for broken systems
 */

#ifndef HAVE_RENAME
# define rename movefile
#endif

#ifndef HAVE_TOWLOWER
# define towlower tolower
#endif

/* HP-UX, ConvexOS and UNIXware don't have this macro */
#ifndef S_ISLNK
# define S_ISLNK(x) (((x) & S_IFMT) == S_IFLNK ? 1 : 0)
#endif

/* AIX doesn't define these in any headers (sigh) */
#ifndef HAVE_STRNCASECMP
extern int strcasecmp (const char *, const char *);
extern int strncasecmp (const char *, const char *, size_t);
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

#ifndef CLOCK_REALTIME
/* clock_gettime is not implemented on OS X */
#define CLOCK_REALTIME 0
static inline int clock_gettime(int clk_id, struct timespec* t)
{
    struct timeval now;
    int rv = gettimeofday(&now, NULL);
    if (rv) return rv;
    t->tv_sec  = now.tv_sec;
    t->tv_nsec = now.tv_usec * 1000;
    return 0;
}
#endif
#endif /* _PROTOS_H */
