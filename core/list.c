/*
 * Copyright (C) 1999-2014  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 * This file is part of FoxEye's source: all Listfile layer.
 */

#include "foxeye.h"

#include <fcntl.h>
#include <errno.h>

#include "list.h"
#include "wtmp.h"
#include "init.h"
#include "tree.h"
#include "direct.h"

typedef struct user_chr
{
  char *greeting;		/* greeting or ban comment */
  struct user_chr *next;
  time_t expire;
  userflag flag;
  lid_t cid;			/* channel index in list */
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

struct clrec_t
{
  char *lname;
  char *lclname;
  user_chr *channels;
  user_hr *host;
  char *passwd;			/* the "passwd" field */
  union				/* NULL by default */
  {
    char *info;			/* the "info" field or ban comment */
    struct clrec_t *owner;	/* owner of this alias */
  }u;
  char *charset;		/* the "charset" field - no default */
  char *login;			/* the ".login" field - "motd" by default */
  char *logout;			/* the ".logoff" field - NULL by default */
  user_fr *fields;
  time_t created;
  userflag flag;
  lid_t uid;
  unsigned progress : 1;	/* is 1 if updating */
  unsigned ignored : 1;
  pthread_mutex_t mutex;
};

static const struct clrec_t CONSOLEUSER = { NULL, NULL, NULL, NULL, NULL,
			{ NULL }, NULL, NULL, NULL, NULL, 0, -1, 0, 0, 0,
			PTHREAD_MUTEX_INITIALIZER };

static NODE *UTree = NULL;		/* list of USERRECORDs */
static struct clrec_t *UList[LID_MAX-LID_MIN+1];

static struct bindtable_t *BT_ChLname;

static time_t _savetime = 0;

#define LISTFILEMODIFIED _savetime = Time

static char _Userflags[] = USERFLAG;

/* for statistics: number of records and memory usage */
static size_t _R_r = 0, _R_s = 0, _R_d = 0, _R_i = 0; /* regular, services, bans, ignores */
static size_t _R_h = 0, _R_n = 0, _R_f =0; /* hosts, names, chans+fields */

/* ----------------------------------------------------------------------------
 * userflag <-> string conversions
 */

char *userflagtostr (userflag uf, char *flstr)
{
  register char *fl = _Userflags;
  register char *str = flstr;
  register userflag ufmask = 1;

  if (uf == (userflag)U_NONE)
    return strcpy (flstr, "-");
  if (uf & U_NEGATE)
    *str++ = '-';
  while (*fl)
  {
    if (uf & ufmask)
      *str++ = *fl;
    ufmask += ufmask;
    fl++;
  }
  *str = 0;
  return flstr;
}

userflag strtouserflag (register const char *ptr, char **endptr)
{
  register userflag uf;
  register char *ch;

  while (*ptr == ' ') ptr++;
  if (*ptr == '-')
  {
    uf = U_NEGATE;
    ptr++;
  }
  else
    uf = 0;
  for (; *ptr; ptr++)
    if ((ch = strchr (_Userflags, *ptr)))
      uf |= (userflag)1 << (ch-_Userflags);
    else
      break;
  if (endptr)
    *endptr = (char *)ptr;
  return uf;
}


/* ----------------------------------------------------------------------------
 * Async-unsafe functions. Lock only when to change. Part I: internal
 *  (assumed UserFileLock is locked)
 */

/*
 * mutexes: what					who may be locked
 * --------------------------------------------------	--------------------
 * UFlock: UList, UTree, ->progress,->lclname,->u.owner	-
 * built-in: all other except ->created and ->uid	UFLock(must)
 * Hlock: ->host					UFLock | built-in
 * Flock: Field, _Fnum, _Falloc				UFLock | built-in
 *
 * More about locks:
 * thread-safe functions have access read-only so above need locks on read;
 * thread-unsafe functions are more complex: they have access read-write
 * but on read they locked by dispatcher so above need locks on write only.
 * built-in locks cannot be rest between calls nor on enter any function
 *
 * Locks descriptions below are:
 *--- when lock --- must be locked prior --- must not be locked prior ---
 */

static rwlock_t UFLock;
static rwlock_t HLock;

static pthread_mutex_t FLock = PTHREAD_MUTEX_INITIALIZER;
static char **Field = NULL;		/* list of fields and channels */
static lid_t _Fnum = 0;
static lid_t _Falloc = 0;

#define strlena(x) (x ? (strlen(x)+1) : 0)

/*
 * Usersfile manipulation functions
 */

/*--- W --- HLock write ---*/
static int _addhost (user_hr **hr, const char *uh)
{
  size_t sz;
  user_hr *h = *hr;

  sz = safe_strlen (uh) + 1;
  if (sz < 6)		/* at least *!i@* :) */
    return 0;
  *hr = safe_malloc (sz + sizeof(user_hr) - sizeof(h->hostmask));
  _R_h += sz + sizeof(user_hr) - sizeof(h->hostmask);
  memcpy ((*hr)->hostmask, uh, sz);
  (*hr)->next = h;
  return 1;
}

/*--- W --- HLock write ---*/
static void _delhost (user_hr **hr)
{
  user_hr *h = *hr;

  *hr = h->next;
  _R_h -= safe_strlen (h->hostmask) + 1 + sizeof(user_hr) - sizeof(h->hostmask);
  FREE (&h);
}

/*--- RW --- UFLock read ---*/
static struct clrec_t *_findbylname (const char *lname)
{
  char lclname[IFNAMEMAX+1];

  unistrlower (lclname, lname, sizeof(lclname));
  return Find_Key (UTree, lclname);
}

/*--- R --- UFLock read --- no HLock ---*/
static struct clrec_t *_findthebest (const char *mask, struct clrec_t *prefer)
{
  struct clrec_t *u, *user = NULL;
  user_hr *hr;
  int n, p = 0, matched = 0;
  lid_t lid;
  char lcmask[HOSTMASKLEN+1];

  unistrlower (lcmask, mask, sizeof(lcmask));  
  rw_rdlock (&HLock);
  lid = LID_MIN;
  do {
    if ((u = UList[lid - LID_MIN]) && !(u->flag & (U_SPECIAL|U_ALIAS)))
    /* pseudo-users hosts are not masks */
      for (hr = u->host; hr; hr = hr->next)
      {
	n = match (hr->hostmask, lcmask);
	/* find max */
	if (n > matched)
	{
	  matched = n;
	  user = u;
	}
	/* find max for prefer */
	if (u == prefer && n > p)
	  p = n;
      }
  } while (lid++ != LID_MAX);
  rw_unlock (&HLock);
  if (p && p == matched)
    return prefer;
  return user;
}

/*--- W --- no HLock ---*/
static int _add_usermask (struct clrec_t *user, const char *mask)
{
  user_hr *hr;
  user_hr **h;
  int r;
  char lcmask[HOSTMASKLEN+1];

  if (user->uid > ID_ANY && strchr(user->lname, '.'))
    /* it's server name rather than user name */
    strfcpy (lcmask, mask, sizeof(lcmask));
  else
    unistrlower (lcmask, mask, sizeof(lcmask));
  /* check for aliases */
  if (user->flag & U_ALIAS)	/* no need lock since threads has R/O access */
    user = user->u.owner;
  rw_wrlock (&HLock);
  for (hr = user->host; hr; hr = hr->next)
  {
    if (match (hr->hostmask, lcmask) > 0)
    {
      rw_unlock (&HLock);
      return 0;			/* found mask is more common, nothing to do */
    }
  }
  /* check if any my masks are matched this and erase it */
  for (h = &user->host; *h; )
  {
    if (match (lcmask, (*h)->hostmask) > 0)	/* overwrite it */
      _delhost (h);
    else
      h = &(*h)->next;
  }
  r = _addhost (h, lcmask);
  rw_unlock (&HLock);
  LISTFILEMODIFIED;
  if (!user->progress)
    Add_Request (I_LOG, "*", F_USERS, _("Added hostmask %s for name %s."),
		 lcmask, user->lname);
  return r;
}

/*--- W --- no HLock ---*/
static int _del_usermask (struct clrec_t *user, const char *mask)
{
  user_hr **h;
  int i = 0;
  char lcmask[HOSTMASKLEN+1];

  if (user->uid > ID_ANY && strchr(user->lname, '.'))
    /* it's server name rather than user name */
    strfcpy (lcmask, mask, sizeof(lcmask));
  else
    unistrlower (lcmask, mask, sizeof(lcmask));  
  /* check for aliases */
  if (user->flag & U_ALIAS)
    user = user->u.owner;
  rw_wrlock (&HLock);
  /* check if any my masks are matched this and erase it */
  for (h = &user->host; *h; )
  {
    if (match (lcmask, (*h)->hostmask) > 0) /* overwrite less common mask */
    {
      _delhost (h);
      i++;
    }
    else
      h = &(*h)->next;
  }
  rw_unlock (&HLock);
  if (i != 0 && !user->progress)
    Add_Request (I_LOG, "*", F_USERS, _("Deleted hostmask %s from name %s."),
		 lcmask, user->lname);
  if (i)
    LISTFILEMODIFIED;
  return i;
}

#define R_NO		-1		/* no such field */
#define R_PASSWD	-2		/* "passwd" field */
#define R_INFO		-3
#define R_CHARSET	-4
#define R_LOGIN		-5
#define R_LOGOUT	-6
#define R_ALIAS		-7
#define R_CONSOLE	-8		/* console - "" */

#define FIELDSMAX	ID_ANY		/* last index for userfield */

static uint32_t LidsBitmap[LID_MAX/32-LID_MIN/32+1];

/*
 * create new lid with class or fixed id
 * returns new lid or 0 if no available
 */

/*--- W --- UFLock write ---*/
static lid_t __addlid (lid_t id, lid_t start, lid_t end)
{
  register int i, j, im, jm;

  i = (start-LID_MIN)/32;
  j = (start-LID_MIN)%32;
  if (id != ID_ANY);			/* fixed id */
  else if (start > end)			/* bans grows down */
  {
    while (j >= 0 && (LidsBitmap[i] & ((uint32_t)1<<j))) j--;
    im = (end-LID_MIN)/32;
    jm = (end-LID_MIN)%32;
    if (j < 0)
    {
      do i--; while (i >= im && ~(LidsBitmap[i]) == 0);
      if (i >= im)
      {
	j = 31;
	while (j >= 0 && (LidsBitmap[i] & ((uint32_t)1<<j))) j--;
      }
    }
    if (j < 0 || i < im || (i == im && j < jm))
      return ID_ME;
  }
  else					/* all other grows up */
  {
    while (j < 32 && (LidsBitmap[i] & ((uint32_t)1<<j))) j++;
    im = (end-LID_MIN)/32;
    jm = (end-LID_MIN)%32;
    if (j == 32)
    {
      do i++; while (i <= im && ~(LidsBitmap[i]) == 0);
      if (i <= im)
      {
	j = 0;
	while (j < 32 && (LidsBitmap[i] & ((uint32_t)1<<j))) j++;
      }
    }
    if (j == 32 || i > im || (i == im && j > jm))
      return ID_ME;
  }
  LidsBitmap[i] |= ((uint32_t)1<<j);
  dprint (5, "users:__addlid: %d %d %d --> %d:%d",
	  (int)id, (int)start, (int)end, i, j);
  return (i*32 + j + LID_MIN);
}

#define _add_lid(id,u) UList[id-LID_MIN] = u;

/*--- W --- UFLock write ---*/
static void __dellid (lid_t id)
{
  LidsBitmap[(id-LID_MIN)/32] &= ~((uint32_t)1<<((id-LID_MIN)%32));
  dprint (5, "users:__dellid: %d", (int)id);
}

/*--- W --- UFLock write ---*/
static void _del_lid (lid_t id, int old)
{
  __dellid (id);
  UList[id-LID_MIN] = NULL;
  if (id && old)			/* delete references to it from Wtmp */
    NewEvent (W_DEL, ID_ME, id, 0);
}

static int usernick_valid (const char *a)
{
  register int i = safe_strlen (a);
  register unsigned char s;

  if (i == 0 || i > LNAMELEN) return (-1);
  while (--i)
    if ((s = *a++) == '@' || s <= ' ' || s == ':' || s == ',')
      return (-1);
  return 0;
}

static int spname_valid (const char *a)
{
  register int t, i = safe_strlen (a);
  register unsigned char s;

  if (i == 0 || i > IFNAMEMAX) return (-1);
  t = 0;
  while (--i)
    if ((s = *a++) == '@')
      t++;
    else if (s <= ' ' || s == ':' || s == ',')
      return (-1);
  return t;
}

/*--- W --- UFLock write ---*/
static struct clrec_t *_add_userrecord (const char *name, userflag uf, lid_t id)
{
  struct clrec_t *user = NULL;
  int i;

  DBG ("_add_userrecord/%c(%#x):%s:%hd",
       (uf & U_SPECIAL) ? 'S' : (id > ID_ME && id < ID_ANY) ? 'I' : 'N',
       uf, NONULL(name), id);
  if (name && _findbylname (name))	/* already exists */
    i = -1;
  else if (uf & U_SPECIAL)		/* special and composite names */
    i = spname_valid (name);
  else if (name)			/* normal names */
    i = usernick_valid (name);
  else					/* bans and other nonamed */
    i = 0;
  if (i == 1 && name[0] == '@')		/* illegal special name */
    return NULL;
  else if (i >= 0)
  {
    user = safe_calloc (1, sizeof(struct clrec_t));
    /* set fields */
    user->lname = safe_strdup (name);
    i = safe_strlen (name);
    user->lclname = safe_malloc (i+1);	/* never NULL */
    unistrlower (user->lclname, name, i+1);
    if (i)
      i += i + 2;
    else
      i = 1;
    user->flag = uf;
    if (!(uf & U_SPECIAL))
      user->flag |= U_ANY;
    if (id != ID_ANY)			/* specified id */
      user->uid = __addlid (id, id, id);
    else if (name)			/* regular/special user */
      user->uid = __addlid (id, ID_ANY+1, LID_MAX);
    else if (uf & U_IGNORED)		/* unnamed ignore */
      user->uid = __addlid (id, ID_ME+1, ID_ANY-1);
    else				/* ban/except/invite/deop */
      user->uid = __addlid (id, ID_REM-1, LID_MIN);
    if (id == ID_ME || user->uid != ID_ME)
    {
      if (name && Insert_Key (&UTree, user->lclname, user, 1) < 0)
        i = -1;
      _add_lid (user->uid, user);
    }
    else
      i = -1;
  }
  if (i < 0)
  {
    if (user)
    {
      _del_lid (user->uid, 0);
      FREE (&user->lname);
      FREE (&user->lclname);
      FREE (&user);
    }
    return NULL;
  }
  pthread_mutex_init (&user->mutex, NULL);
  if (id < ID_REM)
    _R_d++;
  else if (!name)
    _R_i++;
  else if (uf & U_SPECIAL)
    _R_s++;
  else
    _R_r++;
  _R_n += i;
  LISTFILEMODIFIED;
  return user;
}

/*--- W --- no locks ---*/
static void _new_lname_bindings (const char *oldname, const char *newname)
{
  struct binding_t *bind = NULL;
  while ((bind = Check_Bindtable (BT_ChLname, oldname, U_ALL, U_ANYCH, bind)))
  {
    if (bind->name)
      RunBinding (bind, NULL, oldname, newname, NULL, -1, NULL);
    else
      bind->func (newname, oldname);
  }
}

static void _del_aliases (struct clrec_t *);

/*--- W --- UFLock write --- no other locks ---*/
static void _delete_userrecord (struct clrec_t *user, int to_unlock)
{
  user_chr *chr;
  user_fr *f;
  size_t _f;

  if (!user)
  {
    if (to_unlock) rw_unlock (&UFLock);
    return;
  }
  if (!(user->flag & U_ALIAS))		/* nobody will modify this record now */
    _del_aliases (user);		/* so let's rock! delete aliases... */
  pthread_mutex_lock (&user->mutex);	/* just wait for release */
  if (!(user->flag & U_ALIAS))
    _del_lid (user->uid, 1);
  Delete_Key (UTree, user->lclname, user); /* delete from hash */
  pthread_mutex_unlock (&user->mutex);	/* it's unavailable now */
  pthread_mutex_destroy (&user->mutex);
  _f = safe_strlen (user->lname);
  _R_n -= 2 * _f + 1 + (_f ? 1 : 0);
  if (user->uid < ID_REM)
    _R_d--;
  else if (!user->lname)
    _R_i--;
  else if (user->flag & U_SPECIAL)
    _R_s--;
  else
    _R_r--;
  rw_unlock (&UFLock);
  if (!(user->flag & U_ALIAS) && user->lname)
    _new_lname_bindings (user->lname, NULL);
  if (!to_unlock)			/* no locks need now */
    rw_wrlock (&UFLock);
  while (user->host)
    _delhost (&user->host);
  user->progress = 0;
  _f = 0;
  for (chr = user->channels; chr; )
  {
    _f += strlena (chr->greeting) + sizeof(user_chr);
    FREE (&chr->greeting);
    user->channels = chr->next;
    FREE (&chr);
    chr = user->channels;
  }
  _f += strlena (user->passwd) + strlena (user->charset) +
	strlena (user->login) + strlena (user->logout);
  FREE (&user->lname);
  FREE (&user->lclname);
  FREE (&user->passwd);
  FREE (&user->charset);
  FREE (&user->login);
  FREE (&user->logout);
  if (!(user->flag & U_ALIAS))
  {
    _f += strlena (user->u.info);
    FREE (&user->u.info);
  }
  while ((f = user->fields))
  {
    _f += strlena (f->value) + sizeof(user_fr);
    FREE (&f->value);
    user->fields = f->next;
    FREE (&f);
  }
  pthread_mutex_lock (&FLock);
  _R_f -= _f;
  pthread_mutex_unlock (&FLock);
  FREE (&user);
  LISTFILEMODIFIED;
}

/*--- W --- UFLock write ---*/
static void _add_aliases (struct clrec_t *owner, char *list)
{
  char n[LNAMELEN+1];
  struct clrec_t *ur;

  while (*list)
  {
    list = NextWord_Unquoted (n, list, sizeof(n));
    if (_findbylname (n))
      continue;
    ur = _add_userrecord (n, U_ALIAS, owner->uid);
    ur->created = Time;
    ur->u.owner = owner;
  }
}

/*--- W --- UFLock write --- no other locks ---*/
static void _del_aliases (struct clrec_t *owner)
{
  register struct clrec_t *ur;
  lid_t lid;

  lid = LID_MIN;
  do {
    if ((ur = UList[lid - LID_MIN]) && (ur->flag & U_ALIAS) &&
	ur->u.owner == owner)
      _delete_userrecord (ur, 0);
  } while (lid++ != LID_MAX);
}

/* ----------------------------------------------------------------------------
 * Async-unsafe functions. Part II: public
 */

/*--- W --- no locks ---*/
int Add_Clientrecord (const char *name, const uchar *mask, userflag uf)
{
  struct clrec_t *user = NULL;
  char flags[64];			/* I hope, it enough for 18 flags :) */

  /* we cannot add alias with this! */
  if (uf & U_ALIAS)
    return 0;
  /* create the structure */
  if (name && !name[0])
    name = NULL;
  if (!name && match ("*@*", mask) < 0)
  {
    ERROR ("Add_Clientrecord: invalid hostmask pattern %s ignored.",
	   NONULLP((char *)mask));
    mask = NULL;
  }
  if (!name && !mask)		/* empty name has to have valid mask */
    return 0;
  rw_wrlock (&UFLock);
  user = _add_userrecord (name, uf, ID_ANY); /* client/ban */
  if (!user)
  {
    rw_unlock (&UFLock);
    return 0;
  }
  user->created = Time;
  if (mask)			/* don't lock it, it's unreachable yet */
    _add_usermask (user, mask);
  rw_unlock (&UFLock);
  if (uf)
    Add_Request (I_LOG, "*", mask ? (F_USERS | F_AHEAD) : F_USERS,
		 _("Added name %s with flag(s) %s."),
		 NONULLP(name), userflagtostr (uf, flags));
  else
    Add_Request (I_LOG, "*", mask ? (F_USERS | F_AHEAD) : F_USERS,
		 _("Added name %s."), NONULLP(name));
  /* all OK */
  return 1;
}

/*--- W --- no locks ---*/
int Add_Alias (const char *name, const char *hname)
{
  register struct clrec_t *user = NULL, *owner;

  /* create the structure */
  rw_wrlock (&UFLock);
  if ((owner = _findbylname (hname)))
    user = _add_userrecord (name, U_ALIAS, owner->uid);
  if (!user)
  {
    rw_unlock (&UFLock);
    return 0;
  }
  user->created = Time;
  user->u.owner = owner;
  rw_unlock (&UFLock);
  Add_Request (I_LOG, "*", F_USERS, _("Added alias %s for %s."), name, hname);
  /* all OK */
  return 1;
}

/*--- W --- no locks ---*/
void Delete_Clientrecord (const char *lname)
{
  struct clrec_t *user;

  if (!lname)
    return;
  rw_wrlock (&UFLock);
  if (!(user = _findbylname (lname)))
  {
    rw_unlock (&UFLock);
    return;
  }
  _delete_userrecord (user, 1);
  Add_Request (I_LOG, "*", F_USERS, _("Deleted name %s."), lname);
  /* notify interfaces about deleting the name */
  Send_Signal (I_DIRECT | I_SERVICE, lname, S_FLUSH);
}

/*--- W --- no locks ---*/
int Change_Lname (const char *newname, const char *oldname)
{
  struct clrec_t *user;
  int i;
  INTERFACE *iface;

  /* check if oldname exist */
  rw_wrlock (&UFLock);
  user = _findbylname (oldname);
  /* check if newname is valid */
  if (!user || (user->flag & U_SPECIAL) ||
      usernick_valid (newname) < 0 || _findbylname (newname))
  {
    rw_unlock (&UFLock);
    WARNING ("list.c:Change_Lname: cannot do %s => %s.", NONULLP(oldname),
	     NONULLP(newname));
    return 0;
  }
  /* rename user record */
  Delete_Key (UTree, user->lclname, user);
  _R_n -= 2 * safe_strlen (user->lname);
  FREE (&user->lclname);
  pthread_mutex_lock (&user->mutex);
  FREE (&user->lname);
  user->lname = safe_strdup (newname);
  pthread_mutex_unlock (&user->mutex);
  i = safe_strlen (newname);
  user->lclname = safe_malloc (i+1);
  unistrlower (user->lclname, newname, i+1);
  i = Insert_Key (&UTree, user->lclname, user, 1);
  _R_n += 2 * i;
  rw_unlock (&UFLock);
  if (i < 0)
    ERROR ("change Lname %s -> %s: hash error, Lname lost!", oldname, newname);
  LISTFILEMODIFIED;
  /* rename the DCC CHAT interface if exist */
  if ((iface = Find_Iface (I_DIRECT, oldname)))
  {
    Rename_Iface (iface, newname);
    Unset_Iface();
  }
  dprint (2, "changing Lname: %s -> %s", oldname, newname);
  /* run "new-lname" bindtable */
  _new_lname_bindings (oldname, newname);
  return 1;
}

/*--- R --- no locks ---*/
lid_t FindLID (const char *lname)
{
  struct clrec_t *user;
  register lid_t id;

  if (!lname || !*lname)			/* own lid */
    return ID_ME;
  rw_rdlock (&UFLock);
  user = _findbylname (lname);
  if (user)
    id = user->uid;
  else
    id = ID_REM;
  rw_unlock (&UFLock);
  dprint (5, "users:FindLID: %s -> %d", lname, (int)id);
  return id;
}

/*--- R --- no locks ---*/
lid_t Get_LID (struct clrec_t *user)
{
  return user->uid;
}

static int _add_to_list (INTERFACE *iface, char *buf, size_t *len, char *msg)
{
  int n = 0;
  size_t l = strlen(msg);

  dprint (5, "_add_to_list: %s", msg);
  if (*len + l > MESSAGEMAX-2)	/* reserved for ' ' and '\0' */
  {
    n++;
    New_Request (iface, 0, "%s", buf);
    *len = 0;
  }
  if (*len)
    buf[(*len)++] = ' ';
  memcpy (&buf[*len], msg, l+1);
  (*len) += l;
  return n;
}

static int _add_to_list2 (INTERFACE *iface, char *buf, size_t *len, char *msg)
{
  int n = 0;
  size_t l = strlen(msg);

  dprint (5, "_add_to_list: @%s", msg);
  if (*len + l > MESSAGEMAX-3)	/* reserved for ' ', '@', and '\0' */
  {
    n++;
    New_Request (iface, 0, "%s", buf);
    *len = 0;
  }
  if (*len)
    buf[(*len)++] = ' ';
  buf[(*len)++] = '@';
  memcpy (&buf[*len], msg, l+1);
  (*len) += l;
  return n;
}

/*--- W --- no locks ---*/
int Get_Clientlist (INTERFACE *iface, userflag uf, const char *fn,
		    const char *mask)
{
  char buf[MESSAGEMAX];
  size_t len;
  lid_t lid;
  struct clrec_t *u;
  user_hr *h;
  int n, canbenonamed;
  char *fnisservice;
  userflag gf;
  char lcmask[HOSTMASKLEN+1];

  if (!mask || !*mask || !uf || !iface)
    return 0;
  canbenonamed = uf & (U_DENY | U_ACCESS | U_INVITE | U_IGNORED);
  fnisservice = safe_strchr ((char *)fn, '@');	/* isn't NULL if service name */
  gf = uf & U_GLOBALS;
  unistrlower (lcmask, mask, sizeof(lcmask));  
  n = 0;
  len = 0;
  lid = LID_MIN;
  do {
    if ((u = UList[lid - LID_MIN]) && ((u->flag & gf) || /* has global flags */
	(fnisservice && (Get_Flags (u, &fn[1]) & uf)))) /* or service flags */
    {
      if (canbenonamed ||		/* if it's check for ban/invite/etc. */
	  fn == NULL)			/* NULL means check lname and host */
      {
	if (match (lcmask, u->lclname) >= 0)	/* Lname matched to it */
	  n += _add_to_list (iface, buf, &len, u->lname);
	else for (h = u->host; h; h = h->next)
	  if (match (lcmask, h->hostmask) > 0)	/* hostmask matched to it */
	  {
	    n += _add_to_list (iface, buf, &len, /* return lname or hostmask */
			       u->lname ? u->lname : h->hostmask);
	    break;
	  }
      }
      else if (u->lname)		/* field granted and has lname */
      {
	if (match (lcmask, Get_Field (u, fn, NULL)) >= 0)
	  n += _add_to_list (iface, buf, &len, u->lname);
      }
    }
  } while (lid++ != LID_MAX);
  if (len)
  {
    New_Request (iface, 0, "%s", buf);
    n++;
  }
  return n;
}

/*--- W --- no locks ---*/
int Get_Hostlist (INTERFACE *iface, lid_t id)
{
  char buf[MESSAGEMAX];
  size_t len;
  struct clrec_t *u;
  user_hr *h;
  int n = 0;

  dprint (5, "Get_Hostlist: check for %hd", id);
  if (!(u = UList[id-LID_MIN]))	/* no need write lock here, func is read only */
    return 0;
  if (u->flag & U_ALIAS)	/* unaliasing */
    u = u->u.owner;
  for (len = 0, h = u->host; h; h = h->next)
    n += _add_to_list (iface, buf, &len, h->hostmask);
  if (len)
  {
    New_Request (iface, 0, "%s", buf);
    n++;
  }
  return n;
}

/*--- W --- no locks ---*/
int Get_Fieldlist (INTERFACE *iface, lid_t id)
{
  char buf[MESSAGEMAX];
  size_t len;
  struct clrec_t *u;
  int n = 0;
  user_chr *chr;
  user_fr *fr;

  dprint (5, "Get_Fieldlist: check for %hd", id);
  if (!(u = UList[id-LID_MIN]))	/* no need write lock here, func is read only */
    return 0;
  if (u->flag & U_ALIAS)	/* unaliasing */
    u = u->u.owner;
  /* send services first */
  for (chr = u->channels; chr; chr = chr->next)
    if (chr->cid == R_CONSOLE)
      continue;
    else if (chr->cid < ID_ANY || !UList[chr->cid-LID_MIN] ||
	     !(UList[chr->cid-LID_MIN]->flag & U_SPECIAL))
    {
      ERROR ("list.c:Get_Fieldlist:invalid subrecord on id %hd:[%p]id=%hd",
	     id, chr, chr->cid);	/* how it can be so wrong? */
      continue;
    }
    else if (strchr (UList[chr->cid-LID_MIN]->lname, '@'))
      n += _add_to_list (iface, buf, &len, UList[chr->cid-LID_MIN]->lname);
    else
      n += _add_to_list2 (iface, buf, &len, UList[chr->cid-LID_MIN]->lname);
  /* and now named fields too */
  for (fr = u->fields; fr; fr = fr->next)
    if (fr->id < 0 || fr->id >= _Fnum)
    {
      ERROR ("list.c:Get_Fieldlist:invalid field on id %hd:[%p]id=%hd",
	     id, fr, fr->id);		/* how it can be so wrong? */
      continue;
    }
    else
      n += _add_to_list (iface, buf, &len, Field[fr->id]);
  if (len)
  {
    New_Request (iface, 0, "%s", buf);
    n++;
  }
  return n;
}

/*--- W --- no locks ---*/
unsigned short Get_Hosthash (const char *lname, const char *host)
{
  struct clrec_t *u;
  user_hr *h;
  char lchost[HOSTMASKLEN+1];

  if (!host || !*host || !lname)
    return 0;
  unistrlower (lchost, host, sizeof(lchost));  
  u = _findbylname (lname);
  if (u)
    for (h = u->host; h; h = h->next)
      if (match (h->hostmask, lchost) > 0) /* host matched to it */
	return make_hash (h->hostmask);
  return 0;				/* it doesn't found */
}


/* ----------------------------------------------------------------------------
 * Thread-safe functions.
 */

/*--- RW --- UFLock read --- no FLock ---*/
static lid_t _get_index_sp (const char *field)
{
  struct clrec_t *ur = _findbylname (field);

    if (!*field)
      return R_CONSOLE;
    if (ur && !ur->progress && (ur->flag & U_SPECIAL)) /* it might wait updating */
      return ur->uid;
    else
      return R_NO;
}

static lid_t _get_index_fr (const char *field)
{
  lid_t i;

    if (!strcasecmp (field, "passwd"))
      return R_PASSWD;
    if (!strcasecmp (field, "info"))
      return R_INFO;
    if (!strcasecmp (field, "charset"))
      return R_CHARSET;
    if (!strcasecmp (field, ".login"))
      return R_LOGIN;
    if (!strcasecmp (field, ".logout"))
      return R_LOGOUT;
    if (!strcasecmp (field, "alias"))
      return R_ALIAS;
    i = 0;
    pthread_mutex_lock (&FLock);
    if (Field) FOREVER
    {
      if (!safe_strcasecmp (field, Field[i]))
	break;
      i++;
      if (i == _Fnum)
      {
	i = R_NO;
	break;
      }
    }
    else
      i = R_NO;
    pthread_mutex_unlock (&FLock);
    return i;
}

/*--- R --- no locks ---*/
/* returns UFLock locked if found */
struct clrec_t *Find_Clientrecord (const uchar *mask, const char **lname,
				   userflag *uf, const char *net)
{
  struct clrec_t *user = NULL;
  int cancelstate;

  if (!mask || !*mask)
    return NULL;
  /* find the userrecord */
  pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancelstate);
  rw_rdlock (&UFLock);
  user = _findthebest (mask, NULL);
  if (user)
  {
    pthread_mutex_lock (&user->mutex);
    if (lname)
      *lname = user->lname;
    if (uf)
    {
      if (net != NULL)
      {
	register user_chr *c;
	register lid_t i = _get_index_sp (net);

	for (c = user->channels; c; c = c->next)
	  if (c->cid == i)
	    break;
	*uf = (user->flag & U_GLOBALS) | (c ? c->flag : 0);
      }
      else
	*uf = user->flag;
    }
    DBG("list.c:Find_Clientrecord: locked %s", user->lname);
  }
  else
    rw_unlock (&UFLock);
  pthread_setcancelstate(cancelstate, NULL);
  return user;
}

/*--- RW --- no locks ---*/
/* returns UFLock locked if found */
struct clrec_t *Lock_Clientrecord (const char *name)
{
  struct clrec_t *user;
  int err;

  rw_rdlock (&UFLock);
  user = _findbylname (name);
  if (user)
  {
    if (user->flag & U_ALIAS)
      user = user->u.owner;
    err = pthread_mutex_trylock (&user->mutex);
    if (err) {
      rw_unlock (&UFLock);
      user = NULL;
      /* pthread_mutex_trylock should not return unknown error
         so strerror is safe */
      ERROR("list.c:Lock_Clientrecord: cannot lock %s: %s", name, strerror(err));
    } else
      DBG("list.c:Lock_Clientrecord: locked %s", name);
    return user;
  }
  rw_unlock (&UFLock);
  return user;
}

/*--- RW --- no locks ---*/
/* returns UFLock locked if found */
struct clrec_t *Lock_byLID (lid_t id)
{
  struct clrec_t *user;
  int err;

  rw_rdlock (&UFLock);
  if ((user = UList[id-LID_MIN]))
  {
    if (user->flag & U_ALIAS)
      user = user->u.owner;
    err = pthread_mutex_trylock (&user->mutex);
    if (err) {
      rw_unlock (&UFLock);
      user = NULL;
      /* pthread_mutex_trylock should not return unknown error
         so strerror is safe */
      ERROR("list.c:Lock_byLID: cannot lock id %hu: %s", id, strerror(err));
    } else
      DBG("list.c:Lock_byLID: locked %hu", id);
    return user;
  }
  rw_unlock (&UFLock);
  return user;
}

/*--- RW --- UFLock read and built-in --- no other locks ---*/
void Unlock_Clientrecord (struct clrec_t *user)
{
  int err;

  if (!user)
    return;
  DBG("list.c:Unlock_Clientrecord: unlocking \"%s\"", NONULL(user->lname));
  err = pthread_mutex_unlock (&user->mutex);
  rw_unlock (&UFLock);
  if (err)
    ERROR("list.c:Unlock_Clientrecord: cannot unlock: %s", strerror(err));
}

/*--- R --- UFLock read and built-in --- no other locks ---*/
char *Get_Field (struct clrec_t *user, const char *field, time_t *ctime)
{
  lid_t i;
  user_fr *f;
  user_chr *c;
  register char *fn;

  if (field == NULL)
  {
    if (ctime)
      *ctime = user->created;
    return user->lname;
  }
  if ((fn = strrchr (field, '@')) || !*field)	/* try service first */
  {
    if (*field && fn == field)
      i = _get_index_sp (&field[1]);
    else
      i = _get_index_sp (field);
    for (c = user->channels; c; c = c->next)
      if (c->cid == i)
      {
	if (ctime)
	  *ctime = c->expire;
	DBG ("Get_Field:%s:%s[%d]=%s", NONULLP(user->lname), field, (int)i,
	     NONULL(c->greeting));
	return (c->greeting);
      }
    return NULL;
  }
  i = _get_index_fr (field);			/* OOPS!!! unlocked access!!! */
  switch (i)
  {
    case R_NO:
      break;
    case R_PASSWD:
      return user->passwd;
    case R_INFO:
      return user->u.info;
    case R_CHARSET:
      return user->charset;
    case R_LOGIN:
      return user->login;
    case R_LOGOUT:
      return user->logout;
    default:
      for (f = user->fields; f; f = f->next)
	if (f->id == i)
	  return (f->value);
  }
  return NULL;
}

/*--- W --- built-in --- no FLock ---*/
static inline user_chr **_add_channel (user_chr **chr, lid_t i)
{
  register user_chr *c = safe_calloc (1, sizeof(user_chr));

  while (*chr) chr = &(*chr)->next;
  pthread_mutex_lock (&FLock);
  _R_f += sizeof(user_chr);
  pthread_mutex_unlock (&FLock);
  *chr = c;
  c->cid = i;
  return chr;
}

/*--- W --- built-in --- no FLock ---*/
static inline void _del_channel (user_chr **chr, user_chr *c)
{
  while (*chr && *chr != c) chr = &(*chr)->next;
  /* don't do diagnostics here, it should be impossible */
  *chr = c->next;
  pthread_mutex_lock (&FLock);
  _R_f -= strlena (c->greeting) + sizeof(user_chr);
  pthread_mutex_unlock (&FLock);
  FREE (&c->greeting);
  FREE (&c);
}

/*
 * note: call of Set_Field (user, "alias", something, time);
 * will do not change Listfile (delete old & add new aliases)
 * so you must do it yourself
 */
/*--- W --- UFLock read and built-in --- no other locks ---*/
int Set_Field (struct clrec_t *user, const char *field, const char *val,
	       time_t exp)
{
  lid_t i;
  user_fr *f;
  user_chr *chr;
  char **c;
  register char *fn;

  /* we cannot modify Lname with this! */
  if (field == NULL)
    return 0;
  DBG ("Set_Field: %s=%s (%lu)", field, NONULL(val), (unsigned long)exp);
  c = NULL;
  if ((fn = strrchr (field, '@')) || !*field)	/* try service first */
  {
    if (*field && fn == field)			/* special name */
      i = _get_index_sp (&field[1]);
    else					/* composite name */
      i = _get_index_sp (field);
    if (i == R_NO)				/* unknown service */
    {
      /* Set_Field() should be called when dispatcher is locked so OK to send */
      ERROR ("Service \"%s\" not found, field value lost.", field);
      return 0;
    }
    for (chr = user->channels; chr; chr = chr->next)
      if (chr->cid == i)
	break;
    if (!user->progress && !val && chr && !chr->flag)
    {
      _del_channel (&user->channels, chr); /* delete empty channel record */
      LISTFILEMODIFIED;		/* cannot use mutex but value isn't critical */
      return 1;
    }
    if (!chr && val)
      chr = *(_add_channel (&user->channels, i));
    if (chr)
      c = &chr->greeting;
    if (exp && chr)			/* set it now, it valid only for chr */
      chr->expire = exp;
    DBG ("Set_Field: added channel: %p, head=%p", chr, user->channels);
  }
  else switch ((i = _get_index_fr (field)))	/* it's not service */
  {
    case R_PASSWD:
      c = &user->passwd;
      break;
    case R_INFO:
      c = &user->u.info;
      break;
    case R_CHARSET:
      c = &user->charset;
      break;
    case R_LOGIN:
      c = &user->login;
      break;
    case R_LOGOUT:
      c = &user->logout;
      break;
    case R_NO:
      break;
    default:
      for (f = user->fields; f; f = f->next)
	if (f->id == i)
	  break;
      if (f)
      {
	if (!val || !*val)		/* delete the field record */
	{
	  user_fr *ff = user->fields;

	  if (ff != f) for (; ff; ff = ff->next)
	    if (ff->next == f)
	      break;
	  if (ff == f)
	    user->fields = f->next;
	  else
	    ff->next = f->next;
	  pthread_mutex_lock (&FLock);
	  _R_f -= strlena (f->value) + sizeof(user_fr);
	  pthread_mutex_unlock (&FLock);
	  FREE (&f->value);
	  FREE (&f);
	  LISTFILEMODIFIED;
	  return 1;
	}
	c = &f->value;
      }
  }
  if (!c && val)			/* create new field */
  {
    pthread_mutex_lock (&FLock);
    /* add to list if it's unknown yet and does not contain forbidden chars */
    if (i == R_NO && _Fnum < FIELDSMAX && !strpbrk (field, " @:"))
    {
      if (_Fnum == _Falloc)
      {
	_Falloc += 16;
	safe_realloc ((void **)&Field, (_Falloc) * (sizeof(char *)));
	_R_f += 16 * sizeof(char *);
      }
      Field[_Fnum] = safe_strdup (field);
      /* Set_Field() should be called when dispatcher is locked so OK to send */
      dprint (2, "list.c:Set_Field: added \"%s\" to list of known fields.",
	      field);
      _R_f += strlena (field);
      i = _Fnum++;
    }
    pthread_mutex_unlock (&FLock);
    if (i == R_NO)
      /* Set_Field() should be called when dispatcher is locked so OK to send */
      ERROR ("Fields index exceeded, field \"%s\" value lost.", field);
    else
    {
      f = user->fields;
      if (f)
      {
	while (f->next) f = f->next;
	f->next = safe_calloc (1, sizeof(user_fr));
	pthread_mutex_lock (&FLock);
	_R_f += sizeof(user_fr);
	pthread_mutex_unlock (&FLock);
	f->next->id = i;
	c = &f->next->value;
      }
      else
      {
	f = user->fields = safe_calloc (1, sizeof(user_fr));
	pthread_mutex_lock (&FLock);
	_R_f += sizeof(user_fr);
	pthread_mutex_unlock (&FLock);
	f->id = i;
	c = &f->value;
      }
    }
  }
  if (!c)
    return 0;
  if (val && !*val) val = NULL;	/* sanity */
  pthread_mutex_lock (&FLock);
  _R_f += strlena (val) - strlena (*c);
  pthread_mutex_unlock (&FLock);
  FREE (c);
  *c = safe_strdup (val);
  if (i < 0 && *c)		/* eliminate any ':' if it's a main field */
  {
    register char *cc = *c;

    while (*cc)
      if (*cc == ':') *cc++ = ';';
      else cc++;
  }
  LISTFILEMODIFIED;		/* cannot use mutex but value isn't critical */
  return 1;
}

/*
 * almost the same as Set_Field() but adds value to existing field
 */
/*--- W --- UFLock and built-in --- no other locks ---*/
int Grow_Field (struct clrec_t *user, const char *field, const char *val)
{
  char result[LONG_STRING];
  char *f;

  /* we cannot modify Lname with this! */
  if (field == NULL)
    return 0;
  f = Get_Field (user, field, NULL);
  if (f == NULL)
    return Set_Field (user, field, val, 0);
  if (safe_strlen (f) + safe_strlen (val) + 2 > sizeof(result))
    return 0;
  strcpy (result, f);
  strfcat (result, " ", sizeof(result));
  strfcat (result, val, sizeof(result));
  return Set_Field (user, field, result, 0);
}

/*--- R --- no locks ---*/
userflag Match_Client (const char *domain, const char *ident, const char *lname)
{
  userflag uf = 0;
  struct clrec_t *ur = NULL;
  user_hr *hr;
  int cancelstate;
  char uhost[STRING];
  char c = '@';
  register size_t ptr = 0;

  if (!domain || !*domain)		/* empty domain is nonsence! :) */
    return uf;
  if (ident && *ident)			/* prepare the hostmask */
  {
    c = '!';
    uhost[0] = c;
    ptr = unistrlower (&uhost[1], ident, IDENTLEN + 1) + 1;
  }
  uhost[ptr++] = '@';
  unistrlower (&uhost[ptr], domain, sizeof(uhost) - ptr);
  pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancelstate);
  rw_rdlock (&UFLock);
  rw_rdlock (&HLock);
  if (lname)				/* check only this user */
  {
    if ((ur = _findbylname (lname)))
    {
      if (ur->flag & U_ALIAS)	/* unaliasing, don't lock since it's binary */
	ur = ur->u.owner;
      for (hr = ur->host; hr && !uf; hr = hr->next)
	if (match (safe_strchr (hr->hostmask, c), uhost) > 0)
	{
	  pthread_mutex_lock (&ur->mutex);
	  uf = ur->flag;
	  pthread_mutex_unlock (&ur->mutex);
	}
    }
  }
  else					/* check whole userfile */
  {
    lid_t lid;

    lid = LID_MIN;
    do {
      if ((ur = UList[lid - LID_MIN]))
	for (hr = ur->host; hr; hr = hr->next)
	  if (match (safe_strchr (hr->hostmask, c), uhost) > 0)
	  {
	    pthread_mutex_lock (&ur->mutex);
	    uf |= ur->flag;
	    pthread_mutex_unlock (&ur->mutex);
	  }
    } while (lid++ != LID_MAX);
  }
  rw_unlock (&HLock);
  rw_unlock (&UFLock);
  pthread_setcancelstate(cancelstate, NULL);
  dprint (4, "users:Match_User: %s!%s@%s%s, found flags %#x", NONULL(lname),
	  NONULL(ident), domain, ur ? " (records found)" : "", uf);
  return uf;
}

/*--- R --- UFLock and built-in --- no other locks ---*/
userflag Get_Flags (struct clrec_t *user, const char *serv)
{
  userflag uf;
  register lid_t i;
  register user_chr *c;

  if (!user)
    return 0;
  if (!serv)				/* return only global ones */
    return (user->flag & U_GLOBALS);
  else if (!*serv)			/* return global+direct service */
    return user->flag;
  i = _get_index_sp (serv);
  c = user->channels;
  for (; c; c = c->next)
    if (c->cid == i)
      break;
  if (c)
    uf = c->flag;
  else
    uf = 0;
  return uf;
}

/*--- W --- UFLock and built-in --- no other locks ---*/
userflag Set_Flags (struct clrec_t *user, const char *serv, userflag uf)
{
  lid_t i;
  user_chr *chr;

  if (!user)
    return 0;
  DBG ("Set_Flags: %s=%#x", NONULLP(serv), uf);
  uf &= ~U_IMMUTABLE;				/* hold on those */
  if (!serv)
  {
    user->flag &= U_IMMUTABLE;			/* update global flags */
    user->flag |= uf;
    LISTFILEMODIFIED;		/* cannot use mutex but value isn't critical */
    return user->flag;
  }
  else if (!*serv)		/* direct service flags need NULL as arg! */
    return 0;
  if ((i = _get_index_sp (serv)) == R_NO) /* check if it's known service */
    return 0;
  for (chr = user->channels; chr; chr = chr->next)
    if (chr->cid == i)
      break;
  if (!user->progress && uf == 0 && chr && !chr->greeting)
  {
    _del_channel (&user->channels, chr); /* delete empty channel record */
    LISTFILEMODIFIED;		/* cannot use mutex but value isn't critical */
    return 0;
  }
  if (!chr)
    chr = *(_add_channel (&user->channels, i));
  DBG ("Set_Flags: added channel: %p, head=%p", chr, user->channels);
  if (!chr)
    return 0;
  chr->flag = uf;
  LISTFILEMODIFIED;
  return uf;
}

/*--- R --- no locks ---*/
userflag Get_Clientflags (const char *lname, const char *serv)
{
  struct clrec_t *user;
  userflag uf;

  rw_rdlock (&UFLock);
  user = _findbylname (lname);
  if (user)
  {
    if (user->flag & U_ALIAS)	/* unaliasing */
      user = user->u.owner;
    pthread_mutex_lock (&user->mutex);
    uf = Get_Flags (user, serv);
    pthread_mutex_unlock (&user->mutex);
  }
  else
    uf = 0;
  rw_unlock (&UFLock);
  return uf;
}

/*--- W --- UFLock and built-in --- no other locks ---*/
int Add_Mask (struct clrec_t *user, const uchar *mask)
{
  int i = 0;

  if (!user || !mask) return 0;
  if (!*mask)
  {
    ERROR ("Add_Mask: invalid hostmask pattern %s ignored.", mask);
    return 0;
  }
  pthread_mutex_unlock (&user->mutex);		/* unlock to avoid conflicts */
  i = _add_usermask (user, mask);
  pthread_mutex_lock (&user->mutex);
  return i;
}

/*--- W --- UFLock and built-in --- no other locks ---*/
int Delete_Mask (struct clrec_t *user, const uchar *mask)
{
  register int x;

  if (!mask) return 0;
  pthread_mutex_unlock (&user->mutex);		/* unlock to avoid conflicts */
  _del_usermask (user, mask);
  x = user->host ? 0 : -1;
  pthread_mutex_lock (&user->mutex);
  return x;
}

/*--- R --- no locks ---*/
static unsigned int _scan_lids (lid_t start, lid_t end)
{
  register int i, j;
  int k;
  register unsigned int n = 0;

  i = (start-LID_MIN)/32;
  k = (end-LID_MIN+1)/32;
  for (; i < k; i++)
  {
    for (j = 0; j < 32; j++)
      if (LidsBitmap[i] & ((uint32_t)1<<j))
	n++;
  }
  return n;
}

/*--- R --- no locks ---*/
void Status_Clients (INTERFACE *iface)
{
  long int r, s, d, i, h, n, f;

  pthread_mutex_lock (&FLock);
  r = _R_r, s = _R_s, d = _R_d, i = _R_i;
  h = _R_h, n = _R_n, f = _R_f;
  pthread_mutex_unlock (&FLock);
  New_Request (iface, 0,
	       "Listfile: %ld regular, %ld specials, %ld bans, %ld ignores. Total %ld names.",
	       r, s, d, i, (long int)(r+s+d+i));
  New_Request (iface, 0,
	       "Listfile memory usage: records %ld, hosts %ld, subfields %ld bytes.",
	       (long int)(n + (r+s+d) * sizeof(struct clrec_t)), h, f);
  d -= _scan_lids (LID_MIN, ID_REM);
  i -= _scan_lids (ID_ME+1, ID_ANY-1);
  r -= _scan_lids (ID_ANY+1, LID_MAX);
  r += s;
  if (d || i || r)
    ERROR ("Listfile: difference (loss) in bit map%s%.0ld%s%.0ld%s%.0ld",
	   d ? ", bans:" : "", d, i ? ", ignores:" : "", i, r ? ", names:" : "", r);
}

/* ----------------------------------------------------------------------------
 * Listfile management.
 */

static char *_next_field (char **c)
{
  register char *ch, *r;

  ch = r = *c;
  while (*ch && *ch != ':') ch++;
  if (*ch)
    *ch++ = 0;
  *c = ch;
  return r;
}

static FILE *_check_listfile (const char *filename, char *buff, size_t s)
{
  FILE *fp;

  fp = fopen (filename, "r");
  buff[0] = 0;
  if (fp)
  {
    fseek (fp, -11L, SEEK_END);
    if (fread (buff, 1, 11, fp) < 11)
      buff[0] = 0;
    rewind (fp);
  }
  if (strncmp (buff, "\n:::::::::\n", 11) ||	/* file is corrupted? */
	!fgets (buff, s, fp) ||
	strncmp (buff, "#FEU: ", 6))		/* my magic */
  {
    if (fp)
      fclose (fp);
    return NULL;
  }
  return fp;
}

/*
 * since we can have references to another clientrecord in any clientrecord
 * and these referenced may point to clientrecord that isn't loaded yet,
 * we have to manage it with some clienrecord-ahead list, see functions below
 *
 * tree is something like:  r1:a.first => next   => next...
 *			       x.name	  x.chr     x.chr
 *			    r2:a.first => ..................
 */

typedef struct _cral_t {
  struct _cral_t *next;		/* next name or next chr in row */
  union {
    struct _cral_t *first;	/* first link in chain of this name */
    pthread_mutex_t *mutex;
  } a;
  union {
    char *name;			/* name for row */
    user_chr **chr;		/* chr in row */
  } x;
} _cral_t;

typedef struct _cral_bl {
  struct _cral_bl *next;
  _cral_t x[32];
} _cral_bl;

static _cral_t *FirstCRAL = NULL;
static _cral_t *FreeCRAL = NULL;

static _cral_bl *FirstCRALBL = NULL;
static _cral_bl *LastCRALBL = NULL;

/* returns first in row */
static _cral_t **_cral_find (char *name)
{
  _cral_t **cral;

  for (cral = &FirstCRAL; *cral; cral = &(*cral)->next)
    if ((*cral)->x.name == NULL)
    {
      DBG ("list:_cral_find: error! no name at %p!", *cral);
      bot_shutdown ("listfile loader error.", 3);
    }
    else if (!strcmp ((*cral)->x.name, name))
      break;
    else
      DBG ("list:_cral_find: %s != %s", (*cral)->x.name, name);
  DBG ("list:_cral_find(%s)->%p", name, *cral);
  return cral;
}

/* return one free _cral_t from array of free ones */
static _cral_t *_cral_get (void)
{
  register _cral_t *cral;

  if (!FreeCRAL)
  {
    register _cral_bl *bl = safe_malloc (sizeof(_cral_bl));
    register int i = 32;

    cral = FreeCRAL = &bl->x[0];
    while (--i)
    {
      cral->next = &cral[1];
      cral++;
    }
    cral->next = NULL;
    if (LastCRALBL)
      LastCRALBL->next = bl;
    else
      FirstCRALBL = bl;
    LastCRALBL = bl;
    bl->next = NULL;
  }
  cral = FreeCRAL;
  FreeCRAL = cral->next;
  DBG ("list:_cral_get: %p", cral);
  return cral;
}

/*--- W --- *mutex --- no FLock ---*/
static user_chr *_cral_add (char *name, user_chr **chr, char *greeting,
			    pthread_mutex_t *mutex)
{
  _cral_t **cral = _cral_find (name);
  _cral_t *tmp;

  if (!*cral)
  {
    *cral = _cral_get();
    (*cral)->next = NULL;
    (*cral)->a.first = NULL;
    (*cral)->x.name = safe_strdup (name);
    DBG ("list:_cral_add: created new row for %s: %p, newhead=%p", name, *cral, FirstCRAL);
  }
  tmp = _cral_get();
  tmp->next = (*cral)->a.first;
  (*cral)->a.first = tmp;
  DBG ("list:_cral_add: adding channel %s:%s, %p->%p", name, NONULL(greeting),
       tmp->next, tmp);
  tmp->x.chr = chr = _add_channel (chr, R_NO);
  (*chr)->greeting = safe_strdup (greeting);
  pthread_mutex_lock (&FLock);
  _R_f += strlena (greeting);
  pthread_mutex_unlock (&FLock);
  DBG ("list:_cral_add: added channel %s: %p", (*cral)->x.name, *chr);
  tmp->a.mutex = mutex;
  return *chr;
}

/*--- W --- *mutex --- no built-ins with exception for *mutex ---*/
static void _cral_check (char *name, lid_t cid, pthread_mutex_t *mutex)
{
  _cral_t **cral = _cral_find (name);
  _cral_t *head;

  if (!*cral)
    return;
  head = *cral;
  *cral = head->next;			/* delete row from main chain */
  head->next = head->a.first;		/* create free chain from current */
  FREE (&head->x.name);
  for (cral = &head->a.first; *cral; cral = &(*cral)->next)
  {
    if ((*cral)->a.mutex != mutex)
      pthread_mutex_lock ((*cral)->a.mutex);
    (*(*cral)->x.chr)->cid = cid;
    if ((*cral)->a.mutex != mutex)
      pthread_mutex_unlock ((*cral)->a.mutex);
    DBG ("list:_cral_check: chr=%p", *(*cral)->x.chr);
  }
  *cral = FreeCRAL;			/* add freed chain info FreeCRAL */
  FreeCRAL = head;
  DBG ("list:_cral_check: out channel %s(id=%hd), newhead=%p", name, cid, FirstCRAL);
}

/*--- W --- no locks --- no built-ins ---*/
static int _cral_clear (void)
{
  _cral_bl *bl, *next;
  _cral_t *cral, *head;
  int r = 0;

  /* cycle 1: free all _cral_t's */
  for (head = FirstCRAL; head; head = head->next)
  {
    DBG ("list:_cral_clear: clearing %s(%p)", head->x.name, head);
    FREE (&head->x.name);
    for (cral = head->a.first; cral; cral = cral->next)
    {
      user_chr *c;

      pthread_mutex_lock (cral->a.mutex);
      c = *cral->x.chr;
      *cral->x.chr = c->next;
      pthread_mutex_unlock (cral->a.mutex);
      r += strlena (c->greeting) + sizeof(user_chr);
      FREE (&c->greeting);
      FREE (&c);
    }
  }
  /* cycle 2: free all blocks */
  for (bl = FirstCRALBL; bl; bl = next)
  {
    next = bl->next;
    FREE (&bl);
  }
  FirstCRALBL = LastCRALBL = NULL;
  FirstCRAL = FreeCRAL = NULL;
  return r;
}

#define U_NONAMED (U_DENY | U_ACCESS | U_INVITE | U_DEOP | U_QUIET | U_IGNORED)
/*
 * load mode:
 *	reset all
 * update mode: (users that have U_UNSHARED flag and special will be skipped)
 *	reset common: flag, uid, passwd, info, created, host, aliases
 *	update (if found): special fields
 *	don't touch local fields: log(in|out), charset
 * (note: we trust to the caller, it have check listfile to don't erase own)
 */
/*--- W --- no locks ---*/
static int _load_listfile (const char *filename, int update)
{
  char buff[HUGE_STRING];
  char ffn[LONG_STRING];
  struct clrec_t *ur;
  FILE *fp;
  char *c, *v, *cc;
  unsigned int _a, _u, _r, _k;			/* add, update, remove, keep */
  int _f = 0;
  lid_t lid;					/* temporal everywhere below */

  if (O_MAKEFILES)
    return 0;
  filename = expand_path (ffn, filename, sizeof(ffn));
  fp = _check_listfile (filename, buff, sizeof(buff));
  if (!fp)
  {
    Add_Request (I_LOG, "*", F_BOOT, "Bad userfile, unlink it and trying backup...");
    unlink (filename);
    snprintf (buff, sizeof(buff), "%s~", filename);
    fp = _check_listfile (buff, buff, sizeof(buff));
    if (!fp)					/* cannot use even backup */
      return -1;
  }
  _a = _u = _r = _k = 0;
  rw_wrlock (&UFLock);
  lid = LID_MIN;
  do {
    if ((ur = UList[lid - LID_MIN]))
      ur->progress = 1;
  } while (lid++ != LID_MAX);
  ur = NULL;
  while (fgets (buff, sizeof(buff), fp))
  {
    c = buff;
    StrTrim (buff);
    switch (buff[0])
    {
      case '+':				/* a hostmask */
	if (ur)
	  _add_usermask (ur, ++c);
	break;
      case 0:				/* empty line ignored */
      case '#':				/* an comment */
	break;
      case ' ':				/* a field */
	if (!ur)
	  break;
	v = gettoken (++c, NULL);	/* it is field value now */
	_next_field (&c);		/* c points after first ':' now */
	cc = &buff[1];
	if (*c && c < v)		/* check if field is console/service */
	{
	  user_chr *ch;

	  if (strrchr (cc, '@') == cc)	/* it's service name */
	    cc++;
	  lid = _get_index_sp (cc);
	  DBG ("_load_listfile: subrecord %s, lid=%hd", cc, lid);
	  if (lid != R_NO)			/* try to find and add it */
	  {
	    for (ch = ur->channels; ch && ch->cid != lid; ch = ch->next)
	      DBG ("_load_listfile: cid=%hd != lid=%hd", ch->cid, lid);
	    if (!ch)
	      ch = *(_add_channel (&ur->channels, lid));
	    pthread_mutex_lock (&FLock);
	    _R_f += (*v ? strlena (v) : 0) - strlena (ch->greeting);
	    pthread_mutex_unlock (&FLock);
	    FREE (&ch->greeting);
	    ch->greeting = safe_strdup (v);
	  }
	  else /* if no such service added yet then add it to "ahead" list */
	    ch = _cral_add (cc, &ur->channels, v, &ur->mutex);
	  if (!ch)
	  {
	    ERROR ("_load_listfile: unknown subrecord %s(%hd) for \"%s\"",
		   cc, lid, NONULL(ur->lname));
	    break;
	  }
	  ch->flag = strtouserflag (_next_field (&c), NULL);
	  ch->expire = (time_t) strtol (c, NULL, 10);
	  DBG ("_load_listfile: done subrecord %s", &buff[1]);
	  break;
	}
	else if (!strcasecmp (cc, "alias"))
	  _add_aliases (ur, v);
	Set_Field (ur, cc, v, 0);		/* set the field */
	break;
      case '\\':			/* skip if next char if one of "#+\" */
	if (strchr ("#+\\", buff[1]))
	  c++;
      default:				/* new user record */
	v = c;
	if (ur)
	{
	  ur->progress = 0;		/* finish updating of previous */
	  if (ur->lname)
	    _cral_check (ur->lname, ur->uid, &ur->mutex); /* check "ahead" list */
	  pthread_mutex_unlock (&ur->mutex);
	}
	if (!strcmp (buff, ":::::::::"))	/* it is EOF */
	{
	  lid = LID_MIN;
	  _f -= _cral_clear(); 			/* clear "ahead" list */
	  do {
	    if ((ur = UList[lid - LID_MIN]) != NULL && ur->progress)
	    {
	      if (!update || !(ur->flag & (U_UNSHARED|U_SPECIAL)))
	      {
		_delete_userrecord (ur, 0);
		_r++;
	      }
	      else
		ur->progress = 0;
	    }
	    else if (ur != NULL && ur->lname == NULL) /* check nonamed ones */
	    {
	      user_chr *ch, *ch2;
	      userflag flag = ur->flag;

	      pthread_mutex_lock (&ur->mutex);
	      for (ch = ur->channels; ch; ch = ch2)
	      {
		ch2 = ch->next;
		if (ch->expire <= Time)	/* remove expired subrecords */
		  _del_channel (&ur->channels, ch);
		else
		  flag |= ch->flag;
	      }
	      pthread_mutex_unlock (&ur->mutex);
	      /* validate record - nonamed has to have host and at least one of
		 flags U_DENY | U_ACCESS | U_INVITE | U_DEOP | U_QUIET | U_IGNORED
		 on at least one subrecord */
	      if (!(flag & U_NONAMED) || !ur->host)
	      {
		_delete_userrecord (ur, 0);
		_r++;
	      }
	    }
	  } while (lid++ != LID_MAX);
	  if (_r)
	    LISTFILEMODIFIED;
	  rw_unlock (&UFLock);
	  Add_Request (I_LOG, "*", F_BOOT,
		"Loaded %s: %u records added, %u updated, %u removed, %u kept.",
		filename, _a, _u, _r, _k);
	  fclose (fp);
	  DBG ("list.c:_load_listfile: F.list: on end %d %d", (int)_R_f, _f);
	  pthread_mutex_lock (&FLock);
	  _R_f += _f;
	  pthread_mutex_unlock (&FLock);
	  return 0;
	}
	/* only owner has Lname "", all other NULL or non-empty */
	if (*c == ':')
	{
	  v = NULL;
	  c++;							/* 1 */
	}
	else
	{
	/* find the user and empty it */
	  if (*c == '@')	/* if it's service name */
	    c++;
	  DBG ("_load_listfile: starting parsing user line %s", c);
	  ur = _findbylname (_next_field (&c));			/* 1 */
	}
	cc = _next_field (&c);					/* 2 */
	lid = (lid_t) strtol (_next_field (&c), NULL, 10);	/* 3 */
	if (v == NULL)		/* if it's nonamed record */
	  ur = UList[lid-LID_MIN];
	else if (UList[lid-LID_MIN] != ur)
	{
	  /* we could get ID for named record changed in next cases:
	      - we loading wrong file now
	      - we loaded wrong file before
	      - we deleted that Lname and added it again, all before reload
	     we cannot handle first case but in other two cases we will just
	     ignore previous data and load new */
	  ERROR ("_load_listfile: conflicting LID %hd, redo name \"%s\"",
		 lid, v);
	  if (!ur)		/* choose another ID on adding */
	    lid = ID_ANY;
	  else if (!(update && (ur->flag & (U_UNSHARED|U_SPECIAL))) &&
		   ur->progress) /* those will be kept anyway */
	  {
	    _delete_userrecord (ur, 0);
	    ur = NULL;
	  }
	}
	if (ur)
	{
	  user_hr *hr;

	  if (update && (ur->flag & (U_UNSHARED|U_SPECIAL)))
	  {
	    _k++;
	    ur = NULL; /* ignore whole record */
	    break;
	  }
	  if (!ur->progress)
	  {
	    WARNING ("_load_listfile: duplicate record name \"%s\" ignored", v);
	    ur = NULL; /* ignore whole record */
	    break;
	  }
	  _u++;
	  _del_aliases (ur);		/* remove all aliases */
	  rw_wrlock (&HLock);
	  while (ur->host)
	  {
	    hr = ur->host;
	    ur->host = hr->next;
	    _R_h -= safe_strlen (hr->hostmask) + 1 + sizeof(user_hr) -
		    sizeof(hr->hostmask);
	    FREE (&hr);
	  }
	  rw_unlock (&HLock);
	  pthread_mutex_lock (&ur->mutex);
	  ur->flag = strtouserflag (_next_field (&c), NULL);	/* 4 */
	  if (spname_valid (v) > 0)
	    ur->flag |= U_SPECIAL;
	}
	/* or create new user record */
	else if ((ur = _add_userrecord ((v && *v == '@') ? &v[1] : v,
				strtouserflag (_next_field (&c), NULL) | /* 4 */
				((spname_valid (v) > 0) ? U_SPECIAL : 0), lid)))
	{
	  _a++;
	  pthread_mutex_lock (&ur->mutex);
	}
	else
	{
	  ERROR ("_load_listfile: could not add new record for name \"%s\"", v);
	  break;
	}
	/* parse the fields and fill user record */
	_f -= strlena (ur->passwd) + strlena (ur->u.info);
	FREE (&ur->passwd);
	ur->passwd = safe_strdup (cc);
	FREE (&ur->u.info);
	ur->u.info = safe_strdup (_next_field (&c));		/* 5 */
	_f += strlena (ur->passwd) + strlena (ur->u.info);
	if (!update)		/* rest ignored when update */
	{
	  user_chr *chr;
	  user_fr *fr;

	  _f -= strlena (ur->charset) + strlena (ur->login) +
		strlena (ur->logout);
	  FREE (&ur->charset);
	  ur->charset = safe_strdup (_next_field (&c));		/* 6 */
	  FREE (&ur->login);
	  ur->login = safe_strdup (_next_field (&c));		/* 7 */
	  FREE (&ur->logout);
	  ur->logout = safe_strdup (_next_field (&c));		/* 8 */
	  _f += strlena (ur->charset) + strlena (ur->login) +
		strlena (ur->logout);
	  while (ur->channels)
	  {
	    chr = ur->channels;
	    ur->channels = chr->next;
	    _f -= strlena (chr->greeting) + sizeof(user_chr);
	    FREE (&chr->greeting);
	    FREE (&chr);
	  }
	  while (ur->fields)
	  {
	    fr = ur->fields;
	    ur->fields = fr->next;
	    _f -= strlena (fr->value) + sizeof(user_fr);
	    FREE (&fr->value);
	    FREE (&fr);
	  }
	}
	else
	{
	  _next_field (&c);
	  _next_field (&c);
	  _next_field (&c);
	}
	ur->created = (time_t) strtol (c, NULL, 10);		/* 9 */
	dprint (5, "Got info for %s user %s:%s%s info=%s created=%lu",
		(ur->flag & U_SPECIAL) ? "special" : "normal",
		NONULLP(ur->lname), (ur->flag & U_SPECIAL) ? " network=" : "",
		(ur->flag & U_SPECIAL) ? (NONULL(ur->logout)) : "",
		NONULL(ur->u.info), (unsigned long int)ur->created);
	ur->progress = 1;
    }
  }
  if (ur)
  {
    _cral_check (ur->lname, ur->uid, &ur->mutex); /* check "ahead" list */
    pthread_mutex_unlock (&ur->mutex);	/* finish updating of previous */
  }
  _f -= _cral_clear(); /* clear "ahead" list, some may be lost, unavoidable */
  lid = LID_MIN;
  do {
    if ((ur = UList[lid - LID_MIN]))
      ur->progress = 0;			/* keep all records in current state */
  } while (lid++ != LID_MAX);
  LISTFILEMODIFIED;
  rw_unlock (&UFLock);
  Add_Request (I_LOG, "*", F_BOOT,
	       "Unexpected EOF at %s: %u records added, %u updated, %u kept.",
	       filename, _a, _u, _k);
  fclose (fp);
  pthread_mutex_lock (&FLock);
  _R_f += _f;
  pthread_mutex_unlock (&FLock);
  return -1;
}

/*--- W --- no locks ---*/
int Merge_Listfile (char *path)
{
  return _load_listfile (path, 1);
}

static int _nonamed_record_is_invalid (struct clrec_t *ur)
{
  register user_chr *sr;
  register struct clrec_t *sur;
  /* validate record - nonamed has to have host and at least one
     of flags U_DENY | U_ACCESS | U_INVITE | U_DEOP | U_QUIET | U_IGNORED
     on at least one subrecord */
  if (ur->lname != NULL)
    return 0;				/* not unnamed */
  DBG ("_nonamed_record_is_invalid:no lname");
  if (ur->host == NULL)
    return 1;				/* no name and no host */
  DBG ("_nonamed_record_is_invalid:there is host");
  if (ur->flag & U_NONAMED & U_GLOBALS)
    return 0;				/* global flag */
  DBG ("_nonamed_record_is_invalid:no globals");
  for (sr = ur->channels; sr; sr = sr->next)
    if (((sur = UList[sr->cid-LID_MIN])) && (sur->flag & U_SPECIAL) &&
	(sr->flag & U_NONAMED) && (sr->expire >= Time))
      return 0;				/* service flag */
  DBG ("_nonamed_record_is_invalid:no flags");
  return 1;
}

static int _write_listfile (char *str, int fd)
{
  ssize_t sz = safe_strlen (str);
  if (write (fd, str, sz) != sz)
    return 0;
  return 1;
}

/*--- W --- no locks ---*/
static int _save_listfile (const char *filename, int quiet)
{
  struct clrec_t *ur;
  user_hr *hr;
  user_chr *chr;
  user_fr *fr;
  int fd;
  char buff[HUGE_STRING];
  char ffn[LONG_STRING];
  char f[64];				/* I hope it's enough for 19 flags :) */
  struct stat st;
  int i = 0;
  int _r, _s, _d, _i;		/* regular, special, ban, ignore */
  lid_t lid;

  filename = expand_path (ffn, filename, sizeof(ffn));
  if (!stat (filename, &st))
  {
    snprintf (buff, sizeof(buff), "%s~", filename);
    unlink (buff);
    if (rename (filename, buff) && !quiet) {	/* creating backup */
#if _GNU_SOURCE
      register const char *str = strerror_r(errno, buff, sizeof(buff));
      ERROR("Cannot create backup of Listfile: %s", str);
#else
      if (strerror_r(errno, buff, sizeof(buff)) != 0)
        strfcpy(buff, "(failed to decode error)", sizeof(buff));
      ERROR("Cannot create backup of Listfile: %s", buff);
#endif
    }
  }
  fd = open(filename, O_CREAT | O_WRONLY | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP);
  _r = _s = _d = _i = 0;
  if (fd >= 0)
  {
    _savetime = 0;
    snprintf (buff, sizeof(buff), "#FEU: Generated by bot \"%s\" on %s", Nick,
	      ctime (&Time));
    i = _write_listfile (buff, fd);
    lid = LID_MIN;
    do
    {
      if (!(ur = UList[lid - LID_MIN]) || (ur->flag & U_ALIAS))
	continue;
      if (_nonamed_record_is_invalid (ur))
      {
	if (quiet)
	  continue;
	rw_wrlock (&UFLock);
	_delete_userrecord (ur, 0);		/* remove invalid record */
	rw_unlock (&UFLock);
	continue;
      }
      if (ur->uid < ID_REM)			/* nonamed bans/exceptions */
	_d++;
      else if (!ur->lname)			/* nonamed invites */
	_i++;
      else if (ur->flag & U_SPECIAL)		/* specials */
	_s++;
      else					/* regular and me */
	_r++;
      snprintf (buff, sizeof(buff), "%s%s%s:%s:%hd:%s:%s:%s:%s:%s:%lu\n",
		(ur->lname && strchr ("#+\\", ur->lname[0])) ? "\\" : "",
		((ur->flag & U_SPECIAL) && !strchr (ur->lname, '@')) ? "@" : "",
		NONULL(ur->lname), NONULL(ur->passwd), ur->uid,
		userflagtostr (ur->flag, f), NONULL(ur->u.info),
		NONULL(ur->charset), NONULL(ur->login), NONULL(ur->logout),
		(unsigned long int)ur->created);
      i = _write_listfile (buff, fd);
      for (hr = ur->host; hr && i; hr = hr->next)
      {
	snprintf (buff, sizeof(buff), "+%s\n", hr->hostmask);
	i = _write_listfile (buff, fd);
      }
      if (!quiet)
	pthread_mutex_lock (&ur->mutex);
      for (chr = ur->channels; chr && i; chr = chr->next)
      {
	register struct clrec_t *sur;

	if (chr->cid == R_CONSOLE)
	  sur = NULL;				/* it's NULL but for any case */
	else if (!(sur = UList[chr->cid-LID_MIN]) ||
		 !(sur->flag & U_SPECIAL))	/* drop invalid subrecords */
	{
	  register user_chr *c = chr;

	  if (quiet)
	    continue;
	  DBG ("dropped unknown service %d(%s) subrecord from \"%s\": %s",
	       (int)chr->cid, (sur && sur->lname) ? sur->lname : "",
	       NONULL(ur->lname), NONULL(chr->greeting));
	  _del_channel (&ur->channels, c);	/* remove invalid subrecord */
	  continue;
	}
	if (chr->expire && chr->expire < Time)	/* drop expired bans/etc. */
	{
	  register user_chr *c = chr;

	  if (quiet)
	    continue;
	  DBG ("dropped expired service %d(%s) subrecord from \"%s\"",
	       (int)chr->cid, sur ? sur->lname : "", NONULL(ur->lname));
	  _del_channel (&ur->channels, c);	/* remove expired subrecord */
	  continue;
	}
	snprintf (buff, sizeof(buff), " %s%s:%s:%.0lu %s\n",
		  (sur && !safe_strchr(sur->lname, '@')) ? "@" : "",
		  sur ? sur->lname : "",
		  userflagtostr (chr->flag, f), (unsigned long)chr->expire,
		  NONULL(chr->greeting));
	i = _write_listfile (buff, fd);
      }
      if (!quiet)
	pthread_mutex_unlock (&ur->mutex);
      for (fr = ur->fields; fr && i; fr = fr->next)
      {
	snprintf (buff, sizeof(buff), " %s %s\n", Field[fr->id], fr->value);
	i = _write_listfile (buff, fd);
      }
    } while (lid++ != LID_MAX);
    if (i)
      i = _write_listfile (":::::::::\n", fd);	/* empty record - for check */
    close (fd);
  }
  if (!i)
  {
    if (!quiet)
      ERROR ("Error on saving listfile, keeping old one.");
    unlink (filename);				/* error - file corrupted */
    snprintf (buff, sizeof(buff), "%s~", filename);
    if (rename (buff, filename) && !quiet) {	/* restoring from backup */
#if _GNU_SOURCE
      register const char *str = strerror_r(errno, buff, sizeof(buff));
      ERROR("Failed to restore Listfile from backup: %s", str);
#else
      if (strerror_r(errno, buff, sizeof(buff)) != 0)
        strfcpy(buff, "(failed to decode error)", sizeof(buff));
      ERROR("Failed to restore Listfile from backup: %s", buff);
#endif
    }
    return (-1);
  }
  Add_Request (I_LOG, "*", F_BOOT,
	       "Saved %s: %d bans, %d regular, and %d special records.",
	       filename, _d, _r, _s);
  if (quiet)
    return 0;
  pthread_mutex_lock (&FLock);
  _i -= _R_i;
  _d -= _R_d;
  _r -= _R_r;
  _s -= _R_s;
  pthread_mutex_unlock (&FLock);
  if (_i || _d || _r ||  _s)
    ERROR ("_save_listfile: difference in userrecords%s%.0d%s%.0d%s%.0d%s%.0d",
	   _i ? ", ignores=" : "", _i, _d ? ", bans=" : "", _d,
	   _r ? ", regular=" : "", _r, _s ? ", special=" : "", _s);
  return 0;
}

static iftype_t userfile_signal (INTERFACE *iface, ifsig_t signal)
{
  INTERFACE *tmp;
  char buff[STRING];

  switch (signal)
  {
    case S_REPORT:
      printl (buff, sizeof(buff), ReportFormat, 0,
	      NULL, NULL, "Listfile", NULL, 0, 0, 0, Listfile);
      tmp = Set_Iface (iface);
      New_Request (tmp, F_REPORT, "%s", buff);
      Unset_Iface();
      break;
    case S_TIMEOUT:
      if (_savetime && Time - _savetime >= cache_time)
	/* can use Listfile variable - I hope iface locked now */
	_save_listfile (Listfile, 0);
      break;
    case S_REG:
    case S_STOP:
    case S_CONTINUE:
      break;
    case S_TERMINATE:
    case S_SHUTDOWN:
      iface->ift |= I_DIED;
    default:
      if (_savetime)
	_save_listfile (Listfile, signal == S_SHUTDOWN ? 1 : 0);
  }
  return 0;
}

/* all rest: --- W --- no locks ---*/
/* ----------------------------------------------------------------------------
 * Internal dcc bindings:
 * int func(struct peer_t *from, char *args)
 */

static void parse_chattr (char *text, userflag *toset, userflag *tounset)
{
  char here;
  userflag todo;

  text += strcspn (text, "+- |");	/* skip initial garbage */
  FOREVER
  {
    here = *text++;
    if (here == '+')
    {
      todo = strtouserflag (text, &text);
      *toset |= todo;
      *tounset &= ~todo;
    }
    else if (here == '-')
    {
      todo = strtouserflag (text, &text);
      *tounset |= todo;
      *toset &= ~todo;
    }
    else
      break;
  }
}

static void check_perm (userflag to, userflag by, userflag ufmask,
			userflag *toset, userflag *tounset)
{
  userflag testuf;

  if (!*toset && !*tounset)		/* nothing to do! */
    return;
  if (!(by & U_OWNER))			/* master or below */
  {
    ufmask |= (U_OWNER | U_MASTER | U_SPEAK | U_UNSHARED | U_IGNORED);
    testuf = U_OWNER | U_MASTER;
  }
  else
    testuf = 0;
  if (!(by & U_MASTER))			/* op or halfop */
  {
    ufmask |= (U_HALFOP | U_OP | U_AUTO | U_VOICE | U_QUIET | U_INVITE);
    testuf |= U_OP | U_HALFOP;
    if (!(by & U_OP))			/* halfop */
    {
      ufmask |= (U_FRIEND | U_DEOP);
      testuf |= U_SPECIAL;
      if ((to & testuf) || !(by & U_HALFOP))
      {
	*toset = *tounset = 0;		/* seniority! */
	return;
      }
    }
  }
  testuf = *toset & ~ufmask;		/* what is not permitted */
  if (testuf & U_OWNER)			/* some dependencies */
    testuf |= U_MASTER;
  if (testuf & U_MASTER)
    testuf |= U_OP;
  if (testuf & U_OP)
    testuf |= U_HALFOP;
  *toset = testuf & ~to;		/* don't set what is already set */
  testuf = *tounset & ~ufmask;
  if (testuf & U_HALFOP)
    testuf |= U_OP;
  if (testuf & U_OP)
    testuf |= U_MASTER;
  if (testuf & U_MASTER)
    testuf |= U_OWNER;
  *tounset = testuf & to;		/* don't unset what isn't set yet */
}

/*
 * chattr +a-b			gl=1	sv=0	args=0
 * chattr +x-y #chan		1	2	2
 * chattr |+x-y [#chan]		1	1a	2/0
 * chattr +a-b|+x-y [#chan]	1	1a	2/0
 * chattr +a-b |+x-y [#chan]	1	2a	3/0
 */
BINDING_TYPE_dcc (dc_chattr);
static int dc_chattr (struct peer_t *dcc, char *args)
{
  userflag ufp, ufm;
  userflag uf, cf;
  lid_t id = R_NO;
  char *gl, *sv;
  char plus[64+4];			/* I hope it enough for 2*21 flags :) */
  char Chan[IFNAMEMAX+1];
  char *minus;
  struct clrec_t *user;
  const struct clrec_t *who;
  user_chr *chr;

  if (!args)
    return 0;
  gl = safe_strchr (args, ' ');		/* get first word */
  if (gl)
    *gl = 0;
  user = _findbylname (args);		/* find the user */
  if (dcc->iface->ift & I_CONSOLE)
    who = &CONSOLEUSER;
  if (user)
    who = _findbylname (dcc->iface->name); /* find me */
  if (user && (user->flag & U_ALIAS))	/* unaliasing */
    user = user->u.owner;
  if (!user || !who)			/* cannot chattr for non-users */
  {
    New_Request (dcc->iface, 0, _("No user with login name %s found."), args);
    return 0;
  }
  pthread_mutex_lock (&user->mutex);	/* don't need lock UFLock write */
  if (gl)				/* restore string, lname is in *user */
    *gl = ' ';
  args = NextWord (args);
  StrTrim (args);			/* break ending spaces */
  DBG ("list.c:dc_chattr:arg1:%s", args);
  gl = args;				/* try to find arguments */
  args = sv = NextWord (args);		/* (<g>) *(|<l>)?( +<s>)? */
  if (*sv && *sv == '|')
    args = NextWord (sv);		/* <g> |...( ...)? */
  else if ((sv = strchr (gl, '|')) && sv < args)
    sv++;				/* <g>|...( ...)? */
  else					/* <g|l>( ...)? */
    sv = args;
  *Chan = 0;
  if (user->flag & U_SPECIAL)		/* only owners may change that */
    id = _get_index_sp (user->lname);
  else if (*args/* && strchr (SPECIALCHARS, *args)*/)
  {
    id = _get_index_sp (args);		/* so we trying to change subflag? */
    if (id == R_NO)
    {
      pthread_mutex_unlock (&user->mutex);
      New_Request (dcc->iface, 0, _("No such service '%s'."), args);
      return 0;
    }
    strfcpy (Chan, args, sizeof(Chan));
  }
  else					/* let's try to guess default service */
  {
    for (chr = who->channels; chr && chr->cid != R_CONSOLE; chr = chr->next);
    if (chr)
    {
      NextWord_Unquoted (Chan, NextWord (chr->greeting), sizeof(Chan));
      id = _get_index_sp (Chan);
    }
    else
      id = R_NO;
  }
  uf = who->flag;					/* globals + direct */
  if (id != R_NO)
  {
    for (chr = who->channels; chr; chr = chr->next)
      if (chr->cid == id)
	break;
    cf = (uf & U_GLOBALS) | (chr ? chr->flag : 0);	/* globals + service */
  }
  else
    cf = (uf & U_GLOBALS);				/* globals */
  DBG ("list.c:dc_chattr:caller perm=0x%08lx/0x%08lx, id=%hd", (long)uf,
       (long)cf, id);
  if (user->flag & U_SPECIAL)
  {
    if (!((uf | cf) & U_OWNER))		/* only owners may change that */
      uf = 0;
    cf = 0;				/* special usually have not subs */
  }
  if ((uf == 0 && cf == 0))		/* no permissions to do anything */
  {
    pthread_mutex_unlock (&user->mutex);
    New_Request (dcc->iface, 0, _("Permission denied."));
    return 0;
  }
  else if ((sv != args || *args) && id < 0) /* trying to change bad subflags */
  {
    pthread_mutex_unlock (&user->mutex);
    New_Request (dcc->iface, 0, _("You set no default service yet."));
    return 0;
  }
  ufp = ufm = 0;
  if (sv != args || !*args)		/* global attributes */
  {
    parse_chattr (gl, &ufp, &ufm);
    DBG ("list.c:dc_chattr:arg2:%s:0x%08lx/0x%08lx", gl, (long)ufp, (long)ufm);
    /* check permissions - any flag may be global/direct */
    check_perm (user->flag, uf, 0, &ufp, &ufm);
    DBG ("list.c:dc_chattr:0x%08lx/0x%08lx->0x%08lx/0x%08lx", (long)user->flag,
	 (long)uf, (long)ufp, (long)ufm);
    if (ufp || ufm)
    {
      /* set userflags */
      user->flag |= ufp;
      user->flag &= ~ufm;
      if (!(user->flag & U_SPECIAL))
      {
	/* S_FLUSH dcc record if on partyline */
	Add_Request (I_DIRECT, user->lname, F_USERS, "\010");
	/* notice the user if on partyline */
	if (ufm & U_OWNER)
	  minus = _("owner");
	else if (ufm & U_MASTER)
	  minus = _("master");
	else if (ufm & U_OP)
	  minus = _("operator");
	else if (ufm & U_HALFOP)
	  minus = _("half op");
	else
	  minus = NULL;
	if (minus)
	  Add_Request (I_DIRECT, user->lname, F_T_NOTICE,
		       _("OOPS, you are not %s anymore..."), minus);
	if (ufp & U_OWNER)
	  minus = _("owner");
	else if (ufp & U_MASTER)
	  minus = _("master");
	else if (ufp & U_OP)
	  minus = _("operator");
	else if (ufp & U_HALFOP)
	  minus = _("half op");
	else
	  minus = NULL;
	if (minus)
	  Add_Request (I_DIRECT, user->lname, F_T_NOTICE,
		       _("WOW, you are %s now..."), minus);
      }
      LISTFILEMODIFIED;
    }
    New_Request (dcc->iface, 0,
		 _("Global attributes for %s are now: %s."), user->lname,
		 userflagtostr (user->flag, plus));
    /* make change */
    userflagtostr (ufp, plus);
    minus = &plus[strlen(plus)+1];
    userflagtostr (ufm, minus);
    gl = &minus[strlen(minus)+1]; /* gl is free now so let it be plus service */
    ufp = ufm = 0;
  }
  else				/* no global attributes */
  {
    sv = gl;
    minus = plus;
    *plus = 0;
    gl = &plus[1];
  }
  *gl = 0;			/* gl contains ptr to change now */
  if (cf)			/* don't do checks if not permitted anyway */
  {
    parse_chattr (sv, &ufp, &ufm);
    DBG ("list.c:dc_chattr:arg3:%s:0x%08lx/0x%08lx", sv, (long)ufp, (long)ufm);
    for (chr = user->channels; chr && chr->cid != id; chr = chr->next);
    /* check permissions - U_SPECIAL is global only attribute */
    check_perm (chr ? chr->flag : 0, cf, U_SPECIAL, &ufp, &ufm);
    DBG ("list.c:dc_chattr:0x%08lx/0x%08lx->0x%08lx/0x%08lx",
	 chr ? (long)chr->flag : 0L, (long)cf, (long)ufp, (long)ufm);
  }
  else
    chr = NULL;			/* even don't show it! */
  if (cf && (ufp || ufm))
  {
    if (!chr)			/* create the channel record */
      chr = *(_add_channel (&user->channels, id));
    chr->flag |= ufp;		/* set userflags */
    chr->flag &= ~ufm;
    if (!chr->flag && !chr->greeting) /* delete empty channel record */
    {
      register user_chr *cc = user->channels;

      if (cc != chr)
	while (cc && cc->next != chr) cc = cc->next;
      if (cc == chr)
	user->channels = cc->next;
      else
	cc->next = chr->next;
      pthread_mutex_lock (&FLock);
      _R_f -= strlena (chr->greeting) + sizeof(user_chr);
      pthread_mutex_unlock (&FLock);
      DBG ("list.c:dc_chattr:deleting empty %s from %s.", Chan, user->lname);
      FREE (&chr->greeting);
      FREE (&chr);
    }
    userflagtostr (ufp, gl);
    sv = &gl[strlen(gl)+1];	/* sv is also free so let it be minus service */
    userflagtostr (ufm, sv);
    /* notice the user if on partyline */
    if (ufm & U_OWNER)
      args = _("owner");
    else if (ufm & U_MASTER)
      args = _("master");
    else if (ufm & U_OP)
      args = _("operator");
    else if (ufm & U_HALFOP)
      args = _("half op");
    else
      args = NULL;
    if (args)
      Add_Request (I_DIRECT, user->lname, F_T_NOTICE,
		   _("OOPS, you are not %s on %s anymore..."), args, Chan);
    if (ufp & U_OWNER)
      args = _("owner");
    else if (ufp & U_MASTER)
      args = _("master");
    else if (ufp & U_OP)
      args = _("operator");
    else if (ufp & U_HALFOP)
      args = _("half op");
    else
      args = NULL;
    if (args)
      Add_Request (I_DIRECT, user->lname, F_T_NOTICE,
		   _("WOW, you are %s on %s now..."), args, Chan);
    LISTFILEMODIFIED;
  }
  else
    sv = gl;			/* reset to empty line */
  /* send changes to shared bots */
  if (!(user->flag & (U_SPECIAL | U_UNSHARED)))	/* specials are not shared */
  {
    if (*Chan && (*gl || *sv))
      Add_Request (I_DIRECT, "@*", F_SHARE, "\010chattr %s %s%s%s%s|%s%s%s%s %s",
		   user->lname, *plus ? "+" : "", plus, *minus ? "-" : "",
		   minus, *gl ? "+" : "", gl, *sv ? "-" : "", sv, Chan);
    else if (*plus || *minus)
      Add_Request (I_DIRECT, "@*", F_SHARE, "\010chattr %s %s%s%s%s",
		   user->lname, *plus ? "+" : "", plus, *minus ? "-" : "", minus);
  }
  if (*Chan && chr)
    New_Request (dcc->iface, 0,
		 _("Channel attributes for %s on %s are now: %s."),
		 user->lname, Chan, userflagtostr (chr->flag, plus));
  pthread_mutex_unlock (&user->mutex);
  return 1;
}

BINDING_TYPE_dcc (dc__phost);
static int dc__phost (struct peer_t *dcc, char *args)
{
  struct clrec_t *user;
  char *lname = args;

  if (!args)
    return 0;
  while (*args && *args != ' ') args++;
  if (!*args)
    return 0;				/* no hostmask */
  *args = 0;
  user = _findbylname (lname);
  *args = ' ';
  if (!user)				/* no user */
    return 0;
  args = NextWord (args);
  if (strlen (args) < 5 || match ("*.*", args) < 0) /* validation of hostmask */
  {
    New_Request (dcc->iface, 0, "Invalid hostmask pattern: %s", args);
    return 0;
  }
  _add_usermask (user, args);
  if (!(user->flag & (U_SPECIAL | U_UNSHARED)))	/* specials are not shared */
    Add_Request (I_DIRECT, "@*", F_SHARE, "\010+host %s %s", user->lname, args);
  return 1;
}

BINDING_TYPE_dcc (dc__mhost);
static int dc__mhost (struct peer_t *dcc, char *args)
{
  struct clrec_t *user;
  char *lname = args;

  if (!args)
    return 0;
  while (*args && *args != ' ') args++;
  if (!*args)
    return 0;				/* no hostmask */
  *args = 0;
  user = _findbylname (lname);
  *args = ' ';
  args = NextWord (args);
  if (!user || strlen (args) < 5)	/* no user or no hostmask */
    return 0;
  _del_usermask (user, args);
  if (!(user->flag & (U_SPECIAL | U_UNSHARED)))	/* specials are not shared */
    Add_Request (I_DIRECT, "@*", F_SHARE, "\010-host %s %s", user->lname, args);
  return 1;
}

BINDING_TYPE_dcc (dc__puser);
static int dc__puser (struct peer_t *dcc, char *args)
{
  register int i;
  char *net = args;
  char *lname = args, *mask, *attr;
  userflag uf;

  if (!args)
    return 0;
  StrTrim (args);
  if (*net == '-' && net[1] != ' ')
  {
    lname = NextWord (args);
    for (attr = lname; *attr && *attr != ' ' && *attr != '@'; attr++);
    if (*attr == '@')		/* networks should not have '@' in name */
      return 0;
    args = lname;
    for (attr = ++net; *attr != ' '; attr++);
    *attr = 0;			/* get the token */
  }
  else
  {
    lname = args;
    net = NULL;
  }
  if (lname[0] == 0)		/* empty login name is invalid */
    return 0;
  attr = mask = NextWord (lname);
  if (*mask)
    while (*args != ' ') args++;
  else
    args = mask;
  *args = 0;			/* get next token */
  if (!net && (net = strrchr (lname, '@')))
  {
    if (!_findbylname (++net))	/* check for channel@net */
    {
      New_Request (dcc->iface, 0, _("Cannot add name: network does not exist."));
      return 0;
    }
  }
  while (*attr && *attr != ' ') attr++;
  if (*attr)
    *attr = 0;
  else
    attr = NULL;		/* yet another token */
  uf = attr ? strtouserflag (&attr[1], NULL) : 0;
  i = Add_Clientrecord (lname, (strlen (mask) > 4) ? mask : NULL,
			(net ? U_SPECIAL : 0) | uf);	/* validate host */
  if (attr)
    *attr = ' ';		/* release last token */
  if (i && net && net < lname)	/* only when we are adding networks */
  {
    struct clrec_t *u = Lock_Clientrecord (lname);

    pthread_mutex_lock (&FLock);
    _R_f += safe_strlen (net) + 1;
    pthread_mutex_unlock (&FLock);
    u->logout = safe_strdup (net);
    Unlock_Clientrecord (u);
  }
  if (*mask)
    *args = ' ';		/* release hostmask token */
  if (!i)			/* error */
    New_Request (dcc->iface, 0, _("Cannot add user: invalid or already exist."));
  else if (!net && !(uf & U_UNSHARED))	/* specials are not shared */
    Add_Request (I_DIRECT, "@*", F_SHARE, "\010+name %s", lname);
  return i;
}

BINDING_TYPE_dcc (dc__muser);
static int dc__muser (struct peer_t *dcc, char *args)
{
  struct clrec_t *user;
  userflag uf;

  rw_wrlock (&UFLock);
  if (!args || !(user = _findbylname (args)))
  {
    rw_unlock (&UFLock);
    if (args)
      New_Request (dcc->iface, 0, _("Name %s does not exist."), args);
    return 0;
  }
  uf = user->flag;
  _delete_userrecord (user, 1);
  Add_Request (I_LOG, "*", F_USERS, _("Deleted name %s."), args);
  if (!(uf & (U_SPECIAL | U_UNSHARED)))	/* specials are not shared */
    Add_Request (I_DIRECT, "@*", F_SHARE, "\010-name %s", args);
  return 1;
}

static struct bindtable_t *BT_Pass = NULL;

static int user_chpass (const char *pass, char **crypted)
{
  char *spass = NULL;			/* generate a new passwd */
  register struct binding_t *bind = NULL, *bind2 = NULL;
  int i;

  while ((bind2 = Check_Bindtable (BT_Pass, "*", U_ALL, U_ANYCH, bind)))
    bind = bind2;
  if (bind->name)			/* find the last algorithm :) */
    return 0;
  i = 0 - strlena (*crypted);
  FREE (crypted);
  if (pass && *pass)
  {
    bind->func (pass, &spass);
    i += strlena (spass);
    *crypted = safe_strdup (spass);
  }
  pthread_mutex_lock (&FLock);
  _R_f += i;
  pthread_mutex_unlock (&FLock);
  return 1;
}

BINDING_TYPE_dcc (dc_passwd);
static int dc_passwd (struct peer_t *dcc, char *args)
{
  register struct clrec_t *user;
  int i;

  if (!args)					/* don't allow to remove */
    return 0;
  user = _findbylname (dcc->iface->name);
  if (user->flag & U_ALIAS)			/* oh.. but it may not be */
    user = user->u.owner;
  pthread_mutex_lock (&user->mutex);
  LISTFILEMODIFIED;
  if ((i = user_chpass (args, &user->passwd)) &&
      !(user->flag & (U_SPECIAL | U_UNSHARED)))	/* specials are not shared */
    Add_Request (I_DIRECT, "@*", F_SHARE, "\013%s %s", user->lname,
		 NONULL(user->passwd));
  pthread_mutex_unlock (&user->mutex);
  if (!i)
    New_Request (dcc->iface, 0, "Password changing error!");
  else
    Add_Request (I_LOG, "*", F_USERS, "#%s# passwd [something]",
		 dcc->iface->name);
  return (-1);
}

BINDING_TYPE_dcc (dc_chpass);
static int dc_chpass (struct peer_t *dcc, char *args)
{
  register struct clrec_t *user;
  register char *lname = args;
  int i;

  StrTrim (args);
  if (!args)
    return 0;
  while (*args && *args != ' ') args++;
  if (*args)
    *args++ = 0;
  while (*args == ' ') args++;
  user = _findbylname (lname);
  if (user && (user->flag & U_ALIAS))
    user = user->u.owner;
  if (user)
    pthread_mutex_lock (&user->mutex);
  else
    return 0;
  LISTFILEMODIFIED;
  if ((i = user_chpass (args, &user->passwd)) &&
      !(user->flag & (U_SPECIAL | U_UNSHARED)))	/* specials are not shared */
    Add_Request (I_DIRECT, "@*", F_SHARE, "\013%s %s", lname, NONULL(user->passwd));
  pthread_mutex_unlock (&user->mutex);
  if (!i)
    New_Request (dcc->iface, 0, "Password changing error!");
  else if (user->passwd)
    Add_Request (I_LOG, "*", F_USERS, "#%s# chpass %s [something]",
		 dcc->iface->name, lname);
  else
  {
    Add_Request (I_LOG, "*", F_USERS, "#%s# chpass %s [nothing]",
		 dcc->iface->name, lname);
    New_Request (dcc->iface, 0, _("Password for %s erased."), lname);
  }
  return (-1);
}

BINDING_TYPE_dcc (dc_nick);
static int dc_nick (struct peer_t *dcc, char *args)
{
  char *oldname = safe_strdup (dcc->iface->name);
  register int i;

  if ((i = Change_Lname (args, oldname)) &&	/* specials are not shared */
      !(Get_Clientflags (args, NULL) & (U_SPECIAL | U_UNSHARED)))
    Add_Request (I_DIRECT, "@*", F_SHARE, "\010chln %s %s", oldname, args);
  FREE (&oldname);
  return i;
}

BINDING_TYPE_dcc (dc_chnick);
static int dc_chnick (struct peer_t *dcc, char *args)
{
  char *oldname = args;
  char *newname = NextWord (args);
  register int i;

  if (!(oldname = args) || !(newname = gettoken (args, &args)))
    return 0;
  if (!(dcc->uf & U_OWNER) &&
      (Get_Clientflags(oldname, NULL) & (U_SPECIAL | U_MASTER))) {
    New_Request(dcc->iface, F_T_NOTICE, _("Permission denied."));
    Add_Request(I_LOG, "*", F_WARN,
		"Attempt to change nick %s by %s failed: not permitted.",
		oldname, dcc->iface->name);
    *args = ' ';
    return (-1);
  }
  i = Change_Lname (newname, oldname);
  *args = ' ';
  if (i && !(Get_Clientflags (newname, NULL) & (U_SPECIAL | U_UNSHARED)))
    Add_Request (I_DIRECT, "@*", F_SHARE, "\010chln %s", oldname);
  return i;
}

BINDING_TYPE_dcc (dc_reload);
static int dc_reload (struct peer_t *dcc, char *args)
{
  /* can use Listfile variable - I hope iface locked now */
  if (_load_listfile (Listfile, 0))
    New_Request (dcc->iface, 0, _("Cannot load userfile!"));
  return 1;
}

BINDING_TYPE_dcc (dc_save);
static int dc_save (struct peer_t *dcc, char *args)
{
  /* can use Listfile variable - I hope iface locked now */
  if (_save_listfile (Listfile, 0))
    New_Request (dcc->iface, 0, _("Cannot save userfile!"));
  return 1;
}

/*--- UFLock write --- no other locks ---*/
static void _catch_undeleted (void *ptr)
{
  ERROR ("list.c:_catch_undeleted: not empty record found: %s",
	 ((struct clrec_t *)ptr)->lclname);
  _delete_userrecord (ptr, 0);
}

static INTERFACE *ListfileIface = NULL;

char *IFInit_Users (void)
{
  /* do cleanup if this was restart */
  if (ListfileIface)
  {
    struct clrec_t *ur;
    lid_t lid = LID_MIN;
    register int i, _f;

    userfile_signal (ListfileIface, S_TERMINATE);
    rw_wrlock (&UFLock);
    do {
      if ((ur = UList[lid - LID_MIN]) != NULL)
	_delete_userrecord (ur, 0);
    } while (lid++ != LID_MAX);
    /* I hope it's all correct and UTree is empty */
    Destroy_Tree (&UTree, _catch_undeleted);
    rw_unlock (&UFLock);
    rwlock_destroy (&UFLock);
    rwlock_destroy (&HLock);
    _f = _R_f - _Falloc * sizeof(char *);
    for (i = 0; i < _Fnum; i++)
      _f -= strlena (Field[i]);
    /* check if our statistics went to 0 */
    if (_R_r || _R_s || _R_d || _R_i || _R_h || _R_n || _f)
      WARNING ("list.c: bad cleanup: %zd/%zd/%zd/%zd/%zd/%zd/%d", _R_r, _R_s, _R_d,
	       _R_i, _R_h, _R_n, _f);
  }
  rwlock_init (&UFLock, USYNC_THREAD, NULL);
  rwlock_init (&HLock, USYNC_THREAD, NULL);
  /* empty userlist and LIDs bitmap */
  memset (UList, 0, sizeof(UList));
  memset (LidsBitmap, 0, sizeof(LidsBitmap));
  /* create bot userrecord */
  _add_userrecord ("", U_UNSHARED, ID_ME);
  /* load userfile and set it as unmodified ;) */
  if (_load_listfile (Listfile, 0))
    return (_("Cannot load userfile!"));
  _savetime = 0;
  ListfileIface = Add_Iface (I_FILE, NULL, &userfile_signal, NULL, NULL);
  /* sheduler itself will refresh Listfile every minute so it's all */
  /* get crypt bindtable address */
  BT_Pass = Add_Bindtable ("passwd", B_UNDEF);
  BT_ChLname = Add_Bindtable ("new-lname", B_MASK);
  /* add dcc bindings */
  Add_Binding ("dcc", "chattr", U_HALFOP, U_MASTER, &dc_chattr, NULL);
  Add_Binding ("dcc", "+name", U_MASTER, U_MASTER, &dc__puser, NULL);
  Add_Binding ("dcc", "-name", U_MASTER, U_NONE, &dc__muser, NULL);
  Add_Binding ("dcc", "+host", U_MASTER, U_MASTER, &dc__phost, NULL);
  Add_Binding ("dcc", "-host", U_MASTER, U_MASTER, &dc__mhost, NULL);
  Add_Binding ("dcc", "passwd", U_ACCESS, U_NONE, &dc_passwd, NULL);
  Add_Binding ("dcc", "chpass", U_MASTER, U_MASTER, &dc_chpass, NULL);
  Add_Binding ("dcc", "lname", U_ACCESS, U_NONE, &dc_nick, NULL);
  Add_Binding ("dcc", "chln", U_MASTER, U_NONE, &dc_chnick, NULL);
  Add_Binding ("dcc", "reload", U_MASTER, U_NONE, &dc_reload, NULL);
  Add_Binding ("dcc", "save", U_MASTER, U_NONE, &dc_save, NULL);
  return (NULL);
}
