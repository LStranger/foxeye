/*
 * Copyright (C) 1999-2006  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 * Here is userrecords control and upgrade.
 */

#include "foxeye.h"

#include "list.h"
#include "wtmp.h"
#include "init.h"
#include "tree.h"
#include "direct.h"

#ifndef HAVE_RWLOCK_INIT
# include "rwlock_init.h"
#endif

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

struct USERRECORD
{
  lid_t uid;
  userflag flag;
  char *lname;
  char *lclname;
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
  time_t created;
  user_fr *fields;
  pthread_mutex_t mutex;
};

static NODE *UTree = NULL;		/* list of USERRECORDs */
static clrec_t *UList[LID_MAX-LID_MIN+1];

static bindtable_t *BT_ChLname;

static time_t _savetime = 0;

#define LISTFILEMODIFIED if (!_savetime) _savetime = Time;

static char _Userflags[] = USERFLAG;

/* ----------------------------------------------------------------------------
 * userflag <-> string conversions
 */

char *userflagtostr (userflag uf, char *flstr)
{
  register char *fl = _Userflags;
  register char *str = flstr;
  register userflag ufmask = 1;

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

static userflag strtouserflag (const char *str)
{
  register userflag uf = 0;
  register char *ch;

  for (; *str; str++)
    if ((ch = strchr (_Userflags, *str)))
      uf |= 1<<(ch-_Userflags);
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

/*
 * Usersfile manipulation functions
 */

/*--- W --- HLock write ---*/
static int _addhost (user_hr **hr, const char *uh)
{
  size_t sz;
  user_hr *h = *hr;

  sz = safe_strlen ((char *)uh) + 1;
  if (sz < 5)		/* at least *!i@* :) */
    return 0;
  *hr = safe_calloc (1, sz + sizeof(user_hr *));
  strfcpy ((*hr)->hostmask, uh, sz);
  (*hr)->next = h;
  return 1;
}

/*--- W --- HLock write ---*/
static void _delhost (user_hr **hr)
{
  user_hr *h = *hr;

  *hr = h->next;
  FREE (&h);
}

/*--- RW --- UFLock read ---*/
static clrec_t *_findbylname (const char *lname)
{
  char lclname[NAMEMAX+1];

  safe_strlower (lclname, lname, sizeof(lclname));
  return Find_Key (UTree, lclname);
}

/*--- R --- UFLock read --- no HLock ---*/
static clrec_t *_findthebest (const char *mask, clrec_t *prefer)
{
  clrec_t *u, *user = NULL;
  user_hr *hr;
  int n, p = 0, matched = 0;
  lid_t lid;

  rw_rdlock (&HLock);
  lid = LID_MIN;
  do {
    if ((u = UList[lid - LID_MIN]) && !(u->flag & (U_SPECIAL|U_ALIAS)))
    /* pseudo-users hosts are not masks */
      for (hr = u->host; hr; hr = hr->next)
      {
	n = match ((char *)hr->hostmask, mask);
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
static int _add_usermask (clrec_t *user, const char *mask)
{
  user_hr *hr;
  user_hr **h;
  int r;
  char lcmask[HOSTMASKLEN+1];

  safe_strlower (lcmask, mask, sizeof(lcmask));  
  /* check for aliases */
  if (user->flag & U_ALIAS)	/* no need lock since threads has R/O access */
    user = user->u.owner;
  rw_wrlock (&HLock);
  for (hr = user->host; hr; hr = hr->next)
  {
    if (match (hr->hostmask, lcmask) > 0)
      return 0;			/* this mask is more common, nothing to do */
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
static int _del_usermask (clrec_t *user, const char *mask)
{
  user_hr **h;
  int i = 0;
  char lcmask[HOSTMASKLEN+1];

  safe_strlower (lcmask, mask, sizeof(lcmask));  
  /* check for aliases */
  if (user->flag & U_ALIAS)
    user = user->u.owner;
  rw_wrlock (&HLock);
  /* check if any my masks are matched this and erase it */
  for (h = &user->host; *h; )
  {
    if (match (lcmask, (*h)->hostmask) > 0)
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
  if (id != ID_ANY)
    j = (start-LID_MIN)%32;
  else if (start < 0)			/* bans grows down */
  {
    j = i;
    im = (end-LID_MIN)/32;
    jm = (end-LID_MIN)%32;
    while (i >= im && ~(LidsBitmap[i]) == 0) i--;
    if (i < 0)
      return ID_ME;
    if (i == j)
      j = (start-LID_MIN)%32;
    else
      j = 31;
    while (j >= 0 && (LidsBitmap[i] & (1<<j))) j--;
    if (j < 0 || (i == im && j < jm))
      return ID_ME;
  }
  else					/* all other grows up */
  {
    j = i;
    im = (end-LID_MIN)/32;
    jm = (end-LID_MIN)%32;
    while (i <= im && ~(LidsBitmap[i]) == 0) i++;
    if (i > im)
      return ID_ME;
    if (i == j)
      j = (start-LID_MIN)%32;
    else
      j = 0;
    while (j < 32 && (LidsBitmap[i] & (1<<j))) j++;
    if (j == 32 || (i == im && j > jm))
      return ID_ME;
  }
  LidsBitmap[i] |= (1<<j);
  dprint (3, "users:__addlid: %d %d %d --> %d:%d",
	  (int)id, (int)start, (int)end, i, j);
  return (i*32 + j + LID_MIN);
}

#define _add_lid(id,u) UList[id-LID_MIN] = u;

/*--- W --- UFLock write ---*/
static void __dellid (lid_t id)
{
  LidsBitmap[(id-LID_MIN)/32] &= ~(1<<((id-LID_MIN)%32));
  dprint (3, "users:__dellid: %d", (int)id);
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

  if (i == 0 || i > LNAMELEN) return (-1);
  return match ("{^" SPECIALCHARS RESTRICTEDCHARS "}", a);
}

static int spname_valid (const char *a)
{
  register int i = safe_strlen (a);

  if (i == 0 || i > IFNAMEMAX) return (-1);
  return match ("[" SPECIALCHARS "]{^" RESTRICTEDCHARS "}", a);
}

/*--- W --- UFLock write ---*/
static clrec_t *_add_userrecord (const char *name, userflag uf, lid_t id)
{
  clrec_t *user = NULL;
  int i;

  if (!(name || id < ID_REM) || _findbylname (name))
    i = -1;
  else if (uf & U_SPECIAL)
    i = spname_valid (name);
  else if (name)
    i = usernick_valid (name);
  else
    i = 0;
  if (!i)
  {
    user = safe_calloc (1, sizeof(clrec_t));
    /* set fields */
    user->lname = safe_strdup (name);
    i = safe_strlen (name);
    user->lclname = safe_malloc (i+1);	/* never NULL */
    safe_strlower (user->lclname, name, i+1);
    user->flag = uf;
    if (!(uf & U_SPECIAL))
      user->flag |= U_ANY;
    if (id != ID_ANY)			/* specified id */
      user->uid = __addlid (id, id, id);
    else if (!name)			/* ban */
      user->uid = __addlid (id, ID_REM, LID_MIN);
    else if (uf & U_SPECIAL)		/* special client record */
      user->uid = __addlid (id, ID_ME+1, ID_ANY-1);
    else				/* regular user */
      user->uid = __addlid (id, ID_ANY+1, LID_MAX);
    if (id == ID_ME || user->uid != ID_ME)
    {
      if (name)
	i = Insert_Key (&UTree, user->lclname, user, 1);
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
  LISTFILEMODIFIED;
  return user;
}

static void _del_aliases (clrec_t *);

/*--- W --- UFLock write --- no HLock ---*/
static void _delete_userrecord (clrec_t *user, int to_unlock)
{
  user_chr *chr;
  user_fr *f;

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
  pthread_mutex_unlock (&user->mutex);	/* it's unavaiable now */
  pthread_mutex_destroy (&user->mutex);
  if (to_unlock)			/* no locks need now */
    rw_unlock (&UFLock);
  while (user->host)
    _delhost (&user->host);
  user->progress = 0;
  for (chr = user->channels; chr; )
  {
    FREE (&chr->greeting);
    user->channels = chr->next;
    FREE (&chr);
    chr = user->channels;
  }
  FREE (&user->lname);
  FREE (&user->lclname);
  FREE (&user->passwd);
  FREE (&user->charset);
  FREE (&user->login);
  FREE (&user->logout);
  if (!(user->flag & U_ALIAS))
    FREE (&user->u.info);
  while ((f = user->fields))
  {
    FREE (&f->value);
    user->fields = f->next;
    FREE (&f);
  }
  FREE (&user);
  LISTFILEMODIFIED;
}

/*--- W --- UFLock write ---*/
static void _add_aliases (clrec_t *owner, char *list)
{
  char n[LNAMELEN+1];
  register char *c;
  clrec_t *ur;

  while (*list)
  {
    strfcpy (n, list, sizeof(n));
    list = NextWord (list);
    for (c = n; *c && *c != ' '; c++);
    *c = 0;
    if (_findbylname (n))
      continue;
    ur = _add_userrecord (n, U_ALIAS, owner->uid);
    ur->created = Time;
    ur->u.owner = owner;
  }
}

/*--- W --- UFLock write --- no HLock ---*/
static void _del_aliases (clrec_t *owner)
{
  register clrec_t *ur;
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
  clrec_t *user = NULL;
  char flags[64];			/* I hope, it enough for 18 flags :) */

  /* we cannot add alias with this! */
  if (uf & U_ALIAS)
    return 0;
  /* create the structure */
  if (name && !name[0])
    name = NULL;
  rw_wrlock (&UFLock);
  user = _add_userrecord (name, uf, name ? ID_ANY : ID_REM - 1); /* client/ban */
  if (!user)
  {
    rw_unlock (&UFLock);
    return 0;
  }
  user->created = Time;
  if (mask)			/* don't lock it, it's unreachable yet */
    _add_usermask (user, (char *)mask);
  rw_unlock (&UFLock);
  if (uf)
    Add_Request (I_LOG, "*", F_USERS, _("Added name %s with flag(s) %s."),
		 name, userflagtostr (uf, flags));
  else
    Add_Request (I_LOG, "*", F_USERS, _("Added name %s."), name);
  /* all OK */
  return 1;
}

/*--- W --- no locks ---*/
int Add_Alias (const char *name, const char *hname)
{
  register clrec_t *user = NULL, *owner;

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
  clrec_t *user;

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
}

/*--- W --- no locks ---*/
int Change_Lname (char *newname, char *oldname)
{
  clrec_t *user;
  binding_t *bind = NULL;
  int i;

  /* check if oldname exist */
  rw_wrlock (&UFLock);
  user = _findbylname (oldname);
  /* check if newname is valid */
  if (!user || usernick_valid (newname) < 0 || _findbylname (newname))
  {
    rw_unlock (&UFLock);
    return 0;
  }
  /* rename user record */
  Delete_Key (UTree, user->lclname, user);
  FREE (&user->lclname);
  pthread_mutex_lock (&user->mutex);
  FREE (&user->lname);
  user->lname = safe_strdup (newname);
  pthread_mutex_unlock (&user->mutex);
  i = safe_strlen (newname);
  user->lclname = safe_malloc (i+1);
  safe_strlower (user->lclname, newname, i+1);
  i = Insert_Key (&UTree, user->lclname, user, 1);
  rw_unlock (&UFLock);
  if (i < 0)
    Add_Request (I_LOG, "*", F_ERROR,
	    "change Lname %s -> %s: hash error, Lname lost!", oldname, newname);
  LISTFILEMODIFIED;
  /* rename the DCC CHAT interface if exist */
  Rename_Iface (I_DIRECT, oldname, newname);
  dprint (1, "changing Lname: %s -> %s", oldname, newname);
  /* run "new-lname" bindtable */
  while ((bind = Check_Bindtable (BT_ChLname, oldname, -1, -1, bind)))
  {
    if (bind->name)
      RunBinding (bind, NULL, oldname, newname, -1, NULL);
    else
      bind->func (newname, oldname);
  }
  return 1;
}

/*--- R --- no locks ---*/
lid_t GetLID (const char *lname)
{
  clrec_t *user;
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
  dprint (3, "users:GetLID: %s -> %d", lname, (int)id);
  return id;
}

static int _add_to_list (INTERFACE *iface, char *buf, size_t *len, char *msg)
{
  int n = 0;
  size_t l = strlen(msg);

  dprint (4, "_add_to_list: %s", msg);
  if (*len + l > MESSAGEMAX-2)
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

/*--- W --- no locks ---*/
int Get_Clientlist (INTERFACE *iface, userflag uf, const char *fn, char *mask)
{
  char buf[MESSAGEMAX];
  size_t len;
  lid_t lid;
  clrec_t *u;
  user_hr *h;
  int n;
  char lcmask[HOSTMASKLEN+1];

  if (!mask || !*mask || !uf || !iface)
    return 0;
  safe_strlower (lcmask, mask, sizeof(lcmask));  
  n = 0;
  len = 0;
  lid = LID_MIN;
  do {
    if ((u = UList[lid - LID_MIN]) && (u->flag & uf))
    {
      if (fn != NULL)				/* field granted */
      {
	if (match (lcmask, Get_Field (u, fn, NULL)) >= 0)
	  n += _add_to_list (iface, buf, &len, u->lname);
      }
      else				/* NULL means check lname and host */
      {
	if (match (lcmask, u->lclname) >= 0)
	  n += _add_to_list (iface, buf, &len, u->lname);
	else for (h = u->host; h; h = h->next)
	  if (match (lcmask, h->hostmask) > 0)
	  {
	    n += _add_to_list (iface, buf, &len, u->lname);
	    break;
	  }
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
int Get_Hostlist (INTERFACE *iface, const char *name)
{
  char buf[MESSAGEMAX];
  size_t len;
  clrec_t *u;
  user_hr *h;
  int n = 0;

  if (!name || !*name || !iface)
    return n;
  dprint (3, "Get_Hostlist: check for %s", name);
  u = _findbylname (name);	/* no need write lock here, func is read only */
  if (u == NULL)
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

/* ----------------------------------------------------------------------------
 * Thread-safe functions.
 */

/*--- R lock --- UFLock read --- no HLock ---*/
static clrec_t *_findbymask (const uchar *mask)
{
  user_hr *hr;
  char buff[STRING];
  char *c1 = "";
  char *c2 = "";
  lid_t lid;
  clrec_t *u;

  /* set up the mask */
  if (!safe_strchr ((char *)mask, '!'))
  {
    c1 = "*!";
    if (!safe_strchr ((char *)mask, '@'))
      c2 = "*@";
  }
  snprintf (buff, sizeof(buff), "%s%s%s", c1, c2, mask);
  rw_rdlock (&HLock);
  /* find first matched */
  lid = LID_MIN;
  do {
    if ((u = UList[lid - LID_MIN]) && !(u->flag & (U_SPECIAL|U_ALIAS)))
      for (hr = u->host; hr; hr = hr->next)	/* I hope no need to lock? */
	if (match (buff, hr->hostmask) > 0)
	{
	  rw_unlock (&HLock);
	  return u;
	}
  } while (lid++ != LID_MAX);
  rw_unlock (&HLock);
  return NULL;
}

/*--- RW --- UFLock read --- no FLock ---*/
static lid_t _get_index (const char *field)
{
  lid_t i;

  if (!*field)
    return R_CONSOLE;
  else if (strchr (SPECIALCHARS, *field))
  {
    clrec_t *ur = _findbylname (field);
    if (ur)
      return ur->uid;
    else
      return R_NO;
  }
  else
  {
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
}

/*--- R --- no locks ---*/
/* returns UFLock locked if found */
clrec_t *Find_Clientrecord (const uchar *mask, char **lname, userflag *uf,
			    char *net)
{
  clrec_t *user = NULL;
  int wc = Have_Wildcard ((char *)mask) + 1;

  if (!mask || !*mask)
    return NULL;
  /* find the userrecord */
  rw_rdlock (&UFLock);
  if (wc)
    user = _findbymask (mask);
  else				/* if mask is hostmask - find best */
    user = _findthebest ((char *)mask, NULL);
  if (user)
  {
    pthread_mutex_lock (&user->mutex);
    if (lname)
      *lname = user->lname;
    if (uf)
    {
      if (net != NULL && *net == '@')
      {
	register user_chr *c;
	register lid_t i = _get_index (net);

	for (c = user->channels; c; c = c->next)
	  if (c->cid == i)
	    break;
	*uf = (user->flag & U_GLOBALS) | (c ? c->flag : 0);
      }
      else
	*uf = user->flag;
    }
  }
  else
    rw_unlock (&UFLock);
  return user;
}

/*--- RW --- no locks ---*/
/* returns UFLock locked if found */
clrec_t *Lock_Clientrecord (const char *name)
{
  clrec_t *user;

  rw_rdlock (&UFLock);
  user = _findbylname (name);
  if (user)
  {
    if (user->flag & U_ALIAS)
      user = user->u.owner;
    pthread_mutex_lock (&user->mutex);
    return user;
  }
  rw_unlock (&UFLock);
  return user;
}

/*--- RW --- UFLock read and built-in --- no other locks ---*/
void Unlock_Clientrecord (clrec_t *user)
{
  if (!user)
    return;
  pthread_mutex_unlock (&user->mutex);
  rw_unlock (&UFLock);
}

/*--- R --- UFLock read and built-in --- no other locks ---*/
char *Get_Field (clrec_t *user, const char *field, time_t *ctime)
{
  lid_t i;
  user_fr *f;
  user_chr *c;

  if (field == NULL)
  {
    if (ctime)
      *ctime = user->created;
    return user->lname;
  }
  i = _get_index (field);			/* OOPS!!! unlocked access!!! */
  if (i == R_CONSOLE || i > FIELDSMAX)		/* channel */
  {
    for (c = user->channels; c; c = c->next)
      if (c->cid == i)
      {
	if (ctime)
	  *ctime = c->expire;
	return (c->greeting);
      }
    return NULL;
  }
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

static user_chr *_add_channel (user_chr **chr, lid_t i)
{
  register user_chr *c = safe_calloc (1, sizeof(user_chr));

  c->next = *chr;
  *chr = c;
  c->cid = i;
  return c;
}

/*
 * note: call of Set_Field (user, "alias", something);
 * will do not change Listfile (delete old & add new aliases)
 * so you must do it yourself
 */
/*--- W --- UFLock read and built-in --- no other locks ---*/
int Set_Field (clrec_t *user, const char *field, const char *val)
{
  lid_t i;
  user_fr *f;
  user_chr *chr;
  char **c;

  /* we cannot modify Lname with this! */
  if (field == NULL)
    return 0;
  i = _get_index (field);
  chr = NULL;
  c = NULL;
  if (i == R_CONSOLE || i > FIELDSMAX)		/* channel */
  {
    for (chr = user->channels; chr; chr = chr->next)
      if (chr->cid == i)
	break;
    if (!val && !*val && chr && !chr->flag)
    {
      register user_chr *cc = user->channels;

      if (cc != chr)			/* delete empty channel record */
	while (cc && cc->next != chr) cc = cc->next;
      if (cc == chr)
	user->channels = cc->next;
      else
	cc->next = chr->next;
      FREE (&chr->greeting);
      FREE (&chr);
      return 1;
    }
    if (!chr)
      chr = _add_channel (&user->channels, i);
    if (chr)
      c = &chr->greeting;
  }
  else switch (i)
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
	  FREE (&f->value);
	  FREE (&f);
	  return 1;
	}
	c = &f->value;
      }
  }
  if (!c && val && *val)		/* create new field */
  {
    pthread_mutex_lock (&FLock);
    if (i == R_NO && _Fnum < FIELDSMAX && !strchr (SPECIALCHARS, *field))
    {
      if (_Fnum == _Falloc)
      {
	_Falloc += 16;
	safe_realloc ((void **)&Field, (_Falloc) * (sizeof(char *)));
      }
      Field[_Fnum] = safe_strdup (field);
      i = _Fnum++;
    }
    pthread_mutex_unlock (&FLock);
    if (i != R_NO)
    {
      f = user->fields;
      if (f)
      {
	while (f->next) f = f->next;
	f->next = safe_calloc (1, sizeof(user_fr));
	f->next->id = i;
	c = &f->next->value;
      }
      else
      {
	f = user->fields = safe_calloc (1, sizeof(user_fr));
	f->id = i;
	c = &f->value;
      }
    }
  }
  if (!c)
    return 0;
  FREE (c);
  *c = safe_strdup (val);
  LISTFILEMODIFIED;		/* cannot use mutex but value isn't critical */
  return 1;
}

/*
 * almost the same as Set_Field() but adds value to existing field
 */
/*--- W --- UFLock and built-in --- no other locks ---*/
int Grow_Field (clrec_t *user, const char *field, const char *val)
{
  char result[STRING];
  char *f;

  /* we cannot modify Lname with this! */
  if (field == NULL)
    return 0;
  f = Get_Field (user, field, NULL);
  if (f == NULL)
    return Set_Field (user, field, val);
  if (safe_strlen (f) + safe_strlen (val) + 2 > sizeof(result))
    return 0;
  strcpy (result, f);
  strfcat (result, " ", sizeof(result));
  strfcat (result, val, sizeof(result));
  return Set_Field (user, field, result);
}

/*--- R --- no locks ---*/
userflag Match_Client (char *domain, char *ident, const char *lname)
{
  userflag uf = 0;
  clrec_t *ur = NULL;
  user_hr *hr;
  char uhost[STRING];
  char c = '@';

  if (!domain || !*domain)		/* empty domain is nonsence! :) */
    return uf;
  if (ident && *ident)			/* prepare the hostmask */
  {
    snprintf (uhost, sizeof(uhost), "!%s@%s", ident, domain);
    c = '!';
  }
  else
    snprintf (uhost, sizeof(uhost), "@%s", domain);
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
  dprint (3, "users:Match_User: %s!%s@%s%s, found flags 0x%x", NONULL(lname),
	  NONULL(ident), domain, ur ? " (records found)" : "", uf);
  return uf;
}

/*--- R --- UFLock and built-in --- no other locks ---*/
userflag Get_Flags (clrec_t *user, const char *serv)
{
  userflag uf;

  if (!user)
    return 0;
  if (!serv)
    uf = user->flag;
  else if (strchr (SPECIALCHARS, *serv))
  {
    register lid_t i = _get_index (serv);
    register user_chr *c = user->channels;

    for (; c; c = c->next)
      if (c->cid == i)
	break;
    if (*serv == '@')
      uf = (user->flag & U_GLOBALS) | (c ? c->flag : 0);
    else
      uf = c->flag;
  }
  else
    uf = 0;
  return uf;
}

/*--- R --- no locks ---*/
userflag Get_Clientflags (const char *lname, const char *serv)
{
  clrec_t *user;
  userflag uf;

  rw_rdlock (&UFLock);
  user = _findbylname (lname);
  if (user)
  {
    if (user->flag & U_ALIAS)	/* unaliasing */
      user = user->u.owner;
    pthread_mutex_lock (&user->mutex);
  }
  uf = Get_Flags (user, serv);
  rw_unlock (&UFLock);
  pthread_mutex_unlock (&user->mutex);
  return uf;
}

/*--- W --- UFLock and built-in --- no other locks ---*/
int Add_Mask (clrec_t *user, const uchar *mask)
{
  int i = 0;

  if (!user || !mask) return 0;
  pthread_mutex_unlock (&user->mutex);		/* unlock to avoid conflicts */
  i = _add_usermask (user, (char *)mask);
  pthread_mutex_lock (&user->mutex);
  return i;
}

/*--- W --- UFLock and built-in --- no other locks ---*/
void Delete_Mask (clrec_t *user, const uchar *mask)
{
  if (!mask) return;
  pthread_mutex_unlock (&user->mutex);		/* unlock to avoid conflicts */
  _del_usermask (user, (char *)mask);
  pthread_mutex_lock (&user->mutex);
}

/*--- W --- no locks ---*/
static unsigned int _scan_lids (lid_t start, lid_t end)
{
  register int i, j;
  int k;
  register unsigned int n = 0;

  i = start/32 - LID_MIN/32;
  k = (end+1)/32 - LID_MIN/32;
  for (; i < k; i++)
  {
    for (j = 0; j < 32; j++)
      if (LidsBitmap[i] & (1<<j))
	n++;
  }
  return n;
}

/*--- W --- no locks ---*/
void Status_Clients (INTERFACE *iface)
{
  unsigned int a, c, d;
  
  a = _scan_lids ((LID_MIN/32)*32, ID_REM-1);
  c = _scan_lids (ID_ME+1, ID_ANY-1);
  d = _scan_lids (ID_ANY+1, LID_MAX);
  New_Request (iface, 0, "Listfile: %u bans, %u servers, %u users. Total: %u names",
	       a, c, d, a+c+d);
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

static FILE *_check_listfile (char *filename, char *buff, size_t s)
{
  register FILE *fp;

  fp = fopen (filename, "r");
  buff[0] = 0;
  if (fp)
  {
    fseek (fp, -11L, SEEK_END);
    fread (buff, 1, 11, fp);
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
 * load mode:
 *	reset all
 * update mode: (users that have U_UNSHARED flag and special will be skipped)
 *	reset common: flag, uid, passwd, info, created, host, aliases
 *	update (if found): special fields
 *	don't touch local fields: log(in|out), charset
 * (note: we trust to the caller, it have check listfile to don't erase own)
 */
/*--- W --- no locks ---*/
static int _load_listfile (char *filename, int update)
{
  char buff[HUGE_STRING];
  char ffn[LONG_STRING];
  clrec_t *ur;
  FILE *fp;
  char *c, *v, *cc = NULL;
  unsigned int _a, _u, _r, _k;			/* add, update, remove, keep */
  lid_t lid;

  if (O_MAKEFILES)
    return 0;
  filename = (char *)expand_path (ffn, filename, sizeof(ffn));
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
	if (ur && (!update || !(ur->flag & (U_UNSHARED|U_SPECIAL))))
	  _add_usermask (ur, ++c);
	break;
      case 0:				/* empty line ignored */
      case '#':				/* an comment */
	break;
      case ' ':				/* a field */
	if (!ur || (update && (ur->flag & (U_UNSHARED|U_SPECIAL))))
	  break;
	v = NextWord (++c);
	while (*c && *c != ' ') c++;
	*c = 0;				/* break a field and value */
	c = &buff[1];
	_next_field (&c);
	Set_Field (ur, &buff[1], v); /* set the field */
	if (*c)				/* check if field is console/channel */
	{
	  lid_t i = _get_index (&buff[1]);	/* parse */
	  user_chr *ch;

	  for (ch = ur->channels; ch && ch->cid != i; ch = ch->next);
	  if (!ch)
	    break;
	  ch->flag = strtouserflag (_next_field (&c));
	  ch->expire = (time_t) strtol (c, NULL, 10);
	}
	else if (!strcasecmp (&buff[1], "alias"))
	  _add_aliases (ur, v);
	break;
      case '\\':			/* skip if next char if one of "#+\" */
	if (strchr ("#+\\", buff[1]))
	  c++;
      default:				/* new user record */
	v = c;
	if (ur)
	{
	  ur->progress = 0;		/* finish updating of previous */
	  pthread_mutex_unlock (&ur->mutex);
	}
	if (!strcmp (buff, ":::::::::"))	/* it is EOF */
	{
	  lid = LID_MIN;
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
	  } while (lid++ != LID_MAX);
	  LISTFILEMODIFIED;
	  rw_unlock (&UFLock);
	  Add_Request (I_LOG, "*", F_BOOT,
		"Loaded %s: %u records added, %u updated, %u removed, %u keeped.",
		filename, _a, _u, _r, _k);
	  fclose (fp);
	  return 0;
	}
	/* only owner has Lname "", all other NULL or non-empty */
	if (cc && *c == ':')
	{
	  ur = NULL;
	  v = NULL;
	  *c++ = 0;						/* 1 */
	}
	else
	/* find the user and empty it */
	  ur = _findbylname (_next_field (&c));			/* 1 */
	cc = _next_field (&c);					/* 2 */
	if (ur)
	{
	  user_hr *hr;
	  lid_t uid;

	  pthread_mutex_lock (&ur->mutex);
	  if (update && (ur->flag & (U_UNSHARED|U_SPECIAL)))
	  {
	    /* Lid can be erased by init so force it */
	    LidsBitmap[(ur->uid-LID_MIN)/32] |= 1<<((ur->uid-LID_MIN)%32);
	    UList[ur->uid-LID_MIN] = ur;
	    _k++;
	    break;
	  }
	  _u++;
	  _del_aliases (ur);		/* remove all aliases */
	  uid = ur->uid;
	  ur->uid = (lid_t) strtol (_next_field (&c), NULL, 10);/* 3 */
	  if (uid != ur->uid)		/* hmmm, UIDs was renumbered? */
	    NewEvent (W_CHG, uid, ur->uid, 0);	/* uid -> ur->uid */
	  /* Lid can be erased by init so force it */
	  LidsBitmap[(ur->uid-LID_MIN)/32] |= 1<<((ur->uid-LID_MIN)%32);
	  UList[ur->uid-LID_MIN] = ur;
	  rw_wrlock (&HLock);
	  while (ur->host)
	  {
	    hr = ur->host;
	    ur->host = hr->next;
	    FREE (&hr);
	  }
	  rw_unlock (&HLock);
	}
	/* or create new user record */
	else if ((ur = _add_userrecord (v,			/* 3 */
				spname_valid (v) < 0 ? 0 : U_SPECIAL,
				(lid_t) strtol (_next_field (&c), NULL, 10))))
	{
	  _a++;
	  pthread_mutex_lock (&ur->mutex);
	}
	else
	{
	  /* TODO: errors logging... */
	  break;
	}
	/* parse the fields and fill user record */
	FREE (&ur->passwd);
	FREE (&ur->u.info);
	ur->passwd = safe_strdup (cc);
	ur->flag = strtouserflag (_next_field (&c));		/* 4 */
	if (strchr (SPECIALCHARS, v[0]))
	  ur->flag |= U_SPECIAL;
	ur->u.info = safe_strdup (_next_field (&c));		/* 5 */
	if (!update)		/* rest ignored when update */
	{
	  user_chr *chr;
	  user_fr *fr;

	  FREE (&ur->charset);
	  FREE (&ur->login);
	  FREE (&ur->logout);
	  ur->charset = safe_strdup (_next_field (&c));		/* 6 */
	  ur->login = safe_strdup (_next_field (&c));		/* 7 */
	  ur->logout = safe_strdup (_next_field (&c));		/* 8 */
	  while (ur->channels)
	  {
	    chr = ur->channels;
	    ur->channels = chr->next;
	    FREE (&chr->greeting);
	    FREE (&chr);
	  }
	  while (ur->fields)
	  {
	    fr = ur->fields;
	    ur->fields = fr->next;
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
	dprint (4, "Got info for %s user %s:%s%s info=%s created=%lu",
		(ur->flag & U_SPECIAL) ? "special" : "normal", ur->lname,
		(ur->flag & U_SPECIAL) ? " network=" : "",
		(ur->flag & U_SPECIAL) ? ur->logout : "", NONULL(ur->u.info),
		ur->created);
	ur->progress = 1;
    }
  }
  if (ur)
    pthread_mutex_unlock (&ur->mutex);	/* finish updating of previous */
  LISTFILEMODIFIED;
  rw_unlock (&UFLock);
  Add_Request (I_LOG, "*", F_BOOT,
	       "Unexpected EOF at %s: %u records added, %u updated, %u keeped.",
	       filename, _a, _u, _k);
  fclose (fp);
  return -1;
}

/*--- W --- no locks ---*/
int Merge_Listfile (char *path)
{
  return _load_listfile (path, 1);
}

static int _write_listfile (char *str, FILE *fp)
{
  size_t sz = safe_strlen (str);
  if (fwrite (str, 1, sz, fp) != sz)
    return 0;
  return 1;
}

/*--- W --- no locks ---*/
static int _save_listfile (char *filename, int quiet)
{
  FILE *fp;
  clrec_t *ur;
  user_hr *hr;
  user_chr *chr;
  user_fr *fr;
  char buff[HUGE_STRING];
  char ffn[LONG_STRING];
  char f[64];				/* I hope it's enough for 19 flags :) */
  int i = 0;
  unsigned int _r, _b, _s;		/* regular, bot, special */
  lid_t lid;

  filename = (char *)expand_path (ffn, filename, sizeof(ffn));
  snprintf (buff, sizeof(buff), "%s~", filename);
  unlink (buff);
  rename (filename, buff);			/* creating backup */
  fp = fopen (filename, "w");
  _r = _b = _s = 0;
  if (fp)
  {
    _savetime = 0;
    i = fprintf (fp, "#FEU: Generated by bot \"%s\" on %s", Nick, ctime (&Time));
    lid = LID_MIN;
    do
    {
      if (!(ur = UList[lid - LID_MIN]) || (ur->flag & U_ALIAS))
	continue;
      if (ur->flag & U_SPECIAL)
	_s++;
      else if (ur->flag & U_BOT)
	_b++;
      else if (ur->uid)
	_r++;
      snprintf (buff, sizeof(buff), "%s%s:%s:%d:%s:%s:%s:%s:%s:%lu\n",
		(ur->lname && strchr ("#+\\", ur->lname[0])) ? "\\" : "",
		NONULL(ur->lname), NONULL(ur->passwd), (int) ur->uid,
		userflagtostr (ur->flag, f), NONULL(ur->u.info),
		NONULL(ur->charset), NONULL(ur->login), NONULL(ur->logout),
		(unsigned long)ur->created);
      i = _write_listfile (buff, fp);
      for (hr = ur->host; hr && i; hr = hr->next)
      {
	snprintf (buff, sizeof(buff), "+%s\n", hr->hostmask);
	i = _write_listfile (buff, fp);
      }
      for (chr = ur->channels; chr && i; chr = chr->next)
      {
	if (chr->expire)		/* common or channel permanent ban */
	  snprintf (buff, sizeof(buff), " %s:%s:%lu %s\n",
		    (chr->cid == R_CONSOLE && UList[chr->cid]) ? "" : UList[chr->cid]->lname,
		    userflagtostr (chr->flag, f), (unsigned long)chr->expire,
		    NONULL(chr->greeting));
	else				/* console or channel record */
	  snprintf (buff, sizeof(buff), " %s:%s: %s\n",
		    (chr->cid == R_CONSOLE && UList[chr->cid]) ? "" : UList[chr->cid]->lname,
		    userflagtostr (chr->flag, f), NONULL(chr->greeting));
	i = _write_listfile (buff, fp);
      }
      for (fr = ur->fields; fr && i; fr = fr->next)
      {
	snprintf (buff, sizeof(buff), " %s %s\n", Field[fr->id], fr->value);
	i = _write_listfile (buff, fp);
      }
    } while (lid++ != LID_MAX);
    if (i) fwrite (":::::::::\n", 1, 10, fp);	/* empty record - checking */
    fclose (fp);
  }
  if (!i)
  {
    unlink (filename);				/* error - file corrupted */
    snprintf (buff, sizeof(buff), "%s~", filename);
    rename (buff, filename);			/* restoring from backup */
    return (-1);
  }
  Add_Request (I_LOG, "*", F_BOOT,
	       "Saved %s: %u regular, %u bots, and %u special records.",
	       filename, _r, _b, _s);
  return 0;
}

static iftype_t userfile_signal (INTERFACE *iface, ifsig_t signal)
{
  switch (signal)
  {
    case S_REPORT:
      /* oops, still in progress??? TODO! */
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
    default:
      iface->ift |= I_DIED;
      if (_savetime)
	_save_listfile (Listfile, signal == S_SHUTDOWN ? 1 : 0);
  }
  return 0;
}

/* all rest: --- W --- no locks ---*/
/* ----------------------------------------------------------------------------
 * Internal dcc bindings:
 * int func(peer_t *from, char *args)
 */

static void parse_chattr (register char *text, userflag *toset, userflag *tounset)
{
  int plus = 0;
  char here;
  char *last = NULL;
  userflag todo;

  while (*text)
  {
    text += strspn (text, "+- |");
    here = *text;
    *text = 0;
    if (last)
    {
      if (plus == 1)
      {
	todo = strtouserflag (last);
	*toset |= todo;
	*tounset &= ~todo;
      }
      else if (plus)
      {
	todo = strtouserflag (last);
	*tounset |= todo;
	*toset &= ~todo;
      }
    }
    *text++ = here;
    if (here == '+')
      plus = 1;
    else if (here == '-')
      plus = -1;
    else
      return;
    last = text;
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
    ufmask |= (U_OWNER | U_MASTER | U_SPEAK | U_UNSHARED);
    testuf = U_OWNER | U_MASTER;
  }
  else
    testuf = 0;
  if (!(by & U_MASTER))			/* op or halfop */
  {
    ufmask |= (U_HALFOP | U_OP | U_AUTO | U_VOICE | U_QUIET | U_INVITE);
    testuf |= U_OP | U_HALFOP;
  }
  if (!(by & U_OP))			/* halfop */
  {
    ufmask |= (U_FRIEND | U_DEOP | U_BOT);
    testuf |= U_BOT;
  }
  if ((to & testuf) || !(by & U_HALFOP))
  {
    *toset = *tounset = 0;		/* seniority! */
    return;
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
static int dc_chattr (peer_t *dcc, char *args)
{
  userflag ufp, ufm;
  userflag uf, cf;
  lid_t id = R_NO;
  char *gl, *sv;
  char plus[64+4];			/* I hope it enough for 2*21 flags :) */
  char Chan[IFNAMEMAX+1];
  char *minus;
  clrec_t *user, *who;
  register user_chr *chr;

  if (!args)
    return 0;
  gl = safe_strchr (args, ' ');		/* get first word */
  if (gl)
    *gl = 0;
  user = _findbylname (args);		/* find the user */
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
    id = _get_index (user->lname);
  else if (*args && strchr (SPECIALCHARS, *args))
  {
    id = _get_index (args);		/* so we trying to change subflag? */
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
      id = _get_index (Chan);
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
  if (user->flag & U_SPECIAL)		/* only owners may change that */
  {
    uf = ((uf | cf) & U_OWNER);
    cf = 0;
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
    /* check permissions - any flag may be global/direct */
    check_perm (user->flag, uf, 0, &ufp, &ufm);
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
    for (chr = user->channels; chr && chr->cid != id; chr = chr->next);
    /* check permissions - U_BOT is global only attribute */
    check_perm (chr ? chr->flag : 0, cf, U_BOT, &ufp, &ufm);
  }
  else
    chr = NULL;			/* even don't show it! */
  if (cf && (ufp || ufm))
  {
    if (!chr)			/* create the channel record */
      chr = _add_channel (&user->channels, id);
    chr->flag |= ufp;		/* set userflags */
    chr->flag &= ~ufm;
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
    if (args);
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
    if (args);
      Add_Request (I_DIRECT, user->lname, F_T_NOTICE,
		   _("WOW, you are %s on %s now..."), args, Chan);
  }
  else
    sv = gl;			/* reset to empty line */
  if (*Chan && chr)
    New_Request (dcc->iface, 0,
		 _("Channel attributes for %s on %s are now: %s."),
		 user->lname, Chan, userflagtostr (chr->flag, plus));
  /* send changes to shared bots */
  if (*Chan && (*gl || *sv))
    Add_Request (I_DIRECT, "@*", F_SHARE, "\010chattr %s %s%s%s%s|%s%s%s%s %s",
		 user->lname, *plus ? "+" : "", plus, *minus ? "-" : "", minus,
		 *gl ? "+" : "", gl, *sv ? "-" : "", sv, Chan);
  else if (*plus || *minus)
    Add_Request (I_DIRECT, "@*", F_SHARE, "\010chattr %s %s%s%s%s",
		 user->lname, *plus ? "+" : "", plus, *minus ? "-" : "", minus);
  pthread_mutex_unlock (&user->mutex);
  return 1;
}

static int dc__phost (peer_t *dcc, char *args)
{
  clrec_t *user;
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
  _add_usermask (user, args);
  Add_Request (I_DIRECT, "@*", F_SHARE, "\010+host %s %s", user->lname, args);
  return 1;
}

static int dc__mhost (peer_t *dcc, char *args)
{
  clrec_t *user;
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
  Add_Request (I_DIRECT, "@*", F_SHARE, "\010-host %s %s", user->lname, args);
  return 1;
}

static int dc__puser (peer_t *dcc, char *args)
{
  register int i;
  char *net = args;
  char *lname = args, *mask, *attr;

  if (!args)
    return 0;
  StrTrim (args);
  if (*net == '-' && net[1] != ' ')
  {
    lname = NextWord (args);
    if (lname[0] != '@')	/* only networks may be added with this! */
      return 0;
    net++;
    args = lname;
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
  *args = 0;
  while (*attr && *attr != ' ') attr++;
  if (*attr)
    *attr = 0;
  else
    attr = NULL;
  i = Add_Clientrecord (lname, (uchar *)mask, (net ? U_SPECIAL : 0) +
			(attr ? strtouserflag (&attr[1]) : 0));
  if (attr)
    *attr = ' ';
  if (i && net)
  {
    clrec_t *u = Lock_Clientrecord (lname);

    for (attr = net; *attr != ' '; attr++);
    *attr = 0;
    u->logout = safe_strdup (net);
    Unlock_Clientrecord (u);
    *attr = ' ';
  }
  if (*mask)
    *args = ' ';
  if (i)
    Add_Request (I_DIRECT, "@*", F_SHARE, "\010+user %s", net ? net : lname);
  else
    New_Request (dcc->iface, 0, _("Cannot add user: invalid or already exist."));
  return i;
}

static int dc__muser (peer_t *dcc, char *args)
{
  clrec_t *user;

  rw_wrlock (&UFLock);
  if (!args || !(user = _findbylname (args)))
  {
    rw_unlock (&UFLock);
    return 0;
  }
  _delete_userrecord (user, 1);
  Add_Request (I_LOG, "*", F_USERS, _("Deleted name %s."), args);
  Add_Request (I_DIRECT, "@*", F_SHARE, "\010-user %s", args);
  return 1;
}

static bindtable_t *BT_Pass = NULL;

static int user_chpass (const char *pass, char **crypted)
{
  char *spass = NULL;			/* generate a new passwd */
  register binding_t *bind = NULL, *bind2 = NULL;

  while ((bind2 = Check_Bindtable (BT_Pass, "*", -1, -1, bind)))
    bind = bind2;
  if (bind->name)			/* find the last algorithm :) */
    return 0;
  FREE (crypted);
  if (pass && *pass)
  {
    bind->func (pass, &spass);
    *crypted = safe_strdup (spass);
  }
  return 1;
}

static int dc_passwd (peer_t *dcc, char *args)
{
  register clrec_t *user;
  int i;

  if (!args)					/* don't allow to remove */
    return 0;
  user = _findbylname (dcc->iface->name);
  if (user->flag & U_ALIAS)			/* oh.. but it may not be */
    user = user->u.owner;
  pthread_mutex_lock (&user->mutex);
  LISTFILEMODIFIED;
  i = user_chpass (args, &user->passwd);
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

static int dc_chpass (peer_t *dcc, char *args)
{
  register clrec_t *user;
  register char *lname = args;
  int i;

  StrTrim (args);
  if (!args || !*args)
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
  if ((i = user_chpass (args, &user->passwd)))
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

static int dc_nick (peer_t *dcc, char *args)
{
  char *oldname = safe_strdup (dcc->iface->name);
  register int i;

  StrTrim (args);
  if ((i = Change_Lname (args, oldname)))
    Add_Request (I_DIRECT, "@*", F_SHARE, "\010chln %s %s", oldname, args);
  FREE (&oldname);
  return i;
}

static int dc_chnick (peer_t *dcc, char *args)
{
  char *oldname = args;
  char *newname = NextWord (args);
  register int i;

  if (!args || !*newname)
    return 0;
  while (*args != ' ') args++;
  *args = 0;
  StrTrim (args);
  i = Change_Lname (newname, oldname);
  *args = ' ';
  if (i)
    Add_Request (I_DIRECT, "@*", F_SHARE, "\010chln %s", oldname);
  return i;
}

static int dc_reload (peer_t *dcc, char *args)
{
  /* can use Listfile variable - I hope iface locked now */
  if (_load_listfile (Listfile, 0))
    New_Request (dcc->iface, 0, _("Cannot load userfile!"));
  return 1;
}

static int dc_save (peer_t *dcc, char *args)
{
  /* can use Listfile variable - I hope iface locked now */
  if (_save_listfile (Listfile, 0))
    New_Request (dcc->iface, 0, _("Cannot save userfile!"));
  return 1;
}

static INTERFACE *ListfileIface = NULL;

char *IFInit_Users (void)
{
  if (ListfileIface)
    userfile_signal (ListfileIface, S_TERMINATE);
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
  ListfileIface = Add_Iface (NULL, I_FILE, &userfile_signal, NULL, NULL);
  /* sheduler itself will refresh Listfile every minute so it's all */
  /* get crypt bindtable address */
  BT_Pass = Add_Bindtable ("passwd", B_UNDEF);
  BT_ChLname = Add_Bindtable ("new-lname", B_MASK);
  /* add dcc bindings */
  Add_Binding ("dcc", "chattr", U_HALFOP, U_MASTER, &dc_chattr);
  Add_Binding ("dcc", "+user", U_MASTER, U_MASTER, &dc__puser);
  Add_Binding ("dcc", "-user", U_MASTER, -1, &dc__muser);
  Add_Binding ("dcc", "+host", U_MASTER, U_MASTER, &dc__phost);
  Add_Binding ("dcc", "-host", U_MASTER, U_MASTER, &dc__mhost);
  Add_Binding ("dcc", "passwd", U_ACCESS, -1, &dc_passwd);
  Add_Binding ("dcc", "chpass", U_MASTER, U_MASTER, &dc_chpass);
  Add_Binding ("dcc", "lname", U_ACCESS, -1, &dc_nick);
  Add_Binding ("dcc", "chln", U_MASTER, -1, &dc_chnick);
  Add_Binding ("dcc", "reload", U_MASTER, -1, &dc_reload);
  Add_Binding ("dcc", "save", U_MASTER, -1, &dc_save);
  return (NULL);
}
