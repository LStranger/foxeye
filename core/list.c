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
 *
 * Here is userrecords control and upgrade.
 */

#include "foxeye.h"

#include "users.h"
#include "init.h"
#include "tree.h"
#include "dcc.h"

static NODE *UTree = NULL;		/* list of USERRECORDs */
static USERRECORD *FirstUser = NULL;
static USERRECORD *LastUser = NULL;

static char **Field = NULL;		/* list of fields and channels */
static lid_t _Fnum = 0;
static lid_t _Falloc = 0;

BINDTABLE *BT_ChLname;

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
    if ((ch = safe_strchr (_Userflags, *str)))
      uf |= 1<<(ch-_Userflags);
  return uf;
}

/* ----------------------------------------------------------------------------
 * Async-unsafe functions. Lock only when to change. Part I: internal
 *  (assumed UserFileLock is locked)
 */

/*
 * mutexes:
 * UserFileLock: FirstUser, LastUser, _savetime, ->host, ->progress, ->lname,
 *		 ->rfcname, ->prev, ->uid
 * FLock: Field, _Fnum, _Falloc
 * built-in: ->fields, ->channels, ->flag, ->dccdir, ->passwd, ->u.info, ->log*
 * UserFileLock or built-in when read, both when write: ->next
 * UserFileLock or FLock when read, both when write: UTree
 */

pthread_mutex_t UserFileLock = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t FLock = PTHREAD_MUTEX_INITIALIZER;	/* Field & UTree */

/*
 * Usersfile manipulation functions
 */

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

static void _delhost (user_hr **hr)
{
  user_hr *h = *hr;

  *hr = h->next;
  FREE (&h);
}

/* assumed UserFileLock or FLock locked */
static USERRECORD *_findbylname (const char *lname)
{
  char rfcname[LNAMELEN+1];

  strfcpy (rfcname, NONULL(lname), sizeof(rfcname));
  rfc2812_strlower (rfcname);
  return Find_Key (UTree, rfcname);
}

static USERRECORD *_findthebest (const char *mask, USERRECORD *prefer)
{
  USERRECORD *u, *user = NULL;
  user_hr *hr;
  int n, p = 0, matched = 0;

  for (u = FirstUser; u; u = u->next)
  {
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
  }
  if (p && p == matched)
    return prefer;
  return user;
}

static int _add_usermask (USERRECORD *user, const char *mask)
{
  user_hr *hr;
  user_hr **h;

  /* check for aliases */
  if (user->flag & U_ALIAS)
    user = user->u.owner;
  /* userfile is locked now */
  for (hr = user->host; hr; hr = hr->next)
  {
    if (match (hr->hostmask, mask) > 0)
      return 0;			/* this mask is more common, nothing to do */
  }
  /* check if any my masks are matched this and erase it */
  for (h = &user->host; *h; )
  {
    if (match (mask, (*h)->hostmask) > 0)	/* overwrite it */
      _delhost (h);
    else
      h = &(*h)->next;
  }
  LISTFILEMODIFIED;
  if (!user->progress)
    Add_Request (I_LOG, "*", F_USERS, _("Added hostmask %s for name %s."),
		 mask, user->lname);
  return _addhost (h, mask);
}

static int _del_usermask (USERRECORD *user, const char *mask)
{
  user_hr **h;
  int i = 0;

  /* check for aliases */
  if (user->flag & U_ALIAS)
    user = user->u.owner;
  /* check if any my masks are matched this and erase it */
  for (h = &user->host; *h; )
  {
    if (match (mask, (*h)->hostmask) > 0)
    {
      _delhost (h);
      i++;
    }
    else
      h = &(*h)->next;
  }
  if (i != 0 && !user->progress)
    Add_Request (I_LOG, "*", F_USERS, _("Deleted hostmask %s from name %s."),
		 mask, user->lname);
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
#define R_DCCDIR	-7
#define R_ALIAS		-8
#define R_CONSOLE	-9		/* console - "" */

#define FIELDSMAX	ID_CHANN	/* last index for userfield */

static uint32_t LidsBitmap[(LID_MAX+31)/32-LID_MIN/32];

/*
 * create new lid with class or fixed id
 * returns new lid or 0 if no available
 */

static lid_t __addlid (lid_t id, lid_t start, lid_t end)
{
  register int i, j;

  i = start/32 - LID_MIN/32;
  if (id == start)
    j = start%32;
  else
  {
    j = (end+1)/32 - LID_MIN/32;
    if (start < 0)			/* bans grows down */
      while (i >= 0 && ~(LidsBitmap[i]) == 0) i--;
    else				/* all other grows up */
      while (i < j && ~(LidsBitmap[i]) == 0) i++;
    if (i < 0 || i >= j)
      return 0;
    j = 0;
    while (j < 32 && (LidsBitmap[i] & (1<<j))) j++;
  }
  LidsBitmap[i] |= (1<<j);
  dprint (4, "users:__addlid: %d %d %d --> %d:%d",
	  (int)id, (int)start, (int)end, i, j);
  return ((i+LID_MIN/32)*32 + j);
}

static void __dellid (lid_t id)
{
  LidsBitmap[(id-LID_MIN)/32] &= ~(1<<((id-LID_MIN)%32));
  dprint (4, "users:__dellid: %d", (int)id);
}

static void _del_lid (lid_t id, int old)
{
  __dellid (id);
  if (id && old)			/* delete references to it from Wtmp */
    ChangeUid (id, ID_REM);
}

static int usernick_valid (const char *a)
{
  register int i = safe_strlen (a);

  if (i == 0 || i > LNAMELEN) return (-1);
  return match ("{^" RESTRICTEDCHARS "}", a);
}

static int spname_valid (const char *a)
{
  register int i = safe_strlen (a);

  if (i == 0 || i > IFNAMEMAX) return (-1);
  return match ("[" SPECIALCHARS "]{^" RESTRICTEDCHARS "}", a);
}

static USERRECORD *_add_userrecord (const char *name, userflag uf, lid_t id)
{
  USERRECORD *user = NULL;
  int i = 0;

  if ((!name && !(uf & U_KILL) && id >= ID_REM) || _findbylname (name))
    i = -1;
  else if (uf & U_SPECIAL)
    i = spname_valid (name);
  else
    i = usernick_valid (name);
  if (!i)
  {
    user = safe_calloc (1, sizeof(USERRECORD));
    /* set fields */
    user->lname = safe_strdup (name);
    user->rfcname = safe_strdup (name);
    user->flag = uf;
    if (!(uf & U_SPECIAL))
      user->flag |= U_ANY;
    rfc2812_strlower (user->rfcname);
    if (uf & U_SPECIAL)			/* channel */
      user->uid = __addlid (id, ID_CHANN, ID_FIRST-1);
    else if (uf & U_BOT)		/* bot */
      user->uid = __addlid (id, ID_BOT, ID_CHANN-1);
    else if (!name)			/* ban */
      user->uid = __addlid (id, ID_REM, ID_REM-1);
    else				/* regular user */
      user->uid = __addlid (id, ID_FIRST, LID_MAX);
    if (user->uid)
    {
      if (name)
      {
	pthread_mutex_lock (&FLock);
	i = Insert_Key (&UTree, user->rfcname, user, 1);
	pthread_mutex_unlock (&FLock);
      }
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
      FREE (&user->rfcname);
      FREE (&user);
    }
    return NULL;
  }
  pthread_mutex_init (&user->mutex, NULL);
  /* don't lock it because listfile is locked and nobody can access it */
  if (LastUser)
  {
    pthread_mutex_lock (&LastUser->mutex); /* lock for Find_User() */
    LastUser->next = user;
    pthread_mutex_unlock (&LastUser->mutex);
  }
  user->prev = LastUser;
  LastUser = user;
  if (FirstUser == NULL)
    FirstUser = user;
  LISTFILEMODIFIED;
  return user;
}

static void _del_aliases (USERRECORD *);

static void _delete_userrecord (USERRECORD *user, int to_unlock)
{
  user_chr *chr;
  user_fr *f;

  if (!user)
    return;
  pthread_mutex_lock (&FLock);
  Delete_Key (UTree, user->rfcname, user); /* delete from hash */
  pthread_mutex_unlock (&FLock);
  if (user->prev)			/* delete from list */
  {
    pthread_mutex_lock (&user->prev->mutex); /* lock for Find_User() */
    user->prev->next = user->next;
    pthread_mutex_unlock (&user->prev->mutex);
  }
  else
    FirstUser = user->next;
  if (user->next)
    user->next->prev = user->prev;
  else
    LastUser = user->prev;
  while (user->host)
    _del_usermask (user, user->host->hostmask);
  user->progress = 0;
  if (to_unlock)
    pthread_mutex_unlock (&UserFileLock);
  pthread_mutex_lock (&user->mutex);	/* just wait for release */
  for (chr = user->channels; chr; )
  {
    FREE (&chr->greeting);
    user->channels = chr->next;
    FREE (&chr);
    chr = user->channels;
  }
  FREE (&user->lname);
  FREE (&user->rfcname);
  FREE (&user->passwd);
  FREE (&user->charset);
  FREE (&user->login);
  FREE (&user->logout);
  FREE (&user->dccdir);
  if (!(user->flag & U_ALIAS))
  {
    _del_lid (user->uid, 1);
    FREE (&user->u.info);
  }
  for (f = user->fields; f; )
  {
    if (f->id == R_ALIAS)
      _del_aliases (user);
    FREE (&f->value);
    user->fields = f->next;
    FREE (&f);
    f = user->fields;
  }
  pthread_mutex_unlock (&user->mutex);
  pthread_mutex_destroy (&user->mutex);
  FREE (&user);
  LISTFILEMODIFIED;
}

static void _add_aliases (USERRECORD *owner, char *list)
{
  char n[LNAMELEN+1];
  register char *c;
  USERRECORD *ur;

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

static void _del_aliases (USERRECORD *owner)
{
  USERRECORD *ur;

  for (ur = FirstUser; ur; ur = ur->next)
    if ((ur->flag & U_ALIAS) && ur->u.owner == owner)
      _delete_userrecord (ur, 0);
}

/* ----------------------------------------------------------------------------
 * Async-unsafe functions. Part II: public
 */

int Add_Userrecord (const char *name, const uchar *mask, userflag uf)
{
  USERRECORD *user = NULL;
  char flags[64];			/* I hope, it enough for 18 flags :) */

  /* create the structure */
  if (name && !name[0])
    name = NULL;
  pthread_mutex_lock (&UserFileLock);
  user = _add_userrecord (name, uf, 0);
  if (!user)
  {
    pthread_mutex_unlock (&UserFileLock);
    return 0;
  }
  user->created = Time;
  if (mask)
    _add_usermask (user, (char *)mask);
  pthread_mutex_unlock (&UserFileLock);
  if (uf)
    Add_Request (I_LOG, "*", F_USERS, _("Added name %s with flag(s) %s."),
		 name, userflagtostr (uf, flags));
  else
    Add_Request (I_LOG, "*", F_USERS, _("Added name %s."), name);
  /* all OK */
  return 1;
}

int Add_Alias (const char *name, const char *hname)
{
  register USERRECORD *user = NULL, *owner;

  /* create the structure */
  pthread_mutex_lock (&UserFileLock);
  if ((owner = _findbylname (hname)))
    user = _add_userrecord (name, U_ALIAS, owner->uid);
  if (!user)
  {
    pthread_mutex_unlock (&UserFileLock);
    return 0;
  }
  user->created = Time;
  user->u.owner = owner;
  pthread_mutex_unlock (&UserFileLock);
  Add_Request (I_LOG, "*", F_USERS, _("Added alias %s for %s."), name, hname);
  /* all OK */
  return 1;
}

void Delete_Userrecord (const char *lname)
{
  USERRECORD *user;

  if (!lname)
    return;
  pthread_mutex_lock (&UserFileLock);
  if (!(user = _findbylname (lname)))
  {
    pthread_mutex_unlock (&UserFileLock);
    return;
  }
  _delete_userrecord (user, 1);
  CommitWtmp();
  Add_Request (I_LOG, "*", F_USERS, _("Deleted name %s."), lname);
}

int Add_Usermask (const char *lname, const uchar *mask)
{
  USERRECORD *user;
  int i = 0;

  user = _findbylname (lname);
  if (user && mask)
  {
    pthread_mutex_lock (&UserFileLock);
    i = _add_usermask (user, (char *)mask);
    pthread_mutex_unlock (&UserFileLock);
  }
  return i;
}

void Delete_Usermask (const char *lname, const uchar *mask)
{
  USERRECORD *user;

  user = _findbylname (lname);
  if (user && mask)
  {
    pthread_mutex_lock (&UserFileLock);
    _del_usermask (user, (char *)mask);
    pthread_mutex_unlock (&UserFileLock);
  }
}

int Change_Lname (char *newname, char *oldname)
{
  USERRECORD *user;
  BINDING *bind = NULL;

  /* check if oldname exist */
  user = _findbylname (oldname);
  /* check if newname is valid */
  if (!user || usernick_valid (newname) < 0 || _findbylname (newname))
    return 0;
  pthread_mutex_lock (&UserFileLock);
  pthread_mutex_lock (&FLock);
  /* rename user record */
  Delete_Key (UTree, user->rfcname, user);
  FREE (&user->lname);
  FREE (&user->rfcname);
  user->lname = safe_strdup (newname);
  user->rfcname = safe_strdup (newname);
  rfc2812_strlower (user->rfcname);
  if (Insert_Key (&UTree, user->rfcname, user, 1) < 0)
    dprint (1, "change Lname %s -> %s: hash error, Lname lost!", oldname, newname);
  LISTFILEMODIFIED;
  pthread_mutex_unlock (&UserFileLock);
  pthread_mutex_unlock (&FLock);
  /* rename the DCC CHAT interface if exist */
  Rename_Iface (I_CHAT, oldname, newname);
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

lid_t GetLID (const char *lname)
{
  USERRECORD *user;
  register lid_t id;

  if (!lname || !*lname)			/* own lid */
    return ID_BOT;
  pthread_mutex_lock (&FLock);
  user = _findbylname (lname);
  if (user) id = user->uid;
  else id = ID_REM;
  pthread_mutex_unlock (&FLock);
  dprint (4, "users:GetLID: %s -> %d", lname, (int)id);
  return id;
}

/* ----------------------------------------------------------------------------
 * Async-safe functions.
 */

/* two users is attempt to avoid deadlock...
 * userfile must be locked! */
static USERRECORD *_findbymask (const uchar *mask, USERRECORD *user,
				USERRECORD *user2)
{
  USERRECORD *ur;
  user_hr *hr;
  char buff[STRING];
  char *c1 = "";
  char *c2 = "";

  /* check for user */
  for (ur = FirstUser; ur && ur != user; ur = ur->next);
  if (!ur && user2)		/* user is dead? */
    for (ur = FirstUser; ur && ur != user2; ur = ur->next);
  if (!ur)		/* user2 is dead too? i'm sorry... */
    return NULL;
  /* OK, we will search... */
  if (ur == user)
    ur = ur->next;
  /* set up the mask */
  if (!safe_strchr ((char *)mask, '!'))
  {
    c1 = "*!";
    if (!safe_strchr ((char *)mask, '@'))
      c2 = "*@";
  }
  snprintf (buff, sizeof(buff), "%s%s%s", c1, c2, mask);
  /* find next */
  for (; ur; ur = ur->next)
  {
    for (hr = ur->host; hr; hr = hr->next)
      if (match (buff, hr->hostmask) > 0)
	return ur;
  }
  return NULL;
}

void *Find_User (const uchar *mask, char **lname, userflag *uf, void *prev)
{
  USERRECORD *user = NULL;
  int wc = Have_Wildcard ((char *)mask) + 1;

  /* unlock previous */
  if (prev)
  {
    user = ((USERRECORD *)prev)->next;
    pthread_mutex_unlock (&((USERRECORD *)prev)->mutex);
  }
  if (!mask || !*mask)
    return NULL;
  /* find the userrecord */
  pthread_mutex_lock (&UserFileLock);
  if (wc)
    user = _findbymask (mask, (USERRECORD *)prev, user);
  else				/* if mask is hostmask - find best */
    user = _findthebest ((char *)mask, NULL);
  if (user)
  {
    pthread_mutex_lock (&user->mutex);
    if (lname)
      *lname = user->lname;
    if (uf)
      *uf = user->flag;
  }
  pthread_mutex_unlock (&UserFileLock);
  return (void *)user;
}

void *Lock_User (const char *name)
{
  USERRECORD *user;

  pthread_mutex_lock (&UserFileLock);
  pthread_mutex_lock (&FLock);
  user = _findbylname (name);
  pthread_mutex_unlock (&FLock);
  if (user)
    pthread_mutex_lock (&user->mutex);
  pthread_mutex_unlock (&UserFileLock);
  return (void *)user;
}

void Unlock_User (void *user)
{
  if (user)
    pthread_mutex_unlock (&((USERRECORD *)user)->mutex);
}

static lid_t _get_index (const char *field)
{
  lid_t i;

  if (!field || !*field)
    return R_CONSOLE;
  else if (!strcasecmp (field, "passwd"))
    return R_PASSWD;
  else if (!strcasecmp (field, "info"))
    return R_INFO;
  else if (!strcasecmp (field, "charset"))
    return R_CHARSET;
  else if (!strcasecmp (field, ".login"))
    return R_LOGIN;
  else if (!strcasecmp (field, ".logout"))
    return R_LOGOUT;
  else if (!strcasecmp (field, "dccdir"))
    return R_DCCDIR;
  else if (!strcasecmp (field, "alias"))
    return R_ALIAS;
  pthread_mutex_lock (&FLock);
  if (strchr (SPECIALCHARS, *field))
  {
    USERRECORD *ur = _findbylname (field);
    if (ur)
      i = ur->uid;
    else
      i = R_NO;
  }
  else
  {
    i = 0;
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
  }
  pthread_mutex_unlock (&FLock);
  dprint (4, "users:_get_index: %s -> %d", field, (int)i);
  return i;
}

char *Get_Userfield (void *user, const char *field)
{
#define ur ((USERRECORD *)user)
  lid_t i = _get_index (field);
  user_fr *f;
  user_chr *c;

  /* check if this is alias */
  if (ur->flag & U_ALIAS)
    return NULL;
  if (i == R_CONSOLE || i > FIELDSMAX)		/* channel */
  {
    for (c = ur->channels; c; c = c->next)
      if (c->cid == i)
	return (c->greeting);
    return NULL;
  }
  switch (i)
  {
    case R_NO:
      break;
    case R_PASSWD:
      return ur->passwd;
    case R_INFO:
      return ur->u.info;
    case R_CHARSET:
      return ur->charset;
    case R_LOGIN:
      return ur->login;
    case R_LOGOUT:
      return ur->logout;
    case R_DCCDIR:
      return ur->dccdir;
    default:
      for (f = ur->fields; f; f = f->next)
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
 * notice: call of Set_Userfield (user, "alias", something);
 * will do not change Listfile (delete old & add new aliases)
 * so you must do it yourself
 */
int Set_Userfield (void *user, const char *field, char *val)
{
  lid_t i = _get_index (field);
  user_fr *f;
  user_chr *chr = NULL;
  char **c = NULL;

  /* check if this is alias */
  if (ur->flag & U_ALIAS)
    return 0;
  if (i == R_CONSOLE || i > FIELDSMAX)		/* channel */
  {
    for (chr = ur->channels; chr; chr = chr->next)
      if (chr->cid == i)
	break;
    if (!val && !*val && chr && !chr->flag)
    {
      register user_chr *cc = ur->channels;

      if (cc != chr)			/* delete empty channel record */
	while (cc && cc->next != chr) cc = cc->next;
      if (cc == chr)
	ur->channels = cc->next;
      else
	cc->next = chr->next;
      FREE (&chr->greeting);
      FREE (&chr);
      return 1;
    }
    if (!chr)
      chr = _add_channel (&ur->channels, i);
    if (chr)
      c = &chr->greeting;
  }
  else switch (i)
  {
    case R_PASSWD:
      c = &ur->passwd;
      break;
    case R_INFO:
      c = &ur->u.info;
      break;
    case R_CHARSET:
      c = &ur->charset;
      break;
    case R_LOGIN:
      c = &ur->login;
      break;
    case R_LOGOUT:
      c = &ur->logout;
      break;
    case R_DCCDIR:
      c = &ur->dccdir;
    case R_NO:
      break;
    default:
      for (f = ur->fields; f; f = f->next)
	if (f->id == i)
	  break;
      if (f)
      {
	if (!val || !*val)		/* delete the field record */
	{
	  user_fr *ff = ur->fields;

	  if (ff != f) for (; ff; ff = ff->next)
	    if (ff->next == f)
	      break;
	  if (ff == f)
	    ur->fields = f->next;
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
    if (i == R_NO && _Fnum < FIELDSMAX && !strchr (SPECIALCHARS, *field))
    {
      pthread_mutex_lock (&FLock);
      if (_Fnum == _Falloc)
      {
	_Falloc += 16;
	safe_realloc ((void **)&Field, (_Falloc) * (sizeof(char *)));
      }
      Field[_Fnum] = safe_strdup (field);
      i = _Fnum++;
      pthread_mutex_unlock (&FLock);
    }
    if (i != R_NO)
    {
      f = ur->fields;
      if (f)
      {
	while (f->next) f = f->next;
	f->next = safe_calloc (1, sizeof(user_fr));
	f->next->id = i;
	c = &f->next->value;
      }
      else
      {
	f = ur->fields = safe_calloc (1, sizeof(user_fr));
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
#undef ur
}

userflag Match_User (char *domain, char *ident, const char *lname)
{
  userflag uf = 0;
  USERRECORD *ur;
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
  pthread_mutex_lock (&UserFileLock);
  if (lname)				/* check only this user */
  {
    if ((ur = _findbylname (lname)))
      for (hr = ur->host; hr && !uf; hr = hr->next)
	if (match (safe_strchr (hr->hostmask, c), uhost) > 0)
	{
	  pthread_mutex_lock (&ur->mutex);
	  uf = ur->flag;
	  pthread_mutex_unlock (&ur->mutex);
	}
  }
  else					/* check whole userfile */
  {
    for (ur = FirstUser; ur; ur = ur->next)
      for (hr = ur->host; hr; hr = hr->next)
	if (match (safe_strchr (hr->hostmask, c), uhost) > 0)
	{
	  pthread_mutex_lock (&ur->mutex);
	  uf |= ur->flag;
	  pthread_mutex_unlock (&ur->mutex);
	}
  }
  pthread_mutex_unlock (&UserFileLock);
  dprint (5, "users:Match_User: %s!%s@%s, found flags 0x%x", NONULL(lname),
	  NONULL(ident), domain, uf);
  return uf;
}

userflag Get_ChanFlags (const char *lname, const char *chan)
{
  USERRECORD *user;
  userflag uf = 0;

  pthread_mutex_lock (&UserFileLock);
  user = _findbylname (lname);
  if (user)
    pthread_mutex_lock (&user->mutex);
  pthread_mutex_unlock (&UserFileLock);
  if (!user)
    return 0;
  if (!chan)
    uf = user->flag;
  else if (strchr (SPECIALCHARS, *chan))
  {
    register lid_t i = _get_index (chan);
    register user_chr *c = user->channels;

    for (; c; c = c->next)
      if (c->cid == i)
	break;
    if (c)
      uf = c->flag;
  }
  pthread_mutex_unlock (&user->mutex);
  return uf;
}

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

void Status_Users (INTERFACE *iface)
{
  unsigned int a, b, c, d;
  
  a = _scan_lids ((LID_MIN/32)*32, ID_REM-1);
  b = _scan_lids (ID_CHANN, ID_FIRST-1);
  c = _scan_lids (ID_BOT, ID_CHANN-1);
  d = _scan_lids (ID_FIRST, LID_MAX);
  New_Request (iface, 0, "Listfile: %u bans, %u channels, %u bots, %u users. Total: %u names",
	       a, b, c, d, a+b+c+d);
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

  fp = fopen (filename, "rb");
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
 *	don't touch local fields: log(in|out), dccdir, charset
 * (note: we trust to the caller, it have check listfile to don't erase own)
 */
static int _load_listfile (char *filename, int update)
{
  char buff[HUGE_STRING];
  char ffn[LONG_STRING];
  USERRECORD *ur;
  FILE *fp;
  char *c, *v, *cc = NULL;
  unsigned int _a, _u, _r, _k;			/* add, update, remove, keep */

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
  pthread_mutex_lock (&UserFileLock);
  for (ur = FirstUser; ur; ur = ur->next)
    ur->progress = 1;
  while (fgets (buff, sizeof(buff), fp))
  {
    c = buff;
    StrTrim (buff);
    switch (buff[0])
    {
      case '+':				/* a hostmask */
	if (ur && !(ur->flag & (U_UNSHARED|U_SPECIAL)))
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
	Set_Userfield (ur, &buff[1], v); /* set the field */
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
	if (ur && (!update || !(ur->flag & (U_UNSHARED|U_SPECIAL))))
	{
	  ur->progress = 0;		/* finish updating of previous */
	  pthread_mutex_unlock (&ur->mutex);
	}
	if (!strcmp (buff, ":::::::::"))	/* it is EOF */
	{
	  for (ur = FirstUser; ur; ur = ur->next)
	    if (ur->progress)
	    {
	      if (!update || !(ur->flag & (U_UNSHARED|U_SPECIAL)))
	      {
		_delete_userrecord (ur, 0);
		_r++;
	      }
	      else
		ur->progress = 0;
	    }
	  LISTFILEMODIFIED;
	  pthread_mutex_unlock (&UserFileLock);
	  Add_Request (I_LOG, "*", F_BOOT,
		"Loaded %s: %u records added, %u updated, %u removed, %u keeped.",
		filename, _a, _u, _r, _k);
	  fclose (fp);
	  CommitWtmp();
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

	  if (update && (ur->flag & (U_UNSHARED|U_SPECIAL)))
	  {
	    /* Lid can be erased by init so force it */
	    LidsBitmap[(ur->uid-LID_MIN)/32] |= 1<<((ur->uid-LID_MIN)%32);
	    _k++;
	    break;
	  }
	  _u++;
	  _del_aliases (ur);		/* remove all aliases */
	  uid = ur->uid;
	  ur->uid = (lid_t) strtol (_next_field (&c), NULL, 10);/* 3 */
	  if (uid != ur->uid)		/* hmmm, UIDs was renumbered? */
	    ChangeUid (uid, ur->uid);	/* uid -> ur->uid */
	  /* Lid can be erased by init so force it */
	  LidsBitmap[(ur->uid-LID_MIN)/32] |= 1<<((ur->uid-LID_MIN)%32);
	  while (ur->host)
	  {
	    hr = ur->host;
	    ur->host = hr->next;
	    FREE (&hr);
	  }
	}
	/* or create new user record */
	else if (!(ur = _add_userrecord (v, 0,			/* 3 */
				(lid_t) strtol (_next_field (&c), NULL, 10))))
	{
	  /* TODO: errors logging... */
	  break;
	}
	else
	  _a++;
	/* parse the fields and fill user record */
	pthread_mutex_lock (&ur->mutex);
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
	  FREE (&ur->dccdir);
	  FREE (&ur->login);
	  FREE (&ur->logout);
	  ur->charset = safe_strdup (_next_field (&c));		/* 6 */
	  ur->dccdir = safe_strdup (_next_field (&c));		/* 7 */
	  ur->login = safe_strdup (_next_field (&c));		/* 8 */
	  ur->logout = safe_strdup (_next_field (&c));		/* 9 */
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
	  _next_field (&c);
	}
	ur->created = (time_t) strtol (c, NULL, 10);		/* 10 */
	ur->progress = 1;
    }
  }
  if (ur && (!update || !(ur->flag & (U_UNSHARED|U_SPECIAL))))
    pthread_mutex_unlock (&ur->mutex);	/* finish updating of previous */
  LISTFILEMODIFIED;
  pthread_mutex_unlock (&UserFileLock);
  Add_Request (I_LOG, "*", F_BOOT,
	       "Unexpected EOF at %s: %u records added, %u updated, %u keeped.",
	       filename, _a, _u, _k);
  fclose (fp);
  CommitWtmp();
  return -1;
}

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

static int _save_listfile (char *filename, int quiet)
{
  FILE *fp;
  USERRECORD *ur;
  user_hr *hr;
  user_chr *chr;
  user_fr *fr;
  char buff[HUGE_STRING];
  char ffn[LONG_STRING];
  char f[64];				/* I hope it's enough for 19 flags :) */
  char *Chan[ID_FIRST-ID_CHANN];
  int i = 0;
  unsigned int _r, _b, _s;		/* regular, bot, special */

  filename = (char *)expand_path (ffn, filename, sizeof(ffn));
  snprintf (buff, sizeof(buff), "%s~", filename);
  unlink (buff);
  rename (filename, buff);			/* creating backup */
  fp = fopen (filename, "wb");
  _r = _b = _s = 0;
  if (fp)
  {
    pthread_mutex_lock (&UserFileLock);
    _savetime = 0;
    i = fprintf (fp, "#FEU: Generated by bot \"%s\" on %s", Nick, ctime (&Time));
    /* first step: save own and special records */
    for (ur = FirstUser; ur && i; ur = ur->next)
    {
      if ((ur->flag & U_ALIAS) || (!(ur->flag & U_SPECIAL) && ur->uid))
	continue;
      _s++;
      if (!quiet)
	pthread_mutex_lock (&ur->mutex);
      if (ur->uid)
	Chan[ur->uid-ID_CHANN] = ur->lname;
      snprintf (buff, sizeof(buff), "%s%s:%s:%d:%s:%s:%s:%s:%s:%lu\n",
		(ur->lname && strchr ("#+\\", ur->lname[0])) ? "\\" : "",
		NONULL(ur->lname), NONULL(ur->passwd), (int) ur->uid,
		userflagtostr (ur->flag, f), NONULL(ur->u.info),
		NONULL(ur->dccdir), NONULL(ur->login), NONULL(ur->logout),
		(unsigned long)ur->created);
      i = _write_listfile (buff, fp);
      for (fr = ur->fields; fr && i; fr = fr->next)
      {
	snprintf (buff, sizeof(buff), " %s %s\n", Field[fr->id], fr->value);
	i = _write_listfile (buff, fp);
      }
      if (!quiet)
	pthread_mutex_unlock (&ur->mutex);
    }
    /* second step: save all but own and channel records */
    for (ur = FirstUser; ur && i; ur = ur->next)
    {
      if ((ur->flag & (U_ALIAS|U_SPECIAL)) || !ur->uid)
	continue;
      if (ur->flag & U_BOT)
	_b++;
      else
	_r++;
      if (!quiet)
	pthread_mutex_lock (&ur->mutex);
      snprintf (buff, sizeof(buff), "%s%s:%s:%d:%s:%s:%s:%s:%s:%lu\n",
		(ur->lname && strchr ("#+\\", ur->lname[0])) ? "\\" : "",
		NONULL(ur->lname), NONULL(ur->passwd), (int) ur->uid,
		userflagtostr (ur->flag, f), NONULL(ur->u.info),
		NONULL(ur->dccdir), NONULL(ur->login), NONULL(ur->logout),
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
		    chr->cid == R_CONSOLE ? "" : Chan[chr->cid-ID_CHANN],
		    userflagtostr (chr->flag, f), (unsigned long)chr->expire,
		    NONULL(chr->greeting));
	else				/* console or channel record */
	  snprintf (buff, sizeof(buff), " %s:%s: %s\n",
		    chr->cid == R_CONSOLE ? "" : Chan[chr->cid-ID_CHANN],
		    userflagtostr (chr->flag, f), NONULL(chr->greeting));
	i = _write_listfile (buff, fp);
      }
      for (fr = ur->fields; fr && i; fr = fr->next)
      {
	snprintf (buff, sizeof(buff), " %s %s\n", Field[fr->id], fr->value);
	i = _write_listfile (buff, fp);
      }
      if (!quiet)
	pthread_mutex_unlock (&ur->mutex);
    }
    pthread_mutex_unlock (&UserFileLock);
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

static iface_t userfile_signal (INTERFACE *iface, ifsig_t signal)
{
  switch (signal)
  {
    case S_REPORT:
      /* oops, still in progress??? */
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
      iface->iface |= I_DIED;
    default:
      _save_listfile (Listfile, signal == S_SHUTDOWN ? 1 : 0);
  }
  return 0;
}

/* ----------------------------------------------------------------------------
 * Internal dcc bindings:
 * int func(DCC_SESSION *from, char *args)
 */

static int dc_chattr (DCC_SESSION *dcc, char *args)
{
  register userflag ufp, ufm, ufmask;
  userflag cf = 0;
  lid_t id = R_NO;
  int is_global = 1;
  register int i = 0;
  char *bg;
  char plus[64];			/* I hope, it enough for 18 flags :) */
  char Chan[IFNAMEMAX+1];
  char *minus;
  USERRECORD *user;
  USERRECORD *who;
  user_chr *chr = NULL;

  strfcpy (plus, args, sizeof(plus));
  bg = plus;
  while (*bg && *bg != ' ') bg++;	/* parse a first word */
  if (*bg)
    *bg = 0;
  pthread_mutex_lock (&UserFileLock);
  user = _findbylname (plus);		/* find the user */
  if (!user)
  {
    pthread_mutex_unlock (&UserFileLock);
    New_Request (dcc->iface, 0, _("No user with login name %s found."), plus);
    return 0;
  }
  if (user->flag & U_ALIAS)		/* unaliasing */
    user = user->u.owner;
  pthread_mutex_lock (&user->mutex);
  /* find me */
  who = _findbylname (dcc->iface->name);
  /* find my default channel */
  if (who)
  {
    pthread_mutex_lock (&who->mutex);
    for (chr = who->channels; chr && chr->cid != R_CONSOLE; chr = chr->next);
    if (chr)
    {
      strfcpy (Chan, NextWord (chr->greeting), sizeof(Chan));
      for (minus = Chan; *minus && *minus != ' '; minus++);
      *minus = 0;
      id = _get_index (Chan);
      for (chr = who->channels; chr && chr->cid != id; chr = chr->next);
      if (chr)
	cf = chr->flag;
    }
    pthread_mutex_unlock (&who->mutex);
  }
  else
    *Chan = 0;
  pthread_mutex_unlock (&UserFileLock);
  ufp = ufm = 0;
  args = NextWord (args);
  StrTrim (args);			/* break ending spaces */
  FOREVER
    switch (*args)
    {
      case '+':
	*args = 0;			/* break previous */
	if (i == 1)			/* was '+' */
	{
	  ufp |= strtouserflag (bg);
	  ufm &= ~ufp;
	}
	else if (i)			/* was '-' */
	{
	  ufm |= strtouserflag (bg);
	  ufp &= ~ufm;
	}
	*args++ = '+';			/* set back deleted char */
	bg = args;
	i = 1;
	break;
      case '-':
	*args = 0;
	if (i == 1)			/* was '+' */
	{
	  ufp |= strtouserflag (bg);
	  ufm &= ~ufp;
	}
	else if (i)			/* was '-' */
	{
	  ufm |= strtouserflag (bg);
	  ufp &= ~ufm;
	}
	*args++ = '-';
	bg = args;
	i = -1;
	break;
      case '|':
      case ' ':
      case 0:
	*plus = *args;
	*args = 0;
	if (i == 1)			/* was '+' */
	{
	  ufp |= strtouserflag (bg);
	  ufm &= ~ufp;
	}
	else if (i)			/* was '-' */
	{
	  ufm |= strtouserflag (bg);
	  ufp &= ~ufm;
	}
	if (*args)
	  *args++ = *plus;
	if (is_global)			/* global attributes */
	{
	  bg = args;
	  if (*plus == '|')
	    is_global = 0;
	  /* check permissions */
	  ufmask = U_BOT;
	  if (!(dcc->uf & U_OWNER))
	  {
	    ufmask |= (U_OWNER | U_MASTER | U_UNSHARED);
	    if (user->flag & U_OWNER)
	      ufp = ufm = 0;		/* seniority! */
	  }
	  if (!(dcc->uf & U_MASTER))
	  {
	    ufmask |= (U_HALFOP | U_OP | U_AUTOOP | U_DEOP | U_VOICE | U_AUTOVOICE | U_QUIET);
	    if (user->flag & (U_OWNER | U_MASTER))
	      ufp = ufm = 0;		/* seniority! */
	  }
	  ufp &= ~ufmask;		/* what is not permitted */
	  ufm &= ~ufmask;
	  if (ufm & U_HALFOP)		/* some dependencies */
	    ufm |= U_OP;
	  if (ufm & (U_MASTER | U_OP))
	    ufm |= U_OWNER;
	  if (ufp & U_OWNER)
	    ufp |= U_MASTER | U_OP;
	  if (ufp & U_OP)
	    ufp |= U_HALFOP;
	  ufp &= ~user->flag;		/* already set! */
	  ufm &= user->flag;		/* don't set yet! */
	  if (ufp || ufm)
	  {
	    /* set userflags */
	    user->flag |= ufp;
	    user->flag &= ~ufm;
	    /* send changes to shared bots */
	    userflagtostr (ufp, plus);
	    minus = &plus[strlen(plus)+1];
	    userflagtostr (ufm, minus);
	    Add_Request (I_BOT, "*", F_SHARE, "\010chattr %s %s%s%s%s",
			 user->lname, ufp ? "+" : "", plus, ufm ? "-" : "",
			 minus);
	    /* S_FLUSH dcc record if on partyline */
	    Add_Request (I_CHAT, user->lname, F_USERS, "\010");
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
	      Add_Request (I_CHAT, user->lname, F_NOTICE,
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
	      Add_Request (I_CHAT, user->lname, F_NOTICE,
			   _("WOW, you are %s now..."), minus);
	  }
	  New_Request (dcc->iface, 0,
		       _("Global attributes for %s are now: %s."), user->lname,
		       userflagtostr (user->flag, plus));
	  ufp = ufm = 0;
	  i = 0;
	  if (!is_global)		/* was '|' */
	    break;
	  if (!*args)			/* end of args */
	  {
	    pthread_mutex_unlock (&user->mutex);
	    return 1;
	  }
	}
	/* channel attributes - try for channel name first */
	while (*args == ' ') args++;
	if (*args && strchr (SPECIALCHARS, *args))
	{
	  id = _get_index (args);
	  if (id == R_NO)
	  {
	    pthread_mutex_unlock (&user->mutex);
	    New_Request (dcc->iface, 0, _("No such channel '%s'."), args);
	    return 0;
	  }
	  strfcpy (Chan, args, sizeof(Chan));
	}
	if (id < 0)
	{
	  pthread_mutex_unlock (&user->mutex);
	  New_Request (dcc->iface, 0, _("You set no default channel yet."));
	  return 0;
	}
	for (chr = user->channels; chr && chr->cid != id; chr = chr->next);
	/* check permissions */
	ufmask = (U_BOT | U_COMMON | U_HIGHLITE | U_CHAT | U_FSA);
					/* global only attributes */
	if (!(cf & U_OWNER))
	{
	  ufmask = (U_OWNER | U_MASTER | U_UNSHARED);
	  if (chr && (chr->flag & U_OWNER))
	    ufp = ufm = 0;		/* seniority! */
	}
	if (!(dcc->uf & U_MASTER))
	{
	  ufmask |= (U_OP | U_AUTOOP | U_DEOP | U_VOICE | U_AUTOVOICE | U_QUIET);
	  if (chr && (chr->flag & (U_OWNER | U_MASTER)))
	    ufp = ufm = 0;		/* seniority! */
	}
	ufp &= ~ufmask;		/* what is not permitted */
	ufm &= ~ufmask;
	if (ufm & U_MASTER)		/* some dependencies */
	  ufm |= U_OWNER;
	if (ufp & U_OWNER)
	  ufp |= U_MASTER;
	if (chr)
	  ufp &= ~chr->flag;		/* already set! */
	if (chr)
	  ufm &= user->flag;		/* don't set yet! */
	else
	  ufm = 0;
	if (ufp || ufm)
	{
	  if (!chr)			/* create the channel record */
	    chr = _add_channel (&user->channels, id);
	  /* set userflags */
	  chr->flag |= ufp;
	  chr->flag &= ~ufm;
	  /* send changes to shared bots */
	  userflagtostr (ufp, plus);
	  minus = &plus[strlen(plus)+1];
	  userflagtostr (ufm, minus);
	  Add_Request (I_BOT, "*", F_SHARE, "\010chattr %s |%s%s%s%s %s",
		       user->lname, ufp ? "+" : "", plus, ufm ? "-" : "",
		       minus, Chan);
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
	  if (minus);
	    Add_Request (I_CHAT, user->lname, F_NOTICE,
			 _("OOPS, you are not %s on %s anymore..."), minus,
			 Chan);
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
	  if (minus);
	    Add_Request (I_CHAT, user->lname, F_NOTICE,
			 _("WOW, you are %s on %s now..."), minus, Chan);
	}
	New_Request (dcc->iface, 0,
		     _("Channel attributes for %s on %s are now: %s."),
		     user->lname, Chan, userflagtostr (chr->flag, plus));
	pthread_mutex_unlock (&user->mutex);
	return 1;
      default:
	args++;
    }
}

static int dc__phost (DCC_SESSION *dcc, char *args)
{
  USERRECORD *user;
  char *lname = args;

  while (*args && *args != ' ') args++;
  if (!*args)
    return 0;				/* no hostmask */
  *args = 0;
  pthread_mutex_lock (&UserFileLock);
  user = _findbylname (lname);
  *args = ' ';
  args = NextWord (args);
  if (!user || strlen (args) < 5)	/* no user or no hostmask */
  {
    pthread_mutex_unlock (&UserFileLock);
    return 0;
  }
  _add_usermask (user, args);
  pthread_mutex_unlock (&UserFileLock);
  Add_Request (I_BOT, "*", F_SHARE, "\010+host %s %s", user->lname, args);
  return 1;
}

static int dc__mhost (DCC_SESSION *dcc, char *args)
{
  USERRECORD *user;
  char *lname = args;

  while (*args && *args != ' ') args++;
  if (!*args)
    return 0;				/* no hostmask */
  *args = 0;
  pthread_mutex_lock (&UserFileLock);
  user = _findbylname (lname);
  *args = ' ';
  args = NextWord (args);
  if (!user || strlen (args) < 5)	/* no user or no hostmask */
  {
    pthread_mutex_unlock (&UserFileLock);
    return 0;
  }
  _del_usermask (user, args);
  pthread_mutex_unlock (&UserFileLock);
  Add_Request (I_BOT, "*", F_SHARE, "\010-host %s %s", user->lname, args);
  return 1;
}

static int dc__puser (DCC_SESSION *dcc, char *args)
{
  register int i;
  char *lname = args;
  char *mask;

  if (!args)
    return 0;
  StrTrim (args);
  mask = NextWord (args);
  if (*mask)
    while (*args != ' ') args++;
  else
    args = mask;
  *args = 0;
  i = Add_Userrecord (lname, (uchar *)mask, 0);
  if (*mask)
    *args = ' ';
  if (i)
    Add_Request (I_BOT, "*", F_SHARE, "\010+user %s %s", lname, mask);
  else
    New_Request (dcc->iface, 0, _("Cannot add user, one may be already exists."));
  return i;
}

static int dc__muser (DCC_SESSION *dcc, char *args)
{
  USERRECORD *user;

  pthread_mutex_lock (&UserFileLock);
  if (!args || !(user = _findbylname (args)))
  {
    pthread_mutex_unlock (&UserFileLock);
    return 0;
  }
  _delete_userrecord (user, 1);
  CommitWtmp();
  Add_Request (I_LOG, "*", F_USERS, _("Deleted name %s."), args);
  Add_Request (I_BOT, "*", F_SHARE, "\010-user %s", args);
  return 1;
}

static BINDTABLE *BT_Pass = NULL;

static int user_chpass (const char *pass, char **crypted)
{
  char *spass = NULL;			/* generate a new passwd */
  register BINDING *bind = NULL, *bind2 = NULL;

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

static int dc_passwd (DCC_SESSION *dcc, char *args)
{
  register USERRECORD *user;
  int i;

  pthread_mutex_lock (&UserFileLock);
  user = _findbylname (dcc->iface->name);
  pthread_mutex_lock (&user->mutex);
  LISTFILEMODIFIED;
  pthread_mutex_unlock (&UserFileLock);
  i = user_chpass (args, &user->passwd);
  Add_Request (I_BOT, "*", F_SHARE, "\013%s %s", user->lname,
	       NONULL(user->passwd));
  pthread_mutex_unlock (&user->mutex);
  if (!i)
    New_Request (dcc->iface, 0, "Password changing error!");
  else
    Add_Request (I_LOG, "*", F_USERS, "#%s# passwd [something]",
		 dcc->iface->name);
  return (-1);
}

static int dc_chpass (DCC_SESSION *dcc, char *args)
{
  register USERRECORD *user;
  register char *lname = args;
  int i;

  if (args) StrTrim (args);
  if (!args || !*args)
    return 0;
  while (*args && *args != ' ') args++;
  if (*args)
    *args++ = 0;
  while (*args == ' ') args++;
  pthread_mutex_lock (&UserFileLock);
  user = _findbylname (lname);
  if (user && (user->flag & U_ALIAS))
    user = user->u.owner;
  if (user)
    pthread_mutex_lock (&user->mutex);
  LISTFILEMODIFIED;
  pthread_mutex_unlock (&UserFileLock);
  if (!user)
    return 0;
  i = user_chpass (args, &user->passwd);
  Add_Request (I_BOT, "*", F_SHARE, "\013%s %s", lname, NONULL(user->passwd));
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

static int dc_nick (DCC_SESSION *dcc, char *args)
{
  char *oldname = safe_strdup (dcc->iface->name);
  register int i;

  if (args) StrTrim (args);
  if ((i = Change_Lname (args, oldname)))
    Add_Request (I_BOT, "*", F_SHARE, "\010chln %s %s", oldname, args);
  FREE (&oldname);
  return i;
}

static int dc_chnick (DCC_SESSION *dcc, char *args)
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
    Add_Request (I_BOT, "*", F_SHARE, "\010chln %s", oldname);
  return i;
}

static int dc_reload (DCC_SESSION *dcc, char *args)
{
  /* can use Listfile variable - I hope iface locked now */
  if (_load_listfile (Listfile, 0))
    New_Request (dcc->iface, 0, _("Cannot load userfile!"));
  return 1;
}

static int dc_save (DCC_SESSION *dcc, char *args)
{
  /* can use Listfile variable - I hope iface locked now */
  if (_save_listfile (Listfile, 0))
    New_Request (dcc->iface, 0, _("Cannot save userfile!"));
  return 1;
}

INTERFACE *ListfileIface = NULL;

char *IFInit_Users (void)
{
  if (ListfileIface)
    userfile_signal (ListfileIface, S_TERMINATE);
  /* empty LIDs bitmap */
  memset (LidsBitmap, 0, sizeof(LidsBitmap));
  /* create bot userrecord */
  _add_userrecord ("", U_UNSHARED, ID_BOT);
  /* load userfile */
  if (_load_listfile (Listfile, 0))
    return (_("Cannot load userfile!"));
  ListfileIface = Add_Iface (NULL, I_FILE, &userfile_signal, NULL, NULL);
  /* sheduler itself will refresh Listfile every minute so it's all */
  /* get crypt bindtable address */
  BT_Pass = Add_Bindtable ("passwd", B_UNIQMASK);
  BT_ChLname = Add_Bindtable ("new-lname", B_MASK);
  /* add dcc bindings */
  Add_Binding ("dcc", "chattr", U_MASTER, U_MASTER, &dc_chattr);
  Add_Binding ("dcc", "+user", U_MASTER, U_MASTER, &dc__puser);
  Add_Binding ("dcc", "-user", U_MASTER, -1, &dc__muser);
  Add_Binding ("dcc", "+host", U_MASTER, U_MASTER, &dc__phost);
  Add_Binding ("dcc", "-host", U_MASTER, U_MASTER, &dc__mhost);
  Add_Binding ("dcc", "passwd", U_CHAT, -1, &dc_passwd);
  Add_Binding ("dcc", "chpass", U_MASTER, U_MASTER, &dc_chpass);
  Add_Binding ("dcc", "lname", U_CHAT, -1, &dc_nick);
  Add_Binding ("dcc", "chln", U_MASTER, -1, &dc_chnick);
  Add_Binding ("dcc", "reload", U_MASTER, -1, &dc_reload);
  Add_Binding ("dcc", "save", U_MASTER, -1, &dc_save);
  return (NULL);
}
