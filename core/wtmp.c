/*
 * Copyright (C) 2001-2002  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 * wtmp file functions.
 */

#include "foxeye.h"

#include "init.h"
#include "users.h"

/* Note: since users.c calls ChangeUid() that locks Wtmp,
   call no functions from that file but GetLID() is safe */

static pthread_mutex_t WtmpLock = PTHREAD_MUTEX_INITIALIZER;

static char **Events = NULL;
static short _Ealloc = 0;
static short _Enum = 0;

#define EVENTS_MAX	100

/* returns event number or -1 if don't found */
static short _get_event (const char *name)
{
  short i = 0;

  pthread_mutex_lock (&WtmpLock);
  while (i < _Enum)
  {
    if (safe_strcasecmp (Events[i], name))
      break;
    i++;
  }
  if (i == _Enum)
    i = -1;
  pthread_mutex_unlock (&WtmpLock);
  return i;
}

/* returns 0 if success or -1 if fail */
static int _new_event (const char *name)
{
  pthread_mutex_lock (&WtmpLock);
  if (_Enum == _Ealloc)
  {
    void *newevents;

    if (_Ealloc > EVENTS_MAX ||
	!(newevents = realloc (Events, (_Ealloc+16) * sizeof (char *))))
    {
      pthread_mutex_unlock (&WtmpLock);
      return -1;
    }
    _Ealloc += 16;
    Events = newevents;
  }
  Events[_Enum++] = safe_strdup (name);
  pthread_mutex_unlock (&WtmpLock);
  return 0;
}

short Event (const char *ev)
{
  void *user;
  short i = 0;
  char *events, *c;
  char name[SHORT_STRING];

  pthread_mutex_lock (&WtmpLock);
  if (_Ealloc == 0)				/* no events before */
    i = 1;
  pthread_mutex_unlock (&WtmpLock);
  if (i)
  {
    user = Lock_User ("");
    if (user && (events = Get_Userfield (user, "events")))
      while (*events)
      {
	for (c = name; *events && *events != ' ' && c < &name[sizeof(name)-1];
		events++, c++)
	  *c = *events;
	*c = 0;
	if (_get_event (name) < 0)
	  _new_event (name);
      }
    Unlock_User (user);
  }
  i = _get_event (ev);
  if (i < 0)
  {
    size_t s = HUGE_STRING;

    if (_new_event (ev))
      return W_ANY;
    i = 0;
    events = safe_malloc (s);
    c = events;
    *c = 0;
    pthread_mutex_lock (&WtmpLock);
    while (i < _Enum)
    {
      if (events + s < c + safe_strlen(Events[i] + 2))
      {
	s += HUGE_STRING;
	safe_realloc ((void **)&events, s * sizeof(char));
	c = events + strlen (events);
      }
      *c++ = ' ';
      strfcpy (c, NONULL(Events[i]), SHORT_STRING);
    }
    pthread_mutex_unlock (&WtmpLock);
    user = Lock_User ("");
    Set_Userfield (user, "events", events);
    Unlock_User (user);
    FREE (&events);
    i--;					/* new event is last */
  }
  return i + W_USER;
}

#define TBLMAX	32				/* I hope, this enough */

lid_t _add_tbl (lid_t *tbl, lid_t id)
{
  register int i;

  for (i = 0; i < TBLMAX; i++)
    if (tbl[i] == ID_CHANN)			/* nonexistent id */
      break;
  if (i == TBLMAX)
    return ID_CHANN;
  tbl[i] = id;
  return id;
}

lid_t _del_tbl (lid_t *tbl, lid_t id)
{
  register int i = 0;
  lid_t idl = id;

  if (id == ID_CHANN)
  {
    for (; i < TBLMAX && tbl[i] != id; i++)
    {
      idl = tbl[i];
      tbl[i] = id;
    }
  }
  else
  {
    for (; i < TBLMAX && tbl[i] != id; i++);
    if (i == TBLMAX)
      return ID_CHANN;
    for (; i < TBLMAX-1; i++)
      tbl[i] = tbl[i+1];
    tbl[i] = ID_CHANN;
  }
  return idl;
}

/* returns: -1 if file does not exist, 0 otherwise */
static int _scan_wtmp (const char *path, wtmp_t *wtmp,
		       lid_t myid, short event, lid_t fid)
{
  FILE *fp;
  wtmp_t buff[64];
  lid_t tbl[TBLMAX];
  int i;
  size_t n;
  lid_t idl;

  fp = fopen (path, "rb");
  if (!fp)
    return -1;
  for (i = 0; i < TBLMAX; i++) tbl[i] = ID_CHANN;	/* clear */
  while ((n = fread (buff, sizeof(wtmp_t), 64, fp)))
  {
    for (i = 0; i < n; i++)
    {
      if (buff[i].event == W_DOWN && (event == W_ANY || event == W_END))
      {
	if ((idl = _del_tbl (tbl, ID_CHANN)) != ID_CHANN)
	{
	  wtmp->time = buff[i].time;		/* shutdown but no stop */
	  wtmp->event = W_DOWN;
	  wtmp->count = 0;
	  wtmp->fuid = idl;
	  wtmp->uid = myid;
	}
      }
      else if (buff[i].uid == myid && (fid == ID_BOT || fid == buff[i].fuid ||
	       (fid == ID_CHANN && buff[i].fuid > ID_CHANN &&
	        buff[i].fuid < ID_FIRST)))	/* exactly */
      {
	if (event == W_ANY || event == W_END)
	{
	  if (buff[i].event == W_END)
	    _del_tbl (tbl, buff[i].fuid);
	  else if (buff[i].event == W_START)
	    _add_tbl (tbl, buff[i].fuid);
	}
	if (event == W_ANY || event == buff[i].event)
	  memcpy (wtmp, &buff[i], sizeof(wtmp_t));
      }
    }
  }
  fclose (fp);
  return 0;
}

/* finds last matched event
   returns 0 if no error and fills array wtmp */
int FindEvent (wtmp_t *wtmp, const char *lname, short event, lid_t fid)
{
  lid_t myid;
  char path[LONG_STRING];
  char wp[LONG_STRING];
  const char *wpp;
  int i;
  
  Set_Iface (NULL);			/* in order to access Wtpm variable */
  wpp = expand_path (wp, Wtmp, sizeof(wp));
  Unset_Iface();
  pthread_mutex_lock (&WtmpLock);
  if (!lname || (myid = GetLID (lname)) == ID_REM)
  {
    pthread_mutex_unlock (&WtmpLock);
    return -1;
  }
  memset (wtmp, 0, sizeof(wtmp_t));
  /* scan Wtmp first */
  if (_scan_wtmp (wpp, wtmp, myid, event, fid))
  {
    pthread_mutex_unlock (&WtmpLock);
    return -1;
  }
  /* if not found - scan Wtmp.1  ...  Wtmp.$wtmps */
  for (i = 0; i < WTMPS_MAX && !wtmp->time; i++)
  {
    snprintf (path, sizeof(path), "%s.%d", wpp, i + 1);
    if (_scan_wtmp (path, wtmp, myid, event, fid))
      break;
  }
  /* if not found - scan Wtmp.old */
  if (!wtmp->time)
  {
    snprintf (path, sizeof(path), "%s." WTMP_GONE_EXT, wpp);
    _scan_wtmp (path, wtmp, myid, event, fid);
  }
  pthread_mutex_unlock (&WtmpLock);
  return 0;
}

void NewEvent (short event, const char *from, const char *lname, short count)
{
  wtmp_t wtmp;
  char wp[LONG_STRING];
  FILE *fp;

  if (event != W_DOWN || from)			/* don't deadlock on shutdown */
  {
    pthread_mutex_lock (&WtmpLock);
    Set_Iface (NULL);			/* in order to access Wtpm variable */
  }
  fp = fopen (expand_path (wp, Wtmp, sizeof(wp)), "ab");
  if (event != W_DOWN || from)			/* don't deadlock on shutdown */
  {
    Unset_Iface();
  }
  if (fp)
  {
    wtmp.fuid = GetLID (from);
    wtmp.event = event;
    wtmp.time = time (NULL);
    wtmp.uid = GetLID (lname);
    wtmp.count = count;
    fwrite (&wtmp, sizeof(wtmp), 1, fp);
    fclose (fp);
  }
  if (event != W_DOWN || from)			/* don't deadlock on shutdown */
    pthread_mutex_unlock (&WtmpLock);
}

void NewEvents (short event, const char *from,
		size_t n, const char *lname[], short count[])
{
  wtmp_t wtmp;
  char wp[LONG_STRING];
  FILE *fp;
  register size_t i = 0;

  Set_Iface (NULL);			/* in order to access Wtpm variable */
  fp = fopen (expand_path (wp, Wtmp, sizeof(wp)), "ab");
  Unset_Iface();
  pthread_mutex_lock (&WtmpLock);
  wtmp.fuid = GetLID (from);
  wtmp.event = event;
  wtmp.time = time (NULL);
  if (fp)
  {
    while (i < n)
    {
      wtmp.uid = GetLID (lname[i]);
      wtmp.count = count[i];
      fwrite (&wtmp, sizeof(wtmp), 1, fp);
    }
    fclose (fp);
  }
  pthread_mutex_unlock (&WtmpLock);
}

#define UNS_CH_MAX	32

static lid_t changes[UNS_CH_MAX][2] = {{ID_CHANN}};

static int _change_wtmp_file (const char *wf, char *tmp, size_t n)
{
  size_t k, i, j;
  wtmp_t buff[64];
  FILE *dst, *src;
  char bak[LONG_STRING];
  int r = 0;

  src = fopen (wf, "rb");
  if (!src)
    return -1;
  else if (!(dst = fopen (tmp, "wb")))
  {
    fclose (src);
    return -1;
  }
  dprint (4, "wtmp:_change_wtmp_file: %s %s", wf, tmp);
  while ((k = fread (buff, sizeof(wtmp_t), 64, src)))
  {
    for (j = 0; j < k; )
    {
      for (i = 0; i < n; i++)
      {
	if (changes[i][1] == buff[j].uid)
	{
	  buff[j].uid = changes[i][0];
	  r = 1;
	}
	if (changes[i][1] == buff[j].fuid)
	{
	  buff[j].fuid = changes[i][0];
	  r = 1;
	}
      }
      if (buff[j].uid == ID_REM)		/* wtmp record lost */
	memmove (&buff[j], &buff[j+1], (--k - j) * sizeof(wtmp_t));
      else
	j++;
    }
    if (k)
      fwrite (buff, sizeof(wtmp_t), k, dst);
  }
  fclose (src);
  fclose (dst);
  if (r == 0)					/* don't changed */
    unlink (tmp);
  else
  {
    snprintf (bak, sizeof(bak), "%s~", wf);
    unlink (bak);
    if (!rename (wf, bak))
    {
      if (!rename (tmp, wf))
      {
	unlink (bak);
	bak[0] = 0;
      }
      else
	rename (bak, wf);
    }
    if (!*bak)
      dprint (2, "cannot update %s", wf);
  }
  return 0;
}

static void _change_wtmps (size_t n, const char *wfp)
{
  char path[LONG_STRING];
  char path2[LONG_STRING];
  int i = 0;

  if (n == 0) return;
  snprintf (path2, sizeof(path2), "%s.0", wfp);
  /* first - Wtmp */
  _change_wtmp_file (wfp, path2, n);
  /* second - Wtmp.1 ... Wtmp.$wtmps */
  do
  {
    i++;
    snprintf (path, sizeof(path), "%s.%d", wfp, i);
  } while (i <= WTMPS_MAX && !_change_wtmp_file (path, path2, n));
  /* third - Wtmp.old */
  snprintf (path, sizeof(path), "%s." WTMP_GONE_EXT, wfp);
  _change_wtmp_file (path, path2, n);
}

void ChangeUid (lid_t oldid, lid_t newid)
{
  lid_t (* ch)[2];
  char wp[LONG_STRING];
  const char *wfp;

  Set_Iface (NULL);			/* in order to access Wtpm variable */
  wfp = expand_path (wp, Wtmp, sizeof(wp));
  Unset_Iface();
  if (newid == ID_CHANN || oldid == ID_REM)	/* :) */
    return;
  ch = &changes[0];
  pthread_mutex_lock (&WtmpLock);
  while (ch[0][0] != ID_CHANN) ch++;
  ch[0][0] = newid;
  ch[0][1] = oldid;
  ch++;
  if (ch == &changes[UNS_CH_MAX])
  {
    _change_wtmps (UNS_CH_MAX, wfp);
    ch = &changes[0];
  }
  ch[0][0] = ID_CHANN;
  pthread_mutex_unlock (&WtmpLock);
}

void CommitWtmp (void)
{
  int i = 0;
  lid_t (*ch)[2];
  char wp[LONG_STRING];
  const char *wfp;

  Set_Iface (NULL);			/* in order to access Wtpm variable */
  wfp = expand_path (wp, Wtmp, sizeof(wp));
  Unset_Iface();
  pthread_mutex_lock (&WtmpLock);
  for (ch = changes; ch[i][0] != ID_CHANN; i++);
  _change_wtmps (i, wfp);
  changes[0][0] = ID_CHANN;
  pthread_mutex_unlock (&WtmpLock);
}

static uint32_t *GoneBitmap = NULL;

void RotateWtmp (void)
{
  int i, update = 0;
  char wp[LONG_STRING];
  const char *wfp;
  char path[LONG_STRING];
  char path2[LONG_STRING];
  FILE *fp, *dst = NULL;
  register size_t j;
  size_t k;
  wtmp_t buff[64];
  wtmp_t buff2[64];
  uint32_t bits;

  if (wtmps > WTMPS_MAX)
    wtmps = WTMPS_MAX;
  if (wtmps < 1)
    wtmps = 1;
  GoneBitmap = safe_calloc (1, sizeof(uint32_t) * LID_MAX);
  Set_Iface (NULL);			/* in order to access Wtpm variable */
  wfp = expand_path (wp, Wtmp, sizeof(wp));
  Unset_Iface();
  snprintf (path, sizeof(path), "%s.1", wfp);
  snprintf (path2, sizeof(path2), "%s." WTMP_GONE_EXT, wfp);
  pthread_mutex_lock (&WtmpLock);
  /* check if we need to rotate - check the first event of $Wtmp */
  /* mark deletable events for wtmp.gone */
  for (i = WTMPS_MAX; i >= wtmps; i--)
  {
    snprintf (path, sizeof(path), "%s.%d", wfp, i);
    if ((fp = fopen (path, "rb")))
    {
      while ((k = fread (buff, sizeof(wtmp_t), 64, fp)))
	for (j = 0; j < k; j++)
	  GoneBitmap[buff[j].uid] |= 1<<(buff[j].event);
      fclose (fp);
      update = 1;
    }
  }
  if (update)
  {
    /* delete expired events from wtmp.gone (rewrite) */
    snprintf (path, sizeof(path), "%s.0", wfp);
    fp = fopen (path2, "rb");			/* wtmp.gone */
    if (fp) dst = fopen (path, "wb");		/* wtmp.tmp */
    if (dst)
      while ((k = fread (buff, sizeof(wtmp_t), 64, fp)))
      {
	for (j = 0; j < k; )
	{
	  bits = 1<<(buff[j].event);
	  if (GoneBitmap[buff[j].uid] & bits)	/* expired */
	    memmove (&buff[j], &buff[j+1], (--k - j) * sizeof(wtmp_t));
	  else					/* still actual */
	    j++;
	}
	if (k)
	  fwrite (buff, sizeof(wtmp_t), k, dst);
      }
    if (fp) fclose (fp);
    if (dst)
    {
      fclose (dst);
      unlink (path2);				/* wtmp.gone */
      if (rename (path, path2))			/* wtmp.tmp --> wtmp.gone */
	dprint (2, "couldn't make %s!", path2);
    }
    else
      dprint (2, "cannot rewrite %s!", path2);
    /* mark addable events for wtmp.gone: $Wtmp.$wtmps-1...$Wtmp.1, $Wtmp */
    for (; i > 1; i--)
    {
      snprintf (path, sizeof(path), "%s.%d", wfp, i);
      if ((fp = fopen (path, "rb")))
      {
	while ((k = fread (buff, sizeof(wtmp_t), 64, fp)))
	  for (j = 0; j < k; j++)
	    GoneBitmap[buff[j].uid] &= ~(1<<(buff[j].event));
	fclose (fp);
      }
    }
    if ((fp = fopen (wfp, "rb")))
    {
      while ((k = fread (buff, sizeof(wtmp_t), 64, fp)))
	for (j = 0; j < k; j++)
	  GoneBitmap[buff[j].uid] &= ~(1<<(buff[j].event));
      fclose (fp);
    }
    snprintf (path, sizeof(path), "%s.0", wfp);
    dst = fopen (path, "wb+");			/* wtmp.gone */
    /* create events in tmp file in reverse order */
    if (dst) for (i = WTMPS_MAX; i >= wtmps; i--)
    {
      snprintf (path, sizeof(path), "%s.%d", wfp, i);
      if ((fp = fopen (path, "rb")))
      {
	fseek (fp, 0L, SEEK_END);
	while((j = ftell (fp)))
	{
	  if (j <= sizeof(buff))
	  {
	    rewind (fp);
	    k = j / sizeof(wtmp_t);
	  }
	  else
	  {
	    fseek (fp, -sizeof(buff), SEEK_CUR);
	    k = 64;
	  }
	  j = fread (buff, sizeof(wtmp_t), k, fp);
	  fseek (fp, -sizeof(wtmp_t) * k, SEEK_CUR);
	  k = 0;
	  for (; j > 0; )
	  {
	    j--;
	    bits = 1<<(buff[j].event);
	    if (GoneBitmap[buff[j].uid] & bits)
	    {
	      memcpy (&buff2[k++], &buff[j], sizeof(wtmp_t));
	      GoneBitmap[buff[j].uid] &= ~bits;
	    }
	  }
	  if (k)
	    fwrite (buff2, sizeof(wtmp_t), k, dst);
	}
	fclose (fp);
      }
    }
    else
      dprint (2, "cannot open %s!", path);
    /* add events to wtmp.gone in normal order */
    if (dst)
    {
      fp = fopen (path2, "ab");
      while((j = ftell (dst)))
      {
	if (j <= sizeof(buff))
	{
	  rewind (dst);
	  k = j / sizeof(wtmp_t);
	}
	else
	{
	  fseek (dst, -sizeof(buff), SEEK_CUR);
	  k = 64;
	}
	j = fread (buff, sizeof(wtmp_t), k, dst);
	fseek (dst, -sizeof(wtmp_t) * k, SEEK_CUR);
	k = 0;
	for (; j > 0; )
	{
	  j--;
	  memcpy (&buff2[k++], &buff[j], sizeof(wtmp_t));
	}
	fwrite (buff2, sizeof(wtmp_t), k, fp);
      }
      fclose (fp);
      fclose (dst);
      snprintf (path, sizeof(path), "%s.0", wfp);
      unlink (path);
    }
  }
  /* delete superfluous wtmp's */
  for (i = WTMPS_MAX; i >= wtmps; i--)
  {
    snprintf (path, sizeof(path), "%s.%d", wfp, i);
    unlink (path);
  }
  /* rotate all */
  for (; i > 1; i--)
  {
    snprintf (path2, sizeof(path2), "%s.%d", wfp, i);
    snprintf (path, sizeof(path), "%s.%d", wfp, i-1);
    if (rename (path, path2))
      dprint (2, "couldn't rotate %s -> %s!", path, path2);
  }
  if (rename (wfp, path))
    dprint (2, "couldn't rotate %s -> %s!", wfp, path);
  pthread_mutex_unlock (&WtmpLock);
  FREE (&GoneBitmap);
}
