/*
 * Copyright (C) 2001-2011  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 * This file is part of FoxEye's source: wtmp file layer.
 */

#include "foxeye.h"

#include <fcntl.h>
#include <errno.h>

#include "init.h"
#include "wtmp.h"

static pthread_mutex_t WtmpLock = PTHREAD_MUTEX_INITIALIZER;
static char **Events = NULL;
static short _Enum = 0;
static char _Egot = 0;

#define EVENTS_MAX	100

/* returns 0 if success or -1 if fail */
static int _set_event (const char *name, size_t sz)
{
  if (!Events)
    Events = safe_malloc (EVENTS_MAX * sizeof (char *));
  else if (_Enum == EVENTS_MAX)
    return -1;
  Events[_Enum] = safe_malloc (sz+1);
  strfcpy (Events[_Enum++], name, sz+1);
  return 0;
}

/* returns event number or -1 if don't found */
static short _get_event (const char *name)
{
  short i = 0;

  if (!_Egot)					/* no events before */
  {
    clrec_t *user = Lock_Clientrecord ("");
    register char *events;
    register size_t sz;

    if (user)
    {
      events = Get_Field (user, "events", NULL);
      pthread_mutex_lock (&WtmpLock);
      if (!_Egot)				/* still nobody fill it? */
      {
	_Egot = 1;
	if (events) while (*events)		/* ok, let's process! */
	{
	  for (sz = 0; events[sz] && events[sz] != ' '; sz++);
	  _set_event (events, sz);
	  events = NextWord (&events[sz]);
	}
      }
      pthread_mutex_unlock (&WtmpLock);
      Unlock_Clientrecord (user);
    }
  }
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

/* returns event number if success or -1 if fail */
static short _new_event (const char *name)
{
  clrec_t *user;
  short i;

  pthread_mutex_lock (&WtmpLock);
  if (_set_event (name, safe_strlen(name)))
  {
    pthread_mutex_unlock (&WtmpLock);
    return -1;
  }
  i = _Enum - 1;
  pthread_mutex_unlock (&WtmpLock);
  user = Lock_Clientrecord ("");
  Grow_Field (user, "events", name);
  Unlock_Clientrecord (user);
  return i;
}

/* rest are public and not locking itself */
short Event (const char *ev)
{
  short i = 0;

  i = _get_event (ev);
  if (i < 0)
  {
    i = _new_event (ev);
    if (i < 0)
      return W_ANY;
  }
  return i + W_USER;
}

#define MYIDS_MAX 8

/*
 * searches wtmp file for entries for myid with some event
 * fills array wtmp with maximum entries wn, updates array myid
 * entry is valid for any fuid if fid == ID_ME
 * or for any fuid but me if fid == ID_ANY
 * or for only fuid == fid otherwise
 * returns: -1 if file does not exist, number of found entries otherwise
 */
static int _scan_wtmp (const char *path, wtmp_t *wtmp, int wn,
		lid_t myid[], size_t *idn, short event, lid_t fid, time_t upto)
{
  int fd, x = 0;
  wtmp_t buff[64];
  ssize_t i;
  size_t k, n;
  struct stat st;

  DBG ("_scan_wtmp:%s:%d:[%lu]=%hd:%hd:%hd", path, wn, (unsigned long)*idn, myid[0], event, fid);
  if (wn == 0)
    return 0;
  if (stat (path, &st) || st.st_mtime < upto)
    return -1;		/* it's too old to check */
  fd = open (path, O_RDONLY);
  if (fd < 0)
    return -1;
  i = lseek (fd, 0, SEEK_END);
  DBG ("_scan_wtmp: fd=%d size=%zd (errno=%d)", fd, i, errno);
  errno = 0;		/* FreeBSD bug with read */
  while (i > 0)
  {
    if ((size_t)i <= sizeof(buff))
    {
      n = lseek (fd, 0, SEEK_SET);		/* rewind to SOF */
      k = i;
    }
    else
    {
      n = lseek (fd, -(off_t)sizeof(buff), SEEK_CUR);
      k = sizeof(buff);
    }
    i = read (fd, buff, k);
    DBG ("_scan_wtmp: trying %zu bytes (%zu wtmp_t): read %d bytes from %d at %u",
	 k, k / sizeof(wtmp_t), (int)i, fd, (unsigned int)n);
    if (i <= 0)			/* premature stopped, read error? */
      break;
    lseek (fd, -i, SEEK_CUR);	/* back to start of the block */
    i /= sizeof(wtmp_t);
    k = 0;
    for (; i > 0 && wn; )
    {
      if (buff[i-1].time < (uint32_t)upto)
	break;
      i--;
      for (n = *idn; n; )	/* scan it for my ids */
      {
	n--;
	if ((buff[i].uid == myid[n] && buff[i].event == W_DEL) ||
	    (buff[i].fuid == myid[n] && buff[i].event == W_CHG))
	{			/* oops, it was another, delete from myids */
	  (*idn)--;
	  while ((++n) < *idn)
	    myid[n-1] = myid[n];
	  break;
	}
	else if (buff[i].uid == myid[n])
	{
	  DBG ("_scan_wtmp: found: event %hd, from %hd, time %lu", buff[i].event, buff[i].fuid, (unsigned long int)buff[i].time);
	  if (buff[i].event == W_CHG)	/* something joined, add to myids */
	  {
	    if (*idn < MYIDS_MAX)
	    {
	      n = *idn;
	      (*idn)++;
	      myid[n] = buff[i].fuid;
	    }
	  }
	  else if (fid == ID_ME || buff[i].fuid == fid ||
	      (fid == ID_ANY && buff[i].fuid != ID_ME))
	  {
	    if (event == W_ANY || event == buff[i].event ||
		(event == W_END && buff[i].event == W_DOWN))
	    {
	      memcpy (&wtmp[x], &buff[i], sizeof(wtmp_t));
	      x++;
	      wn--;
	    }
	  }
	  break;
	}
      }
    }
    if (wn == 0 || *idn == 0 || i > 0)
      break;
    i = lseek (fd, 0, SEEK_CUR);
  }
  close (fd);
  if (x == 0 && i > 0)		/* time limit reached*/
    return -1;
  return x;
}

/* finds not more than (ws) last matched events not older than (upto)
   returns number of found events */
int FindEvents (wtmp_t *wtmp, int ws, const char *lname, short event,
		lid_t fid, time_t upto)
{
  lid_t myid[MYIDS_MAX]; /* I hope it's enough */
  size_t idn;
  char path[LONG_STRING];
  char wp[LONG_STRING];
  int i, n;

  if (!lname || (myid[0] = FindLID (lname)) == ID_REM)	/* was removed? */
    return 0;

  Set_Iface (NULL);			/* in order to access Wtpm variable */
  if (expand_path (wp, Wtmp, sizeof(wp)) == Wtmp)
    strfcpy (wp, Wtmp, sizeof(wp));
  Unset_Iface();
  idn = 1;				/* started with one myid */
  /* scan Wtmp first */
  n = _scan_wtmp (wp, wtmp, ws, myid, &idn, event, fid, upto);
  if (n < 0)				/* no Wtmp or everything is too old */
    return 0;
  /* if not enough - scan Wtmp.1  ...  Wtmp.$wtmps */
  i = 0;
  while (n < ws && i < WTMPS_MAX)
  {
    register int x;

    snprintf (path, sizeof(path), "%s.%d", wp, ++i);
    x = _scan_wtmp (path, &wtmp[n], ws - n, myid, &idn, event, fid, upto);
    if (x < 0)				/* no more files */
      break;
    n += x;				/* found few events! */
  }
  /* if not enough yet - scan Wtmp.old */
  if (n < ws)
  {
    register int x;

    snprintf (path, sizeof(path), "%s." WTMP_GONE_EXT, wp);
    x = _scan_wtmp (path, &wtmp[n], ws - n, myid, &idn, event, fid, upto);
    if (x > 0)				/* some event found! */
      n += x;
  }
  return n;
}

/* finds last matched event
   returns 0 if no error and fills array wtmp */
int FindEvent (wtmp_t *wtmp, const char *lname, short event, lid_t fid, time_t upto)
{
  memset (wtmp, 0, sizeof(wtmp_t));	/* empty it before start */
  if (FindEvents (wtmp, 1, lname, event, fid, upto))
    return 0;
  return (-1);
}

void NewEvent (short event, lid_t from, lid_t lid, short count)
{
  wtmp_t wtmp;
  char wp[LONG_STRING];
  int fd;

  if (event != W_DOWN)			/* don't deadlock on shutdown */
    Set_Iface (NULL);			/* in order to access Wtpm variable */
  fd = open (expand_path (wp, Wtmp, sizeof(wp)), O_WRONLY | O_CREAT | O_APPEND,
	     S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  if (event != W_DOWN)			/* don't deadlock on shutdown */
    Unset_Iface();
  if (fd >= 0)
  {
    wtmp.fuid = from;
    wtmp.event = event;
    wtmp.time = time (NULL);
    wtmp.uid = lid;
    wtmp.count = count;
    if (write (fd, &wtmp, sizeof(wtmp)) < 0)
      DBG ("wtmp:error on saving new event");
    close (fd);
  }
}

void NewEvents (short event, lid_t from, size_t n, lid_t ids[], short counts[])
{
  wtmp_t wtmp;
  char wp[LONG_STRING];
  int fd;

  if (n <= 0)				/* check for stupidity */
    return;
  if (event != W_DOWN)			/* don't deadlock on shutdown */
    Set_Iface (NULL);			/* in order to access Wtpm variable */
  fd = open (expand_path (wp, Wtmp, sizeof(wp)), O_WRONLY | O_CREAT | O_APPEND,
	     S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
  if (event != W_DOWN)			/* don't deadlock on shutdown */
    Unset_Iface();
  wtmp.fuid = from;
  wtmp.event = event;
  wtmp.time = time (NULL);
  if (fd >= 0)
  {
    register size_t i;

    for (i = 0; i < n; i++)
    {
      wtmp.uid = ids[i];
      wtmp.count = counts[i];
      if (write (fd, &wtmp, sizeof(wtmp)) < 0)
	break;
    }
    close (fd);
  }
}

void RotateWtmp (void)
{
  int i, wfps, update = 0;
  char wfp[LONG_STRING];
  char path[LONG_STRING];
  char path2[LONG_STRING];
  char errb[STRING];
  int fd, dst = -1;
  register ssize_t j;
  ssize_t k;
  wtmp_t buff[64];
  wtmp_t buff2[64];
  uint32_t bits;
  uint32_t *GoneBitmap = NULL;
  time_t t;

  Set_Iface (NULL);			/* in order to access variables */
  if (wtmps > WTMPS_MAX)
    wtmps = WTMPS_MAX; /* max wtmps */
  if (wtmps < 0)
    wtmps = 0; /* min wtmps - keep only current one */
  if (expand_path (wfp, Wtmp, sizeof(wfp)) == Wtmp)
    strfcpy (wfp, Wtmp, sizeof(wfp));
  wfps = wtmps;
  t = Time;
  Unset_Iface();			/* it's thread-safe process now */
  GoneBitmap = safe_calloc (1, sizeof(uint32_t) * LID_MAX);
  i = 0;
  /* check if we need to rotate - check the first event of $Wtmp */
  if ((fd = open (wfp, O_RDONLY)) >= 0)
  {
    if (read (fd, buff, sizeof(wtmp_t)) > 0) /* we have readable Wtmp */
    {
      struct tm tm, tm0;
      time_t t2;

      localtime_r (&t, &tm0);
      t2 = buff[0].time;
      localtime_r (&t2, &tm);
      if (tm.tm_year != tm0.tm_year || tm.tm_mon != tm0.tm_mon)
	i = 1;					/* and it needs rotation */
    }
    close (fd);
  }
  if (i == 0)
    return;				/* nothing to do yet */
  snprintf (path2, sizeof(path2), "%s." WTMP_GONE_EXT, wfp);
  /* mark deletable events for wtmp.gone (from $Wtmp.max...$Wtmp.$wtmps) */
  for (i = WTMPS_MAX; i >= wfps; i--)
  {
    if (i)
    {
      snprintf (path, sizeof(path), "%s.%d", wfp, i);
      fd = open (path, O_RDONLY);
    }
    else
      fd = open (wfp, O_RDONLY);
    if (fd >= 0)
    {
      while ((k = read (fd, buff, sizeof(buff))) > 0)
      {
	k /= sizeof(wtmp_t);
	for (j = 0; j < k; j++)
	  GoneBitmap[buff[j].uid] |= (uint32_t)1 << (buff[j].event);
      }
      close (fd);
      update = 1;
    }
  }
  if (update)
  {
    /* scan for deleted uids and mark these as deletable */
    /* side effect - if entry was changed then new created with the same lid
	and deleted then all events of that lid before change will be lost */
    for (j = 0; j < LID_MAX ; j++)
      if (GoneBitmap[j] & ((uint32_t)1 << W_DEL))
	GoneBitmap[j] = 0xffffffff;		/* set all bits */
    /* delete expired events from wtmp.gone (rewrite) */
    snprintf (path, sizeof(path), "%s.0", wfp);
    fd = open (path2, O_RDONLY);		/* wtmp.gone */
    if (fd >= 0 && (dst = open (path, O_RDWR | O_CREAT,
				S_IRUSR | S_IWUSR)) < 0) /* wtmp.tmp */
    {
      strerror_r (errno, errb, sizeof(errb));
      ERROR ("wtmp: couldn't create %s: %s", path, errb);
    }
    if (dst >= 0)
      while ((k = read (fd, buff, sizeof(buff))) > 0)
      {
	k /= sizeof(wtmp_t);
	for (j = 0; j < k; )
	{
	  bits = (uint32_t)1 << (buff[j].event);
	  if (GoneBitmap[buff[j].uid] & bits)	/* event expired */
	    memmove (&buff[j], &buff[j+1], (--k - j) * sizeof(wtmp_t));
	  else					/* still actual */
	    j++;
	}
	if (k && write (dst, buff, k * sizeof(wtmp_t)) <= 0) /* error! */
	  break;
      }
    if (fd >= 0) close (fd);
    if (dst >= 0)
    {
      close (dst);
      if (unlink (path2) ||			/* wtmp.gone */
	  rename (path, path2))			/* wtmp.tmp --> wtmp.gone */
      {
	strerror_r (errno, errb, sizeof(errb));
	ERROR ("wtmp: couldn't rewrite %s: %s", path2, errb);
      }
      else
	DBG ("wtmp: success on %s.", path2);
    }
    /* scan for deleted uids and mark these as non-addable */
    for (j = 0; j < LID_MAX ; j++)
      if (GoneBitmap[j] & (uint32_t)1 << W_DEL)
	GoneBitmap[j] = 0;			/* unset all bits */
    /* mark non-addable events for wtmp.gone: $Wtmp.$wtmps-1...$Wtmp.1, $Wtmp */
    for (; i > 1; i--)
    {
      snprintf (path, sizeof(path), "%s.%d", wfp, i);
      if ((fd = open (path, O_RDONLY)) >= 0)
      {
	while ((k = read (fd, buff, sizeof(buff))) > 0)
	{
	  k /= sizeof(wtmp_t);
	  for (j = 0; j < k; j++)
	    GoneBitmap[buff[j].uid] &= ~((uint32_t)1 << (buff[j].event));
	}
	close (fd);
      }
    }
    if ((fd = open (wfp, O_RDONLY)) >= 0)
    {
      while ((k = read (fd, buff, sizeof(buff))) > 0)
      {
	k /= sizeof(wtmp_t);
	for (j = 0; j < k; j++)
	  GoneBitmap[buff[j].uid] &= ~((uint32_t)1 << (buff[j].event));
      }
      close (fd);
    }
    snprintf (path, sizeof(path), "%s.0", wfp);
    dst = open (path, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR); /* wtmp.tmp */
    /* create events in tmp file in reverse order */
    if (dst >= 0) for (i = WTMPS_MAX; i >= wfps; i--)
    {
      if (i)
      {
	snprintf (path, sizeof(path), "%s.%d", wfp, i);
	fd = open (path, O_RDONLY);
      }
      else
        fd = open (wfp, O_RDONLY);
      if (fd)
      {
	j = lseek (fd, 0, SEEK_END);
	while(j >= 0)
	{
	  if ((size_t)j <= sizeof(buff))
	  {
	    lseek (fd, 0, SEEK_SET);
	    k = j / sizeof(wtmp_t);
	  }
	  else
	  {
	    lseek (fd, -(off_t)sizeof(buff), SEEK_CUR);
	    k = sizeof(buff) / sizeof(wtmp_t);
	  }
	  j = read (fd, buff, k * sizeof(wtmp_t));
	  if (j <= 0)
	    break;
	  lseek (fd, -j, SEEK_CUR);
	  j /= sizeof(wtmp_t);
	  k = 0;
	  for (; j > 0; )
	  {
	    j--;
	    bits = (uint32_t)1 << (buff[j].event);
	    if (GoneBitmap[buff[j].uid] & bits)
	    {
	      memcpy (&buff2[k++], &buff[j], sizeof(wtmp_t));
	      GoneBitmap[buff[j].uid] &= ~bits;
	    }
	  }
	  if (k && write (dst, buff2, k * sizeof(wtmp_t) <= 0)) /* error! */
	    break;
	  j = lseek (fd, 0, SEEK_CUR);
	}
	close (fd);
      }
    }
    else
    {
      strerror_r (errno, errb, sizeof(errb));
      ERROR ("wtmp: cannot open %s: %s", path, errb);
    }
    /* add events to wtmp.gone in normal order */
    if (dst >= 0)
    {
      fd = open (path2, O_WRONLY | O_CREAT | O_APPEND,
		 S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
      while ((j = lseek (dst, 0, SEEK_CUR)) > 0)
      {
	if ((size_t)j <= sizeof(buff))
	{
	  lseek (dst, 0, SEEK_SET);
	  k = j / sizeof(wtmp_t);
	}
	else
	{
	  lseek (dst, -(off_t)sizeof(buff), SEEK_CUR);
	  k = sizeof(buff) / sizeof(wtmp_t);
	}
	j = read (dst, buff, k * sizeof(wtmp_t));
	if (j <= 0) /* error! */
	  break;
	lseek (dst, -j, SEEK_CUR);
	j /= sizeof(wtmp_t);
	k = 0;
	for (; j > 0; )
	{
	  j--;
	  memcpy (&buff2[k++], &buff[j], sizeof(wtmp_t));
	}
	if (write (fd, buff2, k * sizeof(wtmp_t)) <= 0)
	  break;
      }
      close (fd);
      close (dst);
      snprintf (path, sizeof(path), "%s.0", wfp);
      if (unlink (path) == 0)
	DBG ("wtmp: removed %s.", path);
      DBG ("wtmp: success on %s.", path2);
    }
  }
  /* delete superfluous wtmp's */
  for (i = WTMPS_MAX; i >= wfps; i--)
  {
    snprintf (path, sizeof(path), "%s.%d", wfp, i);
    if (unlink (path) == 0)
      DBG ("wtmp: removed %s.", path);
  }
  /* rotate all other */
  for (; i; i--)
  {
    snprintf (path2, sizeof(path2), "%s.%d", wfp, i+1);
    snprintf (path, sizeof(path), "%s.%d", wfp, i);
    if (rename (path, path2))
    {
      strerror_r (errno, errb, sizeof(errb));
      WARNING ("wtmp: couldn't rotate %s -> %s: %s!", path, path2, errb);
    }
    else
      DBG ("wtmp: rotated %s -> %s.", path, path2);
  }
  /* rotate $Wtmp -> $Wtmp.1 */
  if (wfps && rename (wfp, path))
  {
    strerror_r (errno, errb, sizeof(errb));
    ERROR ("wtmp: couldn't rotate %s -> %s: %s!", wfp, path, errb);
  }
  else if (wfps)
    DBG ("wtmp: rotated %s -> %s.", wfp, path);
  FREE (&GoneBitmap);
}
