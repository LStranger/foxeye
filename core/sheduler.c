/*
 * Copyright (C) 1999-2017  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 * This file is part of FoxEye's source: scheduler interface.
 */

#include "foxeye.h"
#include "sheduler.h"
#include "init.h"
#include "wtmp.h"

#define MAXTABLESIZE 20000	/* can i do it for one second? */

typedef struct
{
  short *ptr;
  short count;
} shedfloodentry_t;

static shedfloodentry_t *Floodtable = NULL;
static unsigned int _SFalloc = 0;
static unsigned int _SFnum = 0;
static struct bindtable_t *BT_TimeShift;

/* create new cell in Floodtable */
int CheckFlood (short *ptr, short floodtype[2])
{
  unsigned int i;

  if (floodtype[0] <= 0)	/* don't check this flood */
    return 0;
  if (floodtype[1] <= 0)	/* oops! */
    return 1;
  for (i = 0; i < _SFnum; i++)	/* find if this is still here */
    if (Floodtable[i].ptr == ptr)
      break;
  if (i >= MAXTABLESIZE)
    bot_shutdown ("Internal error in CheckFlood()", 8);
  if (i >= _SFalloc)
  {
    _SFalloc += 32;
    safe_realloc ((void **)&Floodtable, (_SFalloc) * sizeof(shedfloodentry_t));
  }
  if (floodtype[1] > floodtype[0]) { /* 1 event per some time */
    (*ptr) += floodtype[1] / floodtype[0];
    Floodtable[i].count = 1;
  } else {			/* some events per second */
    (*ptr)++;
    Floodtable[i].count = floodtype[0] / floodtype[1];
  }
  if (i == _SFnum) {
    Floodtable[i].ptr = ptr;
    _SFnum++;
  }
  return ((*ptr) - floodtype[1]);
}

/* delete cells for ptr from Floodtable */
void NoCheckFlood (short *ptr)
{
  register size_t i;

  for (i = 0; i < _SFnum; i++)
    if (Floodtable[i].ptr == ptr)
    {
      _SFnum--;
      if (i != _SFnum)
	memcpy (&Floodtable[i], &Floodtable[_SFnum], sizeof(shedfloodentry_t));
    }
}

/* format: "time[,time,...]" where time is "*[/i]" or "a[-b[/i]]" */
static void _get_mask (char *mask, uint32_t *bitmap, long max)
{
  register long per, first, last;

  bitmap[0] = bitmap[1] = 0;
  while (mask && *mask)
  {
    if (*mask == '*')
    {
      first = 0;
      last = 63;
      mask++;
    }
    else
    {
      first = strtol (mask, &mask, 10);
      if (*mask == '-')
	last = strtol (&mask[1], &mask, 10);
      else
	last = 0;
    }
    if (*mask == '/')
    {
      per = strtol (&mask[1], &mask, 10);
      if (per <= 0)		/* user might set it wrong (thanks to denk) */
	per = 1;
    }
    else
      per = 1;
    while (first >= 0 && first < max)
    {
      if (first < 32)
	bitmap[0] |= (uint32_t)1 << first;
      else
	bitmap[1] |= (uint32_t)1 << (first-32);
      first += per;
      if (first > last)
	break;
    }
    mask = strchr (mask, ',');
    if (mask)
      mask++;
  }
}

//static pthread_mutex_t LockShed = PTHREAD_MUTEX_INITIALIZER;

typedef struct
{
  uint32_t min[2];
  uint32_t hour;
  uint32_t day;
  uint16_t month;
  uint16_t weekday;
  INTERFACE *iface;
  ifsig_t signal;
} shedentry_t;

static shedentry_t *Crontable = NULL;
static unsigned int _SCalloc = 0;
static unsigned int _SCnum = 0;

/* create new cell in Crontable */
void NewShedule (iftype_t ift, const char *name, ifsig_t sig,
		 char *min, char *hr, char *ds, char *mn, char *wk)
{
  INTERFACE *iface;

  if (ift == 0 || name == NULL)
    return;
  iface = Find_Iface (ift, name);
  if (iface)
  {
    Add_Schedule (iface, sig, min, hr, ds, mn, wk);
    Unset_Iface();
  }
  else
    WARNING ("NewShedule: interface %#x \"%s\" not found!", (int)ift, name);
}

void Add_Schedule (INTERFACE *iface, ifsig_t sig,
		   char *min, char *hr, char *ds, char *mn, char *wk)
{
  register shedentry_t *ct;
  uint32_t mask[2];

  if (iface == NULL)
    return;
//  pthread_mutex_lock (&LockShed);
  if (_SCnum >= MAXTABLESIZE)
  {
//    pthread_mutex_unlock (&LockShed);
    bot_shutdown ("Internal error in Add_Shedule()", 8);
  }
  if (_SCnum >= _SCalloc)
  {
    _SCalloc += 32;
    safe_realloc ((void **)&Crontable, (_SCalloc) * sizeof(shedentry_t));
  }
  ct = &Crontable[_SCnum];
  ct->iface = iface;
  ct->signal = sig;
  _get_mask (min, ct->min, 60);
  _get_mask (hr, mask, 24);
  ct->hour = mask[0];
  _get_mask (ds, mask, 31);
  ct->day = mask[0];
  _get_mask (mn, mask, 12);
  ct->month = (uint16_t)mask[0];
  _get_mask (wk, mask, 7);
  ct->weekday = (uint16_t)mask[0];
  _SCnum++;
//  pthread_mutex_unlock (&LockShed);
}

/* delete cell from Crontable */
void KillShedule (iftype_t ift, const char *name, ifsig_t sig,
		  char *min, char *hr, char *ds, char *mn, char *wk)
{
  INTERFACE *iface;

  if (ift == 0 || name == NULL)
    return;
  iface = Find_Iface (ift, name);
  if (iface)
  {
    Stop_Schedule (iface, sig, min, hr, ds, mn, wk);
    Unset_Iface();
  }
  else
    WARNING ("KillShedule: interface %#x \"%s\" not found!", (int)ift, name);
}

void Stop_Schedule (INTERFACE *iface, ifsig_t sig,
		    char *min, char *hr, char *ds, char *mn, char *wk)
{
  register size_t i;
  register shedentry_t *ct;
  uint32_t mask[2];

//  pthread_mutex_lock (&LockShed);
  for (i = 0; i < _SCnum; i++)
  {
    ct = &Crontable[i];
    if (ct->iface == iface)
    {
      _get_mask (min, mask, 60);
      ct->min[0] &= ~(mask[0]);
      ct->min[1] &= ~(mask[1]);
      _get_mask (hr, mask, 24);
      ct->hour &= ~(mask[0]);
      _get_mask (ds, mask, 31);
      ct->day &= ~(mask[0]);
      _get_mask (mn, mask, 12);
      ct->month &= ~((uint16_t)mask[0]);
      _get_mask (wk, mask, 7);
      ct->weekday &= ~((uint16_t)mask[0]);
      if (!ct->min[0] && !ct->min[1] && !ct->hour && !ct->day && !ct->month &&
	  !ct->weekday)
      {
	/* just mark it, it will be freed on next second iteration */
	ct->iface = NULL;
      }
    }
  }
//  pthread_mutex_unlock (&LockShed);
}

typedef struct
{
  time_t timer;
  tid_t id;
  INTERFACE *iface;
  ifsig_t signal;
} shedtimerentry_t;

static shedtimerentry_t *Timerstable = NULL;
static unsigned int _STalloc = 0;
static unsigned int _STnum = 0;
static tid_t _STid = 0;

/* create new cell in Timerstable */
tid_t NewTimer (iftype_t ift, const char *name, ifsig_t sig, unsigned int sec,
		unsigned int min, unsigned int hr, unsigned int ds)
{
  INTERFACE *iface;
  tid_t id = -1;

  if (ift == 0 || name == NULL)
    return id;
  iface = Find_Iface (ift, name);
  if (iface)
  {
    id = Add_Timer (iface, sig, sec + 60*min + 3600*hr + 86400*ds);
    Unset_Iface();
  }
  else
    WARNING ("NewTimer: interface %#x \"%s\" not found!", (int)ift, name);
  return id;
}

tid_t Add_Timer (INTERFACE *iface, ifsig_t sig, time_t timer)
{
  register shedtimerentry_t *ct;
  tid_t id = -1;
  register unsigned int i;

  if (iface == NULL)
    return -1;
//  pthread_mutex_lock (&LockShed);
  for (i = 0; i < _STnum; i++)
  {
    ct = &Timerstable[i];
    if (ct->iface == iface && ct->signal == sig && ct->timer == timer)
    {
      /* duplicate request, ignore it */
      id = ct->id;
      break;
    }
  }
  if (i < _STnum || _STnum >= MAXTABLESIZE)
  {
//    pthread_mutex_unlock (&LockShed);
    WARNING ("Add_Timer: failed for %s +%ld sec (entry %u id %d)", iface->name,
	     (long)timer, i, id);
    return id;
  }
  if (_STnum >= _STalloc)
  {
    _STalloc += 32;
    safe_realloc ((void **)&Timerstable, (_STalloc) * sizeof(shedtimerentry_t));
  }
  ct = &Timerstable[_STnum];
  ct->iface = iface;
  ct->signal = sig;
  ct->timer = timer;
  ct->id = id = _STid++;
  if (_STid < 0)
    _STid = 0;				/* never under zero! */
  _STnum++;
//  pthread_mutex_unlock (&LockShed);
  dprint (3, "Add_Timer: added for %s +%ld sec (id %d)", iface->name,
	  (long)timer, id);
  return id;
}

/* delete cell from Timerstable */
void KillTimer (tid_t tid)
{
  ssize_t i;

  if (tid < 0)
    return;
//  pthread_mutex_lock (&LockShed);
  Set_Iface (NULL);
  for (i = 0; (size_t)i < _STnum; i++)
  {
    if (Timerstable[i].id == tid)
    {
      /* just mark it, it will be freed on next second iteration */
      Timerstable[i].iface = NULL;
      break;
    }
  }
  if ((size_t)i == _STnum)
    i = -1;
//  pthread_mutex_unlock (&LockShed);
  Unset_Iface();
  if (i >= 0)
    dprint (3, "KillTimer: removed id %d", tid);
}

static time_t lasttime = 0;

static volatile sig_atomic_t running = FALSE;
static pthread_t pth_sched;

static iftype_t scheduler_signal (INTERFACE *iface, ifsig_t signal)
{
  switch (signal)
  {
    case S_TERMINATE:
      if (running)
      {
	running = FALSE;
	pthread_cancel(pth_sched);
	pthread_join(pth_sched, NULL);
	Add_Request (I_LOG, "*", F_BOOT, "Scheduler: terminated successfully.");
      }
      _SFnum = _STnum = _SCnum = 0;
      FREE(&Floodtable);
      FREE(&Timerstable);
      FREE(&Crontable);
      iface->ift = I_DIED;
      break;
    case S_SHUTDOWN:
      /* nothing to stop */
      break;
    default: ;
  }
  return 0;
}

static void *_scheduler_thread (void *data)
{
  INTERFACE *scheduler = data;
  int drift;
  struct tm tm;
  struct tm tm0;
  register unsigned int i, j = 0;
  struct binding_t *bind = NULL;
  struct timespec abstime;
  struct timespec req;

  if (clock_gettime(CLOCK_REALTIME, &abstime) != 0)
    //FIXME: how can it be?
    return NULL;
  FOREVER
  {
    /* let check if we were killed prior to anything */
    if (scheduler->ift & (I_FINWAIT | I_DIED))
      return NULL;

    /* if Init isn't finished yet, sleep */
    if (scheduler->ift & I_LOCKED)
      goto _do_sleep;

    /* we are awaken so let rock it */
    pthread_setcancelstate (PTHREAD_CANCEL_DISABLE, &drift);
    Set_Iface (scheduler);

    Time = abstime.tv_sec;
    drift = Time - lasttime;
    /* DBG("processing second %ld, drift %d", (long)Time, drift); */
    if (drift < 0 || drift > MAXDRIFT)	/* it seems system time was changed */
    {
      drift--;				/* assume 1 second passed */
      if (lasttime)			/* if it's on start then it's ok */
      {
	WARNING ("system time was slipped by %d seconds!", drift);
	while ((bind = Check_Bindtable (BT_TimeShift, "*", U_ALL, U_ANYCH, bind)))
	{
	  if (bind->name)
	    RunBinding (bind, NULL, NULL, NULL, NULL, drift, NULL);
	  else
	    bind->func (drift);
	}
      }
      drift = 1;			/* assume 1 second passed */
    }
    /* decrement floodtimers */
    for (i = 0; i < _SFnum; i++)
    {
      register int change = Floodtable[i].count * drift;

      DBG("decrementing flood counter by %hd from %hd", change, *Floodtable[i].ptr);
      if (*Floodtable[i].ptr <= change)
      {
	_SFnum--;
	j++;
	if (i != _SFnum)
	  memcpy (&Floodtable[i], &Floodtable[_SFnum], sizeof(shedfloodentry_t));
      } else
	*Floodtable[i].ptr -= change;
    }
    if (j)
      dprint (3, "Sheduler: removed %u flood timer(s), remained %u/%u",
	      j, _SFnum, MAXTABLESIZE);
//    pthread_mutex_lock (&LockShed);
    /* update time variables */
    localtime_r (&Time, &tm);
    if (lasttime == 0) {
      tm0.tm_min = -1;				/* enforce update on start */
      tm0.tm_mon = tm.tm_mon;			/* don't rotate Wtmp on start */
    } else
      localtime_r (&lasttime, &tm0);
    lasttime = Time;
    if (tm.tm_min != tm0.tm_min)
    {
      shedentry_t sh;
      register iftype_t rc;

      /* update datestamp */
      if (!strftime (TimeString, sizeof(TimeString), "%H:%M %e %b", &tm))
	WARNING ("Cannot form datestamp!");
      DateString[-1] = '\0';		/* split TimeString and DateString */
      /* flush all files */
      Send_Signal (I_FILE, "*", S_TIMEOUT);
      /* run Crontable; will not check for missed minutes due to BT_TimeShift */
      memset (&sh, 0, sizeof(sh));
      if (tm.tm_min > 31)
	sh.min[1] = (uint32_t)1 << (tm.tm_min-32);
      else
	sh.min[0] = (uint32_t)1 << tm.tm_min;
      sh.hour = (uint32_t)1 << tm.tm_hour;
      sh.day = (uint32_t)1 << tm.tm_mday;
      sh.month = (uint16_t)1 << (tm.tm_mon+1);
      sh.weekday = (uint16_t)1 << tm.tm_wday;
      for (i = 0; i < _SCnum; i++)
      {
	register shedentry_t *ct = &Crontable[i];

	if (ct->iface == NULL)
	  continue;
	if (((ct->min[0] & sh.min[0]) || (ct->min[1] & sh.min[1])) &&
	    (ct->hour & sh.hour) && (ct->day & sh.day) &&
	    (ct->month & sh.month) && (ct->weekday & sh.weekday))
	{
//	  pthread_mutex_unlock (&LockShed);
	  if (ct->iface->ift & I_DIED) ;	/* skip deads */
	  else if (ct->signal == S_WAKEUP)	/* special handling */
	    Mark_Iface (ct->iface);
	  else if (ct->iface->IFSignal &&
		   (rc = ct->iface->IFSignal (ct->iface, ct->signal)))
	    ct->iface->ift |= rc;
//	  pthread_mutex_lock (&LockShed);
	}
      }
      /* and now gather garbage, something might be freed */
      for (i = 0; i < _SCnum; i++)
      {
	register shedentry_t *ct = &Crontable[i];

	if (ct->iface != NULL)
	  continue;
	_SCnum--;
	if (i != _SCnum)
	  memcpy (ct, &Crontable[_SCnum], sizeof(shedentry_t));
      }
    }
    /* decrement timers */
    for (i = 0, j = 0; i < _STnum; i++)
    {
      register shedtimerentry_t *ct = &Timerstable[i];
      register iftype_t rc;

      if (ct->iface == NULL)
	continue;
      if (ct->timer > drift)
	ct->timer -= drift;
      else
      {
//	pthread_mutex_unlock (&LockShed);
	if (ct->iface->ift & I_DIED) ;		/* skip deads */
	else if (ct->signal == S_WAKEUP)	/* special handling */
	  Mark_Iface (ct->iface);
	else if (ct->iface->IFSignal &&
		 (rc = ct->iface->IFSignal (ct->iface, ct->signal)))
	  ct->iface->ift |= rc;
//	pthread_mutex_lock (&LockShed);
	ct->iface = NULL;
	j++;
      }
    }
    /* and now gather garbage, something might be freed */
    for (i = 0; i < _STnum; i++)
    {
      register shedtimerentry_t *ct = &Timerstable[i];

      if (ct->iface != NULL)
	continue;
      _STnum--;
      if (i != _STnum)
	memcpy (ct, &Timerstable[_STnum], sizeof(shedtimerentry_t));
    }
//    pthread_mutex_unlock (&LockShed);
    if (j)
      dprint (3, "Sheduler: sent %u timer signal(s), remained %u/%u",
	      j, _STnum, MAXTABLESIZE);
    /* check if we need Wtmp rotation and do it */
    if (tm.tm_mon != tm0.tm_mon)
    {
      dprint (3, "Sheduler: attempt of rotating Wtmp.");
      RotateWtmp();
    }
    Unset_Iface();
    pthread_setcancelstate (PTHREAD_CANCEL_ENABLE, &drift);

_do_sleep:
    /* and now sleep until next second */
    while (clock_gettime(CLOCK_REALTIME, &abstime) == 0 && abstime.tv_sec == Time)
    {
      req.tv_sec = 0;
      req.tv_nsec = 1000000001L - abstime.tv_nsec; /* 1 ns after next second */
      nanosleep(&req, NULL); /* this is where it can be cancelled by a signal */
    }
  }
}

void Status_Sheduler (INTERFACE *iface)
{
  register unsigned int a, b;

//  pthread_mutex_lock (&LockShed);
  b = _SCnum;
  a = _STnum;
//  pthread_mutex_unlock (&LockShed);
  New_Request (iface, 0, _("Timers: flood %u, once %u, periodic %u."),
	       _SFnum, a, b);
}

static INTERFACE *ShedIface = NULL;

char *IFInit_Sheduler (void)
{
  /* create/reset floodtimers table */
  if (!Floodtable)
  {
    Floodtable = safe_calloc (32, sizeof(shedfloodentry_t));
    _SFalloc = 32;
  }
  /* create/reset timers table */
  if (!Timerstable)
  {
    Timerstable = safe_calloc (32, sizeof(shedtimerentry_t));
    _STalloc = 32;
  }
  /* create/reset Crontable */
  if (!Crontable)
  {
    Crontable = safe_calloc (32, sizeof(shedentry_t));
    _SCalloc = 32;
  }
  if (running || _SFnum || _STnum || _SCnum)
  {
    ERROR ("sheduler.c:unclean restart: %uF/%uT/%uP", _SFnum, _STnum, _SCnum);
    _SFnum = _STnum = _SCnum = 0;
  }
  /* register "time-shift" bindtable */
  BT_TimeShift = Add_Bindtable ("time-shift", B_MASK);
  /* init time */
  time (&Time);
  /* create own interface - I_TEMP forever ;) */
  if (!ShedIface)
    ShedIface = Add_Iface (I_TEMP, NULL, &scheduler_signal, NULL, NULL);
  if (pthread_create(&pth_sched, NULL, &_scheduler_thread, ShedIface) == 0)
  {
    running = TRUE;
    Add_Request (I_LOG, "*", F_BOOT, "Scheduler: started successfully.");
  }
  else
    ERROR ("sheduler.c:failed to create a thread");
  return NULL;
}

/* should be called from dispatcher on interface freeing */
void _stop_timers (INTERFACE *iface)
{
  unsigned int i;

//  pthread_mutex_lock (&LockShed);
  for (i = 0; i < _SCnum; i++)
  {
    register shedentry_t *ct = &Crontable[i];

    if (ct->iface == iface)
      ct->iface = NULL;
  }
  for (i = 0; i < _STnum; i++)
  {
    register shedtimerentry_t *ct = &Timerstable[i];

    if (ct->iface == iface)
      ct->iface = NULL;
  }
//  pthread_mutex_unlock (&LockShed);
}
