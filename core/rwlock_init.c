/*
 * Copyright (C) 2005-2010  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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
 * This file is part of FoxEye's source: own implementation of Sun's
 *      read-write locks
 */

#include "foxeye.h"

/* locks order: wr, ct, rd */
struct rwlock_t {
  pthread_mutex_t ct; /* set while testing x */
  pthread_mutex_t wr; /* set while writer waits and works */
  pthread_mutex_t rd; /* set while read or write */
  unsigned int x; /* count of readers working */
};

int rwlock_init (rwlock_t *rwp, int type, void *u)
{
  if (type != USYNC_THREAD)
    return -1;
  pthread_mutex_init (&rwp->ct, NULL);
  pthread_mutex_init (&rwp->rd, NULL);
  pthread_mutex_init (&rwp->wr, NULL);
  rwp->x = 0;
  return 0;
}

int rw_rdlock (rwlock_t *rwp)
{
  unsigned int x;

  pthread_mutex_lock (&rwp->wr); /* wait while write unlocks */
  pthread_mutex_lock (&rwp->ct);
  x = rwp->x++; /* it's 1 now if no other readers and >1 if there were */
  pthread_mutex_unlock (&rwp->ct); /* avoid deadlock by unlocking immediately */
  if (x == 0)
    pthread_mutex_lock (&rwp->rd); /* no lock yet so set it */
  pthread_mutex_unlock (&rwp->wr);
  return 0;
}

int rw_tryrdlock (rwlock_t *rwp)
{
  int n;

  n = pthread_mutex_trylock (&rwp->wr);
  if (n != 0) /* failed on write */
    return n;
  pthread_mutex_lock (&rwp->ct);
  if (rwp->x == 0)
    n = pthread_mutex_trylock (&rwp->rd);
  else
    n = 0;
  if (n == 0) /* succeed */
    rwp->x++;
  pthread_mutex_unlock (&rwp->ct);
  pthread_mutex_unlock (&rwp->wr);
  return n;
}

int rw_wrlock (rwlock_t *rwp)
{
  pthread_mutex_lock (&rwp->wr); /* lock both write and read */
  return pthread_mutex_lock (&rwp->rd);
}

int rw_trywrlock (rwlock_t *rwp)
{
  int n = pthread_mutex_trylock (&rwp->wr);
  if (n != 0)
    return n; /* fail on write lock */
  n = pthread_mutex_trylock (&rwp->rd);
  if (n != 0)
    pthread_mutex_unlock (&rwp->wr); /* fail on read lock */
  return n;
}

int rw_unlock (rwlock_t *rwp)
{
  pthread_mutex_lock (&rwp->ct);
  if (rwp->x > 0)
    rwp->x--; /* it was read lock */
  else
    pthread_mutex_unlock (&rwp->wr); /* it was write lock */
  if (rwp->x == 0)
    pthread_mutex_unlock (&rwp->rd); /* read is unlocked now */
  pthread_mutex_unlock (&rwp->ct);
  return 0;
}

int rwlock_destroy (rwlock_t *rwp)
{
  pthread_mutex_destroy (&rwp->ct);
  pthread_mutex_destroy (&rwp->wr);
  pthread_mutex_destroy (&rwp->rd);
  return 0;
}
