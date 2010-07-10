/*
 * Copyright (C) 2005-2006  Andrej N. Gritsenko <andrej@rep.kiev.ua>
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

struct rwlock_t {
  pthread_mutex_t rd;
  pthread_mutex_t wr;
  unsigned int x;
};

int rwlock_init (rwlock_t *rwp, int type, void *u)
{
  if (type != USYNC_THREAD)
    return -1;
  pthread_mutex_init (&rwp->rd, NULL);
  pthread_mutex_init (&rwp->wr, NULL);
  rwp->x = 0;
  return 0;
}

int rw_rdlock (rwlock_t *rwp)
{
  pthread_mutex_lock (&rwp->rd);
  if (rwp->x == 0)
    pthread_mutex_lock (&rwp->wr);
  rwp->x++;
  pthread_mutex_unlock (&rwp->rd);
  return 0;
}

int rw_tryrdlock (rwlock_t *rwp)
{
  int n;

  pthread_mutex_lock (&rwp->rd);
  if (rwp->x == 0)
    n = pthread_mutex_trylock (&rwp->wr);
  else
    n = 0;
  if (n == 0) /* succeed */
    rwp->x++;
  pthread_mutex_unlock (&rwp->rd);
  return n;
}

int rw_wrlock (rwlock_t *rwp)
{
  return pthread_mutex_lock (&rwp->wr);
}

int rw_trywrlock (rwlock_t *rwp)
{
  return pthread_mutex_trylock (&rwp->wr);
}

int rw_unlock (rwlock_t *rwp)
{
  pthread_mutex_lock (&rwp->rd);
  if (rwp->x > 0)
    rwp->x--;
  if (rwp->x == 0)
    pthread_mutex_unlock (&rwp->wr);
  pthread_mutex_unlock (&rwp->rd);
  return 0;
}

int rwlock_destroy (rwlock_t *rwp)
{
  pthread_mutex_destroy (&rwp->wr);
  pthread_mutex_destroy (&rwp->rd);
  return 0;
}
