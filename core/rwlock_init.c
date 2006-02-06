/* ----------------------------------------------------------------------------
 * FoxEye implementation of Sun's read-write locks
 */

#include <pthread.h>
#include "rwlock_init.h"

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
  rwp->x++;
  pthread_mutex_unlock (&rwp->rd);
  return n;
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
