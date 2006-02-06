/* ----------------------------------------------------------------------------
 * FoxEye implementation of Sun's read-write locks
 */

#define USYNC_THREAD 0

typedef struct {
  pthread_mutex_t rd;
  pthread_mutex_t wr;
  unsigned int x;
} rwlock_t;

int rwlock_init (rwlock_t *, int, void *);
int rw_rdlock (rwlock_t *);
int rw_tryrdlock (rwlock_t *);
#define rw_wrlock(a) pthread_mutex_lock(&(a)->wr)
#define rw_trywrlock(a) pthread_mutex_trylock(&(a)->wr)
int rw_unlock (rwlock_t *);
int rwlock_destroy (rwlock_t *);
