/* 
 * The contents of this file are subject to the Mozilla Public
 * License Version 1.1 (the "License"); you may not use this file
 * except in compliance with the License. You may obtain a copy of
 * the License at http://www.mozilla.org/MPL/
 * 
 * Software distributed under the License is distributed on an "AS
 * IS" basis, WITHOUT WARRANTY OF ANY KIND, either express or
 * implied. See the License for the specific language governing
 * rights and limitations under the License.
 * 
 * The Original Code is the Netscape Portable Runtime library.
 * 
 * The Initial Developer of the Original Code is Netscape
 * Communications Corporation.  Portions created by Netscape are 
 * Copyright (C) 1994-2000 Netscape Communications Corporation.  All
 * Rights Reserved.
 * 
 * Contributor(s):  Silicon Graphics, Inc.
 * 
 * Portions created by SGI are Copyright (C) 2000-2001 Silicon
 * Graphics, Inc.  All Rights Reserved.
 * 
 * Alternatively, the contents of this file may be used under the
 * terms of the GNU General Public License Version 2 or later (the
 * "GPL"), in which case the provisions of the GPL are applicable 
 * instead of those above.  If you wish to allow use of your 
 * version of this file only under the terms of the GPL and not to
 * allow others to use your version of this file under the MPL,
 * indicate your decision by deleting the provisions above and
 * replace them with the notice and other provisions required by
 * the GPL.  If you do not delete the provisions above, a recipient
 * may use your version of this file under either the MPL or the
 * GPL.
 */

/*
 * This file is derived directly from Netscape Communications Corporation,
 * and consists of extensive modifications made during the year(s) 1999-2000.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include "common.h"

/* merge from https://github.com/toffaletti/state-threads/commit/7f57fc9acc05e657bca1223f1e5b9b1a45ed929b */
#ifndef NVALGRIND
#include <valgrind/valgrind.h>
#endif

#ifdef ST_ITERATE_CB
static _st_thread_t *_st_iterate_thread = NULL;
static void _st_iterate_schedule(void);
#define ST_DEBUG_ITERATE_THREADS() _st_iterate_schedule()
#else
#define ST_DEBUG_ITERATE_THREADS()
#endif

#ifdef ST_SWITCH_CB
#define ST_SWITCH_OUT_CB(_thread)		\
  if (_st_this_vp.switch_out_cb != NULL &&	\
    _thread != _st_this_vp.idle_thread) {	\
    _st_this_vp.switch_out_cb(_thread);		\
  }
#define ST_SWITCH_IN_CB()		\
  if (_st_this_vp.switch_in_cb != NULL &&	\
    _st_this_thread != _st_this_vp.idle_thread ) {	\
    _st_this_vp.switch_in_cb(_st_this_thread);		\
  }
#else
#define ST_SWITCH_OUT_CB(_thread)
#define ST_SWITCH_IN_CB()
#endif

static void _st_vp_init(_st_thread_t* thread);
static void _st_vp_swap(_st_thread_t* me, _st_thread_t* thread);
static void *_st_idle_thread_start(void *arg);
static void _st_vp_check_clock(void);

#ifdef ST_SHARED_STACK
extern _st_stack_t _st_primordial_stk;
static void* offset_sp(void* sp, long padding)
{
#if defined (MD_STACK_GROWS_DOWN)
  return (char*)sp - padding;
#elif defined (MD_STACK_GROWS_UP)
  return (char*)sp + padding;
#else
  #error Unknown OS
#endif
}
static void* aligned_sp(void* sp, long padding)
{
  sp = offset_sp(sp, padding);
#if defined (MD_STACK_GROWS_DOWN)
  if ((intptr_t)sp & 0x3f)
    sp = (char*)sp - ((intptr_t)sp & 0x3f);
#elif defined (MD_STACK_GROWS_UP)
  if ((unsigned long)sp & 0x3f)
    sp = (char*)sp + (0x40 - ((unsigned long)sp & 0x3f));
#else
  #error Unknown OS
#endif
  return sp;
}
#endif

/* Global data */
_st_vp_t _st_this_vp;           /* This VP */
_st_thread_t *_st_this_thread;  /* Current thread */
int _st_active_count = 0;       /* Active thread count */

time_t _st_curr_time = 0;       /* Current time as returned by time(2) */
st_utime_t _st_last_tset;       /* Last time it was fetched */


int st_poll(struct pollfd *pds, int npds, st_utime_t timeout)
{
  struct pollfd *pd;
  struct pollfd *epd = pds + npds;
  _st_thread_t *me = _ST_CURRENT_THREAD();
  int n;

  if (me->flags & _ST_FL_INTERRUPT) {
    me->flags &= ~_ST_FL_INTERRUPT;
    errno = EINTR;
    return -1;
  }

  if ((*_st_eventsys->pollset_add)(pds, npds) < 0)
    return -1;

  me->pq.pds = pds;
  me->pq.npds = npds;
  _ST_ADD_IOQ(me->pq);
  if (timeout != ST_UTIME_NO_TIMEOUT)
    _ST_ADD_SLEEPQ(me, timeout);
  me->state = _ST_ST_IO_WAIT;

  _ST_SWITCH_CONTEXT(me);

  n = 0;
  if (_ST_ON_IOQ(me->pq)) {
    /* If we timed out, the pollq might still be on the ioq. Remove it */
    _ST_DEL_IOQ(me->pq);
    (*_st_eventsys->pollset_del)(pds, npds);
  } else {
    /* Count the number of ready descriptors */
    for (pd = pds; pd < epd; pd++) {
      if (pd->revents)
        n++;
    }
  }

  if (me->flags & _ST_FL_INTERRUPT) {
    me->flags &= ~_ST_FL_INTERRUPT;
    errno = EINTR;
    return -1;
  }

  return n;
}

#ifdef ST_SHARED_STACK
static void _st_vp_save_stk(_st_thread_t* me, _st_thread_t **next)
{
  char *bsp;
  _st_stack_t *stack;
  _st_thread_t* thread;
  if (me) me->stack->sp = next;
  me = *next;
  if (me->stack->owner == me) return;
  thread = me->stack->owner;
  me->stack->owner = me;
  if (!thread) return;

  ST_ASSERT(thread->state != _ST_ST_ZOMBIE || thread->term);
  ST_ASSERT(thread->stklen == 0 && !thread->prvstk);

  bsp = thread->bsp;
  stack = thread->stack;
#if defined (MD_STACK_GROWS_DOWN)
  if ((char*)stack->sp < bsp) {
    thread->stklen = bsp - (char*)stack->sp;
    bsp = stack->sp;
  }
#elif defined (MD_STACK_GROWS_UP)
  if ((char*)stack->sp > bsp)
    thread->stklen = (char*)stack->sp - bsp;
#else
  #error Unknown OS
#endif
  else return;

  thread->prvstk = malloc(thread->stklen);
  memcpy(thread->prvstk, bsp, thread->stklen);
  if (thread->state == _ST_ST_IO_WAIT) {
    char* pds = (char*)thread->pq.pds;
    if (pds >= bsp && pds < bsp + thread->stklen)
      thread->pq.pds = (struct pollfd*)(thread->prvstk+(pds-bsp));
  }
#ifdef ST_ITERATE_CB
  if (!_st_iterate_thread)
#endif
  { ST_SWITCH_OUT_CB(thread); }
}
static void _st_vp_restore_stk(void)
{
  _st_thread_t* me = _ST_CURRENT_THREAD();
#ifdef ST_ITERATE_CB
  /* doing _st_iterate_threads */
  if (_st_iterate_thread) me = _st_iterate_thread;
#endif
  if (me->stklen > 0 || me->prvstk) {
    char *bsp = me->bsp;
#if defined (MD_STACK_GROWS_DOWN)
    bsp -= me->stklen;
#endif
    memcpy(bsp, me->prvstk, me->stklen);
    free(me->prvstk);
    me->stklen = 0;
    me->prvstk = NULL;
  }
}
#endif

void _st_vp_schedule(_st_thread_t* me)
{
  _st_thread_t *thread;
  ST_ASSERT(me->state != _ST_ST_RUNNING);

  if (_ST_RUNQ.next != &_ST_RUNQ) {
    /* Pull thread off of the run queue */
    thread = _ST_THREAD_PTR(_ST_RUNQ.next);
    _ST_DEL_RUNQ(thread);
  } else {
    /* If there are no threads to run, switch to the idle thread */
    thread = _st_this_vp.idle_thread;
  }
  ST_ASSERT(thread->state == _ST_ST_RUNNABLE);
  thread->state = _ST_ST_RUNNING;
  if (me == thread) return; /* no changed */
  else if (me->state == _ST_ST_ZOMBIE && !me->term) { /* dead */
    ST_SWITCH_OUT_CB(me);
    me = NULL;
  }
#ifndef ST_SHARED_STACK
  else { ST_SWITCH_OUT_CB(me); }
#endif

  _st_vp_swap(me, thread);

  ST_DEBUG_ITERATE_THREADS();
  ST_SWITCH_IN_CB();
}

/*
 * Initialize this Virtual Processor
 */
int st_init(void)
{
  _st_thread_t *thread;

  if (_st_this_vp.idle_thread) {
    /* Already initialized */
    return 0;
  }

  /* We can ignore return value here */
  if (!_st_eventsys) {
    if (st_cfg_eventsys(ST_EVENTSYS_DEFAULT) < 0)
      return -1;
  }

  if (_st_io_init() < 0)
    return -1;

  memset(&_st_this_vp, 0, sizeof(_st_vp_t));

  ST_INIT_CLIST(&_ST_RUNQ);
  ST_INIT_CLIST(&_ST_IOQ);
  ST_INIT_CLIST(&_ST_ZOMBIEQ);
#ifdef ST_ITERATE_CB
  ST_INIT_CLIST(&_ST_THREADQ);
#endif

  if ((*_st_eventsys->init)() < 0)
    return -1;

#ifdef _WIN32
  SYSTEM_INFO si;
  GetSystemInfo(&si);
  _st_this_vp.pagesize = si.dwPageSize;
#ifdef ST_SHARED_STACK
  _st_primordial_stk.vaddr_size = 
    (char*)si.lpMaximumApplicationAddress - (char*)si.lpMinimumApplicationAddress;
#endif
#else
  _st_this_vp.pagesize = getpagesize();
#endif
  _st_this_vp.last_clock = st_utime();

  /*
   * Initialize primordial thread
   */
  thread = _st_thread_alloc();
  if (!thread)
    return -1;
  thread->name = "INIT";
  thread->start = (void*)st_init;
  thread->state = _ST_ST_RUNNING;
  thread->flags = _ST_FL_PRIMORDIAL | _ST_FL_SHARED_STK;
#ifdef ST_SHARED_STACK
  thread->stack = &_st_primordial_stk;
  thread->stack->owner = thread;
  thread->stack->ref_count = 2; /* prevent release */
  thread->bsp = offset_sp(&thread, -sizeof(thread)*4);
#endif
  _ST_SET_CURRENT_THREAD(thread);
  _st_active_count++;
#ifdef ST_ITERATE_CB
  _ST_ADD_THREADQ(thread);
#endif
#ifdef MD_WINDOWS_FIBER
  thread->context = ConvertThreadToFiber(thread);
#endif

  /*
   * Create idle thread
   */
  _st_this_vp.idle_thread = st_thread_create(_st_idle_thread_start, NULL, 0, ST_DEFAULT_STACK_SIZE);
  if (!_st_this_vp.idle_thread)
  {
    free(thread);
    return -1;
  }
  _st_this_vp.idle_thread->name = "IDLE";
  _st_this_vp.idle_thread->flags = _ST_FL_IDLE_THREAD;
  _st_active_count--;
  _ST_DEL_RUNQ(_st_this_vp.idle_thread);
  return 0;
}


#ifdef ST_SWITCH_CB
st_switch_cb_t st_set_switch_in_cb(st_switch_cb_t cb)
{
  st_switch_cb_t ocb = _st_this_vp.switch_in_cb;
  _st_this_vp.switch_in_cb = cb;
  return ocb;
}

st_switch_cb_t st_set_switch_out_cb(st_switch_cb_t cb)
{
  st_switch_cb_t ocb = _st_this_vp.switch_out_cb;
  _st_this_vp.switch_out_cb = cb;
  return ocb;
}
#endif


/*
 * Start function for the idle thread
 */
/* ARGSUSED */
static void *_st_idle_thread_start(void *arg)
{
  _st_thread_t *me = _ST_CURRENT_THREAD();

  while (_st_active_count > 0) {
    /* Idle vp till I/O is ready or the smallest timeout expired */
    _ST_VP_IDLE();

    /* Check sleep queue for expired threads */
    _st_vp_check_clock();

    me->state = _ST_ST_RUNNABLE;
    _ST_SWITCH_CONTEXT(me);
  }
  fprintf(stderr, "\n** ST EXIT ** \n");
  /* No more threads */
#ifdef _WIN32
  WSACleanup();
  ExitThread(0);
#else
  pthread_exit(NULL);
#endif
  /* NOTREACHED */
  abort();
  return NULL;
}


void st_thread_exit(void *retval)
{
  _st_thread_t *thread = _ST_CURRENT_THREAD();

  thread->retval = retval;
  _st_thread_cleanup(thread);
  _st_active_count--;
  thread->state = _ST_ST_ZOMBIE;
  if (thread->term) {
    /* Put thread on the zombie queue */
    _ST_ADD_ZOMBIEQ(thread);

    /* Notify on our termination condition variable */
    st_cond_signal(thread->term);

    /* Switch context and come back later */
    _ST_SWITCH_CONTEXT(thread);

    /* Continue the cleanup */
    st_cond_destroy(thread->term);
    thread->term = NULL;
  }

#ifdef ST_ITERATE_CB
  _ST_DEL_THREADQ(thread);
#endif

#ifdef MD_WINDOWS_FIBER
  _st_thread_free(thread);
#else
  /* merge from https://github.com/toffaletti/state-threads/commit/7f57fc9acc05e657bca1223f1e5b9b1a45ed929b */
#ifndef NVALGRIND
  if (!(thread->flags & _ST_FL_SHARED_STK)) {
    VALGRIND_STACK_DEREGISTER(thread->stack->valgrind_stack_id);
  }
#endif
  do {
    _st_stack_t *stack = thread->stack;
#ifdef ST_SHARED_STACK
    if (thread->prvstk) 
      free(thread->prvstk);
    if (stack && stack->owner == thread)
      stack->owner = NULL;
#endif
    if (thread->flags & _ST_FL_SHARED_STK)
      _st_thread_free(thread);
    if (stack != NULL) /* no PRIMORDIAL stack */
      _st_stack_free(stack);
  } while (0);
#endif

  /* Find another thread to run */
  _ST_SWITCH_CONTEXT(thread);
  /* NOTREACHED */
  abort();
}


int st_thread_join(_st_thread_t *thread, void **retvalp)
{
  _st_cond_t *term = thread->term;

  /* Can't join a non-joinable thread */
  if (term == NULL) {
    errno = EINVAL;
    return -1;
  }
  if (_ST_CURRENT_THREAD() == thread) {
    errno = EDEADLK;
    return -1;
  }

  /* Multiple threads can't wait on the same joinable thread */
  if (term->wait_q.next != &term->wait_q) {
    errno = EINVAL;
    return -1;
  }

  while (thread->state != _ST_ST_ZOMBIE) {
    if (st_cond_timedwait(term, ST_UTIME_NO_TIMEOUT) != 0)
      return -1;
  }

  if (retvalp)
    *retvalp = thread->retval;

  /*
   * Remove target thread from the zombie queue and make it runnable.
   * When it gets scheduled later, it will do the clean up.
   */
  thread->state = _ST_ST_RUNNABLE;
  _ST_DEL_ZOMBIEQ(thread);
  _ST_ADD_RUNQ(thread);

  return 0;
}


static void _st_thread_main(void)
{
  _st_thread_t *thread;

  /*
   * Cap the stack by zeroing out the saved return address register
   * value. This allows some debugging/profiling tools to know when
   * to stop unwinding the stack. It's a no-op on most platforms.
   */
  MD_CAP_STACK(&thread);
  ST_DEBUG_ITERATE_THREADS();
  ST_SWITCH_IN_CB();

  /* Run thread main */
  thread = _ST_CURRENT_THREAD();
  thread->retval = (*thread->start)(thread->arg);

  /* All done, time to go away */
  st_thread_exit(thread->retval);
}


/*
 * Insert "thread" into the timeout heap, in the position
 * specified by thread->heap_index.  See docs/timeout_heap.txt
 * for details about the timeout heap.
 */
static _st_thread_t **heap_insert(_st_thread_t *thread) {
  int target = thread->heap_index;
  int s = target;
  _st_thread_t **p = &_ST_SLEEPQ;
  int bits = 0;
  int bit;
  int index = 1;

  while (s) {
    s >>= 1;
    bits++;
  }
  for (bit = bits - 2; bit >= 0; bit--) {
    if (thread->due < (*p)->due) {
      _st_thread_t *t = *p;
      thread->left = t->left;
      thread->right = t->right;
      *p = thread;
      thread->heap_index = index;
      thread = t;
    }
    index <<= 1;
    if (target & (1 << bit)) {
      p = &((*p)->right);
      index |= 1;
    } else {
      p = &((*p)->left);
    }
  }
  thread->heap_index = index;
  *p = thread;
  thread->left = thread->right = NULL;
  return p;
}


/*
 * Delete "thread" from the timeout heap.
 */
static void heap_delete(_st_thread_t *thread) {
  _st_thread_t *t, **p;
  int bits = 0;
  int s, bit;

  /* First find and unlink the last heap element */
  p = &_ST_SLEEPQ;
  s = _ST_SLEEPQ_SIZE;
  while (s) {
    s >>= 1;
    bits++;
  }
  for (bit = bits - 2; bit >= 0; bit--) {
    if (_ST_SLEEPQ_SIZE & (1 << bit)) {
      p = &((*p)->right);
    } else {
      p = &((*p)->left);
    }
  }
  t = *p;
  *p = NULL;
  --_ST_SLEEPQ_SIZE;
  if (t != thread) {
    /*
     * Insert the unlinked last element in place of the element we are deleting
     */
    t->heap_index = thread->heap_index;
    p = heap_insert(t);
    t = *p;
    t->left = thread->left;
    t->right = thread->right;

    /*
     * Reestablish the heap invariant.
     */
    for (;;) {
      _st_thread_t *y; /* The younger child */
      int index_tmp;
      if (t->left == NULL)
        break;
      else if (t->right == NULL)
        y = t->left;
      else if (t->left->due < t->right->due)
        y = t->left;
      else
        y = t->right;
      if (t->due > y->due) {
        _st_thread_t *tl = y->left;
        _st_thread_t *tr = y->right;
        *p = y;
        if (y == t->left) {
          y->left = t;
          y->right = t->right;
          p = &y->left;
        } else {
          y->left = t->left;
          y->right = t;
          p = &y->right;
        }
        t->left = tl;
        t->right = tr;
        index_tmp = t->heap_index;
        t->heap_index = y->heap_index;
        y->heap_index = index_tmp;
      } else {
        break;
      }
    }
  }
  thread->left = thread->right = NULL;
}


void _st_add_sleep_q(_st_thread_t *thread, st_utime_t timeout)
{
  thread->due = _ST_LAST_CLOCK + timeout;
  thread->flags |= _ST_FL_ON_SLEEPQ;
  thread->heap_index = ++_ST_SLEEPQ_SIZE;
  heap_insert(thread);
}


void _st_del_sleep_q(_st_thread_t *thread)
{
  heap_delete(thread);
  thread->flags &= ~_ST_FL_ON_SLEEPQ;
}


static void _st_vp_check_clock(void)
{
  _st_thread_t *thread;
  st_utime_t now;

  now = st_utime();
  _ST_LAST_CLOCK = now;

  if (_st_curr_time && now - _st_last_tset > 999000) {
    _st_curr_time = time(NULL);
    _st_last_tset = now;
  }

  while (_ST_SLEEPQ != NULL) {
    thread = _ST_SLEEPQ;
    ST_ASSERT(thread->flags & _ST_FL_ON_SLEEPQ);
    if (thread->due > now)
      break;
    _ST_DEL_SLEEPQ(thread);

    /* If thread is waiting on condition variable, set the time out flag */
    if (thread->state == _ST_ST_COND_WAIT)
      thread->flags |= _ST_FL_TIMEDOUT;

    /* Make thread runnable */
    ST_ASSERT(!(thread->flags & _ST_FL_IDLE_THREAD));
    thread->state = _ST_ST_RUNNABLE;
    _ST_ADD_RUNQ(thread);
  }
}


void st_thread_interrupt(_st_thread_t *thread)
{
  /* If thread is already dead */
  if (thread->state == _ST_ST_ZOMBIE)
    return;

  thread->flags |= _ST_FL_INTERRUPT;

  if (thread->state == _ST_ST_RUNNING || thread->state == _ST_ST_RUNNABLE)
    return;

  if (thread->flags & _ST_FL_ON_SLEEPQ)
    _ST_DEL_SLEEPQ(thread);

  /* Make thread runnable */
  thread->state = _ST_ST_RUNNABLE;
  _ST_ADD_RUNQ(thread);
}


/* Merge from https://github.com/michaeltalyansky/state-threads/commit/cce736426c2320ffec7c9820df49ee7a18ae638c */
#if defined(__arm__) && !defined(MD_USE_BUILTIN_SETJMP) && __GLIBC_MINOR__ >= 19
  extern unsigned long  __pointer_chk_guard;
  #define PTR_MANGLE(var) \
        (var) = (__typeof (var)) ((unsigned long) (var) ^ __pointer_chk_guard)
  #define PTR_DEMANGLE(var)     PTR_MANGLE (var)
#endif

_st_thread_t *st_thread_create(void *(*start)(void *arg), void *arg,
                   int joinable, int stk_size)
{
  _st_thread_t *thread;
#ifdef MD_WINDOWS_FIBER
  if (stk_size <= 0)
    stk_size = ST_DEFAULT_STACK_SIZE;
  stk_size = ((stk_size + _ST_PAGE_SIZE - 1) / _ST_PAGE_SIZE) * _ST_PAGE_SIZE;
  if (!(thread = _st_create_fiber((LPFIBER_START_ROUTINE)_st_thread_main, stk_size)))
    return NULL;
#else
  _st_stack_t *stack;
  void **ptds;
  char *sp;
#ifdef __ia64__
  char *bsp;
#endif
#ifdef ST_SHARED_STACK
  if (stk_size <= 0) {
    _st_thread_t *me = _ST_CURRENT_THREAD();
    thread = _st_thread_alloc();
    if (!thread) return NULL;
    thread->flags = _ST_FL_SHARED_STK;

    stack = me->stack;
    stack->ref_count++;
    stack->sp = aligned_sp(&thread, -stk_size);
    goto init_thread;
  }
#endif
  /* Adjust stack size */
  if (stk_size <= 0)
    stk_size = ST_DEFAULT_STACK_SIZE;
  stk_size = ((stk_size + _ST_PAGE_SIZE - 1) / _ST_PAGE_SIZE) * _ST_PAGE_SIZE;
  stack = _st_stack_new(stk_size);
  if (!stack)
    return NULL;

  /* Allocate thread object and per-thread data off the stack */
#if defined (MD_STACK_GROWS_DOWN)
  sp = stack->stk_top;
#ifdef __ia64__
  /*
   * The stack segment is split in the middle. The upper half is used
   * as backing store for the register stack which grows upward.
   * The lower half is used for the traditional memory stack which
   * grows downward. Both stacks start in the middle and grow outward
   * from each other.
   */
  sp -= (stk_size >> 1);
  bsp = sp;
  /* Make register stack 64-byte aligned */
  if ((unsigned long)bsp & 0x3f)
    bsp = bsp + (0x40 - ((unsigned long)bsp & 0x3f));
  stack->bsp = bsp + _ST_STACK_PAD_SIZE;
#endif
  sp = sp - (ST_KEYS_MAX * sizeof(void *));
  ptds = (void **) sp;
  sp = sp - sizeof(_st_thread_t);
  thread = (_st_thread_t *) sp;

  /* Make stack 64-byte aligned */
  if ((intptr_t)sp & 0x3f)
    sp = sp - ((intptr_t)sp & 0x3f);
  stack->sp = sp - _ST_STACK_PAD_SIZE;
#elif defined (MD_STACK_GROWS_UP)
  sp = stack->stk_bottom;
  thread = (_st_thread_t *) sp;
  sp = sp + sizeof(_st_thread_t);
  ptds = (void **) sp;
  sp = sp + (ST_KEYS_MAX * sizeof(void *));

  /* Make stack 64-byte aligned */
  if ((unsigned long)sp & 0x3f)
    sp = sp + (0x40 - ((unsigned long)sp & 0x3f));
  stack->sp = sp + _ST_STACK_PAD_SIZE;
#else
#error Unknown OS
#endif

  memset(thread, 0, sizeof(_st_thread_t));
  memset(ptds, 0, ST_KEYS_MAX * sizeof(void *));

  /* Initialize thread */
  thread->private_data = ptds;
#ifdef ST_SHARED_STACK
  stack->owner = thread;
  stack->ref_count = 1;
init_thread:
  thread->bsp = stack->sp;
#endif
  thread->stack = stack;
  _st_vp_init(thread);
#endif /* MD_WINDOWS_FIBER */
  thread->name = "";
  thread->start = start;
  thread->arg = arg;
  /* If thread is joinable, allocate a termination condition variable */
  if (joinable) {
    thread->term = st_cond_new();
    if (thread->term == NULL) {
#ifdef MD_WINDOWS_FIBER
      _st_thread_free(thread);
#else
      if (thread->flags & _ST_FL_SHARED_STK)
        _st_thread_free(thread);
      if (stack != NULL)
        _st_stack_free(stack);
#endif
      return NULL;
    }
  }

  /* Make thread runnable */
  thread->state = _ST_ST_RUNNABLE;
  _st_active_count++;
  _ST_ADD_RUNQ(thread);
#ifdef ST_ITERATE_CB
  _ST_ADD_THREADQ(thread);
#endif

  /* merge from https://github.com/toffaletti/state-threads/commit/7f57fc9acc05e657bca1223f1e5b9b1a45ed929b */
#ifndef NVALGRIND
  if (!(thread->flags & _ST_FL_SHARED_STK)) {
    thread->stack->valgrind_stack_id = VALGRIND_STACK_REGISTER(thread->stack->stk_top, thread->stack->stk_bottom);
  }
#endif

  return thread;
}


_st_thread_t *st_thread_self(void)
{
  return _ST_CURRENT_THREAD();
}
const char* st_thread_name(st_thread_t thread, const char *name)
{
  const char *old;
  if (!thread) thread = _ST_CURRENT_THREAD();
  old = thread->name;
  if (name) thread->name = name;
  return old;
}
static int fbytes(char* str, unsigned size)
{
  int i;
  if (size >= 1024*1024*1024)
    i = sprintf(str, "%dG", size/1024/1024/1024);
  else if (size >= 1024*1024)
    i = sprintf(str, "%dM", size/1024/1024);
  else if (size >= 1024)
    i = sprintf(str, "%dK", size/1024);
  else
    i = sprintf(str, "%d", size);
  return i;
}
char* st_thread_stats(st_thread_t thread, const char* format)
{
  static char ST_STATS[1024];
  const char* states = "*RFLCSZU", *p = format;
  int i=0;
  while (*p) {
    if (*p != '%') {
      ST_STATS[i++] = *p++;
      continue;
    }
    ++p;
    switch(*p) {
    case '\0': goto clean;
    case '%': ST_STATS[i++] = *p; break;
    case 'S':/* STATES Joinable PRIMORDIAL ON_SLEEPQ INTERRUPT TIMEDOUT SHARED_STK */
              ST_STATS[i++] = (thread->state != _ST_ST_ZOMBIE || thread->term) ? states[thread->state] : '-';
              ST_STATS[i++] = thread->term ? 'J' : '-';
              ST_STATS[i++] = (thread->flags & _ST_FL_PRIMORDIAL) ? 'P' : '-';
              ST_STATS[i++] = (thread->flags & _ST_FL_ON_SLEEPQ) ?  'Q' : '-';
              ST_STATS[i++] = (thread->flags & _ST_FL_INTERRUPT) ?  'I' : '-';
              ST_STATS[i++] = (thread->flags & _ST_FL_TIMEDOUT) ?   'T' : '-';
              ST_STATS[i++] = (thread->flags & _ST_FL_SHARED_STK) ? 'S' : '-';
              break;
#ifndef MD_WINDOWS_FIBER 
    case 's':/* valgrind_stack_id:stk_size/vaddr_size ref_count|stklen */
#ifndef NVALGRIND
              i += sprintf(ST_STATS+i, "%lu:", thread->stack->valgrind_stack_id);
#endif
              i += fbytes(ST_STATS+i, thread->stack->stk_size);
              ST_STATS[i++] = '/';
              i += fbytes(ST_STATS+i, thread->stack->vaddr_size);
#ifdef ST_SHARED_STACK
              i += sprintf(ST_STATS+i, " %d", thread->stack->ref_count);
              ST_STATS[i++] = '|';
              i += fbytes(ST_STATS+i, thread->stklen);
#endif
              break;
#endif
    case 'a':
              i += sprintf(ST_STATS+i, "%p(%p)", thread->start, thread->arg);
              break;
#ifdef ST_SHARED_STACK
    case 'b':
              i += sprintf(ST_STATS+i, "%p", thread->bsp);
              break;
#endif
    case 'n':
              i += sprintf(ST_STATS+i,"%s", thread->name);
              break;
    }
    ++p;
  }
clean:
  ST_STATS[i++] = '\0';
  return ST_STATS;
}

#ifdef ST_ITERATE_CB
/* To be set from debugger */
st_iterate_cb_t _st_iterate_threads_cb = NULL;
void st_iterate_threads(st_iterate_cb_t cb)
{
  _st_iterate_threads_cb = cb;
  _st_iterate_schedule();
}
static void _st_iterate_schedule(void)
{
  while (_st_iterate_threads_cb || _st_iterate_thread) {
    _st_thread_t* thread = _st_iterate_thread;
    if (!thread) {
      _st_iterate_thread = thread = _ST_CURRENT_THREAD();
      _st_iterate_threads_cb(thread, ST_ITERATE_FLAG_BEGIN);
    }
    else if (thread == _ST_CURRENT_THREAD()) {
      st_iterate_cb_t cb = _st_iterate_threads_cb;
      _st_iterate_thread = NULL;
      _st_iterate_threads_cb = NULL;
      cb(thread, ST_ITERATE_FLAG_END);
      continue;
    }
    else {
      _st_iterate_threads_cb(thread, 0);
    }

    if (_st_iterate_threads_cb) {
      _st_clist_t *q;
      q = thread->tlink.next;
      if (q == &_ST_THREADQ)
        q = q->next;
      ST_ASSERT(q != &_ST_THREADQ);
      _st_iterate_thread = _ST_THREAD_THREADQ_PTR(q);
    }
    else if (thread == _st_iterate_thread)
      _st_iterate_thread = _ST_CURRENT_THREAD();

    if (_st_iterate_thread != thread && _st_iterate_thread)
      _st_vp_swap(thread, _st_iterate_thread);
  }
}
#endif /* ST_ITERATE_CB */

#if defined(_MSC_VER) && defined(ST_SHARED_STACK)
#pragma optimize("", off) /* vc will optimize the shared_stk wrong */
#endif
static void _st_vp_swap(_st_thread_t* me, _st_thread_t* thread)
{
#ifdef ST_SHARED_STACK
#if defined(_MSC_VER)
  _st_thread_t *next = thread;
  _st_vp_save_stk(me, &next);
#else
  _st_vp_save_stk(me, &thread);
#endif
#endif

  if (!me || !MD_SETJMP(me->context)) {
#ifdef ST_ITERATE_CB
    if (!_st_iterate_thread)
#endif
    { _ST_SET_CURRENT_THREAD(thread); }
    /* Resume the thread */
    MD_LONGJMP(thread->context, 1);

    /* Not going to land here */
#ifndef MD_WINDOWS_FIBER
    abort();
#endif
  }

  /* Resume the current thread */
#ifdef ST_SHARED_STACK
  _st_vp_restore_stk();
#endif
}

#ifndef MD_WINDOWS_FIBER
static void _st_vp_init(_st_thread_t* thread)
{
#ifndef __ia64__
  /* Merge from https://github.com/michaeltalyansky/state-threads/commit/cce736426c2320ffec7c9820df49ee7a18ae638c */
#if defined(__arm__) && !defined(MD_USE_BUILTIN_SETJMP) && __GLIBC_MINOR__ >= 19
  volatile void * lsp = PTR_MANGLE(thread->stack->sp);
  if (_setjmp ((thread)->context))
    _st_thread_main();
  (thread)->context[0].__jmpbuf[8] = (long) (lsp);
#else
  MD_INIT_CONTEXT(thread, thread->stack->sp, _st_thread_main);
#endif
#else
  MD_INIT_CONTEXT(thread, thread->stack->sp, thread->stack->bsp, _st_thread_main);
#endif
}
#endif
