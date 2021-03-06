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

#ifndef __ST_COMMON_H__
#define __ST_COMMON_H__

#include <stddef.h>
#include <sys/types.h>
#include <setjmp.h>

/* Enable assertions only if DEBUG is defined */
#if !defined(DEBUG) && !defined(NDEBUG)
#define DEBUG 1
#endif
#include <assert.h>
#define ST_ASSERT(expr) assert(expr)

#define ST_BEGIN_MACRO  {
#define ST_END_MACRO    }

#ifdef DEBUG
#define ST_HIDDEN   /*nothing*/
#else
#define	ST_HIDDEN   static
#endif
#include "st.h"
#include "md.h"
#ifndef MD_WINDOWS_FIBER
#define ST_SHARED_STACK
#endif

/* merge from https://github.com/toffaletti/state-threads/commit/7f57fc9acc05e657bca1223f1e5b9b1a45ed929b */
#ifndef MD_VALGRIND
    #ifndef NVALGRIND
        #define NVALGRIND
    #endif
#else
    #undef NVALGRIND
#endif


/*****************************************
 * Circular linked list definitions
 */

typedef struct _st_clist {
  struct _st_clist *next;
  struct _st_clist *prev;
} _st_clist_t;

/* Insert element "_e" into the list, before "_l" */
#define ST_INSERT_BEFORE(_e,_l)	 \
    ST_BEGIN_MACRO		 \
	(_e)->next = (_l);	 \
	(_e)->prev = (_l)->prev; \
	(_l)->prev->next = (_e); \
	(_l)->prev = (_e);	 \
    ST_END_MACRO

/* Insert element "_e" into the list, after "_l" */
#define ST_INSERT_AFTER(_e,_l)	 \
    ST_BEGIN_MACRO		 \
	(_e)->next = (_l)->next; \
	(_e)->prev = (_l);	 \
	(_l)->next->prev = (_e); \
	(_l)->next = (_e);	 \
    ST_END_MACRO

/* Return the element following element "_e" */
#define ST_NEXT_LINK(_e)  ((_e)->next)

/* Append an element "_e" to the end of the list "_l" */
#define ST_APPEND_LINK(_e,_l) ST_INSERT_BEFORE(_e,_l)

/* Insert an element "_e" at the head of the list "_l" */
#define ST_INSERT_LINK(_e,_l) ST_INSERT_AFTER(_e,_l)

/* Return the head/tail of the list */
#define ST_CLIST_HEAD(_l) (_l)->next
#define ST_CLIST_TAIL(_l) (_l)->prev

/* Remove the element "_e" from it's circular list */
#define ST_REMOVE_LINK(_e)	       \
    ST_BEGIN_MACRO		       \
	(_e)->prev->next = (_e)->next; \
	(_e)->next->prev = (_e)->prev; \
    (_e)->next = (_e)->prev = NULL;\
    ST_END_MACRO

#define ST_IS_LINK(_e) \
    ( (_e)->next || (_e)->prev)

/* Return non-zero if the given circular list "_l" is empty, */
/* zero if the circular list is not empty */
#define ST_CLIST_IS_EMPTY(_l) \
    ((_l)->next == (_l))

/* Initialize a circular list */
#define ST_INIT_CLIST(_l)  \
    ST_BEGIN_MACRO	   \
	(_l)->next = (_l); \
	(_l)->prev = (_l); \
    ST_END_MACRO

#define ST_INIT_STATIC_CLIST(_l) \
    {(_l), (_l)}


/*****************************************
 * Basic types definitions
 */

typedef void  (*_st_destructor_t)(void *);
typedef struct _st_thread _st_thread_t;


typedef struct _st_stack {
  _st_clist_t links;
  char *vaddr;                /* Base of stack's allocated memory */
  int  vaddr_size;            /* Size of stack's allocated memory */
  int  stk_size;              /* Size of usable portion of the stack */
  char *stk_bottom;           /* Lowest address of stack's usable portion */
  char *stk_top;              /* Highest address of stack's usable portion */
  void *sp;                   /* Stack pointer from C's point of view */
#ifdef __ia64__
  void *bsp;                  /* Register stack backing store pointer */
#endif
  /* merge from https://github.com/toffaletti/state-threads/commit/7f57fc9acc05e657bca1223f1e5b9b1a45ed929b */
#ifndef NVALGRIND
  /* id returned by VALGRIND_STACK_REGISTER */
  /* http://valgrind.org/docs/manual/manual-core-adv.html */
  unsigned long valgrind_stack_id;
#endif
#ifdef ST_SHARED_STACK
  int ref_count;              /* shared reference count */
  _st_thread_t *owner;        /* the running thread */
#endif
} _st_stack_t;


typedef struct _st_cond {
  _st_clist_t wait_q;	      /* Condition variable wait queue */
} _st_cond_t;


typedef struct _st_pollq {
  _st_clist_t links;          /* For putting on io queue */
  struct pollfd *pds;         /* Array of poll descriptors */
  int npds;                   /* Length of the array */
} _st_pollq_t;

struct _st_thread {
  const char* name;
  int state;                  /* Thread's state */
  int flags;                  /* Thread's flags */

  void *(*start)(void *arg);  /* The start function of the thread */
  void *arg;                  /* Argument of the start function */
  void *retval;               /* Return value of the start function */
#ifdef MD_WINDOWS_FIBER 
  LPVOID context;             /* fiber's handle */
#else
  _st_stack_t *stack;	      /* Info about thread's stack */
#ifdef ST_SHARED_STACK
  char *bsp, *prvstk;
  size_t stklen;
#endif
  jmp_buf context;            /* Thread's context */
#endif
  _st_clist_t links;          /* For putting on run/sleep/zombie queue */
  _st_clist_t wait_links;     /* For putting on mutex/condvar wait queue */
#ifdef ST_ITERATE_CB
  _st_clist_t tlink;          /* For putting on thread queue */
#endif

  st_utime_t due;             /* Wakeup time when thread is sleeping */
  _st_thread_t *left;         /* For putting in timeout heap */
  _st_thread_t *right;	      /* -- see docs/timeout_heap.txt for details */
  int heap_index;

  void **private_data;        /* Per thread private data */

  _st_cond_t *term;           /* Termination condition variable for join */
  _st_pollq_t pq;             /* For putting on io_q queue */
  void (*atexit_cb)(void* arg, void* retval);
  void* atexit_arg;
};


typedef struct _st_mutex {
  _st_thread_t *owner;        /* Current mutex owner */
  _st_clist_t  wait_q;        /* Mutex wait queue */
} _st_mutex_t;




typedef struct _st_eventsys_ops {
  const char *name;                          /* Name of this event system */
  int  val;                                  /* Type of this event system */
  int  (*init)(void);                        /* Initialization */
  void (*dispatch)(void);                    /* Dispatch function */
  int  (*pollset_add)(struct pollfd *, int); /* Add descriptor set */
  void (*pollset_del)(struct pollfd *, int); /* Delete descriptor set */
  int  (*fd_new)(int);                       /* New descriptor allocated */
  int  (*fd_close)(int);                     /* Descriptor closed */
  int  (*fd_getlimit)(void);                 /* Descriptor hard limit */
} _st_eventsys_t;


typedef struct _st_vp {
  _st_thread_t *idle_thread;  /* Idle thread for this vp */
  st_utime_t last_clock;      /* The last time we went into vp_check_clock() */

  _st_clist_t run_q;          /* run queue for this vp */
  _st_clist_t io_q;           /* io queue for this vp */
  _st_clist_t zombie_q;       /* zombie queue for this vp */
#ifdef ST_ITERATE_CB
  _st_clist_t thread_q;       /* all threads of this vp */
#endif
  int pagesize;

  _st_thread_t *sleep_q;      /* sleep queue for this vp */
  int sleepq_size;	      /* number of threads on sleep queue */

#ifdef ST_SWITCH_CB
  st_switch_cb_t switch_out_cb;	/* called when a thread is switched out */
  st_switch_cb_t switch_in_cb;	/* called when a thread is switched in */
#endif
  void (*atexit_cb)();
#ifdef DEBUG
  int num_threads;
  int num_free_threads;
  int num_stacks;
  int num_free_stacks;
#endif
} _st_vp_t;


typedef struct _st_netfd {
  SOCKET osfd;                   /* Underlying OS file descriptor */
  int inuse;                  /* In-use flag */
  void *private_data;         /* Per descriptor private data */
  _st_destructor_t destructor; /* Private data destructor function */
  void *aux_data;             /* Auxiliary data for internal use */
  struct _st_netfd *next;     /* For putting on the free list */
#ifdef ST_HOOK_SYS
  st_utime_t snd_timeo, rcv_timeo;
#endif
} _st_netfd_t;


/*****************************************
 * Current vp, thread, and event system
 */

extern _st_vp_t	    _st_this_vp;
extern _st_thread_t *_st_this_thread;
extern _st_eventsys_t *_st_eventsys;

#define _ST_CURRENT_THREAD()            (_st_this_thread)
#define _ST_SET_CURRENT_THREAD(_thread) (_st_this_thread = (_thread))

#define _ST_LAST_CLOCK                  (_st_this_vp.last_clock)

#define _ST_RUNQ                        (_st_this_vp.run_q)
#define _ST_IOQ                         (_st_this_vp.io_q)
#define _ST_ZOMBIEQ                     (_st_this_vp.zombie_q)
#ifdef ST_ITERATE_CB
#define _ST_THREADQ                     (_st_this_vp.thread_q)
#endif

#define _ST_PAGE_SIZE                   (_st_this_vp.pagesize)

#define _ST_SLEEPQ                      (_st_this_vp.sleep_q)
#define _ST_SLEEPQ_SIZE                 (_st_this_vp.sleepq_size)

#define _ST_VP_IDLE()                   (*_st_eventsys->dispatch)()


/*****************************************
 * vp queues operations
 */

#define _ST_ADD_IOQ(_pq)    ST_APPEND_LINK(&_pq.links, &_ST_IOQ)
#define _ST_DEL_IOQ(_pq)    ST_REMOVE_LINK(&_pq.links)
#define _ST_ON_IOQ(_pq)     ST_IS_LINK(&_pq.links)

#define _ST_ADD_RUNQ(_thr)  ST_APPEND_LINK(&(_thr)->links, &_ST_RUNQ)
#define _ST_DEL_RUNQ(_thr)  ST_REMOVE_LINK(&(_thr)->links)

#define _ST_ADD_SLEEPQ(_thr, _timeout)  _st_add_sleep_q(_thr, _timeout)
#define _ST_DEL_SLEEPQ(_thr)		_st_del_sleep_q(_thr)

#define _ST_ADD_ZOMBIEQ(_thr)  ST_APPEND_LINK(&(_thr)->links, &_ST_ZOMBIEQ)
#define _ST_DEL_ZOMBIEQ(_thr)  ST_REMOVE_LINK(&(_thr)->links)

#ifdef ST_ITERATE_CB
#define _ST_ADD_THREADQ(_thr)  ST_APPEND_LINK(&(_thr)->tlink, &_ST_THREADQ)
#define _ST_DEL_THREADQ(_thr)  ST_REMOVE_LINK(&(_thr)->tlink)
#endif


/*****************************************
 * Thread states and flags
 */

#define _ST_ST_RUNNING      0 
#define _ST_ST_RUNNABLE     1
#define _ST_ST_IO_WAIT      2
#define _ST_ST_LOCK_WAIT    3
#define _ST_ST_COND_WAIT    4
#define _ST_ST_SLEEPING     5
#define _ST_ST_ZOMBIE       6
#define _ST_ST_SUSPENDED    7

#define _ST_FL_PRIMORDIAL   0x01
#define _ST_FL_IDLE_THREAD  0x02
#define _ST_FL_ON_SLEEPQ    0x04
#define _ST_FL_INTERRUPT    0x08
#define _ST_FL_TIMEDOUT     0x10
#define _ST_FL_SHARED_STK   0x20


/*****************************************
 * Pointer conversion
 */

#ifndef offsetof
#define offsetof(type, identifier) ((size_t)&(((type *)0)->identifier))
#endif

#define _ST_THREAD_PTR(_qp)         \
    ((_st_thread_t *)((char *)(_qp) - offsetof(_st_thread_t, links)))

#define _ST_THREAD_WAITQ_PTR(_qp)   \
    ((_st_thread_t *)((char *)(_qp) - offsetof(_st_thread_t, wait_links)))

#define _ST_STACK_PTR(_qp)  \
    ((_st_stack_t *)((char*)(_qp) - offsetof(_st_stack_t, links)))

#define _ST_POLLQUEUE_PTR(_qp)      \
    ((_st_pollq_t *)((char *)(_qp) - offsetof(_st_pollq_t, links)))

#define _ST_THREAD_PQ_PTR(_qp) \
    ((_st_thread_t *)((char *)(pq) - offsetof(_st_thread_t, pq)))

#ifdef ST_ITERATE_CB
#define _ST_THREAD_THREADQ_PTR(_qp) \
    ((_st_thread_t *)((char *)(_qp) - offsetof(_st_thread_t, tlink)))
#endif


/*****************************************
 * Constants
 */

#ifndef ST_UTIME_NO_TIMEOUT
#define ST_UTIME_NO_TIMEOUT ((st_utime_t) -1LL)
#endif

#ifndef ST_KEYS_MAX
#define ST_KEYS_MAX 16
#endif

#ifndef ST_MIN_POLLFDS_SIZE
#define ST_MIN_POLLFDS_SIZE 64
#endif


/*****************************************
 * Threads context switching
 */

/*
 * Switch away from the current thread context by saving its state and
 * calling the thread scheduler
 */
#define _ST_SWITCH_CONTEXT(_thread)       \
    ST_BEGIN_MACRO                        \
    _st_vp_schedule(_thread);             \
    ST_END_MACRO

/*
 * Number of bytes reserved under the stack "bottom"
 */
#define _ST_STACK_PAD_SIZE MD_STACK_PAD_SIZE

#ifdef ST_HOOK_SYS
#define _ST_SYS_CALL(func) func##_f
#ifdef _WIN32
extern int (WSAAPI *select_f)(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timeval *timeout);
#else
extern int (WSAAPI *select_f)(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
#endif
extern int (WSAAPI *poll_f)(struct pollfd *fds, nfds_t nfds, int timeout);
#ifdef MD_HAVE_EPOLL
struct epoll_event;
extern int (*epoll_wait_f)(int epfd, struct epoll_event *events, int maxevents, int timeout);
#endif
#else
#define _ST_SYS_CALL(func) func
#endif

/*****************************************
 * Forward declarations
 */

void _st_vp_schedule(_st_thread_t *thread);
void _st_thread_cleanup(_st_thread_t *thread);
void _st_add_sleep_q(_st_thread_t *thread, st_utime_t timeout);
void _st_del_sleep_q(_st_thread_t *thread);
#define ST_SIZEOF_KEYS_THREAD (sizeof(_st_thread_t) + (ST_KEYS_MAX * sizeof(void *)))
void _st_thread_free(_st_thread_t *thread);
_st_thread_t* _st_thread_alloc();
#ifdef MD_WINDOWS_FIBER
_st_thread_t *_st_create_fiber(LPFIBER_START_ROUTINE routine, int stk_size);
#else
_st_stack_t *_st_stack_new(int stack_size);
void _st_stack_free(_st_stack_t *ts);
#endif
int _st_io_init(void);

st_utime_t st_utime(void);
_st_cond_t *st_cond_new(void);
int st_cond_destroy(_st_cond_t *cvar);
int st_cond_timedwait(_st_cond_t *cvar, st_utime_t timeout);
int st_cond_signal(_st_cond_t *cvar);
ssize_t st_read(_st_netfd_t *fd, void *buf, size_t nbyte, st_utime_t timeout);
ssize_t st_write(_st_netfd_t *fd, const void *buf, size_t nbyte,
		 st_utime_t timeout);
int st_poll(struct pollfd *pds, int npds, st_utime_t timeout);
_st_thread_t *st_thread_create(void *(*start)(void *arg), void *arg,
			      int joinable, int stk_size);

#endif /* !__ST_COMMON_H__ */

