#include "pt.h"
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#define PT_CONF_NUMEVENTS  32
#ifndef NDEBUG
#define PRINTF(...) printf(__VA_ARGS__)
#else
#define PRINTF(...)
#endif

#define THREAD_NAME(p) (p ? p->name : "NUL")
enum {
  PT_STATE_RUNNING = 1,
  PT_STATE_POLLING = 2,
  PT_STATE_CALLED  = 4,
};

/*
 * Pointer to the currently running process structure.
 */
static struct PT *_list = NULL, *_current = NULL;
/*
 * Structure used for keeping the queue of active events.
 */
struct event_data {
  PT_EVENT event;
  void* data;
  struct PT *p;
  PT_MASK mask;
};
#ifdef PT_CONF_STATS
static int _maxevents;
#endif
static int _nevents, _fevent;
static struct event_data _events[PT_CONF_NUMEVENTS];

/* return next one */
static struct PT* exit_thread(struct PT *p, struct PT *from, PT_MASK mask);
static struct PT* call_thread(struct PT *p, PT_EVENT ev, void* data);
static void do_event(void);
static volatile char _poll_requested;
static void do_poll(void)
{
  struct PT *p;

  _poll_requested = 0;
  /* Call the thread that needs to be polled. */
  for (p = _list; p != NULL;) {
    if (p->state&PT_STATE_POLLING) {
      p->state &= ~PT_STATE_POLLING;
      p = call_thread(p, PT_EVENT_POLL, NULL);
    } else {
#ifndef NDEBUG
      if (p->state == 0)
        printf("PT *ERR: exited '%s' not removed\n", THREAD_NAME(p));
#endif
      p = p->next;
    }
  }
}

int pt_run(void)
{
  /* Process poll events. */
  if (_poll_requested) {
    do_poll();
  }

  /* Process one event from the queue */
  do_event();

  return _nevents + _poll_requested;
}

void pt_start(struct PT *p, void* data)
{
  struct PT *q;

  /* First make sure that we don't try to start a process that is
     already running. */
  for (q = _list; q != p && q != NULL; q = q->next);

  /* If we found the process on the process list, we bail out. */
  if (q == p) {
    return;
  }

  /* Put on the procs list.*/
  p->next = _list;
  _list = p;

  _PT_CLR(&p->ctx);
  p->state = PT_STATE_RUNNING;
  PRINTF("PT INFO: starting '%s' at function %p\n", THREAD_NAME(p), p->thread);

  /* Post a synchronous initialization event to the thread. */
  call_thread(p, PT_EVENT_INIT, data);
}

void pt_poll(struct PT *p, PT_MASK mask)
{
  if (mask != 0) {
    struct PT *q;
    for (q = _list; q != NULL; q = q->next) {
      if (q != p && q->state != 0 && (q->mask& mask)) {
        q->state |= PT_STATE_POLLING;
        _poll_requested = 1;
      }
    }
  } else if (p == NULL){
#ifndef NDEBUG
    printf("PT WARN: poll nothing by mask '0x0' from '%s'\n",
      THREAD_NAME(_current));
#endif
  } else if (p->state == 0) {
#ifndef NDEBUG
    printf("PT WARN: poll exited '%s'\n", THREAD_NAME(p));
#endif
  }
  else {
    p->state |= PT_STATE_POLLING;
    _poll_requested = 1;
  }
}

void pt_exit(struct PT *p, PT_MASK mask)
{
  exit_thread(p, _current, mask);
}

int pt_post(struct PT *p, PT_MASK mask, PT_EVENT ev, void* data)
{
  struct event_data* ev_dat;

  if (mask != 0) {
    PRINTF("PT INFO: cast event %d by mask '0x%x' from '%s', nevents %d\n",
      ev, mask, THREAD_NAME(_current), _nevents);
  } else if (p != NULL) {
    PRINTF("PT INFO: posts event %d to '%s' from '%s', nevents %d\n",
      ev, THREAD_NAME(p), THREAD_NAME(_current), _nevents);
  } else {
#ifndef NDEBUG
    printf("PT WARN: post nothing with event %d by mask '0x0' from '%s'\n",
      ev, THREAD_NAME(_current));
#endif
    return 0;
  }

  if(_nevents == PT_CONF_NUMEVENTS) {
#ifndef NDEBUG
    if(!p) {
      printf("PT *ERR: event queue is full "
        "when broadcast event %d was posted to 0x%x from %s\n",
        ev, mask, THREAD_NAME(_current));
    } else {
      printf("PT *ERR: event queue is full "
        "when event %d was posted to %s from %s\n",
        ev, THREAD_NAME(p), THREAD_NAME(_current));
    }
#endif
    return ENOSPC;
  }

  ev_dat = &_events[(_fevent + _nevents) % PT_CONF_NUMEVENTS];
  ev_dat->event = ev;
  ev_dat->data = data;
  ev_dat->p = p;
  ev_dat->mask = mask;
  ++_nevents;

#if PT_CONF_STATS
  if(_nevents > _maxevents) {
    _maxevents = _nevents;
  }
#endif /* PT_CONF_STATS */

  return 0;
}

void pt_send(struct PT *p, PT_MASK mask, PT_EVENT event, void* data)
{
  struct PT *caller = _current;

  if (mask) {
    struct PT *q;
    for (q = _list; q != NULL;) {
      if (q != p && q != caller && (q->mask & mask))
        q = call_thread(q, event, data);
      else
        q = q->next;
    }
  } else if (p == caller) {
#ifndef NDEBUG
    printf("PT *ERR: '%s' send event %d by mask '0x%x' to self\n", THREAD_NAME(p),
      event, mask);
#endif
    return;
  } else if (p != NULL) {
    call_thread(p, event, data);
  } else {
#ifndef NDEBUG
    printf("PT WARN: send nothing with event %d by mask '0x0' from '%s'\n",
      event, THREAD_NAME(_current));
#endif
    return;
  }

  _current = caller;
}

static struct PT* exit_thread(struct PT *p, struct PT *from, PT_MASK mask)
{
  int i;
  struct event_data* ev;
  register struct PT *q;
  struct PT *old_current = _current;
  if (!p->state) {
#ifndef NDEBUG
    printf("PT *ERR: exited '%s' exit again\n", THREAD_NAME(p));
#endif
    return NULL;
  } else {/* Thread was running */
    PRINTF("PT INFO: exit '%s'\n", THREAD_NAME(p));
    p->state = 0;
  }

  /* remove cached event */
  for (i = 0; i < _nevents; ++i) {
    ev = &_events[(_fevent + i + _nevents) % PT_CONF_NUMEVENTS];
    if (ev->p == p) ev->p = NULL;
  }

  if (mask) {
    /*
     * Post a synchronous event to all processes to inform them that
     * this process is about to exit. This will allow services to
     * deallocate state associated with this process.
     */
    for (q = _list; q != NULL;) {
      if (q != p && q->mask & mask)
        q = call_thread(q, PT_EVENT_EXITED, (void*)p);
      else
        q = q->next;
    }
  }

  if(p->thread != NULL && p != from) {
    /* Post the exit event to the process that is about to exit. */
    _current = p;
    p->thread(p, PT_EVENT_EXIT, NULL);
  }
  _current = old_current;

  /* remove from list */
  if (p == _list) {
    _list = _list->next;
  } else {
    for (q = _list; q != NULL; q = q->next) {
      if(q->next == p) {
        q->next = p->next;
        break;
      }
    }
    /* Make sure the process is in the process list before we try to exit it. */
    if(q == NULL) {
      return NULL;
    }
  }
  q = p->next;
  p->next = NULL;
  return q;
}
static struct PT* call_thread(struct PT *p, PT_EVENT ev, void* data)
{
  int ret;

#ifndef NDEBUG
  if (p->state & PT_STATE_CALLED) {
    printf("PT WARN: '%s' called again with event %d\n", THREAD_NAME(p), ev);
  }
#endif

  if (p->thread == NULL) {
#ifndef NDEBUG
    printf("PT WARN: empty '%s' called with event %d\n", THREAD_NAME(p), ev);
#endif
  } else if (p->state == 0) {
#ifndef NDEBUG
    printf("PT WARN: exited '%s' called with event %d\n", THREAD_NAME(p), ev);
#endif
  } else {
    PRINTF("PT INFO: calling '%s' with event %d\n", THREAD_NAME(p), ev);
    _current = p;
    p->state |= PT_STATE_CALLED;
    ret = p->thread(p, ev, data);
    if(ret == PT_EXITED || ret == PT_ENDED || ev == PT_EVENT_EXIT)
      return exit_thread(p, _current, 0);
    else 
      p->state &= ~PT_STATE_CALLED;
  }
  return p->next;
}

static void do_event(void)
{
  int ev;
  void* data;
  PT_MASK mask;
  struct PT *receiver;
  struct PT *p;

  /*
   * If there are any events in the queue, take the first one and walk
   * through the list of processes to see if the event should be
   * delivered to any of them. If so, we call the event handler
   * function for the process. We only process one event at a time and
   * call the poll handlers inbetween.
   */
again:
  if(_nevents > 0) {

    /* There are events that we should deliver. */
    ev = _events[_fevent].event;
    mask = _events[_fevent].mask;
    data = _events[_fevent].data;
    receiver = _events[_fevent].p;

    /* Since we have seen the new event, we move pointer upwards
       and decrease the number of events. */
    _fevent = (_fevent + 1) % PT_CONF_NUMEVENTS;
    --_nevents;

    /* If this is a broadcast event, we deliver it to all events, in
       order of their priority. */
    if (mask != 0) {
      for(p = _list; p != NULL;) {
        /* If we have been requested to poll a process, we do this in
           between processing the broadcast event. */
        if(_poll_requested) 
          do_poll();
        if (p != receiver && (p->mask & mask))
          p = call_thread(p, ev, data);
        else
          p = p->next;
      }
    } else if (receiver != NULL) {
      /* Make sure that the process actually is running. */
      call_thread(receiver, ev, data);
    }
    else {
      goto again;
    }
  }
}

