#include "pt.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#define PT_CONF_NUMEVENTS  32
#ifndef NDEBUG
#define PRINTF printf
#endif

#define PT_BROADCAST NULL
#define THREAD_NAME_STRING(p) p->name
enum {
  PT_STATE_CALLED = 1,
  PT_STATE_POLL = 2
};

/*
 * Pointer to the currently running process structure.
 */
static struct PT *_list = NULL, *_current = NULL;
/*
 * Structure used for keeping the queue of active events.
 */
struct event_data {
  int ev;
  void* data;
  struct PT *p;
};
#ifdef PT_CONF_STATS
static int _maxevents;
#endif
static int _nevents, _fevent;
static struct event_data _events[PT_CONF_NUMEVENTS];

static void exit_thread(struct PT *p, struct PT *from, unsigned mask);
static void call_thread(struct PT *p, int ev, void* data);
static void do_event(unsigned mask);
static volatile unsigned _poll_requested;
static void do_poll(unsigned mask)
{
  struct PT *p;

  _poll_requested &= ~mask;
  /* Call the thread that needs to be polled. */
  for (p = _list; p != NULL; p = p->next) {
    if ((p->mask&mask) && (p->state&PT_STATE_POLL)) {
      p->state &= ~PT_STATE_POLL;
      call_thread(p, PT_EVENT_POLL, NULL);
    }
  }
}

int pt_run(unsigned mask)
{
  /* Process poll events. */
  if (_poll_requested&mask) {
    do_poll(mask);
  }

  /* Process one event from the queue */
  do_event(mask);

  return _nevents + (_poll_requested ? 1 : 0);
}

void pt_start(struct PT *p, void* data,
  int (*thread)(struct PT *p, int event, void* data))
{
  struct PT *q;

  /* First make sure that we don't try to start a process that is
     already running. */
  for (q = _list; q != p && q != NULL; q = q->next);

  /* If we found the process on the process list, we bail out. */
  if (q == p) {
    return;
  }
  _PT_CLR(&p->ctx);
  p->thread = thread;
  p->state = 0;

  /* Put on the procs list.*/
  p->next = _list;
  _list = p;

  PRINTF("process: starting '%s'\n", THREAD_NAME_STRING(p));

  /* Post a synchronous initialization event to the process. */
  pt_send(p, PT_EVENT_INIT, data);
}

void pt_poll(struct PT *p)
{
  if (pt_alive(p)) {
    p->state |= PT_STATE_POLL;
    _poll_requested |= p->mask;
  }
}

void pt_exit(struct PT *p, unsigned mask)
{
  exit_thread(p, _current, mask);
}

static int post_thread(struct PT *p, unsigned mask, int ev, void* data)
{
  int snum;

  if(_current == NULL) {
    PRINTF("pt_post: NULL posts event %d to thread '%s', nevents %d\n",
      ev,THREAD_NAME_STRING(p), _nevents);
  } else if (p) {
    PRINTF("pt_post: thread '%s' posts event %d to thread '%s', nevents %d\n",
      THREAD_NAME_STRING(_current), ev, THREAD_NAME_STRING(p), _nevents);
  } else {
    PRINTF("pt_post: thread '%s' posts event %d to thread mask '0x%x', nevents %d\n",
      THREAD_NAME_STRING(_current), ev, mask, _nevents);
  }

  if(_nevents == PT_CONF_NUMEVENTS) {
#ifndef NDEBUG
    if(!p) {
      printf("soft panic: event queue is full "
        "when broadcast event %d was posted to 0x%x from %s\n",
        ev, mask, THREAD_NAME_STRING(_current));
    } else {
      printf("soft panic: event queue is full "
        "when event %d was posted to %s from %s\n",
        ev, THREAD_NAME_STRING(p), THREAD_NAME_STRING(_current));
    }
#endif
    return ENOSPC;
  }

  snum = (_fevent + _nevents) % PT_CONF_NUMEVENTS;
  _events[snum].ev = ev;
  _events[snum].data = data;
  _events[snum].p = p;
  ++_nevents;

#if PT_CONF_STATS
  if(_nevents > process_maxevents) {
    _maxevents = _nevents;
  }
#endif /* PT_CONF_STATS */

  return 0;
}

void pt_send(struct PT *p, int event, void* data)
{
  struct PT *caller = _current;
  call_thread(p, event, data);
  _current = caller;
}

static void exit_thread(struct PT *p, struct PT *from, unsigned mask)
{
  register struct PT *q;
  struct PT *old_current = _current;

  PRINTF("process: exit_process '%s'\n", THREAD_NAME_STRING(p));

  if (p == _list) {
    _list = _list->next;
  } else {
    for (q = _list; q != NULL; q = q->next) {
      if(q->next == p) {
        q->next = p->next;
        break;
      }
    }
    /* Make sure the process is in the process list before we try to
       exit it. */
    if(q == NULL) {
      return;
    }
  }

  if(pt_alive(p)) {
    /* Thread was running */
    p->state = 0;

    if(p->thread != NULL && p != from) {
      /* Post the exit event to the process that is about to exit. */
      _current = p;
      p->thread(p, PT_EVENT_EXIT, NULL);
    }

    /*
     * Post a synchronous event to all processes to inform them that
     * this process is about to exit. This will allow services to
     * deallocate state associated with this process.
     */
    for(q = _list; q != NULL; q = q->next) {
      if (q->mask&mask)
        call_thread(q, PT_EVENT_EXITED, (void*)p);
    }
  }

  _current = old_current;
}
static void call_thread(struct PT *p, int ev, void* data)
{
  int ret;

#ifndef NDEBUG
  if(p->state & PT_STATE_CALLED) {
    printf("process: process '%s' called again with event %d\n", THREAD_NAME_STRING(p), ev);
  }
#endif

  if(p->next != NULL && p->thread != NULL) {
    PRINTF("process: calling process '%s' with event %d\n", THREAD_NAME_STRING(p), ev);
    _current = p;
    p->state |= PT_STATE_CALLED;
    ret = p->thread(p, ev, data);
    if(ret == PT_EXITED ||
      ret == PT_ENDED ||
      ev == PT_EVENT_EXIT) {
      exit_thread(p, _current, 0);
    } else {
      p->state &= ~PT_STATE_CALLED;
    }
  }
}

static void do_event(unsigned mask)
{
  int ev;
  void* data;
  struct PT *receiver;
  struct PT *p;

  /*
   * If there are any events in the queue, take the first one and walk
   * through the list of processes to see if the event should be
   * delivered to any of them. If so, we call the event handler
   * function for the process. We only process one event at a time and
   * call the poll handlers inbetween.
   */

  if(_nevents > 0) {

    /* There are events that we should deliver. */
    ev = _events[_fevent].ev;

    data = _events[_fevent].data;
    receiver = _events[_fevent].p;

    /* Since we have seen the new event, we move pointer upwards
       and decrease the number of events. */
    _fevent = (_fevent + 1) % PT_CONF_NUMEVENTS;
    --_nevents;

    /* If this is a broadcast event, we deliver it to all events, in
       order of their priority. */
    if(receiver == PT_BROADCAST) {
      for(p = _list; p != NULL; p = p->next) {

        /* If we have been requested to poll a process, we do this in
           between processing the broadcast event. */
        if(_poll_requested&mask) {
          do_poll(mask);
        }
        call_thread(p, ev, data);
      }
    } else {
      /* Make sure that the process actually is running. */
      call_thread(receiver, ev, data);
    }
  }
}

