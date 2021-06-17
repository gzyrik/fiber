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

#ifndef __ST_THREAD_H__
#define __ST_THREAD_H__

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <process.h>
#include <ws2tcpip.h>
#include <crtdbg.h>
#include <io.h>
typedef SSIZE_T ssize_t;
typedef ULONG  nfds_t;
typedef int mode_t;
struct iovec {
  ULONG iov_len;     /* the length of the buffer */
  _Field_size_bytes_(len) CHAR FAR *iov_base; /* the pointer to the buffer */
};
#else
#include <unistd.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
typedef int SOCKET;
#define INVALID_SOCKET (-1)
#define WSAAPI
#undef closesocket
#define closesocket(s)	close(s)
#endif
#include <sys/types.h>
#include <time.h>
#include <errno.h>

#define ST_VERSION	    "1.9"
#define ST_VERSION_MAJOR    1
#define ST_VERSION_MINOR    9

/* Undefine this to remove the system hook feature. */
#define ST_HOOK_SYS

/* Undefine this to remove the context switch callback feature. */
#define ST_SWITCH_CB

/* Undefine this to remove the context iterate callback feature. */
#define ST_ITERATE_CB

#ifndef ETIME
#define ETIME ETIMEDOUT
#endif

#ifndef ST_UTIME_NO_TIMEOUT
#define ST_UTIME_NO_TIMEOUT ((st_utime_t) -1LL)
#endif

#ifndef ST_UTIME_NO_WAIT
#define ST_UTIME_NO_WAIT 0
#endif

#ifndef __ia64__
#define ST_DEFAULT_STACK_SIZE (64*1024)
#else
#define ST_DEFAULT_STACK_SIZE (128*1024)  /* Includes register stack size */
#endif

#define ST_EVENTSYS_DEFAULT 0
#define ST_EVENTSYS_SELECT  1
#define ST_EVENTSYS_POLL    2
#define ST_EVENTSYS_ALT     3

#if __GNUC__
#pragma GCC visibility push(default)
#endif
#ifdef __cplusplus
extern "C" {
#endif

typedef unsigned long long  st_utime_t;
typedef struct _st_thread * st_thread_t;
typedef struct _st_cond *   st_cond_t;
typedef struct _st_mutex *  st_mutex_t;
typedef struct _st_netfd *  st_netfd_t;
typedef struct _st_chan *   st_chan_t;
/** WARNING: SHOULD call before st_init */
extern int st_cfg_eventsys(int eventsys);
extern int st_init(void (*atterm)());
/** wait for all thread */
extern int st_term(void);
extern int st_getfdlimit(void);
#ifdef _WIN32
extern int* _st_errno(void);
#define st_errno (*_st_errno())
#else
#define st_errno errno
#endif

extern int st_get_eventsys(void);
extern const char *st_get_eventsys_name(void);

#ifdef ST_SWITCH_CB
typedef void (*st_switch_cb_t)(st_thread_t thread);
extern st_switch_cb_t st_set_switch_in_cb(st_switch_cb_t cb);
extern st_switch_cb_t st_set_switch_out_cb(st_switch_cb_t cb);
#endif

extern st_thread_t st_thread_self(void);
/** if |name| != NULL, set the thread or NULL(self), return old name */ 
const char* st_thread_name(st_thread_t thread, const char *name);
extern char* st_thread_stats(st_thread_t thread, const char* format, ...);
extern void st_thread_atexit(st_thread_t thread, void (*cb)(void* arg, void* retval), void* arg);
/** WARNING: MUST destruction local object manually before this */
extern void st_thread_exit(void *retval);
extern int st_thread_join(st_thread_t thread, void **retvalp);
extern void st_thread_interrupt(st_thread_t thread);
/** WARNING: stack_size <= 0 will share the current stack at now sp skip |stack_size| */
extern st_thread_t st_thread_create(void *(*start)(void *arg), void *arg,
				    int joinable, int stack_size);
extern int st_randomize_stacks(int on);
extern int st_set_utime_function(st_utime_t (*func)(void));

extern st_utime_t st_utime(void);
extern st_utime_t st_utime_last_clock(void);
extern int st_timecache_set(int on);
extern time_t st_time(void);
extern int st_usleep(st_utime_t usecs);
extern int st_sleep(int secs);
extern st_cond_t st_cond_new(void);
extern int st_cond_destroy(st_cond_t cvar);
extern int st_cond_timedwait(st_cond_t cvar, st_utime_t timeout);
extern int st_cond_wait(st_cond_t cvar);
extern int st_cond_signal(st_cond_t cvar);
extern int st_cond_broadcast(st_cond_t cvar);
extern st_mutex_t st_mutex_new(void);
extern int st_mutex_destroy(st_mutex_t lock);
extern int st_mutex_lock(st_mutex_t lock);
extern int st_mutex_unlock(st_mutex_t lock);
extern int st_mutex_trylock(st_mutex_t lock);
extern st_chan_t st_chan_new(size_t capacity, size_t elem_size);
extern st_chan_t st_chan_addref(st_chan_t chan, int mustalive);
extern int st_chan_alive(st_chan_t chan);
extern int st_chan_release(st_chan_t *chan, int close);
extern int st_chan_push(st_chan_t chan, const void* ptr, st_utime_t timeout);
extern int st_chan_pop(st_chan_t chan, void* ptr, st_utime_t timeout);

extern int st_key_create(int *keyp, void (*destructor)(void *));
extern int st_key_getlimit(void);
extern int st_thread_setspecific(int key, void *value);
extern void *st_thread_getspecific(int key);

extern st_netfd_t st_netfd_open(SOCKET osfd);
extern st_netfd_t st_netfd_open_socket(SOCKET osfd);
extern void st_netfd_free(st_netfd_t fd);
extern int st_netfd_close(st_netfd_t fd);
extern int st_netfd_fileno(st_netfd_t fd);
extern void st_netfd_setspecific(st_netfd_t fd, void *value,
				 void (*destructor)(void *));
extern void *st_netfd_getspecific(st_netfd_t fd);
extern int st_netfd_serialize_accept(st_netfd_t fd);
extern int st_netfd_poll(st_netfd_t fd, int how, st_utime_t timeout);

extern st_netfd_t st_open(const char *path, int oflags, mode_t mode);
extern st_netfd_t st_socket(int domain, int type, int protocol);
extern int st_poll(struct pollfd *pds, int npds, st_utime_t timeout);
extern st_netfd_t st_bind(int domain, int protocol, int port, int backlog);
/* !ip or 'any' set addr=any; !ip[0] or 'loopback' set addr=loopback; return socklen_t */
extern int st_reset_dns(void);
extern int st_sockaddr(void *sockaddr, int domain, const char* addr, int dft_port);
extern int st_getaddrinfo(const char *name,
  struct addrinfo *hints, unsigned *ttl, st_utime_t timeout);
extern void st_freeaddrinfo(struct addrinfo *hints);
extern const char* st_inetaddr(const void *sockaddr, int addrlen, int *domain, int *port);
extern st_netfd_t st_accept(st_netfd_t fd, struct sockaddr *addr, socklen_t *addrlen,
			    st_utime_t timeout);
extern int st_connect(st_netfd_t fd, const struct sockaddr *addr, int addrlen,
		      st_utime_t timeout);
extern ssize_t st_read(st_netfd_t fd, void *buf, size_t nbyte,
		       st_utime_t timeout);
extern ssize_t st_read_fully(st_netfd_t fd, void *buf, size_t nbyte,
			     st_utime_t timeout);
extern int st_read_resid(st_netfd_t fd, void *buf, size_t *resid,
			 st_utime_t timeout);
extern ssize_t st_readv(st_netfd_t fd, const struct iovec *iov, int iov_size,
			st_utime_t timeout);
extern int st_readv_resid(st_netfd_t fd, struct iovec **iov, int *iov_size,
			  st_utime_t timeout);
extern ssize_t st_write(st_netfd_t fd, const void *buf, size_t nbyte,
			st_utime_t timeout);
extern int st_write_resid(st_netfd_t fd, const void *buf, size_t *resid,
			  st_utime_t timeout);
extern ssize_t st_writev(st_netfd_t fd, const struct iovec *iov, int iov_size,
			 st_utime_t timeout);
extern int st_writev_resid(st_netfd_t fd, struct iovec **iov, int *iov_size,
			   st_utime_t timeout);
extern int st_recv(st_netfd_t fd, void *buf, int len, int flags,
		       st_utime_t timeout);
extern int st_recvfrom(st_netfd_t fd, void *buf, int len, int flags,
		       struct sockaddr *from, socklen_t *fromlen,
		       st_utime_t timeout);
extern int st_send(st_netfd_t fd, const void *buf, size_t len, int flags,
               st_utime_t timeout);
extern int st_sendto(st_netfd_t fd, const void *msg, int len, int flags,
		     const struct sockaddr *to, int tolen, st_utime_t timeout);
extern int st_recvmsg(st_netfd_t fd, struct msghdr *msg, int flags,
		      st_utime_t timeout);
extern int st_sendmsg(st_netfd_t fd, const struct msghdr *msg, int flags,
		      st_utime_t timeout);

#ifdef ST_ITERATE_CB
#define ST_ITERATE_FLAG_BEGIN  1
#define ST_ITERATE_FLAG_END    2
typedef void (*st_iterate_cb_t)(st_thread_t thread, int flags);
/* To be set from debugger */
extern st_iterate_cb_t _st_iterate_threads_cb;
extern void st_iterate_threads(st_iterate_cb_t cb);
#endif

#ifdef __cplusplus
}
#endif
#if __GNUC__
#pragma GCC visibility pop
#endif

#if __cplusplus >= 201103L
#include <functional>
/* 模仿 golang 实现相似的 go */
class st_go {
  mutable int stack_size_;
  mutable const char* name_;
  typedef std::function<void()> detached_t;
  typedef std::function<void*()> joinable_t;
  static void* __st_detached_functor(void* p) {
    auto f= reinterpret_cast<detached_t*>(p);
    (*f)();
    delete f;
    return nullptr;
  }
  static void* __st_joinable_functor(void* p) {
    auto f= reinterpret_cast<joinable_t*>(p);
    void* ret = (*f)();
    delete f;
    return ret;
  }
public:
  st_go(const char* name=nullptr) : stack_size_(ST_DEFAULT_STACK_SIZE), name_(name) {}
  const st_go& operator,(int stack_size) const
  { stack_size_ = stack_size; return *this; }
  const st_go& operator,(const char* name) const
  { name_ = name; return *this; }
  template <typename T> const st_go& operator,(T &&f) const {
    auto* p = new detached_t(std::move(f));
    auto t = st_thread_create(__st_detached_functor, p, false, stack_size_);
    if (name_) st_thread_name(t, name_);
    return *this;
  }
  template <typename T> static st_thread_t create(T &&f, int stack_size = ST_DEFAULT_STACK_SIZE) {
    auto* p = new joinable_t(std::move(f));
    return st_thread_create(__st_joinable_functor, p, true, stack_size);
  }
};
#define ST_GO st_go(__FUNCTION__),
#if !defined(go) && !defined(ST_NOT_DEFINE_GO)
#define go ST_GO
#endif

/* 模仿 golang 实现相似的 chan */
class st_chan {
protected:
  mutable st_chan_t chan_;
  mutable int ret_;
  st_chan(): chan_(nullptr), ret_(0) {}
public:
  st_chan(const st_chan& ch): chan_(st_chan_addref(ch.chan_, true)), ret_(ch.ret_) {}
  st_chan(st_chan&& ch): chan_(ch.chan_), ret_(ch.ret_) { ch.chan_ = nullptr; }
  ~st_chan() { release(); }
  void close() const { if (chan_) { st_chan_release(&chan_, true); chan_ = nullptr; } }
  void release() const { if (chan_) { st_chan_release(&chan_, false); chan_ = nullptr; } }
  int push(st_utime_t timeout = ST_UTIME_NO_TIMEOUT) const { return ret_ = st_chan_push(chan_, nullptr, timeout); }
  int pop(st_utime_t timeout = ST_UTIME_NO_TIMEOUT) const { return ret_ = st_chan_pop(chan_, nullptr, timeout); }
  operator bool() const { return !ret_ && chan_ && st_chan_alive(chan_); }
  const st_chan& operator<< (std::nullptr_t/*ignore*/) const { ret_ = push(); return *this; }
  const st_chan& operator>> (std::nullptr_t/*ignore*/) const { ret_ = pop(); return *this; }
  const st_chan& operator= (std::nullptr_t/*ignore*/) const { release(); return *this; }
  const st_chan& operator= (const st_chan& ch) const
  { release(); chan_ = st_chan_addref(ch.chan_, true); ret_ = ch.ret_; return *this; }
};

/* 只允许可使用 memcpy 的简单数据类型 */
template <class T> class __st_chan final : public st_chan {
public:
  static_assert(std::is_pod<T>::value, "T not POD type");
  explicit __st_chan(size_t capacity = 0) { chan_ = st_chan_new(capacity, sizeof(T)); }
  int push(const T& t, st_utime_t timeout = ST_UTIME_NO_TIMEOUT) const { return st_chan_push(chan_, &t, timeout); }
  int pop(T& t, st_utime_t timeout = ST_UTIME_NO_TIMEOUT) const { return st_chan_pop(chan_, &t, timeout); }
  const __st_chan& operator<< (const T& t) const { ret_ = push(t); return *this; }
  const __st_chan& operator>> (T& t) const { ret_ = pop(t); return *this; }
  using st_chan::operator=; using st_chan::operator>>; using st_chan::operator<<;
};
template <> class __st_chan<void> final : public st_chan {
public:
  explicit __st_chan(size_t capacity = 0) { chan_ = st_chan_new(capacity, 0); }
  using st_chan::operator=; using st_chan::operator>>; using st_chan::operator<<;
};
#if !defined(chan) && !defined(ST_NOT_DEFINE_CHAN)
template <typename T> using chan = __st_chan<T>;
#endif

#if !(defined(__GNUC__) && (__GNUC__ < 5))
/* 另开物理线程, 等待其耗时的非IO操作 */
#include <thread>
template <class Fn, class... Args>
bool st_async(Fn&& fn, Args&&... args) {
  int sfd[2];
  if (pipe(sfd) != 0) return false;
  st_netfd_t fd = st_netfd_open_socket(sfd[0]);
  if (!fd) return false;
  std::thread thread([&] {
    fn(args...);
    write(sfd[1], (void*)sfd, sizeof(int));
  });
  const bool ret = (st_read(fd, (void*)sfd, sizeof(int),
    ST_UTIME_NO_TIMEOUT) == sizeof(int));
  thread.join();
  st_netfd_close(fd);
  close(sfd[1]);
  return ret;
}
#endif
#endif /* !c++11 */

#endif /* !__ST_THREAD_H__ */

