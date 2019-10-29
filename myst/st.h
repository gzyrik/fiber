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
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <poll.h>
typedef int SOCKET;
#define WSAAPI
#endif
#include <sys/types.h>
#include <time.h>
#include <errno.h>

#define ST_VERSION	    "1.9"
#define ST_VERSION_MAJOR    1
#define ST_VERSION_MINOR    9

/* Undefine this to remove the context switch callback feature. */
#define ST_SWITCH_CB

#ifndef ETIME
#define ETIME ETIMEDOUT
#endif

#ifndef ST_UTIME_NO_TIMEOUT
#define ST_UTIME_NO_TIMEOUT ((st_utime_t) -1LL)
#endif

#ifndef ST_UTIME_NO_WAIT
#define ST_UTIME_NO_WAIT 0
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
#ifdef ST_SWITCH_CB
typedef void (*st_switch_cb_t)(void);
#endif

extern int st_init(void);
extern int st_getfdlimit(void);
#ifdef _WIN32
extern int* _st_errno(void);
#define st_errno (*_st_errno())
#else
#define st_errno errno
#endif

extern int st_set_eventsys(int eventsys);
extern int st_get_eventsys(void);
extern const char *st_get_eventsys_name(void);

#ifdef ST_SWITCH_CB
extern st_switch_cb_t st_set_switch_in_cb(st_switch_cb_t cb);
extern st_switch_cb_t st_set_switch_out_cb(st_switch_cb_t cb);
#endif

extern st_thread_t st_thread_self(void);
extern void st_thread_exit(void *retval);
extern int st_thread_join(st_thread_t thread, void **retvalp);
extern void st_thread_interrupt(st_thread_t thread);
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

extern int st_key_create(int *keyp, void (*destructor)(void *));
extern int st_key_getlimit(void);
extern int st_thread_setspecific(int key, void *value);
extern void *st_thread_getspecific(int key);

extern st_netfd_t st_netfd_open(int osfd);
extern st_netfd_t st_netfd_open_socket(int osfd);
extern void st_netfd_free(st_netfd_t fd);
extern int st_netfd_close(st_netfd_t fd);
extern int st_netfd_fileno(st_netfd_t fd);
extern void st_netfd_setspecific(st_netfd_t fd, void *value,
				 void (*destructor)(void *));
extern void *st_netfd_getspecific(st_netfd_t fd);
extern int st_netfd_serialize_accept(st_netfd_t fd);
extern int st_netfd_poll(st_netfd_t fd, int how, st_utime_t timeout);

extern int st_socket(int domain, int type, int protocol);
extern int st_poll(struct pollfd *pds, int npds, st_utime_t timeout);
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
extern st_netfd_t st_open(const char *path, int oflags, mode_t mode);

#ifdef DEBUG
extern void _st_show_thread_stack(st_thread_t thread, const char *messg);
extern void _st_iterate_threads(void);
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
  const char* file_; const int lineno_;
  typedef std::function<void()> detached_type;
  typedef std::function<void*()> joinable_type;
  static void* __st_detached_functor(void* p) {
    auto f= reinterpret_cast<detached_type*>(p);
    (*f)();
    delete f;
    return nullptr;
  }
  static void* __st_joinable_functor(void* p) {
    auto f= reinterpret_cast<joinable_type*>(p);
    void* ret = (*f)();
    delete f;
    return ret;
  }
  friend st_thread_t st_thread(std::function<void*()>const & f, int stack_size);
public:
  st_go(const char* file, int lineno) : stack_size_(0),
  file_(file),lineno_(lineno)
  { (void)file_, (void)lineno_; }
  const st_go& operator,(int stack_size) const
  { stack_size_ = stack_size; return *this; }
  const st_go& operator,(detached_type const&f) const {
    st_thread_create(__st_detached_functor,
      new detached_type(f), false, stack_size_);
    return *this;
  }
};
inline st_thread_t st_thread(std::function<void*()>const & f, int stack_size = 0) {
  return st_thread_create(st_go::__st_joinable_functor,
    new st_go::joinable_type(f), true, stack_size);
}
#if !defined(go) && !defined(ST_NOT_DEFINE_GO)
#define go st_go(__FILE__, __LINE__),
#endif

#include <memory>
class st_chan {
protected:
class __st_pipe {//无缓冲的管线
  struct __st_cxt { //阻塞的上下文
    void* value; __st_cxt* next;
    void append(__st_cxt* cxt) {
      auto tail = this;
      while (tail->next) tail = tail->next;
      tail->next = cxt;
    }
    void remove(__st_cxt* cxt) {
      auto prev = this;
      while (prev->next) {
        if (prev->next == cxt) {
          prev->next = cxt->next;
          return;
        }
        prev = prev->next;
      }
    }
  } *pushing_, *poping_;//阻塞的单向队列
  bool closed_; st_cond_t cond_;
  virtual void assign(void* a, const void* b) = 0;
  bool wait(__st_cxt*& waiting, void* t, st_utime_t dur) {
    if (!dur) return false;
    __st_cxt cxt = {t, nullptr};
    if (waiting) waiting->append(&cxt);
    else waiting = &cxt;
    if (!cond_) cond_ = st_cond_new();
    if (st_cond_timedwait(cond_, dur) < 0) {
      if (closed_) ;
      else if (waiting == &cxt) waiting = waiting->next;
      else waiting->remove(&cxt);
      return false;
    }
    return !closed_;
  }
public:
  virtual bool push(const void* t, st_utime_t dur=ST_UTIME_NO_TIMEOUT) {
    if (closed_) return false;
    else if (!poping_)
      return wait(pushing_, (void*)t, dur);
    if (poping_->value && t && poping_->value != t)
      assign(poping_->value, t);
    poping_ = poping_->next;
    st_cond_signal(cond_);
    return true;
  }
  virtual bool pop(void* t, st_utime_t dur=ST_UTIME_NO_TIMEOUT) {
    if (closed_) return false;
    else if (!pushing_)
      return wait(poping_, t, dur);
    if (t && pushing_->value && t != pushing_->value)
      assign(t, pushing_->value);
    pushing_ = pushing_->next;
    st_cond_signal(cond_);
    return true;
  }
  void close() {
    if (closed_) return;
    closed_ = true;
    if (cond_) st_cond_broadcast(cond_);
  }
  explicit __st_pipe()
    : pushing_(nullptr), poping_(nullptr),
    closed_(false), cond_(nullptr) {}
  virtual ~__st_pipe() {
    if (cond_) st_cond_destroy(cond_);
  }
};
  mutable std::shared_ptr<__st_pipe> queue_;
  mutable bool failed_ = false;//>>或<<操作失败
public:
  const st_chan& operator= (std::nullptr_t/*ignore*/) const {
    queue_.reset();
    return *this;
  }
  const st_chan& operator<< (std::nullptr_t/*ignore*/) const {
    if (!queue_ || !queue_->push(nullptr))
      failed_ = true;
    return *this;
  }
  const st_chan& operator>> (std::nullptr_t/*ignore*/) const {
    if (!queue_ || !queue_->pop(nullptr))
      failed_ = true;
    return *this;
  }
  bool push(std::nullptr_t/*ignore*/, st_utime_t dur) const {
    if (!queue_) return false;
    return queue_->push(nullptr, dur);
  }
  bool pop(std::nullptr_t/*ignore*/, st_utime_t dur) const {
    if (!queue_) return false;
    return queue_->pop(nullptr, dur);
  }
  bool push(const void* t, st_utime_t dur) const {
    if (!queue_) return false;
    return queue_->push(t, dur);
  }
  bool pop(void* t, st_utime_t dur) const {
    if (!queue_) return false;
    return queue_->pop(t, dur);
  }
  void close() const {
    if (queue_) queue_->close();
    queue_.reset();
  }
  operator bool() const { return (bool)queue_ && !failed_; }
};
#include <queue>
/* 模仿 golang 实现相似的 chan */
template <class T> class __st_chan final : public st_chan {
  struct mypipe : public __st_pipe {
    void assign(void* a, const void* b) override {
      *reinterpret_cast<T*>(a) = *reinterpret_cast<const T*>(b);
    }
  };
  struct myqueue : public mypipe { //带缓冲的队列
    const size_t capacity_;
    std::queue<T> queue_;
    bool push(const void* t, st_utime_t dur) override {
      if (queue_.size() >= capacity_)
        return __st_pipe::push(t, dur);
      queue_.emplace(*(T*)t);
      return true;
    }
    bool pop(void* t, st_utime_t dur) override {
      if (queue_.empty()) 
        return __st_pipe::pop(t, dur);
      else if (t)
        std::swap(*(T*)t, queue_.front());
      queue_.pop();
      return true;
    }
    explicit myqueue(size_t capacity) : capacity_(capacity){}
  };
public:
  using st_chan::operator>>;
  using st_chan::operator<<;
  explicit __st_chan(size_t capacity = 0) {
    if (capacity > 0)
      queue_ = std::make_shared<myqueue>(capacity);
    else
      queue_ = std::make_shared<mypipe>();
  }
  const __st_chan& operator= (std::nullptr_t/*ignore*/) const {
    queue_.reset();
    return *this;
  }
  const __st_chan& operator<< (const T& t) const {
    if (!queue_ || !queue_->push(&t))
      failed_ = true;
    return *this;
  }
  const __st_chan& operator>> (T& t) const {
    if (!queue_ || !queue_->pop(&t))
      failed_ = true;
    return *this;
  }
  bool push(const T& t, st_utime_t dur) const {
    if (!queue_) return false;
    return queue_->push(&t, dur);
  }
  bool pop(T& t, st_utime_t dur) const {
    if (!queue_) return false;
    return queue_->pop(&t, dur);
  }
};
template <> class __st_chan<void> final : public st_chan {
  struct myqueue : public __st_pipe {
    const size_t capacity_;
    size_t queue_;
    void assign(void*, const void*) override {}
    bool push(const void*, st_utime_t dur) override {
      if (queue_ >= capacity_)
        return __st_pipe::push(nullptr, dur);
      queue_++;
      return true;
    }
    bool pop(void*, st_utime_t dur) override {
      if (queue_ == 0) 
        return __st_pipe::pop(nullptr, dur);
      --queue_;
      return true;
    }
    explicit myqueue(size_t capacity)
      : capacity_(capacity), queue_(0){}
  };
public:
  explicit __st_chan(size_t capacity = 0){
    queue_ = std::make_shared<myqueue>(capacity);
  }
  using st_chan::operator=;
  using st_chan::operator>>;
  using st_chan::operator<<;
};
#if !defined(chan) && !defined(ST_NOT_DEFINE_CHAN)
template <typename T>
using chan = __st_chan<T>;
#endif

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

#endif /* !c++11 */

#endif /* !__ST_THREAD_H__ */

