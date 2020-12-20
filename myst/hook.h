#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#ifndef _WIN32
#define __USE_GNU
#include <dlfcn.h>
#define SOCKOPTVAL_T void
#define SELECT_TIMEVAL_T struct timeval
#define ST_DLSYM(sym) dlsym(RTLD_NEXT, sym)
static pthread_t _st_netfd_thread;
#define ST_HOOK_THREAD pthread_equal(_st_netfd_thread, pthread_self())
#else
static void* ST_DLSYM(const char* sym)
{
    static HMODULE RTLD_NEXT = 0;
    if (!RTLD_NEXT) RTLD_NEXT = LoadLibrary("Ws2_32.dll"); 
    return GetProcAddress(RTLD_NEXT, sym);
}
static DWORD _st_netfd_thread;
#define ST_HOOK_THREAD  (_st_netfd_thread == GetCurrentThreadId())
//#define __thread __declspec(thread)
#define SOCKOPTVAL_T char
#define SELECT_TIMEVAL_T const struct timeval
#endif
#ifdef __ANDROID__
#define IOCTL_REQUST_T int
#else
#define IOCTL_REQUST_T unsigned long
#endif
static _st_netfd_t** _st_netfd_hook;
static _st_netfd_t* _st_netfd(int osfd)
{
  if (_st_netfd_hook && osfd > -1 && osfd < _st_osfd_limit)
    return _st_netfd_hook[osfd];
  return NULL;
}
#define _ST_HOOK_LIST0 \
  X(int,socket,int domain, int type, int protocol)\
  X(int,connect,int, const struct sockaddr *, socklen_t)\
  X(ssize_t,recv,int sockfd, void *buf, size_t len, int flags)\
  X(ssize_t,recvfrom,int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen)\
  X(ssize_t,send,int sockfd, const void *buf, size_t len, int flags)\
  X(ssize_t,sendto,int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen)\
  X(int,accept,int sockfd, struct sockaddr *addr, socklen_t *addrlen)\
  X(int,setsockopt,int, int, int, const void*, socklen_t)\
  X(int,getsockopt,int, int, int, void*, socklen_t*)\

#ifdef _WIN32
#define _ST_HOOK_LIST _ST_HOOK_LIST0 \
  X(int, closesocket, int)\
  X(int,ioctlsocket, SOCKET, long, u_long*)\
  X(int, WSAGetLastError, void)\
  X(void, WSASetLastError, int)

#else
#define _ST_HOOK_LIST1 _ST_HOOK_LIST0 \
  X(int,close,int)\
  X(unsigned,sleep,unsigned int)\
  X(int,usleep,useconds_t)\
  X(int,nanosleep,const struct timespec *req, struct timespec *rem)\
  X(int,pipe,int pipefd[2])\
  X(int,pipe2,int pipefd[2], int flags)\
  X(int,socketpair,int domain, int type, int protocol, int sv[2])\
  X(ssize_t,read,int, void *, size_t)\
  X(ssize_t,readv,int, const struct iovec *, int)\
  X(ssize_t,recvmsg,int sockfd, struct msghdr *msg, int flags)\
  X(ssize_t,write,int, const void *, size_t)\
  X(ssize_t,writev,int, const struct iovec *, int)\
  X(ssize_t,sendmsg,int sockfd, const struct msghdr *msg, int flags)\
  X(int,fcntl,int, int, ...)\
  X(int,dup,int)\
  X(int,dup2,int, int)\
  X(int,dup3,int, int, int)\
  X(int,ioctl,int, IOCTL_REQUST_T, ...)
/*
  X(FILE*,fopen,const char * __restrict, const char * __restrict)\
  X(int,fclose,FILE*)
*/

#if defined(__linux__)
struct hostent;
#define _ST_HOOK_LIST _ST_HOOK_LIST1 \
  X(int,gethostbyname_r,const char*__restrict, struct hostent*__restrict, char*__restrict, size_t, struct hostent**__restrict, int*__restrict)\
  X(int,gethostbyname2_r,const char*, int, struct hostent*, char*, size_t , struct hostent**, int *)\
  X(int,gethostbyaddr_r,const void*, socklen_t, int type, struct hostent*, char*, size_t, struct hostent**, int *)
#else
#define _ST_HOOK_LIST _ST_HOOK_LIST1
#endif

#endif

#define X(ret, name, ...) static ret (WSAAPI *name##_f)(__VA_ARGS__);
_ST_HOOK_LIST
#undef X

#if defined(__linux__)
struct epoll_event;
#define X(ret, name, ...) __attribute__((weak)) extern ret __##name(__VA_ARGS__);
_ST_HOOK_LIST
__attribute__((weak)) extern int __libc_poll(struct pollfd*, nfds_t, int );
__attribute__((weak)) extern int __select(int, fd_set*, fd_set*, fd_set*, SELECT_TIMEVAL_T*);
__attribute__((weak)) extern int __epoll_wait_nocancel(int, struct epoll_event*, int, int);
#undef X
#endif

int (WSAAPI *select_f)(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, SELECT_TIMEVAL_T *timeout);
int (WSAAPI *poll_f)(struct pollfd *fds, nfds_t nfds, int timeout);
#ifdef MD_HAVE_EPOLL
int (*epoll_wait_f)(int epfd, struct epoll_event *events, int maxevents, int timeout);
#endif
static int _st_hook_init()
{
  if (_st_netfd_hook) return 0;
#ifdef _WIN32
  _st_netfd_thread = GetCurrentThreadId();
  closesocket_f = ST_DLSYM("closesocket");
  ioctlsocket_f = ST_DLSYM("ioctlsocket");
  poll_f = ST_DLSYM("WSAPoll");
#else
  _st_netfd_thread = pthread_self();
  poll_f = ST_DLSYM("poll");
#endif
  if (poll_f) {
#define X(ret, name, ...) name##_f = ST_DLSYM(#name);
    _ST_HOOK_LIST
    select_f = ST_DLSYM("select");
#ifdef MD_HAVE_EPOLL
    epoll_wait_f = ST_DLSYM("epoll_wait");
#endif
#undef X
#ifdef __linux__
  } else {
#define X(ret, name, ...) name##_f = &__##name;
    _ST_HOOK_LIST
    select_f = &__select;
    poll_f = &__libc_poll;
#ifdef MD_HAVE_EPOLL
    epoll_wait_f = &__epoll_wait_nocancel;
#endif
#undef X
#endif
  }
  if (!connect_f || !send_f || !socket_f
    || !sendto_f || !accept_f || !poll_f || !select_f 
#ifndef _WIN32
    || !read_f || !write_f || !readv_f || !writev_f
    || !pipe_f || !socketpair_f || !sendmsg_f
    || !sleep_f || !usleep_f || !nanosleep_f || !close_f || !fcntl_f
    || !dup_f || !dup2_f /* || !fclose_f */
#if defined(__linux__)
    || !pipe2_f
    || !gethostbyname_r_f
    || !gethostbyname2_r_f
    || !gethostbyaddr_r_f
#ifdef MD_HAVE_EPOLL
    || !epoll_wait_f
#endif
#endif
#endif
    )
  {
    errno = EINVAL;
    return -1;
  }
  _st_netfd_hook = calloc(_st_osfd_limit, sizeof(_st_netfd_t*));
  if (!_st_netfd_hook)
    return -1;
  return 0;
}
#ifndef _WIN32
int pipe2(int pipefd[2], int flags)
{
  int err;

  while ((err = (pipe2_f ? pipe2_f(pipefd, flags) : pipe_f(pipefd))) < 0) {
    if (errno != EINTR)
      return -1;
  }
  if (err == 0 && ST_HOOK_THREAD) {
    if (!st_netfd_open_socket(pipefd[0]) || !st_netfd_open_socket(pipefd[1])) {
      err = errno;
      close_f(pipefd[0]);
      close_f(pipefd[1]);
      errno = err;
      return -1;
    }
  }
  return err;
}
int socketpair(int domain, int type, int protocol, int sv[2])
{
  int err;

  while ((err = socketpair_f(domain, type, protocol, sv)) < 0) {
    if (errno != EINTR)
      return -1;
  }
  if (err == 0 && ST_HOOK_THREAD) {
    if (!st_netfd_open_socket(sv[0]) || !st_netfd_open_socket(sv[1])) {
      err = errno;
      close_f(sv[0]);
      close_f(sv[1]);
      errno = err;
      return -1;
    }
  }
  return err;
}
int dup(int oldfd)
{
  int err;

  while ((err = dup_f(oldfd)) < 0) {
    if (errno != EINTR)
      return -1;
  }
  if (err >= 0 && ST_HOOK_THREAD) {
    if (!st_netfd_open_socket(err)) {
      err = errno;
      close_f(err);
      errno = err;
      return -1;
    }
  }
  return err;
}
int dup3(int oldfd, int newfd, int flags)
{
  int err;
  _st_netfd_t* fd;
  if (oldfd == newfd) return 0;

  fd = _st_netfd(newfd);
  if (fd) st_netfd_close(fd);

  while ((err = (dup3_f ? dup3_f(oldfd, newfd, flags) : dup2_f(oldfd,newfd))) < 0) {
    if (errno != EINTR)
      return -1;
  }
  if (err == 0 && ST_HOOK_THREAD) {
    if (!st_netfd_open_socket(newfd)) {
      err = errno;
      close_f(newfd);
      errno = err;
      return -1;
    }
  }
  return err;
}
int close(int sockfd)
{
  _st_netfd_t* fd = _st_netfd(sockfd);
  if (fd) return st_netfd_close(fd);
  if (!close_f) close_f = ST_DLSYM("close");
  return close_f(sockfd);
}
/*
FILE* fopen(const char * __restrict filename , const char * __restrict mode)
{
  FILE* fp;
  if (!fopen_f) fopen_f = ST_DLSYM("fopen");
  fp = fopen_f(filename, mode);
  if (fp && ST_HOOK_THREAD) {
    if (!st_netfd_open(fileno(fp))){
      int err = errno;
      fclose_f(fp);
      errno = err;
      return NULL;
    }
  }
  return fp;
}
int fclose(FILE* fp)
{
  _st_netfd_t* fd = _st_netfd(fileno(fp));
  if (fd) st_netfd_close(fd);
  if (!fclose_f) fclose_f = ST_DLSYM("fclose");
  return fclose_f(fp);
}*/
int __close(int fd) {return close(fd);}
int dup2(int oldfd, int newfd){return dup3(oldfd, newfd, 0);}
int pipe(int pipefd[2]) {return pipe2(pipefd, 0);}
#else
int WSAAPI closesocket(SOCKET sockfd)
{
  _st_netfd_t* fd = _st_netfd(sockfd);
  return fd ? st_netfd_close(fd) : closesocket_f(sockfd);
}
int WSAAPI WSAGetLastError(void) {return st_errno;}
void WSAAPI WSASetLastError(int err) {st_errno=err;}
#endif

//read hook

#define _ST_HOOK(hook, sockfd, ...) \
  _st_netfd_t* fd = _st_netfd(sockfd); \
  if (fd) return st_##hook(fd, ##__VA_ARGS__, fd->rcv_timeo); \
  if (!hook##_f) hook##_f = ST_DLSYM(#hook); \
  return hook##_f(sockfd, ##__VA_ARGS__);
#ifndef _WIN32
ssize_t read(int sockfd, void *buf, size_t nbyte) {_ST_HOOK (read, sockfd, buf, nbyte);}
ssize_t readv(int sockfd, const struct iovec *iov, int iov_size){_ST_HOOK(readv, sockfd, iov, iov_size);}
ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
  struct sockaddr *src_addr, socklen_t *addrlen) {_ST_HOOK(recvfrom, sockfd, buf, len, flags, src_addr, addrlen);}
ssize_t recv(int sockfd, void *buf, size_t len, int flags){_ST_HOOK(recv, sockfd, buf, len, flags);}
ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags){_ST_HOOK(recvmsg, sockfd, msg, flags);}
#else
int WSAAPI recvfrom(SOCKET sockfd, char *buf, int len, int flags,
  struct sockaddr *src_addr, int *addrlen) {_ST_HOOK(recvfrom, sockfd, buf, len, flags, src_addr, addrlen);}
int WSAAPI recv(SOCKET sockfd, char *buf, int len, int flags) {_ST_HOOK(recv, sockfd, buf, len, flags);}
#endif
#undef _ST_HOOK
SOCKET WSAAPI accept(SOCKET sockfd, struct sockaddr *addr, socklen_t *addrlen){
  _st_netfd_t* fd = _st_netfd(sockfd);
  if (fd) {
    fd = st_accept(fd, addr, addrlen, fd->rcv_timeo);
    return fd ? fd->osfd : -1;
  }
  return accept_f(sockfd, addr, addrlen);
}

//write hook
#define _ST_HOOK(hook, sockfd, ...) \
  _st_netfd_t* fd = _st_netfd(sockfd); \
  if (fd) return st_##hook(fd, ##__VA_ARGS__, fd->snd_timeo); \
  if (!hook##_f) hook##_f = ST_DLSYM(#hook); \
  return hook##_f(sockfd, ##__VA_ARGS__)
int WSAAPI connect(SOCKET sockfd, const struct sockaddr *addr, socklen_t addrlen) {_ST_HOOK(connect, sockfd, addr, addrlen);}
#ifndef _WIN32
ssize_t write(int sockfd, const void *buf, size_t nbyte){_ST_HOOK(write, sockfd, buf, nbyte);}
ssize_t writev(int sockfd, const struct iovec *iov, int iov_size){_ST_HOOK(writev, sockfd, iov, iov_size);}
ssize_t send(int sockfd, const void *buf, size_t len, int flags){_ST_HOOK(send, sockfd, buf, len, flags);}
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
  const struct sockaddr *dest_addr, socklen_t addrlen) {_ST_HOOK(sendto, sockfd, buf, len, flags, dest_addr, addrlen);}
ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags){_ST_HOOK(sendmsg, sockfd, msg, flags);}
#else
int WSAAPI send(SOCKET sockfd, const char *buf, int len, int flags) {_ST_HOOK(send, sockfd, buf, len, flags);}
int WSAAPI sendto(SOCKET sockfd, const char *buf, int len, int flags,
  const struct sockaddr *dest_addr, int addrlen) {_ST_HOOK(sendto, sockfd, buf, len, flags, dest_addr, addrlen);}
#endif
#undef _ST_HOOK

SOCKET WSAAPI socket(int domain, int type, int protocol)
{return ST_HOOK_THREAD ? st_netfd_fileno(st_socket(domain, type, protocol)) : socket_f(domain, type, protocol);}
int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{return ST_HOOK_THREAD ? st_poll(fds, nfds, timeout) : poll_f(fds, nfds, timeout);}
int __poll(struct pollfd *fds, nfds_t nfds, int timeout) {return poll(fds, nfds, timeout);}
#ifndef _WIN32
unsigned sleep(unsigned int seconds)
{return ST_HOOK_THREAD ? st_sleep(seconds) : sleep_f(seconds);}
int usleep(useconds_t usec)
{return ST_HOOK_THREAD ? st_usleep(usec) : usleep_f(usec);}
int nanosleep(const struct timespec *req, struct timespec *rem)
{return ST_HOOK_THREAD ? st_usleep(req->tv_sec * 1000000 + req->tv_nsec/1000): nanosleep_f(req, rem);}
#endif
int WSAAPI setsockopt(SOCKET sockfd, int level, int optname, const SOCKOPTVAL_T *optval, socklen_t optlen)
{
  if (level == SOL_SOCKET && (optname == SO_RCVTIMEO || optname == SO_SNDTIMEO)) {
    _st_netfd_t* fd = _st_netfd(sockfd);
    while (fd) {
      st_utime_t us;
      if (optlen == sizeof(struct timeval)) {
        struct timeval* tv = (struct timeval*)optval;
        us = tv->tv_sec * 1000000 + tv->tv_usec;
      }
      else if (optlen == sizeof(st_utime_t))
        us = *(st_utime_t*)optval;
      else if (optlen == sizeof(unsigned))
        us = 1000LL * (*(unsigned*)optval);
      else if (optlen == sizeof(unsigned long))
        us = 1000LL * (*(unsigned long*)optval);
      else
        return -1;

      if (optname == SO_RCVTIMEO)
        fd->rcv_timeo = us;
      else 
        fd->snd_timeo = us;
      return 0;
    }
  }
  return setsockopt_f(sockfd, level, optname, optval, optlen);
}
int WSAAPI getsockopt(SOCKET sockfd, int level, int optname, SOCKOPTVAL_T *optval, socklen_t *optlen)
{
  if (level == SOL_SOCKET && (optname == SO_RCVTIMEO || optname == SO_SNDTIMEO)) {
    _st_netfd_t* fd = _st_netfd(sockfd);
    while (fd) {
      st_utime_t us = (optname == SO_RCVTIMEO ? fd->rcv_timeo : fd->snd_timeo);
      if (*optlen == sizeof(struct timeval)) {
        struct timeval* tv = (struct timeval*)optval;
        tv->tv_sec  = us /1000000;
        tv->tv_usec = us - tv->tv_sec *1000000;
      }
      else if (*optlen == sizeof(st_utime_t))
        *(st_utime_t*)optval = us;
      else if (*optlen == sizeof(unsigned))
        *(unsigned*)optval = (unsigned)(us/1000);
      else if (*optlen == sizeof(unsigned long))
        *(unsigned long*)optval = (unsigned long)(us/1000);
      else
        return -1;
      return 0;
    }
  }
  return getsockopt_f(sockfd, level, optname, optval, optlen);
}
#ifndef _WIN32
int fcntl(int __fd, int __cmd, ...)
{
  va_list va;
  va_start(va, __cmd);
  switch (__cmd) {
  case F_DUPFD:
  case F_DUPFD_CLOEXEC: {// TODO: support FD_CLOEXEC
    int fd = va_arg(va, int);
    va_end(va);
    fd = fcntl_f(__fd, __cmd, fd);
    if (fd >= 0 && ST_HOOK_THREAD && !st_netfd_open_socket(fd)){
      fd = errno;
      close_f(fd);
      errno = fd;
      return -1;
    }
    return fd;
  }
#if defined(F_SETSIG)
  case F_SETSIG:
  case F_SETLEASE:
  case F_NOTIFY:
#endif
#if defined(F_SETPIPE_SZ)
  case F_SETPIPE_SZ:
#endif 
  case F_SETFD:
  case F_SETOWN: {
    int arg = va_arg(va, int);
    va_end(va);
    return fcntl_f(__fd, __cmd, arg);
  }
  case F_SETFL: {
    int flags = va_arg(va, int);
    if (ST_HOOK_THREAD) flags |= O_NONBLOCK;
    va_end(va);
    return fcntl_f(__fd, __cmd, flags);
  }
  case F_GETLK:
  case F_SETLK:
  case F_SETLKW: {
    struct flock* arg = va_arg(va, struct flock*);
    va_end(va);
    return fcntl_f(__fd, __cmd, arg);
  }

#if defined(F_GETOWN_EX)
  case F_GETOWN_EX:
  case F_SETOWN_EX: {
    struct f_owner_exlock* arg = va_arg(va, struct f_owner_exlock*);
    va_end(va);
    return fcntl_f(__fd, __cmd, arg);
  }
#endif
  case F_GETFL:
  case F_GETFD:
  case F_GETOWN:
#if defined(F_GETSIG)
  case F_GETSIG:
  case F_GETLEASE:
#endif
#if defined(F_GETPIPE_SZ)
  case F_GETPIPE_SZ:
#endif
  default: 
    va_end(va);
    return fcntl_f(__fd, __cmd);
  }
}
int ioctl(int fd, IOCTL_REQUST_T request, ...)
{
  void* arg;
  va_list va;
  if (request == FIONBIO && _st_netfd(fd))
    return 0;

  va_start(va, request);
  arg = va_arg(va, void*);
  va_end(va);
  if (!ioctl_f) ioctl_f = ST_DLSYM("ioctl");
  return ioctl_f(fd, request, arg);
}
#else
int WSAAPI ioctlsocket (SOCKET fd, long request, u_long *arg)
{
  if (request == FIONBIO && _st_netfd(fd))
    return 0;

  return ioctlsocket_f(fd, request, arg);
}
#endif
int WSAAPI select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, SELECT_TIMEVAL_T*timeout)
{
  int i, npfds, n;
  struct pollfd pollfds[4];
  struct pollfd* pfds;
  if (!ST_HOOK_THREAD)
    return select_f(nfds, readfds, writefds, exceptfds, timeout);

  do {// 执行一次非阻塞的select, 检测异常或无效fd.
    static struct timeval zero_tv = {0, 0};
    fd_set rfs, wfs, efs;
    FD_ZERO(&rfs);
    FD_ZERO(&wfs);
    FD_ZERO(&efs);
    if (readfds)   rfs = *readfds;
    if (writefds)  wfs = *writefds;
    if (exceptfds) efs = *exceptfds;
    n = select_f(nfds, (readfds ? &rfs : NULL), (writefds ? &wfs : NULL),
      (exceptfds ? &efs : NULL), &zero_tv);
    if (n != 0) {
      if (readfds)   *readfds   = rfs;
      if (writefds)  *writefds  = wfs;
      if (exceptfds) *exceptfds = efs;
      return n;
    }
  } while(0);
  do {// convert fd_set to pollfd, and clear 3 fd_set.
    for (i = npfds = 0, pfds = pollfds, n = sizeof(pollfds)/sizeof(struct pollfd); i < nfds; ++i) {
      int events = 0;
      if (readfds && FD_ISSET(i, readfds))   events |= POLLIN;
      if (writefds && FD_ISSET(i, writefds)) events |= POLLOUT;
      if (events || (exceptfds && FD_ISSET(i, exceptfds))){
        if (npfds == n) {
          n *= 2;
          if (pfds == pollfds)
            pfds = (struct pollfd*)memcpy(malloc(sizeof(struct pollfd)*n), pollfds, sizeof(pollfds));
          else
            pfds = (struct pollfd*)realloc(pfds, sizeof(struct pollfd)*n);
        }
        pfds[npfds].fd = i;
        pfds[npfds].events = events;
        ++npfds;
      }
    }
  } while(0);
  // poll
  n = st_poll(pfds, npfds,
    timeout ? timeout->tv_sec * 1000 + timeout->tv_usec / 1000 : -1);
  if (n <= 0) goto clean;
  // convert pollfd to fd_set.
  if (readfds) FD_ZERO(readfds);
  if (writefds) FD_ZERO(writefds);
  if (exceptfds) FD_ZERO(exceptfds);
  for (i = n = 0; i < npfds; ++i) {
    struct pollfd *pfd = &pfds[i];
    if (readfds && (pfd->revents & POLLIN))  { FD_SET(pfd->fd, readfds);  ++n; }
    if (writefds && (pfd->revents & POLLOUT)){ FD_SET(pfd->fd, writefds); ++n;}
    if (exceptfds && (pfd->revents & ~(POLLIN | POLLOUT))){ FD_SET(pfd->fd, exceptfds); ++n; }
  }
clean:
  if (pfds != pollfds) free(pfds);
  return n;
}

