#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#ifndef _WIN32
#define __USE_GNU
#include <dlfcn.h>
typedef int SOCKET;
#define WINAPI
#else
#define __thread __declspec(thread)
#endif
static __thread _st_netfd_t** _st_netfd_hook;
static _st_netfd_t* _st_netfd(int osfd)
{
  if (_st_netfd_hook && osfd > -1 && osfd < _st_osfd_limit)
    return _st_netfd_hook[osfd];
  return NULL;
}
#define _ST_HOOK_LIST0 \
  X(int,pipe,int pipefd[2])\
  X(int,pipe2,int pipefd[2], int flags)\
  X(int,socket,int domain, int type, int protocol)\
  X(int,socketpair,int domain, int type, int protocol, int sv[2])\
  X(int,connect,int, const struct sockaddr *, socklen_t)\
  X(ssize_t,read,int, void *, size_t)\
  X(ssize_t,readv,int, const struct iovec *, int)\
  X(ssize_t,recv,int sockfd, void *buf, size_t len, int flags)\
  X(ssize_t,recvfrom,int sockfd, void *buf, size_t len, int flags, struct sockaddr *src_addr, socklen_t *addrlen)\
  X(ssize_t,recvmsg,int sockfd, struct msghdr *msg, int flags)\
  X(ssize_t,write,int, const void *, size_t)\
  X(ssize_t,writev,int, const struct iovec *, int)\
  X(ssize_t,send,int sockfd, const void *buf, size_t len, int flags)\
  X(ssize_t,sendto,int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen)\
  X(ssize_t,sendmsg,int sockfd, const struct msghdr *msg, int flags)\
  X(int,accept,int sockfd, struct sockaddr *addr, socklen_t *addrlen)\
  X(unsigned,sleep,unsigned int)\
  X(int,usleep,useconds_t)\
  X(int,nanosleep,const struct timespec *req, struct timespec *rem)\
  X(int,setsockopt,int, int, int, const void*, socklen_t)\
  X(int,getsockopt,int, int, int, void*, socklen_t*)\
  X(int,close,int)\
  X(int,fcntl,int, int, ...)\
  X(int,ioctl,int, unsigned long int, ...)\
  X(int,dup,int)\
  X(int,dup2,int, int)\
  X(int,dup3,int, int, int)\
  X(FILE*,fopen,const char * __restrict, const char * __restrict)\
  X(int,fclose,FILE*)

#if defined(__linux__)
struct hostent;
#define _ST_HOOK_LIST _ST_HOOK_LIST0 \
  X(int,gethostbyname_r,const char*__restrict, struct hostent*__restrict, char*__restrict, size_t, struct hostent**__restrict, int*__restrict)\
  X(int,gethostbyname2_r,const char*, int, struct hostent*, char*, size_t , struct hostent**, int *)\
  X(int,gethostbyaddr_r,const void*, socklen_t, int type, struct hostent*, char*, size_t, struct hostent**, int *)
#else
#define _ST_HOOK_LIST _ST_HOOK_LIST0
#endif

#define X(ret, name, ...) static ret (*name##_f)(__VA_ARGS__);
_ST_HOOK_LIST
#undef X

#if defined(__linux__)
#define X(ret, name, ...) __attribute__((weak)) extern ret __##name(__VA_ARGS__);
_ST_HOOK_LIST
__attribute__((weak)) extern int __libc_poll(struct pollfd*, nfds_t, int );
__attribute__((weak)) extern int __select(int, fd_set*, fd_set*, fd_set*, struct timeval*);
__attribute__((weak)) extern int __epoll_wait_nocancel(int, struct epoll_event*, int, int);
#undef X
#endif

int (*select_f)(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
int (*poll_f)(struct pollfd *fds, nfds_t nfds, int timeout);
int (*epoll_wait_f)(int epfd, struct epoll_event *events, int maxevents, int timeout);

static int _st_hook_init()
{
#ifdef _WIN32
  HMODULE RTLD_NEXT = LoadLibrary("Ws2_32.dll");
  if (!RTLD_NEXT) return -1;
#define dlsym(x,y) (void*)GetProcAddress(x, y)
  poll_f = dlsym(RTLD_NEXT, "WSAPoll");
#else
  poll_f = dlsym(RTLD_NEXT, "poll");
#endif
  if (poll_f) {
#define X(ret, name, ...) name##_f = dlsym(RTLD_NEXT, #name);
    _ST_HOOK_LIST
    select_f = dlsym(RTLD_NEXT, "select");
    epoll_wait_f = dlsym(RTLD_NEXT, "epoll_wait");
#undef X
#if defined(__linux__)
  } else {
#define X(ret, name, ...) name##_f = &__##name;
    _ST_HOOK_LIST
    select_f = &__select;
    poll_f = &__libc_poll;
    epoll_wait_f = &__epoll_wait_nocancel;
#undef X
#endif
  }
  if (!connect_f || !send_f || !socket_f
    || !sendto_f || !accept_f || !poll_f || !select_f 
#ifndef _WIN32
    || !read_f || !write_f || !readv_f || !writev_f
    || !pipe_f || !socketpair_f || !sendmsg_f
    || !sleep_f || !usleep_f || !nanosleep_f || !close_f || !fcntl_f
    || !dup_f || !dup2_f || !fclose_f
#if defined(__linux__)
    || !pipe2_f
    || !gethostbyname_r_f
    || !gethostbyname2_r_f
    || !gethostbyaddr_r_f
    || !epoll_wait_f
#endif
#endif
    )
  {
    return -1;
  }
  _st_netfd_hook = calloc(_st_osfd_limit, sizeof(_st_netfd_t*));
  if (!_st_netfd_hook)
    return -1;
  return 0;
}

int pipe2(int pipefd[2], int flags)
{
  int err;

  while ((err = (pipe2_f ? pipe2_f(pipefd, flags) : pipe_f(pipefd))) < 0) {
    if (errno != EINTR)
      return -1;
  }
  if (err == 0 && _st_netfd_hook) {
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
  if (err == 0 && _st_netfd_hook) {
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
  if (err >= 0 && _st_netfd_hook) {
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
  if (err == 0 && _st_netfd_hook) {
    if (!st_netfd_open_socket(newfd)) {
      err = errno;
      close_f(newfd);
      errno = err;
      return -1;
    }
  }
  return err;
}
int closesocket(SOCKET sockfd) {return close(sockfd);}
int close(int sockfd)
{
  _st_netfd_t* fd = _st_netfd(sockfd);
  return fd ? st_netfd_close(fd) : close_f(sockfd);
}
FILE* fopen(const char * __restrict filename , const char * __restrict mode)
{
  FILE* fp = fopen_f(filename, mode);
  if (fp && _st_netfd_hook) {
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
  return fclose_f(fp);
}
int __close(int fd) {return close(fd);}
int dup2(int oldfd, int newfd){return dup3(oldfd, newfd, 0);}
int pipe(int pipefd[2]) {return pipe2(pipefd, 0);}


//read hook
#define _ST_HOOK(hook, sockfd, ...) \
  _st_netfd_t* fd = _st_netfd(sockfd); \
return fd ? st_##hook(fd, ##__VA_ARGS__, fd->rcv_timeo) : hook##_f(sockfd, ##__VA_ARGS__)
#ifndef _WIN32
ssize_t read(int sockfd, void *buf, size_t nbyte) {_ST_HOOK (read, sockfd, buf, nbyte);}
ssize_t readv(int sockfd, const struct iovec *iov, int iov_size){_ST_HOOK(readv, sockfd, iov, iov_size);}
ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
  struct sockaddr *src_addr, socklen_t *addrlen) {_ST_HOOK(recvfrom, sockfd, buf, len, flags, src_addr, addrlen);}
ssize_t recv(int sockfd, void *buf, size_t len, int flags){_ST_HOOK(recv, sockfd, buf, len, flags);}
ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags){_ST_HOOK(recvmsg, sockfd, msg, flags);}
#else
int recvfrom(SOCKET sockfd, char *buf, int len, int flags,
  struct sockaddr *src_addr, int *addrlen) {_ST_HOOK(recvfrom, sockfd, buf, len, flags, src_addr, addrlen);}
int recv(SOCKET sockfd, char *buf, int len, int flags) {_ST_HOOK(recv, sockfd, buf, len, flags);}
#endif
#undef _ST_HOOK
SOCKET accept(SOCKET sockfd, struct sockaddr *addr, socklen_t *addrlen){
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
  return fd ? st_##hook(fd, ##__VA_ARGS__, fd->snd_timeo) : hook##_f(sockfd, ##__VA_ARGS__)
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {_ST_HOOK(connect, sockfd, addr, addrlen);}
#ifndef _WIN32
ssize_t write(int sockfd, const void *buf, size_t nbyte){_ST_HOOK(write, sockfd, buf, nbyte);}
ssize_t writev(int sockfd, const struct iovec *iov, int iov_size){_ST_HOOK(writev, sockfd, iov, iov_size);}
ssize_t send(int sockfd, const void *buf, size_t len, int flags){_ST_HOOK(send, sockfd, buf, len, flags);}
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
  const struct sockaddr *dest_addr, socklen_t addrlen) {_ST_HOOK(sendto, sockfd, buf, len, flags, dest_addr, addrlen);}
ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags){_ST_HOOK(sendmsg, sockfd, msg, flags);}
#else
int send(int sockfd, const char *buf, int len, int flags) {_ST_HOOK(send, sockfd, buf, len, flags);}
int sendto(int sockfd, const char *buf, int len, int flags,
  const struct sockaddr *dest_addr, int addrlen) {_ST_HOOK(sendto, sockfd, buf, len, flags, dest_addr, addrlen);}
#endif
#undef _ST_HOOK

SOCKET socket(int domain, int type, int protocol)
{return _st_netfd_hook ? st_socket(domain, type, protocol) : socket_f(domain, type, protocol);}
int poll(struct pollfd *fds, nfds_t nfds, int timeout)
{return _st_netfd_hook ? st_poll(fds, nfds, timeout) : poll_f(fds, nfds, timeout);}
int __poll(struct pollfd *fds, nfds_t nfds, int timeout) {return poll(fds, nfds, timeout);}
#ifndef _WIN32
unsigned sleep(unsigned int seconds)
{return _st_netfd_hook ? st_sleep(seconds) : sleep_f(seconds);}
int usleep(useconds_t usec)
{return _st_netfd_hook ? st_usleep(usec) : usleep_f(usec);}
int nanosleep(const struct timespec *req, struct timespec *rem)
{return _st_netfd_hook ? st_usleep(req->tv_sec * 1000000 + req->tv_nsec/1000): nanosleep_f(req, rem);}
#endif
int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen)
{
  int err = setsockopt_f(sockfd, level, optname, optval, optlen);
  if (err == 0 && level == SOL_SOCKET
    && (optname == SO_RCVTIMEO || optname == SO_SNDTIMEO)
    && optlen == sizeof(struct timeval)) {
    _st_netfd_t* fd = _st_netfd(sockfd);
    if (fd) {
      struct timeval* tv = (struct timeval*)optval;
      st_utime_t us = tv->tv_sec * 1000000 + tv->tv_usec;
      if (optname == SO_RCVTIMEO)
        fd->rcv_timeo = us;
      else 
        fd->snd_timeo = us;
    }
  }
  return err;
}
int getsockopt(int sockfd, int level, int optname, void *optval, socklen_t *optlen)
{
  if (level == SOL_SOCKET
    && (optname == SO_RCVTIMEO || optname == SO_SNDTIMEO)
    && *optlen == sizeof(struct timeval)) {
    _st_netfd_t* fd = _st_netfd(sockfd);
    if (fd) {
      st_utime_t us = (optname == SO_RCVTIMEO ? fd->rcv_timeo : fd->snd_timeo);
      struct timeval* tv = (struct timeval*)optval;
      tv->tv_sec  = us /1000000;
      tv->tv_usec = us - tv->tv_sec *1000000;
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
    if (fd >= 0 && _st_netfd_hook && !st_netfd_open_socket(fd)){
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
    if (_st_netfd_hook) flags |= O_NONBLOCK;
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
#endif
int ioctl(int fd, unsigned long int request, ...)
{
  void* arg;
  va_list va;
  if (request == FIONBIO && _st_netfd_hook)
    return 0;

  va_start(va, request);
  arg = va_arg(va, void*);
  va_end(va);
  return ioctl_f(fd, request, arg);
}
int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
{
  int i, npfds, n;
  struct pollfd pollfds[4];
  struct pollfd* pfds;
  if (!_st_netfd_hook)
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

