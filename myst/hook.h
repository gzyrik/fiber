#include <stdio.h>
#include <stdarg.h>
#include <dlfcn.h>
static _st_netfd_t** _st_netfd_hook;
_st_netfd_t* st_netfd(int osfd)
{
  if (osfd > -1 && osfd < _st_osfd_limit)
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
  X(int,close,int)\
  X(int,fcntl,int, int, ...)\
  X(int,ioctl,int, unsigned long int, ...)\
  X(int,dup,int)\
  X(int,dup2,int, int)\
  X(int,dup3,int, int, int)\
  X(int,fclose,FILE*)

#if defined(__linux__)
#define _ST_HOOK_LIST _ST_HOOK_LIST0 \
  X(int,gethostbyname_r,const char *__restrict __name, struct hostent *__restrict __result_buf, char *__restrict __buf, size_t __buflen, struct hostent **__restrict __result, int *__restrict __h_errnop)\
  X(int,gethostbyname2_r,const char *name, int af, struct hostent *ret, char *buf, size_t buflen, struct hostent **result, int *h_errnop)\
  X(int,gethostbyaddr_r,const void *addr, socklen_t len, int type, struct hostent *ret, char *buf, size_t buflen, struct hostent **result, int *h_errnop)
#else
#define _ST_HOOK_LIST _ST_HOOK_LIST0
#endif

#define X(ret, name, ...) static ret (*name##_f)(__VA_ARGS__);
_ST_HOOK_LIST
#undef X

int (*select_f)(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
int (*poll_f)(struct pollfd *fds, nfds_t nfds, int timeout);
int (*epoll_wait_f)(int epfd, struct epoll_event *events, int maxevents, int timeout);

static int _st_hook_init()
{
  _st_netfd_hook = calloc(_st_osfd_limit, sizeof(_st_netfd_t*));
  if (dlsym(RTLD_NEXT, "connect")) {
#define X(ret, name, ...) name##_f = dlsym(RTLD_NEXT, #name);
    _ST_HOOK_LIST
    select_f = dlsym(RTLD_NEXT, "select");
    poll_f = dlsym(RTLD_NEXT, "poll");
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
  if (!pipe_f || !socket_f || !socketpair_f ||
      !connect_f || !read_f || !write_f || !readv_f || !writev_f || !send_f
      || !sendto_f || !sendmsg_f || !accept_f || !poll_f || !select_f
      || !sleep_f|| !usleep_f || !nanosleep_f || !close_f || !fcntl_f
      || !dup_f || !dup2_f || !fclose_f
#if defined(__linux__)
      || !pipe2_f
      || !gethostbyname_r_f
      || !gethostbyname2_r_f
      || !gethostbyaddr_r_f
      || !epoll_wait_f
#endif
     )
  {
    return -1;
  }
  return 0;
}

int pipe2(int pipefd[2], int flags)
{
  int err;

  while ((err = pipe2_f(pipefd, flags)) < 0) {
    if (errno != EINTR)
      return -1;
  }
  if (err == 0) {
    if (!st_netfd_open_socket(pipefd[0]) || !st_netfd_open_socket(pipefd[1])) {
      err = errno;
      close_f(pipefd[0]);
      close_f(pipefd[1]);
      errno = err;
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
  if (err == 0) {
    if (!st_netfd_open_socket(sv[0]) || !st_netfd_open_socket(sv[1])) {
      err = errno;
      close_f(sv[0]);
      close_f(sv[1]);
      errno = err;
    }
  }
  return err;
}
int dup(int oldfd)
{
  int err;

  while ((err =dup_f(oldfd)) < 0) {
    if (errno != EINTR)
      return -1;
  }
  if (err >= 0) {
    if (!st_netfd_open_socket(err)) {
      err = errno;
      close_f(err);
      errno = err;
    }
  }
  return err;
}
int dup3(int oldfd, int newfd, int flags)
{
  int err;
  _st_netfd_t* fd;
  if (oldfd != newfd) return 0;

  fd = st_netfd(newfd);
  if (fd) st_netfd_close(fd);

  while ((err =dup3_f(oldfd, newfd, flags)) < 0) {
    if (errno != EINTR)
      return -1;
  }
  if (err == 0) {
    if (!st_netfd_open_socket(newfd)) {
      err = errno;
      close_f(newfd);
      errno = err;
    }
  }
  return err;
}
int close(int sockfd)
{
    _st_netfd_t* fd = st_netfd(sockfd);
    return fd ? st_netfd_close(fd) : close_f(sockfd);
}
int fclose(FILE* fp)
{
    _st_netfd_t* fd = st_netfd(fileno(fp));
    return fd ? st_netfd_close(fd) : fclose_f(fp);
}
int __close(int fd) {return close(fd);}
int dup2(int oldfd, int newfd){return dup3(oldfd, newfd, 0);}
int pipe(int pipefd[2]) {return pipe2(pipefd, 0);}

//read hook
#define _ST_HOOK(hook, sockfd, ...) \
  _st_netfd_t* fd = st_netfd(sockfd); \
return fd ? st_##hook(fd, ##__VA_ARGS__, fd->rcv_timeo) : hook##_f(sockfd, ##__VA_ARGS__)
ssize_t read(int sockfd, void *buf, size_t nbyte) {_ST_HOOK (read, sockfd, buf, nbyte);}
ssize_t readv(int sockfd, const struct iovec *iov, int iov_size){_ST_HOOK(readv, sockfd, iov, iov_size);}
ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
    struct sockaddr *src_addr, socklen_t *addrlen) {_ST_HOOK(recvfrom, sockfd, buf, len, flags, src_addr, addrlen);}
ssize_t recv(int sockfd, void *buf, size_t len, int flags){_ST_HOOK(recv, sockfd, buf, len, flags);}
ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags){_ST_HOOK(recvmsg, sockfd, msg, flags);}
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen){
  _st_netfd_t* fd = st_netfd(sockfd);
  if (fd) {
    fd = st_accept(fd, addr, addrlen, fd->rcv_timeo);
    return fd ? fd->osfd : -1;
  }
  return accept_f(sockfd, addr, addrlen);
}
#undef _ST_HOOK

//write hook
#define _ST_HOOK(hook, sockfd, ...) \
  _st_netfd_t* fd = st_netfd(sockfd); \
return fd ? st_##hook(fd, ##__VA_ARGS__, fd->snd_timeo) : hook##_f(sockfd, ##__VA_ARGS__)
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {_ST_HOOK(connect, sockfd, addr, addrlen);}
ssize_t write(int sockfd, const void *buf, size_t nbyte){_ST_HOOK(write, sockfd, buf, nbyte);}
ssize_t writev(int sockfd, const struct iovec *iov, int iov_size){_ST_HOOK(writev, sockfd, iov, iov_size);}
ssize_t send(int sockfd, const void *buf, size_t len, int flags){_ST_HOOK(send, sockfd, buf, len, flags);}
ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
    const struct sockaddr *dest_addr, socklen_t addrlen) {_ST_HOOK(sendto, sockfd, buf, len, flags, dest_addr, addrlen);}
ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags){_ST_HOOK(sendmsg, sockfd, msg, flags);}
#undef _ST_HOOK

int socket(int domain, int type, int protocol){return st_socket(domain, type, protocol);}
int poll(struct pollfd *fds, nfds_t nfds, int timeout){return st_poll(fds, nfds, timeout);}
int __poll(struct pollfd *fds, nfds_t nfds, int timeout) {return poll(fds, nfds, timeout);}
unsigned sleep(unsigned int seconds){return st_sleep(seconds);}
int usleep(useconds_t usec) {return st_usleep(usec);}
int nanosleep(const struct timespec *req, struct timespec *rem){return -1;}
int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen)
{
    int err = setsockopt_f(sockfd, level, optname, optval, optlen);
    if (err == 0 && level == SOL_SOCKET && (optname == SO_RCVTIMEO || optname == SO_SNDTIMEO)) {
        _st_netfd_t* fd = st_netfd(sockfd);
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
int fcntl(int __fd, int __cmd, ...)
{
    va_list va;
    va_start(va, __cmd);
    switch (__cmd) {
    case F_DUPFD:
    case F_DUPFD_CLOEXEC:
        {// TODO: support FD_CLOEXEC
            int fd = va_arg(va, int);
            va_end(va);
            fd = fcntl_f(__fd, __cmd, fd);
            if (fd >= 0 && !st_netfd_open_socket(fd)){
                int err = errno;
                close_f(fd);
                return err;
            }
            return fd;
        }
    case F_SETFD:
    case F_SETOWN:
#if defined(__linux__)
    case F_SETSIG:
    case F_SETLEASE:
    case F_NOTIFY:
#endif
#if defined(F_SETPIPE_SZ)
    case F_SETPIPE_SZ:
#endif
        {
            int arg = va_arg(va, int);
            va_end(va);
            return fcntl_f(__fd, __cmd, arg);
        }
    case F_SETFL:
        {
            int flags = va_arg(va, int) | O_NONBLOCK;
            va_end(va);
            return fcntl_f(__fd, __cmd, flags);
        }
    case F_GETLK:
    case F_SETLK:
    case F_SETLKW:
        {
            struct flock* arg = va_arg(va, struct flock*);
            va_end(va);
            return fcntl_f(__fd, __cmd, arg);
        }

#if defined(__linux__)
    case F_GETOWN_EX:
    case F_SETOWN_EX:
        {
            struct f_owner_exlock* arg = va_arg(va, struct f_owner_exlock*);
            va_end(va);
            return fcntl_f(__fd, __cmd, arg);
        }
#endif
    case F_GETFL:
        {
            va_end(va);
            return fcntl_f(__fd, __cmd);
        }
    case F_GETFD:
    case F_GETOWN:
#if defined(__linux__)
    case F_GETSIG:
    case F_GETLEASE:
#endif
#if defined(F_GETPIPE_SZ)
    case F_GETPIPE_SZ:
#endif
    default:
        {
            va_end(va);
            return fcntl_f(__fd, __cmd);
        }
    }
}
int ioctl(int fd, unsigned long int request, ...)
{
    void* arg;
    va_list va;
    if (request == FIONBIO) return 0;

    va_start(va, request);
    arg = va_arg(va, void*);
    va_end(va);
    return ioctl_f(fd, request, arg);
}
int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
{
  int i, n, npfds, timeout_ms = -1;
  short* pfd_map;
  struct pollfd* pfds;
  static struct timeval zero_tv = {0, 0};
  struct {fd_set* fset; int evt;} sets[3]={
    {readfds, POLLIN},
    {writefds, POLLOUT},
    {exceptfds, 0}
  };

  if (timeout)
    timeout_ms = timeout->tv_sec * 1000 + timeout->tv_usec / 1000;
  if (nfds > FD_SETSIZE) nfds = FD_SETSIZE;

  // 执行一次非阻塞的select, 检测异常或无效fd.
  fd_set rfs, wfs, efs;
  FD_ZERO(&rfs);
  FD_ZERO(&wfs);
  FD_ZERO(&efs);
  if (readfds) rfs = *readfds;
  if (writefds) wfs = *writefds;
  if (exceptfds) efs = *exceptfds;
  n = select_f(nfds, (readfds ? &rfs : NULL), (writefds ? &wfs : NULL),
      (exceptfds ? &efs : NULL), &zero_tv);
  if (n != 0) {
    if (readfds) *readfds = rfs;
    if (writefds) *writefds = wfs;
    if (exceptfds) *exceptfds = efs;
    return n;
  }
  // -------------------------------------
  // convert fd_set to pollfd, and clear 3 fd_set.
  pfd_map = calloc(nfds, sizeof(short));
  for (i = 0; i < 3; ++i) {
    fd_set* fds = sets[i].fset;
    if (!fds) continue;
    int event = sets[i].evt;
    for (n = 0; n < nfds; ++n) {
      if (FD_ISSET(n, fds)) pfd_map[n] |= event;
    }
    FD_ZERO(fds);
  }
  pfds = calloc(nfds, sizeof(struct pollfd));
  for(i=0,npfds=0;i<nfds;++i) {
    if (pfd_map[i] != 0) {
      pfds[npfds].fd = i;
      pfds[npfds].events= pfd_map[i];
      ++npfds;
    }
  }
  // -------------------------------------
  // poll
  n = st_poll(pfds, npfds, timeout_ms);
  if (n <= 0) goto clean;
  // convert pollfd to fd_set.
  n = 0;
  for (i = 0; i < npfds; ++i) {
    struct pollfd *pfd = &pfds[i];
    if (pfd->revents & POLLIN) {
      if (readfds) {
        FD_SET(pfd->fd, readfds);
        ++n;
      }
    }

    if (pfd->revents & POLLOUT) {
      if (writefds) {
        FD_SET(pfd->fd, writefds);
        ++n;
      }
    }

    if (pfd->revents & ~(POLLIN | POLLOUT)) {
      if (exceptfds) {
        FD_SET(pfd->fd, exceptfds);
        ++n;
      }
    }
  }
clean:
  free(pfds);
  free(pfd_map);
  return n;
}
