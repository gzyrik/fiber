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

#include <ctype.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include "common.h"

#if EAGAIN != EWOULDBLOCK
#define _IO_NOT_READY_ERROR  ((errno == EAGAIN) || (errno == EWOULDBLOCK))
#else
#define _IO_NOT_READY_ERROR  (errno == EAGAIN)
#endif

#define _LOCAL_MAXIOV  16

/* File descriptor object free list */
static _st_netfd_t *_st_netfd_freelist = NULL;
/* Maximum number of file descriptors that the process can open */
static int _st_osfd_limit = -1;
_st_stack_t _st_primordial_stk;

static void _st_netfd_free_aux_data(_st_netfd_t *fd);

#ifdef ST_HOOK_SYS
#include "hook.h"
#endif

#ifdef _WIN32
int* _st_errno(void) { return _errno(); }
static void _IO_GET_ERRNO()
{
  const int r = _ST_SYS_CALL(WSAGetLastError)();
  switch (r){
  case WSAEWOULDBLOCK: errno = EWOULDBLOCK; break;
  case WSAEINPROGRESS: errno = EINPROGRESS; break;
  case WSAEINTR: errno = EINTR; break;
  case WSAEADDRINUSE: errno = EADDRINUSE; break;
  case WSAETIMEDOUT: errno = ETIMEDOUT; break;
  default: errno = r;
  }
}
static int _ST_SYS_CALL(readv)(SOCKET fd, const struct iovec *iov, int iov_size)
{
  DWORD numberOfBytesRecevd, flags=0;
  if (WSARecv(fd, (LPWSABUF)iov, iov_size, &numberOfBytesRecevd, &flags, NULL, NULL) >= 0)
    return numberOfBytesRecevd;
  return -1;
}
static int _ST_SYS_CALL(writev)(SOCKET fd, struct iovec *iov, int iov_size)
{
  DWORD numberOfBytesRecevd;
  if (WSASend(fd, (LPWSABUF)iov, iov_size, &numberOfBytesRecevd, 0, NULL, NULL) >= 0)
    return numberOfBytesRecevd;
  return -1;
}
static int _ST_SYS_CALL(sendmsg)(SOCKET fd, const struct msghdr *msg, int flags)
{
  DWORD numberOfBytesSent;
  if (WSASendMsg(fd, (LPWSAMSG)msg, 0, &numberOfBytesSent, NULL, NULL) >= 0)
    return numberOfBytesSent;
  return -1;
}
static int _ST_SYS_CALL(recvmsg)(SOCKET fd, struct msghdr *msg, int flags)
{//TODO
  return -1;
}
#else
#include <sys/resource.h>
static void _IO_GET_ERRNO() {}
#ifdef ST_HOOK_SYS
static int closesocket_f(int osfd) {return _ST_SYS_CALL(close)(osfd);}
#endif
#endif

int _st_io_init(void)
{
  int fdlim = (*_st_eventsys->fd_getlimit)();
#ifndef _WIN32
  struct sigaction sigact;
  struct rlimit rlim;

  /* Ignore SIGPIPE */
  sigact.sa_handler = SIG_IGN;
  sigemptyset(&sigact.sa_mask);
  sigact.sa_flags = 0;
  if (sigaction(SIGPIPE, &sigact, NULL) < 0)
    return -1;

  /* Set maximum number of open file descriptors */
  if (getrlimit(RLIMIT_NOFILE, &rlim) < 0)
    return -1;

  if (fdlim > 0 && rlim.rlim_max > (rlim_t) fdlim) {
    rlim.rlim_max = fdlim;
  }
  fdlim = (int)rlim.rlim_cur;
  rlim.rlim_cur = rlim.rlim_max;
  if (setrlimit(RLIMIT_NOFILE, &rlim) >= 0)
    fdlim = (int)rlim.rlim_max;

  getrlimit (RLIMIT_STACK, &rlim);
  _st_primordial_stk.vaddr_size = rlim.rlim_max;
  _st_primordial_stk.stk_size = rlim.rlim_cur;

#else
  WSADATA wsd;
  WSAStartup(MAKEWORD(2, 2), &wsd);
  fdlim = 4096;
  _st_primordial_stk.vaddr_size = 1024*1024;
  _st_primordial_stk.stk_size = 1024*1024;
#endif

  _st_osfd_limit = fdlim;

#ifdef ST_HOOK_SYS
  return _st_hook_init();
#else
  return 0;
#endif
}


int st_getfdlimit(void)
{
  return _st_osfd_limit;
}


void st_netfd_free(_st_netfd_t *fd)
{
  if (!fd->inuse)
    return;

#ifdef ST_HOOK_SYS
  _st_netfd_hook[fd->osfd] = NULL;
#endif

  fd->inuse = 0;
  if (fd->aux_data)
    _st_netfd_free_aux_data(fd);
  if (fd->private_data && fd->destructor)
    (*(fd->destructor))(fd->private_data);
  fd->private_data = NULL;
  fd->destructor = NULL;
  fd->next = _st_netfd_freelist;
  _st_netfd_freelist = fd;
}


static _st_netfd_t *_st_netfd_new(SOCKET osfd, int nonblock, int is_socket)
{
  _st_netfd_t *fd;
  int flags = 1;

#ifdef ST_HOOK_SYS
  if (osfd < 0 || osfd > _st_osfd_limit)
    return NULL;
  if (_st_netfd_hook[osfd] != NULL)
    return _st_netfd_hook[osfd];
#endif

  if ((*_st_eventsys->fd_new)(osfd) < 0)
    return NULL;

  if (_st_netfd_freelist) {
    fd = _st_netfd_freelist;
    _st_netfd_freelist = _st_netfd_freelist->next;
  } else {
    fd = calloc(1, sizeof(_st_netfd_t));
    if (!fd)
      return NULL;
  }

  fd->osfd = osfd;
  fd->inuse = 1;
  fd->next = NULL;

  if (nonblock) {
#ifdef _WIN32
    u_long nonblock = 1;
    if (_ST_SYS_CALL(ioctlsocket) (osfd, FIONBIO, &nonblock) < 0) {
      st_netfd_free(fd);
      return NULL;
    }
#else
    /* Use just one system call */
    if (is_socket && _ST_SYS_CALL(ioctl)(osfd, FIONBIO, &flags) != -1)
      ;
    /* Do it the Posix way */
    else if ((flags = _ST_SYS_CALL(fcntl)(osfd, F_GETFL, 0)) < 0 ||
      _ST_SYS_CALL(fcntl)(osfd, F_SETFL, flags | O_NONBLOCK) < 0) {
      st_netfd_free(fd);
      return NULL;
    }
#endif
  }

#ifdef ST_HOOK_SYS
  fd->snd_timeo = fd->rcv_timeo = ST_UTIME_NO_TIMEOUT;
  _st_netfd_hook[osfd] = fd;
#endif
  return fd;
}


_st_netfd_t *st_netfd_open(SOCKET osfd)
{
  return _st_netfd_new(osfd, 1, 0);
}


_st_netfd_t *st_netfd_open_socket(SOCKET osfd)
{
  return _st_netfd_new(osfd, 1, 1);
}


int st_netfd_close(_st_netfd_t *fd)
{
  if ((*_st_eventsys->fd_close)(fd->osfd) < 0)
    return -1;

  st_netfd_free(fd);
  return _ST_SYS_CALL(closesocket)(fd->osfd);
}


int st_netfd_fileno(_st_netfd_t *fd)
{
  return fd ? (fd->osfd) : INVALID_SOCKET;
}


void st_netfd_setspecific(_st_netfd_t *fd, void *value,
                          _st_destructor_t destructor)
{
  if (value != fd->private_data) {
    /* Free up previously set non-NULL data value */
    if (fd->private_data && fd->destructor)
      (*(fd->destructor))(fd->private_data);
  }
  fd->private_data = value;
  fd->destructor = destructor;
}


void *st_netfd_getspecific(_st_netfd_t *fd)
{
  return (fd->private_data);
}


/*
 * Wait for I/O on a single descriptor.
 */
int st_netfd_poll(_st_netfd_t *fd, int how, st_utime_t timeout)
{
  struct pollfd pd;
  int n;

  pd.fd = fd->osfd;
  pd.events = (short) how;
  pd.revents = 0;

  if ((n = st_poll(&pd, 1, timeout)) < 0)
    return -1;
  if (n == 0) {
    /* Timed out */
    errno = ETIME;
    return -1;
  }
  if (pd.revents & POLLNVAL) {
    errno = EBADF;
    return -1;
  }

  return 0;
}


#ifdef MD_ALWAYS_UNSERIALIZED_ACCEPT
/* No-op */
int st_netfd_serialize_accept(_st_netfd_t *fd)
{
  fd->aux_data = NULL;
  return 0;
}

/* No-op */
static void _st_netfd_free_aux_data(_st_netfd_t *fd)
{
  fd->aux_data = NULL;
}

_st_netfd_t *st_accept(_st_netfd_t *fd, struct sockaddr *addr, socklen_t *addrlen,
                       st_utime_t timeout)
{
  int osfd, err;
  _st_netfd_t *newfd;

  while ((osfd = _ST_SYS_CALL(accept)(fd->osfd, addr, addrlen)) < 0) {
    _IO_GET_ERRNO();
    if (errno == EINTR)
      continue;
    if (!_IO_NOT_READY_ERROR)
      return NULL;
    /* Wait until the socket becomes readable */
    if (st_netfd_poll(fd, POLLIN, timeout) < 0)
      return NULL;
  }

  /* On some platforms the new socket created by accept() inherits */
  /* the nonblocking attribute of the listening socket */
#if defined (MD_ACCEPT_NB_INHERITED)
  newfd = _st_netfd_new(osfd, 0, 1);
#elif defined (MD_ACCEPT_NB_NOT_INHERITED)
  newfd = _st_netfd_new(osfd, 1, 1);
#else
#error Unknown OS
#endif

  if (!newfd) {
    err = errno;
    _ST_SYS_CALL(closesocket)(osfd);
    errno = err;
  }

  return newfd;
}

#else /* MD_ALWAYS_UNSERIALIZED_ACCEPT */
/*
 * On some platforms accept() calls from different processes
 * on the same listen socket must be serialized.
 * The following code serializes accept()'s without process blocking.
 * A pipe is used as an inter-process semaphore.
 */
int st_netfd_serialize_accept(_st_netfd_t *fd)
{
  _st_netfd_t **p;
  int osfd[2], err;

  if (fd->aux_data) {
    errno = EINVAL;
    return -1;
  }
  if ((p = (_st_netfd_t **)calloc(2, sizeof(_st_netfd_t *))) == NULL)
    return -1;
  if (pipe(osfd) < 0) {
    free(p);
    return -1;
  }
  if ((p[0] = st_netfd_open(osfd[0])) != NULL &&
      (p[1] = st_netfd_open(osfd[1])) != NULL &&
      _ST_SYS_CALL(write)(osfd[1], " ", 1) == 1) {
    fd->aux_data = p;
    return 0;
  }
  /* Error */
  err = errno;
  if (p[0])
    st_netfd_free(p[0]);
  if (p[1])
    st_netfd_free(p[1]);
  _ST_SYS_CALL(close)(osfd[0]);
  _ST_SYS_CALL(close)(osfd[1]);
  free(p);
  errno = err;

  return -1;
}

static void _st_netfd_free_aux_data(_st_netfd_t *fd)
{
  _st_netfd_t **p = (_st_netfd_t **) fd->aux_data;

  st_netfd_close(p[0]);
  st_netfd_close(p[1]);
  free(p);
  fd->aux_data = NULL;
}

_st_netfd_t *st_accept(_st_netfd_t *fd, struct sockaddr *addr, socklen_t *addrlen,
                       st_utime_t timeout)
{
  int osfd, err;
  _st_netfd_t *newfd;
  _st_netfd_t **p = (_st_netfd_t **) fd->aux_data;
  ssize_t n;
  char c;

  for ( ; ; ) {
    if (p == NULL) {
      osfd = _ST_SYS_CALL(accept)(fd->osfd, addr, addrlen);
    } else {
      /* Get the lock */
      n = st_read(p[0], &c, 1, timeout);
      if (n < 0)
        return NULL;
      ST_ASSERT(n == 1);
      /* Got the lock */
      osfd = _ST_SYS_CALL(accept)(fd->osfd, addr, addrlen);
      /* Unlock */
      err = errno;
      n = st_write(p[1], &c, 1, timeout);
      ST_ASSERT(n == 1);
      errno = err;
    }
    if (osfd >= 0)
      break;
    if (errno == EINTR)
      continue;
    if (!_IO_NOT_READY_ERROR)
      return NULL;
    /* Wait until the socket becomes readable */
    if (st_netfd_poll(fd, POLLIN, timeout) < 0)
      return NULL;
  }

  /* On some platforms the new socket created by accept() inherits */
  /* the nonblocking attribute of the listening socket */
#if defined (MD_ACCEPT_NB_INHERITED)
  newfd = _st_netfd_new(osfd, 0, 1);
#elif defined (MD_ACCEPT_NB_NOT_INHERITED)
  newfd = _st_netfd_new(osfd, 1, 1);
#else
#error Unknown OS
#endif

  if (!newfd) {
    err = errno;
    _ST_SYS_CALL(closesocket)(osfd);
    errno = err;
  }

  return newfd;
}
#endif /* MD_ALWAYS_UNSERIALIZED_ACCEPT */


int st_connect(_st_netfd_t *fd, const struct sockaddr *addr, int addrlen,
               st_utime_t timeout)
{
  int n, err = 0;
#ifdef _WIN32
  if (timeout ==  ST_UTIME_NO_TIMEOUT)//fix window bug, force 60s timeout
    timeout = 60 * 1000000LL;
#endif

  while (_ST_SYS_CALL(connect)(fd->osfd, addr, addrlen) < 0) {
    _IO_GET_ERRNO();
    if (errno != EINTR) {
      /*
       * On some platforms, if connect() is interrupted (errno == EINTR)
       * after the kernel binds the socket, a subsequent connect()
       * attempt will fail with errno == EADDRINUSE.  Ignore EADDRINUSE
       * iff connect() was previously interrupted.  See Rich Stevens'
       * "UNIX Network Programming," Vol. 1, 2nd edition, p. 413
       * ("Interrupted connect").
       */
      if (errno != EINPROGRESS && !_IO_NOT_READY_ERROR && (errno != EADDRINUSE || err == 0))
        return -1;
      /* Wait until the socket becomes writable */
      if (st_netfd_poll(fd, POLLOUT, timeout) < 0)
        return -1;
      /* Try to find out whether the connection setup succeeded or failed */
      n = sizeof(int);
      if (getsockopt(fd->osfd, SOL_SOCKET, SO_ERROR, (char *)&err,
                     (socklen_t *)&n) < 0)
        return -1;
      if (err) {
        errno = err;
        return -1;
      }
      break;
    }
    err = 1;
  }

  return 0;
}


ssize_t st_read(_st_netfd_t *fd, void *buf, size_t nbyte, st_utime_t timeout)
{
  struct iovec iov;
  iov.iov_base = buf;
  iov.iov_len = nbyte;
  return st_readv(fd, &iov, 1, timeout);
}

int st_read_resid(_st_netfd_t *fd, void *buf, size_t *resid,
                  st_utime_t timeout)
{
  struct iovec iov, *riov;
  int riov_size, rv;

  iov.iov_base = buf;
  iov.iov_len = *resid;
  riov = &iov;
  riov_size = 1;
  rv = st_readv_resid(fd, &riov, &riov_size, timeout);
  *resid = iov.iov_len;
  return rv;
}

ssize_t st_readv(_st_netfd_t *fd, const struct iovec *iov, int iov_size,
                 st_utime_t timeout)
{
  ssize_t n;

  while ((n = _ST_SYS_CALL(readv)(fd->osfd, iov, iov_size)) < 0) {
    _IO_GET_ERRNO();
    if (errno == EINTR)
      continue;
    if (!_IO_NOT_READY_ERROR)
      return -1;
    /* Wait until the socket becomes readable */
    if (st_netfd_poll(fd, POLLIN, timeout) < 0)
      return -1;
  }

  return n;
}

int st_readv_resid(_st_netfd_t *fd, struct iovec **iov, int *iov_size,
                   st_utime_t timeout)
{
  ssize_t n;

  while (*iov_size > 0) {
    if ((n = _ST_SYS_CALL(readv)(fd->osfd, *iov, *iov_size)) < 0) {
      _IO_GET_ERRNO();
      if (errno == EINTR)
        continue;
      if (!_IO_NOT_READY_ERROR)
        return -1;
    } else if (n == 0)
      break;
    else {
      while ((size_t) n >= (*iov)->iov_len) {
        n -= (*iov)->iov_len;
        (*iov)->iov_base = (char *) (*iov)->iov_base + (*iov)->iov_len;
        (*iov)->iov_len = 0;
        (*iov)++;
        (*iov_size)--;
        if (n == 0)
          break;
      }
      if (*iov_size == 0)
        break;
      (*iov)->iov_base = (char *) (*iov)->iov_base + n;
      (*iov)->iov_len -= n;
    }
    /* Wait until the socket becomes readable */
    if (st_netfd_poll(fd, POLLIN, timeout) < 0)
      return -1;
  }

  return 0;
}


ssize_t st_read_fully(_st_netfd_t *fd, void *buf, size_t nbyte,
                      st_utime_t timeout)
{
  size_t resid = nbyte;
  return st_read_resid(fd, buf, &resid, timeout) == 0 ?
    (ssize_t) (nbyte - resid) : -1;
}


int st_write_resid(_st_netfd_t *fd, const void *buf, size_t *resid,
                   st_utime_t timeout)
{
  struct iovec iov, *riov;
  int riov_size, rv;

  iov.iov_base = (void *) buf;            /* we promise not to modify buf */
  iov.iov_len = *resid;
  riov = &iov;
  riov_size = 1;
  rv = st_writev_resid(fd, &riov, &riov_size, timeout);
  *resid = iov.iov_len;
  return rv;
}

ssize_t st_write(_st_netfd_t *fd, const void *buf, size_t nbyte,
                 st_utime_t timeout)
{
  size_t resid = nbyte;
  return st_write_resid(fd, buf, &resid, timeout) == 0 ?
    (ssize_t) (nbyte - resid) : -1;
}


ssize_t st_writev(_st_netfd_t *fd, const struct iovec *iov, int iov_size,
                  st_utime_t timeout)
{
  ssize_t n, rv;
  size_t nleft, nbyte;
  int index, iov_cnt;
  struct iovec *tmp_iov;
  struct iovec local_iov[_LOCAL_MAXIOV];

  /* Calculate the total number of bytes to be sent */
  nbyte = 0;
  for (index = 0; index < iov_size; index++)
    nbyte += iov[index].iov_len;

  rv = (ssize_t)nbyte;
  nleft = nbyte;
  tmp_iov = (struct iovec *) iov;        /* we promise not to modify iov */
  iov_cnt = iov_size;

  while (nleft > 0) {
    if (iov_cnt == 1) {
      if (st_write(fd, tmp_iov[0].iov_base, nleft, timeout) != (ssize_t) nleft)
        rv = -1;
      break;
    }
    if ((n = _ST_SYS_CALL(writev)(fd->osfd, tmp_iov, iov_cnt)) < 0) {
      _IO_GET_ERRNO();
      if (errno == EINTR)
        continue;
      if (!_IO_NOT_READY_ERROR) {
        rv = -1;
        break;
      }
    } else {
      if ((size_t) n == nleft)
        break;
      nleft -= n;
      /* Find the next unwritten vector */
      n = (ssize_t)(nbyte - nleft);
      for (index = 0; (size_t) n >= iov[index].iov_len; index++)
        n -= iov[index].iov_len;

      if (tmp_iov == iov) {
        /* Must copy iov's around */
        if (iov_size - index <= _LOCAL_MAXIOV) {
          tmp_iov = local_iov;
        } else {
          tmp_iov = calloc(1, (iov_size - index) * sizeof(struct iovec));
          if (tmp_iov == NULL)
            return -1;
        }
      }

      /* Fill in the first partial read */
      tmp_iov[0].iov_base = &(((char *)iov[index].iov_base)[n]);
      tmp_iov[0].iov_len = iov[index].iov_len - n;
      index++;
      /* Copy the remaining vectors */
      for (iov_cnt = 1; index < iov_size; iov_cnt++, index++) {
        tmp_iov[iov_cnt].iov_base = iov[index].iov_base;
        tmp_iov[iov_cnt].iov_len = iov[index].iov_len;
      }
    }
    /* Wait until the socket becomes writable */
    if (st_netfd_poll(fd, POLLOUT, timeout) < 0) {
      rv = -1;
      break;
    }
  }

  if (tmp_iov != iov && tmp_iov != local_iov)
    free(tmp_iov);

  return rv;
}


int st_writev_resid(_st_netfd_t *fd, struct iovec **iov, int *iov_size,
                    st_utime_t timeout)
{
  ssize_t n;

  while (*iov_size > 0) {
    if ((n = _ST_SYS_CALL(writev)(fd->osfd, *iov, *iov_size)) < 0) {
      _IO_GET_ERRNO();
      if (errno == EINTR)
        continue;
      if (!_IO_NOT_READY_ERROR)
        return -1;
    } else {
      while ((size_t) n >= (*iov)->iov_len) {
        n -= (*iov)->iov_len;
        (*iov)->iov_base = (char *) (*iov)->iov_base + (*iov)->iov_len;
        (*iov)->iov_len = 0;
        (*iov)++;
        (*iov_size)--;
        if (n == 0)
          break;
      }
      if (*iov_size == 0)
        break;
      (*iov)->iov_base = (char *) (*iov)->iov_base + n;
      (*iov)->iov_len -= n;
    }
    /* Wait until the socket becomes writable */
    if (st_netfd_poll(fd, POLLOUT, timeout) < 0)
      return -1;
  }

  return 0;
}


/*
 * Simple I/O functions for UDP.
 */
int st_recv(_st_netfd_t *fd, void *buf, int len, int flags, st_utime_t timeout)
{
  int n;

  while ((n = _ST_SYS_CALL(recv)(fd->osfd, buf, len, flags)) < 0) {
    _IO_GET_ERRNO();
    if (errno == EINTR)
      continue;
    if (!_IO_NOT_READY_ERROR)
      return -1;
    /* Wait until the socket becomes readable */
    if (st_netfd_poll(fd, POLLIN, timeout) < 0)
      return -1;
  }

  return n;
}


int st_recvfrom(_st_netfd_t *fd, void *buf, int len, int flags, struct sockaddr *from,
                socklen_t *fromlen, st_utime_t timeout)
{
  int n;

  while ((n = _ST_SYS_CALL(recvfrom)(fd->osfd, buf, len, flags, from, fromlen)) < 0) {
    _IO_GET_ERRNO();
    if (errno == EINTR)
      continue;
    if (!_IO_NOT_READY_ERROR)
      return -1;
    /* Wait until the socket becomes readable */
    if (st_netfd_poll(fd, POLLIN, timeout) < 0)
      return -1;
  }

  return n;
}


int st_sendto(_st_netfd_t *fd, const void *msg, int len, int flags,
              const struct sockaddr *to, int tolen, st_utime_t timeout)
{
  int n;

  while ((n = _ST_SYS_CALL(sendto)(fd->osfd, msg, len, flags, to, tolen)) < 0) {
    _IO_GET_ERRNO();
    if (errno == EINTR)
      continue;
    if (!_IO_NOT_READY_ERROR)
      return -1;
    /* Wait until the socket becomes writable */
    if (st_netfd_poll(fd, POLLOUT, timeout) < 0)
      return -1;
  }

  return n;
}


int st_recvmsg(_st_netfd_t *fd, struct msghdr *msg, int flags,
               st_utime_t timeout)
{
  int n;

  while ((n = _ST_SYS_CALL(recvmsg)(fd->osfd, msg, flags)) < 0) {
    _IO_GET_ERRNO();
    if (errno == EINTR)
      continue;
    if (!_IO_NOT_READY_ERROR)
      return -1;
    /* Wait until the socket becomes readable */
    if (st_netfd_poll(fd, POLLIN, timeout) < 0)
      return -1;
  }

  return n;
}

int st_send(_st_netfd_t *fd, const void *buf, size_t len, int flags,
           st_utime_t timeout)
{
  int n;

  while ((n = _ST_SYS_CALL(send)(fd->osfd, buf, len, flags)) < 0) {
    _IO_GET_ERRNO();
    if (errno == EINTR)
      continue;
    if (!_IO_NOT_READY_ERROR)
      return -1;
    /* Wait until the socket becomes writable */
    if (st_netfd_poll(fd, POLLOUT, timeout) < 0)
      return -1;
  }

  return n;
}

int st_sendmsg(_st_netfd_t *fd, const struct msghdr *msg, int flags,
               st_utime_t timeout)
{
  int n;

  while ((n = _ST_SYS_CALL(sendmsg)(fd->osfd, msg, flags)) < 0) {
    _IO_GET_ERRNO();
    if (errno == EINTR)
      continue;
    if (!_IO_NOT_READY_ERROR)
      return -1;
    /* Wait until the socket becomes writable */
    if (st_netfd_poll(fd, POLLOUT, timeout) < 0)
      return -1;
  }

  return n;
}

st_netfd_t st_socket(int domain, int type, int protocol)
{
  int osfd, err;
  _st_netfd_t *newfd;

  while ((osfd = _ST_SYS_CALL(socket)(domain, type, protocol)) < 0) {
    if (errno != EINTR)
      return NULL;
  }

  newfd = _st_netfd_new(osfd, 1, 1);
  if (!newfd) {
    err = errno;
    _ST_SYS_CALL(closesocket)(osfd);
    errno = err;
  }
  return newfd;
}

/*
 * To open FIFOs or other special files.
 */
_st_netfd_t *st_open(const char *path, int oflags, mode_t mode)
{
  int osfd, err;
  _st_netfd_t *newfd;

#ifndef _WIN32
  oflags |= O_NONBLOCK;
#endif
  while ((osfd = open(path, oflags, mode)) < 0) {
    if (errno != EINTR)
      return NULL;
  }

  newfd = _st_netfd_new(osfd, 0, 0);
  if (!newfd) {
    err = errno;
    _ST_SYS_CALL(closesocket)(osfd);
    errno = err;
  }

  return newfd;
}

st_netfd_t st_bind(int domain, int protocol, int port, int backlog)
{
  int n = 1;
  SOCKET fd;
  socklen_t len;
  struct sockaddr_storage sa;
  if (protocol == IPPROTO_UDP)
    fd = socket(domain, SOCK_DGRAM, IPPROTO_UDP);
  else if (protocol == IPPROTO_TCP)
    fd = socket(domain, SOCK_STREAM, IPPROTO_TCP);
  else
    return NULL;

  if (fd == INVALID_SOCKET) return NULL;

  if (domain == AF_INET) {
    struct sockaddr_in* ipv4 = (struct sockaddr_in*)&sa;
    ipv4->sin_family = AF_INET;
    ipv4->sin_port = htons (port);
    ipv4->sin_addr.s_addr = htonl (INADDR_ANY);
    len = sizeof(*ipv4);
  }
  else if (domain == AF_INET6) {
    struct sockaddr_in6* ipv6 = (struct sockaddr_in6*)&sa;
    ipv6->sin6_family = AF_INET6;
    ipv6->sin6_port = htons (port);
    ipv6->sin6_addr = in6addr_any;
    len = sizeof(*ipv6);
  }
  else return NULL;

  if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (char*)&n, sizeof(n)) < 0)
    goto clean;

  if (bind(fd, (struct sockaddr*)&sa, len) < 0)
    goto clean;
  if (protocol == IPPROTO_TCP && listen(fd, backlog) < 0)
    goto clean;
  return st_netfd_open_socket(fd);
clean:
  _ST_SYS_CALL(closesocket)(fd);
  return NULL;
}
static void ip_trim_left(char **pstr)
{
  char ch;
  while ((ch = **pstr) != '\0')
  {
    if (ch != ' ' && ch != '\t' && ch !=  '\r' && ch != '\n')
      break;
    (*pstr) ++;
  }
}
static void ip_get_token(const char **pstr,char *dst,int dstLen,char *sep)
{
  char ch;
  while (dstLen > 1 && (ch = **pstr) != '\0')
  {
    (*pstr) ++;
    if (ch == ':' || ch == '.' || ch == '/' || ch == '%' || ch == ']')
    {
      *sep = ch;
      *dst = 0;
      return;
    }
    *dst = ch;
    dst ++;dstLen --;
  }
  *sep = 0;
  *dst = 0;
}
static int ip_get_ip4(char *token,unsigned char *dst)
{
  int lval;char *end;

  ip_trim_left(&token);
  if (token[0] == 0)
    return -1;

  lval = (int)strtol(token,&end,0);
  if (lval < 0 || lval > 255)
    return -1;

  ip_trim_left(&end);
  if (end[0] != 0) return -1;

  dst[0] = (unsigned char)lval;
  return 0;
}
static int ipv4_decode(const char *host,unsigned char *addr,int* port)
{
  char buf[16],sep;
  int i;

  for (i=0;i<4;i++)
  {
    ip_get_token(&host,buf,16,&sep);
    if (i == 3)
    {
      if (sep == ':')
      {
        char *end;
        int p = (int)strtol(host,&end,0);
        if (end[0] != 0 && end[0]!= '/') return -1;
        if (port) *port = p;
      }
      else if (sep != '\0')
        return -1;
    }
    else if (sep != '.')
      return -1;
    if (ip_get_ip4(buf,addr) < 0)
      return -1;
    addr ++;
  }
  return 0;
}
static int ip_get_ip6(char *token,unsigned char *dst)
{
  int lval;char *end;

  ip_trim_left(&token);
  if (token[0] == 0)
    return 1;

  lval = (int)strtol(token,&end,16);
  if (lval < 0 || lval > 65535)
    return -1;

  ip_trim_left(&end);
  if (end[0] != 0) return -1;

  dst[0] = (unsigned char)(lval>>8);
  dst[1] = (unsigned char)(lval>>0);
  return 0;
}
static int ipv6_decode(const char *host,unsigned char *addr, int* port)
{
  char buf[16],sep;
  unsigned char *paddr = addr;
  unsigned char *pzero = 0;
  int i,ret;
  char endch = '\0';
  if (*host == '['){
    ++host;
    endch = ']';
  }

  for (i=0;i<8;i++)
  {
    ip_get_token(&host,buf,16,&sep);
    if (sep == '.')
    {
      if (paddr > addr+12)
        return -1;
      if (ip_get_ip4(buf,paddr) < 0)
        return -1;
      paddr ++;

      for (i=0;i<3;i++)
      {
        ip_get_token(&host,buf,16,&sep);
        if (sep != ((i==2)?endch:'.'))
          return -1;
        if (ip_get_ip4(buf,paddr) < 0)
          return -1;
        paddr ++;
      }
      break;
    }

    ret = ip_get_ip6(buf,paddr);
    if (ret < 0) return -1;

    if (ret == 0)
    {
      if (pzero && i == 1)
        return -1;
      paddr += 2;
      if (sep == 0 || sep == '/' || sep == '%' || sep == endch)
        break;
      if (paddr >= addr+16)
        return -1;
      continue;
    }

    if (sep == 0 || sep == '/' || sep == '%' || sep == endch)
      break;
    if (pzero != 0 && i > 1)
      return -1;
    pzero = paddr;
  }

  if (sep != 0 && sep != endch)
  {
    int lval;char *end;
    ip_get_token(&host,buf,16,&sep);
    if (sep != endch || buf[0] == 0)
      return -1;

    lval = (int)strtol(buf,&end,16);
    if (lval < 0 || lval > 128)
      return -1;
  }

  if (!pzero)
  {
    if (paddr != addr+16)
      return -1;
  }
  else
  {
    addr += 16;
    if (addr != paddr)
    {
      while (paddr != pzero)
      {
        addr[-1] = paddr[-1];
        addr[-2] = paddr[-2];
        addr -= 2;paddr -= 2;
      }
      while (addr != pzero)
      {
        addr[-1] = 0;
        addr[-2] = 0;
        addr -= 2;
      }
    }
  }
  if (sep == ']')
  {
    if (*host == ':')
    {
      char *end;
      int p = (int)strtol(host+1,&end,0);
      if (end[0] != 0 && end[0] != '/') return -1;
      if (port) *port = p;
    }
    else if (*host != 0)
      return -1;
  }
  return 0;
}
static int guess_domain(const char* p)
{
  int n = 0, c = 0;
  for (; *p; ++p) {
    switch(*p) {
    case ']': case '[':
      return AF_INET6;
    case ':':
      ++c; break;
    case '.':
      n++; break;
    case '_':
      return AF_UNSPEC;
    default:
      if (!isspace(*p) && !isxdigit(*p))
        return AF_UNSPEC;
    }
  }
  if (c > 1) return AF_INET6;
  if (n == 3) return AF_INET;
  return -1;
}
int st_sockaddr(void *sa, int domain, const char* addr, int port)
{
  struct sockaddr_in6* ipv6 = sa;
  struct sockaddr_in* ipv4 = sa;
  int guess = domain;
  if (addr && addr[0]) {
    const char* p = strstr(addr, "://");
    if (p) addr = p + 3;
    while (isspace(*addr)) ++addr;
    guess = guess_domain(addr);
  }
  if (guess < 0) return -1;
  if (guess == AF_INET6) {
    if (domain == AF_INET)
      return -1;
    else if (!addr)
      ipv6->sin6_addr = in6addr_any;
    else if (!addr[0])
      ipv6->sin6_addr = in6addr_loopback;
    else if (ipv6_decode(addr,(unsigned char *)&ipv6->sin6_addr.s6_addr, &port) < 0)
      return -1;
    ipv6->sin6_family = AF_INET6;
    ipv6->sin6_port = htons (port);
    return sizeof(*ipv6);
  }
  if (guess == AF_INET) {
    if (domain == AF_INET6)
      return -1;
    else if (!addr)
      ipv4->sin_addr.s_addr = htonl (INADDR_ANY);
    else if (!addr[0])
      ipv4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    else if (ipv4_decode(addr,(unsigned char *)&ipv4->sin_addr.s_addr, &port) < 0)
      return -1;
    ipv4->sin_family = AF_INET;
    ipv4->sin_port = htons (port);
    return sizeof(*ipv4);
  }
  if (guess == AF_UNSPEC && addr && addr[0]) {
    int slen;
    char name[256];
    const char* p = strrchr(addr,':');
    struct addrinfo hints = {0};
    if (p) {
      port = atoi(p+1);
      if ((slen = p-addr) >= sizeof(name)) return -1;
      memcpy(name, addr, slen);
      name[slen] = '\0';
      addr = name;
    }
    hints.ai_family = domain;
    hints.ai_canonname = (char*)addr;
    if (st_getaddrinfo(&hints, NULL, ST_UTIME_NO_TIMEOUT) <= 0)
      return -1;
    slen = hints.ai_next->ai_addrlen;
    memcpy(sa, hints.ai_next->ai_addr, slen);
    if (hints.ai_next->ai_family == AF_INET6)
      ipv6->sin6_port = htons (port);
    else if (hints.ai_next->ai_family == AF_INET)
      ipv4->sin_port = htons(port);
    st_freeaddrinfo(&hints);
    return slen;
  }
  return -1;
}
const char* st_inetaddr(const void *addr, int addrlen, int *domain, int *port)
{
  const struct sockaddr *sa = addr;
  if (sa->sa_family == AF_INET) {
    const struct sockaddr_in* ipv4 = addr;
    if (domain) *domain = ipv4->sin_family;
    if (port) *port = ntohs(ipv4->sin_port);
    return inet_ntoa(ipv4->sin_addr);
  }
  else if (sa->sa_family  == AF_INET6) {
    static char str[INET6_ADDRSTRLEN];
    const struct sockaddr_in6* ipv6 = addr;
    if (domain) *domain = ipv6->sin6_family;
    if (port) *port = ntohs(ipv6->sin6_port);
    return inet_ntop(ipv6->sin6_family, (void*)&ipv6->sin6_addr, str, INET6_ADDRSTRLEN);
  }
  return NULL;
}

