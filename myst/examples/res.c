/*
 * Copyright (c) 1985, 1988, 1993
 *    The Regents of the University of California.  All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Portions created by SGI are Copyright (C) 2000 Silicon Graphics, Inc.
 * All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met: 
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Silicon Graphics, Inc. nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission. 
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDERS AND CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#if __APPLE__ && __MACH__
#define BIND_8_COMPAT
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>
#include <errno.h>
#include <st.h>
#ifdef __BIONIC__
#include <sys/system_properties.h>
static int res_nsaddr_list(struct sockaddr* addr[])
{
  char buf[96];
  int i, nscount = 0;
  const int port = 53;
  const char* keys[] = {"net.dns1", "net.rmnet0.dns1", "net.dns2", NULL};
  static struct sockaddr_storage sa[3];

  for (i=0; keys[i]; ++i) {
    buf[0] = '\0';
    __system_property_get(keys[i], buf);
    printf("%s=%s\n", keys[i], buf);
    if (!buf[0]) continue;
    sa[nscount].ss_family = AF_INET;
    addr[nscount] = (struct sockaddr*)&sa[nscount];
    if (st_sockaddr(addr[nscount], AF_INET, buf, port) <= 0)
      return -1;
    nscount++;
  }
  return nscount;
}
#endif
#define MAXPACKET 1024

#if !defined(NETDB_INTERNAL) && defined(h_NETDB_INTERNAL)
#define NETDB_INTERNAL h_NETDB_INTERNAL
#endif

/* New in Solaris 7 */
#if !defined(_getshort) && defined(ns_get16)
#define _getshort(cp) ns_get16(cp)
#endif

typedef union {
    HEADER hdr;
    u_char buf[MAXPACKET];
} querybuf_t;

static int dns_skipname(u_char *cp, u_char* eoa)
{
  u_char* p = cp;
  while (p < eoa) {
    int dotLen = *p;
    if ((dotLen & 0xc0) == 0xc0) {
      printf("skip_name not linear!\n");
    }
    if (dotLen < 0 || p + dotLen + 1 >= eoa) return -1;
    if (dotLen == 0) return (int)(p - cp + 1);
    p += dotLen + 1;
  }
  return -1;
}

static int parse_answer(querybuf_t *ans, int len, struct in_addr *addrs)
{
  char buf[MAXPACKET];
  HEADER *ahp;
  u_char *cp, *eoa;
  int type, n, count=0;

  ahp = &ans->hdr;
  eoa = ans->buf + len;
  cp = ans->buf + sizeof(HEADER);
  h_errno = TRY_AGAIN;

  while (ahp->qdcount > 0) {
    ahp->qdcount--;
    n = dns_skipname(cp, eoa);
    if (n < 0) return -1;
    cp += n + QFIXEDSZ;
  }
  while (ahp->ancount > 0 && cp < eoa) {
    ahp->ancount--;
    if ((n = dn_expand(ans->buf, eoa, cp, buf, sizeof(buf))) < 0)
      break;
    cp += n;
    type = _getshort(cp);
    cp += 8;
    n = _getshort(cp);
    cp += 2;
    if (type == T_A){
      if (n > sizeof(*addrs) || cp + n > eoa)
        return -1;
      memcpy(addrs+count, cp, n);
      count++;
    }
    cp += n;
  }

  return count;
}


static int fetch_domain(st_netfd_t nfd, const char *name,
    struct in_addr *addrs, st_utime_t timeout, struct sockaddr* server)
{
  querybuf_t qbuf;
  u_char *buf = qbuf.buf;
  HEADER *hp = &qbuf.hdr;
  int blen = sizeof(qbuf);
  int i, len, id;
  len = res_mkquery(QUERY, name, C_IN, T_A, NULL, 0, NULL, buf, blen);
  if (len <= 0) {
    h_errno = NO_RECOVERY;
    return -1;
  }
  id = hp->id;

  if (st_sendto(nfd, buf, len, 0, server,
	sizeof(struct sockaddr), timeout) != len) {
    h_errno = NETDB_INTERNAL;
    /* EINTR means interrupt by other thread, NOT by a caught signal */
    if (errno == EINTR)
      return -1;
    return 0;
  }

  /* Wait for reply */
  do {
    len = st_recvfrom(nfd, buf, blen, 0, NULL, NULL, timeout);
    if (len <= 0)
      break;
  } while (id != hp->id);

  if (len < HFIXEDSZ) {
    h_errno = NETDB_INTERNAL;
    if (len >= 0)
      errno = EMSGSIZE;
    else if (errno == EINTR)  /* see the comment above */
      return -1;
    return 0;
  }

  hp->ancount = ntohs(hp->ancount);
  hp->qdcount = ntohs(hp->qdcount);
  if ((hp->rcode != NOERROR) || (hp->ancount == 0)) {
    switch (hp->rcode) {
      case NXDOMAIN:
	h_errno = HOST_NOT_FOUND;
	break;
      case SERVFAIL:
	h_errno = TRY_AGAIN;
	break;
      case NOERROR:
	h_errno = NO_DATA;
	break;
      case FORMERR:
      case NOTIMP:
      case REFUSED:
      default:
	h_errno = NO_RECOVERY;
    }
    return 0;
  }
  return parse_answer(&qbuf, len, addrs);
}

static int query_domain(st_netfd_t nfd, const char *name, struct sockaddr *dns_server,
    struct in_addr *addrs, st_utime_t timeout)
{
  int i, nscount = 0;
  struct sockaddr *nsaddr_list[256];
  if (dns_server) nsaddr_list[nscount++] = dns_server;
#ifdef __BIONIC__
  i = res_nsaddr_list(nsaddr_list + nscount);
  if (i > 0) nscount += i;
#else
  for(i=0; i< _res.nscount; ++i)
    nsaddr_list[nscount++] = (struct sockaddr *)&_res.nsaddr_list[i];
#endif
  for (i = 0; i < nscount; i++) {
    int ret = fetch_domain(nfd,  name, addrs, timeout, nsaddr_list[i]);
    if (ret != 0) return ret;
  }
  return -1;
}


#define CLOSE_AND_RETURN(ret) \
  {                           \
    n = errno;                \
    st_netfd_close(nfd);      \
    errno = n;                \
    return (ret);             \
  }


int dns_init(void)
{
#ifdef __BIONIC__
  if(res_init() == -1) {
    h_errno = NETDB_INTERNAL;
    return -1;
  }
#else
  if ((_res.options & RES_INIT) == 0 && res_init() == -1) {
    h_errno = NETDB_INTERNAL;
    return -1;
  }
  if (_res.options & RES_USEVC) {
    h_errno = NETDB_INTERNAL;
    errno = ENOSYS;
    return -1;
  }
#endif
  return 0;
}

int dns_getaddr(const char *host, struct in_addr *addrs, st_utime_t timeout, struct sockaddr* dns)
{
  char name[MAXDNAME], **domain;
  const char *cp;
  int n, maxlen, dots, ret;
  int trailing_dot, tried_as_is;
  st_netfd_t nfd;

  if (!host || *host == '\0') {
    h_errno = HOST_NOT_FOUND;
    return -1;
  }

  /* Create UDP socket */
  if ((nfd = st_socket(PF_INET, SOCK_DGRAM, 0)) == NULL) {
    h_errno = NETDB_INTERNAL;
    return -1;
  }

  maxlen = sizeof(name) - 1;
  n = 0;
  dots = 0;
  trailing_dot = 0;
  tried_as_is = 0;

  for (cp = host; *cp && n < maxlen; cp++) {
    dots += (*cp == '.');
    name[n++] = *cp;
  }
  if (name[n - 1] == '.')
    trailing_dot = 1;

#ifndef __BIONIC__
  /*
   * If there are dots in the name already, let's just give it a try
   * 'as is'.  The threshold can be set with the "ndots" option.
   */
  if (dots >= _res.ndots) {
    if ((ret=query_domain(nfd, host, dns, addrs, timeout)) >= 0)
      CLOSE_AND_RETURN(ret);
    if (h_errno == NETDB_INTERNAL && errno == EINTR)
      CLOSE_AND_RETURN(-1);
    tried_as_is = 1;
  }

  /*
   * We do at least one level of search if
   *     - there is no dot and RES_DEFNAME is set, or
   *     - there is at least one dot, there is no trailing dot,
   *       and RES_DNSRCH is set.
   */
  if ((!dots && (_res.options & RES_DEFNAMES)) ||
      (dots && !trailing_dot && (_res.options & RES_DNSRCH))) {
    name[n++] = '.';
    for (domain = _res.dnsrch; *domain; domain++) {
      strncpy(name + n, *domain, maxlen - n);
      if ((ret=query_domain(nfd, name, dns, addrs, timeout)) >= 0)
        CLOSE_AND_RETURN(ret);
      if (h_errno == NETDB_INTERNAL && errno == EINTR)
        CLOSE_AND_RETURN(-1);
      if (!(_res.options & RES_DNSRCH))
        break;
    }
  }
#endif
  /*
   * If we have not already tried the name "as is", do that now.
   * note that we do this regardless of how many dots were in the
   * name or whether it ends with a dot.
   */
  if (!tried_as_is) {
    if ((ret=query_domain(nfd, host, dns, addrs, timeout)) >= 0)
      CLOSE_AND_RETURN(ret);
  }

  CLOSE_AND_RETURN(-1);
}

