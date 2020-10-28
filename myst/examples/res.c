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
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
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

static int parse_answer(querybuf_t *ans, int len, struct addrinfo *res, st_utime_t* timeout)
{
  char buf[MAXPACKET];
  HEADER *ahp;
  u_char *cp, *eoa;
  int type, n, count=0;
  st_utime_t ttl = ST_UTIME_NO_TIMEOUT;

  while (res->ai_next) {
    res = res->ai_next;
    count++;
  }
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
    if (cp + 4 + 4 + 2 >= eoa)
      return -1;

    type = _getshort(cp);
    cp += 4;
    if (type == T_A || type == T_AAAA)
      ttl = _getlong(cp) * 1000000LL;
	cp += 4;
	n = _getshort(cp);
	cp += 2;

    if (cp + n > eoa) return -1;
    else if (type == T_A && n != sizeof(struct in_addr)) return -1;
    else if (type == T_AAAA && n != sizeof(struct in6_addr)) return -1;

    if (type == T_A || type == T_AAAA) {
      res->ai_next = ( struct addrinfo*)calloc(1, sizeof(struct addrinfo));
      if (!res->ai_next) return -1;
      res = res->ai_next;
      count++;
      if (type == T_A) {
        struct sockaddr_in* ipv4 = calloc(1, sizeof(struct sockaddr_in));
        if (!ipv4) return -1;
        ipv4->sin_family = AF_INET;
        memcpy(&ipv4->sin_addr, cp, n);
        res->ai_addr = (struct sockaddr*)ipv4;
      }
      else {
        struct sockaddr_in6* ipv6 = calloc(1, sizeof(struct sockaddr_in6));
        if (!ipv6) return -1;
        ipv6->sin6_family = AF_INET6;
        memcpy(&ipv6->sin6_addr, cp, n);
        res->ai_addr = (struct sockaddr*)ipv6;
      }
    }
    else if (type == T_CNAME) {
      ;//printf("-.*%s\n", n, cp);
    }
    cp += n;
  }
  if (count > 0) *timeout = ttl;
  return count;
}


static int fetch_domain(st_netfd_t nfd[2], const char *name,
  struct addrinfo *hints, st_utime_t *timeout, struct sockaddr* server)
{
  querybuf_t qbuf;
  u_char *buf = qbuf.buf;
  HEADER *hp = &qbuf.hdr;
  int blen = sizeof(qbuf);
  int i, len, id, f, pf, slen;
  int family = hints->ai_family;
  switch(server->sa_family) {
  case AF_INET:
    f = 0, pf=PF_INET, slen = sizeof(struct sockaddr_in); break;
  case AF_INET6:
    f = 1, pf=PF_INET6, slen = sizeof(struct sockaddr_in6); break;
  default:
    return -1;
  }

  if (!nfd[f] && (nfd[f] = st_socket(pf, SOCK_DGRAM, 0)) == NULL) { /* Create UDP socket */
    h_errno = NETDB_INTERNAL;
    return -1;
  }
  if (family == AF_UNSPEC) family = server->sa_family;
  len = res_mkquery(QUERY, name, C_IN, family == AF_INET6 ? T_AAAA : T_A, NULL, 0, NULL, buf, blen);
  if (len <= 0) {
    h_errno = NO_RECOVERY;
    return -1;
  }
  id = hp->id;

  if (st_sendto(nfd[f], buf, len, 0, server, slen, *timeout) != len) {
    h_errno = NETDB_INTERNAL;
    /* EINTR means interrupt by other thread, NOT by a caught signal */
    if (errno == EINTR)
      return -1;
    return 0;
  }

  /* Wait for reply */
  do {
    len = st_recvfrom(nfd[f], buf, blen, 0, NULL, NULL, *timeout);
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
  return parse_answer(&qbuf, len, hints, timeout);
}

static int query_domain(st_netfd_t nfd[2], const char *name,
  struct addrinfo *hints, st_utime_t *timeout)
{
  int i, nscount = 0;
  struct sockaddr *nsaddr_list[256];
  if (hints->ai_addr) nsaddr_list[nscount++] = hints->ai_addr;
#ifdef __BIONIC__
  i = res_nsaddr_list(nsaddr_list + nscount);
  if (i > 0) nscount += i;
#else
  for(i=0; i< _res.nscount; ++i)
    nsaddr_list[nscount++] = (struct sockaddr *)&_res.nsaddr_list[i];
#endif
  for (i = 0; i < nscount; i++) {
    int ret = fetch_domain(nfd, name, hints, timeout, nsaddr_list[i]);
    if (ret != 0) return ret;
  }
  return -1;
}


#define CLOSE_AND_RETURN(ret) \
  {                           \
    n = errno;                \
    if(nfd[0])st_netfd_close(nfd[0]);   \
    if(nfd[1])st_netfd_close(nfd[1]);   \
    errno = n;                \
    return (ret);             \
  }


static int dns_init(void)
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

static int dns_getaddr(const char *host, struct addrinfo *hints, st_utime_t *timeout)
{
  char name[MAXDNAME], **domain;
  const char *cp;
  int n, maxlen, dots, ret;
  int trailing_dot, tried_as_is;
  st_netfd_t nfd[2] = {NULL, NULL};

  if (!host || *host == '\0') {
    h_errno = HOST_NOT_FOUND;
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
    if ((ret=query_domain(nfd, host, hints, timeout)) >= 0)
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
      if ((ret=query_domain(nfd, name, hints, timeout)) >= 0)
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
    if ((ret=query_domain(nfd, host, hints, timeout)) >= 0)
      CLOSE_AND_RETURN(ret);
  }

  CLOSE_AND_RETURN(-1);
}

void st_freeaddrinfo(struct addrinfo *res)
{
  if (!res) return;
  else if (res->ai_next)
    st_freeaddrinfo(res->ai_next);
  else {
    if (res->ai_addr) free(res->ai_addr);
    free(res);
  }
}

/* timeout for udp send/recv, after return ttl us */
int st_getaddrinfo(const char *node, const char *service,
    const struct addrinfo *hints, struct addrinfo **res, st_utime_t *timeout)
{
  int ret = dns_init();
  struct addrinfo addrs = {0};
  if (ret < 0) return ret;
  addrs.ai_family = AF_UNSPEC;
  if (hints) addrs = *hints;
  addrs.ai_next = NULL;
  ret = dns_getaddr(node, &addrs, timeout);
  if (ret < 0)
    st_freeaddrinfo(addrs.ai_next);
  else
    *res = addrs.ai_next;
  return ret;
}
