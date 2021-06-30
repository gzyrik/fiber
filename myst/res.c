#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "common.h"
//#define _USE_RESOLV_TEST_ 1
#ifdef _USE_RESOLV_TEST_
#if __APPLE__ && __MACH__
#define BIND_8_COMPAT
#endif
#include <arpa/nameser.h>
#include <resolv.h>
typedef union {
  HEADER hdr;
  unsigned char buf[MAXPACKET];
} querybuf_t;
#else
#ifdef _WIN32
extern int get_DNS_Windows(char **outptr);
#endif
#ifdef __BIONIC__
#include <sys/system_properties.h>
#define MAX_DNS_PROPERTIES 8
#endif
#define C_IN         1
#define MAXCDNAME    255
#define MAXLABEL     63
#define HFIXEDSZ     12    /* #/bytes of fixed data in header */
#define QFIXEDSZ     4     /* #/bytes of fixed data in query */
#define INDIR_MASK  0xc0   /* Flag bits indicating name compression. */
#define T_A          1
#define T_CNAME      5
#define T_AAAA       28
#endif
#define MAXPACKET 1500
/*
 * Macro DNS__16BIT reads a network short (16 bit) given in network
 * byte order, and returns its value as an unsigned short.
 */
#define DNS__16BIT(p)  ((unsigned short)((unsigned int) 0xffff & \
    (((unsigned int)((unsigned char)(p)[0]) << 8U) | \
     ((unsigned int)((unsigned char)(p)[1])))))

/*
 * Macro DNS__32BIT reads a network long (32 bit) given in network
 * byte order, and returns its value as an unsigned int.
 */
#define DNS__32BIT(p)  ((unsigned int) \
  (((unsigned int)((unsigned char)(p)[0]) << 24U) | \
   ((unsigned int)((unsigned char)(p)[1]) << 16U) | \
   ((unsigned int)((unsigned char)(p)[2]) <<  8U) | \
   ((unsigned int)((unsigned char)(p)[3]))))

#define DNS__SET16BIT(p, v)  (((p)[0] = (unsigned char)(((v) >> 8) & 0xff)), \
  ((p)[1] = (unsigned char)((v) & 0xff)))
#define DNS__SET32BIT(p, v)  (((p)[0] = (unsigned char)(((v) >> 24) & 0xff)), \
  ((p)[1] = (unsigned char)(((v) >> 16) & 0xff)), \
  ((p)[2] = (unsigned char)(((v) >> 8) & 0xff)), \
  ((p)[3] = (unsigned char)((v) & 0xff)))

#define DNS_HEADER_QID(h)               DNS__16BIT(h)
#define DNS_HEADER_QDCOUNT(h)           DNS__16BIT((h) + 4)
#define DNS_HEADER_ANCOUNT(h)           DNS__16BIT((h) + 6)
#define DNS_HEADER_NSCOUNT(h)           DNS__16BIT((h) + 8)
#define DNS_HEADER_ARCOUNT(h)           DNS__16BIT((h) + 10)

#define DNS_HEADER_SET_QID(h, v)        DNS__SET16BIT(h, v)
#define DNS_HEADER_SET_OPCODE(h, v)     ((h)[2] |= (unsigned char)(((v) & 0xf) << 3))
#define DNS_HEADER_SET_RD(h, v)         ((h)[2] |= (unsigned char)((v) & 0x1))
#define DNS_HEADER_SET_QDCOUNT(h, v)    DNS__SET16BIT((h) + 4, v)
#define DNS_HEADER_SET_ANCOUNT(h, v)    DNS__SET16BIT((h) + 6, v)
#define DNS_HEADER_SET_NSCOUNT(h, v)    DNS__SET16BIT((h) + 8, v)
#define DNS_HEADER_SET_ARCOUNT(h, v)    DNS__SET16BIT((h) + 10, v)

/* Macros for constructing the fixed part of a DNS question */
#define DNS_QUESTION_SET_TYPE(q, v)     DNS__SET16BIT(q, v)
#define DNS_QUESTION_SET_CLASS(q, v)    DNS__SET16BIT((q) + 2, v)
/* Macros for constructing the fixed part of a DNS resource record */
#define DNS_RR_SET_TYPE(r, v)           DNS__SET16BIT(r, v)
#define DNS_RR_SET_CLASS(r, v)          DNS__SET16BIT((r) + 2, v)
#define DNS_RR_SET_TTL(r, v)            DNS__SET32BIT((r) + 4, v)
#define DNS_RR_SET_LEN(r, v)            DNS__SET16BIT((r) + 8, v)

#ifndef T_OPT
#  define T_OPT  41 /* EDNS0 option (meta-RR) */
#endif
#define EDNSFIXEDSZ    11    /* Size of EDNS header */

/* Header format, from RFC 1035:
 *                                  1  1  1  1  1  1
 *    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                      ID                       |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    QDCOUNT                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    ANCOUNT                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    NSCOUNT                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                    ARCOUNT                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * AA, TC, RA, and RCODE are only set in responses.  Brief description
 * of the remaining fields:
 *      ID      Identifier to match responses with queries
 *      QR      Query (0) or response (1)
 *      Opcode  For our purposes, always QUERY
 *      RD      Recursion desired
 *      Z       Reserved (zero)
 *      QDCOUNT Number of queries
 *      ANCOUNT Number of answers
 *      NSCOUNT Number of name server records
 *      ARCOUNT Number of additional records
 *
 * Question format, from RFC 1035:
 *                                  1  1  1  1  1  1
 *    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                                               |
 *  /                     QNAME                     /
 *  /                                               /
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                     QTYPE                     |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *  |                     QCLASS                    |
 *  +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 *
 * The query name is encoded as a series of labels, each represented
 * as a one-byte length (maximum 63) followed by the text of the
 * label.  The list is terminated by a label of length zero (which can
 * be thought of as the root domain).
 */
static int mkquery(const char *name, int dnsclass, int type,
  unsigned short id, int rd, unsigned char *buf,
  size_t buflen, int max_udp_size)
{
  size_t len;
  unsigned char *q;
  const char *p;

  /* Set up the header. */
  q = buf;
  memset(q, 0, HFIXEDSZ);
  DNS_HEADER_SET_QID(q, id);
  DNS_HEADER_SET_OPCODE(q, 0);
  if (rd) {
    DNS_HEADER_SET_RD(q, 1);
  }
  else {
    DNS_HEADER_SET_RD(q, 0);
  }
  DNS_HEADER_SET_QDCOUNT(q, 1);

  if (max_udp_size) {
    DNS_HEADER_SET_ARCOUNT(q, 1);
  }

  /* A name of "." is a screw case for the loop below, so adjust it. */
  if (strcmp(name, ".") == 0)
    name++;

  /* Start writing out the name after the header. */
  q += HFIXEDSZ;
  while (*name)
  {
    if (*name == '.') {
      return -1;
    }

    /* Count the number of bytes in this label. */
    len = 0;
    for (p = name; *p && *p != '.'; p++)
    {
      if (*p == '\\' && *(p + 1) != 0)
        p++;
      len++;
    }
    if (len > MAXLABEL) {
      return -1;
    }

    /* Encode the length and copy the data. */
    *q++ = (unsigned char)len;
    for (p = name; *p && *p != '.'; p++)
    {
      if (*p == '\\' && *(p + 1) != 0)
        p++;
      *q++ = *p;
    }

    /* Go to the next label and repeat, unless we hit the end. */
    if (!*p)
      break;
    name = p + 1;
  }

  /* Add the zero-length label at the end. */
  *q++ = 0;

  /* Finish off the question with the type and class. */
  DNS_QUESTION_SET_TYPE(q, type);
  DNS_QUESTION_SET_CLASS(q, dnsclass);

  q += QFIXEDSZ;
  if (max_udp_size)
  {
    memset(q, 0, EDNSFIXEDSZ);
    q++;
    DNS_RR_SET_TYPE(q, T_OPT);
    DNS_RR_SET_CLASS(q, max_udp_size);
    q += (EDNSFIXEDSZ-1);
  }
  buflen = (q - buf);

  /* Reject names that are longer than the maximum of 255 bytes that's
   * specified in RFC 1035 ("To simplify implementations, the total length of
   * a domain name (i.e., label octets and label length octets) is restricted
   * to 255 octets or less."). */
  if (buflen > (size_t)(MAXCDNAME + HFIXEDSZ + QFIXEDSZ +
      (max_udp_size ? EDNSFIXEDSZ : 0))) {
    return -1;
  }

  return q - buf;
}

static int dns_skipname(unsigned char*cp, unsigned char* eoa)
{
  unsigned char* p = cp;
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
/* Maximum number of indirections allowed for a name */
#define MAX_INDIRS 50

/* Return the length of the expansion of an encoded domain name, or
 * -1 if the encoding is invalid.
 */
static int name_length(const unsigned char *encoded,
  const unsigned char *abuf, int alen)
{
  int n = 0, offset, indir = 0, top;

  /* Allow the caller to pass us abuf + alen and have us check for it. */
  if (encoded >= abuf + alen)
    return -1;

  while (*encoded)
  {
    top = (*encoded & INDIR_MASK);
    if (top == INDIR_MASK)
    {
      /* Check the offset and go there. */
      if (encoded + 1 >= abuf + alen)
        return -1;
      offset = (*encoded & ~INDIR_MASK) << 8 | *(encoded + 1);
      if (offset >= alen)
        return -1;
      encoded = abuf + offset;

      /* If we've seen more indirects than the message length,
       * then there's a loop.
       */
      ++indir;
      if (indir > alen || indir > MAX_INDIRS)
        return -1;
    }
    else if (top == 0x00)
    {
      offset = *encoded;
      if (encoded + offset + 1 >= abuf + alen)
        return -1;
      encoded++;
      while (offset--)
      {
        n += (*encoded == '.' || *encoded == '\\') ? 2 : 1;
        encoded++;
      }
      n++;
    }
    else
    {
      /* RFC 1035 4.1.4 says other options (01, 10) for top 2
       * bits are reserved.
       */
      return -1;
    }
  }

  /* If there were any labels at all, then the number of dots is one
   * less than the number of labels, so subtract one.
   */
  return (n) ? n - 1 : n;
}
static int dns_expand_name(const unsigned char *abuf, const unsigned char* eoa,
  const unsigned char *encoded, char *buf,size_t buflen)
{
  int len, enclen, indir = 0;
  char *q = buf;
  const unsigned char *p;
  union {
    ssize_t sig;
    size_t uns;
  } nlen;

  nlen.sig = name_length(encoded, abuf, eoa - abuf);
  if (nlen.sig < 0)
    return -1;
  if (buflen < nlen.uns + 1)
    return -1;

  if (nlen.uns == 0) {
    /* RFC2181 says this should be ".": the root of the DNS tree.
     * Since this function strips trailing dots though, it becomes ""
     */
    q[0] = '\0';

    /* indirect root label (like 0xc0 0x0c) is 2 bytes long (stupid, but
       valid) */
    if ((*encoded & INDIR_MASK) == INDIR_MASK)
      return 2L;
    else
      return  1L;  /* the caller should move one byte to get past this */
  }

  /* No error-checking necessary; it was all done by name_length(). */
  p = encoded;
  while (*p)
  {
    if ((*p & INDIR_MASK) == INDIR_MASK)
    {
      if (!indir)
      {
        enclen = p + 2U - encoded;
        indir = 1;
      }
      p = abuf + ((*p & ~INDIR_MASK) << 8 | *(p + 1));
    }
    else
    {
      len = *p;
      p++;
      while (len--)
      {
        if (*p == '.' || *p == '\\')
          *q++ = '\\';
        *q++ = *p;
        p++;
      }
      *q++ = '.';
    }
  }
  if (!indir)
    enclen = p + 1U - encoded;

  /* Nuke the trailing period if we wrote one. */
  if (q > buf)
    *(q - 1) = 0;
  else
    *q = 0; /* zero terminate; LCOV_EXCL_LINE: empty names exit above */

  return enclen;
}
static int sock_addr_cmp(const void * a, const void* b)
{
  const struct sockaddr *sa = a, *sb = b;
  if (sa->sa_family != sb->sa_family)
    return (sa->sa_family - sb->sa_family);

  /*
   * With IPv6 address structures, assume a non-hostile implementation that
   * stores the address as a contiguous sequence of bits. Any holes in the
   * sequence would invalidate the use of memcmp().
   */
  if (sa->sa_family == AF_INET) {
    const struct sockaddr_in *v4a = a, *v4b = b;
    return v4a->sin_addr.s_addr - v4b->sin_addr.s_addr;
  } else if (sa->sa_family == AF_INET6) {
    const struct sockaddr_in6  *v6a = a, *v6b = b;
    return memcmp(&(v6a->sin6_addr),  &(v6b->sin6_addr), sizeof(v6a->sin6_addr));
  } 
  return 1;
}
static socklen_t sock_addr_len(const void* p)
{
  const struct sockaddr* addr = (const struct sockaddr*)p;
  switch (addr->sa_family) {
  case AF_INET:
    return sizeof(struct sockaddr_in);
  case AF_INET6:
    return sizeof(struct sockaddr_in6);
  default:
    return 0;
  }
}

static int parse_answer(unsigned char*ans, int len, struct addrinfo *res, unsigned* ttl)
{
  int qdcount, ancount;
  unsigned char *cp, *eoa;
  int type, n, count=0;

  ancount = DNS_HEADER_ANCOUNT(ans);
  if (ancount <= 0) return 0;
  qdcount = DNS_HEADER_QDCOUNT(ans);

  while (res->ai_next) {
    res = res->ai_next;
    count++;
  }
  eoa = ans + len;
  cp = ans + HFIXEDSZ;

  while (qdcount > 0) {
    qdcount--;
    n = dns_skipname(cp, eoa);
    if (n < 0) return -1;
    cp += n + QFIXEDSZ;
  }
  while (ancount > 0 && cp < eoa) {
    char buf[MAXPACKET];
    ancount--;
    if ((n = dns_expand_name(ans, eoa, cp, buf, sizeof(buf))) < 0)
      break;
    cp += n;
    if (cp + 4 + 4 + 2 >= eoa)
      return -1;

    type = DNS__16BIT(cp);
    cp += 4;
    if (ttl && (type == T_A || type == T_AAAA))
      *ttl = DNS__32BIT(cp);
    cp += 4;
    n = DNS__16BIT(cp);
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
        res->ai_addrlen = sizeof(struct sockaddr_in);
        res->ai_addr = (struct sockaddr*)ipv4;
        res->ai_family = PF_INET;
      }
      else {
        struct sockaddr_in6* ipv6 = calloc(1, sizeof(struct sockaddr_in6));
        if (!ipv6) return -1;
        ipv6->sin6_family = AF_INET6;
        memcpy(&ipv6->sin6_addr, cp, n);
        res->ai_addrlen = sizeof(struct sockaddr_in6);
        res->ai_addr = (struct sockaddr*)ipv6;
        res->ai_family = PF_INET6;
      }
    }
    else if (type == T_CNAME) {
      printf("CNAME:%.*s\n", n, cp);
    }
    cp += n;
  }
  return count;
}

static int fetch_domain(const char *name, struct sockaddr* server,
  struct addrinfo *hints, unsigned *ttl, st_utime_t timeout)
{
  int id = rand() % 0xffff;
#ifdef _USE_RESOLV_TEST_
  querybuf_t qbuf;
  HEADER *hp = &qbuf.hdr;
  int len2;
#endif
  unsigned char buf[MAXPACKET];
  const int blen = sizeof(buf);
  int len, family = hints->ai_family;
  st_netfd_t nfd = st_socket(server->sa_family, SOCK_DGRAM, 0);
  if (!nfd) return -1;
  if (family == AF_UNSPEC) family = server->sa_family;
#ifdef _USE_RESOLV_TEST_
  len2 = res_mkquery(QUERY, name, C_IN, family == AF_INET6 ? T_AAAA : T_A, NULL, 0, NULL, qbuf.buf, blen);
  id = ntohs(hp->id);
#endif
  len = mkquery(name, C_IN, family == AF_INET6 ? T_AAAA : T_A, id, 1, buf, blen, 0);
  if (len <= 0) {
    return -1;
  }

  if (st_sendto(nfd, buf, len, 0, server, sock_addr_len(server), timeout) != len) {
    st_netfd_close(nfd);
    return -1;
  }

  /* Wait for reply */
  do {
    len = st_recvfrom(nfd, buf, blen, 0, NULL, NULL, timeout);
    if (len <= 0)
      break;
  } while (id != DNS_HEADER_QID(buf));
  st_netfd_close(nfd);

  if (len < HFIXEDSZ) {
    if (len >= 0)
      errno = EMSGSIZE;
    return -1;
  }
  return parse_answer(buf, len, hints, ttl);
}
#define MAXNS 5
static struct sockaddr_storage _nameserver[MAXNS];
static size_t _nameserver_cnt = 0;
static int read_conf(const char* fname)
{
  char line[1024];
  FILE* fp = fopen(fname, "r");
  if (!fp) return -1;
  while (fgets (line, sizeof(line), fp) != NULL && _nameserver_cnt < MAXNS) {
    if (line[0] == '#' || strncmp(line, "nameserver", 10) != 0)
      continue;
    if (st_sockaddr((struct sockaddr*)&_nameserver[_nameserver_cnt], AF_UNSPEC, line+10, 53) > 0)
      _nameserver_cnt++;
  }
  fclose (fp);
  return 0;
}
int st_reset_dns(void)
{
  srand (time(NULL));
#ifdef _USE_RESOLV_TEST_
  int i;
  if ((_res.options & RES_INIT) == 0 && res_init() < 0)
    return -1;
  _nameserver_cnt = 0;
  for(i=0; i< _res.nscount && i < MAXNS; ++i)
    memcpy(&_nameserver[_nameserver_cnt++], &_res.nsaddr_list[i], sock_addr_len(&_res.nsaddr_list[i]));
#elif defined(_WIN32)
  char *line, *p, *p1;
  _nameserver_cnt = 0;
  if (get_DNS_Windows(&line) < 0)
    return -1;
  p1 = line;
  do {
    p1 = strchr(p = p1, ',');
    if (p1) *p1++ = '\0';
    if (st_sockaddr((struct sockaddr*)&_nameserver[_nameserver_cnt], AF_UNSPEC, p, 53) > 0)
      _nameserver_cnt++;
    else
      fprintf(stderr, "invalid DNS:%s\n", p);
  } while (p1);
  free(line);
#elif defined(__BIONIC__)
  int i,j;
  _nameserver_cnt = 0;
  for (i = 1; i <= MAX_DNS_PROPERTIES && _nameserver_cnt < MAXNS; i++) {
    char key[PROP_NAME_MAX];
    char val[PROP_VALUE_MAX];
    snprintf(key, sizeof(key), "net.dns%u", i);
    memset(val, 0, sizeof(val));
    __system_property_get(key, val);
    if (val[0] && st_sockaddr((struct sockaddr*)&_nameserver[_nameserver_cnt], AF_UNSPEC, val, 53) > 0)
      _nameserver_cnt++;
    for (j = 0; j <= 1 && _nameserver_cnt < MAXNS; j++) {
      snprintf(key, sizeof(key), "net.rmnet%u.dns%u", j, i);
      memset(val, 0, sizeof(val));
      __system_property_get(key, val);
      if (val[0] && st_sockaddr((struct sockaddr*)&_nameserver[_nameserver_cnt], AF_UNSPEC, val, 53) > 0)
        _nameserver_cnt++;
    }
  }
#elif defined(PATH_RESOLV_CONF)
  const char* fname = getenv("PATH_RESOLV_CONF"); 
  if (!fname || !fname[0]) fname = PATH_RESOLV_CONF;
  _nameserver_cnt = 0;
  if (read_conf(fname) < 0) return -1;
#endif
  return _nameserver_cnt;
}
static void _st_freeaddrinfo(struct addrinfo *res)
{
  if (!res) return;
  else if (res->ai_next)
    _st_freeaddrinfo(res->ai_next);
  else {
    if (res->ai_addr) free(res->ai_addr);
    free(res);
  }
}

void st_freeaddrinfo(struct addrinfo *hints)
{
  _st_freeaddrinfo(hints->ai_next);
  hints->ai_next = NULL;
}

/* timeout for udp send/recv, after return ttl */
int st_getaddrinfo(struct addrinfo* hints, unsigned *ttl, st_utime_t timeout)
{
  size_t i;
  int ret;
  if (!hints || hints->ai_next || !hints->ai_canonname || !hints->ai_canonname[0])
    return -1;
  if (hints->ai_addr) {
    ret = fetch_domain(hints->ai_canonname, hints->ai_addr, hints, ttl, timeout);
    if (ret > 0) {
      for (i=0; i<_nameserver_cnt; ++i) {
        if (!sock_addr_cmp(&_nameserver[i], hints->ai_addr))
          return ret;
      }
      if (_nameserver_cnt < MAXNS) ++_nameserver_cnt;
      for (i = _nameserver_cnt - 1; i > 0; --i)
        _nameserver[i] = _nameserver[i-1];
      memcpy(&_nameserver[0], hints->ai_addr, sock_addr_len(hints->ai_addr));
      return ret;
    }
  }
  for (i=0; i<_nameserver_cnt; ++i) {
    ret = fetch_domain(hints->ai_canonname, (struct sockaddr*)&_nameserver[i], hints, ttl, timeout);
    if (ret > 0) {
      if (i > 0) {
        struct sockaddr_storage tmp = _nameserver[i];
        for (; i > 0; --i)
          _nameserver[i] = _nameserver[i-1];
        _nameserver[0] = tmp;
      }
      return ret;
    }
  }
  return -1;
}
