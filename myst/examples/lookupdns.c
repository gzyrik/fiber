/*
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <st.h>

#if !defined(NETDB_INTERNAL) && defined(h_NETDB_INTERNAL)
#define NETDB_INTERNAL h_NETDB_INTERNAL
#endif

/* Resolution timeout (in microseconds) */
#define TIMEOUT (2*1000000LL)

static struct addrinfo _hints;
/* External function defined in the res.c file */
void st_freeaddrinfo(struct addrinfo *res);
int st_getaddrinfo(const char *node, const char *service,
  const struct addrinfo *hints, struct addrinfo **res, st_utime_t *timeout);


static void *do_resolve(void *host)
{
  struct addrinfo *addr=NULL;
  st_utime_t timeout = TIMEOUT;
  int n = st_getaddrinfo(host, NULL, &_hints, &addr, &timeout);

  if (n < 0) {
    fprintf(stderr, "st_getaddrinfo: can't resolve %s: ", (char *)host);
    if (h_errno == NETDB_INTERNAL)
      perror("");
    else
      herror("");
  } else if(addr) {
    struct addrinfo* ai = addr;
    for(n; n>0; --n, ai=ai->ai_next) {
      if (!ai->ai_addr) continue;
      printf("%-40s %s ttl %ds\n", (char *)host,
        st_inetaddr(ai->ai_addr, ai->ai_addrlen, NULL, NULL),
        timeout/1000000);
    }
    st_freeaddrinfo(addr);
  }

  return NULL;
}


/*
 * Asynchronous DNS host name resolution. This program creates one
 * ST thread for each host name (specified as command line arguments).
 * All threads do host name resolution concurrently.
 */
int main(int argc, char *argv[])
{
  int i;

  if (argc < 2) {
    fprintf(stderr, "Usage: %s <hostname1> [<hostname2>] ...\n", argv[0]);
    exit(1);
  }

  if (st_init() < 0) {
    perror("st_init");
    exit(1);
  }

  _hints.ai_family = AF_UNSPEC;
  for (i = 1; i < argc; i++) {
    if (argv[i][0] == '@') {
      struct sockaddr_storage sa;
      _hints.ai_addr = (struct sockaddr*)&sa;
      _hints.ai_addrlen = st_sockaddr(_hints.ai_addr, AF_INET, &argv[i][1], 53);
    }
    else if (!strcmp(argv[i], "-6"))
      _hints.ai_family = AF_INET6;
    else if (!strcmp(argv[i], "-4"))
      _hints.ai_family = AF_INET;
    /* Create a separate thread for each host name */
    else if (st_thread_create(do_resolve, argv[i], 0, 0) == NULL) {
      perror("st_thread_create");
      exit(1);
    }
  }

  st_thread_exit(NULL);

  /* NOTREACHED */
  return 1;
}

