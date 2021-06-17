#include <st.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* External function defined in the res.c file */
static void *do_resolve(struct addrinfo *hints)
{
    int n;
    unsigned ttl = 0;
    st_utime_t timeout = (st_utime_t)hints->ai_flags * 10000000LL; //XXX: ai_flags as timeout
    n = st_getaddrinfo(hints, &ttl, timeout);

    if (n < 0) {
        fprintf(stderr, "st_getaddrinfo: can't resolve %s: ", hints->ai_canonname);
        perror("");
    }
    else {
        struct addrinfo* ai = hints->ai_next;
        for(n; n>0; --n, ai=ai->ai_next) {
            if (!ai->ai_addr) continue;
            printf("%-40s %s ttl %ds\n", hints->ai_canonname,
                st_inetaddr(ai->ai_addr, ai->ai_addrlen, NULL, NULL), ttl);
        }
    }
    st_freeaddrinfo(hints);
    if (hints->ai_addr) free(hints->ai_addr);
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
    struct addrinfo hints;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <hostname1> [<hostname2>] ...\n", argv[0]);
        exit(1);
    }

    if (st_init(NULL) < 0) {
        perror("st_init");
        exit(1);
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = 2;//XXX: timeout default  2s
    for (i = 1; i < argc; i++)
    {
        if (argv[i][0] == '@') {
            if (hints.ai_addr) free(hints.ai_addr);
            hints.ai_addr = malloc(sizeof(struct sockaddr_storage));
            if (st_sockaddr(hints.ai_addr, AF_UNSPEC, &argv[i][1], 53) < 0) {
                perror("st_sockaddr");
                exit(1);
            }
        }
        else if (!strcmp(argv[i], "-6"))
            hints.ai_family = AF_INET6;
        else if (!strcmp(argv[i], "-4"))
            hints.ai_family = AF_INET;
        else if (!strcmp(argv[i], "-t")) {
            if (++i < argc)
                hints.ai_flags = atoi(argv[i]);//XXX: ai_flags as timeout
        }
        else
        {
            /* Create a separate thread for each host name */
            struct addrinfo* h = malloc(sizeof(hints));
            memcpy(h, &hints, sizeof(hints));
            hints.ai_addr = NULL;
            h->ai_canonname = argv[i];
            if (st_thread_create(do_resolve, h, 0, 0) == NULL) {
                perror("st_thread_create");
                exit(1);
            }
        }
    }
    if (hints.ai_addr) free(hints.ai_addr);
    return st_term();
}

