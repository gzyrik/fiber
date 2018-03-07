#ifndef __UCONTEXT_S_H__
#define __UCONTEXT_S_H__
#include <stddef.h>
typedef struct {
#if defined(__x86_64__) || defined(_WIN64) || defined(__amd64__)
    void *regs[ 14 ];
#elif defined(__i386__) || defined(_M_IX86)
    void *regs[ 8 ];
#else
#error unsupport platform!
#endif
    struct {
        char *ss_sp;
        size_t ss_size;
    } uc_stack;
} coctx_t;
#ifdef __cplusplus
extern "C" {
#endif
    int coctx_init(coctx_t*ucp);
    int coctx_make(coctx_t*ucp, void (*func)(void*s1, void*s2), void*s1, void*s2);
    int coctx_swap(coctx_t *oucp, coctx_t *ucp);
#ifdef __cplusplus
}
#endif
#endif /* __UCONTEXT_S_H__ */
