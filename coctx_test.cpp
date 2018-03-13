#include "coctx.h"
#include <cstdio>
#include <cstring>
#undef NDEBUG 
#include <cassert>
//g++ -DCDECL_ASM -std=gnu++11 -o coctx_test.exe coctx_test.cpp  ucontext_s.cpp coctx_swap.S 
static coctx_t f_ctx, m_ctx;
void f(void* s1, void* s2)
{
    assert(!strcmp((char*)s1, "hello"));
    assert(!strcmp((char*)s2, "world"));
    coctx_swap(&f_ctx, &m_ctx);
}
int main()
{
    char f_stack[16384];
    coctx_init(&f_ctx);
    f_ctx.uc_stack.ss_sp = f_stack;
    f_ctx.uc_stack.ss_size = sizeof(f_stack);
    coctx_make(&f_ctx, f, (void*)"hello", (void*)"world");
    coctx_swap(&m_ctx, &f_ctx);
    printf("coctx_swap ok\n");
    return 0;
}
