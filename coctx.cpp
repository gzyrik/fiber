#include "coctx.h"
#include <string.h> //memset
struct coctx_param_t
{
    void *s1;
    void *s2;
};

#define ESP 0
#define EIP 1
#define EAX 2
#define ECX 3
// -----------
#define RSP 0
#define RIP 1
#define RBX 2
#define RDI 3
#define RSI 4

#define RBP 5
#define R12 6
#define R13 7
#define R14 8
#define R15 9
#define RDX 10
#define RCX 11
#define R8 12
#define R9 13


//----- --------
// 32 bit
// | regs[0]: ret |
// | regs[1]: ebx |
// | regs[2]: ecx |
// | regs[3]: edx |
// | regs[4]: edi |
// | regs[5]: esi |
// | regs[6]: ebp |
// | regs[7]: eax |  = esp
enum
{
    kEIP = 0,
    kESP = 7,
};

//-------------
// 64 bit
//low | regs[0]: r15 |
//    | regs[1]: r14 |
//    | regs[2]: r13 |
//    | regs[3]: r12 |
//    | regs[4]: r9  |
//    | regs[5]: r8  | 
//    | regs[6]: rbp |
//    | regs[7]: rdi |
//    | regs[8]: rsi |
//    | regs[9]: ret |  //ret func addr
//    | regs[10]: rdx |
//    | regs[11]: rcx | 
//    | regs[12]: rbx |
//hig | regs[13]: rsp |
enum
{
    kRDI = 7,
    kRSI = 8,
    kRETAddr = 9,
    kRSP = 13,
};

//yasm -rcpp -D_M_IX86=1 -DCDECL_ASM -fwin32 -pgas  coctx_swap.S -o coctx_swap32.obj 
//yasm -rcpp -D_WIN64=1 -fwin64 -pgas  coctx_swap.S -o coctx_swap64.obj
//g++ -o coctx_test.exe -DCDECL_ASM coctx_test.cpp ucontext_s.cpp coctx_swap.S 
int coctx_init(coctx_t *ctx ) noexcept
{
    memset( ctx,0,sizeof(*ctx));
    return 0;
}
int coctx_make(coctx_t*ctx, void (*pfn)(void*s1, void*s2), void*s1, void*s2) noexcept
{
    memset(ctx->regs, 0, sizeof(ctx->regs));
    char *sp = ctx->uc_stack.ss_sp + ctx->uc_stack.ss_size;
#if defined(__x86_64__) || defined(_WIN64) || defined(__amd64__)
    sp = (char*) ((unsigned long)(size_t)sp & -16LL);
    ctx->regs[ kRSP ] = sp - 8;
    ctx->regs[ kRETAddr] = (char*)pfn;
    ctx->regs[ kRDI ] = (char*)s1;
    ctx->regs[ kRSI ] = (char*)s2;
#elif defined(__i386__) || defined(_M_IX86)
    sp -= sizeof(coctx_param_t);
    sp = (char*)((unsigned long)sp & -16L);
    coctx_param_t* param = (coctx_param_t*)sp ;
    param->s1 = s1;
    param->s2 = s2;
    ctx->regs[ kESP ] = (char*)(sp) - sizeof(void*);
    ctx->regs[ kEIP ] = (char*)pfn;
#else
#error unsupport platform!
#endif
    return 0;
}
