#ifndef __PT_H__
#define __PT_H__
#pragma once

#define PT_WAITING 0
#define PT_YIELDED 1
#define PT_EXITED  2
#define PT_ENDED   3

#ifdef __GNUC__
struct pt { void * lc; };

#define _LC_CLR(s) (s) = (void*)0;

#define _LC_RESUME(s) if((s) != (void*)0) goto *(s);

#define _LC_CONCAT2(s1, s2) s1##s2
#define _LC_CONCAT(s1, s2) _LC_CONCAT2(s1, s2)
#define _LC_SET(s) _LC_CONCAT(LC_LABEL, __LINE__): \
    (s) = &&_LC_CONCAT(LC_LABEL, __LINE__);

#define _LC_END(s) _LC_CLR(s)

#else
struct pt { unsigned short lc; };

#define _LC_CLR(s) (s) = 0;

#define _LC_RESUME(s) switch(s) { case 0:

#define _LC_SET(s) (s) = __LINE__; case __LINE__:

#define _LC_END(s) } _LC_CLR(s)

#endif

/** 声明协程函数
 * @param func 函数名称
 * @param ...  相应的形参
 */
#define PT_THREAD(func, ...) char func(struct pt *PT_SELF_PTR, ##__VA_ARGS__)

/** 开始协程函数的实现代码块,必须以 PT_END 结尾
 * @param func 函数名称
 * @param ...  相应的形参
 */
#define PT_BEGIN(func, ...) char func(struct pt *PT_SELF_PTR, ##__VA_ARGS__){\
    char PT_YIELD_FLAG = 1; _LC_RESUME(PT_SELF_PTR->lc)

/** 结束协程函数的实现代码块,必须与 PT_BEGIN 对应 */
#define PT_END _LC_END(PT_SELF_PTR->lc) return PT_ENDED; }

/** 判断条件为真,否则协程出让 */
#define PT_WAIT_UNTIL(condition) do {\
    _LC_SET(PT_SELF_PTR->lc)\
    if(!(condition)) return PT_WAITING; \
} while(0)

/** 协程出让. 继续后再判断条件为真, 否则出让
 * 与 PT_WAIT_UNTIL 区别在于,至少出让一次.
 */
#define PT_YIELD_UNTIL(condition) do {\
    PT_YIELD_FLAG = 0;\
    _LC_SET(PT_SELF_PTR->lc)\
    if((PT_YIELD_FLAG == 0) || !(condition)) return PT_YIELDED;\
} while(0)

/** 协程出让. 继续后,从下行执行 */
#define PT_YIELD() PT_YIELD_UNTIL(1)
#define PT_ALIVE(f) ((f) < PT_EXITED)

/**  等待子协程退出 */
#define PT_WAIT_THREAD(thread) PT_WAIT_UNTIL(!PT_ALIVE(thread))

#define PT_EXIT() do {\
    _LC_CLR(PT_SELF_PTR->lc) return PT_EXITED;\
} while(0)

#define PT_RESTART() do {\
    _LC_CLR(PT_SELF_PTR->lc) return PT_WAITING;\
} while(0)

#define PT_CTX  struct pt

#endif
