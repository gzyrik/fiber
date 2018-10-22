#ifndef __PT_H__
#define __PT_H__
#pragma once

/** 协程状态(返回值)
 * 根据返回值, 不断的重复调用函数, 完成协程的调度
 */
enum {
    /** 调用 PT_WAIT_UNTIL 而退出的返回值 */
    PT_WAITING = 0,

    /** 调用 PT_YIELD 或 PT_YIELD_UNTIL 而退出的返回值 */
    PT_YIELDED = 1,

    /** 主动调用 PT_EXIT 而退出的返回值 */
    PT_EXITED  = 2,

    /** 自然执行到 PT_END 而退出的返回值 */
    PT_ENDED   = 3
};

/** 协程的上下文环境
 * @var typedef PT_CTX;
 * 由于是 stackless 协程, 所以重入后所有函数内定义的局部值都会失效,
 * 可以将需重入的局部值,暂存在自定义的上下文中. 例如
 *      struct my_cxt{ PT_CTX _; int count; } *pt;
 * 注意:
 *   - 为了重新(非重入)执行函数, 必须事先将PT_CTX清除, 例如
 *      _PT_CLR(pt);
 *   - 除 PT_SCHEDULE 和 _PT_CLR 以外的 PT_* 宏函数,
 *     必须只能在 PT_BEGIN 与 PT_END 之间使用.
 */
#ifdef __GNUC__
typedef void* PT_CTX;
#define _LC_RESUME(s) if(_LC_REF(s) != (PT_CTX*)0) goto *_LC_REF(s);

#define _LC_CONCAT2(s1, s2) s1##s2
#define _LC_CONCAT(s1, s2) _LC_CONCAT2(s1, s2)
#define _LC_SET(s) _LC_CONCAT(LC_LABEL, __LINE__): \
    _LC_REF(s) = &&_LC_CONCAT(LC_LABEL, __LINE__);

#define _LC_END(s) _LC_SET(s)

#else
typedef unsigned short PT_CTX;

#define _LC_RESUME(s) switch(_LC_REF(s)) { case 0:

#define _LC_SET(s) _LC_REF(s) = __LINE__; case __LINE__:

#define _LC_END(s) _LC_SET(s) break; }

#endif

/* _LC_* 为内部宏, 不要使用 */
#define _LC_REF(s) (*(PT_CTX*)(s))

/** 清除协程, 务必小心使用
 * 在调用 PT_EXIT 或 到达 PT_END 后, 需要清除使用对应的PT_CTX pt,
 * 才能重新正确执行函数
 */
#define _PT_CLR(s) do { _LC_REF(s) = (PT_CTX)0; } while(0)

/** 调度一个或多个协程
 * 只要有一个调度中的协程,不在退出状态(即没有执行 PT_END,PT_EXIT),
 * 整个调度就返回 true.
 *
 * @param threads 一个或多个协程的函数调用,
 * 多个时可用 &, 例如
 *      while (PT_SCHEDULE(thread1(&pt1) & thread2(&pt2)))
 *          sleep(1);
 */
#define PT_SCHEDULE(threads) ((threads) < PT_EXITED)

/** 开始协程代码块,必须以 PT_END 结尾.
 * 注意: 在此之前的函数内代码,重入时将重复执行!
 */
#define PT_BEGIN(pt) {\
    char PT_YIELD_FLAG = 1; _LC_RESUME(pt)

/** 结束协程代码块,必须与 PT_BEGIN 对应.
 * 返回 PT_ENDED 状态
 * 注意: 在此之后的函数内代码,将永远不会被执行!
 * 就算重入,也将直接跳至该处直接退出.
 */
#define PT_END(pt) _LC_END(pt) return PT_ENDED; }

/** 持续进行条件判断. 若为 true,则继续, 反之出让 */
#define PT_WAIT_UNTIL(pt, condition) do {\
    _LC_SET(pt)\
    if(!(condition)) return PT_WAITING; \
} while(0)

/** 出让并在重入后,持续判断条件
 * 与 PT_WAIT_UNTIL 区别在于,至少出让一次.
 */
#define PT_YIELD_UNTIL(pt, condition) do {\
    PT_YIELD_FLAG = 0;\
    _LC_SET(pt)\
    if((PT_YIELD_FLAG == 0) || !(condition)) return PT_YIELDED;\
} while(0)

/** 出让并在重入后, 从下行执行 */
#define PT_YIELD(pt) PT_YIELD_UNTIL(pt, 1)

/** 持续调度一个或多个子协程
 * 只要有一个调度中的子协程,不在退出状态(即没有执行 PT_END,PT_EXIT)
 * 就出让并在重入后, 持续调度.
 * @see PT_SCHEDULE
 */
#define PT_WAIT_THREAD(pt, threads) PT_WAIT_UNTIL(pt, !PT_SCHEDULE(threads))

/** 退出协程
 * 注意: 就算重入,也将直接跳至该处直接退出.
 * 与 PT_END 区别在于, 返回PT_EXITED 状态
 */
#define PT_EXIT(pt) do { _LC_SET(pt) return PT_EXITED; } while(0)

/** 复位协程
 * 出让并在重入后, 函数将重新从头执行
 */
#define PT_RESTART(pt) do { _PT_CLR(pt); return PT_WAITING; } while(0)

#endif
