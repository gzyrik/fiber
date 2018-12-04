#ifndef __PT_H__
#define __PT_H__
#pragma once

/** 协程状态(返回值)
 * 根据返回值, 不断的重复调用函数, 完成协程的调度
 * 该协程等价于一个状态机
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

/** 协程的上下文环境(状态机)
 * 由于是 stackless 协程, 所以重入后所有函数内定义的局部值都会失效,
 * 可以将需重入的局部值,暂存在自定义的上下文中. 例如
 *      struct my_cxt{ PT_CTX _; int count; } *pt;
 *
 * @note
 *   - _LC_* 为内部私有宏,不要使用
 *   - 为了重新(非重入)执行函数, 必须事先将PT_CTX清除, 例如
 *      _PT_CLR(pt);
 *   - 除 PT_SCHEDULE 和 _PT_CLR 以外的 PT_* 宏函数,
 *     必须只能在 PT_BEGIN 与 PT_END 之间使用.
 *
 * @var typedef PT_CTX;
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
 * @param threads 一个或多个协程的函数调用
 * @return 所有 threads 都处于退出状态时,才返回false
 *
 * @note
 *  多个时可用 &, 例如
 *      while (PT_SCHEDULE(thread1(&pt1) & thread2(&pt2)))
 *          sleep(1);
 */
#define PT_SCHEDULE(threads) ((threads) < PT_EXITED)

/** 开始协程代码块,必须以 PT_END 结尾.
 *  在此之前的函数内代码,重入时将重复执行!
 *
 * @example
 *  int thread_func(ctx_t* pt, char token) PT_BEGIN(pt){
 *    ...
 *  } PT_END(pt)
 */
#define PT_BEGIN(pt) {\
  char PT_YIELD_FLAG = 1; _LC_RESUME(pt)

/** 结束协程代码块,必须与 PT_BEGIN 对应.
 * 返回 PT_ENDED 状态
 *
 * @note
 *  在此之后的函数内代码,将永远不会被执行!
 *  退出状态就算重入,也将直接跳至该处而直接退出.
 */
#define PT_END(pt) _LC_END(pt) return PT_ENDED; }

/** 持续进行条件判断. 若为 true, 则继续, 反之出让 */
#define PT_WAIT_UNTIL(pt, condition) do {\
  _LC_SET(pt)\
  if(!(condition)) return PT_WAITING; \
} while(0)

/** 持续调度一个或多个子协程
 * 只要有一个调度中的子协程,不在退出状态(即没有执行 PT_END,PT_EXIT)
 * 就出让并在重入后, 持续调度.
 * @see PT_SCHEDULE
 */
#define PT_WAIT_THREAD(pt, threads) PT_WAIT_UNTIL(pt, !PT_SCHEDULE(threads))

/** 出让并在重入后,持续判断条件
 * 与 PT_WAIT_UNTIL 区别在于,至少出让一次.
 */
#define PT_YIELD_UNTIL(pt, condition) do {\
  PT_YIELD_FLAG = 0;\
  _LC_SET(pt)\
  if((PT_YIELD_FLAG == 0) || !(condition)) return PT_YIELDED;\
} while(0)

/** 出让一次, 并在重入后, 从下行执行 */
#define PT_YIELD(pt) PT_YIELD_UNTIL(pt, 1)

/** 退出协程
 *
 * @note
 *  就算重入,也将直接跳至该处直接退出.
 *  与 PT_END 区别在于, 返回PT_EXITED 状态
 */
#define PT_EXIT(pt) do { _LC_SET(pt) return PT_EXITED; } while(0)

/** 复位协程
 * 出让并在重入后, 函数将重新从头执行
 */
#define PT_RESTART(pt) do { _PT_CLR(pt); return PT_WAITING; } while(0)

/**
 * @defgroup 基于 PT协程 的事件系统
 * @{
 */

/**
 * 预定义的事件
 */
enum {
  /** 开始事件
   * 由pt_start()产生并提供相应 data
   */
  PT_EVENT_INIT = 0x80,

  /** 唤醒事件
   * 在下个pt_run()中被唤醒
   * 由pt_poll()产生, 无相应 data
   */
  PT_EVENT_POLL,

  /** 退出事件
   * 由自然退出协程或pt_exit()调用产生, 无相应 data
   */
  PT_EVENT_EXIT,

  /** 其他 PT 退出的通知
   * pt_exit()广播产生, data 为 该退出的 PT
   */
  PT_EVENT_EXITED,

  /** 可自定义的事件最小值 */
  PT_EVENT_USER = 0x8a
};

/** 事件数值类型 */
typedef unsigned char PT_EVENT;

/** 协程属性掩码类型 */
typedef unsigned char PT_MASK;

/** 事件处理协程 */
struct PT
{
  /*< private >*/
  PT_CTX ctx;
  unsigned state;
  struct PT *next; // 用于内部 的单链表管理

  /*< public >*/
  /** 协程的运行函数 */
  int (*thread)(struct PT *p, PT_EVENT event, void* data);
  /** 协程的属性掩码 */
  PT_MASK mask;
  /** 协程的名字, 目前仅作调试用 */
  const char* name;
};

/** 初始化 PT 结构
 * @param[in] thread 事件处理函数
 * @param[in] mask 协程的属性掩码
 * @param[in] name 协程的名字
 */
#define PT_INIT_NAME(thread, mask, name) {\
  (PT_CTX)0, 0, (struct PT*)0,\
  thread, (PT_MASK)mask, name\
}
#define PT_INIT(thread, mask) {\
  (PT_CTX)0, 0, (struct PT*)0,\
  thread, (PT_MASK)mask, #thread\
}

/** 事件处理是否还处于运行状态 */
#define pt_alive(p) (p->state != 0)

/** 开始一个事件处理协程
 * 类似于 p->thread(p, PT_EVENT_INIT, data);
 *
 * @param[in] p 处理协程的内存实例
 * @param[in] data PT_EVENT_INIT事件的相应 data 数据
 */
void pt_start(struct PT *p, void* data);

/** 标记在下一次pt_run()中,唤醒该协程
 * 类似于 pt_post(p, PT_EVENT_POLL, NULL);
 */
void pt_poll(struct PT *p);

/** 阻塞方式,让协程处理该事件 */
void pt_send(struct PT *p, PT_EVENT event, void* data);

/** 退出协程
 * 类似于
 *     foreach(q by mask) {
 *       pt_send(q, PT_EVENT_EXITED, p);
 *     }
 *     pt_send(p, PT_EVENT_EXIT, NULL);
 */
void pt_exit(struct PT *p, PT_MASK mask);

/** 投递事件, 非阻塞方式 */
int pt_post(struct PT *p, PT_EVENT event, void* data);

/** 广播事件, 非阻塞方式 */
int pt_cast(PT_MASK mask, PT_EVENT event, void* data);

/** 处理一个缓存的事件
 * @return 返回缓存的事件个数
 */
int pt_run(void);

/** @} */
#endif
