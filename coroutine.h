#ifndef __COROUTINE_H__
#define __COROUTINE_H__
#pragma once
#ifdef _WIN32
#include <WinSock2.h>
#else
typedef struct _OVERLAPPED * LPWSAOVERLAPPED;
#endif
#ifdef __cplusplus
#include <functional>
namespace coroutine {
#else
#define noexcept
#endif
/** 协程ID = (线程内次序<<8) + 线程次序&0xFF. 0 为非法协程ID */
typedef unsigned long routine_t;

/** 协程状态
 * - suspended, 运行函数还没有执行, 或调用了 yield()
 * - dead, 运行函数已退出, 或发生了运行错误
 * - normal, 运行函数中, 又调用 resume() 切换到其他协程
 * - running, 运行函数正在运行中
 * */
enum status { dead = 0, suspended, normal, running };

/** 创建新协程. 
 * 新建的协程处于suspended 状态.
 * @param[in] f 协程运行函数
 * @param[in] stack_size 协程栈长度
 * @return 返回协程ID, 出错返回 0
 * @remarks
 *  - 若stack_size > 0 为独立分配的栈长度
 *  - 若stack_size <=0 则共享当前父协程的栈, 并预留 -stack_size 给父协程.
 *    该预留值应该不小于, 切换子协程前, 父协程的栈内存增量, 否则将发生运行栈重叠;
 *    从而导致协程切换的额外内存消耗.
 */
routine_t create(void*(*f)(void*), const long stack_size) noexcept;

/** 返回协程状态. 线程安全 */
enum status status(routine_t co) noexcept;

/** Starts or continues the execution of coroutine co. 
 * The first time you resume a coroutine, it starts running its body;
 * the data is passed as the arguments to the body function.
 * If the coroutine has yielded, resume restarts it; the data is passed as the results from the yield.
 *
 * If the coroutine runs without any errors, return the data passed to yield (when the coroutine yields) or 
 * returned by the body function (when the coroutine terminates).
 *
 * If there is any error, will throw exception.
 */
void* resume(routine_t co, void* data);

/** Suspends the execution of the calling coroutine.
 * The data to yield are passed as extra results to resume
 *
 * If there is any error, will throw exception.
 */
void* yield(void* data);

/** event mask */
enum { CUSTOM=0, READ=1, WRITE=2, CONNECT=4, ACCEPT=8 };

/** Wait for the events */
long wait(long fd, int events);

int post(routine_t co, int result);

/** entry io poll loop */
void poll(int ms);

/** Use the overlapped for IOCP */
#ifdef _WIN32
LPWSAOVERLAPPED overlap(long fd);
#endif

#ifdef __cplusplus
static inline void* _ffunc_(void* data) noexcept {
    auto f = *(std::function<void*(void*)>*)(data);
    return f(yield(nullptr));
}

inline routine_t create(const std::function<void*(void*)>&f , const long stack_size = 128*1024) noexcept {
    auto ptr = f.target<void*(*)(void*)>();
    auto co = create((void*(*)(void*))(ptr ? *ptr : _ffunc_), stack_size);
    if (co && !ptr) resume(co, (void*)&f);
    return co;
}

/** Creates a new coroutine, with body f.
 * Returns a function that resumes the coroutine each time it is called.
 * The arguments passed to the function behave as the extra arguments to resume.
 * Returns the same values returned by resume, in case of error, propagates the error.
 */
inline std::function<void*(void*)> wrap(const std::function<void*(void*)>& f, const long stack_size = 128*1024) noexcept {
    routine_t id = create(f, stack_size);
    if (!id) return nullptr;
    return [id](void* data) { return resume(id, data); };
}

inline long wait(long fd, int events, const std::function<long(LPWSAOVERLAPPED overlapped, int revents)>& f) {
#ifdef _WIN32
    const long ret = f(overlap(fd), events);
    if (ret < 0 && WSAGetLastError() != ERROR_IO_PENDING) return ret;
    return wait(fd, events);
#else
    if (!(events = (int)wait(fd, events))) return -1;
    return f(nullptr, events);
#endif
}

template<typename T> T* resume(routine_t co, T* data) { return (T*)resume(co, (void*)data); }
template<typename T> T* yield(T* data) { return (T*)yield((void*)data); }
template<typename T> T& resume(routine_t co, T& data) {
    T* r = (T*)resume(co, (void*)&data);
    return r ? *r : data;
}
template<typename T> T& yield(T& data) {
    T* r = (T*)yield((void*)&data);
    return r ? *r : data;
}
}
#endif /* __cplusplus */
#endif
