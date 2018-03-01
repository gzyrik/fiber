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
/** Э��ID = (�߳��ڴ���<<8) + �̴߳���&0xFF. 0 Ϊ�Ƿ�Э��ID */
typedef unsigned long routine_t;

/** Э��״̬
 * - suspended, ���к�����û��ִ��, ������� yield()
 * - dead, ���к������˳�, ���������д���
 * - normal, ���к�����, �ֵ��� resume() �л�������Э��
 * - running, ���к�������������
 * */
enum status { dead = 0, suspended, normal, running };

/** ������Э��. 
 * �½���Э�̴���suspended ״̬.
 * @param[in] f Э�����к���
 * @param[in] stack_size Э��ջ����
 * @return ����Э��ID, �������� 0
 * @remarks
 *  - ��stack_size > 0 Ϊ���������ջ����
 *  - ��stack_size <=0 ������ǰ��Э�̵�ջ, ��Ԥ�� -stack_size ����Э��.
 *    ��Ԥ��ֵӦ�ò�С��, �л���Э��ǰ, ��Э�̵�ջ�ڴ�����, ���򽫷�������ջ�ص�;
 *    �Ӷ�����Э���л��Ķ����ڴ�����.
 */
routine_t create(void*(*f)(void*) noexcept, const long stack_size) noexcept;

/** ����Э��״̬. �̰߳�ȫ */
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

inline routine_t create(const std::function<void*(void*)noexcept>&f , const long stack_size = 128*1024) noexcept {
    auto ptr = f.target<void*(*)(void*) noexcept>();
    auto co = create((void*(*)(void*) noexcept)(ptr ? *ptr : _ffunc_), stack_size);
    if (co && !ptr) resume(co, (void*)&f);
    return co;
}

/** Creates a new coroutine, with body f.
 * Returns a function that resumes the coroutine each time it is called.
 * The arguments passed to the function behave as the extra arguments to resume.
 * Returns the same values returned by resume, in case of error, propagates the error.
 */
inline std::function<void*(void*)> wrap(const std::function<void*(void*)noexcept>& f, const long stack_size = 128*1024) noexcept {
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