#include "coroutine.h"
#include <cassert>
#include <cstring>
#include <vector>
#include <list>
#include <cstdint>
#include <mutex>
#include <system_error>

#ifdef _MSC_VER
#include <Windows.h>
#include "ucontext_w.h"
#pragma comment( lib,"winmm.lib" )
#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable:4293)
#define STACK_ALIGN 1024
#define STACK_MINSIZE 1024
#define _USE_UCONTEXT 1
#define POLL_EVENT_T OVERLAPPED_ENTRY
#define throw_errno(desc) \
    throw std::system_error(std::error_code(GetLastError(), std::system_category()), #desc)
#else
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#define throw_errno(desc) \
    throw std::system_error(std::error_code(errno, std::system_category()), #desc)
typedef int HANDLE;
#define STACK_ALIGN 16
#define STACK_MINSIZE 0
#if __APPLE__ && __MACH__
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <sys/event.h>
#define _USE_KEVENT 1
#define POLL_EVENT_T struct kevent 
#define _XOPEN_SOURCE
#include <ucontext.h>
#else
#include <ucontext.h>
#include <sys/epoll.h> 
#include <sys/eventfd.h>
#define _USE_UCONTEXT 1
#define _USE_EPOLL 1
#define POLL_EVENT_T struct epoll_event
#endif
#endif
static int64_t nowMS(void){
#ifdef _WIN32
    static volatile LONG lastTimeGetTime = 0;
    static volatile uint64_t numWrapTimeGetTime = 0;
    volatile LONG* lastTimeGetTimePtr = &lastTimeGetTime;
    DWORD now = timeGetTime();
    // Atomically update the last gotten time
    DWORD old = InterlockedExchange(lastTimeGetTimePtr, now);
    if (now < old){
        // If now is earlier than old, there may have been a race between
        // threads.
        // 0x0fffffff ~3.1 days, the code will not take that long to execute
        // so it must have been a wrap around.
        if (old > 0xf0000000 && now < 0x0fffffff)
            numWrapTimeGetTime++;
    }
    return (uint64_t)now + (numWrapTimeGetTime << 32);
#elif __APPLE__ && __MACH__
    static mach_timebase_info_data_t _timebase;
    if (!_timebase.denom) mach_timebase_info(&_timebase);
    return (mach_absolute_time()*_timebase.numer / _timebase.denom) / 1000000;

#elif defined(CLOCK_MONOTONIC) || defined(CLOCK_REALTIME)
    /* librt clock_gettime() is our first choice */
    struct timespec ts;
#ifdef CLOCK_MONOTONIC
    clock_gettime(CLOCK_MONOTONIC, &ts);
#else
    clock_gettime(CLOCK_REALTIME, &ts);
#endif
    return (((unsigned long long) ts.tv_sec) * 1000) + (ts.tv_nsec / 1000000);

#else /* !HAVE_CLOCK_GETTIME && ! _WIN32*/
    struct timeval r;
    gettimeofday(&r, nullptr);
    return (((unsigned long long) r.tv_sec) * 1000) + r.tv_usec / 1000;
#endif
}
namespace coroutine {
struct Routine {
#ifdef _WIN32
    WSAOVERLAPPED overlapped;
#endif
#if _USE_UCONTEXT
    ucontext_t ctx;
    char* stack_sp;
    size_t stack_len;
#endif
    const long stack_size;
    const routine_t index;
    void*(*const func)(void*) noexcept;
    enum status status;
    char* fiber_stack;
    Routine *parent;
    void* data;
    long  fd;
    Routine(const routine_t i, void*(*f)(void*)noexcept, const long ss):
        stack_size(ss), index(i), func(f),
        status(suspended), fiber_stack(nullptr), parent(nullptr), 
        data(nullptr), fd(0) {
#if _USE_UCONTEXT
        memset(&ctx, 0, sizeof(ctx));
#endif
    }
    ~Routine() {
        if (!fiber_stack) return;
#if _USE_UCONTEXT
        free(fiber_stack);
#elif _WIN32
        if (stack_size == 0 && index == 0)
            ConvertFiberToThread();
        else
            DeleteFiber((LPVOID)fiber_stack);
#endif
    }
};
struct Ordinator;
static std::mutex _threads_mutex;
static Ordinator* _threads[0x100];
static uint8_t _threads_count;
static uint8_t Occupy(Ordinator* self) {
    std::lock_guard<std::mutex> guard(_threads_mutex);
    for (int i = 0; i<0x100; ++i) {
        const uint8_t idx = static_cast<uint8_t>((i + _threads_count) & 0xFF);
        if (!_threads[idx]) {
            _threads[idx] = self;
            _threads_count = idx+1;
            return idx;
        }
    }
    throw std::overflow_error("thread count overflow 0x100");
}
struct Ordinator : public Routine {
    const uint8_t thread_id;
    std::vector<Routine*> routines;
    std::list<routine_t> indexes;
    Routine* current;
    size_t count;
    HANDLE poll_fd;
#ifndef _WIN32
    int post_wfd, post_rfd;
#endif
    std::once_flag poll_init;
    static void _InitPoll(Ordinator*);
    void InitPoll() { if (!poll_fd) std::call_once(poll_init, _InitPoll, this); }
    Ordinator() : Routine(0, nullptr, 0), current(this),
        count(0), poll_fd(0), thread_id(Occupy(this)){
        routines.push_back(this);
    }
    ~Ordinator() {
        {
            std::lock_guard<std::mutex> guard(_threads_mutex);
            _threads[thread_id] = nullptr;
        }
        if (poll_fd) {
#ifdef _WIN32
            CloseHandle(poll_fd);
#else
            close(poll_fd);
#endif
            poll_fd = 0;
        }
        routines[0] = nullptr;
        for (auto &routine : routines) delete routine;
    }
};
thread_local static Ordinator _ordinator;
static void* YieldFiber(Routine* routine, enum status status) {
    Routine *parent = routine->parent;
    if (!parent) throw std::logic_error("yield no parent routine");
    routine->status = status;
    parent->status = running;
    _ordinator.current = parent;
#if _USE_UCONTEXT
    routine->stack_sp = (char*)&parent;
    routine->stack_len= 0;
    if (routine->ctx.uc_stack.ss_sp && routine->stack_sp <= (char*)routine->ctx.uc_stack.ss_sp + STACK_MINSIZE)
        throw std::overflow_error("routine stack overflow at yield");
    if (status != dead && routine->stack_size <= 0) {//save stack before swap
        char* stack_bp = (char*)(routine->ctx.uc_stack.ss_sp) + routine->ctx.uc_stack.ss_size;
        routine->stack_len = stack_bp - routine->stack_sp;
        routine->fiber_stack = (char*)malloc(routine->stack_len);
        memcpy(routine->fiber_stack, routine->stack_sp, routine->stack_len);
    }
    if (swapcontext(&routine->ctx, &parent->ctx) != 0) throw_errno(swapcontext);
    routine = _ordinator.current;
    if (routine->stack_size <= 0 && routine->stack_len > 0) {//restore stack after swap
        memcpy(routine->stack_sp, routine->fiber_stack, routine->stack_len);
        free(routine->fiber_stack);
        routine->fiber_stack = nullptr;
    }
#elif _WIN32
    SwitchToFiber((LPVOID)parent->fiber_stack);
    if (_ordinator.current != routine)
        throw std::logic_error("current routine changed after yield");
#endif
    return routine->data;
}
#ifdef _WIN32
static void __stdcall entry(LPVOID lpParameter)
#else
static void entry(int a1, int a2)
#endif
{
#ifndef _WIN32
    intptr_t lpParameter = static_cast<intptr_t>(a1);
    if (sizeof(Routine*) > sizeof(int))
        lpParameter |= intptr_t(a2) << (sizeof(int) * 8);
#endif
    Routine *routine = reinterpret_cast<Routine*>(lpParameter);
#if _USE_UCONTEXT
    routine->stack_sp = (char*)&routine;
    routine->stack_len = 0;
    if (routine->ctx.uc_stack.ss_sp && routine->stack_sp <= (char*)routine->ctx.uc_stack.ss_sp + STACK_MINSIZE)
        throw std::overflow_error("routine stack overflow at entry");
#endif
    routine->status = running;
    if (routine->func) routine->data = routine->func(routine->data);
#if _USE_EPOLL
    if (routine->fd && _ordinator.poll_fd)
        epoll_ctl(_ordinator.poll_fd, EPOLL_CTL_DEL, routine->fd, nullptr);
#endif
    YieldFiber(routine, dead);
}
static void* ResumeFiber(Routine* routine) {
    Routine *current = _ordinator.current;
    routine->parent = current;
    current->status = normal;
    routine->status = running;
    _ordinator.current = routine;
#if _USE_UCONTEXT
    current->stack_sp = (char*)&current;
    current->stack_len= 0;
    if (current->ctx.uc_stack.ss_sp && current->stack_sp <= (char*)current->ctx.uc_stack.ss_sp + STACK_MINSIZE)
        throw std::overflow_error("routine stack overflow at resume");
    if (routine->ctx.uc_stack.ss_sp == nullptr) {
        static_assert(sizeof(intptr_t) == sizeof(Routine*), "invalid intptr_t");
        if (getcontext(&routine->ctx) != 0) throw_errno(getcontext);
        if (routine->stack_size <= 0) {
            if (!current->ctx.uc_stack.ss_sp)
                throw std::logic_error("current routine no stack at resume");
            routine->ctx.uc_stack.ss_sp = current->ctx.uc_stack.ss_sp;
            routine->ctx.uc_stack.ss_size = (current->stack_sp - (char*)current->ctx.uc_stack.ss_sp + routine->stack_size - STACK_ALIGN) & ~(STACK_ALIGN-1);
        }
        else {
            routine->fiber_stack = (char*)malloc(routine->stack_size);
            routine->ctx.uc_stack.ss_sp = routine->fiber_stack;
            routine->ctx.uc_stack.ss_size = routine->stack_size;
        }
        routine->ctx.uc_link = &current->ctx;
        intptr_t ptr = reinterpret_cast<intptr_t>(routine);
        const int a1 = static_cast<int>(ptr);
        if (sizeof(Routine*) <= sizeof(int)) {
            if (ptr == static_cast<intptr_t>(a1))
                makecontext(&routine->ctx, (void(*)())entry, 1, a1);
            else
                throw std::logic_error("makecontext argv invalid");
        }
        else {
            const int a2 = static_cast<int>(ptr >> (sizeof(int) * 8));
            ptr = static_cast<intptr_t>(a1);
            ptr |= intptr_t(a2) << (sizeof(int) * 8);
            if (routine == reinterpret_cast<Routine*>(ptr))
                makecontext(&routine->ctx, (void(*)())entry, 2, a1, a2);
            else
                throw std::logic_error("makecontext argv invalid");
        }
    }
    else if (routine->stack_size <= 0) {
        char* stack_bp = (char*)(routine->ctx.uc_stack.ss_sp) + routine->ctx.uc_stack.ss_size;
        if (stack_bp > current->stack_sp) {//save overlapped stack before swap
            current->stack_len = stack_bp - current->stack_sp;
            if (current->stack_size <= 0)
                current->fiber_stack = (char*)malloc(current->stack_len);
            else if (current->stack_sp <= current->fiber_stack + current->stack_len + STACK_MINSIZE)
                throw std::overflow_error("routine shared stack overflow");
            memcpy(current->fiber_stack, current->stack_sp, current->stack_len);
        }
    }
    if (swapcontext(&current->ctx, &routine->ctx) != 0) throw_errno(swapcontext);
    current = _ordinator.current;
    if (current->stack_len > 0) {//restore overlapped stack after swap
        memcpy(current->stack_sp, current->fiber_stack, current->stack_len);
        if (current->stack_size <= 0) {
            free(current->fiber_stack);
            current->fiber_stack = nullptr;
        }
    }
#elif _WIN32 
    if (!current->index && !current->fiber_stack){
        if (!(current->fiber_stack = (char*)ConvertThreadToFiber(nullptr)))
            throw_errno(ConvertThreadToFiber);
    }
    if (!routine->fiber_stack) {
        SIZE_T ss = 0;
        if (routine->stack_size > 0) ss = routine->stack_size;
        if (!(routine->fiber_stack = (char*)CreateFiber(ss, entry, static_cast<LPVOID>(routine))))
            throw_errno(CreateFiber);
    }
    SwitchToFiber((LPVOID)routine->fiber_stack);
    if (_ordinator.current != current)
        throw std::logic_error("current routine changed after resume");
#endif
    void* data = routine->data;
    if (routine->status == dead) {
        _ordinator.routines[routine->index] = nullptr;
        _ordinator.indexes.push_back(routine->index);
        delete routine;
        _ordinator.count--;
    }
    return data;
}
/////////////////////////////////////////////////////////////////////////////////////////////
routine_t create(void*(*f)(void*)noexcept, const long stack_size) noexcept {
    routine_t index = _ordinator.routines.size();

    if (index <= (routine_t(-1) >> 8)) {
        _ordinator.routines.push_back(nullptr);
    }
    else if (!_ordinator.indexes.empty()) {
        index = _ordinator.indexes.front();
        _ordinator.indexes.pop_front();
        assert(!_ordinator.routines[index]);
    }
    else
        return 0; //throw std::overflow_error("routine count overflow");
    Routine *routine = new (std::nothrow) Routine(index, f, stack_size);
    if (!routine) return 0;
    _ordinator.routines[index] = routine;
    _ordinator.count++;
    return (index << 8) | _ordinator.thread_id;
}
enum status status(routine_t id) noexcept {
    const uint8_t thread_id = static_cast<uint8_t>(id & 0xFF);
    id >>= 8;
    if (_ordinator.thread_id == thread_id) {
        if (id >= _ordinator.routines.size() || !_ordinator.routines[id]) return dead;
        return _ordinator.routines[id]->status;
    }
    else if (!_threads[thread_id])
        return dead;
    else {
        std::lock_guard<std::mutex> guard(_threads_mutex);
        const struct Ordinator* o = _threads[thread_id];
        if (!o || id >= o->routines.size() || !o->routines[id]) return dead;
        return o->routines[id]->status;
    }
    return dead;
}
void* resume(routine_t id, void* data) {
    const uint8_t thread_id = static_cast<uint8_t>(id & 0xFF);
    id >>= 8;
    if (_ordinator.thread_id != thread_id)
        throw std::invalid_argument("resume other thread routine_t");
    if (id >= _ordinator.routines.size())
        throw std::invalid_argument("resume invalid routine_t");
    Routine* routine = _ordinator.routines[id];
    if (!routine || routine->status != suspended)
        throw std::logic_error("resume not suspended routine");

    routine->data = data;
    return ResumeFiber(routine);
}

void* yield(void* data) {
    Routine *routine = _ordinator.current;
    if (!routine)
        throw std::logic_error("no current routine to yield");

    routine->data = data;
    YieldFiber(routine, suspended);

    return routine->data;
}
////////////////////////////////////////////////////////////////////////////////////////////////
void Ordinator::_InitPoll(Ordinator*self) {
    HANDLE poll_fd;
#ifdef _WIN32
    if (!(poll_fd = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, 0, 0)))
        throw_errno(CreateIoCompletionPort);
#elif _USE_EPOLL
    if ((poll_fd = epoll_create(FD_SETSIZE)) < 0)
        throw_errno(epoll_create);
#elif _USE_KEVENT
    if (!(poll_fd = kqueue()))
        throw_errno(kqueue);
#endif
#ifndef _WIN32
    int sv [2];
    if (socketpair (AF_UNIX, SOCK_STREAM, 0, sv) < 0)
        throw_errno(socketpair);
    self->post_wfd = sv[0];
    self->post_rfd = sv[1];
#if _USE_EPOLL
    struct epoll_event event = { 0 };
    event.events |= EPOLLIN;
    event.data.u64 = -1;
    if (0 != epoll_ctl(poll_fd, EPOLL_CTL_ADD, sv[1], &event)) throw_errno(epoll_ctl);
#elif _USE_KEVENT
#endif
#endif
    self->poll_fd = poll_fd;
}
static void InitWait(Routine *routine, long fd, int events){
#if _USE_EPOLL
    _ordinator.InitPoll();
    int op = EPOLL_CTL_MOD;
    if (routine->fd != fd) {
        if (routine->fd) epoll_ctl(_ordinator.poll_fd, EPOLL_CTL_DEL, routine->fd, nullptr);
        routine->fd = fd;
        op = EPOLL_CTL_ADD;
    }
    struct epoll_event event = { 0 };
    if (events & (READ | ACCEPT)) event.events |= EPOLLIN;
    if (events & (WRITE | CONNECT)) event.events |= EPOLLOUT;
    event.events |= EPOLLONESHOT;
    event.data.u64 = static_cast<uint64_t>(routine->index);
    if (0 != epoll_ctl(_ordinator.poll_fd, op, fd, &event)) throw_errno(epoll_ctl);
#elif _USE_KEVENT
    struct kevent ev[2];
    int n = 0;
    if (events & (READ | ACCEPT))
        EV_SET(&ev[n++], fd, EVFILT_READ, EV_ADD | EV_ONESHOT | EV_CLEAR, 0, 0, reinterpret_cast<void*>(routine->index));
    if (events &  (WRITE | CONNECT))
        EV_SET(&ev[n++], fd, EVFILT_WRITE, EV_ADD | EV_ONESHOT | EV_CLEAR, 0, 0, reinterpret_cast<void*>(routine->index));
    if (0 != kevent(_ordinator.poll_fd, ev, n, nullptr, 0, nullptr)) throw_errno(kevent);
#endif
}
#ifdef _WIN32
LPWSAOVERLAPPED overlap(long fd) {
    Routine *routine = _ordinator.current;
    if (!routine)
        throw std::logic_error("no current routine to overlap");
    if (routine->fd != fd) {
        _ordinator.poll_fd = CreateIoCompletionPort((HANDLE)fd, _ordinator.poll_fd, static_cast<ULONG_PTR>(routine->index), 0);
        if (!_ordinator.poll_fd) throw_errno(CreateIoCompletionPort);
        routine->fd = fd;
    }
    memset(&routine->overlapped, 0, sizeof(WSAOVERLAPPED));
    return &routine->overlapped;
}
#endif
long wait(long fd, int events){
    Routine *routine = _ordinator.current;
    if (!routine)
        throw std::logic_error("no current routine to wait");
#ifdef _WIN32
    return reinterpret_cast<intptr_t>(YieldFiber(routine, suspended));
#else
    if (events&0xF) InitWait(routine, fd, events);
    const int ret = reinterpret_cast<intptr_t>(YieldFiber(routine, suspended));
    int revents = 0;
#endif
#if _USE_EPOLL
    if (ret & (EPOLLIN | EPOLLPRI))
        revents |= (events & ACCEPT ? ACCEPT : READ);
    if (ret & EPOLLOUT)
        revents |= (events & CONNECT ? CONNECT : WRITE);
    return revents;
#elif _USE_KEVENT
    if (ret & EVFILT_READ)
        revents |= (events & ACCEPT ? ACCEPT : READ);
    if (ret & EVFILT_WRITE)
        revents |= (events & CONNECT ? CONNECT : WRITE);
    return revents;
#endif
}
struct post_event {
    routine_t index;
    int result;
};
void poll(int ms) {
    int64_t tvWait, tvStop;
    if (ms < 0)
        tvWait = -1;
    else {
        tvWait = ms;
        tvStop = nowMS() + ms;
    }
    static const size_t kMaxEvents = 8192;
    std::vector<POLL_EVENT_T> events(128);
    _ordinator.InitPoll();
    while (true) {
#ifdef _WIN32
        ULONG n = 0;
        if (!GetQueuedCompletionStatusEx(_ordinator.poll_fd, &events[0], events.size(), &n, tvWait, FALSE)) {
            if (GetLastError() != WAIT_TIMEOUT) throw_errno(GetQueuedCompletionStatusEx);
        }
#elif _USE_EPOLL
        int n = epoll_wait(_ordinator.poll_fd, &events[0], static_cast<int>(events.size()), tvWait);
        if (n < 0) {
            if (errno != EINTR) throw_errno(epoll_wait);
        }
#elif _USE_KEVENT
        struct timespec timeout;
        timeout.tv_sec = tvWait / 1000;
        timeout.tv_nsec = (tvWait % 1000) * 1000 * 1000;
        int n = kevent(_ordinator.poll_fd, nullptr, 0, &events[0], static_cast<int>(events.size()), &timeout);
#endif
        if (n > 0) {
            for (int i = 0; i < n; ++i) {
                routine_t index; void* data;
#ifdef _WIN32
                index =  static_cast<routine_t>(events[i].lpCompletionKey);
                data = reinterpret_cast<void*>(events[i].dwNumberOfBytesTransferred);
#elif _USE_EPOLL
                if (events[i].data.u64 == uint64_t(-1)) {
                    struct post_event val;
                    if (::read(_ordinator.post_rfd, &val, sizeof(val)) != sizeof(val)) throw_errno("read  post_rfd");
                    index = val.index;
                    data = reinterpret_cast<void*>(val.result);
                }
                else {
                    index = static_cast<routine_t>(events[i].data.u64);
                    data = reinterpret_cast<void*>(events[i].events);
                }
#elif _USE_KEVENT
                index = reinterpret_cast<routine_t>(events[i].udata);
                data = reinterpret_cast<void*>(events[i].filter);
#endif
                if (index >= _ordinator.routines.size() || !_ordinator.routines[index])
                    continue;
                Routine* routine = _ordinator.routines[index];
                if (routine->status == suspended) {
                    routine->data = data;
                    ResumeFiber(routine);
                } 
            }
            if (static_cast<size_t>(n) == events.size() && events.size() < kMaxEvents)
                events.resize(events.size() * 2);
        }
        if (ms >= 0) {
            if ((tvWait = tvStop - nowMS()) <= 0)
                break;
        }
        else if (_ordinator.count == 0)
            break;
    }
}
int post(routine_t id, int result) {
    const uint8_t thread_id = static_cast<uint8_t>(id & 0xFF);
    id >>= 8;
    HANDLE post_wfd;
    if (_ordinator.thread_id == thread_id) {
        if (id >= _ordinator.routines.size() || !_ordinator.routines[id]
            || _ordinator.routines[id]->status == dead)
            return false;
        _ordinator.InitPoll();
#ifdef _WIN32
        post_wfd = _ordinator.poll_fd;
#else
        post_wfd = _ordinator.post_wfd;
#endif
    }
    else if (!_threads[thread_id])
        return false;
    else {
        std::lock_guard<std::mutex> guard(_threads_mutex);
        struct Ordinator* o = _threads[thread_id];
        if (!o || id >= o->routines.size() || !o->routines[id]
            || o->routines[id]->status == dead)
            return false;
        o->InitPoll();
#ifdef _WIN32
        post_wfd = o->poll_fd;
#else
        post_wfd = o->post_wfd;
#endif
    }

#ifdef _WIN32
    if (!PostQueuedCompletionStatus(post_wfd, result, static_cast<ULONG_PTR>(id), nullptr))
        throw_errno(PostQueuedCompletionStatus);
#else
    struct post_event val= {id, result};
    if (::write(post_wfd, &val, sizeof(val)) != sizeof(val))
        throw_errno("write post_wfd");
#endif
    return true;
}
}
#if 1
#include <iostream>
#include <string>
#include <thread>
static void* f(void* data) {
    for(int i=0;i<10;++i)
        coroutine::yield("abc");
    return (void*)"end";
}
static void test0(){
    auto co = coroutine::create(f);
    try {
        for (int i = 0; i < 110; ++i)
            std::cerr << (char*)coroutine::resume(co, nullptr) << std::endl;
    }
    catch (std::exception& e) {
        std::cerr << "exception caught: " << e.what() << std::endl;
    }
    std::cerr << coroutine::status(co) << std::endl;
}
static void test1(){
    auto co = coroutine::wrap([](void*data) {
        for (int i = 0; i<10; ++i) coroutine::yield("abc");
        return (void*)"end";
    });
    try {
        for (int i = 0; i < 110; ++i)
            std::cerr << (char*)co(nullptr)<< std::endl;
    }
    catch (std::exception& e) {
        std::cerr << "exception caught: " << e.what() << std::endl;
    }
}
static long udp() {
#ifdef _WIN32
    long fd = WSASocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0, 0, WSA_FLAG_OVERLAPPED);
    int nZero = 0;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, (char*)&nZero, sizeof(nZero));
    return fd;
#else
#define closesocket close
    return socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
#endif
}
static void* f1(void* addr) {
    int fd = udp();
    char buf[1500] = { 0 };
    int addr_len = sizeof(sockaddr_in);
    int ret = bind(fd, (sockaddr*)addr, addr_len);
    for (int i = 0; i < 10000; ++i) {
        fprintf(stderr, "\r%d", i);
        ret = coroutine::wait(fd, coroutine::READ, [&](LPWSAOVERLAPPED overlapped, int revents) {
#ifdef _WIN32
            WSABUF wsabuf = { sizeof(buf), buf };
            DWORD flags = 0;
            return WSARecv(fd, &wsabuf, 1, nullptr, &flags, overlapped, nullptr);
#else
            return recv(fd, buf, sizeof(buf), 0);
#endif
        });
        if(ret != sizeof(buf)) throw_errno("recv");
    }
    closesocket(fd);
    std::cerr << "done to recv thread" << std::endl;
    return nullptr;
}
static void* f2(void*addr) {
    int fd = udp();
    char buf[1500];
    memset(buf, '0', sizeof(buf));
    for (int i = 0; i < 10000; ++i) {
        int ret = coroutine::wait(fd, coroutine::WRITE, [&](LPWSAOVERLAPPED overlapped, int revents) {
#ifdef _WIN32
            WSABUF wsabuf = { sizeof(buf), buf };
            return WSASendTo(fd, &wsabuf, 1, nullptr, 0, (sockaddr*)addr, sizeof(sockaddr_in), overlapped, nullptr);
#else
            return sendto(fd, buf, sizeof(buf), 0, (sockaddr*)addr, sizeof(sockaddr_in));
#endif
        });
        if(ret != sizeof(buf)) throw_errno("sendto");
    }
    closesocket(fd);
    std::cerr << "done to send thread" << std::endl;
    return nullptr;
};
static void test2() {
#ifdef _WIN32
    WSADATA wsd;
    WSAStartup(MAKEWORD(2, 2), &wsd);
#endif
    struct sockaddr_in ipv4;
    ipv4.sin_addr.s_addr = htonl(INADDR_ANY);
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(37000);

    coroutine::resume(coroutine::create(f1), &ipv4);
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    coroutine::resume(coroutine::create(f2), &ipv4);
    coroutine::poll(-1);
}
static void* f3(void* data) {
    for (int i = 0; i < 10; ++i)
        coroutine::wait(0, coroutine::READ);
    return (void*)"end";
}
static void test3() {
    auto id = coroutine::create(f3);
    coroutine::resume(id,nullptr);
    std::thread th([id] {
        for (int i = 0; i < 100; ++i)
            coroutine::post(id, coroutine::READ);
    });
    coroutine::poll(-1);
    th.join();
}
static void* f4_2(void*) {
    auto id = coroutine::create(f, 0);
    for (int i = 0; i < 10; ++i)
        coroutine::resume(id, nullptr);
    return nullptr;
}
static void f4_1(int n, coroutine::routine_t co[]) {
    auto id = coroutine::create(f4_2, 0);
    coroutine::resume(id, nullptr);
    try {
        char a[1024 * 2] = { 0 };
        a[1023] = 0;
        for (int i = 0; i < 5; ++i) {
            for (int j = 0; j < n; ++j) coroutine::resume(co[j], nullptr);
        }
    }
    catch (std::exception& e) {
        std::cerr << "exception caught: " << e.what() << std::endl;
    }
}
const int n = 1;
static void* f4(void* data) {
    auto co = (coroutine::routine_t*)data;
    for(int i=0;i<n;++i)
        co[i] = coroutine::create(f,0);
    for (int i = 0; i < 5; ++i) {
        for (int j = 0; j < n; ++j) coroutine::resume(co[j], nullptr);
    }
    f4_1(n, co);
    return nullptr;
}
static void test4() {
    coroutine::routine_t c[n];
    auto co = coroutine::create(f4, 1024*4+1024*1024);
    coroutine::resume(co, c);
    std::cerr << coroutine::status(co) << std::endl;
}
int main(int argc, char* argv[]){
    test1();
    return 0;
}
#endif
