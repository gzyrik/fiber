#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include "coroutine.h"
#ifdef _WIN32
#include <Windows.h>
#else
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#endif
#undef NDEBUG 
#include <cassert>
//g++ -DCDECL_ASM -std=gnu++11 coroutine.cpp test.cpp  coctx.cpp coctx_swap.S 
static void* f(void* data) {
    for(int i=0;i<10;++i) coroutine::yield("abc");
    return (void*)"abc";
}
static void test0() {
    auto co = coroutine::create(f);
    for (int i = 0; i < 11; ++i) {
        auto data = (char*)coroutine::resume(co, nullptr);
        fprintf(stderr, "\r%s %d: %s", __FUNCTION__, i, data);
        assert(strcmp(data, "abc") == 0);
    }
    assert(!coroutine::status(co));
    fprintf(stderr, "\r%s done: yield,resume,status\n", __FUNCTION__);
}
static void test1() {
    bool excepted = false;
    auto co = coroutine::create(f);
    try {
        for (int i = 0; i < 110; ++i) {
            auto data = (char*)coroutine::resume(co, nullptr);
            fprintf(stderr, "\r%s %d: %s", __FUNCTION__, i, data);
            assert(strcmp(data, "abc") == 0);
        }
    }
    catch (std::exception& e) { excepted = true; }
    assert(excepted);
    assert(!coroutine::status(co));
    fprintf(stderr, "\r%s done: resume exception\n", __FUNCTION__);
}
static void test2(){
    bool excepted = false;
    auto co = coroutine::wrap([](void*data) {
        for (int i = 0; i<10; ++i) coroutine::yield("abc");
        return (void*)"abc";
    });
    try {
        for (int i = 0; i < 110; ++i) {
            auto data = (char*)co(nullptr);
            fprintf(stderr, "\r%s %d: %s", __FUNCTION__, i, data);
            assert(strcmp(data, "abc") == 0);
        }
    }
    catch (std::exception& e) { excepted = true; }
    assert(excepted);
    fprintf(stderr, "\r%s done: wrap,resume exception\n", __FUNCTION__);
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
static void* test3_recv(void* addr) {
    int fd = udp();
    char buf[1500] = { 0 };
    int addr_len = sizeof(sockaddr_in);
    int ret = bind(fd, (sockaddr*)addr, addr_len);
    for (int i = 0; i < 10000; ++i) {
        fprintf(stderr, "\r%s %d", "test3", i);
        ret = coroutine::recv(fd,  buf, sizeof(buf));
        assert(ret == sizeof(buf));
    }
    closesocket(fd);
    return nullptr;
}
static void* test3_send(void*addr) {
    int fd = udp();
    char buf[1500] = { 0 };
    for (int i = 0; i < 10000; ++i) {
        int ret = coroutine::send(fd, buf, sizeof(buf), addr, sizeof(sockaddr_in));
        assert(ret == sizeof(buf));
    }
    closesocket(fd);
    return nullptr;
}
static void test3() {
    struct sockaddr_in ipv4;
    ipv4.sin_addr.s_addr = htonl(INADDR_ANY);
    ipv4.sin_family = AF_INET;
    ipv4.sin_port = htons(37000);

    coroutine::resume(coroutine::create(test3_recv), &ipv4);
    ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    coroutine::resume(coroutine::create(test3_send), &ipv4);
    coroutine::poll(-1);
    fprintf(stderr, "\r%s done: wait,poll\n", __FUNCTION__);
}
static void* test4_wait(void* data) {
    for (int i = 0; i < 10; ++i){
        fprintf(stderr, "\r%s %d", (char*)data, i);
        assert(coroutine::wait(0, 0x100) == 0x1000);
    }
    return (void*)"end";
}
static void test4() {
    auto id = coroutine::create(test4_wait);
    std::thread th([id] {
        for (int i = 0; i < 10; ++i)
            assert(coroutine::post(id, 0x1000));
    });
    coroutine::resume(id, __FUNCTION__);
    coroutine::poll(-1);
    th.join();
    fprintf(stderr, "\r%s done: wait,poll,post\n", __FUNCTION__);
}
static void test5() {
    auto co = coroutine::wrap([](void*data) {
        fprintf(stderr, "\r%s wait for 1000 ms timtout", (char*)data);
        coroutine::wait(0, 0);
        return nullptr;
    });
    co((void*)__FUNCTION__);
    coroutine::poll(-1);
    fprintf(stderr, "\r%s done: wrap, wait timeout\n", __FUNCTION__);
}
static void* f4_2(void*) {
    auto co = coroutine::create(f, 0);
    //the same as test0()
    for (int i = 0; i < 11; ++i) coroutine::resume(co, nullptr);
    assert(!coroutine::status(co));
    return nullptr;
}
static void f4_1(int n, coroutine::routine_t co[]) {
    auto id = coroutine::create(f4_2, 0);
    coroutine::resume(id, nullptr);
    assert(!coroutine::status(id));
    try {
        char a[1024 * 2] = { 0 };
        a[1023] = 0;
        for (int i = 0; i < 5; ++i) {
            for (int j = 0; j < n; ++j) coroutine::resume(co[j], nullptr);
        }
        a[sizeof(a)-1] = 1;
    }
    catch (std::exception& e) {
        std::cerr << "\nexception caught: " << e.what() << std::endl;
    }
}
const int n = 1;
static void* f4(void* data) {
    auto co = (coroutine::routine_t*)data;
    for(int i=0;i<n;++i) co[i] = coroutine::create(f,0);
    //the same as test0()
    for (int i = 0; i < 6; ++i) {
        for (int j = 0; j < n; ++j) coroutine::resume(co[j], nullptr);
    }
    char a[1024] = "using large stack 1024";
    fprintf(stderr, "\r%s", a);
    f4_1(n, co);
    for (int j = 0; j < n; ++j) assert(!coroutine::status(co[j]));
    return nullptr;
}
static void test6() {
    coroutine::routine_t c[n];
    long stack_size = 1024*2+1024*5;
    auto co = coroutine::create(f4, stack_size);
    fprintf(stderr, "\r%s stack_size=%ld kB", __FUNCTION__, stack_size/1000);
    coroutine::resume(co, c);
    assert(!coroutine::status(co));
    fprintf(stderr, "\r%s done: shared-stack\n", __FUNCTION__);
}
int main(int argc, char* argv[]){
#ifdef _WIN32
    WSADATA wsd;
    WSAStartup(MAKEWORD(2, 2), &wsd);
#endif
    test0(); test1(); test2();//basic
    test3();//poll
    test4();//post
    test5();//timeout
    test6();//shared-stack
    fprintf(stderr, "test passed!\n");
    return 0;
}
