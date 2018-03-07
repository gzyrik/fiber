#include <cstring>
#include <cassert>
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
//g++ -DCDECL_ASM -std=gnu++11 coroutine.cpp main.cpp  ucontext_s.cpp coctx_swap.S 
static void* f(void* data) {
    for(int i=0;i<10;++i)
        coroutine::yield("abc");
    return (void*)"end";
}
static void t0(){
    auto co = coroutine::create(f);
    for (int i = 0; i < 11; ++i)
        std::cerr << (char*)coroutine::resume(co, nullptr) << std::endl;
    std::cerr << coroutine::status(co) << std::endl;
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
        assert(ret == sizeof(buf));
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
        assert(ret == sizeof(buf));
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
    t0();
    printf("test passed!\n");
    return 0;
}
