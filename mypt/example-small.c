#include "pt.h"
#include <stdio.h>
#include <stdlib.h>
#include<time.h>
#ifdef _WIN32
#include <windows.h>
static void sleep(int s) { Sleep(s*1000);}
#else
#include <unistd.h>
#include <sys/time.h>
#endif
static int _count;
static PT_THREAD(consumer, char token);
static PT_THREAD(producer, char token);
static PT_THREAD(driver_thread, PT_CTX* pt1);

PT_BEGIN(consumer, char token) {
    while (_count) {
        PT_WAIT_UNTIL(_count > 0);

        if (rand() < RAND_MAX/2) {
            --_count;
            putc(token,stderr);
        }
        else
            PT_YIELD();
    }
} PT_END

PT_BEGIN(producer, char token) {
    while (_count) {
        PT_YIELD_UNTIL(_count < 9);
        if (rand() > RAND_MAX/2) {
            ++_count;
            putc(token,stderr);
        }
    }
} PT_END

PT_BEGIN(driver_thread, PT_CTX* pt1) {
    static PT_CTX pt2;
    PT_WAIT_THREAD(producer(pt1, '+') & consumer(&pt2, '-'));
} PT_END

int main(void)
{
    PT_CTX driver_pt={0}, pt1={0};

    srand((int)time(0));
    _count = (rand() % 9)+1;
    putc('0'+_count,stderr);

    while(PT_ALIVE(driver_thread(&driver_pt, &pt1))) {
        sleep(1);putc('.',stderr);
    }

    putc('\n',stderr);
    return 0;
}
