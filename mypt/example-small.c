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
typedef struct {
    PT_CTX _;
    int i;
} ctx_t;
static int _count;
static int consumer(ctx_t* pt, char token) PT_BEGIN(pt){
    while (1) {
        PT_WAIT_UNTIL(pt, _count > 0);

        if (rand() > RAND_MAX/3) {
            putc(token,stderr);
            if(--_count == 0) PT_EXIT(pt);
        }
        else
            PT_YIELD(pt);
    }
} PT_END(pt)

static int producer(ctx_t* pt, char token) PT_BEGIN(pt) {
    while (_count) {
        if (rand() > RAND_MAX/2) {
            putc(token,stderr);
            ++_count;
        }
        PT_YIELD_UNTIL(pt, _count < 9);
    }
} PT_END(pt)

static int driver_thread(ctx_t* pt,  ctx_t* pt1) PT_BEGIN(pt) {
    static ctx_t pt2;
    PT_WAIT_THREAD(pt, producer(pt1, '+') & consumer(&pt2, '-'));
} PT_END(pt)

int main(void)
{
    ctx_t driver_pt={0}, pt1={0};

    srand((int)time(0));
    _count = (rand() % 9)+1;
    putc('0'+_count,stderr);

    while(PT_SCHEDULE(driver_thread(&driver_pt, &pt1))) {
        putc('.',stderr);
        sleep(1);
    }

    putc('\n',stderr);
    return 0;
}
