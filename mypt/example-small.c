#include "pt.h"
#include <stdio.h>
#include <stdlib.h>
#include<time.h>
#include <unistd.h>
static int _count;
static int consumer(struct pt *pt) PT_BEGIN(pt) {
    while (_count) {
        PT_WAIT_UNTIL(pt, _count > 0);

        if (rand() < RAND_MAX/2) {
            --_count;
            putc('-',stderr);
        }
        else
            PT_YIELD(pt);
    }
} PT_END(pt)

static int producer(struct pt *pt) PT_BEGIN(pt) {
    while (_count) {
        PT_YIELD_UNTIL(pt, _count < 9);
        if (rand() > RAND_MAX/2) {
            ++_count;
            putc('+',stderr);
        }
    }
} PT_END(pt)

static int driver_thread(struct pt *pt) PT_BEGIN(pt) {
    static struct pt pt1, pt2;
    PT_WAIT_THREAD(pt, producer(&pt1) & consumer(&pt2));
} PT_END(pt)

int main(void)
{
    static struct pt driver_pt;
    srand((int)time(0));
    _count = (rand() % 9)+1;
    putc('0'+_count,stderr);
    while(PT_ALIVE(driver_thread(&driver_pt))) {
        sleep(1);putc('.',stderr);
    }
    putc('\n',stderr);
    return 0;
}
