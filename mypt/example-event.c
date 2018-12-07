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
enum {
  EVENT_ATTACK = PT_EVENT_USER,
  EVENT_WALK,
  EVENT_JUMP,
  EVENT_DIE,
};
static int actor(struct PT *pt, PT_EVENT event, void* data);
static struct PT pt1=PT_INIT_NAME(actor, 1, "a");
static struct PT pt2=PT_INIT_NAME(actor, 2, "b");
static struct PT pt3=PT_INIT_NAME(actor, 4, "c");
int actor(struct PT *pt, PT_EVENT event, void* data) PT_BEGIN(pt) {
  do {
    if (event == PT_EVENT_EXIT)
      break;
    else if (event == EVENT_ATTACK){
      printf("%s attack\n", pt->name);
      pt_post((struct PT*)data, 0, EVENT_WALK, &pt3);
    }
    else if (event == EVENT_WALK){
      printf("%s walk\n", pt->name);
      pt_post((struct PT*)data, 0, EVENT_JUMP, NULL);
    }
    else if (event == EVENT_JUMP){
      printf("%s jump\n", pt->name);
    }

    PT_YIELD(pt);
  } while(1);
  putc('0', stderr);
  pt_exit(pt, 4);
} PT_END(pt)


int main(void)
{
  pt_start(&pt1, NULL);
  pt_start(&pt2, NULL);
  pt_start(&pt3, NULL);
  pt_post(&pt1, 0, EVENT_ATTACK, &pt2);
  int n =0;
  while(1){
    printf("%d ---\n", n++);
    if (!pt_run())
      sleep(1);
  }
  return 0;
}
