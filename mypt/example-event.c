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
  EVENT_WALK = PT_EVENT_USER,
  EVENT_ATTACK,
  EVENT_JUMP,
  EVENT_DIE,
};
static int actor2(struct PT *pt, PT_EVENT event, void* data) PT_BEGIN_DO(pt) 
{
  PT_GOTO_END;
} PT_WHILE_END(pt)
static int actor(struct PT *pt, PT_EVENT event, void* data) PT_BEGIN_DO(pt) 
{
  switch(event) {
    struct PT* from;
  case PT_EVENT_INIT:
    printf("%s start\n", pt->name);
    break;
  case PT_EVENT_EXIT:
    printf("%s exit\n", pt->name);
    PT_GOTO_END;
  case EVENT_WALK:
    printf("%s walk\n", pt->name);
    break;
  case EVENT_ATTACK:
    from = (struct PT*)data;
    printf("%s attack %s\n", pt->name, from->name);
    pt_post(from, 0, EVENT_JUMP, pt);
    break;
  case EVENT_JUMP:
    from = (struct PT*)data;
    printf("%s jump by %s\n", pt->name, from->name);
    pt_send(NULL, 0xF, EVENT_DIE, pt);
    printf("%s die by self\n", pt->name);
    PT_GOTO_END;
  case EVENT_DIE:
    from = (struct PT*)data;
    printf("%s die by %s\n", pt->name, from->name);
    //pt_send(from, 0, EVENT_DIE, pt);
    PT_GOTO_END;
  }
  PT_YIELD(pt);
} PT_WHILE_END(pt)

int main(void)
{
  struct PT a=PT_INIT(actor, 1, "a");
  struct PT b=PT_INIT(actor, 2, "b");
  struct PT c=PT_INIT(actor, 4, "c");
  int n =0;
  pt_start(&a, NULL);
  pt_start(&b, NULL);
  pt_start(&c, NULL);
  pt_post(0, 0xf, EVENT_WALK, NULL);
  pt_post(&a, 0, EVENT_ATTACK, &b);
  while(a.state | b.state | c.state){
    printf("%d ---\n", n++);
    if (!pt_run()) sleep(1);
  }
  return 0;
}
