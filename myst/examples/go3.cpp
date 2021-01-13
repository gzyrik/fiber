#include <st.h>
#include <stdio.h>
static void on_switch_cb_out(st_thread_t thread)
{
  fputs(st_thread_stats(thread, "%3s: %Tn %-8TS %TF %Sl\n", "OUT"), stderr);
}
static void on_switch_cb_in(st_thread_t thread)
{
  fputs(st_thread_stats(thread, "%3s: %Tn\n", "IN"), stderr);
}
static void on_iterate_cb(st_thread_t thread, int flags)
{
  const char* messg[]={"", "begin", "end", "error"};
  fputs(st_thread_stats(thread, "%4Tn: Iteration %s\n", messg[flags&0x3]), stderr);
}
int main(int argc, char *argv[])
{
  fprintf(stderr, "%3s: %s %-8s %-6s %s\n", "ACT", "NAME", "STATUS", "FLAGS", "STACK");
  fputs("_______________________________\n", stderr);
  st_init();
#ifdef ST_SWITCH_CB
  st_set_switch_out_cb(on_switch_cb_out);
  st_set_switch_in_cb(on_switch_cb_in);
#endif
  go 0, "test", [] {
    go 0, "sub0", []{
      //fputs("+\n", stderr);
      st_sleep(1);
    };
    go 0, "sub1", []{
      //fputs("-\n", stderr);
      st_sleep(0);
    };
  };
  st_sleep(1);
  //fputs("$\n", stderr);
#ifdef ST_ITERATE_CB
  st_iterate_threads(on_iterate_cb);
#endif
  return st_thread_exit(NULL), 0;
}
