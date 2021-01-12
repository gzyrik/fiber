#include <st.h>
#include <iostream>
static void on_switch_cb_out(st_thread_t thread)
{
  std::cerr << st_thread_stats(thread, "O:%-8Tn %TS\t%TF\t%Sl\n");
}
static void on_switch_cb_in(st_thread_t thread)
{
  std::cerr << st_thread_stats(thread, "I:%Tn\n");
}
static void on_iterate_cb(st_thread_t thread, int flags)
{
  const char* messg[]={"", "begin", "end", "error"};
  std::cerr << st_thread_stats(thread, "%4Tn: Iteration %s\n", messg[flags&0x3]);
}
int main(int argc, char *argv[])
{
  st_init();
#ifdef ST_SWITCH_CB
  st_set_switch_out_cb(on_switch_cb_out);
  st_set_switch_in_cb(on_switch_cb_in);
#endif
  go 0, "test", [] {
    go 0, "sub0", []{
      std::cerr << '+' << std::endl;
      st_sleep(0);
    };
    go 0, "sub1", []{
      std::cerr << '-' << std::endl;
      st_sleep(0);
    };
  };
  st_sleep(0);
  std::cerr << '$' << std::endl;
#ifdef ST_ITERATE_CB
  st_iterate_threads(on_iterate_cb);
#endif
  return st_thread_exit(NULL), 0;
}
