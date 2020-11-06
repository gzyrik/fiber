#include <st.h>
#include <iostream>
static void on_switch_cb_out(st_thread_t thread)
{
  std::cerr << "O:" << st_thread_stats(thread, "nb") << std::endl;
}
static void on_switch_cb_in(st_thread_t thread)
{
  std::cerr << "I:" << st_thread_stats(thread, "nb") << std::endl;
}
int main(int argc, char *argv[])
{
  st_init();
  st_set_switch_out_cb(on_switch_cb_out);
  st_set_switch_in_cb(on_switch_cb_in);
  go 0, "test", [] {
    go 0, "sub0", []{
      //std::cerr << '+';
      st_sleep(0);
    };
    go 0, "sub1", []{
      //std::cerr << '-';
      st_sleep(0);
    };
  };
  std::cerr << std::endl;
  st_sleep(0);
  //std::cerr << ',';
  return st_thread_exit(NULL), 0;
}
