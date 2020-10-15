#include <st.h>
#include <iostream>
int main(int argc, char *argv[])
{
  st_init();
  chan<int> ch;
  go [=]{
    for (int i = 0; i < 10; ++i) {
      ch << i;
      st_sleep(0);
      std::cout << ',';
    }
    ch.close();
  };
  int v;
  while (ch >> v) std::cout << v;
  ch = nullptr;
  return st_thread_exit(NULL);
}
