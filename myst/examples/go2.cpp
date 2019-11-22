#include "../st.h"
#include <iostream>
int main(int argc, char *argv[])
{
  chan<int> ch;
  st_init();
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
  st_thread_exit(NULL);
  return 0;
}
