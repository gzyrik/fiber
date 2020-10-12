#include "../st.h"
#include <iostream>
int main(int argc, char *argv[])
{
  st_init();
  go 0, []{
    for (int i = 0; i < 10; ++i) {
      std::cerr << ',';
      st_sleep(0);
    }
  };
  for (int i = 0; i < 10; ++i) {
      st_sleep(0);
      std::cerr << '-';
  }
  std::cerr << std::endl;
  return st_thread_exit(NULL);
}
