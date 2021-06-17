#include <st.h>
int main(int argc, char *argv[])
{
  st_init(NULL);
  chan<int> ch;
  go [=]{
    for (int i = 0; i < 10; ++i) 
      ch << i;
    ch.close();
  };
  int v;
  while (ch >> v) fputc('0'+v, stderr);
  ch = nullptr;
  return st_term();
}
