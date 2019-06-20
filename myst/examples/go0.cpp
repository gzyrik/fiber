#include <st.h>
/*
readelf -sW a.o | c++filt -t 
# -s: symbol table
# -W: display in wide format
*/
void foo0()
{
  go []{
    printf("lambda\n");
  };
  printf("function pointer\n");
}
