#include "../st.h"
/*
readelf -sW a.o | c++filt -t 
# -s: symbol table
# -W: display in wide format
*/
void foo0()
{
  go []{
    printf("start 2nd round scheduling ......\n");
  };
  printf("function pointer\n");
}
