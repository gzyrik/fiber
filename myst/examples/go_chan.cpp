#include "../st.h"
void foo0();
/*
readelf -sW a.o | c++filt -t 
# -s: symbol table
# -W: display in wide format
*/
int main ()
{
  /*********************** 1. 基本使用 ************************/
  // chan也是一个模板类,
  // 使用以下代码将创建一个无缓冲区的、用于传递整数的chan：
  chan<int> ch_0;

  st_init();
  go foo0;

  // chan是引用计数的, 复制chan并不会产生新的chan, 只会引用旧的chan.
  // 因此, 创建协程时可以直接拷贝chan.
  go [=]{
    // 在协程中, 向ch_0写入一个整数1.
    // 由于ch_0没有缓冲区, 因此会阻塞当前协程, 直到有人从ch_0中读取数据
    // 然后因已失效(空对象或closed), (bool)ch_0 返回 false :
    puts("[0]");
    if (!(ch_0 << 1))
      puts("[11]");
    puts("[12]");
  };

  go [=] {
    // chan是mutable的, 因此可以直接使用const chan读写数据, 
    // 这在使用lambda表达式时是极为方便的特性.
    puts("[1]");
    // 关闭 ch_0, 将会修改被阻塞的协程状态,后续将调度到"[11]"处
    ch_0.close();
    puts("[2]");
  };

  /*********************** 2. 带缓冲区的Channel ************************/
  // 创建缓冲区容量为1的chan, 传递智能指针:
  chan<int*> ch_1(1);

  go [=] {
    int* p1 = new int(19);

    puts("[3]");
    // 向ch_1中写入一个数据, 由于ch_1有一个缓冲区空位, 因此可以直接写入而不会阻塞当前协程.
    ch_1 << p1;
    puts("[4]");
    // 再次向ch_1中写入p1, 由于ch_1缓冲区已满, 因此阻塞当前协程, 等待缓冲区出现空位.
    ch_1 << p1;
    puts("[13]");
  };

  go [=] {
    int* ptr=nullptr;

    puts("[5]");
    // 由于ch_1在执行前一个协程时被写入了一个元素, 因此下面这个读取数据的操作会立即完成.
    ch_1 >> nullptr;
    puts("[6]");
    // 由于ch_1缓冲区等待写入数据p1完成.
    ch_1 >> ptr;
    printf("[7] *ptr = %d\n", *ptr);
    delete ptr;
  };

  /*********************** 3. Try and Timeout ************************/
  // 前面两种对chan的使用方式都是无限期等待的
  // chan还支持带超时的等待机制, 和非阻塞的模式
  chan<void> ch_2;

  go [=] {
    // 使用TryPop和TryPush接口, 可以立即返回无需等待.
    // 当chan为空时, pop(0)会失败; 当写满时, push(0)会失败.
    puts("[8]");
    int ret = ch_2.pop(0);

    printf("[9] ret=%d\n", ret);
    ret = ch_2.push(100);

    printf("[10] ret=%d\n", ret);
  };

  printf("start ......\n");
  //!!! 一定要在 st_thread_exit() 前手工释放局部对象
  ch_0 = ch_2 = ch_1 = nullptr;
  st_thread_exit(NULL);
  puts("**ERROR: Not here\n");
  return 0;
}
