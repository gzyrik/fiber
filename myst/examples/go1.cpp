#include "../st.h"
void foo0();
void foo()
{
    printf("function pointer\n");
}

struct A {
    void fA() { printf("std::bind\n"); }
    void fB() { printf("std::function\n"); }
};

int main(int argc, char *argv[])
{
    st_init();
    //----------------------------------
    // 使用关键字go创建协程, go后面可以使用:
    //     1.void(*)()函数指针, 比如:foo.
    //     2.也可以使用无参数的lambda, std::bind对象, function对象, 
    //     3.以及一切可以无参调用的仿函数对象
    //     4.可以使用逗号,启动多个.
    //   注意不要忘记句尾的分号";".
    go foo0, foo, []{
        printf("lambda\n");
    };

    go std::bind(&A::fA, A());

    std::function<void()> fn(std::bind(&A::fB, A()));
    go fn;

    // 也可以直接指定栈大小的协程
    //   创建拥有10MB大栈的协程
    go 10 * 1024 * 1024, []{
        printf("large stack\n");
    };

    printf("start ......\n");
    st_thread_exit(NULL);
    printf("end ......\n");
    return 0;
}
