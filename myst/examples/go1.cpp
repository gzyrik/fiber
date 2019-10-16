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
    // ʹ�ùؼ���go����Э��, go�������ʹ��:
    //     1.void(*)()����ָ��, ����:foo.
    //     2.Ҳ����ʹ���޲�����lambda, std::bind����, function����, 
    //     3.�Լ�һ�п����޲ε��õķº�������
    //     4.����ʹ�ö���,�������.
    //   ע�ⲻҪ���Ǿ�β�ķֺ�";".
    go foo0, foo, []{
        printf("lambda\n");
    };

    go std::bind(&A::fA, A());

    std::function<void()> fn(std::bind(&A::fB, A()));
    go fn;

    // Ҳ����ֱ��ָ��ջ��С��Э��
    //   ����ӵ��10MB��ջ��Э��
    go 10 * 1024 * 1024, []{
        printf("large stack\n");
    };

    printf("start ......\n");
    st_thread_exit(NULL);
    printf("end ......\n");
    return 0;
}
