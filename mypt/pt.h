#ifndef __PT_H__
#define __PT_H__
#pragma once

#define PT_WAITING 0
#define PT_YIELDED 1
#define PT_EXITED  2
#define PT_ENDED   3

#ifdef __GNUC__
struct pt { void * lc; };

#define _LC_CLR(s) (s) = (void*)0;

#define _LC_RESUME(s) if((s) != (void*)0) goto *(s);

#define _LC_CONCAT2(s1, s2) s1##s2
#define _LC_CONCAT(s1, s2) _LC_CONCAT2(s1, s2)
#define _LC_SET(s) _LC_CONCAT(LC_LABEL, __LINE__): \
    (s) = &&_LC_CONCAT(LC_LABEL, __LINE__);

#define _LC_END(s) _LC_CLR(s)

#else
struct pt { unsigned short lc; };

#define _LC_CLR(s) (s) = 0;

#define _LC_RESUME(s) switch(s) { case 0:

#define _LC_SET(s) (s) = __LINE__; case __LINE__:

#define _LC_END(s) } _LC_CLR(s)

#endif

/** ����Э�̺���
 * @param func ��������
 * @param ...  ��Ӧ���β�
 */
#define PT_THREAD(func, ...) char func(struct pt *PT_SELF_PTR, ##__VA_ARGS__)

/** ��ʼЭ�̺�����ʵ�ִ����,������ PT_END ��β
 * @param func ��������
 * @param ...  ��Ӧ���β�
 */
#define PT_BEGIN(func, ...) char func(struct pt *PT_SELF_PTR, ##__VA_ARGS__){\
    char PT_YIELD_FLAG = 1; _LC_RESUME(PT_SELF_PTR->lc)

/** ����Э�̺�����ʵ�ִ����,������ PT_BEGIN ��Ӧ */
#define PT_END _LC_END(PT_SELF_PTR->lc) return PT_ENDED; }

/** �ж�����Ϊ��,����Э�̳��� */
#define PT_WAIT_UNTIL(condition) do {\
    _LC_SET(PT_SELF_PTR->lc)\
    if(!(condition)) return PT_WAITING; \
} while(0)

/** Э�̳���. ���������ж�����Ϊ��, �������
 * �� PT_WAIT_UNTIL ��������,���ٳ���һ��.
 */
#define PT_YIELD_UNTIL(condition) do {\
    PT_YIELD_FLAG = 0;\
    _LC_SET(PT_SELF_PTR->lc)\
    if((PT_YIELD_FLAG == 0) || !(condition)) return PT_YIELDED;\
} while(0)

/** Э�̳���. ������,������ִ�� */
#define PT_YIELD() PT_YIELD_UNTIL(1)
#define PT_ALIVE(f) ((f) < PT_EXITED)

/**  �ȴ���Э���˳� */
#define PT_WAIT_THREAD(thread) PT_WAIT_UNTIL(!PT_ALIVE(thread))

#define PT_EXIT() do {\
    _LC_CLR(PT_SELF_PTR->lc) return PT_EXITED;\
} while(0)

#define PT_RESTART() do {\
    _LC_CLR(PT_SELF_PTR->lc) return PT_WAITING;\
} while(0)

#define PT_CTX  struct pt

#endif
