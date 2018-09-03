#ifndef __PT_H__
#define __PT_H__
#pragma once

#define PT_WAITING 0
#define PT_YIELDED 1
#define PT_EXITED  2
#define PT_ENDED   3

#define _LC_REF(s) (*(PT_CTX*)(s))
#define _LC_CLR(s) _LC_REF(s) = (PT_CTX)0;

/** Э�̵������Ļ���
 * @var typedef PT_CTX;
 * ������ stackless Э��, ������������к����ڶ���ľֲ�ֵ����ʧЧ,
 * ���Խ��ֲ�ֵ,�ݴ����Զ������������. ����
 * struct my_cxt{ PT_CTX _; int i; };
 */
#ifdef __GNUC__
typedef void* PT_CTX;

#define _LC_RESUME(s) if(_LC_REF(s) != (PT_CTX*)0) goto *_LC_REF(s);

#define _LC_CONCAT2(s1, s2) s1##s2
#define _LC_CONCAT(s1, s2) _LC_CONCAT2(s1, s2)
#define _LC_SET(s) _LC_CONCAT(LC_LABEL, __LINE__): \
    _LC_REF(s) = &&_LC_CONCAT(LC_LABEL, __LINE__);

#define _LC_END(s) _LC_SET(s)

#else
typedef unsigned short PT_CTX;

#define _LC_RESUME(s) switch(_LC_REF(s)) { case 0:

#define _LC_SET(s) _LC_REF(s) = __LINE__; case __LINE__:

#define _LC_END(s) _LC_SET(s) break; }

#endif

/** ��ʼЭ�̴����,������ PT_END ��β.
 * ע��: �ڴ�֮ǰ�ĺ����ڴ���,����ʱ���ظ�ִ��!
 */
#define PT_BEGIN(pt) {\
    char PT_YIELD_FLAG = 1; _LC_RESUME(pt)

/** ����Э�̴����,������ PT_BEGIN ��Ӧ.
 * ���� PT_EXITED ״̬
 * ע��: �ڴ�֮��ĺ����ڴ���,����Զ���ᱻִ��!
 * ��������,Ҳ��ֱ�������ô�ֱ���˳�.
 */
#define PT_END(pt) _LC_END(pt) return PT_ENDED; }

/** �������������ж�. ��Ϊ true,�����, ��֮���� */
#define PT_WAIT_UNTIL(pt, condition) do {\
    _LC_SET(pt)\
    if(!(condition)) return PT_WAITING; \
} while(0)

/** ���ò��������,�����ж�����
 * �� PT_WAIT_UNTIL ��������,���ٳ���һ��.
 */
#define PT_YIELD_UNTIL(pt, condition) do {\
    PT_YIELD_FLAG = 0;\
    _LC_SET(pt)\
    if((PT_YIELD_FLAG == 0) || !(condition)) return PT_YIELDED;\
} while(0)

/** ���ò��������, ������ִ�� */
#define PT_YIELD(pt) PT_YIELD_UNTIL(pt, 1)

/** ����һ������Э��
 * ֻҪ��һ�������е�Э��,�����˳�״̬(��û��ִ�� PT_END,PT_EXIT),
 * �������Ⱦͷ��� true.
 *
 * @param threads һ������Э�̵ĺ�������,
 * ���ʱ���� &, ����
 *      while (PT_SCHEDULE(thread1(&pt1) & thread2(&pt2))) sleep(1);
 */
#define PT_SCHEDULE(threads) ((threads) < PT_EXITED)

/** ��������һ��������Э��
 * ֻҪ��һ�������е���Э��,�����˳�״̬(��û��ִ�� PT_END,PT_EXIT)
 * �ͳ��ò��������, ��������.
 * @see PT_SCHEDULE
 */
#define PT_WAIT_THREAD(pt, threads) PT_WAIT_UNTIL(pt, !PT_SCHEDULE(threads))

/** �˳�Э��
 * ע��: ��������,Ҳ��ֱ�������ô�ֱ���˳�.
 * �� PT_END ��������, ����PT_EXITED ״̬
 */
#define PT_EXIT(pt) do { _LC_SET(pt) return PT_EXITED; } while(0)

/** ��λЭ��
 * ���ò��������, ���������´�ͷִ��
 */
#define PT_RESTART(pt) do { _LC_CLR(pt) return PT_WAITING; } while(0)

#endif
