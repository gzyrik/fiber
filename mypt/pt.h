#ifndef __PT_H__
#define __PT_H__
#pragma once

/** Э��״̬(����ֵ)
 * ���ݷ���ֵ, ���ϵ��ظ����ú���, ���Э�̵ĵ���
 * ��Э�̵ȼ���һ��״̬��
 */
enum {
  /** ���� PT_WAIT_UNTIL ���˳��ķ���ֵ */
  PT_WAITING = 0,

  /** ���� PT_YIELD �� PT_YIELD_UNTIL ���˳��ķ���ֵ */
  PT_YIELDED = 1,

  /** �������� PT_EXIT ���˳��ķ���ֵ */
  PT_EXITED  = 2,

  /** ��Ȼִ�е� PT_END ���˳��ķ���ֵ */
  PT_ENDED   = 3
};

/** Э�̵������Ļ���(״̬��)
 * ������ stackless Э��, ������������к����ڶ���ľֲ�ֵ����ʧЧ,
 * ���Խ�������ľֲ�ֵ,�ݴ����Զ������������. ����
 *      struct my_cxt{ PT_CTX _; int count; } *pt;
 *
 * @note
 *   - _LC_* Ϊ�ڲ�˽�к�,��Ҫʹ��
 *   - Ϊ������(������)ִ�к���, �������Ƚ�PT_CTX���, ����
 *      _PT_CLR(pt);
 *   - �� PT_SCHEDULE �� _PT_CLR ����� PT_* �꺯��,
 *     ����ֻ���� PT_BEGIN �� PT_END ֮��ʹ��.
 *   - �� gcc ƽ̨,PT_BEGIN �� PT_END ֮�䲻������� switch ���
 *     VC �е�����Ϣ��ʽ������"���ڡ��༭���������ĳ������ݿ�(/ZI)"
 *
 * @var typedef PT_CTX;
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

#define _LC_SET(s) _LC_REF(s) = (PT_CTX)__LINE__; case __LINE__:

#define _LC_END(s) _LC_SET(s) break; }

#endif

/* _LC_* Ϊ�ڲ���, ��Ҫʹ�� */
#define _LC_REF(s) (*(PT_CTX*)(s))

/** ���Э��, ���С��ʹ��
 * �ڵ��� PT_EXIT �� ���� PT_END ��, ��Ҫ���ʹ�ö�Ӧ��PT_CTX pt,
 * ����������ȷִ�к���
 */
#define _PT_CLR(s) do { _LC_REF(s) = (PT_CTX)0; } while(0)

/** ����һ������Э��
 * ���ʾ���ִ��һ�麯���ĵ���
 *
 * @param threads һ������Э�̵ĺ�������
 * @return ���� false ��ʾ�������
 *
 * @remarks
 *  threads ���Э�̵ĺ���ʱ:
 *  - ʹ�� & ����, ϣ���ȴ�����Э��ִ�����.
 *    ����Э��,�������˳�״̬(��ִ�� PT_END,PT_EXIT), �ŷ��� false
 *
 *  - ʹ�� | ����, ��һЭ��ִ����ϼ���.
 *    ֻҪ��һ��,�����˳�״̬(��ִ�� PT_END,PT_EXIT), �ͷ��� false
 *
 * @example
 *  while (PT_SCHEDULE(thread1(&pt1) & thread2(&pt2)))
 *      sleep(1);
 *  while (PT_SCHEDULE(thread1(&pt1) | thread2(&pt2)))
 *      sleep(1);
 */
#define PT_SCHEDULE(threads) ((threads) < PT_EXITED)

/** ��ʼЭ�̴����,������ PT_END ��β.
 *  �ڴ�֮ǰ�ĺ����ڴ���,����ʱ���ظ�ִ��!
 *  �� PT_END ֮���ֹʹ�� return
 *
 * @example
 *  int thread_func(ctx_t* pt, char token) PT_BEGIN(pt){
 *    ...
 *  } PT_END(pt)
 */
#define PT_BEGIN(pt) {\
  char _PT_YIELD_FLAG = 1; _LC_RESUME(pt)

/** ����Э�̴����,������ PT_BEGIN ��Ӧ.
 * ���� PT_ENDED ״̬
 *
 * @note
 *  �ڴ�֮��ĺ����ڴ���,����Զ���ᱻִ��!
 *  �˳�״̬��������,Ҳ��ֱ�������ô���ֱ���˳�.
 *  ��� PT_ENDED ǰ�ʺ������ͷ���Դ.
 */
#define PT_END(pt) _LC_END(pt) return PT_ENDED; }

/** �������������ж�. ��Ϊ true, �����, ��֮���� */
#define PT_WAIT_UNTIL(pt, condition) do {\
  _LC_SET(pt)\
  if(!(condition)) return PT_WAITING;\
} while(0)

/** ��������һ��������Э��
 * ֱ���������,������ִ��.
 *
 * @see PT_SCHEDULE
 */
#define PT_WAIT_THREAD(pt, threads) PT_WAIT_UNTIL(pt, !PT_SCHEDULE(threads))

/** ���ò��������,�����ж�����
 * �� PT_WAIT_UNTIL ��������,���ٳ���һ��.
 */
#define PT_YIELD_UNTIL(pt, condition) do {\
  _PT_YIELD_FLAG = 0;\
  _LC_SET(pt)\
  if((_PT_YIELD_FLAG == 0) || !(condition)) return PT_YIELDED;\
} while(0)

/** ����һ��, ���������, ������ִ�� */
#define PT_YIELD(pt) PT_YIELD_UNTIL(pt, 1)

/** �˳�Э��
 *
 * @note
 *  ��������,Ҳ��ֱ�������ô�ֱ���˳�.
 *  �� PT_END ��������, ����PT_EXITED ״̬
 */
#define PT_EXIT(pt) do { _LC_SET(pt) return PT_EXITED; } while(0)

/** ��λЭ��
 * ���ò��������, ���������´�ͷִ��
 */
#define PT_RESTART(pt) do { _PT_CLR(pt); return PT_WAITING; } while(0)

/**
 * @defgroup ���� PTЭ�� ���¼�ϵͳ
 * @{
 */

/**
 * Ԥ������¼�
 */
enum {
  /** ��ʼ�¼�
   * ��pt_start()�������ṩ��Ӧ data
   */
  PT_EVENT_INIT = 0x80,

  /** �����¼�
   * ���¸�pt_run()�б�����
   * ��pt_poll()����, ����Ӧ data
   */
  PT_EVENT_POLL,

  /** �˳��¼�
   * ����Ȼ�˳�Э�̻�pt_exit()���ò���, ����Ӧ data
   */
  PT_EVENT_EXIT,

  /** ���� PT �˳���֪ͨ
   * pt_exit()�㲥����, data Ϊ ���˳��� PT
   */
  PT_EVENT_EXITED,

  /** ���Զ�����¼���Сֵ */
  PT_EVENT_USER = 0x8a
};

/** �¼���ֵ���� */
typedef unsigned char PT_EVENT;

/** Э�������������� */
typedef unsigned PT_MASK;

/** �¼�����Э��
 * ������ͨ�����¸�ʽ:
 *  int thread(struct PT *pt, PT_EVENT event, void* data) PT_BEGIN(pt) do
 *  {
 *    if (event)
 *      ...
 *    else if (event)
 *      ...
 *    ...
 *    PT_YIELD(pt);
 *  } while(1); PT_END(pt)
 *  �ڲ�����ʹ��return, ���� break 
 */
struct PT
{
  /*< private >*/
  PT_CTX ctx;
  unsigned state;
  struct PT *next; /*< �����ڲ��ĵ�������� */

  /*< public >*/
  /** Э�̵����к��� */
  int (*thread)(struct PT *p, PT_EVENT event, void* data);
  /** Э�̵��������� */
  PT_MASK mask;

  /** Э�̵�����, Ŀǰ���������� */
  const char* name;
};

/** ��ʼ�� PT �ṹ
 * @param[in] thread �¼�������
 * @param[in] mask Э�̵���������
 * @param[in] name Э�̵�����
 */
#define PT_INIT(thread, mask, name) {\
  (PT_CTX)0, 0, (struct PT*)0,\
  thread, (PT_MASK)mask, name\
}

/** ��ʼ�¼�ѭ���Ĵ����, ������ PT_WHILE_END ��β */
#define PT_BEGIN_DO(pt) PT_BEGIN(pt) do

/** �����¼����� */
#define PT_GOTO_END   goto __PT_GOTO_END_LABEL__

/** �����¼�ѭ���Ĵ����, ������ PT_BEGIN_DO ��Ӧ */
#define PT_WHILE_END(pt) while(1); __PT_GOTO_END_LABEL__: PT_END(pt)

/** �¼������Ƿ񻹴�������״̬ */
#define pt_alive(p) (p->state != 0)

/** ��ʼһ���¼�����Э��
 * ������ p->thread(p, PT_EVENT_INIT, data);
 *
 * @param[in] data PT_EVENT_INIT�¼�����Ӧ data ����
 */
void pt_start(struct PT *p, void* data);

/** �˳�Э��
 * ������
 *      if (mask) pt_send(p, mask, PT_EVENT_EXITED, p);
 *      pt_send(p, PT_EVENT_EXIT, NULL);
 * @note
 * ע�� p �����ǵ�ǰЭ��, ���㲥����������ǰЭ��
 */
void pt_exit(struct PT *p, PT_MASK mask);

/** �������һ��pt_run()��,���Ѹ�Э��
 * ������
 *      pt_post(p, mask, PT_EVENT_POLL, NULL);
 */
void pt_poll(struct PT *p, PT_MASK mask);

/** ������ʽ, ����Э�̴�����¼�
 * �� mask ��0, ���� mask �����������Э�����ų� p, ���й㲥
 *
 * @note
 * ע�� p �����ǵ�ǰЭ��, ���㲥����������ǰЭ��
 */
void pt_send(struct PT *p, PT_MASK mask, PT_EVENT event, void* data);

/** ��������ʽ, Ͷ���¼�, �Ӻ��� pt_run() �д���
 * �� mask ��0, ���� mask �����������Э�����ų� p, ���й㲥
 *
 * @return �ɹ����� 0
 */
int pt_post(struct PT *p, PT_MASK mask, PT_EVENT event, void* data);

/** ����һ��������¼�
 * @return ����ʣ��Ļ����¼�����
 */
int pt_run(void);

/** @} */
#endif
