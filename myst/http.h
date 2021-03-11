#ifndef __ST_HTTP_H__
#define __ST_HTTP_H__
#include "st.h"
#include <stdio.h>
#include <stdarg.h>
#if __GNUC__
#pragma GCC visibility push(default)
#endif
#ifdef __cplusplus
extern "C" {
#endif

/** �ַ�������
 * http_key_t ���ú��Դ�Сд���ַ���
 * http_val_t ���ô�Сд���е��ַ���
 */
typedef struct {
  char  *ptr;
  size_t len;
} http_key_t, http_val_t;

/** ���Դ�Сд���ַ��Ƚ� */
int http_strcmp(const char a[], const char b[], size_t len);

/** HTTP ��ͷ������ */
typedef struct {
  http_key_t key;
  http_val_t val;
} http_header_t;

/** HTTP �Ự
 * - method ����ķ���. ����'GET', 'POST'
 * - path ��������·��. ��Ե�ǰhttp_handler_t.path ��·��
 * - version �����HTTP �汾. ���� 'HTTP/1.1'
 * - contentLength �ɶ�ȡ������������,-1��ʾδ֪
 * - header, headerNumber �Ự��������ͳ���
 */
typedef struct {
  http_key_t method;
  http_val_t path;
  http_val_t version;
  ssize_t contentLength;
  size_t headerNumber;
  http_header_t *header;
} http_session_t;

/** ��������ֵ */
const http_val_t* http_get_value(const http_session_t* session, const char* key);
/** ��ȡ HTTP ������*/
int http_read(const http_session_t* session, char* data, size_t length);
/** ������Ӧֵ */
int http_set_status(const http_session_t* session, int status);
/** ������Ӧ��������� */
int http_set_header(const http_session_t* session, const char* key, const char* value_fmt, ...);
/** д����Ӧ������ */
int http_write(const http_session_t* session, const char* data, size_t length);
/** ������ת��ַ */
int http_redirect(const http_session_t* session,  const char* url);
/** ִ�д���
 * @param[in] url ĩβ'/'��ʾ���Ը�·��,��֮ǰ׺���path
 * @retval ʧ�ܷ��ظ���
 * @note
 * ���統ǰ /proxy/test.html
 * - ����url='http://127.0.0.1/', ���� http://127.0.0.1/test.html
 * - ����url='http://127.0.0.1',  ���� http://127.0.0.1/proxy/test.html
 * - ����url='http://127.0.0.1/aaa/', ���� http://127.0.0.1/aaa/test.html
 * - ����url='http://127.0.0.1/aaa',  ���� http://127.0.0.1/aaatest.html
 */
int http_proxy_loop(const http_session_t* session, const char* url);


enum {
  WS_CONTINUATION    = 0x00,
  WS_TEXT            = 0x01,
  WS_BINARY          = 0x02,
  WS_CLOSE           = 0x08,
  WS_PING            = 0x09,
  WS_PONG            = 0x0a,
  WS_FIN             = 0x80,
  WS_TEXT_FRAME      = 0x81,
  WS_BINARY_FRAME    = 0x82,
  WS_MASK            = 0x100,
};
typedef struct http_t http_t;
typedef struct websocket_t websocket_t;
/** websocket �ӿ�
 * - onmessage ���ݽ��ջص�
 * - onclose �ر��¼��ص�
 * - session ��ǰ������ HTTP �Ự
 */
struct websocket_t {
  void (*onmessage)(websocket_t* self, http_t* http, int flags, char* frame, size_t length);
  void (*onclose)(websocket_t* self, http_t* http);
  /*< private >*/
  const http_session_t* session;
};

/** websocket ѭ��
 * ʹ�� websocket_close() ���˳�ѭ��
 * ֻ������ http_handler_t.callback() �е���
 */
int websocket_loop(websocket_t* websocket, const http_session_t* session, const char* protocal);

/** ���͹رձ��Ĳ��˳� websocket_loop ��ѭ�� */
int websocket_close(websocket_t* websocket);

/** ����websocket����
 * @param[in] flags ʹ��WS_*���������ֵ
 * @param[in] data, length �û�����
 * @retval �ɹ����ط��͵��ֽ���
 */
int websocket_send(websocket_t* websocket, int flags, char* data, size_t length);

typedef struct http_handler_t http_handler_t;

/** ·��������
 * - path ���Դ�Сд��·��,ͨ����'/'��ͷ������ĩβ��'/'
 * - callback ������
 * - ������ʽ�����˽��ָ��
 */
struct http_handler_t {
  http_key_t path;
  void (*callback)(http_handler_t* self, http_t* http, const http_session_t* session);
  /*< private >*/
  http_handler_t *next;
};

typedef struct _http_context http_context_t;

/** http ����ӿ�
 * - headerTimeout ÿ���Ự��ͷ����ȡ��ʱ
 * - sessionTimeout ÿ���Ự���ܳ�ʱ
 * - headerBufferSize ÿ���Ựͷ���ֽڿ��ܵ�����ֽ���
 * - headerMaxNumber  ÿ���Ự���Կ��ܵ�������
 * - logFile, logPrintf ��־��ӡ
 * - root ��·��������,��Ϊ��ƥ��ʱ��Ĭ�ϴ���
 * - context ����ѭ��״̬��������
 */
struct http_t {
  st_utime_t headerTimeout;
  st_utime_t sessionTimeout;
  size_t headerBufferSize;
  size_t headerMaxNumber;
  FILE* logFile;
  int (*logPrintf)(FILE * stream, const char * format, va_list arg);
  http_handler_t root;
  /*< private >*/
  http_context_t *context;
};

/** http ����ѭ��
 * ʹ�� http_quit() ���˳�ѭ��
 *
 * @param[in] port �����˿�
 * @param[in] stacksize ÿ���Ự��ջ����
 * @retval ʧ��ֱ�ӷ��ظ���
 */
int http_loop(http_t* http, int port, int stacksize);

/** �˳� http_loop ��ѭ�� */
void http_quit(http_t* http);

/** ��̬����·��������
 * ��handlerΪ����,���ͬʱ��������
 * @retval ʧ��ֱ�ӷ��ظ���
 */
int http_mount(http_t* http, http_handler_t* handler);

/** ��̬ж��·��������
 * @retval ����ж�ظ���
 */
int http_unmount(http_t* http, const char* path);
#ifdef __cplusplus
}
#endif
#if __GNUC__
#pragma GCC visibility pop
#endif
#endif
