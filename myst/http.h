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

/** 字符串引用
 * http_key_t 引用忽略大小写的字符串
 * http_val_t 引用大小写敏感的字符串
 */
typedef struct {
  char  *ptr;
  size_t len;
} http_key_t, http_val_t;

/** 忽略大小写的字符比较 */
int http_strcmp(const char a[], const char b[], size_t len);

/** HTTP 的头部属性 */
typedef struct {
  http_key_t key;
  http_val_t val;
} http_header_t;

/** HTTP 会话
 * - method 请求的方法. 例如'GET', 'POST'
 * - path 请求的相对路径. 相对当前http_handler_t.path 的路径
 * - version 请求的HTTP 版本. 例如 'HTTP/1.1'
 * - contentLength 可读取的数据流长度,-1表示未知
 * - header, headerNumber 会话属性数组和长度
 */
typedef struct {
  http_key_t method;
  http_val_t path;
  http_val_t version;
  ssize_t contentLength;
  size_t headerNumber;
  http_header_t *header;
} http_session_t;

/** 查找属性值 */
const http_val_t* http_get_value(const http_session_t* session, const char* key);
/** 读取 HTTP 数据流*/
int http_read(const http_session_t* session, char* data, size_t length);
/** 设置响应值 */
int http_set_status(const http_session_t* session, int status);
/** 设置响应或代理属性 */
int http_set_header(const http_session_t* session, const char* key, const char* value_fmt, ...);
/** 写入响应数据流 */
int http_write(const http_session_t* session, const char* data, size_t length);
/** 设置跳转地址 */
int http_redirect(const http_session_t* session,  const char* url);
/** 执行代理
 * @param[in] url 末尾'/'表示绝对根路径,反之前缀添加path
 * @retval 失败返回负数
 * @note
 * 例如当前 /proxy/test.html
 * - 设置url='http://127.0.0.1/', 代理 http://127.0.0.1/test.html
 * - 设置url='http://127.0.0.1',  代理 http://127.0.0.1/proxy/test.html
 * - 设置url='http://127.0.0.1/aaa/', 代理 http://127.0.0.1/aaa/test.html
 * - 设置url='http://127.0.0.1/aaa',  代理 http://127.0.0.1/aaatest.html
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
/** websocket 接口
 * - onmessage 数据接收回调
 * - onclose 关闭事件回调
 * - session 当前所属的 HTTP 会话
 */
struct websocket_t {
  void (*onmessage)(websocket_t* self, http_t* http, int flags, char* frame, size_t length);
  void (*onclose)(websocket_t* self, http_t* http);
  /*< private >*/
  const http_session_t* session;
};

/** websocket 循环
 * 使用 websocket_close() 可退出循环
 * 只允许在 http_handler_t.callback() 中调用
 */
int websocket_loop(websocket_t* websocket, const http_session_t* session, const char* protocal);

/** 发送关闭报文并退出 websocket_loop 的循环 */
int websocket_close(websocket_t* websocket);

/** 发送websocket报文
 * @param[in] flags 使用WS_*常量的组合值
 * @param[in] data, length 用户数据
 * @retval 成功返回发送的字节数
 */
int websocket_send(websocket_t* websocket, int flags, char* data, size_t length);

typedef struct http_handler_t http_handler_t;

/** 路径处理器
 * - path 忽略大小写的路径,通常以'/'开头并忽略末尾的'/'
 * - callback 处理函数
 * - 用于链式管理的私有指针
 */
struct http_handler_t {
  http_key_t path;
  void (*callback)(http_handler_t* self, http_t* http, const http_session_t* session);
  /*< private >*/
  http_handler_t *next;
};

typedef struct _http_context http_context_t;

/** http 服务接口
 * - headerTimeout 每个会话的头部读取超时
 * - sessionTimeout 每个会话的总超时
 * - headerBufferSize 每个会话头部字节可能的最大字节数
 * - headerMaxNumber  每个会话属性可能的最大个数
 * - logFile, logPrintf 日志打印
 * - root 根路径处理句柄,作为无匹配时的默认处理
 * - context 处于循环状态的上下文
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

/** http 服务循环
 * 使用 http_quit() 可退出循环
 *
 * @param[in] port 侦听端口
 * @param[in] stacksize 每个会话的栈长度
 * @retval 失败直接返回负数
 */
int http_loop(http_t* http, int port, int stacksize);

/** 退出 http_loop 的循环 */
void http_quit(http_t* http);

/** 动态挂载路径处理器
 * 若handler为链表,则可同时批量挂载
 * @retval 失败直接返回负数
 */
int http_mount(http_t* http, http_handler_t* handler);

/** 动态卸载路径处理器
 * @retval 返回卸载个数
 */
int http_unmount(http_t* http, const char* path);
#ifdef __cplusplus
}
#endif
#if __GNUC__
#pragma GCC visibility pop
#endif
#endif
