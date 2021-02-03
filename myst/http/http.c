#define _CRT_SECURE_NO_WARNINGS
#include "../st.h"
#include "http.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
typedef struct _http_session  _http_session;
struct _http_context {
  st_cond_t term;
  _http_session* session;
  _http_session* free_list;
  size_t handlerNumber, handlerSize;
  http_handler_t **handler;
  st_thread_t thread;
};

struct _http_session {
  http_session_t request;
  _http_session* next;
  http_t* http;
  http_header_t header[1024];
  st_thread_t thread;
  st_netfd_t netfd;
  st_utime_t deadtime;
  char buf[4096];
  size_t bufLen;
  size_t readPos;/* bufLen - readPos is the part of request body*/
  size_t chunkedLength;
  char chunkedRead: 1;
  char closedRead: 1;
  char keepAlive: 1;

  /*< response >*/
  int status;
  char chunkedWrite: 1;
  char closedWrite : 1;
  char websocket : 1;
  size_t writePos;/* writePos - bufLen is response header */
  size_t headerNumber; /* header[request.headerNumber, headerNumber) is response header */
  size_t contentOffset;
  ssize_t contentLength;
};

int http_strcmp(const char a[], const char b[], size_t len)
{
  size_t i;
  for (i=0; i<len; ++i) {
    int ret = toupper(a[i]) - toupper(b[i]);
    if (ret) return ret;
  }
  return 0;
}
static int keycmp(const void *k0, const void* k1)
{
  const http_key_t *a = k0;
  const http_key_t *b = k1;
  if (a->len != b->len) return (int)(a->len - b->len);
  return http_strcmp(a->ptr, b->ptr, a->len);
}
const http_val_t* http_get_value(const http_session_t* session, const char* key)
{
  http_key_t kt;
  http_header_t* ret;
  _http_session* s= (_http_session*)session;
  if (s->websocket) {
    errno = EPERM;
    return NULL;
  }
  kt.ptr = (char*)key;
  kt.len = strlen(key);
  ret = bsearch (&kt, session->header, session->headerNumber,
    sizeof(http_header_t), keycmp);
  if (ret) return &ret->val;
  return NULL;
}
static int read_body(_http_session* s, char* data, size_t length)
{
  int ret = 0;
  size_t bufLen;
  st_utime_t utime;
  if (length == 0) return 0;
  utime = st_utime();
  utime = utime >= s->deadtime ? 0 : s->deadtime - utime;
  bufLen = s->bufLen - s->readPos;
  if (bufLen >= length)
    bufLen = length;
  else if ((ret = st_recv(s->netfd, data + bufLen, (int)(length - bufLen), 0, utime)) < 0){
    s->closedRead = 1;
    return ret;
  }

  if (bufLen > 0) {
    memcpy(data, s->buf+s->readPos, bufLen);
    s->readPos += bufLen;
  }
  return ret + (int)bufLen;
}
static int read_line(_http_session* s, char* line)
{
  char byte;
  do {
    if (read_body(s, &byte, 1) != 1)
      return -1; 
    *line++ = byte;
  } while (byte != '\n');
  *line++ = '\0';
  return 0;
}
int http_read(const http_session_t* session, char* data, size_t length)
{
  _http_session* s= (_http_session*)session;
  if (!s->http->context->thread || s->websocket) {
    errno = EPERM;
    return -1; /* quiting */
  }
  if (s->closedRead) {
    errno = EILSEQ;
    return -1; /* over */
  }
  if (s->chunkedRead) {
    char line[128];
    size_t n, i=0;
    for (; !s->closedRead && i < length; i += n) {
      if (s->chunkedLength == 0) {
        if (read_line(s, line) < 0) return -1;
        s->chunkedLength = atol(line);
        if (s->chunkedLength == 0)
          s->closedRead = 1;
      }
      n = length - i;
      if (n > s->chunkedLength) n = s->chunkedLength;
      if (read_body(s, data+i, n) != n) return -1;
      s->chunkedLength -= n;
      if (s->chunkedLength == 0) {
        if (read_line(s, line) < 0) return -1;
      }
    }
    return i;
  }
  if (s->request.contentLength >= 0) {
    if (s->chunkedLength + length >= (size_t)s->request.contentLength) {
      length = s->request.contentLength - s->chunkedLength;
      s->closedRead = 1;
    }
    s->chunkedLength += length;
  }
  return read_body(s, data, length);
}
int http_redirect(const http_session_t* session,  const char* url)
{
  if (http_set_status(session, 302)) return -1;
  return http_set_header(session,"Location", url);
}
int http_set_status(const http_session_t* session, int statusCode)
{
  _http_session* s= (_http_session*)session;
  if (!s->http->context->thread || s->status == 0 || s->closedWrite || s->websocket) {
    errno = EPERM;
    return -1;
  }
  if (statusCode <= 0) {
    errno = EINVAL;
    return -1;
  }
  s->status = statusCode;
  return 0;
}
int http_set_header(const http_session_t* request, const char* key, const char* val)
{
  size_t klen, vlen;
  http_header_t* header;
  _http_session* s= (_http_session*)request;
  if (!s->http->context->thread || s->status == 0 || s->closedWrite || s->websocket) {
    errno = EPERM;
    return -1;
  }
  if (!key || !val) {
    errno = EINVAL;
    return -1;
  }
  if (request->headerNumber + s->headerNumber >= sizeof(s->header)) {
    errno = ENOMEM;
    return -1;
  }
  while (isspace(*key)) ++key;
  while (isspace(*val)) ++val;
  klen = strlen(key);
  while (klen > 0 && isspace(key[klen-1])) --klen;
  if (!klen) return 0;

  vlen = strlen(val);
  while (vlen > 0 && isspace(val[vlen-1])) --vlen;
  if (s->writePos + klen + 1 + vlen + 2 > sizeof(s->buf)) {
    errno = ENOSPC;
    return -1;
  }

  if (http_strcmp(key, "Transfer-Encoding", klen) == 0)
    s->chunkedWrite = (strncmp(val, "chunked", vlen) == 0);
  else if (http_strcmp(key, "Content-Length", klen) == 0) {
    s->contentLength = atol(val);
    if (s->contentLength == -1) {
      errno = EINVAL;
      return -1;
    }
  }
  else if (http_strcmp(key, "Connection", klen) == 0) {
    if (strncmp(val, "close", vlen) == 0)
      s->keepAlive = 0;
    else if (strncmp(val, "keep-alive", vlen) == 0)
      s->keepAlive = 1;
    else if (strncmp(val, "Upgrade", vlen) == 0)
      s->keepAlive = 1;
  }

  header = s->header + request->headerNumber + s->headerNumber;
  header->key.ptr = s->buf + s->writePos;
  memcpy(header->key.ptr, key, klen);
  header->key.len = klen;
  s->writePos += klen;
  s->buf[s->writePos++] = ':';

  header->val.ptr = s->buf + s->writePos;
  memcpy(header->val.ptr, val, vlen);
  header->val.len = vlen;
  s->writePos += vlen;
  s->buf[s->writePos++] = '\r';
  s->buf[s->writePos++] = '\n';
  s->headerNumber++;
  return 0;
}
static const char* status_message(int status)
{
  switch (status) {
  case 101: return "Switching Protocols";
  case 200: return "OK";
  case 301: return "Moved Permanently";
  case 302: return "Found";
  case 303: return "See Other";
  case 304: return "Not Modified";
  case 400: return "Bad Request";
  case 403: return "Forbidden";
  case 404: return "Not Found";
  case 415: return "Unsupported Media Type";
  case 501: return "Not Implemented";
  default:
  case 500: return "Internal Server Error";
  }
}
static void log_response(http_t* http, _http_session* s)
{
  size_t i;
  if (!http->logPrintf) return;
  http->logPrintf(http->logFile, "> HTTP/1.1 %d %s\n", s->status, status_message(s->status));
  for (i=0; i<s->headerNumber; ++i) {
    http_header_t* h = s->header + s->request.headerNumber + i;
    http->logPrintf(http->logFile, "> %.*s: %.*s\n", (int)h->key.len, h->key.ptr, (int)h->val.len, h->val.ptr);
  }
  http->logPrintf(http->logFile, ">\n");
}
static int response_status_header(_http_session* s, size_t contentLength)
{
  char buf[128];
  int len = sprintf(buf, "HTTP/1.1 %d %s\r\n", s->status, status_message(s->status)); 
  int ret = st_send(s->netfd, buf, len, 0, ST_UTIME_NO_TIMEOUT);
  log_response(s->http, s);
  s->status = 0;
  if (ret < 0) return ret;
  if (!s->websocket && !s->chunkedWrite) {
    if (s->contentLength == -1) {
      char str[128];
      ret = sprintf(str, "%lu", contentLength);
      if (ret < 0) return ret;
      s->contentLength = contentLength;
      ret = http_set_header((http_session_t *)s, "Content-Length", str);
      if (ret < 0) return ret;
    }
    if (s->contentLength == 0) s->closedWrite = 1;
  }
  if (s->writePos > s->bufLen) {
    ret = st_send(s->netfd, s->buf+s->bufLen, s->writePos-s->bufLen, 0, ST_UTIME_NO_TIMEOUT);
    if (ret < 0) return ret;
  }
  return st_send(s->netfd, "\r\n", 2, 0, ST_UTIME_NO_TIMEOUT);
}
int http_write(const http_session_t* session, const char* data, size_t length)
{
  _http_session* s= (_http_session*)session;
  if (!s->http->context->thread || s->status == -1) {
    errno = EPERM;
    return -1; /* quiting nor status*/
  }
  if (s->closedWrite) {
    errno = EILSEQ;
    return -1; /* over */
  }
  if (s->status > 0 && response_status_header(s, length) < 0)
    return -1;
  if (s->websocket)
    return st_send(s->netfd, data, length, 0, ST_UTIME_NO_TIMEOUT);
  else if (s->chunkedWrite) {
    char chunked[128];
    int ret = sprintf(chunked, "%lx\r\n", length);
    if (ret < 0) return ret;
    ret = st_send(s->netfd, chunked, ret, 0, ST_UTIME_NO_TIMEOUT);
    if (ret < 0) return ret;
    if (length > 0) {
      ret = st_send(s->netfd, data, length, 0, ST_UTIME_NO_TIMEOUT);
      if (ret < 0) return ret;
    }
    else
      s->closedWrite = 1;
    return st_send(s->netfd, "\r\n", 2, 0, ST_UTIME_NO_TIMEOUT);
  }
  else if (s->contentLength >= 0) {
    if (s->contentOffset + length >= (size_t)s->contentLength) {
      length = s->contentLength - s->contentOffset;
      s->closedWrite = 1;
    }
    s->contentOffset += length;
  }
  return st_send(s->netfd, data, length, 0, ST_UTIME_NO_TIMEOUT);
}

static void free_session(http_context_t* ctx, _http_session *session)
{
  if (session->netfd) st_netfd_close(session->netfd);
  session->next = ctx->free_list;
  ctx->free_list = session;
}
static int pkeycmp(const void *k0, const void* k1)
{
  const http_key_t *a = *(const http_key_t**)k0;
  const http_key_t *b = *(const http_key_t**)k1;
  return keycmp(a, b);
}
static http_handler_t* find_handler(http_t* http, http_key_t* path)
{
  http_context_t *ctx = http->context;
  const size_t len0 = path->len;
  while (path->len > 0) {
    path->len--;
    if (path->ptr[path->len] == '/') {
      http_handler_t** ret = bsearch (&path, ctx->handler,
        ctx->handlerNumber, sizeof(http_handler_t*), pkeycmp);
      if (ret) {
        path->ptr += path->len + 1;
        path->len = len0 - path->len - 1;
        return *ret;
      }
    }
  }
  path->len = len0;
  if (path->len > 0 && path->ptr[0] == '/') {
    path->ptr++;
    path->len--;
  }
  return &http->root;
}
ssize_t http_parse_request(http_session_t* s, const size_t headerSize,
  const char* const bufptr, const char* const bufend,
  size_t *pos, char* state);
static void log_request(http_t* http, const http_session_t* session, http_handler_t* handler)
{
  size_t i;
  if (!http->logPrintf) return;
  http->logPrintf(http->logFile, "< %.*s %.*s/%.*s %.*s\n",
    (int)session->method.len, session->method.ptr,
    (int)handler->path.len,   handler->path.ptr,
    (int)session->path.len,   session->path.ptr,
    (int)session->version.len,session->version.ptr);
  for (i=0; i<session->headerNumber; ++i) {
    http_header_t* h = &session->header[i];
    http->logPrintf(http->logFile, "< %.*s: %.*s\n",
      (int)h->key.len, h->key.ptr, (int)h->val.len, h->val.ptr);
  }
  http->logPrintf(http->logFile, "<\n");
}
static void* session_thread(void* session)
{
  st_utime_t utime;
  ssize_t ret;
  char parser_state;
  http_handler_t* handler;
  _http_session *s = (_http_session*)session;
restart:
  handler = NULL;
  parser_state = '\0';
  s->websocket = 0;
  utime = st_utime();
  s->deadtime = utime + s->http->headerTimeout;
  s->readPos = s->bufLen = 0;
  s->request.headerNumber = s->headerNumber = 0;
  do {
    /* read the request */
    ret = st_recv(s->netfd, s->buf + s->bufLen,
      sizeof(s->buf) - s->bufLen, 0, s->deadtime - utime);
    if (!s->http->context->thread) return NULL;
    if (ret < 0) return "ReadError";
    s->bufLen += ret;
    if (s->bufLen == sizeof(s->buf))
      return "RequestIsTooLongError";

    /* parse the request */
    ret = http_parse_request(session, sizeof(s->header)/sizeof(s->header[0]),
      s->buf, s->buf + s->bufLen, &s->readPos, &parser_state);
    if (ret < 0) return "ParseError";
    else if (ret > 0) break; /* successfully parsed the request */

    /* request is incomplete, continue the loop */
    utime = st_utime();
    if (utime >= s->deadtime) return "Timeout";
  } while (1);

  qsort(s->request.header, s->request.headerNumber, sizeof(http_header_t), keycmp);
  handler = find_handler(s->http, &s->request.path);
  log_request(s->http, (http_session_t*)s, handler);

  do {
    const http_val_t* val = http_get_value((http_session_t*)s, "Connection");
    s->keepAlive = (val && http_strcmp(val->ptr, "keep-alive", val->len) == 0);
    s->request.contentLength = -1;
    val = http_get_value((http_session_t*)s, "Transfer-Encoding");
    s->chunkedRead = (val && http_strcmp(val->ptr, "chunked", val->len) == 0);
    if (!s->chunkedRead) {
      val = http_get_value((http_session_t*)s, "Content-Length");
      if (val)
        s->request.contentLength = atol(val->ptr);
      if (!val || s->request.contentLength < 0)
        s->keepAlive = 0;
    }
    s->status = -1;
    s->chunkedWrite = s->closedWrite = s->closedRead = 0;
    s->contentOffset = s->chunkedLength = 0;
    s->contentLength = -1;
    s->writePos = s->bufLen;
    s->deadtime += s->http->sessionTimeout - s->http->headerTimeout;
    handler->callback(handler, s->http, (http_session_t*)s);
    if (s->status == -1) s->status = 501; /* no status */
    if (s->status > 0 && response_status_header(s, 0) < 0)
      return "WriteHeader";
    if (!s->http->context->thread || s->websocket)
      break;
    else if (!s->closedWrite)
      return "Insufficient";
    else if (s->keepAlive)
      goto restart;
  } while(0);
  return NULL;
}
static _http_session* alloc_session(http_context_t* ctx, int stacksize)
{
  _http_session* session = ctx->free_list;
  if (session) 
    ctx->free_list = session->next;
  else if (!(session=malloc(sizeof(_http_session))))
    return NULL;
#ifndef NDEBUG
  memset(session, 0xFF, sizeof(_http_session));
#endif
  session->request.header = session->header;
  session->thread = st_thread_create(session_thread, session, 0, stacksize);
  if (!session->thread) {
    free_session(ctx, session);
    return NULL;
  }
  return session;
}
static void on_session_exit(void* arg, void* retval)
{
  _http_session *session = (_http_session*)arg;
  http_context_t* ctx = session->http->context;
  if (ctx->session == session)
    ctx->session = session->next;
  else {
    _http_session* prev = ctx->session;
    while (prev->next != session) prev = prev->next;
    prev->next = session->next;
  }
  free_session(ctx, session);
  if (!ctx->session && !ctx->thread)
    st_cond_signal(ctx->term);
}
static void term_context(http_context_t* ctx)
{
  if (ctx->term) st_cond_destroy(ctx->term);
  if (ctx->handler) free(ctx->handler);
  while (ctx->free_list) {
    _http_session* session = ctx->free_list;
    ctx->free_list = ctx->free_list->next;
    free(session);
  }
}
static int update_handlers(http_t* http, int delta)
{
  size_t num;
  http_handler_t* h;
  http_context_t* ctx = http->context;
  if (!ctx) return 0;

  num = ctx->handlerNumber + delta;
  ctx->handlerNumber = 0;
  if (num > ctx->handlerSize) {
    ctx->handlerSize = (num/16+1) * 16;
    if (ctx->handler) free(ctx->handler);
    ctx->handler = malloc(ctx->handlerSize * sizeof(http_handler_t*));
    if (!ctx->handler) {
      ctx->handlerSize = 0;
      return -1;
    }
  }
  h = http->root.next;
  while (h)  {
    while (h->path.len > 0 && h->path.ptr[h->path.len-1] == '/')
      h->path.len--;
    ctx->handler[ctx->handlerNumber++] = h;
    h = h->next;
  }
  qsort(ctx->handler, ctx->handlerNumber, sizeof(http_handler_t*), pkeycmp);
  return 0;
}
static int init_context(http_context_t* ctx, http_t* http)
{
  int num = 0;
  http_handler_t* h = http->root.next;
  memset(ctx, 0, sizeof(http_context_t));
  ctx->thread = st_thread_self();
  while (h) {
    if (!h->callback || !h->path.len || !h->path.ptr) {
      errno = EINVAL;
      return -1;
    }
    ++num;
    h = h->next;
  }
  http->context = ctx;
  if (!(ctx->term = st_cond_new())) return -1;
  if (update_handlers(http, num) == 0) return 0;
  term_context(ctx);
  return -1;
}
int http_loop(http_t* http, int port, int stacksize)
{
  st_netfd_t sfd;
  http_context_t ctx;
  _http_session* session;
  if (http->headerTimeout > http->sessionTimeout
    || !http->root.callback || !http->headerTimeout){
    errno = EINVAL;
    return -1;
  }
  if (init_context(&ctx, http) != 0)
    return -1;
  if (!(sfd = st_bind(AF_INET, IPPROTO_TCP, port, 128)))
    return -1;

  while (ctx.thread) {
    st_netfd_t cfd = st_accept(sfd, NULL, NULL, ST_UTIME_NO_TIMEOUT);
    if (!cfd) continue;
    session = alloc_session(&ctx, stacksize);
    if (!session) {
      st_netfd_close(cfd);
      continue;
    }
    session->http = http;
    session->netfd = cfd;
    session->next = ctx.session;
    ctx.session = session;
    st_thread_atexit(session->thread, on_session_exit, session);
  }
  st_netfd_close(sfd);
  if (ctx.session) {
    for (; ctx.session; ctx.session = ctx.session->next)
      st_thread_interrupt(ctx.session->thread);
    st_cond_wait(ctx.term);
  }
  http->context = NULL;
  term_context(&ctx);
  return 0;
}

void http_quit(http_t* http)
{
  if (http->context && http->context->thread) {
    st_thread_interrupt(http->context->thread);
    http->context->thread = NULL;
  }
}
static http_handler_t* handler_super(http_handler_t* h, const http_key_t* path)
{
  while (h->next) {
    if (!keycmp(&h->next->path, path))
      return h;
    h = h->next;
  }
  return NULL;
}
int http_mount(http_t* http, http_handler_t* handler)
{
  int num = 0;
  http_handler_t* h = handler;
  while (h) {
    if (!h->callback || !h->path.len || !h->path.ptr) {
      errno = EINVAL;
      return -1;
    }
    if (handler_super(&http->root, &h->path)) {
      if (http->logPrintf) {
        http->logPrintf(http->logFile, "# EEXIST %.*s\n", 
          (int)h->path.len, h->path.ptr);
      }
      errno = EEXIST;
      return -1;
    }
    if (http->logPrintf) {
      http->logPrintf(http->logFile, "# Mount %.*s\n", 
        (int)h->path.len, h->path.ptr);
    }
    ++num;
    if (!h->next) break;
    h = h->next;
  }
  if (!num) return 0;
  h->next = http->root.next;
  http->root.next = handler;
  return update_handlers(http, num);
}
int http_unmount(http_t* http, const char* path)
{
  int num = 0;
  http_key_t key;
  http_handler_t* h;
  if (!http || !path) return  0;
  key.ptr = (char*)path;
  key.len = strlen(path);
  while (key.len > 0 && key.ptr[key.len-1] == '/') key.len--;
  if (key.len == 0) return 0;

  h = &http->root;
  while (h = handler_super(h, &key)) {
    if (http->logPrintf) {
      http->logPrintf(http->logFile, "# Unmount %.*s\n", 
        (int)h->next->path.len, h->next->path.ptr);
    }
    h->next = h->next->next;
    ++num;
  }
  update_handlers(http, -num);
  return num;
}
int websocket_send(websocket_t* websocket, int flags, char* data, size_t size)
{
  unsigned char header[10], *p=header;
  *p++ = flags&0xff;
  if (size < 126)
    *p++ = size & 0xff;
  else if (size < 65536) {
    *p++ = 126;
    *p++ = (size >> 8) & 0xff;
    *p++ = (size >> 0) & 0xff;
  }
  else {
    int k;
    *p++ = 127;
    for (k=56; k>=0; k-= 8)
      *p++ = (size >> k) & 0xff;
  }
  if (flags&WS_MASK) {
    static const unsigned char masking_key[4] = { 0x12, 0x34, 0x56, 0x78 };
    size_t i;
    header[1] |=  0x80;
    *p++ = masking_key[0];
    *p++ = masking_key[1];
    *p++ = masking_key[2];
    *p++ = masking_key[3];
    for (i=0;i<size;++i)
      data[i] = data[i] ^ masking_key[i & 0x3];
  }
  http_write(websocket->session, header, p - header);
  http_write(websocket->session, data,size);
  return p - header + size;
}
int websocket_close(websocket_t* websocket)
{
  _http_session* s= (_http_session*)websocket->session;
  if (!s) {
    errno = EINVAL;
    return -1;
  }
  else {
    char bye[6] = { 0x88, 0x80, 0x00, 0x00, 0x00, 0x00 };
    st_thread_interrupt(s->thread);
    s->keepAlive = 0;
    return http_write(websocket->session, bye, 6);
  }
}
static ssize_t websocket_process(websocket_t* websocket, const void* buf, size_t len)
{
  size_t i;
  size_t ret = 0;
  _http_session* s = (_http_session*)websocket->session;
  while (ret+2 < len) {//Need at least 2
    unsigned char* data = (unsigned char*)buf + ret;
    const char fin = (data[0] & 0x80) == 0x80;
    const char opcode = (data[0] & 0x0f);
    const char mask = (data[1] & 0x80) == 0x80;
    size_t N = (data[1] & 0x7f);
    const size_t header_size = 2 + (N == 126 ? 2 : 0) + (N == 127 ? 8 : 0) + (mask ? 4 : 0);
    if (len -  ret < header_size)
      return ret;

    if (N == 126)
      N = (data[2] << 8) | (size_t)data[3];
    else if (N == 127) {
      N = 0;
      for (i=0; i< 8; ++i) 
        N = (N << 8) | data[2+i];
    }
    if (len - ret < header_size+N)
      return ret;

    if (mask) {
      const char* masking_key = data + header_size - 4;
      for (i = 0; i < N; ++i)
        data[i+header_size] ^= masking_key[i&0x3];
    }
    if (opcode == WS_CLOSE) {
      websocket->onclose(websocket, s->http);
      st_thread_exit(NULL);
    }
    else if (opcode == WS_PING)
      websocket_send(websocket, WS_PONG|WS_FIN, data+header_size, N);
    else
      websocket->onmessage(websocket, s->http, fin|opcode, data+header_size, N);
    ret += header_size + N;
  }
  return ret;
}
void SHA1(char digest[20], const void* data, size_t len);
void BASE64(char result[/* (len+2)/3x4 */], const void* data, size_t len);
static void websocket_accept_key(char sec_websocket_accept[28], const char sec_websocket_key[24])
{
  char digest[20]={0};
  char input[64];
  memcpy(input, sec_websocket_key, 24);
  strcpy(input+24, "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
  SHA1(digest, input, 24+36);
  BASE64(sec_websocket_accept, digest, 20);
}
int websocket_loop(websocket_t* websocket, const http_session_t* session, const char* protocal)
{
  int ret;
  _http_session* s= (_http_session*)session;
  if (!s || s->thread != st_thread_self()) {
    errno = EINVAL;
    return -1;
  }
  do {
    char sec_websocket_accept[29];
    const http_val_t* val = http_get_value(session, "Upgrade");
    if (!val) return -1;
    if (http_strcmp("websocket", val->ptr, val->len) != 0) return -1;
    if (!(val = http_get_value(session, "Connection"))) return -1;
    if (http_strcmp("upgrade", val->ptr, val->len) != 0) return -1;
    if (!(val = http_get_value(session, "Sec-WebSocket-Version"))) return -1;
    if (http_strcmp("13", val->ptr, val->len) != 0) return -1;
    if (!(val = http_get_value(session, "Sec-WebSocket-Key"))) return -1;
    if (val->len != 24) return -1;
    websocket_accept_key(sec_websocket_accept, val->ptr);
    sec_websocket_accept[28] = '\0';
    http_set_status(session, 101);
    http_set_header(session, "Upgrade", "websocket");
    http_set_header(session, "Connection", "Upgrade");
    http_set_header(session, "Sec-WebSocket-Accept", sec_websocket_accept);
    if (protocal) http_set_header(session, "Sec-WebSocket-Protocol", protocal);
  } while (0);
  s->websocket = 1;//destroy all http res
  if (response_status_header(s, 0) < 0)
    return -1;
  s->request.headerNumber = s->headerNumber = 0;
  s->bufLen = 0;
  s->keepAlive = 1;
  websocket->session = session;
  do {
    ret = st_recv(s->netfd, s->buf + s->bufLen,
      sizeof(s->buf) - s->bufLen, 0, ST_UTIME_NO_TIMEOUT);
    if (ret < 0) break;
    s->bufLen += ret;
    ret = websocket_process(websocket, s->buf, s->bufLen);
    if (ret < 0) break;
    s->bufLen -= ret;
    if (s->bufLen > 0 && ret > 0)
      memcpy(s->buf, s->buf+ret, s->bufLen);
  } while (s->keepAlive);
  if (!s->keepAlive) {
    websocket->onclose(websocket, s->http);
    st_thread_exit(NULL);
  }
  return ret;
}

