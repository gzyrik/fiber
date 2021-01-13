#define _CRT_SECURE_NO_WARNINGS
#include "../st.h"
#include "http.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
typedef struct _http_session  _http_session;
static ssize_t parse_request(_http_session *session);
struct _http_context {
  st_cond_t term;
  _http_session* session;
  _http_session* free_list;
  size_t handlerNumber, handlerSize;
  http_handler_t **handler;
  st_thread_t thread;
};

struct _http_session {
  http_session_t base;
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
  size_t writePos;/* writePos - bufLen is response header */
  size_t contentOffset;
  ssize_t contentLength;
};

static int skeyncmp(const char a[], const char b[], size_t len)
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
  return skeyncmp(a->ptr, b->ptr, a->len);
}
http_val_t* http_get_value(http_session_t* session, const char* key)
{
  http_key_t kt = {(char*)key, strlen(key)};
  http_header_t* ret = bsearch (&kt, session->header, session->headerNumber, sizeof(http_header_t), keycmp);
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
int http_read(http_session_t* session, char* data, size_t length)
{
  _http_session* s= (_http_session*)session;
  if (!s->http->context->thread) return -1; /* quiting */
  if (s->closedRead) return -1; /* over */
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
  if (s->base.contentLength >= 0) {
    if (s->chunkedLength + length >= (size_t)s->base.contentLength) {
      length = s->base.contentLength - s->chunkedLength;
      s->closedRead = 1;
    }
    s->chunkedLength += length;
  }
  return read_body(s, data, length);
}
int http_redirect(http_session_t* session,  const char* url)
{
  http_set_status(session, 302);
  return http_set_header(session,"Location", url);
}
int http_set_status(http_session_t* session, int statusCode)
{
  _http_session* s= (_http_session*)session;
  if (!s->http->context->thread) return -1; /* quiting */
  if (s->closedWrite) return -1; /* over */
  if (s->status == 0) return -1; /* already sent */
  if (statusCode <= 0) return -1;
  s->status = statusCode;
  return 0;
}
int http_set_header(http_session_t* session, const char* key, const char* val)
{
  size_t klen, vlen;
  va_list argv;
  _http_session* s= (_http_session*)session;
  if (!s->http->context->thread) return -1; /* quiting */
  if (s->closedWrite) return -1; /* over */
  if (s->status == 0) return -1; /* already sent */
  if (!key || !val) return -1;
  while (isspace(*key)) ++key;
  while (isspace(*val)) ++val;
  klen = strlen(key);
  while (klen > 0 && isspace(key[klen-1])) --klen;
  if (!klen) return 0;

  vlen = strlen(val);
  while (vlen > 0 && isspace(val[vlen-1])) --vlen;
  if (s->writePos + klen + 1 + vlen + 2 > sizeof(s->buf))
    return -1;
  memcpy(s->buf + s->writePos, key, klen);
  s->writePos += klen;
  s->buf[s->writePos++] = ':';
  memcpy(s->buf + s->writePos, val, vlen);
  s->writePos += vlen;
  s->buf[s->writePos++] = '\r';
  s->buf[s->writePos++] = '\n';

  if (skeyncmp(key, "Transfer-Encoding", klen) == 0)
    s->chunkedWrite = (strncmp(val, "chunked", vlen) == 0);
  else if (skeyncmp(key, "Content-Length", klen) == 0) {
    s->contentLength = atol(val);
    if (s->contentLength == -1) return -1;
  }
  else if (skeyncmp(key, "Connection", klen) == 0) {
    if (strncmp(val, "close", vlen) == 0)
      s->keepAlive = 0;
    else if (strncmp(val, "keep-alive", vlen) == 0)
      s->keepAlive = 1;
  }
  return 0;
}
static const char* status_message(int status)
{
  switch (status) {
  case 200: return "OK";
  case 301: return "Moved Permanently";
  case 302: return "Found";
  case 303: return "See Other";
  case 304: return "Not Modified";
  case 400: return "Bad Request";
  case 403: return "Forbidden";
  case 404: return "Not Found";
  case 415: return "Unsupported Media Type";
  default:
  case 500: return "Internal Server Error";
  }
}
static int response_status_header(_http_session* s, size_t contentLength)
{
  char buf[128];
  const char* statusMsg = status_message(s->status);
  int len = sprintf(buf, "HTTP/1.1 %d %s\r\n", s->status, statusMsg); 
  int ret = st_send(s->netfd, buf, len, 0, ST_UTIME_NO_TIMEOUT);
  if (ret < 0) return ret;
  if (!s->chunkedWrite && s->contentLength == -1) {
    char str[128];
    ret = sprintf(str, "%lu", contentLength);
    if (ret < 0) return ret;
    s->contentLength = contentLength;
    ret = http_set_header((http_session_t *)s, "Content-Length", str);
    if (ret < 0) return ret;
  }
  if (s->writePos > s->bufLen) {
    ret = st_send(s->netfd, s->buf+s->bufLen, s->writePos-s->bufLen, 0, ST_UTIME_NO_TIMEOUT);
    if (ret < 0) return ret;
  }
  s->status = 0;
  if (s->contentLength == 0 && !s->chunkedWrite) s->closedWrite = 1;
  return st_send(s->netfd, "\r\n", 2, 0, ST_UTIME_NO_TIMEOUT);
}
int http_write(http_session_t* session, const char* data, size_t length)
{
  _http_session* s= (_http_session*)session;
  if (!s->http->context->thread) return -1; /* quiting */
  if (s->closedWrite) return -1; /* over */
  if (s->status == -1) return -1; /* no status */
  if (s->status > 0 && response_status_header(s, length) < 0)
    return -1;
  if (s->chunkedWrite) {
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
  s->contentOffset += length;
  if (s->contentOffset > (size_t)s->contentLength) return -1;
  if (s->contentOffset == s->contentLength) s->closedWrite = 1;
  return st_send(s->netfd, data, length, 0, ST_UTIME_NO_TIMEOUT);
}

static void free_session(http_context_t* ctx, _http_session *session)
{
  if (session->netfd) st_netfd_close(session->netfd);
  session->next = ctx->free_list;
  ctx->free_list = session;
}
static int url_cmp(const void *k0, const void* k1)
{
  size_t i;
  const http_key_t *a = *(const http_key_t**)k0;
  const http_key_t *b = *(const http_key_t**)k1;
  if (a->len != b->len) return (int)(a->len - b->len);
  for (i=0; i<a->len; ++i) {
    int ret = a->ptr[i] - b->ptr[i];
    if (ret) return ret;
  }
  return 0;
}
static http_handler_t* find_handler(http_context_t *ctx, http_val_t* path)
{
  const size_t len0 = path->len;
  while (path->len > 0) {
    path->len--;
    if (path->ptr[path->len] == '/') {
      http_handler_t** ret = bsearch (&path, ctx->handler,
        ctx->handlerNumber, sizeof(http_handler_t*), url_cmp);
      if (ret) {
        path->ptr += path->len + 1;
        path->len = len0 - path->len - 1;
        return *ret;
      }
    }
  }
  return NULL;
}
static void* session_thread(void* session)
{
  st_utime_t utime;
  http_handler_t* handler = NULL;
  _http_session *s = (_http_session*)session;
restart:
  utime = st_utime();
  s->deadtime = utime + s->http->headerTimeout;
  do {
    /* read the request */
    ssize_t ret = st_recv(s->netfd, s->buf + s->bufLen,
      sizeof(s->buf) - s->bufLen, 0, s->deadtime - utime);
    if (ret < 0) return "ReadError";

    s->bufLen += ret;
    if (s->bufLen == sizeof(s->buf))
      return "RequestIsTooLongError";

    /* parse the request */
    ret = parse_request(s);
    if (!handler && s->base.path.len > 0) {
      handler = find_handler(s->http->context, &s->base.path);
      if (!handler) return "NoHandlerError";
    }
    if (ret > 0) {
      s->readPos = ret;
      qsort(s->base.header, s->base.headerNumber, sizeof(http_header_t), keycmp);
      break; /* successfully parsed the request */
    }
    else if (ret < 0)
      return "ParseError";
    /* request is incomplete, continue the loop */
    utime = st_utime();
    if (utime >= s->deadtime)
      return "Timeout";
  } while (1);
  do {
    void* retval;
    http_val_t* val = http_get_value((http_session_t*)s, "Connection");
    s->keepAlive = (val && skeyncmp(val->ptr, "keep-alive", val->len) == 0);
    s->base.contentLength = -1;
    val = http_get_value((http_session_t*)s, "Transfer-Encoding");
    s->chunkedRead = (val && skeyncmp(val->ptr, "chunked", val->len) == 0);
    if (!s->chunkedRead) {
      val = http_get_value((http_session_t*)s, "Content-Length");
      if (val)
        s->base.contentLength = atol(val->ptr);
      if (!val || s->base.contentLength < 0)
        s->keepAlive = 0;
    }
    s->status = -1;
    s->chunkedWrite = s->closedWrite = s->closedRead = 0;
    s->contentOffset = s->chunkedLength = 0;
    s->contentLength = -1;
    s->writePos = s->bufLen;
    s->deadtime += s->http->sessionTimeout - s->http->headerTimeout;
    retval = handler->callback(handler, s->http, (http_session_t*)s);
    if (s->status == -1) s->status = 500; /* no status */
    if (s->status > 0 && response_status_header(s, 0) < 0)
      return "WriteHeader";
    if (!s->closedWrite) return "Insufficient";
    if (!retval && s->keepAlive) goto restart;
    return retval;
  } while(0);
}
static _http_session* alloc_session(http_context_t* ctx, int stacksize)
{
  _http_session* session = ctx->free_list;
  if (session) {
    ctx->free_list = session->next;
    memset(session, 0, sizeof(_http_session));
  }
  else {
    session = calloc(1, sizeof(_http_session));
    if (!session) return NULL;
  }
  session->base.header = session->header;
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
static int update_handlers(http_t* http, size_t num)
{
  http_handler_t* h;
  http_context_t* ctx = http->context;
  if (!ctx) return 0;

  ctx->handlerNumber += num;
  if (ctx->handlerNumber > ctx->handlerSize) {
    ctx->handlerSize = (ctx->handlerNumber/16+1) * 16;
    if (ctx->handler) free(ctx->handler);
    ctx->handler = calloc(ctx->handlerSize, sizeof(http_handler_t*));
    if (!ctx->handler) return -1;
  }
  num = 0;
  h = http->handler;
  while (h)  {
    while (h->path.len > 0 && h->path.ptr[h->path.len-1] == '/')
      h->path.len--;
    ctx->handler[num++] = h;
    h = h->next;
  }
  if (num != ctx->handlerNumber) return -1;
  qsort(ctx->handler, ctx->handlerNumber, sizeof(http_handler_t*), url_cmp);
  return 0;
}
static int init_context(http_context_t* ctx, http_t* http)
{
  size_t num = 0;
  http_handler_t* h = http->handler;
  memset(ctx, 0, sizeof(http_context_t));
  ctx->thread = st_thread_self();
  while (h) {
    if (!h->callback || !h->path.len || !h->path.ptr) return -1;
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
    || !http->handler || !http->headerTimeout)
    return -1;
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
int http_mount(http_t* http, http_handler_t* handler)
{
  size_t num = 0;
  http_handler_t* h = handler;
  while (h) {
    if (!h->callback || !h->path.len || !h->path.ptr) return -1;

    ++num;
    if (!h->next) break;
    h = h->next;
  }
  if (!num) return 0;
  h->next = http->handler;
  http->handler = handler;
  return update_handlers(http, num);
}
struct phr_header;
int phr_parse_request(const char *buf_start, size_t len, const char **method, size_t *method_len,
  const char **path, size_t *path_len, int *minor_version,
  struct phr_header *headers, size_t *num_headers, size_t last_len);
static ssize_t parse_request(_http_session *session)
{
  int ret;
  http_session_t* base = &session->base;
  base->headerNumber = sizeof(session->header) / sizeof(http_header_t);
  ret = phr_parse_request(session->buf, session->bufLen,
    &base->method.ptr, &base->method.len,
    &base->path.ptr, &base->path.len, &base->minor,
    (struct phr_header*)session->header, &base->headerNumber, 0);
  if (ret == -2) return 0;
  return ret;
}
