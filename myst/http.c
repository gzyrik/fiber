#define _CRT_SECURE_NO_WARNINGS
#include "http.h"
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
static void* bsearchp(const void *key, const void *base, size_t n, size_t size,
  int(*compar)(const void *, const void *), size_t* pos)
{
  size_t k = 0;
  while (k < n) {
    const size_t i = (k + n) / 2;
    void* val = (char*)base + size * i;
    const int cmp = compar(key, val);
    if (cmp > 0) k = i + 1;
    else if (cmp < 0) n = i;
    else {
      *pos = i;
      return val;
    }
  }
  *pos = k;
  return NULL;
}
static void http_log(http_t *http, const char* format, ...) 
{
  va_list args;
  if (!http || !http->logPrintf) return;
  va_start (args, format);
  http->logPrintf(http->logFile, format, args);
  va_end (args);
}
typedef struct _http_session  _http_session;
struct _http_context {
  st_cond_t term;
  _http_session* session;
  _http_session* free_list;
  size_t handlerNumber, handlerSize;
  http_handler_t **handler;
  st_thread_t thread;
};

typedef struct {
  http_session_t base;
  size_t readLen;
  size_t readPos;/* readLen - readPos is the part of request body*/
  size_t chunkedLength;
  char chunkedRead: 1;
  char closedRead: 1;
  char *buf;
} _http_request;

typedef struct {
  int status;
  char chunkedWrite: 1;
  char closedWrite : 1;
  http_header_t *header; /*= request.base.header + request.base.headerNumber, < http->headerMaxNumber*2 */
  size_t headerNumber; /* header[request.headerNumber, headerNumber) is response header */
  size_t contentOffset;
  ssize_t contentLength;
  char *buf;/*= request.buf + request.readLen,  < http.headerBufferSize x 2 */
} _http_response;

struct _http_session {
  _http_request request;
  _http_response response;
  _http_session* next;
  http_t* http;
  st_thread_t thread;
  st_netfd_t netfd;
  st_utime_t deadtime;

  const char *bufEnd;
  const http_header_t* headerEnd;
  http_key_t path;
  char keepAlive: 1;
  char websocket : 1;
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
static int keycmp1(const void *k0, const char* str)
{
  const http_key_t *a = k0;
  return http_strcmp(a->ptr, str, a->len);
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
  _http_request* request = &s->request;
  size_t bufLen;
  st_utime_t utime;
  if (length == 0) return 0;
  utime = st_utime();
  utime = utime >= s->deadtime ? 0 : s->deadtime - utime;
  bufLen = request->readLen - request->readPos;
  if (bufLen >= length)
    bufLen = length;
  else if ((ret = st_recv(s->netfd, data + bufLen, (int)(length - bufLen), 0, utime)) < 0){
    request->closedRead = 1;
    return ret;
  }

  if (bufLen > 0) {
    memcpy(data, request->buf+request->readPos, bufLen);
    request->readPos += bufLen;
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
  _http_request* request;
  _http_session* s= (_http_session*)session;
  if (!s || !s->http->context->thread || s->websocket) {
    errno = EPERM;
    return -1; /* quiting */
  }
  request = &s->request;
  if (request->closedRead) {
    errno = EILSEQ;
    return -1; /* over */
  }
  if (request->chunkedRead) {
    char line[128];
    size_t n, i=0;
    for (; !request->closedRead && i < length; i += n) {
      if (request->chunkedLength == 0) {
        if (read_line(s, line) < 0) return -1;
        request->chunkedLength = atol(line);
        if (request->chunkedLength == 0)
          request->closedRead = 1;
      }
      n = length - i;
      if (n > request->chunkedLength) n = request->chunkedLength;
      if (read_body(s, data+i, n) != n) return -1;
      request->chunkedLength -= n;
      if (request->chunkedLength == 0) {
        if (read_line(s, line) < 0) return -1;
      }
    }
    return i;
  }
  if (request->base.contentLength >= 0) {
    if (request->chunkedLength + length >= (size_t)request->base.contentLength) {
      length = request->base.contentLength - request->chunkedLength;
      request->closedRead = 1;
    }
    request->chunkedLength += length;
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
  _http_response* response;
  _http_session* s= (_http_session*)session;
  if (!s || !s->http->context->thread || s->websocket) {
    errno = EPERM;
    return -1;
  }
  response = &s->response;
  if (response->status == 0 || response->closedWrite) {
    errno = EPERM;
    return -1;
  }
  if (statusCode <= 0) {
    errno = EINVAL;
    return -1;
  }
  response->status = statusCode;
  return 0;
}
static int check_write_header(_http_session* s, http_key_t* key, http_val_t* val)
{
  _http_response* response = &s->response;
  if (keycmp1(key, "Transfer-Encoding") == 0)
    response->chunkedWrite = (keycmp1(val, "chunked") == 0);
  else if (keycmp1(key, "Content-Length") == 0) {
    response->contentLength = atol(val->ptr);
    if (response->contentLength == -1) {
      errno = EINVAL;
      return -1;
    }
  }
  else if (keycmp1(key, "Connection") == 0) {
    if (keycmp1(val, "close") == 0)
      s->keepAlive = 0;
    else if (keycmp1(val, "keep-alive") == 0)
      s->keepAlive = 1;
    else if (keycmp1(val, "Upgrade") == 0)
      s->keepAlive = 1;
  }
  return 0;
}
const http_val_t* http_get_header(const http_session_t* session, const char* str)
{
  http_key_t key;
  _http_response* response;
  _http_session* s = (_http_session*)session;
  if (!s || !s->http->context->thread || s->websocket) {
    errno = EPERM;
    return NULL;
  }
  response = &s->response;
  if (response->status == 0 || response->closedWrite) {
    errno = EPERM;
    return NULL;
  }
  if (!str) {
    errno = EINVAL;
    return NULL;
  }
  while (isspace(*str)) ++str;
  key.ptr = (char*)str;
  key.len = strlen(str);
  while (key.len > 0 && isspace(str[key.len-1])) --key.len;
  if (!key.len) return NULL;

  return bsearch(&key, response->header, response->headerNumber,
    sizeof(http_header_t), keycmp);
}
int http_set_header(const http_session_t* session, const char* str, const char* fmt, ...)
{
  http_key_t key, val;
  _http_response* response;
  http_header_t* header;
  _http_session* s = (_http_session*)session;
  if (!s || !s->http->context->thread || s->websocket) {
    errno = EPERM;
    return -1;
  }
  response = &s->response;
  if (response->status == 0 || response->closedWrite) {
    errno = EPERM;
    return -1;
  }
  if (!str || !fmt) {
    errno = EINVAL;
    return -1;
  }
  do {
    va_list argv;
    while (isspace(*str)) ++str;
    key.ptr = (char*)str;
    key.len = strlen(str);
    while (key.len > 0 && isspace(str[key.len-1])) --key.len;
    if (!key.len) return 0;

    va_start(argv,fmt);
    val.ptr = response->buf;
    while (isspace(*fmt)) ++fmt;
    val.len = vsprintf(val.ptr, fmt, argv);
    va_end(argv);
    while (val.len > 0 && isspace(val.ptr[val.len-1]))
      --val.len;
    if (check_write_header(s, &key, &val) < 0)
      return -1;
  } while (0);
  do {
    size_t pos;
    header = bsearchp(&key, response->header, response->headerNumber,
      sizeof(http_header_t), keycmp, &pos);
    if (header) {
      if (pos < response->headerNumber) {
        memmove(response->header+pos+1, response->header+pos,
          sizeof(http_header_t*) * response->headerNumber - pos);
      }
      header = response->header+pos;
      free(header->key.ptr);
    }
    else if (response->header + response->headerNumber >= s->headerEnd) {
      errno = ENOMEM;
      return -1;
    }
    else
      header = &response->header[response->headerNumber++];
  } while (0);
  header->key.ptr = malloc(key.len + val.len);
  memcpy(header->key.ptr, key.ptr,  key.len);
  header->key.len = key.len;
  header->val.ptr = header->key.ptr + key.len;
  memcpy(header->val.ptr, val.ptr,  val.len);
  header->val.len = val.len;
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
  _http_response* response = &s->response;
  http_log(http, "> HTTP/1.1 %d %s\n",
    response->status, status_message(response->status));
  for (i=0; i<response->headerNumber; ++i) {
    http_header_t* h = &response->header[i];
    http_log(http, "> %.*s: %.*s\n",
      (int)h->key.len, h->key.ptr, (int)h->val.len, h->val.ptr);
  }
  http_log(http, ">\n");
}
static int response_status_header(_http_session* s, size_t contentLength)
{
  int ret;
  size_t i, len=0;
  _http_response* response = &s->response;
  if (!s->websocket && !response->chunkedWrite) {
    if (response->contentLength == -1) {
      char str[128];
      ret = sprintf(str, "%lu", contentLength);
      if (ret < 0) return ret;
      response->contentLength = contentLength;
      ret = http_set_header((http_session_t *)s, "Content-Length", str);
      if (ret < 0) return ret;
    }
    if (response->contentLength == 0) response->closedWrite = 1;
  }
  log_response(s->http, s);
  len += sprintf(response->buf + len, "HTTP/1.1 %d %s\r\n",
    response->status, status_message(response->status)); 
  for (i=0; i<response->headerNumber; ++i) {
    http_header_t* h = &response->header[i];
    len += sprintf(response->buf + len, "%.*s: %.*s\r\n", 
      (int)h->key.len, h->key.ptr, (int)h->val.len, h->val.ptr);
    free(h->key.ptr);
  }
  response->headerNumber = 0;
  len += sprintf(response->buf + len, "\r\n");
  response->status = 0;
  return st_send(s->netfd, response->buf, len, 0, ST_UTIME_NO_TIMEOUT);
}
int http_write(const http_session_t* session, const char* data, size_t length)
{
  _http_session* s= (_http_session*)session;
  _http_response* response;
  if (!s || !s->http->context->thread) {
    errno = EPERM;
    return -1; /* quiting nor status*/
  }
  response = &s->response;
  if (response->status  == -1 || response->closedWrite) {
    errno = EILSEQ;
    return -1; /* over */
  }
  if (response->status > 0 && response_status_header(s, length) < 0)
    return -1;
  if (s->websocket)
    return st_send(s->netfd, data, length, 0, ST_UTIME_NO_TIMEOUT);
  else if (response->chunkedWrite) {
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
      response->closedWrite = 1;
    return st_send(s->netfd, "\r\n", 2, 0, ST_UTIME_NO_TIMEOUT);
  }
  else if (response->contentLength >= 0) {
    if (response->contentOffset + length >= (size_t)response->contentLength) {
      length = response->contentLength - response->contentOffset;
      response->closedWrite = 1;
    }
    response->contentOffset += length;
  }
  return st_send(s->netfd, data, length, 0, ST_UTIME_NO_TIMEOUT);
}

static void free_session(http_context_t* ctx, _http_session *session)
{
  if (session->response.headerNumber != 0) abort();
  if (session->request.base.header) free(session->request.base.header);
  if (session->request.buf) free(session->request.buf);
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
  http_handler_t* h;
  http_context_t *ctx = http->context;
  const size_t len0 = path->len;
  while (path->len > 0) {
    path->len--;
    if (path->ptr[path->len] == '/') {
      http_key_t str;
      http_handler_t** ret = bsearch (&path, ctx->handler,
        ctx->handlerNumber, sizeof(http_handler_t*), pkeycmp);
      if (!ret) continue;
      h = *ret;
      str.ptr = path->ptr + path->len + 1;
      str.len = len0 - path->len - 1;
      while (h) {
        if (!h->pattern.ptr || !h->pattern.len
          || http_regex_match(&str, &h->pattern, NULL) > 0)
          break;
        h = h->next;
      }
      if (!h) continue;
      *path = str;
      return h;
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
static void log_request(http_t* http, const _http_session* s)
{
  size_t i;
  const http_session_t* request = &s->request.base;
  if (!http|| !s || !http->logPrintf) return;
  http_log(http, "< %.*s %.*s %.*s\n",
    (int)request->method.len, request->method.ptr,
    (int)s->path.len, s->path.ptr,
    (int)request->version.len, request->version.ptr);
  for (i=0; i<request->headerNumber; ++i) {
    http_header_t* h = &request->header[i];
    http_log(http, "< %.*s: %.*s\n",
      (int)h->key.len, h->key.ptr, (int)h->val.len, h->val.ptr);
  }
  http_log(http, "<\n");
}
static http_handler_t* init_session(_http_session *s)
{
  http_handler_t* handler; 
  const http_val_t* val;
  _http_request* request = &s->request;
  http_session_t* base = &request->base;
  _http_response* response= &s->response;
  s->websocket = 0;
  s->path = base->path;

  qsort(base->header, base->headerNumber, sizeof(http_header_t), keycmp);
  request->closedRead = 0;
  request->chunkedLength = 0;
  val = http_get_value((http_session_t*)s, "Connection");
  s->keepAlive = (val && keycmp1(val, "keep-alive") == 0);
  base->contentLength = -1;
  val = http_get_value((http_session_t*)s, "Transfer-Encoding");
  request->chunkedRead = (val && keycmp1(val, "chunked") == 0);
  if (!request->chunkedRead) {
    val = http_get_value((http_session_t*)s, "Content-Length");
    if (val)
      base->contentLength = atol(val->ptr);
    if (!val || base->contentLength < 0)
      s->keepAlive = 0;
  }

  handler = find_handler(s->http, &base->path);
  log_request(s->http, s);

  response->status = -1;
  response->chunkedWrite = response->closedWrite = 0;
  response->contentOffset = 0;
  response->contentLength = -1;
  response->headerNumber = 0;
  response->buf = request->buf + request->readLen;
  response->header = base->header + base->headerNumber;

  s->deadtime += s->http->sessionTimeout - s->http->headerTimeout;
  return handler;
}
static void* session_thread(void* session)
{
  st_utime_t utime;
  ssize_t ret;
  char parser_state;
  _http_session *s = (_http_session*)session;
  http_t* http = s->http;
  _http_request* request = &s->request;
restart:
  parser_state = '\0';
  utime = st_utime();
  s->deadtime = utime + s->http->headerTimeout;
  s->request.readPos = s->request.readLen = 0;
  s->request.base.headerNumber = 0;
  do {
    /* read the request */
    ret = st_recv(s->netfd, request->buf + request->readLen,
      http->headerBufferSize - request->readLen, 0, s->deadtime - utime);
    if (!http->context->thread) return NULL;
    if (ret < 0) return "ReadError";
    request->readLen += ret;
    if (request->readLen >= http->headerBufferSize)
      return "RequestIsTooLongError";

    /* parse the request */
    ret = http_parse_request(session, http->headerMaxNumber,
      request->buf, request->buf + request->readLen, &request->readPos, &parser_state);
    if (ret < 0) return "ParseError";
    else if (ret > 0) break; /* successfully parsed the request */

    /* request is incomplete, continue the loop */
    utime = st_utime();
    if (utime >= s->deadtime) return "Timeout";
  } while (1);
  do {
    _http_response* response= &s->response;
    http_handler_t* h = init_session(s);
    while (h && response->status != 0) {
      if (!h->pattern.ptr || !h->pattern.len
        || http_regex_match(&request->base.path, &h->pattern, NULL) > 0)
        h->callback(h, http, (http_session_t*)s);
      h = h->next;
    }
    if (response->status == -1) response->status = 200; /* no status */
    if (response->status > 0 && response_status_header(s, 0) < 0)
      return "WriteHeader";
    if (!http->context->thread || s->websocket)
      break;
    else if (!response->closedWrite)
      return "Insufficient";
    else if (s->keepAlive)
      goto restart;
  } while(0);
  return NULL;
}
static _http_session* alloc_session(http_t* http, int stacksize)
{
  http_context_t* ctx = http->context;
  _http_session* session = ctx->free_list;
  if (session) 
    ctx->free_list = session->next;
  else if (!(session=malloc(sizeof(_http_session))))
    return NULL;
#ifndef NDEBUG
  memset(session, 0xFF, sizeof(_http_session));
#endif
  session->thread = NULL;
  session->request.base.header = NULL;
  session->request.buf = malloc(http->headerBufferSize*2);
  if (!session->request.buf) goto clean;
  session->bufEnd = session->request.buf + http->headerBufferSize*2;
  session->request.base.header = malloc(http->headerMaxNumber*2*sizeof(http_header_t));
  if (!session->request.base.header) goto clean;
  session->headerEnd = session->request.base.header + http->headerMaxNumber*2;

  session->thread = st_thread_create(session_thread, session, 0, stacksize);
  if (session->thread) return session;
clean:
  free_session(ctx, session);
  return NULL;
}
static void on_session_exit(void* arg, void* retval)
{
  _http_session *session = (_http_session*)arg;
  http_context_t* ctx = session->http->context;
  if (ctx->session == session)
    ctx->session = session->next;
  else if (ctx->session) {
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
static int add_handler(http_context_t* ctx, http_handler_t* handler)
{
  size_t pos;
  http_handler_t** ph;
  ph = bsearchp(&handler, ctx->handler, ctx->handlerNumber, sizeof(http_handler_t*), pkeycmp, &pos);
  if (ph) {
    if (!handler->pattern.ptr || !handler->pattern.len) {
      http_handler_t* tail = *ph;
      while (tail->next) tail = tail->next;
      tail->next = handler;
      handler->next = NULL;
    }
    else {
      handler->next = *ph;
      *ph = handler;
    }
    return 0;
  }
  if (ctx->handlerNumber >= ctx->handlerSize) {
    ctx->handlerSize += (ctx->handlerNumber/16+1) * 16;
    ctx->handler = realloc(ctx->handler, ctx->handlerSize * sizeof(http_handler_t*));
    if (!ctx->handler) return -1;
  }
  if (pos < ctx->handlerNumber)
    memmove(ctx->handler+pos+1, ctx->handler+pos, sizeof(http_handler_t*) * ctx->handlerNumber - pos);
  handler->next = NULL;
  ctx->handler[pos] = handler;
  ctx->handlerNumber++;
  return 0;
}
static int init_context(http_context_t* ctx, http_t* http)
{
  http_handler_t* h = http->root.next;
#ifndef NDEBUG
  memset(ctx, 0xFF, sizeof(http_context_t));
#endif
  ctx->free_list = NULL;
  ctx->handlerNumber = 0;
  ctx->handlerSize = 0;
  ctx->handler = NULL;
  ctx->thread = st_thread_self();
  while (h) {
    ctx->handlerSize++;
    h = h->next;
  }
  if (ctx->handlerSize > 0) {
    ctx->handler = calloc(ctx->handlerSize, sizeof(http_handler_t*));
    if (!ctx->handler) return -1;
  }
  h = http->root.next;
  http->root.path.ptr = "/";
  http->root.path.len = 0;
  http->root.next = NULL;
  http->context = ctx;
  if (!(ctx->term = st_cond_new())) return -1;
  if (http_mount(http, h) == 0) return 0;
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

  http_log(http, "# Start port %d\n", port);
  while (ctx.thread) {
    st_netfd_t cfd = st_accept(sfd, NULL, NULL, ST_UTIME_NO_TIMEOUT);
    if (!cfd) continue;
    session = alloc_session(http, stacksize);
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
  http_log(http, "# Quit port %d\n", port);
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
int http_mount(http_t* http, http_handler_t* h)
{
  while (h) {
    http_handler_t* next = h->next;
    if (!h->callback) {
      errno = EINVAL;
      return -1;
    }
    while (h->path.len > 0 && h->path.ptr[h->path.len-1] == '/')
      h->path.len--;
    if (http->context) {
      if (add_handler(http->context, h) < 0)
        return -1;
      http_log(http, "# Mount %.*s/%.*s\n",
        (int)h->path.len, h->path.ptr, (int)h->pattern.len, h->pattern.ptr);
    }
    else {
      h->next = http->root.next;
      http->root.next = h;
    }
    h = next;
  }
  return 0;
}
int http_unmount(http_t* http, http_key_t* path)
{
  int n = 0;
  http_handler_t* h;
  if (!http || !path) return -1;
  while (path->len > 0 && path->ptr[path->len-1] == '/') path->len--;
  if (path->len == 0) return 0;
  if (!http->context) {
    h = handler_super(&http->root, path);
    if (!h) return 0;
    do {
      ++n;
      h->next = h->next->next;
      h = handler_super(h, path);
    } while (h);
  }
  else {
    size_t pos;
    http_context_t* ctx = http->context;
    http_handler_t** ret = bsearchp (&path, ctx->handler,
      ctx->handlerNumber, sizeof(http_handler_t*), pkeycmp, &pos);
    if (!ret) return 0;
    h = *ret;
    if (ctx->handlerNumber > pos + 1)
      memmove(ret, ret+1, sizeof(http_handler_t) * (ctx->handlerNumber - pos - 1));
    ctx->handlerNumber--;
    do {
      ++n;
      h = h->next;
    } while(h);
  }
  http_log(http, "# Unmount %d '%.*s/' \n", n, (int)path->len, path->ptr);
  return n;
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
  http_write(websocket->session, (char*)header, p - header);
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
    http_log(s->http, "> WS_CLOSE\n");
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
      const unsigned char* masking_key = data + header_size - 4;
      for (i = 0; i < N; ++i)
        data[i+header_size] ^= masking_key[i&0x3];
    }
    if (opcode == WS_CLOSE) {
      http_log(s->http, "< WS_CLOSE\n");
      websocket->onclose(websocket, s->http);
      st_thread_exit(NULL);
    }
    else if (opcode == WS_PING)
      websocket_send(websocket, WS_PONG|WS_FIN, (char*)data+header_size, N);
    else
      websocket->onmessage(websocket, s->http, fin|opcode, (char*)data+header_size, N);
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
  size_t readLen = 0;
  _http_response* response;
  _http_session* s = (_http_session*)session;
  if (!s || s->thread != st_thread_self()) {
    errno = EINVAL;
    return -1;
  }
  do {
    char sec_websocket_accept[29];
    const http_val_t* val = http_get_value(session, "Upgrade");
    if (!val) return -1;
    if (keycmp1(val, "websocket") != 0) return -1;
    if (!(val = http_get_value(session, "Connection"))) return -1;
    if (keycmp1(val, "upgrade") != 0) return -1;
    if (!(val = http_get_value(session, "Sec-WebSocket-Version"))) return -1;
    if (keycmp1(val, "13") != 0) return -1;
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
  s->keepAlive = 1;
  websocket->session = session;
  response= &s->response;
  do {
    ret = st_recv(s->netfd, response->buf + readLen,
      s->bufEnd - response->buf - readLen, 0, ST_UTIME_NO_TIMEOUT);
    if (ret < 0) break;
    readLen += ret;
    ret = websocket_process(websocket, response->buf, readLen);
    if (ret < 0) break;
    readLen -= ret;
    if (readLen > 0 && ret > 0)
      memcpy(response->buf, response->buf + ret, readLen);
  } while (s->keepAlive);
  if (!s->keepAlive) {
    websocket->onclose(websocket, s->http);
    st_thread_exit(NULL);
  }
  return ret;
}
static int proxy_pass_headers(st_netfd_t sockfd, _http_session* s, const char* url)
{
  size_t bufLen = 0, i;
  http_session_t* session = (http_session_t*)s;
  _http_response* response = &s->response;
  http_t* http = s->http;
  const char* p = strchr(url, '/');//path
  bufLen += sprintf(response->buf+bufLen, "%.*s", (int)session->method.len, session->method.ptr);
  if (!p)
    bufLen += sprintf(response->buf+bufLen, " %.*s", (int)s->path.len, s->path.ptr);
  else if (!p[1])
    bufLen += sprintf(response->buf+bufLen, " /%.*s", (int)session->path.len, session->path.ptr);
  else
    bufLen += sprintf(response->buf+bufLen, " %s%.*s", p, (int)session->path.len, session->path.ptr);
  bufLen += sprintf(response->buf+bufLen, " %.*s\r\n", (int)session->version.len,session->version.ptr);
  http_log(http, "> %.*s\n", (int)(bufLen-2), response->buf);
  for (i=0; i<session->headerNumber; ++i) {
    int len;
    char* str = response->buf+bufLen;
    http_header_t* h = bsearch(&session->header[i], response->header,
      response->headerNumber, sizeof(http_header_t), keycmp);
    if (h) continue;
    h = &session->header[i];
    if (keycmp1(&h->key, "Host") == 0) {
      len = p ? p - url : strlen(url);
      len = sprintf(str, "Host: %.*s\r\n", len, url);
    }
    else {
      len = sprintf(str, "%.*s: %.*s\r\n",
        (int)h->key.len, h->key.ptr, (int)h->val.len, h->val.ptr);
    }
    http_log(http, "> %.*s\n", (int)(len-2), str);
    bufLen += len;
  }
  for (i=0; i<response->headerNumber; ++i) {
    int len;
    char* str = response->buf+bufLen;
    http_header_t* h =  &response->header[i];
    len = sprintf(str, "%.*s: %.*s\r\n",
      (int)h->key.len, h->key.ptr, (int)h->val.len, h->val.ptr);
    http_log(http, "> %.*s\n", (int)(len-2), str);
    bufLen += len;
    free(h->key.ptr);
  }
  response->headerNumber = 0;
  bufLen += sprintf(response->buf+bufLen,"\r\n");
  http_log(http, ">\n");
  return st_send(sockfd, response->buf, bufLen, 0, ST_UTIME_NO_TIMEOUT);
}
int http_proxy_loop(const http_session_t* session, const char* url)
{
  const char* p;
  int ret;
  http_t *http;
  st_netfd_t sockfd;
  struct sockaddr_storage sa;
  _http_session* s = (_http_session*)session;
  if (!s || !url) {
    errno = EINVAL;
    return -1;
  }
  http = s->http;
  p = strstr(url, "://");
  url = !p ? url : p+3;
  ret = st_sockaddr((struct sockaddr*)&sa, AF_UNSPEC, url, 80);
  if (ret <=0 ) {
    errno = EPERM;
    http_log(http, "# EPERM URL '%s'\n", url);
    return -1;
  }
  sockfd = st_socket(AF_INET, SOCK_STREAM, 0);
  if (!sockfd) return -1;
  ret = st_connect(sockfd, (struct sockaddr*)&sa, ret, ST_UTIME_NO_TIMEOUT);
  if (ret < 0) goto clean;
  proxy_pass_headers(sockfd, s, url);

  while (!s->request.closedRead) {
    _http_response* response = &s->response;
    ret = http_read(session, response->buf, s->bufEnd - response->buf);
    if (ret > 0) st_send(sockfd, response->buf, ret, 0, ST_UTIME_NO_TIMEOUT);
  }
  while (1) {
    _http_response* response = &s->response;
    ret = st_recv(sockfd, response->buf, s->bufEnd - response->buf, 0, s->http->sessionTimeout);
    if (ret <= 0) goto clean;
    st_send(s->netfd, response->buf, ret, 0, ST_UTIME_NO_TIMEOUT);
  }
clean:
  st_netfd_close(sockfd);
  if (ret >=0 || !http->context->thread)
    st_thread_exit(NULL);
  http_log(http, "# Proxy failed '%.*s' ~>'%s'\n",
    (int)s->path.len, s->path.ptr, url); 
  return ret;
}

