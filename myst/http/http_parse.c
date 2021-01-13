#include "http.h"
#include <ctype.h>
// 跳过一切空白,读取单词
static const char* word(const char* buf, const char* const bufend, http_key_t* key)
{
  key->ptr = NULL;
  do {
    if (buf >= bufend) return buf;
    if (isspace(*buf)) ++buf;
    else break;
  } while (1);
  key->ptr = (char*)buf;
  do {
    ++buf;
    if (buf >= bufend) {
      buf = key->ptr;
      key->ptr = NULL;
      return buf;
    }
  } while (!isspace(*buf));
  key->len = buf - key->ptr;
  return buf;
}
// 定义: HTTP空白 是 '不含CRLF或:' 的空白
#define HTTP_SPACE(c) (c == ' ' || c == '\t' || c == '\v' || c == '\f' || c == ':')
// 跳过'HTTP空白'
static const char* skipspace(const char* buf, const char* const bufend)
{
  while (buf < bufend && HTTP_SPACE(*buf))
    ++buf;
  return buf;
}
/* 跳过'HTTP空白',读至下个'HTTP空白', 跳至 |end_ch| 之后 */
static const char* shrink(const char* buf, const char* const bufend, http_val_t* val, const char end_ch)
{
  val->ptr = NULL;
  if ((buf=skipspace(buf, bufend)) == bufend)
    return bufend;
  val->ptr = (char*)buf;
  while (*buf != end_ch && *buf != '\r') {
    ++buf;
    if (buf >= bufend){
      buf = val->ptr;
      val->ptr = NULL;
      return buf;
    }
  }
  val->len = buf - val->ptr;
  while (val->len > 0 && HTTP_SPACE(val->ptr[val->len-1]))
    val->len--;
  if (*buf == end_ch) ++buf; //跳过|end_ch|
  return buf;
}
ssize_t http_parse_request(http_session_t* s, const size_t headerSize,
  const char* const bufptr, const char* const bufend,
  size_t *pos, char* state)
{
  http_header_t* h = s->header + s->headerNumber; 
  const char* buf = bufptr + *pos;
  while (buf < bufend) {
    switch(state[0]) {
    case 0:
      buf = word(buf, bufend, &s->method);
      if (!s->method.ptr) goto part;
      ++state[0];
    case 1:
      buf = word(buf, bufend, &s->path);
      if (!s->path.ptr) goto part;
      ++state[0];
    case 2:
      buf = shrink(buf, bufend, &s->version, '\r');
      if (!s->version.ptr) goto part;
      ++state[0];
    case 3://'\n'
      if ((buf=skipspace(buf, bufend)) == bufend) goto part;
      if (*buf++ != '\n') return -1;
      ++state[0];
    case 4://header
      buf = shrink(buf, bufend, &h->key, ':');
      if (!h->key.ptr) goto part;
      ++state[0];
    case 5:
      buf = shrink(buf, bufend, &h->val, '\r');
      if (!h->val.ptr) goto part;
      if (h->key.len == 0 && h->val.len == 0)
        ++state[0];//ending
      else {
        s->headerNumber++;
        if (s->headerNumber >= headerSize) return -1;
        h++;
        state[0] = 3;//header again
      }
      break;
    case 6://'\n'
      if ((buf=skipspace(buf, bufend)) == bufend) goto part;
      if (*buf++ != '\n') return -1;
      return *pos += buf - bufptr;
    }
  }
part:
  *pos += buf - bufptr;
  return 0;
}
