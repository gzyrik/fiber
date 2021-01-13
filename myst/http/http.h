#ifndef _HTTP
#define _HTTP
#include "../st.h"
typedef struct {
  char  *ptr;
  size_t len;
} http_key_t, http_val_t;

typedef struct {
  http_key_t key;
  http_val_t val;
} http_header_t;

typedef struct {
  http_key_t method;
  http_val_t path;
  http_val_t version;
  ssize_t contentLength;
  size_t headerNumber;
  http_header_t *header;
} http_session_t;

http_val_t* http_get_value(http_session_t* session, const char* key);
int http_read(http_session_t* session, char* data, size_t length);
int http_set_status(http_session_t* session, int status);
int http_set_header(http_session_t* session, const char* key, const char* value);
int http_write(http_session_t* session, const char* data, size_t length);
int http_redirect(http_session_t* session,  const char* url);

typedef struct http_t http_t;
typedef struct http_handler_t http_handler_t;
struct http_handler_t {
  http_key_t path;
  void* (*callback)(http_handler_t* self, http_t* http, http_session_t* session);
  /*< private >*/
  http_handler_t *next;
};
typedef struct _http_context http_context_t;
struct http_t {
  st_utime_t headerTimeout;
  st_utime_t sessionTimeout;
  http_handler_t *handler;
  /*< private >*/
  http_context_t *context;
};

int http_loop(http_t* http, int port, int stacksize);
int http_mount(http_t* http, http_handler_t* handler);
void http_quit(http_t* http);
#endif
