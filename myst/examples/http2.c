#include <http.h>
#include <string.h>
#include <stdio.h>
static void handle_root(http_handler_t* self, http_t* http, const http_session_t* session)
{
  http_set_status(session, 200);
  if (!http_strcmp(session->path.ptr, "quit", session->path.len))
    http_quit(http);
  else
    http_redirect(session, "/quit");
}
struct proxy_pass_t {
  http_handler_t super;
  const char* url;
};
static void handle_proxy(http_handler_t* self, http_t* http, const http_session_t* session)
{
  struct proxy_pass_t* proxy = (struct proxy_pass_t*)self;
  http_set_header(session, "Proxy", "True");
  http_proxy_loop(session, proxy->url);
}
int main(int argc, char* argv[])
{
  http_t http; 
  struct proxy_pass_t proxy;
  http_handler_t* h = (http_handler_t*)&proxy;

  memset(&http, 0, sizeof(http));
  http.headerBufferSize = 1024;
  http.headerMaxNumber = 16;
  http.headerTimeout = 30*1000;
  http.sessionTimeout = 1000*1000;
  http.logFile = stderr;
  http.logPrintf = fprintf;
  http.root.callback = handle_root;

  memset(&proxy, 0, sizeof(proxy));
  proxy.url = "http://10.211.55.2:3344/";
  h->path.len = 6;
  h->path.ptr = "/proxy";
  h->callback = handle_proxy;
  http_mount(&http, h);

  st_init();
  http_loop(&http,  3344,  64*1024);
  return 0;
}
