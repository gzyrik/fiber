#include <http.h>
#include <string.h>
#include <stdio.h>
static void mount(http_t* http, http_handler_t* h, const char* path,
  void (*callback)(http_handler_t* self, http_t* http, const http_session_t* session))
{
  size_t slen = strlen(path);
  memset(h, 0, sizeof(*h));
  if (path[slen-1] != '/') {
    size_t plen = slen;
    while (slen > 0 && path[slen-1] != '/')
      --slen;
    h->pattern.ptr = (char*)path + slen;
    h->pattern.len = plen - slen;
  }
  h->path.ptr = (char*)path;
  h->path.len = slen;
  h->callback = callback;
  http_mount(http, h);
}
static void fastcgi(http_handler_t* self, http_t* http, const http_session_t* session)
{
  fprintf(stderr, "** fastcgi\n");
}
static void root(http_handler_t* self, http_t* http, const http_session_t* session)
{
  http_set_status(session, 200);
  if (!http_strcmp(session->path.ptr, "quit", session->path.len))
    http_quit(http);
  else if (!http_strcmp(session->path.ptr, "add", session->path.len)){
      static http_handler_t h;
      mount(http, &h, "/.*%.lua", fastcgi);
  }
  else if (!http_strcmp(session->path.ptr, "del", session->path.len)){
      http_key_t path;
      path.ptr = "/add/";
      path.len = 5;
      http_unmount(http, &path);
  }
  else
    http_redirect(session, "/quit");
}
int main(int argc, char* argv[])
{
  http_t http; 
  http_handler_t handlers[3];

  memset(&http, 0, sizeof(http));
  http.headerBufferSize = 1024;
  http.headerMaxNumber = 16;
  http.headerTimeout = 30*1000;
  http.sessionTimeout = 1000*1000;
  http.logFile = stderr;
  http.logPrintf = vfprintf;
  http.root.callback = root;

  mount(&http, handlers+0, "/0/", root);
  mount(&http, handlers+1, "/1/", root);
  mount(&http, handlers+2, "/2/", root);

  st_init(NULL);
  http_loop(&http, 3344, 64*1024);
  return 0;
}
