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
int main(int argc, char* argv[])
{
  http_t http; 

  memset(&http, 0, sizeof(http));
  http.headerBufferSize = 1024;
  http.headerMaxNumber = 16;
  http.headerTimeout = 30*1000;
  http.sessionTimeout = 1000*1000;
  http.logFile = stderr;
  http.logPrintf = fprintf;
  http.root.callback = handle_root;

  st_init();
  http_loop(&http, 3344, 64*1024);
  return 0;
}
