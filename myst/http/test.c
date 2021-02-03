#include "http.h"
#include <string.h>
#include <stdio.h>
static void onmessage(websocket_t* websocket, http_t* http, int flags, char* frame, size_t length)
{
  fprintf(stderr, "< %.*s\n", (int)length, frame);
  websocket_close(websocket);
}
static void onclose(websocket_t* websocket, http_t* http)
{
  fprintf(stderr, "# WS CLOSED\n");
}
static void handle_test(http_handler_t* self, http_t* http, const http_session_t* session)
{
  http_unmount(http, "/test");
}
static void handle_root(http_handler_t* self, http_t* http, const http_session_t* session)
{
  http_set_status(session, 200);
  if (!http_strcmp(session->path.ptr, "quit", session->path.len))
    http_quit(http);
  else if (!http_strcmp(session->path.ptr, "test", session->path.len)) {
    static http_handler_t test;
    test.path.ptr = "/test";
    test.path.len = 5;
    test.callback = handle_test;
    http_mount(http, &test);
  }
  else if (!http_strcmp(session->path.ptr, "ws", session->path.len)) {
    websocket_t ws = {onmessage, onclose, NULL};
    websocket_loop(&ws, session, "webrtc");
  }
  else
    http_redirect(session, "/quit");
}
int main(int argc, char* argv[])
{
  http_t http; 

  memset(&http, 0, sizeof(http));
  http.headerTimeout = 30*1000;
  http.sessionTimeout = 1000*1000;
  http.logFile = stderr;
  http.logPrintf = fprintf;
  http.root.path.ptr = "/";
  http.root.path.len = 0;
  http.root.callback = handle_root;

  st_init();
  http_loop(&http,  3344,  64*1024);
  return 0;
}
