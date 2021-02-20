#include <http.h>
#include <string.h>
#include <stdio.h>
struct my_http_t {
  http_t http;
  websocket_t* ws;
};
static void onmessage(websocket_t* websocket, http_t* http, int flags, char* frame, size_t length)
{
  fprintf(stderr, "< %.*s\n", (int)length, frame);
}
static void onclose(websocket_t* websocket, http_t* http)
{
  struct my_http_t *myhttp = (struct my_http_t*)http;
  myhttp->ws = NULL;
  fprintf(stderr, "# WS CLOSED\n");
}
static void handle_root(http_handler_t* self, http_t* http, const http_session_t* session)
{
  struct my_http_t *myhttp = (struct my_http_t*)http;
  http_set_status(session, 200);
  if (!http_strcmp(session->path.ptr, "quit", session->path.len))
    http_quit(http);
  else if (!http_strcmp(session->path.ptr, "ws", session->path.len)) {
    websocket_t ws = {onmessage, onclose, NULL};
    myhttp->ws = &ws;
    websocket_loop(&ws, session, "webrtc");
  }
  else if (!http_strcmp(session->path.ptr, "close", session->path.len)) {
    if (myhttp->ws) websocket_close(myhttp->ws);
  }
}
int main(int argc, char* argv[])
{
  struct my_http_t myhttp; 
  http_t* http = &myhttp.http;

  memset(&myhttp, 0, sizeof(myhttp));
  http->headerBufferSize = 1024;
  http->headerMaxNumber = 16;
  http->headerTimeout = 30*1000;
  http->sessionTimeout = 1000*1000;
  http->logFile = stderr;
  http->logPrintf = fprintf;
  http->root.callback = handle_root;

  st_init();
  http_loop(http, 3344, 64*1024);
  return 0;
}
