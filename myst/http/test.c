#include "http.h"
#include <string.h>
#include <stdio.h>
static void* handle_root(http_handler_t* self, http_t* http, http_session_t* session)
{
    size_t i;
    fprintf(stderr, "%.*s:%.*s\n",
        (int)session->method.len, session->method.ptr, (int)session->path.len, session->path.ptr);
    for (i=0; i<session->headerNumber; ++i) {
        http_header_t* h = &session->header[i];
        fprintf(stderr, "%.*s:%.*s\n", (int)h->key.len, h->key.ptr, (int)h->val.len, h->val.ptr);
    }
    if (!strncmp(session->path.ptr, "quit", session->path.len))
        http_quit(http);
    else
        http_redirect(session, "/quit");
    return NULL;
}
int main(int argc, char* argv[])
{
    http_handler_t root;
    http_t http; 

    memset(&http, 0, sizeof(http));
    http.headerTimeout = 30*1000;
    http.sessionTimeout = 1000*1000;

    memset(&root, 0, sizeof(root));
    root.path.ptr = "/";
    root.path.len = 1;
    root.callback = handle_root;

    http_mount(&http, &root);
    st_init();
    http_loop(&http,  3344,  64*1024);
    return 0;
}
