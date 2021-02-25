#define CPPHTTPLIB_ST_SUPPORT
//#define CPPHTTPLIB_ZLIB_SUPPORT
#include "httplib.h"

int main(int argc, char *argv[])
{
    int httpPort = 8080;
    const char *httpDir = ".", *fileCfg = nullptr;
    for(int i=1;i<argc;++i) {
        if (!strncmp(argv[i], "--port=", 7))
            httpPort = std::atoi(argv[i]+7);
        else if (!strncmp(argv[i], "--rootdir=", 10))
            httpDir = argv[i]+10;
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            const char* help =
                "Usage: %s [options]\r\n"
                "OPTIONS:\r\n"
                " -h, --help      \tPrint this message\r\n"
                " --port=8080     \tHttp service port\r\n"
                " --rootdir=.     \tHttp service root directory\r\n";
            printf(help, argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Invalid `%s', use -h to print help", argv[i]);
            return -1;
        }
    }

#ifdef CPPHTTPLIB_ST_SUPPORT
    if (st_init(NULL) < 0) {
        perror("st_init");
        return -1;
    }
#endif

    httplib::Server websrv;
    if (httpDir && !websrv.set_base_dir(httpDir)) {
        fprintf(stderr, "Invalid path of `--rootdir=%s'", httpDir);
        return -1;
    }

    websrv.listen("*", httpPort);
    perror("HTTP listen");
    return -1;
}
