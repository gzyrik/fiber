#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include "sdp.h"

static const char * const files[] = {
    "./samples/1.sdp",
    "./samples/2.sdp",
    "./samples/3.sdp",
    "./samples/4.sdp",
    "./samples/rfc-example.sdp",
};

int main(void)
{
    size_t i;

    fprintf(stderr, "sizeof(sdp_t)=%lu\n", sizeof(struct sdp_t));
    for (i = 0; i < sizeof(files) / sizeof(*files); i++) {
        int fd = open(files[i], O_RDONLY);
        struct sdp_t sdp;
        char payload[1024*4], dump[1024*4], *errptr;
        int n;

        if (fd < 0) {
            perror("open");
            return 1;
        }

        n = read(fd, payload, sizeof(payload));
        if (n < 0) {
            perror("read");
            return 1;
        }
        payload[n] = 0;
        n = sdp_parse(&sdp, payload, &errptr);
        if (n == 0){
            n = sdp_dump(dump, sizeof(dump), &sdp);
            if (n >= 0 && n < (int)sizeof(dump)) {
                printf("[%s]\n%s\n", files[i], dump);
                continue;
            }
        }
        fprintf(stderr, "%s: invalid sdp %d at\n%s\n", files[i], n, errptr);
        break;
    }
    return 0;
}
