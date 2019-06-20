#include <st.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>

static const uint16_t port = 43333;

void echo_server()
{
    puts("[0]");
    int accept_fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    socklen_t len = sizeof(addr);
    puts("[1]");
    if (-1 == bind(accept_fd, (sockaddr*)&addr, len)) {
        fprintf(stderr, "bind error, please change the port value.\n");
        exit(1);
    }
    puts("[2]");
    if (-1 == listen(accept_fd, 5)) {
        fprintf(stderr, "listen error.\n");
        exit(1);
    }
    puts("[3]");
retry:
    // 阻塞的accept已被HOOK，等待期间切换执行其他协程。
    puts("[4]");
    int sockfd = accept(accept_fd, (sockaddr*)&addr, &len);
    if (sockfd == -1) {
        if (EAGAIN == errno || EINTR == errno)
            goto retry;

        fprintf(stderr, "accept error:%s\n", strerror(errno));
        return ;
    }

    char buf[1024];
retry_read:
    // 阻塞的read已被HOOK，等待期间切换执行其他协程。
    puts("[5]");
    int n = read(sockfd, buf, sizeof(buf));
    puts("[6]");
    if (n == -1) {
        if (EAGAIN == errno || EINTR == errno)
            goto retry_read;

        fprintf(stderr, "read error:%s\n", strerror(errno));
    } else if (n == 0) {
        fprintf(stderr, "read eof\n");
    } else {
        // echo
        // 阻塞的write已被HOOK，等待期间切换执行其他协程。
        puts("[7]");
        ssize_t wn = write(sockfd, buf, n);
        puts("[8]");
        (void)wn;
    }
}

void client()
{
    puts("[9]");
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    // 阻塞的connect已被HOOK，等待期间切换执行其他协程。
    puts("[10]");
    if (-1 == connect(sockfd, (sockaddr*)&addr, sizeof(addr))) {
        fprintf(stderr, "connect error:%s\n", strerror(errno));
        exit(1);
    }

    char buf[12] = "1234";
    int len = strlen(buf) + 1;

    // 阻塞的write已被HOOK，等待期间切换执行其他协程。
    puts("[11]");
    ssize_t wn = write(sockfd, buf, len);
    (void)wn;
    printf("[12]send [%d] %s\n", len, buf);

    char rcv_buf[12];
retry_read:
    // 阻塞的read已被HOOK，等待期间切换执行其他协程。
    puts("[13]");
    int n = read(sockfd, rcv_buf, sizeof(rcv_buf));
    if (n == -1) {
        if (EAGAIN == errno || EINTR == errno)
            goto retry_read;

        fprintf(stderr, "read error:%s\n", strerror(errno));
    } else if (n == 0) {
        fprintf(stderr, "read eof\n");
    } else {
        printf("[14]recv [%d] %s\n", n, rcv_buf);
    }
    puts("[15]");
}

int main()
{
    st_init();
    go echo_server;
    go client;
    go []{
        puts("[16]");
        printf("lambda\n");
        puts("[17]");
    };

    puts("[18]");
    st_thread_exit(NULL);
    return 0;
}
