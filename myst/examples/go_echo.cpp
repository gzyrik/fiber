#include "../st.h"
#include <stdio.h>
#include <string.h>

static const uint16_t port = 43333;

void echo_server()
{
  int n;
  puts("[0]");
  int accept_fd = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
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
  puts("[8]");
  if ((n = recv(sockfd, buf, sizeof(buf), 0)) < 0) {
    if (EAGAIN == errno || EINTR == errno)
      goto retry_read;
    fprintf(stderr, "read errno=%d\n", st_errno);
  } else if (n == 0) {
    fprintf(stderr, "read eof\n");
  } else {
    // echo
    // 阻塞的write已被HOOK，等待期间切换执行其他协程。
    puts("[12]");
    send(sockfd, buf, n, 0);
    puts("[13]");
  }
}

void client()
{
  int n;
  puts("[5]");
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  // 阻塞的connect已被HOOK，等待期间切换执行其他协程。
  puts("[6]");

  if (-1 == connect(sockfd, (sockaddr*)&addr, sizeof(addr))) {
    fprintf(stderr, "connect error:%s\n", strerror(errno));
    exit(1);
  }

  char buf[12] = "1234";
  int len = strlen(buf) + 1;

  // 阻塞的write已被HOOK，等待期间切换执行其他协程。
  puts("[9]");
  send(sockfd, buf, len, 0);
  puts("[10]");

  char rcv_buf[12];
retry_read:
  // 阻塞的read已被HOOK，等待期间切换执行其他协程。
  puts("[11]");
  if ((n = recv(sockfd, rcv_buf, sizeof(rcv_buf), 0)) < 0) {
    if (EAGAIN == errno || EINTR == errno)
      goto retry_read;

    fprintf(stderr, "read errno=%d:%s\n", errno, strerror(errno));
  } else if (n == 0) {
    fprintf(stderr, "read eof\n");
  } else {
    printf("[14]recv %s\n",rcv_buf);
  }
  puts("[15]");
}

int main()
{
  st_init();
  go client;
  go []{
    puts("[7]");
  };
  echo_server();
  st_thread_exit(NULL);
  return 0;
}
