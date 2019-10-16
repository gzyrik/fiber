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
  st_netfd_t netfd = st_netfd_open_socket(accept_fd);

  puts("[4]");
  st_netfd_t sockfd = st_accept(netfd, (sockaddr*)&addr, &len, ST_UTIME_NO_TIMEOUT);
  if (!sockfd) {
    fprintf(stderr, "accept error:%s\n", strerror(errno));
    return ;
  }
  char buf[1024];
  puts("[8]");
  if ((n = st_read(sockfd, buf, sizeof(buf), ST_UTIME_NO_TIMEOUT)) < 0) {
    fprintf(stderr, "read errno=%d\n", st_errno);
  } else if (n == 0) {
    fprintf(stderr, "read eof\n");
  } else {
    // 阻塞的write已被HOOK，等待期间切换执行其他协程。
    puts("[12]");
    st_write(sockfd, buf, n, ST_UTIME_NO_TIMEOUT);
    puts("[13]");
  }
}

void client()
{
  puts("[5]");
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  // 阻塞的connect已被HOOK，等待期间切换执行其他协程。
  puts("[6]");
  st_netfd_t netfd = st_netfd_open_socket(sockfd);
  if (st_connect(netfd, (sockaddr*)&addr, sizeof(addr),ST_UTIME_NO_TIMEOUT) < 0) {
    fprintf(stderr, "connect error:%s\n", strerror(errno));
    exit(1);
  }

  char buf[12] = "1234";
  int len = strlen(buf) + 1;

  // 阻塞的write已被HOOK，等待期间切换执行其他协程。
  puts("[9]");
  st_write(netfd, buf, len, ST_UTIME_NO_TIMEOUT);
  puts("[10]");

  char rcv_buf[12];

  puts("[11]");
  int n = st_read(netfd, rcv_buf, sizeof(rcv_buf), ST_UTIME_NO_TIMEOUT);
  if (n < 0) {
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
#ifdef _WIN32
  WSADATA wsd;
  WSAStartup(MAKEWORD(2, 2), &wsd);
#endif
  st_init();
  go client;
  go []{
    puts("[7]");
  };
  echo_server();
  st_thread_exit(NULL);
  return 0;
}
