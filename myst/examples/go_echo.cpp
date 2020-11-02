#include <st.h>
#include <stdio.h>
#include <string.h>

static const uint16_t port = 43333;
static void echo_server(void)
{
  int n;
  puts("[0]");
#ifdef ST_HOOK_SYS
  int accept_fd = socket(AF_INET, SOCK_STREAM, 0);
#else
  st_netfd_t accept_sfd = st_socket(AF_INET, SOCK_STREAM, 0);
  int accept_fd = st_netfd_fileno(accept_sfd);
#endif
  n = 1;
  if (setsockopt(accept_fd, SOL_SOCKET, SO_REUSEADDR, (char*)&n, sizeof(n)) < 0) {
    fprintf(stderr, "SO_REUSEADDR error.\n");
    exit(1);
  }
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
#ifdef ST_HOOK_SYS
  int sockfd = accept(accept_fd, (sockaddr*)&addr, &len);
  closesocket(accept_fd);
  if (sockfd == -1) 
#else
  st_netfd_t sockfd = st_accept(accept_sfd, (sockaddr*)&addr, &len, ST_UTIME_NO_TIMEOUT);
  st_netfd_close(accept_sfd);
  if (sockfd == NULL) 
#endif
  {
    if (EAGAIN == errno || EINTR == errno)
      goto retry;

    fprintf(stderr, "accept error:%s\n", strerror(errno));
    return ;
  }

  char buf[1024];
retry_read:
  puts("[8]");
#ifdef ST_HOOK_SYS
  n = recv(sockfd, buf, sizeof(buf), 0);
#else
  n = st_recv(sockfd, buf, sizeof(buf), 0, ST_UTIME_NO_TIMEOUT);
#endif
  if (n < 0)
  {
    if (EAGAIN == errno || EINTR == errno)
      goto retry_read;
    fprintf(stderr, "read errno=%d\n", st_errno);
  } else if (n == 0) {
    fprintf(stderr, "read eof\n");
  } else {
    buf[n] = '\0';
    // 阻塞的write已被HOOK，等待期间切换执行其他协程。
    printf("[12]server: recv %s\n",buf);
#ifdef ST_HOOK_SYS
    n = send(sockfd, buf, n, 0);
#else
    n = st_send(sockfd, buf, n, 0, ST_UTIME_NO_TIMEOUT);
#endif
    printf("[13]server: echo ret=%d\n", n);
  }
#ifdef ST_HOOK_SYS
  closesocket(sockfd);
#else
  st_netfd_close(sockfd);
#endif
}

static void client(void)
{
  int n;
  puts("[5]");
#ifdef ST_HOOK_SYS
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
#else
  st_netfd_t sockfd = st_socket(AF_INET, SOCK_STREAM, 0);
#endif
  sockaddr_in addr;
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = inet_addr("127.0.0.1");
  // 阻塞的connect已被HOOK，等待期间切换执行其他协程。
  puts("[6]");

#ifdef ST_HOOK_SYS
  n = connect(sockfd, (sockaddr*)&addr, sizeof(addr));
#else
  n = st_connect(sockfd, (sockaddr*)&addr, sizeof(addr), ST_UTIME_NO_TIMEOUT);
#endif

  if (-1 == n) {
    fprintf(stderr, "connect error:%s\n", strerror(errno));
    exit(1);
  }

  char buf[12] = "1234";
  int len = strlen(buf) + 1;

  // 阻塞的write已被HOOK，等待期间切换执行其他协程。
  puts("[9]");
#ifdef ST_HOOK_SYS
  n = send(sockfd, buf, len, 0);
#else
  n = st_send(sockfd, buf, len, 0, ST_UTIME_NO_TIMEOUT);
#endif
  printf("[10]client: send ret=%d\n", n);

  char rcv_buf[12];
retry_read:
  // 阻塞的read已被HOOK，等待期间切换执行其他协程。
  puts("[11]");
#ifdef ST_HOOK_SYS
  n = recv(sockfd, rcv_buf, sizeof(rcv_buf), 0);
#else
  n = st_recv(sockfd, rcv_buf, sizeof(rcv_buf), 0, ST_UTIME_NO_TIMEOUT);
#endif
  if (n < 0) {
    if (EAGAIN == errno || EINTR == errno)
      goto retry_read;

    fprintf(stderr, "read errno=%d:%s\n", errno, strerror(errno));
  } else if (n == 0) {
    fprintf(stderr, "read eof\n");
  } else {
    printf("[14]client: recv %s\n",rcv_buf);
  }
  puts("[15]");
#ifdef ST_HOOK_SYS
  closesocket(sockfd);
#else
  st_netfd_close(sockfd);
#endif
}

int main()
{
  st_init();
  go client;
  go []{
    printf("[7] other fiber\n");
  };
  echo_server();
  return st_thread_exit(NULL), 0;
}
