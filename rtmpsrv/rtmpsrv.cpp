#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <librtmp/rtmp.h>
#include <librtmp/log.h>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#define CPPHTTPLIB_ST_SUPPORT
#define CPPHTTPLIB_ZLIB_SUPPORT
#include "httplib.h"
bool HUB_Add(int32_t streamId, RTMP* r);
void HUB_Remove(int32_t streamId, RTMP* r);
void HUB_Publish(int32_t streamId, RTMPPacket* packet);
static int _httpPort = 5562, _rtmpPort = 1935;
//rtmp url regex to sockaddr
static std::unordered_map<std::string, std::string> _sourceAddrs;
#define DUPTIME	5000	/* interval we disallow duplicate requests, in msec */
static void toURL(std::ostream& oss, const AVal& av)
{
  if (!av.av_val || !av.av_len) return;
  const std::string url(av.av_val, av.av_len);
  size_t a=0,b=url.find_first_of("+ /?%#&=", a);
  while (b != url.npos) {
    if (b > a) oss<<url.substr(a, b-a);
    oss<<'%'<<std::hex<<(int)url[b];
    b = url.find_first_of("+ /?%#&=", a = b+1);
  }
  oss<<url.substr(a);
}
static bool notifySource(RTMP* r)
{
  std::string addr="127.0.0.1:"+std::to_string(_httpPort);
  for (auto& iter : _sourceAddrs) {
    if (std::regex_match (r->Link.tcUrl.av_val, std::regex(iter.first))){
      addr = iter.second;
      break;
    }
  }
  std::ostringstream oss;
  toURL(oss << " app=", r->Link.app);
  toURL(oss << " flashver=", r->Link.flashVer);
  toURL(oss << " swfUrl=", r->Link.swfUrl);
  toURL(oss << " pageUrl=", r->Link.pageUrl);
  toURL(oss << " jtv=", r->Link.usherToken);
  toURL(oss << " playpath=", r->Link.playpath);

  httplib::Client cli(addr);
  auto res = cli.Post("/ingest", oss.str(), "text/plain");
  if (!res || res->status >= 400)
    return false;
  return true;
}
static std::vector<st_thread_t> _join;
static std::unordered_set<st_thread_t> _childs;
static void* serve_client_thread(void* sockfd)
{
  int32_t streamId = 0;
  RTMPPacket packet = {0};

  RTMP rtmp;
  RTMP_Init(&rtmp);

  if (!RTMP_Serve(&rtmp, (int)(ssize_t)sockfd, NULL)) {
    RTMP_Log(RTMP_LOGERROR, "Handshake failed");
    goto cleanup;
  }

  streamId = RTMP_AcceptStream(&rtmp, &packet);
  if (!streamId) {
    RTMP_Log(RTMP_LOGERROR, "Accept failed");
    goto cleanup;
  }

  if (!HUB_Add(streamId, &rtmp) && !notifySource(&rtmp)) {
    RTMP_Log(RTMP_LOGERROR, "notify source failed");
    goto cleanup;
  }
  while (_rtmpPort && RTMP_IsConnected(&rtmp)
    && RTMP_ReadPacket(&rtmp, &packet)) {
    if (!RTMPPacket_IsReady(&packet) || !packet.m_body)
      continue;
    if (RTMP_ServePacket(&rtmp, &packet))
      HUB_Publish(streamId, &packet);
    RTMPPacket_Free(&packet);
  }

cleanup:
  RTMPPacket_Free(&packet);
  HUB_Remove(streamId, &rtmp);
  RTMP_Close(&rtmp);
  _join.emplace_back(st_thread_self());
  return nullptr;
}

static void* run_service_listen(void*fd)
{
  int sockfd = (int)(ssize_t)fd;
  struct timeval tv={.tv_sec=1,.tv_usec=0};
  socklen_t optlen = sizeof(tv);
  getsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, &optlen);

  while (_rtmpPort) {
    if (!_join.empty()) {
      for (auto& t: _join) {
        st_thread_join(t, nullptr);
        _childs.erase(t);
      }
      _join.clear();
    }
    int clientfd = accept(sockfd, nullptr, nullptr);
    if (clientfd >= 0) {
      st_thread_t t = nullptr;
      if (setsockopt(clientfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0)
        t = st_thread_create(serve_client_thread, (void*)(ssize_t)clientfd, true, 1024*1024);

      if (t)
        _childs.emplace(t);
      else
        close(clientfd);
    }
  }
  close(sockfd);
  for (auto& t : _childs) st_thread_join(t, nullptr);
  _childs.clear();
  _join.clear();
  return nullptr;
}

static void* ingest_file_thread(RTMP* rtmp, FILE* fp)
{
  size_t bufSize = 1024*4;
  char *buf = (char*)malloc(bufSize);
  const uint32_t re = RTMP_GetTime();
  uint32_t startTs = 0;
  do {
    if (fread(buf, 1, 11, fp) != 11)
      break;
    const int pktType = buf[0];
    uint32_t ts = AMF_DecodeInt24(buf+4);
    ts |= uint32_t(buf[7]) << 24;

    if (!startTs) startTs = ts;
    const int32_t diff = (ts - startTs) - (RTMP_GetTime() -re);
    if (diff > 300 && diff < 3000) st_usleep(diff*1000);

    const size_t bodySize = AMF_DecodeInt24(buf+1), pktSize = bodySize + 11;
    if (bufSize < pktSize)
      buf = (char*)realloc(buf, bufSize = pktSize);
    if (fread(buf+11, 1, bodySize, fp) != bodySize)
      break;
    if (pktType == RTMP_PACKET_TYPE_AUDIO
      || pktType == RTMP_PACKET_TYPE_VIDEO
      || pktType == RTMP_PACKET_TYPE_INFO)
    {
      if (RTMP_Write(rtmp, buf, pktSize) != pktSize)
        break;
    }
    if (fseek(fp, 4, SEEK_CUR) != 0)
      break;
  } while(_rtmpPort && !feof(fp));
clean:
  fclose(fp);
  RTMP_Close(rtmp);
  delete rtmp;
  if (buf) free(buf);
  _join.emplace_back(st_thread_self());
  return nullptr;
}
#define ERR_BREAK(x) { res.status = x; break; }
static st_thread_t onServerPost(const httplib::Request& req, httplib::Response& res)
{
  int sockfd=-1, tmp=1;
  struct timeval tv={.tv_sec=1,.tv_usec=0};
  do {
    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd < 0)
      ERR_BREAK(503);

    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof(tmp)) < 0)
      ERR_BREAK(503);

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
      ERR_BREAK(503);

    if (!_rtmpPort) _rtmpPort = 1935;
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(_rtmpPort);
    if (bind(sockfd, (struct sockaddr *) &addr, sizeof(addr)) < 0)
      ERR_BREAK(503);

    if (listen(sockfd, 10) < 0)
      ERR_BREAK(503);

    auto t = st_thread_create(run_service_listen, (void*)(ssize_t)sockfd, true, 0);
    if (!t)
      ERR_BREAK(503);

    res.status = 201;
    return t;
  } while(0);
  _rtmpPort = 0;
  if (sockfd >= 0) close(sockfd);
  return nullptr;
}
static void
onIngestPost(const httplib::Request& req, httplib::Response& res)
{
  FILE* fp=nullptr;
  RTMP* rtmp=nullptr;
  do {
    assert(req.has_header("REMOTE_ADDR"));
    std::string url;{
      std::ostringstream oss;
      oss << "rtmp://" << req.get_header_value("REMOTE_ADDR")
        << ':' << _rtmpPort << ' ' << req.body;
      url = oss.str();
    }
    if (!(rtmp = new RTMP)) ERR_BREAK(503);
    RTMP_Init(rtmp);
    if (!RTMP_SetupURL(rtmp, (char*)url.c_str())) ERR_BREAK(400);

    std::string file(rtmp->Link.playpath.av_val, rtmp->Link.playpath.av_len);
    file.append(".flv");

    char buf[13];
    if (!(fp = fopen(file.c_str(), "rb"))) ERR_BREAK(404);
    if (fread(buf, 1, 13, fp) != 13
      || buf[0] != 'F' || buf[1] != 'L' || buf[2] != 'V')
      ERR_BREAK(500);

    RTMP_EnableWrite(rtmp);
    if (!RTMP_Connect(rtmp, nullptr))
      ERR_BREAK(422);
    struct timeval tv={.tv_sec=1,.tv_usec=0};
    if (setsockopt(RTMP_Socket(rtmp), SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0)
      ERR_BREAK(503);
    if (!RTMP_ConnectStream(rtmp, 0))
      ERR_BREAK(422);

    auto t = st_thread([rtmp, fp]{ return ingest_file_thread(rtmp, fp); }, true);
    if (!t)
      ERR_BREAK(503);

    _childs.emplace(t);
    res.status = 201;
    return;
  } while(0);
  if (fp) fclose(fp);
  if (rtmp) {
    RTMP_Close(rtmp);
    delete rtmp;
  }
}
/*
   POST server
   POST ingest     body is URL
   GET server
   */

int main()
{
  if (st_init() < 0){
    perror("st_init");
    exit(-1);
  }
  st_thread_t server = nullptr;
  httplib::Server http;
  RTMP_debuglevel = RTMP_LOGWARNING;
  http.Get("/", [&](const auto& req, auto& res){
    const char * help = 
      "curl -X POST 127.0.0.1:5562/server -d 1\n"
      "curl -X DELETE 127.0.0.1:5562/server\n"
      "ffmpeg -i theory.flv -f segment -segment_time 10 "
      "-segment_list theory.m3u8 theory/theory%d.ts\n"
      "./ffmpeg -f avfoundation -framerate 30 -i 0 "
      "-vcodec libx264 -f flv rtmp://127.0.0.1/app/xxx\n"
      "./rtmpdump  -r rtmp://127.0.0.1/app/xxx -o xxx.flv\n";
    res.set_content(help, "text/html");
  })
  .Post("/server", [&](const auto& req, auto& res) {
    server = onServerPost(req, res);
  })
  .Delete("/server",[&](const auto& req, auto& res) {
    _rtmpPort = 0;
    if (server) st_thread_join(server, nullptr);
    server = nullptr;
    res.status = 204;
  })
  .Post("/ingest", onIngestPost);
  //.Get(R"(/(\w+)/(\w+).m3u8)", [&](const Request& req, Response& res) {});
  http.set_base_dir("hls");

  http.listen("*", _httpPort);
  perror("Http listen");
  return -1;
}
