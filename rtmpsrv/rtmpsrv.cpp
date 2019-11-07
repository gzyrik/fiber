#include <string.h>
#include <stdlib.h>
#include <librtmp/rtmp.h>
#include <librtmp/log.h>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#define CPPHTTPLIB_ST_SUPPORT //必须开启 HOOK RTMP 内部的 sock 操作
//#define CPPHTTPLIB_ZLIB_SUPPORT
#include "httplib.h"
void HUB_UpdateCreateMs(const std::string& fname, uint32_t createMs);
uint32_t HUB_AddRTMP(int32_t streamId, RTMP* r, bool isPlayer);//返回开始的时刻
void HUB_Remove(int32_t streamId, RTMP* r);
void HUB_Publish(int32_t streamId, RTMPPacket* packet);
static int _httpPort = 5562;
int _rtmpPort = 0;
typedef std::unordered_map<std::string, std::string> FileAddrMap;//文件regex-URL -> 推送服务地址
static FileAddrMap _fileAddrs;
static std::vector<st_thread_t> _joinThreads;//待回收的线程(包括RTMP服务和推送服务的线程)
static std::unordered_set<st_thread_t> _childRtmps;//RTMP服务的子线程
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
static std::string toPath(RTMP* r)
{
  std::string fname(r->Link.app.av_val, r->Link.app.av_len);
  fname.push_back('/');
  fname.append(r->Link.playpath.av_val, r->Link.playpath.av_len);
  fname.append(".flv");
  return fname;
}
static FILE* OpenFLV(const std::string& fname)
{
  char buf[13];
  FILE* fp;
  if (!(fp = fopen(fname.c_str(), "rb")))
    return nullptr;
  if (fread(buf, 1, 13, fp) != 13
    || buf[0] != 'F' || buf[1] != 'L' || buf[2] != 'V')
    return nullptr;
  return fp;
}
static RTMP* ConnectURL(std::string& url, bool write)
{
  RTMP* rtmp = new RTMP;
  while (rtmp) {
    RTMP_Init(rtmp);
    if (!RTMP_SetupURL(rtmp, (char*)url.c_str()))
      break;
    if (write) RTMP_EnableWrite(rtmp);
    if (!RTMP_Connect(rtmp, nullptr))
      break;
    if (!RTMP_ConnectStream(rtmp, 0))
      break;
    return rtmp;
  }
  delete rtmp;
  return nullptr;
}
static void ProcessPackets(int32_t streamId, RTMP* rtmp, RTMPPacket* packet)
{
  while (_rtmpPort && RTMP_IsConnected(rtmp)
    && RTMP_ReadPacket(rtmp, packet)) {
    if (!RTMPPacket_IsReady(packet) || !packet->m_body)
      continue;
    if (RTMP_ServePacket(rtmp, packet))
      HUB_Publish(streamId, packet);
    RTMPPacket_Free(packet);
  }
  HUB_Remove(streamId, rtmp);
}
static void* pull_file_thread(RTMP* rtmp, int32_t streamId)
{
  RTMPPacket packet = {0};
  ProcessPackets(streamId, rtmp, &packet);
  RTMPPacket_Free(&packet);
  RTMP_Close(rtmp);
  delete rtmp;
  _joinThreads.emplace_back(st_thread_self());
  return nullptr;
}
static bool setupPush(int32_t streamId, RTMP* r)
{
  std::string fname(toPath(r)), addr;
  HUB_UpdateCreateMs(fname, RTMP_GetTime());
  for (auto& iter : _fileAddrs) {
    if (std::regex_match (fname, std::regex(iter.first))){
      addr = iter.second;
      break;
    }
  }
  if (addr.empty()) {
    FILE* fp = OpenFLV(fname);
    if (fp) {
      fclose(fp);
      addr = "http://127.0.0.1:" + std::to_string(_httpPort);
    }
  }
  std::ostringstream oss;
  toURL(oss << " app=", r->Link.app);
  toURL(oss << " flashver=", r->Link.flashVer);
  toURL(oss << " swfUrl=", r->Link.swfUrl);
  toURL(oss << " pageUrl=", r->Link.pageUrl);
  toURL(oss << " jtv=", r->Link.usherToken);
  toURL(oss << " playpath=", r->Link.playpath);
  if (addr.find("http://") == 0) {//POST /pushs 启动新推送. 等待新推送连接上来,然后再分发
    httplib::Client cli(addr);
    auto res = cli.Post("/pushs", oss.str(), "text/plain");
    if (res && res->status < 400)
      return true;
  }
  else if (addr.find("rtmp://") == 0) {//向rtmpsrv建立新拉取,直接分发
    RTMP *rtmp = nullptr;
    std::string url = addr + oss.str();
    do {
      if (!(rtmp = ConnectURL(url, false)))
        break;
      //Puller的流ID由对应服务分配, 因此本地只能使用-streamId
      st_thread_t t = st_thread([=] { return pull_file_thread(rtmp, -streamId); });
      if (!t)
        break;

      HUB_AddRTMP(-streamId, rtmp, false);
      _childRtmps.emplace(t);
      return true;
    } while (0);
    if (rtmp) RTMP_Close(rtmp);
    delete rtmp;
  }
  HUB_UpdateCreateMs(fname, 0);
  return false;
}
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

  streamId = RTMP_AcceptStream(&rtmp, &packet);//streamId是递增分配给客户端RTMP的
  if (!streamId) {
    RTMP_Log(RTMP_LOGERROR, "Accept failed");
    goto cleanup;
  }

  RTMP_PrintInfo(&rtmp, RTMP_LOGCRIT, "Accept");

  if (!HUB_AddRTMP(streamId, &rtmp, RTMP_State(&rtmp)&RTMP_STATE_PLAYING)
    && !setupPush(streamId, &rtmp)) {
    RTMP_Log(RTMP_LOGERROR, "setup push failed");
    goto cleanup;
  }

  ProcessPackets(streamId, &rtmp, &packet);

cleanup:
  RTMPPacket_Free(&packet);
  RTMP_Close(&rtmp);
  _joinThreads.emplace_back(st_thread_self());
  return nullptr;
}
static void join_threads()
{//回收线程
  if (_joinThreads.empty()) return;
  for (auto& t: _joinThreads) {
    st_thread_join(t, nullptr);
    _childRtmps.erase(t);
  }
  _joinThreads.clear();
}
static void* run_service_listen(void*fd)
{//RTMP 服务循环
  //struct timeval tv;
  int sockfd = (int)(ssize_t)fd;
  //socklen_t optlen = sizeof(tv);
  //tv.tv_sec = 1,tv.tv_usec = 0;
  //if (0 != getsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, &optlen))
  //  goto clean;

  RTMP_Log(RTMP_LOGCRIT, "[%d]Rtmpsrv at port %d", sockfd, _rtmpPort);
  while (_rtmpPort) {
    join_threads();
    int clientfd = accept(sockfd, nullptr, nullptr);
    if (clientfd >= 0) {
      st_thread_t t = nullptr;
      //if (setsockopt(clientfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv)) == 0)
      t = st_thread_create(serve_client_thread, (void*)(ssize_t)clientfd, true, 1024*1024);

      if (t)
        _childRtmps.emplace(t);
      else
        closesocket(clientfd);
    }
  }
clean:
  closesocket(sockfd);
  for (auto& t : _childRtmps) st_thread_interrupt(t);
  join_threads();
  for (auto& t : _childRtmps) st_thread_join(t, nullptr);
  _childRtmps.clear();
  RTMP_Log(RTMP_LOGCRIT, "[%d]Rtmpsrv Closed", sockfd);
  return nullptr;
}

struct FileInfo{
  st_thread_t thread;
  size_t bytes;
  uint32_t ts, len;
};
static std::unordered_map<int, FileInfo> _files;
static void* push_file_thread(RTMP* rtmp, FILE* fp)
{
  auto iter = _files.find(RTMP_Socket(rtmp));
  FileInfo& info = iter->second;
  size_t bufSize = 1024*4;
  char *buf = (char*)malloc(bufSize);
  const uint32_t startTm = RTMP_GetTime();
  uint32_t startTs = -1;
  info.bytes = 0;
  info.len = 0;
  while (buf && info.thread && !feof(fp)) {
    if (fread(buf, 1, 11, fp) != 11)
      break;
    const int pktType = buf[0];
    info.ts = AMF_DecodeInt24(buf+4) | (uint32_t(buf[7]) << 24);

    if (startTs==-1) startTs = info.ts;
    info.ts -= startTs;

    const int32_t diff = info.ts - (RTMP_GetTime() - startTm);
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
      info.bytes += pktSize;
      if (!info.len) info.len = RTMP_GetDuration(rtmp);
    }
    if (fseek(fp, 4, SEEK_CUR) != 0)
      break;
  }

  fclose(fp);
  RTMP_Close(rtmp);
  delete rtmp;
  if (buf) free(buf);
  if (info.thread)//不是HTTP强制结束,由join_threads()回收
    _joinThreads.emplace_back(info.thread);
  _files.erase(iter);
  return nullptr;
}
static st_thread_t _rtmpThread;
#define ERR_BREAK(x) { res.status = x; break; }
static void onGetRtmpStats(const httplib::Request& req, httplib::Response& res)
{
  if (!_rtmpThread) return;
}

static void onPostRtmp(const httplib::Request& req, httplib::Response& res)
{//创建并返回服务线程run_service_listen
  if (_rtmpThread) return;
  int sockfd=-1, tmp=1;
  //struct timeval tv;
  //tv.tv_sec = 1, tv.tv_usec = 0;
  RTMP_ctrlC = false;
  _rtmpPort = 1935;
  do {
    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sockfd < 0)
      ERR_BREAK(503);
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char*)&tmp, sizeof(tmp)) < 0)
      ERR_BREAK(503);
    //if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&tv, sizeof(tv)) < 0)
    //  ERR_BREAK(503);

    if (req.has_param("port"))
      _rtmpPort = std::stoi(req.get_param_value("port"));

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(_rtmpPort);
    if (bind(sockfd, (struct sockaddr *) &addr, sizeof(addr)) < 0)
      ERR_BREAK(503);

    if (listen(sockfd, 10) < 0)
      ERR_BREAK(503);

    _rtmpThread = st_thread_create(run_service_listen, (void*)(ssize_t)sockfd, true, 0);
    if (!_rtmpThread)
      ERR_BREAK(503);

    res.status = 201;
    return;
  } while(0);
  RTMP_Log(RTMP_LOGERROR, "POST /server failed");
  _rtmpPort = 0;
  if (sockfd >= 0) closesocket(sockfd);
}

static bool UpdateFileAddrs(const std::string& body, FileAddrMap& fileAddrs)
{
  std::istringstream iss(body);
  while (iss) {
    std::string url, addr;
    iss >> url >> addr;
    if (url.empty())
      break;
    else if (addr.empty())
      return false;
    else if (addr != "-")
      fileAddrs[url] = addr;
    else
      fileAddrs.erase(url);
  }
  return true;
}

static void onGetFiles(const httplib::Request& req, httplib::Response& res)
{
  std::unordered_map<std::string, std::string> files;
  for (auto& iter: _fileAddrs)
    files[iter.second].append(iter.first).push_back(',');

  auto& local = files["."];
#ifdef _WIN32
  struct _finddata_t finfo;
  auto handle = _findfirst("*.flv", &finfo);
  if (handle != -1) {
    do {
      local.append(finfo.name).push_back(',');
    } while (_findnext(handle, &finfo) == 0);
    _findclose(handle);
  }
#else
  std::regex flv(R"(.*\.flv)");
  DIR *dirp = opendir (".");
  if (dirp) {
    struct dirent *entry=readdir (dirp);
    while (entry) {
      if (std::regex_match (entry->d_name, flv))
        local.append(entry->d_name).push_back(',');
      entry=readdir (dirp);
    }
    closedir (dirp);
  }
#endif

  std::ostringstream oss;
  for (auto& iter: files){
    if (iter.second.empty()) continue;
    iter.second.back() = '\n';
    oss << iter.first << ' ' << iter.second;
  }
  res.set_content(oss.str(), "text");
}

static void onPutFiles(const httplib::Request& req, httplib::Response& res)
{
  FileAddrMap fileAddrs;
  if (UpdateFileAddrs(req.body, fileAddrs))
    std::swap(_fileAddrs, fileAddrs);
  else
    res.status = 400;
}

static void onPatchFiles(const httplib::Request& req, httplib::Response& res)
{
  FileAddrMap fileAddrs(_fileAddrs);
  if (UpdateFileAddrs(req.body, fileAddrs))
    std::swap(_fileAddrs, fileAddrs);
  else
    res.status = 400;
}

static void onDeleteRtmp(const httplib::Request& req, httplib::Response& res)
{//关闭RTMP服务
  if (!_rtmpThread) return;
  RTMP_ctrlC = true;
  _rtmpPort = 0;
  st_thread_interrupt(_rtmpThread);
  st_thread_join(_rtmpThread, nullptr);
  _rtmpThread = nullptr;
}
static void onGetPushs(const httplib::Request& req, httplib::Response& res)
{
}
static void onPostPushs(const httplib::Request& req, httplib::Response& res)
{
  FILE* fp=nullptr;
  RTMP* rtmp=nullptr;
  join_threads();
  do {
    if (!req.has_header("REMOTE_ADDR"))
      ERR_BREAK(400);
    std::string url;{
      std::ostringstream oss;
      oss << "rtmp://" << req.get_header_value("REMOTE_ADDR")
        << ':' << _rtmpPort << ' ' << req.body;
      url = oss.str();
    }
    if (!(rtmp = ConnectURL(url, true)))
      ERR_BREAK(500);

    if (!(fp = OpenFLV(toPath(rtmp))))
      ERR_BREAK(400);

    st_thread_t t = st_thread([=] { return push_file_thread(rtmp, fp); });
    if (!t)
      ERR_BREAK(503);

    _files[RTMP_Socket(rtmp)].thread = t;
    RTMP_PrintInfo(rtmp, RTMP_LOGCRIT, "Ingest");
    res.status = 201;
    return;
  } while(0);
  RTMP_Log(RTMP_LOGERROR, "POST /files failed");
  if (fp) fclose(fp);
  if (rtmp) RTMP_Close(rtmp);
  delete rtmp;
}
static void onGetPushById(const httplib::Request& req, httplib::Response& res)
{
  int sockfd = std::stoi(req.matches[1]);
  auto iter = _files.find(sockfd);
  if (iter == _files.end()) return;
  FileInfo& info = iter->second;
  double percent =  info.ts / (info.len * 1000.0) * 100.0;
  char buf[256];
  sprintf(buf, "[%d]%.3fkB/%.2fsec %.1f%%", sockfd,
    (double) info.bytes / 1024.0, info.ts / 1000.0,
    ((double)(int)(percent * 10.0)) / 10.0);
  res.set_content(buf, "text");
}
static void onDeletePushById(const httplib::Request& req, httplib::Response& res)
{//强制关闭文件的推送
  int sockfd = std::stoi(req.matches[1]);
  auto iter = _files.find(sockfd);
  if (iter == _files.end()) return;

  auto thread = iter->second.thread;
  iter->second.thread = nullptr;
  //st_thread_interrupt(thread);
  st_thread_join(thread, nullptr);
}

/*
   单服务结点 接口设计:
   - GET /files 获取regex-URL信息
   - PUT /files 更新全部文件regex-URL信息
   - PATCH /files 更新部分文件 regex-URL信息

   - GET /rtmp 获取RTMP信息
   - POST /rtmp 启动RTMP服务
   - DELETE /rtmp 关闭RTMP服务

   - GET /pushs 获取所有的推送信息
   - POST /pushs 启动新的推送,返回ID
   - GET /pushs/ID 获取指定的推送信息
   - DELETE /pushs/ID 强制关闭指定的推送
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
  http.Get("/", [&](const httplib::Request& req, httplib::Response& res){
    const char * help = 
      "curl -X POST 127.0.0.1:5562/rtmp -d 1\n"
      "curl -X DELETE 127.0.0.1:5562/rtmp\n"
      "ffmpeg -i theory.flv -f segment -segment_time 10 "
      "-segment_list theory.m3u8 theory/theory%d.ts\n"
      "./ffmpeg -f avfoundation -framerate 30 -i 0 "
      "-vcodec libx264 -f flv rtmp://127.0.0.1/app/xxx\n"
      "./rtmpdump  -r rtmp://127.0.0.1/app/xxx -o xxx.flv\n";
    res.set_content(help, "text/html");
  })
  .Post("/loglevel", [&](const httplib::Request& req, httplib::Response& res) {
    if (!RTMP_LogSetLevel2(req.body.c_str()))
      res.status = 400;
  })

  .Get("/files", onGetFiles)
  .Put("/files", onPutFiles)
  .Patch("/files", onPatchFiles)

  .Get("/rtmp", onGetRtmpStats)
  .Post("/rtmp", onPostRtmp)
  .Delete("/rtmp", onDeleteRtmp)

  .Get("/pushs", onGetPushs)
  .Post("/pushs", onPostPushs)
  .Get(R"(/pushs/(\d+))", onGetPushById)
  .Delete(R"(/pushs/(\d+))", onDeletePushById);

  http.set_base_dir("hls");
  http.listen("*", _httpPort);
  perror("Http listen");
  return -1;
}
