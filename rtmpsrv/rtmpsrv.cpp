#include <string.h>
#include <stdlib.h>
#include <librtmp/rtmp.h>
#include <librtmp/log.h>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#define CPPHTTPLIB_ST_SUPPORT //���뿪�� HOOK RTMP �ڲ��� sock ����
//#define CPPHTTPLIB_ZLIB_SUPPORT
#include "httplib.h"
#include "rtmpsrv.h"
static int _rtmpPort = 1935;
static st_thread_t _rtmpThread = nullptr;
static FileAddrMap _fileAddrs;//�ļ�regex-URL -> Դ��ַ,֧��regex�滻
static std::unordered_map<SOCKET, TaskInfo> _tasks;//�����������е�����
//----------------------------------------------------------------------------------------------
static bool doFileSource(const std::string& fname,
  const std::string& app, const std::string& playpath, int32_t fakeId)
{
  FILE* fp = openFile(fname);
  if (!fp){
    RTMP_Log(RTMP_LOGERROR, "No exist local file %s", fname.c_str());
    return false;
  }

  auto t = st_go::create([=] {
    return send_stream_thread(RtmpStreamPtr(new FileStream(fp)), fakeId);
  });
  if (!t) {
    RTMP_Log(RTMP_LOGERROR, "st_thread_create failed");
    return false;
  }
  _tasks.emplace(fileno(fp), TaskInfo(t, app, playpath, "file:://" + fname));
  HUB_SetPusher(app, playpath, fakeId, HubPusherPtr(new FilePusher(fakeId)));
  return true;
}
static bool doRtmpSource(const std::string& addr,
  const std::string& app, const std::string& playpath, int32_t fakeId)
{
  RTMP *rtmp = nullptr;
  do {
    auto url = addr;
    if (!(rtmp = ConnectURL(url, false)))//url�Ѱ���app,playpath
      break;
    st_thread_t t = st_go::create([=] {
      return pull_stream_thread(rtmp, fakeId);
    });
    if (!t) {
      RTMP_Log(RTMP_LOGERROR, "st_thread_create failed");
      break;
    }

    RTMP_PrintInfo(rtmp, RTMP_LOGCRIT, "PullTask");
    _tasks.emplace(RTMP_Socket(rtmp), TaskInfo(t, app, playpath, addr));
    HUB_SetPusher(app, playpath, fakeId, HubPusherPtr(new RtmpPusher(*rtmp)));
    return true;
  } while (0);
  if (rtmp) RTMP_Close(rtmp);
  delete rtmp;
  return false;
}
static bool doHttpSource(const std::string& addr,
  const std::string& app, const std::string& playpath, int32_t fakeId)
{
  static const std::regex httpflv(R"(http://([^/]+)(/.+/[^/]+\.flv))", std::regex::icase);
  static const std::regex postask(R"(http://([^/]+)(/tasks/.+/[^/]+))", std::regex::icase);
  std::smatch matches;
  if (std::regex_match(addr, matches, httpflv)) {//����HTTP-FLV ��ʽ
    httplib::Client cli(matches[1]);
    auto res = cli.Get(matches[2], [=](httplib::StreamPtr& stream, bool chunked) {
      char buf[13];
      if (stream->read_chunk(buf, 13) != 13
        || buf[0] != 'F' || buf[1] != 'L' || buf[2] != 'V') {
        RTMP_Log(RTMP_LOGERROR, "invalid head of httpflv stream: %s", addr.c_str());
        return false;
      }
      auto t = st_go::create([=] {
        return send_stream_thread(RtmpStreamPtr(new HttpStream(stream)), fakeId);
      });
      if (!t) {
        RTMP_Log(RTMP_LOGERROR, "st_thread_create failed");
        return false;
      }
      _tasks.emplace(stream->sockfd(), TaskInfo(t, app, playpath, addr));
      HUB_SetPusher(app, playpath, fakeId, HubPusherPtr(new FilePusher(fakeId)));
      stream = nullptr;
      return true;
    });
    if (res && res->status < 400)
      return true;
    RTMP_Log(RTMP_LOGERROR, "can't get httpflv: %s", addr.c_str());
  }
  else if (!_rtmpThread)
    RTMP_Log(RTMP_LOGERROR, "RTMP-SRV closed, can't accept task: %s", addr.c_str());
  else if (std::regex_match(addr, matches, postask)) {
    //POST /tasks ����Զ�̵�����������. �ȴ���������������,Ȼ���ٷַ�
    httplib::Client cli(matches[1]);
    std::ostringstream oss;
    toURL(oss << ':' << _rtmpPort << " app=", app);
    toURL(oss << " playpath=", playpath);
    auto res = cli.Post(matches[2], oss.str(), "text/plain");
    if (res && res->status < 400)
      return true;
    RTMP_Log(RTMP_LOGERROR, "can't invoke remote task: %s", addr.c_str());
  }
  else
    RTMP_Log(RTMP_LOGERROR, "Invalid file addr: %s", addr.c_str());
  return false;
}
static bool setupPushing(const std::string& app, const std::string& playpath, int32_t streamId)
{
  if (!HUB_MarkBegin(app, playpath))//��Ԥ��ʱ��,��ֹ�ظ�����Դ
    return false;

  std::string path(app + "/" + playpath), addr;
  for (auto& iter : _fileAddrs) {
    std::smatch matches;
    if (std::regex_match (path, matches, std::regex(iter.first, std::regex::icase))){
      addr = iter.second;
      auto pos = addr.find('$');//֧���滻 live/(\.*)   http://10.211.55.17/app/$1.flv
      while (pos != addr.npos && pos + 1 < addr.size()) {
        auto idx = addr[pos+1] - '0';
        if (idx >= matches.size()) {
          RTMP_Log(RTMP_LOGERROR, "Invalid path `%s'replace with URL: %s %s",
            path.c_str(), iter.first.c_str(), iter.second.c_str());
          goto clean;
        }
        addr.replace(pos, 2, matches[idx]);
        pos = addr.find('$', pos+2);
      }
      break;
    }
  }
  if (addr.empty()) {//���Զ�ȡ�����ļ�
    if (doFileSource(path + ".flv", app, playpath, -streamId))
      return true;
  }
  else if (addr.find("http://") == 0) {//httpflv���� �� ����Զ�̵������RTMP����
    if (doHttpSource(addr, app, playpath, -streamId))
      return true;
  }
  else if (addr.find("rtmp://") == 0) {//��rtmpsrvֱ������
    if (doRtmpSource(addr, app, playpath, -streamId))
      return true;
  }
  else if (!addr.empty())
    RTMP_Log(RTMP_LOGERROR, "Invalid addr %s", addr.c_str());

clean:
  HUB_MarkEnd(app, playpath);//ʧ�ܻ򲻴���Դ,��λ��ʼʱ��
  return false;
}
//----------------------------------------------------------------------------------------------
static std::vector<st_thread_t> _joinThreads;//�����յ��߳�(����RTMP��������ͷ�����߳�)
static std::unordered_set<st_thread_t> _childRtmps;//RTMP-SRV��������߳�
static void join_threads()
{//�����߳�
  if (_joinThreads.empty()) return;
  for (auto& t: _joinThreads) {
    st_thread_join(t, nullptr);
    _childRtmps.erase(t);
  }
  _joinThreads.clear();
}
static void* send_stream_thread(RtmpStreamPtr fp, int streamId)
{//��ȡ�ļ����ͻ�����
  auto iter = _tasks.find(fp->sockfd());
  TaskInfo& info = iter->second;
  char buf[11];
  const uint32_t startTm = RTMP_GetTime();
  uint32_t startTs = -1;
  RTMPPacket packet = {0};
  packet.m_nChannel = 0x04; /* source channel */

  while (info.thread && fp->ok()) {
    if (!RTMPPacket_ReadFile(&packet, fp.get(), &RtmpStream::read))
      break;

    if (startTs==-1) startTs = packet.m_nTimeStamp;
    if (packet.m_packetType == RTMP_PACKET_TYPE_INFO)
      info.len = packet.m_nInfoField2;
    info.ts = packet.m_nTimeStamp - startTs;

    const int32_t diff = info.ts - (RTMP_GetTime() - startTm);
    if (diff > 300 && diff < 3000) st_usleep(diff*1000);

    if (!HUB_Publish(streamId, &packet)) //��ȡ�ļ���ת��
      break;
    info.bytes += packet.m_nBodySize;
  }

  if (streamId) HUB_Remove(streamId);
  RTMPPacket_Free(&packet);
  if (info.thread == st_thread_self())//����onDeleteTaskById()ǿ�ƽ���,��join_threads()����
    _joinThreads.emplace_back(info.thread);
  _tasks.erase(iter);
  return nullptr;
}
static void* pull_stream_thread(RTMP* rtmp, int32_t streamId)
{//��Ϊ�ͻ���,��ȡ��ת�� RTMP ��
  auto iter = _tasks.find(RTMP_Socket(rtmp));
  TaskInfo& info = iter->second;
  RTMPPacket packet = {0};
  while (RTMP_IsConnected(rtmp)
    && RTMP_ReadPacket(rtmp, &packet)) {
    if (!RTMPPacket_IsReady(&packet) || !packet.m_body)
      continue;
    if (RTMP_ClientPacket(rtmp, &packet)) {
      info.ts = packet.m_nTimeStamp;
      info.bytes += packet.m_nBodySize;
      if (packet.m_packetType == RTMP_PACKET_TYPE_INFO)
        info.len = RTMP_GetDuration(rtmp);
      if (!HUB_Publish(streamId, &packet))
        break;
    }
    RTMPPacket_Free(&packet);
  }

  HUB_Remove(streamId);
  RTMPPacket_Free(&packet);
  RTMP_Close(rtmp);
  delete rtmp;
  if (info.thread == st_thread_self())//����onDeleteTaskById()ǿ�ƽ���,��join_threads()����
    _joinThreads.emplace_back(info.thread);
  _tasks.erase(iter);
  return nullptr;
}
static void* serve_client_thread(void* fd)
{
  int32_t streamId = 0;
  RTMPPacket packet = {0};
  SOCKET sockfd = (SOCKET)(size_t)fd;
  auto iter = _tasks.end();
  TaskInfo* info=nullptr;

  RTMP rtmp;
  RTMP_Init(&rtmp);

  if (!RTMP_Serve(&rtmp, sockfd, NULL)) {
    RTMP_Log(RTMP_LOGERROR, "Handshake failed");
    goto clean;
  }

  streamId = RTMP_AcceptStream(&rtmp, &packet);//streamId�ǵ���������ͻ���RTMP��
  if (!streamId) {
    RTMP_Log(RTMP_LOGERROR, "Accept failed");
    goto clean;
  }
  else {
    const std::string app(rtmp.Link.app.av_val, rtmp.Link.app.av_len);
    const std::string playpath(rtmp.Link.playpath.av_val, rtmp.Link.playpath.av_len);
    if (RTMP_State(&rtmp)&RTMP_STATE_PLAYING) {
      if (HUB_AddPlayer(app, playpath, streamId,
          HubPlayerPtr(new RtmpPlayer(rtmp))) == 0
        && !setupPushing(app, playpath, streamId)) {
        RTMP_Log(RTMP_LOGERROR, "setup %s/%s failed", app.c_str(), playpath.c_str());
        goto clean;
      }
    }
    else {
      int port = 0;
      std::ostringstream oss;
      oss << "rtmp://" << httplib::detail::get_remote_addr(sockfd, &port);
      oss << ':' << port << '/' << app << '/' << playpath;
      iter = _tasks.emplace(sockfd, TaskInfo(st_thread_self(), app, playpath,  oss.str())).first;
      info = &(iter->second);
      HUB_SetPusher(app, playpath, streamId, HubPusherPtr(new RtmpPusher(rtmp)));
    }
  }

  RTMP_PrintInfo(&rtmp, RTMP_LOGCRIT, "Accept");
  //��Ϊ�����, ���ղ�ת�� RTMP ��
  while (_rtmpThread && RTMP_IsConnected(&rtmp)
    && RTMP_ReadPacket(&rtmp, &packet)) {
    if (!RTMPPacket_IsReady(&packet) || !packet.m_body)
      continue;
    if (RTMP_ServePacket(&rtmp, &packet) && info) {
      info->ts = packet.m_nTimeStamp;
      info->bytes += packet.m_nBodySize;
      if (packet.m_packetType == RTMP_PACKET_TYPE_INFO)
        info->len = RTMP_GetDuration(&rtmp);
      if (!HUB_Publish(streamId, &packet))
        break;
    }
    RTMPPacket_Free(&packet);
  }

clean:
  if (streamId) HUB_Remove(streamId);
  RTMPPacket_Free(&packet);
  RTMP_Close(&rtmp);
  if (!info)
    _joinThreads.emplace_back(st_thread_self());
  else {
    if (info->thread == st_thread_self()) //����onDeleteTaskById()ǿ�ƽ���,��join_threads()����
      _joinThreads.emplace_back(info->thread);
    _tasks.erase(iter);
  }
  return nullptr;
}
static void* service_listen_thread(void*fd)
{//RTMP ����ѭ��
  SOCKET sockfd = (SOCKET)(size_t)fd;
  RTMP_Log(RTMP_LOGCRIT, "[%zu]RTMP-SRV at port %d", (size_t)sockfd, _rtmpPort);
  while (_rtmpThread) {
    join_threads();
    SOCKET clientfd = accept(sockfd, nullptr, nullptr);
    if (clientfd != INVALID_SOCKET) {
      auto t = st_thread_create(serve_client_thread, (void*)(size_t)clientfd, true, 1024*1024);
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
  RTMP_Log(RTMP_LOGCRIT, "[%zu]RTMP-SRV Closed", (size_t)sockfd);
  return nullptr;
}
//----------------------------------------------------------------------------------------------
#define ERR_BREAK(x) { res.status = x; break; }
static void onGetFiles(const httplib::Request& req, httplib::Response& res)
{
  std::unordered_map<std::string, std::string> files;
  for (auto& iter: _fileAddrs)
    files[iter.second].append(iter.first).push_back(',');

  FindFlvFiles(".", files);
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
static void onGetRtmpSrvStats(const httplib::Request& req, httplib::Response& res)
{
  if (!_rtmpThread) return;
}
static bool startRtmpSrv(int port)
{
  if (_rtmpThread) return true ;
  RTMP_ctrlC = false;
  SOCKET sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sockfd == INVALID_SOCKET)
    return false;

  do {
    int tmp=1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char*)&tmp, sizeof(tmp)) < 0)
      break;

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(sockfd, (struct sockaddr *) &addr, sizeof(addr)) < 0)
      break;
    if (listen(sockfd, 10) < 0)
      break;

    _rtmpThread = st_thread_create(service_listen_thread, (void*)(size_t)sockfd, true, 0);
    if (!_rtmpThread)
      break;
    _rtmpPort = port;
    return true;
  } while (0);
  closesocket(sockfd);
  perror("RTMP-SRV");
  return false;
}
static void onPostRtmpSrv(const httplib::Request& req, httplib::Response& res)
{
  int port = _rtmpPort;
  if (req.has_param("port"))
    port = std::stoi(req.get_param_value("port"));
  if (!startRtmpSrv(port))
    res.status = 503;
}
static void onDeleteRtmpSrv(const httplib::Request& req, httplib::Response& res)
{//�ر�RTMP����
  if (!_rtmpThread) return;
  auto t = _rtmpThread;
  RTMP_ctrlC = true;
  _rtmpThread = nullptr;
  st_thread_interrupt(t);
  st_thread_join(t, nullptr);
}
static void onGetTasks(const httplib::Request& req, httplib::Response& res)
{
  std::ostringstream oss;
  for (auto& iter : _tasks)
    oss << iter.second.stats(iter.first) << "\r\n";
  res.set_content(oss.str(), "text");
}
static void onPostTasks(const httplib::Request& req, httplib::Response& res)
{
  const std::string &app=req.matches[1], &playpath = req.matches[2];
  RTMP* rtmp=nullptr;
  int32_t fakeId = 0;
  do {
    std::string url;
    if (!req.has_header("REMOTE_ADDR")) {
      RTMP_Log(RTMP_LOGERROR, "req has no REMOTE_ADDR");
      ERR_BREAK(400);
    }
    else {
      std::ostringstream oss;
      oss << "rtmp://" << req.get_header_value("REMOTE_ADDR") << req.body;
      url = oss.str();
    }

    if (!(rtmp = ConnectURL(url, true)))
      ERR_BREAK(500);
    fakeId = RTMP_streamNextId++;
    if (HUB_AddPlayer(app, playpath, fakeId,
        HubPlayerPtr(new RtmpPlayer(*rtmp))) == 0
      && !setupPushing(app, playpath, fakeId)) {
      RTMP_Log(RTMP_LOGERROR, "setup %s/%s failed", app.c_str(), playpath.c_str());
      ERR_BREAK(500);
    }

    RTMP_PrintInfo(rtmp, RTMP_LOGCRIT, "PushTask");
    res.status = 200;
    go [=] {
      RTMPPacket packet = {0};
      while (RTMP_IsConnected(rtmp)
        && RTMP_ReadPacket(rtmp, &packet)) {
        if (!RTMPPacket_IsReady(&packet) || !packet.m_body)
          continue;
        RTMP_ClientPacket(rtmp, &packet);
        RTMPPacket_Free(&packet);
      }
      RTMPPacket_Free(&packet);
      HUB_Remove(fakeId);
      RTMP_Close(rtmp);
      delete rtmp;
    };
    return;
  } while(0);
  if (fakeId) HUB_Remove(fakeId);
  if (rtmp) RTMP_Close(rtmp);
  delete rtmp;
}
static void onGetTaskById(const httplib::Request& req, httplib::Response& res)
{
  SOCKET sockfd = (SOCKET)std::stoull(req.matches[1]);
  auto iter = _tasks.find(sockfd);
  if (iter == _tasks.end()) return;
  res.set_content(iter->second.stats(sockfd), "text");
}
static void onDeleteTaskById(const httplib::Request& req, httplib::Response& res)
{//ǿ�ƹر�����/����������
  SOCKET sockfd = (SOCKET)std::stoull(req.matches[1]);
  auto iter = _tasks.find(sockfd);
  if (iter == _tasks.end()) return;

  auto thread = iter->second.thread;
  iter->second.thread = nullptr;
  st_thread_interrupt(thread);
  st_thread_join(thread, nullptr);
}
static void onGetChunkedFlv(const httplib::Request& req, httplib::Response& res)
{
  const std::string &app=req.matches[1], &playpath = req.matches[2], &path = req.path;
  res.set_header("Content-Type","video/x-flv");
  res.set_header("Connection", "keep-alive");
  res.set_header("Transfer-Encoding","chunked");
  res.transfer = [=](httplib::StreamPtr& stream, bool chunked) {
    int32_t fakeId = RTMP_streamNextId++;
    if (!HUB_AddPlayer(app, playpath, fakeId,
        HubPlayerPtr(new HttpPlayer(stream, fakeId)))
      && !setupPushing(app, playpath, fakeId)) {
      RTMP_Log(RTMP_LOGERROR, "setup HTTP %s pushing failed", path.c_str());
      //���ܵ�HUB_Remove, ��Ϊ�˴� HTTP �Ựû�н���, ���ɶϿ���Ļص����
      return false;
    }
    return true;
  };
}
/*
�ӿ����:
   - GET /files ��ȡregex-URL��Ϣ
   - PUT /files ����ȫ���ļ�regex-URL��Ϣ
   - PATCH /files ���²����ļ� regex-URL��Ϣ

   - POST /rtmpsrv?port=1935 ���� RTMP-SRV ����
   - GET /rtmpsrv    ��ȡ RTMP-SRV ��Ϣ
   - DELETE /rtmpsrv �� ��RTMP-SRV ����

   - POST /tasks/<APP>/<PLAYPATH> �����µ�����
   - GET /tasks ��ȡ���е�����/��������ͳ��
   - GET /tasks/<ID>    ��ȡָ��������ͳ��
   - DELETE /tasks/<ID> ǿ�ƹر�ָ��������

   - GET /<APP>/<PLAYPATH>.flv ��ȡ httpflv ��
     ע��: <PLAYPATH> ���������'/'

��������:
                         /---3----|
                        /         V
   CLI <-1- SRV0 <-2- SRV1 <-6- SRV2
             \                   ^
              \-5->-------->-4---|
 
   1. CLI ���� httpflv ����
        curl SRV0/app/a0.flv --output b.flv
   2. SRV0 ����a0.flv ��Ӧ rtmp://SRV1/app/a1
        SRV1 ����RtmpSrv, SRV0 �� SRV1 ����
   3. SRV1 ����a1.flv ��Ӧ http://SRV2/tasks/app/a2 ����Զ������
        POST SRV2/tasks/app/a2 -d ':1935 app=app playpath=a1'
   4. SRV2 ������Ƶa2.flv, ��Ӧ http://SRV0/app/xxx.flv ��ȡhttpflv
        GET SRV0/app/xxx.flv
   5. SRV0 ��ȡ�����ļ�a/xxx.flv, ������ httpflv ��
   6. SRV2 ����SRV1����
        rtmp://SRV1/app/a1
�ļ���Ӧ��, �����б�:
SRV0: app/a0, app/a/xxx.flv
    ./app/a/xxx.flv
    app/a0 rtmp://SRV1/app/a1
SRV1: app/a1
    app/a1 http://SRV2/tasks/app/a2
SRV2: app/a2
    app/a2 http://SRV0/app/a/xxx.flv
 
��֤���
*/

int main(int argc, char* argv[])
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
      "- GET /files   all regex-URL-List\r\n"
      "- PUT /files   set regex-URL-List\r\n"
      "- PATCH /files update regex-URL-List\r\n"
      "RTMP Server:\r\n"
      "- POST /rtmpsrv?port=1935 start RTMP-SRV\r\n"
      "- GET /rtmpsrv       RTMP-SRV stats\r\n"
      "- DELETE /rtmpsrv    close RTMP-SRV\r\n"
      "RTMP Client: Push/Pull Task\r\n"
      "- POST /tasks/<APP>/<PLAYPATH>   start new pushing task\r\n"
      "- GET /tasks         all task stats\r\n"
      "- GET /tasks/<ID>    get task stats\r\n"
      "- DELETE /tasks/<ID> force close task\r\n"
      "HTTP FLV Stream:\r\n"
      "- GET /<APP>/<PLAYPATH>.flv  httpflv stream\r\n"
      "Examples:\r\n"
      "curl -X POST 10.211.55.17:5562/rtmpsrv -d 1\r\n"
      "curl -X PATCH 127.0.0.1:5562/files -d 'app/.* rtmp://10.211.55.17:1935'\r\n"
      "curl 127.0.0.1:5562/files\r\n"
      "curl http://127.0.0.1:5562/app/xxx.flv --output a.flv\r\n"
      "curl -X DELETE 10.211.55.17:5562/rtmpsrv\r\n"
      "ffmpeg -i theory.flv -f segment -segment_time 10 "
      "-segment_list theory.m3u8 theory/theory%d.ts\r\n"
      "./ffmpeg -f avfoundation -framerate 30 -i 0 "
      "-vcodec libx264 -f flv rtmp://127.0.0.1/app/xxx\r\n"
      "./rtmpdump  -r rtmp://127.0.0.1/app/xxx -o xxx.flv\r\n";
    res.set_content(help, "text/html");
  })
  .Post("/loglevel", [&](const httplib::Request& req, httplib::Response& res) {
    if (!RTMP_LogSetLevel2(req.body.c_str()))
      res.status = 400;
  })

  .Get("/files", onGetFiles)
  .Put("/files", onPutFiles)
  .Patch("/files", onPatchFiles)

  .Get("/rtmpsrv", onGetRtmpSrvStats)
  .Post("/rtmpsrv", onPostRtmpSrv)
  .Delete("/rtmpsrv", onDeleteRtmpSrv)

  .Get("/tasks", onGetTasks)
  .Post(R"(/tasks/(.+)/([^/]+))", onPostTasks)
  .Get(R"(/tasks/(\d+))", onGetTaskById)
  .Delete(R"(/tasks/(\d+))", onDeleteTaskById)

  .Get(R"(/(.+)/([^/]+)\.flv)", onGetChunkedFlv)

  .set_logger([](const httplib::Request& req, const httplib::Response& res) {
    join_threads();//��ʱ�����ѽ������߳�
  });

  const char* help =
    "Usage: %s [options]\r\n"
    "OPTIONS:\r\n"
    " -h, --help      \tPrint this message\r\n"
    " --port=5562     \tHttp service port\r\n"
    " --filecfg=<file>\tFile map config path\r\n"
    " --rootdir=<dir> \tHttp service root directory\r\n"
    " --rtmpsrv=1935  \tStart Rtmp service at port\r\n";

  int httpPort = 5562, rtmpPort = 0;
  const char *httpDir = nullptr, *fileCfg = nullptr;
  for(int i=1;i<argc;++i) {
    if (!strncmp(argv[i], "--port=", 7))
      httpPort = std::atoi(argv[i]+7);
    else if (!strncmp(argv[i], "--filecfg=", 10))
      fileCfg = argv[i]+10;
    else if (!strncmp(argv[i], "--rootdir=", 10))
      httpDir = argv[i]+10;
    else if (!strncmp(argv[i], "--rtmpsrv=", 10)) 
      rtmpPort = std::atoi(argv[i]+10);
    else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
      printf(help, argv[0]);
      return 0;
    } else {
      RTMP_Log(RTMP_LOGERROR, "Invalid `%s', use -h to print help", argv[i]);
      return -1;
    }
  }

  if (fileCfg) {
    std::stringstream body;
    std::ifstream t(fileCfg);
    if (!t) {
      RTMP_Log(RTMP_LOGERROR, "Invalid path of `--filecfg=%s'", fileCfg);
      return -1;
    }
    body << t.rdbuf();
    if (!UpdateFileAddrs(body.str(), _fileAddrs)) {
      RTMP_Log(RTMP_LOGERROR, "Invalid format of `--filecfg=%s'", fileCfg);
      return -1;
    }
  }
  if (rtmpPort && !startRtmpSrv(rtmpPort))
    return -1;

  if (httpDir && !http.set_base_dir(httpDir)) {
    RTMP_Log(RTMP_LOGERROR, "Invalid path of `--rootdir=%s'", httpDir);
    return -1;
  }
  RTMP_Log(RTMP_LOGCRIT, "HTTP-SRV at port=%d rootdir=%s", httpPort, httpDir);
  http.listen("*", httpPort);
  perror("HTTP-SRV listen");
  return -1;
}
