#ifndef __RTMP_SRV_H__
#define __RTMP_SRV_H__
#include "rtmphub.h"
#include <librtmp/rtmp.h>
#include <librtmp/log.h>
class RtmpPlayer : public HubPlayer
{
  RTMP& rtmp;
  virtual bool SendPacket(RTMPPacket* packet) override {
    packet->m_nInfoField2 = rtmp.m_stream_id;
    return RTMP_SendPacket(&rtmp, packet, false);
  }
  virtual bool UpdateChunkSize(int chunkSize) override {
    rtmp.m_outChunkSize = chunkSize;
    return RTMP_SendChunkSize(&rtmp);
  }
public:
  RtmpPlayer(RTMP& r) : rtmp(r) {}
  virtual ~RtmpPlayer() override { RTMP_Close(&rtmp); }
};
class RtmpPusher : public HubPusher
{
  RTMP& rtmp;
  virtual int GetChunkSize() override { return rtmp.m_inChunkSize; }
public:
  RtmpPusher (RTMP& r) : rtmp(r) {}
  virtual ~RtmpPusher() override { RTMP_Close(&rtmp); }
};

class RtmpStream {
public:
  virtual SOCKET sockfd() = 0;
  virtual bool ok() const = 0;
  virtual size_t read(char* buf, size_t bytes) = 0;
  virtual ~RtmpStream() = default;
  static size_t read(void* fs, char* buf, size_t bytes)
  { return ((RtmpStream*)fs)->read(buf, bytes); }
};
typedef std::unique_ptr<RtmpStream> RtmpStreamPtr;
class FileStream : public RtmpStream {
  FILE* fp_;
  SOCKET sockfd() override { return fileno(fp_); }
  bool ok() const  override { return !feof(fp_); }
  size_t read(char* buf, size_t bytes) override {
    if (buf)
      return fread(buf, 1, bytes, fp_);
    if (fseek(fp_, bytes, SEEK_CUR) == 0)
      return bytes;
    return -1;
  }
public:
  FileStream(FILE* fp) : fp_(fp) {}
  ~FileStream() override { fclose(fp_); }
};
class HttpStream : public RtmpStream {
  httplib::StreamPtr stream_;
  SOCKET sockfd() override { return stream_->sockfd(); }
  bool ok() const  override { return stream_->ok(); }
  size_t read(char* buf, size_t bytes) override {
    if (buf)
      return stream_->read_chunk(buf, bytes);
    int i, n;
    for (i=0; i<bytes; i += n) {
      static char tmp[1024];
      n = bytes - i;
      if (n > sizeof(tmp)) n = sizeof(tmp);
      if ((n = stream_->read_chunk(tmp, n)) < 0)
        break;
    }
    return i;
  }
public:
  HttpStream(const httplib::StreamPtr& fp) : stream_(fp) {}
  ~HttpStream() override { stream_->close(); }
};
class FilePusher : public HubPusher
{
  const int32_t streamId;
  virtual int GetChunkSize() override { return 128; }
public:
  FilePusher(int32_t id) : streamId(id) {}
  //依靠!HUB_Publish()结束send_rtmp
  virtual ~FilePusher() override { HUB_Remove(streamId); }
};

static std::ostream& toURL(std::ostream& oss,  const std::string& url)
{
  if (url.empty()) return oss;
  size_t a=0,b=url.find_first_of("+ /?%#&=", a);
  while (b != url.npos) {
    if (b > a) oss<<url.substr(a, b-a);
    oss<<'%'<<std::hex<<(int)url[b];
    b = url.find_first_of("+ /?%#&=", a = b+1);
  }
  return oss<<url.substr(a);
}
static std::ostream& toURL(std::ostream& oss, const AVal& av)
{ return toURL(oss, std::string(av.av_val, av.av_len)); }
static FILE* openFile(const std::string& path)
{
  char buf[13];
  FILE* fp = fopen(path.c_str(), "rb");
  if (!fp) return nullptr;
  if (fread(buf, 1, 13, fp) == 13
    && buf[0] == 'F' && buf[1] == 'L' && buf[2] == 'V')
    return fp;
  fclose(fp);
  return nullptr;
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
static void FindFlvFiles(const std::string& dir, std::unordered_map<std::string, std::string>& files)
{
  static const std::regex flv(R"(.*\.flv)", std::regex::icase);
  auto& flist = files[dir];
#ifdef _WIN32
  struct _finddata_t finfo;
  auto handle = _findfirst((dir + "/*").c_str(), &finfo);
  if (handle != -1) {
    do {
      if (finfo.name[0] == '.')
        ;
      else if (finfo.attrib & _A_SUBDIR)
        FindFlvFiles(dir + "/" + finfo.name, files);
      else if (std::regex_match (finfo.name, flv))
        flist.append(finfo.name).push_back(',');
    } while (_findnext(handle, &finfo) == 0);
    _findclose(handle);
  }
#else
  DIR *dirp = opendir (dir.c_str());
  if (dirp) {
    struct dirent *entry = readdir (dirp);
    while (entry) {
      if (entry->d_name[0] == '.')
        ;
      else if (entry->d_type == DT_DIR)
        FindFlvFiles(dir + "/" + entry->d_name, files);
      else if (std::regex_match (entry->d_name, flv))
        flist.append(entry->d_name).push_back(',');
      else if (entry->d_type == 0) //d_type isnot POSIX, always retry 
        FindFlvFiles(dir + "/" + entry->d_name, files);
      entry=readdir (dirp);
    }
    closedir (dirp);
  }
#endif
}
typedef std::unordered_map<std::string, std::string> FileAddrMap;
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
struct TaskInfo {
  std::string app, playpath, url;
  st_thread_t thread;
  size_t bytes;
  uint32_t ts, len;
  std::string stats(SOCKET sockfd) {
    char buf[256];
    double percent =  ts / (len * 1000.0) * 100.0;
    sprintf(buf, "%s/%s\t/tasks/%zu\t%.3fkB/%.2fsec %.1f%%\t%s",
      app.c_str(), playpath.c_str(), (size_t)sockfd,
      (double) bytes / 1024.0, ts / 1000.0, ((double)(int)(percent * 10.0)) / 10.0, url.c_str());
    return buf;
  }
  TaskInfo(st_thread_t t, const std::string& a, const std::string& p, const std::string& u)
    : thread(t), app(a), playpath(p), url(u), bytes(0), ts(0), len(0){}
};
struct HttpPlayer : public HubPlayer, public httplib::Stream::Listen
{
  const int32_t streamId;
  httplib::StreamPtr stream;
  RTMPReader read;
  virtual bool UpdateChunkSize(int chunkSize) override { return stream != nullptr; }
  virtual bool SendPacket(RTMPPacket* packet) override {
    if (!stream) return false; //closed by httplib
    do {
      char buf[4096];
      int ret = RTMPPacket_Read(packet, &read, buf, sizeof(buf));
      if (ret <= 0) break;
      if (!stream->write_chunk(buf, ret))
        return false;
      packet = NULL;
    } while (read.buf != NULL);
    return true;
  }
public:
  HttpPlayer(httplib::StreamPtr& s, int32_t id) : stream(s), streamId(id) {
    memset(&read, 0, sizeof(read));
    s->set_listen(this);
  }
  virtual ~HttpPlayer() override {
    if (stream) {
      stream->set_listen(nullptr);
      stream->close();
    }
    if (read.buf != NULL)
      free(read.buf);
  }
  virtual void on_closed() override {
    if (!stream) return;
    stream = nullptr;
    HUB_Remove(streamId);
  }
};
static void* send_stream_thread(RtmpStreamPtr fp, int streamId);
static void* pull_stream_thread(RTMP* rtmp, int32_t streamId);
#endif
