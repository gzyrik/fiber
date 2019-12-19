#ifndef __RTMP_SRV_H__
#define __RTMP_SRV_H__
#include "rtmphub.h"
#include <librtmp/rtmp.h>
#include <librtmp/log.h>
class RtmpPlayer : public HubPlayer
{
  RTMP& rtmp;
  const bool onlyListen;
  bool SendPacket(RTMPPacket* packet) override {
    packet->m_nInfoField2 = rtmp.m_stream_id;
    return RTMP_SendPacket(&rtmp, packet, false);
  }
  bool UpdateChunkSize(int chunkSize) override {
    rtmp.m_outChunkSize = chunkSize;
    return RTMP_SendChunkSize(&rtmp);
  }
  bool OnlyListen() const override{ return onlyListen; }
public:
  RtmpPlayer(RTMP& r, bool listen) : rtmp(r), onlyListen(listen) {}
  ~RtmpPlayer() override { RTMP_Close(&rtmp); }
};
class RtmpPusher : public HubPusher
{
  RTMP& rtmp;
  const bool live;
  bool CanLiveAlone() const override { return live; };
  int GetChunkSize() override { return rtmp.m_inChunkSize; }
public:
  RtmpPusher (RTMP& r, bool live) : rtmp(r), live(live) {}
  ~RtmpPusher() override { RTMP_Close(&rtmp); }
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
  bool CanLiveAlone() const override { return false; }//按需动态请求文件
  int GetChunkSize() override { return 128; }
public:
  FilePusher(int32_t id) : streamId(id) {}
  //依靠!HUB_Publish()结束send_rtmp
  ~FilePusher() override { HUB_Remove(streamId); }
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
static RTMP* connectURL(std::string& url, bool write)
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
static void findFiles(const std::regex& reg, const std::string& dir, std::unordered_map<std::string, std::string>& files)
{
  auto& flist = files[dir];
#ifdef _WIN32
  struct _finddata_t finfo;
  auto handle = _findfirst((dir + "/*").c_str(), &finfo);
  if (handle != -1) {
    do {
      if (finfo.name[0] == '.')
        ;
      else if (finfo.attrib & _A_SUBDIR)
        findFiles(reg, dir + "/" + finfo.name, files);
      else if (std::regex_match (finfo.name, reg))
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
        findFiles(reg, dir + "/" + entry->d_name, files);
      else if (std::regex_match (entry->d_name, reg))
        flist.append(entry->d_name).push_back(',');
      else if (entry->d_type == 0) //d_type isnot POSIX, always retry 
        findFiles(reg, dir + "/" + entry->d_name, files);
      entry=readdir (dirp);
    }
    closedir (dirp);
  }
#endif
}
static std::string readStr(std::istream& is)
{//读取符号范围内字符串
  std::string str;
  is >> str;
  if (!str.empty()) {
    char c = str[0];
    if (ispunct(c) && c != '$' && c != '-' && c != '>' && c != '|' && c!= '/') {
      switch(c) {
      case '<': c = '>'; break;
      case '(': c = ')'; break;
      case '{': c = '}'; break;
      case '[': c = ']'; break;
      default: break;
      }
      std::string args;
      std::getline(is, args, c);
      str.erase(str.begin());
      str.append(args);
    }
  }
  return str;
}
typedef std::unordered_map<std::string, std::string> FileAddrMap;
static bool updateFileAddrs(const std::string& body, FileAddrMap& fileAddrs)
{
  std::istringstream iss(body);
  std::string url;
  while ((iss >> url) && !url.empty()) {
    auto addr = readStr(iss);
    if (addr.empty())
      fileAddrs.erase(url);
    else
      fileAddrs[url] = addr;
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
  const bool onlyListen;
  const int32_t streamId;
  httplib::StreamPtr stream;
  RTMPReader read;
  bool OnlyListen() const override { return onlyListen; }
  bool UpdateChunkSize(int chunkSize) override { return stream != nullptr; }
  bool SendPacket(RTMPPacket* packet) override {
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
  HttpPlayer(httplib::StreamPtr& s, int32_t id, bool listen)
    : stream(s), streamId(id), onlyListen(listen)
  {
    memset(&read, 0, sizeof(read));
    s->set_listen(this);
  }
  ~HttpPlayer() override {
    if (stream) {
      stream->set_listen(nullptr);
      stream->write_chunk(nullptr, 0);
      stream->close();
    }
    if (read.buf != NULL)
      free(read.buf);
  }
  void on_closed() override {
    if (!stream) return;
    stream = nullptr;
    HUB_Remove(streamId);
  }
};
static bool existFile(const std::string& input, const std::string& mode)
{
#ifdef _WIN32
  const int F_OK=0,W_OK=2,R_OK=4,X_OK=0;
#endif
  int flags = F_OK;
  for (const auto& c : mode)
  {
    switch(c) {
    case 'R': case 'r': flags |= R_OK; break;
    case 'W': case 'w': flags |= W_OK; break;
    case 'X': case 'x': flags |= X_OK; break;
    default: break;
    }
  }
  return access(input.c_str(), flags) == 0;
}
static bool checkFFmpeg(const std::string& addr, std::vector<std::string>& argv, std::string& redirect)
{
  std::istringstream iss(addr);
  std::string format, input;
  bool param = false;
  while (iss) {
    const auto& v = readStr(iss);
    if (v.empty())
      break;
    else if (v[0] == '>') {
      redirect = v.substr(1);
      redirect.append(readStr(iss));
      if (!iss.eof()) {
        RTMP_Log(RTMP_LOGERROR, "Invalid ffmpeg redirect: %s", addr.c_str());
        return false;
      }
      break;
    }

    argv.emplace_back(v);
    if (v == "-i") {
      argv.emplace_back(input = readStr(iss));
      param = false;
      //check input
      if (format == "avfoundation"){//MacOS 的设备
        //TODO
      }
      else if (!existFile(input, "r")) {
        RTMP_Log(RTMP_LOGERROR, "Invalid ffmpeg input: %s", input.c_str());
        return false;
      }
    }
    else if (v == "-f") {
      argv.emplace_back(format = readStr(iss));
      param = false;
    }
    else if (v[0] == '-')
      param = true;
    else if (param)
      param = false;
    else {
      RTMP_Log(RTMP_LOGERROR, "can't specify output: %s", addr.c_str());
      return false;
    }
  }
  if (input.empty()) { 
    RTMP_Log(RTMP_LOGERROR, "None ffmpeg inputs: %s", addr.c_str());
    return false;
  }
  return true;
}
static std::string lastErrorStr(int errCode = 0)
{
#ifdef _WIN32
  LPSTR lpMsgBuf;
  if (!errCode) errCode = GetLastError(); 
  FormatMessageA(
    FORMAT_MESSAGE_ALLOCATE_BUFFER | 
    FORMAT_MESSAGE_FROM_SYSTEM |
    FORMAT_MESSAGE_IGNORE_INSERTS,
    nullptr, errCode,
    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
    (LPSTR)&lpMsgBuf, 0, nullptr);
  std::string ret(lpMsgBuf);
  LocalFree(lpMsgBuf);
  while (!ret.empty()) {
    if ((ret.back()&0x80) || !isspace(ret.back()))
      break;
    ret.pop_back();
  }
  return ret;
#else
  return std::string(strerror(errCode));
#endif
}
static size_t spawnTask(const char* cmd, const std::vector<std::string>& params, const std::string& redirect)
{
#ifdef _WIN32
  std::ostringstream oss;
  for (auto& s : params) oss << s << ' ';
  STARTUPINFO si = {0};
  PROCESS_INFORMATION pi = {0};
  HANDLE hOutput = INVALID_HANDLE_VALUE;
  if (!redirect.empty()) {
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    hOutput = CreateFileA(redirect.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ,
      &sa, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hOutput == INVALID_HANDLE_VALUE) {
      RTMP_Log(RTMP_LOGERROR, "CreateFile(%s): %s", redirect.c_str(), lastErrorStr().c_str());
      return 0;
    }

    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdError = hOutput;
    si.hStdOutput = hOutput;
  }
  const auto& argv = oss.str();
  si.cb = sizeof(si);
  if (!CreateProcessA(cmd, (LPSTR)argv.c_str(), nullptr,  nullptr,
      true, CREATE_NEW_PROCESS_GROUP, nullptr, nullptr, &si, &pi)) {
    RTMP_Log(RTMP_LOGERROR, "CreateProcess(%s,%s): %s", cmd, argv.c_str(), lastErrorStr().c_str());
    return 0;
  }
  CloseHandle(pi.hThread);
  CloseHandle(pi.hProcess);
  CloseHandle(hOutput);
  return (size_t)pi.dwProcessId;
#else
  int status;
  pid_t pid = fork();
  if (pid < 0) {
    perror("fork");
    return 0;
  }
  else if (pid == 0) {
    char** argv = new char*[params.size()+1];
    for (size_t i = 0; i < params.size(); i++)
      argv[i] = (char*)params[i].c_str();
    argv[params.size()] = nullptr;

    if (!redirect.empty()) {
      int hOutput = ::open(redirect.c_str(), O_CREAT|O_WRONLY|O_APPEND,
        S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH);
      if (hOutput < 0) {
        RTMP_Log(RTMP_LOGERROR, "open(%s): %s", redirect.c_str(), lastErrorStr().c_str());
        exit(127);
      }
      if (dup2(hOutput, STDERR_FILENO) < 0)
        perror("dup2(STDERR_FILENO)");
      else if (dup2(hOutput, STDOUT_FILENO) < 0)
        perror("dup2(STDOUT_FILENO)");
      ::close(hOutput);
    }
    execv(cmd, argv);
    fprintf(stderr, "exec %s: %s\n", cmd, strerror(errno));
    _exit(127);
  }
  else if (waitpid(pid, &status, WNOHANG) != 0) {
    perror("waitpid");
    return 0;
  }
  return (size_t)pid;
#endif
}
static int killTask(size_t pid)
{
#ifdef _WIN32
  return GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, (DWORD)pid)
    ? 0 : GetLastError();
#else
  return kill((pid_t)pid, SIGTERM) ? errno : 0;
#endif
}
struct FFmpegTask : public HubPlayer {
  bool SendPacket(RTMPPacket* packet) override { return true; }
  bool UpdateChunkSize(int chunkSize) override { return true; }
  size_t pid;
  FFmpegTask(size_t p) : pid(p) {}
  bool OnlyListen() const override { return true; }
  ~FFmpegTask() override {
    auto ret = killTask(pid);
    RTMP_Log(ret ? RTMP_LOGERROR : RTMP_LOGCRIT, "kill %zu: %s", pid, lastErrorStr(ret).c_str());
  }
};
static void* send_stream_thread(RtmpStreamPtr fp, int streamId);
static void* pull_stream_thread(RTMP* rtmp, int32_t streamId);
#endif
