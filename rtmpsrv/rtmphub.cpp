#include <stdlib.h>
#include <stdio.h>
#include <librtmp/rtmp.h>
#include <librtmp/log.h>
#include <vector>
#include <string>
#include <cstring>
#include <unordered_map>
#include "rtmphub.h"
//RTMP only do live, others using HLS
typedef std::unordered_map<std::string, struct Hub*> HubMap;//playpath->Hub
typedef HubMap::iterator HubIter;
typedef std::unordered_map<int32_t, HubIter> StreamMap;//streamId -> Hub
struct Kbps
{
};
struct App
{
  HubMap hubs;
  Kbps kbps;
};
typedef std::unordered_map<std::string, struct App> AppMap;
typedef AppMap::iterator AppIter;
static Kbps _kbps;
static StreamMap _streams;
static std::unordered_map<std::string, App> _apps;
struct Hub //转播结点
{
  const AppIter appIter;
  Hub(const AppIter& app=_apps.end()) : appIter(app), streamId(0), startMs(0) {
    memset(&meta, 0, sizeof(meta));
  }
  ~Hub() {
    RTMPPacket_Free(&meta);
    ClearGop();
  }

  RTMPPacket meta;
  std::vector<RTMPPacket> gop;

  void ClearGop() {
    for(auto& packet : gop) RTMPPacket_Free(&packet);
    gop.clear();
  }

  Kbps kbps;
  int32_t streamId;//pusher Id
  std::unique_ptr<HubPusher> pusher;
  uint32_t startMs;
  std::unordered_map<int32_t, std::unique_ptr<HubPlayer> > players;
};
class RtmpPlayer : public HubPlayer
{
  RTMP& rtmp;
  const int32_t streamId;
  virtual bool SendPacket(RTMPPacket* packet) override {
    packet->m_nInfoField2 = streamId;
    return RTMP_SendPacket(&rtmp, packet, false);
  }
  virtual bool UpdateChunkSize(int chunkSize) override {
    rtmp.m_outChunkSize = chunkSize;
    return RTMP_SendChunkSize(&rtmp);
  }
public:
  RtmpPlayer(RTMP& r, int32_t id) : rtmp(r), streamId(id) {}
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

void HUB_Remove(int32_t streamId)
{
  auto iter = _streams.find(streamId);
  if (iter == _streams.end())
    return;
  auto hubIter = iter->second;
  _streams.erase(iter);

  auto& hub = *(hubIter->second);
  auto* app = hub.appIter->first.c_str();
  auto* playpath = hubIter->first.c_str();
  if (hub.players.erase(streamId) > 0) {
    if (hub.players.size() > 0) 
      RTMP_Log(RTMP_LOGCRIT, "%s/%s: Player[%d] Removed, Remaind %d", app, playpath, streamId, (int)hub.players.size());
    else if (hub.pusher){
      RTMP_Log(RTMP_LOGCRIT, "%s/%s: Player[%d] Removed, Close Pusher[%d]", app, playpath, streamId, hub.streamId);
      hub.pusher = nullptr;
    }
  }

  if (hub.streamId == streamId) {
    RTMP_Log(RTMP_LOGCRIT, "%s/%s: Pusher[%d] Removed, Close All Players", app, playpath, streamId);
    hub.startMs = 0;
    hub.streamId = 0;
    hub.pusher = nullptr;
    hub.players.clear();
  }

  if (!hub.pusher && hub.players.empty()) {//remove the empty app
    auto appIter = hub.appIter;
    std::string path(playpath);
    auto& hubs = appIter->second.hubs;
    delete hubIter->second;
    hubs.erase(hubIter);
    if (hubs.empty()) {
      RTMP_Log(RTMP_LOGCRIT, "* Remove App: %s", app);
      _apps.erase(appIter);
    }
    else {
      RTMP_Log(RTMP_LOGCRIT, "* Remove playpath: %s/%s", app, path.c_str());
    }
  }
}
void HUB_MarkFlvStart(const std::string& app, const std::string& playpath, uint32_t startMs)
{
  auto appIter = _apps.find(app);
  if (appIter == _apps.end()){
    if (!startMs) return;
    appIter = _apps.emplace(app, App()).first;
  }
  auto& hubs = appIter->second.hubs;
  auto hubIter = hubs.find(playpath);
  if (hubIter == hubs.end()){
    if (!startMs) return;
    hubIter = hubs.emplace(playpath, new Hub(_apps.find(app))).first;
  }
  hubIter->second->startMs = startMs;//startMs > 0 是推流源已启动的标志
}
static uint32_t HUB_Add(const std::string& app, const std::string& playpath,
  int32_t streamId, std::unique_ptr<HubPlayer>&& player, std::unique_ptr<HubPusher>&& pusher) //返回对应FLV源的开始时刻
{
  auto& hubs = _apps[app].hubs;
  auto hubIter = hubs.find(playpath);
  if (hubIter == hubs.end())
    hubIter = hubs.emplace(playpath, new Hub(_apps.find(app))).first;
  _streams[streamId] = hubIter;

  auto& hub = *(hubIter->second);
  if (player) {
    RTMP_Log(RTMP_LOGCRIT, "%s/%s: add Player[%d]", app.c_str(), playpath.c_str(), streamId);
    if (hub.pusher) {
      player->UpdateChunkSize(hub.pusher->GetChunkSize());
      if (hub.meta.m_nBodySize > 0) 
        player->SendPacket(&hub.meta);
      for (auto& packet : hub.gop) {
        if (!_rtmpPort) break;
        player->SendPacket(&packet);
      }
    }
    std::swap(hub.players[streamId], player);
  }
  if (pusher) {
    int chunkSize = pusher->GetChunkSize();
    RTMP_Log(RTMP_LOGCRIT, "%s/%s: Update Pusher[%d] chunkSize=%d", app.c_str(), playpath.c_str(), streamId, chunkSize);
    hub.streamId = streamId;
    hub.startMs = RTMP_GetTime();

    for(auto& iter : hub.players){
      if (!_rtmpPort) break;
      iter.second->UpdateChunkSize(chunkSize);
    }
    std::swap(hub.pusher, pusher);
  }
  return hub.startMs;
}
uint32_t HUB_AddPlayer(const std::string& app, const std::string& playpath,
  int32_t streamId, std::unique_ptr<HubPlayer>&& player) 
{
  return HUB_Add(app, playpath, streamId, std::move(player), nullptr);
}
uint32_t HUB_SetPusher(const std::string& app, const std::string& playpath,
  int32_t streamId, std::unique_ptr<HubPusher>&& pusher)
{
  return HUB_Add(app, playpath, streamId, nullptr, std::move(pusher));
}
uint32_t HUB_AddRtmp(RTMP& r, int32_t streamId, bool isPlayer)
{
  const std::string app(r.Link.app.av_val, r.Link.app.av_len);
  const std::string playpath(r.Link.playpath.av_val, r.Link.playpath.av_len);
  return HUB_Add(app, playpath, streamId,
    std::unique_ptr<HubPlayer>(isPlayer ? new RtmpPlayer(r, streamId) : nullptr),
    std::unique_ptr<HubPusher>(!isPlayer ? new RtmpPusher(r) : nullptr));
}

void HUB_Publish(int32_t streamId, RTMPPacket* packet)
{
  auto iter = _streams.find(streamId);
  if (iter == _streams.end())
    return;

  packet->m_headerType = RTMP_PACKET_SIZE_LARGE;
  auto& hub = *(iter->second->second);
  switch(packet->m_packetType) {
  case RTMP_PACKET_TYPE_INFO:
    RTMPPacket_Free(&hub.meta);
    memcpy(&hub.meta, packet, sizeof(RTMPPacket));
    break;
  case RTMP_PACKET_TYPE_AUDIO:
    hub.gop.emplace_back(*packet);
    break;
  case RTMP_PACKET_TYPE_VIDEO:
    if (packet->m_body[0] & 0x10) //is key frame ?
      hub.ClearGop();
    hub.gop.emplace_back(*packet);
    break;
  default:
    return;
  }
  auto piter = hub.players.begin();
  while (_rtmpPort && piter != hub.players.end()) {
    auto cur = piter++;
    if (!cur->second->SendPacket(packet))
      hub.players.erase(cur);
  }
  packet->m_body = NULL;//move to hub.meta or hub.gop
  if (hub.pusher && hub.players.empty()) {
    RTMP_Log(RTMP_LOGCRIT, "All Player Removed, Close Pusher[%d]", hub.streamId);
    hub.pusher = nullptr;
  }
}
