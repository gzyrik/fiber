#include <stdlib.h>
#include <stdio.h>
#include <librtmp/rtmp.h>
#include <librtmp/log.h>
#include <vector>
#include <string>
#include <cstring>
#include <unordered_map>
typedef std::unordered_map<std::string, struct Hub> HubMap;
typedef HubMap::iterator HubIter;
typedef std::unordered_map<int32_t, HubIter> StreamMap;
typedef std::unordered_map<std::string, struct App> AppMap;
typedef AppMap::iterator AppIter;
struct Kbps
{
};
struct App {
  HubMap hubs; //playpath->Hub
  Kbps kbps;
};
struct Player {
  int32_t streamId;
  uint32_t createMs;
  double seekMs;
  double stopMs;
};
static Kbps _kbps;
static StreamMap _streams;
static std::unordered_map<std::string, App> _apps;
struct Hub 
{
  const AppIter appIter;
  Hub(const AppIter& app=_apps.end(), RTMP* r=nullptr, bool live=false)
    : appIter(app),publisher(r), live(live)
  {
    memset(&meta, 0, sizeof(meta));
  }
  ~Hub()
  {
    clear_gop();
  }
  RTMP* publisher;
  bool live;
  std::unordered_map<RTMP*, Player> players;

  RTMPPacket meta;
  std::vector<RTMPPacket> gop;
  void clear_gop() {
    for(auto& packet : gop) RTMPPacket_Free(&packet);
    gop.clear();
  }
  Kbps kbps;
};


static Hub* getHub(RTMP* r)
{
  auto appIter = _apps.find(
    std::string(r->Link.app.av_val, r->Link.app.av_len));
  if (appIter == _apps.end()) return nullptr;

  auto& hubs = appIter->second.hubs;
  auto iter2 = hubs.find(
    std::string(r->Link.playpath.av_val, r->Link.playpath.av_len));
  if (iter2 == hubs.end()) return nullptr;
  return &iter2->second;
}

bool HUB_IsLive(RTMP* r)
{
  auto hub = getHub(r);
  return hub && hub->live;
}

void HUB_RemoveClient(int32_t streamId, RTMP* r)
{
  auto iter = _streams.find(streamId);
  if (iter == _streams.end())
    return;
  auto hubIter = iter->second;
  _streams.erase(iter);

  auto& hub = hubIter->second;
  if (hub.publisher == r) {
    hub.publisher = nullptr;
    const auto& playpath = hubIter->first;
    AVal aval={(char*)playpath.data(), (int)playpath.size()};
    for(auto& p : hub.players)
      RTMP_SendPlayStop(p.first, &aval);
  }
  else if (!hub.players.erase(r))
    return;

  if (!hub.publisher && hub.players.empty()) {//remove the alone stream
    auto appIter =hub.appIter;
    auto& hubs = appIter->second.hubs;
    hubs.erase(hubIter);
    if (hubs.empty())
      _apps.erase(appIter);
  }
}

void HUB_SetPublisher(int32_t streamId, RTMP* r, bool live)
{
  const std::string app(r->Link.app.av_val, r->Link.app.av_len);
  const std::string playpath(r->Link.playpath.av_val, r->Link.playpath.av_len);
  auto& hubs = _apps[app].hubs;
  auto hubIter = hubs.find(playpath);
  if (hubIter == hubs.end()) {
    hubIter = hubs.emplace(playpath, Hub(_apps.find(app))).first;
  }
  _streams[streamId] = hubIter;

  auto& hub = hubIter->second;
  hub.publisher = r;
  hub.live = live;
  for(auto& i : hub.players) {
    if (i.first->m_outChunkSize != r->m_inChunkSize){
      i.first->m_outChunkSize = r->m_inChunkSize;
      RTMP_SendChunkSize(i.first);
    }
  }
}

void HUB_AddPlayer(int32_t streamId, RTMP* r, double seekMs, double stopMs)
{
  const std::string app(r->Link.app.av_val, r->Link.app.av_len);
  const std::string playpath(r->Link.playpath.av_val, r->Link.playpath.av_len);
  auto& hubs = _apps[app].hubs;
  auto hubIter = hubs.find(playpath);
  if (hubIter == hubs.end()) {
    hubIter = hubs.emplace(playpath, Hub(_apps.find(app))).first;
  }
  _streams[streamId] = hubIter;

  auto& hub = hubIter->second;
  auto& p = hub.players[r];
  p.streamId = streamId;
  p.seekMs = seekMs;
  p.stopMs = stopMs;
  p.createMs = RTMP_GetTime();
  if (hub.meta.m_nBodySize  == 0) return;
  if (r->m_outChunkSize != hub.publisher->m_inChunkSize) {
    r->m_outChunkSize = hub.publisher->m_inChunkSize;
    RTMP_SendChunkSize(r);
  }
  hub.meta.m_nInfoField2 = streamId;
  RTMP_SendPacket(r, &hub.meta, false);
  for(auto& packet : hub.gop){
    packet.m_nInfoField2 = streamId;
    RTMP_SendPacket(r, &packet, false);
  }
}

void HUB_PublishPacket(RTMPPacket* packet)
{
  auto iter = _streams.find(packet->m_nInfoField2);
  if (iter == _streams.end())
    return;

  packet->m_headerType = RTMP_PACKET_SIZE_LARGE;
  auto& hub = iter->second->second;
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
      hub.clear_gop();
    hub.gop.emplace_back(*packet);
    break;
  default:
    return;
  }
  for(auto& i : hub.players){
    packet->m_nInfoField2 = i.second.streamId;
    RTMP_SendPacket(i.first, packet, false);
  }
  packet->m_body = NULL;
}
