#include <stdlib.h>
#include <stdio.h>
#include <librtmp/rtmp.h>
#include <librtmp/log.h>
#include <vector>
#include <string>
#include <cstring>
#include <unordered_map>
extern int _rtmpPort;
//RTMP only do live, others using HLS
typedef std::unordered_map<std::string, struct Hub*> HubMap;
typedef HubMap::iterator HubIter;
typedef std::unordered_map<int32_t, HubIter> StreamMap;
struct Kbps
{
};
struct App {
  HubMap hubs; //playpath->Hub
  Kbps kbps;
};
typedef std::unordered_map<std::string, struct App> AppMap;
typedef AppMap::iterator AppIter;
struct Player {
  int32_t streamId;
  uint32_t createMs;
};
static Kbps _kbps;
static StreamMap _streams;
static std::unordered_map<std::string, App> _apps;
struct Hub 
{
  const AppIter appIter;
  Hub(const AppIter& app=_apps.end(), RTMP* r=nullptr)
    : appIter(app),pusher(r)
  {
    memset(&meta, 0, sizeof(meta));
  }
  ~Hub()
  {
    clear_gop();
  }
  uint32_t createMs;
  RTMP* pusher;
  std::unordered_map<RTMP*, Player> players;

  RTMPPacket meta;
  std::vector<RTMPPacket> gop;
  void clear_gop() {
    for(auto& packet : gop) RTMPPacket_Free(&packet);
    gop.clear();
  }
  Kbps kbps;
};

void HUB_Remove(int32_t streamId, RTMP* r)
{
  auto iter = _streams.find(streamId);
  if (iter == _streams.end())
    return;
  auto hubIter = iter->second;
  _streams.erase(iter);

  auto& hub = *(hubIter->second);
  if (hub.pusher == r) {
    hub.pusher = nullptr;
    RTMP_Log(RTMP_LOGCRIT, "Pusher[%d] Removed", streamId);
    const auto& playpath = hubIter->first;
    AVal aval={(char*)playpath.data(), (int)playpath.size()};
    for (auto& p : hub.players) {
      if (!_rtmpPort) break;
      RTMP_SendPlayStop(p.first, &aval);// pusher closed then notify its players
    }
  }
  else if (hub.players.erase(r) > 0) {
    RTMP_Log(RTMP_LOGCRIT, "Player[%d] Removed", streamId);
    if (hub.players.empty() && hub.pusher)
      RTMP_Close(hub.pusher);// no player then close the pusher
  }
  else
    return;

  if (!hub.pusher && hub.players.empty()) {//remove the empty app
    auto appIter = hub.appIter;
    auto& hubs = appIter->second.hubs;
    RTMP_Log(RTMP_LOGCRIT, "Remove playpath: %s",hubIter->first.c_str());
    delete hubIter->second;
    hubs.erase(hubIter);
    if (hubs.empty()){
      RTMP_Log(RTMP_LOGCRIT, "Remove App: %s",appIter->first.c_str());
      _apps.erase(appIter);
    }
  }
}

RTMP* HUB_Add(int32_t streamId, RTMP* r)
{
  const std::string app(r->Link.app.av_val, r->Link.app.av_len);
  const std::string playpath(r->Link.playpath.av_val, r->Link.playpath.av_len);
  auto& hubs = _apps[app].hubs;
  auto hubIter = hubs.find(playpath);
  if (hubIter == hubs.end())
    hubIter = hubs.emplace(playpath, new Hub(_apps.find(app))).first;
  _streams[streamId] = hubIter;

  auto& hub = *(hubIter->second);
  if (RTMP_State(r)&RTMP_STATE_PLAYING) {
    auto& p = hub.players[r];
    p.streamId = streamId;
    p.createMs = RTMP_GetTime();
    RTMP_Log(RTMP_LOGCRIT, "[%d]%s/%s: add Player[%d]", RTMP_Socket(r), app.c_str(), playpath.c_str(), streamId);
  }
  else if (hub.pusher != r) {
    RTMP_Log(RTMP_LOGCRIT, "[%d]%s/%s: add Pusher[%d]", RTMP_Socket(r), app.c_str(), playpath.c_str(), streamId);
    hub.pusher = r;
    hub.createMs = RTMP_GetTime();
    for(auto& p : hub.players){
      if (!_rtmpPort) break;
      if (p.first->m_outChunkSize != r->m_inChunkSize){
        p.first->m_outChunkSize = r->m_inChunkSize;
        RTMP_SendChunkSize(p.first);
      }
    }
  }
  if (hub.meta.m_nBodySize  > 0) {
    if (r->m_outChunkSize != hub.pusher->m_inChunkSize) {
      r->m_outChunkSize = hub.pusher->m_inChunkSize;
      RTMP_SendChunkSize(r);
    }
    hub.meta.m_nInfoField2 = streamId;
    RTMP_SendPacket(r, &hub.meta, false);
    for(auto& packet : hub.gop){
     if (!_rtmpPort) break;
      packet.m_nInfoField2 = streamId;
      RTMP_SendPacket(r, &packet, false);
    }
  }
  return hub.pusher;
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
      hub.clear_gop();
    hub.gop.emplace_back(*packet);
    break;
  default:
    return;
  }
  for(auto& i : hub.players){
    if (!_rtmpPort) break;
    packet->m_nInfoField2 = i.second.streamId;
    RTMP_SendPacket(i.first, packet, false);
  }
  packet->m_body = NULL;
}
