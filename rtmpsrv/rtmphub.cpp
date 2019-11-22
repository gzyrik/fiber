#include <stdlib.h>
#include <stdio.h>
#include <librtmp/rtmp.h>
#include <librtmp/log.h>
#include <vector>
#include <string>
#include <cstring>
#include <unordered_map>
#include "st.h"
extern int _rtmpPort;
//RTMP only do live, others using HLS
typedef std::unordered_map<std::string, struct Hub*> HubMap;//playpath->Hub
typedef HubMap::iterator HubIter;
typedef std::unordered_map<int32_t, HubIter> StreamMap;//streamId -> Hub
struct Kbps
{
};
struct App {
  HubMap hubs;
  Kbps kbps;
};
typedef std::unordered_map<std::string, struct App> AppMap;
typedef AppMap::iterator AppIter;
struct Node {
  RTMP* rtmp;
  int sock;
  uint32_t startMs;
};
static Kbps _kbps;
static StreamMap _streams;
static std::unordered_map<std::string, App> _apps;
struct Hub //转播结点
{
  const AppIter appIter;
  Hub(const AppIter& app=_apps.end()) : appIter(app)
  {
    memset(&meta, 0, sizeof(meta));
  }
  ~Hub()
  {
    clear_gop();
  }
  Node pusher;
  std::unordered_map<int32_t, Node> players;

  RTMPPacket meta;
  std::vector<RTMPPacket> gop;
  void clear_gop() {
    for(auto& packet : gop) RTMPPacket_Free(&packet);
    gop.clear();
  }
  Kbps kbps;
};

void HUB_Remove(int32_t streamId, RTMP* r, int sock)
{
  auto iter = _streams.find(streamId);
  if (iter == _streams.end())
    return;
  auto hubIter = iter->second;
  _streams.erase(iter);

  auto& hub = *(hubIter->second);
  if (hub.pusher.rtmp == r || hub.pusher.sock == sock) {
    hub.pusher.rtmp = nullptr;
    hub.pusher.sock = 0;
    RTMP_Log(RTMP_LOGCRIT, "Pusher[%d] Removed", streamId);
    // pusher closed then notify its players
    const auto& playpath = hubIter->first;
    AVal aval={(char*)playpath.data(), (int)playpath.size()};
    for (auto& i : hub.players) {
      if (!_rtmpPort) break;
      auto& p = i.second;
      if (p.rtmp) RTMP_SendPlayStop(p.rtmp, &aval);
    }
  }
  else if (hub.players.erase(streamId) > 0) {
    auto n = hub.players.size();
    if (n > 0) 
      RTMP_Log(RTMP_LOGCRIT, "Player[%d] Removed, Remaind %d", streamId, (int)n);
    else if (hub.pusher.rtmp || hub.pusher.sock){// no player then close the pusher
      if (hub.pusher.rtmp) RTMP_Close(hub.pusher.rtmp);
      if (hub.pusher.sock) closesocket(hub.pusher.sock);
      RTMP_Log(RTMP_LOGCRIT, "Player[%d] Removed, Close %s Pusher", streamId, hubIter->first.c_str());
      hub.pusher.rtmp = nullptr;
      hub.pusher.sock = 0;
    }
  }
  else
    return;

  if (!hub.pusher.rtmp && !hub.pusher.sock && hub.players.empty()) {//remove the empty app
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
  hubIter->second->pusher.startMs = startMs;//startMs > 0 是推流源已启动的标志
}
static uint32_t HUB_Add(const std::string& app, const std::string& playpath,
  int32_t streamId, bool isPlayer, RTMP* r, int sock)
{//返回对应FLV源的开始时刻
  auto& hubs = _apps[app].hubs;
  auto hubIter = hubs.find(playpath);
  if (hubIter == hubs.end())
    hubIter = hubs.emplace(playpath, new Hub(_apps.find(app))).first;
  _streams[streamId] = hubIter;

  auto& hub = *(hubIter->second);
  if (isPlayer) {
    auto& p = hub.players[streamId];
    p.rtmp = r;
    p.sock = sock;
    p.startMs = RTMP_GetTime();
    RTMP_Log(RTMP_LOGCRIT, "[%d]%s/%s: add Player[%d]", sock, app.c_str(), playpath.c_str(), streamId);
    if (hub.pusher.rtmp && r->m_outChunkSize != hub.pusher.rtmp->m_inChunkSize) {
      r->m_outChunkSize = hub.pusher.rtmp->m_inChunkSize;
      RTMP_SendChunkSize(r);
    }
    if (hub.meta.m_nBodySize) {
      hub.meta.m_nInfoField2 = streamId;
      RTMP_SendPacket(r, &hub.meta, false);
    }
    for(auto& packet : hub.gop){
      if (!_rtmpPort) break;
      packet.m_nInfoField2 = streamId;
      RTMP_SendPacket(r, &packet, false);
    }
  }
  else if (hub.pusher.rtmp != r || hub.pusher.sock != sock) {
    RTMP_Log(RTMP_LOGCRIT, "[%d]%s/%s: add Pusher[%d]", sock, app.c_str(), playpath.c_str(), streamId);
    hub.pusher.rtmp = r;
    hub.pusher.sock = sock;
    hub.pusher.startMs = RTMP_GetTime();
    for(auto& i : hub.players){
      if (!_rtmpPort) break;
      auto& p = i.second;
      if (p.rtmp && p.rtmp->m_outChunkSize != r->m_inChunkSize){
        p.rtmp->m_outChunkSize = r->m_inChunkSize;
        RTMP_SendChunkSize(p.rtmp);
      }
    }
  }
  return hub.pusher.startMs;
}
uint32_t HUB_AddRTMP(RTMP* r, int32_t streamId, bool isPlayer)
{
  return HUB_Add(
    std::string(r->Link.app.av_val, r->Link.app.av_len),
    std::string(r->Link.playpath.av_val, r->Link.playpath.av_len),
    streamId, isPlayer, r, RTMP_Socket(r));
}
uint32_t HUB_AddSock(int sock, const std::string& app, const std::string& playpath, int32_t streamId, bool isPlayer)
{
  return HUB_Add(app, playpath, streamId, isPlayer, nullptr, sock);
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
    packet->m_nInfoField2 = i.first;
    auto& p = i.second;
    if (p.rtmp)
      RTMP_SendPacket(p.rtmp, packet, false);
    else if (p.sock)
      send(p.sock, packet->m_body, packet->m_nBodySize, 0);
  }
  packet->m_body = NULL;
}
