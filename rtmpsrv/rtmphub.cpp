#include <stdlib.h>
#include <stdio.h>
#include <vector>
#include <string>
#include <cstring>
#include <memory>
#include <unordered_map>
#include <librtmp/rtmp.h>
#include <librtmp/log.h>
#include "rtmphub.h"
//RTMP only do live, others using HLS
typedef std::unique_ptr<struct Hub> HubPtr;
typedef std::unordered_map<std::string, HubPtr> HubMap;//playpath->Hub
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
  HubPusherPtr pusher;
  uint32_t startMs;
  std::unordered_map<int32_t, HubPlayerPtr> players;
};
static void EraseHub(HubIter hubIter)
{//remove the empty app
  auto& hub = *(hubIter->second);
  auto appIter = hub.appIter;
  const std::string path(hubIter->first);
  auto& hubs = appIter->second.hubs;
  hubs.erase(hubIter);
  if (hubs.empty()) {
    RTMP_Log(RTMP_LOGCRIT, "* Remove App: %s", appIter->first.c_str());
    _apps.erase(appIter);
  }
  else 
    RTMP_Log(RTMP_LOGCRIT, "* Remove playpath: %s/%s", appIter->first.c_str(), path.c_str());
}
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
  if (hub.streamId == streamId)
    RTMP_Log(RTMP_LOGCRIT, "%s/%s\tPusher[%d] removed, close all players", app, playpath, streamId);
  else if (hub.players.erase(streamId) > 0) {
    for (auto& iter : hub.players) {
      if (!iter.second->OnlyListen()){
        RTMP_Log(RTMP_LOGCRIT, "%s/%s\tPlayer[%d] removed, remaind %d",
          app, playpath, streamId, (int)hub.players.size());
        return;
      }
    }
    if (hub.pusher && hub.pusher->CanLiveAlone()){
      RTMP_Log(RTMP_LOGCRIT, "%s/%s\tPlayer[%d] removed, pusher[%d] live, listens=%zu",
        app, playpath, streamId, hub.streamId, hub.players.size());
      return;
    }
    RTMP_Log(RTMP_LOGCRIT, "%s/%s\tPlayer[%d] removed, erase all listens=%zu",
      app, playpath, streamId, hub.players.size());
    _streams.erase(hub.streamId); //强制删除推送者
  }
  else {// can't reach here.
    RTMP_Log(RTMP_LOGERROR, "%s/%s\tInvalid StreamId=%d", app, playpath, streamId);
    return; 
  }

  for(auto& iter : hub.players)
    _streams.erase(iter.first);
  EraseHub(hubIter);
}
bool HUB_MarkBegin(const std::string& app, const std::string& playpath)
{
  auto& hubs = _apps[app].hubs;
  auto hubIter = hubs.find(playpath);
  if (hubIter == hubs.end())
    hubIter = hubs.emplace(playpath, HubPtr(new Hub(_apps.find(app)))).first;
  auto& hub = *(hubIter->second);
  if (hub.startMs != 0) return false;
  hub.startMs = RTMP_GetTime();//startMs > 0 是推流源已启动的标志
  RTMP_Log(RTMP_LOGCRIT, "%s/%s\tMark startMs=%u streamId=%d players=%zu",
    app.c_str(), playpath.c_str(), hub.startMs, hub.streamId, hub.players.size());
  return true;
}
bool HUB_MarkEnd(const std::string& app, const std::string& playpath)
{
  auto appIter = _apps.find(app);
  if (appIter == _apps.end())
    return true;
  auto& hubs = appIter->second.hubs;
  auto hubIter = hubs.find(playpath);
  if (hubIter == hubs.end())
    return true;
  auto& hub = *(hubIter->second);
  if (hub.streamId || !hub.players.empty())
    return false;
  EraseHub(hubIter);
  return true;
}
static uint32_t HUB_Add(const std::string& app, const std::string& playpath,
  int32_t streamId, HubPlayerPtr&& player, HubPusherPtr&& pusher) 
{//返回对应FLV源的开始时刻
  auto& hubs = _apps[app].hubs;
  auto hubIter = hubs.find(playpath);
  if (hubIter == hubs.end())
    hubIter = hubs.emplace(playpath, HubPtr(new Hub(_apps.find(app)))).first;
  _streams[streamId] = hubIter;

  auto& hub = *(hubIter->second);
  if (player) {
    bool ret = true;
    if (hub.pusher)
      ret = player->UpdateChunkSize(hub.pusher->GetChunkSize());
    if (ret && hub.meta.m_nBodySize > 0) 
      ret = player->SendPacket(&hub.meta);
    for (auto& packet : hub.gop) {
      if (!ret) break;
      ret = player->SendPacket(&packet);
    }

    if (ret) {
      RTMP_Log(RTMP_LOGDEBUG, "%s/%s\tAdd Player[%d]", app.c_str(), playpath.c_str(), streamId);
      std::swap(hub.players[streamId], player);
    }
    else 
      RTMP_Log(RTMP_LOGWARNING, "%s/%s\tFailed Player[%d]", app.c_str(), playpath.c_str(), streamId);
  }
  if (pusher) {
    int chunkSize = pusher->GetChunkSize();
    hub.streamId = streamId;
    hub.startMs = RTMP_GetTime();

    for(auto& iter : hub.players)
      iter.second->UpdateChunkSize(chunkSize);

    RTMP_Log(RTMP_LOGCRIT, "%s/%s\tUpdate Pusher[%d] chunkSize=%d startMs=%u players=%zu",
      app.c_str(), playpath.c_str(), streamId, chunkSize, hub.startMs, hub.players.size());
    std::swap(hub.pusher, pusher);
  }
  return hub.startMs;
}
uint32_t HUB_AddPlayer(const std::string& app, const std::string& playpath,
  int32_t streamId, HubPlayerPtr&& player) 
{
  return HUB_Add(app, playpath, streamId, std::move(player), nullptr);
}
uint32_t HUB_SetPusher(const std::string& app, const std::string& playpath,
  int32_t streamId, HubPusherPtr&& pusher)
{
  return HUB_Add(app, playpath, streamId, nullptr, std::move(pusher));
}
bool HUB_Publish(int32_t streamId, RTMPPacket* packet)
{
  auto iter = _streams.find(streamId);
  if (iter == _streams.end())
    return false;

  //packet->m_headerType = RTMP_PACKET_SIZE_LARGE;
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
    return false;
  }
  bool erased = false;
  auto piter = hub.players.begin();
  while (piter != hub.players.end()) {
    auto cur = piter++;
    if (!cur->second->SendPacket(packet)) {
      _streams.erase(cur->first);
      hub.players.erase(cur);
      erased = true;
    }
  }
  packet->m_body = NULL;//move to hub.meta or hub.gop

  if (erased && hub.pusher && !hub.pusher->CanLiveAlone()) {
    for (auto& iter :hub.players) {
      if (!iter.second->OnlyListen())
        return true;
    }
    RTMP_Log(RTMP_LOGCRIT, "All Player Removed, Close Pusher[%d]", hub.streamId);
    hub.pusher = nullptr;
    return false;
  }
  return true;
}
