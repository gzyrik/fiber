#include <stdlib.h>
#include <stdio.h>
#include <librtmp/rtmp.h>
#include <librtmp/log.h>
#include <vector>
#include <string>
#include <unordered_map>
bool SendPlayStop(RTMP *r, const std::string& playpath);
struct StreamNode {
  StreamNode(RTMP* r=nullptr):publisher(r){
    memset(&meta, 0, sizeof(meta));
  }
  ~StreamNode() {
    cleargop();
  }
  RTMP* publisher;
  RTMPPacket meta;
  std::vector<RTMPPacket> gop;
  std::unordered_map<RTMP*, int32_t> players;
  void cleargop() {
    for(auto& packet : gop) RTMPPacket_Free(&packet);
    gop.clear();
  }
};
typedef std::unordered_map<std::string, StreamNode> PathMap;
typedef std::unordered_map<int32_t, PathMap::iterator> StreamMap;
static PathMap _paths;
static StreamMap _streams;
static void ErasePath(PathMap::iterator& iter, int32_t streamId = 0)
{
  _paths.erase(iter);
  //remove the stream
  if (streamId) {
    _streams.erase(streamId);
    return;
  }
  auto iter2 = _streams.begin();
  while (iter2 != _streams.end()) {
    if (iter2->second == iter) {
      _streams.erase(iter2);
      return;
    }
    ++iter2;
  }
}
void Hub_SetPublisher(const std::string& playpath, RTMP* r, int32_t streamId, bool live)
{
  auto iter = _paths.find(playpath);
  if (iter == _paths.end()) {
    if (!r || !streamId) return;// no exist, remove nothing.
    _streams[streamId] = _paths.emplace(playpath, r).first;
  }
  else if (!r)
    ErasePath(iter, streamId);
  else if (streamId) {//set publisher
    iter->second.publisher = r;
    _streams[streamId] = iter;
  }
}
void HUB_RemoveClient(RTMP* r)
{
  auto iter = _paths.begin();
  while (iter != _paths.end()) {
    auto& node = iter->second;
    if (node.publisher == r){
        node.publisher = nullptr;
        for(auto& p : node.players)
            SendPlayStop(p.first, iter->first);
    }
    else
        node.players.erase(r);
    auto cur = iter++;
    //remove the alone stream
    if (!node.publisher && node.players.empty())
      ErasePath(cur);
  }
}

void HUB_AddPlayer(const std::string& playpath, RTMP* r, int32_t streamId, double seekMs, double lenMs)
{
  auto& node = _paths[playpath];
  node.players.emplace(r, streamId);
  if (node.meta.m_nBodySize > 0) {
    node.meta.m_nInfoField2 = streamId;
    node.meta.m_headerType = RTMP_PACKET_SIZE_LARGE;
    RTMP_SendPacket(r, &node.meta, false);
  }
  for(auto& packet : node.gop){
    packet.m_nInfoField2 = streamId;
    packet.m_headerType = RTMP_PACKET_SIZE_LARGE;
    RTMP_SendPacket(r, &packet, false);
  }
}
void HUB_PublishPacket(RTMPPacket* packet)
{
  auto iter = _streams.find(packet->m_nInfoField2);
  if (iter == _streams.end())
      return;

  auto& node = iter->second->second;
  switch(packet->m_packetType)
  {
  case RTMP_PACKET_TYPE_INFO:
    RTMPPacket_Free(&node.meta);
    memcpy(&node.meta, packet, sizeof(RTMPPacket));
    break;
  case RTMP_PACKET_TYPE_AUDIO:
    node.gop.emplace_back(*packet);
    break;
  case RTMP_PACKET_TYPE_VIDEO:
    if (packet->m_body[0] & 0x10) //is key frame ?
      node.cleargop();
    node.gop.emplace_back(*packet);
    break;
  default:
    return;
  }
  for(auto& iter : node.players){
      packet->m_nInfoField2 = iter.second;
      packet->m_headerType = RTMP_PACKET_SIZE_LARGE;
      RTMP_SendPacket(iter.first, packet, false);
  }
  packet->m_body = NULL;
}
