#ifndef __RTMP_HUB_H__
#define __RTMP_HUB_H__
#include <memory>
class HubPlayer
{
public:
  virtual ~HubPlayer() = default;
  virtual bool UpdateChunkSize(int chunkSize) = 0;
  virtual bool SendPacket(struct RTMPPacket* packet) = 0;
};
class HubPusher
{
public:
  virtual ~HubPusher() = default;
  virtual int GetChunkSize() = 0;
};
typedef std::unique_ptr<HubPlayer> HubPlayerPtr;
typedef std::unique_ptr<HubPusher> HubPusherPtr;

bool HUB_MarkBegin(const std::string& app, const std::string& playpath);
bool HUB_MarkEnd(const std::string& app, const std::string& playpath);
//返回对应Pusher的开始时刻
uint32_t HUB_AddPlayer(const std::string& app, const std::string& playpath,
  int32_t streamId, HubPlayerPtr&& player);
uint32_t HUB_SetPusher(const std::string& app, const std::string& playpath,
  int32_t streamId, HubPusherPtr&& pusher);
void HUB_Remove(int32_t streamId);
bool HUB_Publish(int32_t streamId, RTMPPacket* packet);
#endif
