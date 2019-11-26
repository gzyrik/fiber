#ifndef __RTMP_HUB_H__
#define __RTMP_HUB_H__
class HubPlayer
{
public:
  virtual ~HubPlayer(){}
  virtual bool UpdateChunkSize(int chunkSize) = 0;
  virtual bool SendPacket(struct RTMPPacket* packet) = 0;
};
class HubPusher
{
public:
  virtual ~HubPusher(){}
  virtual int GetChunkSize() = 0;
};
void HUB_MarkFlvStart(const std::string& app, const std::string& playpath, uint32_t startMs);
//返回对应Pusher的开始时刻
uint32_t HUB_AddPlayer(const std::string& app, const std::string& playpath,
  int32_t streamId, std::unique_ptr<HubPlayer>&& player);
uint32_t HUB_SetPusher(const std::string& app, const std::string& playpath,
  int32_t streamId, std::unique_ptr<HubPusher>&& pusher);
void HUB_Remove(int32_t streamId);
void HUB_Publish(int32_t streamId, RTMPPacket* packet);
uint32_t HUB_AddRtmp(RTMP& r, int32_t streamId, bool isPlayer);
extern int _rtmpPort;
#endif
