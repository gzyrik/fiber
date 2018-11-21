#include "rtmp_prv.h"
#include <string.h>
#include <stdlib.h>
SAVC(onMetaData);
SAVC(duration);
SAVC(width);
SAVC(height);
SAVC(videocodecid);
SAVC(videodatarate);
SAVC(framerate);
SAVC(audiocodecid);
SAVC(audiodatarate);
SAVC(audiosamplerate);
SAVC(audiosamplesize);
SAVC(audiochannels);
SAVC(stereo);
SAVC(avc1);
SAVC(mp4a);
SAVC(encoder);
SAVC(fileSize);
SAVC2(setDataFrame, "@setDataFrame");
struct H264Buf
{
  unsigned lastStamp;
#define MAX_SPS_SIZE 50
#define MAX_PPS_SIZE 50
  unsigned spsSize;
  unsigned ppsSize;
  unsigned bodySize;
  uint8_t sps[MAX_SPS_SIZE];
  uint8_t pps[MAX_PPS_SIZE];
  uint8_t head[RTMP_MAX_HEADER_SIZE];
  uint8_t body[4];
};
struct AacBuf
{
#define AAC_HEAD_SIZE 7
  int bFirstAAC;
  unsigned bodySize;
  uint8_t head[RTMP_MAX_HEADER_SIZE];
  uint8_t body[4];
};
void FreeMetaBuf(RTMP* r)
{
  if (!r->m_mbuf) return;
  if (r->m_mbuf->vbuf) free(r->m_mbuf->vbuf);
  if (r->m_mbuf->abuf) free(r->m_mbuf->abuf);
  free(r->m_mbuf);
  r->m_mbuf = NULL;
}
int RTMP_WriteMeta(RTMP *r, const char* desc,
  double width, double height, double fps, double videoKbps,
  double sampleRate, double sampleSize, double channels, double audioKbps)
{
  RTMPPacket packet;
  char *enc;
  AVal encoder;
  char pbuf[2048], *pend = pbuf+sizeof(pbuf);

  FreeMetaBuf(r);
  r->m_mbuf = calloc(1, sizeof(RTMP_METABUF));
  if (!r->m_mbuf)
    return FALSE;
  r->m_mbuf->vbuf = calloc(1, sizeof(struct H264Buf)+width*height*3/2);
  r->m_mbuf->abuf = calloc(1, sizeof(struct AacBuf)+channels*sampleSize/8*sampleRate*60/1000);//60ms
  if (!r->m_mbuf->vbuf || !r->m_mbuf->abuf){
    FreeMetaBuf(r);
    return FALSE;
  }

  packet.m_nChannel = 0x03;     // control channel (invoke)
  packet.m_headerType = RTMP_PACKET_SIZE_LARGE;
  packet.m_packetType = RTMP_PACKET_TYPE_INFO;
  packet.m_nTimeStamp = 0;
  packet.m_nInfoField2 = r->m_stream_id;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av_setDataFrame);
  enc = AMF_EncodeString(enc, pend, &av_onMetaData);

  *enc++ = AMF_OBJECT;
  enc = AMF_EncodeNamedNumber(enc, pend, &av_duration,        0.0);
  enc = AMF_EncodeNamedNumber(enc, pend, &av_fileSize,        0.0);
  enc = AMF_EncodeNamedNumber(enc, pend, &av_width,           width);
  enc = AMF_EncodeNamedNumber(enc, pend, &av_height,          height);
  enc = AMF_EncodeNamedString(enc, pend, &av_videocodecid,    &av_avc1);
  enc = AMF_EncodeNamedNumber(enc, pend, &av_videodatarate,   videoKbps);
  enc = AMF_EncodeNamedNumber(enc, pend, &av_framerate,       fps);
  enc = AMF_EncodeNamedString(enc, pend, &av_audiocodecid,    &av_mp4a);
  enc = AMF_EncodeNamedNumber(enc, pend, &av_audiodatarate,   audioKbps); //ex. 128kb\s
  enc = AMF_EncodeNamedNumber(enc, pend, &av_audiosamplerate, sampleRate); //ex. 44100
  enc = AMF_EncodeNamedNumber(enc, pend, &av_audiosamplesize, sampleSize); //ex. 16
  enc = AMF_EncodeNamedNumber(enc, pend, &av_audiochannels,   channels);
  enc = AMF_EncodeNamedBoolean(enc, pend, &av_stereo,         FALSE);
  encoder.av_val = (char*)desc; encoder.av_len = strlen(desc);
  enc = AMF_EncodeNamedString(enc, pend, &av_encoder,         &encoder);
  *enc++ = 0;
  *enc++ = 0;
  *enc++ = AMF_OBJECT_END;

  packet.m_nBodySize = enc - packet.m_body;
  if (!RTMP_SendPacket(r, &packet, FALSE))
    return FALSE;
  return TRUE;
}

static int FileAVCData(struct H264Buf* avc1, const char *data, unsigned size)
{
  uint8_t* body = avc1->body;
  unsigned i = avc1->bodySize;
  const int bIsKeyFrame = (data[0]&0x1f) == 5;
  if(bIsKeyFrame)
  {
    if(i == 0)
    {
      body[i++] = 0x17;// 1:Iframe  7:AVC
      body[i++] = 0x01;// AVC NALU
      body[i++] = 0x00;
      body[i++] = 0x00;
      body[i++] = 0x00;
    }
    // NALU size
    body[i++] = size>>24 &0xff;
    body[i++] = size>>16 &0xff;
    body[i++] = size>>8 &0xff;
    body[i++] = size&0xff;

    // NALU data
    memcpy(&body[i],data,size);
    i+=size;
  }
  else
  {
    if(i == 0)
    {
      body[i++] = 0x27;// 2:Pframe  7:AVC
      body[i++] = 0x01;// AVC NALU
      body[i++] = 0x00;
      body[i++] = 0x00;
      body[i++] = 0x00;
    }
    // NALU size
    body[i++] = size>>24 &0xff;
    body[i++] = size>>16 &0xff;
    body[i++] = size>>8 &0xff;
    body[i++] = size&0xff;

    // NALU data
    memcpy(&body[i],data,size);
    i+=size;
  }
  avc1->bodySize = i;
  return TRUE;
}
static int FillAVCSequence(uint8_t* body,
  uint8_t* sps, int sps_len, uint8_t* pps, int pps_len)
{
  int i = 0;
  body[i++] = 0x17;
  body[i++] = 0x00;

  body[i++] = 0x00;
  body[i++] = 0x00;
  body[i++] = 0x00;

  /*AVCDecoderConfigurationRecord*/
  body[i++] = 0x01;
  body[i++] = sps[1];
  body[i++] = sps[2];
  body[i++] = sps[3];
  body[i++] = 0xff;

  /*sps*/
  body[i++]   = 0xe1;
  body[i++] = (sps_len >> 8) & 0xff;
  body[i++] = sps_len & 0xff;
  memcpy(&body[i],sps,sps_len);
  i +=  sps_len;

  /*pps*/
  body[i++]   = 0x01;
  body[i++] = (pps_len >> 8) & 0xff;
  body[i++] = (pps_len) & 0xff;
  memcpy(&body[i],pps,pps_len);
  i +=  pps_len;
  return i;
}
static int SendPacket(RTMP *r, int bIsAudio, uint8_t *body, unsigned bodySize, uint32_t nTimestamp)
{
  if (!bodySize) return TRUE;
  RTMPPacket packet;
  packet.m_nChannel = (bIsAudio ? 0x5 : 0x4);
  packet.m_body = (char*)body;
  packet.m_nBodySize = bodySize;
  packet.m_hasAbsTimestamp = 1;
  packet.m_packetType = bIsAudio ? RTMP_PACKET_TYPE_AUDIO : RTMP_PACKET_TYPE_VIDEO;
  packet.m_nInfoField2 = r->m_stream_id;
  packet.m_nTimeStamp = nTimestamp;
  packet.m_headerType = (bIsAudio && bodySize !=4) ? RTMP_PACKET_SIZE_MEDIUM : RTMP_PACKET_SIZE_LARGE;
  return RTMP_SendPacket(r, &packet, FALSE);
}
int RTMP_WriteNalu(RTMP *r, const char *buf, int size, unsigned timestamp)
{
  struct H264Buf* avc1;
  if(r->m_mbuf == NULL || buf == NULL || size <= 0)
    return FALSE;
  avc1= (struct H264Buf*)(r->m_mbuf->vbuf);
  if (r->m_mbuf->startStamp == 0)
    r->m_mbuf->startStamp = timestamp;

  timestamp -= r->m_mbuf->startStamp;
  if (avc1->lastStamp != timestamp)
  {
    if (!SendPacket(r, FALSE, avc1->body, avc1->bodySize, avc1->lastStamp))
      return FALSE;
    avc1->lastStamp = timestamp;
    avc1->bodySize = 0;
  }

  switch(buf[0]&0x1f)
  {
  case 7: /* SPS */
    avc1->spsSize = size;
    memcpy(avc1->sps, buf, size);
    return TRUE;
  case 8: /* PPS */
    avc1->ppsSize = size;
    memcpy(avc1->pps, buf, size);
    return TRUE;
  case 5: /* IDR */
    if(avc1->spsSize > 0 && avc1->ppsSize > 0)
    {
      avc1->bodySize = FillAVCSequence(avc1->body,
        avc1->sps, avc1->spsSize, avc1->pps, avc1->ppsSize);
      avc1->spsSize = 0;
      avc1->ppsSize = 0;
    }
  default:
    return FileAVCData(avc1, buf, size);
  }
}

int RTMP_WriteAdts(RTMP *r, const char *buf, int size, unsigned timestamp)
{
  uint8_t* body;
  struct AacBuf* aac;
  if(r->m_mbuf == NULL || buf == NULL || size < AAC_HEAD_SIZE)
    return FALSE;
  aac= (struct AacBuf*)(r->m_mbuf->abuf);
  if (r->m_mbuf->startStamp == 0)
    r->m_mbuf->startStamp = timestamp;

  timestamp -= r->m_mbuf->startStamp;
  body = aac->body;
  if (aac->bFirstAAC){
    const int profile = ((buf[2]&0xc0)>>6)+1;
    const int sample_rate = (buf[2]&0x3c)>>2;
    const int channel = ((buf[2]&0x1)<<2)|((buf[3]&0xc0)>>6);
    body[0] = 0xae;// a:AAC
    body[1] = 0x00;// AAC sequence header
    body[2] = (profile<<3)|((sample_rate&0xe)>>1);
    body[3] = ((sample_rate&0x1)<<7)|(channel<<3);
    aac->bFirstAAC = FALSE;
    if (!SendPacket(r, TRUE, body, 4, timestamp))
      return FALSE;
  }
  body[0] = 0xae;// a:AAC
  body[1] = 0x01;// AAC raw
  size -= AAC_HEAD_SIZE;
  memcpy(body+2, buf+AAC_HEAD_SIZE, size);
  return SendPacket(r, TRUE, body, size+2, timestamp);
}
