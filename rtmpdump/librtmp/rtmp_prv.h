#pragma once
#include <stdlib.h>
#include <string.h>
#include "rtmp_sys.h"
#include "log.h"
#include "http.h"
struct RTMP_METHOD
{
  AVal name;
  int num;
};
struct RTMP_METABUF
{
  void* abuf, *vbuf;
  unsigned startStamp;
};

void FreeMetaBuf(RTMP* r);
struct sockaddr;
bool RTMP_Connect0(RTMP *r, struct sockaddr *svc, int addrlen);
bool RTMP_Connect1(RTMP *r, RTMPPacket *cp);

bool RTMP_TLS_Accept(RTMP *r, void *ctx);
int RTMPSockBuf_Fill(RTMPSockBuf *sb);
int RTMPSockBuf_Send(RTMPSockBuf *sb, const char *buf, int len);
int RTMPSockBuf_Close(RTMPSockBuf *sb);

int RTMP_FindFirstMatchingProperty(AMFObject *obj, const AVal *name, AMFObjectProperty * p);
int RTMP_GetNextMediaPacket(RTMP *r, RTMPPacket *packet);
#define STR2AVAL(av,str)	av.av_val = (char*)str; av.av_len = strlen(av.av_val)
