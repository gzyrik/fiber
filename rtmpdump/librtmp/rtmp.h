#ifndef __RTMP_H__
#define __RTMP_H__
/*
 *      Copyright (C) 2005-2008 Team XBMC
 *      http://www.xbmc.org
 *      Copyright (C) 2008-2009 Andrej Stepanchuk
 *      Copyright (C) 2009-2010 Howard Chu
 *
 *  This file is part of librtmp.
 *
 *  librtmp is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as
 *  published by the Free Software Foundation; either version 2.1,
 *  or (at your option) any later version.
 *
 *  librtmp is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with librtmp see the file COPYING.  If not, write to
 *  the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 *  Boston, MA  02110-1301, USA.
 *  http://www.gnu.org/copyleft/lgpl.html
 */

#if !defined(NO_CRYPTO) && !defined(CRYPTO)
#define CRYPTO
#endif

#include <errno.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "amf.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RTMP_LIB_VERSION	0x020300	/* 2.3 */

#define RTMP_FEATURE_HTTP	0x01
#define RTMP_FEATURE_ENC	0x02
#define RTMP_FEATURE_SSL	0x04
#define RTMP_FEATURE_MFP	0x08	/* not yet supported */
#define RTMP_FEATURE_WRITE	0x10	/* publish, not play */
#define RTMP_FEATURE_HTTP2	0x20	/* server-side rtmpt */

#define RTMP_PROTOCOL_UNDEFINED	-1
#define RTMP_PROTOCOL_RTMP      0
#define RTMP_PROTOCOL_RTMPE     RTMP_FEATURE_ENC
#define RTMP_PROTOCOL_RTMPT     RTMP_FEATURE_HTTP
#define RTMP_PROTOCOL_RTMPS     RTMP_FEATURE_SSL
#define RTMP_PROTOCOL_RTMPTE    (RTMP_FEATURE_HTTP|RTMP_FEATURE_ENC)
#define RTMP_PROTOCOL_RTMPTS    (RTMP_FEATURE_HTTP|RTMP_FEATURE_SSL)
#define RTMP_PROTOCOL_RTMFP     RTMP_FEATURE_MFP

#define RTMP_DEFAULT_CHUNKSIZE	128

/* needs to fit largest number of bytes recv() may return */
#define RTMP_BUFFER_CACHE_SIZE (16*1024)

#define	RTMP_CHANNELS	65600

extern const char RTMPProtocolStringsLower[][7];
extern const AVal RTMP_DefaultFlashVer;
extern bool RTMP_ctrlC;

uint32_t RTMP_GetTime(void);

/*      RTMP_PACKET_TYPE_...                0x00 */
#define RTMP_PACKET_TYPE_CHUNK_SIZE         0x01
/*      RTMP_PACKET_TYPE_...                0x02 */
#define RTMP_PACKET_TYPE_BYTES_READ_REPORT  0x03
#define RTMP_PACKET_TYPE_CONTROL            0x04
#define RTMP_PACKET_TYPE_SERVER_BW          0x05
#define RTMP_PACKET_TYPE_CLIENT_BW          0x06
/*      RTMP_PACKET_TYPE_...                0x07 */
#define RTMP_PACKET_TYPE_AUDIO              0x08
#define RTMP_PACKET_TYPE_VIDEO              0x09
/*      RTMP_PACKET_TYPE_...                0x0A */
/*      RTMP_PACKET_TYPE_...                0x0B */
/*      RTMP_PACKET_TYPE_...                0x0C */
/*      RTMP_PACKET_TYPE_...                0x0D */
/*      RTMP_PACKET_TYPE_...                0x0E */
#define RTMP_PACKET_TYPE_FLEX_STREAM_SEND   0x0F
#define RTMP_PACKET_TYPE_FLEX_SHARED_OBJECT 0x10
#define RTMP_PACKET_TYPE_FLEX_MESSAGE       0x11
#define RTMP_PACKET_TYPE_INFO               0x12
#define RTMP_PACKET_TYPE_SHARED_OBJECT      0x13
#define RTMP_PACKET_TYPE_INVOKE             0x14
/*      RTMP_PACKET_TYPE_...                0x15 */
#define RTMP_PACKET_TYPE_FLASH_VIDEO        0x16

#define RTMP_MAX_HEADER_SIZE 18

#define RTMP_PACKET_SIZE_LARGE    0
#define RTMP_PACKET_SIZE_MEDIUM   1
#define RTMP_PACKET_SIZE_SMALL    2
#define RTMP_PACKET_SIZE_MINIMUM  3

typedef struct RTMPChunk
{
  int c_headerSize;
  int c_chunkSize;
  char *c_chunk;
  char c_header[RTMP_MAX_HEADER_SIZE];
} RTMPChunk;

typedef struct RTMPPacket
{
  uint8_t m_headerType;
  uint8_t m_packetType;
  bool m_hasAbsTimestamp;	/* timestamp absolute or relative? */
  int m_nChannel;
  uint32_t m_nTimeStamp;	/* timestamp */
  int32_t m_nInfoField2;	/* last 4 bytes in a long header, is streamID */
  uint32_t m_nBodySize;
  uint32_t m_nBytesRead;
  RTMPChunk *m_chunk;
  char *m_body;
} RTMPPacket;

typedef struct RTMPSockBuf
{
  int sb_socket;
  int sb_size;		/* number of unprocessed bytes in buffer */
  char *sb_start;		/* pointer into sb_pBuffer of next byte to process */
  char sb_buf[RTMP_BUFFER_CACHE_SIZE];	/* data read from socket */
  int sb_timedout;
  void *sb_ssl;
} RTMPSockBuf;

void RTMPPacket_Reset(RTMPPacket *p);
void RTMPPacket_Dump(RTMPPacket *p);
bool RTMPPacket_Alloc(RTMPPacket *p, uint32_t bobySize);
void RTMPPacket_Free(RTMPPacket *p);

#define RTMPPacket_IsReady(a)	((a)->m_nBytesRead == (a)->m_nBodySize)
#define RTMPPacket_IsMedia(a)	((a)->m_packetType == RTMP_PACKET_TYPE_AUDIO || \
  (a)->m_packetType == RTMP_PACKET_TYPE_VIDEO || \
  (a)->m_packetType == RTMP_PACKET_TYPE_INFO || \
  (a)->m_packetType == RTMP_PACKET_TYPE_FLASH_VIDEO)

  typedef struct RTMP_LNK
  {
    AVal hostname;
    AVal sockshost;

    AVal playpath0;	/* parsed from URL */
    AVal playpath;	/* passed in explicitly */
    AVal tcUrl;
    AVal swfUrl;
    AVal pageUrl;
    AVal app;
    AVal auth;
    AVal flashVer;
    AVal subscribepath;
    AVal usherToken;
    AVal token;
    AVal pubUser;
    AVal pubPasswd;
    AMFObject extras;
    int edepth;

    int seekTime;
    int stopTime;

#define RTMP_LF_AUTH	0x0001	/* using auth param */
#define RTMP_LF_LIVE	0x0002	/* stream is live */
#define RTMP_LF_SWFV	0x0004	/* do SWF verification */
#define RTMP_LF_PLST	0x0008	/* send playlist before play */
#define RTMP_LF_BUFX	0x0010	/* toggle stream on BufferEmpty msg */
#define RTMP_LF_FTCU	0x0020	/* free tcUrl on close */
#define RTMP_LF_FAPU	0x0040	/* free app on close */
    int lFlags;

    int swfAge;

    int protocol;
    int timeout;		/* connection timeout in seconds */

    int pFlags;			/* unused, but kept to avoid breaking ABI */

    unsigned short socksport;
    unsigned short port;

#ifdef CRYPTO
#define RTMP_SWF_HASHLEN	32
    void *dh;			/* for encryption */
    void *rc4keyIn;
    void *rc4keyOut;

    uint32_t SWFSize;
    uint8_t SWFHash[RTMP_SWF_HASHLEN];
    char SWFVerificationResponse[RTMP_SWF_HASHLEN+10];
#endif
  } RTMP_LNK;

  /* state for read() wrapper */
  typedef struct RTMP_READ
  {
    char *buf;
    char *bufpos;
    unsigned int buflen;
    uint32_t timestamp;
    uint8_t dataType;
    uint8_t flags;
#define RTMP_READ_HEADER	0x01
#define RTMP_READ_RESUME	0x02
#define RTMP_READ_NO_IGNORE	0x04
#define RTMP_READ_GOTKF		0x08
#define RTMP_READ_GOTFLVK	0x10
#define RTMP_READ_SEEKING	0x20
    int8_t status;
#define RTMP_READ_COMPLETE	-3
#define RTMP_READ_ERROR	-2
#define RTMP_READ_EOF	-1
#define RTMP_READ_IGNORE	0

    /* if bResume == TRUE */
    uint8_t initialFrameType;
    uint32_t nResumeTS;
    char *metaHeader;
    char *initialFrame;
    uint32_t nMetaHeaderSize;
    uint32_t nInitialFrameSize;
    uint32_t nIgnoredFrameCounter;
    uint32_t nIgnoredFlvFrameCounter;
  } RTMP_READ;

  typedef struct RTMP_METHOD RTMP_METHOD;
  typedef struct RTMP RTMP;
  typedef struct RTMP_METABUF RTMP_METABUF;

  struct RTMP
  {
    int m_inChunkSize;
    int m_outChunkSize;
    int m_nBWCheckCounter;
    int m_nBytesIn;
    int m_nBytesInSent;
    int m_nBufferMS;
    int m_stream_id;		/* returned in _result from createStream */
    int m_mediaChannel;
    uint32_t m_mediaStamp;
    uint32_t m_pauseStamp;
    int m_pausing;
    int m_nServerBW;
    int m_nClientBW;
    uint8_t m_nClientBW2;
#define RTMP_STATE_PLAYING 1
#define RTMP_STATE_PUSHING 2
#define RTMP_STATE_WORKING (RTMP_STATE_PLAYING|RTMP_STATE_PUSHING)
    uint8_t m_state;
    uint8_t m_bSendEncoding;
    uint8_t m_bSendCounter;

    int m_numInvokes;
    int m_numCalls;
    RTMP_METHOD *m_methodCalls;	/* remote method calls queue */

    int m_channelsAllocatedIn;
    int m_channelsAllocatedOut;
    RTMPPacket **m_vecChannelsIn;
    RTMPPacket **m_vecChannelsOut;
    int *m_channelTimestamp;	/* abs timestamp of last packet */

    double m_fAudioCodecs;	/* audioCodecs for the connect packet */
    double m_fVideoCodecs;	/* videoCodecs for the connect packet */
    double m_fEncoding;		/* AMF0 or AMF3 */

    double m_fDuration;		/* duration of stream in seconds */

    int m_msgCounter;		/* RTMPT stuff */
    int m_polling;
    int m_resplen;
    int m_unackd;
    AVal m_clientID;

    RTMP_READ m_read;
    RTMPPacket m_write;
    RTMPSockBuf m_sb;
    RTMP_LNK Link;
    RTMP_METABUF *m_mbuf;
  };

void RTMP_Init(RTMP *r);
void RTMP_Close(RTMP *r);
void RTMP_EnableWrite(RTMP *r);
void RTMP_SetBufferMS(RTMP *r, int size);

/**
 * @defgroup private
 * @{
 */
int RTMP_ParseURL(const char *url, int *protocol, AVal *host,
  	     unsigned int *port, AVal *playpath, AVal *app);
void RTMP_ParsePlaypath(AVal *in, AVal *playpath);
int RTMP_SetOpt(RTMP *r, const AVal *opt, AVal *arg);
void RTMP_SetupStream(RTMP *r, int protocol,
  		AVal *hostname,
  		unsigned int port,
  		AVal *sockshost,
  		AVal *playpath,
  		AVal *tcUrl,
  		AVal *swfUrl,
  		AVal *pageUrl,
  		AVal *app,
  		AVal *auth,
  		AVal *swfSHA256Hash,
  		uint32_t swfSize,
  		AVal *flashVer,
  		AVal *subscribepath,
  		AVal *usherToken,
  		int dStart,
  		int dStop, int bLiveStream, long int timeout);
/**
 * @}
 */

bool RTMP_ReadPacket(RTMP *r, RTMPPacket *packet);
bool RTMP_SendPacket(RTMP *r, RTMPPacket *packet, bool queue);
int RTMP_SendChunk(RTMP *r, RTMPChunk *chunk);

int RTMP_IsConnected(RTMP *r);
int RTMP_Socket(RTMP *r);
int RTMP_State(RTMP* r);
int RTMP_IsTimedout(RTMP *r);
double RTMP_GetDuration(RTMP *r);
/**
 * @defgroup client only
 * @{
 */
bool RTMP_SetupURL(RTMP *r, char *url);
bool RTMP_Connect(RTMP *r, RTMPPacket *cp);
/* @return streamId */
int RTMP_ConnectStream(RTMP *r, int seekTime);
/* @return true if media packet. */
bool RTMP_ClientPacket(RTMP *r, RTMPPacket *packet);
int RTMP_ReconnectStream(RTMP *r, int seekTime);
int RTMP_ToggleStream(RTMP *r);
void RTMP_DeleteStream(RTMP *r);
/**
 * @}
 * @defgroup server only
 * @{
 */
bool RTMP_Serve(RTMP *r, int sockfd, void *tlsCtx);
/* @return streamId */
int RTMP_AcceptStream(RTMP *r, RTMPPacket *packet);
/* @return true if media packet. */
bool RTMP_ServePacket(RTMP *r, RTMPPacket *packet);
bool RTMP_SendPlayStop(RTMP *r, const AVal* playpath);
void *RTMP_TLS_AllocServerContext(const char* certFile, const char* keyFile);
void RTMP_TLS_FreeServerContext(void *tlsCtx);
/**
 * @}
 * @defgroup utils
 * @{
 */
int RTMP_LibVersion(void);
void RTMP_UserInterrupt(void);	/* user typed Ctrl-C */
void RTMP_PrintInfo(RTMP *rtmp, int loglevel, const char* prefix);
/**
 * @}
 */
enum RTMPCtrlType {
  /**
   * The server sends this event to notify the client
   * that a stream has become functional and can be
   * used for communication. By default, this event
   * is sent on ID 0 after the application connect
   * command is successfully received from the
   * client. The event data is 4-byte and represents
   * the stream ID of the stream that became
   * functional.
   */
  RTMP_CTRL_STREAM_BEGIN = 0x00,

  /**
   * The server sends this event to notify the client
   * that the playback of data is over as requested
   * on this stream. No more data is sent without
   * issuing additional commands. The client discards
   * the messages received for the stream. The
   * 4 bytes of event data represent the ID of the
   * stream on which playback has ended.
   */
  RTMP_CTRL_STREAM_EOF = 0x01,

  /**
   * The server sends this event to notify the client
   * that there is no more data on the stream. If the
   * server does not detect any message for a time
   * period, it can notify the subscribed clients
   * that the stream is dry. The 4 bytes of event
   * data represent the stream ID of the dry stream.
   */
  RTMP_CTRL_STREAM_DRY = 0x02,

  /**
   * The client sends this event to inform the server
   * of the buffer size (in milliseconds) that is
   * used to buffer any data coming over a stream.
   * This event is sent before the server starts
   * processing the stream. The first 4 bytes of the
   * event data represent the stream ID and the next
   * 4 bytes represent the buffer length, in
   * milliseconds. 8bytes event-data.
   */
  RTMP_CTRL_SET_BUFFER_MS = 0x03,

  /**
   * The server sends this event to notify the client
   * that the stream is a recorded stream. The
   * 4 bytes event data represent the stream ID of
   * the recorded stream.
   */
  RTMP_CTRL_STREAM_IS_RECORDED = 0x04,

  /**
   * The server sends this event to test whether the
   * client is reachable. Event data is a 4-byte
   * timestamp, representing the local server time
   * when the server dispatched the command. The
   * client responds with kMsgPingResponse on
   * receiving kMsgPingRequest.
   */
  RTMP_CTRL_PING = 0x06,

  /**
   * The client sends this event to the server in
   * response to the ping request. The event data is
   * a 4-byte timestamp, which was received with the
   * kMsgPingRequest request.
   */
  RTMP_CTRL_PONG = 0x07,

  /**
   * SWF verify request
   * For PCUC size=3, for example the payload is "00 1A 01",
   * it's a FMS control event, where the event type is 0x001a and event data is 0x01,
   * please notice that the event data is only 1 byte for this event.
   */
  RTMP_CTRL_SWF_VERIFY = 0x1A,

  /**
   * SWF verify response
   */
  RTMP_CTRL_SWF_HMAC_SHA256= 0x1B,
};

bool RTMP_SendCtrl(RTMP *r, enum RTMPCtrlType nType, unsigned nObject, unsigned nTime);

/* caller probably doesn't know current timestamp, should
 * just use RTMP_Pause instead
 */
int RTMP_SendPause(RTMP *r, int DoPause, int dTime);
int RTMP_Pause(RTMP *r, int DoPause);

int RTMP_SendSeek(RTMP *r, int dTime);
int RTMP_SendServerBW(RTMP *r);
bool RTMP_SendChunkSize(RTMP *r);
int RTMP_SendClientBW(RTMP *r);
void RTMP_UpdateBufferMS(RTMP *r);
void RTMP_DropRequest(RTMP *r, int i, int freeit);

/* rtmpread.c prepare for read */
bool RTMP_ResetRead(RTMP *r, FILE *flvFile, int nSkipKeyFrames);
uint32_t RTMP_GetReadTS(RTMP *r);
int RTMP_GetReadStatus(RTMP *r);
int RTMP_Read(RTMP *r, char *buf, int size);

int RTMP_Write(RTMP *r, const char *buf, int size);

/* hashswf.c */
int RTMP_HashSWF(const char *url, unsigned int *size, unsigned char *hash, int age);

/* h264aac.c */
int RTMP_WriteMeta(RTMP *r, const char* desc,
    double width, double height, double fps, double videoKbps,
    double sampleRate, double sampleSize, double channels, double audioKbps);
int RTMP_WriteNalu(RTMP *r, const char *buf, int size, unsigned timeStamp);
int RTMP_WriteAdts(RTMP *r, const char *buf, int size, unsigned timeStamp);

#ifdef __cplusplus
};
#endif

#endif
