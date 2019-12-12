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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <ctype.h>

#include "rtmp_prv.h"

#ifdef CRYPTO
#ifdef USE_POLARSSL
#include <polarssl/havege.h>
#include <polarssl/md5.h>
#include <polarssl/base64.h>
#define MD5_DIGEST_LENGTH 16

static const char *my_dhm_P =
    "E4004C1F94182000103D883A448B3F80" \
    "2CE4B44A83301270002C20D0321CFD00" \
    "11CCEF784C26A400F43DFB901BCA7538" \
    "F2C6B176001CF5A0FD16D2C48B1D0C1C" \
    "F6AC8E1DA6BCC3B4E1F96B0564965300" \
    "FFA1D0B601EB2800F489AA512C4B248C" \
    "01F76949A60BB7F00A40B1EAB64BDD48" \
    "E8A700D60B7F1200FA8E77B0A979DABF";

static const char *my_dhm_G = "4";

#elif defined(USE_GNUTLS)
#include <gnutls/gnutls.h>
#define MD5_DIGEST_LENGTH 16
#include <nettle/base64.h>
#include <nettle/md5.h>
#else	/* USE_OPENSSL */
#include <openssl/ssl.h>
#include <openssl/rc4.h>
#include <openssl/md5.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#endif
static TLS_CTX RTMP_TLS_ctx;
#endif

#define RTMP_SIG_SIZE 1536
#define RTMP_LARGE_HEADER_SIZE 12

static const int packetSize[] = { 12, 8, 4, 1 };

bool RTMP_ctrlC;
int32_t RTMP_streamNextId = 1;

const char RTMPProtocolStrings[][7] = {
  "RTMP",
  "RTMPT",
  "RTMPE",
  "RTMPTE",
  "RTMPS",
  "RTMPTS",
  "",
  "",
  "RTMFP"
};

const char RTMPProtocolStringsLower[][7] = {
  "rtmp",
  "rtmpt",
  "rtmpe",
  "rtmpte",
  "rtmps",
  "rtmpts",
  "",
  "",
  "rtmfp"
};

static const char *RTMPT_cmds[] = {
  "open",
  "send",
  "idle",
  "close"
};

typedef enum {
  RTMPT_OPEN=0, RTMPT_SEND, RTMPT_IDLE, RTMPT_CLOSE
} RTMPTCmd;

static int DumpMetaData(AMFObject *obj);
static int HandShake(RTMP *r, int FP9HandShake);
static int SocksNegotiate(RTMP *r);

static int SendConnectPacket(RTMP *r, RTMPPacket *cp);
static int SendCheckBW(RTMP *r);
static int SendCheckBWResult(RTMP *r, double txn);
static int SendDeleteStream(RTMP *r, double dStreamId);
static int SendFCSubscribe(RTMP *r, AVal *subscribepath);
static int SendPlay(RTMP *r);
static int SendBytesReceived(RTMP *r);
static int SendUsherToken(RTMP *r, AVal *usherToken);

#if 0				/* unused */
static int SendBGHasStream(RTMP *r, double dId, AVal *playpath);
#endif

static int HandleInvoke(RTMP *r, bool bServer, RTMPPacket *packet, unsigned offset);
static void HandleChangeChunkSize(RTMP *r, const RTMPPacket *packet);
static void HandleAudio(RTMP *r, const RTMPPacket *packet);
static void HandleVideo(RTMP *r, const RTMPPacket *packet);
static void HandleCtrl(RTMP *r, const RTMPPacket *packet);
static void HandleServerBW(RTMP *r, const RTMPPacket *packet);
static void HandleClientBW(RTMP *r, const RTMPPacket *packet);

static int ReadN(RTMP *r, char *buffer, int n);
static int WriteN(RTMP *r, const char *buffer, int n);

static void DecodeTEA(AVal *key, AVal *text);

static int HTTP_Post(RTMP *r, RTMPTCmd cmd, const char *buf, int len);
static int HTTP_read(RTMP *r, int fill);

static void CloseInternal(RTMP *r, int reconnect);

#ifndef _WIN32
static int clk_tck;
#endif

#ifdef CRYPTO
#include "handshake.h"
#endif
SAVC(0);
SAVC(app);
SAVC(connect);
SAVC(flashVer);
SAVC(swfUrl);
SAVC(pageUrl);
SAVC(tcUrl);
SAVC(fpad);
SAVC(capabilities);
SAVC(audioCodecs);
SAVC(videoCodecs);
SAVC(videoFunction);
SAVC(objectEncoding);
SAVC(secureToken);
SAVC(secureTokenResponse);
SAVC(type);
SAVC(nonprivate);
SAVC(createStream);
SAVC(getStreamLength);
SAVC(FCSubscribe);
SAVC(releaseStream);
SAVC(FCPublish);
SAVC(FCUnpublish);
SAVC(publish);
SAVC(live);
SAVC(record);
SAVC(deleteStream);
SAVC(pause);
SAVC(seek);
SAVC(_checkbw);
SAVC(_result);
SAVC(ping);
SAVC(pong);
SAVC(play);
SAVC(set_playlist);
SAVC(onMetaData);
SAVC(duration);
SAVC(video);
SAVC(audio);
SAVC(fmsVer);
SAVC(mode);
SAVC(onBWDone);
SAVC(onFCSubscribe);
SAVC(onFCUnsubscribe);
SAVC(_onbwcheck);
SAVC(_onbwdone);
SAVC(_error);
SAVC(close);
SAVC(code);
SAVC(level);
SAVC(description);
SAVC(onStatus);
SAVC(status);
SAVC(details);
SAVC(clientid);
SAVC(playlist_ready);
SAVC(ex);
SAVC(redirect);
SAVC2(dquote, "\"");
SAVC2(escdquote, "\\\"");
SAVC2(NetStream_Authenticate_UsherToken, "NetStream.Authenticate.UsherToken");
SAVC2(authmod_adobe, "authmod=adobe");
SAVC2(authmod_llnw, "authmod=llnw");
SAVC2(setDataFrame, "@setDataFrame");
SAVC2(NetStream_Failed, "NetStream.Failed");
SAVC2(NetStream_Play_Failed, "NetStream.Play.Failed");
SAVC2(NetStream_Play_StreamNotFound, "NetStream.Play.StreamNotFound");
SAVC2(NetConnection_Connect_InvalidApp, "NetConnection.Connect.InvalidApp");
SAVC2(NetStream_Play_Reset, "NetStream.Play.Reset");
SAVC2(NetStream_Play_Start, "NetStream.Play.Start");
SAVC2(NetStream_Data_Start, "NetStream.Data.Start");
SAVC2(NetStream_Play_Complete, "NetStream.Play.Complete");
SAVC2(NetStream_Play_Stop, "NetStream.Play.Stop");
SAVC2(NetStream_Seek_Notify, "NetStream.Seek.Notify");
SAVC2(NetStream_Pause_Notify, "NetStream.Pause.Notify");
SAVC2(NetStream_Play_PublishNotify, "NetStream.Play.PublishNotify");
SAVC2(NetStream_Play_UnpublishNotify, "NetStream.Play.UnpublishNotify");
SAVC2(NetStream_Publish_Start, "NetStream.Publish.Start");
SAVC2(NetStream_Publish_Rejected, "NetStream.Publish.Rejected");
SAVC2(NetStream_Publish_Denied, "NetStream.Publish.Denied");
SAVC2(NetConnection_Connect_Rejected, "NetConnection.Connect.Rejected");
SAVC2(Playing_resetting, "Playing resetting");
SAVC2(Started_playing, "Started playing");
SAVC2(Started_publishing, "Started publishing");
SAVC2(Stopped_playing, "Stopped playing");

uint32_t
RTMP_GetTime()
{
#ifdef _WIN32
  return timeGetTime();
#else
  struct tms t;
  if (!clk_tck) clk_tck = sysconf(_SC_CLK_TCK);
  return times(&t) * 1000 / clk_tck;
#endif
}

void
RTMP_UserInterrupt()
{
  RTMP_ctrlC = TRUE;
}

void
RTMPPacket_Reset(RTMPPacket *p)
{
  p->m_headerType = 0;
  p->m_packetType = 0;
  p->m_nChannel = 0;
  p->m_nTimeStamp = 0;
  p->m_nInfoField2 = 0;
  p->m_hasAbsTimestamp = FALSE;
  p->m_nBodySize = 0;
  p->m_nBytesRead = 0;
}

bool
RTMPPacket_Alloc(RTMPPacket *p, uint32_t bobySize)
{
  char *ptr;
  if (bobySize > UINT32_MAX - RTMP_MAX_HEADER_SIZE)
    return FALSE;
  ptr = calloc(1, bobySize + RTMP_MAX_HEADER_SIZE);
  if (!ptr)
    return FALSE;
  p->m_body = ptr + RTMP_MAX_HEADER_SIZE;
  p->m_nBytesRead = 0;
  return TRUE;
}

void
RTMPPacket_Free(RTMPPacket *p)
{
  if (p->m_body)
    {
      free(p->m_body - RTMP_MAX_HEADER_SIZE);
      p->m_body = NULL;
    }
}

bool
RTMPPacket_ReadFile(RTMPPacket *p, void* fp, size_t (*readf)(void* fp, char* buf, size_t))
{
  unsigned bodySize;
  char buf[11], *enc, *pend;
  if (readf(fp, buf, 11) != 11)
    return FALSE;

  bodySize = AMF_DecodeInt24(buf+1);
  p->m_packetType = buf[0];
  p->m_nBodySize = 0;
  if (p->m_packetType != RTMP_PACKET_TYPE_AUDIO
    && p->m_packetType != RTMP_PACKET_TYPE_VIDEO
    && p->m_packetType != RTMP_PACKET_TYPE_INFO) {
    if (readf(fp, NULL, bodySize + 4) != bodySize + 4)
      return FALSE;
    return TRUE;
  }

  p->m_nTimeStamp = AMF_DecodeInt24(buf+4) | ((unsigned)buf[7] << 24);
  p->m_headerType = (!p->m_nTimeStamp || p->m_packetType == RTMP_PACKET_TYPE_INFO)
    ? RTMP_PACKET_SIZE_LARGE : RTMP_PACKET_SIZE_MEDIUM;
  p->m_nBodySize = bodySize;
  if (p->m_packetType == RTMP_PACKET_TYPE_INFO)
    p->m_nBodySize += 1+2+av_setDataFrame.av_len;
  if (!p->m_body || p->m_nBodySize > p->m_nBytesRead) {
    RTMPPacket_Free(p);
    RTMPPacket_Alloc(p, p->m_nBodySize);
    p->m_nBytesRead = p->m_nBodySize;
  }

  enc = p->m_body;
  pend = enc + p->m_nBodySize;
  if (p->m_packetType == RTMP_PACKET_TYPE_INFO)
    enc = AMF_EncodeString(enc, pend, &av_setDataFrame);

  if (readf(fp, enc, bodySize) != bodySize)
    return FALSE;
  if (readf(fp, NULL, 4) != 4)
    return FALSE;
  if (p->m_packetType == RTMP_PACKET_TYPE_INFO) {
    AMFObject obj;
    AMFObjectProperty prop;
    AMF_Decode(&obj, enc, bodySize, FALSE);
    AMF_Dump(&obj);
    if (RTMP_FindFirstMatchingProperty(&obj, &av_duration, &prop))
      p->m_nInfoField2 = (uint32_t)prop.p_vu.p_number;
    AMF_Reset(&obj);
  }
  return TRUE;
}

void
RTMPPacket_Dump(RTMPPacket *p)
{
  RTMP_Log(RTMP_LOGDEBUG,
      "RTMP PACKET: packet type: 0x%02x. channel: 0x%02x. info 1: %d info 2: %d. Body size: %u. body: 0x%02x",
      p->m_packetType, p->m_nChannel, p->m_nTimeStamp, p->m_nInfoField2,
      p->m_nBodySize, p->m_body ? (unsigned char)p->m_body[0] : 0);
}

int
RTMP_LibVersion()
{
  return RTMP_LIB_VERSION;
}

void
RTMP_TLS_Init()
{
#ifdef CRYPTO
#ifdef USE_POLARSSL
  /* Do this regardless of NO_SSL, we use havege for rtmpe too */
  RTMP_TLS_ctx = calloc(1,sizeof(struct tls_ctx));
  havege_init(&RTMP_TLS_ctx->hs);
#elif defined(USE_GNUTLS) && !defined(NO_SSL)
  /* Technically we need to initialize libgcrypt ourselves if
   * we're not going to call gnutls_global_init(). Ignoring this
   * for now.
   */
  gnutls_global_init();
  RTMP_TLS_ctx = malloc(sizeof(struct tls_ctx));
  gnutls_certificate_allocate_credentials(&RTMP_TLS_ctx->cred);
  gnutls_priority_init(&RTMP_TLS_ctx->prios, "NORMAL", NULL);
  gnutls_certificate_set_x509_trust_file(RTMP_TLS_ctx->cred,
  	"ca.pem", GNUTLS_X509_FMT_PEM);
#elif !defined(NO_SSL) /* USE_OPENSSL */
  /* libcrypto doesn't need anything special */
  SSL_load_error_strings();
  SSL_library_init();
  OpenSSL_add_all_digests();
  RTMP_TLS_ctx = SSL_CTX_new(SSLv23_method());
  SSL_CTX_set_options(RTMP_TLS_ctx, SSL_OP_ALL);
  SSL_CTX_set_default_verify_paths(RTMP_TLS_ctx);
#endif
#endif
}

void *
RTMP_TLS_AllocServerContext(const char* cert, const char* key)
{
  void *ctx = NULL;
#ifdef CRYPTO
  if (!RTMP_TLS_ctx)
    RTMP_TLS_Init();
#ifdef USE_POLARSSL
  tls_server_ctx *tc = ctx = calloc(1, sizeof(struct tls_server_ctx));
  tc->dhm_P = my_dhm_P;
  tc->dhm_G = my_dhm_G;
  tc->hs = &RTMP_TLS_ctx->hs;
  if (x509parse_crtfile(&tc->cert, cert)) {
      free(tc);
      return NULL;
  }
  if (x509parse_keyfile(&tc->key, key, NULL)) {
      x509_free(&tc->cert);
      free(tc);
      return NULL;
  }
#elif defined(USE_GNUTLS) && !defined(NO_SSL)
  gnutls_certificate_allocate_credentials((gnutls_certificate_credentials*) &ctx);
  if (gnutls_certificate_set_x509_key_file(ctx, cert, key, GNUTLS_X509_FMT_PEM) != 0) {
    gnutls_certificate_free_credentials(ctx);
    return NULL;
  }
#elif !defined(NO_SSL) /* USE_OPENSSL */
  ctx = SSL_CTX_new(SSLv23_server_method());
  if (!SSL_CTX_use_certificate_chain_file(ctx, cert)) {
      SSL_CTX_free(ctx);
      return NULL;
  }
  if (!SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM)) {
      SSL_CTX_free(ctx);
      return NULL;
  }
#endif
#endif
  return ctx;
}

void
RTMP_TLS_FreeServerContext(void *ctx)
{
#ifdef CRYPTO
#ifdef USE_POLARSSL
  x509_free(&((tls_server_ctx*)ctx)->cert);
  rsa_free(&((tls_server_ctx*)ctx)->key);
  free(ctx);
#elif defined(USE_GNUTLS) && !defined(NO_SSL)
  gnutls_certificate_free_credentials(ctx);
#elif !defined(NO_SSL) /* USE_OPENSSL */
  SSL_CTX_free(ctx);
#endif
#endif
}

RTMP *
RTMP_Alloc()
{
  return calloc(1, sizeof(RTMP));
}

void
RTMP_Free(RTMP *r)
{
  free(r);
}

void
RTMP_Init(RTMP *r)
{
#ifdef CRYPTO
  if (!RTMP_TLS_ctx)
    RTMP_TLS_Init();
#endif

  memset(r, 0, sizeof(RTMP));
  r->m_sb.sb_socket = INVALID_SOCKET;
  r->m_inChunkSize = RTMP_DEFAULT_CHUNKSIZE;
  r->m_outChunkSize = RTMP_DEFAULT_CHUNKSIZE;
  r->m_nBufferMS = 30000;
  r->m_nClientBW = 2500000;
  r->m_nClientBW2 = 2;
  r->m_nServerBW = 2500000;
  r->m_fAudioCodecs = 3191.0;
  r->m_fVideoCodecs = 252.0;
  r->Link.timeout = 30;
  r->Link.swfAge = 30;
}

void
RTMP_EnableWrite(RTMP *r)
{
  r->Link.protocol |= RTMP_FEATURE_WRITE;
}

double
RTMP_GetDuration(RTMP *r)
{
  return r->m_read.duration;
}

int
RTMP_IsConnected(RTMP *r)
{
  return r->m_sb.sb_socket != -1;
}

SOCKET
RTMP_Socket(RTMP *r)
{
  return r->m_sb.sb_socket;
}
int RTMP_State(RTMP* r)
{
  return r->m_state;
}
int
RTMP_IsTimedout(RTMP *r)
{
  return r->m_sb.sb_timedout;
}

void
RTMP_SetBufferMS(RTMP *r, int size)
{
  r->m_nBufferMS = size;
}

void
RTMP_UpdateBufferMS(RTMP *r)
{
  RTMP_SendCtrl(r, RTMP_CTRL_SET_BUFFER_MS, r->m_stream_id, r->m_nBufferMS);
}

#undef OSS
#ifdef _WIN32
#define OSS	"WIN"
#elif defined(__sun__)
#define OSS	"SOL"
#elif defined(__APPLE__)
#define OSS	"MAC"
#elif defined(__linux__)
#define OSS	"LNX"
#else
#define OSS	"GNU"
#endif
#define DEF_VERSTR	OSS " 10,0,32,18"
static const char DEFAULT_FLASH_VER[] = DEF_VERSTR;
const AVal RTMP_DefaultFlashVer =
  { (char *)DEFAULT_FLASH_VER, sizeof(DEFAULT_FLASH_VER) - 1 };

static void
SocksSetup(RTMP *r, AVal *sockshost)
{
  if (sockshost->av_len)
    {
      const char *socksport = strchr(sockshost->av_val, ':');
      char *hostname = strdup(sockshost->av_val);

      if (socksport)
	hostname[socksport - sockshost->av_val] = '\0';
      r->Link.sockshost.av_val = hostname;
      r->Link.sockshost.av_len = strlen(hostname);

      r->Link.socksport = socksport ? atoi(socksport + 1) : 1080;
      RTMP_Log(RTMP_LOGDEBUG, "Connecting via SOCKS proxy: %s:%d", r->Link.sockshost.av_val,
	  r->Link.socksport);
    }
  else
    {
      r->Link.sockshost.av_val = NULL;
      r->Link.sockshost.av_len = 0;
      r->Link.socksport = 0;
    }
}

void
RTMP_SetupStream(RTMP *r,
		 int protocol,
		 AVal *host,
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
		 int dStop, int bLiveStream, long int timeout)
{
  RTMP_Log(RTMP_LOGDEBUG, "Protocol : %s", RTMPProtocolStrings[protocol&7]);
  RTMP_Log(RTMP_LOGDEBUG, "Hostname : %.*s", host->av_len, host->av_val);
  RTMP_Log(RTMP_LOGDEBUG, "Port     : %d", port);
  RTMP_Log(RTMP_LOGDEBUG, "Playpath : %s", playpath->av_val);

  if (tcUrl && tcUrl->av_val)
    RTMP_Log(RTMP_LOGDEBUG, "tcUrl    : %s", tcUrl->av_val);
  if (swfUrl && swfUrl->av_val)
    RTMP_Log(RTMP_LOGDEBUG, "swfUrl   : %s", swfUrl->av_val);
  if (pageUrl && pageUrl->av_val)
    RTMP_Log(RTMP_LOGDEBUG, "pageUrl  : %s", pageUrl->av_val);
  if (app && app->av_val)
    RTMP_Log(RTMP_LOGDEBUG, "app      : %.*s", app->av_len, app->av_val);
  if (auth && auth->av_val)
    RTMP_Log(RTMP_LOGDEBUG, "auth     : %s", auth->av_val);
  if (subscribepath && subscribepath->av_val)
    RTMP_Log(RTMP_LOGDEBUG, "subscribepath : %s", subscribepath->av_val);
  if (usherToken && usherToken->av_val)
    RTMP_Log(RTMP_LOGDEBUG, "NetStream.Authenticate.UsherToken : %s", usherToken->av_val);
  if (flashVer && flashVer->av_val)
    RTMP_Log(RTMP_LOGDEBUG, "flashVer : %s", flashVer->av_val);
  if (dStart > 0)
    RTMP_Log(RTMP_LOGDEBUG, "StartTime     : %d msec", dStart);
  if (dStop > 0)
    RTMP_Log(RTMP_LOGDEBUG, "StopTime      : %d msec", dStop);

  RTMP_Log(RTMP_LOGDEBUG, "live     : %s", bLiveStream ? "yes" : "no");
  RTMP_Log(RTMP_LOGDEBUG, "timeout  : %ld sec", timeout);

#ifdef CRYPTO
  if (swfSHA256Hash != NULL && swfSize > 0)
    {
      memcpy(r->Link.SWFHash, swfSHA256Hash->av_val, sizeof(r->Link.SWFHash));
      r->Link.SWFSize = swfSize;
      RTMP_Log(RTMP_LOGDEBUG, "SWFSHA256:");
      RTMP_LogHex(RTMP_LOGDEBUG, r->Link.SWFHash, sizeof(r->Link.SWFHash));
      RTMP_Log(RTMP_LOGDEBUG, "SWFSize  : %u", r->Link.SWFSize);
    }
  else
    {
      r->Link.SWFSize = 0;
    }
#endif

  SocksSetup(r, sockshost);

  if (tcUrl && tcUrl->av_len)
    r->Link.tcUrl = *tcUrl;
  if (swfUrl && swfUrl->av_len)
    r->Link.swfUrl = *swfUrl;
  if (pageUrl && pageUrl->av_len)
    r->Link.pageUrl = *pageUrl;
  if (app && app->av_len)
    r->Link.app = *app;
  if (auth && auth->av_len)
    {
      r->Link.auth = *auth;
      r->Link.lFlags |= RTMP_LF_AUTH;
    }
  if (flashVer && flashVer->av_len)
    r->Link.flashVer = *flashVer;
  else
    r->Link.flashVer = RTMP_DefaultFlashVer;
  if (subscribepath && subscribepath->av_len)
    r->Link.subscribepath = *subscribepath;
  if (usherToken && usherToken->av_len)
    r->Link.usherToken = *usherToken;
  r->m_read.timestamp = dStart;
  r->Link.seekTime = dStart;
  r->Link.stopTime = dStop;
  if (bLiveStream)
    r->Link.lFlags |= RTMP_LF_LIVE;
  r->Link.timeout = timeout;

  r->Link.protocol = protocol;
  r->Link.hostname = *host;
  r->Link.port = port;
  r->Link.playpath = *playpath;

  if (r->Link.port == 0)
    {
      if (protocol & RTMP_FEATURE_SSL)
	r->Link.port = 443;
      else if (protocol & RTMP_FEATURE_HTTP)
	r->Link.port = 80;
      else
	r->Link.port = 1935;
    }
}

enum { OPT_STR=0, OPT_INT, OPT_BOOL, OPT_CONN };
static const char *optinfo[] = {
	"string", "integer", "boolean", "AMF" };

#define OFF(x)	offsetof(struct RTMP,x)

static struct urlopt {
  AVal name;
  off_t off;
  int otype;
  int omisc;
  char *use;
} options[] = {
  { AVC("socks"),     OFF(Link.sockshost),     OPT_STR, 0,
  	"Use the specified SOCKS proxy" },
  { AVC("app"),       OFF(Link.app),           OPT_STR, 0,
	"Name of target app on server" },
  { AVC("tcUrl"),     OFF(Link.tcUrl),         OPT_STR, 0,
  	"URL to played stream" },
  { AVC("pageUrl"),   OFF(Link.pageUrl),       OPT_STR, 0,
  	"URL of played media's web page" },
  { AVC("swfUrl"),    OFF(Link.swfUrl),        OPT_STR, 0,
  	"URL to player SWF file" },
  { AVC("flashver"),  OFF(Link.flashVer),      OPT_STR, 0,
  	"Flash version string (default " DEF_VERSTR ")" },
  { AVC("conn"),      OFF(Link.extras),        OPT_CONN, 0,
  	"Append arbitrary AMF data to Connect message" },
  { AVC("playpath"),  OFF(Link.playpath),      OPT_STR, 0,
  	"Path to target media on server" },
  { AVC("playlist"),  OFF(Link.lFlags),        OPT_BOOL, RTMP_LF_PLST,
  	"Set playlist before play command" },
  { AVC("live"),      OFF(Link.lFlags),        OPT_BOOL, RTMP_LF_LIVE,
  	"Stream is live, no seeking possible" },
  { AVC("subscribe"), OFF(Link.subscribepath), OPT_STR, 0,
  	"Stream to subscribe to" },
  { AVC("jtv"), OFF(Link.usherToken),          OPT_STR, 0,
	"Justin.tv authentication token" },
  { AVC("token"),     OFF(Link.token),	       OPT_STR, 0,
  	"Key for SecureToken response" },
  { AVC("swfVfy"),    OFF(Link.lFlags),        OPT_BOOL, RTMP_LF_SWFV,
  	"Perform SWF Verification" },
  { AVC("swfAge"),    OFF(Link.swfAge),        OPT_INT, 0,
  	"Number of days to use cached SWF hash" },
  { AVC("start"),     OFF(Link.seekTime),      OPT_INT, 0,
  	"Stream start position in milliseconds" },
  { AVC("stop"),      OFF(Link.stopTime),      OPT_INT, 0,
  	"Stream stop position in milliseconds" },
  { AVC("buffer"),    OFF(m_nBufferMS),        OPT_INT, 0,
  	"Buffer time in milliseconds" },
  { AVC("timeout"),   OFF(Link.timeout),       OPT_INT, 0,
  	"Session timeout in seconds" },
  { AVC("pubUser"),   OFF(Link.pubUser),       OPT_STR, 0,
        "Publisher username" },
  { AVC("pubPasswd"), OFF(Link.pubPasswd),     OPT_STR, 0,
        "Publisher password" },
  { {NULL,0}, 0, 0}
};

static const AVal truth[] = {
	AVC("1"),
	AVC("on"),
	AVC("yes"),
	AVC("true"),
	{0,0}
};

static void RTMP_OptUsage()
{
  int i;

  RTMP_Log(RTMP_LOGERROR, "Valid RTMP options are:\n");
  for (i=0; options[i].name.av_len; i++) {
    RTMP_Log(RTMP_LOGERROR, "%10s %-7s  %s\n", options[i].name.av_val,
    	optinfo[options[i].otype], options[i].use);
  }
}

static int
parseAMF(AMFObject *obj, AVal *av, int *depth)
{
  AMFObjectProperty prop = {{0,0}};
  int i;
  char *p, *arg = av->av_val;

  if (arg[1] == ':')
    {
      p = (char *)arg+2;
      switch(arg[0])
	{
	case 'B':
	  prop.p_type = AMF_BOOLEAN;
	  prop.p_vu.p_number = atoi(p);
	  break;
	case 'S':
	  prop.p_type = AMF_STRING;
	  prop.p_vu.p_aval.av_val = p;
	  prop.p_vu.p_aval.av_len = av->av_len - (p-arg);
	  break;
	case 'N':
	  prop.p_type = AMF_NUMBER;
	  prop.p_vu.p_number = strtod(p, NULL);
	  break;
	case 'Z':
	  prop.p_type = AMF_NULL;
	  break;
	case 'O':
	  i = atoi(p);
	  if (i)
	    {
	      prop.p_type = AMF_OBJECT;
	    }
	  else
	    {
	      (*depth)--;
	      return 0;
	    }
	  break;
	default:
	  return -1;
	}
    }
  else if (arg[2] == ':' && arg[0] == 'N')
    {
      p = strchr(arg+3, ':');
      if (!p || !*depth)
	return -1;
      prop.p_name.av_val = (char *)arg+3;
      prop.p_name.av_len = p - (arg+3);

      p++;
      switch(arg[1])
	{
	case 'B':
	  prop.p_type = AMF_BOOLEAN;
	  prop.p_vu.p_number = atoi(p);
	  break;
	case 'S':
	  prop.p_type = AMF_STRING;
	  prop.p_vu.p_aval.av_val = p;
	  prop.p_vu.p_aval.av_len = av->av_len - (p-arg);
	  break;
	case 'N':
	  prop.p_type = AMF_NUMBER;
	  prop.p_vu.p_number = strtod(p, NULL);
	  break;
	case 'O':
	  prop.p_type = AMF_OBJECT;
	  break;
	default:
	  return -1;
	}
    }
  else
    return -1;

  if (*depth)
    {
      AMFObject *o2;
      for (i=0; i<*depth; i++)
	{
	  o2 = &obj->o_props[obj->o_num-1].p_vu.p_object;
	  obj = o2;
	}
    }
  AMF_AddProp(obj, &prop);
  if (prop.p_type == AMF_OBJECT)
    (*depth)++;
  return 0;
}

int RTMP_SetOpt(RTMP *r, const AVal *opt, AVal *arg)
{
  int i;
  void *v;

  for (i=0; options[i].name.av_len; i++) {
    if (opt->av_len != options[i].name.av_len) continue;
    if (strcasecmp(opt->av_val, options[i].name.av_val)) continue;
    v = (char *)r + options[i].off;
    switch(options[i].otype) {
    case OPT_STR: {
      AVal *aptr = v;
      *aptr = *arg; }
      break;
    case OPT_INT: {
      long l = strtol(arg->av_val, NULL, 0);
      *(int *)v = l; }
      break;
    case OPT_BOOL: {
      int j, fl;
      fl = *(int *)v;
      for (j=0; truth[j].av_len; j++) {
        if (arg->av_len != truth[j].av_len) continue;
        if (strcasecmp(arg->av_val, truth[j].av_val)) continue;
        fl |= options[i].omisc; break; }
      *(int *)v = fl;
      }
      break;
    case OPT_CONN:
      if (parseAMF(&r->Link.extras, arg, &r->Link.edepth))
        return FALSE;
      break;
    }
    break;
  }
  if (!options[i].name.av_len) {
    RTMP_Log(RTMP_LOGERROR, "Unknown option %s", opt->av_val);
    RTMP_OptUsage();
    return FALSE;
  }

  return TRUE;
}

bool
RTMP_SetupURL(RTMP *r, char *url)
{
  AVal opt, arg;
  char *p1, *p2, *ptr = strchr(url, ' ');
  int ret, len;
  unsigned int port = 0;

  if (ptr)
    *ptr++ = '\0';

  len = strlen(url);
  ret = RTMP_ParseURL(url, &r->Link.protocol, &r->Link.hostname,
  	&port, &r->Link.playpath0, &r->Link.app);
  if (!ret)
    return ret;
  r->Link.port = port;
  r->Link.playpath = r->Link.playpath0;

  while (ptr && *ptr) {
    /* skip repeated spaces */
    while (*ptr && isspace(*ptr)) *ptr++ = '\0';
    p2 = strchr(ptr, '=');
    if (!p2)
      break;
    opt.av_val = ptr;
    opt.av_len = p2 - ptr;
    *p2++ = '\0';
    arg.av_val = p2;
    ptr = strchr(p2, ' ');
    if (ptr) {
      arg.av_len = ptr - p2;
      *ptr++ = '\0';
    } else {
      arg.av_len = strlen(p2);
    }

    /* unescape */
    port = arg.av_len;
    for (p1=p2; port >0;) {
      if (*p1 == '%') {
        unsigned int c;
        if (port < 3)
          return FALSE;
        sscanf(p1+1, "%02x", &c);
        *p2++ = c;
        port -= 3;
        p1 += 3;
      } else {
        *p2++ = *p1++;
        port--;
      }
    }
    arg.av_len = p2 - arg.av_val;

    ret = RTMP_SetOpt(r, &opt, &arg);
    if (!ret)
      return ret;
  }

  if (!r->Link.tcUrl.av_len)
  {
    r->Link.tcUrl.av_val = url;
    if (r->Link.app.av_len)
    {
      if (r->Link.app.av_val < url + len)
      {
        /* if app is part of original url, just use it */
        r->Link.tcUrl.av_len = r->Link.app.av_len + (r->Link.app.av_val - url);
      }
      else
      {
        len = r->Link.hostname.av_len + r->Link.app.av_len +
          sizeof("rtmpte://:65535/");
        r->Link.tcUrl.av_val = malloc(len);
        r->Link.tcUrl.av_len = snprintf(r->Link.tcUrl.av_val, len,
          "%s://%.*s:%d/%.*s",
          RTMPProtocolStringsLower[r->Link.protocol],
          r->Link.hostname.av_len, r->Link.hostname.av_val,
          r->Link.port,
          r->Link.app.av_len, r->Link.app.av_val);
        r->Link.lFlags |= RTMP_LF_FTCU;
      }
    }
    else
    {
      r->Link.tcUrl.av_len = strlen(url);
    }
  }

#ifdef CRYPTO
  if ((r->Link.lFlags & RTMP_LF_SWFV) && r->Link.swfUrl.av_len)
    RTMP_HashSWF(r->Link.swfUrl.av_val, &r->Link.SWFSize,
	  (unsigned char *)r->Link.SWFHash, r->Link.swfAge);
#endif

  SocksSetup(r, &r->Link.sockshost);

  if (r->Link.port == 0)
    {
      if (r->Link.protocol & RTMP_FEATURE_SSL)
	r->Link.port = 443;
      else if (r->Link.protocol & RTMP_FEATURE_HTTP)
	r->Link.port = 80;
      else
	r->Link.port = 1935;
    }
  return TRUE;
}

static int
add_addr_info(struct sockaddr_storage *service, socklen_t *addrlen, AVal *host, int port)
{
  char *hostname;
  int ret = TRUE;
  if (host->av_val[host->av_len] || host->av_val[0] == '[')
  {
    int v6 = host->av_val[0] == '[';
    hostname = malloc(host->av_len+1 - v6 * 2);
    memcpy(hostname, host->av_val + v6, host->av_len - v6 * 2);
    hostname[host->av_len - v6 * 2] = '\0';
  }
  else
  {
    hostname = host->av_val;
  }

  struct addrinfo hints;
  struct addrinfo *result = NULL;
  struct addrinfo *ptr = NULL;

  memset(&hints, 0, sizeof(hints));

  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = IPPROTO_TCP;

  service->ss_family = AF_UNSPEC;
  *addrlen = 0;

  char portStr[8];

  sprintf(portStr, "%d", port);

  int err = getaddrinfo(hostname, portStr, &hints, &result);

  if (err)
  {
#ifndef _WIN32
#define gai_strerrorA gai_strerror
#endif
    RTMP_Log(RTMP_LOGERROR, "Could not resolve %s: %s (%d)", hostname, gai_strerrorA(GetSockError()), GetSockError());
    ret = FALSE;
    goto finish;
  }

  // they should come back in OS preferred order
  for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
  {
    if (ptr->ai_family == AF_INET || ptr->ai_family == AF_INET6)
    {
      memcpy(service, ptr->ai_addr, ptr->ai_addrlen);
      *addrlen = (socklen_t)ptr->ai_addrlen;
      break;
    }
  }

  freeaddrinfo(result);

  if (service->ss_family == AF_UNSPEC || *addrlen == 0)
  {
    RTMP_Log(RTMP_LOGERROR, "Could not resolve server '%s': no valid address found", hostname);
    ret = FALSE;
    goto finish;
  }

finish:
  if (hostname != host->av_val)
    free(hostname);
  return ret;
}

bool
RTMP_Connect0(RTMP *r, struct sockaddr * service, int addrlen)
{
  int on = 1;
  r->m_sb.sb_timedout = FALSE;
  r->m_pausing = 0;
  r->m_read.duration = 0.0;

  r->m_sb.sb_socket = socket(service->sa_family, SOCK_STREAM, IPPROTO_TCP);
  if (r->m_sb.sb_socket != -1)
    {
      if (connect(r->m_sb.sb_socket, service, addrlen) < 0)
	{
	  int err = GetSockError();
	  RTMP_Log(RTMP_LOGERROR, "%s, failed to connect socket. %d (%s)",
	      __FUNCTION__, err, strerror(err));
	  RTMP_Close(r);
	  return FALSE;
	}

      if (r->Link.socksport)
	{
	  RTMP_Log(RTMP_LOGDEBUG, "%s ... SOCKS negotiation", __FUNCTION__);
	  if (!SocksNegotiate(r))
	    {
	      RTMP_Log(RTMP_LOGERROR, "%s, SOCKS negotiation failed.", __FUNCTION__);
	      RTMP_Close(r);
	      return FALSE;
	    }
	}
    }
  else
    {
      RTMP_Log(RTMP_LOGERROR, "%s, failed to create socket. Error: %d", __FUNCTION__,
	  GetSockError());
      return FALSE;
    }

  /* set timeout */
  {
    SET_RCVTIMEO(tv, r->Link.timeout);
    if (setsockopt
        (r->m_sb.sb_socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv)))
      {
        RTMP_Log(RTMP_LOGERROR, "%s, Setting socket timeout to %ds failed!",
	    __FUNCTION__, r->Link.timeout);
      }
  }

  setsockopt(r->m_sb.sb_socket, IPPROTO_TCP, TCP_NODELAY, (char *) &on, sizeof(on));

  return TRUE;
}

static bool
RTMP_TLS_Accept(RTMP *r, void *ctx)
{
#if defined(CRYPTO) && !defined(NO_SSL)
  TLS_server(ctx, r->m_sb.sb_ssl);
  TLS_setfd(r->m_sb.sb_ssl, r->m_sb.sb_socket);
  if (TLS_accept(r->m_sb.sb_ssl) < 0)
    {
      RTMP_Log(RTMP_LOGERROR, "%s, TLS_Connect failed", __FUNCTION__);
      return FALSE;
    }
  return TRUE;
#else
  return FALSE;
#endif
}

bool
RTMP_Connect1(RTMP *r, RTMPPacket *cp)
{
  if (r->Link.protocol & RTMP_FEATURE_SSL)
    {
#if defined(CRYPTO) && !defined(NO_SSL)
      TLS_client(RTMP_TLS_ctx, r->m_sb.sb_ssl);
      TLS_setfd(r->m_sb.sb_ssl, r->m_sb.sb_socket);
      if (TLS_connect(r->m_sb.sb_ssl) < 0)
	{
	  RTMP_Log(RTMP_LOGERROR, "%s, TLS_Connect failed", __FUNCTION__);
	  RTMP_Close(r);
	  return FALSE;
	}
#else
      RTMP_Log(RTMP_LOGERROR, "%s, no SSL/TLS support", __FUNCTION__);
      RTMP_Close(r);
      return FALSE;

#endif
    }
  if (r->Link.protocol & RTMP_FEATURE_HTTP)
    {
      r->m_msgCounter = 1;
      r->m_clientID.av_val = NULL;
      r->m_clientID.av_len = 0;
      HTTP_Post(r, RTMPT_OPEN, "", 1);
      if (HTTP_read(r, 1) != 0)
	{
	  r->m_msgCounter = 0;
	  RTMP_Log(RTMP_LOGDEBUG, "%s, Could not connect for handshake", __FUNCTION__);
	  RTMP_Close(r);
	  return 0;
	}
      r->m_msgCounter = 0;
    }
  RTMP_Log(RTMP_LOGDEBUG, "%s, ... connected, handshaking", __FUNCTION__);
  if (!HandShake(r, TRUE))
    {
      RTMP_Log(RTMP_LOGERROR, "%s, handshake failed.", __FUNCTION__);
      RTMP_Close(r);
      return FALSE;
    }
  RTMP_Log(RTMP_LOGDEBUG, "%s, handshaked", __FUNCTION__);

  if (!SendConnectPacket(r, cp))
    {
      RTMP_Log(RTMP_LOGERROR, "%s, RTMP connect failed.", __FUNCTION__);
      RTMP_Close(r);
      return FALSE;
    }
  return TRUE;
}

bool
RTMP_Connect(RTMP *r, RTMPPacket *cp)
{
#ifdef _WIN32
  HOSTENT *h;
#endif
  struct sockaddr_storage service;
  socklen_t addrlen = 0;
  if (!r->Link.hostname.av_len)
    return FALSE;
#ifdef _WIN32
  h = gethostbyname("localhost");
  if (!h && GetLastError() == WSAHOST_NOT_FOUND)
  {
    RTMP_Log(RTMP_LOGERROR, "RTMP_Connect: Connection test failed. \n"
      "This error is likely caused by Comodo Internet Security running OBS in sandbox mode. \n"
      "Please add OBS to the Comodo automatic sandbox exclusion list, restart OBS and try again (11001).");
    return FALSE;
  }
#endif

  memset(&service, 0, sizeof(service));

  if (r->Link.socksport)
  {
    /* Connect via SOCKS */
    if (!add_addr_info(&service, &addrlen, &r->Link.sockshost, r->Link.socksport))
      return FALSE;
  }
  else
  {
    /* Connect directly */
    if (!add_addr_info(&service, &addrlen, &r->Link.hostname, r->Link.port))
      return FALSE;
  }

  if (!RTMP_Connect0(r, (struct sockaddr *)&service, addrlen))
    return FALSE;

  r->m_bSendCounter = TRUE;

  return RTMP_Connect1(r, cp);
}

static int
SocksNegotiate(RTMP *r)
{
  unsigned long addr;
  struct sockaddr_storage service;
  socklen_t addrlen = 0;
  memset(&service, 0, sizeof(service));

  add_addr_info(&service, &addrlen, &r->Link.hostname, r->Link.port);

  // not doing IPv6 socks
  if (service.ss_family == AF_INET6)
    return FALSE;

  addr = htonl((*(struct sockaddr_in *)&service).sin_addr.s_addr);

  {
    char packet[] = {
      4, 1,			/* SOCKS 4, connect */
      (r->Link.port >> 8) & 0xFF,
      (r->Link.port) & 0xFF,
      (char)(addr >> 24) & 0xFF, (char)(addr >> 16) & 0xFF,
      (char)(addr >> 8) & 0xFF, (char)addr & 0xFF,
      0
    };				/* NULL terminate */

    WriteN(r, packet, sizeof packet);

    if (ReadN(r, packet, 8) != 8)
      return FALSE;

    if (packet[0] == 0 && packet[1] == 90)
    {
      return TRUE;
    }
    else
    {
      RTMP_Log(RTMP_LOGERROR, "%s, SOCKS returned error code %d", __FUNCTION__, packet[1]);
      return FALSE;
    }
  }
}
int
RTMP_AcceptStream(RTMP *r, RTMPPacket *packet)
{
  r->m_mediaChannel = 0;

  while (RTMP_IsConnected(r) && RTMP_ReadPacket(r, packet))
  {
    if (RTMPPacket_IsReady(packet) && packet->m_body)
    {
      if (RTMPPacket_IsMedia(packet))
        RTMP_Log(RTMP_LOGWARNING, "Received FLV packet before publish()! Ignoring.");
      else
        RTMP_HandlePacket(r, packet);
      if (r->m_state&RTMP_STATE_WORKING)
        break;
      RTMPPacket_Free(packet);
    }
  }

  return r->m_stream_id;
}
int
RTMP_ConnectStream(RTMP *r, int seekTime)
{
  RTMPPacket packet = { 0 };

  /* seekTime was already set by SetupStream / SetupURL.
   * This is only needed by ReconnectStream.
   */
  if (seekTime > 0)
    r->Link.seekTime = seekTime;

  r->m_mediaChannel = 0;

  while (!(r->m_state&RTMP_STATE_WORKING) && RTMP_IsConnected(r) && RTMP_ReadPacket(r, &packet))
  {
    if (RTMPPacket_IsReady(&packet) && packet.m_body)
    {
      if (RTMPPacket_IsMedia(&packet))
        RTMP_Log(RTMP_LOGWARNING, "Received FLV packet before play()! Ignoring.");
      else
        RTMP_HandlePacket(r, &packet);
      RTMPPacket_Free(&packet);
    }
  }

  return r->m_stream_id;
}


int
RTMP_ToggleStream(RTMP *r)
{
  int res;

  if (!r->m_pausing)
  {
    if (RTMP_IsTimedout(r) && r->m_read.status == RTMP_READ_EOF)
      r->m_read.status = 0;

    res = RTMP_SendPause(r, TRUE, r->m_pauseStamp);
    if (!res)
      return res;

    r->m_pausing = 1;
    sleep(1);
  }
  res = RTMP_SendPause(r, FALSE, r->m_pauseStamp);
  r->m_pausing = 3;
  return res;
}

void
RTMP_DeleteStream(RTMP *r)
{
  if (r->m_stream_id < 0)
    return;

  r->m_state &= ~RTMP_STATE_WORKING;

  SendDeleteStream(r, r->m_stream_id);
  r->m_stream_id = -1;
}

/* Read from the stream until we get a media packet.
 * Returns -3 if Play.Close/Stop, -2 if fatal error, -1 if no more media
 * packets, 0 if ignorable error, >0 if there is a media packet
 */
int
RTMP_GetNextMediaPacket(RTMP *r, RTMPPacket *packet)
{
  int bHasMediaPacket = 0;

  while (!bHasMediaPacket && RTMP_IsConnected(r)
    && RTMP_ReadPacket(r, packet))
  {
    if (!RTMPPacket_IsReady(packet) || !packet->m_nBodySize)
    {
      continue;
    }
    RTMP_HandlePacket(r, packet);

    bHasMediaPacket = RTMPPacket_IsMedia(packet);

    if (!bHasMediaPacket)
    {
      RTMPPacket_Free(packet);
      r->m_read.status = RTMP_READ_EOF;
    }
    else if (r->m_pausing == 3)
    {
      if (packet->m_nTimeStamp <= r->m_mediaStamp)
      {
        bHasMediaPacket = 0;
#ifdef _DEBUG
        RTMP_Log(RTMP_LOGDEBUG,
          "Skipped type: %02X, size: %d, TS: %d ms, abs TS: %d, pause: %d ms",
          packet->m_packetType, packet->m_nBodySize,
          packet->m_nTimeStamp, packet->m_hasAbsTimestamp,
          r->m_mediaStamp);
#endif
        RTMPPacket_Free(packet);
        continue;
      }
      r->m_pausing = 0;
    }
  }

  if (bHasMediaPacket)
    r->m_state |= RTMP_STATE_PLAYING;
  else if (r->m_sb.sb_timedout && !r->m_pausing)
    r->m_pauseStamp = r->m_mediaChannel < r->m_channelsAllocatedIn ?
      r->m_channelTimestamp[r->m_mediaChannel] : 0;

  return bHasMediaPacket;
}
bool RTMP_HandlePacket(RTMP *r, RTMPPacket *packet)
{
  int bHasMediaPacket = 0;
  bool bServer = (r->m_bSendCounter == 0);
  switch (packet->m_packetType)
  {
  case RTMP_PACKET_TYPE_CHUNK_SIZE:
    /* chunk size */
    HandleChangeChunkSize(r, packet);
    break;

  case RTMP_PACKET_TYPE_BYTES_READ_REPORT:
    /* bytes read report */
    RTMP_Log(RTMP_LOGDEBUG, "%s, received: bytes read report", __FUNCTION__);
    break;

  case RTMP_PACKET_TYPE_CONTROL:
    /* ctrl */
    HandleCtrl(r, packet);
    break;

  case RTMP_PACKET_TYPE_SERVER_BW:
    /* server bw */
    HandleServerBW(r, packet);
    break;

  case RTMP_PACKET_TYPE_CLIENT_BW:
    /* client bw */
    HandleClientBW(r, packet);
    break;

  case RTMP_PACKET_TYPE_AUDIO:
    /* audio data */
    /*RTMP_Log(RTMP_LOGDEBUG, "%s, received: audio %lu bytes", __FUNCTION__, packet.m_nBodySize); */
    HandleAudio(r, packet);
    bHasMediaPacket = 1;
    if (!r->m_mediaChannel)
      r->m_mediaChannel = packet->m_nChannel;
    if (!r->m_pausing)
      r->m_mediaStamp = packet->m_nTimeStamp;
    break;

  case RTMP_PACKET_TYPE_VIDEO:
    /* video data */
    /*RTMP_Log(RTMP_LOGDEBUG, "%s, received: video %lu bytes", __FUNCTION__, packet.m_nBodySize); */
    HandleVideo(r, packet);
    bHasMediaPacket = 1;
    if (!r->m_mediaChannel)
      r->m_mediaChannel = packet->m_nChannel;
    if (!r->m_pausing)
      r->m_mediaStamp = packet->m_nTimeStamp;
    break;

  case RTMP_PACKET_TYPE_FLEX_STREAM_SEND:
    /* flex stream send */
    RTMP_Log(RTMP_LOGDEBUG,
      "%s, flex stream send, size %u bytes, not supported, ignoring",
      __FUNCTION__, packet->m_nBodySize);
    break;

  case RTMP_PACKET_TYPE_FLEX_SHARED_OBJECT:
    /* flex shared object */
    RTMP_Log(RTMP_LOGDEBUG,
      "%s, flex shared object, size %u bytes, not supported, ignoring",
      __FUNCTION__, packet->m_nBodySize);
    break;

  case RTMP_PACKET_TYPE_FLEX_MESSAGE:
    /* flex message */
    {
      RTMP_Log(RTMP_LOGDEBUG,
        "%s, flex message, size %u bytes, not fully supported",
        __FUNCTION__, packet->m_nBodySize);
      /*RTMP_LogHex(packet.m_body, packet.m_nBodySize); */

      /* some DEBUG code */
#if 0
      RTMP_LIB_AMFObject obj;
      int nRes = obj.Decode(packet.m_body+1, packet.m_nBodySize-1);
      if(nRes < 0) {
        RTMP_Log(RTMP_LOGERROR, "%s, error decoding AMF3 packet", __FUNCTION__);
        /*return; */
      }

      obj.Dump();
#endif

      if (HandleInvoke(r, bServer, packet, 1) == 1)
        bHasMediaPacket = 2;
      break;
    }
  case RTMP_PACKET_TYPE_INFO:
    /* metadata (notify) */
    RTMP_Log(RTMP_LOGDEBUG, "%s, received: notify %u bytes", __FUNCTION__,
      packet->m_nBodySize);
    if (HandleMetadata(&r->m_read, packet->m_body, packet->m_nBodySize))
      bHasMediaPacket = 1;
    break;

  case RTMP_PACKET_TYPE_SHARED_OBJECT:
    RTMP_Log(RTMP_LOGDEBUG, "%s, shared object, not supported, ignoring",
      __FUNCTION__);
    break;

  case RTMP_PACKET_TYPE_INVOKE:
    /* invoke */
    RTMP_Log(RTMP_LOGDEBUG, "%s, received: invoke %u bytes", __FUNCTION__,
      packet->m_nBodySize);
    /*RTMP_LogHex(packet.m_body, packet.m_nBodySize); */

    if (HandleInvoke(r, bServer, packet, 0) == 1)
      bHasMediaPacket = 2;
    break;

  case RTMP_PACKET_TYPE_FLASH_VIDEO:
    {
      /* go through FLV packets and handle metadata packets */
      unsigned int pos = 0;
      uint32_t nTimeStamp = packet->m_nTimeStamp;

      while (pos + 11 < packet->m_nBodySize)
      {
        uint32_t dataSize = AMF_DecodeInt24(packet->m_body + pos + 1);	/* size without header (11) and prevTagSize (4) */

        if (pos + 11 + dataSize + 4 > packet->m_nBodySize)
        {
          RTMP_Log(RTMP_LOGWARNING, "Stream corrupt?!");
          break;
        }
        if (packet->m_body[pos] == 0x12)
        {
          HandleMetadata(&r->m_read, packet->m_body + pos + 11, dataSize);
        }
        else if (packet->m_body[pos] == 8 || packet->m_body[pos] == 9)
        {
          nTimeStamp = AMF_DecodeInt24(packet->m_body + pos + 4);
          nTimeStamp |= (packet->m_body[pos + 7] << 24);
        }
        pos += (11 + dataSize + 4);
      }
      if (!r->m_pausing)
        r->m_mediaStamp = nTimeStamp;

      /* FLV tag(s) */
      /*RTMP_Log(RTMP_LOGDEBUG, "%s, received: FLV tag(s) %lu bytes", __FUNCTION__, packet.m_nBodySize); */
      bHasMediaPacket = 1;
      break;
    }
  default:
    RTMP_Log(RTMP_LOGDEBUG, "%s, unknown packet type received: 0x%02x", __FUNCTION__,
      packet->m_packetType);
#ifdef _DEBUG
    RTMP_LogHex(RTMP_LOGDEBUG, packet->m_body, packet->m_nBodySize);
#endif
  }

  return bHasMediaPacket;
}
#if defined(RTMP_NETSTACK_DUMP)
extern FILE *netstackdump;
extern FILE *netstackdump_read;
#endif

static int
ReadN(RTMP *r, char *buffer, int n)
{
  int nOriginalSize = n;
  int avail;
  char *ptr;

  r->m_sb.sb_timedout = FALSE;

#ifdef _DEBUG
  memset(buffer, 0, n);
#endif

  ptr = buffer;
  while (n > 0)
    {
      int nBytes = 0, nRead;
      if (r->Link.protocol & RTMP_FEATURE_HTTP)
        {
	  int refill = 0;
	  while (!r->m_resplen)
	    {
	      int ret;
	      if (r->m_sb.sb_size < 13 || refill)
	        {
		  if (!r->m_unackd)
		    HTTP_Post(r, RTMPT_IDLE, "", 1);
		  if (RTMPSockBuf_Fill(&r->m_sb) < 1)
		    {
		      if (!r->m_sb.sb_timedout)
		        RTMP_Close(r);
		      return 0;
		    }
		}
	      if ((ret = HTTP_read(r, 0)) == -1)
		{
		  RTMP_Log(RTMP_LOGDEBUG, "%s, No valid HTTP response found", __FUNCTION__);
		  RTMP_Close(r);
		  return 0;
		}
              else if (ret == -2)
                {
                  refill = 1;
                }
              else
                {
                  refill = 0;
                }
	    }
	  if (r->m_resplen && !r->m_sb.sb_size)
	    RTMPSockBuf_Fill(&r->m_sb);
          avail = r->m_sb.sb_size;
	  if (avail > r->m_resplen)
	    avail = r->m_resplen;
	}
      else
        {
          avail = r->m_sb.sb_size;
	  if (avail == 0)
	    {
	      if (RTMPSockBuf_Fill(&r->m_sb) < 1)
	        {
	          if (!r->m_sb.sb_timedout)
	            RTMP_Close(r);
	          return 0;
		}
	      avail = r->m_sb.sb_size;
	    }
	}
      nRead = ((n < avail) ? n : avail);
      if (nRead > 0)
	{
	  memcpy(ptr, r->m_sb.sb_start, nRead);
	  r->m_sb.sb_start += nRead;
	  r->m_sb.sb_size -= nRead;
	  nBytes = nRead;
	  r->m_nBytesIn += nRead;
	  if (r->m_bSendCounter
	      && r->m_nBytesIn > ( r->m_nBytesInSent + r->m_nClientBW / 10))
	    if (!SendBytesReceived(r))
	        return FALSE;
	}
      /*RTMP_Log(RTMP_LOGDEBUG, "%s: %d bytes\n", __FUNCTION__, nBytes); */
#if defined(RTMP_NETSTACK_DUMP)
      fwrite(ptr, 1, nBytes, netstackdump_read);
#endif

      if (nBytes == 0)
	{
	  RTMP_Log(RTMP_LOGDEBUG, "%s, RTMP socket closed by peer", __FUNCTION__);
	  /*goto again; */
	  RTMP_Close(r);
	  break;
	}

      if (r->Link.protocol & RTMP_FEATURE_HTTP)
	r->m_resplen -= nBytes;

#ifdef CRYPTO
      if (r->Link.rc4keyIn)
	{
	  RC4_encrypt(r->Link.rc4keyIn, nBytes, ptr);
	}
#endif

      n -= nBytes;
      ptr += nBytes;
    }

  return nOriginalSize - n;
}

static int
WriteN(RTMP *r, const char *buffer, int n)
{
  const char *ptr = buffer;
#ifdef CRYPTO
  char *encrypted = 0;
  char buf[RTMP_BUFFER_CACHE_SIZE];

  if (r->Link.rc4keyOut)
    {
      if (n > sizeof(buf))
	encrypted = (char *)malloc(n);
      else
	encrypted = (char *)buf;
      ptr = encrypted;
      RC4_encrypt2(r->Link.rc4keyOut, n, buffer, ptr);
    }
#endif

  while (n > 0)
    {
      int nBytes;

      if (r->Link.protocol & RTMP_FEATURE_HTTP)
        nBytes = HTTP_Post(r, RTMPT_SEND, ptr, n);
      else
        nBytes = RTMPSockBuf_Send(&r->m_sb, ptr, n);
      /*RTMP_Log(RTMP_LOGDEBUG, "%s: %d\n", __FUNCTION__, nBytes); */

      if (nBytes < 0)
	{
	  int sockerr = GetSockError();
	  RTMP_Log(RTMP_LOGERROR, "[%d]%s, send(%d bytes) error:%d(%s)",
          r->m_sb.sb_socket, __FUNCTION__, n, sockerr, strerror(sockerr));

	  if (sockerr == EINTR && !RTMP_ctrlC)
	    continue;

	  //RTMP_Close(r);
      RTMPSockBuf_Close(&r->m_sb);
	  n = 1;
	  break;
	}

      if (nBytes == 0)
	break;

      n -= nBytes;
      ptr += nBytes;
    }

#ifdef CRYPTO
  if (encrypted && encrypted != buf)
    free(encrypted);
#endif

  return n == 0;
}



static int
SendConnectPacket(RTMP *r, RTMPPacket *cp)
{
  RTMPPacket packet;
  char pbuf[4096], *pend = pbuf + sizeof(pbuf);
  char *enc;

  if (cp)
    return RTMP_SendPacket(r, cp, TRUE);

  if((r->Link.protocol & RTMP_FEATURE_WRITE))
  {
    if(!RTMP_SendChunkSize(r))
      return false;
  }

  packet.m_nChannel = 0x03;	/* control channel (invoke) */
  packet.m_headerType = RTMP_PACKET_SIZE_LARGE;
  packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
  packet.m_nTimeStamp = 0;
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av_connect);
  enc = AMF_EncodeNumber(enc, pend, ++r->m_numInvokes);
  *enc++ = AMF_OBJECT;

  enc = AMF_EncodeNamedString(enc, pend, &av_app, &r->Link.app);
  if (!enc)
    return FALSE;
  if (r->Link.protocol & RTMP_FEATURE_WRITE)
    {
      enc = AMF_EncodeNamedString(enc, pend, &av_type, &av_nonprivate);
      if (!enc)
	return FALSE;
    }
  if (r->Link.flashVer.av_len)
    {
      enc = AMF_EncodeNamedString(enc, pend, &av_flashVer, &r->Link.flashVer);
      if (!enc)
	return FALSE;
    }
  if (r->Link.swfUrl.av_len)
    {
      enc = AMF_EncodeNamedString(enc, pend, &av_swfUrl, &r->Link.swfUrl);
      if (!enc)
	return FALSE;
    }
  if (r->Link.tcUrl.av_len)
    {
      enc = AMF_EncodeNamedString(enc, pend, &av_tcUrl, &r->Link.tcUrl);
      if (!enc)
	return FALSE;
    }
  if (!(r->Link.protocol & RTMP_FEATURE_WRITE))
    {
      enc = AMF_EncodeNamedBoolean(enc, pend, &av_fpad, FALSE);
      if (!enc)
	return FALSE;
      enc = AMF_EncodeNamedNumber(enc, pend, &av_capabilities, 15.0);
      if (!enc)
	return FALSE;
      enc = AMF_EncodeNamedNumber(enc, pend, &av_audioCodecs, r->m_fAudioCodecs);
      if (!enc)
	return FALSE;
      enc = AMF_EncodeNamedNumber(enc, pend, &av_videoCodecs, r->m_fVideoCodecs);
      if (!enc)
	return FALSE;
      enc = AMF_EncodeNamedNumber(enc, pend, &av_videoFunction, 1.0);
      if (!enc)
	return FALSE;
      if (r->Link.pageUrl.av_len)
	{
	  enc = AMF_EncodeNamedString(enc, pend, &av_pageUrl, &r->Link.pageUrl);
	  if (!enc)
	    return FALSE;
	}
    }
  if (r->m_fEncoding != 0.0 || r->m_bSendEncoding)
    {	/* AMF0, AMF3 not fully supported yet */
      enc = AMF_EncodeNamedNumber(enc, pend, &av_objectEncoding, r->m_fEncoding);
      if (!enc)
	return FALSE;
    }
  if (enc + 3 >= pend)
    return FALSE;
  *enc++ = 0;
  *enc++ = 0;			/* end of object - 0x00 0x00 0x09 */
  *enc++ = AMF_OBJECT_END;

  /* add auth string */
  if (r->Link.auth.av_len)
    {
      enc = AMF_EncodeBoolean(enc, pend, r->Link.lFlags & RTMP_LF_AUTH);
      if (!enc)
	return FALSE;
      enc = AMF_EncodeString(enc, pend, &r->Link.auth);
      if (!enc)
	return FALSE;
    }
  if (r->Link.extras.o_num)
    {
      int i;
      for (i = 0; i < r->Link.extras.o_num; i++)
	{
	  enc = AMFProp_Encode(&r->Link.extras.o_props[i], enc, pend);
	  if (!enc)
	    return FALSE;
	}
    }
  packet.m_nBodySize = enc - packet.m_body;

  return RTMP_SendPacket(r, &packet, TRUE);
}

#if 0				/* unused */
SAVC(bgHasStream);

static int
SendBGHasStream(RTMP *r, double dId, AVal *playpath)
{
  RTMPPacket packet;
  char pbuf[1024], *pend = pbuf + sizeof(pbuf);
  char *enc;

  packet.m_nChannel = 0x03;	/* control channel (invoke) */
  packet.m_headerType = RTMP_PACKET_SIZE_MEDIUM;
  packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
  packet.m_nTimeStamp = 0;
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av_bgHasStream);
  enc = AMF_EncodeNumber(enc, pend, dId);
  *enc++ = AMF_NULL;

  enc = AMF_EncodeString(enc, pend, playpath);
  if (enc == NULL)
    return FALSE;

  packet.m_nBodySize = enc - packet.m_body;

  return RTMP_SendPacket(r, &packet, TRUE);
}
#endif

static bool
SendInvoke(RTMP *r, double transaction_id, const AVal *method, const AVal* props[])
{
  RTMPPacket packet;
  char pbuf[512], *pend = pbuf + sizeof(pbuf);

  packet.m_nChannel = 0x03;     // control channel (invoke)
  packet.m_headerType = RTMP_PACKET_SIZE_MEDIUM;
  packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
  packet.m_nTimeStamp = 0;
  packet.m_nInfoField2 = r->m_stream_id;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  char *enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, method);
  enc = AMF_EncodeNumber(enc, pend, transaction_id);
  *enc++ = AMF_NULL;//args
  if (props)
  {
    *enc++ = AMF_OBJECT;
    while (props[0] && props[1]) {
      enc = AMF_EncodeNamedString(enc, pend, props[0], props[1]);
      props += 2;
    }
    *enc++ = 0;
    *enc++ = 0;
    *enc++ = AMF_OBJECT_END;
  }
  packet.m_nBodySize = enc - packet.m_body;
  return RTMP_SendPacket(r, &packet, transaction_id > 0);
}
static bool
SendOnStatus(RTMP *r, const AVal* props[])
{
  RTMPPacket packet;
  char pbuf[512], *pend = pbuf + sizeof(pbuf);

  packet.m_nChannel = 0x03;     // control channel (invoke)
  packet.m_headerType = RTMP_PACKET_SIZE_MEDIUM;
  packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
  packet.m_nTimeStamp = 0;
  packet.m_nInfoField2 = r->m_stream_id;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  char *enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av_onStatus);
  enc = AMF_EncodeNumber(enc, pend, 0);//transaction_id
  *enc++ = AMF_NULL;//args

  *enc++ = AMF_OBJECT;
  enc = AMF_EncodeNamedString(enc, pend, &av_level, &av_status);
  while (props[0] && props[1]) {
    enc = AMF_EncodeNamedString(enc, pend, props[0], props[1]);
    props += 2;
  }
  *enc++ = 0;
  *enc++ = 0;
  *enc++ = AMF_OBJECT_END;

  packet.m_nBodySize = enc - packet.m_body;
  return RTMP_SendPacket(r, &packet, FALSE);
}
static bool
SendPlayReset(RTMP *r)
{
  const AVal* props[] = {
    &av_code, &av_NetStream_Play_Reset,
    &av_description, &av_Playing_resetting,
    &av_details, &r->Link.playpath,
    &av_clientid, &av_clientid, NULL};
  return SendOnStatus(r, props);
}
static bool
SendPlayStart(RTMP *r)
{
  const AVal* props[] = {
    &av_code, &av_NetStream_Play_Start,
    &av_description, &av_Started_playing,
    &av_details, &r->Link.playpath,
    &av_clientid, &av_clientid, NULL};
  return SendOnStatus(r, props);
}
static bool
SendDataStart(RTMP *r)
{
  RTMPPacket packet;
  char pbuf[512], *pend = pbuf + sizeof(pbuf);

  packet.m_nChannel = 0x03;     // control channel (invoke)
  packet.m_headerType = RTMP_PACKET_SIZE_MEDIUM;
  packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
  packet.m_nTimeStamp = 0;
  packet.m_nInfoField2 = r->m_stream_id;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  char *enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av_onStatus);

  *enc++ = AMF_OBJECT;
  enc = AMF_EncodeNamedString(enc, pend, &av_code, &av_NetStream_Data_Start);
  *enc++ = 0;
  *enc++ = 0;
  *enc++ = AMF_OBJECT_END;

  packet.m_nBodySize = enc - packet.m_body;
  return RTMP_SendPacket(r, &packet, FALSE);
}
bool
RTMP_SendPlayStop(RTMP *r, const AVal*playpath)
{
  const AVal* props[] = {
    &av_code, &av_NetStream_Play_Stop,
    &av_description, &av_Stopped_playing,
    &av_details, playpath,
    &av_clientid, &av_clientid, NULL };
  return SendOnStatus(r, props);
}
static bool
SendPublishStart(RTMP *r)
{
  const AVal* props[] = {
    &av_code, &av_NetStream_Publish_Start,
    &av_description, &av_Started_publishing,
    &av_clientid, &av_clientid, NULL};
  return SendOnStatus(r, props);
}
static bool
RTMP_SendCreateStream(RTMP *r)
{
  return SendInvoke(r, ++r->m_numInvokes, &av_createStream, NULL);
}
int
RTMP_ReconnectStream(RTMP *r, int seekTime)
{
  RTMP_DeleteStream(r);

  RTMP_SendCreateStream(r);

  return RTMP_ConnectStream(r, seekTime);
}

static int
SendFCSubscribe(RTMP *r, AVal *subscribepath)
{
  RTMPPacket packet;
  char pbuf[512], *pend = pbuf + sizeof(pbuf);
  char *enc;
  packet.m_nChannel = 0x03;	/* control channel (invoke) */
  packet.m_headerType = RTMP_PACKET_SIZE_MEDIUM;
  packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
  packet.m_nTimeStamp = 0;
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  RTMP_Log(RTMP_LOGDEBUG, "FCSubscribe: %s", subscribepath->av_val);
  enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av_FCSubscribe);
  enc = AMF_EncodeNumber(enc, pend, ++r->m_numInvokes);
  *enc++ = AMF_NULL;
  enc = AMF_EncodeString(enc, pend, subscribepath);

  if (!enc)
    return FALSE;

  packet.m_nBodySize = enc - packet.m_body;

  return RTMP_SendPacket(r, &packet, TRUE);
}

/* Justin.tv specific authentication */

static int
SendUsherToken(RTMP *r, AVal *usherToken)
{
  RTMPPacket packet;
  char pbuf[1024], *pend = pbuf + sizeof(pbuf);
  char *enc;
  packet.m_nChannel = 0x03;	/* control channel (invoke) */
  packet.m_headerType = RTMP_PACKET_SIZE_MEDIUM;
  packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
  packet.m_nTimeStamp = 0;
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  RTMP_Log(RTMP_LOGDEBUG, "UsherToken: %s", usherToken->av_val);
  enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av_NetStream_Authenticate_UsherToken);
  enc = AMF_EncodeNumber(enc, pend, ++r->m_numInvokes);
  *enc++ = AMF_NULL;
  enc = AMF_EncodeString(enc, pend, usherToken);

  if (!enc)
    return FALSE;

  packet.m_nBodySize = enc - packet.m_body;

  return RTMP_SendPacket(r, &packet, FALSE);
}
/******************************************/


static int
SendReleaseStream(RTMP *r)
{
  RTMPPacket packet;
  char pbuf[1024], *pend = pbuf + sizeof(pbuf);
  char *enc;

  packet.m_nChannel = 0x03;	/* control channel (invoke) */
  packet.m_headerType = RTMP_PACKET_SIZE_MEDIUM;
  packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
  packet.m_nTimeStamp = 0;
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

 enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av_releaseStream);
  enc = AMF_EncodeNumber(enc, pend, ++r->m_numInvokes);
  *enc++ = AMF_NULL;
  enc = AMF_EncodeString(enc, pend, &r->Link.playpath);
  if (!enc)
    return FALSE;

  packet.m_nBodySize = enc - packet.m_body;

  return RTMP_SendPacket(r, &packet, FALSE);
}


static int
SendFCPublish(RTMP *r)
{
  RTMPPacket packet;
  char pbuf[1024], *pend = pbuf + sizeof(pbuf);
  char *enc;

  packet.m_nChannel = 0x03;	/* control channel (invoke) */
  packet.m_headerType = RTMP_PACKET_SIZE_MEDIUM;
  packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
  packet.m_nTimeStamp = 0;
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av_FCPublish);
  enc = AMF_EncodeNumber(enc, pend, ++r->m_numInvokes);
  *enc++ = AMF_NULL;
  enc = AMF_EncodeString(enc, pend, &r->Link.playpath);
  if (!enc)
    return FALSE;

  packet.m_nBodySize = enc - packet.m_body;

  return RTMP_SendPacket(r, &packet, FALSE);
}


static int
SendFCUnpublish(RTMP *r)
{
  RTMPPacket packet;
  char pbuf[1024], *pend = pbuf + sizeof(pbuf);
  char *enc;

  packet.m_nChannel = 0x03;	/* control channel (invoke) */
  packet.m_headerType = RTMP_PACKET_SIZE_MEDIUM;
  packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
  packet.m_nTimeStamp = 0;
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av_FCUnpublish);
  enc = AMF_EncodeNumber(enc, pend, ++r->m_numInvokes);
  *enc++ = AMF_NULL;
  enc = AMF_EncodeString(enc, pend, &r->Link.playpath);
  if (!enc)
    return FALSE;

  packet.m_nBodySize = enc - packet.m_body;

  return RTMP_SendPacket(r, &packet, FALSE);
}


static int
SendPublish(RTMP *r)
{
  RTMPPacket packet;
  char pbuf[1024], *pend = pbuf + sizeof(pbuf);
  char *enc;

  packet.m_nChannel = 0x04;	/* source channel (invoke) */
  packet.m_headerType = RTMP_PACKET_SIZE_LARGE;
  packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
  packet.m_nTimeStamp = 0;
  packet.m_nInfoField2 = r->m_stream_id;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av_publish);
  enc = AMF_EncodeNumber(enc, pend, ++r->m_numInvokes);
  *enc++ = AMF_NULL;
  enc = AMF_EncodeString(enc, pend, &r->Link.playpath);
  if (!enc)
    return FALSE;

  if (r->Link.lFlags & RTMP_LF_LIVE) {
    enc = AMF_EncodeString(enc, pend, &av_live);
    if (!enc)
      return FALSE;
  }

  packet.m_nBodySize = enc - packet.m_body;

  return RTMP_SendPacket(r, &packet, TRUE);
}


static int
SendDeleteStream(RTMP *r, double dStreamId)
{
  RTMPPacket packet;
  char pbuf[256], *pend = pbuf + sizeof(pbuf);
  char *enc;

  packet.m_nChannel = 0x03;	/* control channel (invoke) */
  packet.m_headerType = RTMP_PACKET_SIZE_MEDIUM;
  packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
  packet.m_nTimeStamp = 0;
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av_deleteStream);
  enc = AMF_EncodeNumber(enc, pend, ++r->m_numInvokes);
  *enc++ = AMF_NULL;
  enc = AMF_EncodeNumber(enc, pend, dStreamId);

  packet.m_nBodySize = enc - packet.m_body;

  /* no response expected */
  return RTMP_SendPacket(r, &packet, FALSE);
}


int
RTMP_SendPause(RTMP *r, int DoPause, int iTime)
{
  RTMPPacket packet;
  char pbuf[256], *pend = pbuf + sizeof(pbuf);
  char *enc;

  packet.m_nChannel = 0x08;	/* video channel */
  packet.m_headerType = RTMP_PACKET_SIZE_MEDIUM;
  packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
  packet.m_nTimeStamp = 0;
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av_pause);
  enc = AMF_EncodeNumber(enc, pend, ++r->m_numInvokes);
  *enc++ = AMF_NULL;
  enc = AMF_EncodeBoolean(enc, pend, DoPause);
  enc = AMF_EncodeNumber(enc, pend, (double)iTime);

  packet.m_nBodySize = enc - packet.m_body;

  RTMP_Log(RTMP_LOGDEBUG, "%s, %d, pauseTime=%d", __FUNCTION__, DoPause, iTime);
  return RTMP_SendPacket(r, &packet, TRUE);
}

int RTMP_Pause(RTMP *r, int DoPause)
{
  if (DoPause)
    r->m_pauseStamp = r->m_mediaChannel < r->m_channelsAllocatedIn ?
                      r->m_channelTimestamp[r->m_mediaChannel] : 0;
  return RTMP_SendPause(r, DoPause, r->m_pauseStamp);
}


int
RTMP_SendSeek(RTMP *r, int iTime)
{
  RTMPPacket packet;
  char pbuf[256], *pend = pbuf + sizeof(pbuf);
  char *enc;

  packet.m_nChannel = 0x08;	/* video channel */
  packet.m_headerType = RTMP_PACKET_SIZE_MEDIUM;
  packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
  packet.m_nTimeStamp = 0;
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av_seek);
  enc = AMF_EncodeNumber(enc, pend, ++r->m_numInvokes);
  *enc++ = AMF_NULL;
  enc = AMF_EncodeNumber(enc, pend, (double)iTime);

  packet.m_nBodySize = enc - packet.m_body;

  r->m_read.flags |= RTMP_READ_SEEKING;
  r->m_read.nResumeTS = 0;

  return RTMP_SendPacket(r, &packet, TRUE);
}

bool
RTMP_SendChunkSize(RTMP *r)
{
  RTMPPacket packet;
  char pbuf[256], *pend = pbuf + sizeof(pbuf);

  packet.m_nChannel = 0x02;
  packet.m_headerType = RTMP_PACKET_SIZE_LARGE;
  packet.m_packetType = RTMP_PACKET_TYPE_CHUNK_SIZE;
  packet.m_nTimeStamp = 0;
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;
  packet.m_nBodySize = 4;

  AMF_EncodeInt32(packet.m_body, pend, r->m_outChunkSize);

  return RTMP_SendPacket(r, &packet, FALSE);
}

int
RTMP_SendServerBW(RTMP *r)
{
  RTMPPacket packet;
  char pbuf[256], *pend = pbuf + sizeof(pbuf);

  packet.m_nChannel = 0x02;	/* control channel (invoke) */
  packet.m_headerType = RTMP_PACKET_SIZE_LARGE;
  packet.m_packetType = RTMP_PACKET_TYPE_SERVER_BW;
  packet.m_nTimeStamp = 0;
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  packet.m_nBodySize = 4;

  AMF_EncodeInt32(packet.m_body, pend, r->m_nServerBW);
  return RTMP_SendPacket(r, &packet, FALSE);
}

int
RTMP_SendClientBW(RTMP *r)
{
  RTMPPacket packet;
  char pbuf[256], *pend = pbuf + sizeof(pbuf);

  packet.m_nChannel = 0x02;	/* control channel (invoke) */
  packet.m_headerType = RTMP_PACKET_SIZE_LARGE;
  packet.m_packetType = RTMP_PACKET_TYPE_CLIENT_BW;
  packet.m_nTimeStamp = 0;
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  packet.m_nBodySize = 5;

  AMF_EncodeInt32(packet.m_body, pend, r->m_nClientBW);
  packet.m_body[4] = r->m_nClientBW2;
  return RTMP_SendPacket(r, &packet, FALSE);
}

static int
SendBytesReceived(RTMP *r)
{
  RTMPPacket packet;
  char pbuf[256], *pend = pbuf + sizeof(pbuf);

  packet.m_nChannel = 0x02;	/* control channel (invoke) */
  packet.m_headerType = RTMP_PACKET_SIZE_MEDIUM;
  packet.m_packetType = RTMP_PACKET_TYPE_BYTES_READ_REPORT;
  packet.m_nTimeStamp = 0;
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  packet.m_nBodySize = 4;

  AMF_EncodeInt32(packet.m_body, pend, r->m_nBytesIn);	/* hard coded for now */
  r->m_nBytesInSent = r->m_nBytesIn;

  /*RTMP_Log(RTMP_LOGDEBUG, "Send bytes report. 0x%x (%d bytes)", (unsigned int)m_nBytesIn, m_nBytesIn); */
  return RTMP_SendPacket(r, &packet, FALSE);
}


static int
SendCheckBW(RTMP *r)
{
  RTMPPacket packet;
  char pbuf[256], *pend = pbuf + sizeof(pbuf);
  char *enc;

  packet.m_nChannel = 0x03;	/* control channel (invoke) */
  packet.m_headerType = RTMP_PACKET_SIZE_LARGE;
  packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
  packet.m_nTimeStamp = 0;	/* RTMP_GetTime(); */
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av__checkbw);
  enc = AMF_EncodeNumber(enc, pend, ++r->m_numInvokes);
  *enc++ = AMF_NULL;

  packet.m_nBodySize = enc - packet.m_body;

  /* triggers _onbwcheck and eventually results in _onbwdone */
  return RTMP_SendPacket(r, &packet, FALSE);
}


static int
SendCheckBWResult(RTMP *r, double txn)
{
  RTMPPacket packet;
  char pbuf[256], *pend = pbuf + sizeof(pbuf);
  char *enc;

  packet.m_nChannel = 0x03;	/* control channel (invoke) */
  packet.m_headerType = RTMP_PACKET_SIZE_MEDIUM;
  packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
  packet.m_nTimeStamp = 0x16 * r->m_nBWCheckCounter;	/* temp inc value. till we figure it out. */
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av__result);
  enc = AMF_EncodeNumber(enc, pend, txn);
  *enc++ = AMF_NULL;
  enc = AMF_EncodeNumber(enc, pend, (double)r->m_nBWCheckCounter++);

  packet.m_nBodySize = enc - packet.m_body;

  return RTMP_SendPacket(r, &packet, FALSE);
}


static int
SendPong(RTMP *r, double txn)
{
  RTMPPacket packet;
  char pbuf[256], *pend = pbuf + sizeof(pbuf);
  char *enc;

  packet.m_nChannel = 0x03;	/* control channel (invoke) */
  packet.m_headerType = RTMP_PACKET_SIZE_MEDIUM;
  packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
  packet.m_nTimeStamp = 0x16 * r->m_nBWCheckCounter;	/* temp inc value. till we figure it out. */
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av_pong);
  enc = AMF_EncodeNumber(enc, pend, txn);
  *enc++ = AMF_NULL;

  packet.m_nBodySize = enc - packet.m_body;

  return RTMP_SendPacket(r, &packet, FALSE);
}


static int
SendPlay(RTMP *r)
{
  RTMPPacket packet;
  char pbuf[1024], *pend = pbuf + sizeof(pbuf);
  char *enc;

  packet.m_nChannel = 0x08;	/* we make 8 our stream channel */
  packet.m_headerType = RTMP_PACKET_SIZE_LARGE;
  packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
  packet.m_nTimeStamp = 0;
  packet.m_nInfoField2 = r->m_stream_id;	/*0x01000000; */
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av_play);
  enc = AMF_EncodeNumber(enc, pend, ++r->m_numInvokes);
  *enc++ = AMF_NULL;

  RTMP_Log(RTMP_LOGDEBUG, "%s, seekTime=%d, stopTime=%d, sending play: %s",
      __FUNCTION__, r->Link.seekTime, r->Link.stopTime,
      r->Link.playpath.av_val);
  enc = AMF_EncodeString(enc, pend, &r->Link.playpath);
  if (!enc)
    return FALSE;

  /* Optional parameters start and len.
   *
   * start: -2, -1, 0, positive number
   *  -2: looks for a live stream, then a recorded stream,
   *      if not found any open a live stream
   *  -1: plays a live stream
   * >=0: plays a recorded streams from 'start' milliseconds
   */
  if (r->Link.lFlags & RTMP_LF_LIVE)
    enc = AMF_EncodeNumber(enc, pend, -1000.0);
  else
    {
      if (r->Link.seekTime > 0.0)
	enc = AMF_EncodeNumber(enc, pend, r->Link.seekTime);	/* resume from here */
      else
	enc = AMF_EncodeNumber(enc, pend, 0.0);	/*-2000.0);*/ /* recorded as default, -2000.0 is not reliable since that freezes the player if the stream is not found */
    }
  if (!enc)
    return FALSE;

  /* len: -1, 0, positive number
   *  -1: plays live or recorded stream to the end (default)
   *   0: plays a frame 'start' ms away from the beginning
   *  >0: plays a live or recoded stream for 'len' milliseconds
   */
  /*enc += EncodeNumber(enc, -1.0); */ /* len */
  if (r->Link.stopTime)
    {
      enc = AMF_EncodeNumber(enc, pend, r->Link.stopTime - r->Link.seekTime);
      if (!enc)
	return FALSE;
    }

  packet.m_nBodySize = enc - packet.m_body;

  return RTMP_SendPacket(r, &packet, TRUE);
}



static int
SendPlaylist(RTMP *r)
{
  RTMPPacket packet;
  char pbuf[1024], *pend = pbuf + sizeof(pbuf);
  char *enc;

  packet.m_nChannel = 0x08;	/* we make 8 our stream channel */
  packet.m_headerType = RTMP_PACKET_SIZE_LARGE;
  packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
  packet.m_nTimeStamp = 0;
  packet.m_nInfoField2 = r->m_stream_id;	/*0x01000000; */
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av_set_playlist);
  enc = AMF_EncodeNumber(enc, pend, 0);
  *enc++ = AMF_NULL;
  *enc++ = AMF_ECMA_ARRAY;
  *enc++ = 0;
  *enc++ = 0;
  *enc++ = 0;
  *enc++ = AMF_OBJECT;
  enc = AMF_EncodeNamedString(enc, pend, &av_0, &r->Link.playpath);
  if (!enc)
    return FALSE;
  if (enc + 3 >= pend)
    return FALSE;
  *enc++ = 0;
  *enc++ = 0;
  *enc++ = AMF_OBJECT_END;

  packet.m_nBodySize = enc - packet.m_body;

  return RTMP_SendPacket(r, &packet, TRUE);
}

static int
SendSecureTokenResponse(RTMP *r, AVal *resp)
{
  RTMPPacket packet;
  char pbuf[1024], *pend = pbuf + sizeof(pbuf);
  char *enc;

  packet.m_nChannel = 0x03;	/* control channel (invoke) */
  packet.m_headerType = RTMP_PACKET_SIZE_MEDIUM;
  packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
  packet.m_nTimeStamp = 0;
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av_secureTokenResponse);
  enc = AMF_EncodeNumber(enc, pend, 0.0);
  *enc++ = AMF_NULL;
  enc = AMF_EncodeString(enc, pend, resp);
  if (!enc)
    return FALSE;

  packet.m_nBodySize = enc - packet.m_body;

  return RTMP_SendPacket(r, &packet, FALSE);
}

/*
from http://jira.red5.org/confluence/display/docs/Ping:

Ping is the most mysterious message in RTMP and till now we haven't fully interpreted it yet. In summary, Ping message is used as a special command that are exchanged between client and server. This page aims to document all known Ping messages. Expect the list to grow.

The type of Ping packet is 0x4 and contains two mandatory parameters and two optional parameters. The first parameter is the type of Ping and in short integer. The second parameter is the target of the ping. As Ping is always sent in Channel 2 (control channel) and the target object in RTMP header is always 0 which means the Connection object, it's necessary to put an extra parameter to indicate the exact target object the Ping is sent to. The second parameter takes this responsibility. The value has the same meaning as the target object field in RTMP header. (The second value could also be used as other purposes, like RTT Ping/Pong. It is used as the timestamp.) The third and fourth parameters are optional and could be looked upon as the parameter of the Ping packet. Below is an unexhausted list of Ping messages.

    * type 0: Clear the stream. No third and fourth parameters. The second parameter could be 0. After the connection is established, a Ping 0,0 will be sent from server to client. The message will also be sent to client on the start of Play and in response of a Seek or Pause/Resume request. This Ping tells client to re-calibrate the clock with the timestamp of the next packet server sends.
    * type 1: Tell the stream to clear the playing buffer.
    * type 3: Buffer time of the client. The third parameter is the buffer time in millisecond.
    * type 4: Reset a stream. Used together with type 0 in the case of VOD. Often sent before type 0.
    * type 6: Ping the client from server. The second parameter is the current time.
    * type 7: Pong reply from client. The second parameter is the time the server sent with his ping request.
    * type 26: SWFVerification request
    * type 27: SWFVerification response
*/
bool
RTMP_SendCtrl(RTMP *r, enum RTMPCtrlType nType, unsigned nObject, unsigned nTime)
{
  RTMPPacket packet;
  char pbuf[256], *pend = pbuf + sizeof(pbuf);
  int nSize;
  char *buf;

  RTMP_Log(RTMP_LOGDEBUG, "sending ctrl. type: 0x%04x", (unsigned short)nType);

  packet.m_nChannel = 0x02;	/* control channel (ping) */
  packet.m_headerType = RTMP_PACKET_SIZE_MEDIUM;
  packet.m_packetType = RTMP_PACKET_TYPE_CONTROL;
  packet.m_nTimeStamp = 0;	/* RTMP_GetTime(); */
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  switch(nType) {
  case RTMP_CTRL_SET_BUFFER_MS: nSize = 10; break;	/* buffer time */
  case RTMP_CTRL_SWF_VERIFY: nSize = 3; break;	/* SWF verify request */
  case RTMP_CTRL_SWF_HMAC_SHA256: nSize = 44; break;	/* SWF verify response */
  default: nSize = 6; break;
  }

  packet.m_nBodySize = nSize;

  buf = packet.m_body;
  buf = AMF_EncodeInt16(buf, pend, nType);

  if (nType == RTMP_CTRL_SWF_HMAC_SHA256)
  {
#ifdef CRYPTO
    memcpy(buf, r->Link.SWFVerificationResponse, 42);
    RTMP_Log(RTMP_LOGDEBUG, "Sending SWFVerification response: ");
    RTMP_LogHex(RTMP_LOGDEBUG, (uint8_t *)packet.m_body, packet.m_nBodySize);
#endif
  }
  else if (nType == RTMP_CTRL_SWF_VERIFY)
  {
    *buf = nObject & 0xff;
  }
  else
  {
    if (nSize > 2)
      buf = AMF_EncodeInt32(buf, pend, nObject);

    if (nSize > 6)
      buf = AMF_EncodeInt32(buf, pend, nTime);
  }

  return RTMP_SendPacket(r, &packet, FALSE);
}

static void
AV_erase(RTMP_METHOD *vals, int *num, int i, int freeit)
{
  if (freeit)
    free(vals[i].name.av_val);
  (*num)--;
  for (; i < *num; i++)
    {
      vals[i] = vals[i + 1];
    }
  vals[i].name.av_val = NULL;
  vals[i].name.av_len = 0;
  vals[i].num = 0;
}

void
RTMP_DropRequest(RTMP *r, int i, int freeit)
{
  AV_erase(r->m_methodCalls, &r->m_numCalls, i, freeit);
}

static void
AV_queue(RTMP_METHOD **vals, int *num, AVal *av, int txn)
{
  char *tmp;
  if (!(*num & 0x0f))
    *vals = realloc(*vals, (*num + 16) * sizeof(RTMP_METHOD));
  tmp = malloc(av->av_len + 1);
  memcpy(tmp, av->av_val, av->av_len);
  tmp[av->av_len] = '\0';
  (*vals)[*num].num = txn;
  (*vals)[*num].name.av_len = av->av_len;
  (*vals)[(*num)++].name.av_val = tmp;
}

static void
AV_clear(RTMP_METHOD *vals, int num)
{
  int i;
  for (i = 0; i < num; i++)
    free(vals[i].name.av_val);
  free(vals);
}


#ifdef CRYPTO
static int
b64enc(const unsigned char *input, int length, char *output, int maxsize)
{
#ifdef USE_POLARSSL
  size_t buf_size = maxsize;
  if(base64_encode((unsigned char *) output, &buf_size, input, length) == 0)
    {
      output[buf_size] = '\0';
      return 1;
    }
  else
    {
      RTMP_Log(RTMP_LOGDEBUG, "%s, error", __FUNCTION__);
      return 0;
    }
#elif defined(USE_GNUTLS)
  if (BASE64_ENCODE_RAW_LENGTH(length) <= maxsize)
    base64_encode_raw((uint8_t*) output, length, input);
  else
    {
      RTMP_Log(RTMP_LOGDEBUG, "%s, error", __FUNCTION__);
      return 0;
    }
#else   /* USE_OPENSSL */
  BIO *bmem, *b64;
  BUF_MEM *bptr;

  b64 = BIO_new(BIO_f_base64());
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_write(b64, input, length);
  if (BIO_flush(b64) == 1)
    {
      BIO_get_mem_ptr(b64, &bptr);
      memcpy(output, bptr->data, bptr->length-1);
      output[bptr->length-1] = '\0';
    }
  else
    {
      RTMP_Log(RTMP_LOGDEBUG, "%s, error", __FUNCTION__);
      return 0;
    }
  BIO_free_all(b64);
#endif
  return 1;
}

#ifdef USE_POLARSSL
#define MD5_CTX	md5_context
#define MD5_Init(ctx)	md5_starts(ctx)
#define MD5_Update(ctx,data,len)	md5_update(ctx,(unsigned char *)data,len)
#define MD5_Final(dig,ctx)	md5_finish(ctx,dig)
#elif defined(USE_GNUTLS)
typedef struct md5_ctx	MD5_CTX;
#define MD5_Init(ctx)	md5_init(ctx)
#define MD5_Update(ctx,data,len)	md5_update(ctx,len,data)
#define MD5_Final(dig,ctx)	md5_digest(ctx,MD5_DIGEST_LENGTH,dig)
#else
#endif

static void hexenc(unsigned char *inbuf, int len, char *dst)
{
    char *ptr = dst;
    while(len--) {
        sprintf(ptr, "%02x", *inbuf++);
        ptr += 2;
    }
    *ptr = '\0';
}

static char *
AValChr(AVal *av, char c)
{
  int i;
  for (i = 0; i < av->av_len; i++)
    if (av->av_val[i] == c)
      return &av->av_val[i];
  return NULL;
}

static int
PublisherAuth(RTMP *r, AVal *description)
{
  char *token_in = NULL;
  char *ptr;
  unsigned char md5sum_val[MD5_DIGEST_LENGTH+1];
  MD5_CTX md5ctx;
  int challenge2_data;
#define RESPONSE_LEN 32
#define CHALLENGE2_LEN 16
#define SALTED2_LEN (32+8+8+8)
#define B64DIGEST_LEN	24	/* 16 byte digest => 22 b64 chars + 2 chars padding */
#define B64INT_LEN	8	/* 4 byte int => 6 b64 chars + 2 chars padding */
#define HEXHASH_LEN	(2*MD5_DIGEST_LENGTH)
  char response[RESPONSE_LEN];
  char challenge2[CHALLENGE2_LEN];
  char salted2[SALTED2_LEN];
  AVal pubToken;

  if (strstr(description->av_val, av_authmod_adobe.av_val) != NULL)
    {
      if(strstr(description->av_val, "code=403 need auth") != NULL)
        {
            if (strstr(r->Link.app.av_val, av_authmod_adobe.av_val) != NULL) {
              RTMP_Log(RTMP_LOGERROR, "%s, wrong pubUser & pubPasswd for publisher auth", __FUNCTION__);
              return 0;
            } else if(r->Link.pubUser.av_len && r->Link.pubPasswd.av_len) {
              pubToken.av_val = malloc(r->Link.pubUser.av_len + av_authmod_adobe.av_len + 8);
              pubToken.av_len = sprintf(pubToken.av_val, "?%s&user=%s",
                      av_authmod_adobe.av_val,
                      r->Link.pubUser.av_val);
              RTMP_Log(RTMP_LOGDEBUG, "%s, pubToken1: %s", __FUNCTION__, pubToken.av_val);
            } else {
              RTMP_Log(RTMP_LOGERROR, "%s, need to set pubUser & pubPasswd for publisher auth", __FUNCTION__);
              return 0;
            }
        }
      else if((token_in = strstr(description->av_val, "?reason=needauth")) != NULL)
        {
          char *par, *val = NULL, *orig_ptr;
	  AVal user, salt, opaque, challenge, *aptr = NULL;
	  opaque.av_len = 0;
	  challenge.av_len = 0;

          ptr = orig_ptr = strdup(token_in);
          while (ptr)
            {
              par = ptr;
              ptr = strchr(par, '&');
              if(ptr)
                  *ptr++ = '\0';

              val =  strchr(par, '=');
              if(val)
                  *val++ = '\0';

	      if (aptr) {
		aptr->av_len = par - aptr->av_val - 1;
		aptr = NULL;
	      }
              if (strcmp(par, "user") == 0){
                  user.av_val = val;
		  aptr = &user;
              } else if (strcmp(par, "salt") == 0){
                  salt.av_val = val;
		  aptr = &salt;
              } else if (strcmp(par, "opaque") == 0){
                  opaque.av_val = val;
		  aptr = &opaque;
              } else if (strcmp(par, "challenge") == 0){
                  challenge.av_val = val;
		  aptr = &challenge;
              }

              RTMP_Log(RTMP_LOGDEBUG, "%s, par:\"%s\" = val:\"%s\"", __FUNCTION__, par, val);
            }
	  if (aptr)
	    aptr->av_len = strlen(aptr->av_val);

	  /* hash1 = base64enc(md5(user + _aodbeAuthSalt + password)) */
	  MD5_Init(&md5ctx);
	  MD5_Update(&md5ctx, user.av_val, user.av_len);
	  MD5_Update(&md5ctx, salt.av_val, salt.av_len);
	  MD5_Update(&md5ctx, r->Link.pubPasswd.av_val, r->Link.pubPasswd.av_len);
	  MD5_Final(md5sum_val, &md5ctx);
          RTMP_Log(RTMP_LOGDEBUG, "%s, md5(%s%s%s) =>", __FUNCTION__,
	    user.av_val, salt.av_val, r->Link.pubPasswd.av_val);
          RTMP_LogHexString(RTMP_LOGDEBUG, md5sum_val, MD5_DIGEST_LENGTH);

          b64enc(md5sum_val, MD5_DIGEST_LENGTH, salted2, SALTED2_LEN);
          RTMP_Log(RTMP_LOGDEBUG, "%s, b64(md5_1) = %s", __FUNCTION__, salted2);

            challenge2_data = rand();

            b64enc((unsigned char *) &challenge2_data, sizeof(int), challenge2, CHALLENGE2_LEN);
            RTMP_Log(RTMP_LOGDEBUG, "%s, b64(%d) = %s", __FUNCTION__, challenge2_data, challenge2);

	  MD5_Init(&md5ctx);
	  MD5_Update(&md5ctx, salted2, B64DIGEST_LEN);
            /* response = base64enc(md5(hash1 + opaque + challenge2)) */
	  if (opaque.av_len)
	    MD5_Update(&md5ctx, opaque.av_val, opaque.av_len);
	  else if (challenge.av_len)
	    MD5_Update(&md5ctx, challenge.av_val, challenge.av_len);
	  MD5_Update(&md5ctx, challenge2, B64INT_LEN);
	  MD5_Final(md5sum_val, &md5ctx);

          RTMP_Log(RTMP_LOGDEBUG, "%s, md5(%s%s%s) =>", __FUNCTION__,
	    salted2, opaque.av_len ? opaque.av_val : "", challenge2);
          RTMP_LogHexString(RTMP_LOGDEBUG, md5sum_val, MD5_DIGEST_LENGTH);

          b64enc(md5sum_val, MD5_DIGEST_LENGTH, response, RESPONSE_LEN);
          RTMP_Log(RTMP_LOGDEBUG, "%s, b64(md5_2) = %s", __FUNCTION__, response);

            /* have all hashes, create auth token for the end of app */
            pubToken.av_val = malloc(32 + B64INT_LEN + B64DIGEST_LEN + opaque.av_len);
            pubToken.av_len = sprintf(pubToken.av_val,
                    "&challenge=%s&response=%s&opaque=%s",
                    challenge2,
                    response,
                    opaque.av_len ? opaque.av_val : "");
            RTMP_Log(RTMP_LOGDEBUG, "%s, pubToken2: %s", __FUNCTION__, pubToken.av_val);
            free(orig_ptr);
        }
      else if(strstr(description->av_val, "?reason=authfailed") != NULL)
        {
          RTMP_Log(RTMP_LOGERROR, "%s, Authentication failed: wrong password", __FUNCTION__);
          return 0;
        }
      else if(strstr(description->av_val, "?reason=nosuchuser") != NULL)
        {
          RTMP_Log(RTMP_LOGERROR, "%s, Authentication failed: no such user", __FUNCTION__);
          return 0;
        }
      else
        {
          RTMP_Log(RTMP_LOGERROR, "%s, Authentication failed: unknown auth mode: %s",
                  __FUNCTION__, description->av_val);
          return 0;
        }

      ptr = malloc(r->Link.app.av_len + pubToken.av_len);
      strncpy(ptr, r->Link.app.av_val, r->Link.app.av_len);
      strncpy(ptr + r->Link.app.av_len, pubToken.av_val, pubToken.av_len);
      r->Link.app.av_len += pubToken.av_len;
      if(r->Link.lFlags & RTMP_LF_FAPU)
          free(r->Link.app.av_val);
      r->Link.app.av_val = ptr;

      ptr = malloc(r->Link.tcUrl.av_len + pubToken.av_len);
      strncpy(ptr, r->Link.tcUrl.av_val, r->Link.tcUrl.av_len);
      strncpy(ptr + r->Link.tcUrl.av_len, pubToken.av_val, pubToken.av_len);
      r->Link.tcUrl.av_len += pubToken.av_len;
      if(r->Link.lFlags & RTMP_LF_FTCU)
          free(r->Link.tcUrl.av_val);
      r->Link.tcUrl.av_val = ptr;

      free(pubToken.av_val);
      r->Link.lFlags |= RTMP_LF_FTCU | RTMP_LF_FAPU;

      RTMP_Log(RTMP_LOGDEBUG, "%s, new app: %.*s tcUrl: %.*s playpath: %s", __FUNCTION__,
              r->Link.app.av_len, r->Link.app.av_val,
              r->Link.tcUrl.av_len, r->Link.tcUrl.av_val,
              r->Link.playpath.av_val);
    }
  else if (strstr(description->av_val, av_authmod_llnw.av_val) != NULL)
    {
      if(strstr(description->av_val, "code=403 need auth") != NULL)
        {
            /* This part seems to be the same for llnw and adobe */

            if (strstr(r->Link.app.av_val, av_authmod_llnw.av_val) != NULL) {
              RTMP_Log(RTMP_LOGERROR, "%s, wrong pubUser & pubPasswd for publisher auth", __FUNCTION__);
              return 0;
            } else if(r->Link.pubUser.av_len && r->Link.pubPasswd.av_len) {
              pubToken.av_val = malloc(r->Link.pubUser.av_len + av_authmod_llnw.av_len + 8);
              pubToken.av_len = sprintf(pubToken.av_val, "?%s&user=%s",
                      av_authmod_llnw.av_val,
                      r->Link.pubUser.av_val);
              RTMP_Log(RTMP_LOGDEBUG, "%s, pubToken1: %s", __FUNCTION__, pubToken.av_val);
            } else {
              RTMP_Log(RTMP_LOGERROR, "%s, need to set pubUser & pubPasswd for publisher auth", __FUNCTION__);
              return 0;
            }
        }
      else if((token_in = strstr(description->av_val, "?reason=needauth")) != NULL)
        {
          char *orig_ptr;
          char *par, *val = NULL;
	  char hash1[HEXHASH_LEN+1], hash2[HEXHASH_LEN+1], hash3[HEXHASH_LEN+1];
	  AVal user, nonce, *aptr = NULL;
	  AVal apptmp;

          /* llnw auth method
           * Seems to be closely based on HTTP Digest Auth:
           *    http://tools.ietf.org/html/rfc2617
           *    http://en.wikipedia.org/wiki/Digest_access_authentication
           */

          const char authmod[] = "llnw";
          const char realm[] = "live";
          const char method[] = "publish";
          const char qop[] = "auth";
          /* nc = 1..connection count (or rather, number of times cnonce has been reused) */
          int nc = 1;
          /* nchex = hexenc(nc) (8 hex digits according to RFC 2617) */
          char nchex[9];
          /* cnonce = hexenc(4 random bytes) (initialized on first connection) */
          char cnonce[9];

          ptr = orig_ptr = strdup(token_in);
          /* Extract parameters (we need user and nonce) */
          while (ptr)
            {
              par = ptr;
              ptr = strchr(par, '&');
              if(ptr)
                  *ptr++ = '\0';

              val =  strchr(par, '=');
              if(val)
                  *val++ = '\0';

	      if (aptr) {
		aptr->av_len = par - aptr->av_val - 1;
		aptr = NULL;
	      }
              if (strcmp(par, "user") == 0){
                user.av_val = val;
		aptr = &user;
              } else if (strcmp(par, "nonce") == 0){
                nonce.av_val = val;
		aptr = &nonce;
              }

              RTMP_Log(RTMP_LOGDEBUG, "%s, par:\"%s\" = val:\"%s\"", __FUNCTION__, par, val);
            }
	  if (aptr)
	    aptr->av_len = strlen(aptr->av_val);

          /* FIXME: handle case where user==NULL or nonce==NULL */

          sprintf(nchex, "%08x", nc);
          sprintf(cnonce, "%08x", rand());

          /* hash1 = hexenc(md5(user + ":" + realm + ":" + password)) */
	  MD5_Init(&md5ctx);
	  MD5_Update(&md5ctx, user.av_val, user.av_len);
	  MD5_Update(&md5ctx, ":", 1);
	  MD5_Update(&md5ctx, realm, sizeof(realm)-1);
	  MD5_Update(&md5ctx, ":", 1);
	  MD5_Update(&md5ctx, r->Link.pubPasswd.av_val, r->Link.pubPasswd.av_len);
	  MD5_Final(md5sum_val, &md5ctx);
          RTMP_Log(RTMP_LOGDEBUG, "%s, md5(%s:%s:%s) =>", __FUNCTION__,
	    user.av_val, realm, r->Link.pubPasswd.av_val);
          RTMP_LogHexString(RTMP_LOGDEBUG, md5sum_val, MD5_DIGEST_LENGTH);
          hexenc(md5sum_val, MD5_DIGEST_LENGTH, hash1);

          /* hash2 = hexenc(md5(method + ":/" + app + "/" + appInstance)) */
          /* Extract appname + appinstance without query parameters */
	  apptmp = r->Link.app;
	  ptr = AValChr(&apptmp, '?');
	  if (ptr)
	    apptmp.av_len = ptr - apptmp.av_val;

	  MD5_Init(&md5ctx);
	  MD5_Update(&md5ctx, method, sizeof(method)-1);
	  MD5_Update(&md5ctx, ":/", 2);
	  MD5_Update(&md5ctx, apptmp.av_val, apptmp.av_len);
	  if (!AValChr(&apptmp, '/'))
	    MD5_Update(&md5ctx, "/_definst_", sizeof("/_definst_") - 1);
	  MD5_Final(md5sum_val, &md5ctx);
          RTMP_Log(RTMP_LOGDEBUG, "%s, md5(%s:/%.*s) =>", __FUNCTION__,
	    method, apptmp.av_len, apptmp.av_val);
          RTMP_LogHexString(RTMP_LOGDEBUG, md5sum_val, MD5_DIGEST_LENGTH);
          hexenc(md5sum_val, MD5_DIGEST_LENGTH, hash2);

          /* hash3 = hexenc(md5(hash1 + ":" + nonce + ":" + nchex + ":" + cnonce + ":" + qop + ":" + hash2)) */
	  MD5_Init(&md5ctx);
	  MD5_Update(&md5ctx, hash1, HEXHASH_LEN);
	  MD5_Update(&md5ctx, ":", 1);
	  MD5_Update(&md5ctx, nonce.av_val, nonce.av_len);
	  MD5_Update(&md5ctx, ":", 1);
	  MD5_Update(&md5ctx, nchex, sizeof(nchex)-1);
	  MD5_Update(&md5ctx, ":", 1);
	  MD5_Update(&md5ctx, cnonce, sizeof(cnonce)-1);
	  MD5_Update(&md5ctx, ":", 1);
	  MD5_Update(&md5ctx, qop, sizeof(qop)-1);
	  MD5_Update(&md5ctx, ":", 1);
	  MD5_Update(&md5ctx, hash2, HEXHASH_LEN);
	  MD5_Final(md5sum_val, &md5ctx);
          RTMP_Log(RTMP_LOGDEBUG, "%s, md5(%s:%s:%s:%s:%s:%s) =>", __FUNCTION__,
	    hash1, nonce.av_val, nchex, cnonce, qop, hash2);
          RTMP_LogHexString(RTMP_LOGDEBUG, md5sum_val, MD5_DIGEST_LENGTH);
          hexenc(md5sum_val, MD5_DIGEST_LENGTH, hash3);

          /* pubToken = &authmod=<authmod>&user=<username>&nonce=<nonce>&cnonce=<cnonce>&nc=<nchex>&response=<hash3> */
          /* Append nonces and response to query string which already contains
           * user + authmod */
          pubToken.av_val = malloc(64 + sizeof(authmod)-1 + user.av_len + nonce.av_len + sizeof(cnonce)-1 + sizeof(nchex)-1 + HEXHASH_LEN);
          sprintf(pubToken.av_val,
                  "&nonce=%s&cnonce=%s&nc=%s&response=%s",
                  nonce.av_val, cnonce, nchex, hash3);
          pubToken.av_len = strlen(pubToken.av_val);
          RTMP_Log(RTMP_LOGDEBUG, "%s, pubToken2: %s", __FUNCTION__, pubToken.av_val);

          free(orig_ptr);
        }
      else if(strstr(description->av_val, "?reason=authfail") != NULL)
        {
          RTMP_Log(RTMP_LOGERROR, "%s, Authentication failed", __FUNCTION__);
          return 0;
        }
      else if(strstr(description->av_val, "?reason=nosuchuser") != NULL)
        {
          RTMP_Log(RTMP_LOGERROR, "%s, Authentication failed: no such user", __FUNCTION__);
          return 0;
        }
      else
        {
          RTMP_Log(RTMP_LOGERROR, "%s, Authentication failed: unknown auth mode: %s",
                  __FUNCTION__, description->av_val);
          return 0;
        }

      ptr = malloc(r->Link.app.av_len + pubToken.av_len);
      strncpy(ptr, r->Link.app.av_val, r->Link.app.av_len);
      strncpy(ptr + r->Link.app.av_len, pubToken.av_val, pubToken.av_len);
      r->Link.app.av_len += pubToken.av_len;
      if(r->Link.lFlags & RTMP_LF_FAPU)
          free(r->Link.app.av_val);
      r->Link.app.av_val = ptr;

      ptr = malloc(r->Link.tcUrl.av_len + pubToken.av_len);
      strncpy(ptr, r->Link.tcUrl.av_val, r->Link.tcUrl.av_len);
      strncpy(ptr + r->Link.tcUrl.av_len, pubToken.av_val, pubToken.av_len);
      r->Link.tcUrl.av_len += pubToken.av_len;
      if(r->Link.lFlags & RTMP_LF_FTCU)
          free(r->Link.tcUrl.av_val);
      r->Link.tcUrl.av_val = ptr;

      free(pubToken.av_val);
      r->Link.lFlags |= RTMP_LF_FTCU | RTMP_LF_FAPU;

      RTMP_Log(RTMP_LOGDEBUG, "%s, new app: %.*s tcUrl: %.*s playpath: %s", __FUNCTION__,
              r->Link.app.av_len, r->Link.app.av_val,
              r->Link.tcUrl.av_len, r->Link.tcUrl.av_val,
              r->Link.playpath.av_val);
    }
  else
    {
      return 0;
    }
  return 1;
}
#endif
static void AVreplace(AVal *src, const AVal *orig, const AVal *repl)
{
  char *srcbeg = src->av_val;
  char *srcend = src->av_val + src->av_len;
  char *dest, *sptr, *dptr;
  int n = 0;

  /* count occurrences of orig in src */
  sptr = src->av_val;
  while (sptr < srcend && (sptr = strstr(sptr, orig->av_val)))
  {
    n++;
    sptr += orig->av_len;
  }
  if (!n)
    return;

  dest = (char*)malloc(src->av_len + 1 + (repl->av_len - orig->av_len) * n);

  sptr = src->av_val;
  dptr = dest;
  while (sptr < srcend && (sptr = strstr(sptr, orig->av_val)))
  {
    n = sptr - srcbeg;
    memcpy(dptr, srcbeg, n);
    dptr += n;
    memcpy(dptr, repl->av_val, repl->av_len);
    dptr += repl->av_len;
    sptr += orig->av_len;
    srcbeg = sptr;
  }
  n = srcend - srcbeg;
  memcpy(dptr, srcbeg, n);
  dptr += n;
  *dptr = '\0';
  src->av_val = dest;
  src->av_len = dptr - dest;
}
static int SendConnectResult(RTMP *r, double txn)
{
  RTMPPacket packet;
  char pbuf[384], *pend = pbuf+sizeof(pbuf);
  AMFObject obj;
  AMFObjectProperty p, op;
  AVal av;

  packet.m_nChannel = 0x03;     // control channel (invoke)
  packet.m_headerType = 1; /* RTMP_PACKET_SIZE_MEDIUM; */
  packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
  packet.m_nTimeStamp = 0;
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  char *enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av__result);
  enc = AMF_EncodeNumber(enc, pend, txn);
  *enc++ = AMF_OBJECT;

  STR2AVAL(av, "FMS/3,5,1,525");
  enc = AMF_EncodeNamedString(enc, pend, &av_fmsVer, &av);
  enc = AMF_EncodeNamedNumber(enc, pend, &av_capabilities, 31.0);
  enc = AMF_EncodeNamedNumber(enc, pend, &av_mode, 1.0);
  *enc++ = 0;
  *enc++ = 0;
  *enc++ = AMF_OBJECT_END;

  *enc++ = AMF_OBJECT;

  STR2AVAL(av, "status");
  enc = AMF_EncodeNamedString(enc, pend, &av_level, &av);
  STR2AVAL(av, "NetConnection.Connect.Success");
  enc = AMF_EncodeNamedString(enc, pend, &av_code, &av);
  STR2AVAL(av, "Connection succeeded.");
  enc = AMF_EncodeNamedString(enc, pend, &av_description, &av);
  enc = AMF_EncodeNamedNumber(enc, pend, &av_objectEncoding, r->m_fEncoding);
#if 0
  STR2AVAL(av, "58656322c972d6cdf2d776167575045f8484ea888e31c086f7b5ffbd0baec55ce442c2fb");
  enc = AMF_EncodeNamedString(enc, pend, &av_secureToken, &av);
#endif
  STR2AVAL(p.p_name, "version");
  STR2AVAL(p.p_vu.p_aval, "3,5,1,525");
  p.p_type = AMF_STRING;
  obj.o_num = 1;
  obj.o_props = &p;
  op.p_type = AMF_OBJECT;
  STR2AVAL(op.p_name, "data");
  op.p_vu.p_object = obj;
  enc = AMFProp_Encode(&op, enc, pend);
  *enc++ = 0;
  *enc++ = 0;
  *enc++ = AMF_OBJECT_END;

  packet.m_nBodySize = enc - packet.m_body;

  return RTMP_SendPacket(r, &packet, false);
}

static int SendResultNumber(RTMP *r, double txn, double ID)
{
  RTMPPacket packet;
  char pbuf[256], *pend = pbuf+sizeof(pbuf);

  packet.m_nChannel = 0x03;     // control channel (invoke)
  packet.m_headerType = RTMP_PACKET_SIZE_MEDIUM;
  packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
  packet.m_nTimeStamp = 0;
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  char *enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av__result);
  enc = AMF_EncodeNumber(enc, pend, txn);//transaction_id
  *enc++ = AMF_NULL;//args
  enc = AMF_EncodeNumber(enc, pend, ID);//data

  packet.m_nBodySize = enc - packet.m_body;

  return RTMP_SendPacket(r, &packet, false);
}

/* Returns 0 for OK/Failed/error, 1 for 'Stop or Complete' */
static int
HandleInvoke(RTMP *r, bool bServer, RTMPPacket *packet, unsigned offset)
{
  AMFObject obj;
  AVal method;
  double txn;
  int ret = 0, nRes;
  const char * body = packet->m_body + offset;
  unsigned int nBodySize = packet->m_nBodySize - offset;
  if (body[0] != 0x02)		/* make sure it is a string method name we start with */
  {
    RTMP_Log(RTMP_LOGWARNING, "%s, Sanity failed. no string method in invoke packet",
      __FUNCTION__);
    return 0;
  }

  nRes = AMF_Decode(&obj, body, nBodySize, FALSE);
  if (nRes < 0)
  {
    RTMP_Log(RTMP_LOGERROR, "%s, error decoding invoke packet", __FUNCTION__);
    return 0;
  }

  AMF_Dump(&obj);
  AMFProp_GetString(AMF_GetProp(&obj, NULL, 0), &method);
  txn = AMFProp_GetNumber(AMF_GetProp(&obj, NULL, 1));
  RTMP_Log(RTMP_LOGDEBUG, "%s, %s invoking <%s>", __FUNCTION__, bServer ? "server":"client", method.av_val);

  /* server invoking */
  if (AVMATCH(&method, &av_connect))
  {
    AMFObject cobj;
    AVal pname, pval;
    int i;

    r->Link.tcUrl.av_val = packet->m_body;
    r->Link.tcUrl.av_len = packet->m_nBodySize;
    packet->m_body = NULL;

    AMFProp_GetObject(AMF_GetProp(&obj, NULL, 2), &cobj);
    for (i=0; i<cobj.o_num; i++)
    {
      pname = cobj.o_props[i].p_name;
      pval.av_val = NULL;
      pval.av_len = 0;
      if (cobj.o_props[i].p_type == AMF_STRING)
        pval = cobj.o_props[i].p_vu.p_aval;
      if (AVMATCH(&pname, &av_app))
      {
        r->Link.app = pval;
        pval.av_val = NULL;
        if (!r->Link.app.av_val)
          r->Link.app.av_val = (char*)"";
      }
      else if (AVMATCH(&pname, &av_flashVer))
      {
        r->Link.flashVer = pval;
        pval.av_val = NULL;
      }
      else if (AVMATCH(&pname, &av_swfUrl))
      {
        r->Link.swfUrl = pval;
        pval.av_val = NULL;
      }
      else if (AVMATCH(&pname, &av_tcUrl))
      {
        r->Link.tcUrl = pval;
        pval.av_val = NULL;
      }
      else if (AVMATCH(&pname, &av_pageUrl))
      {
        r->Link.pageUrl = pval;
        pval.av_val = NULL;
      }
      else if (AVMATCH(&pname, &av_audioCodecs))
      {
        r->m_fAudioCodecs = cobj.o_props[i].p_vu.p_number;
      }
      else if (AVMATCH(&pname, &av_videoCodecs))
      {
        r->m_fVideoCodecs = cobj.o_props[i].p_vu.p_number;
      }
      else if (AVMATCH(&pname, &av_objectEncoding))
      {
        r->m_fEncoding = cobj.o_props[i].p_vu.p_number;
      }
    }
    /* Still have more parameters? Copy them */
    if (obj.o_num > 3)
    {
      int i = obj.o_num - 3;
      r->Link.extras.o_num = i;
      r->Link.extras.o_props = (AMFObjectProperty*)malloc(i*sizeof(AMFObjectProperty));
      memcpy(r->Link.extras.o_props, obj.o_props+3, i*sizeof(AMFObjectProperty));
      obj.o_num = 3;
    }
    SendConnectResult(r, txn);
  }
  else if (AVMATCH(&method, &av_createStream))
  {
    SendResultNumber(r, txn, RTMP_streamNextId++);
  }
  else if (AVMATCH(&method, &av_releaseStream))
  {//TODO
  }
  else if (AVMATCH(&method, &av_getStreamLength))
  {
    SendResultNumber(r, txn, 10.0);
  }
  else if (AVMATCH(&method, &av_NetStream_Authenticate_UsherToken))
  {
    AVal usherToken;
    AMFProp_GetString(AMF_GetProp(&obj, NULL, 3), &usherToken);
    AVreplace(&usherToken, &av_dquote, &av_escdquote);
    r->Link.usherToken = usherToken;
  }
  else if (AVMATCH(&method, &av_FCPublish))
  {//TODO
  }
  else if (AVMATCH(&method, &av_publish))
  {
    AVal live={0};
    AMFProp_GetString(AMF_GetProp(&obj, NULL, 3), &r->Link.playpath);
    if (obj.o_num > 4)
      AMFProp_GetString(AMF_GetProp(&obj, NULL, 4), &live);
    if (AVMATCH(&live, &av_live))
      r->Link.lFlags |= RTMP_LF_LIVE;
    r->m_stream_id = packet->m_nInfoField2;
    SendPublishStart(r);
    r->m_state |= RTMP_STATE_PUSHING;
  }
  else if (AVMATCH(&method, &av_play))
  {
    AMFProp_GetString(AMF_GetProp(&obj, NULL, 3), &r->Link.playpath);
    if (obj.o_num > 4){
      r->Link.seekTime = (int)AMFProp_GetNumber(AMF_GetProp(&obj, NULL, 4));
      if (obj.o_num > 5)
        r->Link.stopTime = r->Link.seekTime + (int)AMFProp_GetNumber(AMF_GetProp(&obj, NULL, 5));
    }
    r->m_stream_id = packet->m_nInfoField2;
    RTMP_SendCtrl(r, RTMP_CTRL_STREAM_BEGIN, r->m_stream_id, 0);
    SendPlayReset(r);
    SendPlayStart(r);
    SendDataStart(r);
    r->m_state |= RTMP_STATE_PLAYING;
  }
  else if (AVMATCH(&method, &av_deleteStream)
    || AVMATCH(&method, &av_FCUnpublish))
  {
    RTMP_Close(r);
  }
  /* client invoking */
  else if (AVMATCH(&method, &av__result))
  {
    AVal methodInvoked = {0};
    int i;

    for (i=0; i<r->m_numCalls; i++) {
      if (r->m_methodCalls[i].num == (int)txn) {
        methodInvoked = r->m_methodCalls[i].name;
        AV_erase(r->m_methodCalls, &r->m_numCalls, i, FALSE);
        break;
      }
    }
    if (!methodInvoked.av_val) {
      RTMP_Log(RTMP_LOGDEBUG, "%s, received result id %f without matching request",
        __FUNCTION__, txn);
      goto leave;
    }

    RTMP_Log(RTMP_LOGDEBUG, "%s, received result for method call <%s>", __FUNCTION__,
      methodInvoked.av_val);

    if (AVMATCH(&methodInvoked, &av_connect))
    {
      if (r->Link.token.av_len)
      {
        AMFObjectProperty p;
        if (RTMP_FindFirstMatchingProperty(&obj, &av_secureToken, &p))
        {
          DecodeTEA(&r->Link.token, &p.p_vu.p_aval);
          SendSecureTokenResponse(r, &p.p_vu.p_aval);
        }
      }
      if (r->Link.protocol & RTMP_FEATURE_WRITE)
      {
        SendReleaseStream(r);
        SendFCPublish(r);
      }
      else
      {
        RTMP_SendServerBW(r);
        RTMP_SendCtrl(r, RTMP_CTRL_SET_BUFFER_MS, 0, 300);
      }
      RTMP_SendCreateStream(r);

      if (!(r->Link.protocol & RTMP_FEATURE_WRITE))
      {
        /* Authenticate on Justin.tv legacy servers before sending FCSubscribe */
        if (r->Link.usherToken.av_len)
          SendUsherToken(r, &r->Link.usherToken);
        /* Send the FCSubscribe if live stream or if subscribepath is set */
        if (r->Link.subscribepath.av_len)
          SendFCSubscribe(r, &r->Link.subscribepath);
        else if (r->Link.lFlags & RTMP_LF_LIVE)
          SendFCSubscribe(r, &r->Link.playpath);
      }
    }
    else if (AVMATCH(&methodInvoked, &av_createStream))
    {
      r->m_stream_id = (int)AMFProp_GetNumber(AMF_GetProp(&obj, NULL, 3));

      if (r->Link.protocol & RTMP_FEATURE_WRITE)
      {
        SendPublish(r);
      }
      else
      {
        if (r->Link.lFlags & RTMP_LF_PLST)
          SendPlaylist(r);
        SendPlay(r);
        RTMP_SendCtrl(r, RTMP_CTRL_SET_BUFFER_MS, r->m_stream_id, r->m_nBufferMS);
      }
    }
    else if (AVMATCH(&methodInvoked, &av_play))
    {
      r->m_state |= RTMP_STATE_PLAYING;
    }
    else if (AVMATCH(&methodInvoked, &av_publish))
    {
      r->m_state |= RTMP_STATE_PUSHING;
    }
    free(methodInvoked.av_val);
  }
  else if (AVMATCH(&method, &av_onBWDone))
  {
    if (!r->m_nBWCheckCounter)
      SendCheckBW(r);
  }
  else if (AVMATCH(&method, &av_onFCSubscribe))
  {
    /* SendOnFCSubscribe(); */
  }
  else if (AVMATCH(&method, &av_onFCUnsubscribe))
  {
    RTMP_Close(r);
    ret = 1;
  }
  else if (AVMATCH(&method, &av_ping))
  {
    SendPong(r, txn);
  }
  else if (AVMATCH(&method, &av__onbwcheck))
  {
    SendCheckBWResult(r, txn);
  }
  else if (AVMATCH(&method, &av__onbwdone))
  {
    int i;
    for (i = 0; i < r->m_numCalls; i++)
      if (AVMATCH(&r->m_methodCalls[i].name, &av__checkbw))
      {
        AV_erase(r->m_methodCalls, &r->m_numCalls, i, TRUE);
        break;
      }
  }
  else if (AVMATCH(&method, &av__error))
  {
    AVal methodInvoked = {0};
    int i;

    if (r->Link.protocol & RTMP_FEATURE_WRITE)
    {
      for (i=0; i<r->m_numCalls; i++)
      {
        if (r->m_methodCalls[i].num == txn)
        {
          methodInvoked = r->m_methodCalls[i].name;
          AV_erase(r->m_methodCalls, &r->m_numCalls, i, FALSE);
          break;
        }
      }
      if (!methodInvoked.av_val)
      {
        RTMP_Log(RTMP_LOGDEBUG, "%s, received result id %f without matching request",
          __FUNCTION__, txn);
        goto leave;
      }

      RTMP_Log(RTMP_LOGDEBUG, "%s, received error for method call <%s>", __FUNCTION__,
        methodInvoked.av_val);

      if (AVMATCH(&methodInvoked, &av_connect))
      {
        AMFObject obj2;
        AVal code, level, description;
        AMFProp_GetObject(AMF_GetProp(&obj, NULL, 3), &obj2);
        AMFProp_GetString(AMF_GetProp(&obj2, &av_code, -1), &code);
        AMFProp_GetString(AMF_GetProp(&obj2, &av_level, -1), &level);
        AMFProp_GetString(AMF_GetProp(&obj2, &av_description, -1), &description);
        RTMP_Log(RTMP_LOGDEBUG, "%s, error description: %s", __FUNCTION__, description.av_val);
        if (AVMATCH(&code, &av_NetConnection_Connect_Rejected)) {
          AMFObject ex_obj, obj3;
          int ex_code;
          AMFProp_GetObject(AMF_GetProp(&obj2, &av_ex, -1), &ex_obj);
          AMFProp_GetObject(AMF_GetProp(&ex_obj, NULL, 1), &obj3);
          ex_code = (int)AMFProp_GetNumber(AMF_GetProp(&obj3, &av_code, -1));
          if (ex_code == 302) { /* rediect */
            AVal redirect;
            AMFProp_GetString(AMF_GetProp(&obj3, &av_redirect, -1), &redirect);
            if (redirect.av_len > 0) {
              CloseInternal(r, 1);
              RTMP_SetupURL(r, redirect.av_val);
              if (!RTMP_Connect(r, NULL) || !RTMP_ConnectStream(r, 0))
                goto leave;
            }
          }
        }
#ifdef CRYPTO
        /* if PublisherAuth returns 1, then reconnect */
        if (PublisherAuth(r, &description) == 1)
        {
          CloseInternal(r, 1);
          if (!RTMP_Connect(r, NULL) || !RTMP_ConnectStream(r, 0))
            goto leave;
        }
#endif
      }
    }
    else
    {
      RTMP_Log(RTMP_LOGERROR, "rtmp server sent error");
    }
    free(methodInvoked.av_val);
  }
  else if (AVMATCH(&method, &av_close))
  {
    RTMP_Log(RTMP_LOGERROR, "rtmp server requested close");
    RTMP_Close(r);
  }
  else if (AVMATCH(&method, &av_onStatus))
  {
    AMFObject obj2;
    AVal code, level, description;
    AMFProp_GetObject(AMF_GetProp(&obj, NULL, obj.o_num-1), &obj2);
    AMFProp_GetString(AMF_GetProp(&obj2, &av_code, -1), &code);
    AMFProp_GetString(AMF_GetProp(&obj2, &av_level, -1), &level);
    AMFProp_GetString(AMF_GetProp(&obj2, &av_description, -1), &description);

    RTMP_Log(RTMP_LOGDEBUG, "%s, onStatus: %s", __FUNCTION__, code.av_val);
    if (AVMATCH(&code, &av_NetStream_Failed)
      || AVMATCH(&code, &av_NetStream_Play_Failed)
      || AVMATCH(&code, &av_NetStream_Play_StreamNotFound)
      || AVMATCH(&code, &av_NetConnection_Connect_InvalidApp)
      || AVMATCH(&code, &av_NetStream_Publish_Rejected)
      || AVMATCH(&code, &av_NetStream_Publish_Denied))
    {
      r->m_stream_id = -1;
      RTMP_Close(r);
      RTMP_Log(RTMP_LOGERROR, "Closing connection: %s", code.av_val);
    }

    else if (AVMATCH(&code, &av_NetStream_Play_Start)
      || AVMATCH(&code, &av_NetStream_Play_PublishNotify))
    {
      int i;
      r->m_state |= RTMP_STATE_PLAYING;
      for (i = 0; i < r->m_numCalls; i++)
      {
        if (AVMATCH(&r->m_methodCalls[i].name, &av_play))
        {
          AV_erase(r->m_methodCalls, &r->m_numCalls, i, TRUE);
          break;
        }
      }
    }

    else if (AVMATCH(&code, &av_NetStream_Publish_Start))
    {
      int i;
      r->m_state |= RTMP_STATE_PUSHING;
      for (i = 0; i < r->m_numCalls; i++)
      {
        if (AVMATCH(&r->m_methodCalls[i].name, &av_publish))
        {
          AV_erase(r->m_methodCalls, &r->m_numCalls, i, TRUE);
          break;
        }
      }
    }

    /* Return 1 if this is a Play.Complete or Play.Stop */
    else if (AVMATCH(&code, &av_NetStream_Play_Complete)
      || AVMATCH(&code, &av_NetStream_Play_Stop)
      || AVMATCH(&code, &av_NetStream_Play_UnpublishNotify))
    {
      RTMP_Close(r);
      ret = 1;
    }

    else if (AVMATCH(&code, &av_NetStream_Seek_Notify))
    {
      r->m_read.flags &= ~RTMP_READ_SEEKING;
    }

    else if (AVMATCH(&code, &av_NetStream_Pause_Notify))
    {
      if (r->m_pausing == 1 || r->m_pausing == 2)
      {
        RTMP_SendPause(r, FALSE, r->m_pauseStamp);
        r->m_pausing = 3;
      }
    }
  }
  else if (AVMATCH(&method, &av_playlist_ready))
  {
    int i;
    for (i = 0; i < r->m_numCalls; i++)
    {
      if (AVMATCH(&r->m_methodCalls[i].name, &av_set_playlist))
      {
        AV_erase(r->m_methodCalls, &r->m_numCalls, i, TRUE);
        break;
      }
    }
  }
  else
  {
    RTMP_Log(RTMP_LOGWARNING, "unknown invoking <%s>", method.av_val);
  }
leave:
  AMF_Reset(&obj);
  return ret;
}

int
RTMP_FindFirstMatchingProperty(AMFObject *obj, const AVal *name,
			       AMFObjectProperty * p)
{
  int n;
  /* this is a small object search to locate the "duration" property */
  for (n = 0; n < obj->o_num; n++)
    {
      AMFObjectProperty *prop = AMF_GetProp(obj, NULL, n);

      if (AVMATCH(&prop->p_name, name))
	{
	  memcpy(p, prop, sizeof(*prop));
	  return TRUE;
	}

      if (prop->p_type == AMF_OBJECT || prop->p_type == AMF_ECMA_ARRAY)
	{
	  if (RTMP_FindFirstMatchingProperty(&prop->p_vu.p_object, name, p))
	    return TRUE;
	}
    }
  return FALSE;
}

/* Like above, but only check if name is a prefix of property */
int
RTMP_FindPrefixProperty(AMFObject *obj, const AVal *name,
			       AMFObjectProperty * p)
{
  int n;
  for (n = 0; n < obj->o_num; n++)
    {
      AMFObjectProperty *prop = AMF_GetProp(obj, NULL, n);

      if (prop->p_name.av_len > name->av_len &&
      	  !memcmp(prop->p_name.av_val, name->av_val, name->av_len))
	{
	  memcpy(p, prop, sizeof(*prop));
	  return TRUE;
	}

      if (prop->p_type == AMF_OBJECT || prop->p_type == AMF_ECMA_ARRAY)
	{
	  if (RTMP_FindPrefixProperty(&prop->p_vu.p_object, name, p))
	    return TRUE;
	}
    }
  return FALSE;
}

static int
DumpMetaData(AMFObject *obj)
{
  AMFObjectProperty *prop;
  int n, len;
  for (n = 0; n < obj->o_num; n++)
    {
      char str[256] = "";
      prop = AMF_GetProp(obj, NULL, n);
      switch (prop->p_type)
	{
	case AMF_OBJECT:
	case AMF_ECMA_ARRAY:
	case AMF_STRICT_ARRAY:
	  if (prop->p_name.av_len)
	    RTMP_Log(RTMP_LOGINFO, "%.*s:", prop->p_name.av_len, prop->p_name.av_val);
	  DumpMetaData(&prop->p_vu.p_object);
	  break;
	case AMF_NUMBER:
	  snprintf(str, 255, "%.2f", prop->p_vu.p_number);
	  break;
	case AMF_BOOLEAN:
	  snprintf(str, 255, "%s",
		   prop->p_vu.p_number != 0. ? "TRUE" : "FALSE");
	  break;
	case AMF_STRING:
	  len = snprintf(str, 255, "%.*s", prop->p_vu.p_aval.av_len,
		   prop->p_vu.p_aval.av_val);
	  if (len >= 1 && str[len-1] == '\n')
	    str[len-1] = '\0';
	  break;
	case AMF_DATE:
	  snprintf(str, 255, "timestamp:%.2f", prop->p_vu.p_number);
	  break;
	default:
	  snprintf(str, 255, "INVALID TYPE 0x%02x",
		   (unsigned char)prop->p_type);
	}
      if (str[0] && prop->p_name.av_len)
	{
	  RTMP_Log(RTMP_LOGINFO, "  %-22.*s%s", prop->p_name.av_len,
		    prop->p_name.av_val, str);
	}
    }
  return FALSE;
}

int
HandleMetadata(RTMPReader *r, char *body, unsigned int len)
{
  /* allright we get some info here, so parse it and print it */
  /* also keep duration or filesize to make a nice progress bar */

  AMFObject obj;
  AVal metastring;
  int ret = FALSE;

  int nRes = AMF_Decode(&obj, body, len, FALSE);
  if (nRes < 0)
  {
    RTMP_Log(RTMP_LOGERROR, "%s, error decoding meta data packet", __FUNCTION__);
    return FALSE;
  }

  AMF_Dump(&obj);
  AMFProp_GetString(AMF_GetProp(&obj, NULL, 0), &metastring);
  if (AVMATCH(&metastring, &av_setDataFrame))
    AMFProp_GetString(AMF_GetProp(&obj, NULL, 1), &metastring);

  if (AVMATCH(&metastring, &av_onMetaData))
  {
    AMFObjectProperty prop;
    /* Show metadata */
    RTMP_Log(RTMP_LOGINFO, "Metadata:");
    DumpMetaData(&obj);
    if (RTMP_FindFirstMatchingProperty(&obj, &av_duration, &prop))
    {
      r->duration = prop.p_vu.p_number;
      RTMP_Log(RTMP_LOGDEBUG, "Set duration: %.2f", r->duration);
    }
    /* Search for audio or video tags */
    if (RTMP_FindPrefixProperty(&obj, &av_video, &prop))
      r->dataType |= 1;
    if (RTMP_FindPrefixProperty(&obj, &av_audio, &prop))
      r->dataType |= 4;
    ret = TRUE;
  }
  AMF_Reset(&obj);
  return ret;
}

static void
HandleChangeChunkSize(RTMP *r, const RTMPPacket *packet)
{
  if (packet->m_nBodySize >= 4)
    {
      r->m_inChunkSize = AMF_DecodeInt32(packet->m_body);
      RTMP_Log(RTMP_LOGDEBUG, "%s, received: chunk size change to %d", __FUNCTION__,
	  r->m_inChunkSize);
    }
}

static void
HandleAudio(RTMP *r, const RTMPPacket *packet)
{
}

static void
HandleVideo(RTMP *r, const RTMPPacket *packet)
{
}

static void
HandleCtrl(RTMP *r, const RTMPPacket *packet)
{
  short nType = -1;
  unsigned int tmp;
  if (packet->m_body && packet->m_nBodySize >= 2)
    nType = AMF_DecodeInt16(packet->m_body);
  RTMP_Log(RTMP_LOGDEBUG, "%s, received ctrl. type: %d, len: %d", __FUNCTION__, nType,
    packet->m_nBodySize);
  /*RTMP_LogHex(packet.m_body, packet.m_nBodySize); */

  if (packet->m_nBodySize >= 6)
  {
    switch (nType)
    {
    case RTMP_CTRL_STREAM_BEGIN:
      tmp = AMF_DecodeInt32(packet->m_body + 2);
      RTMP_Log(RTMP_LOGDEBUG, "%s, Stream Begin %d", __FUNCTION__, tmp);
      break;

    case RTMP_CTRL_STREAM_EOF:
      tmp = AMF_DecodeInt32(packet->m_body + 2);
      RTMP_Log(RTMP_LOGDEBUG, "%s, Stream EOF %d", __FUNCTION__, tmp);
      if (r->m_pausing == 1)
        r->m_pausing = 2;
      break;

    case RTMP_CTRL_STREAM_DRY:
      tmp = AMF_DecodeInt32(packet->m_body + 2);
      RTMP_Log(RTMP_LOGDEBUG, "%s, Stream Dry %d", __FUNCTION__, tmp);
      break;

    case RTMP_CTRL_STREAM_IS_RECORDED:
      tmp = AMF_DecodeInt32(packet->m_body + 2);
      RTMP_Log(RTMP_LOGDEBUG, "%s, Stream IsRecorded %d", __FUNCTION__, tmp);
      break;

    case RTMP_CTRL_PING:		/* server ping. reply with pong. */
      tmp = AMF_DecodeInt32(packet->m_body + 2);
      RTMP_Log(RTMP_LOGDEBUG, "%s, Ping %d", __FUNCTION__, tmp);
      RTMP_SendCtrl(r, RTMP_CTRL_PONG, tmp, 0);
      break;

      /* FMS 3.5 servers send the following two controls to let the client
       * know when the server has sent a complete buffer. I.e., when the
       * server has sent an amount of data equal to m_nBufferMS in duration.
       * The server meters its output so that data arrives at the client
       * in realtime and no faster.
       *
       * The rtmpdump program tries to set m_nBufferMS as large as
       * possible, to force the server to send data as fast as possible.
       * In practice, the server appears to cap this at about 1 hour's
       * worth of data. After the server has sent a complete buffer, and
       * sends this BufferEmpty message, it will wait until the play
       * duration of that buffer has passed before sending a new buffer.
       * The BufferReady message will be sent when the new buffer starts.
       * (There is no BufferReady message for the very first buffer;
       * presumably the Stream Begin message is sufficient for that
       * purpose.)
       *
       * If the network speed is much faster than the data bitrate, then
       * there may be long delays between the end of one buffer and the
       * start of the next.
       *
       * Since usually the network allows data to be sent at
       * faster than realtime, and rtmpdump wants to download the data
       * as fast as possible, we use this RTMP_LF_BUFX hack: when we
       * get the BufferEmpty message, we send a Pause followed by an
       * Unpause. This causes the server to send the next buffer immediately
       * instead of waiting for the full duration to elapse. (That's
       * also the purpose of the ToggleStream function, which rtmpdump
       * calls if we get a read timeout.)
       *
       * Media player apps don't need this hack since they are just
       * going to play the data in realtime anyway. It also doesn't work
       * for live streams since they obviously can only be sent in
       * realtime. And it's all moot if the network speed is actually
       * slower than the media bitrate.
       */
    case 31:
      tmp = AMF_DecodeInt32(packet->m_body + 2);
      RTMP_Log(RTMP_LOGDEBUG, "%s, Stream BufferEmpty %d", __FUNCTION__, tmp);
      if (!(r->Link.lFlags & RTMP_LF_BUFX))
        break;
      if (!r->m_pausing)
      {
        r->m_pauseStamp = r->m_mediaChannel < r->m_channelsAllocatedIn ?
          r->m_channelTimestamp[r->m_mediaChannel] : 0;
        RTMP_SendPause(r, TRUE, r->m_pauseStamp);
        r->m_pausing = 1;
      }
      else if (r->m_pausing == 2)
      {
        RTMP_SendPause(r, FALSE, r->m_pauseStamp);
        r->m_pausing = 3;
      }
      break;

    case 32:
      tmp = AMF_DecodeInt32(packet->m_body + 2);
      RTMP_Log(RTMP_LOGDEBUG, "%s, Stream BufferReady %d", __FUNCTION__, tmp);
      break;

    default:
      tmp = AMF_DecodeInt32(packet->m_body + 2);
      RTMP_Log(RTMP_LOGDEBUG, "%s, Stream xx %d", __FUNCTION__, tmp);
      break;
    }

  }

  if (nType == RTMP_CTRL_SWF_VERIFY)
  {
    RTMP_Log(RTMP_LOGDEBUG, "%s, SWFVerification ping received: ", __FUNCTION__);
    if (packet->m_nBodySize > 2 && packet->m_body[2] > 0x01)
    {
      RTMP_Log(RTMP_LOGERROR,
        "%s: SWFVerification Type %d request not supported! Patches welcome...",
        __FUNCTION__, packet->m_body[2]);
    }
#ifdef CRYPTO
    /*RTMP_LogHex(packet.m_body, packet.m_nBodySize); */

    /* respond with HMAC SHA256 of decompressed SWF, key is the 30byte player key, also the last 30 bytes of the server handshake are applied */
    else if (r->Link.SWFSize)
    {
      RTMP_SendCtrl(r, RTMP_CTRL_SWF_HMAC_SHA256, 0, 0);
    }
    else
    {
      RTMP_Log(RTMP_LOGERROR,
        "%s: Ignoring SWFVerification request, use --swfVfy!",
        __FUNCTION__);
    }
#else
    RTMP_Log(RTMP_LOGERROR,
      "%s: Ignoring SWFVerification request, no CRYPTO support!",
      __FUNCTION__);
#endif
  }
}

static void
HandleServerBW(RTMP *r, const RTMPPacket *packet)
{
  r->m_nServerBW = AMF_DecodeInt32(packet->m_body);
  RTMP_Log(RTMP_LOGDEBUG, "%s: server BW = %d", __FUNCTION__, r->m_nServerBW);
}

static void
HandleClientBW(RTMP *r, const RTMPPacket *packet)
{
  r->m_nClientBW = AMF_DecodeInt32(packet->m_body);
  if (packet->m_nBodySize > 4)
    r->m_nClientBW2 = packet->m_body[4];
  else
    r->m_nClientBW2 = -1;
  RTMP_Log(RTMP_LOGDEBUG, "%s: client BW = %d %d", __FUNCTION__, r->m_nClientBW,
      r->m_nClientBW2);
}

static int
DecodeInt32LE(const char *data)
{
  unsigned char *c = (unsigned char *)data;
  unsigned int val;

  val = (c[3] << 24) | (c[2] << 16) | (c[1] << 8) | c[0];
  return val;
}

static int
EncodeInt32LE(char *output, int nVal)
{
  output[0] = nVal;
  nVal >>= 8;
  output[1] = nVal;
  nVal >>= 8;
  output[2] = nVal;
  nVal >>= 8;
  output[3] = nVal;
  return 4;
}

bool
RTMP_ReadPacket(RTMP *r, RTMPPacket *packet)
{
  uint8_t hbuf[RTMP_MAX_HEADER_SIZE] = { 0 };
  char *header = (char *)hbuf;
  int nSize, hSize, nToRead, nChunk;
  //int didAlloc = FALSE;
  int extendedTimestamp=0;

  RTMP_Log(RTMP_LOGDEBUG2, "%s: fd=%d", __FUNCTION__, r->m_sb.sb_socket);

  if (ReadN(r, (char *)hbuf, 1) == 0)
    {
      RTMP_Log(RTMP_LOGDEBUG, "%s, failed to read RTMP packet header", __FUNCTION__);
      return RTMP_IsTimedout(r);
    }

  packet->m_headerType = (hbuf[0] & 0xc0) >> 6;
  packet->m_nChannel = (hbuf[0] & 0x3f);
  header++;
  if (packet->m_nChannel == 0)
    {
      if (ReadN(r, (char *)&hbuf[1], 1) != 1)
	{
      if (RTMP_IsConnected(r))
	  RTMP_Log(RTMP_LOGERROR, "%s, failed to read RTMP packet header 2nd byte",
	      __FUNCTION__);
	  return FALSE;
	}
      packet->m_nChannel = hbuf[1];
      packet->m_nChannel += 64;
      header++;
    }
  else if (packet->m_nChannel == 1)
    {
      int tmp;
      if (ReadN(r, (char *)&hbuf[1], 2) != 2)
	{
      if (RTMP_IsConnected(r))
	  RTMP_Log(RTMP_LOGERROR, "%s, failed to read RTMP packet header 3nd byte",
	      __FUNCTION__);
	  return FALSE;
	}
      tmp = (hbuf[2] << 8) + hbuf[1];
      packet->m_nChannel = tmp + 64;
      RTMP_Log(RTMP_LOGDEBUG, "%s, m_nChannel: %0x", __FUNCTION__, packet->m_nChannel);
      header += 2;
    }

  nSize = packetSize[packet->m_headerType];

  if (packet->m_nChannel >= r->m_channelsAllocatedIn)
    {
      int n = packet->m_nChannel + 10;
      int *timestamp = realloc(r->m_channelTimestamp, sizeof(int) * n);
      RTMPPacket **packets = realloc(r->m_vecChannelsIn, sizeof(RTMPPacket*) * n);
      if (!timestamp)
        free(r->m_channelTimestamp);
      if (!packets)
        free(r->m_vecChannelsIn);
      r->m_channelTimestamp = timestamp;
      r->m_vecChannelsIn = packets;
      if (!timestamp || !packets) {
        r->m_channelsAllocatedIn = 0;
        return FALSE;
      }
      memset(r->m_channelTimestamp + r->m_channelsAllocatedIn, 0, sizeof(int) * (n - r->m_channelsAllocatedIn));
      memset(r->m_vecChannelsIn + r->m_channelsAllocatedIn, 0, sizeof(RTMPPacket*) * (n - r->m_channelsAllocatedIn));
      r->m_channelsAllocatedIn = n;
    }

  if (nSize == RTMP_LARGE_HEADER_SIZE)	/* if we get a full header the timestamp is absolute */
    packet->m_hasAbsTimestamp = TRUE;

  else if (nSize < RTMP_LARGE_HEADER_SIZE)
    {				/* using values from the last message of this channel */
      if (r->m_vecChannelsIn[packet->m_nChannel])
	memcpy(packet, r->m_vecChannelsIn[packet->m_nChannel],
	       sizeof(RTMPPacket));
    }

  nSize--;

  if (nSize > 0 && ReadN(r, header, nSize) != nSize)
    {
      if (RTMP_IsConnected(r))
      RTMP_Log(RTMP_LOGERROR, "%s, failed to read RTMP packet header. type: %x",
	  __FUNCTION__, (unsigned int)hbuf[0]);
      return FALSE;
    }

  hSize = nSize + (header - (char *)hbuf);

  if (nSize >= 3)
    {
      packet->m_nTimeStamp = AMF_DecodeInt24(header);

      /*RTMP_Log(RTMP_LOGDEBUG, "%s, reading RTMP packet chunk on channel %x, headersz %i, timestamp %i, abs timestamp %i", __FUNCTION__, packet.m_nChannel, nSize, packet.m_nTimeStamp, packet.m_hasAbsTimestamp); */

      if (nSize >= 6)
	{
	  packet->m_nBodySize = AMF_DecodeInt24(header + 3);
	  packet->m_nBytesRead = 0;
	  RTMPPacket_Free(packet);

	  if (nSize > 6)
	    {
	      packet->m_packetType = header[6];

	      if (nSize == 11)
		packet->m_nInfoField2 = DecodeInt32LE(header + 7);
	    }
	}
    }

  extendedTimestamp = (packet->m_nTimeStamp == 0xffffff);
  if (extendedTimestamp)
    {
      if (ReadN(r, header + nSize, 4) != 4)
	{
      if (RTMP_IsConnected(r))
	  RTMP_Log(RTMP_LOGERROR, "%s, failed to read extended timestamp",
	      __FUNCTION__);
	  return FALSE;
	}
      packet->m_nTimeStamp = AMF_DecodeInt32(header + nSize);
      hSize += 4;
    }

  RTMP_LogHexString(RTMP_LOGDEBUG2, (uint8_t *)hbuf, hSize);

  if (packet->m_nBodySize > 0 && packet->m_body == NULL)
    {
      if (!RTMPPacket_Alloc(packet, packet->m_nBodySize))
	{
	  RTMP_Log(RTMP_LOGDEBUG, "%s, failed to allocate packet", __FUNCTION__);
	  return FALSE;
	}
      //didAlloc = TRUE;
      packet->m_headerType = (hbuf[0] & 0xc0) >> 6;
    }

  nToRead = packet->m_nBodySize - packet->m_nBytesRead;
  nChunk = r->m_inChunkSize;
  if (nToRead < nChunk)
    nChunk = nToRead;

  /* Does the caller want the raw chunk? */
  if (packet->m_chunk)
    {
      packet->m_chunk->c_headerSize = hSize;
      memcpy(packet->m_chunk->c_header, hbuf, hSize);
      packet->m_chunk->c_chunk = packet->m_body + packet->m_nBytesRead;
      packet->m_chunk->c_chunkSize = nChunk;
    }

  if (ReadN(r, packet->m_body + packet->m_nBytesRead, nChunk) != nChunk)
    {
      if (RTMP_IsConnected(r))
      RTMP_Log(RTMP_LOGERROR, "%s, failed to read RTMP packet body. len: %u",
	  __FUNCTION__, packet->m_nBodySize);
      return FALSE;
    }

  RTMP_LogHexString(RTMP_LOGDEBUG2, (uint8_t *)packet->m_body + packet->m_nBytesRead, nChunk);

  packet->m_nBytesRead += nChunk;

  /* keep the packet as ref for other packets on this channel */
  if (!r->m_vecChannelsIn[packet->m_nChannel])
    r->m_vecChannelsIn[packet->m_nChannel] = malloc(sizeof(RTMPPacket));
  memcpy(r->m_vecChannelsIn[packet->m_nChannel], packet, sizeof(RTMPPacket));
  if (extendedTimestamp)
    {
      r->m_vecChannelsIn[packet->m_nChannel]->m_nTimeStamp = 0xffffff;
    }

  if (RTMPPacket_IsReady(packet))
    {
      /* make packet's timestamp absolute */
      if (!packet->m_hasAbsTimestamp)
	packet->m_nTimeStamp += r->m_channelTimestamp[packet->m_nChannel];	/* timestamps seem to be always relative!! */

      r->m_channelTimestamp[packet->m_nChannel] = packet->m_nTimeStamp;

      /* reset the data from the stored packet. we keep the header since we may use it later if a new packet for this channel */
      /* arrives and requests to re-use some info (small packet header) */
      r->m_vecChannelsIn[packet->m_nChannel]->m_body = NULL;
      r->m_vecChannelsIn[packet->m_nChannel]->m_nBytesRead = 0;
      r->m_vecChannelsIn[packet->m_nChannel]->m_hasAbsTimestamp = FALSE;	/* can only be false if we reuse header */
    }
  else
    {
      packet->m_body = NULL;	/* so it won't be erased on free */
    }

  return TRUE;
}

#ifndef CRYPTO
static int
HandShake(RTMP *r, int FP9HandShake)
{
  int i;
  uint32_t uptime, suptime;
  int bMatch;
  char type;
  char clientbuf[RTMP_SIG_SIZE + 1], *clientsig = clientbuf + 1;
  char serversig[RTMP_SIG_SIZE];

  clientbuf[0] = 0x03;		/* not encrypted */

  uptime = htonl(RTMP_GetTime());
  memcpy(clientsig, &uptime, 4);

  memset(&clientsig[4], 0, 4);

#ifdef _DEBUG
  for (i = 8; i < RTMP_SIG_SIZE; i++)
    clientsig[i] = 0xff;
#else
  for (i = 8; i < RTMP_SIG_SIZE; i++)
    clientsig[i] = (char)(rand() % 256);
#endif

  if (!WriteN(r, clientbuf, RTMP_SIG_SIZE + 1))
    return FALSE;

  if (ReadN(r, &type, 1) != 1)	/* 0x03 or 0x06 */
    return FALSE;

  RTMP_Log(RTMP_LOGDEBUG, "%s: Type Answer   : %02X", __FUNCTION__, type);

  if (type != clientbuf[0])
    RTMP_Log(RTMP_LOGWARNING, "%s: Type mismatch: client sent %d, server answered %d",
	__FUNCTION__, clientbuf[0], type);

  if (ReadN(r, serversig, RTMP_SIG_SIZE) != RTMP_SIG_SIZE)
    return FALSE;

  /* decode server response */

  memcpy(&suptime, serversig, 4);
  suptime = ntohl(suptime);

  RTMP_Log(RTMP_LOGDEBUG, "%s: Server Uptime : %d", __FUNCTION__, suptime);
  RTMP_Log(RTMP_LOGDEBUG, "%s: FMS Version   : %d.%d.%d.%d", __FUNCTION__,
      serversig[4], serversig[5], serversig[6], serversig[7]);

  /* 2nd part of handshake */
  if (!WriteN(r, serversig, RTMP_SIG_SIZE))
    return FALSE;

  if (ReadN(r, serversig, RTMP_SIG_SIZE) != RTMP_SIG_SIZE)
    return FALSE;

  bMatch = (memcmp(serversig, clientsig, RTMP_SIG_SIZE) == 0);
  if (!bMatch)
    {
      RTMP_Log(RTMP_LOGWARNING, "%s, client signature does not match!", __FUNCTION__);
    }
  return TRUE;
}

static int
SHandShake(RTMP *r)
{
  int i;
  char serverbuf[RTMP_SIG_SIZE + 1], *serversig = serverbuf + 1;
  char clientsig[RTMP_SIG_SIZE];
  uint32_t uptime;
  int bMatch;

  if (ReadN(r, serverbuf, 1) != 1)	/* 0x03 or 0x06 */
    return FALSE;

  RTMP_Log(RTMP_LOGDEBUG, "%s: Type Request  : %02X", __FUNCTION__, serverbuf[0]);

  if (serverbuf[0] != 3)
    {
      RTMP_Log(RTMP_LOGERROR, "%s: Type unknown: client sent %02X",
	  __FUNCTION__, serverbuf[0]);
      return FALSE;
    }

  uptime = htonl(RTMP_GetTime());
  memcpy(serversig, &uptime, 4);

  memset(&serversig[4], 0, 4);
#ifdef _DEBUG
  for (i = 8; i < RTMP_SIG_SIZE; i++)
    serversig[i] = 0xff;
#else
  for (i = 8; i < RTMP_SIG_SIZE; i++)
    serversig[i] = (char)(rand() % 256);
#endif

  if (!WriteN(r, serverbuf, RTMP_SIG_SIZE + 1))
    return FALSE;

  if (ReadN(r, clientsig, RTMP_SIG_SIZE) != RTMP_SIG_SIZE)
    return FALSE;

  /* decode client response */

  memcpy(&uptime, clientsig, 4);
  uptime = ntohl(uptime);

  RTMP_Log(RTMP_LOGDEBUG, "%s: Client Uptime : %d", __FUNCTION__, uptime);
  RTMP_Log(RTMP_LOGDEBUG, "%s: Player Version: %d.%d.%d.%d", __FUNCTION__,
      clientsig[4], clientsig[5], clientsig[6], clientsig[7]);

  /* 2nd part of handshake */
  if (!WriteN(r, clientsig, RTMP_SIG_SIZE))
    return FALSE;

  if (ReadN(r, clientsig, RTMP_SIG_SIZE) != RTMP_SIG_SIZE)
    return FALSE;

  bMatch = (memcmp(serversig, clientsig, RTMP_SIG_SIZE) == 0);
  if (!bMatch)
    {
      RTMP_Log(RTMP_LOGWARNING, "%s, client signature does not match!", __FUNCTION__);
    }
  return TRUE;
}
#endif

int
RTMP_SendChunk(RTMP *r, RTMPChunk *chunk)
{
  int wrote;
  char hbuf[RTMP_MAX_HEADER_SIZE];

  RTMP_Log(RTMP_LOGDEBUG2, "%s: fd=%d, size=%d", __FUNCTION__, r->m_sb.sb_socket,
      chunk->c_chunkSize);
  RTMP_LogHexString(RTMP_LOGDEBUG2, (uint8_t *)chunk->c_header, chunk->c_headerSize);
  if (chunk->c_chunkSize)
    {
      char *ptr = chunk->c_chunk - chunk->c_headerSize;
      RTMP_LogHexString(RTMP_LOGDEBUG2, (uint8_t *)chunk->c_chunk, chunk->c_chunkSize);
      /* save header bytes we're about to overwrite */
      memcpy(hbuf, ptr, chunk->c_headerSize);
      memcpy(ptr, chunk->c_header, chunk->c_headerSize);
      wrote = WriteN(r, ptr, chunk->c_headerSize + chunk->c_chunkSize);
      memcpy(ptr, hbuf, chunk->c_headerSize);
    }
  else
    wrote = WriteN(r, chunk->c_header, chunk->c_headerSize);
  return wrote;
}

bool
RTMP_SendPacket(RTMP *r, RTMPPacket *packet, bool queue)
{
  const RTMPPacket *prevPacket;
  uint32_t last = 0;
  uint8_t packet_m_headerType = packet->m_headerType;
  int nSize;
  int hSize, cSize;
  char *header, *hptr, *hend, hbuf[RTMP_MAX_HEADER_SIZE], c;
  uint32_t t = 1;
  char *buffer, *tbuf = NULL, *toff = NULL;
  int nChunkSize;
  int tlen;

  if (packet->m_nChannel >= r->m_channelsAllocatedOut)
  {
    int n = packet->m_nChannel + 10;
    RTMPPacket **packets = realloc(r->m_vecChannelsOut, sizeof(RTMPPacket*) * n);
    if (!packets) {
      free(r->m_vecChannelsOut);
      r->m_vecChannelsOut = NULL;
      r->m_channelsAllocatedOut = 0;
      return FALSE;
    }
    r->m_vecChannelsOut = packets;
    memset(r->m_vecChannelsOut + r->m_channelsAllocatedOut, 0, sizeof(RTMPPacket*) * (n - r->m_channelsAllocatedOut));
    r->m_channelsAllocatedOut = n;
  }

  prevPacket = r->m_vecChannelsOut[packet->m_nChannel];
  if (prevPacket && packet_m_headerType != RTMP_PACKET_SIZE_LARGE)
  {
    /* compress a bit by using the prev packet's attributes */
    if (prevPacket->m_nBodySize == packet->m_nBodySize
      && prevPacket->m_packetType == packet->m_packetType
      && packet_m_headerType == RTMP_PACKET_SIZE_MEDIUM)
      packet_m_headerType = RTMP_PACKET_SIZE_SMALL;

    if (prevPacket->m_nTimeStamp == packet->m_nTimeStamp
      && packet_m_headerType == RTMP_PACKET_SIZE_SMALL)
      packet_m_headerType = RTMP_PACKET_SIZE_MINIMUM;
    last = prevPacket->m_nTimeStamp;
  }

  if (packet_m_headerType > 3)	/* sanity */
  {
    RTMP_Log(RTMP_LOGERROR, "sanity failed!! trying to send header of type: 0x%02x.",
      (unsigned char)packet_m_headerType);
    return FALSE;
  }

  nSize = packetSize[packet_m_headerType];
  hSize = nSize; cSize = 0;
  if (packet->m_nTimeStamp >= last)
  {
    t = packet->m_nTimeStamp - last;
  }
  else
  {
    RTMP_Log(RTMP_LOGWARNING, "Timestamp 0x%x suddenly becomes smaller than 0x%x", packet->m_nTimeStamp, last);
  }

  if (packet->m_body)
  {
    header = packet->m_body - nSize;
    hend = packet->m_body;
  }
  else
  {
    header = hbuf + 6;
    hend = hbuf + sizeof(hbuf);
  }

  if (packet->m_nChannel > 319)
    cSize = 2;
  else if (packet->m_nChannel > 63)
    cSize = 1;
  if (cSize)
  {
    header -= cSize;
    hSize += cSize;
  }

  if (nSize > 1 && t >= 0xffffff)
  {
    header -= 4;
    hSize += 4;
    RTMP_Log(RTMP_LOGWARNING, "Larger timestamp than 24-bit: 0x%x", t);
  }

  hptr = header;
  c = packet_m_headerType<< 6;
  switch (cSize)
  {
  case 0:
    c |= packet->m_nChannel;
    break;
  case 1:
    break;
  case 2:
    c |= 1;
    break;
  }
  *hptr++ = c;
  if (cSize)
  {
    int tmp = packet->m_nChannel - 64;
    *hptr++ = tmp & 0xff;
    if (cSize == 2)
      *hptr++ = tmp >> 8;
  }

  if (nSize > 1)
  {
    hptr = AMF_EncodeInt24(hptr, hend, t > 0xffffff ? 0xffffff : t);
  }

  if (nSize > 4)
  {
    hptr = AMF_EncodeInt24(hptr, hend, packet->m_nBodySize);
    *hptr++ = packet->m_packetType;
  }

  if (nSize > 8)
    hptr += EncodeInt32LE(hptr, packet->m_nInfoField2);

  if (nSize > 1 && t >= 0xffffff)
    hptr = AMF_EncodeInt32(hptr, hend, t);

  nSize = packet->m_nBodySize;
  buffer = packet->m_body;
  nChunkSize = r->m_outChunkSize;

  RTMP_Log(RTMP_LOGDEBUG2, "%s: fd=%d, size=%d", __FUNCTION__, r->m_sb.sb_socket,
    nSize);
  /* send all chunks in one HTTP request */
  if (r->Link.protocol & RTMP_FEATURE_HTTP)
  {
    int chunks = (nSize+nChunkSize-1) / nChunkSize;
    if (chunks > 1)
    {
      tlen = chunks * (cSize + 1) + nSize + hSize;
      tbuf = malloc(tlen);
      if (!tbuf)
        return FALSE;
      toff = tbuf;
    }
  }
  while (nSize + hSize)
  {
    int wrote = TRUE;

    if (nSize < nChunkSize)
      nChunkSize = nSize;

    RTMP_LogHexString(RTMP_LOGDEBUG2, (uint8_t *)header, hSize);
    RTMP_LogHexString(RTMP_LOGDEBUG2, (uint8_t *)buffer, nChunkSize);
    if (tbuf)
    {
      memcpy(toff, header, nChunkSize + hSize);
      toff += nChunkSize + hSize;
    }
    else
    {
      wrote = WriteN(r, header, nChunkSize + hSize);
    }
    if (hSize > 0 && buffer != packet->m_body && header == buffer - hSize) /* restore original head */
      memcpy(header, hbuf, hSize);

    if (!wrote) return FALSE;
    nSize -= nChunkSize;
    buffer += nChunkSize;
    hSize = 0;

    if (nSize > 0)
    {
      hSize = 1;
      if (cSize)
        hSize += cSize;
      //if (t >= 0xffffff)
      //  hSize += 4;
      header = buffer - hSize;
      memcpy(hbuf, header, hSize);
      *header = (0xc0 | c);
      if (cSize)
      {
        int tmp = packet->m_nChannel - 64;
        header[1] = tmp & 0xff;
        if (cSize == 2)
          header[2] = tmp >> 8;
      }
      /*
      if (t >= 0xffffff)
      {
        char* extendedTimestamp = header + 1 + cSize;
        AMF_EncodeInt32(extendedTimestamp, extendedTimestamp + 4, t);
      }*/
    }
  }
  if (tbuf)
  {
    int wrote = WriteN(r, tbuf, toff-tbuf);
    free(tbuf);
    tbuf = NULL;
    if (!wrote)
      return FALSE;
  }

  /* we invoked a remote method */
  if (packet->m_packetType == RTMP_PACKET_TYPE_INVOKE)
  {
    AVal method;
    char *ptr;
    ptr = packet->m_body + 1;
    AMF_DecodeString(ptr, &method);
    RTMP_Log(RTMP_LOGDEBUG, "Invoking %s", method.av_val);
    /* keep it in call queue till result arrives */
    if (queue) {
      int txn;
      ptr += 3 + method.av_len;
      txn = (int)AMF_DecodeNumber(ptr);
      AV_queue(&r->m_methodCalls, &r->m_numCalls, &method, txn);
    }
  }

  if (!r->m_vecChannelsOut[packet->m_nChannel])
    r->m_vecChannelsOut[packet->m_nChannel] = malloc(sizeof(RTMPPacket));
  memcpy(r->m_vecChannelsOut[packet->m_nChannel], packet, sizeof(RTMPPacket));
  return TRUE;
}

bool
RTMP_Serve(RTMP *r, SOCKET sockfd, void *sslCtx)
{
  r->m_sb.sb_socket = sockfd;
  if (sslCtx && !RTMP_TLS_Accept(r, sslCtx))
    return FALSE;
  return SHandShake(r);
}

void
RTMP_Close(RTMP *r)
{
  if (r) CloseInternal(r, 0);
}

static void
CloseInternal(RTMP *r, int reconnect)
{
  int i;

  if (RTMP_IsConnected(r))
    {
      if (r->m_stream_id > 0)
        {
	  i = r->m_stream_id;
	  r->m_stream_id = 0;
          if ((r->Link.protocol & RTMP_FEATURE_WRITE))
	    SendFCUnpublish(r);
	  SendDeleteStream(r, i);
	}
      if (r->m_clientID.av_val)
        {
	  HTTP_Post(r, RTMPT_CLOSE, "", 1);
	  free(r->m_clientID.av_val);
	  r->m_clientID.av_val = NULL;
	  r->m_clientID.av_len = 0;
	}
      RTMPSockBuf_Close(&r->m_sb);
    }

  r->m_stream_id = -1;
  r->m_sb.sb_socket = -1;
  r->m_nBWCheckCounter = 0;
  r->m_nBytesIn = 0;
  r->m_nBytesInSent = 0;

  if (r->m_read.flags & RTMP_READ_HEADER) {
    free(r->m_read.buf);
    r->m_read.buf = NULL;
  }
  r->m_read.dataType = 0;
  r->m_read.flags = 0;
  r->m_read.status = 0;
  r->m_read.nResumeTS = 0;
  r->m_read.nIgnoredFrameCounter = 0;
  r->m_read.nIgnoredFlvFrameCounter = 0;

  r->m_write.m_nBytesRead = 0;
  RTMPPacket_Free(&r->m_write);

  for (i = 0; i < r->m_channelsAllocatedIn; i++)
    {
      if (r->m_vecChannelsIn[i])
	{
	  RTMPPacket_Free(r->m_vecChannelsIn[i]);
	  free(r->m_vecChannelsIn[i]);
	  r->m_vecChannelsIn[i] = NULL;
	}
    }
  free(r->m_vecChannelsIn);
  r->m_vecChannelsIn = NULL;
  free(r->m_channelTimestamp);
  r->m_channelTimestamp = NULL;
  r->m_channelsAllocatedIn = 0;
  for (i = 0; i < r->m_channelsAllocatedOut; i++)
    {
      if (r->m_vecChannelsOut[i])
	{
	  free(r->m_vecChannelsOut[i]);
	  r->m_vecChannelsOut[i] = NULL;
	}
    }
  free(r->m_vecChannelsOut);
  r->m_vecChannelsOut = NULL;
  r->m_channelsAllocatedOut = 0;
  AV_clear(r->m_methodCalls, r->m_numCalls);
  r->m_methodCalls = NULL;
  r->m_numCalls = 0;
  r->m_numInvokes = 0;

  r->m_state = 0;
  r->m_sb.sb_size = 0;

  r->m_msgCounter = 0;
  r->m_resplen = 0;
  r->m_unackd = 0;

  if (r->Link.lFlags & RTMP_LF_FTCU && !reconnect)
    {
      free(r->Link.tcUrl.av_val);
      r->Link.tcUrl.av_val = NULL;
      r->Link.lFlags ^= RTMP_LF_FTCU;
    }
  if (r->Link.lFlags & RTMP_LF_FAPU && !reconnect)
    {
      free(r->Link.app.av_val);
      r->Link.app.av_val = NULL;
      r->Link.lFlags ^= RTMP_LF_FAPU;
    }

  if (!reconnect)
    {
      free(r->Link.playpath0.av_val);
      r->Link.playpath0.av_val = NULL;
    }
#ifdef CRYPTO
  if (r->Link.dh)
    {
      MDH_free(r->Link.dh);
      r->Link.dh = NULL;
    }
  if (r->Link.rc4keyIn)
    {
      RC4_free(r->Link.rc4keyIn);
      r->Link.rc4keyIn = NULL;
    }
  if (r->Link.rc4keyOut)
    {
      RC4_free(r->Link.rc4keyOut);
      r->Link.rc4keyOut = NULL;
    }
#endif
  FreeMetaBuf(r);
}

int
RTMPSockBuf_Fill(RTMPSockBuf *sb)
{
  int nBytes;

  if (!sb->sb_size)
    sb->sb_start = sb->sb_buf;

  while (1)
    {
      nBytes = sizeof(sb->sb_buf) - 1 - sb->sb_size - (sb->sb_start - sb->sb_buf);
#if defined(CRYPTO) && !defined(NO_SSL)
      if (sb->sb_ssl)
	{
	  nBytes = TLS_read(sb->sb_ssl, sb->sb_start + sb->sb_size, nBytes);
	}
      else
#endif
	{
	  nBytes = recv(sb->sb_socket, sb->sb_start + sb->sb_size, nBytes, 0);
	}
      if (nBytes != -1)
	{
	  sb->sb_size += nBytes;
	}
      else
	{
	  int sockerr = GetSockError();
	  if (sockerr == EINTR && !RTMP_ctrlC)
	    continue;

	  if (sockerr == EWOULDBLOCK || sockerr == EAGAIN || sockerr == ETIME)
	    {
	      sb->sb_timedout = TRUE;
	      nBytes = 0;
	    }
      if (sb->sb_socket != INVALID_SOCKET)
	  RTMP_Log(nBytes?RTMP_LOGERROR:RTMP_LOGDEBUG, "[%d]%s, recv error:%d(%s)",
          sb->sb_socket, __FUNCTION__, sockerr, strerror(sockerr));

	}
      break;
    }

  return nBytes;
}

int
RTMPSockBuf_Send(RTMPSockBuf *sb, const char *buf, int len)
{
  int rc;

#if defined(RTMP_NETSTACK_DUMP)
  fwrite(buf, 1, len, netstackdump);
#endif

#if defined(CRYPTO) && !defined(NO_SSL)
  if (sb->sb_ssl)
    {
      rc = TLS_write(sb->sb_ssl, buf, len);
    }
  else
#endif
    {
      rc = send(sb->sb_socket, buf, len, 0);
    }
  return rc;
}

int
RTMPSockBuf_Close(RTMPSockBuf *sb)
{
#if defined(CRYPTO) && !defined(NO_SSL)
  if (sb->sb_ssl)
    {
      TLS_shutdown(sb->sb_ssl);
      TLS_close(sb->sb_ssl);
      sb->sb_ssl = NULL;
    }
#endif
  if (sb->sb_socket != INVALID_SOCKET)
    {
      closesocket(sb->sb_socket);
      RTMP_Log(RTMP_LOGDEBUG, "[%zu]Closed", (size_t)sb->sb_socket);
      sb->sb_socket = INVALID_SOCKET;
    }
  return 0;
}

#define HEX2BIN(a)	(((a)&0x40)?((a)&0xf)+9:((a)&0xf))

static void
DecodeTEA(AVal *key, AVal *text)
{
  uint32_t *v, k[4] = { 0 }, u;
  uint32_t z, y, sum = 0, e, DELTA = 0x9e3779b9;
  int32_t p, q;
  int i, n;
  unsigned char *ptr, *out;

  /* prep key: pack 1st 16 chars into 4 LittleEndian ints */
  ptr = (unsigned char *)key->av_val;
  u = 0;
  n = 0;
  v = k;
  p = key->av_len > 16 ? 16 : key->av_len;
  for (i = 0; i < p; i++)
    {
      u |= ptr[i] << (n * 8);
      if (n == 3)
	{
	  *v++ = u;
	  u = 0;
	  n = 0;
	}
      else
	{
	  n++;
	}
    }
  /* any trailing chars */
  if (u)
    *v = u;

  /* prep text: hex2bin, multiples of 4 */
  n = (text->av_len + 7) / 8;
  out = malloc(n * 8);
  ptr = (unsigned char *)text->av_val;
  v = (uint32_t *) out;
  for (i = 0; i < n; i++)
    {
      u = (HEX2BIN(ptr[0]) << 4) + HEX2BIN(ptr[1]);
      u |= ((HEX2BIN(ptr[2]) << 4) + HEX2BIN(ptr[3])) << 8;
      u |= ((HEX2BIN(ptr[4]) << 4) + HEX2BIN(ptr[5])) << 16;
      u |= ((HEX2BIN(ptr[6]) << 4) + HEX2BIN(ptr[7])) << 24;
      *v++ = u;
      ptr += 8;
    }
  v = (uint32_t *) out;

  /* http://www.movable-type.co.uk/scripts/tea-block.html */
#define MX (((z>>5)^(y<<2)) + ((y>>3)^(z<<4))) ^ ((sum^y) + (k[(p&3)^e]^z));
  z = v[n - 1];
  y = v[0];
  q = 6 + 52 / n;
  sum = q * DELTA;
  while (sum != 0)
    {
      e = sum >> 2 & 3;
      for (p = n - 1; p > 0; p--)
	z = v[p - 1], y = v[p] -= MX;
      z = v[n - 1];
      y = v[0] -= MX;
      sum -= DELTA;
    }

  text->av_len /= 2;
  memcpy(text->av_val, out, text->av_len);
  free(out);
}

static int
HTTP_Post(RTMP *r, RTMPTCmd cmd, const char *buf, int len)
{
  char hbuf[512];
  int hlen = snprintf(hbuf, sizeof(hbuf), "POST /%s%s/%d HTTP/1.1\r\n"
    "Host: %.*s:%d\r\n"
    "Accept: */*\r\n"
    "User-Agent: Shockwave Flash\r\n"
    "Connection: Keep-Alive\r\n"
    "Cache-Control: no-cache\r\n"
    "Content-type: application/x-fcs\r\n"
    "Content-length: %d\r\n\r\n", RTMPT_cmds[cmd],
    r->m_clientID.av_val ? r->m_clientID.av_val : "",
    r->m_msgCounter, r->Link.hostname.av_len, r->Link.hostname.av_val,
    r->Link.port, len);
  RTMPSockBuf_Send(&r->m_sb, hbuf, hlen);
  hlen = RTMPSockBuf_Send(&r->m_sb, buf, len);
  r->m_msgCounter++;
  r->m_unackd++;
  return hlen;
}

static int
HTTP_read(RTMP *r, int fill)
{
  char *ptr;
  int hlen;

restart:
  if (fill)
    RTMPSockBuf_Fill(&r->m_sb);
  if (r->m_sb.sb_size < 13) {
    if (fill)
      goto restart;
    return -2;
  }
  if (strncmp(r->m_sb.sb_start, "HTTP/1.1 200 ", 13))
    return -1;
  r->m_sb.sb_start[r->m_sb.sb_size] = '\0';
  if (!strstr(r->m_sb.sb_start, "\r\n\r\n")) {
    if (fill)
      goto restart;
    return -2;
  }

  ptr = r->m_sb.sb_start + sizeof("HTTP/1.1 200");
  while ((ptr = strstr(ptr, "Content-"))) {
    if (!strncasecmp(ptr+8, "length:", 7)) break;
    ptr += 8;
  }
  if (!ptr)
    return -1;
  hlen = atoi(ptr+16);
  ptr = strstr(ptr+16, "\r\n\r\n");
  if (!ptr)
    return -1;
  ptr += 4;
  if (ptr + (r->m_clientID.av_val ? 1 : hlen) > r->m_sb.sb_start + r->m_sb.sb_size)
    {
      if (fill)
        goto restart;
      return -2;
    }
  r->m_sb.sb_size -= ptr - r->m_sb.sb_start;
  r->m_sb.sb_start = ptr;
  r->m_unackd--;

  if (!r->m_clientID.av_val)
    {
      r->m_clientID.av_len = hlen;
      r->m_clientID.av_val = malloc(hlen+1);
      if (!r->m_clientID.av_val)
        return -1;
      r->m_clientID.av_val[0] = '/';
      memcpy(r->m_clientID.av_val+1, ptr, hlen-1);
      r->m_clientID.av_val[hlen] = 0;
      r->m_sb.sb_size = 0;
    }
  else
    {
      r->m_polling = *ptr++;
      r->m_resplen = hlen - 1;
      r->m_sb.sb_start++;
      r->m_sb.sb_size--;
    }
  return 0;
}

int
RTMP_Write(RTMP *r, const char *buf, int size)
{
  RTMPPacket *pkt = &r->m_write;
  char *pend, *enc;
  int s2 = size, ret, num;

  pkt->m_nChannel = 0x04;	/* source channel */
  pkt->m_nInfoField2 = r->m_stream_id;

  while (s2)
  {
    if (!pkt->m_nBytesRead)
    {
      if (s2 <= 11) /* FLV pkt too small */
        break;

      if (buf[0] == 'F' && buf[1] == 'L' && buf[2] == 'V')
      {
        if (s2 <= 13+11) /* FLV pkt too small */
          break;
        buf += 13;
        s2  -= 13;
      }

      pkt->m_packetType = *buf++;
      pkt->m_nBodySize = AMF_DecodeInt24(buf);
      buf += 3;
      pkt->m_nTimeStamp = AMF_DecodeInt24(buf);
      buf += 3;
      pkt->m_nTimeStamp |= *buf++ << 24;
      buf += 3;
      s2 -= 11;

      if (((pkt->m_packetType == RTMP_PACKET_TYPE_AUDIO
            || pkt->m_packetType == RTMP_PACKET_TYPE_VIDEO) &&
          !pkt->m_nTimeStamp) || pkt->m_packetType == RTMP_PACKET_TYPE_INFO)
      {
        pkt->m_headerType = RTMP_PACKET_SIZE_LARGE;
        if (pkt->m_packetType == RTMP_PACKET_TYPE_INFO) {
          AMFObject obj;
          AMFObjectProperty prop;

          pkt->m_nBodySize += 1+2+av_setDataFrame.av_len;
          AMF_Decode(&obj, buf, size, FALSE);
          AMF_Dump(&obj);
          if (RTMP_FindFirstMatchingProperty(&obj, &av_duration, &prop))
          {
            r->m_read.duration = prop.p_vu.p_number;
            RTMP_Log(RTMP_LOGDEBUG, "Set duration: %.2f", r->m_read.duration);
          }
          AMF_Reset(&obj);
        }
      }
      else
      {
        pkt->m_headerType = RTMP_PACKET_SIZE_MEDIUM;
      }

      if (!RTMPPacket_Alloc(pkt, pkt->m_nBodySize))
      {
        RTMP_Log(RTMP_LOGDEBUG, "%s, failed to allocate packet", __FUNCTION__);
        return -1;
      }
      enc = pkt->m_body;
      pend = enc + pkt->m_nBodySize;
      if (pkt->m_packetType == RTMP_PACKET_TYPE_INFO)
      {
        enc = AMF_EncodeString(enc, pend, &av_setDataFrame);
        pkt->m_nBytesRead = enc - pkt->m_body;
      }
    }
    else
    {
      enc = pkt->m_body + pkt->m_nBytesRead;
    }
    num = pkt->m_nBodySize - pkt->m_nBytesRead;
    if (num > s2)
      num = s2;
    memcpy(enc, buf, num);
    pkt->m_nBytesRead += num;
    s2 -= num;
    buf += num;
    if (pkt->m_nBytesRead == pkt->m_nBodySize)
    {
      ret = RTMP_SendPacket(r, pkt, FALSE);
      RTMPPacket_Free(pkt);
      pkt->m_nBytesRead = 0;
      if (!ret)
        return -1;
      buf += 4;
      if (s2 < 4)
        break;
      s2 -= 4; /* skip back-pointers */
    }
  }
  return size-s2;
}
