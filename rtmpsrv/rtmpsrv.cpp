#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <librtmp/rtmp.h>
#include <librtmp/log.h>
#include <sstream>
#include <unordered_map>
#include <unordered_set>
#define CPPHTTPLIB_ST_SUPPORT
#define CPPHTTPLIB_ZLIB_SUPPORT
#include "httplib.h"
void HUB_SetPublisher(const std::string& playpath, RTMP* r, int32_t streamId, bool live);
void HUB_AddPlayer(const std::string& playpath, RTMP* r, int32_t streamId, double seekMs, double lenMs);
void HUB_RemoveClient(RTMP* r);
bool HUB_IsLive(const std::string& playpath);
void HUB_PublishPacket(RTMPPacket* packet);
static int _httpPort = 5562, _rtmpPort = 1935;
typedef std::pair<std::string, int> SRC_ADDR;
//rtmp url regex to sockaddr
static std::unordered_map<std::string, SRC_ADDR> _sourceAddrs;
//#define SAVC(x) static const AVal av_##x = AVC(#x)

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
SAVC(_result);
SAVC(createStream);
SAVC(getStreamLength);
SAVC(play);
SAVC(publish);
SAVC(live);
SAVC(fmsVer);
SAVC(mode);
SAVC(level);
SAVC(code);
SAVC(description);
SAVC(secureToken);
SAVC(onStatus);
SAVC(status);
SAVC(details);
SAVC(clientid);
SAVC(deleteStream);
SAVC(FCUnpublish);
SAVC2(dquote,"\"");
SAVC2(escdquote,"\\\"");
SAVC2(NetStream_Play_Reset, "NetStream.Play.Reset");
SAVC2(Playing_resetting, "Playing resetting");
SAVC2(NetStream_Play_Start, "NetStream.Play.Start");
SAVC2(Started_playing, "Started playing");
SAVC2(Started_publishing, "Started publishing");
SAVC2(NetStream_Play_Stop, "NetStream.Play.Stop");
SAVC2(Stopped_playing, "Stopped playing");
SAVC2(NetStream_Data_Start, "NetStream.Data.Start");
SAVC2(NetStream_Authenticate_UsherToken, "NetStream.Authenticate.UsherToken");
SAVC2(NetStream_Publish_Start, "NetStream.Publish.Start");
#undef AVC
#define STR2AVAL(av,str)	av.av_val = (char*)str; av.av_len = strlen(av.av_val)
#define DUPTIME	5000	/* interval we disallow duplicate requests, in msec */

typedef struct
{
    int state;
    int arglen;
    int argc;
    uint32_t filetime;	/* time of last download we started */
    AVal filename;	/* name of last download */
    char *connect;
} STREAMING_SERVER;
static char * dumpAMF(AMFObject *obj, char *ptr, AVal *argv, int *argc)
{
    int i, ac = *argc;
    const char opt[] = "NBSO Z";

    for (i=0; i < obj->o_num; i++)
    {
        AMFObjectProperty *p = &obj->o_props[i];
        argv[ac].av_val = ptr+1;
        argv[ac++].av_len = 2;
        ptr += sprintf(ptr, " -C ");
        argv[ac].av_val = ptr;
        if (p->p_name.av_val)
            *ptr++ = 'N';
        *ptr++ = opt[p->p_type];
        *ptr++ = ':';
        if (p->p_name.av_val)
            ptr += sprintf(ptr, "%.*s:", p->p_name.av_len, p->p_name.av_val);
        switch(p->p_type)
        {
        case AMF_BOOLEAN:
            *ptr++ = p->p_vu.p_number != 0 ? '1' : '0';
            argv[ac].av_len = ptr - argv[ac].av_val;
            break;
        case AMF_STRING:
            memcpy(ptr, p->p_vu.p_aval.av_val, p->p_vu.p_aval.av_len);
            ptr += p->p_vu.p_aval.av_len;
            argv[ac].av_len = ptr - argv[ac].av_val;
            break;
        case AMF_NUMBER:
            ptr += sprintf(ptr, "%f", p->p_vu.p_number);
            argv[ac].av_len = ptr - argv[ac].av_val;
            break;
        case AMF_OBJECT:
            *ptr++ = '1';
            argv[ac].av_len = ptr - argv[ac].av_val;
            ac++;
            *argc = ac;
            ptr = dumpAMF(&p->p_vu.p_object, ptr, argv, argc);
            ac = *argc;
            argv[ac].av_val = ptr+1;
            argv[ac++].av_len = 2;
            argv[ac].av_val = ptr+4;
            argv[ac].av_len = 3;
            ptr += sprintf(ptr, " -C O:0");
            break;
        case AMF_NULL:
        default:
            argv[ac].av_len = ptr - argv[ac].av_val;
            break;
        }
        ac++;
    }
    *argc = ac;
    return ptr;
}
static void toURL(std::ostream& oss, const std::string& url)
{
    size_t a=0,b=url.find_first_of("+ /?%#&=", a);
    while (b != url.npos) {
        if (b > a) oss<<url.substr(a, b-a);
        oss<<'%'<<std::hex<<(int)url[b];
        b = url.find_first_of("+ /?%#&=", a = b+1);
    }
    oss<<url.substr(a);
}

static bool SpawnPublisher(STREAMING_SERVER* server, RTMP * r, AVal* playpath,
    SRC_ADDR& src_addr, std::string& body)
{
    std::ostringstream oss;
    char *file, *p, *q, *cmd, *ptr;
    AVal *argv, av;
    int len, argc;
    uint32_t now;

    len = server->arglen + playpath->av_len + 4 +
        sizeof("rtmpdump") + playpath->av_len + 12;
    server->argc += 5;

    cmd = (char*)malloc(len + server->argc * sizeof(AVal));
    ptr = cmd;
    argv = (AVal *)(cmd + len);
    argv[0].av_val = cmd;
    argv[0].av_len = sizeof("rtmpdump")-1;
    ptr += sprintf(ptr, "rtmpdump");
    argc = 1;

    argv[argc].av_val = ptr + 1;
    argv[argc++].av_len = 2;
    argv[argc].av_val = ptr + 5;
    ptr += sprintf(ptr," -r \"%s\"", r->Link.tcUrl.av_val);
    for (auto& iter : _sourceAddrs) {
        if (std::regex_match (r->Link.tcUrl.av_val, std::regex(iter.first))){
            src_addr = iter.second;
            break;
        }
    }
    argv[argc++].av_len = r->Link.tcUrl.av_len;

    if (r->Link.app.av_val)
    {
        argv[argc].av_val = ptr + 1;
        argv[argc++].av_len = 2;
        argv[argc].av_val = ptr + 5;
        ptr += sprintf(ptr, " -a \"%s\"", r->Link.app.av_val);
        toURL(oss << " app=", r->Link.app.av_val);
        argv[argc++].av_len = r->Link.app.av_len;
    }
    if (r->Link.flashVer.av_val)
    {
        argv[argc].av_val = ptr + 1;
        argv[argc++].av_len = 2;
        argv[argc].av_val = ptr + 5;
        ptr += sprintf(ptr, " -f \"%s\"", r->Link.flashVer.av_val);
        toURL(oss << " flashver=", r->Link.flashVer.av_val);
        argv[argc++].av_len = r->Link.flashVer.av_len;
    }
    if (r->Link.swfUrl.av_val)
    {
        argv[argc].av_val = ptr + 1;
        argv[argc++].av_len = 2;
        argv[argc].av_val = ptr + 5;
        ptr += sprintf(ptr, " -W \"%s\"", r->Link.swfUrl.av_val);
        toURL(oss << " swfUrl=", r->Link.swfUrl.av_val);
        argv[argc++].av_len = r->Link.swfUrl.av_len;
    }
    if (r->Link.pageUrl.av_val)
    {
        argv[argc].av_val = ptr + 1;
        argv[argc++].av_len = 2;
        argv[argc].av_val = ptr + 5;
        ptr += sprintf(ptr, " -p \"%s\"", r->Link.pageUrl.av_val);
        toURL(oss << " pageUrl=", r->Link.pageUrl.av_val);
        argv[argc++].av_len = r->Link.pageUrl.av_len;
    }
    if (r->Link.usherToken.av_val)
    {
        argv[argc].av_val = ptr + 1;
        argv[argc++].av_len = 2;
        argv[argc].av_val = ptr + 5;
        ptr += sprintf(ptr, " -j \"%s\"", r->Link.usherToken.av_val);
        toURL(oss << " jtv=", r->Link.usherToken.av_val);
        argv[argc++].av_len = r->Link.usherToken.av_len;
        free(r->Link.usherToken.av_val);
        r->Link.usherToken.av_val = NULL;
        r->Link.usherToken.av_len = 0;
    }
    if (r->Link.extras.o_num) {
        ptr = dumpAMF(&r->Link.extras, ptr, argv, &argc);
        AMF_Reset(&r->Link.extras);
    }
    argv[argc].av_val = ptr + 1;
    argv[argc++].av_len = 2;
    argv[argc].av_val = ptr + 5;
    ptr += sprintf(ptr, " -y \"%.*s\"",
        playpath->av_len, playpath->av_val);
    argv[argc++].av_len = playpath->av_len;

    av = *playpath;
    toURL(oss << " playpath=", std::string(av.av_val, av.av_len));
    /* strip trailing URL parameters */
    q = (char*)memchr(av.av_val, '?', av.av_len);
    if (q)
    {
        if (q == av.av_val)
        {
            av.av_val++;
            av.av_len--;
        }
        else
        {
            av.av_len = q - av.av_val;
        }
    }
    /* strip leading slash components */
    for (p=av.av_val+av.av_len-1; p>=av.av_val; p--)
        if (*p == '/')
        {
            p++;
            av.av_len -= p - av.av_val;
            av.av_val = p;
            break;
        }
    /* skip leading dot */
    if (av.av_val[0] == '.')
    {
        av.av_val++;
        av.av_len--;
    }
    file = (char*)malloc(av.av_len+5);

    memcpy(file, av.av_val, av.av_len);
    file[av.av_len] = '\0';
    for (p=file; *p; p++)
        if (*p == ':')
            *p = '_';

    /* Add extension if none present */
    if (file[av.av_len - 4] != '.')
    {
        av.av_len += 4;
    }
    /* Always use flv extension, regardless of original */
    if (strcmp(file+av.av_len-4, ".flv"))
    {
        strcpy(file+av.av_len-4, ".flv");
    }
    argv[argc].av_val = ptr + 1;
    argv[argc++].av_len = 2;
    argv[argc].av_val = file;
    argv[argc].av_len = av.av_len;
    ptr += sprintf(ptr, " -o %s", file);
    now = RTMP_GetTime();
    if (now - server->filetime < DUPTIME && AVMATCH(&argv[argc], &server->filename))
    {
        printf("Duplicate request, skipping.\n");
        free(file);
        free(cmd);
        return false;
    }
    else
    {
        printf("\n%s\n\n", cmd);
        fflush(stdout);
        server->filetime = now;
        free(server->filename.av_val);
        server->filename = argv[argc++];
        //spawn(argc, argv, cmd);
        free(cmd);
        body = oss.str();
        return true;
    }
}
static bool Invoke(RTMP *r, int32_t streamId, const std::function<void(char*&,char*)>& func)
{
    RTMPPacket packet;
    char pbuf[512], *pend = pbuf+sizeof(pbuf);

    packet.m_nChannel = 0x03;     // control channel (invoke)
    packet.m_headerType = 1; /* RTMP_PACKET_SIZE_MEDIUM; */
    packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
    packet.m_nTimeStamp = 0;
    packet.m_nInfoField2 = streamId;
    packet.m_hasAbsTimestamp = 0;
    packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

    char *enc = packet.m_body;
    func(enc, pend);

    packet.m_nBodySize = enc - packet.m_body;
    return RTMP_SendPacket(r, &packet, false);
}
static bool InvokeOnStatus(RTMP *r, int32_t streamId, const std::function<void(char*&,char*)>& func)
{
    return Invoke(r, streamId, [&](char* &enc, char* pend){
        enc = AMF_EncodeString(enc, pend, &av_onStatus);
        enc = AMF_EncodeNumber(enc, pend, 0);//transaction_id
        *enc++ = AMF_NULL;//args
        
        *enc++ = AMF_OBJECT;
        enc = AMF_EncodeNamedString(enc, pend, &av_level, &av_status);
        func(enc, pend);
        *enc++ = 0;
        *enc++ = 0;
        *enc++ = AMF_OBJECT_END;
    });
}
static void SendPlayStart(RTMP *r, int32_t streamId, AVal* playpath)
{
    RTMP_SendCtrl(r, RTMP_CTRL_STREAM_BEGIN, streamId, 0);
    InvokeOnStatus(r, streamId, [playpath](char* &enc, char* pend){
        enc = AMF_EncodeNamedString(enc, pend, &av_code, &av_NetStream_Play_Reset);
        enc = AMF_EncodeNamedString(enc, pend, &av_description, &av_Playing_resetting);
        enc = AMF_EncodeNamedString(enc, pend, &av_details, playpath);
        enc = AMF_EncodeNamedString(enc, pend, &av_clientid, &av_clientid);
    });
    InvokeOnStatus(r, streamId, [playpath](char* &enc, char* pend){
        enc = AMF_EncodeNamedString(enc, pend, &av_code, &av_NetStream_Play_Start);
        enc = AMF_EncodeNamedString(enc, pend, &av_description, &av_Started_playing);
        enc = AMF_EncodeNamedString(enc, pend, &av_details, playpath);
        enc = AMF_EncodeNamedString(enc, pend, &av_clientid, &av_clientid);
    });
    Invoke(r, streamId, [](char* &enc, char* pend){
        enc = AMF_EncodeString(enc, pend, &av_onStatus);

        *enc++ = AMF_OBJECT;
        enc = AMF_EncodeNamedString(enc, pend, &av_code, &av_NetStream_Data_Start);
        *enc++ = 0;
        *enc++ = 0;
        *enc++ = AMF_OBJECT_END;
    });
}
bool SendPlayStop(RTMP *r, int32_t streamId, AVal* playpath)
{
    return InvokeOnStatus(r, streamId, [playpath](char* &enc, char* pend){
        enc = AMF_EncodeNamedString(enc, pend, &av_code, &av_NetStream_Play_Stop);
        enc = AMF_EncodeNamedString(enc, pend, &av_description, &av_Stopped_playing);
        enc = AMF_EncodeNamedString(enc, pend, &av_details, playpath);
        enc = AMF_EncodeNamedString(enc, pend, &av_clientid, &av_clientid);
    });
}
static int SendPublishStart(RTMP *r, int32_t streamId)
{
    return InvokeOnStatus(r, streamId, [](char* &enc, char* pend){
        enc = AMF_EncodeNamedString(enc, pend, &av_code, &av_NetStream_Publish_Start);
        enc = AMF_EncodeNamedString(enc, pend, &av_description, &av_Started_publishing);
        enc = AMF_EncodeNamedString(enc, pend, &av_clientid, &av_clientid);
    });
}
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
    packet.m_headerType = 1; /* RTMP_PACKET_SIZE_MEDIUM; */
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

static int countAMF(AMFObject *obj, int *argc)
{
    int i, len;

    for (i=0, len=0; i < obj->o_num; i++)
    {
        AMFObjectProperty *p = &obj->o_props[i];
        len += 4;
        (*argc)+= 2;
        if (p->p_name.av_val)
            len += 1;
        len += 2;
        if (p->p_name.av_val)
            len += p->p_name.av_len + 1;
        switch(p->p_type)
        {
        case AMF_BOOLEAN:
            len += 1;
            break;
        case AMF_STRING:
            len += p->p_vu.p_aval.av_len;
            break;
        case AMF_NUMBER:
            len += 40;
            break;
        case AMF_OBJECT:
            len += 9;
            len += countAMF(&p->p_vu.p_object, argc);
            (*argc) += 2;
            break;
        case AMF_NULL:
        default:
            break;
        }
    }
    return len;
}
static void HandleInvoke(STREAMING_SERVER *server, RTMP * r, RTMPPacket *packet, unsigned offset)
{
    const char *body;
    unsigned int nBodySize;
    int nRes;

    body = packet->m_body + offset;
    nBodySize = packet->m_nBodySize - offset;

    if (body[0] != 0x02)		// make sure it is a string method name we start with
    {
        RTMP_Log(RTMP_LOGWARNING, "%s, Sanity failed. no string method in invoke packet",
            __FUNCTION__);
        return;
    }

    AMFObject obj;
    nRes = AMF_Decode(&obj, body, nBodySize, false);
    if (nRes < 0)
    {
        RTMP_Log(RTMP_LOGERROR, "%s, error decoding invoke packet", __FUNCTION__);
        return;
    }

    AMF_Dump(&obj);
    AVal method;
    AMFProp_GetString(AMF_GetProp(&obj, NULL, 0), &method);
    double txn = AMFProp_GetNumber(AMF_GetProp(&obj, NULL, 1));
    RTMP_Log(RTMP_LOGINFO, "%s, client invoking <%s>", __FUNCTION__, method.av_val);

    if (AVMATCH(&method, &av_connect))
    {
        AMFObject cobj;
        AVal pname, pval;
        int i;

        server->connect = packet->m_body;
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
                server->arglen += 6 + pval.av_len;
                server->argc += 2;
            }
            else if (AVMATCH(&pname, &av_flashVer))
            {
                r->Link.flashVer = pval;
                pval.av_val = NULL;
                server->arglen += 6 + pval.av_len;
                server->argc += 2;
            }
            else if (AVMATCH(&pname, &av_swfUrl))
            {
                r->Link.swfUrl = pval;
                pval.av_val = NULL;
                server->arglen += 6 + pval.av_len;
                server->argc += 2;
            }
            else if (AVMATCH(&pname, &av_tcUrl))
            {
                r->Link.tcUrl = pval;
                pval.av_val = NULL;
                server->arglen += 6 + pval.av_len;
                server->argc += 2;
            }
            else if (AVMATCH(&pname, &av_pageUrl))
            {
                r->Link.pageUrl = pval;
                pval.av_val = NULL;
                server->arglen += 6 + pval.av_len;
                server->argc += 2;
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
            server->arglen += countAMF(&r->Link.extras, &server->argc);
        }
        SendConnectResult(r, txn);
    }
    else if (AVMATCH(&method, &av_createStream))
    {
        static int32_t streamID = 0;
        SendResultNumber(r, txn, ++streamID);
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
        server->arglen += 6 + usherToken.av_len;
        server->argc += 2;
        r->Link.usherToken = usherToken;
    }
    else if (AVMATCH(&method, &av_publish))
    {
        AVal playpath, live={0};
        AMFProp_GetString(AMF_GetProp(&obj, NULL, 3), &playpath);
        if (obj.o_num > 4)
            AMFProp_GetString(AMF_GetProp(&obj, NULL, 4), &live);
        HUB_SetPublisher(std::string(playpath.av_val, playpath.av_len),
            r, packet->m_nInfoField2, AVMATCH(&live, &av_live));
        SendPublishStart(r, packet->m_nInfoField2);
    }
    else if (AVMATCH(&method, &av_play))
    {
        AVal playpath;
        double seekMs=-1000, lenMs=-1;
        AMFProp_GetString(AMF_GetProp(&obj, NULL, 3), &playpath);
        if (obj.o_num > 4)
            seekMs = AMFProp_GetNumber(AMF_GetProp(&obj, NULL, 4));
        if (obj.o_num > 5)
            lenMs = AMFProp_GetNumber(AMF_GetProp(&obj, NULL, 5));

        std::string body;
        SRC_ADDR src_addr={"127.0.0.1", _httpPort};
        if (SpawnPublisher(server, r, &playpath, src_addr, body)){
            SendPlayStart(r, packet->m_nInfoField2, &playpath);

            HUB_AddPlayer(std::string(playpath.av_val, playpath.av_len), 
                r, packet->m_nInfoField2, seekMs, lenMs);

            httplib::Client cli(src_addr.first, src_addr.second);
            auto res = cli.Post("/publish", body, "text/plain");
            if (!res || res->status >= 400)
                RTMP_Close(r);
        }
        RTMPPacket pc = {0};
        pc.m_body = server->connect;
        server->connect = NULL;
        RTMPPacket_Free(&pc);
    }
    else if (AVMATCH(&method, &av_deleteStream)
        || AVMATCH(&method, &av_FCUnpublish))
    {
        RTMP_Close(r);
    }
    AMF_Reset(&obj);
}
static void HandleChangeChunkSize(RTMP *r, const RTMPPacket *packet)
{
    if (packet->m_nBodySize >= 4)
    {
        r->m_inChunkSize = AMF_DecodeInt32(packet->m_body);
        RTMP_Log(RTMP_LOGDEBUG, "%s, received: chunk size change to %d", __FUNCTION__,
            r->m_inChunkSize);
    }
}
static void HandlePacket(STREAMING_SERVER *server, RTMP *rtmp, RTMPPacket *packet)
{
    RTMP_Log(RTMP_LOGINFO, "%s, received packet type %02X, size %u bytes", __FUNCTION__,
        packet->m_packetType, packet->m_nBodySize);

    switch (packet->m_packetType)
    {
    case RTMP_PACKET_TYPE_CHUNK_SIZE:
        HandleChangeChunkSize(rtmp, packet);
        break;

    case RTMP_PACKET_TYPE_BYTES_READ_REPORT:
        break;

    case RTMP_PACKET_TYPE_CONTROL:
        //      HandleCtrl(rtmp, packet);
        break;

    case RTMP_PACKET_TYPE_SERVER_BW:
        //      HandleServerBW(rtmp, packet);
        break;

    case RTMP_PACKET_TYPE_CLIENT_BW:
        //     HandleClientBW(rtmp, packet);
        break;

    case RTMP_PACKET_TYPE_AUDIO:
        HUB_PublishPacket(packet);
        break;

    case RTMP_PACKET_TYPE_VIDEO:
        HUB_PublishPacket(packet);
        break;

    case RTMP_PACKET_TYPE_FLEX_STREAM_SEND:
        break;

    case RTMP_PACKET_TYPE_FLEX_SHARED_OBJECT:
        break;

    case RTMP_PACKET_TYPE_FLEX_MESSAGE:
        {
            RTMP_Log(RTMP_LOGDEBUG, "%s, flex message, size %u bytes, not fully supported",
                __FUNCTION__, packet->m_nBodySize);
            //RTMP_LogHex(packet.m_body, packet.m_nBodySize);

            // some DEBUG code
            /*RTMP_LIB_AMFObject obj;
              int nRes = obj.Decode(packet.m_body+1, packet.m_nBodySize-1);
              if(nRes < 0) {
              RTMP_Log(RTMP_LOGERROR, "%s, error decoding AMF3 packet", __FUNCTION__);
            //return;
            }

            obj.Dump(); */

            HandleInvoke(server, rtmp, packet, 1);
            break;
        }
    case RTMP_PACKET_TYPE_INFO:
        HUB_PublishPacket(packet);
        break;

    case RTMP_PACKET_TYPE_SHARED_OBJECT:
        break;

    case RTMP_PACKET_TYPE_INVOKE:
        RTMP_Log(RTMP_LOGDEBUG, "%s, received: invoke %u bytes", __FUNCTION__,
            packet->m_nBodySize);
        //RTMP_LogHex(packet.m_body, packet.m_nBodySize);

        HandleInvoke(server, rtmp, packet, 0);
        break;

    case RTMP_PACKET_TYPE_FLASH_VIDEO:
        break;
    default:
        RTMP_Log(RTMP_LOGDEBUG, "%s, unknown packet type received: 0x%02x", __FUNCTION__,
            packet->m_packetType);
#ifdef _DEBUG
        RTMP_LogHex(RTMP_LOGDEBUG, packet->m_body, packet->m_nBodySize);
#endif
    }
}
static void* rtmp_client_thread(int sockfd, std::vector<st_thread_t>& join)
{
    STREAMING_SERVER server = {0};
    RTMPPacket packet = {0};

    RTMP rtmp;
    RTMP_Init(&rtmp);
    rtmp.m_sb.sb_socket = (int)(ssize_t)sockfd;

    if (!RTMP_Serve(&rtmp)) {
        RTMP_Log(RTMP_LOGERROR, "Handshake failed");
        goto cleanup;
    }

    while (_rtmpPort && RTMP_IsConnected(&rtmp)
        && RTMP_ReadPacket(&rtmp, &packet)) {
        if (RTMPPacket_IsReady(&packet) && packet.m_body) {
            HandlePacket(&server, &rtmp, &packet);
            RTMPPacket_Free(&packet);
        }
    }

cleanup:
    RTMP_LogPrintf("Closing connection... ");
    HUB_RemoveClient(&rtmp);
    RTMPPacket_Free(&packet);
    RTMP_Close(&rtmp);
    RTMP_LogPrintf("Closed connection");
    join.emplace_back(st_thread_self());
    return nullptr;
}

static void* rtmp_service(void*fd)
{
    int sockfd = (int)(ssize_t)fd;
    struct timeval tv={.tv_sec=1,.tv_usec=0};
    socklen_t optlen = sizeof(tv);
    getsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, &optlen);

    std::vector<st_thread_t> join;
    std::unordered_set<st_thread_t> childs;
    while (_rtmpPort) {
        if (!join.empty()) {
            for (auto& t: join) {
                st_thread_join(t, nullptr);
                childs.erase(t);
            }
            join.clear();
        }
        int clientfd = accept(sockfd, nullptr, nullptr);
        if (clientfd >= 0) {
            setsockopt(clientfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
            auto t = st_async([clientfd,&join]{
                return rtmp_client_thread(clientfd, join);
            }, true, 1024*1024);
            childs.emplace(t);
        }
    }
    close(sockfd);
    join.clear();
    for (auto& t : childs) st_thread_join(t, nullptr);
    return nullptr;
}

static void* rtmp_publish(RTMP* rtmp, FILE* fp)
{
    size_t bufSize = 1024*4;
    char *buf = (char*)malloc(bufSize);
    const uint32_t re = RTMP_GetTime();
    uint32_t startTs = 0;
    do {
        if (fread(buf, 1, 11, fp) != 11)
            break;
        uint32_t ts = AMF_DecodeInt24(buf+4);
        ts |= uint32_t(buf[7]) << 24;

        if (!startTs) startTs = ts;
        const uint32_t diff = (ts - startTs) - (RTMP_GetTime() -re);
        if (diff > 300 && diff < 3000) st_usleep(diff*1000);

        const size_t pktSize = AMF_DecodeInt24(buf+1) + 11;
        if (bufSize < pktSize)
            buf = (char*)realloc(buf, bufSize = pktSize);
        if (fseek(fp, -11, SEEK_CUR) != 0)
            break;
        if (fread(buf, 1, pktSize, fp) != pktSize)
            break;
        if (RTMP_Write(rtmp, buf, pktSize) != pktSize)
            break;
        if (fseek(fp, 4, SEEK_CUR) != 0)
            break;
    } while(_rtmpPort && !feof(fp));
clean:
    fclose(fp);
    RTMP_Close(rtmp);
    RTMP_Free(rtmp);
    if (buf) free(buf);
    return nullptr;
}
#define ERR_BREAK(x) { res.status = x; break; }
static st_thread_t OnServerPost(const httplib::Request& req, httplib::Response& res)
{
    int sockfd=-1, tmp=1;
    struct timeval tv={.tv_sec=1,.tv_usec=0};
    do {
        sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sockfd < 0)
            ERR_BREAK(503);

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &tmp, sizeof(tmp)) < 0)
            ERR_BREAK(503);

        if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
            ERR_BREAK(503);

        if (!_rtmpPort) _rtmpPort = 1935;
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port = htons(_rtmpPort);
        if (bind(sockfd, (struct sockaddr *) &addr, sizeof(addr)) < 0)
            ERR_BREAK(503);

        if (listen(sockfd, 10) < 0)
            ERR_BREAK(503);

        res.status = 201;
        return st_thread_create(rtmp_service, (void*)(ssize_t)sockfd, true, 0);
    } while(0);
    _rtmpPort = 0;
    if (sockfd >= 0) close(sockfd);
    return nullptr;
}
static void OnPublishPost(const httplib::Request& req, httplib::Response& res)
{
    FILE* fp=nullptr;
    RTMP* rtmp=nullptr;
    do {
        std::string url;{
            std::ostringstream oss;
            oss << "rtmp://" << req.get_header_value("REMOTE_ADDR")
                << ':' << _rtmpPort << req.body;
            url = oss.str();
        }
        if (!(rtmp = RTMP_Alloc())) ERR_BREAK(503);
        RTMP_Init(rtmp);
        if (!RTMP_SetupURL(rtmp, (char*)url.c_str())) ERR_BREAK(400);

        std::string file(rtmp->Link.playpath.av_val, rtmp->Link.playpath.av_len);
        if (HUB_IsLive(file)) {
            RTMP_Close(rtmp);
            RTMP_Free(rtmp);
            res.status = 200;
            return;
        }

        char buf[13];
        file.append(".flv");
        if (!(fp = fopen(file.c_str(), "rb"))) ERR_BREAK(404);
        if (fread(buf, 1, 13, fp) != 13
            || buf[0] != 'F' || buf[1] != 'L' || buf[2] != 'V')
            ERR_BREAK(500);

        RTMP_EnableWrite(rtmp);
        if (!RTMP_Connect(rtmp, nullptr) || !RTMP_ConnectStream(rtmp, 0))
            ERR_BREAK(422);

        st_async([rtmp, fp]{ return rtmp_publish(rtmp, fp); });
        res.status = 201;
        return;
    } while(0);
    if (fp) fclose(fp);
    if (rtmp) {
        RTMP_Close(rtmp);
        RTMP_Free(rtmp);
    }
}
#undef ERR_BREAK
/*
   POST server
   POST publish     body is URL
   GET server
   */

int main()
{
    if (st_init() < 0){
        perror("st_init");
        exit(1);
    }
    st_thread_t server = nullptr;
    httplib::Server http;
    //RTMP_debuglevel = RTMP_LOGINFO;
    http.Get("/", [&](const auto& req, auto& res){
        const char * help = 
            "curl -X POST 127.0.0.1:5562/server -d 1\n"
            "curl -X DELETE 127.0.0.1:5562/server\n"
            "./ffmpeg -f avfoundation -framerate 30 -i 0 -vcodec libx264 -f flv rtmp://127.0.0.1/app/xxx"
            "./rtmpdump  -r rtmp://127.0.0.1/app/xxx -o xxx.flv\n";
        res.set_content(help, "text/html");
    }).Post("/server", [&](const auto& req, auto& res) {
        server = OnServerPost(req, res);
    }).Delete("/server",[&](const auto& req, auto& res) {
        if (server) {
            _rtmpPort = 0;
            st_thread_join(server, nullptr);
            server = nullptr;
        }
        res.status = 204;
    }).Post("/publish", OnPublishPost);


    http.listen("*", _httpPort);
    return 0;
}
