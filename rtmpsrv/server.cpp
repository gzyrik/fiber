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
#include <st.h>
#define SAVC(x) static const AVal av_##x = AVC(#x)

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
static const AVal av_dquote = AVC("\"");
static const AVal av_escdquote = AVC("\\\"");
static const AVal av_NetStream_Play_Start = AVC("NetStream.Play.Start");
static const AVal av_Started_playing = AVC("Started playing");
static const AVal av_NetStream_Play_Stop = AVC("NetStream.Play.Stop");
static const AVal av_Stopped_playing = AVC("Stopped playing");
static const AVal av_NetStream_Authenticate_UsherToken = AVC("NetStream.Authenticate.UsherToken");
#undef AVC
#define STR2AVAL(av,str)	av.av_val = (char*)str; av.av_len = strlen(av.av_val)
#define DUPTIME	5000	/* interval we disallow duplicate requests, in msec */

typedef struct
{
    int socket;
    int state;
    int streamID;
    int arglen;
    int argc;
    uint32_t filetime;	/* time of last download we started */
    AVal filename;	/* name of last download */
    char *connect;
    st_thread_t thread;

} STREAMING_SERVER;
static void spawn_dumper(int argc, AVal *av, char *cmd){
}
static int SendPlayStart(RTMP *r)
{
  RTMPPacket packet;
  char pbuf[512], *pend = pbuf+sizeof(pbuf);

  packet.m_nChannel = 0x03;     // control channel (invoke)
  packet.m_headerType = 1; /* RTMP_PACKET_SIZE_MEDIUM; */
  packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
  packet.m_nTimeStamp = 0;
  packet.m_nInfoField2 = 0;
  packet.m_hasAbsTimestamp = 0;
  packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

  char *enc = packet.m_body;
  enc = AMF_EncodeString(enc, pend, &av_onStatus);
  enc = AMF_EncodeNumber(enc, pend, 0);
  *enc++ = AMF_OBJECT;

  enc = AMF_EncodeNamedString(enc, pend, &av_level, &av_status);
  enc = AMF_EncodeNamedString(enc, pend, &av_code, &av_NetStream_Play_Start);
  enc = AMF_EncodeNamedString(enc, pend, &av_description, &av_Started_playing);
  enc = AMF_EncodeNamedString(enc, pend, &av_details, &r->Link.playpath);
  enc = AMF_EncodeNamedString(enc, pend, &av_clientid, &av_clientid);
  *enc++ = 0;
  *enc++ = 0;
  *enc++ = AMF_OBJECT_END;

  packet.m_nBodySize = enc - packet.m_body;
  return RTMP_SendPacket(r, &packet, FALSE);
}
static int SendPlayStop(RTMP *r)
{
    RTMPPacket packet;
    char pbuf[512], *pend = pbuf+sizeof(pbuf);

    packet.m_nChannel = 0x03;     // control channel (invoke)
    packet.m_headerType = 1; /* RTMP_PACKET_SIZE_MEDIUM; */
    packet.m_packetType = RTMP_PACKET_TYPE_INVOKE;
    packet.m_nTimeStamp = 0;
    packet.m_nInfoField2 = 0;
    packet.m_hasAbsTimestamp = 0;
    packet.m_body = pbuf + RTMP_MAX_HEADER_SIZE;

    char *enc = packet.m_body;
    enc = AMF_EncodeString(enc, pend, &av_onStatus);
    enc = AMF_EncodeNumber(enc, pend, 0);
    *enc++ = AMF_OBJECT;

    enc = AMF_EncodeNamedString(enc, pend, &av_level, &av_status);
    enc = AMF_EncodeNamedString(enc, pend, &av_code, &av_NetStream_Play_Stop);
    enc = AMF_EncodeNamedString(enc, pend, &av_description, &av_Stopped_playing);
    enc = AMF_EncodeNamedString(enc, pend, &av_details, &r->Link.playpath);
    enc = AMF_EncodeNamedString(enc, pend, &av_clientid, &av_clientid);
    *enc++ = 0;
    *enc++ = 0;
    *enc++ = AMF_OBJECT_END;

    packet.m_nBodySize = enc - packet.m_body;
    return RTMP_SendPacket(r, &packet, FALSE);
}

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

    return RTMP_SendPacket(r, &packet, FALSE);
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
  enc = AMF_EncodeNumber(enc, pend, txn);
  *enc++ = AMF_NULL;
  enc = AMF_EncodeNumber(enc, pend, ID);

  packet.m_nBodySize = enc - packet.m_body;

  return RTMP_SendPacket(r, &packet, FALSE);
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
static void* rtmp_send_thread(void *rtmp)
{
    RTMP* r = (RTMP*)rtmp;
    FILE* fp = fopen("file.flv", "rb");
    fseek(fp, 0, SEEK_END);
    int flv_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *flv_buf = (char*)malloc(flv_size);
    fread(flv_buf, 1, flv_size, fp);
    RTMP_Write(r, flv_buf, flv_size);
    fclose(fp);
clean:
    RTMP_SendCtrl(r, 1, 1, 0);
    SendPlayStop(r);
    RTMP_Close(r);
    return NULL;
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
    nRes = AMF_Decode(&obj, body, nBodySize, FALSE);
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
        SendResultNumber(r, txn, ++server->streamID);
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
    else if (AVMATCH(&method, &av_play))
    {
        char *file, *p, *q, *cmd, *ptr;
        AVal *argv, av;
        int len, argc;
        uint32_t now;
        RTMPPacket pc = {0};
        AMFProp_GetString(AMF_GetProp(&obj, NULL, 3), &r->Link.playpath);
        if (!r->Link.playpath.av_len)
            return;
        /*
           r->Link.seekTime = AMFProp_GetNumber(AMF_GetProp(&obj, NULL, 4));
           if (obj.o_num > 5)
           r->Link.length = AMFProp_GetNumber(AMF_GetProp(&obj, NULL, 5));
           */
        if (r->Link.tcUrl.av_len)
        {
            len = server->arglen + r->Link.playpath.av_len + 4 +
                sizeof("rtmpdump") + r->Link.playpath.av_len + 12;
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
            argv[argc++].av_len = r->Link.tcUrl.av_len;

            if (r->Link.app.av_val)
            {
                argv[argc].av_val = ptr + 1;
                argv[argc++].av_len = 2;
                argv[argc].av_val = ptr + 5;
                ptr += sprintf(ptr, " -a \"%s\"", r->Link.app.av_val);
                argv[argc++].av_len = r->Link.app.av_len;
            }
            if (r->Link.flashVer.av_val)
            {
                argv[argc].av_val = ptr + 1;
                argv[argc++].av_len = 2;
                argv[argc].av_val = ptr + 5;
                ptr += sprintf(ptr, " -f \"%s\"", r->Link.flashVer.av_val);
                argv[argc++].av_len = r->Link.flashVer.av_len;
            }
            if (r->Link.swfUrl.av_val)
            {
                argv[argc].av_val = ptr + 1;
                argv[argc++].av_len = 2;
                argv[argc].av_val = ptr + 5;
                ptr += sprintf(ptr, " -W \"%s\"", r->Link.swfUrl.av_val);
                argv[argc++].av_len = r->Link.swfUrl.av_len;
            }
            if (r->Link.pageUrl.av_val)
            {
                argv[argc].av_val = ptr + 1;
                argv[argc++].av_len = 2;
                argv[argc].av_val = ptr + 5;
                ptr += sprintf(ptr, " -p \"%s\"", r->Link.pageUrl.av_val);
                argv[argc++].av_len = r->Link.pageUrl.av_len;
            }
            if (r->Link.usherToken.av_val)
            {
                argv[argc].av_val = ptr + 1;
                argv[argc++].av_len = 2;
                argv[argc].av_val = ptr + 5;
                ptr += sprintf(ptr, " -j \"%s\"", r->Link.usherToken.av_val);
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
                    r->Link.playpath.av_len, r->Link.playpath.av_val);
            argv[argc++].av_len = r->Link.playpath.av_len;

            av = r->Link.playpath;
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
            }
            else
            {
                printf("\n%s\n\n", cmd);
                fflush(stdout);
                server->filetime = now;
                free(server->filename.av_val);
                server->filename = argv[argc++];
                spawn_dumper(argc, argv, cmd);
            }

            free(cmd);
        }
        pc.m_body = server->connect;
        server->connect = NULL;
        RTMPPacket_Free(&pc);
        RTMP_SendCtrl(r, 0, 1, 0);
        SendPlayStart(r);
        server->thread = st_thread_create(rtmp_send_thread, (void*)r, TRUE, 0);
    }
    AMF_Reset(&obj);
}
static void HandlePacket(STREAMING_SERVER *server, RTMP *rtmp, RTMPPacket *packet)
{
    RTMP_Log(RTMP_LOGINFO, "%s, received packet type %02X, size %u bytes", __FUNCTION__,
            packet->m_packetType, packet->m_nBodySize);

    switch (packet->m_packetType)
    {
    case RTMP_PACKET_TYPE_CHUNK_SIZE:
        //      HandleChangeChunkSize(rtmp, packet);
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
        //RTMP_Log(RTMP_LOGDEBUG, "%s, received: audio %lu bytes", __FUNCTION__, packet.m_nBodySize);
        break;

    case RTMP_PACKET_TYPE_VIDEO:
        //RTMP_Log(RTMP_LOGDEBUG, "%s, received: video %lu bytes", __FUNCTION__, packet.m_nBodySize);
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
void* rtmp_service_thread(void*sockfd)
{
    STREAMING_SERVER server = {0};
    RTMPPacket packet = {0};
    RTMP rtmp;
    RTMP_Init(&rtmp);
    void *retvalp;
    rtmp.m_sb.sb_socket = (ssize_t)sockfd;
    if (!RTMP_Serve(&rtmp)) {
        RTMP_Log(RTMP_LOGERROR, "Handshake failed");
        goto cleanup;
    }
    while (RTMP_IsConnected(&rtmp) && RTMP_ReadPacket(&rtmp, &packet)) {
        if (!RTMPPacket_IsReady(&packet))
            continue;
        HandlePacket(&server, &rtmp, &packet);
        RTMPPacket_Free(&packet);
    }
cleanup:
    RTMP_LogPrintf("Closing connection... ");
    st_thread_join(server.thread, &retvalp);
    RTMP_Close(&rtmp);
    RTMP_LogPrintf("Closed connection");
    return NULL;
}
int main()
{
    struct sockaddr_in addr;
    int sockfd, tmp=1;
    const short port =1935;

    if (st_init() < 0){
        perror("st_init");
        exit(1);
    }
    RTMP_debuglevel = RTMP_LOGINFO;
    sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (char *) &tmp, sizeof(tmp) );

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr *) &addr, sizeof(struct sockaddr_in)) == -1)
    {
        RTMP_Log(RTMP_LOGERROR, "%s, TCP bind failed for port number: %d", __FUNCTION__,
                port);
        exit(1);
    }

    if (listen(sockfd, 10) == -1)
    {
        RTMP_Log(RTMP_LOGERROR, "%s, listen failed", __FUNCTION__);
        close(sockfd);
        exit(1);
    }

    while(1) {
        socklen_t addrlen = sizeof(struct sockaddr_in);
        ssize_t clientfd = (ssize_t)accept(sockfd, (struct sockaddr *) &addr, &addrlen);
        if (clientfd >=0) st_thread_create(rtmp_service_thread, (void*)clientfd, 0, 0);
    }
    st_thread_exit(NULL);
    return 0;
}
