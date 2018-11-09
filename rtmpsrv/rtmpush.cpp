#include <stdlib.h>
#include <stdio.h>
#include <librtmp/rtmp.h>
#include <librtmp/log.h>
#include <unistd.h>
//TODO: fork process to it
int main(int argc, char* argv[])
{
    char* file= argv[1];
    char* url = argv[2];
    RTMPPacket packet = {0};
    RTMP rtmp;
    RTMP_Init(&rtmp);
    //RTMP_LogSetLevel(RTMP_LOGDEBUG);
    if (!RTMP_SetupURL(&rtmp, url))
        return -1;
    RTMP_EnableWrite(&rtmp);
    if (!RTMP_Connect(&rtmp, nullptr))
        return -1;
    if (!RTMP_ConnectStream(&rtmp, 0))
        return -1;
    FILE* fp = fopen(file, "rb");
    fseek(fp, 0, SEEK_END);
    int flv_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *flv_buf = (char*)malloc(flv_size);
    fread(flv_buf, 1, flv_size, fp);
    if (RTMP_Write(&rtmp, flv_buf, flv_size) < 0)
        return -1;
    fclose(fp);
    free(flv_buf);
    while(true) sleep(1);
    RTMP_Close(&rtmp);
}
