nt main()
{
    RTMPPacket packet = {0};
    RTMP rtmp;
    RTMP_Init(&rtmp);
    RTMP_SetupURL(&rtmp, url);
    RTMP_EnableWrite(&rtmp);
    RTMP_Connect(&rtmp, nullptr);
    RTMP_ConnectStream(&rtmp, 0);

}
