#include "rtmp_prv.h"

#ifdef _WIN32
#define fseeko _fseeki64
#define ftello _ftelli64
#endif
SAVC2(setDataFrame, "@setDataFrame");
SAVC(onMetaData);
SAVC(duration);
static bool 
OpenResumeFile(
  FILE ** file,	// opened file [out]
  off_t * size,	// size of the file [out]
  char **metaHeader,	// meta data read from the file [out]
  uint32_t * nMetaHeaderSize,	// length of metaHeader [out]
  double *duration)	// duration of the stream in ms [out]
{
  size_t bufferSize = 0;
  char hbuf[16], *buffer = NULL;

  *nMetaHeaderSize = 0;
  *size = 0;

  fseek(*file, 0, SEEK_END);
  *size = ftello(*file);
  fseek(*file, 0, SEEK_SET);

  if (*size > 0)
  {
    // verify FLV format and read header
    uint32_t prevTagSize = 0;

    // check we've got a valid FLV file to continue!
    if (fread(hbuf, 1, 13, *file) != 13)
    {
      RTMP_Log(RTMP_LOGERROR, "Couldn't read FLV file header!");
      return false;
    }
    if (hbuf[0] != 'F' || hbuf[1] != 'L' || hbuf[2] != 'V'
      || hbuf[3] != 0x01)
    {
      RTMP_Log(RTMP_LOGERROR, "Invalid FLV file!");
      return false;
    }

    if ((hbuf[4] & 0x05) == 0)
    {
      RTMP_Log(RTMP_LOGERROR,
        "FLV file contains neither video nor audio, aborting!");
      return false;
    }

    uint32_t dataOffset = AMF_DecodeInt32(hbuf + 5);
    fseek(*file, dataOffset, SEEK_SET);

    if (fread(hbuf, 1, 4, *file) != 4)
    {
      RTMP_Log(RTMP_LOGERROR, "Invalid FLV file: missing first prevTagSize!");
      return false;
    }
    prevTagSize = AMF_DecodeInt32(hbuf);
    if (prevTagSize != 0)
    {
      RTMP_Log(RTMP_LOGWARNING,
        "First prevTagSize is not zero: prevTagSize = 0x%08X",
        prevTagSize);
    }

    // go through the file to find the meta data!
    off_t pos = dataOffset + 4;
    int bFoundMetaHeader = FALSE;

    while (pos < *size - 4 && !bFoundMetaHeader)
    {
      fseeko(*file, pos, SEEK_SET);
      if (fread(hbuf, 1, 4, *file) != 4)
        break;

      uint32_t dataSize = AMF_DecodeInt24(hbuf + 1);

      if (hbuf[0] == 0x12)
      {
        if (dataSize > bufferSize)
        {
          /* round up to next page boundary */
          bufferSize = dataSize + 4095;
          bufferSize ^= (bufferSize & 4095);
          free(buffer);
          buffer = malloc(bufferSize);
          if (!buffer)
            return false;
        }

        fseeko(*file, pos + 11, SEEK_SET);
        if (fread(buffer, 1, dataSize, *file) != dataSize)
          break;

        AMFObject metaObj;
        int nRes = AMF_Decode(&metaObj, buffer, dataSize, FALSE);
        if (nRes < 0)
        {
          RTMP_Log(RTMP_LOGERROR, "%s, error decoding meta data packet",
            __FUNCTION__);
          break;
        }

        AVal metastring;
        AMFProp_GetString(AMF_GetProp(&metaObj, NULL, 0), &metastring);

        if (AVMATCH(&metastring, &av_onMetaData))
        {
          AMF_Dump(&metaObj);

          *nMetaHeaderSize = dataSize;
          if (*metaHeader)
            free(*metaHeader);
          *metaHeader = (char *) malloc(*nMetaHeaderSize);
          memcpy(*metaHeader, buffer, *nMetaHeaderSize);

          // get duration
          AMFObjectProperty prop;
          if (RTMP_FindFirstMatchingProperty
            (&metaObj, &av_duration, &prop))
          {
            *duration = AMFProp_GetNumber(&prop);
            RTMP_Log(RTMP_LOGDEBUG, "File has duration: %f", *duration);
          }

          bFoundMetaHeader = TRUE;
          break;
        }
        //metaObj.Reset();
        //delete obj;
      }
      pos += (dataSize + 11 + 4);
    }

    free(buffer);
    if (!bFoundMetaHeader)
      RTMP_Log(RTMP_LOGWARNING, "Couldn't locate meta data!");
  }

  return true;
}

static bool
GetLastKeyframe(FILE * file,	// output file [in]
  int nSkipKeyFrames,	// max number of frames to skip when searching for key frame [in]
  uint32_t * dSeek,	// offset of the last key frame [out]
  char **initialFrame,	// content of the last keyframe [out]
  int *initialFrameType,	// initial frame type (audio/video) [out]
  uint32_t * nInitialFrameSize)	// length of initialFrame [out]
{
  char buffer[16];
  uint8_t dataType;
  int bAudioOnly;
  off_t size;

  fseek(file, 0, SEEK_END);
  size = ftello(file);

  fseek(file, 4, SEEK_SET);
  if (fread(&dataType, sizeof(uint8_t), 1, file) != 1)
    return false;

  bAudioOnly = (dataType & 0x4) && !(dataType & 0x1);

  RTMP_Log(RTMP_LOGDEBUG, "bAudioOnly: %d, size: %llu", bAudioOnly,
    (unsigned long long) size);

  // ok, we have to get the timestamp of the last keyframe (only keyframes are seekable) / last audio frame (audio only streams)

  //if(!bAudioOnly) // we have to handle video/video+audio different since we have non-seekable frames
  //{
  // find the last seekable frame
  off_t tsize = 0;
  uint32_t prevTagSize = 0;

  // go through the file and find the last video keyframe
  do
  {
    int xread;
skipkeyframe:
    if (size - tsize < 13)
    {
      RTMP_Log(RTMP_LOGERROR,
        "Unexpected start of file, error in tag sizes, couldn't arrive at prevTagSize=0");
      return false;
    }
    fseeko(file, size - tsize - 4, SEEK_SET);
    xread = fread(buffer, 1, 4, file);
    if (xread != 4)
    {
      RTMP_Log(RTMP_LOGERROR, "Couldn't read prevTagSize from file!");
      return false;
    }

    prevTagSize = AMF_DecodeInt32(buffer);
    //RTMP_Log(RTMP_LOGDEBUG, "Last packet: prevTagSize: %d", prevTagSize);

    if (prevTagSize == 0)
    {
      RTMP_Log(RTMP_LOGERROR, "Couldn't find keyframe to resume from!");
      return false;
    }

    if (prevTagSize < 0 || prevTagSize > size - 4 - 13)
    {
      RTMP_Log(RTMP_LOGERROR,
        "Last tag size must be greater/equal zero (prevTagSize=%d) and smaller then filesize, corrupt file!",
        prevTagSize);
      return false;
    }
    tsize += prevTagSize + 4;

    // read header
    fseeko(file, size - tsize, SEEK_SET);
    if (fread(buffer, 1, 12, file) != 12)
    {
      RTMP_Log(RTMP_LOGERROR, "Couldn't read header!");
      return false;
    }
    //*
#ifdef _DEBUG
    uint32_t ts = AMF_DecodeInt24(buffer + 4);
    ts |= (buffer[7] << 24);
    RTMP_Log(RTMP_LOGDEBUG, "%02X: TS: %d ms", buffer[0], ts);
#endif //*/

    // this just continues the loop whenever the number of skipped frames is > 0,
    // so we look for the next keyframe to continue with
    //
    // this helps if resuming from the last keyframe fails and one doesn't want to start
    // the download from the beginning
    //
    if (nSkipKeyFrames > 0
      && !(!bAudioOnly
        && (buffer[0] != 0x09 || (buffer[11] & 0xf0) != 0x10)))
    {
#ifdef _DEBUG
      RTMP_Log(RTMP_LOGDEBUG,
        "xxxxxxxxxxxxxxxxxxxxxxxx Well, lets go one more back!");
#endif
      nSkipKeyFrames--;
      goto skipkeyframe;
    }

  }
  while ((bAudioOnly && buffer[0] != 0x08) || (!bAudioOnly && (buffer[0] != 0x09 || (buffer[11] & 0xf0) != 0x10)));	// as long as we don't have a keyframe / last audio frame

  // save keyframe to compare/find position in stream
  *initialFrameType = buffer[0];
  *nInitialFrameSize = prevTagSize - 11;
  *initialFrame = (char *) malloc(*nInitialFrameSize);

  fseeko(file, size - tsize + 11, SEEK_SET);
  if (fread(*initialFrame, 1, *nInitialFrameSize, file) != *nInitialFrameSize)
  {
    RTMP_Log(RTMP_LOGERROR, "Couldn't read last keyframe, aborting!");
    return false;
  }

  *dSeek = AMF_DecodeInt24(buffer + 4);	// set seek position to keyframe tmestamp
  *dSeek |= (buffer[7] << 24);
  //}
  //else // handle audio only, we can seek anywhere we'd like
  //{
  //}

  if (*dSeek < 0)
  {
    RTMP_Log(RTMP_LOGERROR,
      "Last keyframe timestamp is negative, aborting, your file is corrupt!");
    return false;
  }
  RTMP_Log(RTMP_LOGDEBUG, "Last keyframe found at: %d ms, size: %d, type: %02X", *dSeek,
    *nInitialFrameSize, *initialFrameType);

  /*
  // now read the timestamp of the frame before the seekable keyframe:
  fseeko(file, size-tsize-4, SEEK_SET);
  if(fread(buffer, 1, 4, file) != 4) {
  RTMP_Log(RTMP_LOGERROR, "Couldn't read prevTagSize from file!");
  goto start;
  }
  uint32_t prevTagSize = RTMP_LIB::AMF_DecodeInt32(buffer);
  fseeko(file, size-tsize-4-prevTagSize+4, SEEK_SET);
  if(fread(buffer, 1, 4, file) != 4) {
  RTMP_Log(RTMP_LOGERROR, "Couldn't read previous timestamp!");
  goto start;
  }
  uint32_t timestamp = RTMP_LIB::AMF_DecodeInt24(buffer);
  timestamp |= (buffer[3]<<24);

  RTMP_Log(RTMP_LOGDEBUG, "Previous timestamp: %d ms", timestamp);
  */

  if (*dSeek != 0)
  {
    // seek to position after keyframe in our file (we will ignore the keyframes resent by the server
    // since they are sent a couple of times and handling this would be a mess)
    fseeko(file, size - tsize + prevTagSize + 4, SEEK_SET);

    // make sure the WriteStream doesn't write headers and ignores all the 0ms TS packets
    // (including several meta data headers and the keyframe we seeked to)
    //bNoHeader = TRUE; if bResume==true this is true anyway
  }

  //}
return true;
}

bool RTMP_ResetRead(RTMP *rtmp, FILE *flvFile, int nSkipKeyFrames)
{
  if (flvFile)
  {
    bool bResume = FALSE;		// true in resume mode
    uint32_t dSeek = 0;		// seek position in resume mode, 0 otherwise
    off_t size = 0;
    double duration = 0;

    // meta header and initial frame for the resume mode (they are read from the file and compared with
    // the stream we are trying to continue
    char *metaHeader = 0;
    uint32_t nMetaHeaderSize = 0;

    // video keyframe for matching
    char *initialFrame = 0;
    uint32_t nInitialFrameSize = 0;
    int initialFrameType = 0;	// tye: audio or video
    if (!OpenResumeFile(&flvFile, &size, &metaHeader, &nMetaHeaderSize, &duration))
      return false;
    if (!GetLastKeyframe(flvFile, nSkipKeyFrames,
        &dSeek, &initialFrame,&initialFrameType, &nInitialFrameSize))
      return false;

    if (bResume && nInitialFrameSize > 0)
      rtmp->m_read.flags |= RTMP_READ_RESUME;
    rtmp->m_read.timestamp = dSeek;
    rtmp->m_read.nResumeTS = dSeek;
    rtmp->m_read.metaHeader = metaHeader;
    rtmp->m_read.nMetaHeaderSize = nMetaHeaderSize;
    rtmp->m_read.initialFrameType = initialFrameType;
    rtmp->m_read.initialFrame = initialFrame;
    rtmp->m_read.nInitialFrameSize = nInitialFrameSize;
    rtmp->m_fDuration = duration;
  }
  return true;
}
uint32_t RTMP_GetReadTS(RTMP *r)
{
  return r->m_read.timestamp;
}
int RTMP_GetReadStatus(RTMP *r)
{
  return r->m_read.status;
}

#define MAX_IGNORED_FRAMES	50
static const char flvHeader[] = { 'F', 'L', 'V', 0x01,
  0x00,				/* 0x04 == audio, 0x01 == video */
  0x00, 0x00, 0x00, 0x09,
  0x00, 0x00, 0x00, 0x00
};
#define HEADERBUF	(128*1024)

static int ReadPacket(RTMPPacket *packet, RTMPReader* r, char *buf, int buflen)
{
  uint32_t prevTagSize = 0;
  int ret = 0;
  int recopy = FALSE;
  unsigned int size;
  char *ptr, *pend;
  uint32_t nTimeStamp = 0;
  unsigned int len;

  while (RTMPPacket_IsMedia(packet))
  {
    char *packetBody = packet->m_body;
    unsigned int nPacketLen = packet->m_nBodySize;

    const int setDataFrameLen = 1+2+av_setDataFrame.av_len;
    if (packet->m_packetType == RTMP_PACKET_TYPE_INFO && nPacketLen >= setDataFrameLen
      && strncmp(packetBody+1+2, av_setDataFrame.av_val, av_setDataFrame.av_len) == 0)
    {//skip av_setDataFrame
      packetBody += setDataFrameLen;
      nPacketLen -= setDataFrameLen;
    }

    /* Return RTMP_READ_COMPLETE if this was completed nicely with
     * invoke message Play.Stop or Play.Complete
    if (rtnGetNextMediaPacket == 2)
    {
      RTMP_Log(RTMP_LOGDEBUG,
        "Got Play.Complete or Play.Stop from server. "
        "Assuming stream is complete");
      ret = RTMP_READ_COMPLETE;
      break;
    }
    */

    r->dataType |= (((packet->m_packetType == RTMP_PACKET_TYPE_AUDIO) << 2) |
      (packet->m_packetType == RTMP_PACKET_TYPE_VIDEO));

    if (packet->m_packetType == RTMP_PACKET_TYPE_VIDEO && nPacketLen <= 5)
    {
      RTMP_Log(RTMP_LOGDEBUG, "ignoring too small video packet: size: %d",
        nPacketLen);
      ret = RTMP_READ_IGNORE;
      break;
    }
    if (packet->m_packetType == RTMP_PACKET_TYPE_AUDIO && nPacketLen <= 1)
    {
      RTMP_Log(RTMP_LOGDEBUG, "ignoring too small audio packet: size: %d",
        nPacketLen);
      ret = RTMP_READ_IGNORE;
      break;
    }

    if (r->flags & RTMP_READ_SEEKING)
    {
      ret = RTMP_READ_IGNORE;
      break;
    }
#ifdef _DEBUG
    RTMP_Log(RTMP_LOGDEBUG, "type: %02X, size: %d, TS: %d ms, abs TS: %d",
      packet->m_packetType, nPacketLen, packet->m_nTimeStamp,
      packet->m_hasAbsTimestamp);
    if (packet->m_packetType == RTMP_PACKET_TYPE_VIDEO)
      RTMP_Log(RTMP_LOGDEBUG, "frametype: %02X", (*packetBody & 0xf0));
#endif

    if (r->flags & RTMP_READ_RESUME)
    {
      /* check the header if we get one */
      if (packet->m_nTimeStamp == 0)
      {
        if (r->nMetaHeaderSize > 0
          && packet->m_packetType == RTMP_PACKET_TYPE_INFO)
        {
          AMFObject metaObj;
          int nRes =
            AMF_Decode(&metaObj, packetBody, nPacketLen, FALSE);
          if (nRes >= 0)
          {
            AVal metastring;
            AMFProp_GetString(AMF_GetProp(&metaObj, NULL, 0), &metastring);
            if (AVMATCH(&metastring, &av_setDataFrame))
              AMFProp_GetString(AMF_GetProp(&metaObj, NULL, 1), &metastring);

            if (AVMATCH(&metastring, &av_onMetaData))
            {
              /* compare */
              if ((r->nMetaHeaderSize != nPacketLen) ||
                (memcmp
                 (r->metaHeader, packetBody,
                  r->nMetaHeaderSize) != 0))
              {
                ret = RTMP_READ_ERROR;
              }
            }
            AMF_Reset(&metaObj);
            if (ret == RTMP_READ_ERROR)
              break;
          }
        }

        /* check first keyframe to make sure we got the right position
         * in the stream! (the first non ignored frame)
         */
        if (r->nInitialFrameSize > 0)
        {
          /* video or audio data */
          if (packet->m_packetType == r->initialFrameType
            && r->nInitialFrameSize == nPacketLen)
          {
            /* we don't compare the sizes since the packet can
             * contain several FLV packets, just make sure the
             * first frame is our keyframe (which we are going
             * to rewrite)
             */
            if (memcmp
              (r->initialFrame, packetBody,
               r->nInitialFrameSize) == 0)
            {
              RTMP_Log(RTMP_LOGDEBUG, "Checked keyframe successfully!");
              r->flags |= RTMP_READ_GOTKF;
              /* ignore it! (what about audio data after it? it is
               * handled by ignoring all 0ms frames, see below)
               */
              ret = RTMP_READ_IGNORE;
              break;
            }
          }

          /* hande FLV streams, even though the server resends the
           * keyframe as an extra video packet it is also included
           * in the first FLV stream chunk and we have to compare
           * it and filter it out !!
           */
          if (packet->m_packetType == RTMP_PACKET_TYPE_FLASH_VIDEO)
          {
            /* basically we have to find the keyframe with the
             * correct TS being nResumeTS
             */
            unsigned int pos = 0;
            uint32_t ts = 0;

            while (pos + 11 < nPacketLen)
            {
              /* size without header (11) and prevTagSize (4) */
              uint32_t dataSize =
                AMF_DecodeInt24(packetBody + pos + 1);
              ts = AMF_DecodeInt24(packetBody + pos + 4);
              ts |= (packetBody[pos + 7] << 24);

#ifdef _DEBUG
              RTMP_Log(RTMP_LOGDEBUG,
                "keyframe search: FLV Packet: type %02X, dataSize: %d, timeStamp: %d ms",
                packetBody[pos], dataSize, ts);
#endif
              /* ok, is it a keyframe?:
               * well doesn't work for audio!
               */
              if (packetBody[pos /*6928, test 0 */ ] ==
                r->initialFrameType
                /* && (packetBody[11]&0xf0) == 0x10 */ )
              {
                if (ts == r->nResumeTS)
                {
                  RTMP_Log(RTMP_LOGDEBUG,
                    "Found keyframe with resume-keyframe timestamp!");
                  if (r->nInitialFrameSize != dataSize
                    || memcmp(r->initialFrame,
                      packetBody + pos + 11,
                      r->nInitialFrameSize) != 0)
                  {
                    RTMP_Log(RTMP_LOGERROR,
                      "FLV Stream: Keyframe doesn't match!");
                    ret = RTMP_READ_ERROR;
                    break;
                  }
                  r->flags |= RTMP_READ_GOTFLVK;

                  /* skip this packet?
                   * check whether skippable:
                   */
                  if (pos + 11 + dataSize + 4 > nPacketLen)
                  {
                    RTMP_Log(RTMP_LOGWARNING,
                      "Non skipable packet since it doesn't end with chunk, stream corrupt!");
                    ret = RTMP_READ_ERROR;
                    break;
                  }
                  packetBody += (pos + 11 + dataSize + 4);
                  nPacketLen -= (pos + 11 + dataSize + 4);

                  goto stopKeyframeSearch;

                }
                else if (r->nResumeTS < ts)
                {
                  /* the timestamp ts will only increase with
                   * further packets, wait for seek
                   */
                  goto stopKeyframeSearch;
                }
              }
              pos += (11 + dataSize + 4);
            }
            if (ts < r->nResumeTS)
            {
              RTMP_Log(RTMP_LOGERROR,
                "First packet does not contain keyframe, all "
                "timestamps are smaller than the keyframe "
                "timestamp; probably the resume seek failed?");
            }
stopKeyframeSearch:
            ;
            if (!(r->flags & RTMP_READ_GOTFLVK))
            {
              RTMP_Log(RTMP_LOGERROR,
                "Couldn't find the seeked keyframe in this chunk!");
              ret = RTMP_READ_IGNORE;
              break;
            }
          }
        }
      }

      if (packet->m_nTimeStamp > 0
        && (r->flags & (RTMP_READ_GOTKF|RTMP_READ_GOTFLVK)))
      {
        /* another problem is that the server can actually change from
         * 09/08 video/audio packets to an FLV stream or vice versa and
         * our keyframe check will prevent us from going along with the
         * new stream if we resumed.
         *
         * in this case set the 'found keyframe' variables to true.
         * We assume that if we found one keyframe somewhere and were
         * already beyond TS > 0 we have written data to the output
         * which means we can accept all forthcoming data including the
         * change between 08/09 <-> FLV packets
         */
        r->flags |= (RTMP_READ_GOTKF|RTMP_READ_GOTFLVK);
      }

      /* skip till we find our keyframe
       * (seeking might put us somewhere before it)
       */
      if (!(r->flags & RTMP_READ_GOTKF) &&
        packet->m_packetType != RTMP_PACKET_TYPE_FLASH_VIDEO)
      {
        RTMP_Log(RTMP_LOGWARNING,
          "Stream does not start with requested frame, ignoring data... ");
        r->nIgnoredFrameCounter++;
        if (r->nIgnoredFrameCounter > MAX_IGNORED_FRAMES)
          ret = RTMP_READ_ERROR;	/* fatal error, couldn't continue stream */
        else
          ret = RTMP_READ_IGNORE;
        break;
      }
      /* ok, do the same for FLV streams */
      if (!(r->flags & RTMP_READ_GOTFLVK) &&
        packet->m_packetType == RTMP_PACKET_TYPE_FLASH_VIDEO)
      {
        RTMP_Log(RTMP_LOGWARNING,
          "Stream does not start with requested FLV frame, ignoring data... ");
        r->nIgnoredFlvFrameCounter++;
        if (r->nIgnoredFlvFrameCounter > MAX_IGNORED_FRAMES)
          ret = RTMP_READ_ERROR;
        else
          ret = RTMP_READ_IGNORE;
        break;
      }

      /* we have to ignore the 0ms frames since these are the first
       * keyframes; we've got these so don't mess around with multiple
       * copies sent by the server to us! (if the keyframe is found at a
       * later position there is only one copy and it will be ignored by
       * the preceding if clause)
       */
      if (!(r->flags & RTMP_READ_NO_IGNORE) &&
        packet->m_packetType != RTMP_PACKET_TYPE_FLASH_VIDEO)
      {
        /* exclude type RTMP_PACKET_TYPE_FLASH_VIDEO since it can
         * contain several FLV packets
         */
        if (packet->m_nTimeStamp == 0)
        {
          ret = RTMP_READ_IGNORE;
          break;
        }
        else
        {
          /* stop ignoring packets */
          r->flags |= RTMP_READ_NO_IGNORE;
        }
      }
    }

    /* calculate packet size and allocate slop buffer if necessary */
    size = nPacketLen +
      ((packet->m_packetType == RTMP_PACKET_TYPE_AUDIO
        || packet->m_packetType == RTMP_PACKET_TYPE_VIDEO
        || packet->m_packetType == RTMP_PACKET_TYPE_INFO) ? 11 : 0) +
      (packet->m_packetType != RTMP_PACKET_TYPE_FLASH_VIDEO ? 4 : 0);

    if (size + 4 > buflen)
    {
      /* the extra 4 is for the case of an FLV stream without a last
       * prevTagSize (we need extra 4 bytes to append it) */
      r->buf = malloc(size + 4);
      if (r->buf == 0)
      {
        RTMP_Log(RTMP_LOGERROR, "Couldn't allocate memory!");
        ret = RTMP_READ_ERROR;		/* fatal error */
        break;
      }
      recopy = TRUE;
      ptr = r->buf;
    }
    else
    {
      ptr = buf;
    }
    pend = ptr + size + 4;

    /* use to return timestamp of last processed packet */

    /* audio (0x08), video (0x09) or metadata (0x12) packets :
     * construct 11 byte header then add rtmp packet's data */
    if (packet->m_packetType == RTMP_PACKET_TYPE_AUDIO
      || packet->m_packetType == RTMP_PACKET_TYPE_VIDEO
      || packet->m_packetType == RTMP_PACKET_TYPE_INFO)
    {
      nTimeStamp = r->nResumeTS + packet->m_nTimeStamp;
      prevTagSize = 11 + nPacketLen;

      *ptr = packet->m_packetType;
      ptr++;
      ptr = AMF_EncodeInt24(ptr, pend, nPacketLen);

#if 0
      if(packet.m_packetType == RTMP_PACKET_TYPE_VIDEO) {

        /* H264 fix: */
        if((packetBody[0] & 0x0f) == 7) { /* CodecId = H264 */
          uint8_t packetType = *(packetBody+1);

          uint32_t ts = AMF_DecodeInt24(packetBody+2); /* composition time */
          int32_t cts = (ts+0xff800000)^0xff800000;
          RTMP_Log(RTMP_LOGDEBUG, "cts  : %d\n", cts);

          nTimeStamp -= cts;
          /* get rid of the composition time */
          CRTMP::EncodeInt24(packetBody+2, 0);
        }
        RTMP_Log(RTMP_LOGDEBUG, "VIDEO: nTimeStamp: 0x%08X (%d)\n", nTimeStamp, nTimeStamp);
      }
#endif

      ptr = AMF_EncodeInt24(ptr, pend, nTimeStamp);
      *ptr = (char)((nTimeStamp & 0xFF000000) >> 24);
      ptr++;

      /* stream id */
      ptr = AMF_EncodeInt24(ptr, pend, 0);
    }

    memcpy(ptr, packetBody, nPacketLen);
    len = nPacketLen;

    /* correct tagSize and obtain timestamp if we have an FLV stream */
    if (packet->m_packetType == RTMP_PACKET_TYPE_FLASH_VIDEO)
    {
      unsigned int pos = 0;
      int delta;

      /* grab first timestamp and see if it needs fixing */
      nTimeStamp = AMF_DecodeInt24(packetBody + 4);
      nTimeStamp |= (packetBody[7] << 24);
      delta = packet->m_nTimeStamp - nTimeStamp + r->nResumeTS;

      while (pos + 11 < nPacketLen)
      {
        /* size without header (11) and without prevTagSize (4) */
        uint32_t dataSize = AMF_DecodeInt24(packetBody + pos + 1);
        nTimeStamp = AMF_DecodeInt24(packetBody + pos + 4);
        nTimeStamp |= (packetBody[pos + 7] << 24);

        if (delta)
        {
          nTimeStamp += delta;
          AMF_EncodeInt24(ptr+pos+4, pend, nTimeStamp);
          ptr[pos+7] = nTimeStamp>>24;
        }

        /* set data type */
        r->dataType |= (((*(packetBody + pos) == RTMP_PACKET_TYPE_AUDIO) << 2) |
          (*(packetBody + pos) == RTMP_PACKET_TYPE_VIDEO));

        if (pos + 11 + dataSize + 4 > nPacketLen)
        {
          if (pos + 11 + dataSize > nPacketLen)
          {
            RTMP_Log(RTMP_LOGERROR,
              "Wrong data size (%u), stream corrupted, aborting!",
              dataSize);
            ret = RTMP_READ_ERROR;
            break;
          }
          RTMP_Log(RTMP_LOGWARNING, "No tagSize found, appending!");

          /* we have to append a last tagSize! */
          prevTagSize = dataSize + 11;
          AMF_EncodeInt32(ptr + pos + 11 + dataSize, pend,
            prevTagSize);
          size += 4;
          len += 4;
        }
        else
        {
          prevTagSize =
            AMF_DecodeInt32(packetBody + pos + 11 + dataSize);

#ifdef _DEBUG
          RTMP_Log(RTMP_LOGDEBUG,
            "FLV Packet: type %02X, dataSize: %lu, tagSize: %lu, timeStamp: %lu ms",
            (unsigned char)packetBody[pos], dataSize, prevTagSize,
            nTimeStamp);
#endif

          if (prevTagSize != (dataSize + 11))
          {
#ifdef _DEBUG
            RTMP_Log(RTMP_LOGWARNING,
              "Tag and data size are not consitent, writing tag size according to dataSize+11: %d",
              dataSize + 11);
#endif

            prevTagSize = dataSize + 11;
            AMF_EncodeInt32(ptr + pos + 11 + dataSize, pend,
              prevTagSize);
          }
        }

        pos += prevTagSize + 4;	/*(11+dataSize+4); */
      }
    }
    ptr += len;

    if (packet->m_packetType != RTMP_PACKET_TYPE_FLASH_VIDEO)
    {
      /* FLV tag packets contain their own prevTagSize */
      AMF_EncodeInt32(ptr, pend, prevTagSize);
    }

    /* In non-live this nTimeStamp can contain an absolute TS.
     * Update ext timestamp with this absolute offset in non-live mode
     * otherwise report the relative one
     */
    /* RTMP_Log(RTMP_LOGDEBUG, "type: %02X, size: %d, pktTS: %dms, TS: %dms, bLiveStream: %d",
     * packet.m_packetType, nPacketLen, packet.m_nTimeStamp, nTimeStamp, r->Link.lFlags & RTMP_LF_LIVE); */
    //r->timestamp = (r->Link.lFlags & RTMP_LF_LIVE) ? packet->m_nTimeStamp : nTimeStamp;
    r->timestamp = packet->m_nTimeStamp;

    ret = size;
    break;
  }

  if (recopy)
  {
    len = ret > buflen ? buflen : ret;
    memcpy(buf, r->buf, len);
    r->bufpos = r->buf + len;
    r->buflen = ret - len;
    return len;
  }
  return ret;
}
int RTMPPacket_Read(RTMPPacket *packet, RTMPReader* r, char *buf, int buflen)
{
  int nRead, total = 0;
  /* can't continue */
fail:
  switch (r->status) {
  case RTMP_READ_EOF:
  case RTMP_READ_COMPLETE:
    return 0;
  case RTMP_READ_ERROR:  /* corrupted stream, resume failed */
    SetSockError(EINVAL);
    return -1;
  default:
    break;
  }

  /* first time thru */
  if (!(r->flags & RTMP_READ_HEADER))
  {
    if (!(r->flags & RTMP_READ_RESUME)) 
    {
      if (!r->buf)
      {
        r->buf = malloc(HEADERBUF);
        memcpy(r->buf, flvHeader, sizeof(flvHeader));
        r->bufpos = r->buf + sizeof(flvHeader);
        r->buflen = HEADERBUF -  sizeof(flvHeader);
      }
      if (packet != NULL)
      {
        nRead = ReadPacket(packet, r, r->bufpos, r->buflen);
        packet = NULL;
        if (nRead < 0) 
        {
          free(r->buf);
          r->bufpos = r->buf = NULL;
          r->buflen = 0;
          r->status = nRead;
          goto fail;
        }
        /* buffer overflow, fix buffer and give up */
        if (r->bufpos < r->buf || r->bufpos > r->buf + HEADERBUF) {
          free(r->buf);
          r->bufpos = r->buf = NULL;
          r->buflen = 0;
          r->status = RTMP_READ_ERROR;
          goto fail;
        }
        r->bufpos += nRead;
        r->buflen -= nRead;
      }
      if (r->dataType != 5)
        return 0;
      r->buf[4] = r->dataType;
      r->buflen = r->bufpos - r->buf;
      r->bufpos = r->buf;
    }
    r->flags |= RTMP_READ_HEADER;
  }

  if ((r->flags & RTMP_READ_SEEKING) && r->buf)
  {
    /* drop whatever's here */
    free(r->buf);
    r->buf = NULL;
    r->bufpos = NULL;
    r->buflen = 0;
  }

  /* If there's leftover data buffered, use it up */
  if (r->buf)
  {
    nRead = r->buflen;
    if (nRead > buflen)
      nRead = buflen;
    memcpy(buf, r->bufpos, nRead);
    r->buflen -= nRead;
    if (!r->buflen)
    {
      free(r->buf);
      r->buf = NULL;
      r->bufpos = NULL;
    }
    else
    {
      r->bufpos += nRead;
    }
    total += nRead;
  }
  if (packet != NULL) {
    nRead = ReadPacket(packet, r, buf + total, buflen - total);
    if (nRead >= 0)
      total += nRead;
    else
      r->status = nRead;
  }
  return total;
}

int
RTMP_Read(RTMP *r, char *buf, int size)
{
  int total = 0;
  while (r->m_read.status >= 0 && size > total) {
    RTMPPacket packet = { 0 };
    total += RTMPPacket_Read(NULL, &r->m_read, buf + total, size - total);
    if (size >= total || RTMP_GetNextMediaPacket(r, &packet) < 0)
      break;
    total += RTMPPacket_Read(&packet, &r->m_read, buf + total, size - total);
    RTMPPacket_Free(&packet);
  }
  return total;
}
