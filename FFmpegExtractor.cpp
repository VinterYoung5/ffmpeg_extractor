/*
 * Copyright 2012 Michael Chen <omxcodec@gmail.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define LOG_NDEBUG 0
#define LOG_TAG "FFmpegExtractor"
#include <utils/Log.h>

#include <stdint.h>
#include <limits.h> /* INT_MAX */
#include <inttypes.h>

#include <utils/misc.h>
#include <utils/String8.h>
#include <cutils/properties.h>

#include <media/NdkMediaFormat.h>
#include <media/stagefright/MetaDataBase.h>
#include <media/stagefright/MediaBufferBase.h>	
#include <media/stagefright/MediaBufferGroup.h>
#include <media/stagefright/MediaErrors.h>
#include <media/stagefright/MetaData.h>
#include <media/stagefright/foundation/avc_utils.h>
#include <media/stagefright/foundation/ABuffer.h>
#include <media/stagefright/foundation/ADebug.h>
#include <media/stagefright/foundation/ABitReader.h>
#include <media/stagefright/foundation/AudioPresentationInfo.h>
#include <media/stagefright/foundation/ColorUtils.h>
#include <media/stagefright/foundation/MediaDefs.h>
#include <media/stagefright/foundation/hexdump.h>


#include "FFmpegExtractor.h"

#include "android/log.h"
#define FF_LOG_TAG                "starFFmpeg"
#define FF_LOG_VERBOSE            ANDROID_LOG_VERBOSE
#define FF_LOG_DEBUG              ANDROID_LOG_DEBUG
#define FF_LOG_INFO               ANDROID_LOG_INFO
#define FF_LOG_WARN               ANDROID_LOG_WARN
#define FF_LOG_ERROR              ANDROID_LOG_ERROR
#define FF_LOG_FATAL              ANDROID_LOG_FATAL
#define FF_LOG2ANDROID(level, TAG, ...)    ((void)__android_log_print(level, TAG, __VA_ARGS__))

#define SIZE_64KB 64 * 1024
#define EXTRACTOR_MAX_PROBE_PACKETS 200

static pthread_mutex_t s_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static int s_ref_count = 0;
enum {
    NO_SEEK = 0,
    SEEK,
};
#define min(a,b) ((a) < (b) ? (a) : (b))
namespace android {

////////////////////////////////////////////////////////////////////////////////

class FFmpegSource : public MediaTrackHelper {
public:
    explicit FFmpegSource(AMediaFormat *format, DataSourceHelper *dataSource, uint32_t trackId, Ffmpeg_stream_info *stream, buffer_data *mData,AVFormatContext *fc);
    virtual status_t init();

    virtual media_status_t start();
    virtual media_status_t stop();

    virtual media_status_t getFormat(AMediaFormat *);

    virtual media_status_t read(MediaBufferHelper **buffer, const ReadOptions *options = NULL);
//    bool supportsNonBlockingRead() override { return true; }
//    virtual media_status_t fragmentedRead(      MediaBufferHelper **buffer, const ReadOptions *options = NULL);

    virtual ~FFmpegSource();

private:
    uint32_t mTrackId;
    Mutex mLock;
    AVFormatContext *sourceFormatContext;
    AMediaFormat *mFormat;
    DataSourceHelper *mDataSource;
    buffer_data *mSourceIoData;
    Ffmpeg_stream_info stream_info;
    int32_t mTimescale;
    bool mStarted;
    bool mIsHeif;
    bool mIsAvif;
    int mSeekFlags;
    MediaBufferHelper *mBuffer;
    bool mEOF;

    FFmpegSource(const FFmpegSource &);
    FFmpegSource &operator=(const FFmpegSource &);
};

////////////////////////////////////////////////////////////////////////////////

FFmpegSource::FFmpegSource(
        AMediaFormat *format,
         DataSourceHelper *dataSource,
        uint32_t trackId, 
        Ffmpeg_stream_info *streamInfo,
        buffer_data  *mData,
        AVFormatContext *fc)
    : mFormat(format),
      mDataSource(dataSource),
      mStarted(false),
      mIsHeif(false),
      mTrackId(trackId),
      mIsAvif(false),
      mEOF(false),
      sourceFormatContext(fc)
    {
    ALOGE("%s %d",__FUNCTION__,__LINE__);
    const char *mime;
    mSourceIoData = NULL;
    stream_info.is_annexb = streamInfo->is_annexb;
    stream_info.bsf_ctx   = streamInfo->bsf_ctx;
    if (!mData) {
        mSourceIoData->source = mData->source;
        ALOGE("%s %d,source %p",__FUNCTION__,__LINE__,mSourceIoData->source);
    }
    bool success = AMediaFormat_getString(mFormat, AMEDIAFORMAT_KEY_MIME, &mime);
    ALOGE("%s %d, trackid %d ,mime %s,this %p,formatctx %p,dataSource %p, annexb %d bsf %p",__FUNCTION__,__LINE__,trackId,mime,this,fc,dataSource,stream_info.is_annexb,stream_info.bsf_ctx);
}

FFmpegSource::~FFmpegSource() {
    ALOGE("%s %d",__FUNCTION__,__LINE__);

}
status_t FFmpegSource::init() {
    ALOGE("%s %d",__FUNCTION__,__LINE__);
    return OK;
}

media_status_t FFmpegSource::start() {
    ALOGE("%s %d",__FUNCTION__,__LINE__);
    Mutex::Autolock autoLock(mLock);


    int32_t tmp;
    if (!AMediaFormat_getInt32(mFormat, AMEDIAFORMAT_KEY_MAX_INPUT_SIZE, &tmp)){
        tmp = 4 * 1024 * 1024;
        ALOGE("%s %d],not get maxinputsize set default %d",__FUNCTION__,__LINE__,tmp);
         
    }
    size_t max_size = tmp;

    // A somewhat arbitrary limit that should be sufficient for 8k video frames
    // If you see the message below for a valid input stream: increase the limit
    const size_t kMaxBufferSize = 64 * 1024 * 1024;
    if (max_size > kMaxBufferSize) {
        ALOGE("bogus max input size: %zu > %zu", max_size, kMaxBufferSize);
        return AMEDIA_ERROR_MALFORMED;
    }
    if (max_size == 0) {
        ALOGE("zero max input size");
        return AMEDIA_ERROR_MALFORMED;
    }

    // Allow up to kMaxBuffers, but not if the total exceeds kMaxBufferSize.
    const size_t kInitialBuffers = 2;
    const size_t kMaxBuffers = 8;
    const size_t realMaxBuffers = min(kMaxBufferSize / max_size, kMaxBuffers);
    mBufferGroup->init(kInitialBuffers, max_size, realMaxBuffers);


    
    mStarted = true;

    return AMEDIA_OK;
}

media_status_t FFmpegSource::stop() {
    ALOGE("%s %d",__FUNCTION__,__LINE__);

    return AMEDIA_OK;
}

media_status_t FFmpegSource::getFormat(AMediaFormat *meta) {
    ALOGE("%s %d",__FUNCTION__,__LINE__);

    Mutex::Autolock autoLock(mLock);
    AMediaFormat_copy(meta, mFormat);
    return AMEDIA_OK;
}

media_status_t FFmpegSource::read(
        MediaBufferHelper **out, const ReadOptions *options) {
    ALOGE("%s %d,",__FUNCTION__,__LINE__);

    Mutex::Autolock autoLock(mLock);
    AVPacket pkt1, *pkt = &pkt1;
    int ret = 0;
    int eof = 0;
    int read  = 0;
    int64_t pktTS = AV_NOPTS_VALUE;
    int key = 0;
    status_t err;
    AVCodecContext *avctx = NULL;
    AMediaFormat *meta = NULL;
    CHECK(mStarted);
    if (options != nullptr && options->getNonBlocking() && !mBufferGroup->has_buffers()) {
        ALOGE("%s %d",__FUNCTION__,__LINE__);
        *out = nullptr;
        return AMEDIA_ERROR_WOULD_BLOCK;
    }
    *out = NULL;
    int64_t targetSampleTimeUs = -1;

    int64_t seekTimeUs;
    ReadOptions::SeekMode mode;
    

    if (options && options->getSeekTo(&seekTimeUs, &mode)) {
        ALOGD("seekTimeUs:%" PRId64, seekTimeUs);

        mSeekFlags = AVSEEK_FLAG_BACKWARD;
        ret = avformat_seek_file(sourceFormatContext, -1, INT64_MIN, seekTimeUs, INT64_MAX, mSeekFlags);
        if (ret < 0) {
            ALOGE("%s: avformat_seek_file error");
        }

        if (mBuffer != NULL) {
            mBuffer->release();
            mBuffer = NULL;
        }

        // fall through
    }

    bool newBuffer = false;
    if (mBuffer == NULL) {    
        newBuffer = true;
        ALOGD(" codec type %d",sourceFormatContext->streams[mTrackId]->codecpar->codec_type);
        if (sourceFormatContext->streams[mTrackId]->codecpar->codec_type == AVMEDIA_TYPE_VIDEO) {
            ALOGD("[%s %d] video w %d, h %d",__FUNCTION__,__LINE__,sourceFormatContext->streams[mTrackId]->codec->width,sourceFormatContext->streams[mTrackId]->codec->height);
        } else{ 
            ALOGD("[%s %d] audio w %d, h %d",__FUNCTION__,__LINE__,sourceFormatContext->streams[mTrackId]->codec->width,sourceFormatContext->streams[mTrackId]->codec->height);
        }

        ret = av_read_frame(sourceFormatContext, pkt);
        if (ret == AVERROR_EOF) {
            eof = 1;
            mEOF = true;
            ALOGD("ret == AVERROR_EOF");
            av_free_packet(pkt);
            return AMEDIA_ERROR_END_OF_STREAM  ;
        } else if (ret == EAGAIN) {
            av_free_packet(pkt);
            return AMEDIA_OK;

        } else if (ret < 0) {
            ALOGD("ret 0x%x return AMEDIA_ERROR_UNKNOWN %d %d",ret,sourceFormatContext->streams[mTrackId]->codec->width,sourceFormatContext->streams[mTrackId]->codec->height);
            av_free_packet(pkt);
            return AMEDIA_ERROR_UNKNOWN;
        }
        ALOGD("read success");
        if (pkt->stream_index == mTrackId) {

        }

        err = mBufferGroup->acquire_buffer(&mBuffer);
        if (err != OK) {
            CHECK(mBuffer == NULL);
            av_free_packet(pkt);
            return AMEDIA_ERROR_UNKNOWN;
        }
        ALOGE("acquire_buffer: pkt %zu  buffer %zu", pkt->size, mBuffer->size());
        if (pkt->size > mBuffer->size()) {
            //ALOGE("buffer too small: pkt %zu > buffer %zu", pkt->size, mBuffer->size());
            mBuffer->release();
            mBuffer = NULL;
            av_free_packet(pkt);
            return AMEDIA_ERROR_UNKNOWN; // ERROR_BUFFER_TOO_SMALL
        }

    }
    ALOGD("raw read pkt, size:%d, key:%d, pts:%lld, dts:%lld",pkt->size, key, pkt->pts, pkt->dts);

    if (sourceFormatContext->streams[mTrackId]->codecpar->codec_type == AVMEDIA_TYPE_VIDEO) {
        
        if (!stream_info.is_annexb) {
            if (ret = av_bsf_send_packet(stream_info.bsf_ctx, eof ? NULL : pkt) < 0) {
                ALOGD("av_bsf_send_packet failed, ret=%d\n", ret);
                return AMEDIA_ERROR_UNKNOWN;
            } 
            while (true) {
                ret = av_bsf_receive_packet(stream_info.bsf_ctx, pkt);
                if (ret == AVERROR_EOF) {

                } else if (ret == AVERROR(EAGAIN)) {
                    
                } 
                ALOGD("filter read pkt, size:%d, key:%d, pts:%lld, dts:%lld,ret %d", pkt->size, key, pkt->pts, pkt->dts,ret);
                if (ret) break;
                //av_packet_unref(pkt);
            }
        }
    }

    {
        hexdump(pkt->data,pkt->size < 16 ? pkt->size : 16);

       memcpy(mBuffer->data(), pkt->data, pkt->size);

       key = pkt->flags & AV_PKT_FLAG_KEY ? 1 : 0;
       pktTS = pkt->pts;
       if (pkt->pts == AV_NOPTS_VALUE) {
           pktTS = pkt->dts;
       }
        meta = mBuffer->meta_data();
        AMediaFormat_clear(meta);
        AMediaFormat_setInt64(
                meta, AMEDIAFORMAT_KEY_TIME_US, ((long double)pktTS * 100));
        AMediaFormat_setInt32(
                meta, AMEDIAFORMAT_KEY_IS_SYNC_FRAME, key);
       
       ALOGD("read pkt, size:%d, key:%d, pts:%lld, dts:%lld",
                 pkt->size, key, pkt->pts, pkt->dts);
       *out = mBuffer;

       mBuffer = NULL;
       av_free_packet(pkt);
   }
    
    
    return AMEDIA_OK;
}

////////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////


FFmpegExtractor::FFmpegExtractor(DataSourceHelper *source)
    : mDataSource(source),
      mFirstTrack(NULL),
      mLastTrack(NULL) 
{
    ALOGD("FFmpegExtractor::FFmpegExtractor");
    mStream_info = {0};
    
    mFileMetaData = AMediaFormat_new();
    int ret = initStreams();
    if (ret < 0) {
        ALOGE("failed to init FFmpegExtractor");
        return;
    }
    mShowStatus = 1;
    //mIoData.source = NULL;

    // start reader here, as we want to extract extradata from bitstream if no extradata
    //startReaderThread();
/*
    while(mProbePkts <= EXTRACTOR_MAX_PROBE_PACKETS && !mEOF &&
        (mFormatCtx->pb ? !mFormatCtx->pb->error : 1) &&
        (mDefersToCreateVideoTrack || mDefersToCreateAudioTrack)) {
        // FIXME, I am so lazy! Should use pthread_cond_wait to wait conditions
        usleep(50000);
    }

    ALOGV("mProbePkts: %d, mEOF: %d, pb->error(if has): %d, mDefersToCreateVideoTrack: %d, mDefersToCreateAudioTrack: %d",
        mProbePkts, mEOF, mFormatCtx->pb ? mFormatCtx->pb->error : 0, mDefersToCreateVideoTrack, mDefersToCreateAudioTrack);
*/
    ALOGE("%s %d annexb %d, %p",__FUNCTION__,__LINE__,mStream_info.is_annexb,&mStream_info);

    mInitCheck = OK;
}

FFmpegExtractor::~FFmpegExtractor() {
    ALOGV("FFmpegExtractor::~FFmpegExtractor");
    Track *track = mFirstTrack;
    while (track) {
        Track *next = track->next;

        delete track;
        track = next;
    }
    mFirstTrack = mLastTrack = NULL;
    delete mDataSource;
    AMediaFormat_delete(mFileMetaData);
}

size_t FFmpegExtractor::countTracks() {
    status_t err;
    if ((err = readMetaData()) != AMEDIA_OK) {
        ALOGV("FFmpegExtractor::countTracks: no tracks");
        return 0;
    }

    size_t n = 0;
    Track *track = mFirstTrack;
    while (track) {
        ++n;
        track = track->next;
    }
    ALOGD("FFmpegExtractor::countTracks[%d]", n);

    return n;
}

MediaTrackHelper* FFmpegExtractor::getTrack(size_t index) {
    ALOGD("FFmpegExtractor::getTrack[%d]", index);
    status_t err;
    if ((err = readMetaData()) != OK) {
        return NULL;
    }

    Track *track = mFirstTrack;
    while (index > 0) {
        if (track == NULL) {
            return NULL;
        }

        track = track->next;
        --index;
    }

    if (track == NULL) {
        return NULL;
    }
    const char *mime;
    if (!AMediaFormat_getString(track->meta, AMEDIAFORMAT_KEY_MIME, &mime)) {
        return NULL;
    }
    ALOGD("%s %d,is_annexb %d,stream %p",__FUNCTION__,__LINE__,mStream_info.is_annexb,&mStream_info);

    FFmpegSource* source = new FFmpegSource(track->meta, mDataSource, track->trackId, &mStream_info, &mIoData, mFormatCtx);
    return source;
}

media_status_t FFmpegExtractor::getTrackMetaData(AMediaFormat *meta, size_t index, uint32_t flags) 
{
    
    ALOGD("%s %d,index %d,flags %d",__FUNCTION__,__LINE__,index,flags);
    
    Track *track = mFirstTrack;
    while (index > 0) {
        if (track == NULL) {
            return AMEDIA_ERROR_UNKNOWN;
        }

        track = track->next;
        --index;
    }

    if (track == NULL) {
        return AMEDIA_ERROR_UNKNOWN;
    }

    return AMediaFormat_copy(meta, track->meta);
}

media_status_t FFmpegExtractor::getMetaData(AMediaFormat *meta) {
    ALOGD("%s %d",__FUNCTION__,__LINE__);
    status_t err;
    if ((err = readMetaData()) != OK) {
        return AMEDIA_ERROR_UNKNOWN;
    }
    AMediaFormat_copy(meta, mFileMetaData);

    return AMEDIA_OK;
}

status_t FFmpegExtractor::readMetaData() {
    ALOGD("%s %d",__FUNCTION__,__LINE__);
    return AMEDIA_OK;
}

uint32_t FFmpegExtractor::flags() const {
    ALOGD("%s %d",__FUNCTION__,__LINE__);

    return 0;
}

// staitc
int FFmpegExtractor::decode_interrupt_cb(void *ctx)
{
    FFmpegExtractor *extrator = static_cast<FFmpegExtractor *>(ctx);
    return extrator->mAbortRequest;
}

int FFmpegExtractor::initStreams()
{
    int err = 0;
    int i = 0;
    status_t status = UNKNOWN_ERROR;
    int eof = 0;
    int ret = 0, audio_ret = -1, video_ret = -1;
    int pkt_in_play_range = 0;
    AVDictionaryEntry *avdict_entry = NULL;
    AVDictionary **opts = NULL;
    int orig_nb_streams = 0;
    int st_index[AVMEDIA_TYPE_NB] = {0};
    int wanted_stream[AVMEDIA_TYPE_NB] = {0};
    st_index[AVMEDIA_TYPE_AUDIO]  = -1;
    st_index[AVMEDIA_TYPE_VIDEO]  = -1;
    wanted_stream[AVMEDIA_TYPE_AUDIO]  = -1;
    wanted_stream[AVMEDIA_TYPE_VIDEO]  = -1;
    const char *mime = NULL;
    
    //initFFmpegDefaultOpts();

    AVIOContext *avio = NULL;
    //buffer_data file_data = {0};
    unsigned char* iobuffer = NULL;
    off64_t getsize = 0;

    status = initFFmpeg();
    if (status != OK) {
        ret = -1;
        return ret;
    }
    mFFmpegInited = true;

    mFormatCtx = avformat_alloc_context();
    if (!mFormatCtx)
    {
        ALOGE("oom for alloc avformat context");
        ret = -1;
        return ret;
    }

    mDataSource->getSize(&getsize);
    mIoData.size = getsize;
    mIoData.source = mDataSource;
    mIoData.offset = 0;

    ALOGD("%s %d.file offset %d , size %d file_data.source %p",__FUNCTION__,__LINE__,mIoData.offset,mIoData.size,mIoData.source);

    iobuffer = (uint8_t *)av_malloc(SIZE_64KB);
    if (!iobuffer) {
        ret = AVERROR(ENOMEM);
        return ret;
    }

    avio = avio_alloc_context(iobuffer, SIZE_64KB, 0, &mIoData, fill_iobuffer, NULL, seek_iobuffer);
    if (!avio) {
        ret = AVERROR(ENOMEM);
        return ret;
    }

    mFormatCtx->pb = avio;
    err = avformat_open_input(&mFormatCtx, NULL, NULL, NULL);

    //mFormatCtx->interrupt_callback.callback = decode_interrupt_cb;
    //mFormatCtx->interrupt_callback.opaque = this;
    //ALOGV("mFilename: %s", mFilename);
    AVDictionary *format_opts = NULL;
    //err = avformat_open_input(&mFormatCtx, mFilename, NULL, &format_opts);
    if (err < 0) {
        ALOGD("%s %d:%s avformat_open_input failed, err:%s",__FUNCTION__,__LINE__, mFilename, av_err2str(err));
        ret = -1;
        return ret;
    }

    if ((avdict_entry = av_dict_get(format_opts, "", NULL, AV_DICT_IGNORE_SUFFIX))) {
        ALOGE("Option %s not found.\n", avdict_entry->key);
        //ret = AVERROR_OPTION_NOT_FOUND;
        ret = -1;
        return ret;
    }

//    if (mGenPTS)
//        mFormatCtx->flags |= AVFMT_FLAG_GENPTS;

    AVDictionary *codec_opts = NULL;
    //opts = setup_find_stream_info_opts(mFormatCtx, &codec_opts);
    orig_nb_streams = mFormatCtx->nb_streams;

    err = avformat_find_stream_info(mFormatCtx, opts);
    if (err < 0) {
        ALOGE("%s: could not find stream info, err:%s", mFilename, av_err2str(err));
        ret = -1;
        return ret;
    }
//    for (i = 0; i < orig_nb_streams; i++)
//        av_dict_free(&opts[i]);
//    av_freep(&opts);

    if (mFormatCtx->pb)
        mFormatCtx->pb->eof_reached = 0; // FIXME hack, ffplay maybe should not use url_feof() to test for the end

    if (mSeekByBytes < 0)
        mSeekByBytes = !!(mFormatCtx->iformat->flags & AVFMT_TS_DISCONT);

    for (i = 0; i < (int)mFormatCtx->nb_streams; i++) {
        mFormatCtx->streams[i]->discard = AVDISCARD_ALL;
    }
    //if (!mVideoDisable)
        st_index[AVMEDIA_TYPE_VIDEO] =
            av_find_best_stream(mFormatCtx, AVMEDIA_TYPE_VIDEO,
                                wanted_stream[AVMEDIA_TYPE_VIDEO], -1, NULL, 0);
    //if (!mAudioDisable)
        st_index[AVMEDIA_TYPE_AUDIO] =
            av_find_best_stream(mFormatCtx, AVMEDIA_TYPE_AUDIO,
                                wanted_stream[AVMEDIA_TYPE_AUDIO],
                                st_index[AVMEDIA_TYPE_VIDEO],
                                NULL, 0);
    
    ALOGD("st_index V %d A %d",st_index[AVMEDIA_TYPE_VIDEO],st_index[AVMEDIA_TYPE_AUDIO]);
    if (mShowStatus) {
        av_dump_format(mFormatCtx, 0, mFilename, 0);
    }

    if (mFormatCtx->duration != AV_NOPTS_VALUE &&
            mFormatCtx->start_time != AV_NOPTS_VALUE) {
        int hours, mins, secs, us;

        ALOGD("file startTime: %lld", mFormatCtx->start_time);

        mDuration = mFormatCtx->duration;

        secs = mDuration / AV_TIME_BASE;
        us = mDuration % AV_TIME_BASE;
        mins = secs / 60;
        secs %= 60;
        hours = mins / 60;
        mins %= 60;
        ALOGD("the duration is %02d:%02d:%02d.%02d",
            hours, mins, secs, (100 * us) / AV_TIME_BASE);
    }

    packet_queue_init(&mVideoQ);
    packet_queue_init(&mAudioQ);

    if (st_index[AVMEDIA_TYPE_AUDIO] >= 0) {
        audio_ret = stream_component_open(st_index[AVMEDIA_TYPE_AUDIO]);
    }

    if (st_index[AVMEDIA_TYPE_VIDEO] >= 0) {
        video_ret = stream_component_open(st_index[AVMEDIA_TYPE_VIDEO]);
    }

    if (mFormatCtx->streams[st_index[AVMEDIA_TYPE_VIDEO]]->codecpar->codec_id == AV_CODEC_ID_H264) {
        mStream_info.is_annexb = strcmp(av_fourcc2str(mFormatCtx->streams[st_index[AVMEDIA_TYPE_VIDEO]]->codecpar->codec_tag), "avc1") == 0 ? false : true; //0x31637661 = "avc1"
        
//        ALOGD("is_annexb %d", mStream_info.is_annexb);  
//        if (mFormatCtx->streams[st_index[AVMEDIA_TYPE_VIDEO]]->codecpar->codec_tag == 0x31637661) {//avc1: nalusize+naludata :avcc mode
//            mStream_info.is_annexb = false;
//        } else if (mFormatCtx->streams[st_index[AVMEDIA_TYPE_VIDEO]]->codecpar->codec_tag == 0x34363248) {//h264:startcode+naludata:annexb mode
//            mStream_info.is_annexb = true;
//        }

        if (!mStream_info.is_annexb) {
            if (ret = open_bitstream_filter(mVideoStream, &mStream_info.bsf_ctx, "h264_mp4toannexb") < 0) {
                ALOGD("open_bitstream_filter failed, ret=%d", ret);  
                return -1;
            } else {
                ALOGD("open_bitstream_filter success"); 
            }
        }
        ALOGD("avc1, need to convert to annexb  0x%x, extra size %d,mStream_info.is_annexb %d bsf %p",
            mFormatCtx->streams[st_index[AVMEDIA_TYPE_VIDEO]]->codecpar->codec_tag,
            mFormatCtx->streams[st_index[AVMEDIA_TYPE_VIDEO]]->codecpar->extradata_size,
            mStream_info.is_annexb,mStream_info.bsf_ctx);   
    }
    

    AMediaFormat_setString(mFileMetaData,
            AMEDIAFORMAT_KEY_MIME, MEDIA_MIMETYPE_CONTAINER_MPEG4);
    if (mDuration != 0) {
        AMediaFormat_setInt64(mFileMetaData, AMEDIAFORMAT_KEY_DURATION, mDuration);
    }

    if ( audio_ret < 0 && video_ret < 0) {
        ALOGE("%s: could not open codecs\n", mFilename);
        ret = -1;
        return ret;
    }

    ret = 0;
    return ret;
}

void FFmpegExtractor::deInitStreams()
{
    packet_queue_destroy(&mVideoQ);
    packet_queue_destroy(&mAudioQ);

    if (mFormatCtx) {
        avformat_close_input(&mFormatCtx);
    }

    if (mFFmpegInited) {
        deInitFFmpeg();
    }
}

int FFmpegExtractor::open_bitstream_filter(AVStream *stream, AVBSFContext **bsf_ctx, const char *name) {
    int ret = 0;
    const AVBitStreamFilter *filter = av_bsf_get_by_name(name);
    if (!filter) {
        ret = -1;
        ALOGE("Unknow bitstream filter");
    }
    if((ret = av_bsf_alloc(filter, bsf_ctx) < 0)) {
        ALOGE("av_bsf_alloc failed");
        return ret;
    }
    if ((ret = avcodec_parameters_copy((*bsf_ctx)->par_in, stream->codecpar)) < 0) {
        ALOGE("avcodec_parameters_copy failed, ret=%d\n", ret);
        return ret;
    }
    if ((ret = av_bsf_init(*bsf_ctx)) < 0) {
        ALOGE("av_bsf_init failed, ret=%d", ret);       
        return ret;
    }
    return ret;
}
const char *codecId2MimeType(enum AVCodecID id) {
    const char * mime = NULL;
    switch (id) {
        case AV_CODEC_ID_MPEG2VIDEO:
            mime = MEDIA_MIMETYPE_VIDEO_MPEG2;
            break;
        case AV_CODEC_ID_MPEG4:
            mime = MEDIA_MIMETYPE_VIDEO_MPEG4;
            break;
        case AV_CODEC_ID_RAWVIDEO:
            mime = MEDIA_MIMETYPE_VIDEO_RAW;
            break;
        case AV_CODEC_ID_H263P:
            mime = MEDIA_MIMETYPE_VIDEO_H263;
            break;
        case AV_CODEC_ID_H263I:
            mime = MEDIA_MIMETYPE_VIDEO_H263;
            break;
        case AV_CODEC_ID_H264:
            mime = MEDIA_MIMETYPE_VIDEO_AVC;
            break;
        case AV_CODEC_ID_VP8:
            mime = MEDIA_MIMETYPE_VIDEO_VP8;
            break;
        case AV_CODEC_ID_VP9:
            mime = MEDIA_MIMETYPE_VIDEO_VP9;
            break;
        case AV_CODEC_ID_HEVC:
            mime = MEDIA_MIMETYPE_VIDEO_HEVC;
            break;
        case AV_CODEC_ID_AV1:
            mime = MEDIA_MIMETYPE_VIDEO_AV1;
            break;
        case AV_CODEC_ID_VVC:
            mime = "video/hvvc";
            break;
        //audio

        case AV_CODEC_ID_AAC:
        case AV_CODEC_ID_AAC_LATM:
            mime = MEDIA_MIMETYPE_AUDIO_AAC;
            break;
        
        case AV_CODEC_ID_QCELP:
            mime = MEDIA_MIMETYPE_AUDIO_QCELP;
            break;
        case AV_CODEC_ID_VORBIS:
            mime = MEDIA_MIMETYPE_AUDIO_VORBIS;
            break;
        case AV_CODEC_ID_OPUS:
            mime = MEDIA_MIMETYPE_AUDIO_OPUS;
            break;
        case AV_CODEC_ID_PCM_ALAW:
            mime = MEDIA_MIMETYPE_AUDIO_G711_ALAW;
            break;
        case AV_CODEC_ID_FLAC:
            mime = MEDIA_MIMETYPE_AUDIO_FLAC;
            break;
        case AV_CODEC_ID_AC3:
            mime = MEDIA_MIMETYPE_AUDIO_AC3;
            break;
        case AV_CODEC_ID_EAC3:
            mime = MEDIA_MIMETYPE_AUDIO_EAC3;
            break;
        case AV_CODEC_ID_ALAC:
            mime = MEDIA_MIMETYPE_AUDIO_ALAC;
            break;
        case AV_CODEC_ID_WMAV1:
        case AV_CODEC_ID_WMAV2:
        case AV_CODEC_ID_WMAPRO:
        case AV_CODEC_ID_WMALOSSLESS:
            mime = MEDIA_MIMETYPE_AUDIO_WMA;
            break;
        case AV_CODEC_ID_DTS:
            mime = MEDIA_MIMETYPE_AUDIO_DTS;
            break;

        default:
            mime  = "unknown_codec";
            break;
    }
    return mime;
}

//int FFmpegExtractor::getMimetypeByCodecId(int stream_id)

int FFmpegExtractor::stream_component_open(int stream_id)
{

    AVCodecParameters *codec_param = NULL;
    //AMediaFormat * meta = NULL;
    bool supported = false;
    uint32_t type = 0;
    const void *data = NULL;
    size_t size = 0;
    int ret = 0;
    int i = 0;

    ALOGD("[%s %d]stream_id: %d",__FUNCTION__,__LINE__, stream_id);

    if (stream_id < 0 || stream_id >= (int)mFormatCtx->nb_streams)
        return -1;
    codec_param = mFormatCtx->streams[stream_id]->codecpar;

//    supported = is_codec_supported(codec_param->codec_id);
//
//    if (!supported) {
//        ALOGE("unsupport the codec(%s)", avcodec_get_name(codec_param->codec_id));
//        return -1;
//    }
//    ALOGI("support the codec(%s)", avcodec_get_name(codec_param->codec_id));

    unsigned streamType;
//    for (size_t i = 0; i < mTracks.size(); ++i) {
//        if (stream_id == mTracks.editItemAt(i).trackId) {
//            ALOGE("this track already exists");
//            return 0;
//        }
//    }

    mFormatCtx->streams[stream_id]->discard = AVDISCARD_DEFAULT;

//    char tagbuf[32];
//    av_get_codec_tag_string(tagbuf, sizeof(tagbuf), codec_param->codec_tag);
//    ALOGV("Tag %s/0x%08x with codec(%s)\n", tagbuf, codec_param->codec_tag, avcodec_get_name(codec_param->codec_id));
    ALOGD("%s %d ",__FUNCTION__,__LINE__);

    switch (codec_param->codec_type) {
        case AVMEDIA_TYPE_VIDEO: {
            if (mVideoStreamIdx == -1)
                mVideoStreamIdx = stream_id;
            if (mVideoStream == NULL)
                mVideoStream = mFormatCtx->streams[stream_id];

    //        ret = check_extradata(codec_param);
    //        if (ret != 1) {
    //            if (ret == -1) {
    //                // disable the stream
    //                mVideoStreamIdx = -1;
    //                mVideoStream = NULL;
    //                packet_queue_end(&mVideoQ);
    //                mFormatCtx->streams[stream_id]->discard = AVDISCARD_ALL;
    //            }
    //            return ret;
    //        }

            if (codec_param->extradata) {
                ALOGV("video stream extradata: codec_param->extradata_size %d",codec_param->extradata_size);
                hexdump(codec_param->extradata, codec_param->extradata_size);
            } else {
                ALOGV("video stream no extradata, but we can ignore it.");
            }
            //
    //        meta = setVideoFormat(mVideoStream);
    //        if (meta == NULL) {
    //            ALOGE("setVideoFormat failed");
    //            return -1;
    //        }

            ALOGV("create a video track");
            //mTracks.push();
            //trackInfo = &mTracks.editItemAt(mTracks.size() - 1);
    //        trackInfo->trackId  = stream_id;
    //        trackInfo->meta   = meta;
    //        trackInfo->mStream = mVideoStream;
    //        trackInfo->mQueue  = &mVideoQ;

            Track *track = new Track;
            if (mLastTrack != NULL) {
                mLastTrack->next = track;
            } else {
                mFirstTrack = track;
            }
            mLastTrack = track;
            ALOGD("%s %d ",__FUNCTION__,__LINE__);
            track->meta = AMediaFormat_new();
            track->timescale = 1000000;
            track->trackId = stream_id;
            track->mStream = mVideoStream;
            const char* pMimeType = codecId2MimeType(mFormatCtx->streams[stream_id]->codec->codec_id);
            AMediaFormat_setInt32(track->meta, AMEDIAFORMAT_KEY_TRACK_ID, stream_id); 
            AMediaFormat_setString(track->meta, AMEDIAFORMAT_KEY_MIME, pMimeType);//"video/hevc");
            AMediaFormat_setInt32(track->meta, AMEDIAFORMAT_KEY_WIDTH,  mFormatCtx->streams[stream_id]->codec->width); 
            AMediaFormat_setInt32(track->meta, AMEDIAFORMAT_KEY_HEIGHT,  mFormatCtx->streams[stream_id]->codec->height); 
            if (mFormatCtx->streams[stream_id]->codec->bit_rate > 0){
                AMediaFormat_setInt32(track->meta, AMEDIAFORMAT_KEY_BIT_RATE,  mFormatCtx->streams[stream_id]->codec->bit_rate); 
            }

            if (mFormatCtx->streams[stream_id]->codec->extradata_size > 0) {
                ALOGD("%s %d have extradata",__FUNCTION__,__LINE__);
//                meta->setData(kKeyRawCodecSpecificData, 0, avctx->extradata, avctx->extradata_size);
            }
            
            //mDefersToCreateVideoTrack = false;
            break;
        }

        case AVMEDIA_TYPE_AUDIO: {
            if (mAudioStreamIdx == -1)
                mAudioStreamIdx = stream_id;
            if (mAudioStream == NULL)
                mAudioStream = mFormatCtx->streams[stream_id];
            if (codec_param->extradata) {
                ALOGV("audio stream extradata(%d):", codec_param->extradata_size);
                //hexdump(codec_param->extradata, codec_param->extradata_size);
            } else {
                ALOGV("audio stream no extradata, but we can ignore it.");
            }
            ALOGD("create a audio track");

            Track *track = new Track;
            if (mLastTrack != NULL) {
                mLastTrack->next = track;
            } else {
                mFirstTrack = track;
            }
            mLastTrack = track;
            
            track->meta = AMediaFormat_new();
            track->timescale = 1000000;
            track->trackId = stream_id;
            track->mStream = mAudioStream;
            const char* pMimeType =  codecId2MimeType(mFormatCtx->streams[stream_id]->codec->codec_id);
            AMediaFormat_setInt32(track->meta, AMEDIAFORMAT_KEY_TRACK_ID, stream_id); 
            AMediaFormat_setString(track->meta, AMEDIAFORMAT_KEY_MIME, pMimeType);
            AMediaFormat_setInt32(track->meta, AMEDIAFORMAT_KEY_CHANNEL_COUNT,  mFormatCtx->streams[stream_id]->codec->channels); 
            AMediaFormat_setInt32(track->meta, AMEDIAFORMAT_KEY_BITS_PER_SAMPLE,  mFormatCtx->streams[stream_id]->codec->bits_per_coded_sample); 
            AMediaFormat_setInt32(track->meta, AMEDIAFORMAT_KEY_BIT_RATE, mFormatCtx->streams[stream_id]->codec->bit_rate); 
            AMediaFormat_setInt32(track->meta, AMEDIAFORMAT_KEY_SAMPLE_RATE, mFormatCtx->streams[stream_id]->codec->sample_rate); 
            

            if (mFormatCtx->streams[stream_id]->codec->extradata_size > 0) {
                ALOGD("have extradata");
//                meta->setData(kKeyRawCodecSpecificData, 0, avctx->extradata, avctx->extradata_size);
            }

            break;
        }
        case AVMEDIA_TYPE_SUBTITLE:
            
            CHECK(!"Should not be here. Unsupported media type.");
            break;
        default:
            CHECK(!"Should not be here. Unsupported media type.");
            break;
        }

    return 0;
}


static CMediaExtractor* CreateExtractor(CDataSource *source, void *) {
    return wrap(new FFmpegExtractor(new DataSourceHelper(source)));
}
static int g_ffmpeg_loglevel = 0;
static void debugFFmpegExtractorConfidence(float *confidence) {
    char value[PROPERTY_VALUE_MAX];
    if (property_get("media.stagefright.ffmpegextractor.confidence", value, NULL)) {
        if (atof(value)) {
            float conf = (atof(value) > 1.0f) ? 1.0f : ((atof(value) <= 0) ? 0.0f : atof(value));
            ALOGD("[debug] set ffmpeg parser confidence from %.2f to %.2f", *confidence,conf);
            *confidence = conf;
        }
    }
}

// FFMPEG LOG LEVEL
// AV_LOG_QUIET    -8
// AV_LOG_PANIC     0
// AV_LOG_FATAL     8
// AV_LOG_ERROR    16
// AV_LOG_WARNING  24
// AV_LOG_INFO     32
// AV_LOG_VERBOSE  40
// AV_LOG_DEBUG    48
// AV_LOG_TRACE    56

static int debugFFmpegLoglevel() {
    int level = AV_LOG_ERROR;
    char value[PROPERTY_VALUE_MAX];
    if (property_get("media.stagefright.ffmpeg.loglevel", value, NULL)) {
        level = atoi(value);
        if (level <= AV_LOG_QUIET)
            level = AV_LOG_QUIET;
        else if (level <= AV_LOG_PANIC)
            level = AV_LOG_PANIC;
        else if (level <= AV_LOG_FATAL)
            level = AV_LOG_FATAL;
        else if (level <= AV_LOG_ERROR)
            level = AV_LOG_ERROR;
        else if (level <= AV_LOG_WARNING)
            level = AV_LOG_WARNING;
        else if (level <= AV_LOG_INFO)
            level = AV_LOG_INFO;
        else if (level <= AV_LOG_VERBOSE)
            level = AV_LOG_VERBOSE;
        else if (level <= AV_LOG_DEBUG)
            level = AV_LOG_DEBUG;
        else if (level <= AV_LOG_TRACE)
            level = AV_LOG_TRACE;
        else
            level = AV_LOG_ERROR;       
    }
    ALOGD("[debug] get ffmpeg log level %d", level); 
    return level;
}

static void ffmpeg_log_to_android_callback(void *ptr, int cur_level, const char *fmt, va_list vl)
{
    //int level_limit = debugFFmpegLoglevel();

    if (g_ffmpeg_loglevel < cur_level) {
        return;
    }
    int loglevel = FF_LOG_VERBOSE;
    if (cur_level <= AV_LOG_ERROR)
        loglevel = FF_LOG_ERROR;
    else if (cur_level <= AV_LOG_WARNING)
        loglevel = FF_LOG_WARN;
    else if (cur_level <= AV_LOG_INFO)
        loglevel = FF_LOG_INFO;
    else if (cur_level <= AV_LOG_VERBOSE)
        loglevel = FF_LOG_VERBOSE;
    else
        loglevel = FF_LOG_DEBUG;

    va_list vl2;
    char line[1024];
    static int print_prefix = 1;

    va_copy(vl2, vl);
    av_log_format_line(ptr, cur_level, fmt, vl2, line, sizeof(line), &print_prefix);
    va_end(vl2);
    FF_LOG2ANDROID(loglevel, FF_LOG_TAG, "%s", line);
}

void packet_queue_init(PacketQueue *q)
{
    memset(q, 0, sizeof(PacketQueue));
    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->cond, NULL);

    av_init_packet(&q->flush_pkt);
    q->flush_pkt.data = (uint8_t *)&q->flush_pkt;
    q->flush_pkt.size = 0;

    packet_queue_put(q, &q->flush_pkt);
}

void packet_queue_destroy(PacketQueue *q)
{
    packet_queue_flush(q);
    pthread_mutex_destroy(&q->mutex);
    pthread_cond_destroy(&q->cond);
}

void packet_queue_flush(PacketQueue *q)
{
    AVPacketList *pkt, *pkt1;

    pthread_mutex_lock(&q->mutex);
    for (pkt = q->first_pkt; pkt != NULL; pkt = pkt1) {
        pkt1 = pkt->next;
        av_free_packet(&pkt->pkt);
        av_freep(&pkt);
    }
    q->last_pkt = NULL;
    q->first_pkt = NULL;
    q->nb_packets = 0;
    q->size = 0;
    pthread_mutex_unlock(&q->mutex);
}

void packet_queue_end(PacketQueue *q)
{
    packet_queue_flush(q);
}

void packet_queue_abort(PacketQueue *q)
{
    pthread_mutex_lock(&q->mutex);

    q->abort_request = 1;

    pthread_cond_signal(&q->cond);

    pthread_mutex_unlock(&q->mutex);
}

int packet_queue_put(PacketQueue *q, AVPacket *pkt)
{
    AVPacketList *pkt1;

    /* duplicate the packet */
    if (pkt != &q->flush_pkt && av_dup_packet(pkt) < 0)
        return -1;

    pkt1 = (AVPacketList *)av_malloc(sizeof(AVPacketList));
    if (!pkt1)
        return -1;
    pkt1->pkt = *pkt;
    pkt1->next = NULL;

    pthread_mutex_lock(&q->mutex);

    if (!q->last_pkt)

        q->first_pkt = pkt1;
    else
        q->last_pkt->next = pkt1;
    q->last_pkt = pkt1;
    q->nb_packets++;
    //q->size += pkt1->pkt.size + sizeof(*pkt1);
    q->size += pkt1->pkt.size;
    pthread_cond_signal(&q->cond);

    pthread_mutex_unlock(&q->mutex);
    return 0;
}

int packet_queue_put_nullpacket(PacketQueue *q, int stream_index)
{
    AVPacket pkt1, *pkt = &pkt1;
    av_init_packet(pkt);
    pkt->data = NULL;
    pkt->size = 0;
    pkt->stream_index = stream_index;
    return packet_queue_put(q, pkt);
}

/* packet queue handling */
/* return < 0 if aborted, 0 if no packet and > 0 if packet.  */
int packet_queue_get(PacketQueue *q, AVPacket *pkt, int block)
{
    AVPacketList *pkt1;
    int ret;

    pthread_mutex_lock(&q->mutex);

    for (;;) {
        if (q->abort_request) {
            ret = -1;
            break;
        }

        pkt1 = q->first_pkt;
        if (pkt1) {
            q->first_pkt = pkt1->next;
            if (!q->first_pkt)
                q->last_pkt = NULL;
            q->nb_packets--;
            //q->size -= pkt1->pkt.size + sizeof(*pkt1);
            q->size -= pkt1->pkt.size;
            *pkt = pkt1->pkt;
            av_free(pkt1);
            ret = 1;
            break;
        } else if (!block) {
            ret = 0;
            break;
        } else {
            pthread_cond_wait(&q->cond, &q->mutex);
        }
    }
    pthread_mutex_unlock(&q->mutex);
    return ret;
}

media_status_t initFFmpeg() 
{
    media_status_t ret = AMEDIA_OK;
    g_ffmpeg_loglevel = debugFFmpegLoglevel();
    ALOGE("g_ffmpeg_loglevel %d",g_ffmpeg_loglevel);
    //av_log_set_level(fflog);
    av_log_set_callback(ffmpeg_log_to_android_callback);
/*
    pthread_mutex_lock(&s_init_mutex);
    if(s_ref_count == 0) {


        //avcodec_register_all();
        //av_register_all();
        //avformat_network_init();

        //ffmpeg_register_android_source();

//        if (av_lockmgr_register(lockmgr)) {
//            ALOGE("could not initialize lock manager!");
//            ret = NO_INIT;
//        }
    }

    // update counter
    s_ref_count++;

    pthread_mutex_unlock(&s_init_mutex);
*/
    return ret;
}

void deInitFFmpeg()
{
//    pthread_mutex_lock(&s_init_mutex);
//
//    // update counter
//    s_ref_count--;
//
//    if(s_ref_count == 0) {
//        av_lockmgr_register(NULL);
//        avformat_network_deinit();
//    }
//
//    pthread_mutex_unlock(&s_init_mutex);
}


int fill_iobuffer(void *opaque, uint8_t *buf, int read_size)
{
    buffer_data *bd = (buffer_data *)opaque;

    ALOGE("%s %d opaque %p, buf %p readsize %d, filesize %d offset %d,source %p",__FUNCTION__,__LINE__,opaque, buf, read_size,bd->size,bd->offset,bd->source);
    if (bd->offset < 0 || bd->size < bd->offset) {
        ALOGE("%s %d return bad size AVERROR_EOF %d",__FUNCTION__, __LINE__,AVERROR_EOF);
        return AVERROR_EOF;
    }

     read_size = read_size < (bd->size - bd->offset) ? read_size : (bd->size - bd->offset);
     if (read_size <= 0) {
        ALOGE("%s %d return eos",__FUNCTION__, __LINE__);
        return AVERROR_EOF;
     }
     //ALOGE("%s %d return eos ,read_size %d, (bd->size - bd->offset) %d",__FUNCTION__, __LINE__,read_size , (bd->size - bd->offset));
     // binder call time cost ? 
     if (bd->source->readAt(bd->offset, buf, read_size) < read_size) {
         ALOGE(" file read size %d",read_size);
         // need to rethink
         return AVERROR_BUFFER_TOO_SMALL;
     }
    bd->offset += read_size;
    ALOGE("%s %d offset %d",__FUNCTION__, __LINE__,bd->offset);
    //bd->offset = bd->offset < bd->size ? bd->offset : bd->size;
//    ALOGD("fill_iobuffer read_size %d dst %02x %02x %02x %02x %02x %02x %02x %02x    %02x %02x %02x %02x %02x %02x %02x %02x",read_size,
//       *(buf),*(buf+1),*(buf+2),*(buf+3),*(buf+4),*(buf+5),*(buf+6),*(buf+7),
//       *(buf+8),*(buf+9),*(buf+10),*(buf+11),*(buf+12),*(buf+13),*(buf+14),*(buf+15));

    return read_size;
}

int64_t seek_iobuffer(void *opaque, int64_t offset, int whence)
{
    buffer_data *bd = (buffer_data *)opaque;
    int64_t ret = -1;

    switch (whence) {
    case AVSEEK_SIZE:
        ret =  bd->size;
        break;
    case SEEK_SET:
        bd->offset = offset;
        ret = (int64_t)bd->offset;
        //ret = (int64_t)bd->source;
        break;
    default:
        ALOGE("%s %d  AVERROR_OPTION_NOT_FOUND",__FUNCTION__, __LINE__);
        break;
    }
    ALOGE("%s %d,opaque %p,  whence %d,readoffset %lld,bd %p,bd->size %d,source %p,bd->offset %d,ret 0x%llx",__FUNCTION__, __LINE__,opaque,whence,(long long)offset,bd, bd->size,bd->source,bd->offset,ret);
    
    return ret;
}

static bool SniffFFMPEGCommon(DataSourceHelper *source, float *confidence,const char *url) 
{
    int err = 0;
    bool ret = false;
    size_t i = 0;
    size_t nb_streams = 0;
    const char *container = NULL;
    AVFormatContext *ic = NULL;
    AVDictionary **opts = NULL;
    AVDictionary *codec_opts = NULL;
    buffer_data file_data = {0};
    AVIOContext *avio = NULL;
    //todo need to be free
    unsigned char* iobuffer = NULL;
    //unsigned char* url_ptr = NULL;
    off64_t getsize = 0;
    status_t status = initFFmpeg();
    if (status != OK) {
        ALOGE("could not init ffmpeg");
        return false;
    }

    ic = avformat_alloc_context();
    if (!ic)
    {
        ALOGE("oom for alloc avformat context");
        ret = false;
        goto fail;
    }
    //strtoll(url, url_ptr)
    //file_data.ptr = (uint8_t *)strtoll(url, NULL, 16);
    //source->getSize(&getsize);
    //file_data.size = getsize;
    //ALOGE(" file ptr %p , size %d ",file_data.ptr,file_data.size);
    iobuffer = (uint8_t *)av_malloc(SIZE_64KB);
    if (!iobuffer) {
        ret = AVERROR(ENOMEM);
        goto fail;
    }

    avio = avio_alloc_context(iobuffer, SIZE_64KB, 0, &file_data, fill_iobuffer, NULL, NULL);
    if (!avio) {
        ret = AVERROR(ENOMEM);
        goto fail;
    }

    ic->pb = avio;

    err = avformat_open_input(&ic, NULL, NULL, NULL);
    if (err < 0) {
        ALOGE("%s: avformat_open_input failed, err:%s", url, av_err2str(err));
        ret = false;
        goto fail;
    }

    //opts = setup_find_stream_info_opts(ic, codec_opts);
    nb_streams = ic->nb_streams;
    err = avformat_find_stream_info(ic, opts);
    if (err < 0) {
        ALOGE("%s: could not find stream info, err:%s", url, av_err2str(err));
        ret = false;
        goto fail;
    }
    for (i = 0; i < nb_streams; i++) {
        av_dict_free(&opts[i]);
    }
    av_freep(&opts);

    av_dump_format(ic, 0, url, 0);

    ALOGD("FFmpegExtrator, url: %s, format_name: %s, format_long_name: %s",
            url, ic->iformat->name, ic->iformat->long_name);

    //container = findMatchingContainer(ic->iformat->name);
    if (container) {
        //adjustContainerIfNeeded(&container, ic);
        //adjustConfidenceIfNeeded(container, ic, confidence);
    }
    ret = true;

fail:
    if (ic) {
        avformat_close_input(&ic);
    }
    if (status == OK) {
        //deInitFFmpeg();
    }

    return ret;
}


static bool SniffFFMPEGLocal(DataSourceHelper *source, float *confidence) 
{
    int err = 0;
    bool ret = false;
    size_t i = 0;
    size_t nb_streams = 0;
    const char *container = NULL;
    AVFormatContext *ic = NULL;
    AVDictionary **opts = NULL;
    AVDictionary *codec_opts = NULL;
    buffer_data file_data = {0};
    AVIOContext *avio = NULL;
    //todo need to be free?
    unsigned char* iobuffer = NULL;
    unsigned char* srcbuffer = NULL;
    //unsigned char* url_ptr = NULL;
    off64_t getsize = 0;

    status_t status = initFFmpeg();
    if (status != OK) {
        ALOGE("could not init ffmpeg");
        return false;
    }

    ic = avformat_alloc_context();
    if (!ic)
    {
        ALOGE("oom for alloc avformat context");
        ret = false;
        goto fail;
    }
    
    //file_data.ptr = (uint8_t *)ptr;
    source->getSize(&getsize);
    file_data.size = getsize;
    file_data.source = source;
    file_data.offset = 0;
    
    ALOGE("%s %d file offset %d , size %d file_data.source %p",__FUNCTION__,__LINE__,file_data.offset,file_data.size,file_data.source);
    iobuffer = (uint8_t *)av_malloc(SIZE_64KB);
    if (!iobuffer) {
        ret = AVERROR(ENOMEM);
        goto fail;
    }

    avio = avio_alloc_context(iobuffer, SIZE_64KB, 0, &file_data, fill_iobuffer, NULL, NULL);
    if (!avio) {
        ret = AVERROR(ENOMEM);
        goto fail;
    }

    ic->pb = avio;

    err = avformat_open_input(&ic, NULL, NULL, NULL);
    if (err < 0) {
        ALOGE("avformat_open_input failed, err:%s", av_err2str(err));
        ret = false;
        goto fail;
    }

    //opts = setup_find_stream_info_opts(ic, codec_opts);
    nb_streams = ic->nb_streams;
    //add by Vinter, limit timecost when find stream info
    ic->probesize = SIZE_64KB;
    ic->max_analyze_duration = AV_TIME_BASE;
    err = avformat_find_stream_info(ic, opts);
    if (err < 0) {
        ALOGE("could not find stream info, err:%s", av_err2str(err));
        ret = false;
        goto fail;
    }
//    for (i = 0; i < nb_streams; i++) {
//        av_dict_free(&opts[i]);
//    }
//    av_freep(&opts);

    av_dump_format(ic, 0, 0, 0);

    ALOGD("FFmpegExtrator, format_name: %s, format_long_name: %s",
             ic->iformat->name, ic->iformat->long_name);
    //todo
    //container = findMatchingContainer(ic->iformat->name);
    if (container) {
        //adjustContainerIfNeeded(&container, ic);
        //adjustConfidenceIfNeeded(container, ic, confidence);
    }
    ret = true;

fail:
    if (ic) {
        avformat_close_input(&ic);
    }
    if (status == OK) {
        //deInitFFmpeg();
    }

    return ret;
}

static bool LegacySniffFFMPEG(DataSourceHelper *source, float *confidence,const char *url) 
{
    bool ret = false;


    uint32_t hdr[2];
    off64_t offset = 0ll;
    if (source->readAt(offset, hdr, 8) < 8) {
        return false;
    }
    ALOGD("[%s %d]source head:0x%x 0x%x",__FUNCTION__,__LINE__, hdr[0],hdr[1]);
    ret = SniffFFMPEGCommon(source, confidence, url);
    if (ret) {
        //AMediaFormat_setString(meta, "extended-extractor-url", url);
    }

    return ret;
}

static CreatorFunc Sniff(
        CDataSource *source, float *confidence, void **,
        FreeMetaFunc *) {
    DataSourceHelper helper(source);
    ALOGE("[%s %d] [%s %s]yangwen source :%p ",__FUNCTION__,__LINE__,__DATE__,__TIME__, source->handle);
    char url[PATH_MAX] = {0};
    //snprintf(url, sizeof(url), "android:%p", source->handle);
    snprintf(url, sizeof(url), "%p", source->handle);


    if (SniffFFMPEGLocal(&helper, confidence) || true) {
        ALOGD("Identified supported ffmpeg through SniffFFMPEGLocal.");
        *confidence = 0.90;
        debugFFmpegExtractorConfidence(confidence);
        return CreateExtractor;
    } else if (LegacySniffFFMPEG(&helper, confidence, url)) {
        ALOGW("Identified supported ffmpeg through LegacySniffFFmpeg.");
        *confidence = 0.10;
        debugFFmpegExtractorConfidence(confidence);
        return CreateExtractor;
    }

    return NULL;
}

static const char *extensions[] = {
    "ogg",
    "oga",
    "opus",
    "3g2",
    "3ga",
    "3gp",
    "3gpp",
    "3gpp2",
    "m4a",
    "m4r",
    "m4v",
    "mov",
    "mp4",
    "qt",
    NULL
};

extern "C" {
// This is the only symbol that needs to be exported
__attribute__ ((visibility ("default")))
ExtractorDef GETEXTRACTORDEF() {
    return {
        EXTRACTORDEF_VERSION,
        UUID("e72b1c3b-9fde-4ee6-8519-fb3bfbcb5719"),
        1, // version
        "FFmpeg Extractor",
        { .v3 = {Sniff, extensions} },
    };
}

} // extern "C"



}  // namespace android


