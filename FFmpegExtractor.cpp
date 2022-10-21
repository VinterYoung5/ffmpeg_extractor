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


#include "FFmpegExtractor.h"

#include "android/log.h"
#define FF_LOG_TAG               "starFFmpeg"
#define FF_LOG_VERBOSE            ANDROID_LOG_VERBOSE
#define FF_LOG_DEBUG              ANDROID_LOG_DEBUG
#define FF_LOG_INFO               ANDROID_LOG_INFO
#define FF_LOG_WARN               ANDROID_LOG_WARN
#define FF_LOG_ERROR              ANDROID_LOG_ERROR
#define FF_LOG_FATAL              ANDROID_LOG_FATAL
#define FFLOG(level, TAG, ...)    ((void)__android_log_print(level, TAG, __VA_ARGS__))

#define EXTRACTOR_MAX_PROBE_PACKETS 200
enum {
    NO_SEEK = 0,
    SEEK,
};
static pthread_mutex_t s_init_mutex = PTHREAD_MUTEX_INITIALIZER;
static int s_ref_count = 0;

namespace android {

////////////////////////////////////////////////////////////////////////////////

FFmpegExtractor::FFmpegExtractor(DataSourceHelper *source)
    : mDataSource(source),
      mFirstTrack(NULL),
      mLastTrack(NULL) 
{
    mFileMetaData = AMediaFormat_new();
    ALOGV("yangwen constuct ffmpeg extractor");
    int ret = initStreams();
    if (ret < 0) {
        ALOGE("failed to init ffmpeg");
        return;
    }

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
    mInitCheck = OK;
}

FFmpegExtractor::~FFmpegExtractor() {
    ALOGV("FFmpegExtractor::~FFmpegExtractor");
}

size_t FFmpegExtractor::countTracks() {
    return 0;
}

MediaTrackHelper* FFmpegExtractor::getTrack(size_t index) {
    ALOGV("FFmpegExtractor::getTrack[%d]", index);
    Track *track = mFirstTrack;
    return new FFmpegSource(track->meta, this, track->trackId, track->timescale);
}

media_status_t FFmpegExtractor::getTrackMetaData(AMediaFormat *meta, size_t index, uint32_t flags) 
{
    return AMEDIA_OK;
}

media_status_t FFmpegExtractor::getMetaData(AMediaFormat *meta) {

    return AMEDIA_OK;
}

uint32_t FFmpegExtractor::flags() const {
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
    AVDictionaryEntry *t = NULL;
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
    mFormatCtx->interrupt_callback.callback = decode_interrupt_cb;
    mFormatCtx->interrupt_callback.opaque = this;
    ALOGV("mFilename: %s", mFilename);
    AVDictionary *format_opts = NULL;
    err = avformat_open_input(&mFormatCtx, mFilename, NULL, &format_opts);
    if (err < 0) {
        ALOGE("%s: avformat_open_input failed, err:%s", mFilename, av_err2str(err));
        ret = -1;
        return ret;
    }

    if ((t = av_dict_get(format_opts, "", NULL, AV_DICT_IGNORE_SUFFIX))) {
        ALOGE("Option %s not found.\n", t->key);
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
    for (i = 0; i < orig_nb_streams; i++)
        av_dict_free(&opts[i]);
    av_freep(&opts);

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
//    if (mShowStatus) {
//        av_dump_format(mFormatCtx, 0, mFilename, 0);
//    }

    if (mFormatCtx->duration != AV_NOPTS_VALUE &&
            mFormatCtx->start_time != AV_NOPTS_VALUE) {
        int hours, mins, secs, us;

        ALOGV("file startTime: %lld", mFormatCtx->start_time);

        mDuration = mFormatCtx->duration;

        secs = mDuration / AV_TIME_BASE;
        us = mDuration % AV_TIME_BASE;
        mins = secs / 60;
        secs %= 60;
        hours = mins / 60;
        mins %= 60;
        ALOGI("the duration is %02d:%02d:%02d.%02d",
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

int FFmpegExtractor::stream_component_open(int stream_index)
{
    /*
    Track *trackInfo = NULL;
    AVCodecParameters *avctx = NULL;
    AMediaFormat * meta = NULL;
    bool supported = false;
    uint32_t type = 0;
    const void *data = NULL;
    size_t size = 0;
    int ret = 0;

    ALOGI("stream_index: %d", stream_index);
    if (stream_index < 0 || stream_index >= (int)mFormatCtx->nb_streams)
        return -1;
    avctx = mFormatCtx->streams[stream_index]->codecpar;

    supported = is_codec_supported(avctx->codec_id);

    if (!supported) {
        ALOGE("unsupport the codec(%s)", avcodec_get_name(avctx->codec_id));
        return -1;
    }
    ALOGI("support the codec(%s)", avcodec_get_name(avctx->codec_id));

    unsigned streamType;
    for (size_t i = 0; i < mTracks.size(); ++i) {
        if (stream_index == mTracks.editItemAt(i).trackId) {
            ALOGE("this track already exists");
            return 0;
        }
    }

    mFormatCtx->streams[stream_index]->discard = AVDISCARD_DEFAULT;

//    char tagbuf[32];
//    av_get_codec_tag_string(tagbuf, sizeof(tagbuf), avctx->codec_tag);
//    ALOGV("Tag %s/0x%08x with codec(%s)\n", tagbuf, avctx->codec_tag, avcodec_get_name(avctx->codec_id));

    switch (avctx->codec_type) {
    case AVMEDIA_TYPE_VIDEO:
        if (mVideoStreamIdx == -1)
            mVideoStreamIdx = stream_index;
        if (mVideoStream == NULL)
            mVideoStream = mFormatCtx->streams[stream_index];

        ret = check_extradata(avctx);
        if (ret != 1) {
            if (ret == -1) {
                // disable the stream
                mVideoStreamIdx = -1;
                mVideoStream = NULL;
                packet_queue_end(&mVideoQ);
                mFormatCtx->streams[stream_index]->discard = AVDISCARD_ALL;
            }
            return ret;
         }

        if (avctx->extradata) {
            ALOGV("video stream extradata:");
            //hexdump(avctx->extradata, avctx->extradata_size);
        } else {
            ALOGV("video stream no extradata, but we can ignore it.");
        }

//        meta = setVideoFormat(mVideoStream);
//        if (meta == NULL) {
//            ALOGE("setVideoFormat failed");
//            return -1;
//        }

        ALOGV("create a video track");
        mTracks.push();
        trackInfo = &mTracks.editItemAt(mTracks.size() - 1);
        trackInfo->trackId  = stream_index;
        trackInfo->meta   = meta;
        trackInfo->mStream = mVideoStream;
        trackInfo->mQueue  = &mVideoQ;

        mDefersToCreateVideoTrack = false;

        break;
    case AVMEDIA_TYPE_AUDIO:
        if (mAudioStreamIdx == -1)
            mAudioStreamIdx = stream_index;
        if (mAudioStream == NULL)
            mAudioStream = mFormatCtx->streams[stream_index];

        ret = check_extradata(avctx);
        if (ret != 1) {
            if (ret == -1) {
                // disable the stream
                mAudioStreamIdx = -1;
                mAudioStream = NULL;
                packet_queue_end(&mAudioQ);
                mFormatCtx->streams[stream_index]->discard = AVDISCARD_ALL;
            }
            return ret;
        }

        if (avctx->extradata) {
            ALOGV("audio stream extradata(%d):", avctx->extradata_size);
            //hexdump(avctx->extradata, avctx->extradata_size);
        } else {
            ALOGV("audio stream no extradata, but we can ignore it.");
        }

//        meta = setAudioFormat(mAudioStream);
//        if (meta == NULL) {
//            ALOGE("setAudioFormat failed");
//            return -1;
//        }

        ALOGV("create a audio track");
        mTracks.push();
        trackInfo = &mTracks.editItemAt(mTracks.size() - 1);
        trackInfo->trackId  = stream_index;
        trackInfo->meta   = meta;
        trackInfo->mStream = mAudioStream;
        trackInfo->mQueue  = &mAudioQ;

        mDefersToCreateAudioTrack = false;

        break;
    case AVMEDIA_TYPE_SUBTITLE:
        
        CHECK(!"Should not be here. Unsupported media type.");
        break;
    default:
        CHECK(!"Should not be here. Unsupported media type.");
        break;
    }
*/
    return 0;
}


////////////////////////////////////////////////////////////////////////////////

FFmpegSource::FFmpegSource(
        AMediaFormat *format,
        FFmpegExtractor *extractor,
        uint32_t trackId, int32_t timeScale)
    {

}

FFmpegSource::~FFmpegSource() {

}

media_status_t FFmpegSource::start() {
    return AMEDIA_OK;
}

media_status_t FFmpegSource::stop() {
    return AMEDIA_OK;
}

media_status_t FFmpegSource::getFormat(AMediaFormat *meta) {
    return AMEDIA_OK;
}

media_status_t FFmpegSource::read(
        MediaBufferHelper **buffer, const ReadOptions *options) {

    return AMEDIA_OK;
}

////////////////////////////////////////////////////////////////////////////////

static CMediaExtractor* CreateExtractor(CDataSource *source, void *) {
    return wrap(new FFmpegExtractor(new DataSourceHelper(source)));
}

static void debugFFmpegExtractor(float *confidence) {
    char value[PROPERTY_VALUE_MAX];
    if (property_get("media.stagefright.ffmpeg.extractor", value, NULL)) {
        if (atof(value)) {
            float conf = (atof(value) > 1.0f) ? 1.0f : ((atof(value) <= 0) ? 0.0f : atof(value));
            *confidence = conf;
            ALOGD("[debug] set ffmpeg parser confidence %d", *confidence);
        }
    }
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

static void ffmpeg_log_to_android_callback(void *ptr, int level, const char *fmt, va_list vl)
{
    int loglevel = FF_LOG_VERBOSE;
    if (level <= AV_LOG_ERROR)
        loglevel = FF_LOG_ERROR;
    else if (level <= AV_LOG_WARNING)
        loglevel = FF_LOG_WARN;
    else if (level <= AV_LOG_INFO)
        loglevel = FF_LOG_INFO;
    else if (level <= AV_LOG_VERBOSE)
        loglevel = FF_LOG_VERBOSE;
    else
        loglevel = FF_LOG_DEBUG;

    va_list vl2;
    char line[1024];
    static int print_prefix = 1;

    va_copy(vl2, vl);
    av_log_format_line(ptr, level, fmt, vl2, line, sizeof(line), &print_prefix);
    va_end(vl2);
    FFLOG(loglevel, FF_LOG_TAG, "%s", line);
}
media_status_t initFFmpeg() 
{
    media_status_t ret = AMEDIA_OK;
    av_log_set_level(AV_LOG_ERROR);
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

static bool SniffFFMPEGCommon(const char *url, float *confidence)
{
    int err = 0;
    bool ret = false;
    size_t i = 0;
    size_t nb_streams = 0;
    const char *container = NULL;
    AVFormatContext *ic = NULL;
    AVDictionary **opts = NULL;
    AVDictionary *codec_opts = NULL;

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
    err = avformat_open_input(&ic, url, NULL, NULL);
    //err = avformat_open_input(&ic, "file:/storage/emulated/0/test.mp4", NULL, NULL);
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

static bool LegacySniffFFMPEG(DataSourceHelper *source, float *confidence,const char *url) 
{
    bool ret = false;


    uint32_t hdr[2];
    off64_t offset = 0ll;
    if (source->readAt(offset, hdr, 8) < 8) {
        return false;
    }
    //ALOGE("[%s %d]source head:0x%x 0x%x",__FUNCTION__,__LINE__, hdr[0],hdr[1]);

    ret = SniffFFMPEGCommon(url, confidence);
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
    snprintf(url, sizeof(url), "android:%p", source->handle);
    //snprintf(url, sizeof(url), "file:%p", source->handle);

    if (LegacySniffFFMPEG(&helper, confidence, url)) {
        ALOGW("Identified supported ffmpeg through LegacySniffFFmpeg.");
        *confidence = 1.0;
        debugFFmpegExtractor(confidence);
        return CreateExtractor;
    }

    return NULL;
}

static const char *extensions[] = {
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


