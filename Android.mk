LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
# include $(TOP)/vendor/xingji/frameworks/multimedia/mediaserver_extension/ffmpeg/ffmpeg_prebuild/Android_prebuilt.mk

LOCAL_SRC_FILES := \
	FFmpegExtractor.cpp

LOCAL_C_INCLUDES += \
	$(TOP)/vendor/xingji/frameworks/multimedia/mediaserver_extension/ffmpeg \
	$(TOP)/vendor/xingji/frameworks/multimedia/mediaserver_extension/ffmpeg/ffmpeg_prebuild/include \
	$(TOP)/frameworks/native/include/media/openmax \
	$(TOP)/frameworks/av/include \
	$(TOP)/frameworks/av/media/libstagefright \
	$(TOP)/frameworks/av/media/ndk/include 

LOCAL_LDLIBS :=-llog

LOCAL_SHARED_LIBRARIES := \
	libavcodec \
	libavformat \
	libavutil \
	libutils \
	libcutils \
	libstagefright \
	libstagefright_foundation


LOCAL_MODULE := libffmpegextractor

LOCAL_MODULE_TAGS := optional

LOCAL_CFLAGS += -D__STDC_CONSTANT_MACROS=1

#ifeq ($(TARGET_ARCH),arm)
#	LOCAL_CFLAGS += -fpermissive
#endif

include $(BUILD_SHARED_LIBRARY)
