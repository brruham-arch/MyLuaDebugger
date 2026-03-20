LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE    := LuaDebugger
LOCAL_SRC_FILES := main.cpp
LOCAL_LDLIBS    := -llog
LOCAL_CFLAGS    := -O2
include $(BUILD_SHARED_LIBRARY)
