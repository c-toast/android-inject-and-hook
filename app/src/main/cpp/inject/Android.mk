LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

# 编译生成的模块的名称
LOCAL_MODULE := inject

LOCAL_LDLIBS	:= -llog

# 需要被编译的源码文件
LOCAL_SRC_FILES :=injecter.cpp inject_utils.cpp

# 编译模块生成可执行文件
include $(BUILD_EXECUTABLE)