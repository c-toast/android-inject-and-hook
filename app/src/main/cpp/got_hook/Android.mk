LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

# 编译生成的模块的名称
LOCAL_MODULE := gothook

LOCAL_LDLIBS	:= -llog

# 需要被编译的源码文件
LOCAL_SRC_FILES :=elf_parser.cpp got_hooker.cpp


# 编译模块生成可执行文件
include $(BUILD_SHARED_LIBRARY)