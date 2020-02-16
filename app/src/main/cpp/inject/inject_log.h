//
// Created by ctoast on 2020/2/5.
//

#pragma once

#include <android/log.h>

#define LOG_TAG "inject"

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define LOGD(...)// __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)