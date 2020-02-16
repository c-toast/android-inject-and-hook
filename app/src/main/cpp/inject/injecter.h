//
// Created by ctoast on 2020/2/5.
//

#pragma once

#include <sys/types.h>

class Injecter{
public:
    Injecter(pid_t pid, char* library_name);

    bool inject_hook();

    virtual void* called_before_detach();

private:
    pid_t pid_;
    char library_path_[128];
    void* handle_=NULL;
    void* dlopen_addr_=NULL;
    void* dlsym_addr_=NULL;
};