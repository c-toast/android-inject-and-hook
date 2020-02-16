//
// Created by ctoast on 2020/2/5.
//
#include "injecter.h"

#include <dirent.h>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <dlfcn.h>
#include <zconf.h>
#include <syscall.h>

#include "inject_log.h"
#include "inject_utils.h"

Injecter::Injecter(pid_t pid, char* library_path){
    pid_=pid;
    strcpy(library_path_,library_path);
}

int find_pid_of(const char *process_name)
{
    int id;
    pid_t pid = -1;
    DIR* dir;
    FILE *fp;
    char filename[32];
    char cmdline[256];

    struct dirent * entry;

    if (process_name == NULL)
        return -1;

    dir = opendir("/proc");
    if (dir == NULL)
        return -1;

    while((entry = readdir(dir)) != NULL) {
        id = atoi(entry->d_name);//read the name in /proc and try to turn it to number
        if (id != 0) {//if the name can be converted number, it represents the pid of process
            sprintf(filename, "/proc/%d/cmdline", id);
            fp = fopen(filename, "r");
            if (fp) {
                fgets(cmdline, sizeof(cmdline), fp);
                fclose(fp);
                LOGD("[d] cmdline: %s,pid %d",cmdline,id);
                //strcmp(process_name, cmdline)
                //as we use strstr instead of strcmp,the process_name should be as accurate as
                //possible, otherwise it may find the pid of other process that have the similar name.
                if (strstr(cmdline,process_name) != NULL) {
                    // process found //
                    LOGI("[+] find the process, process name is %s, pid is %d",cmdline,id);
                    pid = id;
                    break;
                }
            }
        }
    }

    closedir(dir);
    return pid;
}

bool Injecter::inject_hook() {
    ptrace_attach(pid_);
    LOGI("[+] target pid: %d, injecting library name: %s",pid_,library_path_);
    LOGI("[+] start to find dlopen address, its local address is %x",(void*)dlopen);
    dlopen_addr_=get_fun_remote_addr(pid_,(void*)dlopen);
    LOGI("[+] start to find dlsym address, its local address is %x",(void*)dlsym);
    dlsym_addr_=get_fun_remote_addr(pid_,(void*)dlsym);
    LOGI("[+] dlopen remote address: %x, dlsym_addr_ remote address: %x",dlopen_addr_,dlsym_addr_);

    struct pt_regs regs;
    ptrace_getregs(pid_,&regs);

    if(dlopen_addr_==NULL||dlopen_addr_==NULL){
        LOGE("[-] fail to find dlopen or dlsym address in remote process");
        goto DETACH;
    }

    handle_=ptrace_dlopen(pid_,dlopen_addr_,library_path_);
    if(handle_==NULL){
        LOGE("[-] ptrace_dlopen fail");
        goto DETACH;
    }

    called_before_detach();

DETACH:
    LOGI("[+] detach process");
    ptrace_setregs(pid_,&regs);
    ptrace_detach(pid_);

}

void* Injecter::called_before_detach(){
    LOGI("[+] called_before_detach");
    void* func_addr=ptrace_dlsym(pid_,dlsym_addr_,handle_,"_Z13got_hook_mainv");
    LOGI("[+] _Z13got_hook_mainv_addr is %x",func_addr);
    char module_name[128];
    find_module_name_by_addr(pid_,func_addr,module_name);
    LOGI("[+} module_name is %s",module_name);
    struct pt_regs regs;
    ptrace_getregs(pid_,&regs);
    ptrace_call(pid_, func_addr,NULL,0,&regs);
    LOGI("[+] called_before_detach: Target process returned from _Z13got_hook_mainv, return r0=%x, pc=%x, \n", regs.ARM_r0, regs.ARM_pc);
    return regs.ARM_pc == 0 ? (void *) regs.ARM_r0 : NULL;
}

int main(int argc,char* argv[]){
    pid_t pid= find_pid_of("test");
    if(pid==-1){
        LOGE("[-] can not find the pid of process");
        return 0;
    }
    FILE* fp = popen("setenforce 0","r");
    pclose(fp);

    Injecter injecter(pid,"libgothook.so");

    injecter.inject_hook();
    return 0;
}