//
// Created by ctoast on 2020/2/10.
//

#include <elf_parser.h>
#include <cstdlib>
#include <string.h>
#include <bits/sysconf.h>
#include <sys/mman.h>

#include "got_hook_log.h"
#include "elf_parser.h"

//given the module name, this function return module start addr. return null if not exist
void* find_module_addr_by_name(pid_t pid, char *module_name)
{
    char proc_map_name[32];
    void* return_addr = NULL;
    char line[256];
    if (pid < 0)
    {
        sprintf(proc_map_name, "/proc/self/maps");
    }
    else
    {
        sprintf(proc_map_name, "/proc/%d/maps", pid);
    }
    FILE *proc_map = fopen(proc_map_name, "r");
    LOGI("[+] finding %s in process %d", module_name,pid);
    while (fgets(line, sizeof(line), proc_map))
    {
        char *line_ptr = line;
        //format: b6fc1000-b6fd1000 r-xp 00000000 b3:26 336        /system/bin/linker
        void* start_addr = (void*)strtoul(strsep(&line_ptr, "-"), NULL, 16);
        strsep(&line_ptr, " "); //skip end_address
        strsep(&line_ptr, " "); //skip permission
        strsep(&line_ptr, " "); //skip offset
        strsep(&line_ptr, " "); //skip dev
        strsep(&line_ptr, " "); //skip inode
        while (*line_ptr == ' ')
        {
            line_ptr++; //skip blank
        }
        //if the name does not exist, continue;
        if (*line_ptr == '\n')
        {
            continue;
        }
        if (strstr(line_ptr, module_name) != NULL)
        {
            //several module have the same name,
            //only the first one have executing permission
            //so directly break when find the first one
            return_addr = start_addr;
            break;

        }
    }
    fclose(proc_map);
    return return_addr;
}

class GotHooker{
public:
    GotHooker(char* SoFileName,char* FunctionName,void* hook_function_addr);
    ~GotHooker();
    void do_hook();
//protected:
    void* get_targetfunc_rel_addr();
private:
    char* library_name_;
    char* targetfunc_name_;
    void* targetfunc_relocation_addr_=NULL;//the address of the target function's items in .got
    void* targetfunc_original_addr_=NULL;//for convenicence of recovery, store the original data in function's item in .got
    void* hook_function_addr_=NULL;
};

bool change_addr_writtable(long address, bool writable)
{
    long page_size=sysconf(_SC_PAGESIZE);
    long page_start=(address)&(~(page_size-1));
    if(writable){
        return mprotect((void*)page_start,page_size,PROT_READ|PROT_WRITE|PROT_EXEC)!=-1;
    } else{
        return mprotect((void*)page_start,page_size,PROT_READ|PROT_EXEC)!=-1;
    }
}

GotHooker::GotHooker(char *SoFileName, char *FunctionName,void* hook_function_addr) {
    int n=strlen(SoFileName)+1;
    library_name_=new char[n];
    memcpy(library_name_,SoFileName,n);
    n=strlen(FunctionName)+1;
    targetfunc_name_=new char[n];
    memcpy(targetfunc_name_,FunctionName,n);
    hook_function_addr_=hook_function_addr;
}

GotHooker::~GotHooker() {
    delete []library_name_;
    delete []targetfunc_name_;
}

void* GotHooker::get_targetfunc_rel_addr() {
    void* so_base_addr=NULL;  //address where so file load
    void* symbol_got_addr=NULL;
    void* symbol_got_item_vaddr=NULL;
    long loadsegment_offset=-1;
    ElfParser Parser(library_name_);

    so_base_addr=find_module_addr_by_name(-1,library_name_);//m_SoFileName;
    if(so_base_addr==NULL)
    {
        LOGE("[-] get_targetfunc_rel_addr: fail to get %s address",library_name_);
        return NULL;
    }

    symbol_got_item_vaddr=Parser.get_symbol_got_item_vaddr(targetfunc_name_);
    loadsegment_offset=Parser.get_loadsegment_offset();
    if(symbol_got_item_vaddr==NULL||loadsegment_offset==-1){
        LOGE("[-] get_targetfunc_rel_addr: fail to get symbol_got_item_vaddr or load segment");
        return NULL;
    }

    symbol_got_addr=(void*)((long)so_base_addr + (long)symbol_got_item_vaddr-loadsegment_offset);
    LOGI("[+] get_targetfunc_rel_addr: Symbol relocating address is %p",symbol_got_addr);
    return symbol_got_addr;
}

void GotHooker::do_hook(){
    targetfunc_relocation_addr_= get_targetfunc_rel_addr();
    if(targetfunc_relocation_addr_==NULL){
        LOGE("do_hook: fail because targetfunc_relocation_addr_ is NULL");
        return;
    }

    targetfunc_original_addr_=(void*)*(long*)targetfunc_relocation_addr_;
    LOGI("[+] do_hook: address recorded in .got table is %p",targetfunc_original_addr_);
    change_addr_writtable((long) targetfunc_relocation_addr_, true);
    if(hook_function_addr_!=NULL){
        *(long*)targetfunc_relocation_addr_=(long)hook_function_addr_;
    }
    change_addr_writtable((long) targetfunc_relocation_addr_, false);
    LOGI("[+] do_hook: after changing, address recorded in .got table is %p",*(long*)targetfunc_relocation_addr_);
}

void got_hook_main(){
    LOGI("[+] got_hook_main: enter got_hook_main");
    GotHooker hooker("/data/app/com.example.hjz.appfortest-yal6qdoVhjli-jlfF_lkgg==/lib/arm/libnative-lib.so","stringFromJNI",0);
    hooker.do_hook();
}
