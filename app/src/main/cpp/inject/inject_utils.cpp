//
// Created by ctoast on 2020/2/5.
//

#include "inject_utils.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/mman.h>
#include <linux/uio.h>
#include <elf.h>
#include <wait.h>
#include <dlfcn.h>

#include "inject_log.h"

int ptrace_attach(pid_t pid)
{
    if (ptrace(PTRACE_ATTACH, pid, NULL, 0) < 0) {
        perror("[-] ptrace_attach");
        return -1;
    }

    int status = 0;
    waitpid(pid, &status , WUNTRACED);

    return 0;
}

int ptrace_detach(pid_t pid)
{
    if (ptrace(PTRACE_DETACH, pid, NULL, 0) < 0) {
        perror("[-] ptrace_detach");
        return -1;
    }

    return 0;
}

int ptrace_getregs(pid_t pid, struct pt_regs * regs)
{
#if defined (__aarch64__)
    int regset = NT_PRSTATUS;//general-purpose registers
    struct iovec ioVec;

    ioVec.iov_base = regs;
    ioVec.iov_len = sizeof(*regs);
    if (ptrace(PTRACE_GETREGSET, pid, (void*)regset, &ioVec) < 0) {
        perror("[-] ptrace_getregs: Can not get register values");
        return -1;
    }

    return 0;
#else
    if (ptrace(PTRACE_GETREGS, pid, NULL, regs) < 0) {
        perror("[-] ptrace_getregs: Can not get register values");
        return -1;
    }

    return 0;
#endif
}

int ptrace_setregs(pid_t pid, struct pt_regs * regs)
{
#if defined (__aarch64__)
    int regset = NT_PRSTATUS;
    struct iovec ioVec;

    ioVec.iov_base = regs;
    ioVec.iov_len = sizeof(*regs);
    if (ptrace(PTRACE_SETREGSET, pid, (void*)regset, &ioVec) < 0) {
        perror("[-] ptrace_setregs: Can not get register values");
        return -1;
    }

    return 0;
#else
    if (ptrace(PTRACE_SETREGS, pid, NULL, regs) < 0) {
        perror("[-] ptrace_setregs: Can not set register values");
        return -1;
    }

    return 0;
#endif
}

int ptrace_writedata(pid_t pid, uint8_t *dest, uint8_t *data, size_t size)
{
    long i, j, remain;
    uint8_t *laddr;
    size_t bytes_width = sizeof(long);

    union u {
        long val;
        char chars[sizeof(long)];
    } d;

    j = size / bytes_width;
    remain = size % bytes_width;

    laddr = data;

    for (i = 0; i < j; i ++) {
        memcpy(d.chars, laddr, bytes_width);
        ptrace(PTRACE_POKETEXT, pid, dest, d.val);

        dest  += bytes_width;
        laddr += bytes_width;
    }

    if (remain > 0) {
        d.val = ptrace(PTRACE_PEEKTEXT, pid, dest, 0);
        for (i = 0; i < remain; i ++) {
            d.chars[i] = *laddr ++;
        }

        ptrace(PTRACE_POKETEXT, pid, dest, d.val);
    }

    return 0;
}

int ptrace_continue(pid_t pid)
{
    if (ptrace(PTRACE_CONT, pid, NULL, 0) < 0) {
        perror("[-] ptrace_cont");
        return -1;
    }

    return 0;
}

int ptrace_call(pid_t pid, void* addr, long *params, int num_params, struct pt_regs* regs) {
    int i;
#if defined(__arm__)
    int num_param_registers = 4;
#elif defined(__aarch64__)
    int num_param_registers = 8;
#endif

    for (i = 0; i < num_params && i < num_param_registers; i ++) {
        regs->uregs[i] = params[i];
    }

    if (i < num_params) {
        regs->ARM_sp -= (num_params - i) * sizeof(long) ;
        ptrace_writedata(pid, (uint8_t *)regs->ARM_sp, (uint8_t *)&params[i], (num_params - i) * sizeof(long));
    }

    regs->ARM_pc = (long)addr;
    if (regs->ARM_pc & 1) {
        /* thumb */
        regs->ARM_pc &= (~1u);
        regs->ARM_cpsr |= CPSR_T_MASK;
    } else {
        /* arm */
        regs->ARM_cpsr &= ~CPSR_T_MASK;
    }

    regs->ARM_lr = 0;

    if (ptrace_setregs(pid, regs) == -1
        || ptrace_continue(pid) == -1) {
        printf("[-] error\n");
        return -1;
    }

    int stat = 0;
    waitpid(pid, &stat, WUNTRACED);
    while (stat != 0xb7f) {
        if (ptrace_continue(pid) == -1) {
            printf("[-] error\n");
            return -1;
        }
        waitpid(pid, &stat, WUNTRACED);
    }
    return 0;
}

//return NULL if fail
void* find_space_by_mmap(int target_pid, int size){
    struct pt_regs regs;
    if (ptrace_getregs(target_pid, &regs) == -1)
        return 0;

    long parameters[10];

    /* call mmap */
    parameters[0] = 0;  // addr
    parameters[1] = size; // size
    parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;  // prot
    parameters[3] = MAP_ANONYMOUS | MAP_PRIVATE; // flags
    parameters[4] = 0; //fd
    parameters[5] = 0; //offset

    void* remote_mmap_addr = get_fun_remote_addr(target_pid,(void*)mmap);

    if (remote_mmap_addr == NULL) {
        LOGE("[-] Get Remote mmap address fails.\n");
        return 0;
    }
    LOGI("[+] find_space_by_mmap: start to call mmap, size of space to be mapped is %d",size);
    ptrace_call(target_pid,  remote_mmap_addr, parameters, 6, &regs);

    ptrace_getregs(target_pid, &regs);

    LOGI("[+] find_space_by_mmap: Target process returned from mmap, return r0=%x,  pc=%x, \n", regs.ARM_r0, regs.ARM_pc);

    return regs.ARM_pc == 0 ? (void *) regs.ARM_r0 : 0;
}

//return the handle of library in target process. return NULL if fail
void* ptrace_dlopen(pid_t pid, void* dlopen_addr, char* filename)
{
    LOGI("start to dlopen %s",filename);
    struct pt_regs regs;
    ptrace_getregs(pid, &regs);
    long params[2];

    size_t filename_len = strlen(filename) + 1;
    LOGI("[+] ptrace_dlopen: Try to find space for string %s in target process",filename);
    void* filename_addr;
    filename_addr= find_space_by_mmap(pid, filename_len);
    LOGI("[+] ptrace_dlopen: String \"%s\" address %x",filename, filename_addr);
    if (filename_addr == NULL ) {
        LOGE("[+] ptrace_dlopen: Call Remote mmap fails.");
        return NULL;
    }
    ptrace_writedata(pid, (uint8_t*)filename_addr, (uint8_t*)filename, filename_len);
    params[0] = (long)filename_addr;  //filename pointer
    params[1] = RTLD_NOW | RTLD_GLOBAL; // flag

    if (dlopen_addr == NULL) {
        return NULL;
    }

    ptrace_call(pid,  dlopen_addr, params, 2, &regs);

    ptrace_getregs(pid, &regs);

    LOGI("[+] ptrace_dlopen: Target process returned from dlopen, return r0=%x, pc=%x, \n", regs.ARM_r0, regs.ARM_pc);
    if(regs.ARM_r0==0){
        LOGI("[-] ptrace_dlopen: %s",dlerror());
    }

    return regs.ARM_pc == 0 ? (void *) regs.ARM_r0 : NULL;
}

//return the symbol address. return NULL if fail
void *ptrace_dlsym(pid_t target_pid, void *remote_dlsym_address, void *handle, char *symbol_name)
{
    LOGI("[+] start to dlsym %s",symbol_name);
    struct pt_regs regs;
    ptrace_getregs(target_pid, &regs);

    long params[2];
    size_t name_len=strlen((char*)symbol_name)+1;
    LOGI("[+] Try to find space for string %s in target process",symbol_name);
    void* symbol_name_address=find_space_by_mmap(target_pid,name_len);
    LOGI("[+] string %s address %p",symbol_name,symbol_name_address);
    if(symbol_name_address==NULL)
    {
        LOGE("[-] Call Remote mmap fails.");
        return NULL;
    }
    ptrace_writedata(target_pid,(uint8_t*)symbol_name_address,(uint8_t*)symbol_name,name_len);
    params[0]=(long)handle;
    params[1]=(long)symbol_name_address;
    ptrace_call(target_pid,remote_dlsym_address,params,2,&regs);

    ptrace_getregs(target_pid,&regs);

    LOGI("[+] Target process returned from dlysm, return r0=%x,pc=%x,\n",regs.ARM_r0,regs.ARM_pc);
    return regs.ARM_pc==0?(void*)regs.ARM_r0:NULL;
}

//given the pid and address, this function will find the module that include the address in target
//process.it will obtain the module name and return module start address. if the module does not
//exist, return NULL
void* find_module_name_by_addr(pid_t pid, void* address, char *const module_name)
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
    LOGI("[+] finding module containning %x in process %d", address,pid);
    while (fgets(line, sizeof(line), proc_map))
    {
        char *line_ptr = line;
        //format of the str in line: b6fc1000-b6fd1000 r-xp 00000000 b3:26 336        /system/bin/linker
        void* start_addr = (void*)strtoul(strsep(&line_ptr, "-"), NULL, 16);
        void* end_addr = (void*)strtoul(strsep(&line_ptr, " "), NULL, 16);
        //if find the module that contains our address, obtains its name
        if (address >= start_addr && address < end_addr)
        {
            strsep(&line_ptr, " "); //skip permission
            strsep(&line_ptr, " "); //skip offset
            strsep(&line_ptr, " "); //skip dev
            strsep(&line_ptr, " "); //skip inode
            while (*line_ptr == ' ')
            {
                line_ptr++; //skip blank
            }
            if(module_name!=NULL)
                strcpy(module_name, strsep(&line_ptr,"\n"));    //elimate last '\n'
            return_addr = start_addr;
            break;
        }
    }
    fclose(proc_map);
    return return_addr;
}

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

//return NULL if fail
void* get_fun_remote_addr(pid_t pid, void* func_local_addr)
{
    char module_name[64];
    void* local_module_start = find_module_name_by_addr(-1, func_local_addr, module_name);
    if (local_module_start == NULL)
    {
        return NULL;
    }
    void* remote_module_start = find_module_addr_by_name(pid, module_name);
    if (remote_module_start == NULL)
    {
        return NULL;
    }
    return (void*)((long)func_local_addr - (long)local_module_start + (long)remote_module_start);
}



