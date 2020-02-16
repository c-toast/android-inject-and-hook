//
// Created by ctoast on 2020/2/5.
//

#pragma once

#include <sys/types.h>
#include <sys/ptrace.h>

#if defined(__aarch64__)
#define pt_regs         user_pt_regs
#define uregs   regs
#define ARM_pc  pc
#define ARM_sp  sp
#define ARM_cpsr    pstate
#define ARM_lr      regs[30]
#define ARM_r0      regs[0]
#endif

#define CPSR_T_MASK     ( 1u << 5 )

int ptrace_attach(pid_t pid);

int ptrace_detach(pid_t pid);

int ptrace_getregs(pid_t pid, struct pt_regs * regs);

int ptrace_setregs(pid_t pid, struct pt_regs * regs);

int ptrace_writedata(pid_t pid, uint8_t *dest, uint8_t *data, size_t size);

int ptrace_continue(pid_t pid);

int ptrace_call(pid_t pid, void* addr, long *params, int num_params, struct pt_regs* regs);

//return NULL if fail
void* find_space_by_mmap(int target_pid, int size);

//return the handle of library in target process. return NULL if fail
void* ptrace_dlopen(pid_t pid, void* dlopen_addr, char* filename);

//return the symbol address. return NULL if fail
void *ptrace_dlsym(pid_t target_pid, void *remote_dlsym_address, void *handle, char *symbol_name);

//given the pid and address, this function will find the module that include the address in target
//process.it will obtain the module name and return module start address. if the module does not
//exist, return NULL
void* find_module_name_by_addr(pid_t pid, void* address, char *const module_name);

//given the module name, this function return module start addr. return null if not exist
void* find_module_addr_by_name(pid_t pid, char *module_name);

//return NULL if fail
void* get_fun_remote_addr(pid_t pid, void* func_local_addr);
