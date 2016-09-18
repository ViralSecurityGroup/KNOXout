#ifndef THREADINFO_H
#define THREADINFO_H

//64bit structs according to sources from Z5 Lollipop 32.0.A.6.200
//32bit structs according to sources from Z3C Lollipop 23.4.A.1.200

#if (__LP64__)
#define KERNEL_START 0xffffffc000000000
#define THREAD_SIZE 16384
#else
#define KERNEL_START 0xc0000000
#define THREAD_SIZE 8192
#endif

typedef unsigned int u32;
struct task_struct;
struct thread_info;

struct list_head {
        struct list_head *next, *prev;
};

static inline struct thread_info* get_thread_info(unsigned long sp)
{
	return (struct thread_info*)(sp & ~(THREAD_SIZE - 1));
}

static inline struct thread_info* current_thread_info()
{
	register unsigned long sp asm ("sp");
	return get_thread_info(sp);
}

static inline int is_cpu_timer_valid(struct list_head* cpu_timer) 
{
	if (cpu_timer->next != cpu_timer->prev)
		return 0;

	if ((unsigned long)cpu_timer->next < KERNEL_START)
		return 0;

	return 1;
}

typedef struct {
	int counter;
} atomic_t;

typedef struct kernel_cap_struct {
	__u32 cap[2];
} kernel_cap_t;

struct task_security_struct {
	u32 osid;		/* SID prior to last execve */
	u32 sid;		/* current SID */
	u32 exec_sid;		/* exec SID */
	u32 create_sid;		/* fscreate SID */
	u32 keycreate_sid;	/* keycreate SID */
	u32 sockcreate_sid;	/* fscreate SID */
};

struct task_struct_partial
{
	/* ... */
	struct list_head cpu_timers[3];
	struct cred *real_cred;
	struct cred *cred;
	struct cred *replacement_session_keyring;
	char comm[16];
	/* ... */
};


struct task_struct_partial_parents
{
	/* ... */
	pid_t pid;
	pid_t tgid;
	void *real_parent;
	void *parent;
};

struct cred {
	atomic_t	usage;
	uid_t		uid;		/* real UID of the task */
	gid_t		gid;		/* real GID of the task */
	uid_t		suid;		/* saved UID of the task */
	gid_t		sgid;		/* saved GID of the task */
	uid_t		euid;		/* effective UID of the task */
	gid_t		egid;		/* effective GID of the task */
	uid_t		fsuid;		/* UID for VFS ops */
	gid_t		fsgid;		/* GID for VFS ops */
	unsigned	securebits;	/* SUID-less security management */
	kernel_cap_t	cap_inheritable; /* caps our children can inherit */
	kernel_cap_t	cap_permitted;	/* caps we're permitted */
	kernel_cap_t	cap_effective;	/* caps we can actually use */
	kernel_cap_t	cap_bset;	/* capability bounding set */
	unsigned char	jit_keyring;	/* default keyring to attach requested
					 * keys to */
#if (__LP64__)
	void	*session_keyring; /* keyring inherited over fork */
	void	*process_keyring; /* keyring private to this process */
	void	*thread_keyring; /* keyring private to this thread */
	void	*request_key_auth; /* assumed request_key authority */
#else
	void	*thread_keyring; /* keyring private to this thread */
	void	*request_key_auth; /* assumed request_key authority */
	void	*tgcred; /* thread-group shared credentials */
#endif
	struct task_security_struct	*security;	/* subjective LSM security */
	/* ... */
};

#if (__LP64__)
struct thread_info {
        unsigned long           flags;          /* low level flags */
        unsigned long           addr_limit;     /* address limit */
        struct task_struct      *task;          /* main task structure */
        /* ... */
};
#else
struct thread_info
{
	unsigned long flags;
	int preempt_count;
	unsigned long addr_limit;
	struct task_struct *task;
	/* ... */
};
#endif

struct security_operations {
    char name[16];

    int (*binder_set_context_mgr) (void*);
    int (*binder_transaction) (void*, void*);
    int (*binder_transfer_binder) (void*, void*);
    int (*binder_transfer_file) (void*, void*, void*);

    int (*ptrace_access_check) (void*, unsigned int);
    int (*ptrace_traceme) (void*);
    int (*capget) (void*, void*, void*, void*);
    int (*capset) (void*, const void*, const void*, const void*, const void*);
    int (*capable) (const void*, void*, int, int);
    int (*quotactl) (int cmds, int type, int id, void *sb);
    int (*quota_on) (void*dentry);
    int (*syslog) (int type);
    int (*settime) (const void*ts, const void*tz);
    int (*vm_enough_memory) (void*mm, long pages);

    int (*bprm_set_creds) (void*bprm);
    int (*bprm_check_security) (void*bprm);
    int (*bprm_secureexec) (void*bprm);
    void (*bprm_committing_creds) (void*bprm);
    void (*bprm_committed_creds) (void*bprm);

    int (*sb_alloc_security) (void*sb);
    void (*sb_free_security) (void*sb);
    int (*sb_copy_data) (char *orig, char *copy);
    int (*sb_remount) (void*sb, void *data);
    int (*sb_kern_mount) (void*sb, int flags, void *data);
    int (*sb_show_options) (void*m, void*sb);
    int (*sb_statfs) (void*dentry);
    int (*sb_mount) (const char *dev_name, void*path,
             const char *type, unsigned long flags, void *data);
    int (*sb_umount) (void*mnt, int flags);
    int (*sb_pivotroot) (void*old_path,
                 void*new_path);
    int (*sb_set_mnt_opts) (void*sb,
                void*opts);
    int (*sb_clone_mnt_opts) (const void*oldsb,
                   void*newsb);
    int (*sb_parse_opts_str) (char *options, void*opts);

#ifdef CONFIG_SECURITY_PATH
    int (*path_unlink) (void*dir, void*dentry);
    int (*path_mkdir) (void*dir, void*dentry, int mode);
    int (*path_rmdir) (void*dir, void*dentry);
    int (*path_mknod) (void*dir, void*dentry, int mode,
               unsigned int dev);
    int (*path_truncate) (void*path);
    int (*path_symlink) (void*dir, void*dentry,
                 const char *old_name);
    int (*path_link) (void*old_dentry, void*new_dir,
              void*new_dentry);
    int (*path_rename) (void*old_dir, void*old_dentry,
                void*new_dir, void*new_dentry);
    int (*path_chmod) (void*path, int mode);
    int (*path_chown) (void*path, kuid_t uid, kgid_t gid);
    int (*path_chroot) (void*path);
#endif

    int (*inode_alloc_security) (void*inode);
    void (*inode_free_security) (void*inode);
    int (*inode_init_security) (void*inode, void*dir,
                    const void*qstr, char **name,
                    void **value, size_t *len);
    int (*inode_create) (void*dir,
                 void*dentry, int mode);
    int (*inode_link) (void*old_dentry,
               void*dir, void*new_dentry);
    int (*inode_unlink) (void*dir, void*dentry);
    int (*inode_symlink) (void*dir,
                  void*dentry, const char *old_name);
    int (*inode_mkdir) (void*dir, void*dentry, int mode);
    int (*inode_rmdir) (void*dir, void*dentry);
    int (*inode_mknod) (void*dir, void*dentry,
                int mode, dev_t dev);
    int (*inode_rename) (void*old_dir, void*old_dentry,
                 void*new_dir, void*new_dentry);
    int (*inode_readlink) (void*dentry);
    int (*inode_follow_link) (void*dentry, void*nd);
    int (*inode_permission) (void*inode, int mask);
    int (*inode_setattr)    (void*dentry, void*attr);
    int (*inode_getattr) (void*mnt, void*dentry);
    int (*inode_setxattr) (void*dentry, const char *name,
                   const void *value, size_t size, int flags);
    void (*inode_post_setxattr) (void*dentry, const char *name,
                     const void *value, size_t size, int flags);
    int (*inode_getxattr) (void*dentry, const char *name);
    int (*inode_listxattr) (void*dentry);
    int (*inode_removexattr) (void*dentry, const char *name);
    int (*inode_need_killpriv) (void*dentry);
    int (*inode_killpriv) (void*dentry);
    int (*inode_getsecurity) (const void*inode, const char *name, void **buffer, char alloc);
    int (*inode_setsecurity) (void*inode, const char *name, const void *value, size_t size, int flags);
    int (*inode_listsecurity) (void*inode, char *buffer, size_t buffer_size);
    void (*inode_getsecid) (const void*inode, u32 *secid);

    int (*file_permission) (void*file, int mask);
    int (*file_alloc_security) (void*file);
    void (*file_free_security) (void*file);
    int (*file_ioctl) (void*file, unsigned int cmd,
               unsigned long arg);
    int (*mmap_addr) (unsigned long addr);
    int (*mmap_file) (void*file,
              unsigned long reqprot, unsigned long prot,
              unsigned long flags);
    int (*file_mprotect) (void*vma,
                  unsigned long reqprot,
                  unsigned long prot);
    int (*file_lock) (void*file, unsigned int cmd);
    int (*file_fcntl) (void*file, unsigned int cmd,
               unsigned long arg);
    int (*file_set_fowner) (void*file);
    int (*file_send_sigiotask) (void*tsk,
                    void*fown, int sig);
    int (*file_receive) (void*file);
    int (*file_open) (void*file, const void*cred);

    int (*task_create) (unsigned long clone_flags);
    void (*task_free) (void*task);
    int (*cred_alloc_blank) (void*cred, int gfp);
    void (*cred_free) (void*cred);
    int (*cred_prepare)(void*new, const void*old,
                int gfp);
    void (*cred_transfer)(void*new, const void*old);
    int (*kernel_act_as)(void*new, u32 secid);
    int (*kernel_create_files_as)(void*new, void*inode);
    int (*kernel_module_request)(char *kmod_name);
    int (*kernel_module_from_file)(void*file);
    int (*task_fix_setuid) (void*new, const void*old,
                int flags);
    int (*task_setpgid) (void*p, pid_t pgid);
    int (*task_getpgid) (void*p);
    int (*task_getsid) (void*p);
    void (*task_getsecid) (void*p, u32 *secid);
    int (*task_setnice) (void*p, int nice);
    int (*task_setioprio) (void*p, int ioprio);
    int (*task_getioprio) (void*p);
    int (*task_setrlimit) (void*p, unsigned int resource,
            void*new_rlim);
    int (*task_setscheduler) (void*p);
    int (*task_getscheduler) (void*p);
    int (*task_movememory) (void*p);
    int (*task_kill) (void*p,
              void*info, int sig, u32 secid);
    int (*task_wait) (void*p);
    int (*task_prctl) (int option, unsigned long arg2,
               unsigned long arg3, unsigned long arg4,
               unsigned long arg5);
    void (*task_to_inode) (void*p, void*inode);

    int (*ipc_permission) (void*ipcp, short flag);
    void (*ipc_getsecid) (void*ipcp, u32 *secid);

    int (*msg_msg_alloc_security) (void*msg);
    void (*msg_msg_free_security) (void*msg);

    int (*msg_queue_alloc_security) (void*msq);
    void (*msg_queue_free_security) (void*msq);
    int (*msg_queue_associate) (void*msq, int msqflg);
    int (*msg_queue_msgctl) (void*msq, int cmd);
    int (*msg_queue_msgsnd) (void*msq,
                 void*msg, int msqflg);
    int (*msg_queue_msgrcv) (void*msq,
                 void*msg,
                 void*target,
                 long type, int mode);

    int (*shm_alloc_security) (void*shp);
    void (*shm_free_security) (void*shp);
    int (*shm_associate) (void*shp, int shmflg);
    int (*shm_shmctl) (void*shp, int cmd);
    int (*shm_shmat) (void*shp,
              char __user *shmaddr, int shmflg);

    int (*sem_alloc_security) (void*sma);
    void (*sem_free_security) (void*sma);
    int (*sem_associate) (void*sma, int semflg);
    int (*sem_semctl) (void*sma, int cmd);
    int (*sem_semop) (void*sma,
              void*sops, unsigned nsops, int alter);

    int (*netlink_send) (void*sk, void*skb);

    void (*d_instantiate) (void*dentry, void*inode);

    int (*getprocattr) (void*p, char *name, char **value);
    int (*setprocattr) (void*p, char *name, void *value, size_t size);
    int (*secid_to_secctx) (u32 secid, char **secdata, u32 *seclen);
    int (*secctx_to_secid) (const char *secdata, u32 seclen, u32 *secid);
    void (*release_secctx) (char *secdata, u32 seclen);

    int (*inode_notifysecctx)(void*inode, void *ctx, u32 ctxlen);
    int (*inode_setsecctx)(void*dentry, void *ctx, u32 ctxlen);
    int (*inode_getsecctx)(void*inode, void **ctx, u32 *ctxlen);

#define CONFIG_SECURITY_NETWORK
#ifdef CONFIG_SECURITY_NETWORK
    int (*unix_stream_connect) (void*sock, void*other, void*newsk);
    int (*unix_may_send) (void*sock, void*other);

    int (*socket_create) (int family, int type, int protocol, int kern);
    int (*socket_post_create) (void*sock, int family,
                   int type, int protocol, int kern);
    int (*socket_bind) (void*sock,
                void*address, int addrlen);
    int (*socket_connect) (void*sock,
                   void*address, int addrlen);
    int (*socket_listen) (void*sock, int backlog);
    int (*socket_accept) (void*sock, void*newsock);
    int (*socket_sendmsg) (void*sock,
                   void*msg, int size);
    int (*socket_recvmsg) (void*sock,
                   void*msg, int size, int flags);
    int (*socket_getsockname) (void*sock);
    int (*socket_getpeername) (void*sock);
    int (*socket_getsockopt) (void*sock, int level, int optname);
    int (*socket_setsockopt) (void*sock, int level, int optname);
    int (*socket_shutdown) (void*sock, int how);
    int (*socket_sock_rcv_skb) (void*sk, void*skb);
    int (*socket_getpeersec_stream) (void*sock, char __user *optval, int __user *optlen, unsigned len);
    int (*socket_getpeersec_dgram) (void*sock, void*skb, u32 *secid);
    int (*sk_alloc_security) (void*sk, int family, int priority);
    void (*sk_free_security) (void*sk);
    void (*sk_clone_security) (const void*sk, void*newsk);
    void (*sk_getsecid) (void*sk, u32 *secid);
    void (*sock_graft) (void*sk, void*parent);
    int (*inet_conn_request) (void*sk, void*skb,
                  void*req);
    void (*inet_csk_clone) (void*newsk, const void*req);
    void (*inet_conn_established) (void*sk, void*skb);
    int (*secmark_relabel_packet) (u32 secid);
    void (*secmark_refcount_inc) (void);
    void (*secmark_refcount_dec) (void);
    void (*req_classify_flow) (const void*req, void*fl);
    int (*tun_dev_alloc_security) (void **security);
    void (*tun_dev_free_security) (void *security);
    int (*tun_dev_create) (void);
    int (*tun_dev_attach_queue) (void *security);
    int (*tun_dev_attach) (void*sk, void *security);
    int (*tun_dev_open) (void *security);
    void (*skb_owned_by) (void*skb, void*sk);
#endif  /* CONFIG_SECURITY_NETWORK */

#ifdef CONFIG_SECURITY_NETWORK_XFRM
    int (*xfrm_policy_alloc_security) (void**ctxp,
            void*sec_ctx);
    int (*xfrm_policy_clone_security) (void*old_ctx, void**new_ctx);
    void (*xfrm_policy_free_security) (void*ctx);
    int (*xfrm_policy_delete_security) (void*ctx);
    int (*xfrm_state_alloc_security) (void*x,
        void*sec_ctx,
        u32 secid);
    void (*xfrm_state_free_security) (void*x);
    int (*xfrm_state_delete_security) (void*x);
    int (*xfrm_policy_lookup) (void*ctx, u32 fl_secid, u8 dir);
    int (*xfrm_state_pol_flow_match) (void*x,
                      void*xp,
                      const void*fl);
    int (*xfrm_decode_session) (void*skb, u32 *secid, int ckall);
#endif  /* CONFIG_SECURITY_NETWORK_XFRM */

    /* key management security hooks */
#define CONFIG_KEYS
#ifdef CONFIG_KEYS
    int (*key_alloc) (void*key, const void*cred, unsigned long flags);
    void (*key_free) (void*key);
    int (*key_permission) (int key_ref,
                   const void*cred,
                   int perm);
    int (*key_getsecurity)(void*key, char **_buffer);
#endif  /* CONFIG_KEYS */

#define CONFIG_AUDIT
#ifdef CONFIG_AUDIT
    int (*audit_rule_init) (u32 field, u32 op, char *rulestr, void **lsmrule);
    int (*audit_rule_known) (void*krule);
    int (*audit_rule_match) (u32 secid, u32 field, u32 op, void *lsmrule,
                 void*actx);
    void (*audit_rule_free) (void *lsmrule);
#endif /* CONFIG_AUDIT */
};

#endif /* THREADINFO_H */
