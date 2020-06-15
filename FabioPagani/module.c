/*
  This module does absolutely nothings at all. We just build it with debugging
symbols and then read the DWARF symbols from it.
*/
#include <linux/module.h>
#include <linux/version.h>

#include <linux/ioport.h>
#include <linux/fs_struct.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/utsname.h>
#include <net/tcp.h>
#include <net/route.h>
#include <net/udp.h>
#include <linux/mount.h>
#include <linux/inetdevice.h>
#include <net/protocol.h>


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,20,0)
struct xa_node xa;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0)
#include <linux/lockref.h>
struct lockref lockref;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,26)
#include <linux/fdtable.h>
#else
#include <linux/file.h>
#endif

#include <net/ip_fib.h>
#include <linux/un.h>
#include <net/af_unix.h>
#include <linux/pid.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
#include <linux/pid_namespace.h>
struct pid_namespace pid_namespace;
#endif


#ifdef CONFIG_NETFILTER
#include <linux/netfilter.h>

struct nf_hook_ops nf_hook_ops;
struct nf_sockopt_ops nf_sockopt_ops;

#ifdef CONFIG_NETFILTER_XTABLES
#include <linux/netfilter/x_tables.h>
struct xt_table xt_table;
#endif

#endif

#include <linux/radix-tree.h>
#include <net/tcp.h>
#include <net/udp.h>

#include <linux/termios.h>
#include <asm/termbits.h>

#include <linux/notifier.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,17)
struct atomic_notifier_head atomic_notifier_head;
#endif

#include <linux/tty_driver.h>
struct tty_driver tty_driver;

#include <linux/tty.h>
struct tty_struct tty_struct;

struct udp_seq_afinfo udp_seq_afinfo;
struct tcp_seq_afinfo tcp_seq_afinfo;

struct files_struct files_struct;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
struct uts_namespace uts_namespace;
#endif

struct sock sock;
struct inet_sock inet_sock;
struct vfsmount vfsmount;
struct in_device in_device;
struct fib_table fib_table;
struct unix_sock unix_sock;
struct pid pid;
struct radix_tree_root radix_tree_root;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,12)
#ifdef CONFIG_NET_SCHED
#include <net/sch_generic.h>
struct Qdisc qdisc;
#endif
#endif

struct inet_protosw inet_protosw;

/********************************************************************
The following structs are not defined in headers, so we cant import
them. Hopefully they dont change too much.
*********************************************************************/

struct kthread_create_info
{
     /* Information passed to kthread() from kthreadd. */
     int (*threadfn)(void *data);
     void *data;
     int node;

     /* Result passed back to kthread_create() from kthreadd. */
     struct task_struct *result;
     struct completion done;

     struct list_head list;
};

struct kthread_create_info kthread_create_info;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
#include <net/net_namespace.h>
#endif

#include <net/ip.h>
#include <net/sock.h>
#include <net/ip_fib.h>
#include <linux/compiler.h>

#define EMBEDDED_HASH_SIZE (L1_CACHE_BYTES / sizeof(struct hlist_head))

#define __rcu

struct fn_zone {
  struct fn_zone     *fz_next;       /* Next not empty zone  */
  struct hlist_head  *fz_hash;       /* Hash table pointer   */
  seqlock_t               fz_lock;
  u32                     fz_hashmask;    /* (fz_divisor - 1)     */
  u8                      fz_order;       /* Zone order (0..32)   */
  u8                      fz_revorder;    /* 32 - fz_order        */
  __be32                  fz_mask;        /* inet_make_mask(order) */

  struct hlist_head       fz_embedded_hash[EMBEDDED_HASH_SIZE];

  int                     fz_nent;        /* Number of entries    */
  int                     fz_divisor;     /* Hash size (mask+1)   */
} fn_zone;

struct fn_hash {
  struct fn_zone    *fn_zones[33];
  struct fn_zone    *fn_zone_list;
} fn_hash;

struct fib_alias
{
    struct list_head        fa_list;
    struct fib_info         *fa_info;
    u8                      fa_tos;
    u8                      fa_type;
    u8                      fa_scope;
    u8                      fa_state;
#ifdef CONFIG_IP_FIB_TRIE
        struct rcu_head         rcu;
#endif
};

struct fib_node
{
    struct hlist_node       fn_hash;
    struct list_head        fn_alias;
    __be32                  fn_key;
    struct fib_alias        fn_embedded_alias;
};


struct fib_node fib_node;
struct fib_alias fib_alias;

struct rt_hash_bucket {
  struct rtable __rcu     *chain;
} rt_hash_bucket;

#ifndef RADIX_TREE_MAP_SHIFT

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,18)
#define RADIX_TREE_MAP_SHIFT    6
#else
#define RADIX_TREE_MAP_SHIFT    (CONFIG_BASE_SMALL ? 4 : 6)
#endif
#define RADIX_TREE_MAP_SIZE     (1UL << RADIX_TREE_MAP_SHIFT)
#define RADIX_TREE_MAP_MASK     (RADIX_TREE_MAP_SIZE-1)
#define RADIX_TREE_TAG_LONGS    ((RADIX_TREE_MAP_SIZE + BITS_PER_LONG - 1) / BITS_PER_LONG)
#define RADIX_TREE_MAX_TAGS     2

struct radix_tree_node {
    unsigned int    height;         /* Height from the bottom */
    unsigned int    count;
    struct rcu_head rcu_head;
    void            *slots[RADIX_TREE_MAP_SIZE];
    unsigned long   tags[RADIX_TREE_MAX_TAGS][RADIX_TREE_TAG_LONGS];
};
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
#define OUR_OWN_MOD_STRUCTS
#endif

#if LINUX_VERSION_CODE == KERNEL_VERSION(2,6,18)
#define OUR_OWN_MOD_STRUCTS
#endif

#ifdef OUR_OWN_MOD_STRUCTS
struct module_sect_attr
{
        struct module_attribute mattr;
        char *name;
        unsigned long address;
};

struct module_sect_attrs
{
        struct attribute_group grp;
        unsigned int nsections;
        struct module_sect_attr attrs[0];
};

struct module_sect_attrs module_sect_attrs;

#else

struct module_sections module_sect_attrs;

#endif

struct module_kobject module_kobject;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
// we can't get the defintion of mod_tree_root directly
// because it is declared in module.c as a static struct
// the latch_tree_root struct has the variables we want
// immediately after it though

#include <linux/rbtree_latch.h>

struct latch_tree_root ltr;

#endif

#ifdef CONFIG_SLAB

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22)
/*
 * struct kmem_cache
 *
 * manages a cache.
 */

struct kmem_cache {
/* 1) per-cpu data, touched during every alloc/free */
	struct array_cache *array[NR_CPUS];
/* 2) Cache tunables. Protected by cache_chain_mutex */
	unsigned int batchcount;
	unsigned int limit;
	unsigned int shared;

	unsigned int buffer_size;
	u32 reciprocal_buffer_size;
/* 3) touched by every alloc & free from the backend */

	unsigned int flags;		/* constant flags */
	unsigned int num;		/* # of objs per slab */

/* 4) cache_grow/shrink */
	/* order of pgs per slab (2^n) */
	unsigned int gfporder;

	/* force GFP flags, e.g. GFP_DMA */
	gfp_t gfpflags;

	size_t colour;			/* cache colouring range */
	unsigned int colour_off;	/* colour offset */
	struct kmem_cache *slabp_cache;
	unsigned int slab_size;
	unsigned int dflags;		/* dynamic flags */

	/* constructor func */
	void (*ctor)(void *obj);

/* 5) cache creation/removal */
	const char *name;
	struct list_head next;

/* 6) statistics */
#if STATS
	unsigned long num_active;
	unsigned long num_allocations;
	unsigned long high_mark;
	unsigned long grown;
	unsigned long reaped;
	unsigned long errors;
	unsigned long max_freeable;
	unsigned long node_allocs;
	unsigned long node_frees;
	unsigned long node_overflow;
	atomic_t allochit;
	atomic_t allocmiss;
	atomic_t freehit;
	atomic_t freemiss;
#endif
#if DEBUG
	/*
	 * If debugging is enabled, then the allocator can add additional
	 * fields and/or padding to every object. buffer_size contains the total
	 * object size including these internal fields, the following two
	 * variables contain the offset to the user object and its size.
	 */
	int obj_offset;
	int obj_size;
#endif
	/*
	 * We put nodelists[] at the end of kmem_cache, because we want to size
	 * this array to nr_node_ids slots instead of MAX_NUMNODES
	 * (see kmem_cache_init())
	 * We still use [MAX_NUMNODES] and not [1] or [0] because cache_cache
	 * is statically defined, so we reserve the max number of nodes.
	 */
	struct kmem_list3 *nodelists[MAX_NUMNODES];
	/*
	 * Do not add fields after nodelists[]
	 */
};
#else

struct kmem_cache {
/* 1) per-cpu data, touched during every alloc/free */
        struct array_cache *array[NR_CPUS];
/* 2) Cache tunables. Protected by cache_chain_mutex */
        unsigned int batchcount;
        unsigned int limit;
        unsigned int shared;

        unsigned int buffer_size;
/* 3) touched by every alloc & free from the backend */
        struct kmem_list3 *nodelists[MAX_NUMNODES];

        unsigned int flags;             /* constant flags */
        unsigned int num;               /* # of objs per slab */

/* 4) cache_grow/shrink */
        /* order of pgs per slab (2^n) */
        unsigned int gfporder;

        /* force GFP flags, e.g. GFP_DMA */
        gfp_t gfpflags;

        size_t colour;                  /* cache colouring range */
        unsigned int colour_off;        /* colour offset */
        struct kmem_cache *slabp_cache;
        unsigned int slab_size;
        unsigned int dflags;            /* dynamic flags */

        /* constructor func */
        void (*ctor) (void *, struct kmem_cache *, unsigned long);

        /* de-constructor func */
        void (*dtor) (void *, struct kmem_cache *, unsigned long);

/* 5) cache creation/removal */
        const char *name;
        struct list_head next;

/* 6) statistics */
#if STATS
        unsigned long num_active;
        unsigned long num_allocations;
        unsigned long high_mark;
        unsigned long grown;
        unsigned long reaped;
        unsigned long errors;
        unsigned long max_freeable;
        unsigned long node_allocs;
        unsigned long node_frees;
        unsigned long node_overflow;
        atomic_t allochit;
        atomic_t allocmiss;
        atomic_t freehit;
        atomic_t freemiss;
#endif
#if DEBUG
        /*
         * If debugging is enabled, then the allocator can add additional
         * fields and/or padding to every object. buffer_size contains the total
         * object size including these internal fields, the following two
         * variables contain the offset to the user object and its size.
         */
        int obj_offset;
        int obj_size;
#endif
};

#endif /*kmem_cache decl*/

struct kmem_cache kmem_cache;
#endif

struct kmem_list3 {
         struct list_head slabs_partial; /* partial list first, better asm code */
         struct list_head slabs_full;
         struct list_head slabs_free;
        unsigned long free_objects;
         unsigned int free_limit;
         unsigned int colour_next;       /* Per-node cache coloring */
         spinlock_t list_lock;
         struct array_cache *shared;     /* shared per node */
         struct array_cache **alien;     /* on other nodes */
         unsigned long next_reap;        /* updated without locking */
         int free_touched;               /* updated without locking */
};

struct kmem_list3 kmem_list3;

struct slab {
     struct list_head list;
     unsigned long colouroff;
     void *s_mem;            /* including colour offset */
     unsigned int inuse;     /* num of objs active in slab */
     unsigned int free;
     unsigned short nodeid;
 };

struct slab slab;
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,31)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
/* Starting with Linux kernel 3.7 the struct timekeeper is defined in include/linux/timekeeper_internal.h */
#include <linux/timekeeper_internal.h>
#else
/* Before Linux kernel 3.7 the struct timekeeper has to be taken from kernel/time/timekeeping.c */

typedef u64 cycle_t;

struct timekeeper {
	/* Current clocksource used for timekeeping. */
	struct clocksource *clock;
	/* NTP adjusted clock multiplier */
	u32	mult;
	/* The shift value of the current clocksource. */
	int	shift;

	/* Number of clock cycles in one NTP interval. */
	cycle_t cycle_interval;
	/* Number of clock shifted nano seconds in one NTP interval. */
	u64	xtime_interval;
	/* shifted nano seconds left over when rounding cycle_interval */
	s64	xtime_remainder;
	/* Raw nano seconds accumulated per NTP interval. */
	u32	raw_interval;

	/* Clock shifted nano seconds remainder not stored in xtime.tv_nsec. */
	u64	xtime_nsec;
	/* Difference between accumulated time and NTP time in ntp
	 * shifted nano seconds. */
	s64	ntp_error;
	/* Shift conversion between clock shifted nano seconds and
	 * ntp shifted nano seconds. */
	int	ntp_error_shift;

	/* The current time */
	struct timespec xtime;
	/*
	 * wall_to_monotonic is what we need to add to xtime (or xtime corrected
	 * for sub jiffie times) to get to monotonic time.  Monotonic is pegged
	 * at zero at system boot time, so wall_to_monotonic will be negative,
	 * however, we will ALWAYS keep the tv_nsec part positive so we can use
	 * the usual normalization.
	 *
	 * wall_to_monotonic is moved after resume from suspend for the
	 * monotonic time not to jump. We need to add total_sleep_time to
	 * wall_to_monotonic to get the real boot based time offset.
	 *
	 * - wall_to_monotonic is no longer the boot time, getboottime must be
	 * used instead.
	 */
	struct timespec wall_to_monotonic;
	/* time spent in suspend */
	struct timespec total_sleep_time;
	/* The raw monotonic time for the CLOCK_MONOTONIC_RAW posix clock. */
	struct timespec raw_time;

	/* Offset clock monotonic -> clock realtime */
	ktime_t offs_real;

	/* Offset clock monotonic -> clock boottime */
	ktime_t offs_boot;

	/* Seqlock for all timekeeper values */
	seqlock_t lock;
};

#endif

struct timekeeper my_timekeeper;

struct log {
         u64 ts_nsec;            /* timestamp in nanoseconds */
         u16 len;                /* length of entire record */
         u16 text_len;           /* length of text buffer */
         u16 dict_len;           /* length of dictionary buffer */
         u8 facility;            /* syslog facility */
         u8 flags:5;             /* internal record flags */
         u8 level:3;             /* syslog level */
};

struct log my_log;

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,3,0)

struct mnt_namespace {
	atomic_t		count;
	struct mount *	root;
	struct list_head	list;
	wait_queue_head_t poll;
	int event;
};

struct mnt_pcp {
	int mnt_count;
	int mnt_writers;
};

struct mount {
	struct list_head mnt_hash;
	struct mount *mnt_parent;
	struct dentry *mnt_mountpoint;
	struct vfsmount mnt;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0)
        struct callback_head rcu;
#endif
#ifdef CONFIG_SMP
	struct mnt_pcp __percpu *mnt_pcp;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
	atomic_t mnt_longterm;		/* how many of the refs are longterm */
#endif
#else
	int mnt_count;
	int mnt_writers;
#endif
	struct list_head mnt_mounts;	/* list of children, anchored here */
	struct list_head mnt_child;	/* and going through their mnt_child */
	struct list_head mnt_instance;	/* mount instance on sb->s_mounts */
	const char *mnt_devname;	/* Name of device e.g. /dev/dsk/hda1 */
	struct list_head mnt_list;
	struct list_head mnt_expire;	/* link in fs-specific expiry list */
	struct list_head mnt_share;	/* circular list of shared mounts */
	struct list_head mnt_slave_list;/* list of slave mounts */
	struct list_head mnt_slave;	/* slave list entry */
	struct mount *mnt_master;	/* slave is on master->mnt_slave_list */
	struct mnt_namespace *mnt_ns;	/* containing namespace */
#ifdef CONFIG_FSNOTIFY
	struct hlist_head mnt_fsnotify_marks;
	__u32 mnt_fsnotify_mask;
#endif
	int mnt_id;			/* mount identifier */
	int mnt_group_id;		/* peer group identifier */
	int mnt_expiry_mark;		/* true if marked for expiry */
	int mnt_pinned;
	int mnt_ghosts;
};

#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,13,0)
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
    struct proc_dir_entry {
        unsigned int low_ino;
        umode_t mode;
        nlink_t nlink;
        kuid_t uid;
        kgid_t gid;
        loff_t size;
        const struct inode_operations *proc_iops;
        const struct file_operations *proc_fops;
        struct proc_dir_entry *next, *parent, *subdir;
        void *data;
        atomic_t count;         /* use count */
        atomic_t in_use;        /* number of callers into module in progress; */
                              /* negative -> it's going away RSN */
        struct completion *pde_unload_completion;
        struct list_head pde_openers;   /* who did ->open, but not ->release */
        spinlock_t pde_unload_lock; /* proc_fops checks and pde_users bumps */
        u8 namelen;
        char name[];
    };
#else
   struct proc_dir_entry {
        unsigned int low_ino;
        umode_t mode;
        nlink_t nlink;
        kuid_t uid;
        kgid_t gid;
        loff_t size;
        const struct inode_operations *proc_iops;
        const struct file_operations *proc_fops;
        struct proc_dir_entry *parent;
        struct rb_root subdir;
        struct rb_node subdir_node;
        void *data;
        atomic_t count;     /* use count */
        atomic_t in_use;    /* number of callers into module in progress; */
                /* negative -> it's going away RSN */
        struct completion *pde_unload_completion;
        struct list_head pde_openers;   /* who did ->open, but not ->release */
        spinlock_t pde_unload_lock; /* proc_fops checks and pde_users bumps */
        u8 namelen;
        char name[];
   };
#endif
#endif

struct resource resource;

#if LINUX_VERSION_CODE == KERNEL_VERSION(5,2,9)


#define BUSY_WORKER_HASH_ORDER 6
#define WQ_NAME_LEN	  24

struct workqueue_struct {
	struct list_head	pwqs;		/* WR: all pwqs of this wq */
	struct list_head	list;		/* PR: list of all workqueues */

	struct mutex		mutex;		/* protects this wq */
	int			work_color;	/* WQ: current work color */
	int			flush_color;	/* WQ: current flush color */
	atomic_t		nr_pwqs_to_flush; /* flush in progress */
	struct wq_flusher	*first_flusher;	/* WQ: first flusher */
	struct list_head	flusher_queue;	/* WQ: flush waiters */
	struct list_head	flusher_overflow; /* WQ: flush overflow list */

	struct list_head	maydays;	/* MD: pwqs requesting rescue */
	struct worker		*rescuer;	/* I: rescue worker */

	int			nr_drainers;	/* WQ: drain in progress */
	int			saved_max_active; /* WQ: saved pwq max_active */

	struct workqueue_attrs	*unbound_attrs;	/* PW: only for unbound wqs */
	struct pool_workqueue	*dfl_pwq;	/* PW: only for unbound wqs */

#ifdef CONFIG_SYSFS
	struct wq_device	*wq_dev;	/* I: for sysfs interface */
#endif
#ifdef CONFIG_LOCKDEP
	char			*lock_name;
	struct lock_class_key	key;
	struct lockdep_map	lockdep_map;
#endif
	char			name[WQ_NAME_LEN]; /* I: workqueue name */

	/*
	 * Destruction of workqueue_struct is RCU protected to allow walking
	 * the workqueues list without grabbing wq_pool_mutex.
	 * This is used to dump all workqueues from sysrq.
	 */
	struct rcu_head		rcu;

	/* hot fields used during command issue, aligned to cacheline */
	unsigned int		flags ____cacheline_aligned; /* WQ: WQ_* flags */
	struct pool_workqueue __percpu *cpu_pwqs; /* I: per-cpu pwqs */
	struct pool_workqueue __rcu *numa_pwq_tbl[]; /* PWR: unbound pwqs indexed by node */
};

struct pool_workqueue {
	struct worker_pool	*pool;		/* I: the associated pool */
	struct workqueue_struct *wq;		/* I: the owning workqueue */
	int			work_color;	/* L: current color */
	int			flush_color;	/* L: flushing color */
	int			refcnt;		/* L: reference count */
	int			nr_in_flight[WORK_NR_COLORS];
						/* L: nr of in_flight works */
	int			nr_active;	/* L: nr of active works */
	int			max_active;	/* L: max active works */
	struct list_head	delayed_works;	/* L: delayed works */
	struct list_head	pwqs_node;	/* WR: node on wq->pwqs */
	struct list_head	mayday_node;	/* MD: node on wq->maydays */

	/*
	 * Release of unbound pwq is punted to system_wq.  See put_pwq()
	 * and pwq_unbound_release_workfn() for details.  pool_workqueue
	 * itself is also sched-RCU protected so that the first pwq can be
	 * determined without grabbing wq->mutex.
	 */
	struct work_struct	unbound_release_work;
	struct rcu_head		rcu;
} __aligned(1 << WORK_STRUCT_FLAG_BITS);


struct worker_pool {
	spinlock_t		lock;		/* the pool lock */
	int			cpu;		/* I: the associated cpu */
	int			node;		/* I: the associated node ID */
	int			id;		/* I: pool ID */
	unsigned int		flags;		/* X: flags */

	unsigned long		watchdog_ts;	/* L: watchdog timestamp */

	struct list_head	worklist;	/* L: list of pending works */

	int			nr_workers;	/* L: total number of workers */
	int			nr_idle;	/* L: currently idle workers */

	struct list_head	idle_list;	/* X: list of idle workers */
	struct timer_list	idle_timer;	/* L: worker idle timeout */
	struct timer_list	mayday_timer;	/* L: SOS timer for workers */

	/* a workers is either on busy_hash or idle_list, or the manager */
	DECLARE_HASHTABLE(busy_hash, BUSY_WORKER_HASH_ORDER);
						/* L: hash of busy workers */

	struct worker		*manager;	/* L: purely informational */
	struct list_head	workers;	/* A: attached workers */
	struct completion	*detach_completion; /* all workers detached */

	struct ida		worker_ida;	/* worker IDs for task name */

	struct workqueue_attrs	*attrs;		/* I: worker attributes */
	struct hlist_node	hash_node;	/* PL: unbound_pool_hash node */
	int			refcnt;		/* PL: refcnt for unbound pools */

	/*
	 * The current concurrency level.  As it's likely to be accessed
	 * from other CPUs during try_to_wake_up(), put it in a separate
	 * cacheline.
	 */
	atomic_t		nr_running ____cacheline_aligned_in_smp;

	/*
	 * Destruction of pool is RCU protected to allow dereferences
	 * from get_work_pool().
	 */
	struct rcu_head		rcu;
} ____cacheline_aligned_in_smp;

struct worker {
	/* on idle list while idle, on busy hash table while busy */
	union {
		struct list_head	entry;	/* L: while idle */
		struct hlist_node	hentry;	/* L: while busy */
	};

	struct work_struct	*current_work;	/* L: work being processed */
	work_func_t		current_func;	/* L: current_work's fn */
	struct pool_workqueue	*current_pwq; /* L: current_work's pwq */
	struct list_head	scheduled;	/* L: scheduled works */

	/* 64 bytes boundary on 64bit, 32 on 32bit */

	struct task_struct	*task;		/* I: worker task */
	struct worker_pool	*pool;		/* A: the associated pool */
						/* L: for rescuers */
	struct list_head	node;		/* A: anchored at pool->workers */
						/* A: runs through worker->node */

	unsigned long		last_active;	/* L: last active timestamp */
	unsigned int		flags;		/* X: flags */
	int			id;		/* I: worker id */
	int			sleeping;	/* None */

	/*
	 * Opaque string set with work_set_desc().  Printed out with task
	 * dump for debugging - WARN, BUG, panic or sysrq.
	 */
	char			desc[WORKER_DESC_LEN];

	/* used only by rescuers to point to the target workqueue */
	struct workqueue_struct	*rescue_wq;	/* I: the workqueue to rescue */

	/* used by the scheduler to determine a worker's last known identity */
	work_func_t		last_func;
};

struct workqueue_struct wqs;
struct pool_workqueue pwq;
struct worker_pool wq;
struct worker w;

#endif

#if LINUX_VERSION_CODE == KERNEL_VERSION(4,15,18)

#define BUSY_WORKER_HASH_ORDER 6
#define WQ_NAME_LEN	  24

struct workqueue_struct {
	struct list_head	pwqs;		/* WR: all pwqs of this wq */
	struct list_head	list;		/* PR: list of all workqueues */

	struct mutex		mutex;		/* protects this wq */
	int			work_color;	/* WQ: current work color */
	int			flush_color;	/* WQ: current flush color */
	atomic_t		nr_pwqs_to_flush; /* flush in progress */
	struct wq_flusher	*first_flusher;	/* WQ: first flusher */
	struct list_head	flusher_queue;	/* WQ: flush waiters */
	struct list_head	flusher_overflow; /* WQ: flush overflow list */

	struct list_head	maydays;	/* MD: pwqs requesting rescue */
	struct worker		*rescuer;	/* I: rescue worker */

	int			nr_drainers;	/* WQ: drain in progress */
	int			saved_max_active; /* WQ: saved pwq max_active */

	struct workqueue_attrs	*unbound_attrs;	/* PW: only for unbound wqs */
	struct pool_workqueue	*dfl_pwq;	/* PW: only for unbound wqs */

#ifdef CONFIG_SYSFS
	struct wq_device	*wq_dev;	/* I: for sysfs interface */
#endif
#ifdef CONFIG_LOCKDEP
	struct lockdep_map	lockdep_map;
#endif
	char			name[WQ_NAME_LEN]; /* I: workqueue name */

	/*
	 * Destruction of workqueue_struct is sched-RCU protected to allow
	 * walking the workqueues list without grabbing wq_pool_mutex.
	 * This is used to dump all workqueues from sysrq.
	 */
	struct rcu_head		rcu;

	/* hot fields used during command issue, aligned to cacheline */
	unsigned int		flags ____cacheline_aligned; /* WQ: WQ_* flags */
	struct pool_workqueue __percpu *cpu_pwqs; /* I: per-cpu pwqs */
	struct pool_workqueue __rcu *numa_pwq_tbl[]; /* PWR: unbound pwqs indexed by node */
};

struct worker_pool {
	spinlock_t		lock;		/* the pool lock */
	int			cpu;		/* I: the associated cpu */
	int			node;		/* I: the associated node ID */
	int			id;		/* I: pool ID */
	unsigned int		flags;		/* X: flags */

	unsigned long		watchdog_ts;	/* L: watchdog timestamp */

	struct list_head	worklist;	/* L: list of pending works */
	int			nr_workers;	/* L: total number of workers */

	/* nr_idle includes the ones off idle_list for rebinding */
	int			nr_idle;	/* L: currently idle ones */

	struct list_head	idle_list;	/* X: list of idle workers */
	struct timer_list	idle_timer;	/* L: worker idle timeout */
	struct timer_list	mayday_timer;	/* L: SOS timer for workers */

	/* a workers is either on busy_hash or idle_list, or the manager */
	DECLARE_HASHTABLE(busy_hash, BUSY_WORKER_HASH_ORDER);
						/* L: hash of busy workers */

	/* see manage_workers() for details on the two manager mutexes */
	struct worker		*manager;	/* L: purely informational */
	struct mutex		attach_mutex;	/* attach/detach exclusion */
	struct list_head	workers;	/* A: attached workers */
	struct completion	*detach_completion; /* all workers detached */

	struct ida		worker_ida;	/* worker IDs for task name */

	struct workqueue_attrs	*attrs;		/* I: worker attributes */
	struct hlist_node	hash_node;	/* PL: unbound_pool_hash node */
	int			refcnt;		/* PL: refcnt for unbound pools */

	/*
	 * The current concurrency level.  As it's likely to be accessed
	 * from other CPUs during try_to_wake_up(), put it in a separate
	 * cacheline.
	 */
	atomic_t		nr_running ____cacheline_aligned_in_smp;

	/*
	 * Destruction of pool is sched-RCU protected to allow dereferences
	 * from get_work_pool().
	 */
	struct rcu_head		rcu;
} ____cacheline_aligned_in_smp;

/*
 * The per-pool workqueue.  While queued, the lower WORK_STRUCT_FLAG_BITS
 * of work_struct->data are used for flags and the remaining high bits
 * point to the pwq; thus, pwqs need to be aligned at two's power of the
 * number of flag bits.
 */
struct pool_workqueue {
	struct worker_pool	*pool;		/* I: the associated pool */
	struct workqueue_struct *wq;		/* I: the owning workqueue */
	int			work_color;	/* L: current color */
	int			flush_color;	/* L: flushing color */
	int			refcnt;		/* L: reference count */
	int			nr_in_flight[WORK_NR_COLORS];
						/* L: nr of in_flight works */
	int			nr_active;	/* L: nr of active works */
	int			max_active;	/* L: max active works */
	struct list_head	delayed_works;	/* L: delayed works */
	struct list_head	pwqs_node;	/* WR: node on wq->pwqs */
	struct list_head	mayday_node;	/* MD: node on wq->maydays */

	/*
	 * Release of unbound pwq is punted to system_wq.  See put_pwq()
	 * and pwq_unbound_release_workfn() for details.  pool_workqueue
	 * itself is also sched-RCU protected so that the first pwq can be
	 * determined without grabbing wq->mutex.
	 */
	struct work_struct	unbound_release_work;
	struct rcu_head		rcu;
} __aligned(1 << WORK_STRUCT_FLAG_BITS);


struct worker {
	/* on idle list while idle, on busy hash table while busy */
	union {
		struct list_head	entry;	/* L: while idle */
		struct hlist_node	hentry;	/* L: while busy */
	};

	struct work_struct	*current_work;	/* L: work being processed */
	work_func_t		current_func;	/* L: current_work's fn */
	struct pool_workqueue	*current_pwq; /* L: current_work's pwq */
	bool			desc_valid;	/* ->desc is valid */
	struct list_head	scheduled;	/* L: scheduled works */

	/* 64 bytes boundary on 64bit, 32 on 32bit */

	struct task_struct	*task;		/* I: worker task */
	struct worker_pool	*pool;		/* I: the associated pool */
						/* L: for rescuers */
	struct list_head	node;		/* A: anchored at pool->workers */
						/* A: runs through worker->node */

	unsigned long		last_active;	/* L: last active timestamp */
	unsigned int		flags;		/* X: flags */
	int			id;		/* I: worker id */

	/*
	 * Opaque string set with work_set_desc().  Printed out with task
	 * dump for debugging - WARN, BUG, panic or sysrq.
	 */
	char			desc[WORKER_DESC_LEN];

	/* used only by rescuers to point to the target workqueue */
	struct workqueue_struct	*rescue_wq;	/* I: the workqueue to rescue */
};


struct workqueue_struct wqs;
struct pool_workqueue pwq;
struct worker_pool wq;
struct worker w;

#endif
