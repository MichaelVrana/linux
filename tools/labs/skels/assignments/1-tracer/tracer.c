#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/hashtable.h>
#include <linux/miscdevice.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/kprobes.h>
#include <asm/atomic.h>
#include "tracer.h"

MODULE_DESCRIPTION("Tracer");
MODULE_AUTHOR("Michael Vrána <vranami8@fit.cvut.cz>");
MODULE_LICENSE("GPL v2");

#define procfs_filename "tracer"

#define TRACER_HASH_TABLE_BITS 8
#define TRACER_MEMORY_HASH_TABLE_BITS 10

#define alloc(name, type) type *name = kmalloc(sizeof(*name), GFP_ATOMIC)

struct tracer_mem_block_node {
	struct list_head head;
	u64 address;
	u64 size;
};

struct tracer_hlist_node {
	struct hlist_node node;
	struct list_head alloc_mem_blocks;
	atomic_t kmalloc;
	atomic_t kfree;
	atomic_t kmalloc_mem;
	atomic_t kfree_mem;
	atomic_t sched;
	atomic_t up;
	atomic_t down;
	atomic_t lock;
	atomic_t unlock;
	pid_t pid;
};

DEFINE_HASHTABLE(tracer_hash_table, TRACER_HASH_TABLE_BITS);
DEFINE_RWLOCK(lock);

static struct tracer_hlist_node *get_tracer_entry(pid_t pid)
{
	struct tracer_hlist_node *curr;

	hash_for_each_possible (tracer_hash_table, curr, node, pid) {
		if (curr->pid == pid)
			return curr;
	}

	return NULL;
}

#define HANDLER_NAME(name) name##_entry_handler

#define DEFINE_CALL_COUNT_KRETPROBE(name, func_name, node_member)              \
	static int HANDLER_NAME(func_name)(struct kretprobe_instance * ri,     \
					   struct pt_regs * regs)              \
	{                                                                      \
		struct tracer_hlist_node *tracer_entry;                        \
                                                                               \
		if (!current || !current->pid)                                 \
			return 1;                                              \
                                                                               \
		read_lock(&lock);                                              \
                                                                               \
		tracer_entry = get_tracer_entry(current->pid);                 \
                                                                               \
		if (!tracer_entry) {                                           \
			read_unlock(&lock);                                    \
			return 1;                                              \
		}                                                              \
                                                                               \
		atomic_inc(&tracer_entry->node_member);                        \
		read_unlock(&lock);                                            \
		return 1;                                                      \
	}                                                                      \
	NOKPROBE_SYMBOL(HANDLER_NAME(func_name));                              \
                                                                               \
	static struct kretprobe name = {                                       \
		.entry_handler = HANDLER_NAME(func_name),                        \
		.kp = { \
			.symbol_name = #func_name, \
		},                                 \
		.maxactive = 20,                                               \
	};

static void delete_list(struct list_head *list)
{
	struct list_head *curr;
	struct list_head *tmp;
	struct tracer_mem_block_node *node;

	list_for_each_safe (curr, tmp, list) {
		node = list_entry(curr, struct tracer_mem_block_node, head);

		list_del(curr);
		kfree(node);
	}
}

static int tracer_print(struct seq_file *m, void *v)
{
	size_t i;
	struct tracer_hlist_node *curr;

	seq_puts(
		m,
		"PID\tkmalloc\tkfree\tkmalloc_mem\tkfree_mem\tsched\tup\tdown\tlock\tunlock\n");

	read_lock(&lock);

	hash_for_each (tracer_hash_table, i, curr, node) {
		seq_printf(m, "%u\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n",
			   curr->pid, atomic_read(&curr->kmalloc),
			   atomic_read(&curr->kfree),
			   atomic_read(&curr->kmalloc_mem),
			   atomic_read(&curr->kfree_mem),
			   atomic_read(&curr->sched), atomic_read(&curr->up),
			   atomic_read(&curr->down), atomic_read(&curr->lock),
			   atomic_read(&curr->unlock));
	}

	read_unlock(&lock);

	return 0;
}

static struct tracer_hlist_node *tracer_hlist_node_init(pid_t pid)
{
	alloc(node, struct tracer_hlist_node);

	node->pid = pid;

	INIT_LIST_HEAD(&node->alloc_mem_blocks);

	atomic_set(&node->kmalloc, 0);
	atomic_set(&node->kfree, 0);
	atomic_set(&node->kmalloc_mem, 0);
	atomic_set(&node->kfree_mem, 0);
	atomic_set(&node->sched, 0);
	atomic_set(&node->up, 0);
	atomic_set(&node->down, 0);
	atomic_set(&node->lock, 0);
	atomic_set(&node->unlock, 0);

	return node;
}

static void track_process(pid_t pid)
{
	struct tracer_hlist_node *tracer_entry = tracer_hlist_node_init(pid);

	write_lock(&lock);
	hash_add(tracer_hash_table, &tracer_entry->node, pid);
	write_unlock(&lock);
}

static void stop_tracking_process(pid_t pid)
{
	struct tracer_hlist_node *node;

	write_lock(&lock);

	node = get_tracer_entry(pid);

	if (!node)
		return;

	hash_del(&node->node);

	write_unlock(&lock);

	delete_list(&node->alloc_mem_blocks);
	kfree(node);
}

static void delete_hash_table(void)
{
	size_t i;
	struct hlist_node *tmp;
	struct tracer_hlist_node *curr;

	write_lock(&lock);

	hash_for_each_safe (tracer_hash_table, i, tmp, curr, node) {
		delete_list(&curr->alloc_mem_blocks);

		hash_del(&curr->node);
		kfree(curr);
	}

	write_unlock(&lock);
}

static long ioctl_handler(struct file *file, unsigned int command,
			  unsigned long arg)
{
	switch (command) {
	case TRACER_ADD_PROCESS:
		track_process(arg);
		break;

	case TRACER_REMOVE_PROCESS:
		stop_tracking_process(arg);
		break;
	}

	return 0;
}

static int proc_read_open(struct inode *inode, struct file *file)
{
	return single_open(file, tracer_print, NULL);
}

static const struct proc_ops pops = {
	.proc_open = proc_read_open,
	.proc_read = seq_read,
	.proc_release = single_release,
};

static const struct file_operations fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = ioctl_handler,
};

static struct miscdevice miscdev = {
	.minor = TRACER_DEV_MINOR,
	.name = TRACER_DEV_NAME,
	.fops = &fops,
};

struct proc_dir_entry *proc_entry;

DEFINE_CALL_COUNT_KRETPROBE(sched_probe, schedule, sched)
DEFINE_CALL_COUNT_KRETPROBE(up_probe, up, up)
DEFINE_CALL_COUNT_KRETPROBE(down_probe, down, down)
DEFINE_CALL_COUNT_KRETPROBE(lock_probe, mutex_lock_nested, lock)
DEFINE_CALL_COUNT_KRETPROBE(unlock_probe, mutex_unlock, unlock)

static struct kretprobe *probes[] = {
	&sched_probe, &up_probe, &down_probe, &lock_probe, &unlock_probe,
};

static int tracer_init(void)
{
	if (register_kretprobes(probes, ARRAY_SIZE(probes))) {
		pr_err("Failed to register kretprobes");
		return -EIO;
	}

	proc_entry = proc_create(procfs_filename, 0444, NULL, &pops);

	if (!proc_entry) {
		pr_err("Failed to create procfs entry");
		return -EIO;
	}

	if (misc_register(&miscdev)) {
		pr_err("Failed to register miscdevice");
		return -EIO;
	}

	return 0;
}

static void tracer_exit(void)
{
	proc_remove(proc_entry);
	misc_deregister(&miscdev);
	unregister_kretprobes(probes, ARRAY_SIZE(probes));
	delete_hash_table();
}

module_init(tracer_init);
module_exit(tracer_exit);