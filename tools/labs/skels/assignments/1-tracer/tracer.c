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
#define MAX_ACTIVE_KRETPROBES 20

#define alloc(name, type) type *name = kmalloc(sizeof(*name), GFP_ATOMIC)

struct tracer_mem_block_node {
	struct list_head head;
	void *ptr;
	size_t size;
};

struct tracer_hlist_node {
	struct hlist_node node;
	struct list_head allocated_mem_blocks;
	atomic_t kmalloc;
	u32 kfree;
	u64 kmalloc_mem;
	u64 kfree_mem;
	atomic_t sched;
	atomic_t up;
	atomic_t down;
	atomic_t lock;
	atomic_t unlock;
	pid_t pid;
};

DEFINE_HASHTABLE(tracer_hash_table, TRACER_HASH_TABLE_BITS);
DEFINE_RWLOCK(lock);

// used to prevent deadlock when calling kmalloc/kfree inside kreprobes handler cirtical sections
static pid_t lock_owner = 0;

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
		if (tracer_entry)                                              \
			atomic_inc(&tracer_entry->node_member);                \
                                                                               \
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
		.maxactive = MAX_ACTIVE_KRETPROBES,                                               \
	};

static struct tracer_mem_block_node *tracer_mem_block_node_init(void *ptr,
								size_t size)
{
	alloc(node, struct tracer_mem_block_node);

	node->ptr = ptr;
	node->size = size;

	return node;
}

static void
tracer_hlist_node_record_mem_block(struct tracer_hlist_node *tracer_entry,
				   void *ptr, size_t size)
{
	struct tracer_mem_block_node *mem_block_node =
		tracer_mem_block_node_init(ptr, size);

	tracer_entry->kmalloc_mem += size;

	list_add(&mem_block_node->head, &tracer_entry->allocated_mem_blocks);
}

static void
tracer_hlist_node_free_mem_block(struct tracer_hlist_node *tracer_entry,
				 void *ptr)
{
	struct tracer_mem_block_node *curr;

	list_for_each_entry (curr, &tracer_entry->allocated_mem_blocks, head) {
		if (curr->ptr != ptr)
			continue;

		tracer_entry->kfree_mem += curr->size;

		list_del(&curr->head);
		kfree(curr);

		return;
	}
}

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
		seq_printf(m, "%u\t%u\t%u\t%llu\t%llu\t%u\t%u\t%u\t%u\t%u\n",
			   curr->pid, atomic_read(&curr->kmalloc), curr->kfree,
			   curr->kmalloc_mem, curr->kfree_mem,
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

	INIT_LIST_HEAD(&node->allocated_mem_blocks);

	node->kfree = 0;
	node->kmalloc_mem = 0;
	node->kfree_mem = 0;
	atomic_set(&node->kmalloc, 0);
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

	if (!node) {
		write_unlock(&lock);
		return;
	}

	hash_del(&node->node);

	write_unlock(&lock);

	delete_list(&node->allocated_mem_blocks);
	kfree(node);
}

static void delete_hash_table(void)
{
	size_t i;
	struct hlist_node *tmp;
	struct tracer_hlist_node *curr;

	write_lock(&lock);

	hash_for_each_safe (tracer_hash_table, i, tmp, curr, node) {
		delete_list(&curr->allocated_mem_blocks);

		hash_del(&curr->node);
		kfree(curr);
	}

	write_unlock(&lock);
}

struct kmalloc_kretprobe_data {
	size_t size;
};

static int kmalloc_entry_handler(struct kretprobe_instance *ri,
				 struct pt_regs *regs)
{
	struct tracer_hlist_node *tracer_entry;
	struct kmalloc_kretprobe_data *probe_data;

	if (!current || !current->pid || current->pid == lock_owner)
		return 1;

	read_lock(&lock);

	tracer_entry = get_tracer_entry(current->pid);

	if (!tracer_entry) {
		read_unlock(&lock);
		return 1;
	}

	atomic_inc(&tracer_entry->kmalloc);
	read_unlock(&lock);

	probe_data = (struct kmalloc_kretprobe_data *)ri->data;
	probe_data->size = (size_t)regs_get_kernel_argument(regs, 0);

	return 0;
}
NOKPROBE_SYMBOL(kmalloc_entry_handler);

static int kmalloc_ret_handler(struct kretprobe_instance *ri,
			       struct pt_regs *regs)
{
	struct tracer_hlist_node *tracer_entry;
	void *ptr = (void *)regs_return_value(regs);
	struct kmalloc_kretprobe_data *probe_data =
		(struct kmalloc_kretprobe_data *)ri->data;

	write_lock(&lock);
	lock_owner = current->pid;

	tracer_entry = get_tracer_entry(current->pid);

	if (tracer_entry)
		tracer_hlist_node_record_mem_block(tracer_entry, ptr,
						   probe_data->size);

	lock_owner = 0;
	write_unlock(&lock);

	return 0;
}
NOKPROBE_SYMBOL(kmalloc_ret_handler);

static struct kretprobe kmalloc_probe = { 
	.entry_handler = kmalloc_entry_handler,
	.handler = kmalloc_ret_handler,
	.kp = { 
		.symbol_name = "__kmalloc",
	}, 
	.maxactive = MAX_ACTIVE_KRETPROBES,
	.data_size = sizeof(struct kmalloc_kretprobe_data),
};

static int kfree_entry_handler(struct kretprobe_instance *ri,
			       struct pt_regs *regs)
{
	struct tracer_hlist_node *tracer_entry;
	void *ptr = (void *)regs_get_kernel_argument(regs, 0);

	if (!current || !current->pid || current->pid == lock_owner)
		return 1;

	write_lock(&lock);
	lock_owner = current->pid;

	tracer_entry = get_tracer_entry(current->pid);

	if (tracer_entry) {
		++(tracer_entry->kfree);
		tracer_hlist_node_free_mem_block(tracer_entry, ptr);
	}

	lock_owner = 0;
	write_unlock(&lock);

	return 1;
}
NOKPROBE_SYMBOL(kfree_entry_handler);

static struct kretprobe kfree_probe = { 
	.entry_handler = kfree_entry_handler,
	.kp = { 
		.symbol_name = "kfree",
	},
	.maxactive = MAX_ACTIVE_KRETPROBES,
};

static int do_exit_entry_handler(struct kretprobe_instance *ri,
				 struct pt_regs *regs)
{
	if (current && current->pid)
		stop_tracking_process(current->pid);

	return 1;
}
NOKPROBE_SYMBOL(do_exit_entry_handler);

static struct kretprobe do_exit_probe = {
	.entry_handler = do_exit_entry_handler,
	.kp = {
		.symbol_name = "do_exit",
	},
	.maxactive = MAX_ACTIVE_KRETPROBES,
};

DEFINE_CALL_COUNT_KRETPROBE(sched_probe, schedule, sched)
DEFINE_CALL_COUNT_KRETPROBE(up_probe, up, up)
DEFINE_CALL_COUNT_KRETPROBE(down_probe, down_interruptible, down)
DEFINE_CALL_COUNT_KRETPROBE(lock_probe, mutex_lock_nested, lock)
DEFINE_CALL_COUNT_KRETPROBE(unlock_probe, mutex_unlock, unlock)

static struct kretprobe *probes[] = {
	&kmalloc_probe, &kfree_probe, &sched_probe,  &up_probe,
	&down_probe,	&lock_probe,  &unlock_probe, &do_exit_probe,
};

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

static struct proc_dir_entry *proc_entry;

static int tracer_init(void)
{
	proc_entry = proc_create(procfs_filename, 0444, NULL, &pops);

	if (!proc_entry) {
		pr_err("Failed to create procfs entry");
		return -EIO;
	}

	if (misc_register(&miscdev)) {
		pr_err("Failed to register miscdevice");
		return -EIO;
	}

	if (register_kretprobes(probes, ARRAY_SIZE(probes))) {
		pr_err("Failed to register kretprobes");
		return -EIO;
	}

	return 0;
}

static void tracer_exit(void)
{
	unregister_kretprobes(probes, ARRAY_SIZE(probes));
	proc_remove(proc_entry);
	misc_deregister(&miscdev);
	delete_hash_table();
}

module_init(tracer_init);
module_exit(tracer_exit);