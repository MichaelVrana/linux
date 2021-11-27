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
#include "tracer.h"

MODULE_DESCRIPTION("Tracer");
MODULE_AUTHOR("Michael Vrána <vranami8@fit.cvut.cz>");
MODULE_LICENSE("GPL v2");

#define procfs_filename "tracer"

#define TRACER_HASH_TABLE_BITS 8
#define TRACER_MEMORY_HASH_TABLE_BITS 10

struct tracer_mem_block_node {
	struct list_head head;
	u64 address;
	u64 size;
};

struct tracer_hlist_node {
	struct hlist_node node;
	struct list_head alloc_mem_blocks;
	u64 kmalloc;
	u64 kfree;
	u64 kmalloc_mem;
	u64 kfree_mem;
	u64 sched;
	u64 up;
	u64 down;
	u64 lock;
	u64 unlock;
	pid_t pid;
};

DEFINE_HASHTABLE(tracer_hash_table, TRACER_HASH_TABLE_BITS);
DEFINE_RWLOCK(lock);

static struct tracer_hlist_node *get_tracer_entry(pid_t pid)
{
	struct tracer_hlist_node *curr;

	read_lock(&lock);

	hash_for_each_possible (tracer_hash_table, curr, node, pid) {
		if (curr->pid == pid) {
			read_unlock(&lock);
			return curr;
		}
	}

	read_unlock(&lock);
	return NULL;
}

static char func_name[NAME_MAX] = "__kmalloc";

// struct my_data {
// 	ktime_t entry_stamp;
// };

static int entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	// struct my_data *data;

	if (!current->mm)
		return 1; /* Skip kernel threads */

	// data = (struct my_data *)ri->data;
	// data->entry_stamp = ktime_get();
	return 0;
}
NOKPROBE_SYMBOL(entry_handler);

static int ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
	unsigned long retval = regs_return_value(regs);
	struct my_data *data = (struct my_data *)ri->data;
	s64 delta;
	ktime_t now;

	now = ktime_get();
	// delta = ktime_to_ns(ktime_sub(now, data->entry_stamp));

	pr_info("%s returned %lu and took %lld ns to execute\n", func_name,
		retval, (long long)now);

	return 0;
}
NOKPROBE_SYMBOL(ret_handler);

static struct kretprobe my_kretprobe = {
	.handler = ret_handler,
	.entry_handler = entry_handler,
	// .data_size = sizeof(struct my_data),
	.data_size = 0,
	.maxactive = 20,
};

static int kretprobe_init(void)
{
	int ret;

	my_kretprobe.kp.symbol_name = func_name;
	ret = register_kretprobe(&my_kretprobe);
	if (ret < 0) {
		pr_err("register_kretprobe failed, returned %d\n", ret);
		return -1;
	}
	pr_info("Planted return probe at %s: %p\n", my_kretprobe.kp.symbol_name,
		my_kretprobe.kp.addr);
	return 0;
}

static void kretprobe_exit(void)
{
	unregister_kretprobe(&my_kretprobe);
	pr_info("kretprobe at %p unregistered\n", my_kretprobe.kp.addr);

	/* nmissed > 0 suggests that maxactive was set too low. */
	pr_info("Missed probing %d instances of %s\n", my_kretprobe.nmissed,
		my_kretprobe.kp.symbol_name);
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
		seq_printf(
			m,
			"%u\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\t%llu\n",
			curr->pid, curr->kmalloc, curr->kfree,
			curr->kmalloc_mem, curr->kfree_mem, curr->sched,
			curr->up, curr->down, curr->lock, curr->unlock);
	}

	read_unlock(&lock);

	return 0;
}

static struct tracer_hlist_node *tracer_hlist_node_init(pid_t pid)
{
	struct tracer_hlist_node *node = kmalloc(sizeof(node), GFP_KERNEL);

	INIT_LIST_HEAD(&node->alloc_mem_blocks);

	node->kmalloc = 0;
	node->kfree = 0;
	node->kmalloc_mem = 0;
	node->kfree_mem = 0;
	node->sched = 0;
	node->up = 0;
	node->down = 0;
	node->lock = 0;
	node->unlock = 0;

	return node;
}

static void track_process(pid_t pid)
{
	struct tracer_hlist_node *tracer_entry = tracer_hlist_node_init(pid);

	write_lock(&lock);
	hash_add(tracer_hash_table, &tracer_entry->node, pid);
	write_unlock(&lock);
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

static void delete_hash_table(void)
{
	size_t i, j;
	struct hlist_node *tmp1, *tmp2;
	struct tracer_hlist_node *curr;

	hash_for_each_safe (tracer_hash_table, i, tmp1, curr, node) {
		delete_list(&curr->alloc_mem_blocks);

		hash_del(&curr->node);
		kfree(curr);
	}
}

static long ioctl(struct file *file, unsigned int command, unsigned long arg)
{
	return 1;
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
	.unlocked_ioctl = ioctl,
};

static struct miscdevice miscdev = {
	.minor = TRACER_DEV_MINOR,
	.name = TRACER_DEV_NAME,
	.fops = &fops,
};

struct proc_dir_entry *proc_entry;

static int __init tracer_init(void)
{
	proc_entry = proc_create(procfs_filename, 0444, NULL, &pops);

	if (!proc_entry)
		return -EIO;

	if (misc_register(&miscdev))
		return -EIO;

	return kretprobe_init();
}

static void __exit tracer_exit(void)
{
	proc_remove(proc_entry);
	misc_deregister(&miscdev);
	delete_hash_table();
	kretprobe_exit();
}

module_init(tracer_init);
module_exit(tracer_exit);