#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include "tracer.h"

MODULE_DESCRIPTION("Tracer");
MODULE_AUTHOR("Michael Vrána <vranami8@fit.cvut.cz>");
MODULE_LICENSE("GPL v2");

#define procfs_filename "tracer"

struct proc_dir_entry *proc_entry;

static int tracer_print(struct seq_file *m, void *v)
{
	seq_puts(m, "Hello world\n");

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

static int tracer_init(void)
{
	proc_entry = proc_create(procfs_filename, 0444, NULL, &pops);

	if (!proc_entry)
		return -ENOMEM;

	return 0;
}

static void tracer_exit(void)
{
	proc_remove(proc_entry);
}

module_init(tracer_init);
module_exit(tracer_exit);