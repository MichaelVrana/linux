// SPDX-License-Identifier: GPL-2.0+

/*
 * list.c - Linux kernel list API
 *
 * TODO 1/0: Fill in name / email
 * Author: Michael Vrána <vranami8@fit.cvut.cz>
 */
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>

#define FALSE 0
#define TRUE 1

#define PROCFS_MAX_SIZE 512

#define procfs_dir_name "list"
#define procfs_file_read "preview"
#define procfs_file_write "management"

struct proc_dir_entry *proc_list;
struct proc_dir_entry *proc_list_read;
struct proc_dir_entry *proc_list_write;

#define COMMAND_LENGTH 4

enum command {
	PARSE_ERROR = -1,
	ADD_START = 1,
	ADD_END = 2,
	DEL_FIRST = 3,
	DEL_ALL = 4
};

struct list_node {
	const char *str;
	struct list_head list;
};

static struct list_node *list_node_init(const char *str)
{
	struct list_node *node = kmalloc(sizeof(*node), GFP_KERNEL);

	node->str = str;

	return node;
}

/* TODO 2: define your list! */
LIST_HEAD(head);

static int list_proc_show(struct seq_file *m, void *v)
{
	struct list_node *curr;

	/* TODO 3: print your list. One element / line. */
	list_for_each_entry (curr, &head, list) {
		seq_puts(m, curr->str);
		seq_putc(m, '\n');
	}

	return 0;
}

static int list_read_open(struct inode *inode, struct file *file)
{
	return single_open(file, list_proc_show, NULL);
}

static int list_write_open(struct inode *inode, struct file *file)
{
	return single_open(file, list_proc_show, NULL);
}

static int buffer_starts_with(const char *buffer, const char *pattern)
{
	for (size_t i = 0; pattern[i]; ++i)
		if (buffer[i] != pattern[i])
			return FALSE;

	return TRUE;
}

static int parse_command(const char *buffer, unsigned long size)
{
	if (size < COMMAND_LENGTH)
		return PARSE_ERROR;

	if (buffer_starts_with(buffer, "add")) {
		switch (buffer[3]) {
		case 'f':
			return ADD_START;
		case 'e':
			return ADD_END;
		}
	}

	if (buffer_starts_with(buffer, "del")) {
		switch (buffer[3]) {
		case 'f':
			return DEL_FIRST;
		case 'a':
			return DEL_ALL;
		}
	}

	return PARSE_ERROR;
}

#define is_whitespace(c) (c == ' ' || c == '\t')

static size_t word_length(const char *buffer, unsigned long size,
			  size_t word_cursor)
{
	size_t length = 0;

	while (word_cursor < size && !is_whitespace(buffer[word_cursor])) {
		++length;
		++word_cursor;
	}

	return length;
}

static size_t find_word_start(const char *buffer, unsigned long size,
			      size_t cursor)
{
	while (cursor < size && is_whitespace(buffer[cursor]))
		++cursor;

	return cursor;
}

static char *extract_string(const char *buffer, unsigned long size)
{
	size_t word_start = find_word_start(buffer, size, COMMAND_LENGTH);
	size_t length = word_length(buffer, size, word_start);
	char *str = kmalloc(length + 1, GFP_KERNEL);

	memcpy(str, buffer + word_start, length);
	str[length] = '\0';

	return str;
}

static void add_start(const char *str)
{
	struct list_node *node = list_node_init(str);
	list_add(&node->list, &head);
}

static void add_end(const char *str)
{
	struct list_node *node = list_node_init(str);
	list_add_tail(&node->list, &head);
}

static int process_command(const char *buffer, size_t size)
{
	int command = parse_command(buffer, size);

	switch (command) {
	case ADD_START:
		add_start(extract_string(buffer, size));
		break;
	case ADD_END:
		add_end(extract_string(buffer, size));
		break;

	default:
		return 0;
	}

	return 1;
}

static ssize_t list_write(struct file *file, const char __user *buffer,
			  size_t count, loff_t *offs)
{
	char local_buffer[PROCFS_MAX_SIZE];
	unsigned long local_buffer_size = 0;

	local_buffer_size = count;
	if (local_buffer_size > PROCFS_MAX_SIZE)
		local_buffer_size = PROCFS_MAX_SIZE;

	memset(local_buffer, 0, PROCFS_MAX_SIZE);
	if (copy_from_user(local_buffer, buffer, local_buffer_size))
		return -EFAULT;

	/* local_buffer contains your command written in /proc/list/management
	 * TODO 4/0: parse the command and add/delete elements.
	 */
	if (!process_command(buffer, count)) return -EFAULT;

	return local_buffer_size;
}

static const struct proc_ops r_pops = {
	.proc_open = list_read_open,
	.proc_read = seq_read,
	.proc_release = single_release,
};

static const struct proc_ops w_pops = {
	.proc_open = list_write_open,
	.proc_write = list_write,
	.proc_release = single_release,
};

static int list_init(void)
{
	proc_list = proc_mkdir(procfs_dir_name, NULL);
	if (!proc_list)
		return -ENOMEM;

	proc_list_read =
		proc_create(procfs_file_read, 0000, proc_list, &r_pops);
	if (!proc_list_read)
		goto proc_list_cleanup;

	proc_list_write =
		proc_create(procfs_file_write, 0222, proc_list, &w_pops);
	if (!proc_list_write)
		goto proc_list_read_cleanup;

	return 0;

proc_list_read_cleanup:
	proc_remove(proc_list_read);
proc_list_cleanup:
	proc_remove(proc_list);
	return -ENOMEM;
}

static void list_exit(void)
{
	proc_remove(proc_list);
}

module_init(list_init);
module_exit(list_exit);

MODULE_DESCRIPTION("Linux kernel list API");
/* TODO 5: Fill in your name / email address */
MODULE_AUTHOR("FirstName LastName <your@email.com>");
MODULE_LICENSE("GPL v2");
