// SPDX-License-Identifier: GPL-2.0


/* Displays debugging information about an io_uring file descriptor in the /proc filesystem. */
void io_uring_show_fdinfo(struct seq_file *m, struct file *f);
