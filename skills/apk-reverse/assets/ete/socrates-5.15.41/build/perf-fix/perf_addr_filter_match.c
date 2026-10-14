// SPDX-License-Identifier: GPL-2.0
/* Replacement for the recorded kernel/events/core.c function, not a module. */
static bool perf_addr_filter_match(struct perf_addr_filter *filter,
				     struct file *file, unsigned long offset,
				     unsigned long size)
{
	/* d_inode(NULL) won't be equal to any mapped user-space file */
	if (!filter->path.dentry)
		return false;

	if (d_inode(filter->path.dentry) != file_inode(file))
		return false;

	/* A VMA is half-open. A point may match its start, never its end. */
	if (!size)
		return false;

	if (filter->offset >= offset)
		return filter->offset - offset < size;

	/* A nonempty filter ending at the VMA start has no overlap either.
	 * Subtraction also avoids wrapping either exclusive end address.
	 */
	return filter->size > offset - filter->offset;
}
