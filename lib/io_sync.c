// SPDX-License-Identifier: GPL-2.0+
#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include "erofs/io.h"

#define pr_fmt(fmt) "EROFS IO_SYNC: " FUNC_LINE_FMT fmt "\n"
#include "erofs/print.h"

extern const char *erofs_devname;
extern int erofs_devfd;

struct erofs_fd {
	int fd;
};

struct erofs_fd *erofs_new_fd(int fd)
{
	struct erofs_fd *erofs_fd = malloc(sizeof(struct erofs_fd));
	if (!erofs_fd)
		return ERR_PTR(-ENOMEM);
	erofs_fd->fd = fd;
	return erofs_fd;
}

void erofs_close_fd(struct erofs_fd *fd)
{
	close(fd->fd);
	free(fd);
}

int erofs_io_drain(void)
{
	return 0;
}

static bool fixed_buf_in_use;
static char fixed_buf[IO_BLOCK_SIZE];

void *erofs_io_get_fixed_buffer(void)
{
	if (fixed_buf_in_use)
		return ERR_PTR(-EAGAIN);
	fixed_buf_in_use = true;
	return fixed_buf;
}

int dev_write_from_fixed_buffer(void *buf, u64 offset, size_t len)
{
	DBG_BUGON(((char *)buf - fixed_buf) < 0);
	DBG_BUGON(((char *)buf + len - fixed_buf) > IO_BLOCK_SIZE);
	fixed_buf_in_use = false;
	return dev_write(buf, offset, len, false);
}

int buffer_copy_from_fd(struct erofs_fd *fd, void *buffer, u64 offset, unsigned int len)
{
	ssize_t ret = pread64(fd->fd, buffer, len, offset);
	if (ret != len) {
		if (ret < 0)
			return -errno;
		return -EAGAIN;
	}
	return 0;
}

int dev_copy_from_fd(struct erofs_fd *fd, u64 dev_offset, unsigned int len)
{
	int ret;
	char buf[IO_BLOCK_SIZE];

	ret = lseek(fd->fd, 0, SEEK_SET);
	if (ret < 0)
		return -errno;
	while (len) {
		unsigned int this_size = len;

		if (this_size > IO_BLOCK_SIZE)
			this_size = IO_BLOCK_SIZE;
		len -= this_size;

		ret = read(fd->fd, buf, this_size);
		if (ret != this_size) {
			if (ret < 0)
				return -errno;
			return -EAGAIN;
		}

		ret = dev_write(buf, dev_offset, this_size, false);
		if (ret)
			return ret;

		dev_offset += this_size;
	}
	return 0;
}

int __dev_write(void *buf, u64 offset, size_t len, bool free_buf)
{
	int ret;

	ret = pwrite64(erofs_devfd, buf, len, (off64_t)offset);
	if (ret != (int)len) {
		if (ret < 0) {
			erofs_err("Failed to write data into device - %s:[%" PRIu64 ", %zd].",
				  erofs_devname, offset, len);
			return -errno;
		}

		erofs_err("Writing data into device - %s:[%" PRIu64 ", %zd] - was truncated.",
			  erofs_devname, offset, len);
		return -ERANGE;
	}
	if (free_buf)
		free(buf);
	return 0;
}
