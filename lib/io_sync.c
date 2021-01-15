#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif
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

int erofs_io_drain()
{
	return 0;
}

void *erofs_io_get_fixed_buffer()
{
    void *buf = malloc(IO_BLOCK_SIZE);
    if (!buf)
        return ERR_PTR(-ENOMEM);
    return buf;
}

int dev_write_from_fixed_buffer(void *buf, u64 offset, size_t len)
{
    return dev_write(buf, offset, len, true);
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
    int ret = pwrite64(erofs_devfd, buf, len, (off64_t)offset);
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
    return 0;
}
