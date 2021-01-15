// SPDX-License-Identifier: GPL-2.0+
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
