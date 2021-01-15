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
