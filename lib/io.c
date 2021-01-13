// SPDX-License-Identifier: GPL-2.0+
/*
 * erofs-utils/lib/io.c
 *
 * Copyright (C) 2018 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 */
#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <stdlib.h>
#include "erofs/io.h"
#include "erofs/list.h"
#include "config.h"
#ifdef HAVE_LINUX_FS_H
#include <linux/fs.h>
#endif
#ifdef HAVE_LINUX_FALLOC_H
#include <linux/falloc.h>
#endif
#ifdef HAVE_LIBURING
#include <liburing.h>
#endif

#define pr_fmt(fmt) "EROFS IO: " FUNC_LINE_FMT fmt "\n"
#include "erofs/print.h"

static const char *erofs_devname;
static int erofs_devfd = -1;
static u64 erofs_devsz;

#define IO_BLOCK_SIZE (32*1024)
#ifdef HAVE_LIBURING
#define IO_QUEUE_DEPTH 64
static struct io_uring ring;
static int num_pending_sqe = 0;
#endif

struct erofs_fd {
	int fd;
	int inflight_io;
	int io_finished;
};

struct erofs_io_data {
	struct list_head free_list;
	int opcode;
	int buffer_index;
	struct erofs_fd *source_fd;
	/* offset into IO file/dev */
	off_t first_offset, offset;
	unsigned int first_len, len;
	union {
		off_t dev_offset; /* if EROFS_IO_TO_DEV    */
		void *buffer;     /* if EROFS_IO_TO_BUFFER */
	} target;
	struct iovec iovec;
} erofs_io_buffer_heads[IO_QUEUE_DEPTH];

#define EROFS_IO_RW_MASK 1
#define EROFS_IO_READ 0
#define EROFS_IO_WRITE 1

#define EROFS_IO_TARGET_MASK (3 << 1)
#define EROFS_IO_TO_BUFFER (0 << 1)
#define EROFS_IO_TO_DEV (1 << 1)
#define EROFS_IO_WRITEV (2 << 1)

LIST_HEAD(erofs_io_buffer_free_list);
int inflight_io = 0;

char erofs_io_buffer[IO_QUEUE_DEPTH][IO_BLOCK_SIZE];

int erofs_io_init() {
	int ret = 0;
#ifdef HAVE_LIBURING
	ret = io_uring_queue_init(IO_QUEUE_DEPTH, &ring, 0);
	if (ret < 0) {
		erofs_err("failed to init io_uring: %s", erofs_strerror(ret));
		return ret;
	}

	struct iovec iovec = {
		.iov_base = erofs_io_buffer,
		.iov_len  = sizeof(erofs_io_buffer),
	};
	ret = io_uring_register_buffers(&ring, &iovec, 1);
	if (ret < 0) {
		erofs_err("failed to register buffers to io_uring: %s", erofs_strerror(ret));
		return ret;
	}

	for (int i = 0; i < IO_QUEUE_DEPTH; i++) {
		struct erofs_io_data *item = &erofs_io_buffer_heads[i];
		item->buffer_index = i;
		list_add_tail(&item->free_list, &erofs_io_buffer_free_list);
	}
#endif
	return ret;
}

void erofs_io_exit() {
#ifdef HAVE_LIBURING
	io_uring_queue_exit(&ring);
#endif
}

struct erofs_fd *erofs_new_fd(int fd) {
	struct erofs_fd *erofs_fd = malloc(sizeof(*erofs_fd));
	if (!erofs_fd)
		return ERR_PTR(-ENOMEM);
	erofs_fd->fd = fd;
	erofs_fd->inflight_io = 0;
	erofs_fd->io_finished = 0;
	return erofs_fd;
}

void erofs_close_fd(struct erofs_fd *fd) {
	if (!fd->inflight_io) {
		close(fd->fd);
		free(fd);
		return;
	}
	fd->io_finished = 1;
}

static void queue_prepped(struct io_uring_sqe *sqe, struct erofs_io_data *data) {
	DBG_BUGON(!sqe);
	off_t continue_offset = data->offset - data->first_offset;
	erofs_dbg("prepare sqe data %p op %d offset %#lx(+%#lx) len %#x, inflight %d", data, data->opcode, data->offset, continue_offset, data->len, inflight_io);
	if ((data->opcode & EROFS_IO_TARGET_MASK) == EROFS_IO_TO_BUFFER) {
		data->iovec.iov_base = data->target.buffer + continue_offset;
		data->iovec.iov_len = data->len;
	}
	if ((data->opcode & EROFS_IO_RW_MASK) == EROFS_IO_READ) {
		if ((data->opcode & EROFS_IO_TARGET_MASK) == EROFS_IO_TO_DEV) {
			erofs_dbg("prepare sqe read from fd %d", data->source_fd->fd);
			io_uring_prep_read_fixed(sqe, data->source_fd->fd,
					erofs_io_buffer[data->buffer_index] + continue_offset,
					data->len, data->offset, 0);
		} else
			io_uring_prep_readv(sqe, data->source_fd->fd, &data->iovec, 1, data->offset);
	} else {
		if ((data->opcode & EROFS_IO_TARGET_MASK) == EROFS_IO_TO_DEV)
			io_uring_prep_write_fixed(sqe, 0,
					erofs_io_buffer[data->buffer_index] + continue_offset,
					data->len, data->offset, 0);
		else
			io_uring_prep_writev(sqe, 0, &data->iovec, 1, data->offset);

		sqe->flags |= IOSQE_FIXED_FILE;
	}

	io_uring_sqe_set_data(sqe, data);
	num_pending_sqe++;
}

static int erofs_uring_submit() {
	if (!num_pending_sqe)
		return 0;
	int ret = io_uring_submit(&ring);
	if (ret >= 0)
		num_pending_sqe = 0;
	return ret;
}

static int handle_comp(int wait) {
	int handled_comp = 0;
	int ret;
	struct io_uring_cqe *cqe;
	while(inflight_io) {
		if (wait && !handled_comp)
			ret = io_uring_wait_cqe(&ring, &cqe);
		else {
			ret = io_uring_peek_cqe(&ring, &cqe);
			if (ret == -EAGAIN) {
				cqe = NULL;
				ret = 0;
			}
		}
		if (ret < 0) {
			erofs_err("failed io_uring_peek_cqe: %s", erofs_strerror(ret));
			return ret;
		}
		if (!cqe)
			break;
		handled_comp++;

		struct erofs_io_data *data = io_uring_cqe_get_data(cqe);
		erofs_dbg("got cqe data %p op %d with res %d. inflight %d", data, data->opcode, cqe->res, inflight_io);
		struct io_uring_sqe *sqe;
		if (cqe->res < 0) {
			if (cqe->res == -EAGAIN) {
				sqe = io_uring_get_sqe(&ring);
				queue_prepped(sqe, data);
				io_uring_cqe_seen(&ring, cqe);
				continue;
			}
			erofs_err("cqe failed: %s", erofs_strerror(cqe->res));
			return cqe->res;
		} else if (cqe->res != data->len) {
			/* Short read/write, adjust and requeue */
			data->offset += cqe->res;
			data->len -= cqe->res;
			sqe = io_uring_get_sqe(&ring);
			queue_prepped(sqe, data);
			io_uring_cqe_seen(&ring, cqe);
			continue;
		}

		if ((data->opcode & EROFS_IO_RW_MASK) == EROFS_IO_READ) {
			data->source_fd->inflight_io--;
			if (!data->source_fd->inflight_io && data->source_fd->io_finished) {
				erofs_dbg("close fd %d", data->source_fd->fd);
				close(data->source_fd->fd);
				free(data->source_fd);
				data->source_fd = NULL;
			}
		}
		if ((data->opcode & EROFS_IO_RW_MASK) == EROFS_IO_READ &&
				(data->opcode & EROFS_IO_TARGET_MASK) == EROFS_IO_TO_DEV) {
			data->opcode = EROFS_IO_WRITE | EROFS_IO_TO_DEV;
			data->first_offset = data->offset = data->target.dev_offset;
			data->len = data->first_len;
			sqe = io_uring_get_sqe(&ring);
			queue_prepped(sqe, data);
		} else {
			list_add_tail(&data->free_list, &erofs_io_buffer_free_list);
			inflight_io--;
		}
		io_uring_cqe_seen(&ring, cqe);
	}
	ret = erofs_uring_submit();
	if (ret < 0) {
		erofs_err("failed io_uring_submit: %s", erofs_strerror(ret));
		return ret;
	}
	return handled_comp;
}

int erofs_io_drain() {
	int ret;
	while (inflight_io) {
		ret = handle_comp(1);
		if (ret < 0)
			return ret;
	}
	return 0;
}

int buffer_copy_from_fd(struct erofs_fd *fd, void *buffer, u64 offset, unsigned int len) {
	int ret;
	while (len) {
		if (list_empty(&erofs_io_buffer_free_list))
			goto handle_comp;
		struct erofs_io_data *data =
				list_first_entry(&erofs_io_buffer_free_list, struct erofs_io_data, free_list);

		struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
		if (!sqe)
			goto handle_comp;

		list_del(&data->free_list);
		data->opcode = EROFS_IO_READ | EROFS_IO_TO_BUFFER;
		data->offset = data->first_offset = offset;
		data->len = data->first_len = len;
		data->source_fd = fd;
		data->source_fd->inflight_io++;
		data->target.buffer = buffer;
		queue_prepped(sqe, data);
		len = 0;
		inflight_io++;
		ret = erofs_uring_submit();
		if (ret < 0) {
			erofs_err("failed io_uring_submit: %s", erofs_strerror(ret));
			return ret;
		}

handle_comp:
		ret = handle_comp(len);
		if (ret < 0)
			return ret;
	}
	return 0;
}

int dev_copy_from_fd(struct erofs_fd *fd, u64 dev_offset, unsigned int len) {
	off_t offset = 0;
	int ret;

	while (len) {
		/* Queue up as many reads as we can */
		while (len) {
			unsigned int this_size = len;
			if (list_empty(&erofs_io_buffer_free_list))
				break;
			if (this_size > IO_BLOCK_SIZE)
				this_size = IO_BLOCK_SIZE;
			len -= this_size;

			struct erofs_io_data *data =
					list_first_entry(&erofs_io_buffer_free_list, struct erofs_io_data, free_list);
			struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
			if (!sqe)
				break;

			list_del(&data->free_list);
			data->opcode = EROFS_IO_READ | EROFS_IO_TO_DEV;
			data->offset = data->first_offset = offset;
			data->len = data->first_len = this_size;
			data->source_fd = fd;
			data->source_fd->inflight_io++;
			data->target.dev_offset = dev_offset + offset;

			queue_prepped(sqe, data);
			offset += this_size;
			inflight_io++;
		}

		ret = erofs_uring_submit();
		if (ret < 0) {
			erofs_err("failed io_uring_submit: %s", erofs_strerror(ret));
			return ret;
		}

		ret = handle_comp(len);
		if (ret < 0)
			return ret;
	}
	return 0;
}

int dev_get_blkdev_size(int fd, u64 *bytes)
{
	errno = ENOTSUP;
#ifdef BLKGETSIZE64
	if (ioctl(fd, BLKGETSIZE64, bytes) >= 0)
		return 0;
#endif

#ifdef BLKGETSIZE
	{
		unsigned long size;
		if (ioctl(fd, BLKGETSIZE, &size) >= 0) {
			*bytes = ((u64)size << 9);
			return 0;
		}
	}
#endif
	return -errno;
}

void dev_close(void)
{
	io_uring_unregister_files(&ring);
	close(erofs_devfd);
	erofs_devname = NULL;
	erofs_devfd   = -1;
	erofs_devsz   = 0;
}

int dev_open(const char *dev)
{
	struct stat st;
	int fd, ret;

	fd = open(dev, O_RDWR | O_CREAT | O_BINARY, 0644);
	if (fd < 0) {
		erofs_err("failed to open(%s).", dev);
		return -errno;
	}

	ret = fstat(fd, &st);
	if (ret) {
		erofs_err("failed to fstat(%s).", dev);
		close(fd);
		return -errno;
	}

	switch (st.st_mode & S_IFMT) {
	case S_IFBLK:
		ret = dev_get_blkdev_size(fd, &erofs_devsz);
		if (ret) {
			erofs_err("failed to get block device size(%s).", dev);
			close(fd);
			return ret;
		}
		erofs_devsz = round_down(erofs_devsz, EROFS_BLKSIZ);
		break;
	case S_IFREG:
		ret = ftruncate(fd, 0);
		if (ret) {
			erofs_err("failed to ftruncate(%s).", dev);
			close(fd);
			return -errno;
		}
		/* INT64_MAX is the limit of kernel vfs */
		erofs_devsz = INT64_MAX;
		break;
	default:
		erofs_err("bad file type (%s, %o).", dev, st.st_mode);
		close(fd);
		return -EINVAL;
	}

#ifdef HAVE_LIBURING
	ret = io_uring_register_files(&ring, &fd, 1);
	if (ret < 0) {
		erofs_err("failed to register file %s to io_uring.", dev);
		close(fd);
		return ret;
	}
#endif

	erofs_devname = dev;
	erofs_devfd = fd;

	erofs_info("successfully to open %s", dev);
	return 0;
}

/* XXX: temporary soluation. Disk I/O implementation needs to be refactored. */
int dev_open_ro(const char *dev)
{
	int fd = open(dev, O_RDONLY | O_BINARY);

	if (fd < 0) {
		erofs_err("failed to open(%s).", dev);
		return -errno;
	}

	erofs_devfd = fd;
	erofs_devname = dev;
	erofs_devsz = INT64_MAX;
	return 0;
}

u64 dev_length(void)
{
	return erofs_devsz;
}

int dev_write(const void *buf, u64 offset, size_t len)
{
	int ret;

	if (cfg.c_dry_run)
		return 0;

	if (!buf) {
		erofs_err("buf is NULL");
		return -EINVAL;
	}

	if (offset >= erofs_devsz || len > erofs_devsz ||
	    offset > erofs_devsz - len) {
		erofs_err("Write posion[%" PRIu64 ", %zd] is too large beyond the end of device(%" PRIu64 ").",
			  offset, len, erofs_devsz);
		return -EINVAL;
	}

	while (len) {
		if (list_empty(&erofs_io_buffer_free_list))
			goto handle_comp;
		struct erofs_io_data *data =
				list_first_entry(&erofs_io_buffer_free_list, struct erofs_io_data, free_list);

		struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
		if (!sqe)
			goto handle_comp;

		list_del(&data->free_list);
		data->opcode = EROFS_IO_WRITE | EROFS_IO_TO_BUFFER;
		data->offset = data->first_offset = offset;
		data->len = data->first_len = len;
		data->target.buffer = (void*)buf;
		queue_prepped(sqe, data);
		len = 0;
		inflight_io++;
		ret = erofs_uring_submit();
		if (ret < 0) {
			erofs_err("failed io_uring_submit: %s", erofs_strerror(ret));
			return ret;
		}

handle_comp:
		ret = handle_comp(len);
		if (ret < 0)
			return ret;
	}
	return 0;
}

int dev_fillzero(u64 offset, size_t len, bool padding)
{
	static const char zero[EROFS_BLKSIZ] = {0};
	int ret;

	if (cfg.c_dry_run)
		return 0;

#if defined(HAVE_FALLOCATE) && defined(FALLOC_FL_PUNCH_HOLE)
	if (!padding && fallocate(erofs_devfd, FALLOC_FL_PUNCH_HOLE |
				  FALLOC_FL_KEEP_SIZE, offset, len) >= 0)
		return 0;
#endif
	while (len > EROFS_BLKSIZ) {
		ret = dev_write(zero, offset, EROFS_BLKSIZ);
		if (ret)
			return ret;
		len -= EROFS_BLKSIZ;
		offset += EROFS_BLKSIZ;
	}
	return dev_write(zero, offset, len);
}

int dev_fsync(void)
{
	int ret;

	ret = fsync(erofs_devfd);
	if (ret) {
		erofs_err("Could not fsync device!!!");
		return -EIO;
	}
	return 0;
}

int dev_resize(unsigned int blocks)
{
	int ret;
	struct stat st;
	u64 length;

	if (cfg.c_dry_run || erofs_devsz != INT64_MAX)
		return 0;

	ret = fstat(erofs_devfd, &st);
	if (ret) {
		erofs_err("failed to fstat.");
		return -errno;
	}

	length = (u64)blocks * EROFS_BLKSIZ;
	if (st.st_size == length)
		return 0;
	if (st.st_size > length)
		return ftruncate(erofs_devfd, length);

	length = length - st.st_size;
#if defined(HAVE_FALLOCATE)
	if (fallocate(erofs_devfd, 0, st.st_size, length) >= 0)
		return 0;
#endif
	return dev_fillzero(st.st_size, length, true);
}

int dev_read(void *buf, u64 offset, size_t len)
{
	int ret;

	if (cfg.c_dry_run)
		return 0;

	if (!buf) {
		erofs_err("buf is NULL");
		return -EINVAL;
	}
	if (offset >= erofs_devsz || len > erofs_devsz ||
	    offset > erofs_devsz - len) {
		erofs_err("read posion[%" PRIu64 ", %zd] is too large beyond"
			  "the end of device(%" PRIu64 ").",
			  offset, len, erofs_devsz);
		return -EINVAL;
	}

	ret = pread64(erofs_devfd, buf, len, (off64_t)offset);
	if (ret != (int)len) {
		erofs_err("Failed to read data from device - %s:[%" PRIu64 ", %zd].",
			  erofs_devname, offset, len);
		return -errno;
	}
	return 0;
}
