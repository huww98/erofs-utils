// SPDX-License-Identifier: GPL-2.0+
#include <stdlib.h>
#include <liburing.h>
#include "erofs/io.h"
#include "erofs/list.h"
#include "config.h"

#define pr_fmt(fmt) "EROFS IO_URING: " FUNC_LINE_FMT fmt "\n"
#include "erofs/print.h"

#define IO_QUEUE_DEPTH 256
static struct io_uring ring;
static int num_pending_sqe;

struct erofs_io_data {
	struct list_head free_list;
	int opcode;
	int buffer_index;
	struct erofs_fd *source_fd;
	/* offset into IO file/dev */
	off_t first_offset, offset;
	unsigned int first_len, len;
	union {
		off_t dev_offset; /* if EROFS_IO_READ_TO_DEV    */
		void *buffer;     /* if EROFS_IO_BUFFER or EROFS_IO_WRITE_FIXED_BUFFER */
	} target;
	struct iovec iovec;
} erofs_io_buffer_heads[IO_QUEUE_DEPTH];

#define EROFS_IO_RW_MASK 1
#define EROFS_IO_WRITE 1

#define EROFS_IO_TARGET_MASK (3 << 1)
#define EROFS_IO_BUFFER (0 << 1)
#define EROFS_IO_WRITE_FIXED_BUFFER (1 << 1)

#define EROFS_IO_FREE_BUFFER (1 << 3)

LIST_HEAD(erofs_io_buffer_free_list);
int inflight_io;

char erofs_io_buffer[IO_QUEUE_DEPTH][IO_BLOCK_SIZE];

int erofs_io_uring_init(void)
{
	int ret;

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
	return ret;
}

void erofs_io_uring_exit(void)
{
	io_uring_queue_exit(&ring);
}

static void queue_prepped(struct io_uring_sqe *sqe, struct erofs_io_data *data)
{
	DBG_BUGON(!sqe);
	off_t continue_offset = data->offset - data->first_offset;
	erofs_dbg("prepare sqe data %p op %d offset %#lx(+%#lx) len %#x, inflight %d", data, data->opcode, data->offset, continue_offset, data->len, inflight_io);
	if ((data->opcode & EROFS_IO_TARGET_MASK) == EROFS_IO_BUFFER) {
		data->iovec.iov_base = data->target.buffer + continue_offset;
		data->iovec.iov_len = data->len;
	}
	if ((data->opcode & EROFS_IO_TARGET_MASK) == EROFS_IO_WRITE_FIXED_BUFFER)
		io_uring_prep_write_fixed(sqe, 0,
				data->target.buffer + continue_offset,
				data->len, data->offset, 0);
	else
		io_uring_prep_writev(sqe, 0, &data->iovec, 1, data->offset);

	sqe->flags |= IOSQE_FIXED_FILE;

	io_uring_sqe_set_data(sqe, data);
	num_pending_sqe++;
}

static int erofs_uring_submit(void)
{
	int ret;

	if (!num_pending_sqe)
		return 0;
	ret = io_uring_submit(&ring);
	if (ret >= 0)
		num_pending_sqe = 0;
	return ret;
}

static int handle_comp(int wait)
{
	int handled_comp = 0;
	int ret;
	struct io_uring_cqe *cqe;

	while (inflight_io) {
		if (wait && !handled_comp)
			ret = io_uring_wait_cqe(&ring, &cqe);
		else {
			ret = io_uring_peek_cqe(&ring, &cqe);
			if (ret == -EAGAIN) {
				cqe = NULL;
				ret = 0;
			}
		}
		if (ret == -EINTR)
			continue;
		if (ret < 0) {
			erofs_err("failed to get cqe: %s", erofs_strerror(ret));
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

		if (data->opcode & EROFS_IO_FREE_BUFFER)
			free(data->target.buffer);

		list_add_tail(&data->free_list, &erofs_io_buffer_free_list);
		inflight_io--;
		io_uring_cqe_seen(&ring, cqe);
	}
	ret = erofs_uring_submit();
	if (ret < 0) {
		erofs_err("failed io_uring_submit: %s", erofs_strerror(ret));
		return ret;
	}
	return handled_comp;
}

int erofs_io_drain(void)
{
	int ret;

	while (inflight_io) {
		ret = handle_comp(1);
		if (ret < 0)
			return ret;
	}
	return 0;
}

void *erofs_io_get_fixed_buffer(void)
{
	int ret;
	while (list_empty(&erofs_io_buffer_free_list)) {
		ret = handle_comp(1);
		if (ret < 0)
			return ERR_PTR(ret);
	}

	struct erofs_io_data *data = list_first_entry(
			&erofs_io_buffer_free_list, struct erofs_io_data, free_list);
	list_del(&data->free_list);
	return erofs_io_buffer[data->buffer_index];
}

int dev_write_from_fixed_buffer(void *buf, u64 offset, size_t len)
{
	int ret;
	int buffer_index = ((char(*)[IO_BLOCK_SIZE])buf - erofs_io_buffer);
	DBG_BUGON(buffer_index < 0 || buffer_index >= IO_QUEUE_DEPTH);
	struct erofs_io_data *data = &erofs_io_buffer_heads[buffer_index];
	DBG_BUGON(data->free_list.next != NULL);

	while (len) {
		struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
		if (!sqe)
			goto handle_comp;

		data->opcode = EROFS_IO_WRITE | EROFS_IO_WRITE_FIXED_BUFFER;
		data->offset = data->first_offset = offset;
		data->len = data->first_len = len;
		data->target.buffer = buf;
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

int erofs_io_uring_dev_open(int fd)
{
	int ret;

	ret = io_uring_register_files(&ring, &fd, 1);
	if (ret < 0)
		erofs_err("failed to register fd %d to io_uring.", fd);
	return ret;
}

void erofs_io_uring_dev_close(void)
{
	io_uring_unregister_files(&ring);
}

int __dev_write(void *buf, u64 offset, size_t len, bool free_buf)
{
	int ret;

	while (len) {
		if (list_empty(&erofs_io_buffer_free_list))
			goto handle_comp;
		struct erofs_io_data *data = list_first_entry(
				&erofs_io_buffer_free_list, struct erofs_io_data, free_list);

		struct io_uring_sqe *sqe = io_uring_get_sqe(&ring);
		if (!sqe)
			goto handle_comp;

		list_del(&data->free_list);
		data->opcode = EROFS_IO_WRITE | EROFS_IO_BUFFER;
		if (free_buf)
			data->opcode |= EROFS_IO_FREE_BUFFER;
		data->offset = data->first_offset = offset;
		data->len = data->first_len = len;
		data->target.buffer = buf;
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
