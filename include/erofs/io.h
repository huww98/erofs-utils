/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * erofs-utils/include/erofs/io.h
 *
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 */
#ifndef __EROFS_IO_H
#define __EROFS_IO_H

#include <unistd.h>
#include "internal.h"

#ifndef O_BINARY
#define O_BINARY	0
#endif

#define IO_BLOCK_SIZE (32*1024)

int erofs_io_init();
void erofs_io_exit();
int erofs_io_drain();
struct erofs_fd *erofs_new_fd(int fd);
void erofs_close_fd(struct erofs_fd * fd);
/*
 * return a buffer of size IO_BLOCK_SIZE
 * should be passed to *_write_from_fixed_buffer function later
 */
void *erofs_io_get_fixed_buffer();
int dev_write_from_fixed_buffer(void *buf, u64 offset, size_t len);
int buffer_copy_from_fd(struct erofs_fd *fd, void *buffer, u64 offset, unsigned int len);
int dev_copy_from_fd(struct erofs_fd *fd, u64 offset, unsigned int len);
int dev_open(const char *devname);
int dev_open_ro(const char *dev);
void dev_close(void);
int dev_write(void *buf, u64 offset, size_t len, bool free_buf);
int dev_read(void *buf, u64 offset, size_t len);
int dev_fillzero(u64 offset, size_t len, bool padding);
int dev_fsync(void);
int dev_resize(erofs_blk_t nblocks);
u64 dev_length(void);

static inline int blk_copy_from_fd(struct erofs_fd *fd, erofs_blk_t blkaddr,
				u32 nblocks)
{
	return dev_copy_from_fd(fd, blknr_to_addr(blkaddr),
			 blknr_to_addr(nblocks));
}

static inline int blk_write(void *buf, erofs_blk_t blkaddr,
			    u32 nblocks, bool free_buf)
{
	return dev_write(buf, blknr_to_addr(blkaddr),
			 blknr_to_addr(nblocks), free_buf);
}

static inline int blk_write_from_fixed_buffer(void *buf, erofs_blk_t blkaddr,
			    u32 nblocks)
{
	return dev_write_from_fixed_buffer(buf, blknr_to_addr(blkaddr),
			 blknr_to_addr(nblocks));
}

static inline int blk_read(void *buf, erofs_blk_t start,
			    u32 nblocks)
{
	return dev_read(buf, blknr_to_addr(start),
			 blknr_to_addr(nblocks));
}

#endif

