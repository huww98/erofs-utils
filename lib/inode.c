// SPDX-License-Identifier: GPL-2.0+
/*
 * erofs-utils/lib/inode.c
 *
 * Copyright (C) 2018-2019 HUAWEI, Inc.
 *             http://www.huawei.com/
 * Created by Li Guifu <bluce.liguifu@huawei.com>
 * with heavy changes by Gao Xiang <gaoxiang25@huawei.com>
 */
#define _GNU_SOURCE
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <dirent.h>
#include "erofs/print.h"
#include "erofs/inode.h"
#include "erofs/cache.h"
#include "erofs/io.h"
#include "erofs/compress.h"
#include "erofs/xattr.h"
#include "erofs/exclude.h"

#define S_SHIFT                 12
static unsigned char erofs_ftype_by_mode[S_IFMT >> S_SHIFT] = {
	[S_IFREG >> S_SHIFT]  = EROFS_FT_REG_FILE,
	[S_IFDIR >> S_SHIFT]  = EROFS_FT_DIR,
	[S_IFCHR >> S_SHIFT]  = EROFS_FT_CHRDEV,
	[S_IFBLK >> S_SHIFT]  = EROFS_FT_BLKDEV,
	[S_IFIFO >> S_SHIFT]  = EROFS_FT_FIFO,
	[S_IFSOCK >> S_SHIFT] = EROFS_FT_SOCK,
	[S_IFLNK >> S_SHIFT]  = EROFS_FT_SYMLINK,
};

static unsigned char erofs_mode_to_ftype(umode_t mode)
{
	return erofs_ftype_by_mode[(mode & S_IFMT) >> S_SHIFT];
}

#define NR_INODE_HASHTABLE	16384

struct list_head inode_hashtable[NR_INODE_HASHTABLE];

void erofs_inode_manager_init(void)
{
	unsigned int i;

	for (i = 0; i < NR_INODE_HASHTABLE; ++i)
		init_list_head(&inode_hashtable[i]);
}

static struct erofs_inode *erofs_igrab(struct erofs_inode *inode)
{
	++inode->i_count;
	return inode;
}

/* get the inode from the (source) inode # */
struct erofs_inode *erofs_iget(dev_t dev, ino_t ino)
{
	struct list_head *head =
		&inode_hashtable[(ino ^ dev) % NR_INODE_HASHTABLE];
	struct erofs_inode *inode;

	list_for_each_entry(inode, head, i_hash)
		if (inode->i_ino[1] == ino && inode->dev == dev)
			return erofs_igrab(inode);
	return NULL;
}

struct erofs_inode *erofs_iget_by_nid(erofs_nid_t nid)
{
	struct list_head *head =
		&inode_hashtable[nid % NR_INODE_HASHTABLE];
	struct erofs_inode *inode;

	list_for_each_entry(inode, head, i_hash)
		if (inode->nid == nid)
			return erofs_igrab(inode);
	return NULL;
}

unsigned int erofs_iput(struct erofs_inode *inode)
{
	struct erofs_dentry *d, *t;

	if (inode->i_count > 1)
		return --inode->i_count;

	list_for_each_entry_safe(d, t, &inode->i_subdirs, d_child)
		free(d);

	list_del(&inode->i_hash);
	free(inode);
	return 0;
}

static int dentry_add_sorted(struct erofs_dentry *d, struct list_head *head)
{
	struct list_head *pos;

	list_for_each(pos, head) {
		struct erofs_dentry *d2 =
			container_of(pos, struct erofs_dentry, d_child);

		if (strcmp(d->name, d2->name) < 0)
			break;
	}
	list_add_tail(&d->d_child, pos);
	return 0;
}

struct erofs_dentry *erofs_d_alloc(struct erofs_inode *parent,
				   const char *name)
{
	struct erofs_dentry *d = malloc(sizeof(*d));

	if (!d)
		return ERR_PTR(-ENOMEM);

	strncpy(d->name, name, EROFS_NAME_LEN - 1);
	d->name[EROFS_NAME_LEN - 1] = '\0';

	dentry_add_sorted(d, &parent->i_subdirs);
	return d;
}

int erofs_prepare_dir_file(struct erofs_inode *dir)
{
	struct erofs_dentry *d;
	unsigned int d_size, i_nlink;

	/* dot is pointed to the current dir inode */
	d = erofs_d_alloc(dir, ".");
	d->inode = erofs_igrab(dir);
	d->type = EROFS_FT_DIR;

	/* dotdot is pointed to the parent dir */
	d = erofs_d_alloc(dir, "..");
	d->inode = erofs_igrab(dir->i_parent);
	d->type = EROFS_FT_DIR;

	/* let's calculate dir size and update i_nlink */
	d_size = 0;
	i_nlink = 0;
	list_for_each_entry(d, &dir->i_subdirs, d_child) {
		int len = strlen(d->name) + sizeof(struct erofs_dirent);

		if (d_size % EROFS_BLKSIZ + len > EROFS_BLKSIZ)
			d_size = round_up(d_size, EROFS_BLKSIZ);
		d_size += len;

		i_nlink += (d->type == EROFS_FT_DIR);
	}
	dir->i_size = d_size;
	/*
	 * if there're too many subdirs as compact form, set nlink=1
	 * rather than upgrade to use extented form instead.
	 */
	if (i_nlink > USHRT_MAX &&
	    dir->inode_isize == sizeof(struct erofs_inode_compact))
		dir->i_nlink = 1;
	else
		dir->i_nlink = i_nlink;

	return 0;
}

static void fill_dirblock(char *buf, unsigned int size, unsigned int q,
			  struct erofs_dentry *head, struct erofs_dentry *end)
{
	unsigned int p = 0;

	/* write out all erofs_dirents + filenames */
	while (head != end) {
		const unsigned int namelen = strlen(head->name);
		struct erofs_dirent d = {
			.nid = cpu_to_le64(head->nid),
			.nameoff = cpu_to_le16(q),
			.file_type = head->type,
		};

		memcpy(buf + p, &d, sizeof(d));
		memcpy(buf + q, head->name, namelen);
		p += sizeof(d);
		q += namelen;

		head = list_next_entry(head, d_child);
	}
	memset(buf + q, 0, size - q);
}

static int write_dirblock(unsigned int q, struct erofs_dentry *head,
			  struct erofs_dentry *end, erofs_blk_t blkaddr)
{
	void *buf = erofs_io_get_fixed_buffer();
	if (IS_ERR(buf))
		return PTR_ERR(buf);
	DBG_BUGON(IO_BLOCK_SIZE < EROFS_BLKSIZ);

	fill_dirblock(buf, EROFS_BLKSIZ, q, head, end);
	return blk_write_from_fixed_buffer(buf, blkaddr, 1);
}

int erofs_write_dir_file(struct erofs_inode *dir)
{
	struct erofs_dentry *head = list_first_entry(&dir->i_subdirs,
						     struct erofs_dentry,
						     d_child);
	struct erofs_dentry *d;
	int ret;
	unsigned int q, used, blkno;

	q = used = blkno = 0;

	list_for_each_entry(d, &dir->i_subdirs, d_child) {
		const unsigned int len = strlen(d->name) +
			sizeof(struct erofs_dirent);

		if (used + len > EROFS_BLKSIZ) {
			ret = write_dirblock(q, head, d,
					     dir->u.i_blkaddr + blkno);
			if (ret)
				return ret;

			head = d;
			q = used = 0;
			++blkno;
		}
		used += len;
		q += sizeof(struct erofs_dirent);
	}

	DBG_BUGON(used > EROFS_BLKSIZ);
	if (dir->datalayout == EROFS_INODE_FLAT_PLAIN) {
		DBG_BUGON(dir->idata_size);
		return write_dirblock(q, head, d, dir->u.i_blkaddr + blkno);
	}
	DBG_BUGON(dir->datalayout != EROFS_INODE_FLAT_INLINE);
	DBG_BUGON(used != dir->i_size % EROFS_BLKSIZ);
	DBG_BUGON(used != dir->idata_size);
	DBG_BUGON(!used);
	/* fill tail-end dir block */
	fill_dirblock(dir->idata, dir->idata_size, q, head, d);
	return 0;
}

/* rules to decide whether a file could be compressed or not */
static bool erofs_file_is_compressible(struct erofs_inode *inode)
{
	return true;
}

static int write_uncompressed_file_from_fd(struct erofs_inode *inode, struct erofs_fd *fd)
{
	const unsigned int nblocks = erofs_blknr(inode->i_size);
	int ret;

	if (inode->datalayout == EROFS_INODE_FLAT_INLINE) {
		DBG_BUGON(!inode->bh_inline);
		ret = blk_copy_from_fd(fd, inode->u.i_blkaddr, nblocks);
		if (ret)
			return ret;

		ret = buffer_copy_from_fd(fd, inode->idata,
				blknr_to_addr(nblocks), inode->idata_size);
	} else {
		DBG_BUGON(inode->datalayout != EROFS_INODE_FLAT_PLAIN);
		DBG_BUGON(inode->bh_inline);
		ret = dev_copy_from_fd(fd, blknr_to_addr(inode->u.i_blkaddr),
				inode->i_size);
	}
	return ret;
}

static bool erofs_bh_flush_write_inode(struct erofs_buffer_head *bh)
{
	struct erofs_inode *const inode = bh->fsprivate;
	const u16 icount = EROFS_INODE_XATTR_ICOUNT(inode->xattr_isize);
	erofs_off_t off = erofs_btell(bh, false);
	void *buf = erofs_io_get_fixed_buffer();
	if (IS_ERR(buf))
		return false;
	union {
		struct erofs_inode_compact dic;
		struct erofs_inode_extended die;
	} *u = buf;
	DBG_BUGON(sizeof(*u) > IO_BLOCK_SIZE);
	memset(u, 0, sizeof(*u));
	int ret;

	switch (inode->inode_isize) {
	case sizeof(struct erofs_inode_compact):
		u->dic.i_format = cpu_to_le16(0 | (inode->datalayout << 1));
		u->dic.i_xattr_icount = cpu_to_le16(icount);
		u->dic.i_mode = cpu_to_le16(inode->i_mode);
		u->dic.i_nlink = cpu_to_le16(inode->i_nlink);
		u->dic.i_size = cpu_to_le32((u32)inode->i_size);

		u->dic.i_ino = cpu_to_le32(inode->i_ino[0]);

		u->dic.i_uid = cpu_to_le16((u16)inode->i_uid);
		u->dic.i_gid = cpu_to_le16((u16)inode->i_gid);

		switch (inode->i_mode & S_IFMT) {
		case S_IFCHR:
		case S_IFBLK:
		case S_IFIFO:
		case S_IFSOCK:
			u->dic.i_u.rdev = cpu_to_le32(inode->u.i_rdev);
			break;

		default:
			if (is_inode_layout_compression(inode))
				u->dic.i_u.compressed_blocks =
					cpu_to_le32(inode->u.i_blocks);
			else
				u->dic.i_u.raw_blkaddr =
					cpu_to_le32(inode->u.i_blkaddr);
			break;
		}
		break;
	case sizeof(struct erofs_inode_extended):
		u->die.i_format = cpu_to_le16(1 | (inode->datalayout << 1));
		u->die.i_xattr_icount = cpu_to_le16(icount);
		u->die.i_mode = cpu_to_le16(inode->i_mode);
		u->die.i_nlink = cpu_to_le32(inode->i_nlink);
		u->die.i_size = cpu_to_le64(inode->i_size);

		u->die.i_ino = cpu_to_le32(inode->i_ino[0]);

		u->die.i_uid = cpu_to_le16(inode->i_uid);
		u->die.i_gid = cpu_to_le16(inode->i_gid);

		u->die.i_ctime = cpu_to_le64(inode->i_ctime);
		u->die.i_ctime_nsec = cpu_to_le32(inode->i_ctime_nsec);

		switch (inode->i_mode & S_IFMT) {
		case S_IFCHR:
		case S_IFBLK:
		case S_IFIFO:
		case S_IFSOCK:
			u->die.i_u.rdev = cpu_to_le32(inode->u.i_rdev);
			break;

		default:
			if (is_inode_layout_compression(inode))
				u->die.i_u.compressed_blocks =
					cpu_to_le32(inode->u.i_blocks);
			else
				u->die.i_u.raw_blkaddr =
					cpu_to_le32(inode->u.i_blkaddr);
			break;
		}
		break;
	default:
		erofs_err("unsupported on-disk inode version of nid %llu",
			  (unsigned long long)inode->nid);
		BUG_ON(1);
	}

	ret = dev_write_from_fixed_buffer(buf, off, inode->inode_isize);
	if (ret)
		return false;
	off += inode->inode_isize;

	if (inode->xattr_isize) {
		char *xattrs = erofs_export_xattr_ibody(&inode->i_xattrs,
							inode->xattr_isize);
		if (IS_ERR(xattrs))
			return false;

		ret = dev_write(xattrs, off, inode->xattr_isize, true);
		if (ret)
			return false;

		off += inode->xattr_isize;
	}

	if (inode->extent_isize) {
		/* write compression metadata */
		off = Z_EROFS_VLE_EXTENT_ALIGN(off);
		ret = dev_write(inode->compressmeta, off, inode->extent_isize, true);
		if (ret)
			return false;
	}

	inode->bh = NULL;
	erofs_iput(inode);
	return erofs_bh_flush_generic_end(bh);
}

static struct erofs_bhops erofs_write_inode_bhops = {
	.flush = erofs_bh_flush_write_inode,
};

static bool erofs_bh_flush_write_inline(struct erofs_buffer_head *bh)
{
	struct erofs_inode *const inode = bh->fsprivate;
	const erofs_off_t off = erofs_btell(bh, false);
	int ret;

	ret = dev_write(inode->idata, off, inode->idata_size, true);
	if (ret)
		return false;

	inode->idata_size = 0;
	inode->idata = NULL;

	erofs_iput(inode);
	return erofs_bh_flush_generic_end(bh);
}

static struct erofs_bhops erofs_write_inline_bhops = {
	.flush = erofs_bh_flush_write_inline,
};

static void erofs_prepare_inode_bh(struct erofs_inode *inode)
{
	struct erofs_buffer_head *bh = inode->bh;
	bh->fsprivate = erofs_igrab(inode);
	bh->op = &erofs_write_inode_bhops;
}

int erofs_prepare_inode_buffer_for_compressed(struct erofs_inode *inode)
{
	unsigned int inodesize;
	struct erofs_buffer_head *bh;

	DBG_BUGON(!inode->extent_isize);
	inodesize = Z_EROFS_VLE_EXTENT_ALIGN(inode->inode_isize + inode->xattr_isize) +
			inode->extent_isize;
	bh = erofs_balloc(INODE, inodesize, 0, 0);
	if (IS_ERR(bh))
		return PTR_ERR(bh);
	inode->bh = bh;
	erofs_prepare_inode_bh(inode);
	return 0;
}

/* determine datalayout, idata_size; allocate bh, bh_inline, bh_data, idata */
int erofs_prepare_inode_buffer_for_uncompressed(struct erofs_inode *inode)
{
	unsigned int inodesize, tail_size, data_size;
	struct erofs_buffer_head *bh, *ibh;
	int ret;

	DBG_BUGON(inode->bh || inode->bh_inline || inode->bh_data);

	inodesize = inode->inode_isize + inode->xattr_isize;

	tail_size = inode->i_size % EROFS_BLKSIZ;
	bh = erofs_balloc(INODE, inodesize, 0, tail_size);
	if (bh == ERR_PTR(-ENOSPC)) {
		/* cannot inline tail data, fallback to EROFS_INODE_FLAT_PLAIN */
		inode->datalayout = EROFS_INODE_FLAT_PLAIN;
		/* retry alloc without request inline */
		bh = erofs_balloc(INODE, inodesize, 0, 0);
		if (IS_ERR(bh))
			return PTR_ERR(bh);
	} else if (IS_ERR(bh)) {
		return PTR_ERR(bh);
	} else if (tail_size) {
		inode->idata_size = tail_size;
		inode->idata = malloc(tail_size);
		if (!inode->idata)
			return -ENOMEM;
		inode->datalayout = EROFS_INODE_FLAT_INLINE;

		/* allocate inline buffer */
		ibh = erofs_battach(bh, META, inode->idata_size);
		if (IS_ERR(ibh))
			return PTR_ERR(ibh);

		ibh->fsprivate = erofs_igrab(inode);
		ibh->op = &erofs_write_inline_bhops;
		inode->bh_inline = ibh;
	} else /* file size is block-aligned */
		inode->datalayout = EROFS_INODE_FLAT_PLAIN;

	inode->bh = bh;
	erofs_prepare_inode_bh(inode);

	if (inode->datalayout == EROFS_INODE_FLAT_INLINE)
		data_size = round_down(inode->i_size, EROFS_BLKSIZ);
	else
		data_size = round_up(inode->i_size, EROFS_BLKSIZ);

	if (data_size) {
		bh = erofs_balloc(DATA, data_size, 0, 0);
		if (IS_ERR(bh))
			return PTR_ERR(bh);
		/* data blocks should be directly commited to dev */
		bh->op = &erofs_skip_write_bhops;
		inode->bh_data = bh;
		ret = erofs_mapbh(bh->block);
		DBG_BUGON(ret < 0);
		inode->u.i_blkaddr = bh->block->blkaddr;
	}

	return 0;
}

/* will free buf */
int erofs_write_file_from_buffer(struct erofs_inode *inode, char *buf)
{
	const unsigned int nblocks = erofs_blknr(inode->i_size);
	int ret;

	ret = erofs_prepare_inode_buffer_for_uncompressed(inode);
	if (ret)
		return ret;

	if (inode->datalayout == EROFS_INODE_FLAT_INLINE) {
		DBG_BUGON(!inode->bh_inline);
		memcpy(inode->idata, buf + blknr_to_addr(nblocks),
		       inode->idata_size);
		ret = blk_write(buf, inode->u.i_blkaddr, nblocks, true);
	} else {
		DBG_BUGON(inode->datalayout != EROFS_INODE_FLAT_PLAIN);
		DBG_BUGON(inode->bh_inline);
		ret = dev_write(buf, blknr_to_addr(inode->u.i_blkaddr),
				inode->i_size, true);
	}
	return ret;
}

int erofs_write_file(struct erofs_inode *inode)
{
	int ret, fd;

	if (!inode->i_size) {
		ret = erofs_prepare_inode_buffer_for_uncompressed(inode);
		if (ret)
			return ret;
		DBG_BUGON(inode->datalayout != EROFS_INODE_FLAT_PLAIN);
		return 0;
	}

	if (cfg.c_compr_alg_master && erofs_file_is_compressible(inode)) {
		ret = erofs_write_compressed_file(inode);

		if (!ret) {
			ret = erofs_prepare_inode_buffer_for_compressed(inode);
			return ret;
		}
		if (ret != -ENOSPC)
			return ret;
	}

	/* fallback to all data uncompressed */
	ret = erofs_prepare_inode_buffer_for_uncompressed(inode);
	if (ret)
		return ret;
	fd = open(inode->i_srcpath, O_RDONLY | O_BINARY);
	if (fd < 0)
		return -errno;
	struct erofs_fd *erofs_fd = erofs_new_fd(fd);
	if (IS_ERR(erofs_fd))
		return PTR_ERR(erofs_fd);
	ret = write_uncompressed_file_from_fd(inode, erofs_fd);
	erofs_close_fd(erofs_fd);
	return ret;
}

int erofs_write_tail_end(struct erofs_inode *inode)
{
	struct erofs_buffer_head *bh;
	int ret;
	erofs_off_t pos, tail_size;

	bh = inode->bh_data;
	tail_size = inode->i_size % EROFS_BLKSIZ;
	if (!tail_size)
		goto out;

	if (inode->datalayout == EROFS_INODE_FLAT_PLAIN) {
		erofs_mapbh(bh->block);
		pos = erofs_btell(bh, true) - EROFS_BLKSIZ;
		ret = dev_fillzero(pos + tail_size,
				EROFS_BLKSIZ - tail_size,
				false);
		if (ret)
			return ret;
	}

out:
	/* now bh_data can drop directly */
	if (bh) {
		/*
		 * Don't leave DATA buffers which were written in the global
		 * buffer list. It will make balloc() slowly.
		 */
#if 0
		bh->op = &erofs_drop_directly_bhops;
#else
		erofs_bdrop(bh, false);
#endif
		inode->bh_data = NULL;
	}
	return 0;
}

static bool erofs_should_use_inode_extended(struct erofs_inode *inode)
{
	if (cfg.c_force_inodeversion == FORCE_INODE_EXTENDED)
		return true;
	if (inode->i_size > UINT_MAX)
		return true;
	if (inode->i_uid > USHRT_MAX)
		return true;
	if (inode->i_gid > USHRT_MAX)
		return true;
	if (inode->i_nlink > USHRT_MAX)
		return true;
	return false;
}

static u32 erofs_new_encode_dev(dev_t dev)
{
	const unsigned int major = major(dev);
	const unsigned int minor = minor(dev);

	return (minor & 0xff) | (major << 8) | ((minor & ~0xff) << 12);
}

#ifdef WITH_ANDROID
int erofs_droid_inode_fsconfig(struct erofs_inode *inode,
			       struct stat64 *st,
			       const char *path)
{
	/* filesystem_config does not preserve file type bits */
	mode_t stat_file_type_mask = st->st_mode & S_IFMT;
	unsigned int uid = 0, gid = 0, mode = 0;
	const char *fspath;
	char *decorated = NULL;

	inode->capabilities = 0;
	if (!cfg.fs_config_file && !cfg.mount_point)
		return 0;

	if (!cfg.mount_point ||
	/* have to drop the mountpoint for rootdir of canned fsconfig */
	    (cfg.fs_config_file && erofs_fspath(path)[0] == '\0')) {
		fspath = erofs_fspath(path);
	} else {
		if (asprintf(&decorated, "%s/%s", cfg.mount_point,
			     erofs_fspath(path)) <= 0)
			return -ENOMEM;
		fspath = decorated;
	}

	if (cfg.fs_config_file)
		canned_fs_config(fspath, S_ISDIR(st->st_mode),
				 cfg.target_out_path,
				 &uid, &gid, &mode, &inode->capabilities);
	else
		fs_config(fspath, S_ISDIR(st->st_mode),
			  cfg.target_out_path,
			  &uid, &gid, &mode, &inode->capabilities);

	erofs_dbg("/%s -> mode = 0x%x, uid = 0x%x, gid = 0x%x, "
		  "capabilities = 0x%" PRIx64 "\n",
		  fspath, mode, uid, gid, inode->capabilities);

	if (decorated)
		free(decorated);
	st->st_uid = uid;
	st->st_gid = gid;
	st->st_mode = mode | stat_file_type_mask;
	return 0;
}
#else
static int erofs_droid_inode_fsconfig(struct erofs_inode *inode,
				      struct stat64 *st,
				      const char *path)
{
	return 0;
}
#endif

int erofs_fill_inode(struct erofs_inode *inode,
		     struct stat64 *st,
		     const char *path)
{
	int err = erofs_droid_inode_fsconfig(inode, st, path);

	if (err)
		return err;
	inode->i_mode = st->st_mode;
	inode->i_uid = st->st_uid;
	inode->i_gid = st->st_gid;
	inode->i_ctime = st->st_ctime;
	inode->i_ctime_nsec = st->st_ctim.tv_nsec;

	switch (cfg.c_timeinherit) {
	case TIMESTAMP_CLAMPING:
		if (st->st_ctime < sbi.build_time)
			break;
	case TIMESTAMP_FIXED:
		inode->i_ctime = sbi.build_time;
		inode->i_ctime_nsec = sbi.build_time_nsec;
	default:
		break;
	}
	inode->i_nlink = 1;	/* fix up later if needed */

	switch (inode->i_mode & S_IFMT) {
	case S_IFCHR:
	case S_IFBLK:
	case S_IFIFO:
	case S_IFSOCK:
		inode->u.i_rdev = erofs_new_encode_dev(st->st_rdev);
	case S_IFDIR:
		inode->i_size = 0;
		break;
	case S_IFREG:
	case S_IFLNK:
		inode->i_size = st->st_size;
		break;
	default:
		return -EINVAL;
	}

	strncpy(inode->i_srcpath, path, sizeof(inode->i_srcpath) - 1);
	inode->i_srcpath[sizeof(inode->i_srcpath) - 1] = '\0';

	inode->dev = st->st_dev;
	inode->i_ino[1] = st->st_ino;

	if (erofs_should_use_inode_extended(inode)) {
		if (cfg.c_force_inodeversion == FORCE_INODE_COMPACT) {
			erofs_err("file %s cannot be in compact form",
				  inode->i_srcpath);
			return -EINVAL;
		}
		inode->inode_isize = sizeof(struct erofs_inode_extended);
	} else {
		inode->inode_isize = sizeof(struct erofs_inode_compact);
	}

	list_add(&inode->i_hash,
		 &inode_hashtable[(st->st_ino ^ st->st_dev) %
				  NR_INODE_HASHTABLE]);
	return 0;
}

struct erofs_inode *erofs_new_inode(void)
{
	static unsigned int counter;
	struct erofs_inode *inode;

	inode = malloc(sizeof(struct erofs_inode));
	if (!inode)
		return ERR_PTR(-ENOMEM);

	inode->i_parent = NULL;	/* also used to indicate a new inode */

	inode->i_ino[0] = counter++;	/* inode serial number */
	inode->i_count = 1;

	init_list_head(&inode->i_subdirs);
	init_list_head(&inode->i_xattrs);

	inode->idata_size = 0;
	inode->xattr_isize = 0;
	inode->extent_isize = 0;

	inode->bh = inode->bh_inline = inode->bh_data = NULL;
	inode->idata = NULL;
	return inode;
}

/* get the inode from the (source) path */
struct erofs_inode *erofs_iget_from_path(const char *path, bool is_src)
{
	struct stat64 st;
	struct erofs_inode *inode;
	int ret;

	/* currently, only source path is supported */
	if (!is_src)
		return ERR_PTR(-EINVAL);

	ret = lstat64(path, &st);
	if (ret)
		return ERR_PTR(-errno);

	/*
	 * lookup in hash table first, if it already exists we have a
	 * hard-link, just return it. Also don't lookup for directories
	 * since hard-link directory isn't allowed.
	 */
	if (!S_ISDIR(st.st_mode)) {
		inode = erofs_iget(st.st_dev, st.st_ino);
		if (inode)
			return inode;
	}

	/* cannot find in the inode cache */
	inode = erofs_new_inode();
	if (IS_ERR(inode))
		return inode;

	ret = erofs_fill_inode(inode, &st, path);
	if (ret) {
		free(inode);
		return ERR_PTR(ret);
	}

	return inode;
}

void erofs_fixup_meta_blkaddr(struct erofs_inode *rootdir)
{
	const erofs_off_t rootnid_maxoffset = 0xffff << EROFS_ISLOTBITS;
	struct erofs_buffer_head *const bh = rootdir->bh;
	erofs_off_t off, meta_offset;

	erofs_mapbh(bh->block);
	off = erofs_btell(bh, false);

	if (off > rootnid_maxoffset)
		meta_offset = round_up(off - rootnid_maxoffset, EROFS_BLKSIZ);
	else
		meta_offset = 0;
	sbi.meta_blkaddr = erofs_blknr(meta_offset);
	rootdir->nid = (off - meta_offset) >> EROFS_ISLOTBITS;
}

erofs_nid_t erofs_lookupnid(struct erofs_inode *inode)
{
	struct erofs_buffer_head *const bh = inode->bh;
	erofs_off_t off, meta_offset;

	if (!bh)
		return inode->nid;

	erofs_mapbh(bh->block);
	off = erofs_btell(bh, false);

	meta_offset = blknr_to_addr(sbi.meta_blkaddr);
	DBG_BUGON(off < meta_offset);
	return inode->nid = (off - meta_offset) >> EROFS_ISLOTBITS;
}

void erofs_d_invalidate(struct erofs_dentry *d)
{
	struct erofs_inode *const inode = d->inode;

	d->nid = erofs_lookupnid(inode);
	erofs_iput(inode);
}

struct erofs_inode *erofs_mkfs_build_tree(struct erofs_inode *dir)
{
	int ret;
	DIR *_dir;
	struct dirent *dp;
	struct erofs_dentry *d;

	ret = erofs_prepare_xattr_ibody(dir);
	if (ret < 0)
		return ERR_PTR(ret);

	if (!S_ISDIR(dir->i_mode)) {
		if (S_ISLNK(dir->i_mode)) {
			char *const symlink = malloc(dir->i_size);

			if (!symlink)
				return ERR_PTR(-ENOMEM);
			ret = readlink(dir->i_srcpath, symlink, dir->i_size);
			if (ret < 0) {
				free(symlink);
				return ERR_PTR(-errno);
			}

			ret = erofs_write_file_from_buffer(dir, symlink);
			if (ret)
				return ERR_PTR(ret);
		} else {
			ret = erofs_write_file(dir);
			if (ret)
				return ERR_PTR(ret);
		}

		erofs_write_tail_end(dir);
		return dir;
	}

	_dir = opendir(dir->i_srcpath);
	if (!_dir) {
		erofs_err("%s, failed to opendir at %s: %s",
			  __func__, dir->i_srcpath, erofs_strerror(errno));
		return ERR_PTR(-errno);
	}

	while (1) {
		/*
		 * set errno to 0 before calling readdir() in order to
		 * distinguish end of stream and from an error.
		 */
		errno = 0;
		dp = readdir(_dir);
		if (!dp)
			break;

		if (is_dot_dotdot(dp->d_name) ||
		    !strncmp(dp->d_name, "lost+found", strlen("lost+found")))
			continue;

		/* skip if it's a exclude file */
		if (erofs_is_exclude_path(dir->i_srcpath, dp->d_name))
			continue;

		d = erofs_d_alloc(dir, dp->d_name);
		if (IS_ERR(d)) {
			ret = PTR_ERR(d);
			goto err_closedir;
		}

		/* to count i_nlink for directories */
		d->type = (dp->d_type == DT_DIR ?
			EROFS_FT_DIR : EROFS_FT_UNKNOWN);
	}

	if (errno) {
		ret = -errno;
		goto err_closedir;
	}
	closedir(_dir);

	ret = erofs_prepare_dir_file(dir);
	if (ret)
		goto err;

	ret = erofs_prepare_inode_buffer_for_uncompressed(dir);
	if (ret)
		goto err;

	if (IS_ROOT(dir))
		erofs_fixup_meta_blkaddr(dir);

	list_for_each_entry(d, &dir->i_subdirs, d_child) {
		char buf[PATH_MAX];
		unsigned char ftype;

		if (is_dot_dotdot(d->name)) {
			erofs_d_invalidate(d);
			continue;
		}

		ret = snprintf(buf, PATH_MAX, "%s/%s",
			       dir->i_srcpath, d->name);
		if (ret < 0 || ret >= PATH_MAX) {
			/* ignore the too long path */
			goto fail;
		}

		d->inode = erofs_mkfs_build_tree_from_path(dir, buf);
		if (IS_ERR(d->inode)) {
			ret = PTR_ERR(d->inode);
fail:
			d->inode = NULL;
			d->type = EROFS_FT_UNKNOWN;
			goto err;
		}

		ftype = erofs_mode_to_ftype(d->inode->i_mode);
		DBG_BUGON(ftype == EROFS_FT_DIR && d->type != ftype);
		d->type = ftype;

		erofs_d_invalidate(d);
		erofs_info("add file %s/%s (nid %llu, type %d)",
			   dir->i_srcpath, d->name, (unsigned long long)d->nid,
			   d->type);
	}
	erofs_write_dir_file(dir);
	erofs_write_tail_end(dir);
	return dir;

err_closedir:
	closedir(_dir);
err:
	return ERR_PTR(ret);
}

struct erofs_inode *erofs_mkfs_build_tree_from_path(struct erofs_inode *parent,
						    const char *path)
{
	struct erofs_inode *const inode = erofs_iget_from_path(path, true);

	if (IS_ERR(inode))
		return inode;

	/* a hardlink to the existed inode */
	if (inode->i_parent) {
		++inode->i_nlink;
		return inode;
	}

	/* a completely new inode is found */
	if (parent)
		inode->i_parent = parent;
	else
		inode->i_parent = inode;	/* rootdir mark */

	return erofs_mkfs_build_tree(inode);
}

