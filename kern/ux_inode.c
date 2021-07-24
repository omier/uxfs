/*--------------------------------------------------------------*/
/*--------------------------- ux_inode.c -----------------------*/
/*--------------------------------------------------------------*/

#include <linux/fs.h>
#include <linux/buffer_head.h>
#include <linux/statfs.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/uaccess.h>
#include "ux_fs.h"
#include "ux_xattr.h"
#include "ux_acl.h"

/*
 * This function looks for "name" in the directory "dip".
 * If found the inode number is returned.
 */

int ux_find_entry(struct inode *dip, char *name)
{
	struct ux_inode *uip = (struct ux_inode *)dip->i_private;
	struct super_block *sb = dip->i_sb;
	struct buffer_head *bh;
	struct ux_dirent *dirent;
	int i, blk;

	printk("uxfs: start %s with dir=%lu name=%s\n",
		__func__, dip->i_ino, name);

	for (blk = 0; blk < uip->i_blocks; blk++) {
		bh = sb_bread(sb, uip->i_addr[blk]);
		dirent = (struct ux_dirent *)bh->b_data;
		for (i = 0; i < UX_DIRS_PER_BLOCK; i++) {
			if (strcmp(dirent->d_name, name) == 0) {
				brelse(bh);
				return dirent->d_ino;
			}
			dirent++;
		}
		brelse(bh);
	}

	return 0;
}

/*
 * This function is called in response to an iget(). For
 * example, we call iget() from ux_lookup().
 */

struct inode *ux_iget(struct super_block *sb, unsigned long ino)
{
	struct buffer_head *bh;
	struct ux_inode *di;
	struct inode *inode;
	void* default_acl_in_fs;
	void* access_acl_in_fs;
	struct buffer_head *acl_bh;
	
	int block;

	printk("uxfs: start %s with inode=%lu\n", __func__, ino);

	if (ino < UX_ROOT_INO || ino > UX_MAXFILES) {
		printk("uxfs: Bad inode number %lu\n", ino);
		return ERR_PTR(-ENOENT);
	}

	/*
	 * Note that for simplicity, there is only one
	 * inode per block!
	 */

	block = UX_INODE_BLOCK + ino;
	bh = sb_bread(sb, block);
	if (!bh) {
		printk("Unable to read inode %lu\n", ino);
		return ERR_PTR(-EIO);
	}

	inode = iget_locked(sb, ino);
	if (!inode)
		return ERR_PTR(-ENOMEM);
	if (!(inode->i_state & I_NEW))
		return inode;

	di = (struct ux_inode *)(bh->b_data);

	inode->i_mode = di->i_mode;
	
	printk("ux_fs: 1");
	
	if (di->i_mode & S_IFDIR) {
		inode->i_mode |= S_IFDIR;
		inode->i_op = &ux_dir_inops;
		inode->i_fop = &ux_dir_operations;
	} else if (di->i_mode & S_IFREG) {
		inode->i_mode |= S_IFREG;
		inode->i_op = &ux_file_inops;
		inode->i_fop = &ux_file_operations;
		inode->i_mapping->a_ops = &ux_aops;
	}
	i_uid_write(inode, di->i_uid);
	i_gid_write(inode, di->i_gid);
	set_nlink(inode, di->i_nlink);
	inode->i_size = di->i_size;
	inode->i_blocks = di->i_blocks;
	inode->i_blkbits = UX_BSIZE_BITS;
	inode->i_atime.tv_sec = di->i_atime;
	inode->i_mtime.tv_sec = di->i_mtime;
	inode->i_ctime.tv_sec = di->i_ctime;
	inode->i_atime.tv_nsec = 0;
	inode->i_mtime.tv_nsec = 0;
	inode->i_ctime.tv_nsec = 0;
	inode->i_private = kmalloc(sizeof(struct ux_inode), GFP_KERNEL);

	if (!di->i_acl_blk_addr) {
		printk("ux_fs: 4");
		di->i_acl_blk_addr = ux_data_alloc(sb);

		printk("ux_fs: 6");
		inode->i_default_acl = posix_acl_from_mode(inode->i_mode, GFP_KERNEL);
		printk("ux_fs: 7");
		inode->i_acl = posix_acl_from_mode(inode->i_mode, GFP_KERNEL);
	} else {
		printk("ux_fs: 8");
		acl_bh = sb_bread(sb, di->i_acl_blk_addr);
		printk("ux_fs: 9");
		if (!acl_bh) {
			printk("ux_fs: 10");
			printk("Unable to read inode's %lu acl at block %lu\n", ino, di->i_acl_blk_addr);
			return ERR_PTR(-EIO);
		}

		printk("ux_fs: 11");
		default_acl_in_fs = kmalloc(di->i_default_acl_size, GFP_KERNEL);
		printk("ux_fs: 17");
		access_acl_in_fs = kmalloc(di->i_access_acl_size, GFP_KERNEL);
		
		printk("ux_fs: 12");
		memcpy(default_acl_in_fs, acl_bh->b_data + UX_DEFAULT_ACL_OFFSET, di->i_default_acl_size);
		printk("ux_fs: 13, size: %d", di->i_default_acl_size);
		memcpy(access_acl_in_fs, acl_bh->b_data + UX_ACCESS_ACL_OFFSET, di->i_access_acl_size);
		printk("ux_fs: 14, size: %d", di->i_access_acl_size);
		inode->i_default_acl = ux_acl_from_disk(default_acl_in_fs, di->i_default_acl_size);
		printk("ux_fs: 15, count: %d", inode->i_default_acl->a_count);
		inode->i_acl = ux_acl_from_disk(access_acl_in_fs, di->i_access_acl_size);
		printk("ux_fs: 16, count: %d", inode->i_acl->a_count);
		brelse(acl_bh);
		printk("ux_fs: 18");
	}

	memcpy(inode->i_private, di, sizeof(struct ux_inode));
	brelse(bh);
	unlock_new_inode(inode);
	printk("ux_fs: 2");
	return inode;
}

/*
 * This function is called to write a dirty inode to disk.
 */

int ux_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	printk("ux_fs: 300");
	unsigned long ino = inode->i_ino;
	printk("ux_fs: 301");
	struct ux_inode* uip = (struct ux_inode *)inode->i_private;
	printk("ux_fs: 302");
	struct buffer_head* bh;
	struct buffer_head* acl_bh;
	void* default_acl_in_fs;
	void* access_acl_in_fs;
	int error = 0;

	struct ux_fs *fs = (struct ux_fs *)inode->i_sb->s_fs_info;
	struct ux_superblock *usb = fs->u_sb;

	printk("uxfs: start %s with inode=%lu\n", __func__, ino);
	printk("uxfs: %s: super block { s_nifree: %u, s_block: %p, s_inode: %p, s_magic: %u, s_mod: %u, s_nbfree: %u }",
	__func__, usb->s_nifree, usb->s_block, usb->s_inode, usb->s_magic, usb->s_mod, usb->s_nbfree);

	if (ino < UX_ROOT_INO || ino > UX_MAXFILES) {
		printk("ux_fs: 303");
		printk("uxfs: %s bad inode number %lu\n", __func__, ino);
		return -EIO;
	}

	printk("ux_fs: 304");
	bh = sb_bread(inode->i_sb, UX_INODE_BLOCK + ino);
	if (!bh) {
		printk("ux_fs: 305");
		printk("Unable to write inode %lu\n", ino);
		return ERR_PTR(-EIO);
	}

	uip->i_mode = inode->i_mode;
	uip->i_nlink = inode->i_nlink;
	uip->i_atime = inode->i_atime.tv_sec;
	uip->i_mtime = inode->i_mtime.tv_sec;
	uip->i_ctime = inode->i_ctime.tv_sec;
	uip->i_uid = __kuid_val(inode->i_uid);
	uip->i_gid = __kgid_val(inode->i_gid);
	uip->i_size = inode->i_size;
	uip->i_blocks = inode->i_blocks;

	if (inode->i_acl || inode->i_default_acl) {
		printk("ux_fs: 306: i_acl: %p, i_default_acl: %p", inode->i_acl, inode->i_default_acl);
		acl_bh = sb_bread(inode->i_sb, uip->i_acl_blk_addr);
		printk("ux_fs: inode %lu acl at block %lu", ino, uip->i_acl_blk_addr);
		if (!acl_bh) {
			printk("ux_fs: 307");
			printk("Unable to write inode's %lu acl at block %lu\n", ino, uip->i_acl_blk_addr);
			return ERR_PTR(-EIO);
		}
		if (inode->i_default_acl) {
			error = posix_acl_valid(inode->i_sb->s_user_ns, inode->i_default_acl);
			if (error) {
				printk("ux_write_inode: default_acl is invalid, count: %u, refcount: %u, error: %d", inode->i_default_acl->a_count, inode->i_default_acl->a_refcount, error);
				// return error;
			} else {
				printk("count = %d", inode->i_default_acl->a_count);
				struct posix_acl_entry *pa, *pe;
				FOREACH_ACL_ENTRY(pa, inode->i_default_acl, pe) {
					printk("default_acl: {e_gid: %u, e_uid: %u, e_perm: %u, e_tag: %d}", pa->e_gid, pa->e_uid, pa->e_perm, pa->e_tag);
					break;
				}

				printk("ux_fs: 308, count: %u, refcount: %u", inode->i_default_acl->a_count, inode->i_default_acl->a_refcount);
				default_acl_in_fs = ux_acl_to_disk(inode->i_default_acl, &uip->i_default_acl_size);
        printk("uxfs: %s <ux_acl_to_disk default>: super block { s_nifree: %u, s_block: %p, s_inode: %p, s_magic: %u, s_mod: %u, s_nbfree: %u }",
					__func__, usb->s_nifree, usb->s_block, usb->s_inode, usb->s_magic, usb->s_mod, usb->s_nbfree);
        printk("ux_fs: 309, size: %d", uip->i_default_acl_size);
				memcpy(acl_bh->b_data + UX_DEFAULT_ACL_OFFSET, default_acl_in_fs, uip->i_default_acl_size);
        printk("uxfs: %s <ux_acl_to_disk default after memcpy>: super block { s_nifree: %u, s_block: %p, s_inode: %p, s_magic: %u, s_mod: %u, s_nbfree: %u }",
					__func__, usb->s_nifree, usb->s_block, usb->s_inode, usb->s_magic, usb->s_mod, usb->s_nbfree);
        printk("ux_fs: 311");
			}
		}

		error = 0;
		if (inode->i_acl) {
			error = posix_acl_valid(inode->i_sb->s_user_ns, inode->i_acl);
			if (error) {
				printk("ux_write_inode: access_acl is invalid, count: %u, refcount: %u, error: %d", inode->i_acl->a_count, inode->i_acl->a_refcount, error);
				// return error;
			} else {
				printk("count = %d", inode->i_acl->a_count);
				struct posix_acl_entry *pa, *pe;
				FOREACH_ACL_ENTRY(pa, inode->i_acl, pe) {
					printk("access_acl: {e_gid: %u, e_uid: %u, e_perm: %u, e_tag: %d}", pa->e_gid, pa->e_uid, pa->e_perm, pa->e_tag);
					break;
				}

				printk("ux_fs: 308, count: %u, refcount: %u", inode->i_acl->a_count, inode->i_acl->a_refcount);
				access_acl_in_fs = ux_acl_to_disk(inode->i_acl, &uip->i_access_acl_size);
				printk("ux_fs: 310, size: %d", uip->i_access_acl_size);
        printk("uxfs: %s <ux_acl_to_disk regular>: super block { s_nifree: %u, s_block: %p, s_inode: %p, s_magic: %u, s_mod: %u, s_nbfree: %u }",
	__func__, usb->s_nifree, usb->s_block, usb->s_inode, usb->s_magic, usb->s_mod, usb->s_nbfree);
				memcpy(acl_bh->b_data + UX_ACCESS_ACL_OFFSET, access_acl_in_fs, uip->i_access_acl_size);
        printk("uxfs: %s <ux_acl_to_disk regular after memcpy>: super block { s_nifree: %u, s_block: %p, s_inode: %p, s_magic: %u, s_mod: %u, s_nbfree: %u }",
	__func__, usb->s_nifree, usb->s_block, usb->s_inode, usb->s_magic, usb->s_mod, usb->s_nbfree);
				printk("ux_fs: 312");
			}
		}

		mark_buffer_dirty(acl_bh);
		brelse(acl_bh);
	}

	printk("uxfs: after %s: super block { s_nifree: %u, s_block: %p, s_inode: %p, s_magic: %u, s_mod: %u, s_nbfree: %u }",
	__func__, usb->s_nifree, usb->s_block, usb->s_inode, usb->s_magic, usb->s_mod, usb->s_nbfree);
	memcpy(bh->b_data, uip, sizeof(struct ux_inode));
	mark_buffer_dirty(bh);
	brelse(bh);

	return 0;
}

/*
 * This function gets called when the link count goes to zero.
 */

void ux_evict_inode(struct inode *inode)
{
	unsigned long inum = inode->i_ino;
	struct ux_inode *uip = (struct ux_inode *)inode->i_private;
	struct super_block *sb = inode->i_sb;
	struct ux_fs *fs = (struct ux_fs *)sb->s_fs_info;
	struct ux_superblock *usb = fs->u_sb;
	int i;

	printk("uxfs: start %s with inode=%lu nlink=%u\n",
		__func__, inum, inode->i_nlink);

	if (!inode->i_nlink) {
		usb->s_nbfree += uip->i_blocks;
		for (i = 0; i < uip->i_blocks; i++) {
			usb->s_block[uip->i_addr[i]] = UX_BLOCK_FREE;
			uip->i_addr[i] = UX_BLOCK_FREE;
		}
		usb->s_inode[inum] = UX_INODE_FREE;
		usb->s_nifree++;
		ux_write_super(sb);
	}

	kfree(inode->i_private);
	inode->i_private = NULL;

	truncate_inode_pages_final(&inode->i_data);
	invalidate_inode_buffers(inode);
	clear_inode(inode);
}

/*
 * This function is called when the filesystem is being
 * unmounted. We free the ux_fs structure allocated during
 * ux_read_super() and free the superblock buffer_head.
 */

void ux_put_super(struct super_block *sb)
{
	struct ux_fs *fs = (struct ux_fs *)sb->s_fs_info;
	struct buffer_head *bh = fs->u_sbh;

	printk("uxfs: start %s\n", __func__);

	/*
	 * Free the ux_fs structure allocated by ux_read_super
	 */

	kfree(fs);
	brelse(bh);
}

/*
 * This function will be called by the df command.
 */

int ux_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct ux_fs *fs = (struct ux_fs *)sb->s_fs_info;
	struct ux_superblock *usb = fs->u_sb;
	u64 id = huge_encode_dev(sb->s_bdev->bd_dev);

	printk("uxfs: start %s\n", __func__);

	buf->f_type = UX_MAGIC;
	buf->f_bsize = UX_BSIZE;
	buf->f_blocks = UX_MAXBLOCKS;
	buf->f_bfree = usb->s_nbfree;
	buf->f_bavail = usb->s_nbfree;
	buf->f_files = UX_MAXFILES;
	buf->f_ffree = usb->s_nifree;
	buf->f_fsid.val[0] = (u32)id;
	buf->f_fsid.val[1] = (u32)(id >> 32);
	buf->f_namelen = UX_NAMELEN;
	return 0;
}

/*
 * This function is called to write the superblock to disk. We
 * simply mark it dirty and then set the s_dirt field of the
 * in-core superblock to 0 to prevent further unnecessary calls.
 */

void ux_write_super(struct super_block *sb)
{
	struct ux_fs *fs = (struct ux_fs *)sb->s_fs_info;
	struct buffer_head *bh = fs->u_sbh;

	printk("uxfs: start %s\n", __func__);

	if (!(sb->s_flags & SB_RDONLY))
		mark_buffer_dirty(bh);

	printk("uxfs:  stop %s\n", __func__);
}

static const struct super_operations ux_sops = {
	.write_inode	= ux_write_inode,
	.evict_inode	= ux_evict_inode,
	.put_super	= ux_put_super,
	.statfs		= ux_statfs,
};

static int ux_read_super(struct super_block *sb, void *data, int silent)
{
	struct buffer_head *bh = NULL;
	struct ux_superblock *usb = NULL;
	struct ux_fs *fs = NULL;
	struct inode *inode = NULL;
	int ret = -EINVAL;

	printk("uxfs: start %s with silent=%d\n", __func__, silent);

	if (!sb_set_blocksize(sb, UX_BSIZE)) {
		if (!silent)
			printk("uxfs: %s unable to set blocksize %u\n",
				__func__, UX_BSIZE);
		goto out;
	}

	bh = sb_bread(sb, 0);
	if (!bh)
		goto out;

	usb = (struct ux_superblock *)bh->b_data;
	if (usb->s_magic != UX_MAGIC) {
		if (!silent)
			printk("uxfs: %s unable to find filesystem\n",
				__func__);
		goto out;
	}
	if (usb->s_mod == UX_FSDIRTY) {
		printk("uxfs: %s Filesystem is not clean. Write and run fsck!\n",
			__func__);
		goto out;
	}

	printk("uxfs: %s: super block { s_nifree: %u, s_block: %p, s_inode: %p, s_magic: %u, s_mod: %u, s_nbfree: %u }",
	__func__, usb->s_nifree, usb->s_block, usb->s_inode, usb->s_magic, usb->s_mod, usb->s_nbfree);
	/*
	 *  We should really mark the superblock to
	 *  be dirty and write it back to disk.
	 */

	fs = kmalloc(sizeof(struct ux_fs), GFP_KERNEL);
	if (!fs) {
		ret = -ENOMEM;
		goto out;
	}
	fs->u_sb = usb;
	fs->u_sbh = bh;
	sb->s_fs_info = fs;

	sb->s_magic = UX_MAGIC;
	sb->s_op = &ux_sops;
	sb->s_xattr = ux_xattr_handlers;
	sb->s_flags = (sb->s_flags & ~SB_POSIXACL) | SB_POSIXACL;

	printk("ux_fs: 211");
	inode = ux_iget(sb, UX_ROOT_INO);
	printk("ux_fs: 212");
	if (IS_ERR(inode)) {
		printk("ux_fs: 213");
		ret = PTR_ERR(inode);
		goto out;
	}

	sb->s_root = d_make_root(inode);
	printk("ux_fs: 214");
	if (!sb->s_root) {
		printk("ux_fs: 215");
		/* Nothing needed for the inode cleanup */
		ret = -ENOMEM;
		goto out;
	}

	printk("ux_fs: 216");
	ux_write_super(sb);
	printk("ux_fs: 217");

	printk("uxfs: after %s: super block { s_nifree: %u, s_block: %p, s_inode: %p, s_magic: %u, s_mod: %u, s_nbfree: %u }",
	__func__, usb->s_nifree, usb->s_block, usb->s_inode, usb->s_magic, usb->s_mod, usb->s_nbfree);
	printk("uxfs:  stop %s\n", __func__);
	return 0;

out:
	printk("ux_fs: 2 out");
	kfree(fs);
	brelse(bh);

	printk("uxfs: fail %s with %d\n", __func__, ret);
	return ret;
}

static struct dentry *ux_mount(struct file_system_type *fs_type, int flags,
				const char *dev_name, void *data)
{
	printk("uxfs: start %s with dev=%s\n", __func__, dev_name);

	return mount_bdev(fs_type, flags, dev_name, data, ux_read_super);
}

static struct file_system_type ux_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "uxfs",
	.mount		= ux_mount,
	.kill_sb	= kill_block_super,
	.fs_flags	= FS_REQUIRES_DEV,
};

static int __init init_uxfs(void)
{
	printk("uxfs: start %s\n", __func__);

	return register_filesystem(&ux_fs_type);
}

static void __exit exit_uxfs(void)
{
	printk("uxfs: start %s\n", __func__);

	unregister_filesystem(&ux_fs_type);
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("A primitive filesystem for Linux");
MODULE_AUTHOR("Steve Pate <spate@veritas.com>");

module_init(init_uxfs)
module_exit(exit_uxfs)
