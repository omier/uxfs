/*--------------------------------------------------------------*/
/*---------------------------- ux_dir.c ------------------------*/
/*--------------------------------------------------------------*/

#include <linux/fs.h>
#include <linux/cred.h>
#include <linux/buffer_head.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/slab.h>

#include "ux_fs.h"
#include "ux_xattr.h"
#include "ux_acl.h"

/*
 * Add "name" to the directory "dip"
 */

int ux_diradd(struct inode *dip, const char *name, int inum)
{
	struct ux_inode *uip = (struct ux_inode *)dip->i_private;
	struct buffer_head *bh;
	struct super_block *sb = dip->i_sb;
	struct ux_dirent *dirent;
	__u32 blk;
	int i, pos;

	for (blk = 0; blk < uip->i_blocks; blk++) {
		bh = sb_bread(sb, uip->i_addr[blk]);
		dirent = (struct ux_dirent *)bh->b_data;
		for (i = 0; i < UX_DIRS_PER_BLOCK; i++) {
			if (dirent->d_ino != 0) {
				dirent++;
				continue;
			} else {
				dirent->d_ino = inum;
				strcpy(dirent->d_name, name);
				mark_buffer_dirty(bh);
				mark_inode_dirty(dip);
				brelse(bh);
				return 0;
			}
		}
		brelse(bh);
	}

	/*
	 * We didn't find an empty slot so need to allocate
	 * a new block if there's space in the inode.
	 */

	if (uip->i_blocks < UX_DIRECT_BLOCKS) {
		pos = uip->i_blocks;
		blk = ux_data_alloc(sb);
		uip->i_blocks++;
		uip->i_size += UX_BSIZE;
		dip->i_size += UX_BSIZE;
		dip->i_blocks++;
		uip->i_addr[pos] = blk;
		bh = sb_bread(sb, blk);
		memset(bh->b_data, 0, UX_BSIZE);
		mark_inode_dirty(dip);
		dirent = (struct ux_dirent *)bh->b_data;
		dirent->d_ino = inum;
		strcpy(dirent->d_name, name);
		mark_buffer_dirty(bh);
		brelse(bh);
	}

	return 0;
}

/*
 * Remove "name" from the specified directory.
 */

int ux_dirdel(struct inode *dip, char *name)
{
	struct ux_inode *uip = (struct ux_inode *)dip->i_private;
	struct buffer_head *bh;
	struct super_block *sb = dip->i_sb;
	struct ux_dirent *dirent;
	__u32 blk = 0;
	int i, ino;

	while (blk < uip->i_blocks) {
		bh = sb_bread(sb, uip->i_addr[blk]);
		blk++;
		dirent = (struct ux_dirent *)bh->b_data;
		for (i = 0; i < UX_DIRS_PER_BLOCK; i++) {
			if (!strcmp(dirent->d_name, name)) {
				ino = dirent->d_ino;
				dirent->d_ino = 0;
				dirent->d_name[0] = '\0';
				mark_buffer_dirty(bh);
				brelse(bh);
				return ino;
			}

			dirent++;
		}
		brelse(bh);
	}

	return 0;
}

int ux_readdir(struct file *filp, struct dir_context *ctx)
{
	unsigned long pos;
	struct inode *inode = filp->f_inode;
	struct ux_inode *uip = (struct ux_inode *)inode->i_private;
	struct ux_dirent *udir;
	struct buffer_head *bh;
	__u32 blk;

start_again:
	pos = ctx->pos;
	if (pos >= inode->i_size)
		return 0;
	blk = (pos + 1) / UX_BSIZE;
	blk = uip->i_addr[blk];
	bh = sb_bread(inode->i_sb, blk);
	udir = (struct ux_dirent *)(bh->b_data + pos % UX_BSIZE);

	/*
	 * Skip over 'null' directory entries.
	 */

	if (udir->d_ino == 0) {
		ctx->pos += sizeof(struct ux_dirent);
		brelse(bh);
		goto start_again;
	} else {
		dir_emit(ctx, udir->d_name, sizeof(udir->d_name),
			udir->d_ino, DT_UNKNOWN);
	}
	ctx->pos += sizeof(struct ux_dirent);
	brelse(bh);
	return 0;
}

const struct file_operations ux_dir_operations = {
	.read		= generic_read_dir,
	.iterate_shared	= ux_readdir,
	.fsync		= generic_file_fsync,
};

/*
 * When we reach this point, ux_lookup() has already been called
 * to create a negative entry in the dcache. Thus, we need to
 * allocate a new inode on disk and associate it with the dentry.
 */

int ux_create(struct inode *dip, struct dentry *dentry, umode_t mode, bool excl)
{
	printk("ux_create: 1");
	struct super_block *sb = dip->i_sb;
	printk("ux_create: 2");
	struct ux_inode *nip;
	printk("ux_create: 3");
	struct inode *inode;
	struct posix_acl *acl, *default_acl;
	void* default_acl_in_fs;
	void* access_acl_in_fs;
	struct buffer_head *acl_bh;
	ino_t inum;
	int error;

	/*
	 * See if the entry exists. If not, create a new
	 * disk inode, and incore inode. The add the new
	 * entry to the directory.
	 */
	printk("ux_create: 4");
	inum = ux_find_entry(dip, (char *)dentry->d_name.name);
	printk("ux_create: 5");
	if (inum) {
		printk("ux_create: 6");
		return -EEXIST;
	}

	printk("ux_create: 7");
	inode = new_inode(sb);
	printk("ux_create: 8");
	if (!inode) {
		printk("ux_create: 9");
		return -ENOSPC;
	}

	printk("ux_create: 10");
	inum = ux_inode_alloc(sb);
	printk("ux_create: 11");
	if (!inum) {
		printk("ux_create: 12");
		iput(inode);
		printk("ux_create: 13");
		return -ENOSPC;
	}

	printk("ux_create: 14");
	ux_diradd(dip, (char *)dentry->d_name.name, inum);
	printk("ux_create: 15");
	set_nlink(inode, 1);
	inode->i_size = 0;
	inode->i_blocks = 0;
	inode->i_blkbits = UX_BSIZE_BITS;
	inode->i_uid = current_fsuid();
	inode->i_gid = (dip->i_mode & S_ISGID) ?
			dip->i_gid : current_fsgid();
	inode->i_mtime = inode->i_atime =
			 inode->i_ctime = current_time(dip);
	inode->i_op = &ux_file_inops;
	inode->i_fop = &ux_file_operations;
	inode->i_mapping->a_ops = &ux_aops;
	inode->i_mode = mode | S_IFREG;
	inode->i_ino = inum;
	printk("ux_create: 16");
	inode->i_private = kmalloc(sizeof(struct ux_inode), GFP_KERNEL);

	printk("ux_create: 17");
	nip = (struct ux_inode *)inode->i_private;
	nip->i_mode = mode | S_IFREG;
	nip->i_nlink = 1;
	nip->i_atime = nip->i_ctime = nip->i_mtime = inode->i_atime.tv_sec;
	nip->i_uid = __kuid_val(inode->i_uid);
	nip->i_gid = __kgid_val(inode->i_gid);
	nip->i_size = 0;
	nip->i_blocks = 0;
	printk("ux_create: 18");
	memset(nip->i_addr, 0, UX_DIRECT_BLOCKS * sizeof(nip->i_addr[0]));

	if (!nip->i_acl_blk_addr) {
		printk("ux_fs: 4");
		nip->i_acl_blk_addr = ux_data_alloc(sb);

		printk("ux_fs: 6");
		inode->i_default_acl = posix_acl_from_mode(inode->i_mode, GFP_KERNEL);
		printk("ux_fs: 7");
		inode->i_acl = posix_acl_from_mode(inode->i_mode, GFP_KERNEL);
	}

	printk("ux_create: 19");
	error = ux_init_acl(inode, dip);
	printk("ux_create: 20");
	if (error) {
		printk("ux_create: 21");
		return error;
	}

	printk("ux_create: 22");
	insert_inode_hash(inode);
	d_instantiate(dentry, inode);
	mark_inode_dirty(inode);

	return 0;
}

/*
 * Make a new directory. We already have a negative dentry
 * so must create the directory and instantiate it.
 */

int ux_mkdir(struct inode *dip, struct dentry *dentry, umode_t mode)
{
	struct ux_inode *nip;
	struct buffer_head *bh;
	struct super_block *sb = dip->i_sb;
	struct ux_dirent *dirent;
	struct inode *inode;
	ino_t inum;
	int blk;
	int error;

	/*
	 * Make sure there isn't already an entry. If not,
	 * allocate one, a new inode and new incore inode.
	 */

	inum = ux_find_entry(dip, (char *)dentry->d_name.name);
	if (inum)
		return -EEXIST;

	inode = new_inode(sb);
	if (!inode)
		return -ENOSPC;

	inum = ux_inode_alloc(sb);
	if (!inum) {
		iput(inode);
		return -ENOSPC;
	}

	ux_diradd(dip, (char *)dentry->d_name.name, inum);

	set_nlink(inode, 2);
	inode->i_size = UX_BSIZE;
	inode->i_blocks = 1;
	inode->i_blkbits = UX_BSIZE_BITS;
	inode->i_uid = current_fsuid();
	inode->i_gid = (dip->i_mode & S_ISGID) ?
			dip->i_gid : current_fsgid();
	inode->i_mtime = inode->i_atime =
			inode->i_ctime = current_time(dip);
	inode->i_op = &ux_dir_inops;
	inode->i_fop = &ux_dir_operations;
	inode->i_mapping->a_ops = &ux_aops;
	inode->i_mode = mode | S_IFDIR;
	inode->i_ino = inum;
	inode->i_private = kmalloc(sizeof(struct ux_inode), GFP_KERNEL);

	nip = (struct ux_inode *)inode->i_private;
	nip->i_mode = mode | S_IFDIR;
	nip->i_nlink = 2;
	nip->i_atime = nip->i_ctime
		     = nip->i_mtime = inode->i_atime.tv_sec;
	nip->i_uid = __kuid_val(current_fsuid());
	nip->i_gid = (dip->i_mode & S_ISGID) ?
		      __kgid_val(dip->i_gid) : __kgid_val(current_fsgid());
	nip->i_size = 512;
	nip->i_blocks = 1;
	memset(nip->i_addr, 0, UX_DIRECT_BLOCKS * sizeof(nip->i_addr[0]));
	
	blk = ux_data_alloc(sb);
	nip->i_addr[0] = blk;

	if (!nip->i_acl_blk_addr) {
		printk("ux_mkdir: 4");
		nip->i_acl_blk_addr = ux_data_alloc(sb);

		printk("ux_mkdir: 6");
		inode->i_default_acl = posix_acl_from_mode(inode->i_mode, GFP_KERNEL);
		printk("ux_mkdir: 7");
		inode->i_acl = posix_acl_from_mode(inode->i_mode, GFP_KERNEL);
	}

	printk("ux_mkdir: 19");
	error = ux_init_acl(inode, dip);
	printk("ux_mkdir: 20");
	if (error) {
		printk("ux_mkdir: 21");
		return error;
	}
	bh = sb_bread(sb, blk);
	memset(bh->b_data, 0, UX_BSIZE);
	dirent = (struct ux_dirent *)bh->b_data;
	dirent->d_ino = inum;
	strcpy(dirent->d_name, ".");
	dirent++;
	dirent->d_ino = inode->i_ino;
	strcpy(dirent->d_name, "..");
	mark_buffer_dirty(bh);
	brelse(bh);

	insert_inode_hash(inode);
	d_instantiate(dentry, inode);
	mark_inode_dirty(inode);

	/*
	 * Increment the link count of the parent directory.
	 */

	inode_inc_link_count(dip);
	return 0;
}

/*
 * Remove the specified directory.
 */

int ux_rmdir(struct inode *dip, struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	int inum;

	if (inode->i_nlink > 2)
		return -ENOTEMPTY;

	/*
	 * Remove the entry from the parent directory
	 */

	inum = ux_dirdel(dip, (char *)dentry->d_name.name);
	if (!inum)
		return -ENOTDIR;
	inode_dec_link_count(dip);

	/*
	 * Clean up the inode
	 */

	clear_nlink(inode);

	return 0;
}

/*
 * Lookup the specified file. A call is made to iget() to
 * bring the inode into core.
 */

struct dentry *ux_lookup(struct inode *dip, struct dentry *dentry,
			unsigned int flags)
{
	struct inode *inode = NULL;
	int inum;

	if (dentry->d_name.len > UX_NAMELEN)
		return ERR_PTR(-ENAMETOOLONG);

	inum = ux_find_entry(dip, (char *)dentry->d_name.name);
	if (inum) {
		inode = ux_iget(dip->i_sb, inum);
		if (IS_ERR(inode))
			return ERR_PTR(PTR_ERR(inode));
	}

	d_add(dentry, inode);
	return NULL;
}

/*
 * Called in response to an ln command/syscall.
 */

int ux_link(struct dentry *old, struct inode *dip, struct dentry *new)
{
	struct inode *inode = old->d_inode;
	int error;

	/*
	 * Add the new file (new) to its parent directory (dip)
	 */

	error = ux_diradd(dip, new->d_name.name, inode->i_ino);

	/*
	 * Increment the link count of the target inode
	 */

	inode_inc_link_count(inode);
	mark_inode_dirty(inode);
	atomic_inc(&inode->i_count);
	d_instantiate(new, inode);
	return 0;
}

/*
 * Called to remove a file (decrement its link count)
 */

int ux_unlink(struct inode *dip, struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;

	ux_dirdel(dip, (char *)dentry->d_name.name);
	inode_dec_link_count(inode);
	return 0;
}

const struct inode_operations ux_dir_inops = {
	.create	= ux_create,
	.lookup	= ux_lookup,
	.mkdir	= ux_mkdir,
	.rmdir	= ux_rmdir,
	.link	= ux_link,
	.unlink	= ux_unlink,
	.listxattr	= generic_listxattr,
	.get_acl	= ux_get_acl,
	.set_acl	= ux_set_acl,
};
