#include <linux/init.h>
#include <linux/buffer_head.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include "ux_xattr.h"
#include "ux_acl.h"
#include "ux_fs.h"

struct posix_acl* ux_get_acl(struct inode *inode, int type)
{
	struct ux_inode* uip = (struct ux_inode*)inode->i_private;
	struct buffer_head* acl_bh;
	struct posix_acl *acl;
	int error;
	void *default_acl_in_fs, *access_acl_in_fs;

	printk("ux_get_acl: 1");
	if (!uip->i_acl_blk_addr) {
		printk("ux_get_acl: 4");
		uip->i_acl_blk_addr = ux_data_alloc(inode->i_sb);
	}

	printk("ux_get_acl: 2.5, count: %u, refcount: %u", inode->i_acl->a_count, inode->i_acl->a_refcount);
	acl_bh = sb_bread(inode->i_sb, uip->i_acl_blk_addr);
	printk("ux_fs: 9");
	if (!acl_bh) {
		printk("ux_get_acl: Unable to read inode's %lu acl at block %lu\n", inode->i_ino, uip->i_acl_blk_addr);
		return ERR_PTR(-EIO);
	}
	
	switch (type) {
	case ACL_TYPE_ACCESS:
		printk("ux_fs: 17");
		access_acl_in_fs = kmalloc(uip->i_access_acl_size, GFP_KERNEL);
		
		
		printk("ux_fs: 13, size: %d", uip->i_default_acl_size);
		memcpy(access_acl_in_fs, acl_bh->b_data + UX_ACCESS_ACL_OFFSET, uip->i_access_acl_size);
		printk("ux_fs: 14, size: %d", uip->i_access_acl_size);
		
		acl = posix_acl_from_xattr(inode->i_sb->s_user_ns, access_acl_in_fs, uip->i_access_acl_size);
		printk("ux_get_acl: 15, count: %u, refcount: %u", acl->a_count, acl->a_refcount);
		brelse(acl_bh);
		return acl;
	case ACL_TYPE_DEFAULT:
		printk("ux_get_acl: 3, count: %u, refcount: %u", inode->i_default_acl->a_count, inode->i_default_acl->a_refcount);
		printk("ux_fs: 11");
		default_acl_in_fs = kmalloc(uip->i_default_acl_size, GFP_KERNEL);
		printk("ux_fs: 12");
		memcpy(default_acl_in_fs, acl_bh->b_data + UX_DEFAULT_ACL_OFFSET, uip->i_default_acl_size);
		acl = posix_acl_from_xattr(inode->i_sb->s_user_ns, default_acl_in_fs, uip->i_default_acl_size);
		printk("ux_get_acl: 16, count: %u, refcount: %u", acl->a_count, acl->a_refcount);

		brelse(acl_bh);
		return acl;
	default:
		printk("ux_get_acl: 4");
		BUG();
	}
}

static int __ux_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
	printk("__ux_set_acl: 1");
	struct ux_inode* uip = (struct ux_inode*)inode->i_private;
	struct buffer_head* acl_bh;
	int error;
	void *default_acl_in_fs, *access_acl_in_fs;

	if (!acl) {
		printk("__ux_set_acl: 1, acl is NULL");
		return -EINVAL;
	}

	if (!inode) {
		printk("__ux_set_acl: inode is NULL");
		return -EINVAL;
	}

	if (!uip->i_acl_blk_addr) {
		printk("ux_fs: 4");
		uip->i_acl_blk_addr = ux_data_alloc(inode->i_sb);
	}

	acl_bh = sb_bread(inode->i_sb, uip->i_acl_blk_addr);
	printk("__ux_set_acl: inode %lu acl at block %lu", inode->i_ino, uip->i_acl_blk_addr);
	if (!acl_bh) {
		printk("__ux_set_acl: Unable to write inode's %lu acl at block %lu\n", inode->i_ino, uip->i_acl_blk_addr);
		return ERR_PTR(-EIO);
	}

	printk("__ux_set_acl: 1.5, count: %u, refcount: %u", acl->a_count, acl->a_refcount);
	printk("__ux_set_acl: 2");
	switch(type) {
		case ACL_TYPE_ACCESS:
			printk("__ux_set_acl: 3, count: %d", acl->a_count);

			error = posix_acl_valid(inode->i_sb->s_user_ns, acl);
			if (error) {
				printk("ux_write_inode: access_acl is invalid, count: %u, refcount: %u, error: %d", acl->a_count, acl->a_refcount, error);
				// return error;
			} else {
				printk("count = %d", acl->a_count);
				struct posix_acl_entry *pa, *pe;
				FOREACH_ACL_ENTRY(pa, acl, pe) {
					printk("__ux_set_acl: access_acl: {e_gid: %u, e_uid: %u, e_perm: %u, e_tag: %d}", pa->e_gid, pa->e_uid, pa->e_perm, pa->e_tag);
					break;
				}

				printk("__ux_set_acl: 308, count: %u, refcount: %u", acl->a_count, acl->a_refcount);
				access_acl_in_fs = kmalloc(UX_BSIZE/2, GFP_KERNEL);
				uip->i_access_acl_size = posix_acl_to_xattr(inode->i_sb->s_user_ns, acl, access_acl_in_fs, UX_BSIZE/2);
				printk("__ux_set_acl: 310, size: %d", uip->i_access_acl_size);
				memcpy(acl_bh->b_data + UX_ACCESS_ACL_OFFSET, access_acl_in_fs, uip->i_access_acl_size);
				printk("__ux_set_acl: 312");
			}
			printk("__ux_set_acl: 4");
			printk("__ux_set_acl: 4.55, count: %u, refcount: %u", acl->a_count, acl->a_refcount);
			break;

		case ACL_TYPE_DEFAULT:
			printk("__ux_set_acl: 5, count: %d", acl->a_count);
			printk("__ux_set_acl: 5.5, count: %u, refcount: %u", acl->a_count, acl->a_refcount);
			if (!S_ISDIR(inode->i_mode)) {
				printk("__ux_set_acl: 6");
				return acl ? -EACCES : 0;
			}

			printk("__ux_set_acl: 7");
			error = posix_acl_valid(inode->i_sb->s_user_ns, acl);
			if (error) {
				printk("__ux_set_acl: default_acl is invalid, count: %u, refcount: %u, error: %d", acl->a_count, acl->a_refcount, error);
				return error;
			} else {
				printk("count = %d", acl->a_count);
				struct posix_acl_entry *pa, *pe;
				FOREACH_ACL_ENTRY(pa, acl, pe) {
					printk("default_acl: {e_gid: %u, e_uid: %u, e_perm: %u, e_tag: %d}", pa->e_gid, pa->e_uid, pa->e_perm, pa->e_tag);
					break;
				}

				printk("__ux_set_acl: 308, count: %u, refcount: %u", acl->a_count, acl->a_refcount);
				default_acl_in_fs = kmalloc(UX_BSIZE/2, GFP_KERNEL);
				uip->i_default_acl_size  = posix_acl_to_xattr(inode->i_sb->s_user_ns, acl, default_acl_in_fs, UX_BSIZE/2);
        printk("__ux_set_acl: 309, size: %d", uip->i_default_acl_size);
				memcpy(acl_bh->b_data + UX_DEFAULT_ACL_OFFSET, default_acl_in_fs, uip->i_default_acl_size);
        printk("__ux_set_acl: 311");
			}
			printk("__ux_set_acl: 7.5, count: %u, refcount: %u", acl->a_count, acl->a_refcount);
			break;

		default:
			printk("__ux_set_acl: 8");
			brelse(acl_bh);
			return -EINVAL;
	}

	mark_buffer_dirty(acl_bh);
	brelse(acl_bh);
	mark_inode_dirty(inode);
	set_cached_acl(inode, type, acl);
	printk("__ux_set_acl: 10, count: %u, refcount: %u", acl->a_count, acl->a_refcount);
	return 0;
}

int ux_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
	int error;
	int update_mode = 0;
	printk("ux_set_acl: 1");
	umode_t mode = inode->i_mode;

	printk("ux_set_acl: 2");
	printk("ux_set_acl: 2.5, count: %u, refcount: %u", acl->a_count, acl->a_refcount);
	if (type == ACL_TYPE_ACCESS && acl) {
		printk("ux_set_acl: 3, mode: %u, count: %d", mode, acl->a_count);
		printk("ux_set_acl: 3.5, count: %u, refcount: %u", acl->a_count, acl->a_refcount);
		error = posix_acl_update_mode(inode, &mode, &acl);
		printk("ux_set_acl: 3.55, count: %u, refcount: %u", acl->a_count, acl->a_refcount);
		printk("ux_set_acl: 4, mode: %u, count: %d", mode, acl->a_count);
		if (error) {
			printk("ux_set_acl: 5");
			return error;
		}

		printk("ux_set_acl: 6");
		update_mode = 1;
	}

	printk("ux_set_acl: 7");
	printk("ux_set_acl: 7.5, count: %u, refcount: %u", acl->a_count, acl->a_refcount);
	error = __ux_set_acl(inode, acl, type);
	printk("ux_set_acl: 7.55, count: %u, refcount: %u", acl->a_count, acl->a_refcount);
	printk("ux_set_acl: 8");
	if (!error && update_mode) {
		printk("ux_set_acl: 9, update_mode: %u", update_mode);
		inode->i_mode = mode;
		printk("ux_set_acl: 10");
		inode->i_ctime = current_time(inode);
		printk("ux_set_acl: 11");
		printk("ux_set_acl: 11.5, count: %u, refcount: %u", acl->a_count, acl->a_refcount);
		mark_inode_dirty(inode);
		printk("ux_set_acl: 11.55, count: %u, refcount: %u", acl->a_count, acl->a_refcount);
		printk("ux_set_acl: 12");
	}

	printk("ux_set_acl: 13");
	return error;
}

/*
 * Initialize the ACLs of a new inode. Called from ux_new_inode.
 *
 * dir->i_mutex: down
 * inode->i_mutex: up (access to inode is still exclusive)
 */
int ux_init_acl(struct inode *inode, struct inode *dir)
{
	struct posix_acl *default_acl, *acl;
	int error;
	printk("ux_init_acl: 1");
	error = posix_acl_create(dir, &inode->i_mode, &default_acl, &acl);
	printk("ux_init_acl: 2");
	if (error) {
		printk("ux_init_acl: 3");
		return error;
	}

	inode->i_default_acl = NULL;
	inode->i_acl = NULL;

	printk("ux_init_acl: 4");
	if (default_acl) {
		printk("ux_init_acl: 5");
		printk("ux_init_acl: 5.5, count: %u, refcount: %u", default_acl->a_count, default_acl->a_refcount);
		error = __ux_set_acl(inode, default_acl, ACL_TYPE_DEFAULT);
		printk("ux_init_acl: 5.55, count: %u, refcount: %u", default_acl->a_count, default_acl->a_refcount);
		printk("ux_init_acl: 6");
		printk("ux_init_acl: 6.5, count: %u, refcount: %u", default_acl->a_count, default_acl->a_refcount);
		posix_acl_release(default_acl);
		printk("ux_init_acl: 6.55, count: %u, refcount: %u", default_acl->a_count, default_acl->a_refcount);
	}

	printk("ux_init_acl: 7");
	if (acl) {
		printk("ux_init_acl: 8");
		if (!error) {
			printk("ux_init_acl: 9");
			printk("ux_init_acl: 9.5, count: %u, refcount: %u", acl->a_count, acl->a_refcount);
			error = __ux_set_acl(inode, acl, ACL_TYPE_ACCESS);
			printk("ux_init_acl: 9.55, count: %u, refcount: %u", acl->a_count, acl->a_refcount);
			printk("ux_init_acl: 10");
		}
		printk("ux_init_acl: 11");
		printk("ux_init_acl: 11.5, count: %u, refcount: %u", acl->a_count, acl->a_refcount);
		posix_acl_release(acl);
		printk("ux_init_acl: 11.55, count: %u, refcount: %u", acl->a_count, acl->a_refcount);
		printk("ux_init_acl: 12");
	}

	printk("ux_init_acl: 13");
	return error;
}