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

	if (!inode) {
		return -EINVAL;
	}

	if (!uip->i_acl_blk_addr) {
		uip->i_acl_blk_addr = ux_data_alloc(inode->i_sb);
	}

	acl_bh = sb_bread(inode->i_sb, uip->i_acl_blk_addr);
	if (!acl_bh) {
		return ERR_PTR(-EIO);
	}
	
	switch (type) {
	case ACL_TYPE_ACCESS:
		access_acl_in_fs = kmalloc(uip->i_access_acl_size, GFP_KERNEL);
		memcpy(access_acl_in_fs, acl_bh->b_data + UX_ACCESS_ACL_OFFSET, uip->i_access_acl_size);
		acl = posix_acl_from_xattr(inode->i_sb->s_user_ns, access_acl_in_fs, uip->i_access_acl_size);
		
		brelse(acl_bh);
		return acl;
	case ACL_TYPE_DEFAULT:
		default_acl_in_fs = kmalloc(uip->i_default_acl_size, GFP_KERNEL);
		memcpy(default_acl_in_fs, acl_bh->b_data + UX_DEFAULT_ACL_OFFSET, uip->i_default_acl_size);
		acl = posix_acl_from_xattr(inode->i_sb->s_user_ns, default_acl_in_fs, uip->i_default_acl_size);

		brelse(acl_bh);
		return acl;
	default:
		brelse(acl_bh);
		BUG();
	}
}

static int __ux_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
	struct ux_inode* uip = (struct ux_inode*)inode->i_private;
	struct buffer_head* acl_bh;
	int error;
	void *default_acl_in_fs, *access_acl_in_fs;

	if (!acl) {
		return -EINVAL;
	}

	if (!inode) {
		return -EINVAL;
	}

	if (!uip->i_acl_blk_addr) {
		uip->i_acl_blk_addr = ux_data_alloc(inode->i_sb);
	}

	acl_bh = sb_bread(inode->i_sb, uip->i_acl_blk_addr);
	if (!acl_bh) {
		return ERR_PTR(-EIO);
	}

	switch(type) {
		case ACL_TYPE_ACCESS:
			error = posix_acl_valid(inode->i_sb->s_user_ns, acl);
			if (error) {
				return error;
			}

			access_acl_in_fs = kmalloc(UX_BSIZE/2, GFP_KERNEL);
			uip->i_access_acl_size = posix_acl_to_xattr(inode->i_sb->s_user_ns, acl, access_acl_in_fs, UX_BSIZE/2);
			memcpy(acl_bh->b_data + UX_ACCESS_ACL_OFFSET, access_acl_in_fs, uip->i_access_acl_size);
			
			break;

		case ACL_TYPE_DEFAULT:
			if (!S_ISDIR(inode->i_mode)) {
				return acl ? -EACCES : 0;
			}
			
			error = posix_acl_valid(inode->i_sb->s_user_ns, acl);
			if (error) {
				
				return error;
			}
				
			default_acl_in_fs = kmalloc(UX_BSIZE/2, GFP_KERNEL);
			uip->i_default_acl_size  = posix_acl_to_xattr(inode->i_sb->s_user_ns, acl, default_acl_in_fs, UX_BSIZE/2);
			
			memcpy(acl_bh->b_data + UX_DEFAULT_ACL_OFFSET, default_acl_in_fs, uip->i_default_acl_size);
			
			break;

		default:
			brelse(acl_bh);
			return -EINVAL;
	}

	mark_buffer_dirty(acl_bh);
	brelse(acl_bh);
	mark_inode_dirty(inode);
	set_cached_acl(inode, type, acl);
	
	return 0;
}

int ux_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
	int error;
	int update_mode = 0;
	umode_t mode = inode->i_mode;
	
	if (type == ACL_TYPE_ACCESS && acl) {
		error = posix_acl_update_mode(inode, &mode, &acl);
		
		if (error) {
			return error;
		}

		update_mode = 1;
	}

	error = __ux_set_acl(inode, acl, type);
	if (!error && update_mode) {
		inode->i_mode = mode;
		inode->i_ctime = current_time(inode);
		mark_inode_dirty(inode);
	}

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
	
	error = posix_acl_create(dir, &inode->i_mode, &default_acl, &acl);
	if (error) {
		return error;
	}

	inode->i_default_acl = NULL;
	inode->i_acl = NULL;
	
	if (default_acl) {
		error = __ux_set_acl(inode, default_acl, ACL_TYPE_DEFAULT);
		posix_acl_release(default_acl);
	}
	
	if (acl) {
		if (!error) {
			error = __ux_set_acl(inode, acl, ACL_TYPE_ACCESS);
		}
		
		posix_acl_release(acl);
	}

	return error;
}