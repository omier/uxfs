#include <linux/init.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include "ux_xattr.h"
#include "ux_acl.h"
#include "ux_fs.h"

/*
 * Convert from filesystem to in-memory representation.
 */
struct posix_acl* ux_acl_from_disk(const void *value, int size)
{
	const char *end = (char *)value + size;
	int n, count;
	struct posix_acl *acl;

	if (!value)
		return NULL;
	
	value = (char *)value;
	count = ux_acl_count(size);
	if (count < 0)
		return ERR_PTR(-EINVAL);
	if (count == 0)
		return NULL;
	acl = posix_acl_alloc(count, GFP_KERNEL);
	if (!acl)
		return ERR_PTR(-ENOMEM);
	for (n=0; n < count; n++) {
		ux_acl_entry *entry =
			(ux_acl_entry *)value;
		if ((char *)value + sizeof(ux_acl_entry) > end)
			goto fail;
		acl->a_entries[n].e_tag  = entry->e_tag;
		acl->a_entries[n].e_perm = entry->e_perm;
		switch(acl->a_entries[n].e_tag) {
			case ACL_USER_OBJ:
			case ACL_GROUP_OBJ:
			case ACL_MASK:
			case ACL_OTHER:
				value = (char *)value +
					sizeof(ux_acl_entry);
				break;

			case ACL_USER:
				value = (char *)value + sizeof(ux_acl_entry);
				if ((char *)value > end)
					goto fail;
				acl->a_entries[n].e_uid = entry->e_uid;
				break;
			case ACL_GROUP:
				value = (char *)value + sizeof(ux_acl_entry);
				if ((char *)value > end)
					goto fail;
				acl->a_entries[n].e_gid = entry->e_gid;
				break;

			default:
				goto fail;
		}
	}
	if (value != end)
		goto fail;
	return acl;

fail:
	posix_acl_release(acl);
	return ERR_PTR(-EINVAL);
}

/*
 * Convert from in-memory to filesystem representation.
 */
void* ux_acl_to_disk(const struct posix_acl *acl, int *size)
{
	printk("ux_fs: 400");
	char *acl_entries;
	size_t n;

	printk("ux_fs: 401");
	*size = ux_acl_size(acl->a_count);
	printk("ux_fs: 402");
	acl_entries = kmalloc(*size, GFP_KERNEL);
	printk("ux_fs: 403");

	for (n=0; n < acl->a_count; n++) {
		printk("ux_fs: 404-%d", n);
		const struct posix_acl_entry *acl_e = &acl->a_entries[n];
		printk("ux_fs: 405-%d", n);
		ux_acl_entry *entry = (ux_acl_entry *)acl_entries;
		entry->e_tag = cpu_to_le16(acl_e->e_tag);
		entry->e_perm = cpu_to_le16(acl_e->e_perm);
		switch(acl_e->e_tag) {
			case ACL_USER:
				entry->e_uid = acl_e->e_uid;
				acl_entries += sizeof(ux_acl_entry);
				break;
			case ACL_GROUP:
				entry->e_gid = acl_e->e_gid;
				acl_entries += sizeof(ux_acl_entry);
				break;

			case ACL_USER_OBJ:
			case ACL_GROUP_OBJ:
			case ACL_MASK:
			case ACL_OTHER:
				acl_entries += sizeof(ux_acl_entry);
				break;

			default:
				goto fail;
		}
	}
	return acl_entries;

fail:
	printk("ux_fs: 406");
	kfree(acl_entries);
	return ERR_PTR(-EINVAL);
}

struct posix_acl* ux_get_acl(struct inode *inode, int type)
{
	switch (type) {
	case ACL_TYPE_ACCESS:
		return inode->i_acl;
		break;
	case ACL_TYPE_DEFAULT:
		return inode->i_default_acl;
		break;
	default:
		BUG();
	}
}

static int __ux_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
	struct ux_inode* uip = (struct ux_inode*)inode->i_private;

	switch(type) {
		case ACL_TYPE_ACCESS:
			inode->i_acl = acl;
			break;

		case ACL_TYPE_DEFAULT:
			if (!S_ISDIR(inode->i_mode))
				return acl ? -EACCES : 0;
			inode->i_default_acl = acl;
			break;

		default:
			return -EINVAL;
	}


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
		if (error)
			return error;
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