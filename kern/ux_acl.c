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
static struct posix_acl *
ux_acl_from_disk(const void *value, size_t size)
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
		if ((char *)value + sizeof(ux_acl_entry_short) > end)
			goto fail;
		acl->a_entries[n].e_tag  = le16_to_cpu(entry->e_tag);
		acl->a_entries[n].e_perm = le16_to_cpu(entry->e_perm);
		switch(acl->a_entries[n].e_tag) {
			case ACL_USER_OBJ:
			case ACL_GROUP_OBJ:
			case ACL_MASK:
			case ACL_OTHER:
				value = (char *)value +
					sizeof(ux_acl_entry_short);
				break;

			case ACL_USER:
				value = (char *)value + sizeof(ux_acl_entry);
				if ((char *)value > end)
					goto fail;
				acl->a_entries[n].e_uid =
					make_kuid(&init_user_ns,
						  le32_to_cpu(entry->e_id));
				break;
			case ACL_GROUP:
				value = (char *)value + sizeof(ux_acl_entry);
				if ((char *)value > end)
					goto fail;
				acl->a_entries[n].e_gid =
					make_kgid(&init_user_ns,
						  le32_to_cpu(entry->e_id));
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
static void *
ux_acl_to_disk(const struct posix_acl *acl, size_t *size)
{
	char *acl_entries;
	size_t n;

	*size = ux_acl_size(acl->a_count);
	acl_entries = kmalloc(acl->a_count * sizeof(ux_acl_entry), GFP_KERNEL);

	for (n=0; n < acl->a_count; n++) {
		const struct posix_acl_entry *acl_e = &acl->a_entries[n];
		ux_acl_entry *entry = (ux_acl_entry *)acl_entries;
		entry->e_tag = cpu_to_le16(acl_e->e_tag);
		entry->e_perm = cpu_to_le16(acl_e->e_perm);
		switch(acl_e->e_tag) {
			case ACL_USER:
				entry->e_id = cpu_to_le32(
					from_kuid(&init_user_ns, acl_e->e_uid));
				acl_entries += sizeof(ux_acl_entry);
				break;
			case ACL_GROUP:
				entry->e_id = cpu_to_le32(
					from_kgid(&init_user_ns, acl_e->e_gid));
				acl_entries += sizeof(ux_acl_entry);
				break;

			case ACL_USER_OBJ:
			case ACL_GROUP_OBJ:
			case ACL_MASK:
			case ACL_OTHER:
				acl_entries += sizeof(ux_acl_entry_short);
				break;

			default:
				goto fail;
		}
	}
	return acl_entries;

fail:
	kfree(acl_entries);
	return ERR_PTR(-EINVAL);
}

/*
 * inode->i_mutex: don't care
 */
struct posix_acl *
ux_get_acl(struct inode *inode, int type)
{
	int name_index;
	char *value = NULL;
	struct posix_acl *acl;
	int retval;

	switch (type) {
	case ACL_TYPE_ACCESS:
		name_index = UX_XATTR_INDEX_POSIX_ACL_ACCESS;
		break;
	case ACL_TYPE_DEFAULT:
		name_index = UX_XATTR_INDEX_POSIX_ACL_DEFAULT;
		break;
	default:
		BUG();
	}
	retval = ux_xattr_get(inode, name_index, "", NULL, 0);
	if (retval > 0) {
		value = kmalloc(retval, GFP_KERNEL);
		if (!value)
			return ERR_PTR(-ENOMEM);
		retval = ux_xattr_get(inode, name_index, "", value, retval);
	}
	if (retval > 0)
		acl = ux_acl_from_disk(value, retval);
	else if (retval == -ENODATA || retval == -ENOSYS)
		acl = NULL;
	else
		acl = ERR_PTR(retval);
	kfree(value);

	return acl;
}

static int
__ux_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
	int name_index;
	void *value = NULL;
	size_t size = 0;
	int error;

	switch(type) {
		case ACL_TYPE_ACCESS:
			name_index = UX_XATTR_INDEX_POSIX_ACL_ACCESS;
			break;

		case ACL_TYPE_DEFAULT:
			name_index = UX_XATTR_INDEX_POSIX_ACL_DEFAULT;
			if (!S_ISDIR(inode->i_mode))
				return acl ? -EACCES : 0;
			break;

		default:
			return -EINVAL;
	}
 	if (acl) {
		value = ux_acl_to_disk(acl, &size);
		if (IS_ERR(value))
			return (int)PTR_ERR(value);
	}

	error = ux_xattr_set(inode, name_index, "", value, size, 0);

	kfree(value);
	if (!error)
		set_cached_acl(inode, type, acl);
	return error;
}

/*
 * inode->i_mutex: down
 */
int
ux_set_acl(struct inode *inode,
	     struct posix_acl *acl, int type)
{
	int error;
	int update_mode = 0;
	umode_t mode = inode->i_mode;

	printk("set_acl");

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
int
ux_init_acl(struct inode *inode, struct inode *dir)
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