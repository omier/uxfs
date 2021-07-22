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
	printk("ux_acl_from_disk: 1");
	const char *end = (char *)value + size;
	int n, count;
	struct posix_acl *acl;

	if (!value) {
		printk("ux_acl_from_disk: 2");
		return NULL;
	}
	
	value = (char *)value;
	printk("ux_acl_from_disk: 3, size: %d", size);
	count = ux_acl_count(size);
	printk("ux_acl_from_disk: 4, count: %d", count);
	if (count < 0) {
		printk("ux_acl_from_disk: 5");
		return ERR_PTR(-EINVAL);
	}

	if (count == 0) {
		printk("ux_acl_from_disk: 6");
		return NULL;
	}

	printk("ux_acl_from_disk: 7");
	acl = posix_acl_alloc(count, GFP_KERNEL);
	printk("ux_acl_from_disk: 8");
	if (!acl) {
		printk("ux_acl_from_disk: 9");
		return ERR_PTR(-ENOMEM);
	}

	for (n=0; n < count; n++) {
		printk("ux_acl_from_disk: 10-%d", n);
		struct posix_acl_entry *entry = (struct posix_acl_entry *)value;
		printk("ux_acl_from_disk: 11-%d", n);
		if ((char *)value + sizeof(struct posix_acl_entry) > end) {
			printk("ux_acl_from_disk: 12-%d", n);
			goto fail;
		}
		acl->a_entries[n].e_tag  = entry->e_tag;
		printk("ux_acl_from_disk: 13-%d", n);
		acl->a_entries[n].e_perm = entry->e_perm;
		printk("ux_acl_from_disk: 14-%d", n);
		switch(acl->a_entries[n].e_tag) {
			case ACL_USER_OBJ:
			case ACL_GROUP_OBJ:
			case ACL_MASK:
			case ACL_OTHER:
				printk("ux_acl_from_disk: 15-%d", n);
				value = (char *)value +
					sizeof(struct posix_acl_entry);
				break;

			case ACL_USER:
				printk("ux_acl_from_disk: 16-%d", n);
				value = (char *)value + sizeof(struct posix_acl_entry);
				if ((char *)value > end) {
					printk("ux_acl_from_disk: 17-%d", n);
					goto fail;
				}

				acl->a_entries[n].e_uid = entry->e_uid;
				printk("ux_acl_from_disk: 18-%d", n);
				break;
			case ACL_GROUP:
				printk("ux_acl_from_disk: 19-%d", n);
				value = (char *)value + sizeof(struct posix_acl_entry);
				if ((char *)value > end) {
					printk("ux_acl_from_disk: 20-%d", n);
					goto fail;
				}

				printk("ux_acl_from_disk: 21-%d", n);
				acl->a_entries[n].e_gid = entry->e_gid;
				printk("ux_acl_from_disk: 22-%d", n);
				break;

			default:
				goto fail;
		}
	}

	if (value != end) {
		printk("ux_acl_from_disk: 23");
		goto fail;
	}

	printk("ux_acl_from_disk: 24");
	return acl;

fail:
	printk("ux_acl_from_disk: 25");
	posix_acl_release(acl);
	return ERR_PTR(-EINVAL);
}

/*
 * Convert from in-memory to filesystem representation.
 */
void* ux_acl_to_disk(const struct posix_acl *acl, int *size)
{
	printk("ux_acl_to_disk: 1");
	char *acl_entries;
	size_t n;

	printk("ux_acl_to_disk: 2 count: %d", acl->a_count);
	*size = ux_acl_size(acl->a_count);
	printk("ux_acl_to_disk: 3, size: %d", *size);
	acl_entries = kmalloc(*size, GFP_KERNEL);
	printk("ux_acl_to_disk: 4");

	for (n=0; n < acl->a_count; n++) {
		printk("ux_acl_to_disk: 5-%d", n);
		const struct posix_acl_entry *acl_e = &acl->a_entries[n];
		printk("ux_acl_to_disk: 6-%d", n);
		struct posix_acl_entry *entry = (struct posix_acl_entry *)acl_entries;
		entry->e_tag = acl_e->e_tag;
		entry->e_perm = acl_e->e_perm;
		switch(acl_e->e_tag) {
			case ACL_USER:
				entry->e_uid = acl_e->e_uid;
				acl_entries += sizeof(struct posix_acl_entry);
				break;
			case ACL_GROUP:
				entry->e_gid = acl_e->e_gid;
				acl_entries += sizeof(struct posix_acl_entry);
				break;

			case ACL_USER_OBJ:
			case ACL_GROUP_OBJ:
			case ACL_MASK:
			case ACL_OTHER:
				acl_entries += sizeof(struct posix_acl_entry);
				break;

			default:
				goto fail;
		}
	}
	return acl_entries;

fail:
	printk("ux_acl_to_disk: 7");
	kfree(acl_entries);
	return ERR_PTR(-EINVAL);
}

struct posix_acl* ux_get_acl(struct inode *inode, int type)
{
	printk("ux_get_acl: 1");
	switch (type) {
	case ACL_TYPE_ACCESS:
		printk("ux_get_acl: 2, count: %d", inode->i_acl->a_count);
		return inode->i_acl;
		break;
	case ACL_TYPE_DEFAULT:
		printk("ux_get_acl: 3, count: %d", inode->i_default_acl->a_count);
		return inode->i_default_acl;
		break;
	default:
		printk("ux_get_acl: 4");
		BUG();
	}
}

static int __ux_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
	printk("__ux_set_acl: 1");
	struct ux_inode* uip = (struct ux_inode*)inode->i_private;

	printk("__ux_set_acl: 2");
	switch(type) {
		case ACL_TYPE_ACCESS:
			printk("__ux_set_acl: 3, count: %d", acl->a_count);
			inode->i_acl = acl;
			printk("__ux_set_acl: 4");
			break;

		case ACL_TYPE_DEFAULT:
			printk("__ux_set_acl: 5, count: %d", acl->a_count);
			if (!S_ISDIR(inode->i_mode)) {
				printk("__ux_set_acl: 6");
				return acl ? -EACCES : 0;
			}

			printk("__ux_set_acl: 7");
			inode->i_default_acl = acl;
			break;

		default:
			printk("__ux_set_acl: 8");
			return -EINVAL;
	}

	printk("__ux_set_acl: 9");
	set_cached_acl(inode, type, acl);
	printk("__ux_set_acl: 10");
	return 0;
}

int ux_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
	int error;
	int update_mode = 0;
	printk("ux_set_acl: 1");
	umode_t mode = inode->i_mode;

	printk("ux_set_acl: 2");
	if (type == ACL_TYPE_ACCESS && acl) {
		printk("ux_set_acl: 3, mode: %u, count: %d", mode, acl->a_count);
		error = posix_acl_update_mode(inode, &mode, &acl);
		printk("ux_set_acl: 4, mode: %u, count: %d", mode, acl->a_count);
		if (error) {
			printk("ux_set_acl: 5");
			return error;
		}

		printk("ux_set_acl: 6");
		update_mode = 1;
	}

	printk("ux_set_acl: 7");
	error = __ux_set_acl(inode, acl, type);
	printk("ux_set_acl: 8");
	if (!error && update_mode) {
		printk("ux_set_acl: 9, update_mode: %u", update_mode);
		inode->i_mode = mode;
		printk("ux_set_acl: 10");
		inode->i_ctime = current_time(inode);
		printk("ux_set_acl: 11");
		mark_inode_dirty(inode);
		printk("ux_set_acl: 12");
	}

	printk("ux_set_acl: 13");
	return error;
}

/*
 * Clone an ACL.
 */
static struct posix_acl * ux_acl_clone(const struct posix_acl *acl, gfp_t flags)
{
	struct posix_acl *clone = NULL;

	if (acl) {
		int size = ux_acl_size(acl->a_count);
		struct posix_acl_entry *pa, *pe;
		printk("size = %d", size);
		printk("count = %d", acl->a_count);
		FOREACH_ACL_ENTRY(pa, acl, pe) {
			printk("{e_gid: %u, e_uid: %u, e_perm: %u, e_tag: %d}", pa->e_gid, pa->e_uid, pa->e_perm, pa->e_tag);
			break;
		}
		clone = kmemdup(acl, size, flags);
		if (clone)
			refcount_set(&clone->a_refcount, 1);
	}
	return clone;
}

static int ux_acl_create_masq(struct posix_acl *acl, umode_t *mode_p)
{
	struct posix_acl_entry *pa, *pe;
	struct posix_acl_entry *group_obj = NULL, *mask_obj = NULL;
	umode_t mode = *mode_p;
	int not_equiv = 0;

	/* assert(atomic_read(acl->a_refcount) == 1); */

	FOREACH_ACL_ENTRY(pa, acl, pe) {
                switch(pa->e_tag) {
                        case ACL_USER_OBJ:
				pa->e_perm &= (mode >> 6) | ~S_IRWXO;
				mode &= (pa->e_perm << 6) | ~S_IRWXU;
				break;

			case ACL_USER:
			case ACL_GROUP:
				not_equiv = 1;
				break;

                        case ACL_GROUP_OBJ:
				group_obj = pa;
                                break;

                        case ACL_OTHER:
				pa->e_perm &= mode | ~S_IRWXO;
				mode &= pa->e_perm | ~S_IRWXO;
                                break;

                        case ACL_MASK:
				mask_obj = pa;
				not_equiv = 1;
                                break;

			default:
				return -EIO;
                }
        }

	if (mask_obj) {
		mask_obj->e_perm &= (mode >> 3) | ~S_IRWXO;
		mode &= (mask_obj->e_perm << 3) | ~S_IRWXG;
	} else {
		if (!group_obj)
			return -EIO;
		group_obj->e_perm &= (mode >> 3) | ~S_IRWXO;
		mode &= (group_obj->e_perm << 3) | ~S_IRWXG;
	}

	*mode_p = (*mode_p & ~S_IRWXUGO) | mode;
        return not_equiv;
}

int ux_acl_create(struct inode *dir, umode_t *mode,
		struct posix_acl **default_acl, struct posix_acl **acl)
{
	struct posix_acl *p;
	struct posix_acl *clone;
	int ret;

	*acl = NULL;
	*default_acl = NULL;

	if (S_ISLNK(*mode) || !IS_POSIXACL(dir))
		return 0;

	p = get_acl(dir, ACL_TYPE_DEFAULT);
	if (!p || p == ERR_PTR(-EOPNOTSUPP)) {
		*mode &= ~current_umask();
		return 0;
	}
	if (IS_ERR(p))
		return PTR_ERR(p);

	ret = -ENOMEM;
	clone = ux_acl_clone(p, GFP_NOFS);
	if (!clone)
		goto err_release;

	ret = ux_acl_create_masq(clone, mode);
	if (ret < 0)
		goto err_release_clone;

	if (ret == 0)
		posix_acl_release(clone);
	else
		*acl = clone;

	if (!S_ISDIR(*mode))
		posix_acl_release(p);
	else
		*default_acl = p;

	return 0;

err_release_clone:
	posix_acl_release(clone);
err_release:
	posix_acl_release(p);
	return ret;
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
	error = ux_acl_create(dir, &inode->i_mode, &default_acl, &acl);
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
		error = __ux_set_acl(inode, default_acl, ACL_TYPE_DEFAULT);
		printk("ux_init_acl: 6");
		posix_acl_release(default_acl);
	}

	printk("ux_init_acl: 7");
	if (acl) {
		printk("ux_init_acl: 8");
		if (!error) {
			printk("ux_init_acl: 9");
			error = __ux_set_acl(inode, acl, ACL_TYPE_ACCESS);
			printk("ux_init_acl: 10");
		}
		printk("ux_init_acl: 11");
		posix_acl_release(acl);
		printk("ux_init_acl: 12");
	}

	printk("ux_init_acl: 13");
	return error;
}