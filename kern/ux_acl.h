#include <linux/posix_acl_xattr.h>

typedef struct {
	__le16		e_tag;
	__le16		e_perm;
	__le32		e_id;
} ux_acl_entry;

typedef struct {
	__le16		e_tag;
	__le16		e_perm;
} ux_acl_entry_short;

static size_t ux_acl_size(int count)
{
	if (count <= 4) {
		return count * sizeof(ux_acl_entry_short);
	} else {
		return 4 * sizeof(ux_acl_entry_short) +
		       (count - 4) * sizeof(ux_acl_entry);
	}
}

static int ux_acl_count(size_t size)
{
	ssize_t s;
	s = size - 4 * sizeof(ux_acl_entry_short);
	if (s < 0) {
		if (size % sizeof(ux_acl_entry_short))
			return -1;
		return size / sizeof(ux_acl_entry_short);
	} else {
		if (s % sizeof(ux_acl_entry))
			return -1;
		return s / sizeof(ux_acl_entry) + 4;
	}
}

extern struct posix_acl* ux_acl_from_disk(const void *value, size_t size);
extern void* ux_acl_to_disk(const struct posix_acl *acl, size_t *size);
extern struct posix_acl *ux_get_acl(struct inode *inode, int type);
extern int ux_set_acl(struct inode *inode, struct posix_acl *acl, int type);
extern int ux_init_acl (struct inode *, struct inode *);
