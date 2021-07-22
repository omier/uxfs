#include <linux/posix_acl.h>
#include <linux/posix_acl_xattr.h>

#define ux_acl_size(count) sizeof(struct posix_acl) + count * sizeof(struct posix_acl_entry)
#define ux_acl_count(size) (size - sizeof(struct posix_acl)) / sizeof(struct posix_acl_entry)

extern struct posix_acl *ux_acl_from_disk(const void *value, int size);
extern void *ux_acl_to_disk(const struct posix_acl *acl, int *size);
extern struct posix_acl *ux_get_acl(struct inode *inode, int type);
extern int ux_set_acl(struct inode *inode, struct posix_acl *acl, int type);
extern int ux_init_acl(struct inode *, struct inode *);
