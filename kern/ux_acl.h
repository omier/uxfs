#include <linux/posix_acl.h>
#include <linux/posix_acl_xattr.h>

extern struct posix_acl *ux_get_acl(struct inode *inode, int type);
extern int ux_set_acl(struct inode *inode, struct posix_acl *acl, int type);
extern int ux_init_acl(struct inode *, struct inode *);
