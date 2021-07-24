#include <linux/xattr.h>
#include <linux/posix_acl.h>
#include <linux/posix_acl_xattr.h>

/* Name indexes */
#define UX_XATTR_INDEX_POSIX_ACL_ACCESS		1
#define UX_XATTR_INDEX_POSIX_ACL_DEFAULT	2

extern const struct xattr_handler ux_xattr_user_handler;
extern const struct xattr_handler *ux_xattr_handlers[];

extern ssize_t ux_listxattr(struct dentry *, char *, size_t);
extern int ux_xattr_get(struct inode *, int, const char *, void *, size_t);
extern int ux_xattr_set(struct inode *, int, const char *, const void *, size_t, int);
