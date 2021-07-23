#include <linux/xattr.h>
#include <linux/posix_acl.h>
#include <linux/posix_acl_xattr.h>

/* Magic value in attribute blocks */
#define UX_XATTR_MAGIC		0xEA020000

/* Name indexes */
#define UX_XATTR_INDEX_POSIX_ACL_ACCESS		1
#define UX_XATTR_INDEX_POSIX_ACL_DEFAULT	2

#define UX_XATTR_PAD_BITS		2
#define UX_XATTR_PAD		(1<<UX_XATTR_PAD_BITS)
#define UX_XATTR_ROUND		(UX_XATTR_PAD-1)
#define UX_XATTR_LEN(name_len) \
	(((name_len) + UX_XATTR_ROUND + \
	sizeof(struct ux_xattr_entry)) & ~UX_XATTR_ROUND)
#define UX_XATTR_NEXT(entry) \
	( (struct ux_xattr_entry *)( \
	  (char *)(entry) + UX_XATTR_LEN((entry)->e_name_len)) )
#define UX_XATTR_SIZE(size) \
	(((size) + UX_XATTR_ROUND) & ~UX_XATTR_ROUND)


extern const struct xattr_handler ux_xattr_user_handler;
extern const struct xattr_handler *ux_xattr_handlers[];

extern ssize_t ux_listxattr(struct dentry *, char *, size_t);
extern int ux_xattr_get(struct inode *, int, const char *, void *, size_t);
extern int ux_xattr_set(struct inode *, int, const char *, const void *, size_t, int);
