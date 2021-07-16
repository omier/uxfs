#include <linux/xattr.h>

/* Magic value in attribute blocks */
#define UX_XATTR_MAGIC		0xEA020000

/* Maximum number of references to one attribute block */
#define UX_XATTR_REFCOUNT_MAX		1024

/* Name indexes */
#define UX_XATTR_INDEX_USER					1
#define UX_XATTR_INDEX_POSIX_ACL_ACCESS		2
#define UX_XATTR_INDEX_POSIX_ACL_DEFAULT	3

struct ux_xattr_header {
	__le32	h_magic;	/* magic number for identification */
	__le32	h_refcount;	/* reference count */
	__le32	h_blocks;	/* number of disk blocks used */
	__le32	h_hash;		/* hash value of all attributes */
	__u32	h_reserved[4];	/* zero right now */
};

struct ux_xattr_entry {
	__u8	e_name_len;	/* length of name */
	__u8	e_name_index;	/* attribute name index */
	__le16	e_value_offs;	/* offset in disk block of value */
	__le32	e_value_block;	/* disk block attribute is stored on (n/i) */
	__le32	e_value_size;	/* size of attribute value */
	__le32	e_hash;		/* hash value of name and value */
	char	e_name[];	/* attribute name */
};

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