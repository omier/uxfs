#include <linux/buffer_head.h>
#include <linux/posix_acl_xattr.h>
#include "ux_xattr.h"
#include "ux_fs.h"

static const struct xattr_handler *ux_xattr_handler_map[] = {
	[UX_XATTR_INDEX_POSIX_ACL_ACCESS]  = &posix_acl_access_xattr_handler,
	[UX_XATTR_INDEX_POSIX_ACL_DEFAULT] = &posix_acl_default_xattr_handler,
};

const struct xattr_handler *ux_xattr_handlers[] = {
	&posix_acl_access_xattr_handler,
	&posix_acl_default_xattr_handler,
	NULL
};

static inline const struct xattr_handler *
ux_xattr_handler(int name_index)
{
	const struct xattr_handler *handler = NULL;

	if (name_index > 0 && name_index < ARRAY_SIZE(ux_xattr_handler_map))
		handler = ux_xattr_handler_map[name_index];
	return handler;
}

int ux_simple_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
	int error;

	if (type == ACL_TYPE_ACCESS) {
		error = posix_acl_update_mode(inode,
				&inode->i_mode, &acl);
		if (error)
			return error;
	}

	inode->i_ctime = current_time(inode);
	set_cached_acl(inode, type, acl);
	return 0;
}
