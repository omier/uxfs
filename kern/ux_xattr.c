#include <linux/buffer_head.h>
#include <linux/posix_acl_xattr.h>
#include "ux_xattr.h"
#include "ux_fs.h"


#define HDR(bh) ((struct ux_xattr_header *)((bh)->b_data))
#define ENTRY(ptr) ((struct ux_xattr_entry *)(ptr))
#define FIRST_ENTRY(bh) ENTRY(HDR(bh)+1)
#define IS_LAST_ENTRY(entry) (*(__u32 *)(entry) == 0)


static int ux_xattr_set2(struct inode *, struct buffer_head *,
			   struct ux_xattr_header *);

static void ux_xattr_rehash(struct ux_xattr_header *,
			      struct ux_xattr_entry *);

static const struct xattr_handler *ux_xattr_handler_map[] = {
	[UX_XATTR_INDEX_USER]			= &ux_xattr_user_handler,
	[UX_XATTR_INDEX_POSIX_ACL_ACCESS]  = &posix_acl_access_xattr_handler,
	[UX_XATTR_INDEX_POSIX_ACL_DEFAULT] = &posix_acl_default_xattr_handler,
};

static bool
ux_xattr_user_list(struct dentry *dentry)
{
	return true;
}

static int
ux_xattr_user_get(const struct xattr_handler *handler,
		    struct dentry *unused, struct inode *inode,
		    const char *name, void *buffer, size_t size)
{
	return ux_xattr_get(inode, UX_XATTR_INDEX_USER,
			      name, buffer, size);
}

static int
ux_xattr_user_set(const struct xattr_handler *handler,
		    struct dentry *unused, struct inode *inode,
		    const char *name, const void *value,
		    size_t size, int flags)
{
	return ux_xattr_set(inode, UX_XATTR_INDEX_USER,
			      name, value, size, flags);
}

const struct xattr_handler ux_xattr_user_handler = {
	.prefix	= XATTR_USER_PREFIX,
	.list	= ux_xattr_user_list,
	.get	= ux_xattr_user_get,
	.set	= ux_xattr_user_set,
};

const struct xattr_handler *ux_xattr_handlers[] = {
	&ux_xattr_user_handler,
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

static bool
ux_xattr_header_valid(struct ux_xattr_header *header)
{
	if (header->h_magic != cpu_to_le32(UX_XATTR_MAGIC) ||
	    header->h_blocks != cpu_to_le32(1))
		return false;

	return true;
}

static bool
ux_xattr_entry_valid(struct ux_xattr_entry *entry,
		       char *end, size_t end_offs)
{
	struct ux_xattr_entry *next;
	size_t size;

	next = UX_XATTR_NEXT(entry);
	if ((char *)next >= end)
		return false;

	if (entry->e_value_block != 0)
		return false;

	size = le32_to_cpu(entry->e_value_size);
	if (size > end_offs ||
	    le16_to_cpu(entry->e_value_offs) + size > end_offs)
		return false;

	return true;
}

static int
ux_xattr_cmp_entry(int name_index, size_t name_len, const char *name,
		     struct ux_xattr_entry *entry)
{
	int cmp;

	cmp = name_index - entry->e_name_index;
	if (!cmp)
		cmp = name_len - entry->e_name_len;
	if (!cmp)
		cmp = memcmp(name, entry->e_name, name_len);

	return cmp;
}


#define NAME_HASH_SHIFT 5
#define VALUE_HASH_SHIFT 16

/*
 * ux_xattr_hash_entry()
 *
 * Compute the hash of an extended attribute.
 */
static inline void ux_xattr_hash_entry(struct ux_xattr_header *header,
					 struct ux_xattr_entry *entry)
{
	__u32 hash = 0;
	char *name = entry->e_name;
	int n;

	for (n=0; n < entry->e_name_len; n++) {
		hash = (hash << NAME_HASH_SHIFT) ^
		       (hash >> (8*sizeof(hash) - NAME_HASH_SHIFT)) ^
		       *name++;
	}

	if (entry->e_value_block == 0 && entry->e_value_size != 0) {
		__le32 *value = (__le32 *)((char *)header +
			le16_to_cpu(entry->e_value_offs));
		for (n = (le32_to_cpu(entry->e_value_size) +
		     UX_XATTR_ROUND) >> UX_XATTR_PAD_BITS; n; n--) {
			hash = (hash << VALUE_HASH_SHIFT) ^
			       (hash >> (8*sizeof(hash) - VALUE_HASH_SHIFT)) ^
			       le32_to_cpu(*value++);
		}
	}
	entry->e_hash = cpu_to_le32(hash);
}

#undef NAME_HASH_SHIFT
#undef VALUE_HASH_SHIFT

#define BLOCK_HASH_SHIFT 16

/*
 * ux_xattr_rehash()
 *
 * Re-compute the extended attribute hash value after an entry has changed.
 */
static void ux_xattr_rehash(struct ux_xattr_header *header,
			      struct ux_xattr_entry *entry)
{
	struct ux_xattr_entry *here;
	__u32 hash = 0;
	
	ux_xattr_hash_entry(header, entry);
	here = ENTRY(header+1);
	while (!IS_LAST_ENTRY(here)) {
		if (!here->e_hash) {
			/* Block is not shared if an entry's hash value == 0 */
			hash = 0;
			break;
		}
		hash = (hash << BLOCK_HASH_SHIFT) ^
		       (hash >> (8*sizeof(hash) - BLOCK_HASH_SHIFT)) ^
		       le32_to_cpu(here->e_hash);
		here = UX_XATTR_NEXT(here);
	}
	header->h_hash = cpu_to_le32(hash);
}

#undef BLOCK_HASH_SHIFT


ssize_t ux_listxattr(struct dentry *dentry, char *buffer, size_t buffer_size)
{
	struct inode *inode = d_inode(dentry);
	struct buffer_head *bh = NULL;
	struct ux_xattr_entry *entry;
	char *end;
	size_t rest = buffer_size;
	int error;

	down_read(&UX_I(inode)->xattr_sem);
	error = 0;
	if (!UX_I(inode)->i_file_acl)
		goto cleanup;
	bh = sb_bread(inode->i_sb, UX_I(inode)->i_file_acl);
	printk("ux_listxattr: %p", bh);
	error = -EIO;
	if (!bh)
		goto cleanup;
	end = bh->b_data + bh->b_size;
	if (!ux_xattr_header_valid(HDR(bh))) {
bad_block:
		// ext2_error(inode->i_sb, "ext2_xattr_list",
		// 	"inode %ld: bad block %d", inode->i_ino,
		// 	EXT2_I(inode)->i_file_acl);
		printk("ux_listxattr: bad_block header");
		error = -EIO;
		goto cleanup;
	}

	/* check the on-disk data structure */
	entry = FIRST_ENTRY(bh);
	while (!IS_LAST_ENTRY(entry)) {
		if (!ux_xattr_entry_valid(entry, end,
		    inode->i_sb->s_blocksize))
			printk("ux_listxattr: bad_block entry");
			goto bad_block;
		entry = UX_XATTR_NEXT(entry);
	}

	/* list the attribute names */
	for (entry = FIRST_ENTRY(bh); !IS_LAST_ENTRY(entry);
	     entry = UX_XATTR_NEXT(entry)) {
		const struct xattr_handler *handler =
			ux_xattr_handler(entry->e_name_index);

		if (handler && (!handler->list || handler->list(dentry))) {
			const char *prefix = handler->prefix ?: handler->name;
			size_t prefix_len = strlen(prefix);
			size_t size = prefix_len + entry->e_name_len + 1;

			if (buffer) {
				if (size > rest) {
					error = -ERANGE;
					goto cleanup;
				}
				memcpy(buffer, prefix, prefix_len);
				buffer += prefix_len;
				memcpy(buffer, entry->e_name, entry->e_name_len);
				buffer += entry->e_name_len;
				*buffer++ = 0;
			}
			rest -= size;
		}
	}
	error = buffer_size - rest;  /* total size */

cleanup:
	brelse(bh);
	up_read(&UX_I(inode)->xattr_sem);

	return error;
}

int ux_xattr_get(struct inode *inode, int name_index, const char *name, void *buffer, size_t buffer_size)
{
	struct buffer_head *bh = NULL;
	struct ux_xattr_entry *entry;
	size_t name_len, size;
	char *end;
	int error, not_found;

	if (name == NULL)
		return -EINVAL;
	name_len = strlen(name);
	if (name_len > 255)
		return -ERANGE;

	down_read(&UX_I(inode)->xattr_sem);
	error = -ENODATA;
	if (!UX_I(inode)->i_file_acl)
		goto cleanup;
	bh = sb_bread(inode->i_sb, UX_I(inode)->i_file_acl);
	error = -EIO;
	if (!bh)
		goto cleanup;
	
	end = bh->b_data + bh->b_size;
	if (!ux_xattr_header_valid(HDR(bh))) {
bad_block:
		// ext2_error(inode->i_sb, "ext2_xattr_get",
		// 	"inode %ld: bad block %d", inode->i_ino,
		// 	EXT2_I(inode)->i_file_acl);
		error = -EIO;
		goto cleanup;
	}

	/* find named attribute */
	entry = FIRST_ENTRY(bh);
	while (!IS_LAST_ENTRY(entry)) {
		if (!ux_xattr_entry_valid(entry, end,
		    inode->i_sb->s_blocksize))
			goto bad_block;

		not_found = ux_xattr_cmp_entry(name_index, name_len, name,
						 entry);
		if (!not_found)
			goto found;
		if (not_found < 0)
			break;

		entry = UX_XATTR_NEXT(entry);
	}
	error = -ENODATA;
	goto cleanup;
found:
	size = le32_to_cpu(entry->e_value_size);
	if (buffer) {
		error = -ERANGE;
		if (size > buffer_size)
			goto cleanup;
		/* return value of attribute */
		memcpy(buffer, bh->b_data + le16_to_cpu(entry->e_value_offs),
			size);
	}
	error = size;

cleanup:
	brelse(bh);
	up_read(&UX_I(inode)->xattr_sem);

	return error;
}

int ux_xattr_set(struct inode *inode, int name_index, const char *name, const void *value, size_t value_len, int flags)
{
	struct super_block *sb = inode->i_sb;
	struct buffer_head *bh = NULL;
	struct ux_xattr_header *header = NULL;
	struct ux_xattr_entry *here = NULL, *last = NULL;
	size_t name_len, free, min_offs = sb->s_blocksize;
	int not_found = 1, error;
	char *end;


	if (value == NULL)
		value_len = 0;
	if (name == NULL)
		return -EINVAL;
	name_len = strlen(name);
	if (name_len > 255 || value_len > sb->s_blocksize)
		return -ERANGE;

	down_write(&UX_I(inode)->xattr_sem);
	if (UX_I(inode)->i_file_acl) {
		/* The inode already has an extended attribute block. */
		bh = sb_bread(sb, UX_I(inode)->i_file_acl);
		error = -EIO;
		if (!bh)
			goto cleanup;
		header = HDR(bh);
		end = bh->b_data + bh->b_size;
		if (!ux_xattr_header_valid(header)) {
bad_block:
			// ext2_error(sb, "ux_xattr_set",
			// 	"inode %ld: bad block %d", inode->i_ino, 
			// 	   UX_I(inode)->i_file_acl);
			error = -EIO;
			goto cleanup;
		}
		/*
		 * Find the named attribute. If not found, 'here' will point
		 * to entry where the new attribute should be inserted to
		 * maintain sorting.
		 */
		last = FIRST_ENTRY(bh);
		while (!IS_LAST_ENTRY(last)) {
			if (!ux_xattr_entry_valid(last, end, sb->s_blocksize))
				goto bad_block;
			if (last->e_value_size) {
				size_t offs = le16_to_cpu(last->e_value_offs);
				if (offs < min_offs)
					min_offs = offs;
			}
			if (not_found > 0) {
				not_found = ux_xattr_cmp_entry(name_index,
								 name_len,
								 name, last);
				if (not_found <= 0)
					here = last;
			}
			last = UX_XATTR_NEXT(last);
		}
		if (not_found > 0)
			here = last;

		/* Check whether we have enough space left. */
		free = min_offs - ((char*)last - (char*)header) - sizeof(__u32);
	} else {
		/* We will use a new extended attribute block. */
		free = sb->s_blocksize -
			sizeof(struct ux_xattr_header) - sizeof(__u32);
	}

	if (not_found) {
		/* Request to remove a nonexistent attribute? */
		error = -ENODATA;
		if (flags & XATTR_REPLACE)
			goto cleanup;
		error = 0;
		if (value == NULL)
			goto cleanup;
	} else {
		/* Request to create an existing attribute? */
		error = -EEXIST;
		if (flags & XATTR_CREATE)
			goto cleanup;
		free += UX_XATTR_SIZE(le32_to_cpu(here->e_value_size));
		free += UX_XATTR_LEN(name_len);
	}
	error = -ENOSPC;
	if (free < UX_XATTR_LEN(name_len) + UX_XATTR_SIZE(value_len))
		goto cleanup;

	/* Here we know that we can set the new attribute. */

	if (header) {
		lock_buffer(bh);
		if (header->h_refcount != cpu_to_le32(1)) {
			int offset;

			unlock_buffer(bh);
			header = kmemdup(HDR(bh), bh->b_size, GFP_KERNEL);
			error = -ENOMEM;
			if (header == NULL)
				goto cleanup;
			header->h_refcount = cpu_to_le32(1);

			offset = (char *)here - bh->b_data;
			here = ENTRY((char *)header + offset);
			offset = (char *)last - bh->b_data;
			last = ENTRY((char *)header + offset);
		}
	} else {
		/* Allocate a buffer where we construct the new block. */
		header = kzalloc(sb->s_blocksize, GFP_KERNEL);
		error = -ENOMEM;
		if (header == NULL)
			goto cleanup;
		end = (char *)header + sb->s_blocksize;
		header->h_magic = cpu_to_le32(UX_XATTR_MAGIC);
		header->h_blocks = header->h_refcount = cpu_to_le32(1);
		last = here = ENTRY(header+1);
	}

	/* Iff we are modifying the block in-place, bh is locked here. */

	if (not_found) {
		/* Insert the new name. */
		size_t size = UX_XATTR_LEN(name_len);
		size_t rest = (char *)last - (char *)here;
		memmove((char *)here + size, here, rest);
		memset(here, 0, size);
		here->e_name_index = name_index;
		here->e_name_len = name_len;
		memcpy(here->e_name, name, name_len);
	} else {
		if (here->e_value_size) {
			char *first_val = (char *)header + min_offs;
			size_t offs = le16_to_cpu(here->e_value_offs);
			char *val = (char *)header + offs;
			size_t size = UX_XATTR_SIZE(
				le32_to_cpu(here->e_value_size));

			if (size == UX_XATTR_SIZE(value_len)) {
				/* The old and the new value have the same
				   size. Just replace. */
				here->e_value_size = cpu_to_le32(value_len);
				memset(val + size - UX_XATTR_PAD, 0,
				       UX_XATTR_PAD); /* Clear pad bytes. */
				memcpy(val, value, value_len);
				goto skip_replace;
			}

			/* Remove the old value. */
			memmove(first_val + size, first_val, val - first_val);
			memset(first_val, 0, size);
			min_offs += size;

			/* Adjust all value offsets. */
			last = ENTRY(header+1);
			while (!IS_LAST_ENTRY(last)) {
				size_t o = le16_to_cpu(last->e_value_offs);
				if (o < offs)
					last->e_value_offs =
						cpu_to_le16(o + size);
				last = UX_XATTR_NEXT(last);
			}

			here->e_value_offs = 0;
		}
		if (value == NULL) {
			/* Remove the old name. */
			size_t size = UX_XATTR_LEN(name_len);
			last = ENTRY((char *)last - size);
			memmove(here, (char*)here + size,
				(char*)last - (char*)here);
			memset(last, 0, size);
		}
	}

	if (value != NULL) {
		/* Insert the new value. */
		here->e_value_size = cpu_to_le32(value_len);
		if (value_len) {
			size_t size = UX_XATTR_SIZE(value_len);
			char *val = (char *)header + min_offs - size;
			here->e_value_offs =
				cpu_to_le16((char *)val - (char *)header);
			memset(val + size - UX_XATTR_PAD, 0,
			       UX_XATTR_PAD); /* Clear the pad bytes. */
			memcpy(val, value, value_len);
		}
	}

skip_replace:
	if (IS_LAST_ENTRY(ENTRY(header+1))) {
		/* This block is now empty. */
		if (bh && header == HDR(bh))
			unlock_buffer(bh);  /* we were modifying in-place. */
		error = ux_xattr_set2(inode, bh, NULL);
	} else {
		ux_xattr_rehash(header, here);
		if (bh && header == HDR(bh))
			unlock_buffer(bh);  /* we were modifying in-place. */
		error = ux_xattr_set2(inode, bh, header);
	}

cleanup:
	if (!(bh && header == HDR(bh)))
		kfree(header);
	brelse(bh);
	up_write(&UX_I(inode)->xattr_sem);

	return error;
}

/*
 * Second half of ux_xattr_set(): Update the file system.
 */
static int
ux_xattr_set2(struct inode *inode, struct buffer_head *old_bh,
		struct ux_xattr_header *header)
{
	struct super_block *sb = inode->i_sb;
	struct buffer_head *new_bh = NULL;
	int error = 0;

	if (header) {
		if (old_bh && header == HDR(old_bh)) {
			/* Keep this block. No need to lock the block as we
			   don't need to change the reference count. */
			new_bh = old_bh;
			get_bh(new_bh);
		} else {
			/* We need to allocate a new block */
			__u32 blk = ux_data_alloc(sb);
			if (!blk)
				goto cleanup;
			
			new_bh = sb_getblk(sb, blk);
			if (unlikely(!new_bh)) {
				mark_inode_dirty(inode);
				error = -ENOMEM;
				goto cleanup;
			}
			lock_buffer(new_bh);
			memcpy(new_bh->b_data, header, new_bh->b_size);
			set_buffer_uptodate(new_bh);
			unlock_buffer(new_bh);			
		}
		mark_buffer_dirty(new_bh);
		if (IS_SYNC(inode)) {
			sync_dirty_buffer(new_bh);
			error = -EIO;
			if (buffer_req(new_bh) && !buffer_uptodate(new_bh))
				goto cleanup;
		}
	}

	/* Update the inode. */
	UX_I(inode)->i_file_acl = new_bh ? new_bh->b_blocknr : 0;
	inode->i_ctime = current_time(inode);
	if (IS_SYNC(inode)) {
		error = sync_inode_metadata(inode, 1);
		/* In case sync failed due to ENOSPC the inode was actually
		 * written (only some dirty data were not) so we just proceed
		 * as if nothing happened and cleanup the unused block */
		if (error && error != -ENOSPC) {
			if (new_bh && new_bh != old_bh) {
				mark_inode_dirty(inode);
			}
			goto cleanup;
		}
	} else
		mark_inode_dirty(inode);

	error = 0;
	if (old_bh && old_bh != new_bh) {
		/*
		 * If there was an old block and we are no longer using it,
		 * release the old block.
		 */
		lock_buffer(old_bh);
		if (HDR(old_bh)->h_refcount == cpu_to_le32(1)) {
			mark_inode_dirty(inode);
			/* We let our caller release old_bh, so we
			 * need to duplicate the buffer before. */
			get_bh(old_bh);
			bforget(old_bh);
		} else {
			/* Decrement the refcount only. */
			le32_add_cpu(&HDR(old_bh)->h_refcount, -1);
			mark_inode_dirty(inode);
			mark_buffer_dirty(old_bh);
		}
		unlock_buffer(old_bh);
	}

cleanup:
	brelse(new_bh);

	return error;
}