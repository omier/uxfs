/*--------------------------------------------------------------*/
/*---------------------------- ux_fs.h -------------------------*/
/*--------------------------------------------------------------*/

extern const struct address_space_operations ux_aops;
extern const struct inode_operations ux_file_inops;
extern const struct inode_operations ux_dir_inops;
extern const struct file_operations ux_dir_operations;
extern const struct file_operations ux_file_operations;


#define UX_NAMELEN              28        
#define UX_DIRS_PER_BLOCK       16
#define UX_DIRECT_BLOCKS        16
#define UX_MAXFILES             32
#define UX_MAXBLOCKS            470
#define UX_FIRST_DATA_BLOCK     50
#define UX_BSIZE                512
#define UX_BSIZE_BITS           9
#define UX_MAGIC                0x58494e55
#define UX_INODE_BLOCK          8
#define UX_ROOT_INO             2

/*
 * The on-disk superblock. The number of inodes and 
 * data blocks is fixed.
 */

struct ux_superblock {
        __u32        s_magic;
        __u32        s_mod;
        __u32        s_nifree;
        __u32        s_inode[UX_MAXFILES];
        __u32        s_nbfree;
        __u32        s_block[UX_MAXBLOCKS];
};

/*
 * The on-disk inode.
 */

struct ux_inode {
        __u32        i_mode;
        __u32        i_nlink;
        __u32        i_atime;
        __u32        i_mtime;
        __u32        i_ctime;
        __s32        i_uid;
        __s32        i_gid;
        __u32        i_size;
        __u32        i_blocks;
        __u32        i_addr[UX_DIRECT_BLOCKS];
};

/*
 * file system inode data in memory.
 */
struct ux_inode_info {
	__le32	i_data[15];
	__u32	i_file_acl;
	__u32	i_dir_acl;

#ifdef __KERNEL__
	/*
	 * Extended attributes can be read independently of the main file
	 * data. Taking i_mutex even when reading would cause contention
	 * between readers of EAs and writers of regular file data, so
	 * instead we synchronize on xattr_sem when reading or changing
	 * EAs.
	 */
	struct rw_semaphore xattr_sem;
	// rwlock_t i_meta_lock;

	struct inode	vfs_inode;
#endif
	// struct list_head i_orphan;	/* unlinked but open inodes */
};

/*
 * Allocation flags
 */

#define UX_INODE_FREE     0
#define UX_INODE_INUSE    1
#define UX_BLOCK_FREE     0
#define UX_BLOCK_INUSE    1

/*
 * Filesystem flags
 */

#define UX_FSCLEAN        0
#define UX_FSDIRTY        1

/*
 * FIxed size directory entry.
 */

struct ux_dirent {
        __u32       d_ino;
        char        d_name[UX_NAMELEN];
};

/*
 * Used to hold filesystem information in-core permanently.
 */

struct ux_fs {
        struct ux_superblock      *u_sb;
        struct buffer_head        *u_sbh;
};

#ifdef __KERNEL__

static inline struct ux_inode_info *UX_I(struct inode *inode)
{
        return container_of(inode, struct ux_inode_info, vfs_inode);
}

extern ino_t ux_inode_alloc(struct super_block *);
extern __u32 ux_data_alloc(struct super_block *);

extern int ux_find_entry(struct inode *, char *);
extern int ux_unlink(struct inode *, struct dentry *);
extern int ux_link(struct dentry *, struct inode *, 
                   struct dentry *);

extern struct inode* ux_iget(struct super_block*, unsigned long);
extern void ux_write_super(struct super_block *sb);

#endif
