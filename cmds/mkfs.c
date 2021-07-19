/*--------------------------------------------------------------*/
/*---------------------------- mkfs.c --------------------------*/
/*--------------------------------------------------------------*/

#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <time.h>
#include <linux/fs.h>
#include <linux/xattr.h>
#include <linux/posix_acl.h>
#include <linux/posix_acl_xattr.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include "../kern/ux_fs.h"
#include "../kern/ux_acl.h"

// /*
//  * Allocate a new ACL with the specified number of entries.
//  */
// struct posix_acl* ux_posix_acl_alloc(int count)
// {
// 	const size_t size = sizeof(struct posix_acl) + count * sizeof(struct posix_acl_entry);
// 	struct posix_acl *acl = malloc(size);
// 	if (acl) {
// 		atomic_set(&acl->a_refcount, 1);
// 	        acl->a_count = count;
//         }
// 	return acl;
// }

// /*
//  * Create an ACL representing the file mode permission bits of an inode.
//  */
// struct posix_acl* ux_posix_acl_from_mode(unsigned short mode)
// {
// 	struct posix_acl *acl = ux_posix_acl_alloc(3);
// 	if (!acl) {
// 	   return NULL;
//         }

// 	acl->a_entries[0].e_tag  = ACL_USER_OBJ;
// 	acl->a_entries[0].e_perm = (mode & S_IRWXU) >> 6;

// 	acl->a_entries[1].e_tag  = ACL_GROUP_OBJ;
// 	acl->a_entries[1].e_perm = (mode & S_IRWXG) >> 3;

// 	acl->a_entries[2].e_tag  = ACL_OTHER;
// 	acl->a_entries[2].e_perm = (mode & S_IRWXO);
// 	return acl;
// }

int main(int argc, char **argv)
{
        struct ux_dirent        dir;
        struct ux_superblock    sb;
        struct ux_inode         inode;
        time_t                  tm;
        off_t                   nsectors = UX_MAXBLOCKS;
        int                     devfd, error, i;
        int                     map_blks;
        char                    block[UX_BSIZE];
        struct posix_acl* acl;
        size_t acl_size;
        void* acl_in_fs;

        if (argc != 2) {
                fprintf(stderr, "uxmkfs: Need to specify device\n");
                exit(1);
        }
        devfd = open(argv[1], O_WRONLY);
        if (devfd < 0) {
                fprintf(stderr, "uxmkfs: Failed to open device\n");
                exit(1);
        }
        error = lseek(devfd, (off_t)(nsectors * 512), SEEK_SET);
        if (error == -1) {
                fprintf(stderr, "uxmkfs: Cannot create filesystem"
                        " of specified size\n");
                exit(1);
        }
        lseek(devfd, 0, SEEK_SET);

        /*
         * Fill in the fields of the superblock and write
         * it out to the first block of the device.
         */

        sb.s_magic = UX_MAGIC;
        sb.s_mod = UX_FSCLEAN;
        sb.s_nifree = UX_MAXFILES - 4;  
        sb.s_nbfree = UX_MAXBLOCKS - 2;

        /*
         * First 4 inodes are in use. Inodes 0 and 1 are not
         * used by anything, 2 is the root directory and 3 is
         * lost+found.
         */

        sb.s_inode[0]  = UX_INODE_INUSE;
        sb.s_inode[1]  = UX_INODE_INUSE;
        sb.s_inode[2]  = UX_INODE_INUSE;
        sb.s_inode[3]  = UX_INODE_INUSE;

        /*
         * The rest of the inodes are marked unused
         */

        for (i = 4 ; i < UX_MAXFILES ; i++) {
                sb.s_inode[i] = UX_INODE_FREE;
        }

        /*
         * The first two blocks are allocated for the entries
         * for the root and lost+found directories.
         */

        sb.s_block[0] = UX_BLOCK_INUSE;
        sb.s_block[1] = UX_BLOCK_INUSE;
        // sb.s_block[2] = UX_BLOCK_INUSE;
        // sb.s_block[3] = UX_BLOCK_INUSE;

        /*
         * The rest of the blocks are marked unused
         */

        for (i = 2 ; i < UX_MAXBLOCKS ; i++) {
                sb.s_block[i] = UX_BLOCK_FREE;
        }

        write(devfd, (char *)&sb, sizeof(struct ux_superblock));

        /*
         * The root directory and lost+found directory inodes
         * must be initialized.
         */

        time(&tm);
        memset((void *)&inode, 0, sizeof(struct ux_inode));
        inode.i_mode = S_IFDIR | 0755;
        inode.i_nlink = 3;        /* ".", ".." and "lost+found" */
        inode.i_atime = tm;
        inode.i_mtime = tm;
        inode.i_ctime = tm;
        inode.i_uid = 0;
        inode.i_gid = 0;
        inode.i_size = UX_BSIZE;
        inode.i_blocks = 1;
        inode.i_addr[0] = UX_FIRST_DATA_BLOCK;
        // inode.i_acl_blk_addr = inode.i_addr[0] + 1;
        // acl = ux_posix_acl_from_mode(inode.i_mode);
        // acl_in_fs = ux_acl_to_disk(acl, &inode.i_default_acl_size);

        lseek(devfd, UX_INODE_BLOCK * UX_BSIZE + 1024, SEEK_SET);
        write(devfd, (char *)&inode, sizeof(struct ux_inode));
        // lseek(devfd, inode.i_acl_blk_addr * UX_BSIZE + UX_DEFAULT_ACL_OFFSET, SEEK_SET);
        // write(devfd, (char *)acl_in_fs, inode.i_default_acl_size);

        memset((void *)&inode, 0 , sizeof(struct ux_inode));
        inode.i_mode = S_IFDIR | 0755;
        inode.i_nlink = 2;        /* "." and ".." */
        inode.i_atime = tm;
        inode.i_mtime = tm;
        inode.i_ctime = tm;
        inode.i_uid = 0;
        inode.i_gid = 0;
        inode.i_size = UX_BSIZE;
        inode.i_blocks = 1;
        inode.i_addr[0] = UX_FIRST_DATA_BLOCK + 1;
        // inode.i_acl_blk_addr = inode.i_addr[0] + 1;
        // acl = ux_posix_acl_from_mode(inode.i_mode);
        // acl_in_fs = ux_acl_to_disk(acl, &inode.i_access_acl_size);
        

        lseek(devfd, UX_INODE_BLOCK * UX_BSIZE + 1536, SEEK_SET);
        write(devfd, (char *)&inode, sizeof(struct ux_inode));
        // lseek(devfd, inode.i_acl_blk_addr * UX_BSIZE + UX_ACCESS_ACL_OFFSET, SEEK_SET);
        // write(devfd, (char *)acl_in_fs, inode.i_access_acl_size);

        /*
         * Fill in the directory entries for root 
         */

        lseek(devfd, UX_FIRST_DATA_BLOCK * UX_BSIZE, SEEK_SET);
        memset((void *)&block, 0, UX_BSIZE);
        write(devfd, block, UX_BSIZE);
        lseek(devfd, UX_FIRST_DATA_BLOCK * UX_BSIZE, SEEK_SET);
        dir.d_ino = 2;
        strcpy(dir.d_name, ".");
        write(devfd, (char *)&dir, sizeof(struct ux_dirent));
        dir.d_ino = 2;
        strcpy(dir.d_name, "..");
        write(devfd, (char *)&dir, sizeof(struct ux_dirent));
        dir.d_ino = 3;
        strcpy(dir.d_name, "lost+found");
        write(devfd, (char *)&dir, sizeof(struct ux_dirent));

        /*
         * Fill in the directory entries for lost+found 
         */

        lseek(devfd, UX_FIRST_DATA_BLOCK * UX_BSIZE + UX_BSIZE,
              SEEK_SET);
        memset((void *)&block, 0, UX_BSIZE);
        write(devfd, block, UX_BSIZE);
        lseek(devfd, UX_FIRST_DATA_BLOCK * UX_BSIZE + UX_BSIZE, 
              SEEK_SET);
        dir.d_ino = 2;
        strcpy(dir.d_name, ".");
        write(devfd, (char *)&dir, sizeof(struct ux_dirent));
        dir.d_ino = 2;
        strcpy(dir.d_name, "..");
        write(devfd, (char *)&dir, sizeof(struct ux_dirent));
}

