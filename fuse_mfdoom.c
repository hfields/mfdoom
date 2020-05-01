/*
  Directory sizes are incorrect.

  fuse_mfdoom: a silly filesystem designed to be miserable to use
  Adapted from fuse_stupid.c

  gcc -Wall `pkg-config fuse --cflags --libs` fuse_mfdoom.c -o fuse_mfdoom
*/

#define FUSE_USE_VERSION 26

#include <assert.h>
#include <errno.h>
#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MFDOOM_MAGIC_BIG_ENDIAN 0x6d66646f6f6d2121L
#define MFDOOM_MAGIC_LITTLE_ENDIAN 0x21216d6f6f64666dL

#define BLOCK_SIZE      4096            /* 4kb block size */
#define BLOCKS_PER_FILE 1048576         /* Max file size, in blocks (2^32 bytes) */
#define DISK_SIZE       10510336        /* approx 10mb backing file */

typedef size_t          block_t;        /* Block-address type */

static int              backing_file_fd; /* Fd for all access to backing file */
static gid_t            gid;            /* GID we were invoked under */
static uid_t            uid;            /* UID we were invoked under */
static time_t           mount_time;     /* Time the filesystem was mounted */

static const char       backing_file_name[] = "fat_disk"; /* Fixed name of backing file */

struct sblock {
    unsigned long       magic;          /* Magic number identifying filesys */
    size_t              total_blocks;   /* Total blocks (disk size) */
    size_t              block_size;     /* Size of each block */
    size_t              dir_count;      /* Number of directories */
    size_t              access_count;   /* Total number of file accesses */
    block_t             fat_start;      /* First block of File Allocation Table */
    block_t             files_start;    /* First block of files */
    block_t             free_list;      /* First block of free list */
};

static union {
    struct sblock       s;
    char                pad[BLOCK_SIZE];
}
                        superblock;

#define TABLE_BLOCKS    5              /* Number of blocks in FAT */
#define TABLE_LEN       TABLE_BLOCKS * BLOCK_SIZE / sizeof(block_t) 
                                       /* Length of FAT in block_t's */
static block_t          fat_table[TABLE_LEN];

/*
 * Despite the extra fields, we set DIRENT_LENGTH to 64. NAME_LENGTH
 * must incorporate the sizes of all fields in mfdoom_dirent.  Also
 * note that NAME_LENGTH must be 255 or less, so that the namelen
 * field in dirent can be only one byte.
 */
#define DIRENT_LENGTH   64
#define NAME_LENGTH     (DIRENT_LENGTH - 1 - 1 - 2 * sizeof (size_t))

/*
 * Directory entry.
 */
typedef struct {
    block_t             file_start;     /* Starting block of the file */
    size_t              size;           /* Size of the file */
    unsigned char       type;           /* Entry type (see below) */
    unsigned char       namelen;        /* Length of name */
    char                name[NAME_LENGTH];  /* File name */
    size_t              accesses;       /* Number of times the file has been accessed */
}
                        mfdoom_dirent;

#define DIR_SIZE        (BLOCKS_PER_FILE / sizeof (mfdoom_dirent) * BLOCK_SIZE )
                                        /* Max entries in a directory */

/*
 * Variables for random file moves
 */
#define MOVE_DENOM  4               /* Constant for calculating probability of random move */
unsigned char random_moves = 1;     /* Whether random file moves are allowed */
size_t checked_dirs = 0;            /* Previously considered dirs in random selection */


/*
 * Space for holding a directory block in memory.
 */
static block_t          dirblock = 0;   /* Block represented by dirbuf */
static mfdoom_dirent*   dirbuf;         /* Current directory block buffer */
static mfdoom_dirent*   dirend;         /* End of directory block buffer */

/*
 * File types.  Note that these do *not* match unix types!
 */
#define TYPE_EMPTY      0               /* Empty directory entry MUST BE ZERO */
#define TYPE_DIR        1               /* Subdirectory */
#define TYPE_FILE       2               /* Plain file */

/*
 * Handy macros for converting between block numbers (used in block
 * pointers of type block_t) and byte offsets (used by the Unix I/O
 * interface).  Note that BYTES_TO_BLOCKS rounds *upward* if the
 * offset isn't an exact multiple of the block size.
 */
#define BLOCKS_TO_BYTES(x)      ((x) * superblock.s.block_size)
#define BYTES_TO_BLOCKS(x)      (((x) + superblock.s.block_size - 1) \
                                  / superblock.s.block_size)

/*
 * Macro to convert a byte offset to a byte offset in a file.
 */
#define OFFSET_IN_BLOCK(x)      ((x) % superblock.s.block_size)

/*
 * Macro to find the next block in a linked-list in the FAT
 */
#define NEXT_BLOCK(x)           (fat_table[(x) - superblock.s.files_start])

/*
 * Number of directory entries stored in a block.
 */
#define DIRENTS_PER_BLOCK       (superblock.s.block_size / DIRENT_LENGTH)


/*
 * Read from a given block on the backing file/device.  We always read
 * in one-block units.  Always succeeds; aborts the program on failures.
 */
static void read_block(block_t block, void *buf)
{
    assert(lseek(backing_file_fd, BLOCKS_TO_BYTES(block), SEEK_SET) != -1);
    int read_size = read(backing_file_fd, buf, superblock.s.block_size);
    assert(read_size
      == superblock.s.block_size);
}

/*
 * Write to a given block on the backing file/device.  We always write
 * in one-block units.  Always succeeds; aborts the program on failures.
 */
static void write_block(block_t block, const void *buf)
{
    assert(lseek(backing_file_fd, BLOCKS_TO_BYTES(block), SEEK_SET) != -1);
    int write_size = write(backing_file_fd, buf, superblock.s.block_size);
    assert(write_size
      == superblock.s.block_size);
}

/*
 * Rewrite the superblock.
 */
static void flush_superblock()
{
    write_block(0, &superblock);
}

/*
 * Rewrite the FAT.
 */
static void flush_fat()
{
    // Write each block of the FAT
    for (int i = 0; i < TABLE_BLOCKS; i++) {
        write_block(superblock.s.fat_start + i, 
            fat_table + (BLOCKS_TO_BYTES(i) / sizeof(block_t)));
    }  
}

/*
 * Fetch a directory block.
 */
static void fetch_dirblock(size_t block)
{
    if (dirblock == block)
        return;                         /* Efficiency: no work needed */
    dirblock = block;
    read_block(dirblock, dirbuf);
}

/*
 * Rewrite the current directory block.
 */
static void flush_dirblock()
{
    write_block(dirblock, dirbuf);
}

static void* fuse_mfdoom_init(struct fuse_conn_info *conn)
{
    size_t              sblock_size, fat_size;

    /*
     * Read superblock and FAT, if they exist.  We don't use read_block
     * because if we just created the backing file, the read will fail
     * and we'll need to initialize the backing file.
     */
    assert(lseek(backing_file_fd, 0, SEEK_SET) != -1);
    sblock_size = read(backing_file_fd, &superblock, sizeof superblock);
    fat_size = read(backing_file_fd, &fat_table, BLOCK_SIZE * TABLE_BLOCKS);
    if (sblock_size == sizeof superblock
       && fat_size == BLOCK_SIZE * TABLE_BLOCKS
       &&  superblock.s.magic == MFDOOM_MAGIC_LITTLE_ENDIAN) {
        /*
         * The backing file exists and is valid. Create a buffer for
         * holding directory blocks.  We don't need to fill it.
         */
        dirbuf = (mfdoom_dirent*)calloc(superblock.s.block_size, 1);
        dirend = (mfdoom_dirent*)((char *)dirbuf + superblock.s.block_size);
        return NULL;
    }
    /*
     * The filesystem doesn't exist.  Make it.
     *
     * Create superblock.
     */
    memset(&superblock, 0, sizeof superblock);
    superblock.s.magic = MFDOOM_MAGIC_LITTLE_ENDIAN;
    superblock.s.total_blocks = DISK_SIZE / BLOCK_SIZE;
    superblock.s.block_size = BLOCK_SIZE;
    superblock.s.dir_count = 1;
    superblock.s.access_count = 0;

    /*
     * The FAT starts just past the superblock
     * Create FAT
     */
    superblock.s.fat_start = sizeof(superblock) / superblock.s.block_size;
    memset(&fat_table, 0, BLOCKS_TO_BYTES(TABLE_BLOCKS));

    /*
     * The root directory starts just past the FAT
     */
    superblock.s.files_start = superblock.s.fat_start + TABLE_BLOCKS;

    /*
     * Create an initial root directory and write it to disk.  We
     * depend on the fact that calloc zeros the memory it allocates,
     * and the fact that TYPE_EMPTY is zero.
     */
    dirbuf = (mfdoom_dirent*)calloc(superblock.s.block_size, 1);
    dirend = (mfdoom_dirent*)((char *)dirbuf + superblock.s.block_size);

    dirblock = superblock.s.files_start;
    dirbuf[0].type = TYPE_DIR;
    dirbuf[0].file_start = superblock.s.files_start;
    dirbuf[0].size = DIR_SIZE * DIRENT_LENGTH;
    dirbuf[0].namelen = 1;
    memcpy(dirbuf[0].name, ".", 1);

    dirbuf[1].type = TYPE_DIR;
    dirbuf[1].file_start = superblock.s.files_start;
    dirbuf[1].size = DIR_SIZE * DIRENT_LENGTH;
    dirbuf[1].namelen = 2;
    memcpy(dirbuf[1].name, "..", 2);
    write_block(superblock.s.files_start, dirbuf);

    /*
     * Update the FAT
     * Set each block in FAT to point to the next one
     * Leave the last entry pointing to block 0
     * Update free list
     */

    fat_table[0] = 0;

    for (int i = 1; i < TABLE_LEN - 1; i++) {
        fat_table[i] = superblock.s.files_start + i + 1;
    }

    superblock.s.free_list = fat_table[1] - 1;

    /*
     * The rest of the code will be simpler if the backing file is the
     * size of the "true" disk.  We can do that with truncate.  We
     * deliberately don't check the return code because you can't
     * truncate a real device.
     */
    ftruncate(backing_file_fd, DISK_SIZE);

    /*
     * Finally, flush the FAT and superblock to disk.  We write 
     * these last so that if we crash, the disk won't appear valid.
     */
    flush_fat();
    flush_superblock();

    /*
     * We're expected to return a pointer to user data; we have none.
     */
    return NULL;
}

/*
 * Look up a pathname component in a directory that starts at "block".
 */
static mfdoom_dirent* lookup_component(block_t block,
  const char *start, const char *end)
{
    mfdoom_dirent*      dirent;
    size_t              len;

    len = end - start;
    if (len > NAME_LENGTH)
        len = NAME_LENGTH;
    while (block != 0) {
        fetch_dirblock(block);
        for (dirent = dirbuf;  dirent < dirend;  dirent++) {
            if (dirent->type != TYPE_EMPTY
              &&  len == dirent->namelen
              &&  memcmp(dirent->name, start, len) == 0)
                return dirent;
        }

        block = NEXT_BLOCK(block);
    }
    return NULL;
}

/*
 * Find a directory entry.  If parent is nonzero, return the parent instead
 * of the entry itself.  If it succeeds, returns a pointer to the dirent.
 * On failure, returns NULL.
 */
static mfdoom_dirent* find_dirent(const char *path, int parent)
{
    const char *        component_start;
    const char *        cp;
    mfdoom_dirent*      dirent;
    block_t             parent_dirblock;
    mfdoom_dirent*      parent_dirent;

    /*
     * File #1 is the root directory, so we can just start there.
     */
    fetch_dirblock(superblock.s.files_start);
    parent_dirblock = dirblock;
    parent_dirent = dirent = &dirbuf[0];
    for (cp = component_start = path;  *cp != '\0';  cp++) {
        if (*cp == '/') {
            if (cp != component_start) {
                /* Descend a directory level */
                parent_dirblock = dirblock;
                parent_dirent = dirent;
                dirent = lookup_component(dirent->file_start,
                  component_start, cp);
                if (dirent == NULL  ||  dirent->type != TYPE_DIR)
                    return NULL;
            }
            component_start = cp + 1;
        }
    }
    if (component_start == cp) {
        if (parent) {
            fetch_dirblock(parent_dirblock);
            return parent_dirent;
        }
        else
            return dirent;
    }
    else {
        if (!parent) {
            dirent = lookup_component(dirent->file_start,
              component_start, cp);
        }
        return dirent;
    }
}

static int fuse_mfdoom_getattr(const char *path, struct stat *stbuf)
{
    mfdoom_dirent*   dirent;

    memset(stbuf, 0, sizeof(struct stat));

    dirent = find_dirent(path, 0);
    if (dirent == NULL)
        return -ENOENT;
    if (dirent->type == TYPE_DIR) {
        /*
         * We don't support permissions so we make everything the same.
         */
        stbuf->st_mode = S_IFDIR | 0755;
        /*
         * NEEDSWORK: nlink should be 2 plus number of subdirectories.
         */
        stbuf->st_nlink = 2;
    }
    else {
        /*
         * We don't support permissions so we make everything the same.
         */
        stbuf->st_mode = S_IFREG | 0644;
        stbuf->st_nlink = 1;
    }
    stbuf->st_size = dirent->size;
    stbuf->st_uid = uid;
    stbuf->st_gid = gid;
    stbuf->st_blksize = superblock.s.block_size;
    /*
     * Since we don't support timestamps, set everything to the mount time.
     */
    stbuf->st_atime = stbuf->st_ctime = stbuf->st_mtime = mount_time;
    return 0;
}

static int fuse_mfdoom_fgetattr(const char *path, struct stat *stbuf,
  struct fuse_file_info *fi)
{
    return fuse_mfdoom_getattr(path, stbuf);
}

static int fuse_mfdoom_access(const char *path, int mask)
{
    mfdoom_dirent*   dirent;

    dirent = find_dirent(path, 0);
    if (dirent == NULL)
        return -ENOENT;
    /*
     * If a file exists, we allow access--except we disallow writing
     * directories.
     */
    if (dirent->type == TYPE_DIR  &&  mask == W_OK)
        return -EACCES;

    return 0;
}

static int fuse_mfdoom_readdir(const char *path, void *buf,
  fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi)
{
    block_t             block;
    mfdoom_dirent*      dirent;
    block_t             last_block;
    char                name[NAME_LENGTH + 1];

    (void) fi;          /* Suppress unused-argument warnings */

    dirent = find_dirent(path, 0);
    if (dirent == NULL)
        return -ENOENT;
    if (dirent->type != TYPE_DIR)
        return -ENOTDIR;

    name[sizeof name - 1] = '\0';
    block = dirent->file_start;
    while (block != 0) {
        fetch_dirblock(block);
        for (dirent = dirbuf;  dirent < dirend;  dirent++) {
            if (offset > 0) {
                offset -= sizeof (dirent);
                continue;
            }
            if (dirent->type != TYPE_EMPTY) {
                memcpy(name, dirent->name, dirent->namelen);
                name[dirent->namelen] = '\0';
                if (filler(buf, name, NULL, 0))
                    return 0;
            }
        }

        block = NEXT_BLOCK(block);
    }

    return 0;
}

/*
 * Get a new file block from the free list.
 * Update superblock free list pointer accordingly.
 */
static size_t get_next_free_block() 
{
    block_t             block;

    block = superblock.s.free_list;
    superblock.s.free_list = NEXT_BLOCK(block);
    flush_superblock();
    return block;
}

/*
 * Mark a block as newly-freed.
 * Update superblock free list pointer and FAT accordingly.
 */
static void free_block(block_t block) 
{
    /*
     * Set FAT entry of newly-freed block to point to 
     * old start of free list
     * Update free list
     */
    NEXT_BLOCK(block) = superblock.s.free_list;
    superblock.s.free_list = block;

    flush_fat();
    flush_superblock();
}

/*
 * Given a start block, iterate through all connected
 * blocks and free them.
 */
static void free_blocks(block_t block)
{
    block_t             next_block;

    while (block != 0) {
        next_block = NEXT_BLOCK(block);
        free_block(block);
        block = next_block;
    }
}

static int fuse_mfdoom_mknod(const char *path, mode_t mode, dev_t rdev)
{
    block_t             block;
    const char*         cp;
    mfdoom_dirent*      dirent;
    block_t             last_block;
    size_t              len;
    block_t             parent_block;

    if (find_dirent(path, 0) != NULL)
        return -EEXIST;                 /* Pathname already exists */
    if (!S_ISREG(mode))
        return -EACCES;                 /* Only supported for plain files */

    /*
     * Find the directory to make the new file in.
     */
    dirent = find_dirent(path, 1);
    block = parent_block = dirent->file_start;
    /*
     * Find an empty slot.
     */
    while (block != 0) {
        fetch_dirblock(block);
        for (dirent = dirbuf;  dirent < dirend;  dirent++) {
            if (dirent->type == TYPE_EMPTY)
                goto doublebreak;
        }

        block = NEXT_BLOCK(block);
    }
doublebreak:
    if (block == 0)
        return -EFBIG;                  /* No room in the directory */
    dirent->file_start = get_next_free_block();
    if (dirent->file_start == 0)
        return -ENOSPC;                 /* No space for new files */
    dirent->type = TYPE_FILE;
    dirent->size = 0;
    dirent->accesses = 0;
    cp = strrchr(path, '/');
    if (cp == NULL)
        cp = path;
    else
        cp++;
    len = strlen(cp);
    if (len > NAME_LENGTH)
        len = NAME_LENGTH;
    dirent->namelen = len;
    memcpy(dirent->name, cp, len);

    // Update FAT
    fat_table[dirent->file_start - superblock.s.files_start] = 0;

    flush_dirblock();
    flush_fat();

    return 0;
}

static int fuse_mfdoom_create(const char *path, mode_t mode,
  struct fuse_file_info *fi)
{
    return fuse_mfdoom_mknod(path, mode | S_IFREG, 0);
}

static int fuse_mfdoom_mkdir(const char *path, mode_t mode)
{
    block_t             block;
    const char*         cp;
    mfdoom_dirent*      dirent;
    block_t             last_block;
    size_t              len;
    block_t             parent_file_start;
    size_t              parent_size;

    if (find_dirent(path, 0) != NULL)
        return -EEXIST;                 /* Pathname already exists */

    /*
     * Find the directory to make the directory in.
     */
    dirent = find_dirent(path, 1);
    parent_file_start = dirent->file_start;
    parent_size = dirent->size;
    /*
     * Find an empty slot.  We depend on the fact that fetch_dirblock
     * sets dirblock as a side effect.
     */
    block = parent_file_start;
    while (block != 0) {
        fetch_dirblock(block);
        for (dirent = dirbuf;  dirent < dirend;  dirent++) {
            if (dirent->type == TYPE_EMPTY)
                goto doublebreak;
        }

        block = NEXT_BLOCK(block);
    }
doublebreak:
    if (block == 0)
        return -EFBIG;                  /* No room in the directory */
    dirent->file_start = get_next_free_block();
    if (dirent->file_start == 0)
        return -ENOSPC;                 /* No space for new files */
    dirent->type = TYPE_DIR;
    dirent->size = DIR_SIZE * DIRENT_LENGTH;
    cp = strrchr(path, '/');
    if (cp == NULL)
        cp = path;
    else
        cp++;
    len = strlen(cp);
    if (len > NAME_LENGTH)
        len = NAME_LENGTH;
    dirent->namelen = len;
    memcpy(dirent->name, cp, len);
    flush_dirblock();

    /*
     * Initialize the new directory block.
     * Update and save FAT and superblock
     */
    dirblock = dirent->file_start;
    memset(dirbuf, 0, superblock.s.block_size);
    dirbuf[0].type = TYPE_DIR;
    dirbuf[0].file_start = dirblock;
    dirbuf[0].size = DIR_SIZE * DIRENT_LENGTH;
    dirbuf[0].namelen = 1;
    memcpy(dirbuf[0].name, ".", 1);
    dirbuf[1].type = TYPE_DIR;
    dirbuf[1].file_start = parent_file_start;
    dirbuf[1].size = parent_size;
    dirbuf[1].namelen = 2;
    memcpy(dirbuf[1].name, "..", 2);

    fat_table[dirblock - superblock.s.files_start] = 0;
    superblock.s.dir_count++;
    
    flush_dirblock();
    flush_fat();
    flush_superblock();

    return 0;
}

static int fuse_mfdoom_unlink(const char *path)
{
    block_t             block;
    block_t             start_block;
    block_t             next_block;
    mfdoom_dirent*      going_dirent;

    /*
     * Find the file being removed.
     */
    going_dirent = find_dirent(path, 0);
    if (going_dirent == NULL)
        return -ENOENT;

    start_block = going_dirent->file_start;
    superblock.s.access_count -= going_dirent->accesses;

    /*
     * Remove the file by zeroing its directory entry.
     */
    memset(going_dirent, 0, sizeof *going_dirent);

    /*
     * Free file space.
     */
    free_blocks(start_block);

    /*
     * Write the directory and superblock back
     */
    flush_dirblock();
    flush_superblock();
    return 0;
}

static int fuse_mfdoom_rmdir(const char *path)
{
    block_t             start_block;
    block_t             next_block;
    block_t             block;
    mfdoom_dirent*      dirent;
    int                 first_block;
    block_t             going_block;
    mfdoom_dirent*      going_dirent;
    size_t              last_block;

    /*
     * Find the directory being removed.
     */
    going_dirent = find_dirent(path, 0);
    if (going_dirent == NULL)
        return -ENOENT;
    going_block = dirblock;
    /*
     * Make sure it's empty.
     */
    block = start_block = going_dirent->file_start;
    first_block = 1;
    while (block != 0) {
        fetch_dirblock(block);
        // Skip first two entries (. and ..)
        for (dirent = first_block ? dirbuf + 2 : dirbuf;
          dirent < dirend;
          dirent++) {
            if (dirent->type != TYPE_EMPTY)
                return -ENOTEMPTY;
        }
        first_block = 0;

        block = NEXT_BLOCK(block);
    }
    /*
     * Remove the directory.
     */
    fetch_dirblock(going_block);
    memset(going_dirent, 0, sizeof *going_dirent);

    /*
     * Write the parent back, free directory
     * space, and update superblock (flushed
     * as a side effect of free_blocks)
     */
    superblock.s.dir_count--;
    flush_dirblock();
    free_blocks(start_block);

    return 0;
}

/*
 * Given an offset and a starting block, finds the block the offset is in
 */
static size_t offset_to_block(block_t start_block, off_t offset) 
{
    block_t             block;

    block = start_block;

    // Iterate through the FAT until we reach our offset
    for (int block_i = 0; block_i < offset / superblock.s.block_size; block_i++) {
        // Invalid block
        if (block == 0) {
            return 0;
        }

        block = NEXT_BLOCK(block);   
    }

    return block;
}

static int fuse_mfdoom_truncate(const char *path, off_t size)
{
    block_t             block;
    block_t             next_block;
    int                 block_change;
    char                buffer[BLOCK_SIZE];
    mfdoom_dirent*      dirent;
    size_t              oldsize;

    dirent = find_dirent(path, 0);
    if (dirent == NULL)
        return -ENOENT;
    
    assert(superblock.s.block_size == BLOCK_SIZE);
    oldsize = dirent->size;
    block_change = (size / superblock.s.block_size) - (oldsize / superblock.s.block_size);

    /*
     * If we are extending the file, we need to zero it.
     */
    if (size > dirent->size) {
        // Allocate new blocks as necessary
        if (block_change > 0) {
            block = dirent->file_start;

            // Traverse FAT to last block in file
            while (NEXT_BLOCK(block) != 0) {
                block = NEXT_BLOCK(block);
            }

            // Allocate new blocks and update FAT
            for (int i = 0; i < block_change; i++) {
                NEXT_BLOCK(block) = get_next_free_block();
                block = NEXT_BLOCK(block);
            }

            NEXT_BLOCK(block) = 0;
            flush_fat();
        }

        block = offset_to_block(dirent->file_start, oldsize);

        if (OFFSET_IN_BLOCK(oldsize) != 0) {
            read_block(block, buffer);
            memset(buffer + OFFSET_IN_BLOCK(oldsize), 0,
              superblock.s.block_size - OFFSET_IN_BLOCK(oldsize));
            write_block(block, buffer);
            oldsize = BLOCKS_TO_BYTES(BYTES_TO_BLOCKS(oldsize));
        }
        memset(buffer, 0, superblock.s.block_size);
        while (oldsize < size) {
            write_block(block, buffer);
            oldsize += superblock.s.block_size;
        }
    }

    // If we are shortening the file, free space if possible
    else {
        if (block_change < 0) {
            block = dirent->file_start;

            // Traverse FAT to the new last block in the file
            for (int block_i = 0; block_i < size / superblock.s.block_size; block_i++) {
                block = NEXT_BLOCK(block);
            }

            block = NEXT_BLOCK(block);
            while (block != 0) {
                next_block = NEXT_BLOCK(block);
                free_block(block);
                block = next_block;
            }
        }
    }
    dirent->size = size;

    /*
     * Write the parent directory back.
     */
    flush_dirblock();
    return 0;
}

static int fuse_mfdoom_open(const char *path, struct fuse_file_info *fi)
{
    mfdoom_dirent*      dirent;

    dirent = find_dirent(path, 0);
    if (dirent == NULL)
        return -ENOENT;
    if (dirent->type != TYPE_FILE)
        return -EACCES;

    // Increment accesses (but not for directories)
    dirent->accesses++;
    superblock.s.access_count++;

    /*
     * Write the directory and superblock back
     */
    flush_dirblock();
    flush_superblock();

    /*
     * Open succeeds if the file exists.
     */
    return 0;
}

static int fuse_mfdoom_read(const char *path, char *buf, size_t size,
  off_t offset, struct fuse_file_info *fi)
{
    block_t             block;
    char                blockbuf[BLOCK_SIZE];
    size_t              bytes_read;
    mfdoom_dirent*      dirent;
    size_t              read_size;

    dirent = find_dirent(path, 0);
    if (dirent == NULL)
        return -ENOENT;
    if (dirent->type != TYPE_FILE)
        return -EACCES;

    read_size = dirent->size;           /* Amount to read (max is file size) */
    if (offset >= read_size)
        return 0;
    if (offset + size > read_size)
        size = read_size - offset;      /* Don't read past EOF */

    block = offset_to_block(dirent->file_start, offset);
    offset = OFFSET_IN_BLOCK(offset);

    for (bytes_read = 0;  size > 0;  block = NEXT_BLOCK(block), offset = 0) {
        read_size = superblock.s.block_size - offset;
        if (read_size > size)
            read_size = size;
        read_block(block, blockbuf);    /* Read in full-block units */
        memcpy(buf, blockbuf, read_size);
        bytes_read += read_size;
        buf += read_size;
        size -= read_size;
    }

    return bytes_read;
}

/*
 * Given a path to a directory, recursively finds a random
 * subdirectory. If no subdirectory is randomly selected,
 * returns 0.
 */
static int find_random_dir(const char *path, char *buf)
{
    block_t             block;
    mfdoom_dirent*      dirent;
    block_t             last_block;
    float               prob;
    float               random;
    char                child_path[BLOCK_SIZE];

    memset(child_path, 0, sizeof(child_path));

    dirent = find_dirent(path, 0);
    if (dirent == NULL)
        return -ENOENT;
    if (dirent->type != TYPE_DIR)
        return -ENOTDIR;

    /*
    * Generate a random float between 0.0 and 1.0
    * to determine if the parent directory should
    * be selected.
    */
    prob = 1.0 / (float)(superblock.s.dir_count - checked_dirs);
    random = (float)rand()/(float)(RAND_MAX);

    /*
     * Parent directory selected
     */ 
    if (random <= prob) {
        memcpy(buf, path, strlen(path));
        checked_dirs = 0;
        return 1;
    }

    /*
     * Recurse on subdirectories
     */ 
    else {
        checked_dirs++;
        block = dirent->file_start;
        while (block != 0) {
            fetch_dirblock(block);
            for (dirent = dirbuf;  dirent < dirend;  dirent++) {
                if (dirent->type == TYPE_DIR 
                        && strcmp(dirent->name, ".")
                        && strcmp(dirent->name, "..")) {

                    strcat(child_path, path);
                    strcat(child_path, dirent->name);
                    strcat(child_path, "/");

                    if (find_random_dir(child_path, buf)) {
                        checked_dirs = 0;
                        return 1;
                    }

                    else {
                        /* 
                        * Re-fetch dirblock to avoid side effects
                        * of recursive calls and reset child path
                        */
                        fetch_dirblock(block);
                        memset(child_path, 0, sizeof(child_path));
                    }
                }
            }

            block = NEXT_BLOCK(block);
        }
    }

    return 0;
}

static int mfdoom_rename(const char *from, const char *to)
{
    block_t             block;
    block_t             nextblock;
    const char*         cp;
    mfdoom_dirent*      from_dirent;
    mfdoom_dirent*      to_dirent;
    char                dirent_buf[sizeof(mfdoom_dirent)];
    size_t              len;

    /*
     * If paths are the same, don't need to do anything
     */
    if (strcmp(from, to) == 0)
        return 0;

    /*
     * Find the file being renamed.
     */
    from_dirent = find_dirent(from, 0);
    if (from_dirent == NULL)
        return -ENOENT;

    /*
     * Store from_dirent in a local buffer
     */
    memcpy(dirent_buf, from_dirent, sizeof(mfdoom_dirent));

    /*
     * Check if new path already exists.
     * If so, overwrite file and free space, then
     * modify existing dirent
     */
    if ((to_dirent = find_dirent(to, 0)) != NULL) {
        free_blocks(to_dirent->file_start);
        goto doublebreak;
    }

    /*
     * Find the directory to make the new file in.
     */
    to_dirent = find_dirent(to, 1);
    block = to_dirent->file_start;

    /*
     * Find an empty slot.
     */
    while (block != 0) {
        fetch_dirblock(block);
        for (to_dirent = dirbuf;  to_dirent < dirend;  to_dirent++) {
            if (to_dirent->type == TYPE_EMPTY)
                goto doublebreak;
        }

        block = NEXT_BLOCK(block);
    }
doublebreak:
    if (block == 0)
        return -EFBIG;                  /* No room in the directory */

    memcpy(to_dirent, dirent_buf, sizeof(mfdoom_dirent));
    cp = strrchr(to, '/');
    if (cp == NULL)
        cp = to;
    else
        cp++;
    len = strlen(cp);
    if (len > NAME_LENGTH)
        len = NAME_LENGTH;
    to_dirent->namelen = len;
    memcpy(to_dirent->name, cp, len);

    flush_dirblock();

    /*
     * Re-find the file being renamed.
     * Zero it to delete the entry
     */
    from_dirent = find_dirent(from, 0);
    if (from_dirent == NULL)
        return -ENOENT;
    memset(from_dirent, 0, sizeof *from_dirent);
    flush_dirblock();

    return 0;
}

static int fuse_mfdoom_write(const char *path, const char *buf, size_t size,
  off_t offset, struct fuse_file_info *fi)
{
    block_t             block;
    char                blockbuf[BLOCK_SIZE];
    size_t              bytes_written;
    mfdoom_dirent*      dirent;
    off_t               orig_offset = offset;
    size_t              write_size;
    size_t              accesses;
    float               prob;
    float               random;
    char                name[NAME_LENGTH];
    char                random_path[BLOCK_SIZE];

    dirent = find_dirent(path, 0);
    if (dirent == NULL)
        return -ENOENT;
    if (dirent->type != TYPE_FILE)
        return -EACCES;

    // Save file name and access count for later
    accesses = dirent->accesses;
    memcpy(name, dirent->name, dirent->namelen);

    // Don't write beyond max file size
    if (size > BLOCKS_PER_FILE * superblock.s.block_size - offset)
        size = BLOCKS_PER_FILE * superblock.s.block_size - offset;

    if (offset >= BLOCKS_PER_FILE * superblock.s.block_size)
        return -EFBIG;                          /* File is too big */
    else if (size == 0)
        return -EIO;                            /* Empty writes are illegal */

    assert(superblock.s.block_size == BLOCK_SIZE);

    block = offset_to_block(dirent->file_start, offset);
    offset = OFFSET_IN_BLOCK(offset);

    for (bytes_written = 0;  size > 0;  block = NEXT_BLOCK(block), offset = 0) {
        if (offset == 0  &&  size >= superblock.s.block_size)
            read_block(block, blockbuf);        /* Only read if necessary */
        write_size = size;
        if (write_size > superblock.s.block_size - offset)
            write_size = superblock.s.block_size - offset;
        memcpy(blockbuf + offset, buf, write_size);
        write_block(block, blockbuf);
        buf += write_size;
        size -= write_size;
        bytes_written += write_size;
        if (dirent->size < orig_offset + bytes_written)
            dirent->size = orig_offset + bytes_written;
    }

    flush_dirblock();

    /*
     * If random moves are enabled, randomly move directory
     * with probability depending on how often this file has
     * been accessed compared to other files.
     */
    if (random_moves) {
        /*
         * Probability of random move is file accesses
         * divided by total accesses plus MOVE_DENOM
         */
        prob = (float)accesses / (float)(superblock.s.access_count + MOVE_DENOM);
        random = (float)rand()/(float)(RAND_MAX);

        if (random <= prob) {
            memset(random_path, 0, sizeof(random_path));
            
            /*
             * Try to find a random directory to move the file into. 
             * If no path is generated, write to root. If the original 
             * path is generated, just randomly generate again. 
             */
            find_random_dir("/", random_path);
            strcat(random_path, name);
            mfdoom_rename(path, random_path);
        }
    }

    return bytes_written;
}

static int fuse_mfdoom_rename(const char *from, const char *to)
{
    return mfdoom_rename(from, to);
}

static struct fuse_operations fuse_mfdoom_oper = {
        .init           = fuse_mfdoom_init,
        .getattr        = fuse_mfdoom_getattr,
        .fgetattr       = fuse_mfdoom_fgetattr,
        .access         = fuse_mfdoom_access,
        .readdir        = fuse_mfdoom_readdir,
        .mknod          = fuse_mfdoom_mknod,
        .create         = fuse_mfdoom_create,
        .mkdir          = fuse_mfdoom_mkdir,
        .unlink         = fuse_mfdoom_unlink,
        .rmdir          = fuse_mfdoom_rmdir,
        .rename         = fuse_mfdoom_rename,
        .truncate       = fuse_mfdoom_truncate,
        .open           = fuse_mfdoom_open,
        .read           = fuse_mfdoom_read,
        .write          = fuse_mfdoom_write
};

int main(int argc, char *argv[])
{
    // Open the backing file. If it doesn't exist, create it
    backing_file_fd = open(backing_file_name, O_RDWR | O_CREAT, 0600);
    if (backing_file_fd < 0) {
        perror("fuse_mfdoom: Couldn't open disk: ");
        exit(1);
    }

    uid = getuid();
    gid = getgid();
    time(&mount_time);

    return fuse_main(argc, argv, &fuse_mfdoom_oper, NULL);
}