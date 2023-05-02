#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "free-map.h"
#include "inode.h"
#include "threads/malloc.h"

#define min(x, y) ((x) < (y) ? (x) : (y))
#define max(x, y) ((x) > (y) ? (x) : (y))

#define MAX_CACHE 64

struct cache_item {
  block_sector_t sector;
  bool valid, accessed, dirty;
  char data[BLOCK_SECTOR_SIZE];
} cache[MAX_CACHE];

static int bpointer;

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

struct indirect_block {
  block_sector_t items[128];
};

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {
  off_t length;         /* File size in bytes. */

  block_sector_t direct[12];
  block_sector_t indirect;
  block_sector_t dbl_indirect;

  unsigned magic;       /* Magic number. */
  uint32_t unused[112]; /* Not used. */
};

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors(off_t size) { return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); }

/* In-memory inode. */
struct inode {
  struct list_elem elem;  /* Element in inode list. */
  block_sector_t sector;  /* Sector number of disk location. */
  int open_cnt;           /* Number of openers. */
  bool removed;           /* True if deleted, false otherwise. */
  int deny_write_cnt;     /* 0: writes ok, >0: deny writes. */
  struct inode_disk data; /* Inode content. */
};

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {
  ASSERT(inode != NULL);
  if (pos >= inode->data.length)
    return -1;

  pos /= BLOCK_SECTOR_SIZE;
  if (pos < 12) {
    return inode->data.direct[pos];
  }
  else if (pos < 12 + 128) {
    struct indirect_block ind;
    block_read_b(fs_device, inode->data.indirect, &ind);
    return ind.items[pos - 12];
  }
  else {
    pos -= 12 + 128;
    struct indirect_block ind, ind2;
    block_read_b(fs_device, inode->data.dbl_indirect, &ind);
    block_read_b(fs_device, ind.items[pos / 128], &ind2);
    return ind2.items[pos % 128];
  }
  return -1;
}

static size_t alloc_ind_space(struct indirect_block* ind, block_sector_t start, size_t cnt) {
  int allocated = 0;
  bool success = true;

  for (size_t i = start; i < min(start + cnt, 128) && success; i++) {
    if (free_map_allocate(1, &ind->items[i])) {
      static char zeros[BLOCK_SECTOR_SIZE];
      block_write_b(fs_device, ind->items[i], zeros);
      allocated++;
    }
    else {
      success = false;
    }
  }
  return allocated;
}

static size_t alloc_dbl_ind_space(struct indirect_block* dbl_ind, block_sector_t start, size_t cnt) {
  int allocated = 0;
  bool success = true;

  for (size_t i = start; i < min(start + cnt, 128 * 128) && success;) {
    static struct indirect_block ind;
    if (!dbl_ind->items[i / 128]) {
      if (!free_map_allocate(1, &dbl_ind->items[i / 128])) {
        success = false; break;
      }
      memset(&ind, 0, sizeof(ind));
    } else {
      block_read_b(fs_device, dbl_ind->items[i / 128], &ind);
    }

    int expected_num = min(cnt - allocated, 128 - i % 128);
    int actual_num = alloc_ind_space(&ind, i % 128, expected_num);

    if (actual_num == 0) {
      free_map_release(dbl_ind->items[i / 128], 1);
      dbl_ind->items[i / 128] = 0;
    } else {
      block_write_b(fs_device, dbl_ind->items[i / 128], ind.items);
    }

    allocated += actual_num;
    if (actual_num != expected_num) {
      success = false;
      break;
    }
    i += actual_num;
  }
  return allocated;
}

static size_t alloc_space(struct inode_disk* inode_disk, block_sector_t start, size_t cnt) {
  int origin_start = start, origin_cnt = cnt;
  int allocated = 0;
  bool success = true;

  /* Direct block */
  for (size_t i = start; i < min(start + cnt, 12) && success; i++) {
    if (free_map_allocate(1, &inode_disk->direct[i])) {
      static char zeros[BLOCK_SECTOR_SIZE];
      block_write_b(fs_device, inode_disk->direct[i], zeros);
      allocated++;
    }
    else {
      success = false;
    };
  }

  /* Indirect block */
  start = origin_start + allocated - 12;
  cnt = origin_cnt - allocated;
  if (success && start < 128 && cnt > 0) {
    struct indirect_block ind;
    if (!inode_disk->indirect) {
      if (!free_map_allocate(1, &inode_disk->indirect)) {
        success = false;
      }
      memset(&ind, 0, sizeof(ind));
    } else {
      block_read_b(fs_device, inode_disk->indirect, &ind);
    }

    if (success) {
      int expected_num = min(cnt, 128 - start);
      int actual_num = alloc_ind_space(&ind, start, expected_num);

      if (actual_num == 0) {
        free_map_release(inode_disk->indirect, 1);
        inode_disk->indirect = 0;
      } else {
        block_write_b(fs_device, inode_disk->indirect, ind.items);
      }

      allocated += actual_num;
      if (actual_num != expected_num)
        success = false;
    }
  }

  /* Double indirect block */
  start = origin_start + allocated - 12 - 128;
  cnt = origin_cnt - allocated;
  if (success && cnt > 0) {
    struct indirect_block dbl_ind;
    if (!inode_disk->dbl_indirect) {
      if (!free_map_allocate(1, &inode_disk->dbl_indirect))
        success = false;
      memset(&dbl_ind, 0, sizeof(dbl_ind));
    } else {
      block_read_b(fs_device, inode_disk->dbl_indirect, &dbl_ind);
    }

    if (success) {
      int expected_num = min(cnt, 128 * 128 - start);
      int actual_num = alloc_dbl_ind_space(&dbl_ind, start, expected_num);

      if (actual_num == 0) {
        free_map_release(inode_disk->dbl_indirect, 1);
        inode_disk->dbl_indirect = 0;
      } else {
        block_write_b(fs_device, inode_disk->dbl_indirect, dbl_ind.items);
      }

      allocated += actual_num;
      if (actual_num != expected_num)
        success = false;
    }
  }

  return allocated;
}

static bool indirect_block_empty(struct indirect_block* ind) {
  for (int i = 0; i < 128; i++)
    if (ind->items[i] != 0)
      return false;
  return true;
}

static void dealloc_ind_space(struct indirect_block* ind, block_sector_t start, size_t cnt) {
  for (size_t i = start; i < min(start + cnt, 128); i++) {
    free_map_release(ind->items[i], 1);
    ind->items[i] = 0;
  }
}

static void dealloc_dbl_ind_space(struct indirect_block* dbl_ind,
    block_sector_t start, size_t cnt) {
  int deallocated = 0;

  for (size_t i = start; i < min(start + cnt, 128 * 128);) {
    static struct indirect_block ind;
    block_read_b(fs_device, dbl_ind->items[i], &ind);

    size_t expected_num = min(cnt - deallocated, 128 - i % 128);
    dealloc_ind_space(&ind, i % 128, expected_num);

    if (indirect_block_empty(&ind)) {
      free_map_release(dbl_ind->items[i], 1);
      dbl_ind->items[i] = 0;
    } else {
      block_write_b(fs_device, dbl_ind->items[i], &ind);
    }

    deallocated += expected_num;
  }
}


static void dealloc_space(struct inode_disk* inode_disk, block_sector_t start, size_t cnt) {
  ASSERT(0 < cnt && cnt <= 12 + 128 + 128 * 128);

  /* Direct block */
  int origin_start = start, origin_cnt = cnt;
  int deallocated = 0;
  for (size_t i = start; i < min(start + cnt, 12); i++) {
    free_map_release(inode_disk->direct[i], 1);
    inode_disk->direct[i] = 0;
    deallocated++;
  }

  /* Indirect block */
  start = origin_start + deallocated - 12;
  cnt = origin_cnt - deallocated;
  if (cnt > 0) {
    int expected_num = min(cnt, 128 - start);
    struct indirect_block ind;
    block_read_b(fs_device, inode_disk->indirect, &ind);
    dealloc_ind_space(&ind, start, expected_num);
    if (indirect_block_empty(&ind)) {
      free_map_release(inode_disk->indirect, 1);
      inode_disk->indirect = 0;
    } else {
      block_write_b(fs_device, inode_disk->indirect, &ind);
    }
  }

  /* Double indirect block */
  start = origin_start + deallocated - 12 - 128;
  cnt = origin_cnt - deallocated;
  if (cnt > 0) {
    struct indirect_block dbl_ind;
    block_read_b(fs_device, inode_disk->dbl_indirect, &dbl_ind);

    int expected_num = min(cnt, 128 * 128 - start);
    dealloc_dbl_ind_space(&dbl_ind, start, expected_num);
    if (indirect_block_empty(&dbl_ind)) {
      free_map_release(inode_disk->dbl_indirect, 1);
      inode_disk->dbl_indirect = 0;
    } else {
      block_write_b(fs_device, inode_disk->dbl_indirect, &dbl_ind);
    }

    deallocated += expected_num;
  }
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void inode_init(void) {
  list_init(&open_inodes);
  for (int i = 0; i < MAX_CACHE; i++)
    cache[i].valid = false;
  bpointer = 0;
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length) {
  struct inode_disk* disk_inode = NULL;
  bool success = true;

  ASSERT(length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc(1, sizeof *disk_inode);
  if (disk_inode != NULL) {
    disk_inode->length = length;
    disk_inode->magic = INODE_MAGIC;

    size_t expected_num = (length + BLOCK_SECTOR_SIZE - 1) / BLOCK_SECTOR_SIZE;
    size_t actual_num = alloc_space(disk_inode, 0, expected_num);
    if (expected_num != actual_num) {
      dealloc_space(disk_inode, 0, actual_num);
      success = false;
    }

    if (success)
      block_write_b(fs_device, sector, disk_inode);
    free(disk_inode);
  }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode* inode_open(block_sector_t sector) {
  struct list_elem* e;
  struct inode* inode;

  /* Check whether this inode is already open. */
  for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e = list_next(e)) {
    inode = list_entry(e, struct inode, elem);
    if (inode->sector == sector) {
      inode_reopen(inode);
      return inode;
    }
  }

  /* Allocate memory. */
  inode = malloc(sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front(&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  block_read_b(fs_device, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode* inode_reopen(struct inode* inode) {
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber(const struct inode* inode) { return inode->sector; }

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode* inode) {
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0) {
    /* Remove from inode list and release lock. */
    list_remove(&inode->elem);

    /* Deallocate blocks if removed. */
    if (inode->removed) {
      free_map_release(inode->sector, 1);

      size_t expected_num = (inode->data.length + BLOCK_SECTOR_SIZE - 1) / BLOCK_SECTOR_SIZE;
      dealloc_space(&inode->data, 0, expected_num);
    }

    free(inode);
  }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove(struct inode* inode) {
  ASSERT(inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode* inode, void* buffer_, off_t size, off_t offset) {
  uint8_t* buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t* bounce = NULL;

  while (size > 0) {
    /* Disk sector to read, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Read full sector directly into caller's buffer. */
      block_read_b(fs_device, sector_idx, buffer + bytes_read);
    } else {
      /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }
      block_read_b(fs_device, sector_idx, bounce);
      memcpy(buffer + bytes_read, bounce + sector_ofs, chunk_size);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }
  free(bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
  const uint8_t* buffer = buffer_;
  off_t origin_size = size, origin_offset = offset, origin_length = inode->data.length;
  off_t bytes_written = 0;
  uint8_t* bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  if (offset + size > inode->data.length) {
    int start = (inode->data.length + BLOCK_SECTOR_SIZE - 1) / BLOCK_SECTOR_SIZE;
    int end = (offset + size - 1) / BLOCK_SECTOR_SIZE;
    int expected_num = end - start + 1;
    if (expected_num > 0) {
      int actual_num = alloc_space(&inode->data, start, expected_num);
      if (actual_num != expected_num) {
        dealloc_space(&inode->data, start, actual_num);
        return 0;
      }
    }
    inode->data.length = offset + size;
  }
  block_write_b(fs_device, inode->sector, &inode->data);

  while (size > 0) {
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Write full sector directly to disk. */
      block_write_b(fs_device, sector_idx, (void *)(buffer + bytes_written));
    } else {
      /* We need a bounce buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }

      /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
      if (sector_ofs > 0 || chunk_size < sector_left)
        block_read_b(fs_device, sector_idx, bounce);
      else
        memset(bounce, 0, BLOCK_SECTOR_SIZE);
      memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
      block_write_b(fs_device, sector_idx, bounce);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }
  free(bounce);

  if (bytes_written != origin_size) {
    if (origin_offset + origin_size > inode->data.length) {
      int start = (inode->data.length + bytes_written + BLOCK_SECTOR_SIZE - 1)
        / BLOCK_SECTOR_SIZE;
      int end = (origin_offset + origin_size - 1) / BLOCK_SECTOR_SIZE;
      size_t expected_num = end - start + 1;
      if (expected_num > 0)
        dealloc_space(&inode->data, start, expected_num);
    }
    inode->data.length = max(origin_length, origin_length + bytes_written);
    block_write_b(fs_device, inode->sector, &inode->data);
  }

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode* inode) {
  inode->deny_write_cnt++;
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode* inode) {
  ASSERT(inode->deny_write_cnt > 0);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode* inode) { return inode->data.length; }

/* Cache */

static void cache_evict(struct block* block, int id);
static void cache_insert(struct block* block, block_sector_t sector, int id);
static int cache_hit(struct block* block, block_sector_t sector);
static int cache_miss(struct block* block, block_sector_t sector);
static int access_buffer(struct block* block, block_sector_t sector);

static void cache_evict(struct block* block, int id) {
  ASSERT(cache[id].valid);

  if (cache[id].dirty)
    block_write(block, cache[id].sector, cache[id].data);
  cache[id].valid = false;
}

static void cache_insert(struct block* block, block_sector_t sector, int id) {
  if (cache[id].valid)
    cache_evict(block, id);

  cache[id].sector = sector;
  cache[id].valid = true;
  cache[id].dirty = false;
  cache[id].accessed = false;
  block_read(block, sector, cache[id].data);
}

static int cache_hit(struct block* block UNUSED, block_sector_t sector) {
  for (int i = 0; i < MAX_CACHE; i++)
    if (cache[i].valid && cache[i].sector == sector)
      return i;
  return -1;
}

static int cache_miss(struct block* block, block_sector_t sector) {
  for (int i = 0; i < MAX_CACHE; i++) {
    if (!cache[bpointer].valid || !cache[bpointer].accessed) {
      cache_insert(block, sector, bpointer);
      return bpointer;
    }
    else {
      cache[bpointer].accessed = false;
      bpointer++;
    }
  }
  cache_insert(block, sector, bpointer);
  return bpointer;
}

static int access_buffer(struct block* block, block_sector_t sector) {
  int cache_id = -1;
  if ((cache_id = cache_hit(block, sector)) == -1)
    cache_id = cache_miss(block, sector);
  return cache_id;
}


void block_read_b(struct block* block, block_sector_t sector, void* buffer) {
  int cache_id = access_buffer(block, sector);
  memcpy(buffer, cache[cache_id].data, BLOCK_SECTOR_SIZE);
}

void block_write_b(struct block* block, block_sector_t sector, void* buffer) {
  int cache_id = access_buffer(block, sector);
  memcpy(cache[cache_id].data, buffer, BLOCK_SECTOR_SIZE);
  cache[cache_id].dirty = true;
}

void write_back_all(struct block* block) {
  for (int i = 0; i < MAX_CACHE; i++)
    if (cache[i].valid)
      cache_evict(block, i);
}
