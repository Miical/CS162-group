#include "filesys/filesys.h"
#include <debug.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include "directory.h"
#include "filesys.h"
#include "free-map.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "inode.h"

/* Partition that contains the file system. */
struct block* fs_device;

static bool check_pwd(struct dir* pwd);
static int get_next_part(char part[NAME_MAX + 1], const char** srcp);
static struct inode* path_parse(const char* name, struct dir* pwd);
static bool path_parse_filename(const char* name, char part[NAME_MAX + 1]);
static struct dir* path_parse_dir(const char* name, struct dir* pwd);
static void do_format(void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init(bool format) {
  fs_device = block_get_role(BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC("No file system device found, can't initialize file system.");

  inode_init();
  free_map_init();

  if (format)
    do_format();

  free_map_open();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done(void) {
  free_map_close();
  write_back_all(fs_device);
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create(const char* name, off_t initial_size, struct dir* pwd) {
  if (free_map_remain() < 2048)
    return false;
  if (!check_pwd(pwd))
    return false;
  char filename[NAME_MAX + 1];
  if (!path_parse_filename(name, filename))
    return false;
  struct dir* dir = path_parse_dir(name, pwd);

  block_sector_t inode_sector = 0;
  bool success = (dir != NULL && free_map_allocate(1, &inode_sector) &&
                  inode_create(inode_sector, initial_size, false) && dir_add(dir, filename, inode_sector));
  if (!success && inode_sector != 0)
    free_map_release(inode_sector, 1);
  dir_close(dir);

  return success;
}

bool filesys_mkdir(const char* name, struct dir* pwd) {
  if (free_map_remain() < 2048)
    return false;
  if (!check_pwd(pwd))
    return false;
  char filename[NAME_MAX + 1];
  if (!path_parse_filename(name, filename))
    return false;
  struct dir* dir = path_parse_dir(name, pwd);

  block_sector_t inode_sector = 0;
  bool success = (dir != NULL && free_map_allocate(1, &inode_sector) &&
    dir_create(inode_sector, 2) && dir_add(dir, filename, inode_sector));
  if (!success && inode_sector != 0)
    free_map_release(inode_sector, 1);

  if (success) {
    struct dir *new_dir = dir_open(inode_open(inode_sector));
    success = dir_add(new_dir, ".", inode_sector);
    success &= dir_add(new_dir, "..", inode_get_inumber(dir_get_inode(dir)));
    if (!success)
      PANIC("filesys mkdir fail.");
    dir_close(new_dir);
  }
  dir_close(dir);

  return success;
}

bool filesys_chdir(const char* name, struct dir** pwd) {
  struct inode *inode = path_parse(name, *pwd);
  if (inode == NULL) return false;
  if (!inode_isdir(inode)) {
    inode_close(inode);
    return false;
  }

  dir_close(*pwd);
  struct dir *dir = dir_open(inode);
  if (dir == NULL)
    return false;

  *pwd = dir;
  return true;
}


/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file* filesys_open(const char* name, struct dir* pwd) {
  struct inode* inode = path_parse(name, pwd);
  return file_open(inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove(const char* name, struct dir* pwd) {
  bool success;
  char filename[NAME_MAX];
  if (!path_parse_filename(name, filename))
    return false;
  struct dir* dir = path_parse_dir(name, pwd);
  if (dir == NULL) return false;
  struct inode* inode = path_parse(name, pwd);
  if (inode == NULL) { dir_close(dir); return false; }

  if (inode_isdir(inode)) {
    struct dir *dir_to_rm = dir_open(inode);
    if (inode_get_inumber(dir_get_inode(pwd)) == inode_get_inumber(dir_get_inode(dir_to_rm))) {
      success = dir_remove(pwd, "..") && dir_remove(pwd, ".") && dir_remove(dir, filename);
    } else if (dir_entry_number(dir_to_rm) != 2) {
      success = false;
      dir_close(dir_to_rm);
    } else {
      success = dir_remove(dir, filename);
    }
  } else {
    success = dir != NULL && dir_remove(dir, filename);
  }
  dir_close(dir);
  return success;
}

static bool check_pwd(struct dir* pwd) {
  struct inode *inode;
  if (!dir_lookup(pwd, ".", &inode))
    return false;
  inode_close(inode);
  return true;
}

static struct dir* path_parse_dir(const char* name, struct dir* pwd) {
  int len = strlen(name);
  if (len == 0) return NULL;
  if (len == 1 && name[0] == '/') return NULL;

  char* t = (char *)malloc(sizeof(char) * (len + 1));
  strlcpy(t, name, len);
  char* tail = t + strlen(name) - 1;
  if (*tail == '/') --tail;
  while (*tail != '/' && tail >= t) --tail;
  if (tail < t) {
    free(t);
    return dir_reopen(pwd);
  }

  if (tail == t) {
    free(t);
    return dir_open_root();
  }

  *tail = '\0';
  struct inode *inode = path_parse(t, pwd);
  return dir_open(inode);
}

static bool path_parse_filename(const char* name, char part[NAME_MAX + 1]) {
  size_t len = strlen(name);
  const char *r = name + len - 1, *l;
  if (*r == '/') --r;
  l = r;
  while (l >= name && *l != '/') l--;
  l++;
  if (r - l + 1 > NAME_MAX)
    return false;
  memcpy(part, l, (r - l + 1) * sizeof(char));
  part[r - l + 1] = '\0';
  return true;
}

static struct inode* path_parse(const char* name, struct dir* pwd) {
  bool success = true;

  struct inode *inode;
  if (name[0] == '/') {
    inode = inode_open(ROOT_DIR_SECTOR);
    if (strlen(name) == 1)
      return inode;
  }
  else inode = inode_reopen(dir_get_inode(pwd));

  int st;
  char part[NAME_MAX + 1];
  const char *srcp = name;
  bool at_lease_one = false;
  while (success) {
    st = get_next_part(part, &srcp);
    if (st == -1) success = false;
    if (st == 0 || st == -1) break;
    at_lease_one = true;

    struct dir* dir;
    if (!inode_isdir(inode) || (dir = dir_open(inode)) == NULL) {
      success = false; break;
    }
    success = dir_lookup(dir, part, &inode);
    dir_close(dir);
  }
  if (!at_lease_one) success = false;

  if (success) return inode;
  inode_close(inode);
  return NULL;
}

/* Extracts a file name part from *SRCP into PART, and updates *SRCP so that the
   next call will return the next file name part. Returns 1 if successful, 0 at
   end of string, -1 for a too-long file name part. */
static int get_next_part(char part[NAME_MAX + 1], const char** srcp) {
  const char* src = *srcp;
  char* dst = part;

  /* Skip leading slashes.  If it's all slashes, we're done. */
  while (*src == '/')
    src++;
  if (*src == '\0')
    return 0;

  /* Copy up to NAME_MAX character from SRC to DST.  Add null terminator. */
  while (*src != '/' && *src != '\0') {
    if (dst < part + NAME_MAX)
      *dst++ = *src;
    else
      return -1;
    src++;
  }
  *dst = '\0';

  /* Advance source pointer. */
  *srcp = src;
  return 1;
}

/* Formats the file system. */
static void do_format(void) {
  printf("Formatting file system...");
  free_map_create();
  if (!dir_create(ROOT_DIR_SECTOR, 16))
    PANIC("root directory creation failed");

  struct dir* dir = dir_open_root();
  if (dir == NULL || !dir_add(dir, ".", ROOT_DIR_SECTOR))
    PANIC("filesys format fail");
  dir_close(dir);

  free_map_close();
  printf("done.\n");
}
