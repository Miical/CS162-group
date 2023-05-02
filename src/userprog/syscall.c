#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall-nr.h>
#include "process.h"
#include "pagedir.h"
#include "syscall.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "lib/float.h"

struct lock templock;

static void syscall_exit(int status);
static uint32_t syscall_practice(uint32_t num);
static void syscall_halt(void);
static int syscall_exec(const char *filename);
static int syscall_wait(pid_t pid);
static int syscall_create(const char* name, off_t initial_size);
static int syscall_remove(const char* name);
static int syscall_open(const char* name);
static int syscall_filesize(int fd);
static int syscall_read(int fd, void *buffer, size_t length);
static int syscall_write(int fd, void *buffer, size_t length);
static void syscall_seek(int fd, off_t pos);
static int syscall_tell(int fd);
static int syscall_close(int fd);
static int syscall_compute_e(int n);
static bool syscall_chdir(const char* dir);
static bool syscall_mkdir(const char* dir);
static bool syscall_readdir(int fd, char* name);
static bool syscall_isdir(int fd);
static int syscall_inumber(int fd);


/* Address verification */

static void syscall_exit(int status);

static void validate_byte(const char* buffer) {
  if (buffer == NULL || !is_user_vaddr(buffer)
    || pagedir_get_page(thread_current()->pcb->pagedir, buffer) == NULL) {
      syscall_exit(-1);
    }
}

static void validate_string(const char* string) {
  while (true) {
    validate_byte(string);
    if (*string == '\0') return;
    else string++;
  }
}

static void validate_buffer(const void* buffer, size_t length) {
  char *addr_b = (char *)buffer;
  while (length--)
    validate_byte(addr_b++);
}

static void validate_argv(const uint32_t* argv, int count) {
  validate_buffer(argv, count * sizeof(uint32_t));
}

/* File open */

struct list openedfiles;

struct openedfile {
  uint32_t fd;
  pid_t pid;
  bool isdir;
  void* f;
  struct list_elem elem;
};

static int add_openedfile(void* f, bool isdir) {
  struct openedfile *new_openedfile =
    (struct openedfile *)malloc(sizeof(struct openedfile));
  if (new_openedfile == NULL)
    return -1;
  new_openedfile->isdir = isdir;
  new_openedfile->f = f;
  new_openedfile->pid = thread_current()->tid;

  uint32_t new_fd = 1;
  struct list_elem *e;
  for (e = list_begin(&openedfiles); e != list_end(&openedfiles);
       e = list_next(e)) {
    struct openedfile *of = list_entry(e, struct openedfile, elem);
    if (of->fd > new_fd + 1) {
      new_openedfile->fd = ++new_fd;
      list_insert(e, &new_openedfile->elem);
      return new_fd;
    }
    else new_fd = of->fd;
  }
  new_openedfile->fd = ++new_fd;
  list_push_back(&openedfiles, &new_openedfile->elem);
  return new_fd;
}

static bool rm_openedfile(uint32_t fd) {
  struct list_elem *e;
  for (e = list_begin(&openedfiles); e != list_end(&openedfiles);
       e = list_next(e)) {
    struct openedfile *of = list_entry(e, struct openedfile, elem);
    if (of->fd == fd) {
      list_remove(e);
      free(of);
      return true;
    }
  }
  return false;
}

static struct openedfile* get_openedfile(uint32_t fd) {
  struct list_elem *e;
  for (e = list_begin(&openedfiles); e != list_end(&openedfiles);
       e = list_next(e)) {
    struct openedfile *of = list_entry(e, struct openedfile, elem);
    if (of->fd == fd) return of;
  }
  return NULL;
}

static bool isdir_fd(uint32_t fd) {
  struct openedfile *of = get_openedfile(fd);
  if (of) return of->isdir;
  else return NULL;
}

static struct file* get_file(uint32_t fd) {
  struct openedfile *of = get_openedfile(fd);
  if (of && !of->isdir) return (struct file *)of->f;
  else return NULL;
}

static struct dir* get_directory(uint32_t fd) {
  struct openedfile *of = get_openedfile(fd);
  if (of && of->isdir) return (struct dir *)of->f;
  else return NULL;
}

void close_all_fd_of_process(pid_t pid) {
  lock_acquire(&templock);
  struct list_elem *e;
  for (e = list_begin(&openedfiles); e != list_end(&openedfiles);) {
    struct openedfile *of = list_entry(e, struct openedfile, elem);
    if (of->pid == pid) {
      struct list_elem *elem_to_rm = e;
      e = list_next(e);
      if (of->isdir) dir_close((struct dir *)of->f);
      else file_close((struct file *)of->f);
      list_remove(elem_to_rm);
      free(of);
    } else {
      e = list_next(e);
    }
  }
  lock_release(&templock);
}

/* System call */

static void syscall_handler(struct intr_frame*);

void syscall_init(void) {
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  list_init(&openedfiles);
  lock_init(&templock);
}

static void syscall_exit(int status) {
  struct thread* t = thread_current();
  if (t->pcb->parent_pcb != NULL)
    get_childprocess(&t->pcb->parent_pcb->childlist, t->tid)->exitstatus = status;
  printf("%s: exit(%d)\n", t->pcb->process_name, status);
  process_exit();
}

static uint32_t syscall_practice(uint32_t num) {
  return num + 1;
}

static void syscall_halt() {
  shutdown_power_off();
}

static int syscall_exec(const char *filename) {
  return process_execute(filename);
}

static int syscall_wait(pid_t pid) {
  return process_wait(pid);
}

static int syscall_create(const char* name, off_t initial_size) {
  lock_acquire(&templock);
  int st = filesys_create(name, initial_size, thread_current()->pcb->pwd);
  lock_release(&templock);
  return st;
}

static int syscall_remove(const char* name) {
  lock_acquire(&templock);
  int st = filesys_remove(name, thread_current()->pcb->pwd);
  lock_release(&templock);
  return st;
}

static int syscall_open(const char* name) {
  lock_acquire(&templock);
  int st;
  struct file* fp = filesys_open(name, thread_current()->pcb->pwd);
  if (fp != NULL) {
    if (inode_isdir(file_get_inode(fp))) {
      struct dir* dir = dir_open(inode_reopen(file_get_inode(fp)));
      file_close(fp);
      st = add_openedfile((void *)dir, true);
      if (!st) dir_close(dir);
    } else {
      st = add_openedfile(fp, false);
      if (!st) file_close(fp);
    }
  } else {
    st = -1;
  }
  lock_release(&templock);
  return st;
}

static int syscall_filesize(int fd) {
  int st;
  lock_acquire(&templock);
  struct file* fp = get_file(fd);
  if (fp != NULL) {
    st = inode_length(file_get_inode(fp));
  } else {
    st = -1;
  }
  lock_release(&templock);
  return st;
}

static int syscall_read(int fd, void *buffer, size_t length) {
  int st;
  lock_acquire(&templock);
  if (fd == STDIN_FILENO) {
    int8_t *p = (int8_t *)buffer;
    while (length--)
      *p++ = input_getc();
    st = length;
  } else {
    struct file* fp = get_file(fd);
    if (fp != NULL) {
      st = file_read(fp, buffer, length);
    } else {
      st = -1;
    }
  }
  lock_release(&templock);
  return st;
}

static int syscall_write(int fd, void *buffer, size_t length) {
  int st;
  if (fd == STDOUT_FILENO) {
    putbuf((char*)buffer, length);
    st = length;
  } else if (isdir_fd(fd)) {
    st = -1;
  } else {
    struct file* fp = get_file(fd);
    if (fp != NULL) {
      lock_acquire(&templock);
      st = file_write(fp, buffer, length);
      lock_release(&templock);
    } else {
      st = -1;
    }
  }
  return st;
}

static void syscall_seek(int fd, off_t pos) {
  lock_acquire(&templock);
  struct file* fp = get_file(fd);
  if (fp != NULL) file_seek(fp, pos);
  lock_release(&templock);
}

static int syscall_tell(int fd) {
  int st;
  lock_acquire(&templock);
  struct file* fp = get_file(fd);
  if (fp != NULL) {
    st = file_tell(fp);
  } else {
    st = -1;
  }
  lock_release(&templock);
  return st;
}

static int syscall_close(int fd) {
  int st;
  lock_acquire(&templock);
  struct openedfile *of = get_openedfile(fd);
  if (of != NULL && of->pid == thread_current()->tid) {
    if (of->isdir) dir_close((struct dir *)of->f);
    else file_close((struct file *)of->f);
    rm_openedfile(fd);
    st = 1;
  } else {
    st = -1;
  }
  lock_release(&templock);
  return st;
}

static int syscall_compute_e(int n) {
  return sys_sum_to_e(n);
}

static bool syscall_chdir(const char* dir) {
  lock_acquire(&templock);
  bool st = filesys_chdir(dir, &thread_current()->pcb->pwd);
  lock_release(&templock);
  return st;
}

static bool syscall_mkdir(const char* dir) {
  lock_acquire(&templock);
  bool st = filesys_mkdir(dir, thread_current()->pcb->pwd);
  lock_release(&templock);
  return st;
}

static bool syscall_readdir(int fd, char* name) {
  struct dir* dir = get_directory(fd);
  lock_acquire(&templock);
  bool st = dir_readdir(dir, name);
  lock_release(&templock);
  return st;
}

static bool syscall_isdir(int fd) {
  return isdir_fd(fd);
}

static int syscall_inumber(int fd) {
  int ret = true;
  lock_acquire(&templock);
  if (isdir_fd(fd)) {
    struct dir *dir = get_directory(fd);
    if (dir != NULL) ret = inode_get_inumber(dir_get_inode(dir));
    else ret = false;
  } else {
    struct file* fp = get_file(fd);
    if (fp != NULL) ret = inode_get_inumber(file_get_inode(fp));
    else ret = false;
  }
  lock_release(&templock);
  return ret;
}

static void syscall_handler(struct intr_frame* f) {
  uint32_t* args = ((uint32_t*)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  validate_argv(args, 1);

  switch(args[0]) {
    case SYS_PRACTICE:
      validate_argv(args + 1, 1);
      f->eax = syscall_practice(args[1]);
      break;

    case SYS_HALT:
      syscall_halt();
      break;

    case SYS_EXIT:
      validate_argv(args + 1, 1);
      syscall_exit(args[1]);
      break;

    case SYS_EXEC:
      validate_argv(args + 1, 1);
      validate_string((char *)args[1]);
      f->eax = syscall_exec((char *)args[1]);
      break;

    case SYS_WAIT:
      validate_argv(args + 1, 1);
      f->eax = syscall_wait(args[1]);
      break;

    case SYS_CREATE:
      validate_argv(args + 1, 2);
      validate_string((char *)args[1]);
      f->eax = syscall_create((char *)args[1], args[2]);
      break;

    case SYS_REMOVE:
      validate_argv(args + 1, 1);
      validate_string((char *)args[1]);
      f->eax = syscall_remove((char *)args[1]);
      break;

    case SYS_OPEN:
      validate_argv(args + 1, 1);
      validate_string((char *)args[1]);
      f->eax = syscall_open((char *)args[1]);
      break;

    case SYS_FILESIZE:
      validate_argv(args + 1, 1);
      f->eax = syscall_filesize(args[1]);
      break;

    case SYS_READ:
      validate_argv(args + 1, 3);
      validate_buffer((void *)args[2], args[3]);
      f->eax = syscall_read(args[1], (void *)args[2], (size_t)args[3]);
      break;

    case SYS_WRITE:
      validate_argv(args + 1, 3);
      validate_buffer((void *)args[2], args[3]);
      f->eax = syscall_write(args[1], (void *)args[2], (size_t)args[3]);
      break;

    case SYS_SEEK:
      validate_argv(args + 1, 2);
      syscall_seek(args[1], args[2]);
      break;

    case SYS_TELL:
      validate_argv(args + 1, 1);
      f->eax = syscall_tell(args[1]);
      break;

    case SYS_CLOSE:
      validate_argv(args + 1, 1);
      f->eax = syscall_close(args[1]);
      break;

    case SYS_COMPUTE_E:
      validate_argv(args + 1, 1);
      f->eax = syscall_compute_e(args[1]);
      break;

    case SYS_CHDIR:
      validate_argv(args + 1, 1);
      f->eax = syscall_chdir((const char *)args[1]);
      break;

    case SYS_MKDIR:
      validate_argv(args + 1, 1);
      f->eax = syscall_mkdir((const char *)args[1]);
      break;

    case SYS_READDIR:
      validate_argv(args + 1, 2);
      f->eax = syscall_readdir((int)args[1], (char *)args[2]);
      break;

    case SYS_ISDIR:
      validate_argv(args + 1, 1);
      f->eax = syscall_isdir((int)args[1]);
      break;

    case SYS_INUMBER:
      validate_argv(args + 1, 1);
      f->eax = syscall_inumber((int)args[1]);
      break;

    default:
      printf("Unimplemented system call: %d\n", (int)args[0]);
      break;
  }
}
