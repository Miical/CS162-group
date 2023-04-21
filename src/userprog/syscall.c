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

typedef char lock_t;
typedef char sema_t;

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
static tid_t syscall_pthread_create(stub_fun sfun, pthread_fun tfun, void* arg);
static void syscall_pthread_exit(void);
static tid_t syscall_pthread_join(tid_t tid);
static bool syscall_lock_init(lock_t* lock);
static bool syscall_lock_acquire(lock_t* lock);
static bool syscall_lock_release(lock_t* lock);
static bool syscall_sema_init(sema_t* sema, int val);
static bool syscall_sema_down(sema_t* sema);
static bool syscall_sema_up(sema_t* sema);
static tid_t syscall_get_tid(void);


/* Address verification */

static void syscall_exit(int status);

static bool valid_addr(const char* buffer) {
  return !(buffer == NULL || !is_user_vaddr(buffer)
    || pagedir_get_page(thread_current()->pcb->pagedir, buffer) == NULL);
}

static void validate_byte(const char* buffer) {
  if (!valid_addr(buffer)) {
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
  struct file* f;
  struct list_elem elem;
};

static int add_openedfile(struct file* f) {
  struct openedfile *new_openedfile =
    (struct openedfile *)malloc(sizeof(struct openedfile));
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

static struct file* get_file(uint32_t fd) {
  struct openedfile *of = get_openedfile(fd);
  if (of) return of->f;
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
      file_close(of->f);
      list_remove(elem_to_rm);
      free(of);
    } else {
      e = list_next(e);
    }
  }
  lock_release(&templock);
}


/* Synch. */
struct list locklist;
struct list semalist;
int lock_cnt, sema_cnt;
struct lockelem { struct lock lock; struct list_elem elem; int id; };
struct semaelem { struct semaphore sema; struct list_elem elem; int id; };

lock_t new_lock(void);
sema_t new_sema(int initval);
struct lock *get_lock(int id);
struct semaphore *get_sema(int id);

lock_t new_lock() {
  struct lockelem *le = (struct lockelem *) malloc(sizeof(struct lockelem));
  if (le == NULL)
    return -1;
  lock_init(&le->lock);
  le->id = ++lock_cnt;
  list_push_back(&locklist, &le->elem);
  return lock_cnt;
}

sema_t new_sema(int initval) {
  struct semaelem *se = (struct semaelem *) malloc(sizeof(struct semaelem));
  if (se == NULL)
    return -1;
  sema_init(&se->sema, initval);
  se->id = ++sema_cnt;
  list_push_back(&semalist, &se->elem);
  return sema_cnt;
}

struct lock *get_lock(int id) {
  struct list_elem *e;
  for (e = list_begin(&locklist); e != list_end(&locklist); e = list_next(e)) {
    struct lockelem *le = list_entry(e, struct lockelem, elem);
    if (le->id == id) return &le->lock;
  }
  return NULL;
}

struct semaphore *get_sema(int id) {
  struct list_elem *e;
  for (e = list_begin(&semalist); e != list_end(&semalist); e = list_next(e)) {
    struct semaelem *se = list_entry(e, struct semaelem, elem);
    if (se->id == id) return &se->sema;
  }
  return NULL;
}

/* System call */

static void syscall_handler(struct intr_frame*);

void syscall_init(void) {
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  list_init(&openedfiles);
  list_init(&locklist);
  list_init(&semalist);
  lock_init(&templock);
  lock_cnt = sema_cnt = 0;
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
  int st = filesys_create(name, initial_size);
  lock_release(&templock);
  return st;
}

static int syscall_remove(const char* name) {
  lock_acquire(&templock);
  int st = filesys_remove(name);
  lock_release(&templock);
  return st;
}

static int syscall_open(const char* name) {
  lock_acquire(&templock);
  int st;
  struct file* fp = filesys_open(name);
  if (fp != NULL) {
    st = add_openedfile(fp);
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
  lock_acquire(&templock);
  if (fd == STDOUT_FILENO) {
    putbuf((char*)buffer, length);
    st = length;
  } else {
    struct file* fp = get_file(fd);
    if (fp != NULL) {
      st = file_write(fp, buffer, length);
    } else {
      st = -1;
    }
  }
  lock_release(&templock);
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
    file_close(of->f);
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

static tid_t syscall_pthread_create(stub_fun sfun, pthread_fun tfun, void* arg) {
  return pthread_execute(sfun, tfun, arg);
}

static void syscall_pthread_exit() {
  pthread_exit();
}

static tid_t syscall_pthread_join(tid_t tid) {
  return pthread_join(tid);
}

static bool syscall_lock_init(lock_t* lock) {
  if (!valid_addr((char *)lock)) return false;
  lock_t t = new_lock();
  if (t == -1) return false;
  *lock = t;
  return true;
}

static bool syscall_lock_acquire(lock_t* lock) {
  if (!valid_addr((char *)lock)) return false;
  struct lock *t = get_lock(*lock);
  if (t == NULL) return false;
  if (lock_held_by_current_thread(t)) return false;

  lock_acquire(t);
  return true;
}

static bool syscall_lock_release(lock_t* lock) {
  if (!valid_addr((char *)lock)) return false;
  struct lock *t = get_lock(*lock);
  if (t == NULL) return false;
  if (!lock_held_by_current_thread(t)) return false;

  lock_release(t);
  return true;
}

static bool syscall_sema_init(sema_t* sema, int val) {
  if (!valid_addr((char *)sema)) return false;
  sema_t s = new_sema(val);
  if (s == -1) return false;
  *sema = s;
  return true;
}

static bool syscall_sema_down(sema_t* sema) {
  if (!valid_addr((char *)sema)) return false;

  struct semaphore *s = get_sema(*sema);
  if (s == NULL) return false;
  sema_down(s);
  return true;
}

static bool syscall_sema_up(sema_t* sema) {
  if (!valid_addr((char *)sema)) return false;
  struct semaphore *s = get_sema(*sema);
  if (s == NULL) return false;
  sema_up(s);
  return true;
}

static tid_t syscall_get_tid() {
  return thread_tid();
}

static void syscall_handler(struct intr_frame* f UNUSED) {
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

    case SYS_PT_CREATE:
      validate_argv(args + 1, 3);
      f->eax = syscall_pthread_create((stub_fun)args[1],
        (pthread_fun)args[2], (void *)args[3]);
      break;

    case SYS_PT_EXIT:
      syscall_pthread_exit();
      break;

    case SYS_PT_JOIN:
      validate_argv(args + 1, 1);
      f->eax = syscall_pthread_join(args[1]);
      break;

    case SYS_LOCK_INIT:
      validate_argv(args + 1, 1);
      f->eax = syscall_lock_init((lock_t *)args[1]);
      break;

    case SYS_LOCK_ACQUIRE:
      validate_argv(args + 1, 1);
      f->eax = syscall_lock_acquire((lock_t *)args[1]);
      break;

    case SYS_LOCK_RELEASE:
      validate_argv(args + 1, 1);
      f->eax = syscall_lock_release((lock_t *)args[1]);
      break;

    case SYS_SEMA_INIT:
      validate_argv(args + 1, 2);
      f->eax = syscall_sema_init((sema_t *)args[1], (int)args[2]);
      break;

    case SYS_SEMA_DOWN:
      validate_argv(args + 1, 1);
      f->eax = syscall_sema_down((sema_t *)args[1]);
      break;

    case SYS_SEMA_UP:
      validate_argv(args + 1, 1);
      f->eax = syscall_sema_up((sema_t *)args[1]);
      break;

    case SYS_GET_TID:
      f->eax = syscall_get_tid();
      break;

    default:
      printf("Unimplemented system call: %d\n", (int)args[0]);
      break;
  }
}
