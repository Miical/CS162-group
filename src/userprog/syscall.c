#include <stdint.h>
#include <stdio.h>
#include <syscall-nr.h>
#include "process.h"
#include "pagedir.h"
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

struct lock templock;

static void exit_process_with_status(int status) {
  struct thread* t = thread_current();
  if (t->pcb->parent_pcb != NULL)
    get_childprocess(&t->pcb->parent_pcb->childlist, t->tid)->exitstatus = status;
  printf("%s: exit(%d)\n", t->pcb->process_name, status);
  process_exit();
}

static void verify_address_b(void* addr) {
  if (addr == NULL || !is_user_vaddr(addr)
    || pagedir_get_page(thread_current()->pcb->pagedir, addr) == NULL) {
      exit_process_with_status(-1);
    }
}

static void verify_address_i(void* addr) {
  char *addr_b = (char *) addr;
  verify_address_b(addr_b);
  verify_address_b(addr_b + 1);
  verify_address_b(addr_b + 2);
  verify_address_b(addr_b + 3);
}

static void verify_string(char *file_name) {
  while (true) {
    verify_address_b(file_name);
    if (*file_name == '\0') return;
    else file_name++;
  }
}

static void verify_buffer(void *buffer, unsigned size) {
  char *addr_b = (char *)buffer;
  while (size--)
    verify_address_b(addr_b++);
}

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
    } else {
      e = list_next(e);
    }
  }
  lock_release(&templock);
}

static void syscall_handler(struct intr_frame*);

void syscall_init(void) {
  intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall");
  list_init(&openedfiles);
  lock_init(&templock);
}

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  verify_address_i(args);

  if (args[0] == SYS_PRACTICE) {
    f->eax = args[1] + 1;
  }
  else if (args[0] == SYS_HALT) {
    shutdown_power_off();
  }
  else if (args[0] == SYS_EXIT) {
    verify_address_i(args + 1);
    f->eax = args[1];
    exit_process_with_status(args[1]);
  }
  else if (args[0] == SYS_EXEC) {
    verify_address_i(args + 1);
    verify_string((char *)args[1]);
    f->eax = process_execute((char *) args[1]);
  }
  else if (args[0] == SYS_WAIT) {
    f->eax = process_wait(args[1]);
  }
  else if (args[0] == SYS_CREATE) {
    verify_address_i(args + 1);
    verify_address_i(args + 2);
    verify_string((char *)args[1]);
    lock_acquire(&templock);
    f->eax = filesys_create((char *)args[1], args[2]);
    lock_release(&templock);
  }
  else if (args[0] == SYS_REMOVE) {
    verify_address_i(args + 1);
    verify_string((char *)args[1]);
    lock_acquire(&templock);
    f->eax = filesys_remove((char *) args[1]);
    lock_release(&templock);
  }
  else if (args[0] == SYS_OPEN) {
    verify_address_i(args + 1);
    verify_string((char *)args[1]);
    lock_acquire(&templock);
    struct file* fp = filesys_open((char *)args[1]);
    if (fp != NULL) {
      f->eax = add_openedfile(fp);
    } else {
      f->eax = -1;
    }
    lock_release(&templock);
  }
  else if (args[0] == SYS_FILESIZE) {
    verify_address_i(args + 1);
    lock_acquire(&templock);
    struct file* fp = get_file(args[1]);
    if (fp != NULL) {
      f->eax = inode_length(file_get_inode(fp));
    } else {
      f->eax = -1;
    }
    lock_release(&templock);
  }
  else if (args[0] == SYS_READ) {
    verify_address_i(args + 1);
    verify_address_i(args + 2);
    verify_address_i(args + 3);
    verify_buffer((void *)args[2], args[3]);
    lock_acquire(&templock);
    if (args[1] == STDIN_FILENO) {
      int8_t *p = (int8_t *)args[2];
      unsigned size = args[3];
      while (size--)
        *p++ = input_getc();
    } else {
      struct file* fp = get_file(args[1]);
      if (fp != NULL) {
        f->eax = file_read(fp, (void *)args[2], args[3]);
      } else {
        f->eax = -1;
      }
    }
    lock_release(&templock);
  }
  else if (args[0] == SYS_WRITE) {
    verify_address_i(args + 1);
    verify_address_i(args + 2);
    verify_address_i(args + 3);
    verify_buffer((void *)args[2], args[3]);
    lock_acquire(&templock);
    if (args[1] == STDOUT_FILENO) {
      putbuf((char*)args[2], (size_t)args[3]);
      f->eax = args[3];
    } else {
      struct file* fp = get_file(args[1]);
      if (fp != NULL) {
        f->eax = file_write(fp, (void *)args[2], args[3]);
      } else {
        f->eax = -1;
      }
    }
    lock_release(&templock);
  } else if (args[0] == SYS_SEEK) {
    verify_address_i(args + 1);
    verify_address_i(args + 2);
    lock_acquire(&templock);
    struct file* fp = get_file(args[1]);
    if (fp != NULL) file_seek(fp, args[2]);
    lock_release(&templock);
  } else if (args[0] == SYS_TELL) {
    verify_address_i(args + 1);
    lock_acquire(&templock);
    struct file* fp = get_file(args[1]);
    if (fp != NULL) {
      f->eax = file_tell(fp);
    } else {
      f->eax = -1;
    }
    lock_release(&templock);
  } else if (args[0] == SYS_CLOSE) {
    verify_address_i(args + 1);
    lock_acquire(&templock);
    struct openedfile *of = get_openedfile(args[1]);
    if (of != NULL && of->pid == thread_current()->tid) {
      file_close(of->f);
      ASSERT(rm_openedfile(args[1]));
    } else {
      f->eax = -1;
    }
    lock_release(&templock);
  }
}
