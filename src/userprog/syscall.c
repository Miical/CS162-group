#include <stdio.h>
#include <syscall-nr.h>
#include "process.h"
#include "pagedir.h"
#include "userprog/syscall.h"
#include "threads/vaddr.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "../devices/shutdown.h"

static void syscall_handler(struct intr_frame*);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

static bool valid_address_b(void* addr) {
  return addr != NULL
    && is_user_vaddr(addr)
    && pagedir_get_page(thread_current()->pcb->pagedir, addr) != NULL;
}

static bool valid_address_i(void* addr) {
  char *addr_b = (char *) addr;
  return valid_address_b(addr_b)
    && valid_address_b(addr_b + 1)
    && valid_address_b(addr_b + 2)
    && valid_address_b(addr_b + 3);
}

static bool valid_string(char *file_name) {
  while (true) {
    if (valid_address_b(file_name)) {
      if (*file_name == '\0') return true;
      file_name++;
    } else {
      return false;
    }
  }
}

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

/*
  if (!valid_address_i((void *)args)) {
    f->eax = -1;
    printf("%s: exit(-1)\n", thread_current()->pcb->process_name);
    process_exit();
  }
*/

  if (args[0] == SYS_PRACTICE) {
    f->eax = args[1] + 1;
  }
  else if (args[0] == SYS_HALT) {
    shutdown_power_off();
  }
  else if (args[0] == SYS_EXIT) {
    f->eax = args[1];
    printf("%s: exit(%d)\n", thread_current()->pcb->process_name, args[1]);
    process_exit();
  }
  else if (args[0] == SYS_EXEC) {
    if (valid_address_i((void *)(args + 1)) && valid_string((char *)args[1])) {
      f->eax = process_execute((char *) args[1]);
    } else {
      f->eax = -1;
      printf("%s: exit(-1)\n", thread_current()->pcb->process_name);
      process_exit();
    }
  }
  else if (args[0] == SYS_WAIT) {
    f->eax = process_wait(args[1]);
  }
  else if (args[0] == SYS_WRITE) {
    // int write(int fd, const void* buffer, unsigned length);
    if (args[1] == STDOUT_FILENO) {
      putbuf((char*)args[2], (size_t)args[3]);
      f->eax = args[3];
    }
  }
}
