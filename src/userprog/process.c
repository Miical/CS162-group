#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pagedir.h"
#include "process.h"
#include "syscall.h"
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

static struct list loadlock_list;
static thread_func start_process NO_RETURN;
static thread_func start_pthread NO_RETURN;
static bool load(const char* file_name, void (**eip)(void), void** esp);
bool setup_thread(void (**eip)(void), void** esp, void* exec_);

/* Initializes user programs in the system by ensuring the main
   thread has a minimal PCB so that it can execute and wait for
   the first user process. Any additions to the PCB should be also
   initialized here if main needs those members */
void userprog_init(void) {
  struct thread* t = thread_current();
  bool success;

  /* Allocate process control block
     It is important that this is a call to calloc and not malloc,
     so that t->pcb->pagedir is guaranteed to be NULL (the kernel's
     page directory) when t->pcb is assigned, because a timer interrupt
     can come at any time and activate our pagedir */
  t->pcb = calloc(sizeof(struct process), 1);
  success = t->pcb != NULL;

  /* Kill the kernel if we did not succeed */
  ASSERT(success);

  /* initialization PCB */
  list_init(&t->pcb->childlist);

  /* initialization loadlock_list */
  list_init(&loadlock_list);
}

/* Return the loadlock corresponding to the pid.
   Returns NULL if not present in the list. */
struct loadlock* get_loadlock(pid_t pid) {
  struct list_elem *e;
  for (e = list_begin(&loadlock_list); e != list_end(&loadlock_list);
       e = list_next(e)) {
    struct loadlock *ll = list_entry(e, struct loadlock, elem);
    if (ll->pid == pid) return ll;
  }
  return NULL;
}

/* Create and insert a new loadlock. */
struct loadlock* add_loadlock(pid_t pid) {
  struct loadlock *ll = (struct loadlock *)malloc(sizeof(struct loadlock));
  ll->pid = pid; ll->loaded = false; ll->pcb = NULL;
  sema_init(&ll->sema, 0);
  sema_init(&ll->sema_done, 0);
  list_push_front(&loadlock_list, &ll->elem);
  return ll;
}

/* Remove the loadlock corresponding to the pid. */
void rm_loadlock(pid_t pid) {
  struct loadlock *ll = get_loadlock(pid);
  if (ll != NULL) {
    list_remove(&ll->elem);
    free(ll);
  }
}

/* Return the childprocess corresponding to the pid.
   Returns NULL if not present in the list. */
struct childprocess* get_childprocess(struct list* childlist, pid_t pid) {
  struct list_elem *e;
  for (e = list_begin(childlist); e != list_end(childlist);
       e = list_next(e)) {
    struct childprocess *cp = list_entry(e, struct childprocess, elem);
    if (cp->pid == pid) return cp;
  }
  return NULL;
}

/* Create and insert a new childprocess. */
struct childprocess* add_childprocess(struct list* childlist, pid_t pid) {
  struct childprocess *cp = (struct childprocess *)malloc(sizeof(struct childprocess));
  cp->pid = pid; cp->exitstatus = 0;
  sema_init(&cp->sema, 0);
  list_push_front(childlist, &cp->elem);
  return cp;
}

/* Remove the loadlock corresponding to the pid. */
void rm_childprocess(struct list* childlist, pid_t pid) {
  struct childprocess *cp= get_childprocess(childlist, pid);
  if (cp != NULL) {
    list_remove(&cp->elem);
    free(cp);
  }
}

/* Remove entire list. */
void rm_childlist(struct list* childlist) {
  while (!list_empty(childlist)) {
    struct childprocess *cp = list_entry(
      list_begin(childlist), struct childprocess, elem);
    list_pop_front(childlist);
    free(cp);
  }
}

/*  Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   process id, or TID_ERROR if the thread cannot be created. */
pid_t process_execute(const char* file_name) {
  char* fn_copy;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy(fn_copy, file_name, PGSIZE);

  /* Create executable name */
  size_t name_len = strcspn(file_name, " \0") + 1;
  char *exec_name = malloc(name_len * sizeof(char));
  strlcpy(exec_name, file_name, name_len);
  exec_name[name_len - 1] = '\0';

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(exec_name, PRI_DEFAULT, start_process, fn_copy);
  if (tid == TID_ERROR)
    palloc_free_page(fn_copy);
  free(exec_name);

  /* Waiting for the executing process to be loaded. */
  add_loadlock(tid);
  struct loadlock *ll = get_loadlock(tid);
  sema_down(&ll->sema);
  pid_t ret = (ll->loaded ? tid : -1);

  /* Set the parent process pcb pointer of the child process
     and set childlist. */
  struct thread* t = thread_current();
  add_childprocess(&t->pcb->childlist, tid);
  if (ret != -1) {
    ll->pcb->parent_pcb = t->pcb;
    sema_up(&ll->sema_done);
  } else {
    struct childprocess *cp = get_childprocess(&t->pcb->childlist, tid);
    cp->exitstatus = -1;
    sema_up(&cp->sema);
    rm_loadlock(tid);
  }

  return ret;
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process(void* file_name_) {
  char* file_name = (char*)file_name_;
  struct thread* t = thread_current();
  struct intr_frame if_;
  bool success, pcb_success;

  /* Allocate process control block */
  struct process* new_pcb = malloc(sizeof(struct process));
  success = pcb_success = new_pcb != NULL;

  /* Initialize process control block */
  if (success) {
    // Ensure that timer_interrupt() -> schedule() -> process_activate()
    // does not try to activate our uninitialized pagedir
    new_pcb->pagedir = NULL;
    t->pcb = new_pcb;

    // Continue initializing the PCB as normal
    t->pcb->main_thread = t;
    strlcpy(t->pcb->process_name, t->name, sizeof t->name);
    list_init(&t->pcb->childlist);
    list_init(&t->pcb->threads);
  }

  /* Create executable name */
  size_t name_len = strcspn(file_name, " \0") + 1;
  char *exec_name = malloc(name_len * sizeof (char));
  strlcpy(exec_name, file_name, name_len);
  exec_name[name_len - 1] = '\0';

  /* Initialize interrupt frame and load executable. */
  if (success) {
    memset(&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;
    asm("fsave (%0)" : : "g"(&if_.fpu));
    success = load(exec_name, &if_.eip, &if_.esp);
  }
  free(exec_name);

  /* Handle failure with succesful PCB malloc. Must free the PCB */
  if (!success && pcb_success) {
    // Avoid race where PCB is freed before t->pcb is set to NULL
    // If this happens, then an unfortuantely timed timer interrupt
    // can try to activate the pagedir, but it is now freed memory
    struct process* pcb_to_free = t->pcb;
    t->pcb = NULL;
    free(pcb_to_free);
  }

  /* Put the arguments for the initial function on the stack */
  if (success) {
    // Parsing filename
    int argc = 0;
    char *ag_start = file_name, *ag_end = file_name;
    while (true) {
      while (*ag_start == ' ') ag_start++;
      ag_end = ag_start;
      if (*ag_start == '\0') break;
      while (*ag_end != ' ' && *ag_end != '\0') ag_end++;

      char *esp_ch = ((char *)if_.esp) - (ag_end - ag_start + 1);
      if_.esp = (void *)esp_ch;
      while (ag_start != ag_end) *esp_ch++ = *ag_start++;
      *esp_ch = '\0';
      ++argc;
    }

    // Stack align
    ag_start = (char *)if_.esp;
    if_.esp = (char **)if_.esp - (argc - 1);
    if_.esp = (void *)((uint32_t)if_.esp & 0xfffffff0);
    if_.esp = (char **)if_.esp + (argc - 1);

    // Construct *argv[]
    char **esp_ch = (char **)if_.esp;
    *--esp_ch = (char *)0x0;
    for (int i = 0; i < argc; i++) {
      *--esp_ch = ag_start;
      while (*ag_start != '\0') ag_start++;
      ag_start++;
    }
    --esp_ch;
    *esp_ch = (char *)(esp_ch + 1);
    if_.esp = (void *)esp_ch;

    // Construct argc
    if_.esp = (void *)((int *)if_.esp - 1);
    *(int *)if_.esp = argc;

    // Constart return value
    if_.esp = (void *) ((uint32_t *)if_.esp - 1);
    *(uint32_t *)if_.esp = 0;
  }

  /* Clean up. Exit on failure or jump to userspace */
  palloc_free_page(file_name);
  if (!success) {
    sema_up(&get_loadlock(t->tid)->sema);
    thread_exit();
  }

  /* Loaded successfully */
  struct loadlock *ll = get_loadlock(t->tid);
  ll->loaded = true;
  ll->pcb = t->pcb;
  sema_up(&ll->sema);
  sema_down(&ll->sema_done);
  rm_loadlock(t->tid);

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

/* Waits for process with PID child_pid to die and returns its exit status.
   If it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If child_pid is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given PID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(pid_t child_pid) {
  struct list *childlist = &thread_current()->pcb->childlist;
  struct childprocess *cp = get_childprocess(childlist, child_pid);
  if (cp == NULL) return -1;

  sema_down(&cp->sema);
  int ret = cp->exitstatus;
  rm_childprocess(childlist, child_pid);
  return ret;
}

/* Free the current process's resources. */
void process_exit(void) {
  struct thread* cur = thread_current();
  uint32_t* pd;
  pid_t pid = thread_current()->tid;

  /* If this thread does not have a PCB, don't worry */
  if (cur->pcb == NULL) {
    thread_exit();
    NOT_REACHED();
  }

  /* Set child process status in parent pcb */
  struct childprocess* cp = get_childprocess(
    &cur->pcb->parent_pcb->childlist, pid);
  sema_up(&cp->sema);

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pcb->pagedir;
  if (pd != NULL) {
    /* Correct ordering here is crucial.  We must set
         cur->pcb->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
    cur->pcb->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }

  /* Close all its open file descriptors */
  close_all_fd_of_process(cur->tid);

  /* Close executable file */
  file_allow_write(cur->pcb->executable_file);
  file_close(cur->pcb->executable_file);

  /* Free the PCB of this process and kill this thread
     Avoid race where PCB is freed before t->pcb is set to NULL
     If this happens, then an unfortuantely timed timer interrupt
     can try to activate the pagedir, but it is now freed memory */
  struct process* pcb_to_free = cur->pcb;
  rm_childlist(&pcb_to_free->childlist);
  rm_childthreadlist(&pcb_to_free->threads);
  cur->pcb = NULL;
  free(pcb_to_free);

  thread_exit();
}

/* Sets up the CPU for running user code in the current
   thread. This function is called on every context switch. */
void process_activate(void) {
  struct thread* t = thread_current();

  /* Activate thread's page tables. */
  if (t->pcb != NULL && t->pcb->pagedir != NULL)
    pagedir_activate(t->pcb->pagedir);
  else
    pagedir_activate(NULL);

  /* Set thread's kernel stack for use in processing interrupts.
     This does nothing if this is not a user process. */
  tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void** esp);
static bool validate_segment(const struct Elf32_Phdr*, struct file*);
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char* file_name, void (**eip)(void), void** esp) {
  lock_acquire(&templock);
  struct thread* t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file* file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pcb->pagedir = pagedir_create();
  if (t->pcb->pagedir == NULL)
    goto done;
  process_activate();

  /* Open executable file. */
  file = filesys_open(file_name);
  if (file == NULL) {
    printf("load: %s: open failed\n", file_name);
    goto done;
  }

  /* Protect executable file. */
  file_deny_write(file);
  t->pcb->executable_file = file;

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 ||
      ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024) {
    printf("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type) {
      case PT_NULL:
      case PT_NOTE:
      case PT_PHDR:
      case PT_STACK:
      default:
        /* Ignore this segment. */
        break;
      case PT_DYNAMIC:
      case PT_INTERP:
      case PT_SHLIB:
        goto done;
      case PT_LOAD:
        if (validate_segment(&phdr, file)) {
          bool writable = (phdr.p_flags & PF_W) != 0;
          uint32_t file_page = phdr.p_offset & ~PGMASK;
          uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint32_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0) {
            /* Normal segment.
                     Read initial part from disk and zero the rest. */
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
          } else {
            /* Entirely zero.
                     Don't read anything from disk. */
            read_bytes = 0;
            zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment(file, file_page, (void*)mem_page, read_bytes, zero_bytes, writable))
            goto done;
        } else
          goto done;
        break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(esp))
    goto done;

  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;

  success = true;

done:
  lock_release(&templock);

  /* We arrive here whether the load is successful or not. */
  return success;
}

/* load() helpers. */

static bool install_page(void* upage, void* kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr* phdr, struct file* file) {
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void*)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void*)(phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) {
    /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t* kpage = palloc_get_page(PAL_USER);
    if (kpage == NULL)
      return false;

    /* Load this page. */
    if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
      palloc_free_page(kpage);
      return false;
    }
    memset(kpage + page_read_bytes, 0, page_zero_bytes);

    /* Add the page to the process's address space. */
    if (!install_page(upage, kpage, writable)) {
      palloc_free_page(kpage);
      return false;
    }

    /* Advance. */
    read_bytes -= page_read_bytes;
    zero_bytes -= page_zero_bytes;
    upage += PGSIZE;
  }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack(void** esp) {
  uint8_t* kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    success = install_page(((uint8_t*)PHYS_BASE) - PGSIZE, kpage, true);
    if (success)
      thread_current()->user_stack = *esp = PHYS_BASE;
    else
      palloc_free_page(kpage);
  }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool install_page(void* upage, void* kpage, bool writable) {
  struct thread* t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pcb->pagedir, upage) == NULL &&
          pagedir_set_page(t->pcb->pagedir, upage, kpage, writable));
}

/* Returns true if t is the main thread of the process p */
bool is_main_thread(struct thread* t, struct process* p) { return p->main_thread == t; }

/* Gets the PID of a process */
pid_t get_pid(struct process* p) { return (pid_t)p->main_thread->tid; }

/* Creates a new stack for the thread and sets up its arguments.
   Stores the thread's entry point into *EIP and its initial stack
   pointer into *ESP. Handles all cleanup if unsuccessful. Returns
   true if successful, false otherwise.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. You may find it necessary to change the
   function signature. */
bool setup_thread(void (**eip)(void), void** esp, void* exec_) {
  void **argt = (void **)exec_;
  stub_fun sf = (stub_fun)argt[0];
  pthread_fun tf = (pthread_fun)argt[1];
  void *arg = (void *)argt[2];
  struct process *pcb = (struct process *)argt[3];

  /* Setup entry function. */
  *eip = (void(*)(void))sf;

  /* Setup stack. */
  uint8_t* kpage;
  size_t bias = (list_size(&pcb->threads) + 1) * PGSIZE;
  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    bool success = install_page(((uint8_t*)PHYS_BASE) - PGSIZE - bias, kpage, true);
    if (success) {
      thread_current()->user_stack = *esp
        = (void *)((uint8_t*)PHYS_BASE - bias);
    }
    else {
      palloc_free_page(kpage);
      return false;
    }
  }

  /* Construct arguments. */
  uint32_t *p = (uint32_t *)*esp;
  *--p = (uint32_t) arg;
  *--p = (uint32_t) tf;
  *--p = 0;
  *esp = (void *)p;

  return true;
}

/* Starts a new thread with a new user stack running SF, which takes
   TF and ARG as arguments on its user stack. This new thread may be
   scheduled (and may even exit) before pthread_execute () returns.
   Returns the new thread's TID or TID_ERROR if the thread cannot
   be created properly.

   This function will be implemented in Project 2: Multithreading and
   should be similar to process_execute (). For now, it does nothing.
   */
tid_t pthread_execute(stub_fun sf, pthread_fun tf, void* arg) {
  tid_t tid;
  struct thread *t = thread_current();

  /* Create a name for new thread. */
  char *name = palloc_get_page(0);
  if (name == NULL)
    return TID_ERROR;
  strlcpy(name, "(sub)", PGSIZE);
  strlcat(name, t->pcb->process_name, PGSIZE);

  /* Compress arguments for starting thread. */
  void **argt = (void **)malloc(sizeof(void *) * 4);
  if (argt == NULL) {
    palloc_free_page(name);
    return TID_ERROR;
  }
  argt[0] = (void *)sf; argt[1] = (void *)tf;
  argt[2] = arg; argt[3] = t->pcb;

  /* Create a new thread. */
  tid = thread_create(name, PRI_DEFAULT, start_pthread, argt);
  palloc_free_page(name);
  if (tid == TID_ERROR)
    return TID_ERROR;
  add_childthread(&t->pcb->threads, tid);

  return tid;
}

/* A thread function that creates a new user thread and starts it
   running. Responsible for adding itself to the list of threads in
   the PCB.

   This function will be implemented in Project 2: Multithreading and
   should be similar to start_process (). For now, it does nothing. */
static void start_pthread(void* exec_) {
  void **argt = (void **)exec_;
  struct process *pcb = (struct process *)argt[3];

  struct thread *t = thread_current();
  struct intr_frame if_;
  int success;

  /* Set pcb. */
  t->pcb = pcb;
  process_activate();

  /* Initialize interrupt frame and setup thread. */
  memset(&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  asm("fsave (%0)" : : "g"(&if_.fpu));
  success = setup_thread(&if_.eip, &if_.esp, exec_);
  free(argt);

  if (!success)
    pthread_exit();

  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

/* Waits for thread with TID to die, if that thread was spawned
   in the same process and has not been waited on yet. Returns TID on
   success and returns TID_ERROR on failure immediately, without
   waiting.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
tid_t pthread_join(tid_t tid) {
  struct thread *t = thread_current();
  struct childthread *ct = get_childthread(&t->pcb->threads, tid);

  if (ct == NULL)
    return TID_ERROR;

  tid_t ret;
  lock_acquire(&ct->lock);
  if (ct->joined) {
    ret = TID_ERROR;
  } else {
    cond_wait(&ct->cond, &ct->lock);
    ct->joined = true;
    ret = tid;
  }
  lock_release(&ct->lock);

  return ret;
}

/* Free the current thread's resources. Most resources will
   be freed on thread_exit(), so all we have to do is deallocate the
   thread's userspace stack. Wake any waiters on this thread.

   The main thread should not use this function. See
   pthread_exit_main() below.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit(void) {
  struct thread *t = thread_current();
  struct childthread *ct = get_childthread(&t->pcb->threads, t->tid);
  lock_acquire(&ct->lock);

  /* Deallocate the thread's userspace stack. */
  process_activate();
  void* kpage = pagedir_get_page(t->pcb->pagedir, t->user_stack);
  pagedir_clear_page(t->pcb->pagedir, t->user_stack);
  palloc_free_page(kpage);

  /* Wake any waiters on this thread. */
  cond_signal(&ct->cond, &ct->lock);

  lock_release(&ct->lock);
  thread_exit();
}

/* Only to be used when the main thread explicitly calls pthread_exit.
   The main thread should wait on all threads in the process to
   terminate properly, before exiting itself. When it exits itself, it
   must terminate the process in addition to all necessary duties in
   pthread_exit.

   This function will be implemented in Project 2: Multithreading. For
   now, it does nothing. */
void pthread_exit_main(void) {}
