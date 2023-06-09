#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "filesys/directory.h"
#include <list.h>
#include <stdint.h>

// At most 8MB can be allocated to the stack
// These defines will be used in Project 2: Multithreading
#define MAX_STACK_PAGES (1 << 11)
#define MAX_THREADS 127

/* PIDs and TIDs are the same type. PID should be
   the TID of the main thread of the process */
typedef tid_t pid_t;

/* Used to determine whether the child process is loaded */
struct loadlock {
   pid_t pid;
   bool loaded;                /* Whether the process was successfully loaded */
   struct process* pcb;        /* Process control block if loaded */
   struct semaphore sema;      /* The semaphore used to block the creator thread */
   struct semaphore sema_done; /* The semaphore used to block the child process */
   struct list_elem elem;
};
struct loadlock* get_loadlock(pid_t pid);
struct loadlock* add_loadlock(pid_t pid);
void rm_loadlock(pid_t pid);

/* Used to manage child processes */
struct childprocess {
   pid_t pid;
   int exitstatus;        /* Exit status */
   struct semaphore sema; /* Used to wait for child processes */
   struct list_elem elem;
};
struct childprocess* get_childprocess(struct list* childlist, pid_t pid);
struct childprocess* add_childprocess(struct list* childlist, pid_t pid);
void rm_childprocess(struct list* childlist, pid_t pid);
void rm_childlist(struct list* childlist);

/* Thread functions (Project 2: Multithreading) */
typedef void (*pthread_fun)(void*);
typedef void (*stub_fun)(pthread_fun, void*);

/* The process control block for a given process. Since
   there can be multiple threads per process, we need a separate
   PCB from the TCB. All TCBs in a process will have a pointer
   to the PCB, and the PCB will have a pointer to the main thread
   of the process, which is `special`. */
struct process {
  /* Owned by process.c. */
  uint32_t* pagedir;            /* Page directory. */
  struct dir* pwd;              /* Current directory  */
  char process_name[16];        /* Name of the main thread */
  struct thread* main_thread;   /* Pointer to main thread */
  struct file* executable_file; /* Process executable file */
  struct process* parent_pcb;   /* Pointer to parent process pcb */
  struct list childlist;        /* Child process list */
};

void userprog_init(void);

pid_t process_execute(const char* file_name);
int process_wait(pid_t);
void process_exit(void);
void process_activate(void);

bool is_main_thread(struct thread*, struct process*);
pid_t get_pid(struct process*);

tid_t pthread_execute(stub_fun, pthread_fun, void*);
tid_t pthread_join(tid_t);
void pthread_exit(void);
void pthread_exit_main(void);

#endif /* userprog/process.h */
