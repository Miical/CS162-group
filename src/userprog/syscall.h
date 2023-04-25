#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "process.h"

extern struct lock templock;

void syscall_init(void);
void close_all_fd_of_process(pid_t pid);
void rm_all_lock_of_process(pid_t pid);
void rm_all_sema_of_process(pid_t pid);

#endif /* userprog/syscall.h */
