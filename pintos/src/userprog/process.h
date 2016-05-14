#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

/* Process identifier type. */
typedef int pid_t;
#define PID_ERROR ((pid_t) -1)

tid_t process_execute (const char *cmdline);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
