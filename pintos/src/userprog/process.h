#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

/* Process identifier type. */
typedef int pid_t;
#define PID_ERROR ((pid_t) -1)

#define MIN_FD 3
#define MIN_NUM_FDS 128
/* A relationship between a child and parent process.
   
   Holds the status of the parent and child and a lock to read and write the
   statuses. This structure should be allocated on the heap, not on the stack,
   because it is shared between two different stacks, and one may be removed
   without the other's knowledge.
   If a child dies first, the parent will delete the relationship data.
   If a parent dies fist, the child will delete the relationship data. */
struct relationship
  {
    struct list_elem elem;
    bool parent_exited;
    bool child_exited;
    bool load_success;
    int exit_status;
    int child_pid;
    struct lock relation_lock;
    struct condition wait_cond;
  };

struct process
  {
    /* Owned by userprog/process.c. */
    struct file *exe;                   /* Executable file pointer. */
    char *file_name;                    /* Full executable name. */
    struct file **fd_table;             /* Dynamic Array of open fds. */
    int fdt_size;                       /* Current size of fd table. */
    int next_fd;                        /* Next free file descriptor. */

    /* Shared between a parent and child process. */
    struct relationship *rel;           /* Shared data with parent. */
    struct list children;               /* List of child relationships. */    
    struct semaphore load_child_sema;   /* Semaphore for load synch. */

#ifdef VM
    /* Process owned Virtual Memory Management. */
    struct spt *supp_pt;                /* Supplemental page table. */
#endif
  };

tid_t process_execute (const char *cmdline);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);
void init_process (struct thread *, char *);

#endif /* userprog/process.h */
