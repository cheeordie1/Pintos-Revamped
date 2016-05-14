#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include <user/syscall.h>
#include "userprog/process.h"

/* Lock used by allocate_pid(). */
static struct lock pid_lock;

static void syscall_handler (struct intr_frame *);
static void syscall_halt (void);
static void syscall_exit (int);
static pid_t syscall_exec (const char *);
static int syscall_wait (pid_t);
static bool syscall_create (const char *, unsigned);
static bool syscall_remove (const char *);
static int syscall_open (const char *);
static int syscall_filesize (int);
static int syscall_read (int, void *, unsigned);
static int syscall_write (int, const void *, unsigned);
static void syscall_seek (int, unsigned);
static unsigned syscall_tell (int);
static void syscall_close (int);
static int get_user_ (const uint8_t *);
static bool put_user_ (uint8_t *, uint8_t);
static int get_user (const uint8_t *);
static bool put_user (uint8_t *, uint8_t);
static bool validate_buffer (uint8_t *, size_t);
static pid_t allocate_pid (void);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&pid_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int sys_code = *(int *) f->esp;
  int arg0, arg1, arg2;

  /* First retrieve arguments. */
  switch (sys_code)
    {
      /* One Argument. */
      case SYS_EXIT:
      case SYS_EXEC:
      case SYS_WAIT:
      case SYS_REMOVE:
      case SYS_OPEN:
      case SYS_FILESIZE:
      case SYS_TELL:
      case SYS_CLOSE:
        arg0 = *(int *) (f->esp + 1);
        break;

      /* Two Arguments. */
      case SYS_CREATE:
      case SYS_SEEK:
        arg0 = *(int *) (f->esp + 1);
        arg1 = *(int *) (f->esp + 2);
        break;

      /* Three Arguments. */
      case SYS_READ:
      case SYS_WRITE:
        arg0 = *(int *) (f->esp + 1);
        arg1 = *(int *) (f->esp + 2);
        arg2 = *(int *) (f->esp + 3);
        break;
    }
  
  /* Second switch to execute functions. */
  switch (sys_code)
    {
      case SYS_HALT:
        syscall_halt ();
        break;
      case SYS_EXIT:
        syscall_exit (arg0);
        break;
      case SYS_EXEC:
        f->eax = syscall_exec ((const char *) arg0);
        break;
      case SYS_WAIT:
        f->eax = syscall_wait ((pid_t) arg0);
        break;

      default:
        printf ("Unexpected System Call Code. Terminating thread %s",
                thread_current ()->name);
        thread_exit ();
    }
}

/* Terminates Pintos by calling power_off(). */
static void
syscall_halt ()
{
  shutdown_power_off ();
}

/* Terminates the current user program, returning status
   to the kernel. If the process's parent waits for it (see below),
   this is the status that will be returned. Conventionally, a status
   of 0 indicates success and nonzero values indicate errors. */
static void
syscall_exit (int status)
{
  /* TODO Notify parent of exit. */
  thread_exit ();
}

/* Runs the executable whose name is given in cmd_line,
   passing any given arguments, and returns the new 
   process's program id (pid). Must return pid -1, 
   which otherwise should not be a valid pid, if the
   program cannot load or run for any reason. 
   Thus, the parent process cannot return from the exec until
   it knows whether the child process successfully loaded its
   executable. */
static pid_t
syscall_exec (const char *file)
{
  if (!validate_buffer ((uint8_t *) file, strnlen (file, PGSIZE)))
    return PID_ERROR;
  tid_t tid_child = process_execute (file);
  if (tid_child == TID_ERROR)
    return PID_ERROR;
  return allocate_pid ();
}

/* Waits for a child process pid and retrieves the child's
   exit status. */ 
static int
syscall_wait (pid_t pid)
{

}

/* Reads a byte at user virtual address UADDR
   only after checking that the address is below
   PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user_ (const uint8_t *uaddr)
{
  if (!is_user_vaddr (uaddr))
    return -1;
  return get_user (uaddr);
}

/* Writes BYTE to user address UDST
   only after checking that UDST is below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user_ (uint8_t *udst, uint8_t byte)
{
  if (!is_user_vaddr (udst))
    return false;
  return put_user (udst, byte);
}


/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));
  return result;
}
 
/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

/* Validate a buffer by checking that its start and end are
   below PHYS_BASE and that each byte is okay to read. */
static bool
validate_buffer (uint8_t *buf, size_t len)
{
  int byte;
  uint16_t cur_byte;

  for (cur_byte = 0; cur_byte < len; cur_byte++)
    {
      byte = get_user_ (buf);
      if (byte == -1)
        return false;
      buf++;
    }
  return true;
}

/* Allocate process id. This identifier of a process is unique
   among all processes. */
static pid_t
allocate_pid ()
{
  static pid_t next_pid = 1;
  pid_t pid;

  lock_acquire (&pid_lock);
  pid = next_pid++;
  lock_release (&pid_lock);

  return pid;
}
