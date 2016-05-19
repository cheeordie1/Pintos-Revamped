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

#define WRITE_LIMIT 512

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

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  if (!validate_buffer (f->esp, sizeof (int)))
    thread_exit ();

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
        if (!validate_buffer (f->esp + 4, sizeof (int)))
          syscall_exit (-1);
        arg0 = *(int *) (f->esp + 4);
        break;

      /* Two Arguments. */
      case SYS_CREATE:
      case SYS_SEEK:
        if (!validate_buffer (f->esp + 4, sizeof (int)) ||
            !validate_buffer (f->esp + 8, sizeof (int)))
          syscall_exit (-1);
        arg0 = *(int *) (f->esp + 4);
        arg1 = *(int *) (f->esp + 8);
        break;

      /* Three Arguments. */
      case SYS_READ:
      case SYS_WRITE:
        if (!validate_buffer (f->esp + 4, sizeof (int)) ||
            !validate_buffer (f->esp + 8, sizeof (int)) ||
            !validate_buffer (f->esp + 12, sizeof (int)))
          syscall_exit (-1);
        arg0 = *(int *) (f->esp + 4);
        arg1 = *(int *) (f->esp + 8);
        arg2 = *(int *) (f->esp + 12);
        break;

      default:
        printf ("Could not match the arguments for system call code %d.\n",
                sys_code);
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
      case SYS_CREATE:
        f->eax = syscall_create ((const char *) arg0, (unsigned) arg1);
        break;
      case SYS_REMOVE:
        f->eax = syscall_remove ((const char *) arg0);
        break;
      case SYS_OPEN:
        f->eax = syscall_open ((const char *) arg0);
        break;
      case SYS_FILESIZE:
        f->eax = syscall_filesize (arg0);
        break;
      case SYS_READ:
        f->eax = syscall_read (arg0, (void *) arg1, (unsigned) arg2);
        break;
      case SYS_WRITE:
        f->eax = syscall_write (arg0, (const void *) arg1, (unsigned) arg2);
        if ((int) f->eax < 0)
          thread_exit ();
        break;
      case SYS_SEEK:
        syscall_seek (arg0, (unsigned) arg1);
        break;
      case SYS_TELL:
        f->eax = syscall_tell (arg0);
        break;
      case SYS_CLOSE:
        syscall_close (arg0);
        break;

      default:
        printf ("Unexpected System Call Code %d\n. Terminating thread %s.\n",
                sys_code, thread_current ()->name);
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
  char *name_buf;
  struct thread *t = thread_current ();
  t->rel->exit_status = status;
  if (t->file_name == NULL)
    name_buf = t->file_name;
  else 
    name_buf = t->name;
  printf ("%s: exit(%d)\n", name_buf, status);
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
  tid_t tid = process_execute (file);
  if (tid == TID_ERROR)
    return PID_ERROR;
  return tid;
}

/* Waits for a child process pid and retrieves the child's
   exit status. */ 
static int
syscall_wait (pid_t pid)
{
  int status = process_wait (pid);
  return status;
}

/*Creates a new file called file initially initial_size bytes in size.
  Returns true if successful, false otherwise. Creating a new file does
  not open it: opening the new file is a separate operation which would
  require a open system call.  */
static bool
syscall_create (const char *file, unsigned initial_size)
{
  return 0;
}

/* Deletes the file called file. Returns true if successful,
   false otherwise. A file may be removed regardless of whether
   it is open or closed, and removing an open file does not close it. */
static bool
syscall_remove (const char *file)
{
  return 0;
}

/* Opens the file called file. Returns a nonnegative integer handle
   called a "file descriptor" (fd), or -1 if the file could not be opened.

   File descriptors numbered 0 and 1 are reserved for the console:
       fd 0 (STDIN_FILENO) is standard input,
       fd 1 (STDOUT_FILENO) is standard output.

   When a single file is opened more than once, whether by a single
   process or different processes, each open returns a new file descriptor. */
static int
syscall_open (const char *file)
{
  return 0;
}

/* Returns the size, in bytes, of the file open as fd. */
static int
syscall_filesize (int fd)
{
  return 0;
}

/* Reads size bytes from the file open as fd into buffer.
   Returns the number of bytes actually read (0 at end of file),
   or -1 if the file could not be read 
   (due to a condition other than end of file). 
   Fd 0 reads from the keyboard using input_getc(). */
static int
syscall_read (int fd, void *buffer, unsigned length)
{
  return 0;
}

/* Writes size bytes from buffer to the open file fd. Returns the
   number of bytes actually written, which may be less than size
   if some bytes could not be written.
       
   Writes as many bytes as possible up to end-of-file and return
   the actual number written, or 0 if no bytes could be written at all.

   Fd 1 writes to the console. 
   Returns -1 if the buffer has invalid addresses. */
static int
syscall_write (int fd, const void *buffer, unsigned length)
{
  int bytes_written;

  /* Validate every address in the buffer belongs to the user. */
  if (!validate_buffer (buffer, length))
    return -1;
  /* Do nothing for invalid file descriptors. */
  if (fd <= STDIN_FILENO)
    return 0;
  /* Use putbuf to write to STDIN. */
  if (fd == STDOUT_FILENO)
    {
      while (length >= WRITE_LIMIT)
        {
          putbuf (buffer, WRITE_LIMIT);
          length = length - WRITE_LIMIT;
          bytes_written += WRITE_LIMIT;
        }
      putbuf (buffer, length);
      bytes_written += length;
    }
  /* TODO Use file_write to write to other file descriptors. */
  return bytes_written;
}

/* Changes the next byte to be read or written in open file fd to position,
   expressed in bytes from the beginning of the file. 
   (Thus, a position of 0 is the file's start.)

   A seek past the current end of a file is not an error. 
   A later read obtains 0 bytes, indicating end of file. 
   A later write extends the file, filling any unwritten gap with zeros. */
static void
syscall_seek (int fd, unsigned position)
{
  return 0;
}

/* Returns the position of the next byte to be read or written in open
   file fd, expressed in bytes from the beginning of the file.  */
static unsigned
syscall_tell (int fd)
{
  return 0;
}

/* Closes file descriptor fd. Exiting or terminating a process 
   implicitly closes all its open file descriptors, as if by calling
   this function for each one.  */
static void
syscall_close (int fd)
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
  size_t cur_byte;

  for (cur_byte = 0; cur_byte < len; cur_byte++)
    {
      byte = get_user_ (buf);
      if (byte == -1)
        return false;
      buf++;
    }
  return true;
}
