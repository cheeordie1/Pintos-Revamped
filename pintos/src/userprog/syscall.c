#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include <user/syscall.h>

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

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int sys_code = get_user (f->esp);
  if (sys_code == -1)
    thread_exit ();
  int arg0, arg1, arg2;
  switch (sys_code)
    {
      case SYS_HALT:
        syscall_halt ();
        break;
    }
}

static void
syscall_halt ()
{
  shutdown_power_off ();
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
