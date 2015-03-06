#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
	lock_init(&fs_lock);
	intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  thread_exit ();
}

void halt(void) {
		shutdown_power_off();
}

void exit(int status) {	
	struct thread* current = thread_current();
	if (thread_alive(cur->parent))  {
		cur->cp->status = status;
	}
	printf ("%s: exit(%d)\n", current->name, status);
	thread_exit();	
}
