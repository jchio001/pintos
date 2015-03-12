#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syscall-nr.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"
#include "devices/shutdown.h"

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
  int arg[3];
  int esp = user_to_kernel_ptr((const void*) f->esp);
  switch (* (int*) esp) {
	case SYS_HALT:
		halt();
		break;
	case SYS_WRITE:
		//We were given this code for write.
		get_arg(f, &arg[0], 3);
		check_valid_buffer((void *) arg[1], (unsigned) arg[2]);
		arg[1] = user_to_kernel_ptr((const void *) arg[1]);
		f->eax = write(arg[0], (const void *) arg[1],
		(unsigned) arg[2]);
		break;
  }
  thread_exit ();
}

void halt(void) {
	shutdown_power_off();
}


int write (int fd, const void *buff, unsigned size) {
	if (fd == 1) {
		putbuf(buff, size);
		return size;
	}
	
	lock_acquire(&fs_lock);
	struct file *write_file = process_get_file(fd);
	if (write_file  == NULL) {
		lock_release(&fs_lock);
		return -1;
	}
	//I want the below line of code to be before the release of the lock
	//to ensure that my write will not be interrupted
	int sz = file_write(write_file, buff, size);
	return sz; 
}

void exit(int status) {	
	struct thread* cur = thread_current();
	//cp sounds very awkward, but it's the simplest way to say child process
	if (thread_alive(cur->parent_id) && (cur->cp != NULL)  {
		cur->cp->status = status;
	}
	printf ("%s: exit(%d)\n", cur->name, status);
	thread_exit();	
}

pid_t exec(const char *cmd_line) {
	pid_t pid = process_execute(cmd_line);
	struct child_process* child = get_child_process(pid);
	if (cp != NULL)
		return -1;
		
	if (cp->load == NOT_LOADED)
		sema_down(&cp->load_sema);
	
	//Note to self: need to fix up my load enum
	if (cp->load == FAIL) {
		remove_child_process(cp);
      		return -1;
	}
	
	return pid;

}

void check_valid_ptr (const void *ptr) {
	//0x08048000 is the bottom address of our virtual address space
	if (!is_user_vaddr(ptr) || ptr < 0x08048000){
		exit(-1);
	}
}

int user_to_kernel_ptr (const void *addr) {
	struct thread *cur = thread_current();
	check_valid_ptr(addr);
	void  *ptr = pagedir_get_page(cur->pagedir, addr);
	if (!ptr)
		exit(-1);

	return (int) ptr;
}

struct child_process* get_child_process(int pid) {
	struct thread *cur = thread_current();
	struct list_elem *cntr = list_begin(&cur->child_list);
	struct child_process *child;	

	for (; cntr != list_end(&cur->child_list); cntr = list_next(cntr)) {
		child = list_entry(cntr, struct child_process, elem);
		if (pid == child->pid)
			return child;
	}
	
	return NULL;
}

void remove_child_process(struct child_process *child) {
	list_remove(&child->elem);
	free(child);
}


void get_arg (struct intr_frame *f, int *arg, int n) {
	int i;
	int *ptr;
	for (i = 0; i < n; i++) {
		ptr = (int *) f->esp + i + 1;
		check_valid_ptr((const void *) ptr);
		arg[i] = *ptr;
	}
}

void check_valid_buffer(void* buffer, unsigned sz) {
	unsigned i = 0;
	char* buff = (char *) buffer; //our local buffer
	for (; i < sz; ++i) {
		check_valid_ptr((const void*) buff);
		++buff;
	}
}
