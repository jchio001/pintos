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
	case SYS_WAIT:
		get_arg(f, &arg[0], 1);
		f->eax = wait(arg[0]);
		break;
	case SYS_CREATE:
		get_arg(f, &arg[0], 2);
		check_valid_string((const void *) arg[0]);
		arg[0] = user_to_kernel_ptr((const void *) arg[0]);
		f->eax = create((const char *)arg[0], (unsigned) arg[1]);
		break;
	case SYS_REMOVE:
		get_arg(f, &arg[0], 1);
		check_valid_string((const void *) arg[0]);
		arg[0] = user_to_kernel_ptr((const void *) arg[0]);
		f->eax = remove((const char *) arg[0]);
		break;
	case SYS_OPEN:		
		get_arg(f, &arg[0], 1);
		check_valid_string((const void *) arg[0]);
		arg[0] = user_to_kernel_ptr((const void *) arg[0]);
		f->eax = open((const char *) arg[0]);
		break; 
	case SYS_READ:
		get_arg(f, &arg[0], 3);
		check_valid_buffer((void *) arg[1], (unsigned) arg[2]);
		arg[1] = user_to_kernel_ptr((const void *) arg[1]);
		f->eax = read(arg[0], (void *) arg[1], (unsigned) arg[2]);
		break;
	case SYS_FILESIZE:
		get_arg(f, &arg[0], 1);
		f->eax = filesize(arg[0]);
		break;
	default:
		thread_exit();
		break;
  }
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
	if (thread_alive(cur->parent_id) && (cur->cp != NULL))
		cur->cp->status = status;
	
	printf ("%s: exit(%d)\n", cur->name, status);
	thread_exit();	
}

pid_t exec(const char *cmd_line) {
	pid_t pid = process_execute(cmd_line);
	struct child_process* child = get_child_process(pid);
	//note to self: == NULL or !(whatever vars), not !=.
	if (child == NULL)
		return -1;
		
	if (child->load == NOT_LOADED)
		sema_down(&child->load_sema);
	
	//Note to self: need to fix up my load enum
	if (child->load == FAIL) {
		remove_child_process(child);
      	return -1;
	}
	
	return pid;

}

int wait (pid_t pid) {
  return process_wait(pid);
}

bool create (const char *file, unsigned initial_size) {
  lock_acquire(&fs_lock);
  bool create_suc = filesys_create(file, initial_size);
  lock_release(&fs_lock);
  return create_suc;
}

bool remove (const char *file) {
	lock_acquire(&fs_lock);
	bool remove_suc = filesys_remove(file);
	lock_release(&fs_lock);
	return remove_suc;
}

int open (const char *file) {
	lock_acquire(&fs_lock);
	struct file *opened_file = filesys_open(file);
	//no point opening a file that DNE
	if (opened_file == NULL) {
		lock_release(&fs_lock);
		return -1;
	}
	int file_des = process_add_file(opened_file);
	lock_release(&fs_lock);
	return file_des;
}

int read (int fd, void *buffer, unsigned size) {
  unsigned counter = 0;
  uint8_t* buff_local = (uint8_t *) buffer;
  if (fd == 0) {
      for (; counter < size; counter++) {
	  buff_local[i] = input_getc();
      }
      return size;
   }
   
  lock_acquire(&fs_lock);
  struct file *f = process_get_file(fd);
  if (f == NULL) {
      lock_release(&fs_lock);
      return -1;
  }
  int bytes = file_read(f, buffer, size);
  lock_release(&fs_lock);
  return bytes;
}

int filesize (int fd) {
	
  lock_acquire(&fs_lock);
  struct file *f = process_get_file(fd);
  
  if (!f) {
      lock_release(&fs_lock);
      return -1;
  }
  
  int len = file_length(f);
  lock_release(&fs_lock);
  return len;
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

//based the naming of these functions on the given sample code.
void check_valid_buffer(void* buffer, unsigned sz) {
	unsigned i = 0;
	char* buff = (char *) buffer; //our local buffer
	for (; i < sz; ++i) {
		check_valid_ptr((const void*) buff);
		++buff;
	}
}

void check_valid_string (const void* str) {
  while (* (char *) user_to_kernel_ptr(str) != 0)    
      str = (char *) str + 1;    
}
