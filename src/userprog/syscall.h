#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include "threads/synch.h"

void syscall_init (void);
void halt(void);
void exit(int status);
pid_t exec(const char *cmd_line);
int wait (pid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);

enum load_state {NOT_LOADED, SUCCESS, FAIL};
struct lock fs_lock; //lock for filesystem

struct process_file {
	struct file* file;
	int fd;
	struct list_elem elem;
};

struct child_process {
	int pid;
	int status;
	load_state load; //Loading status of a child process

	struct semaphore load_sema; //seamphores for loading + exiting
	struct semaphore exit_sema;	
	
	bool wait; //Is this child process waiting for something?
	bool exit; //Did this child process quit?
	struct list_elem elem;
};

int write (int fd, const void *buff, unsigned size);

void get_arg (struct intr_frame *f, int *arg, int n);
void check_valid_ptr(const void *ptr);
void check_valid_buffer (void* buffer, unsigned size);

int user_to_kernel_ptr(const void *addr);
struct child_process* get_child_process(int pid);
void remove_child_process(struct child_process *child);

#endif /* userprog/syscall.h */
