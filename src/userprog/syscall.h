#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>
#include "threads/synch.h"

void syscall_init (void);
void halt(void);
void exit(int status);

typedef enum {NOT_LOADED, SUCCESS, FAIL} load_state;
struct lock fs_lock; //lock for filesystem

struct child_process {
	int pid;
	load_state load; //Loading status of a child process
	bool wait; //Is this child process waiting for something?
	bool exit; //Did this child process quit?

};

#endif /* userprog/syscall.h */
