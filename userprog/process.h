#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"

typedef int pid_t;

// File states
enum load_status{
    NOT_LOADED,         /* Initial state */
    LOAD_SUCCESS,       /* Loaded successfuly */
    LOAD_FAILED         /* Did not load */
  };

/* Child process info struct */
struct process{
    struct list_elem elem;        /* Child process list */
    pid_t pid;                    /* Process thread identity */
    bool is_alive;                /* Process start status */
    bool is_waited;               /* Process wait status */
    int exit_status;              /* Process exit status */
    enum load_status load_status; /* Load status of file being executed */
    struct semaphore wait;        /* Wait for process to exit, then return state */
    struct semaphore load;        /* Wait for file to load or fail */
  };

tid_t process_execute (const char *);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
