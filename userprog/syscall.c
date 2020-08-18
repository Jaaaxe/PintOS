#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/process.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "threads/vaddr.h"
#include "threads/malloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"

#define ARG_CODE 0
#define ARG_0    4
#define ARG_1    8
#define ARG_2    12

#define EXIT_ERROR -1
#define MAX_BUF 512 // Helps split large buffers when writing to stdout
#define MIN_FD 2 // In 0 Out 1

/* Maps file structures and descriptors */
struct file_map{
    struct list_elem elem;      /* List element*/
    int fd;                     /* File descriptor. */
    struct file *file;          /* File structure. */
};

/* Set to limit a single thread per file operation */
static struct semaphore sema;
static void syscall_handler (struct intr_frame *f);
static uint32_t load_stack (struct intr_frame *f, int);
bool is_valid_ptr (void *);
bool is_valid_buffer (void *buffer, size_t length);
bool is_valid_string (const char *str);
bool sys_create (const char *name, unsigned int initial_size);
bool sys_remove (const char *file);
void sys_halt (void);
void sys_exit (int status);
void sys_seek (int fd, unsigned position);
void sys_close (int fd);
int sys_wait (pid_t pid);
int sys_open (const char *file);
int sys_filesize (int fd);
int sys_read (int fd, void *buffer, unsigned length);
int sys_write (int fd, const void *buffer, unsigned int length);
unsigned sys_tell (int fd);
pid_t sys_exec (const char *cmd_line);
struct file_map *get_file (int fd);

/* Reads a byte at user virtual address UADDR and returns value*/
static int get_user (const uint8_t *uaddr){
  if ((uint32_t) uaddr >= (uint32_t) PHYS_BASE)
    return -1;

  int result;
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
       : "=&a" (result) : "m" (*uaddr));

  return result;
}

/* Writes a byte to UDST user address and returns true or false depending on success*/
  static bool put_user (uint8_t *udst, uint8_t byte){
  if ((uint32_t) udst < (uint32_t) PHYS_BASE)
    return false;

  int error_code;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}


void syscall_init (void){
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  // Semaphore for file access is set up here
  sema_init (&sema, 1);
}

static void syscall_handler (struct intr_frame *f){
  int call = (int) load_stack (f, ARG_CODE);

  switch (call)
    {
      case SYS_HALT:
        sys_halt();
        break;

      case SYS_EXIT:
        sys_exit ((int) load_stack (f, ARG_0));
        break;

      case SYS_EXEC:
        f->eax = sys_exec ((const char *) load_stack (f, ARG_0));
        break;

      case SYS_WAIT:
        f->eax = sys_wait ((pid_t) load_stack (f, ARG_0));
        break;

      case SYS_CREATE:
        f->eax = sys_create ((const char *) load_stack (f, ARG_0),
          (unsigned int) load_stack (f, ARG_1));
        break;

      case SYS_REMOVE:
        f->eax = sys_remove ((const char *) load_stack (f, ARG_0));
        break;

      case SYS_OPEN:
        f->eax = sys_open ((const char *) load_stack (f, ARG_0));
        break;

      case SYS_FILESIZE:
        f->eax = sys_filesize ((int) load_stack (f, ARG_0));
        break;

      case SYS_READ:
        f->eax = sys_read ((int) load_stack (f, ARG_0),
            (void *) load_stack (f, ARG_1),
            (unsigned int) load_stack (f, ARG_2));
        break;

      case SYS_WRITE:
        f->eax = sys_write ((int) load_stack (f, ARG_0),
            (const void *) load_stack (f, ARG_1),
            (unsigned int) load_stack (f, ARG_2));
        break;

      case SYS_SEEK:
        sys_seek ((int) load_stack (f, ARG_0),
          (unsigned) load_stack (f, ARG_1));
        break;

      case SYS_TELL:
        f->eax = sys_tell ((int) load_stack (f, ARG_0));
        break;

      case SYS_CLOSE:
        sys_close ((int) load_stack (f, ARG_0));
        break;
	  // For all unknown system calls
      default:
        sys_exit (EXIT_ERROR); 
        break;
    }
}

// Stack pointer validation and dereferencing
static uint32_t load_stack (struct intr_frame *f, int offset){
  if (!is_valid_ptr (f->esp + offset))
    sys_exit (EXIT_ERROR);

  return *((uint32_t *) (f->esp + offset));
}

// Validate user pointer
bool is_valid_ptr (void *vaddr){
  if (get_user ((uint8_t *) vaddr) == -1)
    return false;

  return true;
}

// Validating buffer
bool is_valid_buffer (void *buffer, size_t length){
  size_t i;
  char *buf = (char *) buffer;

  for (i = 0; i < length; i++){
      if (!is_valid_ptr (buf + i))
        return false;
  }

  return true;
}

// Validating string
bool is_valid_string (const char *str){
  int c;
  size_t i = 0;

    while (1){
      c = get_user ((uint8_t *) (str + i));

      if (c == -1)
        return false;

      if (c == '\0')
        return true;

      i++;
    }
}

// Exit pintos
void sys_halt (void){
  shutdown_power_off ();
}

// Ends process with a status
void sys_exit (int status){
  // Exit status is saved so it can be accessed for process exit
  struct thread *cur = thread_current ();
  cur->exit_status = status;

  thread_exit ();
}

// Runs commands and returns process id
pid_t sys_exec (const char *cmd_line){
  if (!is_valid_string (cmd_line))
    sys_exit (EXIT_ERROR);

  return process_execute (cmd_line);
}

// Hold for process termination
int sys_wait (pid_t pid){
  return process_wait (pid);
}

// File creation: takes in args file name and size
bool sys_create (const char *name, unsigned int initial_size){
  if (!is_valid_string(name))
    sys_exit (EXIT_ERROR);

  bool success;

  sema_down (&sema);
  success = filesys_create (name, initial_size);
  sema_up (&sema);

  return success;
}

// File removal: takes in the name of the file to be removed
bool sys_remove (const char *file){
  if (!is_valid_string (file))
    sys_exit (EXIT_ERROR);

  bool success;

  sema_down (&sema);
  success = filesys_remove (file);
  sema_up (&sema);

  return success;
}

// Open file: takes in the name of the file to be opened
int sys_open (const char *file){
  if (!is_valid_string (file))
    sys_exit (EXIT_ERROR);

  int fd = MIN_FD;
  struct file_map *fm;
  struct thread *cur = thread_current ();

  // Search for unused file descriptor
  while (fd >= MIN_FD && get_file (fd) != NULL)
    fd++;
  // If wrapped
  if (fd < MIN_FD) 
    sys_exit (EXIT_ERROR);

  fm = malloc (sizeof (struct file_map));

  if (fm == NULL)
    return -1;

  fm->fd = fd;

  sema_down (&sema);
  fm->file = filesys_open (file);
  sema_up (&sema);

  if (fm->file == NULL){
      free (fm);
      return -1;
  }
  // Add to the thread of current files opened 
  list_push_back (&cur->files, &fm->elem);

  return fm->fd;
}

// Size of the file is retrieved from the descriptor
int sys_filesize (int fd){
  struct file_map *fm = get_file (fd);
  int size;

  if (fm == NULL)
    return -1;

  sema_down (&sema);
  size = file_length (fm->file);
  sema_up (&sema);

  return size;
}

// Buffer reads file contents
int sys_read (int fd, void *buffer, unsigned length){
  size_t i = 0;
  struct file_map *fm;
  int ret;
  // stdin is handled separately
  if (fd == STDIN_FILENO){ 
      while (i++ < length)
        if (!put_user (((uint8_t *) buffer + i), (uint8_t) input_getc ()))
          sys_exit (EXIT_ERROR);

      return i;
  }

  if (!is_valid_buffer (buffer, length))
    sys_exit (EXIT_ERROR);

  fm = get_file (fd);

  if (fm == NULL)
    sys_exit (EXIT_ERROR);

  sema_down (&sema);
  ret = file_read (fm->file, buffer, length);
  sema_up (&sema);

  return ret;
}

// Buffered contents are written to a file
int sys_write (int fd, const void *buffer, unsigned int length){
  struct file_map *fm;
  unsigned int len;
  char *buf;
  int ret;

  if (!is_valid_buffer ((void *) buffer, length))
    sys_exit (EXIT_ERROR);

  // stdout is handled seperately
  if (fd == STDOUT_FILENO){ 
  
      len = length;
      buf = (char *) buffer;

      // Large buffers get broken up
      while (len > MAX_BUF){
        putbuf ((const char *) buf, MAX_BUF);
        len -= MAX_BUF;
        buf += MAX_BUF;
      }

      putbuf ((const char *) buf, len);
      return length;
   }

  fm = get_file (fd);

  if (fm == NULL)
    sys_exit (EXIT_ERROR);

  sema_down (&sema);
  ret = file_write (fm->file, buffer, length);
  sema_up (&sema);

  return ret;
}

// Moving to a certain file position by seeking
void sys_seek (int fd, unsigned position){
  struct file_map *fm = get_file (fd);

  if (fm == NULL)
    return;

  sema_down (&sema);
  file_seek (fm->file, position);
  sema_up (&sema);
}

// Find the current position in a file
unsigned sys_tell (int fd){
  struct file_map *fm = get_file (fd);
  unsigned int ret;

  if (fm == NULL)
    return 0;

  sema_down (&sema);
  ret = file_tell (fm->file);
  sema_up (&sema);

  return ret;
}

// File closed
void sys_close (int fd){
  struct file_map *fm = get_file (fd);

  if (fm == NULL)
    return;

  sema_down (&sema);
  file_close (fm->file);
  sema_up (&sema);

  // Get it removed from thread list and deallocate memory
  list_remove (&fm->elem);
  free (fm);
}

/* Attempt to file a valid file_map structure for the given file descriptor. */

// Try to file file_map structure for a file descriptor 
struct file_map *
get_file(int fd){
  struct thread *cur = thread_current ();
  struct list_elem *e;
  struct file_map *fm;

  for (e = list_begin (&cur->files); e != list_end (&cur->files);
  	e = list_next (e)){
      fm = list_entry (e, struct file_map, elem);

      if (fm->fd == fd)
        return fm;
    }

  return NULL;
}

// Closing all the files
void close_all_files (struct thread *t){
  struct list_elem *e;
  struct file_map *fm;

  e = list_begin (&t->files);

  while (e != list_end (&t->files)){
      fm = list_entry (e, struct file_map, elem);
      // Moving to the next element
      e = list_next (e);
      // File closed
      sema_down (&sema);
      file_close (fm->file);
      sema_up (&sema);
      // Remove from list and deallocate memory
      list_remove (&fm->elem);
      free (fm);
    }
}
