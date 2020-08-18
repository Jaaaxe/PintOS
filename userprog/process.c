#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "threads/malloc.h"
#include "userprog/syscall.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

bool esp_move (void **, size_t);
bool gen_argv (void **, void **, int *);
bool stack_build (void **, const char *);
bool argument_setup (void **, const char *);
void get_filen (const char *, char *);
void paren_updt (struct thread *child);
void process_release (struct thread *t);
void paren_updt_status (struct thread *child, enum load_status status);
struct process *ini_process (tid_t);
struct process *fetch_child_process (struct thread *, tid_t);


/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *args)
{
  tid_t tid;
  char *args_copy;
  char file_name[NAME_MAX_SIZE];
  struct process *prc;
  struct thread *crnt;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  args_copy = palloc_get_page(0);

  if (args_copy == NULL)
    return TID_ERROR;

  strlcpy (args_copy, args, PGSIZE);
  get_filen (args, file_name);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(file_name, PRI_DEFAULT, start_process, args_copy, true);

  if (tid == TID_ERROR)
    palloc_free_page (args_copy);
    crnt = thread_current ();

  // Starting the processs information
  prc = ini_process(tid);

  if (prc==NULL){
      palloc_free_page(args_copy);
      return -1;
  }

  // Add the process as the current thread's child
  list_push_back (&crnt->children, &prc->elem);

  // If the file can't be loaded then exec should be returning a -1
  sema_down (&prc->load);
  if (prc->load_status==LOAD_FAILED)
    return -1;

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process (void *args_){
  struct thread *thrd = thread_current ();
  char *args = args_;
  struct intr_frame if_;
  bool success;
  

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

  success = load (args, &if_.eip, &if_.esp);
  palloc_free_page (args);

  // The load status of the child is sent to parent 
  paren_updt_status (thrd, success ? LOAD_SUCCESS : LOAD_FAILED);

  /* If load failed, quit. */
  if (!success)
    thread_exit ();

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait (tid_t child_tid){
  
  int exit_status;
  struct thread *crnt = thread_current ();
  struct process *prc = fetch_child_process (crnt, child_tid);
  

  // If ivalid or not a child
  if (prc == NULL)
    return -1;

  // If the wait process is ongoing
  if (prc->is_waited)
    return -1;

  // Set it as a process that is being waited on
  prc->is_waited = true;

  // If the process has not exited then wait
  sema_down (&prc->wait);
  exit_status = prc->exit_status;

  // Once completed we can then remove child process
  list_remove (&prc->elem);
  free (prc);

  return exit_status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *crnt = thread_current ();
  uint32_t *pd;

  if (crnt->is_user)
    paren_updt (crnt);

  if (!list_empty (&crnt->children))
    process_release (crnt);

  if (!list_empty (&crnt->files))
    close_all_files (crnt);

  if (crnt->exec != NULL){
      file_allow_write (crnt->exec);
      file_close (crnt->exec);
  }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = crnt->pagedir;
  if (pd != NULL)
    {
      /* Correct ordering here is crucial.  We must set
         crnt->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      crnt->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }

  // This allows bad tests to pass by letting the system exit 
  if (crnt->is_user)
    printf ("%s: exit(%d)\n",crnt->name,crnt->exit_status);
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *args, void (**eip) (void), void **esp)
{
  char file_name[NAME_MAX_SIZE];
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;
  

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();

  if (t->pagedir == NULL)
    goto done;

  process_activate ();
  get_filen (args, file_name);

  /* Open executable file. */
  file = filesys_open (file_name);

  if (file == NULL)
    {
      printf ("load: %s: open failed\n", file_name);
      goto done;
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type)
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file))
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Setting up arguments*/
  if (!argument_setup (esp, args))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  if (success){
      t->exec = file;
      file_deny_write (file);
  }else
      file_close (file);

  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false;
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable))
        {
          palloc_free_page (kpage);
          return false;
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp)
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL)
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success) {
        *esp = PHYS_BASE;
      } else
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

//--------------------------------------------------------------------

/* Getting a single argument from CL arguments */
void get_filen (const char *args, char *file_name){
  size_t i;
  // Leaving space for nulls characters by subtracting 1
  for (i = 0; i < (NAME_MAX_SIZE - 1); i++){
      if (args[i] == '\0' || args[i] == ' ')
        break;
      file_name[i] = args[i];
    }
  file_name[i] = '\0';
}

/* Check for stack overflow and there isn't one move stack pointer*/
bool esp_move (void **esp, size_t size) {
  // This would cause one and would only run simple systems
  if (size > ((uint32_t) PHYS_BASE))
    return false;
  // Check if new location fits user address space specs
  if (!is_user_vaddr ((const void *) (*esp - size)))
    return false;
  
  *esp -= size;
  return true;
}

/* Adding CL args onto the stack */
bool stack_build (void **esp, const char *args){
  void *esp_tmp = *esp;
  size_t length, align;
  char *crnt = ((char *)args)+strlen(args);
  char *start, *end;

  while (crnt >= args){
      // Looks for the end of the argument
      while (crnt >= args && (*crnt == ' ' || *crnt == '\0'))
        crnt--;

      end = crnt + 1;

      // Looks up the start of the current argument
      while (crnt >= args && *crnt != ' ')
        crnt--;

      start = crnt + 1;
      // In order to make room for \0 we should add 1
      length = (end - start) + 1;

      if (!esp_move (&esp_tmp, length))
        return false;

      strlcpy (esp_tmp, start, length);
    }

  // Memory gets rounded down and stack pointer gets updated
  align = ((uint32_t) esp_tmp) % 4;

  if (!esp_move (&esp_tmp, align))
    return false;

  memset(esp_tmp, 0, align);
  *esp = esp_tmp;

  return true;
}

/* Adding argv pointers into the stack */
bool gen_argv(void **start, void **esp, int *argc){
  void *esp_tmp = *esp;
  // Get into user space by subtracting 1
  char *crnt = *start - 1;
  char *end = (char *) esp_tmp;

  // Setting null to argv[argc] depending on current
  if (!esp_move (&esp_tmp, sizeof (char *)))
    return false;

  *((char **) esp_tmp) = 0;

  while (crnt >= end)
    {

      // Looking for argument end
      while (crnt >= end && *crnt == '\0')
        crnt--;

      // Looking for start of argument
      while (crnt >= end && *crnt != '\0')
        crnt--;

      // Verifying align area
      if (*(crnt + 1) == 0)
        break;

      // Adding argument pointer to the stack
      if (!esp_move (&esp_tmp, sizeof (char *)))
        return false;

      *((char **) esp_tmp) = (crnt + 1);
      // Increasing argc by 1
      *argc += 1;
    }

  // Setting argv and updating the stack pointer
  if (!esp_move (&esp_tmp, sizeof (char **)))
    return false;

  *((char ***) esp_tmp) = ((char **) (esp_tmp + sizeof (char *)));
  *esp = esp_tmp;

  return true;
}

/* argv pointers, argc, arguments and the return address gets added to the stack */
bool argument_setup (void **esp, const char *args){
  void *esp_tmp = *esp;
  int argc = 0;

  if (!stack_build (&esp_tmp, args))
    return false;

  if (!gen_argv (esp, &esp_tmp, &argc))
    return false;

  // Setting argc
  if (!esp_move (&esp_tmp, sizeof (int)))
    return false;

  *((int *) esp_tmp) = argc;

  // Setting return address
  if (!esp_move (&esp_tmp, sizeof (int)))
    return false;

  *((int *) esp_tmp) = 0;

  // Updating the stack pointer
  *esp = esp_tmp;

  return true;
}

/* Making a process info struct for child process */
struct process * ini_process (tid_t tid){
  struct process *prc = malloc (sizeof (struct process));

  if (prc == NULL)
    return prc;

  memset (prc, 0, sizeof (struct process));

  prc->pid = (pid_t) tid;
  prc->is_alive = true;
  prc->is_waited = false;
  prc->load_status = NOT_LOADED;

  sema_init (&prc->load, 0);
  sema_init (&prc->wait, 0);

  return prc;
}

/* All process info that is stored about child processes gets freed */
void process_release(struct thread *t){
  struct list_elem *e;
  struct process *prc;

  e = list_begin (&t->children);

  while (e != list_end (&t->children)){
      prc = list_entry (e, struct process, elem);
      // Moving to next
      e = list_next (e);

      // Removing parent 
      if (prc->is_alive)
        remove_parent (prc->pid);

      // Remove from child process list
      list_remove (&prc->elem);
      // Free memory
      free (prc);
    }
}

/* From a certain parent thread, look for the info of a specific child process*/
struct process *
fetch_child_process (struct thread *t, tid_t child_tid){
  struct list_elem *e;
  struct process *prc;

  if (t == NULL)
    return NULL;

  for (e = list_begin (&t->children); e != list_end (&t->children);
    e = list_next (e))
    {
      prc = list_entry (e, struct process, elem);

      if (prc->pid == (pid_t) child_tid)
        return prc;
    }

  return NULL;
}

/* Once a child exits update the info tracker of the parent thread's process*/
void paren_updt (struct thread *child){
  struct process *prc = fetch_child_process (child->parent, child->tid);

  if (prc == NULL)
    return;

  prc->exit_status = child->exit_status;
  sema_up (&prc->wait);
}

/* The load status of the current process's file is sent to parent*/
void paren_updt_status (struct thread *child, enum load_status status){
  struct process *prc = fetch_child_process (child->parent, child->tid);

  if (prc == NULL)
    return;

  prc->load_status = status;
  sema_up (&prc->load);
}
