/*
 * Copyright (C) 2000 - 2007 Jeff Dike (jdike@{addtoit,linux.intel}.com)
 * Licensed under the GPL
 */

#include "linux/stddef.h"
#include "linux/fs.h"
#include "linux/smp_lock.h"
#include "linux/ptrace.h"
#include "linux/sched.h"
#include "asm/current.h"
#include "asm/processor.h"
#include "asm/uaccess.h"
#include "as-layout.h"
#include "mem_user.h"
#include "skas.h"
#include "os.h"
#include "internal.h"
#include "aha.h"
#include "os.h"
void flush_thread(void)
{
	void *data = NULL;
	int ret;

	arch_flush_thread(&current->thread.arch);

	ret = unmap(&current->mm->context.id, 0, STUB_START, 0, &data);
	ret = ret || unmap(&current->mm->context.id, STUB_END,
			   host_task_size - STUB_END, 1, &data);
	if (ret) {
		printk(KERN_ERR "flush_thread - clearing address space failed, "
		       "err = %d\n", ret);
		force_sig(SIGKILL, current);
	}

	__switch_mm(&current->mm->context.id);
}

void start_thread(struct pt_regs *regs, unsigned long eip, unsigned long esp)
{
	set_fs(USER_DS);
	PT_REGS_IP(regs) = eip;
	PT_REGS_SP(regs) = esp;
}

static long execve1(char *file, char __user * __user *argv,
		    char __user *__user *env)
{
	long error;

	error = do_execve(file, argv, env, &current->thread.regs);
	if (error == 0) {
		task_lock(current);
		current->ptrace &= ~PT_DTRACE;
#ifdef SUBARCH_EXECVE1
		SUBARCH_EXECVE1(&current->thread.regs.regs);
#endif
		task_unlock(current);
	}
	return error;
}

long um_execve(char *file, char __user *__user *argv, char __user *__user *env)
{
	long err;

	err = execve1(file, argv, env);
	if (!err)
		UML_LONGJMP(current->thread.exec_buf, 1);
	return err;
}

/*
 * Generate a "unique" file on the host operating system containing the
 * file name and arguments that are dumped.
 * My uuid hack wuuuurgs, performance bye bye it is already gone with the
 * massive amount of IO
 *
 * The filename is returned through parameters and the length of the string
 * is returned. On error negative value is returned. See snprintf
 */
int create_filename(char *fn, int size){
    int a,b;
    long ncycles;
    /* Query the processor cycles and concatenate it with a prefix */
    asm volatile("rdtsc" : "=a" (a), "=d" (b));
    ncycles =  ((long long )a|(long long)b<<32);
    /* Return the length of the string, negative value on failure */
    return snprintf(fn,size,"out/AHA_%lx.out",ncycles);
}


/*
 * Tansfers the file names and arguments to the host OS
 * The transfer via files is an good awfull solution.
 * The dumping is done in a best effort manner. If it succeds
 * to write all the data the tag / line DONE is at the end of the
 * file
 * TODO need to extract PID and PPID?
 */
void dump_execve(char __user *file, char __user *__user *argv,
        char __user *__user *env)
{
    char *p, *a, *q;
    struct openflags flg;
    int mode = 0644;
    int fd,cnt;

    flg.w = 1;
    flg.c = 1;
    cnt = 0;

    p = kmalloc(MAX_DUMP_BUF,GFP_KERNEL);
    q = kmalloc(MAX_DUMP_BUF, GFP_KERNEL);
    if (p && q) {
        if (create_filename(p,MAX_DUMP_BUF)<0)
            return;

        if ((fd = os_open_file(p,flg,mode))<0)
            return;

     /* Dump the file from execve */
        if (strncpy_from_user(p,file,MAX_DUMP_BUF) > 0){
            cnt = snprintf((char*)q,MAX_DUMP_BUF,"file=%s\n",p);
            if ((cnt>0) & (cnt < MAX_DUMP_BUF))
                os_write_file(fd,q,cnt);

        }
        /* Dump the arguments */
        for (;;) {
            if (get_user(a,argv))
                break;
            if (!a)
                break;
            if (strncpy_from_user(p,a, MAX_DUMP_BUF) > 0) {
                cnt=snprintf(q,MAX_DUMP_BUF,"argument=%s\n",p);
                if ((cnt>0) & (cnt<MAX_DUMP_BUF))
                    os_write_file(fd,q,cnt);

            }
            argv++;
        }
        /* FIXME the MAGIC word is not escaped it could emerge as argument */
        cnt = snprintf(q,cnt,"DONE\n");
        if ((cnt >0) & (cnt < MAX_DUMP_BUF))
            os_write_file(fd,q,cnt);
        os_close_file(fd);
        kfree(p);
        kfree(q);
    }
}

long sys_execve(char __user *file, char __user *__user *argv,
		char __user *__user *env)
{
	long error;
	char *filename;

    dump_execve(file,argv,env);
    lock_kernel();
	filename = getname(file);
	error = PTR_ERR(filename);
	if (IS_ERR(filename)) goto out;
	error = execve1(filename, argv, env);
	putname(filename);
 out:
	unlock_kernel();
	return error;
}
