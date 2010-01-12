#include "shared/aha.h"
/*
 * Generate a "unique" file on the host operating system containing the
 * file name and arguments that are dumped.
 * My uuid hack wuuuurgs, performance bye bye it is already gone with the
 * massive amount of IO
 *
 * The filename is returned through parameters and the length of the string
 * is returned. On error negative value is returned. See snprintf
 */
int aha_create_filename(char *fn, int size)
{
    int a,b;
    long ncycles;
    /* Query the processor cycles and concatenate it with a prefix */
    asm volatile("rdtsc" : "=a" (a), "=d" (b));
    ncycles =  ((long long )a|(long long)b<<32);
    /* Return the length of the string, negative value on failure */
    return snprintf(fn,size,"AHA_%lx.dat",ncycles);
}

inline void __aha_os_write_file_ck(int fd, char* buf, int cnt)
{
    if ((cnt > 0) & (cnt < MAX_DUMP_BUF)){
        os_write_file(fd,buf,cnt);
    }
}

/* Log PIDs and PPID */
inline void __aha_dump_pid_ppids(int fd,char* buf,int cnt)
{
    struct task_struct *tsk;
    tsk = current;
    cnt = snprintf(buf,MAX_DUMP_BUF,"pid=%d\n",tsk->pid);
    __aha_os_write_file_ck(fd,buf,cnt);
    cnt = snprintf(buf,MAX_DUMP_BUF,"ppid=%d\n",tsk->parent->pid);
    __aha_os_write_file_ck(fd,buf,cnt);
    cnt = snprintf(buf,MAX_DUMP_BUF,"rppid=%d\n",tsk->real_parent->pid);
    __aha_os_write_file_ck(fd,buf,cnt);
}

inline void  __aha_set_done_tag(int fd, char* buf,int cnt)
{
    /* FIXME the MAGIC word is not escaped it could emerge as argument */
    cnt = snprintf(buf,cnt,"DONE=1\n");
    __aha_os_write_file_ck(fd,buf,cnt);

}

 /* Tansfers the file names and arguments to the host OS
 * The transfer via files is an good awfull solution.
 * The dumping is done in a best effort manner. If it succeds
 * to write all the data the tag / line DONE is at the end of the
 * file
 * TODO clone system calls should be monitored true aiming to avoid disrupted
 * trees
 */
char* aha_dump_execve(char __user *file, char __user *__user *argv,
        char __user *__user *env)
{
    char *p, *a, *q, *r;
    int mode = 0644;
    int fd,cnt;
    struct openflags flg;
    r = NULL;
    flg.w = 1;
    flg.c = 1;

    /* Allocate memory once to win time */
    p = kmalloc(MAX_DUMP_BUF,GFP_KERNEL);
    q = kmalloc(MAX_DUMP_BUF, GFP_KERNEL);
    r = kmalloc(MAX_DUMP_BUF,GFP_KERNEL);
    if (!(p && q && r))
        return NULL;
    if (aha_create_filename(r,MAX_DUMP_BUF)<0)
        return NULL;
        /* Go into output queue */
    cnt=snprintf(p,MAX_DUMP_BUF,"out/%s",r);
    if ((cnt<0) | (cnt>MAX_DUMP_BUF))
        return NULL;
    if ((fd = os_open_file(p,flg,mode))<0)
        return NULL;

    /* Dump the file from execve */
    if (strncpy_from_user(p,file,MAX_DUMP_BUF) > 0){
     cnt = snprintf((char*)q,MAX_DUMP_BUF,"file=%s\n",p);
     __aha_os_write_file_ck(fd,q,cnt);
    }
    /* Dump the arguments */
    for (;;) {
        if (get_user(a,argv))
            break;
            if (!a)
                break;
            if (strncpy_from_user(p,a, MAX_DUMP_BUF) > 0) {
                cnt=snprintf(q,MAX_DUMP_BUF,"argument=%s\n",p);
                __aha_os_write_file_ck(fd,q,cnt);
            }
            argv++;
    }
    __aha_dump_pid_ppids(fd,q,cnt);
    __aha_set_done_tag(fd,q,cnt);
    os_close_file(fd);
    kfree(p);
    kfree(q);

    return r; /* Return the filename that was created */
}

void aha_handle_insult_messages(struct ReplyMessage *msg, char __user* file,
                            char __user* __user* argv)
{
    char buf[16];
    char* addr;
    int cnt;
    /* Simply swap the commands. Insult is a program in user - space that takes
     * as argv[0] an integer as argument which serves as index on a static
     * list of insults. argv[0] is overwritten to ensure that we do not smash
     * the stack if no other command line arguments are used.
     *
     * FIXME The environment is untouched?
     * FIXME I assume that argv[0] has 4 bytes. In worst case user application
     * crashes
     */

     if(!copy_to_user(file,"/sbin/insult",13)){
         cnt = snprintf((char*)&buf,16,"%d",msg->insult);
         if ((cnt > 0) && (cnt<16))
             if (!get_user(addr,argv))
                 copy_to_user(addr,buf,cnt+1); /* Copy 0 byte too */
      }
     /* The argument list should be already terminated by the other program */
}

void aha_get_reply_message(char* key, struct ReplyMessage *msg)
{
    int fd,size;
    char filename[128];
    filename[0]=0;
    snprintf((char*)filename,128,"in/%s",key);

    /* Give AHA the time to write the reply */
    msleep_interruptible(50);
    fd = os_open_file(filename, of_read(OPENFLAGS()), 0);
    if (fd <0){
        printk("Could not open reply file: %s\n",filename);
        return;
    }

    size = os_read_file(fd,msg,sizeof(struct ReplyMessage));
    /* Make sure that we got a complete message */
    if (size == sizeof(struct ReplyMessage)){
        printk("AHA (%s) told me to ...\n",key);
        printk("block %d\n",msg->block);
        printk("exitcode: %d\n",msg->exitcode);
        printk("substitue: %d\n",msg->substitue);
        printk("insult:%d\n",msg->insult);
    }else
        printk("The message %s is corrupted. Got only %d bytes\n",filename,
               size);

    os_close_file(fd);
}
