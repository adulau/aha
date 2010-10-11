
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

/* Internal function for aha_dump_execve
 *
 * int fd     Open file descritor
 * char buf   Buffer that should be written in the file descritor
 * int cnt    The number that should be written
 * int size   Size of the buffer
 */
inline void __aha_os_write_file_ck(int fd, char* buf, int size, int cnt)
{
    if ((cnt > 0) & (cnt < size)){
        os_write_file(fd,buf,cnt);
    } else {
        AHA_PRINTK("Cannot write. buffer is too small size = %d cnt=%d, \
                   fd=%d\n", size, cnt,fd);
    }
}

/* Log PIDs and PPID
 * int fd     Open file descriptor
 * char buff  A buffer for storing the messages
 * int size   The buffer size
 */
inline void __aha_dump_pid_ppids(int fd, char* buf, int size)
{
    struct task_struct *tsk;
    int cnt;
    tsk = current;
    cnt = snprintf(buf,size,"pid=%d\n",tsk->pid);
    AHA_PRINTK("__aha_dump_pid_ppids\n");
    __aha_os_write_file_ck(fd,buf,size,cnt);
    cnt = snprintf(buf,size,"ppid=%d\n",tsk->parent->pid);
    __aha_os_write_file_ck(fd,buf,size,cnt);
    cnt = snprintf(buf,size,"rppid=%d\n",tsk->real_parent->pid);
    __aha_os_write_file_ck(fd,buf,size,cnt);
}

inline void  __aha_set_done_tag(int fd, char* buf,int size)
{
    int cnt;
    /* FIXME the MAGIC word is not escaped it could emerge as argument */
    cnt = snprintf(buf,size,"DONE=1\n");
    AHA_PRINTK("__aha_set_done_tag\n");
    __aha_os_write_file_ck(fd,buf,size,cnt);

}

inline void  __aha_set_type_tag(int fd, char* buf,int size,int tag)
{
    int cnt; /* May break inline but makes code more readable */
    /* FIXME Espacing is not done */
    cnt = snprintf(buf,size,"type=%d\n",tag);
    AHA_PRINTK("__aha_set_type_tag\n");
     __aha_os_write_file_ck(fd,buf,size,cnt);


}


inline void __aha_dump_str_array(int fd, char** argv,char*id, char* p, char*q)
{
    char* a;
    int cnt;
    AHA_PRINTK("__aha_dump_str_array\n");
    for (;;) {
        if (get_user(a,argv))
            break;
            if (!a)
                break;
            if (strncpy_from_user(p,a, (MAX_DUMP_BUF / 2) - 4  ) > 0) {
                cnt=snprintf(q,MAX_DUMP_BUF,"%s=%s\n",id,p);
                __aha_os_write_file_ck(fd,q,MAX_DUMP_BUF,cnt);
            }
            argv++;
    }
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
    char *p, *q, *r;
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
    if ((fd = os_open_file(p,flg,mode))<0)
        return NULL;
    /* Set message type */
    __aha_set_type_tag(fd,p,MAX_DUMP_BUF,EXECVE_MESSAGE);
    /* Dump the file from execve */
    if (strncpy_from_user(p,file,MAX_DUMP_BUF) > 0){
     cnt = snprintf((char*)q,MAX_DUMP_BUF,"file=%s\n",p);
     __aha_os_write_file_ck(fd,q,MAX_DUMP_BUF,cnt);
    }
   __aha_dump_str_array(fd,argv,"argument",p,q);
   __aha_dump_str_array(fd,env,"env",p,q);
   __aha_dump_pid_ppids(fd,q,MAX_DUMP_BUF);
    __aha_set_done_tag(fd,q,MAX_DUMP_BUF);
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

/*
 * Get the reply message from AHA daemon
 *
 * Key is the pure filename without queue prefix
 * msg is the prior allocated buffer for reply message which is mofified by
 *     the function
 */
void aha_get_reply_message(char* key, struct ReplyMessage *msg)
{
    int fd,size;
    char filename[128];
    filename[0]=0;

    snprintf((char*)filename,128,"in/%s",key);
    /* Give AHA the time to write the reply */
    msleep_interruptible(__aha_poll_delay);
    fd = os_open_file(filename, of_read(OPENFLAGS()), 0);
    if ( fd < 0 ) {
        AHA_PRINTK("Could not open reply file: %s\n",filename);
        return;
    }

    size = os_read_file(fd,msg,sizeof(struct ReplyMessage));
    /* Make sure that we got a complete message */
    if (size == sizeof(struct ReplyMessage)){
        AHA_PRINTK("AHA (%s) told me to ...\n",key);
        AHA_PRINTK("block %d\n",msg->block);
        AHA_PRINTK("exitcode: %d\n",msg->exitcode);
        AHA_PRINTK("substitue: %d\n",msg->substitue);
        AHA_PRINTK("insult:%d\n",msg->insult);
    } else
        AHA_PRINTK("The message %s is corrupted. Got only %d bytes\n",filename,
                   size);

    os_close_file(fd);
}

void aha_record_sys_clone(int pid, int ppid)
{
    #define filename__size 32
    #define buf__size 64
    char filename[filename__size];
    struct openflags flg;
    char buf[buf__size];
    int fd,cnt;
    int mode = 0644;
    flg.w = 1;
    flg.c = 1;
    cnt = 0;
    AHA_PRINTK("aha_record_sys_clone\n");
    aha_create_filename((char*)&filename,filename__size);
    snprintf((char*)&buf, buf__size,"out/%s",filename);
    fd = os_open_file(buf,flg,mode);
    if (fd > 0){
        __aha_set_type_tag(fd,(char*)&buf,buf__size,CLONE_MESSAGE);
        cnt = snprintf((char*)&buf,buf__size,"pid=%d\n",pid);
        __aha_os_write_file_ck(fd,buf,buf__size,cnt);
        cnt = snprintf((char*)&buf,buf__size,"ppid=%d\n",ppid);
        __aha_os_write_file_ck(fd,(char*)&buf,buf__size,cnt);
        __aha_set_done_tag(fd,(char*)&buf,buf__size);
        os_close_file(fd);
    }else{
        AHA_PRINTK("rec_sys_clone: Failed to open file %s\n",buf);
    }
    #undef filename__size
    #undef buf__size
}

/* Tracks if a thread exits, aiming to free up pids in the process trees
 * Process trees are internally read fronm task_struct
 */
void aha_dump_exits(void)
{
    int mode = 0644;
    int fd;
    struct openflags flg;
    char filename[32];
    char qn[64];
    char buf[16];
    flg.w = 1;
    flg.c = 1;
    if (aha_create_filename((char*)&filename,32)>0){
        /* Put message in output queue */
        if (snprintf((char*)&qn,64,"out/%s",filename)>0){
            if ((fd = os_open_file(qn,flg,mode))>0){
                __aha_set_type_tag(fd,(char*)&buf,16,EXIT_MESSAGE);
                __aha_dump_pid_ppids(fd,(char*)&buf,16);
                __aha_set_done_tag (fd,(char*)&buf,16);
                os_close_file(fd);
            }
        }else{
            AHA_PRINTK("record-exit: Could not put filename in output queue\n");
        }
    }else{
        AHA_PRINTK("record-exit: No filename could be generated\n");
    }
}

