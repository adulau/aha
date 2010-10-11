#ifndef AHA
#define AHA
#define AHA_DEBUG
#include "linux/kernel.h" /* printk is declared there */
#include "linux/stddef.h"
#include "linux/ptrace.h" /* access to kmalloc */
#include "os.h"
#include "linux/delay.h"
#include "aha-defs.h"
#define MAX_DUMP_BUF 1024
struct ReplyMessage{
    int block;
    int exitcode;
    int substitue;
    int insult;
};

#define EXECVE_MESSAGE 1
#define CLONE_MESSAGE  2
#define EXIT_MESSAGE   3
#ifdef AHA_DEBUG
    #define AHA_PRINTK(args...) printk(args)
#else
    #define AHA_PRINTK(...)
#endif
int aha_create_filename(char *fn, int size);
char* aha_dump_execve(char __user *file, char __user *__user *argv,\
        char __user *__user *env);

void aha_handle_insult_messages(struct ReplyMessage *msg, char __user* file,\
                            char __user* __user* argv);
void aha_get_reply_message(char* key, struct ReplyMessage *msg);
void aha_record_sys_clone(int pid, int ppid);
void aha_dump_exits(void);
#endif
