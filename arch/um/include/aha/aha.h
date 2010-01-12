#ifndef AHA
#define AHA
/*FIXME use AHA name space */
#define MAX_DUMP_BUF 512
struct ReplyMessage{
    int block;
    int exitcode;
    int substitue;
    int insult;
};

extern void aha_test(void);
#endif
