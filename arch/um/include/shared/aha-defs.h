#ifndef __AHA_DEFS__
#define __AHA_DEFS__
/* Global variables used for the aha framework */

/* Polling delay for sys_execve. AHA polls the permissions for each system call.
 * The delay must be expressed in ms
 * This delay is read once in the main from the conf/polldelay file. Thus one
 * write. Each sys_execve calls read then this global variable
 */
extern int __aha_poll_delay;
#define AHA_DEF_POLL_DELAY 100
#endif
