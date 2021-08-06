/*
 * Insulting program that should be installed on the honeypot.
 * The kernel then swaps the filename for do_execve with this one
 *
 * (c) 2010 Gerard Wagener
 * LICENSE GPL
 */
#include <stdio.h>
#include <stdlib.h>
#define N 5

/* The element 0 is reserved for that insult is not set and if the program is
 * started from the shell with no arguments nothing should happen
 * atoi(sss) -> 0
 */
char* list[] = {"",
                "Fuck you",
               "Is that all? I want to do more ...",
               "Go away",
               "I love you"};

int main(int argc, char* argv[]){
    int idx;
    /* If another argv is used, then maybe only argv[0] is allocated when
     * no command lines are delivered. Therefore the kernel overwrites this
     * to avoid to allocate / smash the stack
     */
     idx=atoi(argv[0]);
     if ((idx>=0) && (idx<N))
        printf("%s\n",list[idx]);
     return 0;
}

