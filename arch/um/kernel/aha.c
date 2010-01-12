#include "shared/aha.h"
void aha_test(void){
    char __user *arg;
    printk("Hello World\n");
}

void aha_test2(char __user* __user* argv){
    char *a;
    a = kmalloc(90, GFP_KERNEL);
}

