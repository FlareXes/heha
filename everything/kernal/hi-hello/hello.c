// hello_kernel_module.c
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("A simple kernel module - Hello World with Parameters");

// Define a parameter variable with a default value
static char *who_to_greet = "kernel";
module_param(who_to_greet, charp, S_IRUGO); // Define the parameter and its type

static int __init hello_init(void) {
  printk(KERN_INFO "Hello, %s!\n", who_to_greet);
  return 0;
}

static void __exit hello_exit(void) {
  printk(KERN_INFO "Goodbye, %s!\n", who_to_greet);
}

module_init(hello_init);
module_exit(hello_exit);
