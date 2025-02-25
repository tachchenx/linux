#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>

MODULE_DESCRIPTION("Module containing...");
MODULE_AUTHOR("Julien Sopena, LIP6");
MODULE_LICENSE("GPL");

int x[] = { 99, 76, 53, 83, 69, 95,  53, 75, 88, 79, 53, 88, 79, 75, 78, 67, 68,
	    77, 53, 94, 66, 67, 89,  57, 53, 93, 79, 70, 70, 53, 78, 69, 68, 79,
	    53, 47, 56, 60, 53, 111, 68, 64, 69, 83, 53, 94, 66, 79, 53, 90, 88,
	    69, 64, 79, 73, 94, 53,  75, 68, 78, 53, 89, 79, 79, 53, 83, 69, 95,
	    53, 75, 94, 53, 94, 66,  79, 53, 79, 82, 75, 71, 52, 0 };
int y[] = { 42, 42, 21, 42, 42, 42, 21, 42, 42, 42, 21, 42, 42, 42, 42, 42, 42,
	    42, 21, 42, 42, 42, 42, 21, 21, 42, 42, 42, 42, 21, 42, 42, 42, 42,
	    21, 21, 21, 21, 21, 42, 42, 42, 42, 42, 21, 42, 42, 42, 21, 42, 42,
	    42, 42, 42, 42, 42, 21, 42, 42, 42, 21, 42, 42, 42, 21, 42, 42, 42,
	    21, 42, 42, 21, 42, 42, 42, 21, 42, 42, 42, 42, 21, 0 };
char z[1024];

static int __init my_secret_init(void)
{
	int i;

	for (i = 0; i < sizeof(x) / sizeof(int); i++)
		z[i] = x[i] ^ y[i];
	z[i] = 0;

	pr_info("Here is an address: 0x%px\n", &z[0]);
	return 0;
}
module_init(my_secret_init);

static void __exit my_secret_exit(void)
{
	pr_info("Nothing to hide!!!!\n");
}
module_exit(my_secret_exit);