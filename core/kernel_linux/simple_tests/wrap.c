#include <linux/module.h>

int
wrap_main1(int a1, int a2, int a3, int a4, int a5, int a6)
{
    return a1 + a2 + a3 + a4 + a5 + a6;
}
EXPORT_SYMBOL_GPL(wrap_main1);

int
wrap_main2(int a1, int a2, int a3, int a4, int a5, int a6)
{
    return a1 * a2 * a3 * a4 * a5 * a6;
}
EXPORT_SYMBOL_GPL(wrap_main2);
