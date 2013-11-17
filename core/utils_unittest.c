typedef char bool;
#include <sys/types.h>
#include "configure.h"
#include "globals.h"
#include "configure_defines.h"
#include "utils.h"
#include <assert.h>

int main() {
	unsigned long x = 0x0fffffff40000000;
	unsigned int y = 4;
	unsigned char z = 4;
	assert(ALIGNED(x, y));
	assert(!ALIGNED(x + 1, y));
	assert(ALIGN_FORWARD(x, y) == x);
	assert(ALIGN_FORWARD_UINT(x, z) == 0x40000000);
	assert(ALIGN_FORWARD_UINT(x, y) == 0x40000000);
	assert(ALIGN_BACKWARD(x, y) == x);
    return 0;    
}
