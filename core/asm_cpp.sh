#!/bin/bash
cpp  -I$(pwd){,/linux,/x86,/lib} -Ddynamorio_EXPORTS -E $1 -o $2
sed 's/@N@/\n/g' x86.S
