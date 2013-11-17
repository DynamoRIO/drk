#!/usr/bin/env python

import re
import sys
import subprocess

# TODO(peter): I copied this function from debugging/setup_gdb.py. This code
# should be unified.
def check_open(args):
    popen = subprocess.Popen(args, stdout=subprocess.PIPE)
    result = popen.communicate()[0]
    assert popen.returncode == 0
    return result

def main():
    assert len(sys.argv) == 2
    code = check_open(['cpp', '-fdirectives-only', '-fpreprocessed', '-dD', sys.argv[1]])
    matches = re.findall('(\s*#\s*define\s+)([a-zA-Z_0-9]+)(.*)', code)
    for match in matches:
        print '-D%s' % match[1],

if __name__ == '__main__':
    main()
