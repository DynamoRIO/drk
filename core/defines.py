#!/usr/bin/env python3

import re
import sys
import subprocess


def check_open(args):
    popen = subprocess.Popen(args, stdout=subprocess.PIPE, text=True)
    result = popen.communicate()[0]
    assert popen.returncode == 0
    return result


def main():
    assert len(sys.argv) == 2
    code = check_open(
        ["cpp", "-fdirectives-only", "-fpreprocessed", "-dD", sys.argv[1]]
    )
    matches = re.findall("(\s*#\s*define\s+)([a-zA-Z_0-9]+)(.*)", code)
    for match in matches:
        print(f"-D{match[1]}", end=" ")


if __name__ == "__main__":
    main()
