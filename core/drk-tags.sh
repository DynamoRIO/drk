#!/bin/bash
ctags-exuberant '--exclude=win32/*' '--exclude=*.S' '--exclude=exports.c'\
    '--exclude=lib/include/*'\
    '--regex-c=/([^ \t]+)[ \t]+VAR_IN_SECTION/\1/d,definition/'\
    '--regex-c=/DECLARE_[A-Z]*_VAR\(([^ \t,]*[\t ]+)*\**([^ ,]+),/\2/d,definition/'\
    '--regex-asm=/DECLARE_[A-Z_]*FUNC\((.+)\)/\1/d,definition/'\
    '--regex-asm=/#[ \t]*define[ \t]+([^( \t]+)/\1/d,definition/'\
    '--regex-c++=/OPTION_?[^(]*\([^,)]*,[ \t]*([^, )\t]+).*/\1/d,definition/'\
    -R .
