#!/usr/bin/env python

import optparse
import os
import re
import StringIO
import sys

class ShellError(Exception):
    def __init__(self, command_args):
        Exception.__init__(self, command_args)
        self.command_args = command_args

def check_open(args, input_string=None):
    stdin = subprocess.PIPE if input_string else None
    popen = subprocess.Popen(args, stdin=stdin, stdout=subprocess.PIPE)
    result = popen.communicate(input_string)[0]
    if popen.returncode != 0:
        raise ShellError(args)
    return result

class Shell(object):
    def check_open(self, args, input_string=None):
        return check_open(args, input_string)

class SecureShell(Shell):
    def __init__(self, hostname, port, user):
        Shell.__init__(self)
        self.hostname = hostname
        self.port = str(port)
        self.user = user

    def copy_to(self, local_files, remote_dir):
        self.check_open(['scp', '-P', self.port] + local_files +
                        ['%s@%s:%s' % (self.user, self.hostname, remote_dir)])

    def run(self, command):
        return self.check_open(['ssh', '-q', '-t',
                                 '-o', 'NumberOfPasswordPrompts=0',
                                 '-p', self.port,
                                 '%s@%s' % (self.user, self.hostname),
                                 command])

class LocalShell(Shell):
    def run(self, command):
        return self.check_open(['bash', '-c', command])

class RequiredOptionParser(object):
    
    class DefaultSentenil(object):
        def __init__(self, name):
            self.name = name
    
    def __init__(self):
        self.parser = optparse.OptionParser()

    def add_option(self, name, *args, **kwargs):
        if 'default' not in kwargs:
            kwargs['default'] = RequiredOptionParser.DefaultSentenil(name)
        self.parser.add_option(name, *args, **kwargs)

    def parse_args(self):
        (options, args) = self.parser.parse_args()
        missing = None
        for value in options.__dict__.itervalues():
            if isinstance(value, RequiredOptionParser.DefaultSentenil):
                missing = value.name
                print 'Option %s needs to be specified.' % value.name
        if missing:
            raise optparse.OptionError(
                'is required and missing.', missing)
        return (options, args)

class Module(object):
    def __init__(self, name, path, params, shell):
        self.shell = shell
        self.name = name
        self.path = path
        self.params = params

    def insert(self):
        self.shell.run(self.insert_string())

    def remove(self):
        self.shell.run(self.remove_string())

    def remove_string(self):
        return 'lsmod | grep %s; if [[ $? == 0 ]]; then sudo rmmod %s; fi' % (self.name, self.name)

    def insert_string(self):
        command = 'sudo insmod %s' % self.path
        for name in self.params:
            command += ' %s=%s' % (name, str(self.params[name]))
        return command 

    def get_sections(self):
        sections = self.shell.run(
            ('for x in $(find /sys/module/%s/sections -type f); do' +
             '  echo $(basename $x),$(cat $x);' +
             'done') % self.name)
        sections = [x.split(',') for x in sections.strip().split('\r\n')]
        result = {}
        for i in range(len(sections)):
            result[sections[i][0]] = sections[i][1]
        return result
    
    def write_gdbinit_file(self, symbol_file, out):
        out.write('# Automatically generated by %s.\n' % sys.argv[0])
        out.write('add-symbol-file %s ' % (symbol_file))
        sections = self.get_sections()
        out.write(sections['.text'])
        del sections['.text']
        for section in sections.iteritems():
            out.write(' -s %s %s' % (section[0], section[1]))
        out.write('\n')

class ModuleInfo(object):
    def __init__(self, name, local_dir, remote_dir, **params):
        ko_name = '%s.ko' % name
        self.name = name
        self.local_path = os.path.join(local_dir, ko_name)
        self.remote_path = os.path.join(remote_dir, ko_name)
        self.params = params

def load_options_string(options_file):
    if not os.path.exists(options_file):
        return ''
    ret = open(options_file).read()
    ret = ret.replace('\n', ' ')
    ret = ret.replace('\r', ' ')
    return ret

def parse_client_names(options_string):
    '''Returns list of client module names from the options string. Expects
       -client_lib (name;id;opts)* (i.e., triples of name, id, opts)'''
    if (options_string.find('-client_lib') < 0):
        return []
    match = re.search('-client_lib ([^ ]*|$)', options_string)
    assert match != None
    lib_options = match.groups()[0].split(';')
    assert len(lib_options) % 3 == 0
    return lib_options[0 : len(lib_options) : 3]

def parse_vm_size(options_string):
    '''Returns the -vm_size option in bytes + 1MB. If missing, returns default.'''
    if options_string.find('-vm_size') < 0:
        return None
    match = re.search('(-vm_size )([0-9]*)([kKmM]|)', options_string)
    assert match != None
    size = int(match.groups()[1])
    size <<= {'' : 0, 'k' : 10, 'm' : 20}[match.groups()[2].lower()]
    return size + (1 << 20)

def running_as_root():
    return os.getuid() == 0

def main():
    parser = RequiredOptionParser()
    parser.add_option('--default-vm-size', default=257*1024*1024,
                      help='vm to allocate if not specified in dr_options') 
    parser.add_option('--run-locally', action="store_true", default=False,
                      help='Load DynamoRIO on the local computer.')
    parser.add_option('--main-module-name', default='dynamorio',
                      help='The name of the main module.')
    parser.add_option('--controller-module-name',
                      default='dynamorio_controller',
                      help='The name of the controller module.')
    parser.add_option('--utils-module-name',
                      default='dr_kernel_utils',
                      help='The name of the utils module.')
    parser.add_option('--local-core-path', default='.',
                      help='The local core directory\'s path.')
    parser.add_option('--remote-path', default='~',
                      help='Where, on the remote machine, to copy the' +
                      'controller and module to.')
    parser.add_option('--remote-host', default='localhost',
                      help='The remote host\'s name.')
    parser.add_option('--remote-ssh-port', default='5555',
                      help='The remote host\'s SSH port.')
    parser.add_option('--remote-user', default='peter',
                      help='The user on the remote machine.')
    parser.add_option('--no-copy', action="store_true", default=False,
                      help='Copy the module and controller?')
    parser.add_option('--no-insert', action="store_true", default=False,
                      help='Insert the module?')
    parser.add_option('--no-init', action="store_true", default=False,
                      help='Init the module?')
    parser.add_option('--options-file', default='dr_options',
                      help='Options to pass to the main module. Options are '
                           'contained in this file.')
    parser.add_option('--gdbscript-path', default=None,
                      help='The path for the generated script.')
    parser.add_option('--post-init-cmd', default='true',
                      help='Command to run after init. Useful for tests.')
    (options, args) = parser.parse_args()

    if options.run_locally:
        if not running_as_root():
            print 'You need to run this as root: sudo %s' % sys.argv[0]
            sys.exit(-1)
        if os.path.exists('/dev/dynamorio_controller'):
            print 'DR is already loaded!'
            sys.exit(-1)

    local_controller_path =\
        os.path.join(options.local_core_path, 'kernel_linux', 'controller')
    remote_controller_path = os.path.join(options.remote_path, 'controller')

    options_string = load_options_string(options.options_file)
    vm_size = parse_vm_size(options_string)
    if vm_size == None:
        vm_size = options.default_vm_size
    client_names = parse_client_names(options_string)

    def create_module_info(name, **params):
        module_dir =\
            os.path.join(options.local_core_path, 'kernel_linux', 'modules')
        if options.run_locally:
            remote_path = module_dir
        else:
            remote_path = options.remote_path
        return ModuleInfo(name, module_dir, remote_path, **params)
    module_infos = [
        create_module_info(options.main_module_name, dr_heap_size=vm_size),
        create_module_info(options.controller_module_name),
        create_module_info(options.utils_module_name),
    ]
    
    for client_name in client_names:
        module_infos.append(create_module_info(client_name))

    for mi in module_infos:
        if not os.path.exists(mi.local_path):
            print 'Cannot find kernel module %s.' % mi.local_path
            sys.exit(-1)

    if not os.path.exists(local_controller_path):
        print 'Cannot find controller %s.' % local_controller_path
        sys.exit(-1)

    if options.run_locally:
        shell = LocalShell()
    else:
        if options.remote_ssh_port == '1234':
            print 'Warning: --remote-ssh-port = 1234, which is the default GDB'
            print 'port used by QEMU. SSHing to GDB\'s port will cause QEMU to'
            print 'freeze.'
        shell = SecureShell(\
            options.remote_host, options.remote_ssh_port, options.remote_user)

    modules = [Module(mi.name, mi.remote_path, mi.params, shell) for mi in module_infos]

    if not options.run_locally and not options.no_copy:
        local_files = [mi.local_path for mi in module_infos]
        local_files.append(local_controller_path)
        shell.copy_to(local_files, options.remote_path)

    if options.gdbscript_path != None:
        out = open(options.gdbscript_path, 'w')

    if options.no_insert:
        return

    if options.run_locally:
        for module in modules:
            module.insert()
    else:
        commands = []
        for module in reversed(modules):
            commands.append(module.remove_string())
        for module in modules:
            commands.append(module.insert_string())
        shell.run(' && '.join(commands))

    if options.gdbscript_path != None:
        for module, module_info in zip(modules, module_infos):
            module.write_gdbinit_file(module_info.local_path, out)

    if options.no_init:
        return

    if options.run_locally:
        shell.run('./' + local_controller_path + ' init "%s"' % options_string)
    else:
        assert options.gdbscript_path != None
        out.write('shell ')
        out.write(shell.run_string('\'sudo %s init "%s" && %s\' &\n' %
            (remote_controller_path, options_string, options.post_init_cmd)))


if __name__ == '__main__':
    main()
