#!/usr/bin/env python

import os
import sys
import unittest

class ProgramTestCase(unittest.TestCase):
    def __init__(self, name, command):
        unittest.TestCase.__init__(self)
        self.name = name
        self.command = command

    @staticmethod
    def create_instance(name, command):
        '''Creates a new subclass of ProgramTest with given name. This is useful
        because TextTestRunner prints the test case's class name.'''
        new_class = type(name, (ProgramTestCase,), {})
        return new_class(name, command)

    def runTest(self):
        self.assertEqual(0, os.system(self.command))

    def id(self):
        return self.name

def program_test_suite():
    suite = unittest.TestSuite()
    for root, dirs, files in os.walk('.'):
        for file in files:
            path = os.path.join(root, file)
            if path.endswith('_unittest'):
                suite.addTest(ProgramTestCase.create_instance(file, path))
    return suite

def python_module_test_suite(name):
    return unittest.defaultTestLoader.loadTestsFromName(name)

def main():
    runner = unittest.TextTestRunner(verbosity=1)
    suite = unittest.TestSuite()
    suite.addTest(program_test_suite())
    runner.run(suite)

if __name__ == '__main__':
    main()
