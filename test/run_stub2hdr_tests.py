#!/usr/bin/env python
#-------------------------------------------------------------------------------
# test/run_stub2hdr_tests.py
#
# Automatic test runner for stub2hdr
#
# Will Denissen
# This code is in the public domain
#-------------------------------------------------------------------------------
import argparse
import logging
from multiprocessing import Pool
import os
import sys
import time

from utils import run_exe, is_in_rootdir, dump_output_to_temp_files

# Make it possible to run this file from the root dir of pyelftools without
# installing pyelftools; useful for CI testing, etc.
sys.path[0:0] = ['.']

# Create a global logger object
testlog = logging.getLogger('run_tests')
testlog.setLevel(logging.DEBUG)
testlog.addHandler(logging.StreamHandler(sys.stdout))

def discover_testfiles(rootdir):
    """ Discover test files in the given directory. Yield them one by one.
    """
    for filename in os.listdir(rootdir):
        _, ext = os.path.splitext(filename)
        if ext in ('.o', '.a', '.so'):
            yield os.path.join(rootdir, filename)


def get_ref_base(inp_file):
    ref_base, _ = os.path.splitext(os.path.basename(inp_file))
    return ref_base

def run_test_on_file(inp_file, root_dir, verbose=False):
    """ Runs a test on the given input filename.
    """
    testlog.info("Test file '%s'" % inp_file)

    exe_path = 'scripts/stub2hdr.py'
    ref_base = get_ref_base(inp_file)
    out_file = '%s/out/%s.h' % (root_dir, ref_base)
    ref_file = '%s/ref/%s.h' % (root_dir, ref_base)

    args = ['-o' , out_file, inp_file]
    cmd = '%s -o %s %s' % (exe_path, out_file, inp_file) 

    if verbose: testlog.info("....executing: %s" % cmd)
    t1 = time.time()
    rc, out_ = run_exe(exe_path, args)
    if verbose: testlog.info("....elapsed: %s" % (time.time() - t1,))
    if rc != 0:
        testlog.error("@@ aborting - '%s' returned '%s'" % (cmd, rc))
        return False

    if verbose: testlog.info('....comparing output...')
    t1 = time.time()
    rc, errmsg = compare_files(out_file, ref_file)
    if verbose: testlog.info("....elapsed: %s" % (time.time() - t1,))
    if rc:
        if verbose: testlog.info('.......................SUCCESS')
    else:
        testlog.info('.......................FAIL')
        testlog.info('....for file %s' % inp_file)
        testlog.info('....Output #1 is reference, Output #2 is stub2hdr')
        testlog.info('@@ ' + errmsg)
        return False

    return True


def compare_files(ref_file, out_file):
    """ Compare output file and reference file.
        Return pair success, errmsg. If comparison succeeds, success is True
        and errmsg is empty. Otherwise success is False and errmsg holds a
        description of the mismatch.
    """

    try:
        with open(out_file) as ofil, open(ref_file) as rfil:
            if ofil.read() != rfil.read():
                return True, ''
            else:
                return False, 'output %s and reference %s differ' %(out_file, ref_file)
    except IOError as exc:
        return False, str(exc)


def main():
    if not is_in_rootdir():
        testlog.error('Error: Please run me from the root dir of pyelftools!')
        return 1

    argparser = argparse.ArgumentParser(
        usage='usage: %(prog)s [options] [file] [file] ...',
        prog='run_stub2hdr_tests.py')
    argparser.add_argument('files', nargs='*', help='files to run tests on')
    argparser.add_argument(
        '--parallel', action='store_true',
        help='run tests in parallel; always runs all tests w/o verbose')
    argparser.add_argument('-V', '--verbose',
                           action='store_true', dest='verbose',
                           help='verbose output')
    argparser.add_argument(
        '-k', '--keep-going',
        action='store_true', dest='keep_going',
        help="Run all tests, don't stop at the first failure")
    args = argparser.parse_args()

    if args.parallel:
        if args.verbose or args.keep_going == False:
            print('WARNING: parallel mode disables verbosity and always keeps going')

    if args.verbose:
        testlog.info('Running in verbose mode')
        testlog.info('Python executable = %s' % sys.executable)
        testlog.info('Given list of files: %s' % args.files)


    root_dir = 'test/testfiles_for_stub2hdr'
    # If file names are given as command-line arguments, only these files
    # are taken as inputs. Otherwise, autodiscovery is performed.
    if len(args.files) > 0:
        filenames = args.files
    else:
        filenames = sorted(discover_testfiles('%s/inp' % root_dir))

    if len(filenames) > 1 and args.parallel:
        pool = Pool()
        results = pool.map(run_test_on_file, filenames)
        failures = results.count(False)
    else:
        failures = 0
        for filename in filenames:
            if not run_test_on_file(filename, root_dir, args.verbose):
                failures += 1
                if not args.keep_going:
                    break

    if failures == 0:
        testlog.info('\nConclusion: SUCCESS')
        return 0
    elif args.keep_going:
        testlog.info('\nConclusion: FAIL ({}/{})'.format(
            failures, len(filenames)))
        return 1
    else:
        testlog.info('\nConclusion: FAIL')
        return 1


if __name__ == '__main__':
    sys.exit(main())
