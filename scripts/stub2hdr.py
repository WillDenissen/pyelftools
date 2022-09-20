#!/usr/bin/env python
#-------------------------------------------------------------------------------
# scripts/stub2header.py
#
#
# Will Denissen
# This code is in the public domain
#-------------------------------------------------------------------------------
import argparse
import sys

# For running from development directory. It should take precedence over the
# installed pyelftools.
sys.path.insert(0, '.')

from elftools import __version__
from elftools.elf.elffile import ELFFile
from elftools.dwarf.datatype_cpp import describe_cpp_datatype

class DumpHeader:

    def __init__(self, ifile, ofile):
        """ dump header from the .debug_info section.
            ifile:
                input stream to read from

            ofile:
                output stream to write to
        """
        self.ifile = ifile
        self.ofile = ofile

    def dump_die(self, die, lvl = 0):
        """ A recursive function for showing information about a DIE and its
            children.
            die:
                die to dump from
            lvl:
                indentation level 
        """
        self.emit('%*s%s' % (lvl, '  ', die))
        self.emit('Type: %s' % describe_cpp_datatype(die))

        for cdie in die.iter_children():
            self.dump_die(cdie, lvl + 1)

    def dump_header(self):
        """ dump header from the elffile.
        """
        elffile = ELFFile(self.ifile)

        if not elffile.has_dwarf_info():
            print('  file has no DWARF info')
            sys.exit(1)

        # get_dwarf_info returns a DWARFInfo context object, which is the
        # starting point for all DWARF-based processing in pyelftools.
        dwarfinfo = elffile.get_dwarf_info()

        for cu in dwarfinfo.iter_CUs():
            self.emit(cu)
            if cu['version'] >= 5:
                unit_type = cu.header.unit_type
                if unit_type == 'DW_UT_type':
                    guard = 'Type_%x' % cu['type_signature'] 
                    self.emit('#ifndef %s' % guard)
                    self.emit('#define %s' % guard)
                    self.dump_die(cu.get_top_DIE())
                    self.emit('#endif')
                elif unit_type == 'DW_UT_compile':
                    self.dump_die(cu.get_top_DIE())
                else:
                    raise NotImplementedError("Only DW_UT_type and DW_UT_compile are supported")
            else:
                raise NotImplementedError("Only DWARF version >= 5 is supported")

    def emit(self, str):
        print(str, file = self.ofile)

SCRIPT_DESCRIPTION = 'Extract header file from an ELF/DWARF formatted stub file'
VERSION_STRING = '%%(prog)s: based on pyelftools %s' % __version__

def main(stream=None):
    argparser = argparse.ArgumentParser(
            # usage='%(prog)s [options] <elf/dwarf-stubfile>',
            description=SCRIPT_DESCRIPTION,
            prog='readelf.py')
    argparser.add_argument('-v', '--version',
            action='version', version=VERSION_STRING)
    argparser.add_argument('-o', 
            dest = 'ofile',
            help='output header file')
    argparser.add_argument( 
            dest = 'ifile',
            help='input ELF/DWARFv5 stubfile')
    args = argparser.parse_args()

    if not args.ifile:
        argparser.print_help()
        return

    print('Processing file:', args.ifile)
    ofile = open(args.ofile, 'w') if args.ofile else sys.stdout
    with open(args.ifile, 'rb') as ifile:
        dumper = DumpHeader(ifile, ofile)
        dumper.dump_header()


def profile_main():
    # Run 'main' redirecting its output to readelfout.txt
    # Saves profiling information in readelf.profile
    PROFFILE = 'readelf.profile'
    import cProfile
    cProfile.run('main(open("readelfout.txt", "w"))', PROFFILE)

    # Dig in some profiling stats
    import pstats
    p = pstats.Stats(PROFFILE)
    p.sort_stats('cumulative').print_stats(25)


#-------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
    #profile_main()
