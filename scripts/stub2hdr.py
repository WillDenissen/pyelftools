#!/usr/bin/env python3
#-------------------------------------------------------------------------------
# scripts/stub2hdr.py
#
# Extracts a header file from a stubbed ELF (object/archive/shared object) file
# The stubbed ELF file must contain no implementations i.e:
#   - only uninitialized variables 
#   - empty function bodies
#
# Will Denissen
# This code is in the public domain
#-------------------------------------------------------------------------------
import argparse
import sys, os

# For running from development directory. It should take precedence over the
# installed pyelftools.
dev_dir = os.path.dirname(sys.argv[0]) + '/..'
sys.path.insert(0, dev_dir)

from elftools import __version__
from elftools.elf.elffile import ELFFile
from elftools.common.utils import bytes2str
from elftools.dwarf.enums import ENUM_DW_ATE

PROG = 'stub2hdr.py'

def pr_exit(self, die):
    print('ERROR: Stub files cannot contain dies of type %s' % die.tag)
    sys.exit(1)

def pr_skip(self, die):
    pass

def st_subrange(self, die):
    if 'DW_AT_upper_bound' in die.attributes:
        res = '[%s]' % (die.attributes['DW_AT_upper_bound'] + 1, )
    elif 'DW_AT_count' in die.attributes:
        res = '[%s]' % (die.attributes['DW_AT_upper_bound'], )
    else:
        res = '[]'

    return res

def st_dim(tdie):
    if DIE_has_attr(tdie, 'DW_AT_upper_bound'):
        return '[%s]' % (tdie.attributes['DW_AT_upper_bound'].value + 1,)
    if DIE_has_attr(tdie, 'DW_AT_count'):
        return '[%s]' % tdie.attributes['DW_AT_count'].value
    else:
        return '[]'

def st_array(tdie):
    txt = st_type(DIE_typeof(tdie))
    for dim in tdie.iter_children():
        if dim.tag == 'DW_TAG_subrange_type':
            txt += st_dim(dim)
    return txt


def st_attr_dflt(val):
    return '%s' % val

def st_attr_string(val):
  return bytes2str(val)

def st_attr_ref(val):
      return '<0x%x>' % val

def st_attr_hex(val):
  return '0x%x' % (val)


def st_attr_hex_addr(val):
  return '<0x%x>' % val


def st_attr_split_64bit(val):
  lo_w =  val        & 0xFFFFFFFF
  hi_w = (val >> 32) & 0xFFFFFFFF

  return '0x%x 0x%x' % (lo_w, hi_w)


def st_attr_block(val):
  s = '%s byte block: ' % len(val)
  s += ' '.join('%02x' % item for item in val)
  return s

# dispatch table for st_attr_<x>(val) functions
form2st_attr = dict(
  DW_FORM_ref1       = st_attr_ref,
  DW_FORM_ref2       = st_attr_ref,
  DW_FORM_ref4       = st_attr_ref,
  DW_FORM_ref8       = st_attr_ref,
  DW_FORM_ref_udata  = st_attr_ref,        
  DW_FORM_ref_addr   = st_attr_ref,
  DW_FORM_data4      = st_attr_dflt,
  DW_FORM_data8      = st_attr_dflt,
  DW_FORM_addr       = st_attr_hex,
  DW_FORM_sec_offset = st_attr_hex,
  DW_FORM_flag       = st_attr_dflt,
  DW_FORM_data1      = st_attr_dflt,
  DW_FORM_data2      = st_attr_dflt,
  DW_FORM_sdata      = st_attr_dflt,
  DW_FORM_udata      = st_attr_dflt,
  DW_FORM_string     = st_attr_string,
  DW_FORM_strp       = st_attr_string,
  DW_FORM_block1     = st_attr_block,
  DW_FORM_block2     = st_attr_block,
  DW_FORM_block4     = st_attr_block,
  DW_FORM_block      = st_attr_block,
)

def st_attr(die, aname):
    attr = die.attributes[aname]
    return form2st_attr.get(attr.form, st_attr_dflt)(attr.value) 

def DIE_typeof(die):
    return die.get_DIE_from_attribute('DW_AT_type') if DIE_has_type(die) else None

def DIE_has_name(die):
    return DIE_has_attr(die, 'DW_AT_name')

def DIE_has_type(die):
    return die and DIE_has_attr(die, 'DW_AT_type')
    
def DIE_has_attr(die, aname):
    return aname in die.attributes

def DIE_attr(die, aname):
    return die.attributes[aname]

def st_name(die):
    return st_attr(die, 'DW_AT_name')

def st_opt_name(die, default = '/* no name */'):
    return st_name(die) if DIE_has_name(die) else default

def st_base(tdie):
    return st_name(tdie)

def st_typedef(tdie):
    return st_name(tdie)

def st_enum(tdie):
    return 'enum %s' % st_name(tdie)

def st_struct(tdie):
    return 'struct %s' % st_name(tdie)

def st_union(tdie):
    return 'union %s' % st_name(tdie)

def st_const(tdie):
    return 'const ' + st_type(DIE_typeof(tdie))

def st_pointer(tdie):
    return '*' + st_type(DIE_typeof(tdie))

def st_reference(tdie):
    return '&' + st_type(DIE_typeof(tdie))

def st_subroutine(tdie):
    prms_st = ', '.join(st_type(pdie) for pdie in tdie.iter_children() 
    if pdie.tag in ('DW_TAG_formal_parameter', 'DW_TAG_unspecified_parameters') and not DIE_has_attr(pdie, 'DW_AT_artificial'))
    return '%s(%s)(%s)' % (st_type(DIE_typeof(tdie)), st_opt_name(tdie), prms_st)

def DIE_is_ptr_to_member_struct(tdie):
    if tdie.tag == 'DW_TAG_structure_type':
        members = tuple(die for die in tdie.iter_children() if die.tag == 'DW_TAG_member')
        return len(members) == 2 and st_opt_name(members[0]) == '__pfn' and st_opt_name(members[1]) == '__delta'
    return False


# dispatch table for st_type 
# contains st_<x>(die) -> string functions
# tags that cannot exist in a ELF stub will be mapped on st_exit
tag2st_func = dict(
  #DW_TAG_null                     =
  DW_TAG_array_type               = st_array,
  #DW_TAG_class_type               = st_class,
  #DW_TAG_entry_point              =
  DW_TAG_enumeration_type         = st_enum,
  #DW_TAG_formal_parameter         =
  #DW_TAG_imported_declaration     =
  #DW_TAG_label                    =
  #DW_TAG_lexical_block            =
  #DW_TAG_member                   =
  DW_TAG_pointer_type             = st_pointer,
  DW_TAG_reference_type           = st_reference,
  #DW_TAG_compile_unit             =
  #DW_TAG_string_type              =
  DW_TAG_structure_type           = st_struct,
  DW_TAG_subroutine_type          = st_subroutine,
  DW_TAG_typedef                  = st_typedef,
  DW_TAG_union_type               = st_union,
  #DW_TAG_unspecified_parameters   =
  #DW_TAG_variant                  =
  #DW_TAG_common_block             =
  #DW_TAG_common_inclusion         =
  #DW_TAG_inheritance              =
  #DW_TAG_inlined_subroutine       =
  #DW_TAG_module                   =
  #DW_TAG_ptr_to_member_type       =
  #DW_TAG_set_type                 =
  #DW_TAG_subrange_type            =
  #DW_TAG_with_stmt                =
  #DW_TAG_access_declaration       =
  DW_TAG_base_type                = st_base,
  #DW_TAG_catch_block              =
  DW_TAG_const_type               = st_const,
  #DW_TAG_constant                 =
  #DW_TAG_enumerator               =
  #DW_TAG_file_type                =
  #DW_TAG_friend                   =
  #DW_TAG_namelist                 =
  #DW_TAG_namelist_item            =
  #DW_TAG_namelist_items           =
  #DW_TAG_packed_type              =
  #DW_TAG_subprogram               =
  #DW_TAG_template_type_parameter  =
  #DW_TAG_template_type_param      =
  #DW_TAG_template_value_parameter =
  #DW_TAG_template_value_param     =
  #DW_TAG_thrown_type              =
  #DW_TAG_try_block                =
  #DW_TAG_variant_part             =
  #DW_TAG_variable                 =
  #DW_TAG_volatile_type            =
  #DW_TAG_dwarf_procedure          =
  #DW_TAG_restrict_type            =
  #DW_TAG_interface_type           =
  #DW_TAG_namespace                =
  #DW_TAG_imported_module          =
  #DW_TAG_unspecified_type         =
  #DW_TAG_partial_unit             =
  #DW_TAG_imported_unit            =
  #DW_TAG_mutable_type             =
  #DW_TAG_condition                =
  #DW_TAG_shared_type              =
  #DW_TAG_type_unit                =
  #DW_TAG_rvalue_reference_type    =
)

def st_type(tdie):
    if tdie == None:
        return 'void'
    if tdie.tag in tag2st_func:
        return tag2st_func[tdie.tag](tdie)
    return '/* tag: %s */' % tdie.tag

def pr_variable(self, die):
    tdie = DIE_typeof(die)
    self.pr_ln('%s %s;' % (st_type(tdie), st_name(die)))

def pr_typedef(self, die):
    tdie = DIE_typeof(die)
    self.pr_ln('typedef %s %s;' % (st_type(tdie), st_name(die)))

tag2usr_cls = dict(
    DW_TAG_structure_type = 'struct',
    DW_TAG_union_type     = 'union',
    DW_TAG_class_type     = 'class',
)

def pr_enumerator(self, die):
    name = st_name(die)
    if DIE_has_attr(die, 'DW_AT_const_value'):
        self.pr_ln('%-50s = %s' % (name, st_attr(die, 'DW_AT_const_value')))
    else:
        self.pr_ln('%-50s' % name)

def pr_enumeration_type(self, die):
    self.pr_ln('enum %s {' % st_opt_name(die))
    ch_l = [ch for ch in die.iter_children()]
    self.ind_lvl += 1
    for ch in ch_l:
        self.pr_def(ch)
        if ch != ch_l[-1]:
            self.pr(',')
    self.ind_lvl -= 1
    self.pr_ln('};')

def pr_user_type(self, die):
    # skip anonymous user types at outer nesting
    # they will be printed in a named context
    if not DIE_has_name(die) and self.nst_lvl == 0:
        return

    self.pr_ln('%s %s {' % (tag2usr_cls[die.tag], st_opt_name(die)))
    self.ind_lvl += 1
    self.nst_lvl += 1
    for ch in die.iter_children():
        self.pr_def(ch)
    self.nst_lvl -= 1
    self.ind_lvl -= 1
    self.pr_ln('};')

def pr_subprogram(self, die):
    tdie = DIE_typeof(die)
    self.pr_ln('%s %s (' % (st_type(tdie), st_name(die)))
    self.ind_lvl += 1
    ch_l = [ch for ch in die.iter_children()]
    for ch in ch_l:
        self.pr_def(ch)
        if  ch != ch_l[-1]:
            self.pr(',')
    self.ind_lvl -= 1
    self.pr_ln(');')

def pr_type_unit(self, die):
    self.pr_children(die)

def pr_compile_unit(self, die):
    self.pr_ln('// produced by: %s' % st_attr(die, 'DW_AT_producer'))
    self.pr_ln('// symbols of : %s' % st_name(die))
    self.pr_children(die)

# dispatch table for pr_def(self, die)
# contains all pr_<x>(self, die) functions
# contains only type/variable/function definition tags
# tags that cannot exist in a ELF stub will be mapped on pr_exit
tag2pr_func = dict(
  DW_TAG_null                     = pr_exit,
  #DW_TAG_array_type               =
  DW_TAG_class_type               = pr_user_type,
  DW_TAG_entry_point              = pr_exit,
  DW_TAG_enumeration_type         = pr_enumeration_type,
  #DW_TAG_formal_parameter         =
  DW_TAG_imported_declaration     = pr_exit,
  DW_TAG_label                    = pr_exit,
  DW_TAG_lexical_block            = pr_exit,
  DW_TAG_member                   = pr_variable,
  #DW_TAG_pointer_type             =
  #DW_TAG_reference_type           =
  DW_TAG_compile_unit             = pr_compile_unit, 
  #DW_TAG_string_type              = 
  DW_TAG_structure_type           = pr_user_type,
  #DW_TAG_subroutine_type          = 
  DW_TAG_typedef                  = pr_typedef,
  DW_TAG_union_type               = pr_user_type,
  #DW_TAG_unspecified_parameters   = 
  #DW_TAG_variant                  = 
  DW_TAG_common_block             = pr_exit,
  #DW_TAG_common_inclusion         = 
  #DW_TAG_inheritance              = 
  #DW_TAG_inlined_subroutine       = 
  #DW_TAG_module                   = 
  #DW_TAG_ptr_to_member_type       = 
  #DW_TAG_set_type                 = 
  #DW_TAG_subrange_type            = pr_subrange_type,
  DW_TAG_with_stmt                = pr_exit,
  #DW_TAG_access_declaration       = 
  DW_TAG_base_type                = pr_skip,
  DW_TAG_catch_block              = pr_exit,
  #DW_TAG_const_type               = 
  #DW_TAG_constant                 = 
  DW_TAG_enumerator               = pr_enumerator,
  #DW_TAG_file_type                = 
  #DW_TAG_friend                   = 
  #DW_TAG_namelist                 = 
  #DW_TAG_namelist_item            = 
  #DW_TAG_namelist_items           = 
  #DW_TAG_packed_type              = 
  DW_TAG_subprogram               = pr_subprogram,
  #DW_TAG_template_type_parameter  = 
  #DW_TAG_template_type_param      = 
  #DW_TAG_template_value_parameter = 
  #DW_TAG_template_value_param     = 
  #DW_TAG_thrown_type              = 
  DW_TAG_try_block                = pr_exit,
  #DW_TAG_variant_part             = 
  DW_TAG_variable                 = pr_variable, 
  #DW_TAG_volatile_type            = 
  #DW_TAG_dwarf_procedure          = 
  #DW_TAG_restrict_type            = 
  #DW_TAG_interface_type           = 
  #DW_TAG_namespace                = 
  #DW_TAG_imported_module          = 
  #DW_TAG_unspecified_type         = 
  #DW_TAG_partial_unit             = 
  #DW_TAG_imported_unit            = 
  #DW_TAG_mutable_type             = 
  #DW_TAG_condition                = 
  #DW_TAG_shared_type              = 
  DW_TAG_type_unit                = pr_type_unit,
  #DW_TAG_rvalue_reference_type    = 
)

class DumpHeader:
    def __init__(self, ifile, ofile, args):
        ''' dump header from the .debug_info section.
            ifile:
                input stream to read from

            ofile:
                output stream to write to
        '''
        self.ifile   = ifile
        self.ofile   = ofile
        self.ind_lvl = 0       # indentation level
        self.nst_lvl = 0       # nesting level of user types
        self.args    = args

        elffile      = ELFFile(self.ifile)
        if not elffile.has_dwarf_info():
            print('ERROR: file has no DWARF info')
            sys.exit(1)

        # get_dwarf_info returns a DWARFInfo context object, which is the
        # starting point for all DWARF-based processing in pyelftools.
        self.dwarfinfo = elffile.get_dwarf_info()

    def dump_header(self):
        ''' dump header from the elffile.
        '''
        self.pr('// generated by  : %s' % PROG)
        self.pr('\n// generated from: %s' % self.args.ifnam)

        cu_l = []
        tu_l = []
    
        for cu in self.dwarfinfo.iter_CUs():
            if cu['version'] >= 5:
                unit_type = cu.header.unit_type
                if unit_type == 'DW_UT_type':
                    tu_l.append(cu)
                elif unit_type == 'DW_UT_compile':
                    cu_l.append(cu)
                else:
                    raise NotImplementedError('Only DW_UT_type and DW_UT_compile are supported')
            else:
                raise NotImplementedError('Only DWARF version >= 5 is supported')

        for tu in reversed(tu_l):
            guard = 'Type_%x' % tu['type_signature'] 
            self.pr('\n\n#ifndef %s' % guard)
            self.pr('\n#define %s' % guard)
            self.pr_def(tu.get_top_DIE())
            self.pr('\n#endif')

        for cu in cu_l:
            self.pr_def(cu.get_top_DIE())

        self.pr('\n// end of header\n')

    def pr_def(self, die):
        ''' Prints the definition expressed by the DIE by dispatching it to the proper pr_???(self, die) function.
            die:
                die to print definition of.
        '''
        if die.tag in tag2pr_func:
            if self.args.verbose:
                self.pr_tag(die)
                self.pr_attrs(die)
            tag2pr_func[die.tag](self, die)
        else:
            self.pr_tag(die)
            self.pr_attrs(die)
            self.pr_children(die)

    def pr_tag(self, die):
        self.pr_ln('// 0x%x: DIE %s, size=%s, has_children=%s' % (
            die.offset, die.tag, die.size, die.has_children))

    def pr_attr(self, die, aname):
        if  self.args.verbose:
            self.pr_ln('//   %-18s:  %s' % (aname, st_attr(die, aname)))
        else:
            self.pr_ln('// %s' % (die.attributes[aname],))

    def pr_attrs(self, die):
        for aname in die.attributes:
            self.pr_attr(die, aname)

    def pr_children(self, die):        
        self.ind_lvl += 1
        for ch in die.iter_children():
            self.pr_def(ch) 
        self.ind_lvl -= 1
 
    def pr_ln(self, txt):
        '''returns txt on a new line with the current indentation'''
        self.pr('\n%*s%s' % (2*self.ind_lvl, '', txt))

    def pr(self, txt):
        '''writes txt to output file'''
        self.ofile.write(txt)

SCRIPT_DESCRIPTION = 'Extract header file from an ELF/DWARF formatted stub file'
VERSION_STRING = '%%(prog)s: based on pyelftools %s' % __version__

def main(stream=None):
    argparser = argparse.ArgumentParser(
            # usage='%(prog)s [options] <elf+dwarf-stubfile>',
            description=SCRIPT_DESCRIPTION,
            prog=PROG)
    argparser.add_argument('-v', '--version',
            action='version', version=VERSION_STRING)
    argparser.add_argument('-V', '--verbose',
            action='store_true',
            dest='verbose',
            help='verbose output')
    argparser.add_argument('-o', 
            dest = 'odir',
            help='output directory')
    argparser.add_argument( 
            dest = 'idir',
            help='input directory')
    args = argparser.parse_args()

    if not args.idir:
        argparser.print_help()
        return

    if not args.odir:
        args.odir = args.idir[:-3]+'out'

    print('... Reading from: %s ...' % args.idir)
    print('... Writing   to: %s ...' % args.odir)

    for ifnam in os.listdir(args.idir):
        if not ifnam.endswith('.so'): continue
        args.ifnam = ifnam
        ofnam = '%s.h' % ifnam[3:-3]
        print('... Processing file: <idir>/%s --> <odir>%s ...' % (ifnam, ofnam))
        ipath = args.idir +'/'+ifnam
        opath = args.odir +'/'+ofnam

        ofile = open(opath, 'w')
        with open(ipath, 'rb') as ifile:
            dumper = DumpHeader(ifile, ofile, args)
            dumper.dump_header()

def profile_main():
    progbase = PROG[:-3]
    PROFFILE = progbase+ '.profile'
    import cProfile
    cProfile.run("main(open('%s_out.txt', 'w'))" % progbase, PROFFILE)

    # Dig in some profiling stats
    import pstats
    p = pstats.Stats(PROFFILE)
    p.sort_stats('cumulative').print_stats(25)

#-------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
    #profile_main()
