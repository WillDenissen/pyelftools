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
from collections import defaultdict
import argparse
import sys, os

# For running from development directory. It should take precedence over the
# installed pyelftools.
dev_dir = os.path.dirname(os.path.realpath(sys.argv[0])) + '/..'
sys.path.insert(0, dev_dir)

from elftools import __version__
from elftools.elf.elffile import ELFFile
from elftools.common.utils import bytes2str

PROG = 'stub2hdr.py'


def is_main_file(die):
    return (DIE_attr(die, 'DW_AT_decl_file').value == 1) if DIE_has_attr(die, 'DW_AT_decl_file') else 1;

def pr_exit(self, die):
    pass
    # print('ERROR: Stub files cannot contain dies of type %s' % die.tag)
    # sys.exit(1)

def pr_skip(self, die):
    pass

def st_subrange(die):
    if DIE_has_attr(die, 'DW_AT_upper_bound'):
        return '[%s]' % (DIE_attr(die, 'DW_AT_upper_bound').value + 1, )
    elif DIE_has_attr(die, 'DW_AT_count'):
        return '[%s]' % (DIE_attr(die, 'DW_AT_count').value, )
    else:
        return '[]'

PEEL_TAGS = (
    'DW_TAG_array_type', 
    'DW_TAG_pointer_type', 
    'DW_TAG_reference_type', 
    'DW_TAG_const_type', 
    'DW_TAG_restrict_type'
    )

def peel_off_types(tdie):
    '''walks over parent to child types list and peels off all types in PEEL_TAGS
    
        returns 
          tdie_l : a parent child type list with tags within PEEL_TAGS
          tdie   : fist child type with tag not in PEEL_TAGS 
    '''
    tdie_l = []
    while tdie and tdie.tag in PEEL_TAGS:
        tdie_l.append(tdie)
        tdie = DIE_typeof(tdie)
    return tdie_l, tdie

def st_dims(tdie):
    txt = ''
    for dim in tdie.iter_children():
        if dim.tag == 'DW_TAG_subrange_type':
            txt += st_subrange(dim)

    return txt

# TODO proper sub_expression nesting
def sub_expr(txt):
    if txt[-1] == ']':
        return '(%s)' % txt
    else:
        return txt

def st_type_expr(tdie_l, name):
    txt = name
    for tdie in tdie_l:
        if   tdie.tag in 'DW_TAG_array_type':
            txt = sub_expr(txt) + st_dims(tdie)
        elif tdie.tag in 'DW_TAG_pointer_type':
            txt = '*%s' % txt
        elif tdie.tag in 'DW_TAG_reference_type':
            txt = '&%s' % txt
        elif tdie.tag in 'DW_TAG_const_type':
            txt = 'const %s' % txt
        elif tdie.tag in 'DW_TAG_restrict_type':
            txt = '__restrict %s' % txt
    return txt

def st_var(die):
    name           = st_opt_name(die)
    tdie           = DIE_typeof(die)
    tdie_l, chtdie = peel_off_types(tdie)
    cnst_st        = ''
    if len(tdie_l) and tdie_l[-1].tag == 'DW_TAG_const_type':
        tdie_l.pop()
        cnst_st = 'const '
    return  '%s%s %s' % (cnst_st, st_type(chtdie), st_type_expr(tdie_l, name)) 

def st_form_dflt(die, val):
    return '%s' % val

def st_form_flag(die, val):
    return '%s' % bool(val)

def st_form_string(die, val):
    return bytes2str(val) if val else 'None'

def st_form_ref(die, val):
    return '<0x%x>' % (val + die.cu.cu_offset)

def st_form_ref_sig8(die, val):
    return '<signature 0x%x>' % val

def st_form_hex(die, val):
    return '0x%x' % (val)

def st_form_hex_addr(die, val):
    return '<0x%x>' % val

def st_form_split_64bit(die, val):
    lo_w =  val        & 0xFFFFFFFF
    hi_w = (val >> 32) & 0xFFFFFFFF

    return '0x%x 0x%x' % (lo_w, hi_w)

def st_form_block(die, val):
  s = '%s byte block: ' % len(val)
  s += ' '.join('%02x' % item for item in val)
  return s

# dispatch table for st_form_<x>(die, val) functions
form2st_form = defaultdict(
    lambda: st_form_dflt, # default_factory
    # DW_FORM_null                =
    DW_FORM_addr                = st_form_hex,
    DW_FORM_ref                 = st_form_ref,
    DW_FORM_block2              = st_form_block,
    DW_FORM_block4              = st_form_block,
    # DW_FORM_data2               = 
    # DW_FORM_data4               = 
    # DW_FORM_data8               = 
    DW_FORM_string              = st_form_string,
    DW_FORM_block               = st_form_block,
    DW_FORM_block1              = st_form_block,
    # DW_FORM_data1               = 
    # DW_FORM_flag                = 
    # DW_FORM_sdata               = 
    DW_FORM_strp                = st_form_string,
    # DW_FORM_udata               = 
    DW_FORM_ref_addr            = st_form_ref,
    DW_FORM_ref1                = st_form_ref,
    DW_FORM_ref2                = st_form_ref,
    DW_FORM_ref4                = st_form_ref,
    DW_FORM_ref8                = st_form_ref,
    DW_FORM_ref_udata           = st_form_ref,        
    # DW_FORM_indirect            =
    # DW_FORM_sec_offset          =
    DW_FORM_sec_offset          = st_form_hex,
    # DW_FORM_exprloc             =
    # DW_FORM_flag_present        =
    # DW_FORM_strx                =
    # DW_FORM_addrx               =
    # DW_FORM_ref_sup4            =
    # DW_FORM_strp_sup            =
    # DW_FORM_data16              =
    # DW_FORM_line_strp           =
    DW_FORM_ref_sig8            = st_form_ref_sig8,
    # DW_FORM_implicit_const      =
    # DW_FORM_loclistx            =
    # DW_FORM_rnglistx            =
    # DW_FORM_ref_sup8            =
    # DW_FORM_strx1               =
    # DW_FORM_strx2               =
    # DW_FORM_strx3               =
    # DW_FORM_strx4               =
    # DW_FORM_addrx1              =
    # DW_FORM_addrx2              =
    # DW_FORM_addrx3              =
    # DW_FORM_addrx4              =

    # DW_FORM_GNU_addr_index      =
    # DW_FORM_GNU_str_index       =
    # DW_FORM_GNU_ref_alt         =
    # DW_FORM_GNU_strp_alt        =
)

def st_attr(die, aname):
    attr = die.attributes[aname]
    return form2st_form[attr.form](die, attr.value) 

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
    return 'enum %s' % st_opt_name(tdie)

def st_struct(tdie):
    return 'struct %s' % st_opt_name(tdie)

def st_union(tdie):
    return 'union %s' % st_opt_name(tdie)

def st_unspec_param(tdie):
    return '...'

def get_params(die):
    return [ch for ch in die.iter_children() if ch.tag in ('DW_TAG_formal_parameter', 'DW_TAG_unspecified_parameters') and not DIE_has_attr(ch, 'DW_AT_artificial')]

def st_subroutine(tdie):
    pdie_l = get_params(tdie)
    prms_st = ', '.join(st_type(pdie) for pdie in pdie_l)
    return '%s(%s)(%s)' % (st_type(DIE_typeof(tdie)), st_opt_name(tdie), prms_st)

# dispatch table for st_type 
# contains st_<x>(die) -> string functions
# tags that cannot exist in a ELF stub will be mapped on st_exit
tag2st_func = dict(
  #DW_TAG_null                     =
  #DW_TAG_array_type               = see st_type_expr
  #DW_TAG_class_type               = st_class,
  #DW_TAG_entry_point              =
  DW_TAG_enumeration_type         = st_enum,
  #DW_TAG_formal_parameter         =
  #DW_TAG_imported_declaration     =
  #DW_TAG_label                    =
  #DW_TAG_lexical_block            =
  #DW_TAG_member                   =
  #DW_TAG_pointer_type             = see st_type_expr
  #DW_TAG_reference_type           = see st_type_expr
  #DW_TAG_compile_unit             =
  #DW_TAG_string_type              =
  DW_TAG_structure_type           = st_struct,
  DW_TAG_subroutine_type          = st_subroutine,
  DW_TAG_typedef                  = st_typedef,
  DW_TAG_union_type               = st_union,
  DW_TAG_unspecified_parameters   = st_unspec_param,
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
  #DW_TAG_const_type               = see st_type_expr
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
  #DW_TAG_restrict_type            = see st_type_expr
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

# TODO strip modifiers and dimensions
def st_type(tdie):
    if tdie == None:
        return 'void'
    if tdie.tag in tag2st_func:
        return tag2st_func[tdie.tag](tdie)
    return '/* <Die 0x%x> */' % tdie.offset

def pr_variable(self, die):
    if not DIE_has_attr(die, 'DW_AT_external'): return
    if not is_main_file(die): return
    self.pr_ln('extern %s;' % st_var(die))

def pr_member(self, die):
    self.pr_ln('%s;' % st_var(die))

def pr_param(self, die):
    self.pr_ln(st_var(die))

def pr_typedef(self, die):
    if not is_main_file(die): return
    self.pr_ln('typedef %s;' % st_var(die))

def pr_varargs(self, die):
    self.pr_ln('...')

def pr_enumerator(self, die):
    name = st_name(die)
    if DIE_has_attr(die, 'DW_AT_const_value'):
        self.pr_ln('%-50s = %s' % (name, st_attr(die, 'DW_AT_const_value')))
    else:
        self.pr_ln('%-50s' % name)

def pr_enumeration_type(self, die):
    if not is_main_file(die): return
    self.pr_ln('enum %s {' % st_opt_name(die))
    ch_l = [ch for ch in die.iter_children()]
    self.ind_lvl += 1
    for ch in ch_l:
        self.pr_def(ch)
        if ch != ch_l[-1]:
            self.pr(',')
    self.ind_lvl -= 1
    self.pr_ln('};')

tag2usr_cls = dict(
    DW_TAG_structure_type = 'struct',
    DW_TAG_union_type     = 'union',
    DW_TAG_class_type     = 'class',
)

def pr_user_type(self, die):
    # skip anonymous user types at outer nesting
    # they will be printed in a named context
    if not DIE_has_name(die) and self.nst_lvl == 0: return
    if not is_main_file(die): return

    self.pr_ln('%s %s {' % (tag2usr_cls[die.tag], st_opt_name(die)))
    self.ind_lvl += 1
    self.nst_lvl += 1
    for ch in die.iter_children():
        self.pr_def(ch)
    self.nst_lvl -= 1
    self.ind_lvl -= 1
    self.pr_ln('};')


def pr_subprogram(self, die):
    if not DIE_has_attr(die, 'DW_AT_external'): return
    if not is_main_file(die): return
    tdie = DIE_typeof(die)
    self.pr_ln('extern %s %s (' % (st_type(tdie), st_name(die)))
    self.ind_lvl += 1
    pdie_l = get_params(die)
    for ch in pdie_l:
        self.pr_def(ch)
        if  ch != pdie_l[-1]:
            self.pr(',')
    self.ind_lvl -= 1
    self.pr_ln(');')

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
  DW_TAG_formal_parameter         = pr_param,
  DW_TAG_imported_declaration     = pr_exit,
  DW_TAG_label                    = pr_exit,
  DW_TAG_lexical_block            = pr_exit,
  DW_TAG_member                   = pr_member,
  #DW_TAG_pointer_type             =
  #DW_TAG_reference_type           =
  DW_TAG_compile_unit             = pr_compile_unit, 
  #DW_TAG_string_type              = 
  DW_TAG_structure_type           = pr_user_type,
  #DW_TAG_subroutine_type          = 
  DW_TAG_typedef                  = pr_typedef,
  DW_TAG_union_type               = pr_user_type,
  DW_TAG_unspecified_parameters   = pr_varargs,
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
  #DW_TAG_type_unit                 =
  #DW_TAG_rvalue_reference_type    = 
)

class HeaderDumper:
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
            print('ERROR: file has no DWARF info', file = sys.stderr)
            sys.exit(1)

        # get_dwarf_info returns a DWARFInfo context object, which is the
        # starting point for all DWARF-based processing in pyelftools.
        self.dwarfinfo = elffile.get_dwarf_info()
        self.pubnames  = self.dwarfinfo.get_pubnames()
        self.pubtypes  = self.dwarfinfo.get_pubtypes()
        self.cu_l      = []
        self.tu_l      = []
    
        for cu in self.dwarfinfo.iter_CUs():
            if cu['version'] >= 5:
                unit_type = cu.header.unit_type
                if unit_type == 'DW_UT_type':
                    self.tu_l.append(cu)
                elif unit_type == 'DW_UT_compile':
                    self.cu_l.append(cu)
                else:
                    raise NotImplementedError('Only DW_UT_type and DW_UT_compile are supported')
            else:
                raise NotImplementedError('Only DWARF version >= 5 is supported')

        self.cu_ofs2tdie_l = self.collect_cu_ofs2die_l(self.pubtypes)
        self.cu_ofs2pdie_l = self.collect_cu_ofs2die_l(self.pubnames)


    def find_die(self, pent):
        for cu in self.dwarfinfo.iter_CUs():
            if cu.cu_offset == pent.cu_ofs:
                for die in cu.iter_DIEs():
                    if die.offset == pent.die_ofs:
                        return die
        self.pr_ln('ERROR: die with (cu_ofs=%x, die_ofs=%x) not found' % (pent.cu_ofs, pent.die_ofs))
        

    def collect_cu_ofs2die_l(self, pubs):
        if pubs:
            cu_ofs2die_l = {}
            for name, pent in pubs.items():
                # self.pr_ln('// %8x %8x %s' % (pent.cu_ofs, pent.die_ofs, name))
                cu_ofs = pent.cu_ofs
                die = self.find_die(pent)
                if die:
                    cu_ofs2die_l[cu_ofs] = cu_ofs2die_l.get(cu_ofs, []) + [die]
                # TODO why are compile units in this list?
            return cu_ofs2die_l

    def dump_header(self):
        ''' dump header from the elffile.
        '''
        self.pr('// generated by  : %s' % PROG)
        self.pr('\n// generated from: %s' % self.ifile.name)

        # for tu in reversed(self.tu_l):
        #     self.dump_pub(tu)
        #     self.pr_type_unit(tu)

        for cu in self.cu_l:
            self.dump_pub(cu)
            # tdie = cu.get_top_DIE()
            # self.pr_def(tdie)

        self.pr('\n// end of header\n')

    def dump_pub(self, cu):
        fdcl_l = self.get_decl_files(cu)
        cu_ofs = cu.cu_offset

        self.pr_ln('// cu %s' % fdcl_l[0])

        for cu_ofs2die_l, name in ((self.cu_ofs2tdie_l, 'pubtypes'), (self.cu_ofs2pdie_l, 'pubnames')):
            self.ind_lvl += 1
            self.pr_ln('// defined %s:' % name)

            self.ind_lvl += 1
            if cu_ofs2die_l and cu_ofs in cu_ofs2die_l:
                for die in cu_ofs2die_l[cu_ofs]:
                    self.pr_tag(die)
                    if die and DIE_has_attr(die, 'DW_AT_decl_file'):
                        fidx = DIE_attr(die, 'DW_AT_decl_file').value - 1
                        self.pr(' %-60s %s' % (st_opt_name(die), fdcl_l[fidx]))
                        # assert(die.get_parent().tag == DW_TAG_compile_unit)
            self.ind_lvl -= 2

    def get_decl_files(self, cu):
        fdcl_l = []
        lp     = self.dwarfinfo.line_program_for_CU(cu)

        if lp:
            # ver5 = lp.header.version >= 5
            idir_l = [os.path.dirname(cu.get_top_DIE().get_full_path())]
            idir_l += [bytes2str(idir) for idir in lp.header['include_directory']]
            for nr, fent in enumerate(lp.header['file_entry']):
                fdcl_l.append('%s/%s' % (idir_l[fent.dir_index], bytes2str(fent.name)))

        return fdcl_l

    def pr_type_unit(self, tu):
            tdie   = tu.get_top_DIE()
            self.pr_ln('// tu %s' % tdie.get_full_path())
            # cdie_l = [cdie for cdie in tdie.iter_children()]
            #if not is_main_file(cdie_l[0]): return 

            # guard  = 'Type_%x' % tu['type_signature'] 
            # self.pr('\n\n#ifndef %s' % guard)
            # self.pr('\n#define %s' % guard)
            # for cdie in cdie_l:
            #     self.pr_def(cdie)
            # self.pr('\n#endif')


    def pr_def(self, die):
        ''' Prints the definition expressed by the DIE by dispatching it to the proper pr_???(self, die) function.
            die:
                die to print definition of.
        '''
        if die.tag in tag2pr_func:
            self.pr_tag(die)
            self.pr_attrs(die)
            tag2pr_func[die.tag](self, die)
        else:
            self.pr_tag(die)
            self.pr_attrs(die)
            self.pr_children(die)

    def pr_tag(self, die):
        if 'f' in self.args.verbosity:
            self.pr_ln('// 0x%x: %s, size=%s, has_children=%s' % (
            die.offset, die.tag, die.size, die.has_children))
        elif 't' in self.args.verbosity:
            self.pr_ln('// 0x%x: %s' % (die.offset, die.tag[7:]))        # trim 'DW_TAG_'

    def pr_attr(self, die, aname):
        if 'f' in self.args.verbosity:
            self.pr_ln('//   %-18s:   %s' % (aname, st_attr(die, aname)))
        elif 't' in self.args.verbosity:
            self.pr_ln('//   %-18s:   %s' % (aname[6:], st_attr(die, aname))) # trim 'DW_AT_'
    
    def pr_attrs(self, die):
        if not die: return
        if self.args.verbosity:
            for aname in die.attributes:
                if aname not in self.args.skip_aname:
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

SKIP_ANAME = (
    #'DW_AT_decl_file',
    'DW_AT_decl_line',
    'DW_AT_decl_column',
    'DW_AT_byte_size',
    'DW_AT_encoding',
    'DW_AT_sibling',
    'DW_AT_location',
    'DW_AT_frame_base',
    'DW_AT_call_all_calls',
    'DW_AT_stmt_list',
    'DW_AT_macros',
    'DW_AT_low_pc',
    'DW_AT_high_pc'
    )

def process_file(ipath, opath, args):
    ifile = open(ipath, 'rb') if ipath else sys.stdin
    ofile = open(opath, 'wb') if opath else sys.stdout

    print('... Processing file: %s --> %s ...' % (ifile.name, ofile.name), file = sys.stderr)

    dumper = HeaderDumper(ifile, ofile, args)
    dumper.dump_header()

def main():
    argparser = argparse.ArgumentParser(
            # usage='%(prog)s [options] <elf+dwarf-stubfile>',
            description = SCRIPT_DESCRIPTION,
            prog        = PROG)
    argparser.add_argument('-v', '--version',
            action      = 'version', 
            version     = VERSION_STRING)
    argparser.add_argument('-V', '--verbosity',
            default     = '',
            dest        = 'verbosity',
            help        = 'verbosity of output: one of t)ype f)ull')
    argparser.add_argument('-o', 
            dest        = 'opath',
            help        = 'output file')
    argparser.add_argument( 
            dest        = 'ipath',
            help        = 'input file')
    args = argparser.parse_args()

    if 'f' in args.verbosity:
        args.skip_aname = tuple()
    elif 't' in args.verbosity:
        args.skip_aname = SKIP_ANAME

    process_file(args.ipath, args.opath, args)

#-------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
