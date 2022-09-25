#!/usr/bin/env python3
#-------------------------------------------------------------------------------
# scripts/stub2hdr.py
#
# Extracts a header filefrom a stub ELF (object/archive/shared object) file
# The stub ELF file must contain no implementations i.e:
#   - only uninitialized variables 
#   - empty function bodies
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
from elftools.common.utils import bytes2str
from elftools.dwarf.enums import ENUM_DW_ATE

PROG = 'stub2hdr.py'

enc2str = dict(
    # DW_ATE_address         = '',
    # DW_ATE_boolean         = '',
    # DW_ATE_complex_float   = '',
    # DW_ATE_float           = '',
      DW_ATE_signed          = 'signed',
    # DW_ATE_signed_char     = '',
      DW_ATE_unsigned        = 'unsigned',
    # DW_ATE_unsigned_char   = '',
    # DW_ATE_imaginary_float = '',
    # DW_ATE_packed_decimal  = '',
    # DW_ATE_numeric_string  = '',
    # DW_ATE_edited          = '',
    # DW_ATE_signed_fixed    = '',
    # DW_ATE_unsigned_fixed  = '',
    # DW_ATE_decimal_float   = '',
    # DW_ATE_UTF             = '',
    # DW_ATE_UCS             = '',
    # DW_ATE_ASCII           = '',
)

DW_ATE_raw2name = dict((v, k) for k, v in ENUM_DW_ATE.items())

def pr_exit(self, die):
    print('ERROR: Stub files cannot contain dies of type %s' % die.tag)
    sys.exit(1)

def pr_skip(self, die):
    pass


def st_subrange_type(self, die):
    if 'DW_AT_upper_bound' in die.attributes:
        res = '[%s]' % (die.attributes['DW_AT_upper_bound'].value + 1)
    elif 'DW_AT_count' in die.attributes:
        res = '[%s]' % die.attributes['DW_AT_count'].value
    else:
        res = '[]'

    return res

# dispatch table for st_<x>(self, die) functions
# contains only type/variable/function type tags
# tags that cannot exist in a ELF stub will be mapped on pr_exit
deftag2st_func = dict(
  DW_TAG_null                     = pr_exit,
  #DW_TAG_array_type               = st_array
  #DW_TAG_class_type
  #DW_TAG_pointer_type             =
  #DW_TAG_reference_type           =
  #DW_TAG_string_type              = 
  #DW_TAG_subroutine_type          = 
  #DW_TAG_unspecified_parameters   = 
  #DW_TAG_variant                  = 
  #DW_TAG_common_inclusion         = 
  #DW_TAG_inheritance              = 
  #DW_TAG_inlined_subroutine       = 
  #DW_TAG_module                   = 
  #DW_TAG_ptr_to_member_type       = 
  #DW_TAG_set_type                 = 
  #DW_TAG_subrange_type            = st_subrange_type,
  DW_TAG_with_stmt                = pr_exit,
  #DW_TAG_access_declaration       = 
  #DW_TAG_base_type                = 
  DW_TAG_catch_block              = pr_exit,
  #DW_TAG_const_type               = 
  #DW_TAG_constant                 = 
  #DW_TAG_enumerator               = pr_enumerator,
  #DW_TAG_file_type                = 
  #DW_TAG_friend                   = 
  #DW_TAG_namelist                 = 
  #DW_TAG_namelist_item            = 
  #DW_TAG_namelist_items           = 
  #DW_TAG_packed_type              = 
  #DW_TAG_subprogram               = pr_subprogram,
  #DW_TAG_template_type_parameter  = 
  #DW_TAG_template_type_param      = 
  #DW_TAG_template_value_parameter = 
  #DW_TAG_template_value_param     = 
  #DW_TAG_thrown_type              = 
  #DW_TAG_try_block                = pr_exit,
  #DW_TAG_variant_part             = 
  #DW_TAG_variable                  = pr_variable, 
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
  #DW_TAG_type_unit                = pr_type_unit,
  #DW_TAG_rvalue_reference_type    = 
)

def st_var(vdie):
    '''Given a DIE that describes a DW_TAG_variable, a DW_TAG_parameter, or a DW_TAG_member
       containing an optional DW_AT_type
       
    Returns the C/C++ declaration as a single line string
    '''
    return str(parse_var(vdie))

def strip_mods(tdie):
    mods = []
    # peel off the type modifiers from tdie
    while tdie.tag in ('DW_TAG_const_type', 'DW_TAG_pointer_type', 'DW_TAG_reference_type'):
        mods.insert(0, tdie.tag)
        tdie = DIE_type(tdie)
    return tdie, mods

def get_scopes(tdie):
    prnt = tdie.get_parent()
    scps = list()
    while prnt.tag in ('DW_TAG_class_type', 'DW_TAG_structure_type', 'DW_TAG_union_type', 'DW_TAG_namespace'):
        scps.insert(0, DIE_opt_name(prnt, '/*anonymous*/'))
        prnt = prnt.get_parent()
    return scps

def strip_prefix(tdie):
    if tdie.tag == 'DW_TAG_ptr_to_member_type':
        prfx = DIE_name(tdie.get_DIE_from_attribute('DW_AT_containing_type')) + '::'
        tdie = DIE_type(tdie)
    elif 'DW_AT_object_pointer' in tdie.attributes: # Older compiler... Subroutine, but with an object pointer
        prfx = DIE_name(DIE_type(DIE_type(tdie.get_DIE_from_attribute('DW_AT_object_pointer')))) + '::'
    else:
        prfx = ''

    return tdie, prfx

def st_params(tdie):
    params = tuple(st_param(pdie, pdie) for pdie in tdie.iter_children() 
    if pdie.tag in ('DW_TAG_formal_parameter', 'DW_TAG_unspecified_parameters') and 'DW_AT_artificial' not in pdie.attributes)
    return ', '.join(params)

def st_return(tdie):
    if DIE_has_type(tdie):
        rtrn_td = parse_var(tdie)
        rtrn_st = str(rtrn_td)
        if not rtrn_td.is_pointer:
            rtrn_st += ' '
    else:
        rtrn_st = 'void '
    return rtrn_st
    

def parse_var(vdie):
    '''parse a DIE that describes a variable, a parameter, or a member

    Returns a TypeDesc.

    Does not follow named struct/union/class/type defs.
    '''

    # TODO proper injection of name into TypeDesc
    td = TypeDesc()
    name = DIE_name(vdie)

    if not DIE_has_type(vdie):
        return td

    tdie = DIE_type(vdie)
    tdie, td.mods = strip_mods(tdie)

    if td.is_pointer and not DIE_has_type(tdie): # void* is encoded as a pointer to nothing
        return td

    # From this point on, tdie doesn't change
    if tdie.tag in ('DW_TAG_ptr_to_member_type', 'DW_TAG_subroutine_type'):
        tdie, prfx_st = strip_prefix(tdie)

        if tdie.tag == 'DW_TAG_subroutine_type':
            params_st = st_params(tdie)
            rtrn_st   = st_return(tdie)

            if td.is_pointer:
                td.mods.pop()
                td.name = '%s(%s*)(%s)' % (rtrn_st, prfx_st, params_st)
            else:
                td.name = '%s(%s)' % (rtrn_st, params_st)
            return td
    elif DIE_is_ptr_to_member_struct(tdie):
        dt = parse_var(next(tdie.iter_children())) # The first element is pfn, a function pointer with a this
        dt.mods.pop() # Pop the extra pointer
        dt.tag = 'DW_TAG_ptr_to_member_type' # Not a function pointer per se
        return dt
    elif tdie.tag == 'DW_TAG_array_type':
        td.dims = (_dim_size(sub)
            for sub in tdie.iter_children()
            if sub.tag == 'DW_TAG_subrange_type')
        td.name = st_var(tdie)
        return td
    elif tdie.tag == 'DW_TAG_base_type':
        td.name = '%s %s' % (DIE_name(tdie), name)
        return td
    elif tdie.tag == 'DW_TAG_structure_type':        
        td.name = 'struct %s %s' % (DIE_name(tdie), name)
        return td
    elif tdie.tag == 'DW_TAG_union_type':        
        td.name = 'union %s %s' % (DIE_name(tdie), name)
        return td
    elif tdie.tag in ('DW_TAG_typedef_type', 'DW_class_type'):        
        td.name = '%s %s' % (DIE_name(tdie), name)
        return td

    # Now the nonfunction types
    # Blank name is sometimes legal (unnamed unions, etc)
    td.name = DIE_opt_name(tdie, '/*anonymous*/')
    td.scps = get_scopes(tdie)
    return td

tag2mod = dict(
    DW_TAG_pointer_type   = '*',
    DW_TAG_reference_type = '&',
    DW_TAG_const_type     = 'const',
)

class TypeDesc(object):
    ''' Encapsulates a description of a datatype, as parsed from DWARF DIEs.

        name - name for primitive datatypes, element name for arrays, the
            whole name for functions and function pointers

        mods - a collection of 'const'/'pointer'/'reference', from the
            chain of DIEs preceeding the real type DIE

        scps - a collection of struct/class/namespace names, parents of the
            real type DIE

        tag - the tag of the real type DIE

        dims - the collection of array dimensions, if the type is an array. 
            -1 means an array of unknown dimension.

    '''

    def __init__(self):
        self.name = 'void'
        self.mods = [] # Reads left to right
        self.scps = [] # Reads left to right
        self.dims = []

    def __str__(self):
        '''Returns the C/C++ type description in a single line
        
           (<scp0>::...::<scpn>::)?<name>([<dim0>]...[dimn])?
        '''
        # Some reference points from dwarfdump:
        # const->pointer->const->char = const char *const
        # const->reference->const->int = const const int &
        # const->reference->int = const int &
        name = str(self.name)
        mods = self.mods

        desc = []
        # Initial const applies to the var ifself, other consts apply to the pointee
        if len(mods) and mods[0] == 'const':
            desc.append('const')
            mods = mods[1:]

        # ref->const in the end, const goes in front
        if mods[-2:] == ('DW_TAG_reference_type', 'DW_TAG_const_type'):
            desc.append('const')
            mods = mods[0:-1]

        if self.scps:
            name = '::'.join(self.scps)+'::' + name
        desc.append(name)

        if len(mods):
            desc.append(''.join(tag2mod[mod] for mod in mods))

        if self.dims:
            dims = ''.join('[%s]' % (str(dim) if dim > 0 else '',)
                for dim in self.dims)
        else:
            dims = ''

        return ' '.join(desc)+dims

    @property
    def is_pointer(self):
        return len(self.mods) and self.mods[-1] == 'DW_TAG_pointer_type'
    

def DIE_string(die, aname):
    return bytes2str(die.attributes[aname].value) 

def DIE_name(die):
    return DIE_string(die, 'DW_AT_name') 

def DIE_opt_name(die, default = ''):
    return DIE_name(die) if DIE_has_name(die) else default

def DIE_type(die):
    return die.get_DIE_from_attribute('DW_AT_type')

def DIE_has_name(die):
    return DIE_has_attr(die, 'DW_AT_name')

def DIE_has_type(die):
    return DIE_has_attr(die, 'DW_AT_type')
    
def DIE_has_attr(die, aname):
    return aname in die.attributes

class ClassDesc(object):
    def __init__(self):
        self.scps = ()
        self.const_member = False

def get_class_spec_if_member(func_spec, the_func):
    if 'DW_AT_object_pointer' in the_func.attributes:
        this_param = the_func.get_DIE_from_attribute('DW_AT_object_pointer')
        this_td = parse_var(this_param)
        cd = ClassDesc()
        cd.scps = this_td.scps + (this_td.name,)
        cd.const_member = any(('const', 'pointer') == this_td.mods[i:i+2]
            for i in range(len(this_td.mods))) # const -> pointer -> const for this arg of const
        return cd

    # Check the parent element chain - could be a class
    parent = func_spec.get_parent()

    scps = []
    while parent.tag in ('DW_TAG_class_type', 'DW_TAG_structure_type', 'DW_TAG_namespace'):
        scps.insert(0, DIE_name(parent))
        parent = parent.get_parent()
    if scps:
        cs = ClassDesc()
        cs.scps = scps
        return cs

    return None

def st_param(param_spec, param):
    if param_spec.tag == 'DW_TAG_formal_parameter':
        if 'DW_AT_name' in param.attributes:
            name = DIE_name(param)
        elif 'DW_AT_name' in param_spec.attributes:
            name = DIE_name(param_spec)
        else:
            name = None
        type = parse_var(param_spec)
        return  str(type)
    else: # unspecified_parameters AKA variadic
        return '...'

def DIE_is_ptr_to_member_struct(tdie):
    if tdie.tag == 'DW_TAG_structure_type':
        members = tuple(die for die in tdie.iter_children() if die.tag == 'DW_TAG_member')
        return len(members) == 2 and DIE_opt_name(members[0]) == '__pfn' and DIE_opt_name(members[1]) == '__delta'
    return False

def _dim_size(die):
    if 'DW_AT_upper_bound' in die.attributes:
        return die.attributes['DW_AT_upper_bound'].value + 1
    if 'DW_AT_count' in die.attributes:
        return die.attributes['DW_AT_count'].value
    else:
        return -1

def pr_variable(self, die):
    self.pr_ln(st_var(die))

tag2usr_cls = dict(
    DW_TAG_structure_type = 'struct',
    DW_TAG_union_type     = 'union',
    DW_TAG_class_type     = 'class',
)

def pr_user_type(self, die):
    # skip anonymous user types at outer nesting
    # they will be printed in a named context
    if not DIE_has_name(die) and self.nst_lvl == 0:
        return

    self.pr_ln('%s %s {' % (tag2usr_cls[die.tag], DIE_opt_name(die, '/*anonymous*/')))
    self.ind_lvl += 1
    self.nst_lvl += 1
    for ch in die.iter_children():
        self.pr_die(ch)
        self.pr(';')
    self.nst_lvl -= 1
    self.ind_lvl -= 1
    self.pr_ln('};')

def pr_subprogram(self, die):
    self.pr_ln('%s %s (' % (st_var(die), DIE_name(die)))
    self.ind_lvl += 1
    ch_l = [ch for ch in die.iter_children()]
    for ch in ch_l:
        self.pr_die(ch)
        if  ch != ch_l[-1]:
            self.pr(',')
    self.ind_lvl -= 1
    self.pr_ln(');')

def pr_type_unit(self, die):
    self.pr_children(die)

def pr_compile_unit(self, die):
    self.pr_ln('// produced by: %s' % DIE_string(die, 'DW_AT_producer'))
    self.pr_ln('// symbols of : %s' % DIE_name(die))
    self.pr_children(die)

# dispatch table for pr_<x>(self, die) functions
# contains only type/variable/function definition tags
# tags that cannot exist in a ELF stub will be mapped on pr_exit
deftag2pr_func = dict(
  DW_TAG_null                     = pr_exit,
  #DW_TAG_array_type 
  DW_TAG_class_type               = pr_user_type,
  DW_TAG_entry_point              = pr_exit,
  #DW_TAG_enumeration_type         = pr_enumeration_type,
  DW_TAG_formal_parameter         = pr_variable,
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
  DW_TAG_typedef                  = pr_variable,
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
  #DW_TAG_enumerator               = pr_enumerator,
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
  DW_TAG_variable                  = pr_variable, 
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
        self.pr('\n// generated from: %s' % self.args.ifilename)

        for cu in self.dwarfinfo.iter_CUs():
            if cu['version'] >= 5:
                unit_type = cu.header.unit_type
                if unit_type == 'DW_UT_type':
                    guard = 'Type_%x' % cu['type_signature'] 
                    self.pr('\n\n#ifndef %s' % guard)
                    self.pr('\n#define %s' % guard)
                    self.pr_die(cu.get_top_DIE())
                    self.pr('\n#endif')
                elif unit_type == 'DW_UT_compile':
                    self.pr_die(cu.get_top_DIE())
                else:
                    raise NotImplementedError('Only DW_UT_type and DW_UT_compile are supported')
            else:
                raise NotImplementedError('Only DWARF version >= 5 is supported')
        self.pr('\n// end of header\n')

    def pr_die(self, die):
        ''' Dumps a DIE by dispatching it to the proper pr_???(self, die) function.
            die:
                die to dump
        '''
        if die.tag in deftag2pr_func:
            if self.args.verbose:
                self.pr_tag(die)
                self.pr_attrs(die)
            deftag2pr_func[die.tag](self, die)
        else:
            self.pr_tag(die)
            self.pr_attrs(die)
            self.pr_children(die)

    def pr_tag(self, die):
        self.pr_ln('// DIE %s, size=%s, has_children=%s' % (
            die.tag, die.size, die.has_children))

    def pr_attr(self, die, aname):
        aval = die.attributes[aname]
        if not self.args.verbose:
            aval = aval.value
        self.pr_ln('//   %-18s:  %s' % (aname, aval))

    def pr_attrs(self, die):
        for attrname in die.attributes:
            self.pr_attr(die, attrname)

    def pr_children(self, die):        
        self.ind_lvl += 1
        for ch in die.iter_children():
            self.pr_die(ch) 
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
            dest = 'ofilename',
            help='output header filename')
    argparser.add_argument( 
            dest = 'ifilename',
            help='input ELF/DWARFv5 stubfilename')
    args = argparser.parse_args()

    if not args.ifilename:
        argparser.print_help()
        return

    print('... Processing file: %s ...' % args.ifilename)
    ofile = open(args.ofilename, 'w') if args.ofilename else sys.stdout
    with open(args.ifilename, 'rb') as ifile:
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
