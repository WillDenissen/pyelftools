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

tag2str = dict(
    DW_TAG_pointer_type   = '*',
    DW_TAG_reference_type = '&',
    DW_TAG_const_type     = 'const',
    DW_TAG_structure_type = 'struct',
    DW_TAG_union_type     = 'union',
    DW_TAG_class_type     = '',
)

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

def st_var(var_die):
    '''Given a DIE that describes a DW_TAG_variable, a DW_TAG_parameter, or a DW_TAG_member
       containing an optional DW_AT_type
       
    Returns the C/C++ declaration as a single line string
    '''
    return str(parse_var(var_die))

def parse_var(var_die):
    '''parse a DIE that describes a variable, a parameter, or a member

    Returns a TypeDesc.

    Does not follow typedefs, named struct/union/class defs.
    '''
    # name = safe_DIE_name(var_die)
    t = TypeDesc(safe_DIE_name(var_die))

    if not DIE_has_type(var_die):
        t.tag = 'DW_TAG_null'
        return t

    name     = DIE_name(var_die)
    type_die = DIE_type(var_die)

    mods = []
    # Unlike readelf, dwarfdump doesn't chase typedefs
    while type_die.tag in ('DW_TAG_const_type', 'DW_TAG_pointer_type', 'DW_TAG_reference_type'):
        modifier = type_die.tag
        mods.insert(0, modifier)
        if not DIE_has_type(type_die): # void* is encoded as a pointer to nothing
            t.tag = 'DW_TAG_null'
            t.name = 'void'
            t.modifiers = tuple(mods)
            return t
        type_die = DIE_type(type_die)

    # From this point on, type_die doesn't change
    t.tag = type_die.tag
    t.modifiers = tuple(mods)

    if t.tag in ('DW_TAG_ptr_to_member_type', 'DW_TAG_subroutine_type'):
        if t.tag == 'DW_TAG_ptr_to_member_type':
            ptr_prefix = DIE_name(type_die.get_DIE_from_attribute('DW_AT_containing_type')) + '::'
            type_die = DIE_type(type_die)
        elif 'DW_AT_object_pointer' in type_die.attributes: # Older compiler... Subroutine, but with an object pointer
            ptr_prefix = DIE_name(DIE_type(DIE_type(type_die.get_DIE_from_attribute('DW_AT_object_pointer')))) + '::'
        else: # Not a pointer to member
            ptr_prefix = ''

        if t.tag == 'DW_TAG_subroutine_type':
            params = tuple(format_function_param(p, p) for p in type_die.iter_children() 
            if p.tag in ('DW_TAG_formal_parameter', 'DW_TAG_unspecified_parameters') and 'DW_AT_artificial' not in p.attributes)
            params = ', '.join(params)
            if DIE_has_type(type_die):
                retval_type = parse_var(type_die)
                is_pointer = retval_type.modifiers and retval_type.modifiers[-1] == 'pointer'
                retval_type = str(retval_type)
                if not is_pointer:
                    retval_type += ' '
            else:
                retval_type = 'void '

            if len(mods) and mods[-1] == 'pointer':
                mods.pop()
                t.modifiers = tuple(mods)
                t.name = '%s(%s*)(%s)' % (retval_type, ptr_prefix, params)
            else:
                t.name = '%s(%s)' % (retval_type, params)
            return t
    elif DIE_is_ptr_to_member_struct(type_die):
        dt = parse_var(next(type_die.iter_children())) # The first element is pfn, a function pointer with a this
        dt.modifiers = tuple(dt.modifiers[:-1]) # Pop the extra pointer
        dt.tag = 'DW_TAG_ptr_to_member_type' # Not a function pointer per se
        return dt
    elif t.tag == 'DW_TAG_array_type':
        t.dimensions = (_array_subtype_size(sub)
            for sub in type_die.iter_children()
            if sub.tag == 'DW_TAG_subrange_type')
        t.name = st_var(type_die)
        return t
    elif t.tag == 'DW_TAG_base_type':
        encstr = DW_ATE_raw2name[type_die.attributes['DW_AT_encoding'].value]
        t.name = enc2str.get(encstr, '') + ' ' + DIE_name(type_die) + ' ' + name
        return t
    elif t.tag == 'DW_TAG_structure_type':        
        t.name = 'struct ' + DIE_name(type_die) + ' ' + name
        return t
    elif t.tag == 'DW_TAG_union_type':
        t.name = 'union ' + DIE_name(type_die) + ' ' + name
        return t

    # Now the nonfunction types
    # Blank name is sometimes legal (unnamed unions, etc)

    t.name = safe_DIE_name(type_die, t.tag + ' ')

    # Check the nesting - important for parameters
    parent = type_die.get_parent()
    scopes = list()
    while parent.tag in ('DW_TAG_class_type', 'DW_TAG_structure_type', 'DW_TAG_union_type', 'DW_TAG_namespace'):
        scopes.insert(0, safe_DIE_name(parent, parent.tag + ' '))
        # If unnamed scope, fall back to scope type - like 'structure '
        parent = parent.get_parent()
    t.scopes = tuple(scopes)

    return t

class TypeDesc(object):
    ''' Encapsulates a description of a datatype, as parsed from DWARF DIEs.

        name - name for primitive datatypes, element name for arrays, the
            whole name for functions and function pointers

        modifiers - a collection of 'const'/'pointer'/'reference', from the
            chain of DIEs preceeding the real type DIE

        scopes - a collection of struct/class/namespace names, parents of the
            real type DIE

        tag - the tag of the real type DIE, stripped of initial DW_TAG_ and
            final _type

        dimensions - the collection of array dimensions, if the type is an
            array. -1 means an array of unknown dimension.

    '''
    def __init__(self, name = ''):
        self.name = name
        self.modifiers = () # Reads left to right
        self.scopes = () # Reads left to right
        self.tag = None
        self.dimensions = None

    def __str__(self):
        '''Returns the C/C++ type description in a single line'''
        # Some reference points from dwarfdump:
        # const->pointer->const->char = const char *const
        # const->reference->const->int = const const int &
        # const->reference->int = const int &
        name = str(self.name)
        mods = self.modifiers

        desc = []
        # Initial const applies to the var ifself, other consts apply to the pointee
        if len(mods) and mods[0] == 'const':
            desc.append('const')
            mods = mods[1:]

        # ref->const in the end, const goes in front
        if mods[-2:] == ('DW_TAG_reference_type', 'DW_TAG_const_type'):
            desc.append('const')
            mods = mods[0:-1]

        if self.scopes:
            name = '::'.join(self.scopes)+'::' + name
        desc.append(name)

        if len(mods):
            desc.append(''.join(tag2str[mod] for mod in mods))

        if self.dimensions:
            dims = ''.join('[%s]' % (str(dim) if dim > 0 else '',)
                for dim in self.dimensions)
        else:
            dims = ''

        return ' '.join(desc)+dims

def DIE_name(die):
    return bytes2str(die.attributes['DW_AT_name'].value)

def safe_DIE_name(die, default = ''):
    return bytes2str(die.attributes['DW_AT_name'].value) if DIE_has_type(die) else default

def DIE_type(die):
    return die.get_DIE_from_attribute('DW_AT_type')

def DIE_has_type(die):
    return 'DW_AT_type' in die.attributes

class ClassDesc(object):
    def __init__(self):
        self.scopes = ()
        self.const_member = False

def get_class_spec_if_member(func_spec, the_func):
    if 'DW_AT_object_pointer' in the_func.attributes:
        this_param = the_func.get_DIE_from_attribute('DW_AT_object_pointer')
        this_type = parse_var(this_param)
        class_spec = ClassDesc()
        class_spec.scopes = this_type.scopes + (this_type.name,)
        class_spec.const_member = any(('const', 'pointer') == this_type.modifiers[i:i+2]
            for i in range(len(this_type.modifiers))) # const -> pointer -> const for this arg of const
        return class_spec

    # Check the parent element chain - could be a class
    parent = func_spec.get_parent()

    scopes = []
    while parent.tag in ('DW_TAG_class_type', 'DW_TAG_structure_type', 'DW_TAG_namespace'):
        scopes.insert(0, DIE_name(parent))
        parent = parent.get_parent()
    if scopes:
        cs = ClassDesc()
        cs.scopes = tuple(scopes)
        return cs

    return None

def format_function_param(param_spec, param):
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

def DIE_is_ptr_to_member_struct(type_die):
    if type_die.tag == 'DW_TAG_structure_type':
        members = tuple(die for die in type_die.iter_children() if die.tag == 'DW_TAG_member')
        return len(members) == 2 and safe_DIE_name(members[0]) == '__pfn' and safe_DIE_name(members[1]) == '__delta'
    return False

def _array_subtype_size(sub):
    if 'DW_AT_upper_bound' in sub.attributes:
        return sub.attributes['DW_AT_upper_bound'].value + 1
    if 'DW_AT_count' in sub.attributes:
        return sub.attributes['DW_AT_count'].value
    else:
        return -1

def pr_variable(self, die):
    self.pr_ln(st_var(die))

def pr_structure_type(self, die):
    self.pr_ln('struct %s {' % DIE_name(die))
    self.inc_level()
    for ch in die.iter_children():
        self.pr_die(ch)
        self.pr(';')
    self.dec_level()
    self.pr_ln('};')

def pr_subprogram(self, die):
    self.pr_ln('%s %s (' % (st_var(die), DIE_name(die)))
    self.inc_level()
    ch_l = [ch for ch in die.iter_children()]
    for ch in ch_l:
        self.pr_die(ch)
        if  ch != ch_l[-1]:
            self.pr(',')
    self.dec_level()
    self.pr_ln(');')

def pr_type_unit(self, die):
    self.pr_children(die)

def pr_compile_unit(self, die):
    self.pr_ln(self.pr_attr(die, 'DW_AT_producer'))
    self.pr_ln(self.pr_attr(die, 'DW_AT_name'))
    self.pr_children(die)

# dispatch table for pr_<x>(self, die) functions
# contains only type/variable/function definition tags
# tags that cannot exist in a ELF stub will be mapped on pr_exit
deftag2pr_func = dict(
  DW_TAG_null                     = pr_exit,
  #DW_TAG_array_type 
  #DW_TAG_class_type
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
  DW_TAG_structure_type           = pr_structure_type,
  #DW_TAG_subroutine_type          = 
  #DW_TAG_typedef                  = pr_typedef,
  #DW_TAG_union_type
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
        self.ifile = ifile
        self.ofile = ofile
        self.level = 0
        self.args  = args
        elffile = ELFFile(self.ifile)

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
        self.inc_level()
        for ch in die.iter_children():
            self.pr_die(ch) 
        self.dec_level()

    def inc_level(self, lvl = 1):
        self.level += lvl
 
    def dec_level(self, lvl = 1):
        self.level = max(0, self.level - lvl)
 
    def pr_ln(self, txt):
        '''returns txt on a new line with the current indentation'''
        self.pr('\n%*s%s' % (2*self.level, '', txt))

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
