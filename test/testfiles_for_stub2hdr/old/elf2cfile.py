#!/usr/bin/env python
import sys

# see https://github.com/eliben/pyelftools

# For running from development directory. It should take precedence over the
# installed pyelftools.
sys.path.insert(0, '.')

from elftools.common.exceptions  import ELFError
from elftools.elf.elffile        import ELFFile
from elftools.dwarf.dwarfinfo    import DWARFInfo
from elftools.dwarf.datatype_cpp import describe_cpp_datatype, 

ref_map = {}

def init_ref_map(cu):
  for d in cu.iter_DIEs():
    addr = d.offset - cu.cu_offset
    ref_map[addr] = d


def att(d, anam):
  a, res = None, ''  

  if anam in d.attributes:
    a    = d.attributes[anam]
    res  = ''
  else:
    a    = None
    res  = '/* ERROR: die has no attribute %s */' % anam
    res += pr_nl('0x%08x:' % d.offset)
    res += pr_nl(d.tag)

  return a, res


def ref(addr):
  return ref_map[addr] if addr in ref_map else None


def pr_val(d, anam):
  a, res = att(d, anam)

  if a:
    res += pr_attr(a)

  return res


def pr_nam(d, no_name = False):
  a, res = att(d, 'DW_AT_name')

  if a:
    res += pr_attr(a)
  else:
    res = ''

  return res


tag_map = dict(
  DW_TAG_enumeration_type         = 'enum '  ,
  DW_TAG_structure_type           = 'struct ',
  DW_TAG_union_type               = 'union ' ,
)


def pr_named_type(d):
  return '%s%s' % (tag_map.get(d.tag, ''), pr_nam(d)), ''


def pr_unnamed_type(d):
  return '%s%s' % (tag_map.get(d.tag, ''), pr_nam(d, no_name = True)), ''


def pr_pointer_type(d):
  pre, suf = pr_typ(d)

  return '%s*' % pre, suf


def pr_const_type(d):
  pre, suf = pr_typ(d)

  return 'const %s' % pre, suf


def pr_array_type(d):
  pre, suf = pr_typ(d)
  
  return pre, suf + pr_ch_l(d, 0)


def pr_typedef_type(d):
  pre, suf = pr_typ(d)
  
  return pre, suf + pr_ch_l(d, 0)


def pr_subrange_type(d, inc):
  a, res = att(d, 'DW_AT_upper_bound')

  if a:
    res = '[%s]' % (a.value + 1)

  return res


def pr_unknown_type(d):
  res  = '/* ERROR: unknown type\n'
  res += pr_unknown(d, 0)
  res += '*/'

  return res, ''


typ_map = dict(
  DW_TAG_base_type                = pr_named_type,
  DW_TAG_enumeration_type         = pr_named_type,
  DW_TAG_structure_type           = pr_unnamed_type,
  DW_TAG_union_type               = pr_unnamed_type,
  DW_TAG_typedef                  = pr_typedef_type,
  DW_TAG_array_type               = pr_array_type,
  DW_TAG_pointer_type             = pr_pointer_type,
  DW_TAG_const_type               = pr_const_type,
)


def pr_typ(d):
  suf = ''
  a,   pre = att(d, 'DW_AT_type')

  if a:
    addr      = a.value
    rd        = ref(addr)

    if rd:
      pre, suf = typ_map.get(rd.tag, pr_unknown_type)(rd)
    else:
      pre += '/* ERROR: reference at address 0x%x not found */' % addr

  return pre, suf


def pr_nl(s='', inc = 0):
  return '\n%s%s' %(' ' * inc, s)


def pr_attr_dflt(val):
  return '%s' % val


def pr_attr_ref(val):
  return '<0x%08x>' % (val)


def pr_attr_hex(val):
  return '0x%x' % (val)


def pr_attr_hex_addr(val):
  return '<0x%x>' % (val)


def pr_attr_split_64bit(val):
  lo_w =  val        & 0xFFFFFFFF
  hi_w = (val >> 32) & 0xFFFFFFFF

  return '0x%x 0x%x' % (lo_w, hi_w)


def pr_attr_block(val):
  s = '%s byte block: ' % len(val)
  s += ' '.join('%02x' % item for item in val)
  return s
  

attr_map = dict(
  DW_FORM_ref1       = pr_attr_ref,
  DW_FORM_ref2       = pr_attr_ref,
  DW_FORM_ref4       = pr_attr_ref,
  DW_FORM_ref8       = pr_attr_split_64bit,
  DW_FORM_ref_udata  = pr_attr_ref,        
  DW_FORM_ref_addr   = pr_attr_hex_addr,
  DW_FORM_data4      = pr_attr_hex,
  DW_FORM_data8      = pr_attr_split_64bit,
  DW_FORM_addr       = pr_attr_hex,
  DW_FORM_sec_offset = pr_attr_hex,
  DW_FORM_flag       = pr_attr_dflt,
  DW_FORM_data1      = pr_attr_dflt,
  DW_FORM_data2      = pr_attr_dflt,
  DW_FORM_sdata      = pr_attr_dflt,
  DW_FORM_udata      = pr_attr_dflt,
  DW_FORM_string     = pr_attr_dflt,
  DW_FORM_strp       = pr_attr_dflt,
  DW_FORM_block1     = pr_attr_block,
  DW_FORM_block2     = pr_attr_block,
  DW_FORM_block4     = pr_attr_block,
  DW_FORM_block      = pr_attr_block,
)

def pr_attr(a):
  return attr_map.get(a.form, pr_attr_dflt)(a.value)


def pr_member(d, inc):
  pre, suf = pr_typ(d)

  return pr_nl('%-50s %s%s;' % (pre, pr_nam(d), suf), inc)


def pr_enumerator(d, inc):
  return pr_nl('%-50s = %s' % (pr_nam(d), pr_val(d, 'DW_AT_const_value')), inc)



def pr_ch_l(d, inc, sep ='', flt = lambda ch: True):
  ch_l = [pr_die(ch, inc) for ch in d.iter_children() if flt(ch)]
      
  return sep.join(ch_l)  


def pr_typedef(d, inc):
  pre, suf = pr_typ(d)
  
  return pr_nl('typedef %-50s %s%s;' % (pre, pr_nam(d), suf), inc)


cur_fil = ''

def pr_compile_unit(d, inc):
  global cur_fil

  res = ''

  if 'gcc' not in pr_val(d, 'DW_AT_name'):
    cur_fil = pr_val(d, 'DW_AT_name')

    res += pr_nl('// source file: %s\n' % cur_fil, inc)
    res += pr_nl('// translator: %s\n' % pr_val(d, 'DW_AT_producer'), inc)
    res += pr_ch_l(d, inc)
  else:
    cur_fil = ''

  return res 


def pr_enumeration_type(d, inc):
  res  = pr_nl('enum %s {' % pr_nam(d), inc)
  res += pr_ch_l(d, inc + 2, ',')
  res += pr_nl('};', inc)

  return res 


def pr_subprogram(d, inc):
  res  = pr_nl('%s(' % pr_val(d, 'DW_AT_name'), inc) 
  res += pr_ch_l(d, inc + 2, ',', flt = lambda ch: ch.tag == 'DW_TAG_formal_parameter')
  res += pr_nl(') {}', inc)
#  res += pr_ch_l(d, inc + 2, '', flt = lambda ch: ch.tag != 'DW_TAG_formal_parameter')

  return res 


def pr_formal_parameter(d, inc):
  pre, suf = pr_typ(d)

  return pr_nl('%-50s %s%s' % (pre, pr_nam(d), suf), inc)


def pr_variable(d, inc):
  pre, suf = pr_typ(d)

  return pr_nl('%-50s %s%s;' % (pre, pr_nam(d), suf), inc)


def pr_struct_type(d, inc):
  res  = pr_nl('struct %s {' % pr_nam(d), inc)
  res += pr_ch_l(d, inc + 2)
  res += pr_nl('};', inc)

  return res 


def pr_union_type(d, inc):
  res  = pr_nl('union %s {' % pr_nam(d), inc)
  res += pr_ch_l(d, inc + 2)
  res += pr_nl('};', inc)
  
  return res 


def pr_lexical_block(d, inc):
  res  = pr_nl('{', inc)
  res += pr_ch_l(d, inc + 2)
  res += pr_nl('}', inc)

  return res


def pr_unknown(d, inc):
  res  = pr_nl('0x%08x:' % d.offset)
  res += pr_nl(d.tag, inc)
  
  for a in d.attributes.itervalues():
    res += pr_nl('%-18s: %s' % (a.name, pr_attr(a)), inc)

  res += pr_ch_l(d, inc + 2, '\n')
  
  return res

def pr_null(d, inc):
  return ''

die_d = dict(
  #DW_TAG_null                     = 
  DW_TAG_array_type               = pr_null,
  #DW_TAG_class_type               = 
  #DW_TAG_entry_point              = 
  DW_TAG_enumeration_type         = pr_enumeration_type,
  DW_TAG_formal_parameter         = pr_formal_parameter,
  #DW_TAG_imported_declaration     = 
  #DW_TAG_label                    = 
  DW_TAG_lexical_block            = pr_lexical_block, 
  DW_TAG_member                   = pr_member,
  DW_TAG_pointer_type             = pr_null,
  #DW_TAG_reference_type           = 
  DW_TAG_compile_unit             = pr_compile_unit, 
  #DW_TAG_string_type              = 
  DW_TAG_structure_type           = pr_struct_type,
  #DW_TAG_subroutine_type          = 
  DW_TAG_typedef                  = pr_typedef,
  DW_TAG_union_type               = pr_union_type,
  #DW_TAG_unspecified_parameters   = 
  #DW_TAG_variant                  = 
  #DW_TAG_common_block             = 
  #DW_TAG_common_inclusion         = 
  #DW_TAG_inheritance              = 
  #DW_TAG_inlined_subroutine       = 
  #DW_TAG_module                   = 
  #DW_TAG_ptr_to_member_type       = 
  #DW_TAG_set_type                 = 
  DW_TAG_subrange_type            = pr_subrange_type,
  #DW_TAG_with_stmt                = 
  #DW_TAG_access_declaration       = 
  DW_TAG_base_type                = pr_null,
  #DW_TAG_catch_block              = 
  DW_TAG_const_type               = pr_null,
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
  #DW_TAG_try_block                = 
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
  #DW_TAG_type_unit                = 
  #DW_TAG_rvalue_reference_type    = 

  #DW_TAG_lo_user                  = 
  #DW_TAG_hi_user                  = 
)


def pr_die(d, inc = 0):
  ext, res  = att(d, 'DW_AT_external')
  nam, res  = att(d, 'DW_AT_name')
  do_pr     = nam

  return die_d.get(d.tag, pr_unknown)(d, inc) if do_pr else ''


def gen_stub(inam):
  with open(inam, 'rb') as ifil:
    try:
      elffile = ELFFile(ifil)

      if elffile.has_dwarf_info():
        dwarfinfo = elffile.get_dwarf_info()

        for cu in dwarfinfo.iter_CUs():
          init_ref_map(cu)
      
          res  = pr_die(cu.get_top_DIE(), 0)          
          res += '\n'
          onam = '%s.h' % inam[:-3]
          with open(onam, 'w') as ofil:
            print("...writing to %s ..." % onam)
            print(res, file = ofil) 
      else:
        sys.stderr.write('ERROR: No debug info found in %s\n' % inam)
        sys.exit(1)
    except ELFError as ex:
      sys.stderr.write('ELF error: %s\n' % ex)
      sys.exit(1)


def main():
  gen_stub(sys.argv[1])

if __name__ == '__main__':
  main()


