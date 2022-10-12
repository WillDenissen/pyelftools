# def parse_var(vdie):
#     '''parse a DIE that describes a variable, a parameter, or a member
#     with DW_AT_type in it, tries to return the C++ datatype as a string

#     Returns a TypeDesc.

#     Does not follow named struct/union/class/type defs.
#     '''

#     td = TypeDesc()

#     if not DIE_has_type(vdie):
#         td.tag = 'DW_TAG_null'
#         return td

#     tdie = DIE_typeof(vdie)
#     tdie, td.mods = strip_mods(tdie)

#     if td.is_pointer and not DIE_has_type(tdie): # void* is encoded as a pointer to nothing
#         return td

#     # From this point on, tdie doesn't change
#     td.tag = tdie.tag

#     if tdie.tag in ('DW_TAG_ptr_to_member_type', 'DW_TAG_subroutine_type'):
#         tdie, prfx_st = strip_prefix(tdie)

#         if tdie.tag == 'DW_TAG_subroutine_type':
#             prms_st = st_params(tdie)
#             rtrn_st = st_return(tdie)

#             if td.is_pointer:
#                 td.mods.pop()
#                 td.name = '%s(%s*)(%s)' % (rtrn_st, prfx_st, prms_st)
#             else:
#                 td.name = '%s(%s)' % (rtrn_st, prms_st)
#             return td
#     elif DIE_is_ptr_to_member_struct(tdie):
#         dt = parse_var(next(tdie.iter_children())) # The first element is pfn, a function pointer with a this
#         dt.mods.pop() # Pop the extra pointer
#         dt.tag = 'DW_TAG_ptr_to_member_type' # Not a function pointer per se
#         return dt

#     # Now the nonfunction types
#     # Blank name is sometimes legal (unnamed unions, etc)

#     tname = st_opt_name(tdie)
#     vname = st_opt_name(vdie)

#     if tdie.tag in ('DW_TAG_base_type', 'DW_TAG_typedef_type', 'DW_TAG_class_type'):        
#         tname = tname
#     elif tdie.tag == 'DW_TAG_enumeration_type':        
#         tname = 'enum %s' % tname
#     elif tdie.tag == 'DW_TAG_structure_type':        
#         tname = 'struct %s' % tname
#     elif tdie.tag == 'DW_TAG_union_type':
#         tname = 'union %s' % tname

#     td.name = '%s %s' % (tname, vname)    
#     td.scps = get_scopes(tdie)

#     return td

# mod2str = dict(
#     DW_TAG_pointer_type   = '*',
#     DW_TAG_reference_type = '&',
#     DW_TAG_const_type     = 'const',
# )

# class TypeDesc(object):
#     ''' Encapsulates a description of a variable/parameter/member type, as parsed from DWARF DIEs.

#         name - name for primitive datatypes, element name for arrays, the
#             whole name for functions and function pointers

#         mods - a collection of 'const'/'pointer'/'reference', from the
#             chain of DIEs preceeding the real type DIE

#         scps - a collection of struct/class/namespace names, parents of the
#             real type DIE

#         tag - the tag of the real type DIE

#         dims - the collection of array dimensions, if the type is an array. 
#             -1 means an array of unknown dimension.

#     '''

#     def __init__(self):
#         self.name  = 'void'  # name of referenced type
#         self.mods  = []      # Reads left to right
#         self.scps  = []      # Reads left to right
#         self.dims  = []
#         self.tag   = 'DW_TAG_null'

#     def __str__(self):
#         '''Returns the C/C++ variable/member description in a single line
        
#            <tref> (<mod0>...<modn>)?(<scp0>::...::<scpn>::)?<name>([<dim0>]...[dimn])?
#         '''
#         # Some reference points from dwarfdump:
#         # const->pointer->const->char = const char *const
#         # const->reference->const->int = const const int &
#         # const->reference->int = const int &
#         name = self.name
#         mods = self.mods

#         desc = []
#         # Initial const applies to the var ifself, other consts apply to the pointee
#         if len(mods) and mods[0] == 'const':
#             desc.append('const')
#             mods = mods[1:]

#         # ref->const in the end, const goes in front
#         if mods[-2:] == ('DW_TAG_reference_type', 'DW_TAG_const_type'):
#             desc.append('const')
#             mods = mods[0:-1]

#         if self.scps:
#             name = '::'.join(self.scps)+'::' + name
#         desc.append(name)

#         if len(mods):
#             desc.append(''.join(mod2str[mod] for mod in mods))

#         if self.dims:
#             dims = ''.join('[%s]' % (str(dim) if dim > 0 else '',)
#                 for dim in self.dims)
#         else:
#             dims = ''

#         return ' '.join(desc)+dims

#     @property
#     def is_pointer(self):
#         return len(self.mods) and self.mods[-1] == 'DW_TAG_pointer_type'
    
# def strip_mods(tdie):
#     mods = []
#     # peel off the type modifiers from tdie
#     while tdie.tag in ('DW_TAG_const_type', 'DW_TAG_pointer_type', 'DW_TAG_reference_type'):
#         mods.insert(0, tdie.tag)
#         if not DIE_has_type(tdie):
#             return None, mods
#         tdie = DIE_typeof(tdie)
#     return tdie, mods

# def get_scopes(tdie):
#     prnt = tdie.get_parent()
#     scps = list()
#     while prnt.tag in ('DW_TAG_class_type', 'DW_TAG_structure_type', 'DW_TAG_union_type', 'DW_TAG_namespace'):
#         scps.insert(0, st_opt_name(prnt))
#         prnt = prnt.get_parent()
#     return scps

# def strip_prefix(tdie):
#     if tdie.tag == 'DW_TAG_ptr_to_member_type':
#         prfx = st_name(tdie.get_DIE_from_attribute('DW_AT_containing_type')) + '::'
#         tdie = DIE_typeof(tdie)
#     elif 'DW_AT_object_pointer' in tdie.attributes: # Older compiler... Subroutine, but with an object pointer
#         prfx = st_name(DIE_typeof(DIE_typeof(tdie.get_DIE_from_attribute('DW_AT_object_pointer')))) + '::'
#     else:
#         prfx = ''

#     return tdie, prfx


# def st_return(tdie):
#     if DIE_has_type(tdie):
#         rtrn_st = st_var(tdie) + ' '
#     else:
#         rtrn_st = 'void '
#     return rtrn_st
    
# def st_var(vdie):
#     '''Given a DIE that describes a DW_TAG_variable, a DW_TAG_formal_parameter, or a DW_TAG_member
#        containing an optional DW_AT_type
       
#     Returns the C/C++ declaration as a single line string
#     '''
#     return str(parse_var(vdie))


# class ClassDesc(object):
#     def __init__(self):
#         self.scps = ()
#         self.const_member = False

# def get_class_spec_if_member(func_spec, the_func):
#     if DIE_has_attr(the_func, 'DW_AT_object_pointer'):
#         this_param = the_func.get_DIE_from_attribute('DW_AT_object_pointer')
#         this_td = parse_var(this_param)
#         cd = ClassDesc()
#         cd.scps = this_td.scps + (this_td.name,)
#         cd.const_member = any(('const', 'pointer') == this_td.mods[i:i+2]
#             for i in range(len(this_td.mods))) # const -> pointer -> const for this arg of const
#         return cd

#     # Check the parent element chain - could be a class
#     parent = func_spec.get_parent()

#     scps = []
#     while parent.tag in ('DW_TAG_class_type', 'DW_TAG_structure_type', 'DW_TAG_namespace'):
#         scps.insert(0, st_name(parent))
#         parent = parent.get_parent()
#     if scps:
#         cs = ClassDesc()
#         cs.scps = scps
#         return cs

#     return None

# def st_param(pdie):
#     if pdie.tag == 'DW_TAG_formal_parameter':
#            return st_var(pdie)
#     else: # unspecified_parameters AKA variadic
#         return '...'

# def DIE_is_ptr_to_member_struct(tdie):
#     if tdie.tag == 'DW_TAG_structure_type':
#         members = tuple(die for die in tdie.iter_children() if die.tag == 'DW_TAG_member')
#         return len(members) == 2 and st_opt_name(members[0]) == '__pfn' and st_opt_name(members[1]) == '__delta'
#     return False

