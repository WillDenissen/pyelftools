# Demonstrator stub2hdr.py
Test framework for the `stub2hdr.py` tool (of only 636 lines!)

It demonstates that for each ***test file*** ```<x>.c``` found in `src/*`:
- a ***stublib*** ```lib<x>.so``` can be build from the ***test file***
- a ***header*** ```<x>.h``` can be extracted from the ***stublib*** 
- a ***precompiled header*** ```<x>.h.gch``` can be generated from the ***header***
 - which is `100x` times bigger than the ***stublib***

So the dataflow is:
```
src/<x>.c --> (gcc) --> src/bld/lib<x>.so --> (stub2header.py) --> out/<x>.h --> (gcc) --> out/<x>h.gch```
```
The file system structure is:
```
.
├── makefile             # runs the whole test suite
├── out
│   ├── <x>.h
│   └── <x>.h.gch
├── README.md
└── src
    ├── makefile         # builds the stublibs: <x>.c --> bld/lib<x>.so
    ├── <x>.c
    └── bld
        └── lib<x>.so    
```
To run the test suite: 
```
> make
```
and the last line must contain ALL PASSED

## OPEN ISSUES:

The following issues need to be investigated in more detail.
### Debuginfo objects 

RHEL allows installing debuginfo object which contain all debug information in DWARF. 
https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/developer_guide/intro.debuginfo. 
It assumes the following relative locations between the executable and the debuginfo object.

```
bin/sleep --> /usr/lib/debug/bin/sleep.debug

/usr/lib/debug/
├── bin -> usr/bin
├── lib -> usr/lib
├── lib64 -> usr/lib64
├── sbin -> usr/sbin
└── usr
    ├── bin
    ├── lib
    ├── lib64
    └── sbin
```

Open Issue: Can we use a x.debug file to extract a stub lib source file x.c from it?

### GNU C extensions
GNU C provides several language features not found in ISO standard C.

#### Attributes
GNU C provides attributes on types/variable/functions as an extension.
These attributes are not preserved in DWARF, and would make the compile/link interface compiler dependend.
Therefore, GNU C attributes are not allowed to be used in stublibs.
Once attributes are standardized in DWARF, they canbeconme part of the generated headers.

https://gcc.gnu.org/onlinedocs/gcc/Attribute-Syntax.html#Attribute-Syntax