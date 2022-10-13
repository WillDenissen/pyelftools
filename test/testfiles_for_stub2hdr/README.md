
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
