
Test framework for the `stub2hdr.py` tool (of only 636 lines!)

It demonstates that for each test file ```<x>.c``` found in `src/*`:
- a stub can be build ```lib<x>.so```
- a header can be extracted from the stub ```<x>.h```
- a precompiled header ```<x>.h.gch``` can be generated from the header
 - that is `100x` times bigger than the stublib

So the dataflow is:
```
src/<x>.c --> src/bld/lib<x>.so --> out/<x>.h --> (gcc) --> out/<x>h.gch```
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
