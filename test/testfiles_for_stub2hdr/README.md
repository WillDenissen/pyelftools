Test framework for the `stub2hdr.py` tool

It demonstates that for each test file ```<x>.c``` found in `src/*`:
- a stub can be build ```lib<x>.so````
- a header can be extracted from the stub ````<x>.h```
- a precompiled header ```<x>.h.gch``` can be generated from the header
 - that is `100x` times bigger than the stublib

So the dataflow is as follows:
src/<x>.c --> src/bld/lib<x>.so --> out/<x>.h --> (gcc) --> out/<x>h.gch

```.
├── makefile             # 
├── out
│   ├── <x>.h            # lib<x>/so --> stub2hdr.py --> <x>.h --> gcc --> <x>.h.gch
│   └── <x>.h.gch        # gcc precompiled header
├── README.md
└── src
    ├── bld
    │   └── lib<x>.so    # stublib of <x>.c
    ├── makefile         # stub: <x>.c --> bld/lib<x>.so
    └── <x>.c
```
To run the test suite: 
```
> make
```
and the last line must contain ALL PASSED
