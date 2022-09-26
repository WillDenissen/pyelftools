Test framework for the scripts/stub2hdr.py tool


```.
├── makefile             # demo: <x>.c --> lib<x>.so --> <x>.h (gcc checked)
├── out
│   ├── <x>.h            # lib<x>/so --> stub2hdr.py --> <x>.h --> gcc --> <x>.h.gch
│   └── <x>.h.gch        # gcc precompiled header
├── README.md
└── src
    ├── bld
    │   └── lib<x>.so    # stublib of <x>.c
    ├── makefile         # stub: <x>.c --> lib<x>.so
    └── <x>.c
```
Run 
```
> make
```
and the last line must contain ALL PASSED
