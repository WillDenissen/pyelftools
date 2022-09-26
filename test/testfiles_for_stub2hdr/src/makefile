CC           = gcc
CFLAGS       = -fPIC 
LFLAGS       = -shared -nodefaultlibs -nostdlib -Wl,-z,defs -Wl,--no-allow-shlib-undefined
gcc_DFLAGS   = -g -gpubnames -grecord-gcc-switches -gstrict-dwarf -g3 -gdwarf-5 -feliminate-unused-debug-symbols -feliminate-unused-debug-types -fdebug-types-section
clang_DFLAGS = -g -gpubnames -gstrict-dwarf -g3 -gdwarf-5 -feliminate-unused-debug-types -fdebug-types-section

DFLAGS       = $(CFLAGS) $(GCC_DFLAGS) ${${CC}_DFLAGS} 

ODFLAGS      = -hpx -w -g
REFLAGS      = -a -W --debug-dump

# -gsplit-dwarf not needed for stublibs
# -fdebug-types-section NYI by pyelftools
# -gdwarf-4 shows no .debug_types content

# -feliminate-unused-debug-symbols	Perform unused symbol elimination in debug info.
# -feliminate-unused-debug-types	Perform unused type elimination in debug info.
# -ggnu-pubnames					Generate DWARF pubnames and pubtypes sections with GNU extensions.

 
ALL_SRCS  := $(wildcard *.c) 
ALL_STUBS := $(ALL_SRCS:%.c=bld/lib%.so)

all: clean stubs

stubs: $(ALL_STUBS)

bld/lib%.so: %.c
	$(CC) $(DFLAGS) $(LFLAGS) -o $@ $<

clean:
	-@rm -rf bld/* 