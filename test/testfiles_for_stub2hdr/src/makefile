CC           = gcc
#CC           = clang
CFLAGS       = -fPIC -Wall -pedantic -Wno-return-type -Wno-unused-function
LFLAGS       = -shared -nodefaultlibs -nostdlib -Wl,-z,defs -Wl,--no-allow-shlib-undefined
GFLAGS       = -g -gpubnames -grecord-gcc-switches -gstrict-dwarf -g3 -gdwarf-5
gcc_FFLAGS   = -feliminate-unused-debug-symbols -feliminate-unused-debug-types -fdebug-types-section
clang_FFLAGS = -feliminate-unused-debug-types -fdebug-types-section

DFLAGS       = $(CFLAGS) $(GFLAGS) ${${CC}_FFLAGS} 

ODFLAGS      = -hpx -w -g
REFLAGS      = -a -W --debug-dump

# -gsplit-dwarf not needed for stublibs
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