GFLAGS = -V

demo: clean check

check: genhdrs
	-@cd out; gcc -c *.h && echo ALL PASSED

genhdrs: bldstubs
	python3 ../../scripts/stub2hdr.py $(GFLAGS) -o out src/bld

bldstubs:
	cd src; make stubs

clean:
	-@cd src/bld; rm -rf *
	-@cd out; rm -rf *.h *.gch


