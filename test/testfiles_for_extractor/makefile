# https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/developer_guide/intro.debuginfo
# The on-disk debuginfo file, if available (for example, /usr/lib/debug/bin/sleep.debug). 

demo: clean extract

extract:
	python3 ../../scripts/extract_stub.py -o out inp

clean:
	-@cd out; rm -rf *


