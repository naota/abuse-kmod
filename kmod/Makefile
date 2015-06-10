KDIR ?= /lib/modules/`uname -r`/build

default:
	$(MAKE) -C $(KDIR) M=$$PWD
check:
	$(MAKE) -C $(KDIR) M=$$PWD C=1
clean:
	rm -f abuse.ko abuse.o
