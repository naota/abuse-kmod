KDIR ?= /lib/modules/`uname -r`/build

default:
	$(MAKE) -C $(KDIR) M=$$PWD
check:
	$(MAKE) -C $(KDIR) M=$$PWD C=1
clean:
	$(MAKE) -C $(KDIR) M=$$PWD clean
