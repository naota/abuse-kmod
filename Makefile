test: kmod/abuse.ko
	@lsmod | grep -q abuse || sudo insmod kmod/abuse.ko
	sudo $(PWD)/test.sh

kmod/abuse.ko:
	(cd kmod; $(MAKE))
